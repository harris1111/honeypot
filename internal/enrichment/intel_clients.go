package enrichment

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"golang.org/x/time/rate"

	"github.com/harris/honeypot/internal/store"
)

// Config configures optional Threat Intelligence API endpoints, keys, and Redis caching.
type Config struct {
	GreyNoiseBaseURL string // default https://api.greynoise.io
	GreyNoiseAPIKey  string
	AbuseIPDBBaseURL string // default https://api.abuseipdb.com
	AbuseIPDBAPIKey  string
	VirusTotalBaseURL string // default https://www.virustotal.com (strictly GET /api/v3/files/{sha256}!)
	VirusTotalAPIKey  string
	MinSeverity      int32 // skip low-noise events (< 40) to preserve quota
	CacheTTL         time.Duration
}

// IPIntel holds normalized Threat Intelligence classification for one IP.
type IPIntel struct {
	CountryCode string `json:"country_code"`
	ASN         int    `json:"asn"`
	GreyNoise   string `json:"greynoise_classification"` // benign | malicious | unknown
	AbuseScore  int    `json:"abuseipdb_score"`
}

// VTReputation holds hash-only VirusTotal detection statistics.
type VTReputation struct {
	Malicious int `json:"malicious"`
	Total     int `json:"total"`
}

// Client enriches IPs and file SHA256 hashes asynchronously using 24h Redis caches and per-provider rate limits.
type Client struct {
	pg        *store.Postgres
	rd        *redis.Client
	geo       *GeoResolver
	cfg       Config
	httpCli   *http.Client
	gnLimiter *rate.Limiter
	abLimiter *rate.Limiter
	vtLimiter *rate.Limiter

	OnEnriched func(ctx context.Context, ip string, intel IPIntel)
}

// NewClient constructs the Cached Threat Intel & GeoIP Enrichment client.
func NewClient(pg *store.Postgres, rd *store.Redis, geo *GeoResolver, cfg Config) *Client {
	if cfg.GreyNoiseBaseURL == "" {
		cfg.GreyNoiseBaseURL = "https://api.greynoise.io"
	}
	if cfg.AbuseIPDBBaseURL == "" {
		cfg.AbuseIPDBBaseURL = "https://api.abuseipdb.com"
	}
	if cfg.VirusTotalBaseURL == "" {
		cfg.VirusTotalBaseURL = "https://www.virustotal.com"
	}
	if cfg.MinSeverity <= 0 {
		cfg.MinSeverity = 40
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = 24 * time.Hour
	}
	var rc *redis.Client
	if rd != nil {
		rc = rd.Client
	}
	return &Client{
		pg:        pg,
		rd:        rc,
		geo:       geo,
		cfg:       cfg,
		httpCli:   &http.Client{Timeout: 8 * time.Second},
		gnLimiter: rate.NewLimiter(rate.Every(1*time.Second), 5),
		abLimiter: rate.NewLimiter(rate.Every(2*time.Second), 5),
		vtLimiter: rate.NewLimiter(rate.Every(15*time.Second), 4), // VT free tier = 4 req/min
	}
}

// EnrichIP resolves offline GeoIP + Redis-cached GreyNoise & AbuseIPDB, persists results, and calls OnEnriched.
func (c *Client) EnrichIP(ctx context.Context, ip string, severity int32) (IPIntel, error) {
	geoRes := c.geo.Lookup(ip)
	intel := IPIntel{
		CountryCode: geoRes.CountryCode,
		ASN:         geoRes.ASN,
		GreyNoise:   "unknown",
	}

	if severity < c.cfg.MinSeverity && c.cfg.GreyNoiseAPIKey == "" {
		return intel, nil
	}

	if c.rd != nil {
		if raw, err := c.rd.Get(ctx, "intel:ip:"+ip).Bytes(); err == nil {
			_ = json.Unmarshal(raw, &intel)
			if intel.CountryCode == "" {
				intel.CountryCode = geoRes.CountryCode
			}
			if intel.ASN == 0 {
				intel.ASN = geoRes.ASN
			}
			if c.pg != nil {
				_ = c.pg.UpdateTelemetryEnrichment(ctx, ip, intel.CountryCode, intel.ASN, intel.GreyNoise, intel.AbuseScore)
			}
			if c.OnEnriched != nil {
				c.OnEnriched(ctx, ip, intel)
			}
			return intel, nil
		}
	}

	// Query GreyNoise if API key/mock URL configured
	if c.cfg.GreyNoiseAPIKey != "" || !strings.Contains(c.cfg.GreyNoiseBaseURL, "api.greynoise.io") {
		if err := c.gnLimiter.Wait(ctx); err == nil {
			intel.GreyNoise = c.queryGreyNoise(ctx, ip)
		}
	}

	// Query AbuseIPDB if API key/mock URL configured
	if c.cfg.AbuseIPDBAPIKey != "" || !strings.Contains(c.cfg.AbuseIPDBBaseURL, "api.abuseipdb.com") {
		if err := c.abLimiter.Wait(ctx); err == nil {
			intel.AbuseScore = c.queryAbuseIPDB(ctx, ip)
		}
	}

	if c.rd != nil {
		if b, err := json.Marshal(intel); err == nil {
			_ = c.rd.Set(ctx, "intel:ip:"+ip, b, c.cfg.CacheTTL).Err()
		}
	}
	if c.pg != nil {
		_ = c.pg.UpdateTelemetryEnrichment(ctx, ip, intel.CountryCode, intel.ASN, intel.GreyNoise, intel.AbuseScore)
	}
	if c.OnEnriched != nil {
		c.OnEnriched(ctx, ip, intel)
	}
	return intel, nil
}

// EnrichArtifactHash performs strictly HASH-ONLY VirusTotal lookup (GET /api/v3/files/{sha256}, NEVER uploads files).
func (c *Client) EnrichArtifactHash(ctx context.Context, sha256Hex string) (VTReputation, error) {
	if len(sha256Hex) != 64 {
		return VTReputation{}, fmt.Errorf("invalid sha256 hash length")
	}
	for i := 0; i < len(sha256Hex); i++ {
		ch := sha256Hex[i]
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')) {
			return VTReputation{}, fmt.Errorf("invalid sha256 hex char")
		}
	}
	if c.cfg.VirusTotalAPIKey == "" && strings.Contains(c.cfg.VirusTotalBaseURL, "virustotal.com") {
		return VTReputation{}, nil
	}
	if c.rd != nil {
		if raw, err := c.rd.Get(ctx, "intel:vt:"+sha256Hex).Bytes(); err == nil {
			var rep VTReputation
			if json.Unmarshal(raw, &rep) == nil {
				return rep, nil
			}
		}
	}
	if err := c.vtLimiter.Wait(ctx); err != nil {
		return VTReputation{}, err
	}

	u := fmt.Sprintf("%s/api/v3/files/%s", strings.TrimRight(c.cfg.VirusTotalBaseURL, "/"), sha256Hex)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return VTReputation{}, err
	}
	if c.cfg.VirusTotalAPIKey != "" {
		req.Header.Set("x-apikey", c.cfg.VirusTotalAPIKey)
	}
	resp, err := c.httpCli.Do(req)
	if err != nil {
		return VTReputation{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return VTReputation{}, nil
	}

	var body struct {
		Data struct {
			Attributes struct {
				LastAnalysisStats struct {
					Malicious  int `json:"malicious"`
					Suspicious int `json:"suspicious"`
					Undetected int `json:"undetected"`
					Harmless   int `json:"harmless"`
				} `json:"last_analysis_stats"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if json.NewDecoder(resp.Body).Decode(&body) != nil {
		return VTReputation{}, nil
	}
	st := body.Data.Attributes.LastAnalysisStats
	rep := VTReputation{
		Malicious: st.Malicious + st.Suspicious,
		Total:     st.Malicious + st.Suspicious + st.Undetected + st.Harmless,
	}
	if c.rd != nil {
		if b, err := json.Marshal(rep); err == nil {
			_ = c.rd.Set(ctx, "intel:vt:"+sha256Hex, b, c.cfg.CacheTTL).Err()
		}
	}
	if c.pg != nil && rep.Total > 0 {
		_ = c.pg.UpdateMalwareVT(ctx, sha256Hex, rep.Malicious, rep.Total)
	}
	return rep, nil
}

func (c *Client) queryGreyNoise(ctx context.Context, ip string) string {
	u := fmt.Sprintf("%s/v3/community/%s", strings.TrimRight(c.cfg.GreyNoiseBaseURL, "/"), ip)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "unknown"
	}
	if c.cfg.GreyNoiseAPIKey != "" {
		req.Header.Set("key", c.cfg.GreyNoiseAPIKey)
	}
	resp, err := c.httpCli.Do(req)
	if err != nil {
		return "unknown"
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "unknown"
	}
	var res struct {
		Riot           bool   `json:"riot"`
		Noise          bool   `json:"noise"`
		Classification string `json:"classification"`
	}
	if json.NewDecoder(resp.Body).Decode(&res) != nil {
		return "unknown"
	}
	switch strings.ToLower(res.Classification) {
	case "benign":
		return "benign"
	case "malicious":
		return "malicious"
	default:
		if res.Riot {
			return "benign"
		}
		return "unknown"
	}
}

func (c *Client) queryAbuseIPDB(ctx context.Context, ip string) int {
	u := fmt.Sprintf("%s/api/v2/check?ipAddress=%s&maxAgeInDays=30", strings.TrimRight(c.cfg.AbuseIPDBBaseURL, "/"), ip)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0
	}
	if c.cfg.AbuseIPDBAPIKey != "" {
		req.Header.Set("Key", c.cfg.AbuseIPDBAPIKey)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.httpCli.Do(req)
	if err != nil {
		return 0
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return 0
	}
	var res struct {
		Data struct {
			AbuseConfidenceScore int `json:"abuseConfidenceScore"`
		} `json:"data"`
	}
	if json.NewDecoder(resp.Body).Decode(&res) != nil {
		return 0
	}
	return res.Data.AbuseConfidenceScore
}
