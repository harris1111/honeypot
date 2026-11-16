package guard

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/harris/honeypot/internal/pki"
	"github.com/harris/honeypot/internal/store"
)

// NginxSignedFeed is served on Hive :9443 /api/v1/guard/feeds/nginx over strict mTLS
// and cryptographically verified via Ed25519 + monotonic revision on nginx-guard nodes.
type NginxSignedFeed struct {
	PayloadB64   string `json:"payload_b64"`
	SignatureB64 string `json:"signature_b64"`
}

// FeedPayload is the canonical JSON document signed by Hive's Ed25519 key.
type FeedPayload struct {
	Revision        int64    `json:"revision"`
	SignedAt        string   `json:"signed_at"`
	CloudflareCIDRs []string `json:"cloudflare_cidrs"`
	BlockedPrefixes []string `json:"blocked_prefixes"`
}

// FeedSigner builds and signs validated IP/CIDR feeds for nginx-guard.
type FeedSigner struct {
	ca *pki.CA
	pg *store.Postgres
}

// NewFeedSigner creates a signed feed producer using Hive CA's Ed25519 keypair.
func NewFeedSigner(ca *pki.CA, pg *store.Postgres) *FeedSigner {
	return &FeedSigner{ca: ca, pg: pg}
}

// BuildSignedNginxFeed queries active nginx-targeted IP/CIDR blocks and signs with Hive's Ed25519 key.
func (f *FeedSigner) BuildSignedNginxFeed(ctx context.Context) (NginxSignedFeed, FeedPayload, error) {
	rev, err := f.pg.NextFeedRevision(ctx)
	if err != nil {
		return NginxSignedFeed{}, FeedPayload{}, err
	}

	// Fetch active IP/CIDR entries that are approved/enforced and DO NOT overlap protected_allowlist
	rows, err := f.pg.Pool.Query(ctx, `
		SELECT gd.indicator_value
		FROM guard_decisions gd
		WHERE gd.status IN ('approved', 'enforced')
		  AND gd.target_sync IN ('nginx', 'both')
		  AND gd.indicator_type IN ('ip', 'cidr')
		  AND (gd.ttl_expires_at IS NULL OR gd.ttl_expires_at > NOW())
		  AND NOT EXISTS (
		      SELECT 1 FROM protected_allowlist pa WHERE pa.cidr && gd.indicator_value::inet
		  )
	`)
	if err != nil {
		return NginxSignedFeed{}, FeedPayload{}, err
	}
	defer rows.Close()

	prefixSet := make(map[string]struct{})
	for rows.Next() {
		var raw string
		if rows.Scan(&raw) == nil {
			if norm, ok := normalizeNetipPrefix(raw); ok {
				prefixSet[norm] = struct{}{}
			}
		}
	}
	if err := rows.Err(); err != nil {
		return NginxSignedFeed{}, FeedPayload{}, err
	}

	blocked := make([]string, 0, len(prefixSet))
	for p := range prefixSet {
		blocked = append(blocked, p)
	}
	sort.Strings(blocked)

	// Query system-locked Cloudflare edge CIDRs from protected_allowlist
	cfRows, err := f.pg.Pool.Query(ctx, `
		SELECT cidr::text FROM protected_allowlist WHERE label ILIKE '%Cloudflare%' ORDER BY cidr::text
	`)
	var cfCIDRs []string
	if err == nil {
		defer cfRows.Close()
		for cfRows.Next() {
			var c string
			if cfRows.Scan(&c) == nil {
				cfCIDRs = append(cfCIDRs, c)
			}
		}
	}

	payload := FeedPayload{
		Revision:        rev,
		SignedAt:        time.Now().UTC().Format(time.RFC3339),
		CloudflareCIDRs: cfCIDRs,
		BlockedPrefixes: blocked,
	}
	rawJSON, err := json.Marshal(payload)
	if err != nil {
		return NginxSignedFeed{}, FeedPayload{}, err
	}
	sig := f.ca.SignFeed(rawJSON)

	return NginxSignedFeed{
		PayloadB64:   base64.StdEncoding.EncodeToString(rawJSON),
		SignatureB64: base64.StdEncoding.EncodeToString(sig),
	}, payload, nil
}

func normalizeNetipPrefix(raw string) (string, bool) {
	s := strings.TrimSpace(raw)
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked().String(), true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		un := a.Unmap()
		bits := 32
		if un.Is6() {
			bits = 64
		}
		return netip.PrefixFrom(un, bits).Masked().String(), true
	}
	return "", false
}
