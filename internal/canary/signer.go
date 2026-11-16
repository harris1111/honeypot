package canary

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/harris/honeypot/internal/store"
	honeypotv1 "github.com/harris/honeypot/proto/gen/honeypot/v1"
)

const base62Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// Record describes a persisted or verified Canary API Key.
type Record struct {
	ID                   string
	KeyPrefix            string
	ProviderStyle        string
	NodeID               string
	PlacementSource      string
	PlacementPath        string
	PaidUpstreamEligible bool
	HitCount             int64
}

// Signer operates exclusively on Central Hive, keeping master HMAC-SHA256 & AES-256-GCM keys off exposed Sensors.
type Signer struct {
	hmacSecret []byte
	aesKey     []byte
}

// NewSigner constructs a Hive Canary Signer from 32-byte master secret material.
func NewSigner(masterSecret []byte) (*Signer, error) {
	if len(masterSecret) < 16 {
		return nil, errors.New("master secret must be >= 16 bytes")
	}
	hMac := sha256.Sum256(append([]byte("canary-hmac:"), masterSecret...))
	hAES := sha256.Sum256(append([]byte("canary-aes:"), masterSecret...))
	return &Signer{
		hmacSecret: hMac[:],
		aesKey:     hAES[:],
	}, nil
}

// GenerateToken creates a realistic sk-proj-* or sk-ant-api03-* traceable Canary API Key.
func (s *Signer) GenerateToken(providerStyle, nodeTag, trapTag string, now time.Time) (string, error) {
	if providerStyle != "openai" && providerStyle != "anthropic" {
		return "", fmt.Errorf("unsupported provider style %q", providerStyle)
	}
	nodeB62 := padBase62(normalizeTag(nodeTag), 4)
	trapB62 := padBase62(normalizeTag(trapTag), 2)
	tsB62 := encodeBase62Uint64(uint64(now.UTC().Unix()), 6)
	randPart, err := randomBase62(16)
	if err != nil {
		return "", err
	}
	core := nodeB62 + trapB62 + tsB62 + randPart
	sig := s.computeTag(providerStyle, core)

	if providerStyle == "anthropic" {
		return fmt.Sprintf("sk-ant-api03-%s%s%s-%s-%s", nodeB62, trapB62, tsB62, randPart, sig), nil
	}
	return fmt.Sprintf("sk-proj-%s%s", core, sig), nil
}

// VerifyFormat checks whether token matches our HMAC-SHA256 signature in constant time without hitting the DB.
func (s *Signer) VerifyFormat(token string) (providerStyle string, ok bool) {
	token = strings.TrimSpace(token)
	switch {
	case strings.HasPrefix(token, "sk-proj-"):
		body := strings.TrimPrefix(token, "sk-proj-")
		if len(body) != 4+2+6+16+12 {
			return "", false
		}
		core := body[:28]
		sig := body[28:]
		expected := s.computeTag("openai", core)
		if subtle.ConstantTimeCompare([]byte(sig), []byte(expected)) == 1 {
			return "openai", true
		}
	case strings.HasPrefix(token, "sk-ant-api03-"):
		body := strings.TrimPrefix(token, "sk-ant-api03-")
		parts := strings.Split(body, "-")
		if len(parts) != 3 || len(parts[0]) != 12 || len(parts[1]) != 16 || len(parts[2]) != 12 {
			return "", false
		}
		core := parts[0] + parts[1]
		sig := parts[2]
		expected := s.computeTag("anthropic", core)
		if subtle.ConstantTimeCompare([]byte(sig), []byte(expected)) == 1 {
			return "anthropic", true
		}
	}
	return "", false
}

func (s *Signer) computeTag(style, core string) string {
	mac := hmac.New(sha256.New, s.hmacSecret)
	_, _ = mac.Write([]byte(style + ":" + core))
	sum := mac.Sum(nil)
	out := make([]byte, 12)
	for i := 0; i < 12; i++ {
		out[i] = base62Alphabet[int(sum[i])%len(base62Alphabet)]
	}
	return string(out)
}

// EncryptPlaintext encrypts a Canary Key plaintext with AES-256-GCM for DB storage.
func (s *Signer) EncryptPlaintext(plaintext string) ([]byte, error) {
	blk, err := aes.NewCipher(s.aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, []byte(plaintext), nil), nil
}

// DecryptPlaintext decrypts an AES-256-GCM encrypted Canary Key plaintext.
func (s *Signer) DecryptPlaintext(ciphertext []byte) (string, error) {
	blk, err := aes.NewCipher(s.aesKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		return "", err
	}
	ns := gcm.NonceSize()
	if len(ciphertext) < ns {
		return "", errors.New("ciphertext too short")
	}
	plain, err := gcm.Open(nil, ciphertext[:ns], ciphertext[ns:], nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// MintAndStore mints a Canary Key on Hive and saves it into PostgreSQL canary_keys.
func (s *Signer) MintAndStore(ctx context.Context, pg *store.Postgres, providerStyle, nodeID, trapTag, placementSource, placementPath string, paidEligible bool) (*honeypotv1.CanaryKeySeed, error) {
	nodeTag := "node"
	if len(nodeID) >= 4 {
		nodeTag = nodeID[:4]
	}
	raw, err := s.GenerateToken(providerStyle, nodeTag, trapTag, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	enc, err := s.EncryptPlaintext(raw)
	if err != nil {
		return nil, err
	}
	hashBytes := store.HashKeySHA256(raw)
	prefix := raw
	if len(prefix) > 16 {
		prefix = prefix[:16]
	}
	var nodePtr *string
	if _, err := uuid.Parse(nodeID); err == nil {
		nodePtr = &nodeID
	}
	var keyID string
	err = pg.Pool.QueryRow(ctx, `
		INSERT INTO canary_keys (key_prefix, key_hash, key_plaintext_enc, provider_style, node_id, placement_source, placement_path, paid_upstream_eligible)
		VALUES ($1, $2, $3, $4, $5::uuid, $6, $7, $8)
		RETURNING id::text
	`, prefix, hashBytes, enc, providerStyle, nodePtr, placementSource, placementPath, paidEligible).Scan(&keyID)
	if err != nil {
		return nil, err
	}
	return &honeypotv1.CanaryKeySeed{
		CanaryKeyId:          keyID,
		KeyPlaintext:         raw,
		KeyHashHex:           hex.EncodeToString(hashBytes),
		ProviderStyle:        providerStyle,
		PlacementSource:      placementSource,
		PlacementPath:        placementPath,
		PaidUpstreamEligible: paidEligible,
	}, nil
}

// LookupByHash looks up a Canary Key record in PostgreSQL by SHA-256 hex digest.
func LookupByHash(ctx context.Context, pg *store.Postgres, hashHex string) (Record, bool, error) {
	hashBytes, err := hex.DecodeString(strings.TrimSpace(hashHex))
	if err != nil || len(hashBytes) != 32 {
		return Record{}, false, nil
	}
	var rec Record
	var nodeNull *string
	err = pg.Pool.QueryRow(ctx, `
		SELECT id::text, key_prefix, provider_style, node_id::text, placement_source, placement_path, paid_upstream_eligible, hit_count
		FROM canary_keys
		WHERE key_hash = $1
	`, hashBytes).Scan(&rec.ID, &rec.KeyPrefix, &rec.ProviderStyle, &nodeNull, &rec.PlacementSource, &rec.PlacementPath, &rec.PaidUpstreamEligible, &rec.HitCount)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			return Record{}, false, nil
		}
		return Record{}, false, err
	}
	if nodeNull != nil {
		rec.NodeID = *nodeNull
	}
	return rec, true, nil
}

// SensorKeyPool manages pre-minted Hive Canary Keys on a Sensor VPS without exposing master secrets.
type SensorKeyPool struct {
	mu      sync.Mutex
	bySource map[string][]*honeypotv1.CanaryKeySeed
	allByHash map[string]*honeypotv1.CanaryKeySeed
}

// NewSensorKeyPool constructs an empty SensorKeyPool.
func NewSensorKeyPool() *SensorKeyPool {
	return &SensorKeyPool{
		bySource:  make(map[string][]*honeypotv1.CanaryKeySeed),
		allByHash: make(map[string]*honeypotv1.CanaryKeySeed),
	}
}

// AddSeeds stores Hive-pushed CanaryKeySeeds into the local pool.
func (p *SensorKeyPool) AddSeeds(seeds []*honeypotv1.CanaryKeySeed) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, s := range seeds {
		if s == nil {
			continue
		}
		if s.KeyHashHex == "" && s.KeyPlaintext != "" {
			sum := sha256.Sum256([]byte(s.KeyPlaintext))
			s.KeyHashHex = hex.EncodeToString(sum[:])
		}
		if s.GetKeyHashHex() == "" {
			continue
		}
		if _, dup := p.allByHash[s.GetKeyHashHex()]; dup {
			continue
		}
		p.allByHash[s.GetKeyHashHex()] = s
		p.bySource[s.GetPlacementSource()] = append(p.bySource[s.GetPlacementSource()], s)
	}
}

// SnapshotSeeds returns a copy of all currently loaded CanaryKeySeeds for persistence on the Sensor.
func (p *SensorKeyPool) SnapshotSeeds() []*honeypotv1.CanaryKeySeed {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]*honeypotv1.CanaryKeySeed, 0, len(p.allByHash))
	for _, s := range p.allByHash {
		out = append(out, s)
	}
	return out
}

// MintDefaultPoolForNode pre-mints initial OpenAI & Anthropic canary keys across Cowrie, Git, and LLM traps.
func (s *Signer) MintDefaultPoolForNode(ctx context.Context, pg *store.Postgres, nodeID string) ([]*honeypotv1.CanaryKeySeed, error) {
	specs := []struct {
		style, tag, source, path string
		paidEligible             bool
	}{
		{"openai", "cw", "cowrie_honeyfs", "/var/www/app/.env", true},
		{"anthropic", "ca", "cowrie_honeyfs", "/var/www/app/.env", true},
		{"openai", "gl", "git_lure", "/.env.production", true},
		{"openai", "lp", "llm_pool", "/key/generate", false},
		{"anthropic", "la", "llm_pool", "/key/generate", false},
	}
	var out []*honeypotv1.CanaryKeySeed
	for _, sp := range specs {
		seed, err := s.MintAndStore(ctx, pg, sp.style, nodeID, sp.tag, sp.source, sp.path, sp.paidEligible)
		if err != nil {
			return out, err
		}
		out = append(out, seed)
	}
	return out, nil
}

// PeekBySource returns a stable Canary key for static breadcrumbs (e.g. cowrie_honeyfs, git_lure).
func (p *SensorKeyPool) PeekBySource(source, providerStyle string) (*honeypotv1.CanaryKeySeed, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, s := range p.bySource[source] {
		if providerStyle == "" || s.GetProviderStyle() == providerStyle {
			return s, true
		}
	}
	for _, s := range p.allByHash {
		if providerStyle == "" || s.GetProviderStyle() == providerStyle {
			return s, true
		}
	}
	return nil, false
}

// DispensePoolKey pops/rotates a pre-minted Canary key (e.g. for LiteLLM /key/generate).
func (p *SensorKeyPool) DispensePoolKey(source string) (*honeypotv1.CanaryKeySeed, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	list := p.bySource[source]
	if len(list) == 0 {
		for _, s := range p.allByHash {
			return s, true
		}
		return nil, false
	}
	first := list[0]
	if len(list) > 1 {
		p.bySource[source] = append(list[1:], first) // rotate cleanly without exhausting pool
	}
	return first, true
}

// LookupToken checks whether an incoming Bearer/x-api-key matches a known Sensor-pooled Canary Key.
func (p *SensorKeyPool) LookupToken(token string) (*honeypotv1.CanaryKeySeed, bool) {
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	h := hex.EncodeToString(sum[:])
	p.mu.Lock()
	defer p.mu.Unlock()
	s, ok := p.allByHash[h]
	return s, ok
}

func normalizeTag(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
			b.WriteByte(c)
		}
	}
	return b.String()
}

func padBase62(s string, length int) string {
	if len(s) >= length {
		return s[:length]
	}
	return strings.Repeat("0", length-len(s)) + s
}

func encodeBase62Uint64(v uint64, width int) string {
	buf := make([]byte, width)
	for i := width - 1; i >= 0; i-- {
		buf[i] = base62Alphabet[v%62]
		v /= 62
	}
	return string(buf)
}

func randomBase62(length int) (string, error) {
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	for i := range buf {
		buf[i] = base62Alphabet[int(buf[i])%len(base62Alphabet)]
	}
	return string(buf), nil
}
