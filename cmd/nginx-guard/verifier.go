package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/harris/honeypot/internal/guard"
)

// FeedVerifier enforces Ed25519 signature authenticity and anti-rollback revision monotonicity
// persisted atomically on disk across nginx-guard restarts.
type FeedVerifier struct {
	mu          sync.Mutex
	pubKey      ed25519.PublicKey
	revFilePath string
	lastRev     int64
}

// NewFeedVerifier loads persisted last_applied_revision from stateDir and binds Hive's Ed25519 pubkey.
func NewFeedVerifier(pubKey []byte, stateDir string) (*FeedVerifier, error) {
	if len(pubKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("expected %d-byte Ed25519 pubkey, got %d", ed25519.PublicKeySize, len(pubKey))
	}
	v := &FeedVerifier{
		pubKey:      ed25519.PublicKey(append([]byte(nil), pubKey...)),
		revFilePath: filepath.Join(stateDir, "last_applied_revision"),
	}
	if b, err := os.ReadFile(v.revFilePath); err == nil {
		if n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); err == nil && n > 0 {
			v.lastRev = n
		}
	}
	return v, nil
}

// LastAppliedRevision returns the highest successfully applied feed revision.
func (v *FeedVerifier) LastAppliedRevision() int64 {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.lastRev
}

// Verify decodes base64 feed bytes, validates the Ed25519 signature, and rejects stale revisions.
func (v *FeedVerifier) Verify(feed guard.NginxSignedFeed) (guard.FeedPayload, error) {
	rawJSON, err := base64.StdEncoding.DecodeString(strings.TrimSpace(feed.PayloadB64))
	if err != nil {
		return guard.FeedPayload{}, fmt.Errorf("decode payload_b64: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(feed.SignatureB64))
	if err != nil {
		return guard.FeedPayload{}, fmt.Errorf("decode signature_b64: %w", err)
	}
	if !ed25519.Verify(v.pubKey, rawJSON, sig) {
		return guard.FeedPayload{}, errors.New("feed Ed25519 signature verification failed")
	}

	var payload guard.FeedPayload
	if err := json.Unmarshal(rawJSON, &payload); err != nil {
		return guard.FeedPayload{}, fmt.Errorf("unmarshal feed payload: %w", err)
	}

	v.mu.Lock()
	last := v.lastRev
	v.mu.Unlock()

	if payload.Revision <= last {
		return guard.FeedPayload{}, fmt.Errorf("stale or replayed feed revision %d <= last applied %d", payload.Revision, last)
	}
	return payload, nil
}

// CommitRevision persists the newly applied revision atomically on disk after nginx -t passes.
func (v *FeedVerifier) CommitRevision(rev int64) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if rev <= v.lastRev {
		return nil
	}
	_ = os.MkdirAll(filepath.Dir(v.revFilePath), 0o700)
	tmp := v.revFilePath + ".tmp"
	if err := os.WriteFile(tmp, []byte(strconv.FormatInt(rev, 10)+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, v.revFilePath); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	v.lastRev = rev
	return nil
}
