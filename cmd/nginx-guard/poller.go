package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/harris/honeypot/internal/guard"
)

// Poller fetches Ed25519-signed blocklist feeds from Hive's mTLS :9443 endpoint,
// verifies anti-rollback & signature, writes dual-stack geo{} configs, and commits revisions.
type Poller struct {
	feedURL  string
	client   *http.Client
	verifier *FeedVerifier
	writer   *NginxWriter
}

func NewPoller(feedURL string, client *http.Client, verifier *FeedVerifier, writer *NginxWriter) *Poller {
	return &Poller{
		feedURL:  strings.TrimRight(feedURL, "/"),
		client:   client,
		verifier: verifier,
		writer:   writer,
	}
}

// PollOnce fetches, verifies, applies, and persists one feed update.
func (p *Poller) PollOnce(ctx context.Context) (appliedRev int64, reloaded bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.feedURL, nil)
	if err != nil {
		return 0, false, err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return 0, false, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return 0, false, fmt.Errorf("hive feed status %d: %s", resp.StatusCode, string(b))
	}

	var signed guard.NginxSignedFeed
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8*1024*1024)).Decode(&signed); err != nil {
		return 0, false, fmt.Errorf("decode signed feed: %w", err)
	}
	payload, err := p.verifier.Verify(signed)
	if err != nil {
		return 0, false, err
	}
	reloaded, err = p.writer.Apply(payload)
	if err != nil {
		return 0, false, err
	}
	if err := p.verifier.CommitRevision(payload.Revision); err != nil {
		return 0, reloaded, err
	}
	return payload.Revision, reloaded, nil
}
