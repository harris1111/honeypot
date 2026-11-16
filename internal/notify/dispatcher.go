package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Config configures optional Telegram, Discord, and generic Webhook alert destinations
// plus digest batching window to avoid webhook floods during mass internet scans.
type Config struct {
	TelegramBotToken string
	TelegramChatID   string
	DiscordWebhook   string
	GenericWebhook   string
	DigestWindow     time.Duration
}

// AlertEvent represents a high-confidence incident or Canary trigger queued for notification.
type AlertEvent struct {
	RuleKey   string `json:"rule_key"`
	Severity  string `json:"severity"`
	Title     string `json:"title"`
	SourceIP  string `json:"source_ip"`
	Details   string `json:"details"`
	Timestamp time.Time `json:"timestamp"`
}

// Dispatcher batches burst alerts per RuleKey over DigestWindow and fans out via Telegram/Discord/Webhook.
type Dispatcher struct {
	cfg     Config
	httpCli *http.Client

	mu      sync.Mutex
	buckets map[string][]AlertEvent
}

// NewDispatcher creates a rate-grouped notification dispatcher.
func NewDispatcher(cfg Config) *Dispatcher {
	if cfg.DigestWindow <= 0 {
		cfg.DigestWindow = 10 * time.Second
	}
	return &Dispatcher{
		cfg:     cfg,
		httpCli: &http.Client{Timeout: 8 * time.Second},
		buckets: make(map[string][]AlertEvent),
	}
}

// Enqueue records an alert into its RuleKey batch bucket.
func (d *Dispatcher) Enqueue(ev AlertEvent) {
	if d == nil {
		return
	}
	if ev.RuleKey == "" {
		ev.RuleKey = "default"
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	d.mu.Lock()
	d.buckets[ev.RuleKey] = append(d.buckets[ev.RuleKey], ev)
	d.mu.Unlock()
}

// Run starts the background digest flush loop until ctx is canceled.
func (d *Dispatcher) Run(ctx context.Context) {
	t := time.NewTicker(d.cfg.DigestWindow)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			_ = d.Flush(context.Background())
			return
		case <-t.C:
			_ = d.Flush(ctx)
		}
	}
}

// Flush collapses each queued bucket into a single concise digest message per destination.
func (d *Dispatcher) Flush(ctx context.Context) (sentDigests int) {
	d.mu.Lock()
	if len(d.buckets) == 0 {
		d.mu.Unlock()
		return 0
	}
	snap := d.buckets
	d.buckets = make(map[string][]AlertEvent)
	d.mu.Unlock()

	for ruleKey, events := range snap {
		if len(events) == 0 {
			continue
		}
		summary := formatDigest(ruleKey, events)
		dispatched := false
		if d.cfg.TelegramBotToken != "" && d.cfg.TelegramChatID != "" {
			u := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", d.cfg.TelegramBotToken)
			if d.postJSON(ctx, u, map[string]any{"chat_id": d.cfg.TelegramChatID, "text": summary}) == nil {
				dispatched = true
			}
		}
		if d.cfg.DiscordWebhook != "" {
			if d.postJSON(ctx, d.cfg.DiscordWebhook, map[string]any{"content": summary}) == nil {
				dispatched = true
			}
		}
		if d.cfg.GenericWebhook != "" {
			if d.postJSON(ctx, d.cfg.GenericWebhook, map[string]any{
				"rule_key": ruleKey,
				"count":    len(events),
				"summary":  summary,
				"events":   events,
			}) == nil {
				dispatched = true
			}
		}
		if dispatched {
			sentDigests++
		}
	}
	return sentDigests
}

func (d *Dispatcher) postJSON(ctx context.Context, targetURL string, payload any) error {
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.httpCli.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook status %d", resp.StatusCode)
	}
	return nil
}

func formatDigest(ruleKey string, events []AlertEvent) string {
	first := events[0]
	ipSet := make(map[string]bool)
	for _, ev := range events {
		if ev.SourceIP != "" {
			ipSet[ev.SourceIP] = true
		}
	}
	ips := make([]string, 0, len(ipSet))
	for ip := range ipSet {
		ips = append(ips, ip)
		if len(ips) >= 5 {
			break
		}
	}
	if len(events) == 1 {
		return fmt.Sprintf("[%s] %s | ip=%s | %s", strings.ToUpper(first.Severity), first.Title, first.SourceIP, first.Details)
	}
	return fmt.Sprintf("[DIGEST x%d | %s] %s | sample_ips=%s | %s", len(events), ruleKey, first.Title, strings.Join(ips, ","), first.Details)
}
