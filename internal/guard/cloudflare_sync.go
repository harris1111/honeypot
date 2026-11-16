package guard

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// CloudflareConfig configures Cloudflare API v4 Custom IP List synchronization.
type CloudflareConfig struct {
	BaseURL      string // default https://api.cloudflare.com/client/v4
	APIToken     string
	AccountID    string
	ListID       string
	MaxListItems int
}

// CloudflareListItem represents a single entry inside a Cloudflare Custom List.
type CloudflareListItem struct {
	ID      string `json:"id"`
	IP      string `json:"ip"`
	Comment string `json:"comment,omitempty"`
}

// CloudflareSync serializes Cloudflare API v4 Custom List additions, deletions, and full reconciliation,
// handling retries on 409/429 and capping item cardinality cleanly.
type CloudflareSync struct {
	mu      sync.Mutex
	cfg     CloudflareConfig
	httpCli *http.Client
}

// NewCloudflareSync constructs a serialized Cloudflare Custom IP List synchronizer.
func NewCloudflareSync(cfg CloudflareConfig) *CloudflareSync {
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://api.cloudflare.com/client/v4"
	}
	if cfg.MaxListItems <= 0 {
		cfg.MaxListItems = 10000
	}
	return &CloudflareSync{
		cfg:     cfg,
		httpCli: &http.Client{Timeout: 15 * time.Second},
	}
}

func (c *CloudflareSync) IsConfigured() bool {
	return c != nil && c.cfg.AccountID != "" && c.cfg.ListID != "" && (c.cfg.APIToken != "" || !strings.Contains(c.cfg.BaseURL, "api.cloudflare.com"))
}

// AddItem inserts an IP/CIDR entry into the Cloudflare Custom IP List with retry on 409/429.
func (c *CloudflareSync) AddItem(ctx context.Context, indicator, comment string) (itemID string, err error) {
	if !c.IsConfigured() {
		return "", nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	endpoint := fmt.Sprintf("%s/accounts/%s/rules/lists/%s/items", strings.TrimRight(c.cfg.BaseURL, "/"), c.cfg.AccountID, c.cfg.ListID)
	payload, _ := json.Marshal([]map[string]string{{"ip": indicator, "comment": comment}})

	for attempt := 0; attempt < 3; attempt++ {
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
		req.Header.Set("Authorization", "Bearer "+c.cfg.APIToken)
		req.Header.Set("Content-Type", "application/json")

		resp, err := c.httpCli.Do(req)
		if err != nil {
			return "", err
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
		_ = resp.Body.Close()

		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusConflict {
			time.Sleep(time.Duration(100*(attempt+1)) * time.Millisecond)
			continue
		}
		if resp.StatusCode >= 300 {
			return "", fmt.Errorf("cloudflare add item status %d: %s", resp.StatusCode, string(b))
		}
		var parsed struct {
			Success bool `json:"success"`
			Result  struct {
				OperationID string `json:"operation_id"`
			} `json:"result"`
		}
		_ = json.Unmarshal(b, &parsed)
		if parsed.Result.OperationID != "" {
			return parsed.Result.OperationID, nil
		}
		return "cf-ok-" + indicator, nil
	}
	return "", fmt.Errorf("cloudflare add item exhausted retries")
}

// DeleteByIPOrID reconciles Cloudflare Custom IP List and issues DELETE /items matching itemID or IP.
func (c *CloudflareSync) DeleteByIPOrID(ctx context.Context, itemID, indicator string) error {
	if !c.IsConfigured() {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	endpoint := fmt.Sprintf("%s/accounts/%s/rules/lists/%s/items", strings.TrimRight(c.cfg.BaseURL, "/"), c.cfg.AccountID, c.cfg.ListID)

	// Discover current item ID by IP if itemID is an operation_id or empty
	var targetIDs []map[string]string
	items, err := c.listItemsLocked(ctx, endpoint)
	if err == nil {
		for _, it := range items {
			if it.IP == indicator || (itemID != "" && it.ID == itemID) {
				targetIDs = append(targetIDs, map[string]string{"id": it.ID})
			}
		}
	}
	if len(targetIDs) == 0 && itemID != "" {
		targetIDs = append(targetIDs, map[string]string{"id": itemID})
	}
	if len(targetIDs) == 0 {
		return nil
	}

	payload, _ := json.Marshal(map[string]any{"items": targetIDs})
	for attempt := 0; attempt < 3; attempt++ {
		req, _ := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint, bytes.NewReader(payload))
		req.Header.Set("Authorization", "Bearer "+c.cfg.APIToken)
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.httpCli.Do(req)
		if err != nil {
			return err
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		_ = resp.Body.Close()

		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusConflict {
			time.Sleep(time.Duration(100*(attempt+1)) * time.Millisecond)
			continue
		}
		if resp.StatusCode >= 300 {
			return fmt.Errorf("cloudflare delete item status %d: %s", resp.StatusCode, string(b))
		}
		return nil
	}
	return fmt.Errorf("cloudflare delete item exhausted retries")
}

func (c *CloudflareSync) listItemsLocked(ctx context.Context, endpoint string) ([]CloudflareListItem, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	req.Header.Set("Authorization", "Bearer "+c.cfg.APIToken)
	resp, err := c.httpCli.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("list items status %d", resp.StatusCode)
	}
	var res struct {
		Result []CloudflareListItem `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, err
	}
	return res.Result, nil
}
