package budget

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// CachedResponse holds a prompt-normalized $0 cached LLM response.
type CachedResponse struct {
	Text      string `json:"text"`
	TokensIn  int32  `json:"tokens_in"`
	TokensOut int32  `json:"tokens_out"`
}

// PromptCache caches normalized repetitive probes in Redis so scanners cannot burn paid upstream credits.
type PromptCache struct {
	rd  *redis.Client
	ttl time.Duration
}

// NewPromptCache creates a Redis-backed prompt cache (default 24h TTL).
func NewPromptCache(rd *redis.Client, ttl time.Duration) *PromptCache {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	return &PromptCache{rd: rd, ttl: ttl}
}

func cacheKey(dialect, personaModel, messagesJSON string) string {
	norm := strings.ToLower(strings.TrimSpace(dialect + "|" + personaModel + "|" + messagesJSON))
	sum := sha256.Sum256([]byte(norm))
	return "llm:promptcache:" + hex.EncodeToString(sum[:])
}

// Get retrieves a cached $0 response if present.
func (c *PromptCache) Get(ctx context.Context, dialect, personaModel, messagesJSON string) (CachedResponse, bool) {
	if c == nil || c.rd == nil {
		return CachedResponse{}, false
	}
	raw, err := c.rd.Get(ctx, cacheKey(dialect, personaModel, messagesJSON)).Bytes()
	if err != nil {
		return CachedResponse{}, false
	}
	var out CachedResponse
	if json.Unmarshal(raw, &out) != nil || out.Text == "" {
		return CachedResponse{}, false
	}
	return out, true
}

// Set saves an upstream response in the prompt cache.
func (c *PromptCache) Set(ctx context.Context, dialect, personaModel, messagesJSON string, resp CachedResponse) {
	if c == nil || c.rd == nil || resp.Text == "" {
		return
	}
	b, err := json.Marshal(resp)
	if err != nil {
		return
	}
	_ = c.rd.Set(ctx, cacheKey(dialect, personaModel, messagesJSON), b, c.ttl).Err()
}
