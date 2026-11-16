package llmproxy

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/harris/honeypot/internal/traps/llmproxy/chameleon"
)

func (rt *Router) handleAnthropicMessages(w http.ResponseWriter, r *http.Request) {
	chameleon.SetAnthropicHeaders(w)
	raw := readLimitedJSONBody(r)
	var req struct {
		Model     string          `json:"model"`
		Stream    bool            `json:"stream"`
		MaxTokens int32           `json:"max_tokens"`
		Messages  json.RawMessage `json:"messages"`
		Tools     json.RawMessage `json:"tools"`
	}
	_ = json.Unmarshal(raw, &req)
	auth := strings.TrimSpace(r.Header.Get("x-api-key"))
	if auth == "" {
		auth = strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	}
	msgs := string(req.Messages)
	if msgs == "" {
		msgs = "[]"
	}
	tools := string(req.Tools)
	if tools == "" {
		tools = "[]"
	}
	rt.relayAndServe(w, r, "anthropic", auth, req.Model, req.Stream, req.MaxTokens, msgs, tools)
}
