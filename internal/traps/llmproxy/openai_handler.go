package llmproxy

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/harris/honeypot/internal/traps/llmproxy/aicves"
	"github.com/harris/honeypot/internal/traps/llmproxy/chameleon"
)

func (rt *Router) handleOpenAI(w http.ResponseWriter, r *http.Request) {
	chameleon.SetOpenAIHeaders(w)
	p := r.URL.Path

	switch {
	case r.Method == http.MethodGet && p == "/v1/models":
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"object": "list",
			"data": []map[string]any{
				{"id": "gpt-4o", "object": "model", "owned_by": "openai"},
				{"id": "gpt-4o-2024-11-20", "object": "model", "owned_by": "openai"},
				{"id": "o3-mini", "object": "model", "owned_by": "openai"},
				{"id": "claude-3-7-sonnet-20250219", "object": "model", "owned_by": "anthropic"},
			},
		})
		return

	case r.Method == http.MethodGet && p == "/v1/dashboard/billing/credit_grants":
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"object":          "credit_summary",
			"total_granted":   2500.00,
			"total_used":      412.85,
			"total_available": 2087.15,
		})
		return

	case r.Method == http.MethodPost && p == "/v1/embeddings":
		_ = readLimitedJSONBody(r)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"object": "list",
			"model":  "text-embedding-3-large",
			"data":   []map[string]any{{"object": "embedding", "index": 0, "embedding": []float64{0.012, -0.044, 0.089, 0.003}}},
			"usage":  map[string]int{"prompt_tokens": 8, "total_tokens": 8},
		})
		return
	}

	raw := readLimitedJSONBody(r)
	if aicves.CheckVLLMMultimodalExploit(w, r, raw, rt.nodeID, rt.emitAIEvent) {
		return
	}

	var req struct {
		Model     string          `json:"model"`
		Stream    bool            `json:"stream"`
		MaxTokens int32           `json:"max_tokens"`
		Messages  json.RawMessage `json:"messages"`
		Tools     json.RawMessage `json:"tools"`
	}
	_ = json.Unmarshal(raw, &req)
	auth := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if auth == "" {
		auth = strings.TrimSpace(r.Header.Get("x-api-key"))
	}
	msgs := string(req.Messages)
	if msgs == "" {
		msgs = "[]"
	}
	tools := string(req.Tools)
	if tools == "" {
		tools = "[]"
	}
	rt.relayAndServe(w, r, "openai", auth, req.Model, req.Stream, req.MaxTokens, msgs, tools)
}
