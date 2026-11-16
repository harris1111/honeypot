package llmproxy

import (
	"encoding/json"
	"net/http"
	"strings"
)

func (rt *Router) handleOllama(w http.ResponseWriter, r *http.Request) {
	p := strings.TrimPrefix(r.URL.Path, "/ollama")
	if r.Method == http.MethodGet && p == "/api/tags" {
		rt.recordEndpointProbe(r, "ollama:tags", "OLLAMA-MODEL-ENUM", "Returned decoy Ollama models (llama3.1:70b, qwen2.5-coder:32b)", "", "")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"models": []map[string]any{
				{"name": "llama3.1:70b", "size": 39968421000, "details": map[string]string{"family": "llama", "parameter_size": "70B"}},
				{"name": "qwen2.5-coder:32b", "size": 19851349000, "details": map[string]string{"family": "qwen2", "parameter_size": "32B"}},
			},
		})
		return
	}
	if r.Method == http.MethodGet && p == "/api/ps" {
		rt.recordEndpointProbe(r, "ollama:ps", "OLLAMA-PS-ENUM", "Returned running GPU decoy model list", "", "")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"models": []map[string]any{
				{"name": "llama3.1:70b", "model": "llama3.1:70b", "size": 39968421000, "size_vram": 24564000000},
			},
		})
		return
	}

	raw := readLimitedJSONBody(r)
	var req struct {
		Model    string          `json:"model"`
		Prompt   string          `json:"prompt"`
		Stream   *bool           `json:"stream"`
		Messages json.RawMessage `json:"messages"`
	}
	_ = json.Unmarshal(raw, &req)
	streamMode := true
	if req.Stream != nil {
		streamMode = *req.Stream
	}
	msgs := string(req.Messages)
	if msgs == "" {
		wrapped, _ := json.Marshal([]map[string]string{{"role": "user", "content": req.Prompt}})
		msgs = string(wrapped)
	}
	// Unauthenticated Ollama ALWAYS enforces $0 budget gating (empty authToken)
	rt.relayAndServe(w, r, "ollama", "", req.Model, streamMode, 512, msgs, "[]")
}
