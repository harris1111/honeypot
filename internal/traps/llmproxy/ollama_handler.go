package llmproxy

import (
	"encoding/json"
	"net/http"
	"strings"
)

func (rt *Router) handleOllama(w http.ResponseWriter, r *http.Request) {
	p := strings.TrimPrefix(r.URL.Path, "/ollama")
	if r.Method == http.MethodGet && p == "/api/tags" {
		rt.recordEndpointProbe(r, "ollama:tags", "OLLAMA-MODEL-ENUM", "Returned decoy Ollama models (deepseek-v4, qwen3.8-coder:32b, llama4:70b, mistral-large-4)", "", "")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"models": []map[string]any{
				{"name": "deepseek-v4:latest", "size": 68451042000, "details": map[string]string{"family": "deepseek", "parameter_size": "236B-MoE", "quantization_level": "Q4_K_M"}},
				{"name": "qwen3.8-coder:32b", "size": 19851349000, "details": map[string]string{"family": "qwen3", "parameter_size": "32B", "quantization_level": "Q4_K_M"}},
				{"name": "qwen3.8:72b", "size": 43218904000, "details": map[string]string{"family": "qwen3", "parameter_size": "72B", "quantization_level": "Q4_K_M"}},
				{"name": "llama4:70b", "size": 40968421000, "details": map[string]string{"family": "llama4", "parameter_size": "70B", "quantization_level": "Q4_K_M"}},
				{"name": "mistral-large-4:latest", "size": 71420100000, "details": map[string]string{"family": "mistral", "parameter_size": "123B", "quantization_level": "Q4_K_M"}},
				{"name": "gemma4:27b", "size": 16480210000, "details": map[string]string{"family": "gemma4", "parameter_size": "27B", "quantization_level": "Q4_K_M"}},
			},
		})
		return
	}
	if r.Method == http.MethodGet && p == "/api/ps" {
		rt.recordEndpointProbe(r, "ollama:ps", "OLLAMA-PS-ENUM", "Returned running GPU decoy model list", "", "")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"models": []map[string]any{
				{"name": "qwen3.8-coder:32b", "model": "qwen3.8-coder:32b", "size": 19851349000, "size_vram": 19851349000},
				{"name": "llama4:70b", "model": "llama4:70b", "size": 40968421000, "size_vram": 24564000000},
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
