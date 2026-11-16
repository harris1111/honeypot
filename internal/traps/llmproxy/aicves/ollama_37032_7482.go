package aicves

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/harris/honeypot/internal/canary"
	"github.com/harris/honeypot/internal/traps/webcve"
)

// HandleOllamaCVEs handles CVE-2024-37032 (Probllama /api/pull path traversal & rogue registry SSRF)
// and CVE-2026-7482 (Bleeding Llama /api/show Modelfile Canary disclosure).
func HandleOllamaCVEs(w http.ResponseWriter, r *http.Request, nodeID, aiGatewayURL string, pool *canary.SensorKeyPool, emit EventSink) bool {
	p := strings.TrimPrefix(r.URL.Path, "/ollama")
	switch {
	case r.Method == http.MethodPost && p == "/api/pull":
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 256*1024))
		var req struct {
			Name     string `json:"name"`
			Model    string `json:"model"`
			Insecure bool   `json:"insecure"`
		}
		_ = json.Unmarshal(raw, &req)
		target := req.Name
		if target == "" {
			target = req.Model
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{\"status\":\"pulling manifest\"}\n{\"status\":\"verifying sha256 digest\"}\n{\"status\":\"success\"}\n"))

		isTraversal := strings.Contains(target, "..") || strings.Contains(target, "://") || strings.Contains(target, "/")
		score := int32(75)
		if isTraversal {
			score = 92
		}
		if emit != nil {
			emit(buildAIEvent(nodeID, r, "CVE-2024-37032", true, score, "ollama", string(raw), "Ollama /api/pull Probllama rogue registry logged: "+target, map[string]any{
				"model":    target,
				"insecure": req.Insecure,
				"urls":     webcve.ExtractHTTPURLs(string(raw)),
			}, ""), webcve.ExtractHTTPURLs(string(raw)))
		}
		return true

	case r.Method == http.MethodPost && p == "/api/show":
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 128*1024))
		oai, cid := peekCanary(pool, "openai")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"modelfile": fmt.Sprintf("FROM qwen3.8-coder:32b\nSYSTEM \"Internal gateway proxy URL %s/v1 using API key %s\"\n", strings.TrimRight(aiGatewayURL, "/"), oai),
			"template":  "{{ .System }}\n{{ .Prompt }}",
			"details":   map[string]any{"family": "qwen3", "parameter_size": "32B"},
		})
		if emit != nil {
			emit(buildAIEvent(nodeID, r, "CVE-2026-7482", false, 80, "ollama", string(raw), "Ollama /api/show Modelfile Canary disclosure", map[string]any{
				"path": p,
			}, cid), nil)
		}
		return true

	case r.Method == http.MethodPost && (p == "/api/create" || p == "/api/push"):
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 256*1024))
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{\"status\":\"success\"}\n"))
		if emit != nil {
			emit(buildAIEvent(nodeID, r, "CVE-2024-37032", true, 82, "ollama", string(raw), "Ollama model create/push probed", map[string]any{"path": p}, ""), webcve.ExtractHTTPURLs(string(raw)))
		}
		return true
	}
	return false
}
