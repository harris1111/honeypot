package aicves

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/harris/honeypot/internal/canary"
	"github.com/harris/honeypot/internal/traps/webcve"
)

// HandleLiteLLM handles CVE-2026-47101 / CVE-2026-47102 / CVE-2024-4264 LiteLLM admin & privesc lures.
// /key/generate dispenses a Sensor-pooled Canary Key (marked paid_upstream_eligible=false on Hive)
// so attackers immediately loop into the Chameleon LLM Gateway at $0 upstream risk.
func HandleLiteLLM(w http.ResponseWriter, r *http.Request, nodeID string, pool *canary.SensorKeyPool, emit EventSink) bool {
	p := r.URL.Path
	switch {
	case r.Method == http.MethodPost && p == "/key/generate":
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 128*1024))
		keyVal := "sk-proj-pool0000000000000000000000000000000000"
		cid := ""
		if pool != nil {
			if seed, ok := pool.DispensePoolKey("llm_pool"); ok {
				keyVal = seed.GetKeyPlaintext()
				cid = seed.GetCanaryKeyId()
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"key":        keyVal,
			"token":      keyVal,
			"expires":    nil,
			"max_budget": 100.0,
			"models":     []string{"gpt-4o", "claude-3-7-sonnet-20250219"},
		})
		if emit != nil {
			emit(buildAIEvent(nodeID, r, "CVE-2026-47101", false, 88, "litellm", string(raw), "LiteLLM /key/generate dispensed pooled Canary Key", map[string]any{
				"dispensed_canary_id": cid,
			}, cid), nil)
		}
		return true

	case r.Method == http.MethodPost && (p == "/user/new" || p == "/model/new" || p == "/config/update"):
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 256*1024))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "updated", "path": strings.TrimPrefix(p, "/")})
		urls := webcve.ExtractHTTPURLs(string(raw))
		if emit != nil {
			emit(buildAIEvent(nodeID, r, "CVE-2026-47102", false, 86, "litellm", string(raw), "LiteLLM config/model admin exploit probe captured", map[string]any{
				"path": p,
				"urls": urls,
			}, ""), urls)
		}
		return true
	}
	return false
}
