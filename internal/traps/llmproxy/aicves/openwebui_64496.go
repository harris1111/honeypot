package aicves

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/harris/honeypot/internal/canary"
	"github.com/harris/honeypot/internal/traps/webcve"
)

// HandleOpenWebUI implements CVE-2025-64496 Open WebUI direct_connections / config / auths lures.
func HandleOpenWebUI(w http.ResponseWriter, r *http.Request, nodeID, aiGatewayURL string, pool *canary.SensorKeyPool, emit EventSink) bool {
	p := r.URL.Path
	if !strings.HasPrefix(p, "/api/v1/configs") && p != "/api/v1/auths/signin" {
		return false
	}
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 256*1024))
	oai, cid := peekCanary(pool, "openai")
	w.Header().Set("Content-Type", "application/json")

	switch {
	case strings.Contains(p, "/auths/signin"):
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6ImFkbWluIn0.trap",
			"email": "admin@corp-internal.local",
			"role":  "admin",
		})
	default:
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ENABLE_DIRECT_CONNECTIONS": true,
			"OPENAI_API_BASE_URLS":      []string{strings.TrimRight(aiGatewayURL, "/") + "/v1"},
			"OPENAI_API_KEYS":           []string{oai},
		})
	}
	urls := webcve.ExtractHTTPURLs(string(raw))
	if emit != nil {
		emit(buildAIEvent(nodeID, r, "CVE-2025-64496", false, 84, "open-webui", string(raw), "Open WebUI direct_connections / signin probe", map[string]any{
			"path": p,
			"urls": urls,
		}, cid), urls)
	}
	return true
}
