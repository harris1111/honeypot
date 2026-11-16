package aicves

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/harris/honeypot/internal/canary"
	"github.com/harris/honeypot/internal/traps/webcve"
)

// HandleShadowRay implements CVE-2023-48022 (Anyscale Ray unauthenticated job RCE + 8x NVIDIA H100 decoy cluster).
func HandleShadowRay(w http.ResponseWriter, r *http.Request, nodeID string, pool *canary.SensorKeyPool, emit EventSink) bool {
	p := r.URL.Path
	switch {
	case r.Method == http.MethodGet && p == "/api/version":
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"version":     "2.7.1",
			"ray_version": "2.7.1",
			"python_version": "3.10.12",
		})
		return true

	case r.Method == http.MethodGet && p == "/api/cluster_status":
		oai, _ := peekCanary(pool, "openai")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"result": true,
			"data": map[string]any{
				"clusterStatus": map[string]any{
					"autoscalingSummary": "Active Nodes: 4x p5.48xlarge (32x NVIDIA H100 80GB)",
					"gpusAvailable":      8,
					"gpuType":            "NVIDIA H100 80GB HBM3",
					"envHint":            map[string]string{"OPENAI_API_KEY": oai},
				},
			},
		})
		return true

	case r.Method == http.MethodPost && (strings.HasPrefix(p, "/api/jobs") || strings.HasPrefix(p, "/api/job_agent/jobs")):
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 512*1024))
		var req struct {
			Entrypoint string         `json:"entrypoint"`
			RuntimeEnv map[string]any `json:"runtime_env"`
		}
		_ = json.Unmarshal(raw, &req)
		var b [8]byte
		_, _ = rand.Read(b[:])
		subID := "raysubmit_" + hex.EncodeToString(b[:])

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"job_id":        subID,
			"submission_id": subID,
		})

		urls := webcve.ExtractHTTPURLs(string(raw))
		if emit != nil {
			emit(buildAIEvent(nodeID, r, "CVE-2023-48022", true, 95, "shadowray", string(raw), "ShadowRay unauthenticated Ray job submission captured", map[string]any{
				"entrypoint":  req.Entrypoint,
				"runtime_env": req.RuntimeEnv,
				"urls":        urls,
			}, ""), urls)
		}
		return true
	}
	return false
}
