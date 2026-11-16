package aicves

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"

	"github.com/harris/honeypot/internal/traps/webcve"
)

var (
	vllmMediaTagRe   = regexp.MustCompile(`(?i)"(?:video_url|image_url|audio_url)"`)
	internalTargetRe = regexp.MustCompile(`(?i)(?:169\.254\.169\.254|127\.0\.0\.1|localhost|10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|file://|oast\.|interact\.sh)`)
)

// CheckVLLMMultimodalExploit inspects /v1/chat/completions or /v1/completions payloads for
// CVE-2025-6242 / CVE-2026-22778 vLLM MediaConnector SSRF or oversized multimodal heap probes.
// Never dials attacker media URLs.
func CheckVLLMMultimodalExploit(w http.ResponseWriter, r *http.Request, body []byte, nodeID string, emit EventSink) bool {
	if !vllmMediaTagRe.Match(body) {
		return false
	}
	lower := strings.ToLower(string(body))
	isVideo := strings.Contains(lower, "video_url")
	isSSRF := internalTargetRe.MatchString(lower)
	isOversized := len(body) > 256*1024
	if !isVideo && !isSSRF && !isOversized {
		return false
	}

	cve := "CVE-2025-6242"
	if isVideo || isOversized {
		cve = "CVE-2026-22778"
	}
	urls := webcve.ExtractHTTPURLs(string(body))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"object":  "error",
		"message": "vLLM MediaConnector failed to process multimodal media input cleanly.",
		"type":    "InvalidMediaError",
		"code":    400,
	})

	if emit != nil {
		emit(buildAIEvent(nodeID, r, cve, true, 94, "vllm", string(body), "vLLM multimodal SSRF / MediaConnector probe captured without dialing", map[string]any{
			"urls":         urls,
			"is_ssrf":      isSSRF,
			"is_oversized": isOversized,
		}, ""), urls)
	}
	return true
}
