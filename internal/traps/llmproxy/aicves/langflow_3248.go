package aicves

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/harris/honeypot/internal/canary"
	"github.com/harris/honeypot/internal/netwrap"
	"github.com/harris/honeypot/internal/traps/webcve"
	honeypotv1 "github.com/harris/honeypot/proto/gen/honeypot/v1"
)

// EventSink emits captured AI-KEV TelemetryEvents + extracted dropper URLs.
type EventSink func(ev *honeypotv1.TelemetryEvent, extractedURLs []string)

var pythonShellCallRe = regexp.MustCompile(`(?is)(?:os\.system|subprocess\.(?:run|Popen|check_output|call)|eval|exec)\s*\(\s*['"]([^'"]+)['"]`)

// HandleLangflow handles CVE-2025-3248 / CVE-2026-33017 (/api/v1/validate/code) and CVE-2026-5027 (/api/v1/files/).
func HandleLangflow(w http.ResponseWriter, r *http.Request, nodeID, aiGatewayURL string, pool *canary.SensorKeyPool, emit EventSink) bool {
	p := r.URL.Path
	if p != "/api/v1/validate/code" && !strings.HasPrefix(p, "/api/v1/files/") {
		return false
	}

	raw, _ := io.ReadAll(io.LimitReader(r.Body, 512*1024))
	w.Header().Set("Content-Type", "application/json")

	if strings.HasPrefix(p, "/api/v1/files/") {
		oai, _ := peekCanary(pool, "openai")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "NODE_ENV=production\nOPENAI_BASE_URL=%s/v1\nOPENAI_API_KEY=%s\n", strings.TrimRight(aiGatewayURL, "/"), oai)
		if emit != nil {
			emit(buildAIEvent(nodeID, r, "CVE-2026-5027", true, 92, "langflow", string(raw), "Langflow files traversal probed", map[string]any{"path": p}, ""), nil)
		}
		return true
	}

	var req struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(raw, &req)
	codeText := req.Code
	if codeText == "" {
		codeText = string(raw)
	}

	var cmds []string
	var simOut strings.Builder
	for _, m := range pythonShellCallRe.FindAllStringSubmatch(codeText, 8) {
		cmds = append(cmds, m[1])
		simOut.WriteString(webcve.SimulateShellCommand(m[1], false))
	}
	urls := webcve.ExtractHTTPURLs(codeText)
	outMsg := simOut.String()
	if outMsg == "" && len(cmds) > 0 {
		outMsg = "uid=1000(langflow) gid=1000(langflow) groups=1000(langflow)"
	}

	w.WriteHeader(http.StatusOK)
	var fnErrs []string
	if outMsg != "" {
		fnErrs = []string{strings.TrimSpace(outMsg)}
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"imports":  map[string]any{"errors": []string{}},
		"function": map[string]any{"errors": fnErrs},
	})

	if emit != nil {
		cve := "CVE-2025-3248"
		if strings.Contains(codeText, "CVE-2026-33017") || len(cmds) > 0 {
			cve = "CVE-2025-3248"
		}
		emit(buildAIEvent(nodeID, r, cve, true, 96, "ai-infra-gateway", codeText, "Langflow code validation Python RCE captured", map[string]any{
			"commands": cmds,
			"urls":     urls,
		}, ""), urls)
	}
	return true
}

func peekCanary(pool *canary.SensorKeyPool, style string) (key, id string) {
	if pool == nil {
		return "sk-proj-aikev00000000000000000000000000000000", ""
	}
	if s, ok := pool.PeekBySource("", style); ok {
		return s.GetKeyPlaintext(), s.GetCanaryKeyId()
	}
	return "sk-proj-aikev00000000000000000000000000000000", ""
}

func buildAIEvent(nodeID string, r *http.Request, cveID string, kev bool, score int32, persona, rawPayload, summary string, iocs map[string]any, canaryID string) *honeypotv1.TelemetryEvent {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ip == "" {
		ip = strings.Trim(r.RemoteAddr, "[]")
	}
	if len(rawPayload) > 32768 {
		rawPayload = rawPayload[:32768]
	}
	iocBytes, _ := json.Marshal(iocs)
	port := uint32(80)
	proto := "http"
	if r.TLS != nil {
		port = 443
		proto = "https"
	}
	return &honeypotv1.TelemetryEvent{
		EventUuid:         randomAIUUID(),
		NodeId:            nodeID,
		SourceIp:          ip,
		DestPort:          port,
		Protocol:          proto,
		TrapKind:          "llmproxy",
		Persona:           persona,
		CveId:             cveID,
		IsKev:             kev,
		Ja4:               netwrap.JA4FromContext(r.Context()),
		Ja4H:              netwrap.ComputeJA4H(r),
		HttpMethod:        r.Method,
		HttpHost:          r.Host,
		HttpPath:          r.RequestURI,
		RawPayload:        rawPayload,
		ResponseSummary:   summary,
		ExtractedIocsJson: string(iocBytes),
		CanaryKeyId:       canaryID,
		SeverityScore:     score,
		ObservedAt:        timestamppb.Now(),
	}
}

func randomAIUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
