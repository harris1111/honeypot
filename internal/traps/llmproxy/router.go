package llmproxy

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/harris/honeypot/internal/canary"
	"github.com/harris/honeypot/internal/netwrap"
	"github.com/harris/honeypot/internal/spool"
	"github.com/harris/honeypot/internal/traps/llmproxy/aicves"
	"github.com/harris/honeypot/internal/traps/llmproxy/budget"
	"github.com/harris/honeypot/internal/traps/llmproxy/chameleon"
	honeypotv1 "github.com/harris/honeypot/proto/gen/honeypot/v1"
)

// Router runs on edge Sensors, routing Family C AI infrastructure KEVs and
// delegating OpenAI / Anthropic / Ollama inference prompts over Hive's RelayLLMStream gRPC RPC.
type Router struct {
	nodeID       string
	aiGatewayURL string
	relayClient  honeypotv1.SensorControlServiceClient
	keyPool      *canary.SensorKeyPool
	sp           *spool.BoltSpool
	tarpit       *budget.TarpitLimiter
	onURLs       func(ctx context.Context, srcIP, eventUUID string, urls []string)
}

// NewRouter creates a stateless Sensor-side Chameleon LLM & AI-KEV HTTP router.
func NewRouter(
	nodeID, aiGatewayURL string,
	relayClient honeypotv1.SensorControlServiceClient,
	keyPool *canary.SensorKeyPool,
	sp *spool.BoltSpool,
	tarpit *budget.TarpitLimiter,
	onURLs func(ctx context.Context, srcIP, eventUUID string, urls []string),
) *Router {
	if tarpit == nil {
		tarpit = budget.NewTarpitLimiter(0, 0, 0, 0)
	}
	return &Router{
		nodeID:       nodeID,
		aiGatewayURL: aiGatewayURL,
		relayClient:  relayClient,
		keyPool:      keyPool,
		sp:           sp,
		tarpit:       tarpit,
		onURLs:       onURLs,
	}
}

func (rt *Router) emitAIEvent(ev *honeypotv1.TelemetryEvent, urls []string) {
	if rt.sp != nil && ev != nil {
		_ = rt.sp.EnqueueEvent(ev)
	}
	if rt.onURLs != nil && ev != nil && len(urls) > 0 {
		rt.onURLs(context.Background(), ev.GetSourceIp(), ev.GetEventUuid(), urls)
	}
}

func (rt *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 1. Family C AI Infrastructure KEV lures
	if aicves.HandleLangflow(w, r, rt.nodeID, rt.aiGatewayURL, rt.keyPool, rt.emitAIEvent) {
		return
	}
	if aicves.HandleShadowRay(w, r, rt.nodeID, rt.keyPool, rt.emitAIEvent) {
		return
	}
	if aicves.HandleOllamaCVEs(w, r, rt.nodeID, rt.aiGatewayURL, rt.keyPool, rt.emitAIEvent) {
		return
	}
	if aicves.HandleLiteLLM(w, r, rt.nodeID, rt.keyPool, rt.emitAIEvent) {
		return
	}
	if aicves.HandleOpenWebUI(w, r, rt.nodeID, rt.aiGatewayURL, rt.keyPool, rt.emitAIEvent) {
		return
	}

	p := r.URL.Path
	switch {
	case strings.HasPrefix(p, "/v1/messages"):
		rt.handleAnthropicMessages(w, r)
	case strings.HasPrefix(p, "/v1/"):
		rt.handleOpenAI(w, r)
	case p == "/" && portFromReq(r) == 11434:
		rt.recordEndpointProbe(r, "ollama:runtime", "OLLAMA-OPEN-API", "Ollama root banner served", "", "")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("Ollama is running"))
		return
	case p == "/api/version" || p == "/ollama/api/version":
		rt.recordEndpointProbe(r, "ollama:version", "OLLAMA-VERSION-PROBE", "Returned decoy Ollama version 0.5.7", "", "")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"version":"0.5.7"}`))
		return
	case strings.HasPrefix(p, "/api/tags") || strings.HasPrefix(p, "/api/ps") || strings.HasPrefix(p, "/api/chat") || strings.HasPrefix(p, "/api/generate") || strings.HasPrefix(p, "/ollama/"):
		rt.handleOllama(w, r)
	case p == "/" || strings.HasPrefix(p, "/ui"):
		rt.handleLiteLLMUI(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (rt *Router) recordEndpointProbe(r *http.Request, persona, cveTag, summary, payload, authToken string) {
	if rt.sp == nil {
		return
	}
	canaryID := ""
	score := int32(45)
	if strings.TrimSpace(authToken) != "" && rt.keyPool != nil {
		if s, ok := rt.keyPool.LookupToken(authToken); ok {
			canaryID = s.GetCanaryKeyId()
			score = 95
		}
	}
	_ = rt.sp.EnqueueEvent(&honeypotv1.TelemetryEvent{
		EventUuid:       newLLMUUID(),
		NodeId:          rt.nodeID,
		SourceIp:        clientIPFromReq(r),
		DestPort:        portFromReq(r),
		Protocol:        protoFromReq(r),
		TrapKind:        "llmproxy",
		Persona:         persona,
		CveId:           cveTag,
		Ja4:             netwrap.JA4FromContext(r.Context()),
		Ja4H:            netwrap.ComputeJA4H(r),
		HttpMethod:      r.Method,
		HttpHost:        r.Host,
		HttpPath:        r.RequestURI,
		RawPayload:      truncateStr(payload, 4096),
		ResponseSummary: summary,
		CanaryKeyId:     canaryID,
		SeverityScore:   score,
		ObservedAt:      timestamppb.Now(),
	})
}

func (rt *Router) relayAndServe(
	w http.ResponseWriter,
	r *http.Request,
	dialect, authToken, model string,
	streamReq bool,
	maxTokens int32,
	messagesJSON, toolsJSON string,
) {
	ip := clientIPFromReq(r)
	eventUUID := newLLMUUID()
	hashHex := ""
	canaryID := ""
	if strings.TrimSpace(authToken) != "" {
		sum := sha256.Sum256([]byte(strings.TrimSpace(authToken)))
		hashHex = hex.EncodeToString(sum[:])
		if rt.keyPool != nil {
			if s, ok := rt.keyPool.LookupToken(authToken); ok {
				canaryID = s.GetCanaryKeyId()
			}
		}
	}
	flags := chameleon.ClassifyProbes(messagesJSON, toolsJSON)

	// Record base TelemetryEvent immediately in spool
	if rt.sp != nil {
		score := int32(55)
		if canaryID != "" {
			score = 95
		}
		_ = rt.sp.EnqueueEvent(&honeypotv1.TelemetryEvent{
			EventUuid:         eventUUID,
			NodeId:            rt.nodeID,
			SourceIp:          ip,
			DestPort:          portFromReq(r),
			Protocol:          protoFromReq(r),
			TrapKind:          "llmproxy",
			Persona:           dialect + ":" + model,
			CveId:             "LLM-CHAMELEON-API",
			Ja4:               netwrap.JA4FromContext(r.Context()),
			Ja4H:              netwrap.ComputeJA4H(r),
			HttpMethod:        r.Method,
			HttpHost:          r.Host,
			HttpPath:          r.RequestURI,
			RawPayload:        truncateStr(messagesJSON, 32768),
			ResponseSummary:   "Chameleon LLM request flags=" + strings.Join(flags, ","),
			CanaryKeyId:       canaryID,
			SeverityScore:     score,
			ObservedAt:        timestamppb.Now(),
		})
	}

	// If Hive relay isn't connected/available, degrade directly via bounded Tarpit + offline spool
	if rt.relayClient == nil {
		rt.serveTarpitWithSpool(w, r, ip, eventUUID, canaryID, dialect, model, flags, messagesJSON, toolsJSON, streamReq)
		return
	}

	relayStream, err := rt.relayClient.RelayLLMStream(r.Context(), &honeypotv1.RelayLLMRequest{
		NodeId:             rt.nodeID,
		EventUuid:          eventUUID,
		SourceIp:           ip,
		ApiDialect:         dialect,
		RequestedModel:     model,
		CanaryKeyHashHex:   hashHex,
		Stream:             streamReq,
		RequestedMaxTokens: maxTokens,
		ProbeFlags:         flags,
		MessagesJson:       messagesJSON,
		ToolsJson:          toolsJSON,
	})
	if err != nil {
		rt.serveTarpitWithSpool(w, r, ip, eventUUID, canaryID, dialect, model, flags, messagesJSON, toolsJSON, streamReq)
		return
	}

	first, err := relayStream.Recv()
	if err != nil {
		rt.serveTarpitWithSpool(w, r, ip, eventUUID, canaryID, dialect, model, flags, messagesJSON, toolsJSON, streamReq)
		return
	}

	switch first.GetDirective() {
	case honeypotv1.RelayLLMChunk_DIRECTIVE_RATE_LIMIT_429:
		budget.WriteVendor429(w, dialect)
		return
	case honeypotv1.RelayLLMChunk_DIRECTIVE_SLOW_TARPIT:
		rt.serveTarpitWithSpool(w, r, ip, eventUUID, first.GetCanaryKeyId(), dialect, model, flags, messagesJSON, toolsJSON, streamReq)
		return
	}

	// Deliver streamed or cached chunks in authentic vendor envelope
	rt.writeRelayStreamResponse(w, dialect, model, streamReq, first, relayStream)
}

func (rt *Router) writeRelayStreamResponse(
	w http.ResponseWriter,
	dialect, model string,
	streamReq bool,
	first *honeypotv1.RelayLLMChunk,
	relayStream honeypotv1.SensorControlService_RelayLLMStreamClient,
) {
	if !streamReq {
		var full strings.Builder
		full.WriteString(first.GetDeltaText())
		tokIn, tokOut := int(first.GetTokensIn()), int(first.GetTokensOut())
		if !first.GetDone() {
			for {
				c, err := relayStream.Recv()
				if err != nil {
					break
				}
				full.WriteString(c.GetDeltaText())
				if c.GetTokensIn() > 0 {
					tokIn = int(c.GetTokensIn())
				}
				if c.GetTokensOut() > 0 {
					tokOut = int(c.GetTokensOut())
				}
				if c.GetDone() {
					break
				}
			}
		}
		if tokOut == 0 {
			tokOut = len(strings.Fields(full.String()))
		}
		switch dialect {
		case "anthropic":
			chameleon.WriteAnthropicMessageJSON(w, model, full.String(), tokIn, tokOut)
		case "ollama":
			w.Header().Set("Content-Type", "application/x-ndjson")
			chameleon.WriteOllamaNDJSONLine(w, model, full.String(), true, true)
		default:
			chameleon.WriteOpenAIChatJSON(w, model, full.String(), tokIn, tokOut)
		}
		return
	}

	flusher, _ := w.(http.Flusher)
	rc := http.NewResponseController(w)
	switch dialect {
	case "anthropic":
		chameleon.SetAnthropicHeaders(w)
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		chameleon.WriteAnthropicSSEStart(w, "msg_"+newLLMUUID()[:16], model, 16)
	case "ollama":
		w.Header().Set("Content-Type", "application/x-ndjson")
	default:
		chameleon.SetOpenAIHeaders(w)
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
	}

	writeChunk := func(c *honeypotv1.RelayLLMChunk) {
		_ = rc.SetWriteDeadline(time.Now().Add(30 * time.Second))
		switch dialect {
		case "anthropic":
			if c.GetDeltaText() != "" {
				chameleon.WriteAnthropicSSEDelta(w, c.GetDeltaText())
			}
			if c.GetDone() {
				chameleon.WriteAnthropicSSEStop(w, int(c.GetTokensOut()))
			}
		case "ollama":
			chameleon.WriteOllamaNDJSONLine(w, model, c.GetDeltaText(), c.GetDone(), true)
		default:
			if c.GetDeltaText() != "" || !c.GetDone() {
				chameleon.WriteOpenAISSEChunk(w, "chatcmpl-live01", model, c.GetDeltaText(), "")
			}
			if c.GetDone() {
				chameleon.WriteOpenAISSEChunk(w, "chatcmpl-live01", model, "", "stop")
				chameleon.WriteOpenAISSEDone(w)
			}
		}
		if flusher != nil {
			flusher.Flush()
		}
	}

	writeChunk(first)
	if first.GetDone() {
		return
	}
	for {
		c, err := relayStream.Recv()
		if err != nil {
			break
		}
		writeChunk(c)
		if c.GetDone() {
			break
		}
	}
}

func (rt *Router) serveTarpitWithSpool(
	w http.ResponseWriter,
	r *http.Request,
	ip, eventUUID, canaryID, dialect, model string,
	flags []string,
	messagesJSON, toolsJSON string,
	streamReq bool,
) {
	mode, text := rt.tarpit.ServeSlowTarpitOr429(r.Context(), w, ip, dialect, model, streamReq)
	if rt.sp != nil {
		_ = rt.sp.EnqueueLLMConversation(&honeypotv1.LlmConversation{
			ConversationUuid:  eventUUID,
			EventUuid:         eventUUID,
			NodeId:            rt.nodeID,
			CanaryKeyId:       canaryID,
			SourceIp:          ip,
			ApiDialect:        dialect,
			RequestedModel:    model,
			EmulatedPersona:   model,
			ProbeFlags:        flags,
			MessagesJson:      messagesJSON,
			ToolsJson:         toolsJSON,
			ResponseText:      text,
			DegradedMode:      mode,
			EstimatedCostUsd:  0,
			CreatedAt:         timestamppb.Now(),
		})
	}
}

func readLimitedJSONBody(r *http.Request) []byte {
	if r.Body == nil {
		return nil
	}
	b, _ := io.ReadAll(io.LimitReader(r.Body, 2*1024*1024))
	return b
}

func clientIPFromReq(r *http.Request) string {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ip == "" {
		ip = strings.Trim(r.RemoteAddr, "[]")
	}
	return ip
}

func portFromReq(r *http.Request) uint32 {
	if la, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok && la != nil {
		if _, portStr, err := net.SplitHostPort(la.String()); err == nil {
			if p, err := strconv.Atoi(portStr); err == nil && p > 0 && p <= 65535 {
				return uint32(p)
			}
		}
	}
	if _, portStr, err := net.SplitHostPort(r.Host); err == nil {
		if p, err := strconv.Atoi(portStr); err == nil && p > 0 && p <= 65535 {
			return uint32(p)
		}
	}
	if r.TLS != nil {
		return 443
	}
	return 80
}

func protoFromReq(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func truncateStr(s string, max int) string {
	if len(s) > max {
		return s[:max]
	}
	return s
}

func newLLMUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
