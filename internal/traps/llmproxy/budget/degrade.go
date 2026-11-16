package budget

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/harris/honeypot/internal/traps/llmproxy/chameleon"
)

const (
	DefaultMaxConcurrentTarpits = 128
	DefaultMaxTarpitsPerIP      = 2
	DefaultTarpitMaxDuration    = 60 * time.Second
	DefaultTarpitChunkInterval  = 2 * time.Second
)

// TarpitLimiter enforces bounded global & per-IP slow SSE tarpit concurrency on edge Sensors.
// Excess connections shed immediately with authentic 429 rate-limit envelopes.
type TarpitLimiter struct {
	mu          sync.Mutex
	globalSem   chan struct{}
	perIP       map[string]int
	maxPerIP    int
	chunkDelay  time.Duration
	maxDuration time.Duration
}

// NewTarpitLimiter creates a bounded Sensor-side slow-drip tarpit controller.
func NewTarpitLimiter(maxGlobal, maxPerIP int, chunkDelay, maxDuration time.Duration) *TarpitLimiter {
	if maxGlobal <= 0 {
		maxGlobal = DefaultMaxConcurrentTarpits
	}
	if maxPerIP <= 0 {
		maxPerIP = DefaultMaxTarpitsPerIP
	}
	if chunkDelay <= 0 {
		chunkDelay = DefaultTarpitChunkInterval
	}
	if maxDuration <= 0 {
		maxDuration = DefaultTarpitMaxDuration
	}
	return &TarpitLimiter{
		globalSem:   make(chan struct{}, maxGlobal),
		perIP:       make(map[string]int),
		maxPerIP:    maxPerIP,
		chunkDelay:  chunkDelay,
		maxDuration: maxDuration,
	}
}

func (l *TarpitLimiter) acquire(ip string) bool {
	select {
	case l.globalSem <- struct{}{}:
	default:
		return false
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.perIP[ip] >= l.maxPerIP {
		<-l.globalSem
		return false
	}
	l.perIP[ip]++
	return true
}

func (l *TarpitLimiter) release(ip string) {
	l.mu.Lock()
	if l.perIP[ip] <= 1 {
		delete(l.perIP, ip)
	} else {
		l.perIP[ip]--
	}
	l.mu.Unlock()
	<-l.globalSem
}

// ActiveCount reports active concurrent slow tarpit streams (exposed for testing & telemetry).
func (l *TarpitLimiter) ActiveCount() int {
	return len(l.globalSem)
}

var cannedTarpitTokens = []string{
	"Analyzing ", "requested ", "context ", "and ", "verifying ",
	"runtime ", "constraints ", "for ", "this ", "environment...",
}

// ServeSlowTarpitOr429 streams $0 canned tokens slowly (using ResponseController.SetWriteDeadline per chunk)
// when within semaphore bounds, or immediately sheds excess load with HTTP 429.
// Returns the applied degraded_mode ("slow_tarpit" or "rate_limit_429").
func (l *TarpitLimiter) ServeSlowTarpitOr429(ctx context.Context, w http.ResponseWriter, ip, dialect, model string, stream bool) (mode string, fullText string) {
	if !l.acquire(ip) {
		WriteVendor429(w, dialect)
		return "rate_limit_429", ""
	}
	defer l.release(ip)

	if !stream {
		// Brief bounded tarpit delay for non-streaming calls before canned completion
		rc := http.NewResponseController(w)
		_ = rc.SetWriteDeadline(time.Now().Add(l.chunkDelay + 5*time.Second))
		select {
		case <-ctx.Done():
			return "slow_tarpit", ""
		case <-time.After(l.chunkDelay):
		}
		reply := "Checking environment configuration... Please ensure valid workspace permissions and retry if needed."
		switch dialect {
		case "anthropic":
			chameleon.WriteAnthropicMessageJSON(w, model, reply, 24, 18)
		case "ollama":
			w.Header().Set("Content-Type", "application/x-ndjson")
			chameleon.WriteOllamaNDJSONLine(w, model, reply, true, true)
		default:
			chameleon.WriteOpenAIChatJSON(w, model, reply, 24, 18)
		}
		return "slow_tarpit", reply
	}

	rc := http.NewResponseController(w)
	flusher, _ := w.(http.Flusher)

	switch dialect {
	case "anthropic":
		chameleon.SetAnthropicHeaders(w)
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		chameleon.WriteAnthropicSSEStart(w, "msg_tarpit001", model, 16)
	case "ollama":
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.WriteHeader(http.StatusOK)
	default:
		chameleon.SetOpenAIHeaders(w)
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
	}
	if flusher != nil {
		flusher.Flush()
	}

	deadline := time.Now().Add(l.maxDuration)
	var assembled string
	for i, tok := range cannedTarpitTokens {
		if time.Now().After(deadline) {
			break
		}
		// Extend write deadline per chunk while preserving default HTTP server WriteTimeout for normal routes.
		_ = rc.SetWriteDeadline(time.Now().Add(l.chunkDelay + 5*time.Second))
		select {
		case <-ctx.Done():
			return "slow_tarpit", assembled
		case <-time.After(l.chunkDelay):
		}
		assembled += tok
		switch dialect {
		case "anthropic":
			chameleon.WriteAnthropicSSEDelta(w, tok)
		case "ollama":
			chameleon.WriteOllamaNDJSONLine(w, model, tok, false, true)
		default:
			chameleon.WriteOpenAISSEChunk(w, "chatcmpl-tarpit001", model, tok, "")
		}
		if flusher != nil {
			flusher.Flush()
		}
		_ = i
	}

	switch dialect {
	case "anthropic":
		chameleon.WriteAnthropicSSEStop(w, len(cannedTarpitTokens))
	case "ollama":
		chameleon.WriteOllamaNDJSONLine(w, model, "", true, true)
	default:
		chameleon.WriteOpenAISSEChunk(w, "chatcmpl-tarpit001", model, "", "stop")
		chameleon.WriteOpenAISSEDone(w)
	}
	if flusher != nil {
		flusher.Flush()
	}
	return "slow_tarpit", assembled
}

// WriteVendor429 writes an authentic HTTP 429 rate-limit error matching OpenAI/Anthropic/Ollama formats.
func WriteVendor429(w http.ResponseWriter, dialect string) {
	w.Header().Set("Retry-After", "60")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusTooManyRequests)
	switch dialect {
	case "anthropic":
		_ = json.NewEncoder(w).Encode(map[string]any{
			"type": "error",
			"error": map[string]string{
				"type":    "rate_limit_error",
				"message": "Number of request tokens has exceeded your per-minute rate limit.",
			},
		})
	default:
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{
				"message": "Rate limit reached for requests. Please try again in 60s.",
				"type":    "tokens",
				"param":   nil,
				"code":    "rate_limit_exceeded",
			},
		})
	}
}
