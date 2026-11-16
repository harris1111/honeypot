package chameleon

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

func randSuffix(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	const chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	out := make([]byte, n)
	for i, v := range b {
		out[i] = chars[int(v)%len(chars)]
	}
	return string(out)
}

// SetOpenAIHeaders sets authentic OpenAI API response headers.
func SetOpenAIHeaders(w http.ResponseWriter) {
	w.Header().Set("openai-version", "2020-10-01")
	w.Header().Set("openai-organization", "org-prod-gateway")
	w.Header().Set("x-ratelimit-limit-requests", "10000")
	w.Header().Set("x-ratelimit-remaining-requests", "9997")
	w.Header().Set("x-request-id", "req_"+randSuffix(24))
}

// WriteOpenAIChatJSON emits a full non-streaming OpenAI chat completion response.
func WriteOpenAIChatJSON(w http.ResponseWriter, model, content string, tokensIn, tokensOut int) {
	SetOpenAIHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"id":                 "chatcmpl-" + randSuffix(22),
		"object":             "chat.completion",
		"created":            time.Now().UTC().Unix(),
		"model":              model,
		"system_fingerprint": "fp_" + strings.ToLower(randSuffix(10)),
		"choices": []map[string]any{
			{
				"index":         0,
				"message":       map[string]any{"role": "assistant", "content": content},
				"finish_reason": "stop",
			},
		},
		"usage": map[string]int{
			"prompt_tokens":     tokensIn,
			"completion_tokens": tokensOut,
			"total_tokens":      tokensIn + tokensOut,
		},
	})
}

// WriteOpenAISSEChunk writes one OpenAI SSE data chunk.
func WriteOpenAISSEChunk(w http.ResponseWriter, id, model, delta, finishReason string) {
	choice := map[string]any{
		"index": 0,
		"delta": map[string]any{},
	}
	if delta != "" {
		choice["delta"] = map[string]any{"content": delta}
	}
	if finishReason != "" {
		choice["finish_reason"] = finishReason
	}
	b, _ := json.Marshal(map[string]any{
		"id":                 id,
		"object":             "chat.completion.chunk",
		"created":            time.Now().UTC().Unix(),
		"model":              model,
		"system_fingerprint": "fp_6b91c8e21a",
		"choices":            []any{choice},
	})
	_, _ = fmt.Fprintf(w, "data: %s\n\n", string(b))
}

// WriteOpenAISSEDone terminates an OpenAI SSE stream.
func WriteOpenAISSEDone(w http.ResponseWriter) {
	_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
}

// SetAnthropicHeaders sets authentic Anthropic response headers.
func SetAnthropicHeaders(w http.ResponseWriter) {
	w.Header().Set("anthropic-ratelimit-requests-limit", "4000")
	w.Header().Set("anthropic-ratelimit-requests-remaining", "3998")
	w.Header().Set("request-id", "req_"+randSuffix(24))
}

// WriteAnthropicMessageJSON emits a full non-streaming Anthropic Messages response.
func WriteAnthropicMessageJSON(w http.ResponseWriter, model, content string, tokensIn, tokensOut int) {
	SetAnthropicHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"id":          "msg_" + randSuffix(22),
		"type":        "message",
		"role":        "assistant",
		"model":       model,
		"stop_reason": "end_turn",
		"content":     []map[string]string{{"type": "text", "text": content}},
		"usage":       map[string]int{"input_tokens": tokensIn, "output_tokens": tokensOut},
	})
}

// WriteAnthropicSSEStart begins an authentic Anthropic SSE sequence.
func WriteAnthropicSSEStart(w http.ResponseWriter, msgID, model string, tokensIn int) {
	start, _ := json.Marshal(map[string]any{
		"type": "message_start",
		"message": map[string]any{
			"id": msgID, "type": "message", "role": "assistant", "model": model,
			"content": []any{}, "usage": map[string]int{"input_tokens": tokensIn, "output_tokens": 0},
		},
	})
	_, _ = fmt.Fprintf(w, "event: message_start\ndata: %s\n\n", string(start))
	_, _ = fmt.Fprint(w, "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n")
	_, _ = fmt.Fprint(w, "event: ping\ndata: {\"type\":\"ping\"}\n\n")
}

// WriteAnthropicSSEDelta emits an Anthropic text_delta SSE event.
func WriteAnthropicSSEDelta(w http.ResponseWriter, delta string) {
	ev, _ := json.Marshal(map[string]any{
		"type":  "content_block_delta",
		"index": 0,
		"delta": map[string]string{"type": "text_delta", "text": delta},
	})
	_, _ = fmt.Fprintf(w, "event: content_block_delta\ndata: %s\n\n", string(ev))
}

// WriteAnthropicSSEStop finishes an Anthropic SSE sequence cleanly.
func WriteAnthropicSSEStop(w http.ResponseWriter, tokensOut int) {
	_, _ = fmt.Fprint(w, "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n")
	md, _ := json.Marshal(map[string]any{
		"type":  "message_delta",
		"delta": map[string]any{"stop_reason": "end_turn", "stop_sequence": nil},
		"usage": map[string]int{"output_tokens": tokensOut},
	})
	_, _ = fmt.Fprintf(w, "event: message_delta\ndata: %s\n\n", string(md))
	_, _ = fmt.Fprint(w, "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
}

// WriteOllamaNDJSONLine emits one Ollama /api/chat or /api/generate NDJSON line.
func WriteOllamaNDJSONLine(w http.ResponseWriter, model, delta string, done bool, isChat bool) {
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	obj := map[string]any{
		"model":      model,
		"created_at": ts,
		"done":       done,
	}
	if isChat {
		obj["message"] = map[string]string{"role": "assistant", "content": delta}
	} else {
		obj["response"] = delta
	}
	if done {
		obj["done_reason"] = "stop"
	}
	b, _ := json.Marshal(obj)
	_, _ = fmt.Fprintf(w, "%s\n", string(b))
}
