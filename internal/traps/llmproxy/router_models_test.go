package llmproxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/harris/honeypot/internal/traps/llmproxy/chameleon"
)

func TestDecoyModelEndpointsAndPersonaDefaults2026(t *testing.T) {
	rt := NewRouter("test-node", "http://127.0.0.1:4000", nil, nil, nil, nil, nil)

	// 1. OpenAI /v1/models advertises frontier lineup
	recOAI := httptest.NewRecorder()
	rt.ServeHTTP(recOAI, httptest.NewRequest(http.MethodGet, "/v1/models", nil))
	if recOAI.Code != http.StatusOK {
		t.Fatalf("expected 200 on /v1/models, got %d", recOAI.Code)
	}
	var modelsResp struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recOAI.Body.Bytes(), &modelsResp); err != nil {
		t.Fatalf("decode /v1/models: %v", err)
	}
	seenOAI := map[string]bool{}
	for _, m := range modelsResp.Data {
		seenOAI[m.ID] = true
	}
	for _, want := range []string{"gpt-6-astra", "claude-opus-5-5", "gemini-4-argon", "deepseek-v4"} {
		if !seenOAI[want] {
			t.Fatalf("expected frontier decoy model %q in /v1/models, got %+v", want, modelsResp.Data)
		}
	}

	// 2. Ollama /api/tags advertises flagship open-weight lineup
	recOllama := httptest.NewRecorder()
	rt.ServeHTTP(recOllama, httptest.NewRequest(http.MethodGet, "/api/tags", nil))
	if recOllama.Code != http.StatusOK {
		t.Fatalf("expected 200 on /api/tags, got %d", recOllama.Code)
	}
	bodyOllama := recOllama.Body.String()
	for _, want := range []string{"deepseek-v4:latest", "qwen3.8-coder:32b", "llama4:70b", "mistral-large-4:latest"} {
		if !strings.Contains(bodyOllama, want) {
			t.Fatalf("expected open-weight decoy model %q in /api/tags, got %s", want, bodyOllama)
		}
	}

	// 3. Empty-model ResolvePersona uses late-2026 defaults while preserving caller model names
	if p := chameleon.ResolvePersona(nil, "openai", ""); p.EmulatedModel != "gpt-6-astra" {
		t.Fatalf("expected default openai model gpt-6-astra, got %q", p.EmulatedModel)
	}
	if p := chameleon.ResolvePersona(nil, "anthropic", ""); p.EmulatedModel != "claude-opus-5-5" {
		t.Fatalf("expected default anthropic model claude-opus-5-5, got %q", p.EmulatedModel)
	}
	if p := chameleon.ResolvePersona(nil, "ollama", ""); p.EmulatedModel != "qwen3.8-coder:32b" {
		t.Fatalf("expected default ollama model qwen3.8-coder:32b, got %q", p.EmulatedModel)
	}
}
