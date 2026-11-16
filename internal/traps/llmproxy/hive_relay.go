package llmproxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/harris/honeypot/internal/store"
	"github.com/harris/honeypot/internal/traps/llmproxy/budget"
	"github.com/harris/honeypot/internal/traps/llmproxy/chameleon"
	honeypotv1 "github.com/harris/honeypot/proto/gen/honeypot/v1"
)

// UpstreamConfig configures the single cheap OpenAI-compatible model endpoint used exclusively by Hive.
type UpstreamConfig struct {
	BaseURL                  string // e.g. https://api.deepseek.com/v1
	APIKey                   string // strictly on Hive, NEVER sent to edge Sensors
	Model                    string // e.g. deepseek-v4 or gpt-6.1-terra
	PricePer1KUSD            float64
	AllowUnauthenticatedChat bool
}

// HiveRelay implements Hive's RelayLLMStream server-streaming RPC with persona defense,
// split-token stream scrubbing, Redis caching, and atomic USD budget enforcement.
type HiveRelay struct {
	mu       sync.RWMutex
	pg       *store.Postgres
	cache    *budget.PromptCache
	breaker  *budget.CircuitBreaker
	upstream UpstreamConfig
	httpCli  *http.Client
}

// GetConfig returns a snapshot of the active runtime upstream LLM configuration.
func (h *HiveRelay) GetConfig() UpstreamConfig {
	if h == nil {
		return UpstreamConfig{}
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.upstream
}

// UpdateConfig hot-reloads the upstream LLM URL/key/model and daily budget cap cleanly.
func (h *HiveRelay) UpdateConfig(cfg UpstreamConfig, maxDailyUSD float64) {
	if h == nil {
		return
	}
	if cfg.PricePer1KUSD <= 0 {
		cfg.PricePer1KUSD = 0.0005
	}
	h.mu.Lock()
	h.upstream = cfg
	h.mu.Unlock()
	if h.breaker != nil {
		h.breaker.SetMaxDailyUSD(maxDailyUSD)
	}
}

// NewHiveRelay constructs a Hive-side Chameleon LLM relay engine.
func NewHiveRelay(pg *store.Postgres, rd *store.Redis, upstream UpstreamConfig, cfg budget.BudgetConfig) *HiveRelay {
	if upstream.PricePer1KUSD <= 0 {
		upstream.PricePer1KUSD = 0.0005
	}
	var cache *budget.PromptCache
	var breaker *budget.CircuitBreaker
	if rd != nil && rd.Client != nil {
		cache = budget.NewPromptCache(rd.Client, 24*time.Hour)
		breaker = budget.NewCircuitBreaker(rd.Client, cfg)
	}
	return &HiveRelay{
		pg:       pg,
		cache:    cache,
		breaker:  breaker,
		upstream: upstream,
		httpCli:  &http.Client{Timeout: 30 * time.Second},
	}
}

// Breaker returns the active Redis Lua circuit breaker for budget telemetry inspection.
func (h *HiveRelay) Breaker() *budget.CircuitBreaker {
	if h == nil {
		return nil
	}
	return h.breaker
}

// HandleRelayStream serves SensorControlService.RelayLLMStream.
func (h *HiveRelay) HandleRelayStream(req *honeypotv1.RelayLLMRequest, stream honeypotv1.SensorControlService_RelayLLMStreamServer) error {
	ctx := stream.Context()

	var (
		canaryRec store.CanaryAuthRecord
		hasCanary bool
	)
	if hashBytes, err := hex.DecodeString(strings.TrimSpace(req.GetCanaryKeyHashHex())); err == nil && len(hashBytes) == 32 && h.pg != nil {
		canaryRec, hasCanary, _ = h.pg.VerifyCanaryHashAndTouch(ctx, hashBytes)
	}

	var personas []store.LLMPersonaRow
	if h.pg != nil {
		personas, _ = h.pg.ListLLMPersonas(ctx)
	}
	persona := chameleon.ResolvePersona(personas, req.GetApiDialect(), req.GetRequestedModel())

	// Layer 1 ($0): Prompt-normalized Redis Cache check
	if h.cache != nil {
		if hit, ok := h.cache.Get(ctx, req.GetApiDialect(), persona.EmulatedModel, req.GetMessagesJson()); ok {
			_ = stream.Send(&honeypotv1.RelayLLMChunk{
				Directive:       honeypotv1.RelayLLMChunk_DIRECTIVE_CACHED,
				EmulatedPersona: persona.EmulatedModel,
				DeltaText:       hit.Text,
				Done:            true,
				FinishReason:    "stop",
				TokensIn:        hit.TokensIn,
				TokensOut:       hit.TokensOut,
				CanaryKeyId:     canaryRec.ID,
			})
			h.saveConversation(ctx, req, canaryRec.ID, persona.EmulatedModel, hit.Text, "cached", hit.TokensIn, hit.TokensOut, 0)
			return nil
		}
	}

	// Gate paid upstream spend strictly to verified seeded Canary keys OR explicit AllowUnauthenticatedChat opt-in
	upCfg := h.GetConfig()
	paidAllowed := false
	degradeMode := "slow_tarpit"
	var denialReason string
	budgetKeyID := canaryRec.ID
	budgetSource := canaryRec.PlacementSource
	eligible := hasCanary && canaryRec.PaidUpstreamEligible
	if !hasCanary && upCfg.AllowUnauthenticatedChat && strings.TrimSpace(upCfg.BaseURL) != "" && strings.TrimSpace(upCfg.APIKey) != "" {
		eligible = true
		budgetKeyID = "unauth-ip:" + req.GetSourceIp()
		budgetSource = "unauth_optin"
	}
	if h.breaker != nil {
		dec, err := h.breaker.TryAcquire(ctx, budgetKeyID, budgetSource, eligible, req.GetSourceIp())
		if err == nil && dec.AllowedPaid {
			paidAllowed = true
			degradeMode = "none"
		} else if err == nil {
			denialReason = dec.DenialReason
		}
	}

	if !paidAllowed || strings.TrimSpace(upCfg.BaseURL) == "" || strings.TrimSpace(upCfg.APIKey) == "" {
		// Unauthenticated Ollama or /key/generate pool keys stay $0 with synthetic template or Slow SSE Tarpit
		if denialReason == "canary_not_eligible" || (!paidAllowed && strings.TrimSpace(upCfg.BaseURL) == "") {
			synthetic := buildZeroCostDeceptionReply(persona, req.GetMessagesJson())
			_ = stream.Send(&honeypotv1.RelayLLMChunk{
				Directive:       honeypotv1.RelayLLMChunk_DIRECTIVE_CACHED,
				EmulatedPersona: persona.EmulatedModel,
				DeltaText:       synthetic,
				Done:            true,
				FinishReason:    "stop",
				TokensIn:        24,
				TokensOut:       int32(len(strings.Fields(synthetic))),
				CanaryKeyId:     canaryRec.ID,
			})
			h.saveConversation(ctx, req, canaryRec.ID, persona.EmulatedModel, synthetic, "cached", 24, int32(len(strings.Fields(synthetic))), 0)
			return nil
		}
		// Budget or RPM exceeded -> direct Sensor to activate bounded Slow SSE Tarpit
		_ = stream.Send(&honeypotv1.RelayLLMChunk{
			Directive:       honeypotv1.RelayLLMChunk_DIRECTIVE_SLOW_TARPIT,
			EmulatedPersona: persona.EmulatedModel,
			Done:            true,
			FinishReason:    denialReason,
			CanaryKeyId:     canaryRec.ID,
		})
		h.saveConversation(ctx, req, canaryRec.ID, persona.EmulatedModel, "[degraded:"+denialReason+"]", degradeMode, 0, 0, 0)
		return nil
	}

	// Forward over cheap upstream OpenAI-compatible endpoint with persona system prompt + stream sanitizer
	maxTok := chameleon.ClampMaxTokens(int(req.GetRequestedMaxTokens()), persona.MaxTokensCap)
	fullResp, tokIn, tokOut, err := h.callAndSanitizeUpstream(ctx, upCfg, persona, maxTok, req.GetMessagesJson(), canaryRec.ID, stream)
	if err != nil {
		// Seamless failover to $0 tarpit so attacker never sees backend proxy errors
		_ = stream.Send(&honeypotv1.RelayLLMChunk{
			Directive:       honeypotv1.RelayLLMChunk_DIRECTIVE_SLOW_TARPIT,
			EmulatedPersona: persona.EmulatedModel,
			Done:            true,
			FinishReason:    "upstream_fallback",
			CanaryKeyId:     canaryRec.ID,
		})
		h.saveConversation(ctx, req, canaryRec.ID, persona.EmulatedModel, "[upstream_fallback]", "slow_tarpit", 0, 0, 0)
		return nil
	}

	costUSD := float64(tokIn+tokOut) / 1000.0 * upCfg.PricePer1KUSD
	postCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if h.breaker != nil {
		h.breaker.ReconcileActualCost(postCtx, time.Now().UTC().Format("2006-01-02"), costUSD)
	}
	if h.cache != nil && fullResp != "" {
		h.cache.Set(postCtx, req.GetApiDialect(), persona.EmulatedModel, req.GetMessagesJson(), budget.CachedResponse{
			Text:      fullResp,
			TokensIn:  tokIn,
			TokensOut: tokOut,
		})
	}
	h.saveConversation(postCtx, req, canaryRec.ID, persona.EmulatedModel, fullResp, "none", tokIn, tokOut, costUSD)
	return nil
}

// TestConnection tests either the configured upstream OpenAI-compatible provider or built-in $0 responder.
func (h *HiveRelay) TestConnection(ctx context.Context, prompt string) (mode, model, reply string, latencyMs int64, err error) {
	if strings.TrimSpace(prompt) == "" {
		prompt = "Say OK and report what internal service you provide."
	}
	start := time.Now()
	upCfg := h.GetConfig()
	if strings.TrimSpace(upCfg.BaseURL) == "" || strings.TrimSpace(upCfg.APIKey) == "" {
		p := chameleon.ResolvePersona(nil, "openai", "gpt-6-astra")
		wrapped, _ := json.Marshal([]map[string]string{{"role": "user", "content": prompt}})
		return "builtin_free", "chameleon-zero-cost", buildZeroCostDeceptionReply(p, string(wrapped)), time.Since(start).Milliseconds(), nil
	}

	modelName := strings.TrimSpace(upCfg.Model)
	if modelName == "" {
		if strings.Contains(strings.ToLower(upCfg.BaseURL), "openai.com") {
			modelName = "gpt-6.1-terra"
		} else {
			modelName = "deepseek-v4"
		}
	}
	payload, _ := json.Marshal(map[string]any{
		"model": modelName,
		"messages": []map[string]string{
			{"role": "system", "content": "Reply in one short sentence confirming this internal AI gateway node is online."},
			{"role": "user", "content": prompt},
		},
		"max_tokens": 96,
		"stream":     false,
	})
	tCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(tCtx, http.MethodPost, strings.TrimRight(upCfg.BaseURL, "/")+"/chat/completions", bytes.NewReader(payload))
	if err != nil {
		return "live_upstream", modelName, "", time.Since(start).Milliseconds(), err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+upCfg.APIKey)

	resp, err := h.httpCli.Do(req)
	if err != nil {
		return "live_upstream", modelName, "", time.Since(start).Milliseconds(), err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if resp.StatusCode >= 400 {
		return "live_upstream", modelName, "", time.Since(start).Milliseconds(), fmt.Errorf("upstream status %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var parsed struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil || len(parsed.Choices) == 0 {
		return "live_upstream", modelName, "", time.Since(start).Milliseconds(), fmt.Errorf("unexpected response from upstream")
	}
	return "live_upstream", modelName, strings.TrimSpace(parsed.Choices[0].Message.Content), time.Since(start).Milliseconds(), nil
}

func (h *HiveRelay) callAndSanitizeUpstream(
	ctx context.Context,
	upCfg UpstreamConfig,
	persona chameleon.ResolvedPersona,
	maxTokens int,
	messagesJSON, canaryID string,
	stream honeypotv1.SensorControlService_RelayLLMStreamServer,
) (fullText string, tokIn, tokOut int32, err error) {
	var userMsgs []map[string]any
	_ = json.Unmarshal([]byte(messagesJSON), &userMsgs)
	combined := make([]map[string]any, 0, len(userMsgs)+1)
	combined = append(combined, map[string]any{"role": "system", "content": persona.SystemPrompt})
	for _, m := range userMsgs {
		// Strip attacker-provided system & developer role overrides that probe underlying model weights
		if r, _ := m["role"].(string); strings.EqualFold(r, "system") || strings.EqualFold(r, "developer") {
			continue
		}
		combined = append(combined, m)
	}

	modelName := strings.TrimSpace(upCfg.Model)
	if modelName == "" {
		if strings.Contains(strings.ToLower(upCfg.BaseURL), "openai.com") {
			modelName = "gpt-6.1-terra"
		} else {
			modelName = "deepseek-v4"
		}
	}
	payload, _ := json.Marshal(map[string]any{
		"model":      modelName,
		"messages":   combined,
		"max_tokens": maxTokens,
		"stream":     true,
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(upCfg.BaseURL, "/")+"/chat/completions", bytes.NewReader(payload))
	if err != nil {
		return "", 0, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+upCfg.APIKey)

	resp, err := h.httpCli.Do(req)
	if err != nil {
		return "", 0, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", 0, 0, fmt.Errorf("upstream status %d: %s", resp.StatusCode, string(b))
	}

	sanitizer := chameleon.NewStreamSanitizer(persona)
	var outBuf strings.Builder

	// Handle either SSE stream or direct single JSON response from mock/compatible upstreams
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if !strings.Contains(ct, "text/event-stream") {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
		var parsed struct {
			Choices []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			} `json:"choices"`
			Usage struct {
				PromptTokens     int32 `json:"prompt_tokens"`
				CompletionTokens int32 `json:"completion_tokens"`
			} `json:"usage"`
		}
		if err := json.Unmarshal(raw, &parsed); err != nil || len(parsed.Choices) == 0 {
			return "", 0, 0, fmt.Errorf("decode non-stream upstream: %w", err)
		}
		clean := sanitizer.Push(parsed.Choices[0].Message.Content) + sanitizer.Flush()
		_ = stream.Send(&honeypotv1.RelayLLMChunk{
			Directive:       honeypotv1.RelayLLMChunk_DIRECTIVE_STREAM,
			EmulatedPersona: persona.EmulatedModel,
			DeltaText:       clean,
			Done:            true,
			FinishReason:    "stop",
			TokensIn:        parsed.Usage.PromptTokens,
			TokensOut:       parsed.Usage.CompletionTokens,
			CanaryKeyId:     canaryID,
		})
		return clean, parsed.Usage.PromptTokens, parsed.Usage.CompletionTokens, nil
	}

	scanner := bufio.NewScanner(io.LimitReader(resp.Body, 4*1024*1024))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if data == "[DONE]" {
			break
		}
		var chunk struct {
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if json.Unmarshal([]byte(data), &chunk) != nil || len(chunk.Choices) == 0 {
			continue
		}
		tokOut++
		if emitted := sanitizer.Push(chunk.Choices[0].Delta.Content); emitted != "" {
			outBuf.WriteString(emitted)
			_ = stream.Send(&honeypotv1.RelayLLMChunk{
				Directive:       honeypotv1.RelayLLMChunk_DIRECTIVE_STREAM,
				EmulatedPersona: persona.EmulatedModel,
				DeltaText:       emitted,
				CanaryKeyId:     canaryID,
			})
		}
	}

	tail := sanitizer.Flush()
	outBuf.WriteString(tail)
	tokIn = int32(len(messagesJSON) / 4)
	_ = stream.Send(&honeypotv1.RelayLLMChunk{
		Directive:       honeypotv1.RelayLLMChunk_DIRECTIVE_STREAM,
		EmulatedPersona: persona.EmulatedModel,
		DeltaText:       tail,
		Done:            true,
		FinishReason:    "stop",
		TokensIn:        tokIn,
		TokensOut:       tokOut,
		CanaryKeyId:     canaryID,
	})
	return outBuf.String(), tokIn, tokOut, nil
}

func (h *HiveRelay) saveConversation(ctx context.Context, req *honeypotv1.RelayLLMRequest, canaryID, personaModel, respText, degraded string, tokIn, tokOut int32, cost float64) {
	if h.pg == nil || req.GetEventUuid() == "" || req.GetNodeId() == "" {
		return
	}
	dbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := h.pg.InsertLLMConversation(dbCtx, req.GetNodeId(), &honeypotv1.LlmConversation{
		ConversationUuid:  req.GetEventUuid(),
		EventUuid:         req.GetEventUuid(),
		NodeId:            req.GetNodeId(),
		CanaryKeyId:       canaryID,
		SourceIp:          req.GetSourceIp(),
		ApiDialect:        req.GetApiDialect(),
		RequestedModel:    req.GetRequestedModel(),
		EmulatedPersona:   personaModel,
		ProbeFlags:        req.GetProbeFlags(),
		MessagesJson:      req.GetMessagesJson(),
		ToolsJson:         req.GetToolsJson(),
		ResponseText:      respText,
		DegradedMode:      degraded,
		UpstreamTokensIn:  tokIn,
		UpstreamTokensOut: tokOut,
		EstimatedCostUsd:  cost,
	}); err != nil {
		log.Printf("saveConversation insert error node=%s event=%s: %v", req.GetNodeId(), req.GetEventUuid(), err)
	}
}

func buildZeroCostDeceptionReply(persona chameleon.ResolvedPersona, messagesJSON string) string {
	lower := strings.ToLower(messagesJSON)
	if strings.Contains(lower, "which model") || strings.Contains(lower, "who created") || strings.Contains(lower, "what model") {
		if persona.VendorFamily == "anthropic" {
			return "I am " + persona.EmulatedModel + ", an AI assistant created by Anthropic."
		}
		if persona.VendorFamily == "ollama" {
			return "Running local model " + persona.EmulatedModel + " on Ollama runtime."
		}
		return "I am " + persona.EmulatedModel + ", a large language model trained by OpenAI."
	}
	return "Environment initialized for " + persona.EmulatedModel + ". Ready to process your next instruction."
}
