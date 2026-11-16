package adminapi

import (
	"net/http"
	"strings"

	"github.com/harris/honeypot/internal/store"
	"github.com/harris/honeypot/internal/traps/llmproxy"
)

func (s *Server) handleListLLMConversations(w http.ResponseWriter, r *http.Request) {
	rows, err := s.pg.Pool.Query(r.Context(), `
		SELECT id::text, COALESCE(canary_key_id::text, ''), host(source_ip), api_dialect, requested_model,
		       emulated_persona, probe_flags, messages_json::text, tools_json::text, response_text,
		       degraded_mode, upstream_tokens_in, upstream_tokens_out, estimated_cost_usd::float8, created_at::text
		FROM llm_conversations ORDER BY created_at DESC LIMIT 100
	`)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()
	out := make([]map[string]any, 0)
	for rows.Next() {
		var id, ckid, sip, dial, reqm, emp, msgs, tools, resp, deg, at string
		var flags []string
		var ti, to int
		var cost float64
		if rows.Scan(&id, &ckid, &sip, &dial, &reqm, &emp, &flags, &msgs, &tools, &resp, &deg, &ti, &to, &cost, &at) == nil {
			out = append(out, map[string]any{
				"id": id, "canary_key_id": ckid, "source_ip": sip, "api_dialect": dial,
				"requested_model": reqm, "emulated_persona": emp, "probe_flags": flags,
				"messages_json": msgs, "tools_json": tools, "response_text": resp,
				"degraded_mode": deg, "tokens_in": ti, "tokens_out": to, "cost_usd": cost, "created_at": at,
			})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"conversations": out})
}

func (s *Server) handleListPersonas(w http.ResponseWriter, r *http.Request) {
	personas, err := s.pg.ListLLMPersonas(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"personas": personas})
}

func (s *Server) handleUpsertPersona(w http.ResponseWriter, r *http.Request) {
	var req store.LLMPersonaRow
	if err := decodeJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.pg.UpsertLLMPersona(r.Context(), req); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	actor := actorFromCtx(r)
	_ = s.pg.InsertAuditLog(r.Context(), actor.Username, "llm_persona_upsert", "llm_persona", req.ModelPattern, nil, remoteHost(r))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleLLMBudget(w http.ResponseWriter, r *http.Request) {
	var spent, capUSD float64
	if s.breaker != nil {
		spent = s.breaker.CurrentDailySpentUSD(r.Context())
		capUSD = s.breaker.MaxDailyUSD()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"spent_today_usd": spent,
		"cap_usd":         capUSD,
	})
}

func maskSecret(s string) string {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return ""
	}
	if len(trimmed) <= 8 {
		return "****"
	}
	return trimmed[:4] + "..." + trimmed[len(trimmed)-4:]
}

func (s *Server) buildLLMSettingsResponse(r *http.Request) map[string]any {
	var baseURL, apiKey, model string
	var allowUnauth bool
	if s.llmRelay != nil {
		cfg := s.llmRelay.GetConfig()
		baseURL = cfg.BaseURL
		apiKey = cfg.APIKey
		model = cfg.Model
		allowUnauth = cfg.AllowUnauthenticatedChat
	}
	var spent, capUSD float64
	if s.breaker != nil {
		spent = s.breaker.CurrentDailySpentUSD(r.Context())
		capUSD = s.breaker.MaxDailyUSD()
	}
	activeMode := "builtin_free"
	if strings.TrimSpace(baseURL) != "" && strings.TrimSpace(apiKey) != "" && capUSD > 0 {
		activeMode = "live_upstream"
	}
	if model == "" {
		model = "deepseek-v4"
	}
	return map[string]any{
		"base_url":                   baseURL,
		"model":                      model,
		"has_api_key":                strings.TrimSpace(apiKey) != "",
		"api_key_masked":             maskSecret(apiKey),
		"max_daily_usd":              capUSD,
		"allow_unauthenticated_chat": allowUnauth,
		"spent_today_usd":            spent,
		"active_mode":                activeMode,
	}
}

func (s *Server) handleGetLLMSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.buildLLMSettingsResponse(r))
}

func (s *Server) handleUpdateLLMSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		BaseURL                  string  `json:"base_url"`
		APIKey                   string  `json:"api_key"`
		ClearAPIKey              bool    `json:"clear_api_key"`
		Model                    string  `json:"model"`
		MaxDailyUSD              float64 `json:"max_daily_usd"`
		AllowUnauthenticatedChat bool    `json:"allow_unauthenticated_chat"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	baseURL := strings.TrimSpace(req.BaseURL)
	if baseURL != "" && !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		writeJSONError(w, http.StatusBadRequest, "base_url must start with http:// or https://")
		return
	}
	model := strings.TrimSpace(req.Model)
	if model == "" {
		model = "deepseek-v4"
	}
	maxUSD := req.MaxDailyUSD
	if maxUSD < 0 {
		maxUSD = 0
	}

	var plainKey string
	var encKey []byte
	if !req.ClearAPIKey {
		if k := strings.TrimSpace(req.APIKey); k != "" {
			plainKey = k
			var encErr error
			encKey, encErr = s.auth.encryptBytes([]byte(plainKey))
			if encErr != nil {
				writeJSONError(w, http.StatusInternalServerError, encErr.Error())
				return
			}
		} else {
			if err := s.pg.Pool.QueryRow(r.Context(), `SELECT api_key_enc FROM llm_runtime_settings WHERE id = 1`).Scan(&encKey); err == nil && len(encKey) > 0 {
				if dec, decErr := s.auth.decryptBytes(encKey); decErr == nil {
					plainKey = string(dec)
				}
			} else if s.llmRelay != nil {
				if cur := strings.TrimSpace(s.llmRelay.GetConfig().APIKey); cur != "" {
					plainKey = cur
					encKey, _ = s.auth.encryptBytes([]byte(cur))
				}
			}
		}
	}

	_, err := s.pg.Pool.Exec(r.Context(), `
		INSERT INTO llm_runtime_settings (id, base_url, api_key_enc, model, max_daily_usd, allow_unauthenticated_chat, updated_at)
		VALUES (1, $1, $2, $3, $4, $5, NOW())
		ON CONFLICT (id) DO UPDATE
		SET base_url = EXCLUDED.base_url,
		    api_key_enc = EXCLUDED.api_key_enc,
		    model = EXCLUDED.model,
		    max_daily_usd = EXCLUDED.max_daily_usd,
		    allow_unauthenticated_chat = EXCLUDED.allow_unauthenticated_chat,
		    updated_at = NOW()
	`, baseURL, encKey, model, maxUSD, req.AllowUnauthenticatedChat)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if s.llmRelay != nil {
		s.llmRelay.UpdateConfig(llmproxy.UpstreamConfig{
			BaseURL:                  baseURL,
			APIKey:                   plainKey,
			Model:                    model,
			AllowUnauthenticatedChat: req.AllowUnauthenticatedChat,
		}, maxUSD)
	}

	actor := actorFromCtx(r)
	_ = s.pg.InsertAuditLog(r.Context(), actor.Username, "llm_settings_updated", "llm_runtime_settings", "1", map[string]any{
		"base_url":                   baseURL,
		"model":                      model,
		"max_daily_usd":              maxUSD,
		"allow_unauthenticated_chat": req.AllowUnauthenticatedChat,
		"has_api_key":                plainKey != "",
	}, remoteHost(r))

	writeJSON(w, http.StatusOK, s.buildLLMSettingsResponse(r))
}

func (s *Server) handleTestLLMSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Prompt string `json:"prompt"`
	}
	_ = decodeJSON(r, &req)
	if s.llmRelay == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"mode":       "builtin_free",
			"model":      "chameleon-zero-cost",
			"reply":      "Environment initialized. Ready to process your next instruction.",
			"latency_ms": 1,
		})
		return
	}
	mode, model, reply, latencyMs, err := s.llmRelay.TestConnection(r.Context(), req.Prompt)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"mode":       mode,
			"model":      model,
			"reply":      "",
			"latency_ms": latencyMs,
			"error":      err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"mode":       mode,
		"model":      model,
		"reply":      reply,
		"latency_ms": latencyMs,
	})
}
