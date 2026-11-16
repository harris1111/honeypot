package adminapi

import (
	"net/http"

	"github.com/harris/honeypot/internal/store"
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
	var spent float64
	if s.breaker != nil {
		spent = s.breaker.CurrentDailySpentUSD(r.Context())
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"spent_today_usd": spent,
		"cap_usd":         5.0,
	})
}
