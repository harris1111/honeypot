package adminapi

import (
	"errors"
	"net/http"

	"github.com/harris/honeypot/internal/guard"
	"github.com/harris/honeypot/internal/policy"
)

func (s *Server) handleListDecisions(w http.ResponseWriter, r *http.Request) {
	statusFilter := r.URL.Query().Get("status")
	rows, err := s.pg.Pool.Query(r.Context(), `
		SELECT id::text, incident_id::text, indicator_type, indicator_value, target_sync, status, decided_by, reason,
		       COALESCE(ttl_expires_at::text, ''), cloudflare_item_id, nginx_revision, created_at::text, updated_at::text
		FROM guard_decisions
		WHERE ($1 = '' OR status = $1)
		ORDER BY created_at DESC LIMIT 200
	`, statusFilter)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()
	out := make([]guard.DecisionRow, 0)
	for rows.Next() {
		var d guard.DecisionRow
		var exp string
		if rows.Scan(&d.ID, &d.IncidentID, &d.IndicatorType, &d.IndicatorValue, &d.TargetSync, &d.Status, &d.DecidedBy, &d.Reason,
			&exp, &d.CloudflareItemID, &d.NginxRevision, &d.CreatedAt, &d.UpdatedAt) == nil {
			if exp != "" {
				d.TTLExpiresAt = &exp
			}
			out = append(out, d)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"decisions": out})
}

func (s *Server) handleApproveDecisions(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IDs        []string `json:"ids"`
		TargetSync string   `json:"target_sync"`
		TTLHours   int      `json:"ttl_hours"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	actor := actorFromCtx(r)
	approved := 0
	for _, id := range req.IDs {
		if err := s.guardMgr.ApproveDecision(r.Context(), id, actor.Username, req.TargetSync, req.TTLHours); err != nil {
			if errors.Is(err, policy.ErrProtectedAllowlist) {
				writeJSONError(w, http.StatusForbidden, err.Error())
				return
			}
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		approved++
	}
	writeJSON(w, http.StatusOK, map[string]int{"approved": approved})
}

func (s *Server) handleRejectDecision(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req struct{ Reason string `json:"reason"` }
	_ = decodeJSON(r, &req)
	actor := actorFromCtx(r)
	if err := s.guardMgr.RejectDecision(r.Context(), id, actor.Username, req.Reason); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleUnbanDecision(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req struct{ Reason string `json:"reason"` }
	_ = decodeJSON(r, &req)
	actor := actorFromCtx(r)
	if err := s.guardMgr.UnbanOrRollback(r.Context(), id, actor.Username, req.Reason); err != nil {
		writeJSONError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "rolled_back"})
}

func (s *Server) handleManualBlock(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IndicatorType  string `json:"indicator_type"`
		IndicatorValue string `json:"indicator_value"`
		TargetSync     string `json:"target_sync"`
		TTLHours       int    `json:"ttl_hours"`
		Reason         string `json:"reason"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	actor := actorFromCtx(r)
	id, err := s.guardMgr.ManualBlock(r.Context(), req.IndicatorType, req.IndicatorValue, req.TargetSync, req.TTLHours, actor.Username, req.Reason)
	if err != nil {
		if errors.Is(err, policy.ErrProtectedAllowlist) {
			writeJSONError(w, http.StatusForbidden, err.Error())
			return
		}
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"id": id})
}

func (s *Server) handleListAllowlist(w http.ResponseWriter, r *http.Request) {
	rows, err := s.pg.Pool.Query(r.Context(), `
		SELECT id::text, cidr::text, label, is_system_locked, created_by, created_at::text
		FROM protected_allowlist ORDER BY is_system_locked DESC, cidr::text ASC
	`)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()
	out := make([]map[string]any, 0)
	for rows.Next() {
		var id, cidr, label, by, at string
		var locked bool
		if rows.Scan(&id, &cidr, &label, &locked, &by, &at) == nil {
			out = append(out, map[string]any{
				"id": id, "cidr": cidr, "label": label, "is_system_locked": locked, "created_by": by, "created_at": at,
			})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"allowlist": out})
}

func (s *Server) handleAddAllowlist(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CIDR  string `json:"cidr"`
		Label string `json:"label"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	actor := actorFromCtx(r)
	if err := s.pg.AddAllowlistCIDR(r.Context(), req.CIDR, req.Label, actor.Username, false); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]bool{"ok": true})
}

func (s *Server) handleDeleteAllowlist(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.pg.DeleteAllowlistCIDR(r.Context(), id); err != nil {
		writeJSONError(w, http.StatusForbidden, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleListPolicyRules(w http.ResponseWriter, r *http.Request) {
	rules, err := policy.ListRules(r.Context(), s.pg)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": rules})
}

func (s *Server) handleUpsertPolicyRule(w http.ResponseWriter, r *http.Request) {
	var req policy.RuleRow
	if err := decodeJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	_, err := s.pg.Pool.Exec(r.Context(), `
		INSERT INTO policy_rules (name, priority, enabled, conditions_json, action, default_ttl_hours, target_sync)
		VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7)
		ON CONFLICT (name) DO UPDATE
		SET priority = EXCLUDED.priority, enabled = EXCLUDED.enabled, conditions_json = EXCLUDED.conditions_json,
		    action = EXCLUDED.action, default_ttl_hours = EXCLUDED.default_ttl_hours, target_sync = EXCLUDED.target_sync, updated_at = NOW()
	`, req.Name, req.Priority, req.Enabled, req.ConditionsJSON, req.Action, req.DefaultTTLHours, req.TargetSync)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	actor := actorFromCtx(r)
	_ = s.pg.InsertAuditLog(r.Context(), actor.Username, "policy_rule_upsert", "policy_rule", req.Name, map[string]any{"action": req.Action}, remoteHost(r))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleWAFExpression(w http.ResponseWriter, r *http.Request) {
	rows, err := s.pg.Pool.Query(r.Context(), `
		SELECT DISTINCT ja4 FROM telemetry_events
		WHERE ja4 <> '' AND severity_score >= 85
		LIMIT 20
	`)
	var ja4s []string
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var fp string
			if rows.Scan(&fp) == nil {
				ja4s = append(ja4s, fp)
			}
		}
	}
	expr := guard.BuildWirefilterExpression(guard.WAFConfig{
		CloudflareEnterpriseJA4Enabled: s.cfg.CloudflareEnterprise,
		ListName:                       "honeypot_blocklist",
	}, ja4s)
	writeJSON(w, http.StatusOK, map[string]any{
		"expression":         expr,
		"enterprise_enabled": s.cfg.CloudflareEnterprise,
	})
}

func (s *Server) handleAuditLogs(w http.ResponseWriter, r *http.Request) {
	rows, err := s.pg.Pool.Query(r.Context(), `
		SELECT id, actor, action, target_type, target_id, details_json::text, COALESCE(host(source_ip), ''), created_at::text
		FROM audit_logs ORDER BY created_at DESC LIMIT 100
	`)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()
	out := make([]map[string]any, 0)
	for rows.Next() {
		var id int64
		var actor, act, tt, tid, det, sip, at string
		if rows.Scan(&id, &actor, &act, &tt, &tid, &det, &sip, &at) == nil {
			out = append(out, map[string]any{
				"id": id, "actor": actor, "action": act, "target_type": tt, "target_id": tid,
				"details": det, "source_ip": sip, "created_at": at,
			})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"logs": out})
}
