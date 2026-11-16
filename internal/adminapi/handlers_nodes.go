package adminapi

import (
	"fmt"
	"net/http"
	"time"

	"github.com/harris/honeypot/internal/pki"
	honeypotv1 "github.com/harris/honeypot/proto/gen/honeypot/v1"
)

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var totalEvents, openIncidents, pendingTriage, malwareCount, canaryHits, sshSessions24h int64
	_ = s.pg.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM telemetry_events WHERE observed_at >= NOW() - INTERVAL '24 hours'`).Scan(&totalEvents)
	_ = s.pg.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM attack_incidents WHERE status = 'open'`).Scan(&openIncidents)
	_ = s.pg.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM guard_decisions WHERE status = 'pending_approval'`).Scan(&pendingTriage)
	_ = s.pg.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM malware_artifacts`).Scan(&malwareCount)
	_ = s.pg.Pool.QueryRow(ctx, `SELECT COALESCE(SUM(hit_count), 0) FROM canary_keys`).Scan(&canaryHits)
	_ = s.pg.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM ssh_session_replays WHERE started_at >= NOW() - INTERVAL '24 hours'`).Scan(&sshSessions24h)

	topCVEs := make([]map[string]any, 0)
	if rows, err := s.pg.Pool.Query(ctx, `
		SELECT cve_id, COUNT(*) AS cnt
		FROM telemetry_events
		WHERE observed_at >= NOW() - INTERVAL '24 hours' AND cve_id <> ''
		GROUP BY cve_id ORDER BY cnt DESC LIMIT 10
	`); err == nil {
		defer rows.Close()
		for rows.Next() {
			var cve string
			var cnt int64
			if rows.Scan(&cve, &cnt) == nil {
				topCVEs = append(topCVEs, map[string]any{"cve_id": cve, "count": cnt})
			}
		}
	}

	eventsByTrap := make([]map[string]any, 0)
	if rows, err := s.pg.Pool.Query(ctx, `
		SELECT trap_kind, COUNT(*) AS cnt
		FROM telemetry_events
		WHERE observed_at >= NOW() - INTERVAL '24 hours'
		GROUP BY trap_kind ORDER BY cnt DESC
	`); err == nil {
		defer rows.Close()
		for rows.Next() {
			var tk string
			var cnt int64
			if rows.Scan(&tk, &cnt) == nil {
				eventsByTrap = append(eventsByTrap, map[string]any{"trap_kind": tk, "count": cnt})
			}
		}
	}

	topIPs := make([]map[string]any, 0)
	if rows, err := s.pg.Pool.Query(ctx, `
		SELECT host(source_ip), COUNT(*) AS cnt, COALESCE(MAX(country_code), '')
		FROM telemetry_events
		WHERE observed_at >= NOW() - INTERVAL '24 hours'
		GROUP BY source_ip ORDER BY cnt DESC LIMIT 8
	`); err == nil {
		defer rows.Close()
		for rows.Next() {
			var ip, cc string
			var cnt int64
			if rows.Scan(&ip, &cnt, &cc) == nil {
				topIPs = append(topIPs, map[string]any{"ip": ip, "count": cnt, "country_code": cc})
			}
		}
	}

	recentSSHSessions := make([]map[string]any, 0)
	if rows, err := s.pg.Pool.Query(ctx, `
		SELECT id::text, host(source_ip), username, auth_succeeded, COALESCE(commands, ARRAY[]::TEXT[]), duration_ms, started_at::text
		FROM ssh_session_replays
		ORDER BY (cardinality(commands) > 0) DESC, auth_succeeded DESC, started_at DESC
		LIMIT 8
	`); err == nil {
		defer rows.Close()
		for rows.Next() {
			var id, sip, usr, st string
			var authOK bool
			var cmds []string
			var dur int64
			if rows.Scan(&id, &sip, &usr, &authOK, &cmds, &dur, &st) == nil {
				if cmds == nil {
					cmds = []string{}
				}
				recentSSHSessions = append(recentSSHSessions, map[string]any{
					"id":             id,
					"source_ip":      sip,
					"username":       usr,
					"auth_succeeded": authOK,
					"commands":       cmds,
					"duration_ms":    dur,
					"started_at":     st,
				})
			}
		}
	}

	recentServiceEvents := make([]map[string]any, 0)
	if rows, err := s.pg.Pool.Query(ctx, `
		SELECT id::text, host(source_ip), dest_port, protocol, trap_kind, persona, cve_id, http_method, http_path, response_summary, severity_score, observed_at::text
		FROM telemetry_events
		WHERE trap_kind <> 'cowrie'
		ORDER BY observed_at DESC LIMIT 10
	`); err == nil {
		defer rows.Close()
		for rows.Next() {
			var id, sip, proto, tk, pers, cve, meth, hpath, sum, obs string
			var dport, score int
			if rows.Scan(&id, &sip, &dport, &proto, &tk, &pers, &cve, &meth, &hpath, &sum, &score, &obs) == nil {
				recentServiceEvents = append(recentServiceEvents, map[string]any{
					"id":               id,
					"source_ip":        sip,
					"dest_port":        dport,
					"protocol":         proto,
					"trap_kind":        tk,
					"persona":          pers,
					"cve_id":           cve,
					"http_method":      meth,
					"http_path":        hpath,
					"response_summary": sum,
					"severity_score":   score,
					"observed_at":      obs,
				})
			}
		}
	}

	var spentUSD float64
	if s.breaker != nil {
		spentUSD = s.breaker.CurrentDailySpentUSD(ctx)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"events_24h":            totalEvents,
		"ssh_sessions_24h":      sshSessions24h,
		"open_incidents":        openIncidents,
		"pending_triage":        pendingTriage,
		"malware_count":         malwareCount,
		"canary_hits":           canaryHits,
		"llm_spent_usd":         spentUSD,
		"top_cves":              topCVEs,
		"events_by_trap":        eventsByTrap,
		"top_ips":               topIPs,
		"recent_ssh_sessions":   recentSSHSessions,
		"recent_service_events": recentServiceEvents,
	})
}

func (s *Server) handleListNodes(w http.ResponseWriter, r *http.Request) {
	rows, err := s.pg.Pool.Query(r.Context(), `
		SELECT id::text, name, region, COALESCE(host(public_ipv4), ''), cert_serial, COALESCE(cert_expires_at::text, ''), agent_version, status, COALESCE(last_heartbeat_at::text, ''), metrics_json::text
		FROM sensor_nodes ORDER BY created_at DESC
	`)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()
	nodes := make([]map[string]any, 0)
	for rows.Next() {
		var id, name, region, ipv4, serial, exp, ver, status, hb, metrics string
		if rows.Scan(&id, &name, &region, &ipv4, &serial, &exp, &ver, &status, &hb, &metrics) == nil {
			nodes = append(nodes, map[string]any{
				"id": id, "name": name, "region": region, "public_ipv4": ipv4,
				"cert_serial": serial, "cert_expires_at": exp, "agent_version": ver,
				"status": status, "last_heartbeat_at": hb, "metrics": metrics,
			})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"nodes": nodes})
}

func (s *Server) handleCreateJoinToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Role   string `json:"role"`
		Name   string `json:"name"`
		Region string `json:"region"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Role == "" {
		req.Role = "sensor"
	}
	if req.Name == "" {
		writeJSONError(w, http.StatusBadRequest, "name required")
		return
	}
	if req.Region == "" {
		req.Region = "default"
	}

	raw, hash, err := pki.GenerateJoinToken()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	tid, err := s.pg.CreateJoinToken(r.Context(), hash, req.Role, req.Name, req.Region, 24*time.Hour)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	hiveAddr := s.cfg.DefaultHiveIngress
	if hiveAddr == "" {
		hiveAddr = "enroll.hive.internal:9443"
	}
	fp := s.ca.RootFingerprintSHA256()
	joinCmd := fmt.Sprintf("sensor-agent --hive-addr %s --enroll-token %s --ca-fingerprint %s", hiveAddr, raw, fp)
	if req.Role == "nginx_guard" {
		joinCmd = fmt.Sprintf("nginx-guard --hive-addr %s --enroll-token %s --ca-fingerprint %s", hiveAddr, raw, fp)
	}

	actor := actorFromCtx(r)
	_ = s.pg.InsertAuditLog(r.Context(), actor.Username, "join_token_created", "node_join_token", tid.String(), map[string]any{"name": req.Name, "role": req.Role}, remoteHost(r))
	writeJSON(w, http.StatusCreated, map[string]any{
		"token_id":       tid.String(),
		"join_token":     raw,
		"ca_fingerprint": fp,
		"install_cmd":    joinCmd,
	})
}

func (s *Server) handleRevokeNode(w http.ResponseWriter, r *http.Request) {
	nodeID := r.PathValue("id")
	actor := actorFromCtx(r)
	if err := s.pg.RevokeNode(r.Context(), nodeID, actor.Username); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if s.hub != nil {
		s.hub.DisconnectNode(r.Context(), nodeID)
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (s *Server) handleRotateNodeCert(w http.ResponseWriter, r *http.Request) {
	nodeID := r.PathValue("id")
	if s.hub == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "hub unavailable")
		return
	}
	err := s.hub.SendCommand(nodeID, &honeypotv1.HiveCommand{
		Payload: &honeypotv1.HiveCommand_RotateCert{
			RotateCert: &honeypotv1.RotateCertCommand{Reason: "admin_requested"},
		},
	})
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, err.Error())
		return
	}
	actor := actorFromCtx(r)
	_ = s.pg.InsertAuditLog(r.Context(), actor.Username, "node_rotate_cert", "sensor_node", nodeID, nil, remoteHost(r))
	writeJSON(w, http.StatusOK, map[string]bool{"dispatched": true})
}
