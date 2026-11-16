package adminapi

import (
	"fmt"
	"net/http"
	"net/netip"
	"strings"

	"github.com/harris/honeypot/internal/store"
	honeypotv1 "github.com/harris/honeypot/proto/gen/honeypot/v1"
)

func (s *Server) handleListTraps(w http.ResponseWriter, r *http.Request) {
	rows, err := s.pg.Pool.Query(r.Context(), `
		SELECT id::text, node_id::text, trap_kind, container_name, image, listen_port, protocol, config_json::text, desired_state, actual_state, updated_at::text
		FROM trap_deployments ORDER BY updated_at DESC
	`)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()
	out := make([]store.TrapDeploymentRow, 0)
	for rows.Next() {
		var t store.TrapDeploymentRow
		if rows.Scan(&t.ID, &t.NodeID, &t.TrapKind, &t.ContainerName, &t.Image, &t.ListenPort, &t.Protocol, &t.ConfigJSON, &t.DesiredState, &t.ActualState, &t.UpdatedAt) == nil {
			out = append(out, t)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"traps": out})
}

func (s *Server) handleDeployTrap(w http.ResponseWriter, r *http.Request) {
	var req store.TrapDeploymentRow
	if err := decodeJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.DesiredState = "running"
	id, err := s.pg.UpsertTrapDeployment(r.Context(), req)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if s.hub != nil {
		_ = s.hub.SendCommand(req.NodeID, &honeypotv1.HiveCommand{
			Payload: &honeypotv1.HiveCommand_DeployTrap{
				DeployTrap: &honeypotv1.DeployTrapCommand{
					DeploymentId:  id,
					TrapKind:      req.TrapKind,
					ContainerName: req.ContainerName,
					Image:         req.Image,
					ListenPort:    uint32(req.ListenPort),
					Protocol:      req.Protocol,
					ConfigJson:    req.ConfigJSON,
				},
			},
		})
	}
	actor := actorFromCtx(r)
	_ = s.pg.InsertAuditLog(r.Context(), actor.Username, "trap_deploy", "trap_deployment", id, map[string]any{"trap_kind": req.TrapKind, "port": req.ListenPort}, remoteHost(r))
	writeJSON(w, http.StatusCreated, map[string]string{"id": id})
}

func (s *Server) handleStopTrap(w http.ResponseWriter, r *http.Request) {
	s.handleTrapLifecycle(w, r, "stop")
}

func (s *Server) handleRestartTrap(w http.ResponseWriter, r *http.Request) {
	s.handleTrapLifecycle(w, r, "restart")
}

func (s *Server) handleTrapLifecycle(w http.ResponseWriter, r *http.Request, op string) {
	depID := r.PathValue("id")
	var nodeID, cname string
	err := s.pg.Pool.QueryRow(r.Context(), `SELECT node_id::text, container_name FROM trap_deployments WHERE id = $1::uuid`, depID).Scan(&nodeID, &cname)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "trap not found")
		return
	}
	if op == "stop" {
		_ = s.pg.UpdateTrapActualState(r.Context(), depID, "stopped", "stopped")
		if s.hub != nil {
			_ = s.hub.SendCommand(nodeID, &honeypotv1.HiveCommand{
				Payload: &honeypotv1.HiveCommand_StopTrap{StopTrap: &honeypotv1.StopTrapCommand{DeploymentId: depID, ContainerName: cname}},
			})
		}
	} else {
		if s.hub != nil {
			_ = s.hub.SendCommand(nodeID, &honeypotv1.HiveCommand{
				Payload: &honeypotv1.HiveCommand_RestartTrap{RestartTrap: &honeypotv1.RestartTrapCommand{DeploymentId: depID, ContainerName: cname}},
			})
		}
	}
	actor := actorFromCtx(r)
	_ = s.pg.InsertAuditLog(r.Context(), actor.Username, "trap_"+op, "trap_deployment", depID, nil, remoteHost(r))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleFetchTrapLogs(w http.ResponseWriter, r *http.Request) {
	depID := r.PathValue("id")
	var nodeID, cname string
	if err := s.pg.Pool.QueryRow(r.Context(), `SELECT node_id::text, container_name FROM trap_deployments WHERE id = $1::uuid`, depID).Scan(&nodeID, &cname); err != nil {
		writeJSONError(w, http.StatusNotFound, "trap not found")
		return
	}
	if s.hub == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "hub unavailable")
		return
	}
	err := s.hub.SendCommand(nodeID, &honeypotv1.HiveCommand{
		Payload: &honeypotv1.HiveCommand_FetchLogs{
			FetchLogs: &honeypotv1.FetchLogsCommand{DeploymentId: depID, ContainerName: cname, TailLines: 200},
		},
	})
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]bool{"requested": true})
}

func (s *Server) handleToggleCVE(w http.ResponseWriter, r *http.Request) {
	var req struct {
		NodeID  string `json:"node_id"`
		CVEID   string `json:"cve_id"`
		Enabled bool   `json:"enabled"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.hub != nil {
		targets := []string{req.NodeID}
		if req.NodeID == "" || req.NodeID == "all" {
			targets = s.hub.ConnectedNodes()
		}
		for _, nid := range targets {
			_ = s.hub.SendCommand(nid, &honeypotv1.HiveCommand{
				Payload: &honeypotv1.HiveCommand_ToggleCvePack{
					ToggleCvePack: &honeypotv1.ToggleCvePackCommand{CveId: req.CVEID, Enabled: req.Enabled},
				},
			})
		}
	}
	actor := actorFromCtx(r)
	_ = s.pg.InsertAuditLog(r.Context(), actor.Username, "cve_toggle", "cve_pack", req.CVEID, map[string]any{"enabled": req.Enabled}, remoteHost(r))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handlePoCPreflight verifies operator public IP is inside protected_allowlist BEFORE offering self-test PoC curls.
func (s *Server) handlePoCPreflight(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OperatorIP string `json:"operator_ip"`
		SensorHost string `json:"sensor_host"`
		CVEID      string `json:"cve_id"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(req.OperatorIP) == "" {
		peer := remoteHost(r)
		if addr, parseErr := netip.ParseAddr(peer); parseErr == nil && !addr.Unmap().IsLoopback() {
			req.OperatorIP = peer
		} else {
			writeJSONError(w, http.StatusBadRequest, "accessed via loopback/SSH tunnel; specify your real public operator_ip explicitly")
			return
		}
	}
	allowed, err := s.pg.CheckAllowlistOverlap(r.Context(), req.OperatorIP)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid operator IP: "+err.Error())
		return
	}
	if !allowed {
		writeJSON(w, http.StatusPreconditionFailed, map[string]any{
			"allowlisted": false,
			"message":     fmt.Sprintf("Operator IP %s is NOT in protected_allowlist! Add it before running PoC self-tests.", req.OperatorIP),
		})
		return
	}
	if req.SensorHost == "" {
		req.SensorHost = "http://sensor-ip:80"
	}
	curl := fmt.Sprintf(`curl -i -H "X-Middleware-Subrequest: src/middleware:src/middleware" "%s/admin"`, req.SensorHost)
	switch req.CVEID {
	case "CVE-2024-4577":
		curl = fmt.Sprintf(`curl -i -d '<?php echo md5("kev-check"); ?>' "%s/cgi-bin/php-cgi.exe?%%add+allow_url_include%%3d1+%%add+auto_prepend_file%%3dphp://input"`, req.SensorHost)
	case "CVE-2021-44228":
		curl = fmt.Sprintf(`curl -i -H 'X-Api-Version: ${jndi:ldap://canary.invalid/test}' "%s/"`, req.SensorHost)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"allowlisted": true,
		"curl":        curl,
	})
}
