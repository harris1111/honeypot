package adminapi

import (
	"fmt"
	"net/http"

	honeypotv1 "github.com/harris/honeypot/proto/gen/honeypot/v1"
)

func (s *Server) handleListCanaries(w http.ResponseWriter, r *http.Request) {
	rows, err := s.pg.Pool.Query(r.Context(), `
		SELECT id::text, key_prefix, provider_style, COALESCE(node_id::text, ''), placement_source, placement_path,
		       paid_upstream_eligible, hit_count, COALESCE(last_hit_at::text, ''), created_at::text
		FROM canary_keys ORDER BY created_at DESC LIMIT 200
	`)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()
	out := make([]map[string]any, 0)
	for rows.Next() {
		var id, pref, st, nid, psrc, ppath, lh, at string
		var paid bool
		var hits int64
		if rows.Scan(&id, &pref, &st, &nid, &psrc, &ppath, &paid, &hits, &lh, &at) == nil {
			out = append(out, map[string]any{
				"id": id, "key_prefix": pref, "provider_style": st, "node_id": nid,
				"placement_source": psrc, "placement_path": ppath, "paid_upstream_eligible": paid,
				"hit_count": hits, "last_hit_at": lh, "created_at": at,
			})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"canaries": out})
}

func (s *Server) handleMintCanary(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProviderStyle   string `json:"provider_style"`
		NodeID          string `json:"node_id"`
		PlacementSource string `json:"placement_source"`
		PlacementPath   string `json:"placement_path"`
		PaidEligible    bool   `json:"paid_upstream_eligible"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.ProviderStyle == "" {
		req.ProviderStyle = "openai"
	}
	if req.PlacementSource == "" {
		req.PlacementSource = "custom_lure"
	}
	seed, err := s.canary.MintAndStore(r.Context(), s.pg, req.ProviderStyle, req.NodeID, "ad", req.PlacementSource, req.PlacementPath, req.PaidEligible)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Push live canary key seed to target Sensor if currently connected
	if s.hub != nil && req.NodeID != "" {
		_ = s.hub.SendCommand(req.NodeID, &honeypotv1.HiveCommand{
			Payload: &honeypotv1.HiveCommand_SyncCanaryKeys{
				SyncCanaryKeys: &honeypotv1.SyncCanaryKeysCommand{Keys: []*honeypotv1.CanaryKeySeed{seed}},
			},
		})
	}
	envVar := "OPENAI_API_KEY"
	if req.ProviderStyle == "anthropic" {
		envVar = "ANTHROPIC_API_KEY"
	}
	envLure := fmt.Sprintf("# Lure generated for %s\n%s=%s\n", req.PlacementSource, envVar, seed.GetKeyPlaintext())

	actor := actorFromCtx(r)
	_ = s.pg.InsertAuditLog(r.Context(), actor.Username, "canary_minted", "canary_key", seed.GetCanaryKeyId(), map[string]any{"source": req.PlacementSource}, remoteHost(r))
	writeJSON(w, http.StatusCreated, map[string]any{
		"seed":     seed,
		"env_lure": envLure,
	})
}
