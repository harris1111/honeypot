package adminapi

import (
	"net/http"
	"strings"
)

func (s *Server) handleListIncidents(w http.ResponseWriter, r *http.Request) {
	rows, err := s.pg.Pool.Query(r.Context(), `
		SELECT id::text, correlation_key, title, severity, confidence_score, host(primary_ip),
		       ARRAY(SELECT host(x) FROM unnest(related_ips) AS x), trap_kinds, cve_ids,
		       malware_sha256s, yara_match_count, country_code, asn, greynoise_classification,
		       abuseipdb_score, status, first_seen_at::text, last_seen_at::text
		FROM attack_incidents
		ORDER BY last_seen_at DESC LIMIT 100
	`)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()
	out := make([]map[string]any, 0)
	for rows.Next() {
		var id, ckey, title, sev, pip, cc, gn, status, first, last string
		var score, ycnt, asn, abscore int
		var relIPs, traps, cves, shas []string
		if rows.Scan(&id, &ckey, &title, &sev, &score, &pip, &relIPs, &traps, &cves, &shas, &ycnt, &cc, &asn, &gn, &abscore, &status, &first, &last) == nil {
			out = append(out, map[string]any{
				"id": id, "correlation_key": ckey, "title": title, "severity": sev, "confidence_score": score,
				"primary_ip": pip, "related_ips": relIPs, "trap_kinds": traps, "cve_ids": cves,
				"malware_sha256s": shas, "yara_match_count": ycnt, "country_code": cc, "asn": asn,
				"greynoise_classification": gn, "abuseipdb_score": abscore, "status": status,
				"first_seen_at": first, "last_seen_at": last,
			})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"incidents": out})
}

func (s *Server) handleGetIncident(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	evRows, err := s.pg.Pool.Query(r.Context(), `
		SELECT id::text, host(source_ip), trap_kind, persona, cve_id, is_kev, ja4, ja4h, hassh,
		       http_method, http_path, raw_payload, response_summary, extracted_iocs::text, severity_score, observed_at::text
		FROM telemetry_events
		WHERE incident_id = $1::uuid
		ORDER BY observed_at ASC LIMIT 200
	`, id)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer evRows.Close()
	events := make([]map[string]any, 0)
	for evRows.Next() {
		var eid, sip, tk, pers, cve, ja4, ja4h, hassh, meth, hpath, rawp, sum, iocs, obs string
		var kev bool
		var score int
		if evRows.Scan(&eid, &sip, &tk, &pers, &cve, &kev, &ja4, &ja4h, &hassh, &meth, &hpath, &rawp, &sum, &iocs, &score, &obs) == nil {
			events = append(events, map[string]any{
				"id": eid, "source_ip": sip, "trap_kind": tk, "persona": pers, "cve_id": cve, "is_kev": kev,
				"ja4": ja4, "ja4h": ja4h, "hassh": hassh, "http_method": meth, "http_path": hpath,
				"raw_payload": rawp, "response_summary": sum, "extracted_iocs": iocs, "severity_score": score, "observed_at": obs,
			})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"incident_id": id, "events": events})
}

func (s *Server) handleGetSSHReplay(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var repID, sip, hassh, user, cast, started string
	var authOK bool
	var cmds []string
	var durMs int64
	err := s.pg.Pool.QueryRow(r.Context(), `
		SELECT id::text, host(source_ip), hassh, username, auth_succeeded, commands, asciicast_v2, duration_ms, started_at::text
		FROM ssh_session_replays WHERE id = $1::uuid OR event_id = $1::uuid
	`, id).Scan(&repID, &sip, &hassh, &user, &authOK, &cmds, &cast, &durMs, &started)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "ssh replay not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id": repID, "source_ip": sip, "hassh": hassh, "username": user, "auth_succeeded": authOK,
		"commands": cmds, "asciicast_v2": cast, "duration_ms": durMs, "started_at": started,
	})
}

func (s *Server) handleListTelemetry(w http.ResponseWriter, r *http.Request) {
	trapFilter := strings.TrimSpace(r.URL.Query().Get("trap"))
	rows, err := s.pg.Pool.Query(r.Context(), `
		SELECT id::text, host(source_ip), dest_port, protocol, trap_kind, persona, cve_id, is_kev,
		       ja4, hassh, http_method, http_path, raw_payload, response_summary,
		       greynoise_classification, severity_score, observed_at::text
		FROM telemetry_events
		WHERE ($1 = '' OR trap_kind = $1)
		ORDER BY observed_at DESC LIMIT 150
	`, trapFilter)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()
	events := make([]map[string]any, 0)
	for rows.Next() {
		var id, sip, proto, tk, pers, cve, ja4, hassh, meth, hpath, rawp, sum, gn, obs string
		var destPort, score int
		var kev bool
		if rows.Scan(&id, &sip, &destPort, &proto, &tk, &pers, &cve, &kev, &ja4, &hassh, &meth, &hpath, &rawp, &sum, &gn, &score, &obs) == nil {
			events = append(events, map[string]any{
				"id": id, "source_ip": sip, "dest_port": destPort, "protocol": proto,
				"trap_kind": tk, "persona": pers, "cve_id": cve, "is_kev": kev,
				"ja4": ja4, "hassh": hassh, "http_method": meth, "http_path": hpath,
				"raw_payload": rawp, "response_summary": sum, "greynoise": gn,
				"severity_score": score, "observed_at": obs,
			})
		}
	}

	replaysRows, _ := s.pg.Pool.Query(r.Context(), `
		SELECT id::text, host(source_ip), username, hassh, auth_succeeded, COALESCE(commands, ARRAY[]::TEXT[]), duration_ms, started_at::text
		FROM ssh_session_replays ORDER BY started_at DESC LIMIT 40
	`)
	replays := make([]map[string]any, 0)
	if replaysRows != nil {
		defer replaysRows.Close()
		for replaysRows.Next() {
			var id, sip, usr, h, st string
			var authOK bool
			var cmds []string
			var d int64
			if replaysRows.Scan(&id, &sip, &usr, &h, &authOK, &cmds, &d, &st) == nil {
				if cmds == nil {
					cmds = []string{}
				}
				replays = append(replays, map[string]any{
					"id":             id,
					"source_ip":      sip,
					"username":       usr,
					"hassh":          h,
					"auth_succeeded": authOK,
					"commands":       cmds,
					"duration_ms":    d,
					"started_at":     st,
				})
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events, "replays": replays})
}
