package adminapi

import (
	"fmt"
	"math"
	"net/http"
	"time"

	"github.com/harris/honeypot/internal/enrichment"
)

type radarBucket struct {
	BucketISO string `json:"bucket_iso"`
	Label     string `json:"label"`
	Cowrie    int64  `json:"cowrie"`
	WebCVE    int64  `json:"webcve"`
	LLMProxy  int64  `json:"llmproxy"`
	InfraTrap int64  `json:"infratrap"`
	Heralding int64  `json:"heralding"`
	Total     int64  `json:"total"`
}

func (s *Server) handleLiveRadar(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	window := r.URL.Query().Get("window")
	if window != "24h" {
		window = "60m"
	}

	var events24h, events60m, events5m, uniqueIPs24h, critical24h, sshIntrusions24h, activeBans, onlineSensors int64
	_ = s.pg.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM telemetry_events WHERE observed_at >= NOW() - INTERVAL '24 hours'`).Scan(&events24h)
	_ = s.pg.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM telemetry_events WHERE observed_at >= NOW() - INTERVAL '60 minutes'`).Scan(&events60m)
	_ = s.pg.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM telemetry_events WHERE observed_at >= NOW() - INTERVAL '5 minutes'`).Scan(&events5m)
	_ = s.pg.Pool.QueryRow(ctx, `SELECT COUNT(DISTINCT source_ip) FROM telemetry_events WHERE observed_at >= NOW() - INTERVAL '24 hours'`).Scan(&uniqueIPs24h)
	_ = s.pg.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM telemetry_events WHERE observed_at >= NOW() - INTERVAL '24 hours' AND (severity_score >= 80 OR is_kev OR canary_key_id IS NOT NULL)`).Scan(&critical24h)
	_ = s.pg.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM ssh_session_replays WHERE started_at >= NOW() - INTERVAL '24 hours'`).Scan(&sshIntrusions24h)
	_ = s.pg.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM guard_decisions WHERE status IN ('approved', 'enforced')`).Scan(&activeBans)
	_ = s.pg.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM sensor_nodes WHERE status = 'online'`).Scan(&onlineSensors)

	evPerMin := math.Round((float64(events5m)/5.0)*10) / 10

	// Active/registered sensors (target nodes on the world threat map)
	sensorNodes := make([]map[string]any, 0)
	if rows, err := s.pg.Pool.Query(ctx, `
		SELECT id::text, name, region, COALESCE(host(public_ipv4), ''), status
		FROM sensor_nodes
		ORDER BY (status = 'online') DESC, created_at ASC
		LIMIT 20
	`); err == nil {
		defer rows.Close()
		for rows.Next() {
			var id, name, region, pubIP, status string
			if rows.Scan(&id, &name, &region, &pubIP, &status) == nil {
				sensorNodes = append(sensorNodes, map[string]any{
					"id":        id,
					"name":      name,
					"region":    region,
					"public_ip": pubIP,
					"status":    status,
					"geo":       enrichment.ResolveSensorGeoPoint(region, pubIP),
				})
			}
		}
	}
	if len(sensorNodes) == 0 {
		sensorNodes = append(sensorNodes, map[string]any{
			"id":        "hive-default-sensor",
			"name":      "primary-honeypot-sensor",
			"region":    "default",
			"public_ip": "",
			"status":    "online",
			"geo":       enrichment.ResolveSensorGeoPoint("default", ""),
		})
	}

	// Timeline series (30x2m for 60m window or 24x1h for 24h window)
	numSlots := 30
	stepSecs := 120.0
	intervalExpr := "60 minutes"
	labelFmt := "15:04"
	if window == "24h" {
		numSlots = 24
		stepSecs = 3600.0
		intervalExpr = "24 hours"
		labelFmt = "15:00"
	}

	nowUTC := time.Now().UTC()
	timeline := make([]radarBucket, numSlots)
	for i := 0; i < numSlots; i++ {
		ageSlots := numSlots - 1 - i
		ts := nowUTC.Add(-time.Duration(float64(ageSlots)*stepSecs) * time.Second)
		timeline[i] = radarBucket{
			BucketISO: ts.Format(time.RFC3339),
			Label:     ts.Format(labelFmt),
		}
	}

	slotSQL := fmt.Sprintf(`
		SELECT LEAST(%d, GREATEST(0, floor(extract(epoch from (NOW() - observed_at)) / %v)::int)) AS age_slot,
		       trap_kind,
		       COUNT(*)
		FROM telemetry_events
		WHERE observed_at >= NOW() - INTERVAL '%s'
		GROUP BY age_slot, trap_kind
	`, numSlots-1, int(stepSecs), intervalExpr)

	if rows, err := s.pg.Pool.Query(ctx, slotSQL); err == nil {
		defer rows.Close()
		for rows.Next() {
			var ageSlot int
			var tk string
			var cnt int64
			if rows.Scan(&ageSlot, &tk, &cnt) == nil {
				idx := numSlots - 1 - ageSlot
				if idx < 0 || idx >= numSlots {
					continue
				}
				switch tk {
				case "cowrie":
					timeline[idx].Cowrie += cnt
				case "webcve":
					timeline[idx].WebCVE += cnt
				case "llmproxy":
					timeline[idx].LLMProxy += cnt
				case "infratrap":
					timeline[idx].InfraTrap += cnt
				case "heralding":
					timeline[idx].Heralding += cnt
				}
				timeline[idx].Total += cnt
			}
		}
	}

	// 5-stage Kill-Chain funnel (24h window)
	var bruteCount, exploitCount, credAbuseCount, containCount int64
	_ = s.pg.Pool.QueryRow(ctx, `
		SELECT (SELECT COUNT(*) FROM telemetry_events WHERE observed_at >= NOW() - INTERVAL '24 hours' AND trap_kind IN ('cowrie', 'heralding'))
		     + (SELECT COUNT(*) FROM ssh_session_replays WHERE started_at >= NOW() - INTERVAL '24 hours' AND NOT auth_succeeded)
	`).Scan(&bruteCount)
	_ = s.pg.Pool.QueryRow(ctx, `
		SELECT (SELECT COUNT(*) FROM telemetry_events WHERE observed_at >= NOW() - INTERVAL '24 hours' AND (severity_score >= 70 OR is_kev))
		     + (SELECT COUNT(*) FROM ssh_session_replays WHERE started_at >= NOW() - INTERVAL '24 hours' AND cardinality(commands) > 0)
	`).Scan(&exploitCount)
	_ = s.pg.Pool.QueryRow(ctx, `
		SELECT (SELECT COUNT(*) FROM llm_conversations WHERE created_at >= NOW() - INTERVAL '24 hours')
		     + (SELECT COALESCE(SUM(hit_count), 0) FROM canary_keys)
	`).Scan(&credAbuseCount)
	_ = s.pg.Pool.QueryRow(ctx, `
		SELECT (SELECT COUNT(*) FROM malware_artifacts)
		     + (SELECT COUNT(*) FROM guard_decisions WHERE status IN ('pending_approval', 'approved', 'enforced'))
	`).Scan(&containCount)

	killChain := []map[string]any{
		{"stage": "recon", "label": "Recon & Service Scans", "description": "Port, banner, model & CVE discovery probes", "count": events24h},
		{"stage": "bruteforce", "label": "Credential & Auth Probes", "description": "SSH/Telnet/FTP/Mail login attempts", "count": bruteCount},
		{"stage": "exploitation", "label": "Shell & Exploit Attempts", "description": "High-severity CVE payloads & interactive SSH commands", "count": exploitCount},
		{"stage": "credential_abuse", "label": "Canary & AI Gateway Abuse", "description": "Stolen honey keys or AI prompt injection/probing", "count": credAbuseCount},
		{"stage": "containment", "label": "Quarantined & Mitigated", "description": "Captured malware artifacts & Guard block rules", "count": containCount},
	}

	// Top targeted ports & trap matrix
	vectorMatrix := make([]map[string]any, 0)
	if rows, err := s.pg.Pool.Query(ctx, `
		SELECT dest_port, protocol, trap_kind, COUNT(*) AS cnt, COUNT(DISTINCT source_ip) AS uips, COALESCE(MAX(severity_score), 0)
		FROM telemetry_events
		WHERE observed_at >= NOW() - INTERVAL '24 hours'
		GROUP BY dest_port, protocol, trap_kind
		ORDER BY cnt DESC
		LIMIT 12
	`); err == nil {
		defer rows.Close()
		for rows.Next() {
			var port, maxSev int
			var proto, tk string
			var cnt, uips int64
			if rows.Scan(&port, &proto, &tk, &cnt, &uips, &maxSev) == nil {
				vectorMatrix = append(vectorMatrix, map[string]any{
					"dest_port":    port,
					"protocol":     proto,
					"trap_kind":    tk,
					"count":        cnt,
					"unique_ips":   uips,
					"max_severity": maxSev,
				})
			}
		}
	}

	// Top attacker origins with offline GeoIP/RIR coordinates
	attackOrigins := make([]map[string]any, 0)
	if rows, err := s.pg.Pool.Query(ctx, `
		SELECT host(te.source_ip),
		       COUNT(*) AS cnt,
		       COUNT(DISTINCT te.trap_kind) AS dtraps,
		       COALESCE((ARRAY_AGG(te.trap_kind ORDER BY te.severity_score DESC, te.observed_at DESC))[1], ''),
		       COALESCE((ARRAY_AGG(te.dest_port ORDER BY te.severity_score DESC, te.observed_at DESC))[1], 0),
		       COALESCE(MAX(te.severity_score), 0),
		       MAX(te.observed_at)::text,
		       COALESCE(MAX(NULLIF(te.country_code, '')), MAX(NULLIF(ai.country_code, '')), ''),
		       COALESCE(MAX(NULLIF(te.greynoise_classification, 'unknown')), MAX(NULLIF(ai.greynoise_classification, 'unknown')), 'unknown'),
		       COALESCE(MAX(te.asn), MAX(ai.asn), 0),
		       COALESCE(MAX(te.abuseipdb_score), MAX(ai.abuseipdb_score), 0)
		FROM telemetry_events te
		LEFT JOIN attack_incidents ai ON ai.id = te.incident_id
		WHERE te.observed_at >= NOW() - INTERVAL '24 hours'
		GROUP BY te.source_ip
		ORDER BY cnt DESC, MAX(te.severity_score) DESC
		LIMIT 36
	`); err == nil {
		defer rows.Close()
		for rows.Next() {
			var ip, topTrap, lastSeen, cc, gn string
			var topPort, maxSev, asn, abScore int
			var cnt, dtraps int64
			if rows.Scan(&ip, &cnt, &dtraps, &topTrap, &topPort, &maxSev, &lastSeen, &cc, &gn, &asn, &abScore) == nil {
				attackOrigins = append(attackOrigins, map[string]any{
					"ip":             ip,
					"count":          cnt,
					"distinct_traps": dtraps,
					"top_trap":       topTrap,
					"top_port":       topPort,
					"max_severity":   maxSev,
					"last_seen_at":   lastSeen,
					"greynoise":      gn,
					"asn":            asn,
					"abuse_score":    abScore,
					"geo":            enrichment.ResolveIPGeoPoint(ip, cc),
				})
			}
		}
	}

	// Top commands typed by SSH attackers
	topCommands := make([]map[string]any, 0)
	if rows, err := s.pg.Pool.Query(ctx, `
		SELECT trim(cmd) AS c, COUNT(*) AS cnt
		FROM ssh_session_replays, unnest(commands) AS cmd
		WHERE started_at >= NOW() - INTERVAL '7 days' AND trim(cmd) <> ''
		GROUP BY c
		ORDER BY cnt DESC
		LIMIT 12
	`); err == nil {
		defer rows.Close()
		for rows.Next() {
			var cmd string
			var cnt int64
			if rows.Scan(&cmd, &cnt) == nil {
				topCommands = append(topCommands, map[string]any{
					"command": cmd,
					"count":   cnt,
				})
			}
		}
	}

	// Latest 60 enriched events across all traps
	recentFeed := make([]map[string]any, 0)
	if rows, err := s.pg.Pool.Query(ctx, `
		SELECT te.id::text, host(te.source_ip), te.dest_port, te.protocol, te.trap_kind, te.persona,
		       te.cve_id, te.is_kev, te.http_method, te.http_path, LEFT(te.raw_payload, 1024),
		       te.response_summary, te.severity_score, (te.canary_key_id IS NOT NULL),
		       te.observed_at::text, COALESCE(te.country_code, ''), COALESCE(sr.id::text, '')
		FROM telemetry_events te
		LEFT JOIN ssh_session_replays sr ON sr.node_id = te.node_id AND sr.event_id = te.id
		ORDER BY te.observed_at DESC
		LIMIT 60
	`); err == nil {
		defer rows.Close()
		for rows.Next() {
			var id, sip, proto, tk, pers, cve, meth, hpath, rawp, sum, obs, cc, replayID string
			var port, score int
			var kev, canaryHit bool
			if rows.Scan(&id, &sip, &port, &proto, &tk, &pers, &cve, &kev, &meth, &hpath, &rawp, &sum, &score, &canaryHit, &obs, &cc, &replayID) == nil {
				recentFeed = append(recentFeed, map[string]any{
					"id":               id,
					"source_ip":        sip,
					"dest_port":        port,
					"protocol":         proto,
					"trap_kind":        tk,
					"persona":          pers,
					"cve_id":           cve,
					"is_kev":           kev,
					"http_method":      meth,
					"http_path":        hpath,
					"raw_payload":      rawp,
					"response_summary": sum,
					"severity_score":   score,
					"canary_hit":       canaryHit,
					"observed_at":      obs,
					"ssh_replay_id":    replayID,
					"geo":              enrichment.ResolveIPGeoPoint(sip, cc),
				})
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"window": window,
		"kpis": map[string]any{
			"events_24h":          events24h,
			"events_60m":          events60m,
			"events_5m":           events5m,
			"events_per_min":      evPerMin,
			"unique_ips_24h":      uniqueIPs24h,
			"critical_events_24h": critical24h,
			"ssh_intrusions_24h":  sshIntrusions24h,
			"active_bans":         activeBans,
			"online_sensors":      onlineSensors,
		},
		"sensor_nodes":   sensorNodes,
		"timeline":       timeline,
		"kill_chain":     killChain,
		"vector_matrix":  vectorMatrix,
		"attack_origins": attackOrigins,
		"top_commands":   topCommands,
		"recent_feed":    recentFeed,
	})
}
