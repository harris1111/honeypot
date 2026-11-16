package correlation

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/harris/honeypot/internal/store"
	honeypotv1 "github.com/harris/honeypot/proto/gen/honeypot/v1"
)

// IncidentSnapshot represents an upserted correlated attack incident handed off to the Policy Engine.
type IncidentSnapshot struct {
	ID                       string   `json:"id"`
	CorrelationKey           string   `json:"correlation_key"`
	Title                    string   `json:"title"`
	Severity                 string   `json:"severity"`
	ConfidenceScore          int      `json:"confidence_score"`
	PrimaryIP                string   `json:"primary_ip"`
	RelatedIPs               []string `json:"related_ips"`
	TrapKinds                []string `json:"trap_kinds"`
	CVEIDs                   []string `json:"cve_ids"`
	CanaryKeyIDs             []string `json:"canary_key_ids"`
	MalwareSHA256s           []string `json:"malware_sha256s"`
	YaraMatchCount           int      `json:"yara_match_count"`
	GreyNoiseClassification  string   `json:"greynoise_classification"`
	AbuseIPDBScore           int      `json:"abuseipdb_score"`
	IsKEV                    bool     `json:"is_kev"`
	JA4                      string   `json:"ja4"`
}

// Engine correlates TelemetryEvents across IPs (shared Canary keys, malware hashes, C2 URLs,
// SSH public keys, or rare JA4 + CVE) into attack_incidents and notifies the Policy Engine.
type Engine struct {
	pg                *store.Postgres
	onIncidentUpdated func(ctx context.Context, inc IncidentSnapshot)
}

// NewEngine creates the Multi-IP Kill-Chain Correlator.
func NewEngine(pg *store.Postgres, onUpdated func(ctx context.Context, inc IncidentSnapshot)) *Engine {
	return &Engine{pg: pg, onIncidentUpdated: onUpdated}
}

// CorrelateEvent links an incoming TelemetryEvent into an attack_incident and triggers Policy evaluation.
func (e *Engine) CorrelateEvent(ctx context.Context, ev *honeypotv1.TelemetryEvent) (IncidentSnapshot, error) {
	if e == nil || e.pg == nil || ev == nil || ev.GetSourceIp() == "" {
		return IncidentSnapshot{}, nil
	}

	corrKey, title, extraScore := deriveCorrelationKey(ev)
	sevScore := int(ev.GetSeverityScore())
	if extraScore > sevScore {
		sevScore = extraScore
	}
	if sevScore > 100 {
		sevScore = 100
	}

	var canaryArr []string
	if ev.GetCanaryKeyId() != "" {
		canaryArr = []string{ev.GetCanaryKeyId()}
	} else {
		canaryArr = []string{}
	}
	var cveArr []string
	if ev.GetCveId() != "" {
		cveArr = []string{ev.GetCveId()}
	} else {
		cveArr = []string{}
	}
	var shaArr []string
	if ev.GetArtifactSha256() != "" {
		shaArr = []string{ev.GetArtifactSha256()}
	} else {
		shaArr = []string{}
	}
	trapArr := []string{}
	if ev.GetTrapKind() != "" {
		trapArr = []string{ev.GetTrapKind()}
	}

	var inc IncidentSnapshot
	err := e.pg.Pool.QueryRow(ctx, `
		INSERT INTO attack_incidents (
			correlation_key, title, severity, confidence_score, primary_ip, related_ips,
			trap_kinds, cve_ids, canary_key_ids, malware_sha256s, first_seen_at, last_seen_at
		) VALUES (
			$1, $2, $3, $4, $5::inet, ARRAY[$5::inet],
			$6, $7, $8::uuid[], $9, NOW(), NOW()
		)
		ON CONFLICT (correlation_key) DO UPDATE
		SET last_seen_at = NOW(),
		    confidence_score = GREATEST(attack_incidents.confidence_score, EXCLUDED.confidence_score),
		    severity = CASE
		        WHEN GREATEST(attack_incidents.confidence_score, EXCLUDED.confidence_score) >= 90 THEN 'critical'
		        WHEN GREATEST(attack_incidents.confidence_score, EXCLUDED.confidence_score) >= 70 THEN 'high'
		        WHEN GREATEST(attack_incidents.confidence_score, EXCLUDED.confidence_score) >= 40 THEN 'medium'
		        ELSE 'low'
		    END,
		    related_ips = (SELECT ARRAY(SELECT DISTINCT x FROM unnest(attack_incidents.related_ips || EXCLUDED.related_ips) AS x)),
		    trap_kinds = (SELECT ARRAY(SELECT DISTINCT x FROM unnest(attack_incidents.trap_kinds || EXCLUDED.trap_kinds) AS x WHERE x <> '')),
		    cve_ids = (SELECT ARRAY(SELECT DISTINCT x FROM unnest(attack_incidents.cve_ids || EXCLUDED.cve_ids) AS x WHERE x <> '')),
		    canary_key_ids = (SELECT ARRAY(SELECT DISTINCT x FROM unnest(attack_incidents.canary_key_ids || EXCLUDED.canary_key_ids) AS x)),
		    malware_sha256s = (SELECT ARRAY(SELECT DISTINCT x FROM unnest(attack_incidents.malware_sha256s || EXCLUDED.malware_sha256s) AS x WHERE x <> ''))
		RETURNING id::text, correlation_key, title, severity, confidence_score, host(primary_ip),
		          ARRAY(SELECT host(x) FROM unnest(related_ips) AS x), trap_kinds, cve_ids,
		          ARRAY(SELECT x::text FROM unnest(canary_key_ids) AS x), malware_sha256s,
		          yara_match_count, greynoise_classification, abuseipdb_score
	`, corrKey, title, scoreToSeverity(sevScore), sevScore, ev.GetSourceIp(),
		trapArr, cveArr, canaryArr, shaArr).Scan(
		&inc.ID, &inc.CorrelationKey, &inc.Title, &inc.Severity, &inc.ConfidenceScore, &inc.PrimaryIP,
		&inc.RelatedIPs, &inc.TrapKinds, &inc.CVEIDs, &inc.CanaryKeyIDs, &inc.MalwareSHA256s,
		&inc.YaraMatchCount, &inc.GreyNoiseClassification, &inc.AbuseIPDBScore,
	)
	if err != nil {
		return IncidentSnapshot{}, err
	}
	inc.IsKEV = ev.GetIsKev()
	inc.JA4 = ev.GetJa4()

	if ev.GetEventUuid() != "" {
		_, _ = e.pg.Pool.Exec(ctx, `
			UPDATE telemetry_events SET incident_id = $1::uuid WHERE id = $2::uuid AND node_id = $3::uuid
		`, inc.ID, ev.GetEventUuid(), ev.GetNodeId())
	}

	if e.onIncidentUpdated != nil {
		e.onIncidentUpdated(ctx, inc)
	}
	return inc, nil
}

// ReevaluateAfterEnrichment updates incident IP reputation / YARA counts when async background jobs finish
// and re-triggers the Policy Engine cleanly.
func (e *Engine) ReevaluateAfterEnrichment(ctx context.Context, ip, gnClass string, abuseScore int, artifactSHA string, yaraMatches []string) error {
	if e == nil || e.pg == nil {
		return nil
	}
	if ip != "" && gnClass != "" {
		_, _ = e.pg.Pool.Exec(ctx, `
			UPDATE attack_incidents
			SET greynoise_classification = $2,
			    abuseipdb_score = CASE WHEN $3 > abuseipdb_score THEN $3 ELSE abuseipdb_score END
			WHERE primary_ip = $1::inet OR $1::inet = ANY(related_ips)
		`, ip, gnClass, abuseScore)
	}
	if artifactSHA != "" && len(yaraMatches) > 0 {
		_, _ = e.pg.Pool.Exec(ctx, `
			UPDATE attack_incidents
			SET yara_match_count = yara_match_count + $2,
			    confidence_score = LEAST(100, confidence_score + 20),
			    severity = 'critical'
			WHERE $1 = ANY(malware_sha256s)
		`, artifactSHA, len(yaraMatches))
	}

	// Reload affected incidents and trigger Policy Engine re-evaluation
	rows, err := e.pg.Pool.Query(ctx, `
		SELECT id::text, correlation_key, title, severity, confidence_score, host(primary_ip),
		       ARRAY(SELECT host(x) FROM unnest(related_ips) AS x), trap_kinds, cve_ids,
		       ARRAY(SELECT x::text FROM unnest(canary_key_ids) AS x), malware_sha256s,
		       yara_match_count, greynoise_classification, abuseipdb_score
		FROM attack_incidents
		WHERE ($1 <> '' AND (primary_ip = $1::inet OR $1::inet = ANY(related_ips)))
		   OR ($2 <> '' AND $2 = ANY(malware_sha256s))
	`, ip, artifactSHA)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var inc IncidentSnapshot
		if err := rows.Scan(
			&inc.ID, &inc.CorrelationKey, &inc.Title, &inc.Severity, &inc.ConfidenceScore, &inc.PrimaryIP,
			&inc.RelatedIPs, &inc.TrapKinds, &inc.CVEIDs, &inc.CanaryKeyIDs, &inc.MalwareSHA256s,
			&inc.YaraMatchCount, &inc.GreyNoiseClassification, &inc.AbuseIPDBScore,
		); err == nil && e.onIncidentUpdated != nil {
			e.onIncidentUpdated(ctx, inc)
		}
	}
	return rows.Err()
}

func deriveCorrelationKey(ev *honeypotv1.TelemetryEvent) (key, title string, minScore int) {
	if ev.GetCanaryKeyId() != "" {
		return "canary:" + ev.GetCanaryKeyId(), "Kill-Chain: Canary Key Stolen & Reused", 100
	}
	if ev.GetArtifactSha256() != "" {
		return "sha256:" + ev.GetArtifactSha256(), "Malware Dropper Distribution (" + ev.GetArtifactSha256()[:12] + ")", 85
	}
	var iocs map[string]any
	_ = json.Unmarshal([]byte(ev.GetExtractedIocsJson()), &iocs)
	if urlsRaw, ok := iocs["urls"].([]any); ok && len(urlsRaw) > 0 {
		if first, ok := urlsRaw[0].(string); ok {
			if u, err := url.Parse(first); err == nil && u.Host != "" {
				return "c2:" + strings.ToLower(u.Host+u.Path), "C2 Payload URL Campaign (" + u.Host + ")", 80
			}
		}
	}
	if ev.GetJa4() != "" && ev.GetCveId() != "" {
		return fmt.Sprintf("ja4cve:%s:%s", ev.GetJa4(), ev.GetCveId()), fmt.Sprintf("Fingerprinted Scanner Campaign (%s)", ev.GetCveId()), int(ev.GetSeverityScore())
	}
	cveTag := ev.GetCveId()
	if cveTag == "" {
		cveTag = ev.GetTrapKind()
	}
	return "ip:" + ev.GetSourceIp() + ":" + cveTag, fmt.Sprintf("Targeted Probe from %s (%s)", ev.GetSourceIp(), cveTag), int(ev.GetSeverityScore())
}

func scoreToSeverity(score int) string {
	switch {
	case score >= 90:
		return "critical"
	case score >= 70:
		return "high"
	case score >= 40:
		return "medium"
	default:
		return "low"
	}
}
