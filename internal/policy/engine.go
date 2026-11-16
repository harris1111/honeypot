package policy

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/harris/honeypot/internal/correlation"
	"github.com/harris/honeypot/internal/store"
)

var (
	ErrProtectedAllowlist = errors.New("target overlaps protected allowlist or violates safe minimum CIDR prefix floor")
	ErrInvalidIndicator   = errors.New("invalid network indicator")
)

// NormalizeIndicator canonicalizes IPv4 to /32 and IPv6 addresses to /64 prefixes per Phase 6 contract,
// preserving valid CIDRs while enforcing safe minimum prefix length floors (/24 IPv4, /48 IPv6).
func NormalizeIndicator(indType, raw string) (indTypeOut, canonical string, err error) {
	clean := strings.TrimSpace(raw)
	if indType == "ja4" || indType == "waf_expr" {
		if clean == "" {
			return "", "", ErrInvalidIndicator
		}
		return indType, clean, nil
	}

	if p, pErr := netip.ParsePrefix(clean); pErr == nil {
		un := p.Addr().Unmap()
		bits := p.Bits()
		if un.Is4() {
			if bits < 24 {
				return "", "", fmt.Errorf("%w: IPv4 CIDR /%d too broad (min /24)", ErrProtectedAllowlist, bits)
			}
			out := netip.PrefixFrom(un, bits).Masked()
			if bits == 32 {
				return "ip", un.String(), nil
			}
			return "cidr", out.String(), nil
		}
		if bits < 48 {
			return "", "", fmt.Errorf("%w: IPv6 CIDR /%d too broad (min /48)", ErrProtectedAllowlist, bits)
		}
		if bits > 64 {
			bits = 64
		}
		return "cidr", netip.PrefixFrom(un, bits).Masked().String(), nil
	}

	addr, aErr := netip.ParseAddr(clean)
	if aErr != nil {
		return "", "", fmt.Errorf("%w: %v", ErrInvalidIndicator, aErr)
	}
	un := addr.Unmap()
	if un.Is4() {
		return "ip", un.String(), nil
	}
	// IPv6 attacker canonicalized to /64
	return "cidr", netip.PrefixFrom(un, 64).Masked().String(), nil
}

// ValidateTargetAllowed checks indicator prefix safety AND PostgreSQL GIST `cidr && $1::inet` allowlist overlap.
func ValidateTargetAllowed(ctx context.Context, pg *store.Postgres, indType, raw string) (normType, normVal string, err error) {
	normType, normVal, err = NormalizeIndicator(indType, raw)
	if err != nil {
		return "", "", err
	}
	if normType != "ip" && normType != "cidr" {
		return normType, normVal, nil
	}
	overlap, err := pg.CheckAllowlistOverlap(ctx, normVal)
	if err != nil {
		return "", "", err
	}
	if overlap {
		return "", "", fmt.Errorf("%w: %s overlaps protected_allowlist", ErrProtectedAllowlist, normVal)
	}
	return normType, normVal, nil
}

// EvalOutcome describes what Policy Engine decided for an incident.
type EvalOutcome struct {
	MatchedRuleName string `json:"matched_rule_name"`
	Action          string `json:"action"` // allowlist_stop | ignore | triage_queue | auto_enforce | none
	DecisionID      string `json:"decision_id,omitempty"`
	IndicatorValue  string `json:"indicator_value,omitempty"`
}

// Engine evaluates protected allowlists & ordered policy rules for incidents,
// maintaining Zero Blind Auto-Ban defaults.
type Engine struct {
	pg *store.Postgres
	onAutoEnforced func(ctx context.Context, decisionID string)
}

// NewEngine creates a Policy Engine backed by PostgreSQL.
func NewEngine(pg *store.Postgres, onAutoEnforced func(ctx context.Context, decisionID string)) *Engine {
	return &Engine{pg: pg, onAutoEnforced: onAutoEnforced}
}

// EvaluateIncident inspects protected allowlist first, then runs enabled policy rules sorted by Priority ASC.
func (e *Engine) EvaluateIncident(ctx context.Context, inc correlation.IncidentSnapshot) (EvalOutcome, error) {
	if e == nil || e.pg == nil || inc.PrimaryIP == "" {
		return EvalOutcome{Action: "none"}, nil
	}

	// Step 1: Hard Protected Allowlist check
	indType, indVal, err := ValidateTargetAllowed(ctx, e.pg, "ip", inc.PrimaryIP)
	if err != nil {
		_ = e.pg.InsertAuditLog(ctx, "policy_engine", "allowlist_hit", "attack_incident", inc.ID, map[string]any{
			"ip":     inc.PrimaryIP,
			"reason": err.Error(),
		}, inc.PrimaryIP)
		return EvalOutcome{Action: "allowlist_stop", IndicatorValue: inc.PrimaryIP}, nil
	}

	// Also reject if ANY related_ip overlaps protected allowlist (canonicalizing ::ffff: first)
	for _, rip := range inc.RelatedIPs {
		normVal := rip
		if addr, err := netip.ParseAddr(strings.TrimSpace(rip)); err == nil {
			normVal = addr.Unmap().String()
		}
		if overlap, _ := e.pg.CheckAllowlistOverlap(ctx, normVal); overlap {
			_ = e.pg.InsertAuditLog(ctx, "policy_engine", "allowlist_hit", "attack_incident", inc.ID, map[string]any{
				"related_ip": normVal,
			}, normVal)
			return EvalOutcome{Action: "allowlist_stop", IndicatorValue: normVal}, nil
		}
	}

	// Step 2: Load rules in strict priority order
	rules, err := ListRules(ctx, e.pg)
	if err != nil {
		return EvalOutcome{}, err
	}

	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		if !EvaluateCondition(rule.ConditionsJSON, inc) {
			continue
		}

		switch rule.Action {
		case "ignore":
			// Priority 1 Benign suppression: auto-dismiss stale pending approvals so Shodan/Censys never trigger alerts
			_, _ = e.pg.Pool.Exec(ctx, `
				UPDATE guard_decisions
				SET status = 'rejected', reason = $2, updated_at = NOW()
				WHERE indicator_value = $1 AND status = 'pending_approval'
			`, indVal, "Auto-dismissed by rule: "+rule.Name)
			return EvalOutcome{MatchedRuleName: rule.Name, Action: "ignore", IndicatorValue: indVal}, nil

		case "triage_queue", "auto_enforce":
			status := "pending_approval"
			decidedBy := ""
			if rule.Action == "auto_enforce" {
				status = "approved"
				decidedBy = "policy_rule:" + rule.Name
			}
			var decID string
			// Idempotent active check matching uq_guard_decisions_active_indicator (includes pending_unban)
			_ = e.pg.Pool.QueryRow(ctx, `
				SELECT id::text FROM guard_decisions
				WHERE indicator_value = $1 AND status IN ('pending_approval', 'approved', 'enforced', 'pending_unban')
				LIMIT 1
			`, indVal).Scan(&decID)

			if decID == "" {
				var incPtr *string
				if strings.TrimSpace(inc.ID) != "" {
					idCopy := inc.ID
					incPtr = &idCopy
				}
				err := e.pg.Pool.QueryRow(ctx, `
					INSERT INTO guard_decisions (
						incident_id, rule_id, indicator_type, indicator_value, target_sync,
						status, decided_by, reason, ttl_expires_at
					) VALUES (
						$1::uuid, $2::uuid, $3, $4, $5,
						$6, $7, $8,
						CASE WHEN $9 > 0 THEN NOW() + ($9 || ' hours')::interval ELSE NULL END
					)
					RETURNING id::text
				`, incPtr, rule.ID, indType, indVal, rule.TargetSync, status, decidedBy, "Matched rule: "+rule.Name, rule.DefaultTTLHours).Scan(&decID)
				if err != nil {
					return EvalOutcome{}, err
				}
			}
			if rule.Action == "auto_enforce" && e.onAutoEnforced != nil {
				e.onAutoEnforced(ctx, decID)
			}
			return EvalOutcome{
				MatchedRuleName: rule.Name,
				Action:          rule.Action,
				DecisionID:      decID,
				IndicatorValue:  indVal,
			}, nil
		}
	}

	return EvalOutcome{Action: "none", IndicatorValue: indVal}, nil
}
