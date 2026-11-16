package policy

import (
	"context"

	"github.com/harris/honeypot/internal/store"
)

// RuleRow represents a configured row in PostgreSQL policy_rules.
type RuleRow struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Priority        int    `json:"priority"`
	Enabled         bool   `json:"enabled"`
	ConditionsJSON  string `json:"conditions_json"`
	Action          string `json:"action"` // ignore | triage_queue | auto_enforce
	DefaultTTLHours int    `json:"default_ttl_hours"`
	TargetSync      string `json:"target_sync"` // nginx | cloudflare | both
	IsDefaultSeed   bool   `json:"is_default_seed"`
}

// ListRules loads all policy rules ordered ascending by Priority (1 = highest precedence).
func ListRules(ctx context.Context, pg *store.Postgres) ([]RuleRow, error) {
	rows, err := pg.Pool.Query(ctx, `
		SELECT id::text, name, priority, enabled, conditions_json::text, action, default_ttl_hours, target_sync, is_default_seed
		FROM policy_rules
		ORDER BY priority ASC, created_at ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RuleRow
	for rows.Next() {
		var r RuleRow
		if err := rows.Scan(&r.ID, &r.Name, &r.Priority, &r.Enabled, &r.ConditionsJSON, &r.Action, &r.DefaultTTLHours, &r.TargetSync, &r.IsDefaultSeed); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
