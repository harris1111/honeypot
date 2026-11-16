package guard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/harris/honeypot/internal/pki"
	"github.com/harris/honeypot/internal/policy"
	"github.com/harris/honeypot/internal/store"
)

// DecisionRow represents a row in guard_decisions for Admin UI & enforcement workers.
type DecisionRow struct {
	ID               string  `json:"id"`
	IncidentID       *string `json:"incident_id,omitempty"`
	IndicatorType    string  `json:"indicator_type"`
	IndicatorValue   string  `json:"indicator_value"`
	TargetSync       string  `json:"target_sync"`
	Status           string  `json:"status"`
	DecidedBy        string  `json:"decided_by"`
	Reason           string  `json:"reason"`
	TTLExpiresAt     *string `json:"ttl_expires_at,omitempty"`
	CloudflareItemID string  `json:"cloudflare_item_id"`
	NginxRevision    int64   `json:"nginx_revision"`
	CreatedAt        string  `json:"created_at"`
	UpdatedAt        string  `json:"updated_at"`
}

// Manager orchestrates human-approved guard decisions, Cloudflare Custom List sync,
// Ed25519 Nginx feeds, emergency rollbacks, and expired TTL reclamation.
type Manager struct {
	pg         *store.Postgres
	cf         *CloudflareSync
	feedSigner *FeedSigner
}

// NewManager initializes the Active Guard orchestration manager on Central Hive.
func NewManager(ca *pki.CA, pg *store.Postgres, cf *CloudflareSync) *Manager {
	return &Manager{
		pg:         pg,
		cf:         cf,
		feedSigner: NewFeedSigner(ca, pg),
	}
}

// ServeSignedNginxFeed serves the mTLS-protected signed Nginx feed endpoint on :9443.
func (m *Manager) ServeSignedNginxFeed(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	feed, _, err := m.feedSigner.BuildSignedNginxFeed(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(feed)
}

// ApproveDecision transitions pending_approval -> approved/enforced, enforces allowlists, syncs Cloudflare,
// advances guard_feed_revision_seq, and writes audit_logs.
func (m *Manager) ApproveDecision(ctx context.Context, decisionID, actor, targetSyncOverride string, ttlHours int) error {
	var indType, indVal, targetSync string
	err := m.pg.Pool.QueryRow(ctx, `
		SELECT indicator_type, indicator_value, target_sync
		FROM guard_decisions WHERE id = $1::uuid
	`, decisionID).Scan(&indType, &indVal, &targetSync)
	if err != nil {
		return err
	}
	if targetSyncOverride != "" {
		targetSync = targetSyncOverride
	}
	if _, _, err := policy.ValidateTargetAllowed(ctx, m.pg, indType, indVal); err != nil {
		return err
	}
	if (targetSync == "nginx" || targetSync == "both") && indType != "ip" && indType != "cidr" {
		return fmt.Errorf("nginx target supports ip/cidr indicators only, got %s", indType)
	}

	rev, err := m.pg.NextFeedRevision(ctx)
	if err != nil {
		return err
	}

	var cfID string
	status := "approved"
	if (targetSync == "cloudflare" || targetSync == "both") && m.cf != nil && m.cf.IsConfigured() {
		id, cfErr := m.cf.AddItem(ctx, indVal, "Honeypot Guard approved by "+actor)
		if cfErr == nil && id != "" {
			cfID = id
			status = "enforced"
		}
	}

	_, err = m.pg.Pool.Exec(ctx, `
		UPDATE guard_decisions
		SET status = $2,
		    target_sync = $3,
		    decided_by = $4,
		    cloudflare_item_id = COALESCE(NULLIF($5, ''), cloudflare_item_id),
		    nginx_revision = $6,
		    ttl_expires_at = CASE WHEN $7 > 0 THEN NOW() + ($7 || ' hours')::interval ELSE ttl_expires_at END,
		    updated_at = NOW()
		WHERE id = $1::uuid
	`, decisionID, status, targetSync, actor, cfID, rev, ttlHours)
	if err != nil {
		return err
	}
	return m.pg.InsertAuditLog(ctx, actor, "guard_approve", "guard_decision", decisionID, map[string]any{
		"indicator": indVal, "target_sync": targetSync, "revision": rev,
	}, "")
}

// RejectDecision marks a pending decision rejected cleanly.
func (m *Manager) RejectDecision(ctx context.Context, decisionID, actor, reason string) error {
	_, err := m.pg.Pool.Exec(ctx, `
		UPDATE guard_decisions
		SET status = 'rejected', decided_by = $2, reason = COALESCE(NULLIF($3, ''), reason), updated_at = NOW()
		WHERE id = $1::uuid
	`, decisionID, actor, reason)
	if err != nil {
		return err
	}
	return m.pg.InsertAuditLog(ctx, actor, "guard_reject", "guard_decision", decisionID, map[string]any{"reason": reason}, "")
}

// ManualBlock enforces allowlist + /24/48 floors + chk_nginx_ip_cidr_only and immediately stages/enforces a block.
func (m *Manager) ManualBlock(ctx context.Context, indType, indVal, targetSync string, ttlHours int, actor, reason string) (string, error) {
	normType, normVal, err := policy.ValidateTargetAllowed(ctx, m.pg, indType, indVal)
	if err != nil {
		return "", err
	}
	if (targetSync == "nginx" || targetSync == "both") && normType != "ip" && normType != "cidr" {
		return "", fmt.Errorf("nginx/both target requires ip or cidr")
	}

	rev, err := m.pg.NextFeedRevision(ctx)
	if err != nil {
		return "", err
	}
	var id string
	err = m.pg.Pool.QueryRow(ctx, `
		INSERT INTO guard_decisions (indicator_type, indicator_value, target_sync, status, decided_by, reason, nginx_revision, ttl_expires_at)
		VALUES ($1, $2, $3, 'pending_approval', $4, $5, $6, CASE WHEN $7 > 0 THEN NOW() + ($7 || ' hours')::interval ELSE NULL END)
		RETURNING id::text
	`, normType, normVal, targetSync, actor, reason, rev, ttlHours).Scan(&id)
	if err != nil {
		return "", err
	}
	if err := m.ApproveDecision(ctx, id, actor, targetSync, ttlHours); err != nil {
		return "", err
	}
	return id, nil
}

// UnbanOrRollback moves decision to pending_unban, drops from Nginx feed immediately,
// deletes from Cloudflare Custom List, and transitions to rolled_back.
func (m *Manager) UnbanOrRollback(ctx context.Context, decisionID, actor, reason string) error {
	var indVal, cfID string
	err := m.pg.Pool.QueryRow(ctx, `
		UPDATE guard_decisions
		SET status = 'pending_unban', decided_by = $2, reason = COALESCE(NULLIF($3, ''), reason), updated_at = NOW()
		WHERE id = $1::uuid
		RETURNING indicator_value, cloudflare_item_id
	`, decisionID, actor, reason).Scan(&indVal, &cfID)
	if err != nil {
		return err
	}

	rev, _ := m.pg.NextFeedRevision(ctx)
	if m.cf != nil && m.cf.IsConfigured() {
		if delErr := m.cf.DeleteByIPOrID(ctx, cfID, indVal); delErr != nil {
			// Keep in pending_unban for background retry rather than falsely claiming rolled_back
			return delErr
		}
	}

	_, err = m.pg.Pool.Exec(ctx, `
		UPDATE guard_decisions
		SET status = 'rolled_back', nginx_revision = $2, updated_at = NOW()
		WHERE id = $1::uuid
	`, decisionID, rev)
	if err != nil {
		return err
	}
	return m.pg.InsertAuditLog(ctx, actor, "guard_unban", "guard_decision", decisionID, map[string]any{
		"indicator": indVal, "revision": rev, "reason": reason,
	}, "")
}

// ExpireTTLs reaps expired enforced blocks and cleans up Cloudflare & Nginx feeds.
func (m *Manager) ExpireTTLs(ctx context.Context) (int, error) {
	rows, err := m.pg.Pool.Query(ctx, `
		SELECT id::text, indicator_value, cloudflare_item_id
		FROM guard_decisions
		WHERE status IN ('approved', 'enforced', 'pending_unban')
		  AND ttl_expires_at IS NOT NULL
		  AND ttl_expires_at <= NOW()
	`)
	if err != nil {
		return 0, err
	}
	type expiredItem struct{ id, val, cfID string }
	var items []expiredItem
	for rows.Next() {
		var it expiredItem
		if rows.Scan(&it.id, &it.val, &it.cfID) == nil {
			items = append(items, it)
		}
	}
	rows.Close()

	count := 0
	for _, it := range items {
		if m.cf != nil && m.cf.IsConfigured() {
			if err := m.cf.DeleteByIPOrID(ctx, it.cfID, it.val); err != nil {
				continue
			}
		}
		rev, _ := m.pg.NextFeedRevision(ctx)
		if _, err := m.pg.Pool.Exec(ctx, `
			UPDATE guard_decisions SET status = 'expired', nginx_revision = $2, updated_at = NOW() WHERE id = $1::uuid
		`, it.id, rev); err == nil {
			count++
		}
	}
	return count, nil
}

// ReconcilePending retries failed Cloudflare additions (approved -> enforced) and stuck unbans (pending_unban -> rolled_back).
func (m *Manager) ReconcilePending(ctx context.Context) {
	if m.cf == nil || !m.cf.IsConfigured() {
		return
	}
	// Retry approved Cloudflare additions that failed earlier
	if rows, err := m.pg.Pool.Query(ctx, `
		SELECT id::text, indicator_value, decided_by
		FROM guard_decisions
		WHERE status = 'approved' AND target_sync IN ('cloudflare', 'both')
	`); err == nil {
		type rowItem struct{ id, val, actor string }
		var items []rowItem
		for rows.Next() {
			var it rowItem
			if rows.Scan(&it.id, &it.val, &it.actor) == nil {
				items = append(items, it)
			}
		}
		rows.Close()
		for _, it := range items {
			if cfID, cfErr := m.cf.AddItem(ctx, it.val, "Honeypot Guard approved by "+it.actor); cfErr == nil && cfID != "" {
				_, _ = m.pg.Pool.Exec(ctx, `
					UPDATE guard_decisions SET status = 'enforced', cloudflare_item_id = $2, updated_at = NOW() WHERE id = $1::uuid
				`, it.id, cfID)
			}
		}
	}

	// Retry stuck pending_unban Cloudflare deletions
	if rows, err := m.pg.Pool.Query(ctx, `
		SELECT id::text, indicator_value, cloudflare_item_id
		FROM guard_decisions WHERE status = 'pending_unban'
	`); err == nil {
		type rowItem struct{ id, val, cfID string }
		var items []rowItem
		for rows.Next() {
			var it rowItem
			if rows.Scan(&it.id, &it.val, &it.cfID) == nil {
				items = append(items, it)
			}
		}
		rows.Close()
		for _, it := range items {
			if m.cf.DeleteByIPOrID(ctx, it.cfID, it.val) == nil {
				rev, _ := m.pg.NextFeedRevision(ctx)
				_, _ = m.pg.Pool.Exec(ctx, `
					UPDATE guard_decisions SET status = 'rolled_back', nginx_revision = $2, updated_at = NOW() WHERE id = $1::uuid
				`, it.id, rev)
			}
		}
	}
}
