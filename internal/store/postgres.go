package store

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/harris/honeypot/migrations"
	honeypotv1 "github.com/harris/honeypot/proto/gen/honeypot/v1"
)

var (
	ErrTokenInvalid      = errors.New("join token invalid, expired, or already used")
	ErrAllowlistLocked   = errors.New("cannot delete system-locked allowlist entry")
	ErrNodeNotFound      = errors.New("sensor node not found")
	ErrProtectedAllowlist = errors.New("indicator overlaps protected allowlist")
)

// Postgres wraps pgxpool.Pool and implements persistence across all 15 canonical tables.
type Postgres struct {
	Pool *pgxpool.Pool
}

// OpenPostgres connects to PostgreSQL, verifies health, and runs embedded goose migrations.
func OpenPostgres(ctx context.Context, dsn string) (*Postgres, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse postgres dsn: %w", err)
	}
	cfg.MaxConns = 25
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect postgres: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	pg := &Postgres{Pool: pool}
	if err := pg.Migrate(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return pg, nil
}

// Close closes the underlying connection pool.
func (p *Postgres) Close() {
	if p != nil && p.Pool != nil {
		p.Pool.Close()
	}
}

// Migrate applies all embedded SQL migrations via goose under a PostgreSQL advisory lock.
func (p *Postgres) Migrate(ctx context.Context) error {
	lockConn, err := p.Pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire migration lock conn: %w", err)
	}
	defer lockConn.Release()
	if _, err := lockConn.Exec(ctx, `SELECT pg_advisory_lock(73918273)`); err != nil {
		return fmt.Errorf("acquire advisory lock: %w", err)
	}
	defer func() { _, _ = lockConn.Exec(context.Background(), `SELECT pg_advisory_unlock(73918273)`) }()

	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("goose dialect: %w", err)
	}
	db := stdlib.OpenDBFromPool(p.Pool)
	defer func() { _ = db.Close() }()
	if err := goose.UpContext(ctx, db, "."); err != nil {
		return fmt.Errorf("goose up: %w", err)
	}
	// Ensure today + tomorrow partitions exist immediately
	now := time.Now().UTC()
	for i := -1; i <= 2; i++ {
		if err := p.EnsureTelemetryPartition(ctx, now.AddDate(0, 0, i)); err != nil {
			return err
		}
	}
	return nil
}

// EnsureTelemetryPartition creates the daily range partition for telemetry_events if missing.
func (p *Postgres) EnsureTelemetryPartition(ctx context.Context, day time.Time) error {
	start := time.Date(day.UTC().Year(), day.UTC().Month(), day.UTC().Day(), 0, 0, 0, 0, time.UTC)
	end := start.AddDate(0, 0, 1)
	partName := fmt.Sprintf("telemetry_events_%s", start.Format("20060102"))
	sql := fmt.Sprintf(
		"CREATE TABLE IF NOT EXISTS %s PARTITION OF telemetry_events FOR VALUES FROM ('%s') TO ('%s')",
		partName, start.Format(time.RFC3339), end.Format(time.RFC3339),
	)
	if _, err := p.Pool.Exec(ctx, sql); err != nil {
		return fmt.Errorf("create telemetry partition %s: %w", partName, err)
	}
	return nil
}

// DropExpiredTelemetryPartitions drops daily partitions strictly older than retentionDays.
func (p *Postgres) DropExpiredTelemetryPartitions(ctx context.Context, retentionDays int) (int, error) {
	if retentionDays <= 0 {
		return 0, nil
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -retentionDays).Format("20060102")
	rows, err := p.Pool.Query(ctx, `
		SELECT inhrelid::regclass::text
		FROM pg_inherits
		WHERE inhparent = 'telemetry_events'::regclass
	`)
	if err != nil {
		return 0, err
	}
	var toDrop []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return 0, err
		}
		if strings.HasPrefix(name, "telemetry_events_20") && len(name) == len("telemetry_events_20060102") {
			suffix := strings.TrimPrefix(name, "telemetry_events_")
			if suffix < cutoff {
				toDrop = append(toDrop, name)
			}
		}
	}
	rows.Close()
	for _, tbl := range toDrop {
		if _, err := p.Pool.Exec(ctx, "DROP TABLE IF EXISTS "+pgx.Identifier{tbl}.Sanitize()); err != nil {
			return 0, err
		}
	}
	return len(toDrop), nil
}

// CreateJoinToken inserts a hashed one-time enrollment token for a Sensor or nginx-guard instance.
func (p *Postgres) CreateJoinToken(ctx context.Context, tokenHash []byte, role, intendedName, region string, ttl time.Duration) (uuid.UUID, error) {
	if role == "" {
		role = "sensor"
	}
	if region == "" {
		region = "default"
	}
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	var id uuid.UUID
	err := p.Pool.QueryRow(ctx, `
		INSERT INTO node_join_tokens (token_hash, node_role, intended_name, region, expires_at)
		VALUES ($1, $2, $3, $4, NOW() + $5::interval)
		RETURNING id
	`, tokenHash, role, intendedName, region, fmt.Sprintf("%d seconds", int(ttl.Seconds()))).Scan(&id)
	return id, err
}

// ConsumedJoinToken represents the atomic result of consuming a one-time join token.
type ConsumedJoinToken struct {
	TokenID      uuid.UUID
	NodeID       uuid.UUID
	NodeRole     string
	IntendedName string
	Region       string
}

// ConsumeJoinToken atomically marks a valid join token used and registers/updates the node row inside one transaction.
func (p *Postgres) ConsumeJoinToken(ctx context.Context, tokenHash []byte, publicIPv4, publicIPv6, agentVersion, certSerial string, certExpiresAt time.Time) (ConsumedJoinToken, error) {
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return ConsumedJoinToken{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	nodeID := uuid.New()
	var res ConsumedJoinToken
	err = tx.QueryRow(ctx, `
		UPDATE node_join_tokens
		SET used_at = NOW()
		WHERE token_hash = $1 AND used_at IS NULL AND expires_at > NOW()
		RETURNING id, node_role, intended_name, region
	`, tokenHash).Scan(&res.TokenID, &res.NodeRole, &res.IntendedName, &res.Region)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ConsumedJoinToken{}, ErrTokenInvalid
		}
		return ConsumedJoinToken{}, err
	}
	res.NodeID = nodeID

	var ipv4Ptr, ipv6Ptr *string
	if ip, err := netip.ParseAddr(strings.TrimSpace(publicIPv4)); err == nil && ip.Is4() {
		s := ip.String()
		ipv4Ptr = &s
	}
	if ip, err := netip.ParseAddr(strings.TrimSpace(publicIPv6)); err == nil && ip.Is6() {
		s := ip.String()
		ipv6Ptr = &s
	}

	err = tx.QueryRow(ctx, `
		INSERT INTO sensor_nodes (id, name, region, public_ipv4, public_ipv6, cert_serial, cert_expires_at, agent_version, status, last_heartbeat_at)
		VALUES ($1, $2, $3, $4::inet, $5::inet, $6, $7, $8, 'online', NOW())
		ON CONFLICT (name) DO UPDATE SET
			region = EXCLUDED.region,
			public_ipv4 = COALESCE(EXCLUDED.public_ipv4, sensor_nodes.public_ipv4),
			public_ipv6 = COALESCE(EXCLUDED.public_ipv6, sensor_nodes.public_ipv6),
			cert_serial = EXCLUDED.cert_serial,
			cert_expires_at = EXCLUDED.cert_expires_at,
			agent_version = EXCLUDED.agent_version,
			status = 'online',
			last_heartbeat_at = NOW()
		RETURNING id
	`, nodeID, res.IntendedName, res.Region, ipv4Ptr, ipv6Ptr, certSerial, certExpiresAt, agentVersion).Scan(&res.NodeID)
	if err != nil {
		return ConsumedJoinToken{}, err
	}

	if _, err := tx.Exec(ctx, `UPDATE node_join_tokens SET used_by_node_id = $1 WHERE id = $2`, res.NodeID, res.TokenID); err != nil {
		return ConsumedJoinToken{}, err
	}

	// Auto-lock enrolled node public IPs into protected_allowlist so Active Guard never blocks our own nodes.
	for _, ipPtr := range []*string{ipv4Ptr, ipv6Ptr} {
		if ipPtr == nil {
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO protected_allowlist (cidr, label, is_system_locked, created_by)
			VALUES ($1::inet, $2, TRUE, 'system')
			ON CONFLICT (cidr) DO NOTHING
		`, *ipPtr, "Enrolled Node: "+res.IntendedName); err != nil {
			return ConsumedJoinToken{}, err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return ConsumedJoinToken{}, err
	}
	return res, nil
}

// NodeCertState holds active certificate verification state for a node.
type NodeCertState struct {
	NodeID     string
	CertSerial string
	Status     string
}

// GetNodeCertState looks up active cert serial and status for mTLS peer validation.
func (p *Postgres) GetNodeCertState(ctx context.Context, nodeID string) (NodeCertState, error) {
	var st NodeCertState
	err := p.Pool.QueryRow(ctx, `
		SELECT id::text, cert_serial, status FROM sensor_nodes WHERE id = $1::uuid
	`, nodeID).Scan(&st.NodeID, &st.CertSerial, &st.Status)
	if errors.Is(err, pgx.ErrNoRows) {
		return NodeCertState{}, ErrNodeNotFound
	}
	return st, err
}

// UpdateNodeCert updates the active cert serial and expiry after two-phase RenewNodeCert.
func (p *Postgres) UpdateNodeCert(ctx context.Context, nodeID, certSerial string, expiresAt time.Time) error {
	tag, err := p.Pool.Exec(ctx, `
		UPDATE sensor_nodes
		SET cert_serial = $2, cert_expires_at = $3
		WHERE id = $1::uuid AND status != 'revoked'
	`, nodeID, certSerial, expiresAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNodeNotFound
	}
	return nil
}

// RevokeNode marks a sensor_node revoked so its mTLS cert is immediately rejected across :9443.
func (p *Postgres) RevokeNode(ctx context.Context, nodeID, actor string) error {
	tag, err := p.Pool.Exec(ctx, `UPDATE sensor_nodes SET status = 'revoked' WHERE id = $1::uuid`, nodeID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNodeNotFound
	}
	return p.InsertAuditLog(ctx, actor, "node_revoked", "sensor_node", nodeID, map[string]any{}, "")
}

// UpdateNodeHeartbeat persists latest node telemetry metrics.
func (p *Postgres) UpdateNodeHeartbeat(ctx context.Context, nodeID string, hb *honeypotv1.NodeHeartbeat) error {
	metrics, _ := json.Marshal(map[string]any{
		"cpu_pct":            hb.GetCpuPct(),
		"mem_used_mb":        hb.GetMemUsedMb(),
		"mem_total_mb":       hb.GetMemTotalMb(),
		"disk_free_mb":       hb.GetDiskFreeMb(),
		"spool_queued_items": hb.GetSpoolQueuedItems(),
		"spool_bytes":        hb.GetSpoolBytes(),
		"trap_count":         len(hb.GetTraps()),
	})
	_, err := p.Pool.Exec(ctx, `
		UPDATE sensor_nodes
		SET status = CASE WHEN status = 'revoked' THEN 'revoked' ELSE 'online' END,
			agent_version = COALESCE(NULLIF($2, ''), agent_version),
			last_heartbeat_at = NOW(),
			metrics_json = $3::jsonb
		WHERE id = $1::uuid
	`, nodeID, hb.GetAgentVersion(), string(metrics))
	return err
}

// ListAllowlistCIDRs returns all protected allowlist CIDRs.
func (p *Postgres) ListAllowlistCIDRs(ctx context.Context) ([]string, error) {
	rows, err := p.Pool.Query(ctx, `SELECT cidr::text FROM protected_allowlist ORDER BY is_system_locked DESC, created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// CheckAllowlistOverlap checks if target (IP or CIDR) overlaps any entry in protected_allowlist using PostgreSQL &&.
func (p *Postgres) CheckAllowlistOverlap(ctx context.Context, target string) (bool, error) {
	var overlaps bool
	err := p.Pool.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM protected_allowlist WHERE cidr && $1::inet)
	`, target).Scan(&overlaps)
	return overlaps, err
}

// AddAllowlistCIDR adds an allowlist entry (idempotent).
func (p *Postgres) AddAllowlistCIDR(ctx context.Context, cidr, label, actor string, systemLocked bool) error {
	if _, err := netip.ParsePrefix(cidr); err != nil {
		if addr, err2 := netip.ParseAddr(cidr); err2 == nil {
			cidr = netip.PrefixFrom(addr, addr.BitLen()).String()
		} else {
			return fmt.Errorf("invalid IP/CIDR %q: %w", cidr, err)
		}
	}
	_, err := p.Pool.Exec(ctx, `
		INSERT INTO protected_allowlist (cidr, label, is_system_locked, created_by)
		VALUES ($1::inet, $2, $3, $4)
		ON CONFLICT (cidr) DO UPDATE SET label = EXCLUDED.label
	`, cidr, label, systemLocked, actor)
	return err
}

// DeleteAllowlistCIDR deletes a non-system-locked allowlist entry.
func (p *Postgres) DeleteAllowlistCIDR(ctx context.Context, id string) error {
	var locked bool
	err := p.Pool.QueryRow(ctx, `SELECT is_system_locked FROM protected_allowlist WHERE id = $1::uuid`, id).Scan(&locked)
	if err != nil {
		return err
	}
	if locked {
		return ErrAllowlistLocked
	}
	_, err = p.Pool.Exec(ctx, `DELETE FROM protected_allowlist WHERE id = $1::uuid AND is_system_locked = FALSE`, id)
	return err
}

// InsertAuditLog records an administrative or security control action.
func (p *Postgres) InsertAuditLog(ctx context.Context, actor, action, targetType, targetID string, details map[string]any, sourceIP string) error {
	b, _ := json.Marshal(details)
	var ipPtr *string
	if ip, err := netip.ParseAddr(strings.TrimSpace(sourceIP)); err == nil {
		s := ip.String()
		ipPtr = &s
	}
	_, err := p.Pool.Exec(ctx, `
		INSERT INTO audit_logs (actor, action, target_type, target_id, details_json, source_ip)
		VALUES ($1, $2, $3, $4, $5::jsonb, $6::inet)
	`, actor, action, targetType, targetID, string(b), ipPtr)
	return err
}

// InsertEventsBatch persists TelemetryEvents, SshSessionReplays, and LlmConversations idempotently.
// Returns acked UUIDs and rejected dead-letter UUIDs.
func (p *Postgres) InsertEventsBatch(ctx context.Context, nodeID string, req *honeypotv1.PushEventsBatchRequest) (acked []string, deadletter []string, err error) {
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	for _, ev := range req.GetEvents() {
		if _, err := uuid.Parse(ev.GetEventUuid()); err != nil {
			deadletter = append(deadletter, ev.GetEventUuid())
			continue
		}
		if _, err := netip.ParseAddr(ev.GetSourceIp()); err != nil {
			deadletter = append(deadletter, ev.GetEventUuid())
			continue
		}
		observed := time.Now().UTC()
		if ev.GetObservedAt() != nil {
			observed = ev.GetObservedAt().AsTime().UTC()
		}
		if err := p.ensurePartitionTx(ctx, tx, observed); err != nil {
			return nil, nil, err
		}
		raw := ev.GetRawPayload()
		if len(raw) > 32768 {
			raw = raw[:32768]
		}
		iocs := ev.GetExtractedIocsJson()
		if iocs == "" {
			iocs = "{}"
		}
		var canaryPtr *string
		if _, err := uuid.Parse(ev.GetCanaryKeyId()); err == nil {
			id := ev.GetCanaryKeyId()
			canaryPtr = &id
		}
		_, execErr := tx.Exec(ctx, `
			INSERT INTO telemetry_events (
				id, node_id, source_ip, source_port, dest_port, protocol, trap_kind,
				persona, cve_id, is_kev, ja4, ja4h, hassh, http_method, http_host, http_path,
				raw_payload, artifact_sha256, response_summary, extracted_iocs, canary_key_id,
				severity_score, observed_at
			) VALUES (
				$1::uuid, $2::uuid, $3::inet, $4, $5, $6, $7,
				$8, $9, $10, $11, $12, $13, $14, $15, $16,
				$17, $18, $19, $20::jsonb, $21::uuid,
				$22, $23
			) ON CONFLICT (observed_at, node_id, id) DO NOTHING
		`, ev.GetEventUuid(), nodeID, ev.GetSourceIp(), int(ev.GetSourcePort()), int(ev.GetDestPort()),
			nonEmpty(ev.GetProtocol(), "http"), nonEmpty(ev.GetTrapKind(), "webcve"),
			ev.GetPersona(), ev.GetCveId(), ev.GetIsKev(), ev.GetJa4(), ev.GetJa4H(), ev.GetHassh(),
			ev.GetHttpMethod(), ev.GetHttpHost(), ev.GetHttpPath(),
			raw, ev.GetArtifactSha256(), ev.GetResponseSummary(), iocs, canaryPtr,
			int16(ev.GetSeverityScore()), observed)
		if execErr != nil {
			return nil, nil, execErr
		}
		acked = append(acked, ev.GetEventUuid())
	}

	for _, rep := range req.GetSshReplays() {
		if _, err := uuid.Parse(rep.GetEventUuid()); err != nil {
			deadletter = append(deadletter, rep.GetReplayUuid())
			continue
		}
		if _, err := netip.ParseAddr(rep.GetSourceIp()); err != nil {
			deadletter = append(deadletter, rep.GetReplayUuid())
			continue
		}
		started := time.Now().UTC()
		if rep.GetStartedAt() != nil {
			started = rep.GetStartedAt().AsTime().UTC()
		}
		cmds := rep.GetCommands()
		if cmds == nil {
			cmds = []string{}
		}
		_, execErr := tx.Exec(ctx, `
			INSERT INTO ssh_session_replays (
				event_id, node_id, source_ip, hassh, username, auth_succeeded, commands, asciicast_v2, duration_ms, started_at
			) VALUES (
				$1::uuid, $2::uuid, $3::inet, $4, $5, $6, $7, $8, $9, $10
			) ON CONFLICT (node_id, event_id) DO NOTHING
		`, rep.GetEventUuid(), nodeID, rep.GetSourceIp(), rep.GetHassh(), rep.GetUsername(),
			rep.GetAuthSucceeded(), cmds, rep.GetAsciicastV2(), rep.GetDurationMs(), started)
		if execErr != nil {
			return nil, nil, execErr
		}
		acked = append(acked, rep.GetReplayUuid())
	}

	for _, lc := range req.GetLlmConversations() {
		if _, err := uuid.Parse(lc.GetEventUuid()); err != nil {
			deadletter = append(deadletter, lc.GetConversationUuid())
			continue
		}
		if _, err := netip.ParseAddr(lc.GetSourceIp()); err != nil {
			deadletter = append(deadletter, lc.GetConversationUuid())
			continue
		}
		created := time.Now().UTC()
		if lc.GetCreatedAt() != nil {
			created = lc.GetCreatedAt().AsTime().UTC()
		}
		var canaryPtr *string
		if _, err := uuid.Parse(lc.GetCanaryKeyId()); err == nil {
			id := lc.GetCanaryKeyId()
			canaryPtr = &id
		}
		msgs := nonEmpty(lc.GetMessagesJson(), "[]")
		tools := nonEmpty(lc.GetToolsJson(), "[]")
		probes := lc.GetProbeFlags()
		if probes == nil {
			probes = []string{}
		}
		_, execErr := tx.Exec(ctx, `
			INSERT INTO llm_conversations (
				event_id, node_id, canary_key_id, source_ip, api_dialect, requested_model,
				emulated_persona, probe_flags, messages_json, tools_json, response_text,
				degraded_mode, upstream_tokens_in, upstream_tokens_out, estimated_cost_usd, created_at
			) VALUES (
				$1::uuid, $2::uuid, $3::uuid, $4::inet, $5, $6,
				$7, $8, $9::jsonb, $10::jsonb, $11,
				$12, $13, $14, $15, $16
			) ON CONFLICT (node_id, event_id) DO NOTHING
		`, lc.GetEventUuid(), nodeID, canaryPtr, lc.GetSourceIp(), nonEmpty(lc.GetApiDialect(), "openai"),
			lc.GetRequestedModel(), lc.GetEmulatedPersona(), probes, msgs, tools, lc.GetResponseText(),
			nonEmpty(lc.GetDegradedMode(), "none"), lc.GetUpstreamTokensIn(), lc.GetUpstreamTokensOut(),
			lc.GetEstimatedCostUsd(), created)
		if execErr != nil {
			return nil, nil, execErr
		}
		acked = append(acked, lc.GetConversationUuid())
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, nil, err
	}
	return acked, deadletter, nil
}

func (p *Postgres) ensurePartitionTx(ctx context.Context, tx pgx.Tx, day time.Time) error {
	start := time.Date(day.UTC().Year(), day.UTC().Month(), day.UTC().Day(), 0, 0, 0, 0, time.UTC)
	end := start.AddDate(0, 0, 1)
	partName := fmt.Sprintf("telemetry_events_%s", start.Format("20060102"))
	sql := fmt.Sprintf(
		"CREATE TABLE IF NOT EXISTS %s PARTITION OF telemetry_events FOR VALUES FROM ('%s') TO ('%s')",
		partName, start.Format(time.RFC3339), end.Format(time.RFC3339),
	)
	_, err := tx.Exec(ctx, sql)
	return err
}

// TrapDeploymentRow represents one row in trap_deployments.
type TrapDeploymentRow struct {
	ID            string `json:"id"`
	NodeID        string `json:"node_id"`
	TrapKind      string `json:"trap_kind"`
	ContainerName string `json:"container_name"`
	Image         string `json:"image"`
	ListenPort    int    `json:"listen_port"`
	Protocol      string `json:"protocol"`
	ConfigJSON    string `json:"config_json"`
	DesiredState  string `json:"desired_state"`
	ActualState   string `json:"actual_state"`
	UpdatedAt     string `json:"updated_at"`
}

// UpsertTrapDeployment records or updates a trap deployment desired state on Hive.
func (p *Postgres) UpsertTrapDeployment(ctx context.Context, row TrapDeploymentRow) (string, error) {
	var id string
	cfg := nonEmpty(row.ConfigJSON, "{}")
	proto := nonEmpty(row.Protocol, "tcp")
	desired := nonEmpty(row.DesiredState, "running")
	actual := nonEmpty(row.ActualState, "stopped")
	err := p.Pool.QueryRow(ctx, `
		INSERT INTO trap_deployments (node_id, trap_kind, container_name, image, listen_port, protocol, config_json, desired_state, actual_state)
		VALUES ($1::uuid, $2, $3, $4, $5, $6, $7::jsonb, $8, $9)
		ON CONFLICT (node_id, trap_kind, container_name, listen_port, protocol) DO UPDATE
		SET image = EXCLUDED.image,
		    config_json = EXCLUDED.config_json,
		    desired_state = EXCLUDED.desired_state,
		    updated_at = NOW()
		RETURNING id::text
	`, row.NodeID, row.TrapKind, row.ContainerName, row.Image, row.ListenPort, proto, cfg, desired, actual).Scan(&id)
	return id, err
}

// UpdateTrapActualState updates desired/actual state for a trap deployment row.
func (p *Postgres) UpdateTrapActualState(ctx context.Context, deploymentID, desired, actual string) error {
	_, err := p.Pool.Exec(ctx, `
		UPDATE trap_deployments
		SET desired_state = COALESCE(NULLIF($2, ''), desired_state),
		    actual_state = COALESCE(NULLIF($3, ''), actual_state),
		    updated_at = NOW()
		WHERE id = $1::uuid
	`, deploymentID, desired, actual)
	return err
}

// LLMPersonaRow defines one deception profile in llm_personas.
type LLMPersonaRow struct {
	ModelPattern  string   `json:"model_pattern"`
	VendorFamily  string   `json:"vendor_family"`
	SystemPrompt  string   `json:"system_prompt"`
	AntiLeakTerms []string `json:"anti_leak_terms"`
	DegradeMode   string   `json:"degrade_mode"`
	MaxDailyUSD   float64  `json:"max_daily_usd"`
	MaxTokensCap  int      `json:"max_tokens_cap"`
	UpdatedAt     string   `json:"updated_at"`
}

// CanaryAuthRecord describes a verified Canary key row for Hive RelayLLMStream authorization.
type CanaryAuthRecord struct {
	ID                   string
	ProviderStyle        string
	PlacementSource      string
	PaidUpstreamEligible bool
}

// ListLLMPersonas loads all configured Chameleon LLM personas.
func (p *Postgres) ListLLMPersonas(ctx context.Context) ([]LLMPersonaRow, error) {
	rows, err := p.Pool.Query(ctx, `
		SELECT model_pattern, vendor_family, system_prompt, anti_leak_terms, degrade_mode, max_daily_usd::float8, max_tokens_cap, updated_at::text
		FROM llm_personas
		ORDER BY length(model_pattern) DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LLMPersonaRow
	for rows.Next() {
		var r LLMPersonaRow
		if err := rows.Scan(&r.ModelPattern, &r.VendorFamily, &r.SystemPrompt, &r.AntiLeakTerms, &r.DegradeMode, &r.MaxDailyUSD, &r.MaxTokensCap, &r.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// UpsertLLMPersona saves or updates a Chameleon LLM persona profile.
func (p *Postgres) UpsertLLMPersona(ctx context.Context, r LLMPersonaRow) error {
	terms := r.AntiLeakTerms
	if terms == nil {
		terms = []string{}
	}
	if r.DegradeMode == "" {
		r.DegradeMode = "slow_tarpit"
	}
	if r.MaxTokensCap <= 0 {
		r.MaxTokensCap = 512
	}
	_, err := p.Pool.Exec(ctx, `
		INSERT INTO llm_personas (model_pattern, vendor_family, system_prompt, anti_leak_terms, degrade_mode, max_daily_usd, max_tokens_cap, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
		ON CONFLICT (model_pattern) DO UPDATE
		SET vendor_family = EXCLUDED.vendor_family,
		    system_prompt = EXCLUDED.system_prompt,
		    anti_leak_terms = EXCLUDED.anti_leak_terms,
		    degrade_mode = EXCLUDED.degrade_mode,
		    max_daily_usd = EXCLUDED.max_daily_usd,
		    max_tokens_cap = EXCLUDED.max_tokens_cap,
		    updated_at = NOW()
	`, r.ModelPattern, r.VendorFamily, r.SystemPrompt, terms, r.DegradeMode, r.MaxDailyUSD, r.MaxTokensCap)
	return err
}

// VerifyCanaryHashAndTouch validates a SHA-256 canary hash and atomically increments hit counters.
func (p *Postgres) VerifyCanaryHashAndTouch(ctx context.Context, hashBytes []byte) (CanaryAuthRecord, bool, error) {
	if len(hashBytes) != 32 {
		return CanaryAuthRecord{}, false, nil
	}
	var rec CanaryAuthRecord
	err := p.Pool.QueryRow(ctx, `
		UPDATE canary_keys
		SET hit_count = hit_count + 1,
		    first_hit_at = COALESCE(first_hit_at, NOW()),
		    last_hit_at = NOW()
		WHERE key_hash = $1
		RETURNING id::text, provider_style, placement_source, paid_upstream_eligible
	`, hashBytes).Scan(&rec.ID, &rec.ProviderStyle, &rec.PlacementSource, &rec.PaidUpstreamEligible)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			return CanaryAuthRecord{}, false, nil
		}
		return CanaryAuthRecord{}, false, err
	}
	return rec, true, nil
}

// InsertLLMConversation persists a single intercepted LLM conversation on Hive.
func (p *Postgres) InsertLLMConversation(ctx context.Context, nodeID string, lc *honeypotv1.LlmConversation) error {
	var canaryPtr *string
	if _, err := uuid.Parse(lc.GetCanaryKeyId()); err == nil {
		id := lc.GetCanaryKeyId()
		canaryPtr = &id
	}
	probes := lc.GetProbeFlags()
	if probes == nil {
		probes = []string{}
	}
	_, err := p.Pool.Exec(ctx, `
		INSERT INTO llm_conversations (
			event_id, node_id, canary_key_id, source_ip, api_dialect, requested_model,
			emulated_persona, probe_flags, messages_json, tools_json, response_text,
			degraded_mode, upstream_tokens_in, upstream_tokens_out, estimated_cost_usd
		) VALUES (
			$1::uuid, $2::uuid, $3::uuid, $4::inet, $5, $6,
			$7, $8, $9::jsonb, $10::jsonb, $11,
			$12, $13, $14, $15
		) ON CONFLICT (node_id, event_id) DO NOTHING
	`, lc.GetEventUuid(), nodeID, canaryPtr, lc.GetSourceIp(), nonEmpty(lc.GetApiDialect(), "openai"),
		lc.GetRequestedModel(), lc.GetEmulatedPersona(), probes, nonEmpty(lc.GetMessagesJson(), "[]"),
		nonEmpty(lc.GetToolsJson(), "[]"), lc.GetResponseText(), nonEmpty(lc.GetDegradedMode(), "none"),
		lc.GetUpstreamTokensIn(), lc.GetUpstreamTokensOut(), lc.GetEstimatedCostUsd())
	return err
}

// UpsertMalwareArtifact stores or increments seen_count & source_urls for a quarantined SHA256 binary.
func (p *Postgres) UpsertMalwareArtifact(ctx context.Context, sha256Hex, md5Hex string, size int64, mimeType, sourceURL, storagePath string, yaraMatches []string) (int64, error) {
	if yaraMatches == nil {
		yaraMatches = []string{}
	}
	var urls []string
	if strings.TrimSpace(sourceURL) != "" {
		urls = []string{strings.TrimSpace(sourceURL)}
	} else {
		urls = []string{}
	}
	var seenCount int64
	err := p.Pool.QueryRow(ctx, `
		INSERT INTO malware_artifacts (sha256, md5, file_size, mime_type, source_urls, storage_path, yara_matches, seen_count)
		VALUES ($1, $2, $3, $4, $5, $6, $7, 1)
		ON CONFLICT (sha256) DO UPDATE
		SET seen_count = malware_artifacts.seen_count + 1,
		    last_seen_at = NOW(),
		    yara_matches = CASE WHEN cardinality(EXCLUDED.yara_matches) > 0 THEN EXCLUDED.yara_matches ELSE malware_artifacts.yara_matches END,
		    source_urls = (
		        SELECT COALESCE(array_agg(DISTINCT u), ARRAY[]::TEXT[])
		        FROM unnest(malware_artifacts.source_urls || EXCLUDED.source_urls) AS u
		        WHERE u <> ''
		    )
		RETURNING seen_count
	`, sha256Hex, md5Hex, size, nonEmpty(mimeType, "application/octet-stream"), urls, storagePath, yaraMatches).Scan(&seenCount)
	return seenCount, err
}

// HasMalwareArtifact reports whether a SHA256 binary already exists in malware_artifacts.
func (p *Postgres) HasMalwareArtifact(ctx context.Context, sha256Hex string) (bool, error) {
	var exists bool
	err := p.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM malware_artifacts WHERE sha256 = $1)`, sha256Hex).Scan(&exists)
	return exists, err
}

// UpdateMalwareVT updates VirusTotal hash reputation counts on malware_artifacts.
func (p *Postgres) UpdateMalwareVT(ctx context.Context, sha256Hex string, malicious, total int) error {
	_, err := p.Pool.Exec(ctx, `
		UPDATE malware_artifacts
		SET vt_malicious_count = $2, vt_total_engines = $3, vt_checked_at = NOW()
		WHERE sha256 = $1
	`, sha256Hex, malicious, total)
	return err
}

// UpdateTelemetryEnrichment updates IP reputation and GeoIP fields on recent telemetry events.
func (p *Postgres) UpdateTelemetryEnrichment(ctx context.Context, ip, country string, asn int, gnClass string, abuseScore int) error {
	_, err := p.Pool.Exec(ctx, `
		UPDATE telemetry_events
		SET country_code = CASE WHEN $2 <> '' THEN $2 ELSE country_code END,
		    asn = CASE WHEN $3 > 0 THEN $3 ELSE asn END,
		    greynoise_classification = CASE WHEN $4 <> '' THEN $4 ELSE greynoise_classification END,
		    abuseipdb_score = CASE WHEN $5 > 0 THEN $5 ELSE abuseipdb_score END
		WHERE source_ip = $1::inet
		  AND observed_at >= NOW() - INTERVAL '7 days'
	`, ip, country, asn, nonEmpty(gnClass, "unknown"), abuseScore)
	return err
}

// NextFeedRevision atomically advances and returns the monotonic guard feed sequence.
func (p *Postgres) NextFeedRevision(ctx context.Context) (int64, error) {
	var rev int64
	err := p.Pool.QueryRow(ctx, `SELECT nextval('guard_feed_revision_seq')`).Scan(&rev)
	return rev, err
}

// HashKeySHA256 computes a SHA-256 key hash for canary_keys lookups.
func HashKeySHA256(key string) []byte {
	sum := sha256.Sum256([]byte(key))
	return sum[:]
}

func nonEmpty(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}
