-- +goose Up
-- +goose StatementBegin

-- 8. canary_keys
CREATE TABLE IF NOT EXISTS canary_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_prefix TEXT NOT NULL,
    key_hash BYTEA NOT NULL UNIQUE,
    key_plaintext_enc BYTEA NOT NULL,
    provider_style TEXT NOT NULL CHECK (provider_style IN ('openai', 'anthropic')),
    node_id UUID REFERENCES sensor_nodes(id) ON DELETE SET NULL,
    placement_source TEXT NOT NULL,
    placement_path TEXT NOT NULL DEFAULT '',
    paid_upstream_eligible BOOLEAN NOT NULL DEFAULT TRUE,
    hit_count BIGINT NOT NULL DEFAULT 0,
    first_hit_at TIMESTAMPTZ,
    last_hit_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 9. attack_incidents
CREATE TABLE IF NOT EXISTS attack_incidents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    correlation_key TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'medium' CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    confidence_score SMALLINT NOT NULL DEFAULT 0,
    primary_ip INET NOT NULL,
    related_ips INET[] NOT NULL DEFAULT ARRAY[]::INET[],
    trap_kinds TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    cve_ids TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    canary_key_ids UUID[] NOT NULL DEFAULT ARRAY[]::UUID[],
    malware_sha256s TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    yara_match_count INTEGER NOT NULL DEFAULT 0,
    country_code TEXT NOT NULL DEFAULT '',
    asn INTEGER NOT NULL DEFAULT 0,
    greynoise_classification TEXT NOT NULL DEFAULT 'unknown' CHECK (greynoise_classification IN ('benign', 'malicious', 'unknown')),
    abuseipdb_score SMALLINT NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'triaged', 'blocked', 'dismissed')),
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_attack_incidents_last_seen ON attack_incidents (last_seen_at DESC);

-- 10. telemetry_events (Daily range-partitioned table)
CREATE TABLE IF NOT EXISTS telemetry_events (
    id UUID NOT NULL,
    node_id UUID NOT NULL REFERENCES sensor_nodes(id) ON DELETE CASCADE,
    incident_id UUID REFERENCES attack_incidents(id) ON DELETE SET NULL,
    source_ip INET NOT NULL,
    source_port INTEGER NOT NULL DEFAULT 0,
    dest_port INTEGER NOT NULL DEFAULT 0,
    protocol TEXT NOT NULL DEFAULT 'http',
    trap_kind TEXT NOT NULL,
    persona TEXT NOT NULL DEFAULT '',
    cve_id TEXT NOT NULL DEFAULT '',
    is_kev BOOLEAN NOT NULL DEFAULT FALSE,
    ja4 TEXT NOT NULL DEFAULT '',
    ja4h TEXT NOT NULL DEFAULT '',
    hassh TEXT NOT NULL DEFAULT '',
    http_method TEXT NOT NULL DEFAULT '',
    http_host TEXT NOT NULL DEFAULT '',
    http_path TEXT NOT NULL DEFAULT '',
    raw_payload TEXT NOT NULL DEFAULT '' CHECK (octet_length(raw_payload) <= 32768),
    artifact_sha256 TEXT NOT NULL DEFAULT '',
    response_summary TEXT NOT NULL DEFAULT '',
    extracted_iocs JSONB NOT NULL DEFAULT '{}'::jsonb,
    canary_key_id UUID REFERENCES canary_keys(id) ON DELETE SET NULL,
    country_code TEXT NOT NULL DEFAULT '',
    asn INTEGER NOT NULL DEFAULT 0,
    greynoise_classification TEXT NOT NULL DEFAULT 'unknown' CHECK (greynoise_classification IN ('benign', 'malicious', 'unknown')),
    abuseipdb_score SMALLINT NOT NULL DEFAULT 0,
    severity_score SMALLINT NOT NULL DEFAULT 0,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (observed_at, node_id, id)
) PARTITION BY RANGE (observed_at);

CREATE TABLE IF NOT EXISTS telemetry_events_default PARTITION OF telemetry_events DEFAULT;
CREATE INDEX IF NOT EXISTS idx_telemetry_events_observed_brin ON telemetry_events USING BRIN (observed_at);
CREATE INDEX IF NOT EXISTS idx_telemetry_events_iocs_gin ON telemetry_events USING GIN (extracted_iocs);
CREATE INDEX IF NOT EXISTS idx_telemetry_events_source_ip ON telemetry_events (source_ip);
CREATE INDEX IF NOT EXISTS idx_telemetry_events_incident_id ON telemetry_events (incident_id);

-- 11. ssh_session_replays
CREATE TABLE IF NOT EXISTS ssh_session_replays (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id UUID NOT NULL,
    node_id UUID NOT NULL REFERENCES sensor_nodes(id) ON DELETE CASCADE,
    source_ip INET NOT NULL,
    hassh TEXT NOT NULL DEFAULT '',
    username TEXT NOT NULL DEFAULT '',
    auth_succeeded BOOLEAN NOT NULL DEFAULT FALSE,
    commands TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    asciicast_v2 TEXT NOT NULL DEFAULT '',
    duration_ms BIGINT NOT NULL DEFAULT 0,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (node_id, event_id)
);

-- 12. llm_conversations
CREATE TABLE IF NOT EXISTS llm_conversations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id UUID NOT NULL,
    node_id UUID NOT NULL REFERENCES sensor_nodes(id) ON DELETE CASCADE,
    canary_key_id UUID REFERENCES canary_keys(id) ON DELETE SET NULL,
    source_ip INET NOT NULL,
    api_dialect TEXT NOT NULL CHECK (api_dialect IN ('openai', 'anthropic', 'ollama', 'litellm')),
    requested_model TEXT NOT NULL DEFAULT '',
    emulated_persona TEXT NOT NULL DEFAULT '',
    probe_flags TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    messages_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    tools_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    response_text TEXT NOT NULL DEFAULT '',
    degraded_mode TEXT NOT NULL DEFAULT 'none' CHECK (degraded_mode IN ('none', 'cached', 'rate_limit_429', 'slow_tarpit')),
    upstream_tokens_in INTEGER NOT NULL DEFAULT 0,
    upstream_tokens_out INTEGER NOT NULL DEFAULT 0,
    estimated_cost_usd NUMERIC(10, 6) NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (node_id, event_id)
);

-- 13. malware_artifacts
CREATE TABLE IF NOT EXISTS malware_artifacts (
    sha256 TEXT PRIMARY KEY,
    md5 TEXT NOT NULL,
    file_size BIGINT NOT NULL,
    mime_type TEXT NOT NULL DEFAULT 'application/octet-stream',
    source_urls TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    storage_path TEXT NOT NULL,
    yara_matches TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    vt_malicious_count INTEGER NOT NULL DEFAULT 0,
    vt_total_engines INTEGER NOT NULL DEFAULT 0,
    vt_checked_at TIMESTAMPTZ,
    seen_count BIGINT NOT NULL DEFAULT 1,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 14. policy_rules
CREATE TABLE IF NOT EXISTS policy_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE,
    priority INTEGER NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    conditions_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    action TEXT NOT NULL CHECK (action IN ('ignore', 'triage_queue', 'auto_enforce')),
    default_ttl_hours INTEGER NOT NULL DEFAULT 168,
    target_sync TEXT NOT NULL DEFAULT 'both' CHECK (target_sync IN ('nginx', 'cloudflare', 'both')),
    is_default_seed BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed 5 default policy rules (Priority #1 = Benign suppression; Zero auto_enforce defaults!)
INSERT INTO policy_rules (name, priority, enabled, conditions_json, action, default_ttl_hours, target_sync, is_default_seed) VALUES
    ('Benign Internet Scanner Suppression', 1, TRUE, '{"all":[{"field":"greynoise_classification","op":"eq","value":"benign"}]}'::jsonb, 'ignore', 0, 'nginx', TRUE),
    ('Canary Key Compromised & Reused', 2, TRUE, '{"all":[{"field":"canary_key_used","op":"eq","value":true}]}'::jsonb, 'triage_queue', 720, 'both', TRUE),
    ('Active CISA KEV Exploit Payload', 3, TRUE, '{"all":[{"field":"is_kev","op":"eq","value":true}]}'::jsonb, 'triage_queue', 168, 'both', TRUE),
    ('Malware Dropper / YARA Hit', 4, TRUE, '{"all":[{"field":"yara_match_count","op":"gt","value":0}]}'::jsonb, 'triage_queue', 336, 'both', TRUE),
    ('High-Confidence Multi-Trap Scanner', 5, TRUE, '{"all":[{"field":"confidence_score","op":"gte","value":80},{"field":"distinct_traps","op":"gte","value":2}]}'::jsonb, 'triage_queue', 168, 'nginx', TRUE)
ON CONFLICT (name) DO NOTHING;

-- 15. guard_decisions
CREATE TABLE IF NOT EXISTS guard_decisions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id UUID REFERENCES attack_incidents(id) ON DELETE SET NULL,
    rule_id UUID REFERENCES policy_rules(id) ON DELETE SET NULL,
    indicator_type TEXT NOT NULL CHECK (indicator_type IN ('ip', 'cidr', 'ja4', 'waf_expr')),
    indicator_value TEXT NOT NULL,
    target_sync TEXT NOT NULL CHECK (target_sync IN ('nginx', 'cloudflare', 'both')),
    status TEXT NOT NULL DEFAULT 'pending_approval' CHECK (status IN ('pending_approval', 'approved', 'enforced', 'pending_unban', 'rejected', 'expired', 'rolled_back')),
    decided_by TEXT NOT NULL DEFAULT '',
    reason TEXT NOT NULL DEFAULT '',
    ttl_expires_at TIMESTAMPTZ,
    cloudflare_item_id TEXT NOT NULL DEFAULT '',
    nginx_revision BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_nginx_ip_cidr_only CHECK (NOT (target_sync IN ('nginx', 'both') AND indicator_type NOT IN ('ip', 'cidr')))
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_guard_decisions_active_indicator
    ON guard_decisions (indicator_type, indicator_value)
    WHERE status IN ('pending_approval', 'approved', 'enforced', 'pending_unban');

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS guard_decisions;
DROP TABLE IF EXISTS policy_rules;
DROP TABLE IF EXISTS malware_artifacts;
DROP TABLE IF EXISTS llm_conversations;
DROP TABLE IF EXISTS ssh_session_replays;
DROP TABLE IF EXISTS telemetry_events;
DROP TABLE IF EXISTS attack_incidents;
DROP TABLE IF EXISTS canary_keys;
-- +goose StatementEnd
