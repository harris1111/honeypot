# Architecture & Design Rationale

This document describes the trust boundaries, data/control flows, module ownership, and non-obvious engineering decisions across the Distributed Cyber Deception & Active Defense Honeypot Platform. Code remains the canonical owner of implementation details; each section links to its executable owner.

---

## 1. Security Model & Trust Boundaries

The platform assumes **every Edge Sensor VPS will eventually be scanned, probed, and attacked**, while a **compromised trap container** (e.g., Cowrie or Heralding) could attempt SSRF, lateral host pivot, or outbound C2 staging. Consequently, trust is partitioned across four strict boundaries:

1. **Public Attack Surface (Unprivileged Edge Sensor Host + Isolated `br-trap` Bridge):**
   - Native Go traps (`:80`, `:443`, `:2375`, `:6443`, `:6379`, `:3306`, `:5432`) run unprivileged under UID `1000` (`honeypot`) with only `CAP_NET_BIND_SERVICE` ([`scripts/install-sensor.sh`](scripts/install-sensor.sh)).
   - Container traps run inside an isolated Docker bridge (`trap_isolated_net`, interface `br-trap`, `enable_icc=false`) with `CapDrop=ALL`, `ReadonlyRootfs=true`, `no-new-privileges:true`, and UID `1000:1000` enforced by [`cmd/docker-guard-proxy`](cmd/docker-guard-proxy/guard.go).
   - Host firewall [`scripts/lockdown-nftables.sh`](scripts/lockdown-nftables.sh) drops unsolicited input from `br-trap` to the host (`input_host_protect`), drops new outbound connections from `br-trap` (`forward_egress_drop`), and blocks UID `1000` access to cloud IMDS (`169.254.169.254`, `fd00:ec2::254`). *Design note:* `trap_isolated_net` keeps Docker `Internal=false` so external `PortBindings` DNAT works cleanly, relying on `nftables` `ct state new drop` (with `established,related accept`) rather than Docker's `internal: true` flag which suppresses port forwarding.
2. **Docker Control Boundary (`docker-guard-proxy`):**
   - `sensor-agent` never mounts `/var/run/docker.sock`. It speaks exclusively to `docker-guard-proxy` (`127.0.0.1:23750`), which enforces strict canonical URL paths, `DisallowUnknownFields()` JSON decoding, re-marshaled request forwarding, allowlisted image prefixes (`cowrie/cowrie`, `johnnykv/heralding`), `hp-trap-*` container prefixes, env allowlists (blocking `LD_PRELOAD`, `PYTHONPATH`, etc.), and `filepath.EvalSymlinks` bind-root containment ([`cmd/docker-guard-proxy/guard.go`](cmd/docker-guard-proxy/guard.go)).
3. **Zero-Trust Edge-to-Hive Ingress (`:9443`, TLS 1.3 Strict mTLS):**
   - Sensors do not require Tailscale/WireGuard. All Hive communication crosses port `:9443` ([`internal/pki/ca.go`](internal/pki/ca.go), [`internal/hubgrpc/server.go`](internal/hubgrpc/server.go)).
   - **Enrollment SNI (`enroll.*`):** Allows bootstrap without a client certificate only during `EnrollNode` (`verifyEnrollSNI`); the sensor verifies the Hive Root CA SHA-256 fingerprint before transmitting its single-use `hpj_*` token (`sha256` hashed in `node_join_tokens`, atomically consumed only after validating the client CSR).
   - **Authenticated mTLS SNI (all other SNIs):** Enforces `tls.RequireAnyClientCert` with empty `ClientCAs` at TLS handshake + `VerifyConnection` leaf validation against the internal ECDSA P-256 Root CA, checking `revoked` node status (`sensor_nodes`) and enforcing SPIFFE role URIs (`spiffe://honeypot.internal/role/sensor/node/...` vs `role/nginx_guard`). Revoking a node in [`internal/adminapi/handlers_nodes.go`](internal/adminapi/handlers_nodes.go) invokes `DisconnectNode`, terminating live `StreamControl` sessions immediately and poisoning the Redis revocation cache.
4. **Zero-Public-Exposure Control Plane (`:8443`):**
   - [`internal/adminapi/server.go`](internal/adminapi/server.go) validates `HIVE_ADMIN_BIND_ADDR` at startup (`ValidateAdminBindAddr`), rejecting `0.0.0.0`, `::`, or non-VPN physical NICs unless `--unsafe-dev-bind` is explicitly passed. HTTP middleware further filters peers via `ADMIN_ALLOWED_CIDRS`, sets a Wasm-compatible CSP (`'wasm-unsafe-eval'` for `asciinema-player` without `'unsafe-eval'`), rate-limits logins, checks per-session HMAC + CSRF tokens + RFC 6238 TOTP, and logs every mutation to `audit_logs`.

---

## 2. End-to-End Deception & Active Defense Flow

```mermaid
sequenceDiagram
    participant A1 as Attacker IP_1
    participant A2 as Attacker IP_2
    participant Sensor as Edge Sensor (:80/:443/:22)
    participant Hive as Central Hive (:9443)
    participant Intel as Enrichment + YARA-X + Correlator
    participant Policy as Policy Engine + Admin (:8443)
    participant Guard as Cloudflare + nginx-guard

    A1->>Sensor: Triggers Next.js CVE-2025-29927 or inspects Cowrie honeyfs
    Sensor-->>A1: Returns realistic decoy holding HMAC Canary Key K
    Sensor->>Sensor: Enqueues TelemetryEvent in offline-safe BoltDB WAL
    A2->>Sensor: Probes Chameleon /v1/chat/completions with stolen Key K
    Sensor->>Hive: RelayLLM (mTLS :9443)
    Hive->>Hive: Verifies Canary Key + Atomic Redis Lua daily USD budget
    Hive-->>Sensor: Streams scrubbed SSE response (DeepSeek/vendor leaks stripped)
    Sensor->>Hive: PushEventsBatch (mTLS gRPC)
    Hive->>Intel: Updates telemetry, YARA-X scans payloads, queries GreyNoise/MMDB/VT
    Intel->>Policy: Reevaluates Kill-Chain Incident (links IP_1 + IP_2 via Canary Key)
    Policy->>Policy: GreyNoise==benign -> ignore; Attack -> stage pending_approval
    Policy->>Guard: Operator approves -> Sync Cloudflare List + sign Ed25519 Nginx feed
    Guard->>Guard: nginx-guard verifies signature & revision -> nginx -t -> reload
```

---

## 3. Binary & Package Ownership Map

| Binary / Module | Responsibility & Boundary | Key Entry Points |
|---|---|---|
| **`cmd/hive`** | Central control plane binary (gRPC + HTTPS `:9443`, Private Admin `:8443`, DB/Redis, Correlator, Policy, Guard, Relay, Alerting, Vault) | [`cmd/hive/main.go`](cmd/hive/main.go) |
| **`cmd/sensor-agent`** | Edge VPS daemon: enrollment, BoltDB spool flusher, `StreamControl`, container reconciliation, Dual TLS/JA4 Web/LLM/Infra traps, `SafeDownloader` | [`cmd/sensor-agent/main.go`](cmd/sensor-agent/main.go), [`control.go`](cmd/sensor-agent/control.go), [`native_traps.go`](cmd/sensor-agent/native_traps.go) |
| **`cmd/docker-guard-proxy`** | Least-privilege Unix-socket HTTP proxy mediating Docker container creation/lifecycle | [`cmd/docker-guard-proxy/main.go`](cmd/docker-guard-proxy/main.go), [`guard.go`](cmd/docker-guard-proxy/guard.go) |
| **`cmd/nginx-guard`** | Production web edge daemon polling signed Ed25519 blocklists and reloading Nginx safely | [`cmd/nginx-guard/main.go`](cmd/nginx-guard/main.go), [`nginx_writer.go`](cmd/nginx-guard/nginx_writer.go) |
| **`internal/pki`** | ECDSA P-256 CA, Ed25519 feed signing/verification, SPIFFE URI certs, hot `ClientCertStore` rotation | [`internal/pki/ca.go`](internal/pki/ca.go), [`enroll.go`](internal/pki/enroll.go), [`rotation.go`](internal/pki/rotation.go) |
| **`internal/store` + `migrations/`** | PostgreSQL `pgxpool` + embedded `goose` migrations (15 tables + `guard_feed_revision_seq`) + Redis helpers | [`internal/store/postgres.go`](internal/store/postgres.go), [`migrations/00001_core_nodes.sql`](migrations/00001_core_nodes.sql), [`00002_telemetry_incidents.sql`](migrations/00002_telemetry_incidents.sql) |
| **`internal/spool`** | Crash-safe bbolt write-ahead log (`events_pending`, `deadletter`) bounded by byte cap | [`internal/spool/bolt_spool.go`](internal/spool/bolt_spool.go) |
| **`internal/canary`** | HMAC-SHA256 statelessly verifiable `sk-proj-*` / `sk-ant-*` keys mapped to `placement_source` & `paid_upstream_eligible` | [`internal/canary/signer.go`](internal/canary/signer.go) |
| **`internal/orchestrator`** | Docker trap profiles, Cowrie Python protocol-2 `fs.pickle` generator, log tailing, chunked `ArtifactSink` | [`internal/orchestrator/docker_manager.go`](internal/orchestrator/docker_manager.go), [`fspickle.go`](internal/orchestrator/fspickle.go), [`honeyfs_seeder.go`](internal/orchestrator/honeyfs_seeder.go) |
| **`internal/netwrap`** | Peeked dual-mode ACME (`certmagic`) + Raw-IP ECDSA TLS, JA4 TLS & JA4H HTTP fingerprinting | [`internal/netwrap`](internal/netwrap) |
| **`internal/traps/{webcve,infratrap,cowrieparser}`** | 13 declarative YAML CVE packs, bare `go-git/v5` `.git` server, 5 native TCP/HTTP infra traps, Cowrie JSON & `.cast` replay sanitizer | [`internal/traps/webcve`](internal/traps/webcve), [`infratrap`](internal/traps/infratrap), [`cowrieparser`](internal/traps/cowrieparser) |
| **`internal/traps/llmproxy`** | OpenAI/Anthropic/Ollama/LiteLLM adapters, `HiveRelay`, `StreamSanitizer`, Redis Lua `CircuitBreaker`, `TarpitLimiter`, 5 AI KEV handlers | [`internal/traps/llmproxy`](internal/traps/llmproxy) |
| **`internal/{malware,enrichment,correlation}`** | Sensor SSRF-hardened downloader, Vault + YARA-X Dual-Scanner, GeoIP/GreyNoise/AbuseIPDB/VT enrichment, Multi-IP Kill-Chain Correlator | [`internal/malware`](internal/malware), [`internal/enrichment`](internal/enrichment), [`internal/correlation`](internal/correlation) |
| **`internal/{policy,guard,notify,adminapi}`** | Priority Policy Engine, Cloudflare WAF + Nginx signed feed manager, Telegram/Discord/Webhook alerts, Admin REST & WS server | [`internal/policy`](internal/policy), [`internal/guard`](internal/guard), [`internal/notify`](internal/notify), [`internal/adminapi`](internal/adminapi) |
| **`web/`** | Vite + React 19 + TypeScript + Tailwind + Recharts + `asciinema-player` SPA embedded via `//go:embed all:dist` | [`web/embed.go`](web/embed.go), [`web/src/pages`](web/src/pages) |

---

## 4. Key Architectural Decisions & Trade-Offs

### YARA Dual-Scanner (`!yarax` vs `-tags yarax`)
- **Decision:** Provide two compile-time backends sharing the `Scanner` interface in [`internal/malware/yara`](internal/malware/yara). Default `CGO_ENABLED=0` builds compile the pure-Go substring/regex matcher (`scanner_purego.go`) so edge sensors and developer machines need zero Rust/C dependencies. Production [`Dockerfile.hive`](deployments/hive/Dockerfile.hive) compiles `VirusTotal/yara-x` `v1.23.0` (`libyara_x_capi`) and builds `hive` with `CGO_ENABLED=1 go build -tags yarax` (`scanner_yarax.go`).
- **Trade-off:** Longer Docker build time on Hive vs zero-CGo static portability on Sensors.

### All-in-One Port Layout vs Multi-VPS Topology
- **Decision:** Keep PostgreSQL (`HIVE_PG_PORT=15432`) and Redis (`HIVE_REDIS_PORT=16379`) on loopback-only non-default ports inside [`docker-compose.hive.yml`](deployments/hive/docker-compose.hive.yml).
- **Rationale:** On an All-in-One single VPS deployment, host ports `5432` and `6379` remain unoccupied so the `sensor-agent` native PostgreSQL and Redis credential traps can listen publicly on `0.0.0.0:5432` and `0.0.0.0:6379` without colliding with Hive's real backing stores.

### Chameleon LLM Cost Containment & Mid-Chunk Leak Prevention
- **Decision:** Upstream API keys never leave Hive ([`internal/traps/llmproxy/hive_relay.go`](internal/traps/llmproxy/hive_relay.go)). Attacker-controlled `system` and `developer` messages are stripped; an authentic persona prompt is prepended and sanitized model names are injected. [`budget.CircuitBreaker`](internal/traps/llmproxy/budget/circuit_breaker.go) atomically reserves micro-USD budget via a Redis Lua script strictly for seeded `paid_upstream_eligible` keys (`cowrie_honeyfs`, `git_lure`, `k8s_secret`, `php_env`). Everything else (`/key/generate` `llm_pool`, unauthenticated Ollama) routes to deterministic static deception or a bounded Slow SSE Tarpit (`128` global, `2` per IP, `60s` max). `StreamSanitizer` buffers an explicit sliding holdback window (`>= 80` bytes) across SSE deltas before flushing so split vendor words (`"Deep"` + `"Seek"`) are caught cleanly.

### Anti-Rollback Nginx Edge Synchronization
- **Decision:** Guard state is serialized into `FeedPayload` containing `Revision` (PostgreSQL `guard_feed_revision_seq`), Cloudflare CIDRs (always allowed for real-IP extraction via `$http_cf_connecting_ip`), and approved blocked prefixes ([`internal/guard/manager.go`](internal/guard/manager.go)). Hive signs payloads with Ed25519. [`cmd/nginx-guard/nginx_writer.go`](cmd/nginx-guard/nginx_writer.go) parses every CIDR strictly with `netip.ParsePrefix` (rejecting raw template interpolation), renders dual-stack IPv4 + `::ffff:` `ngx_http_geo_module` rules, backups up the active `.conf`, validates with `nginx -t` (rolling back on error), and bypasses its 60s reload debounce whenever an Emergency Unban drops a previously blocked IP.
