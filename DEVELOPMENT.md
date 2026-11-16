# Developer & Contributor Guide

This guide covers building, running tests locally, and extending each subsystem while preserving the platform's security invariants.

---

## 1. Local Toolchain Setup

| Tool | Minimum Version | Purpose |
|---|---|---|
| Go | `1.26+` (tested with `go1.27.3`) | Hive, Sensor Agent, Docker Guard Proxy, Nginx Guard |
| Node.js & `pnpm` | Node `22+`, `pnpm 10+` | Admin Console SPA (`web/`) |
| Docker Engine + Compose v2 | Current | Test PostgreSQL 17, Redis 7, live `nginx:alpine` test, Hive `-tags yarax` image |
| `protoc-gen-go` & `protoc-gen-go-grpc` | Installed via `make tools` | Protobuf codegen with `go tool buf generate` |

### Common Commands ([`Makefile`](Makefile))

```bash
# Regenerate gRPC stubs after editing proto/honeypot/v1/agent.proto
make proto

# Build React bundle (web/dist/) + all 4 CGO_ENABLED=0 static Go binaries into bin/
make build

# Run static analysis + pure-Go unit tests
go vet ./...
make test

# Frontend lint, Vitest suite, and TypeScript check
pnpm --dir web lint && pnpm --dir web test && pnpm --dir web build
```

---

## 2. Running the Full Integration & Race Suite

Integration tests cover PostgreSQL migrations, GIST allowlist overlaps, Redis Lua concurrency, live `nginx:alpine` reloads, and the full Phase 1-7 end-to-end pipeline (`internal/e2e/full_stack_test.go`).

Start disposable local Postgres 17 and Redis 7 containers on the default test ports (`15432` and `16379`):

```bash
docker run -d --name honeypot-test-pg \
  -e POSTGRES_USER=honeypot \
  -e POSTGRES_PASSWORD=honeypot_test_pw \
  -e POSTGRES_DB=honeypot \
  -p 127.0.0.1:15432:5432 \
  postgres:17-alpine

docker run -d --name honeypot-test-redis \
  -p 127.0.0.1:16379:6379 \
  redis:7-alpine

# Wait ~5s for pg_isready, then run the full -race test suite:
RUN_INTEGRATION_TESTS=1 go test -race -count=1 ./...

# Verify CGO_ENABLED=0 static agent/edge compilation & unit tests:
CGO_ENABLED=0 go test -count=1 \
  ./internal/pki/... ./internal/spool/... ./internal/canary/... \
  ./internal/orchestrator/... ./internal/traps/cowrieparser/... \
  ./internal/netwrap/... ./internal/traps/webcve/... ./internal/traps/infratrap/... \
  ./internal/malware/... ./internal/notify/... \
  ./cmd/docker-guard-proxy/... ./cmd/sensor-agent/...

# Clean up disposable test containers afterward:
docker rm -f honeypot-test-pg honeypot-test-redis
```

To verify the native YARA-X C API build (`-tags yarax`), build the multi-stage Hive container:

```bash
docker build -f deployments/hive/Dockerfile.hive -t honeypot-hive:dev .
```

---

## 3. Extension Playbooks

### Adding a Declarative Web CVE Pack

1. Create a new YAML pack under [`internal/traps/webcve/packs/`](internal/traps/webcve/packs) (reference an existing pack such as [`nextjs_29927.yaml`](internal/traps/webcve/packs/nextjs_29927.yaml) or [`react2shell_55182.yaml`](internal/traps/webcve/packs/react2shell_55182.yaml) for schema fields: `id`, `cve_id`, `severity`, `matchers`, `response`, `canary_injections`, `extract_urls`). `embed.go` embeds all `*.yaml` files automatically.
2. Add deterministic matching, canary injection, and false-positive negative tests in [`internal/traps/webcve/webcve_test.go`](internal/traps/webcve/webcve_test.go).
3. Verify toggleability via `Engine.TogglePack(cveID, enabled)` and `go test -race -count=1 ./internal/traps/webcve/...`.

### Adding a Native Infrastructure Trap or AI KEV

- **AI Stack KEVs:** Add an HTTP handler module in [`internal/traps/llmproxy/aicves/`](internal/traps/llmproxy/aicves), register its route in [`internal/traps/llmproxy/router.go`](internal/traps/llmproxy/router.go), extract any callback/payload URLs for `SafeDownloader` quarantine, and cover with tests in `llmproxy_test.go`.
- **Network Protocol / Daemon Traps:** Implement the listener/handler in [`internal/traps/infratrap/`](internal/traps/infratrap), wire the new `subtype` into `StartInfraTrap` inside [`cmd/sensor-agent/native_traps.go`](cmd/sensor-agent/native_traps.go) (always wrap HTTP listeners with `netutil.LimitListener` and timeouts), and add tests in `infratrap_test.go`.

### Adding a Containerized Trap Profile

1. Add the pinned image profile to `BuiltinProfiles` in [`internal/orchestrator/profiles.go`](internal/orchestrator/profiles.go) (must enforce non-root `User`, e.g., `"1000:1000"`).
2. Add any required honeyfs seeding in [`internal/orchestrator/honeyfs_seeder.go`](internal/orchestrator/honeyfs_seeder.go) and wire it into `DeployTrap` ([`internal/orchestrator/docker_manager.go`](internal/orchestrator/docker_manager.go)).
3. Allowlist the image repo prefix and any specific environment variable prefixes in [`cmd/docker-guard-proxy/guard.go`](cmd/docker-guard-proxy/guard.go) (`allowedImages`, `allowedEnvPrefixes`), then add escape-rejection and allow tests in [`guard_test.go`](cmd/docker-guard-proxy/guard_test.go).

### Extending Hive <-> Sensor gRPC Contracts

1. Edit [`proto/honeypot/v1/agent.proto`](proto/honeypot/v1/agent.proto) (`AgentFrame` / `HiveCommand` / RPC definitions).
2. Run `make proto` to regenerate `proto/gen/honeypot/v1/`.
3. Implement Hive dispatch/handling in [`internal/hubgrpc/server.go`](internal/hubgrpc/server.go) (enforcing `id.Role == "sensor"` vs `"nginx_guard"`) and Sensor handling in [`cmd/sensor-agent/control.go`](cmd/sensor-agent/control.go).

### Adding Schema Migrations, Admin Endpoints & UI Pages

1. **PostgreSQL Schema:** Create sequential `migrations/0000N_<name>.sql` with `-- +goose Up` / `-- +goose Down` blocks ([`migrations/embed.go`](migrations/embed.go) embeds all SQL automatically). Note: tests run concurrently against shared DBs in CI/local runs—use unique test identifiers or PostgreSQL advisory locks (`pg_advisory_lock`) if modifying singleton tables like `admin_users`.
2. **Admin API:** Register new handlers in `registerRoutes` inside [`internal/adminapi/server.go`](internal/adminapi/server.go) wrapped with `s.withAuth(...)` (automatically enforces TOTP session + `X-CSRF-Token` on non-GET methods) and record mutations via `s.pg.InsertAuditLog(...)`.
3. **Frontend SPA:** Add typed API calls in `web/src/lib/api.ts`, build components/pages under `web/src/pages/`, and render attacker-controlled fields strictly as escaped React text/code nodes (never `dangerouslySetInnerHTML`; Wasm CSP forbids `eval`). Run `pnpm --dir web test` to verify XSS regression checks.

---

## 4. Non-Negotiable Engineering Guardrails

- **Never relax `docker-guard-proxy` validation** (`CapDrop=["ALL"]`, `ReadonlyRootfs=true`, `NetworkMode="trap_isolated_net"`, `DisallowUnknownFields()`, `EvalSymlinks` bind containment).
- **Never emit raw strings into Nginx configs:** `cmd/nginx-guard` must validate every IP/CIDR through `netip.ParsePrefix` before writing `geo{}` blocks.
- **Never bypass SSRF checks in `SafeDownloader`:** all outbound malware fetches from sensors run custom DNS `DialContext` pinning + IP re-validation (`internal/malware/safe_downloader.go`).
- **Never commit secrets or real server infrastructure details:** keep `.env`, `pki/`, `*.pem`, `*.key`, and `/plans/` ignored in [`.gitignore`](.gitignore).
