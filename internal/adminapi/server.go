package adminapi

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"path"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/harris/honeypot/internal/canary"
	"github.com/harris/honeypot/internal/guard"
	"github.com/harris/honeypot/internal/hubgrpc"
	"github.com/harris/honeypot/internal/malware"
	"github.com/harris/honeypot/internal/pki"
	"github.com/harris/honeypot/internal/store"
	"github.com/harris/honeypot/internal/traps/llmproxy"
	"github.com/harris/honeypot/internal/traps/llmproxy/budget"
	"github.com/redis/go-redis/v9"
)

// Config configures the zero-public-exposure Admin Console API & SPA server.
type Config struct {
	BindAddr             string
	AdminIface           string   // e.g. tailscale0 | wg0
	UnsafeDevBind        bool
	AllowedPeerCIDRs     []string // defaults to loopback + Tailscale CGNAT + ULA
	CAFingerprintSHA256  string
	DefaultHiveIngress   string
	CloudflareEnterprise bool
	StaticFS             fs.FS
}

// Server serves the private Admin REST API, live WebSocket ticker, and embedded React SPA on :8443.
type Server struct {
	cfg      Config
	ca       *pki.CA
	pg       *store.Postgres
	rd       *redis.Client
	hub      *hubgrpc.Server
	guardMgr *guard.Manager
	canary   *canary.Signer
	vault    *malware.Vault
	breaker  *budget.CircuitBreaker
	llmRelay *llmproxy.HiveRelay
	auth     *AuthManager
	wsHub    *WSHub
	allowed  []netip.Prefix
	mux      *http.ServeMux
	loginMu  sync.Mutex
	loginLim map[string]*rate.Limiter
}

// ValidateAdminBindAddr enforces Zero Public Exposure on :8443:
// Allows ONLY loopback (127.0.0.1 / ::1) or an IP verified to belong to tailscale0/wg0/AdminIface,
// explicitly refusing 0.0.0.0, ::, or generic RFC1918/Docker NICs unless --unsafe-dev-bind is set.
func ValidateAdminBindAddr(bindAddr, adminIface string, unsafeDevBind bool) error {
	host, _, err := net.SplitHostPort(strings.TrimSpace(bindAddr))
	if err != nil || host == "" {
		return fmt.Errorf("invalid admin bind address %q: %w", bindAddr, err)
	}
	if unsafeDevBind {
		return nil
	}
	if host == "127.0.0.1" || host == "::1" || strings.EqualFold(host, "localhost") {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsUnspecified() {
		return fmt.Errorf("refusing unsafe admin bind host %q (0.0.0.0/:: prohibited without --unsafe-dev-bind)", host)
	}
	if adminIface == "" {
		return fmt.Errorf("refusing non-loopback admin bind %q without verified HIVE_ADMIN_IFACE (tailscale0/wg0)", host)
	}
	if adminIface != "tailscale0" && adminIface != "wg0" && !strings.HasPrefix(adminIface, "wg") {
		return fmt.Errorf("admin interface %q must be a VPN interface (tailscale0/wg0)", adminIface)
	}
	iface, err := net.InterfaceByName(adminIface)
	if err != nil {
		return fmt.Errorf("lookup VPN interface %s: %w", adminIface, err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return err
	}
	for _, a := range addrs {
		if ipNet, ok := a.(*net.IPNet); ok && ipNet.IP.Equal(ip) {
			return nil
		}
	}
	return fmt.Errorf("bind IP %s does not belong to VPN interface %s", host, adminIface)
}

// NewServer creates the hardened Admin API + SPA handler.
func NewServer(
	cfg Config,
	ca *pki.CA,
	pg *store.Postgres,
	rd *store.Redis,
	hub *hubgrpc.Server,
	guardMgr *guard.Manager,
	canarySigner *canary.Signer,
	vault *malware.Vault,
	breaker *budget.CircuitBreaker,
	authSecret []byte,
) (*Server, error) {
	if err := ValidateAdminBindAddr(cfg.BindAddr, cfg.AdminIface, cfg.UnsafeDevBind); err != nil {
		return nil, err
	}
	cidrs := cfg.AllowedPeerCIDRs
	if len(cidrs) == 0 {
		cidrs = []string{"127.0.0.0/8", "::1/128", "100.64.0.0/10", "fc00::/7"}
	}
	var allowed []netip.Prefix
	for _, c := range cidrs {
		if p, err := netip.ParsePrefix(strings.TrimSpace(c)); err == nil {
			allowed = append(allowed, p)
		}
	}
	var rc *redis.Client
	if rd != nil {
		rc = rd.Client
	}

	s := &Server{
		cfg:      cfg,
		ca:       ca,
		pg:       pg,
		rd:       rc,
		hub:      hub,
		guardMgr: guardMgr,
		canary:   canarySigner,
		vault:    vault,
		breaker:  breaker,
		auth:     NewAuthManager(pg, authSecret, false),
		wsHub:    NewWSHub(rd),
		allowed:  allowed,
		mux:      http.NewServeMux(),
		loginLim: make(map[string]*rate.Limiter),
	}
	s.registerRoutes()
	return s, nil
}

// SetLLMRelay wires the live HiveRelay instance and restores any persisted runtime LLM settings from Postgres.
func (s *Server) SetLLMRelay(ctx context.Context, r *llmproxy.HiveRelay) {
	s.llmRelay = r
	if s.llmRelay == nil || s.pg == nil {
		return
	}
	var baseURL, model string
	var encKey []byte
	var maxDaily float64
	var allowUnauth bool
	err := s.pg.Pool.QueryRow(ctx, `
		SELECT base_url, api_key_enc, model, max_daily_usd::float8, allow_unauthenticated_chat
		FROM llm_runtime_settings WHERE id = 1
	`).Scan(&baseURL, &encKey, &model, &maxDaily, &allowUnauth)
	if err != nil {
		return
	}
	var apiKey string
	if len(encKey) > 0 {
		if plain, decErr := s.auth.decryptBytes(encKey); decErr == nil {
			apiKey = string(plain)
		}
	}
	s.llmRelay.UpdateConfig(llmproxy.UpstreamConfig{
		BaseURL:                  strings.TrimSpace(baseURL),
		APIKey:                   strings.TrimSpace(apiKey),
		Model:                    strings.TrimSpace(model),
		AllowUnauthenticatedChat: allowUnauth,
	}, maxDaily)
}

// StartBackgroundWorkers launches the WebSocket live feed Redis subscriber loop.
func (s *Server) StartBackgroundWorkers(ctx context.Context) {
	go s.wsHub.Run(ctx)
}

// Handler returns the wrapped http.Handler with strict CSP, Peer CIDR allowlist, Auth, CSRF, and Audit middlewares.
func (s *Server) Handler() http.Handler {
	return s.securityHeadersMiddleware(s.peerAllowlistMiddleware(s.mux))
}

func (s *Server) registerRoutes() {
	// Auth endpoints (no CSRF required for initial setup/login before cookie exists)
	s.mux.HandleFunc("GET /api/admin/auth/status", s.handleAuthStatus)
	s.mux.HandleFunc("POST /api/admin/auth/setup", s.handleAuthSetup)
	s.mux.HandleFunc("POST /api/admin/auth/login", s.handleAuthLogin)
	s.mux.HandleFunc("POST /api/admin/auth/logout", s.withAuth(s.handleAuthLogout))

	// Live WebSocket stream
	s.mux.HandleFunc("GET /api/admin/ws", s.wsHub.ServeWS(s.auth))

	// Overview & Nodes
	s.mux.HandleFunc("GET /api/admin/overview", s.withAuth(s.handleOverview))
	s.mux.HandleFunc("GET /api/admin/nodes", s.withAuth(s.handleListNodes))
	s.mux.HandleFunc("POST /api/admin/nodes/join-token", s.withAuth(s.handleCreateJoinToken))
	s.mux.HandleFunc("POST /api/admin/nodes/{id}/revoke", s.withAuth(s.handleRevokeNode))
	s.mux.HandleFunc("POST /api/admin/nodes/{id}/rotate-cert", s.withAuth(s.handleRotateNodeCert))

	// Traps & CVE Packs
	s.mux.HandleFunc("GET /api/admin/traps", s.withAuth(s.handleListTraps))
	s.mux.HandleFunc("POST /api/admin/traps/deploy", s.withAuth(s.handleDeployTrap))
	s.mux.HandleFunc("POST /api/admin/traps/{id}/stop", s.withAuth(s.handleStopTrap))
	s.mux.HandleFunc("POST /api/admin/traps/{id}/restart", s.withAuth(s.handleRestartTrap))
	s.mux.HandleFunc("POST /api/admin/traps/{id}/logs", s.withAuth(s.handleFetchTrapLogs))
	s.mux.HandleFunc("POST /api/admin/cves/toggle", s.withAuth(s.handleToggleCVE))
	s.mux.HandleFunc("POST /api/admin/traps/poc-preflight", s.withAuth(s.handlePoCPreflight))

	// Guard, Allowlist & Policy Rules
	s.mux.HandleFunc("GET /api/admin/guard/decisions", s.withAuth(s.handleListDecisions))
	s.mux.HandleFunc("POST /api/admin/guard/decisions/approve", s.withAuth(s.handleApproveDecisions))
	s.mux.HandleFunc("POST /api/admin/guard/decisions/{id}/reject", s.withAuth(s.handleRejectDecision))
	s.mux.HandleFunc("POST /api/admin/guard/decisions/{id}/unban", s.withAuth(s.handleUnbanDecision))
	s.mux.HandleFunc("POST /api/admin/guard/manual-block", s.withAuth(s.handleManualBlock))
	s.mux.HandleFunc("GET /api/admin/guard/allowlist", s.withAuth(s.handleListAllowlist))
	s.mux.HandleFunc("POST /api/admin/guard/allowlist", s.withAuth(s.handleAddAllowlist))
	s.mux.HandleFunc("DELETE /api/admin/guard/allowlist/{id}", s.withAuth(s.handleDeleteAllowlist))
	s.mux.HandleFunc("GET /api/admin/guard/rules", s.withAuth(s.handleListPolicyRules))
	s.mux.HandleFunc("POST /api/admin/guard/rules", s.withAuth(s.handleUpsertPolicyRule))
	s.mux.HandleFunc("GET /api/admin/guard/waf-expr", s.withAuth(s.handleWAFExpression))
	s.mux.HandleFunc("GET /api/admin/audit-logs", s.withAuth(s.handleAuditLogs))

	// Telemetry, Incidents & Replays
	s.mux.HandleFunc("GET /api/admin/incidents", s.withAuth(s.handleListIncidents))
	s.mux.HandleFunc("GET /api/admin/incidents/{id}", s.withAuth(s.handleGetIncident))
	s.mux.HandleFunc("GET /api/admin/replays/{id}", s.withAuth(s.handleGetSSHReplay))
	s.mux.HandleFunc("GET /api/admin/telemetry", s.withAuth(s.handleListTelemetry))

	// LLM Spy & Persona Studio
	s.mux.HandleFunc("GET /api/admin/llm/conversations", s.withAuth(s.handleListLLMConversations))
	s.mux.HandleFunc("GET /api/admin/llm/personas", s.withAuth(s.handleListPersonas))
	s.mux.HandleFunc("PUT /api/admin/llm/personas", s.withAuth(s.handleUpsertPersona))
	s.mux.HandleFunc("GET /api/admin/llm/budget", s.withAuth(s.handleLLMBudget))
	s.mux.HandleFunc("GET /api/admin/llm/settings", s.withAuth(s.handleGetLLMSettings))
	s.mux.HandleFunc("PUT /api/admin/llm/settings", s.withAuth(s.handleUpdateLLMSettings))
	s.mux.HandleFunc("POST /api/admin/llm/test", s.withAuth(s.handleTestLLMSettings))

	// Canary Key Factory
	s.mux.HandleFunc("GET /api/admin/canaries", s.withAuth(s.handleListCanaries))
	s.mux.HandleFunc("POST /api/admin/canaries", s.withAuth(s.handleMintCanary))

	// Malware Vault
	s.mux.HandleFunc("GET /api/admin/malware", s.withAuth(s.handleListMalware))
	s.mux.HandleFunc("GET /api/admin/malware/{sha}/preview", s.withAuth(s.handlePreviewMalware))
	s.mux.HandleFunc("GET /api/admin/malware/{sha}/export.zip", s.withAuth(s.handleExportMalwareZip))

	// Embedded SPA
	s.mux.HandleFunc("GET /", s.serveSPA)
}

func (s *Server) securityHeadersMiddleware(next http.Handler) http.Handler {
	const csp = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; worker-src 'self' blob:; connect-src 'self'; object-src 'none'; base-uri 'none'"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", csp)
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) peerAllowlistMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = strings.Trim(r.RemoteAddr, "[]")
		}
		addr, parseErr := netip.ParseAddr(host)
		if parseErr != nil {
			http.Error(w, "forbidden peer address", http.StatusForbidden)
			return
		}
		un := addr.Unmap()
		var ok bool
		for _, pref := range s.allowed {
			if pref.Contains(un) {
				ok = true
				break
			}
		}
		if !ok {
			http.Error(w, "client IP not in ADMIN_ALLOWED_CIDRS", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

type ctxActorKey struct{}

func (s *Server) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, ok := s.auth.VerifyRequestSession(r)
		if !ok {
			writeJSONError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			hdr := strings.TrimSpace(r.Header.Get("X-CSRF-Token"))
			if subtle.ConstantTimeCompare([]byte(hdr), []byte(claims.CSRF)) != 1 {
				writeJSONError(w, http.StatusForbidden, "invalid or missing X-CSRF-Token")
				return
			}
		}
		ctx := context.WithValue(r.Context(), ctxActorKey{}, claims)
		next(w, r.WithContext(ctx))
	}
}

func actorFromCtx(r *http.Request) sessionClaims {
	c, _ := r.Context().Value(ctxActorKey{}).(sessionClaims)
	return c
}

func (s *Server) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	var count int
	_ = s.pg.Pool.QueryRow(r.Context(), `SELECT COUNT(*) FROM admin_users`).Scan(&count)
	claims, loggedIn := s.auth.VerifyRequestSession(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"initialized": count > 0,
		"logged_in":   loggedIn,
		"username":    claims.Username,
		"csrf_token":  claims.CSRF,
	})
}

func (s *Server) handleAuthSetup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	uri, secret, err := s.auth.SetupInitialAdmin(r.Context(), req.Username, req.Password)
	if err != nil {
		writeJSONError(w, http.StatusConflict, err.Error())
		return
	}
	_ = s.pg.InsertAuditLog(r.Context(), req.Username, "admin_setup", "admin_user", req.Username, nil, remoteHost(r))
	writeJSON(w, http.StatusCreated, map[string]string{
		"totp_uri":    uri,
		"totp_secret": secret,
	})
}

func (s *Server) allowLoginAttempt(ip string) bool {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	lim, ok := s.loginLim[ip]
	if !ok {
		if len(s.loginLim) > 1024 {
			s.loginLim = make(map[string]*rate.Limiter)
		}
		lim = rate.NewLimiter(rate.Every(10*time.Second), 5)
		s.loginLim[ip] = lim
	}
	return lim.Allow()
}

func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if !s.allowLoginAttempt(remoteHost(r)) {
		writeJSONError(w, http.StatusTooManyRequests, "too many login attempts; slow down")
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		TOTPCode string `json:"totp_code"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	cookieVal, csrf, err := s.auth.Authenticate(r.Context(), req.Username, req.Password, req.TOTPCode)
	if err != nil {
		_ = s.pg.InsertAuditLog(r.Context(), req.Username, "admin_login_failed", "admin_user", req.Username, nil, remoteHost(r))
		writeJSONError(w, http.StatusUnauthorized, err.Error())
		return
	}
	s.auth.SetSessionCookie(w, cookieVal)
	_ = s.pg.InsertAuditLog(r.Context(), req.Username, "admin_login", "admin_user", req.Username, nil, remoteHost(r))
	writeJSON(w, http.StatusOK, map[string]any{
		"username":   req.Username,
		"csrf_token": csrf,
	})
}

func (s *Server) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	s.auth.ClearSessionCookie(w)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) serveSPA(w http.ResponseWriter, r *http.Request) {
	if s.cfg.StaticFS == nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<!doctype html><html><body><div id=\"root\">Honeypot Admin API</div></body></html>"))
		return
	}
	clean := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
	if clean == "" {
		clean = "index.html"
	}
	if _, err := fs.Stat(s.cfg.StaticFS, clean); err != nil || strings.HasSuffix(clean, "/") {
		clean = "index.html"
	}
	raw, err := fs.ReadFile(s.cfg.StaticFS, clean)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	switch {
	case strings.HasSuffix(clean, ".html"):
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	case strings.HasSuffix(clean, ".js"):
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	case strings.HasSuffix(clean, ".css"):
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	case strings.HasSuffix(clean, ".wasm"):
		w.Header().Set("Content-Type", "application/wasm")
	case strings.HasSuffix(clean, ".svg"):
		w.Header().Set("Content-Type", "image/svg+xml")
	}
	_, _ = w.Write(raw)
}

func decodeJSON(r *http.Request, dst any) error {
	if r.Body == nil {
		return errors.New("empty request body")
	}
	return json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20)).Decode(dst)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func remoteHost(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return strings.Trim(r.RemoteAddr, "[]")
	}
	return h
}
