package adminapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	yekazip "github.com/yeka/zip"

	"github.com/harris/honeypot/internal/canary"
	"github.com/harris/honeypot/internal/guard"
	"github.com/harris/honeypot/internal/malware"
	"github.com/harris/honeypot/internal/malware/yara"
	"github.com/harris/honeypot/internal/pki"
	"github.com/harris/honeypot/internal/store"
)

func TestAdminBindAddrZeroPublicExposureValidation(t *testing.T) {
	if err := ValidateAdminBindAddr("0.0.0.0:8443", "", false); err == nil {
		t.Fatal("expected refusal for 0.0.0.0:8443 without --unsafe-dev-bind")
	}
	if err := ValidateAdminBindAddr("[::]:8443", "tailscale0", false); err == nil {
		t.Fatal("expected refusal for [::]:8443 without --unsafe-dev-bind")
	}
	if err := ValidateAdminBindAddr("192.168.1.10:8443", "eth0", false); err == nil {
		t.Fatal("expected refusal for non-VPN interface eth0")
	}
	if err := ValidateAdminBindAddr("127.0.0.1:8443", "", false); err != nil {
		t.Fatalf("expected 127.0.0.1:8443 allowed, got %v", err)
	}
	if err := ValidateAdminBindAddr("0.0.0.0:8443", "", true); err != nil {
		t.Fatalf("expected --unsafe-dev-bind explicitly allowed, got %v", err)
	}
}

func TestAdminAPIAuthTOTPCSRFCSPAndAES256ZipExport(t *testing.T) {
	if os.Getenv("RUN_INTEGRATION_TESTS") != "1" {
		t.Skip("set RUN_INTEGRATION_TESTS=1 for AdminAPI DB/Redis test")
	}
	ctx := context.Background()
	pgDSN := envOr("HIVE_POSTGRES_DSN", "postgres://honeypot:honeypot_test_pw@127.0.0.1:15432/honeypot?sslmode=disable")
	redisAddr := envOr("HIVE_REDIS_ADDR", "127.0.0.1:16379")

	pg, err := store.OpenPostgres(ctx, pgDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	rd, err := store.OpenRedis(ctx, redisAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rd.Close() }()

	lockConn, err := pg.Pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire advisory lock conn: %v", err)
	}
	if _, err := lockConn.Exec(ctx, `SELECT pg_advisory_lock(73918299)`); err != nil {
		lockConn.Release()
		t.Fatalf("pg_advisory_lock: %v", err)
	}
	defer func() {
		_, _ = lockConn.Exec(context.Background(), `SELECT pg_advisory_unlock(73918299)`)
		lockConn.Release()
	}()

	_, _ = pg.Pool.Exec(ctx, `DELETE FROM admin_users`)

	ca, _ := pki.InitOrLoad(t.TempDir())
	signer, _ := canary.NewSigner([]byte("0123456789abcdef0123456789abcdef"))
	sc, _ := yara.NewDefaultScanner()
	vaultDir := t.TempDir()
	vault, err := malware.NewVault(vaultDir, pg, sc, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Write a known quarantined sample & DB row to verify AE-2 AES-256 ZIP export
	sample := []byte("#!/bin/sh\necho malware_test\n")
	shaHex := strings.Repeat("b", 64)
	_ = os.MkdirAll(vaultDir+"/bb", 0o700)
	_ = os.WriteFile(vaultDir+"/bb/"+shaHex+".bin", sample, 0o400)
	_, _ = pg.UpsertMalwareArtifact(ctx, shaHex, strings.Repeat("c", 32), int64(len(sample)), "text/x-sh", "http://evil/x.sh", vaultDir+"/bb/"+shaHex+".bin", []string{"Test"})

	srv, err := NewServer(Config{
		BindAddr: "127.0.0.1:8443",
	}, ca, pg, rd, nil, guard.NewManager(ca, pg, nil), signer, vault, nil, []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// 1. Setup initial Admin -> returns TOTP secret
	setupResp, err := ts.Client().Post(ts.URL+"/api/admin/auth/setup", "application/json", strings.NewReader(`{"username":"operator","password":"SuperSecretPassword1!"}`))
	if err != nil || setupResp.StatusCode != 201 {
		t.Fatalf("admin setup failed: %v %v", setupResp, err)
	}
	var setupData struct {
		TOTPSecret string `json:"totp_secret"`
	}
	_ = json.NewDecoder(setupResp.Body).Decode(&setupData)
	_ = setupResp.Body.Close()

	// Verify strict Wasm-compatible CSP header
	csp := setupResp.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "'wasm-unsafe-eval'") || strings.Contains(csp, "'unsafe-eval'") {
		t.Fatalf("unexpected CSP header: %q", csp)
	}

	// 2. Login with Argon2id + valid TOTP code
	code, err := totp.GenerateCode(setupData.TOTPSecret, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	loginBody, _ := json.Marshal(map[string]string{
		"username":  "operator",
		"password":  "SuperSecretPassword1!",
		"totp_code": code,
	})
	loginResp, err := ts.Client().Post(ts.URL+"/api/admin/auth/login", "application/json", bytes.NewReader(loginBody))
	if err != nil || loginResp.StatusCode != 200 {
		t.Fatalf("admin login failed: %v", loginResp)
	}
	var loginData struct {
		CSRFToken string `json:"csrf_token"`
	}
	_ = json.NewDecoder(loginResp.Body).Decode(&loginData)
	cookies := loginResp.Cookies()
	_ = loginResp.Body.Close()
	if len(cookies) == 0 || loginData.CSRFToken == "" {
		t.Fatal("expected HttpOnly cookie + CSRF token on login")
	}

	// 3. Mutating request WITHOUT CSRF token must be rejected 403
	reqNoCSRF, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/admin/canaries", strings.NewReader(`{"provider_style":"openai"}`))
	for _, c := range cookies {
		reqNoCSRF.AddCookie(c)
	}
	noCSRFResp, err := ts.Client().Do(reqNoCSRF)
	if err != nil || noCSRFResp.StatusCode != 403 {
		t.Fatalf("expected 403 without X-CSRF-Token, got %v", noCSRFResp)
	}
	_ = noCSRFResp.Body.Close()

	// 4. Mutating request WITH CSRF token succeeds
	reqCSRF, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/admin/canaries", strings.NewReader(`{"provider_style":"openai","placement_source":"test_admin"}`))
	reqCSRF.Header.Set("X-CSRF-Token", loginData.CSRFToken)
	for _, c := range cookies {
		reqCSRF.AddCookie(c)
	}
	csrfResp, err := ts.Client().Do(reqCSRF)
	if err != nil || csrfResp.StatusCode != 201 {
		t.Fatalf("expected 201 with valid CSRF token, got %v", csrfResp)
	}
	_ = csrfResp.Body.Close()

	// 5. Cross-origin WebSocket upgrade must be rejected 403
	wsReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/admin/ws", nil)
	wsReq.Header.Set("Origin", "https://evil.example.com")
	for _, c := range cookies {
		wsReq.AddCookie(c)
	}
	wsResp, err := ts.Client().Do(wsReq)
	if err != nil || wsResp.StatusCode != 403 {
		t.Fatalf("expected cross-origin WS rejected 403, got %v", wsResp)
	}
	_ = wsResp.Body.Close()

	// 6. Export AES-256 encrypted WinZip AE-2 malware archive & verify decryption
	zipReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/admin/malware/"+shaHex+"/export.zip?password=infected", nil)
	for _, c := range cookies {
		zipReq.AddCookie(c)
	}
	zipResp, err := ts.Client().Do(zipReq)
	if err != nil || zipResp.StatusCode != 200 {
		t.Fatalf("malware zip export failed: %v", zipResp)
	}
	zipBytes, _ := io.ReadAll(zipResp.Body)
	_ = zipResp.Body.Close()

	zr, err := yekazip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil || len(zr.File) != 1 || zr.File[0].Name != shaHex+".bin" {
		t.Fatalf("unexpected AE-2 zip structure: err=%v files=%v", err, zr)
	}
	zr.File[0].SetPassword("infected")
	rc, err := zr.File[0].Open()
	if err != nil {
		t.Fatal(err)
	}
	decrypted, _ := io.ReadAll(rc)
	_ = rc.Close()
	if !bytes.Equal(decrypted, sample) {
		t.Fatalf("decrypted zip sample mismatch: got %q want %q", string(decrypted), string(sample))
	}
}

func envOr(k, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return fallback
}
