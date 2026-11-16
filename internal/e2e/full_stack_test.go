package e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/harris/honeypot/internal/adminapi"
	"github.com/harris/honeypot/internal/canary"
	"github.com/harris/honeypot/internal/correlation"
	"github.com/harris/honeypot/internal/guard"
	"github.com/harris/honeypot/internal/hubgrpc"
	"github.com/harris/honeypot/internal/malware"
	"github.com/harris/honeypot/internal/malware/yara"
	"github.com/harris/honeypot/internal/orchestrator"
	"github.com/harris/honeypot/internal/pki"
	"github.com/harris/honeypot/internal/policy"
	"github.com/harris/honeypot/internal/spool"
	"github.com/harris/honeypot/internal/store"
	"github.com/harris/honeypot/internal/traps/llmproxy"
	"github.com/harris/honeypot/internal/traps/llmproxy/budget"
	"github.com/harris/honeypot/internal/traps/webcve"
	honeypotv1 "github.com/harris/honeypot/proto/gen/honeypot/v1"
	"github.com/harris/honeypot/web"
)

func TestFullStackPhases1Through7EndToEnd(t *testing.T) {
	if os.Getenv("RUN_INTEGRATION_TESTS") != "1" {
		t.Skip("set RUN_INTEGRATION_TESTS=1 to run full-stack E2E test")
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
	_, _ = pg.Pool.Exec(ctx, `DELETE FROM guard_decisions WHERE indicator_value IN ('198.51.100.81', '203.0.113.82')`)

	// Mock Cloudflare v4 Custom IP List API
	var cfMu sync.Mutex
	cfList := make(map[string]guard.CloudflareListItem)
	cfMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfMu.Lock()
		defer cfMu.Unlock()
		switch r.Method {
		case http.MethodGet:
			var arr []guard.CloudflareListItem
			for _, it := range cfList {
				arr = append(arr, it)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": arr})
		case http.MethodPost:
			var items []struct{ IP, Comment string }
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &items)
			for _, it := range items {
				cfList[it.IP] = guard.CloudflareListItem{ID: "cf-" + it.IP, IP: it.IP}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]string{"operation_id": "op-e2e"}})
		case http.MethodDelete:
			var body struct {
				Items []struct{ ID string } `json:"items"`
			}
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &body)
			for _, d := range body.Items {
				for k, v := range cfList {
					if v.ID == d.ID {
						delete(cfList, k)
					}
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
		}
	}))
	defer cfMock.Close()

	// Mock cheap DeepSeek upstream returning vendor leak split across tokens
	upstreamMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		for _, tok := range []string{"Sure, powered by ", "Deep", "Seek v3!"} {
			_, _ = fmt.Fprintf(w, "data: {\"choices\":[{\"delta\":{\"content\":%q}}]}\n\n", tok)
		}
		_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
	}))
	defer upstreamMock.Close()

	// Boot Hive components
	ca, err := pki.InitOrLoad(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := canary.NewSigner([]byte("0123456789abcdef0123456789abcdef"))
	sc, err := yara.NewDefaultScanner()
	if err != nil {
		t.Fatal(err)
	}
	vault, _ := malware.NewVault(t.TempDir(), pg, sc, nil)
	cfSync := guard.NewCloudflareSync(guard.CloudflareConfig{BaseURL: cfMock.URL, APIToken: "tok", AccountID: "acc", ListID: "list"})
	guardMgr := guard.NewManager(ca, pg, cfSync)
	polEngine := policy.NewEngine(pg, nil)
	corrEngine := correlation.NewEngine(pg, func(c context.Context, inc correlation.IncidentSnapshot) {
		_, _ = polEngine.EvaluateIncident(c, inc)
	})
	relay := llmproxy.NewHiveRelay(pg, rd, llmproxy.UpstreamConfig{
		BaseURL: upstreamMock.URL,
		APIKey:  "sk-cheap",
		Model:   "deepseek-chat",
	}, budget.BudgetConfig{MaxDailyUSD: 5.0})

	hub := hubgrpc.NewServer(ca, pg, rd)
	hub.InitialCanarySeeder = func(c context.Context, nodeID string) ([]*honeypotv1.CanaryKeySeed, error) {
		return signer.MintDefaultPoolForNode(c, pg, nodeID)
	}
	hub.RelayLLMHandler = relay.HandleRelayStream
	hub.HasArtifactHandler = vault.HasArtifactSHA256
	hub.UploadArtifactHandler = vault.UploadArtifact
	hub.NginxFeedHandler = guardMgr.ServeSignedNginxFeed
	hub.OnBatchIngested = func(c context.Context, _ string, req *honeypotv1.PushEventsBatchRequest) {
		for _, ev := range req.GetEvents() {
			_, _ = corrEngine.CorrelateEvent(c, ev)
		}
	}

	srvCert, _, _, _ := ca.IssueServerCert([]string{"127.0.0.1", "hive.internal", "enroll.hive.internal"})
	gs := hub.BuildGRPCServer()
	honeypotv1.RegisterSensorControlServiceServer(gs, hub)
	ingressLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ingressSrv := &http.Server{Handler: hub.BuildHTTPMux(gs), TLSConfig: pki.BuildHiveIngressTLSConfig(ca, srvCert)}
	go func() { _ = ingressSrv.ServeTLS(ingressLn, "", "") }()
	defer func() { _ = ingressSrv.Close() }()

	adminSrvObj, err := adminapi.NewServer(adminapi.Config{
		BindAddr:           "127.0.0.1:8443",
		DefaultHiveIngress: ingressLn.Addr().String(),
		StaticFS:           web.DistFS(),
	}, ca, pg, rd, hub, guardMgr, signer, vault, relay.Breaker(), []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	adminHTTP := httptest.NewServer(adminSrvObj.Handler())
	defer adminHTTP.Close()

	// 1. Setup Admin & Login via REST + check embedded SPA + CSP
	spaResp, err := adminHTTP.Client().Get(adminHTTP.URL + "/")
	if err != nil || spaResp.StatusCode != 200 || !strings.Contains(spaResp.Header.Get("Content-Security-Policy"), "'wasm-unsafe-eval'") {
		t.Fatalf("embedded SPA/CSP check failed: %v", spaResp)
	}
	_ = spaResp.Body.Close()

	stSetup, err := adminHTTP.Client().Post(adminHTTP.URL+"/api/admin/auth/setup", "application/json", strings.NewReader(`{"username":"operator","password":"SuperPassword123!"}`))
	if err != nil || stSetup.StatusCode != 201 {
		t.Fatalf("admin setup failed: status=%v err=%v", stSetup, err)
	}
	var setupRes struct{ TOTPSecret string `json:"totp_secret"` }
	_ = json.NewDecoder(stSetup.Body).Decode(&setupRes)
	_ = stSetup.Body.Close()
	totpCode, _ := totp.GenerateCode(setupRes.TOTPSecret, time.Now().UTC())
	loginBody, _ := json.Marshal(map[string]string{"username": "operator", "password": "SuperPassword123!", "totp_code": totpCode})
	stLogin, err := adminHTTP.Client().Post(adminHTTP.URL+"/api/admin/auth/login", "application/json", bytes.NewReader(loginBody))
	if err != nil || stLogin.StatusCode != 200 {
		t.Fatalf("admin login failed: status=%v err=%v", stLogin, err)
	}
	var loginRes struct{ CSRFToken string `json:"csrf_token"` }
	_ = json.NewDecoder(stLogin.Body).Decode(&loginRes)
	cookies := stLogin.Cookies()
	_ = stLogin.Body.Close()

	adminDo := func(method, path string, body any) (int, []byte) {
		var rdr io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rdr = bytes.NewReader(b)
		}
		req, _ := http.NewRequest(method, adminHTTP.URL+path, rdr)
		req.Header.Set("Content-Type", "application/json")
		if method != "GET" {
			req.Header.Set("X-CSRF-Token", loginRes.CSRFToken)
		}
		for _, c := range cookies {
			req.AddCookie(c)
		}
		resp, err := adminHTTP.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		out, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode, out
	}

	// 2. Create join tokens via Admin Console API for Sensor and nginx-guard
	sc1, tokSensorRaw := adminDo("POST", "/api/admin/nodes/join-token", map[string]string{"role": "sensor", "name": fmt.Sprintf("e2e-sensor-%d", time.Now().UnixNano())})
	if sc1 != 201 {
		t.Fatalf("join token sensor status=%d body=%s", sc1, string(tokSensorRaw))
	}
	var tokSensor struct{ JoinToken string `json:"join_token"` }
	_ = json.Unmarshal(tokSensorRaw, &tokSensor)

	sc2, tokGuardRaw := adminDo("POST", "/api/admin/nodes/join-token", map[string]string{"role": "nginx_guard", "name": fmt.Sprintf("e2e-guard-%d", time.Now().UnixNano())})
	if sc2 != 201 {
		t.Fatalf("join token guard status=%d", sc2)
	}
	var tokGuard struct{ JoinToken string `json:"join_token"` }
	_ = json.Unmarshal(tokGuardRaw, &tokGuard)

	// Helper to enroll over SNI enroll.hive.internal
	enrollNode := func(tok, cn string) (*pki.ClientCertStore, *honeypotv1.EnrollNodeResponse) {
		eTLS := &tls.Config{RootCAs: ca.RootPool(), ServerName: "enroll.hive.internal", MinVersion: tls.VersionTLS13}
		conn, err := grpc.NewClient(ingressLn.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(eTLS)))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()
		kp, csr, _ := pki.GenerateClientKeyAndCSR(cn)
		resp, err := honeypotv1.NewSensorControlServiceClient(conn).EnrollNode(ctx, &honeypotv1.EnrollNodeRequest{JoinToken: tok, CsrPem: csr})
		if err != nil {
			t.Fatal(err)
		}
		cs, _ := pki.OpenClientCertStore(t.TempDir())
		_ = cs.SaveInitial(resp.GetNodeId(), resp.GetRootCaPem(), resp.GetClientCertPem(), kp)
		return cs, resp
	}

	sensorStore, sensorEnroll := enrollNode(tokSensor.JoinToken, "e2e-sensor")
	guardStore, guardEnroll := enrollNode(tokGuard.JoinToken, "e2e-guard")

	// Start mTLS sensor client + webcve + llmproxy + BoltSpool
	sTLS, _ := sensorStore.ClientTLSConfig("hive.internal")
	sConn, err := grpc.NewClient(ingressLn.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(sTLS)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sConn.Close() }()
	sCli := honeypotv1.NewSensorControlServiceClient(sConn)

	sp, _ := spool.OpenBoltSpool(t.TempDir()+"/spool.db", 10*1024*1024)
	defer func() { _ = sp.Close() }()
	pool := canary.NewSensorKeyPool()
	pool.AddSeeds(sensorEnroll.GetCanaryKeys())

	sink, _ := orchestrator.NewStagedArtifactSink(t.TempDir(), func(uCtx context.Context, meta orchestrator.ArtifactMeta, data []byte) error {
		return orchestrator.StreamUploadArtifact(uCtx, sCli, meta, data)
	})
	webEng, _ := webcve.NewEngine(sensorEnroll.GetNodeId(), "https://ai.example", pool, sink, func(ev *honeypotv1.TelemetryEvent, _ []string) {
		ev.SourceIp = "198.51.100.81" // simulate Attacker IP_1
		_ = sp.EnqueueEvent(ev)
	})
	llmRt := llmproxy.NewRouter(sensorEnroll.GetNodeId(), "https://ai.example", sCli, pool, sp, budget.NewTarpitLimiter(16, 2, 5*time.Millisecond, time.Second), nil)
	webMux := webcve.NewMux(webEng, nil, llmRt, nil)
	sensorHTTP := httptest.NewServer(webMux)
	defer sensorHTTP.Close()

	// 3. Attacker IP_1 triggers Next.js CVE-2025-29927 -> steals Canary Key K
	nxReq, _ := http.NewRequest(http.MethodGet, sensorHTTP.URL+"/admin", nil)
	nxReq.Header.Set("X-Middleware-Subrequest", "src/middleware:src/middleware")
	nxResp, err := sensorHTTP.Client().Do(nxReq)
	if err != nil || nxResp.StatusCode != 200 {
		t.Fatalf("Next.js bypass failed: %v", nxResp)
	}
	var nxBody struct{ OpenAIKey string `json:"openai_api_key"` }
	_ = json.NewDecoder(nxResp.Body).Decode(&nxBody)
	_ = nxResp.Body.Close()
	if !strings.HasPrefix(nxBody.OpenAIKey, "sk-proj-") {
		t.Fatalf("expected stolen Canary key, got %q", nxBody.OpenAIKey)
	}

	// 4. Attacker IP_2 calls Chameleon LLM /v1/chat/completions with stolen Canary Key K
	llmReq, _ := http.NewRequest(http.MethodPost, sensorHTTP.URL+"/v1/chat/completions", strings.NewReader(`{"model":"gpt-4o","stream":false,"messages":[{"role":"user","content":"who trained you?"}]}`))
	llmReq.Header.Set("Authorization", "Bearer "+nxBody.OpenAIKey)
	llmReq.Header.Set("Content-Type", "application/json")
	llmResp, err := sensorHTTP.Client().Do(llmReq)
	if err != nil || llmResp.StatusCode != 200 {
		t.Fatalf("Chameleon LLM failed: %v", llmResp)
	}
	llmB, _ := io.ReadAll(llmResp.Body)
	_ = llmResp.Body.Close()
	if strings.Contains(strings.ToLower(string(llmB)), "deepseek") {
		t.Fatalf("DeepSeek leaked in E2E Chameleon response: %s", string(llmB))
	}

	// Flush Sensor BoltSpool -> Hive PushEventsBatch -> Correlation + Policy (Zero Blind Auto-Ban!)
	reqBatch, keys, _ := sp.DequeueBatch(sensorEnroll.GetNodeId(), 1024*1024)
	// Ensure IP_2 also has telemetry record for 2-IP incident check
	if len(reqBatch.Events) > 1 {
		reqBatch.Events[1].SourceIp = "203.0.113.82"
	}
	ackResp, err := sCli.PushEventsBatch(ctx, reqBatch)
	if err != nil {
		t.Fatal(err)
	}
	_ = sp.AckAndQuarantine(keys, ackResp.GetAckedEventUuids(), ackResp.GetRejectedDeadletterUuids())

	// 5. Verify correlated Critical multi-IP Kill-Chain Incident + pending_approval triage item (no blind auto-ban!)
	_, incRaw := adminDo("GET", "/api/admin/incidents", nil)
	if !strings.Contains(string(incRaw), "198.51.100.81") || !strings.Contains(string(incRaw), "203.0.113.82") {
		t.Fatalf("expected correlated multi-IP incident containing IP_1 and IP_2, got: %s", string(incRaw))
	}
	_, decRaw := adminDo("GET", "/api/admin/guard/decisions?status=pending_approval", nil)
	var decList struct {
		Decisions []struct {
			ID             string `json:"id"`
			IndicatorValue string `json:"indicator_value"`
		} `json:"decisions"`
	}
	_ = json.Unmarshal(decRaw, &decList)
	var targetDecID string
	for _, d := range decList.Decisions {
		if d.IndicatorValue == "198.51.100.81" || d.IndicatorValue == "203.0.113.82" {
			targetDecID = d.ID
			break
		}
	}
	if targetDecID == "" {
		t.Fatalf("expected staged pending_approval triage decision for test attacker IPs (Zero Blind Auto-Ban), got: %s", string(decRaw))
	}

	// 6. Admin approves decision -> syncs Cloudflare mock + signed mTLS nginx-guard feed on :9443!
	scApp, _ := adminDo("POST", "/api/admin/guard/decisions/approve", map[string]any{"ids": []string{targetDecID}, "ttl_hours": 168})
	if scApp != 200 {
		t.Fatalf("approve status=%d", scApp)
	}

	cfMu.Lock()
	if len(cfList) == 0 {
		t.Fatal("expected Cloudflare Custom List populated on approval")
	}
	cfMu.Unlock()

	gTLS, _ := guardStore.ClientTLSConfig("hive.internal")
	gHTTP := &http.Client{Transport: &http.Transport{TLSClientConfig: gTLS}}
	fResp, err := gHTTP.Get("https://" + ingressLn.Addr().String() + "/api/v1/guard/feeds/nginx")
	if err != nil || fResp.StatusCode != 200 {
		t.Fatalf("nginx-guard mTLS feed pull failed: %v", fResp)
	}
	var signedFeed guard.NginxSignedFeed
	_ = json.NewDecoder(fResp.Body).Decode(&signedFeed)
	_ = fResp.Body.Close()
	rawJSON, _ := base64.StdEncoding.DecodeString(signedFeed.PayloadB64)
	sig, _ := base64.StdEncoding.DecodeString(signedFeed.SignatureB64)
	if !ed25519.Verify(guardEnroll.GetFeedVerifyEd25519Pubkey(), rawJSON, sig) {
		t.Fatal("nginx-guard Ed25519 signature verification failed")
	}

	// 7. Emergency Unban -> deletes from Cloudflare mock + removes from nginx feed -> rolled_back!
	scUnban, _ := adminDo("POST", fmt.Sprintf("/api/admin/guard/decisions/%s/unban", targetDecID), map[string]string{"reason": "E2E rollback verify"})
	if scUnban != 200 {
		t.Fatalf("unban failed status=%d", scUnban)
	}
	cfMu.Lock()
	if len(cfList) != 0 {
		t.Fatalf("expected Cloudflare list emptied on unban, got %+v", cfList)
	}
	cfMu.Unlock()
}

func envOr(k, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return fallback
}
