package main

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/harris/honeypot/internal/adminapi"
	"github.com/harris/honeypot/internal/canary"
	"github.com/harris/honeypot/internal/correlation"
	"github.com/harris/honeypot/internal/enrichment"
	"github.com/harris/honeypot/internal/guard"
	"github.com/harris/honeypot/internal/hubgrpc"
	"github.com/harris/honeypot/internal/malware"
	"github.com/harris/honeypot/internal/malware/yara"
	"github.com/harris/honeypot/internal/notify"
	"github.com/harris/honeypot/internal/pki"
	"github.com/harris/honeypot/internal/policy"
	"github.com/harris/honeypot/internal/store"
	"github.com/harris/honeypot/internal/traps/llmproxy"
	"github.com/harris/honeypot/internal/traps/llmproxy/budget"
	honeypotv1 "github.com/harris/honeypot/proto/gen/honeypot/v1"
	"github.com/harris/honeypot/web"
)

func main() {
	var (
		pgDSN         = flag.String("postgres-dsn", envOr("HIVE_POSTGRES_DSN", "postgres://honeypot:honeypot_test_pw@127.0.0.1:5432/honeypot?sslmode=disable"), "PostgreSQL DSN")
		redisAddr     = flag.String("redis-addr", envOr("HIVE_REDIS_ADDR", "127.0.0.1:6379"), "Redis address")
		pkiDir        = flag.String("pki-dir", envOr("HIVE_PKI_DIR", "/var/lib/honeypot-hive/pki"), "PKI state directory")
		vaultDir      = flag.String("vault-dir", envOr("HIVE_VAULT_DIR", envOr("HIVE_QUARANTINE_DIR", "/var/lib/honeypot-hive/quarantine")), "Malware quarantine vault directory")
		ingressAddr   = flag.String("ingress-addr", envOr("HIVE_INGRESS_ADDR", ":9443"), "mTLS Sensor/Guard ingress bind address")
		ingressSANs   = flag.String("ingress-sans", envOr("HIVE_INGRESS_SANS", "127.0.0.1,localhost,hive.internal,enroll.hive.internal"), "Comma-separated SANs for Hive server cert")
		adminBind     = flag.String("admin-bind", envOr("HIVE_ADMIN_BIND_ADDR", "127.0.0.1:8443"), "Private Admin Console bind address (loopback or VPN interface ONLY)")
		adminIface    = flag.String("admin-iface", envOr("HIVE_ADMIN_IFACE", ""), "Verified VPN interface name when binding non-loopback admin IP (tailscale0/wg0)")
		unsafeDevBind = flag.Bool("unsafe-dev-bind", false, "Allow binding Admin Console to non-private interface (DANGEROUS: dev only)")
		adminCIDRs    = flag.String("admin-allowed-cidrs", envOr("ADMIN_ALLOWED_CIDRS", "127.0.0.0/8,::1/128,100.64.0.0/10,fc00::/7"), "Comma-separated CIDRs permitted to access Admin Console")
		createToken   = flag.String("create-join-token", "", "Create one-time join token for <role>:<name> (e.g., sensor:vps-sg-1) and exit")
	)
	flag.Parse()

	if *createToken == "" {
		if err := adminapi.ValidateAdminBindAddr(*adminBind, *adminIface, *unsafeDevBind); err != nil {
			log.Fatalf("SECURITY REFUSAL: %v", err)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ca, err := pki.InitOrLoad(*pkiDir)
	if err != nil {
		log.Fatalf("init PKI: %v", err)
	}
	pg, err := store.OpenPostgres(ctx, *pgDSN)
	if err != nil {
		log.Fatalf("open postgres: %v", err)
	}
	defer pg.Close()

	if *createToken != "" {
		role, name, ok := strings.Cut(*createToken, ":")
		if !ok || name == "" {
			log.Fatalf("expected <role>:<name>, got %q", *createToken)
		}
		raw, hash, err := pki.GenerateJoinToken()
		if err != nil {
			log.Fatalf("generate join token: %v", err)
		}
		id, err := pg.CreateJoinToken(ctx, hash, role, name, "default", 24*time.Hour)
		if err != nil {
			log.Fatalf("store join token: %v", err)
		}
		fmt.Printf("TOKEN_ID=%s\nJOIN_TOKEN=%s\nCA_FINGERPRINT=%s\n", id, raw, ca.RootFingerprintSHA256())
		return
	}

	rd, err := store.OpenRedis(ctx, *redisAddr)
	if err != nil {
		log.Fatalf("open redis: %v", err)
	}
	defer func() { _ = rd.Close() }()

	srvCert, _, _, err := ca.IssueServerCert(strings.Split(*ingressSANs, ","))
	if err != nil {
		log.Fatalf("issue server cert: %v", err)
	}

	canarySecret, err := loadOrCreateCanaryMasterKey(*pkiDir)
	if err != nil {
		log.Fatalf("load canary master key: %v", err)
	}
	canarySigner, err := canary.NewSigner(canarySecret)
	if err != nil {
		log.Fatalf("init canary signer: %v", err)
	}

	hub := hubgrpc.NewServer(ca, pg, rd)
	hub.InitialCanarySeeder = func(ctx context.Context, nodeID string) ([]*honeypotv1.CanaryKeySeed, error) {
		return canarySigner.MintDefaultPoolForNode(ctx, pg, nodeID)
	}
	maxDailyUSD := 5.0
	if rawMax := envOr("HIVE_LLM_MAX_DAILY_USD", ""); rawMax != "" {
		if parsed, pErr := strconv.ParseFloat(rawMax, 64); pErr == nil && parsed >= 0 {
			maxDailyUSD = parsed
		}
	}
	llmRelay := llmproxy.NewHiveRelay(pg, rd, llmproxy.UpstreamConfig{
		BaseURL: envOr("HIVE_UPSTREAM_LLM_URL", ""),
		APIKey:  envOr("HIVE_UPSTREAM_LLM_KEY", ""),
		Model:   envOr("HIVE_UPSTREAM_LLM_MODEL", "deepseek-v4"),
	}, budget.BudgetConfig{MaxDailyUSD: maxDailyUSD})
	hub.RelayLLMHandler = llmRelay.HandleRelayStream

	yaraScanner, err := yara.NewDefaultScanner()
	if err != nil {
		log.Fatalf("init yara scanner: %v", err)
	}
	defer func() { _ = yaraScanner.Close() }()

	geo := enrichment.OpenGeoResolver(envOr("HIVE_GEOIP_CITY_MMDB", ""), envOr("HIVE_GEOIP_ASN_MMDB", ""))
	defer geo.Close()

	cfSync := guard.NewCloudflareSync(guard.CloudflareConfig{
		APIToken:  envOr("CLOUDFLARE_API_TOKEN", ""),
		AccountID: envOr("CLOUDFLARE_ACCOUNT_ID", ""),
		ListID:    envOr("CLOUDFLARE_LIST_ID", ""),
	})
	guardMgr := guard.NewManager(ca, pg, cfSync)
	hub.NginxFeedHandler = guardMgr.ServeSignedNginxFeed

	notifier := notify.NewDispatcher(notify.Config{
		TelegramBotToken: envOr("TELEGRAM_BOT_TOKEN", ""),
		TelegramChatID:   envOr("TELEGRAM_CHAT_ID", ""),
		DiscordWebhook:   envOr("DISCORD_WEBHOOK_URL", ""),
		GenericWebhook:   envOr("ALERT_WEBHOOK_URL", ""),
	})
	go notifier.Run(ctx)

	policyEngine := policy.NewEngine(pg, func(pCtx context.Context, decisionID string) {
		if aErr := guardMgr.ApproveDecision(pCtx, decisionID, "policy_auto_enforce", "", 0); aErr != nil {
			log.Printf("auto_enforce sync error for %s: %v", decisionID, aErr)
		}
	})
	corrEngine := correlation.NewEngine(pg, func(pCtx context.Context, inc correlation.IncidentSnapshot) {
		if _, pErr := policyEngine.EvaluateIncident(pCtx, inc); pErr != nil {
			log.Printf("policy evaluate incident %s error: %v", inc.ID, pErr)
		}
		if inc.ConfidenceScore >= 80 || len(inc.CanaryKeyIDs) > 0 {
			notifier.Enqueue(notify.AlertEvent{
				RuleKey:  inc.CorrelationKey,
				Severity: inc.Severity,
				Title:    inc.Title,
				SourceIP: inc.PrimaryIP,
				Details:  fmt.Sprintf("traps=%v cves=%v", inc.TrapKinds, inc.CVEIDs),
			})
		}
	})

	go func() {
		t := time.NewTicker(1 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				_, _ = guardMgr.ExpireTTLs(ctx)
				guardMgr.ReconcilePending(ctx)
			}
		}
	}()
	intelClient := enrichment.NewClient(pg, rd, geo, enrichment.Config{
		GreyNoiseAPIKey:  envOr("GREYNOISE_API_KEY", ""),
		AbuseIPDBAPIKey:  envOr("ABUSEIPDB_API_KEY", ""),
		VirusTotalAPIKey: envOr("VIRUSTOTAL_API_KEY", ""),
	})
	intelClient.OnEnriched = func(eCtx context.Context, ip string, intel enrichment.IPIntel) {
		_ = corrEngine.ReevaluateAfterEnrichment(eCtx, ip, intel.GreyNoise, intel.AbuseScore, "", nil)
	}

	vault, err := malware.NewVault(*vaultDir, pg, yaraScanner, func(vCtx context.Context, shaHex, _, _ string, matches []string) {
		go func(s string, m []string) {
			bCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_, _ = intelClient.EnrichArtifactHash(bCtx, s)
			_ = corrEngine.ReevaluateAfterEnrichment(bCtx, "", "", 0, s, m)
		}(shaHex, matches)
	})
	if err != nil {
		log.Fatalf("init malware vault: %v", err)
	}
	hub.HasArtifactHandler = vault.HasArtifactSHA256
	hub.UploadArtifactHandler = vault.UploadArtifact
	hub.OnBatchIngested = func(bCtx context.Context, _ string, req *honeypotv1.PushEventsBatchRequest) {
		for _, ev := range req.GetEvents() {
			_, _ = corrEngine.CorrelateEvent(bCtx, ev)
			if ev.GetSeverityScore() >= 40 && ev.GetSourceIp() != "" {
				ip := ev.GetSourceIp()
				sev := ev.GetSeverityScore()
				go func(targetIP string, score int32) {
					c, cancel := context.WithTimeout(context.Background(), 8*time.Second)
					defer cancel()
					_, _ = intelClient.EnrichIP(c, targetIP, score)
				}(ip, sev)
			}
		}
	}
	hub.OnCommandFrame = func(nodeID string, ack *honeypotv1.CommandAck, chunk *honeypotv1.ContainerLogChunk) {
		if ack != nil && !ack.GetOk() {
			log.Printf("node=%s cmd=%s failed: %s", nodeID, ack.GetCommandId(), ack.GetMessage())
		}
		if chunk != nil {
			log.Printf("node=%s deployment=%s log: %s", nodeID, chunk.GetDeploymentId(), chunk.GetLine())
		}
	}
	gs := hub.BuildGRPCServer()
	honeypotv1.RegisterSensorControlServiceServer(gs, hub)

	ingressSrv := &http.Server{
		Addr:              *ingressAddr,
		Handler:           hub.BuildHTTPMux(gs),
		TLSConfig:         pki.BuildHiveIngressTLSConfig(ca, srvCert),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("Hive mTLS ingress listening on %s (CA fp=%s)", *ingressAddr, ca.RootFingerprintSHA256())
		if err := ingressSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Fatalf("ingress server error: %v", err)
		}
	}()

	var peerCIDRs []string
	for _, c := range strings.Split(*adminCIDRs, ",") {
		if t := strings.TrimSpace(c); t != "" {
			peerCIDRs = append(peerCIDRs, t)
		}
	}
	adminAPI, err := adminapi.NewServer(adminapi.Config{
		BindAddr:             *adminBind,
		AdminIface:           *adminIface,
		UnsafeDevBind:        *unsafeDevBind,
		AllowedPeerCIDRs:     peerCIDRs,
		DefaultHiveIngress:   envOr("HIVE_PUBLIC_INGRESS", "enroll.hive.internal:9443"),
		CloudflareEnterprise: strings.EqualFold(envOr("CLOUDFLARE_ENTERPRISE_JA4_ENABLED", "false"), "true"),
		StaticFS:             web.DistFS(),
	}, ca, pg, rd, hub, guardMgr, canarySigner, vault, llmRelay.Breaker(), canarySecret)
	if err != nil {
		log.Fatalf("init admin console server: %v", err)
	}
	adminAPI.SetLLMRelay(ctx, llmRelay)
	adminAPI.StartBackgroundWorkers(ctx)

	adminSrv := &http.Server{
		Addr:              *adminBind,
		Handler:           adminAPI.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		log.Printf("Hive private Admin Console listening on http://%s (SSH tunnel: ssh -L 8443:%s user@hive-vps)", *adminBind, *adminBind)
		if err := adminSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("admin server error: %v", err)
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = adminSrv.Shutdown(shutdownCtx)
	_ = ingressSrv.Shutdown(shutdownCtx)
	gs.GracefulStop()
}

func envOr(k, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return fallback
}

func loadOrCreateCanaryMasterKey(pkiDir string) ([]byte, error) {
	if env := strings.TrimSpace(os.Getenv("HIVE_CANARY_MASTER_KEY")); env != "" {
		return []byte(env), nil
	}
	path := filepath.Join(pkiDir, "canary_master.key")
	if b, err := os.ReadFile(path); err == nil && len(b) >= 32 {
		return b, nil
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		return nil, err
	}
	return buf, nil
}
