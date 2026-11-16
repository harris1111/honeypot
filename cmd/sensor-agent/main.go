package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/harris/honeypot/internal/canary"
	"github.com/harris/honeypot/internal/malware"
	"github.com/harris/honeypot/internal/orchestrator"
	"github.com/harris/honeypot/internal/pki"
	"github.com/harris/honeypot/internal/spool"
	honeypotv1 "github.com/harris/honeypot/proto/gen/honeypot/v1"
)

func main() {
	var (
		stateDir       = flag.String("state-dir", envOr("SENSOR_STATE_DIR", "/var/lib/honeypot-sensor"), "Sensor state directory")
		hiveAddr       = flag.String("hive-addr", envOr("SENSOR_HIVE_ADDR", "127.0.0.1:9443"), "Hive ingress host:port")
		hiveSNI        = flag.String("hive-sni", envOr("SENSOR_HIVE_SNI", "hive.internal"), "Hive mTLS server name")
		enrollSNI      = flag.String("enroll-sni", envOr("SENSOR_ENROLL_SNI", "enroll.hive.internal"), "Hive bootstrap SNI")
		joinToken      = flag.String("enroll-token", "", "One-time join token to enroll this sensor node")
		caFingerprint  = flag.String("ca-fingerprint", "", "Expected SHA-256 hex fingerprint of Hive Root CA")
		publicIPv4     = flag.String("public-ipv4", "", "Reported public IPv4")
		dockerProxyURL = flag.String("docker-proxy", envOr("SENSOR_DOCKER_PROXY", "http://127.0.0.1:23750"), "docker-guard-proxy base URL")
		aiGatewayURL   = flag.String("ai-gateway-url", envOr("SENSOR_AI_GATEWAY_URL", "https://ai-proxy.internal-gw.local"), "Injected fake AI gateway URL for honeypot breadcrumbs")
		httpAddr       = flag.String("http-addr", envOr("SENSOR_HTTP_ADDR", ""), "Public HTTP deception listener addr (e.g. :80)")
		httpsAddr      = flag.String("https-addr", envOr("SENSOR_HTTPS_ADDR", ""), "Public Dual-Mode TLS/JA4 listener addr (e.g. :443)")
		decoyDomains   = flag.String("decoy-domains", envOr("SENSOR_DECOY_DOMAINS", ""), "Comma-separated ACME decoy domains")
		acmeEmail      = flag.String("acme-email", envOr("SENSOR_ACME_EMAIL", ""), "ACME registration email for decoy domains")
	)
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	certStore, err := pki.OpenClientCertStore(filepath.Join(*stateDir, "pki"))
	if err != nil {
		log.Fatalf("open cert store: %v", err)
	}
	bootState := loadBootstrapState(filepath.Join(*stateDir, "bootstrap.json"))

	if *joinToken != "" {
		resp, err := enroll(ctx, certStore, *hiveAddr, *enrollSNI, *joinToken, *caFingerprint, *publicIPv4)
		if err != nil {
			log.Fatalf("enroll failed: %v", err)
		}
		if err := bootState.SaveInitialEnrollment(resp); err != nil {
			log.Fatalf("save bootstrap state: %v", err)
		}
		log.Printf("Enrolled sensor node_id=%s canary_seeds=%d", certStore.NodeID(), len(resp.GetCanaryKeys()))
		if flag.NArg() == 0 && !envBool("SENSOR_RUN_AFTER_ENROLL") {
			return
		}
	}

	if !certStore.IsEnrolled() {
		log.Fatal("sensor not enrolled; run with --enroll-token and --ca-fingerprint")
	}

	sp, err := spool.OpenBoltSpool(filepath.Join(*stateDir, "spool.db"), 512*1024*1024)
	if err != nil {
		log.Fatalf("open bolt spool: %v", err)
	}
	defer func() { _ = sp.Close() }()

	tlsCfg, err := certStore.ClientTLSConfig(*hiveSNI)
	if err != nil {
		log.Fatalf("client TLS config: %v", err)
	}
	conn, err := grpc.NewClient(*hiveAddr, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		log.Fatalf("dial hive: %v", err)
	}
	defer func() { _ = conn.Close() }()

	client := honeypotv1.NewSensorControlServiceClient(conn)
	keyPool := canary.NewSensorKeyPool()
	keyPool.AddSeeds(bootState.CanarySeeds)

	artifactSink, err := orchestrator.NewStagedArtifactSink(filepath.Join(*stateDir, "artifacts"), func(upCtx context.Context, meta orchestrator.ArtifactMeta, data []byte) error {
		return orchestrator.StreamUploadArtifact(upCtx, client, meta, data)
	})
	if err != nil {
		log.Fatalf("init artifact sink: %v", err)
	}

	var domains []string
	for _, d := range strings.Split(*decoyDomains, ",") {
		if trimmed := strings.TrimSpace(d); trimmed != "" {
			domains = append(domains, trimmed)
		}
	}
	nativeRT, err := newNativeTrapRuntime(ctx, certStore.NodeID(), *stateDir, *aiGatewayURL, domains, *acmeEmail, sp, keyPool, artifactSink)
	if err != nil {
		log.Fatalf("init native trap runtime: %v", err)
	}
	nativeRT.SetLLMClient(client)
	defer nativeRT.CloseAll()

	safeDL := malware.NewSafeDownloader(certStore.NodeID(), artifactSink, bootState.Allowlist)
	nativeRT.onURLsExtract = func(_ context.Context, srcIP, eventUUID string, urls []string) {
		for _, u := range urls {
			go func(targetURL, ip, evID string) {
				dCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
				defer cancel()
				_, _ = safeDL.Fetch(dCtx, targetURL, ip, evID)
			}(u, srcIP, eventUUID)
		}
	}

	// Replay saved CVE toggles
	for cveID, en := range bootState.CveToggles {
		nativeRT.ToggleCVE(cveID, en)
	}

	if err := nativeRT.StartWebListeners(*httpAddr, *httpsAddr); err != nil {
		log.Fatalf("start web deception listeners: %v", err)
	}

	ctrl := newSensorController(certStore.NodeID(), *stateDir, *dockerProxyURL, *aiGatewayURL, certStore, bootState, sp, keyPool, artifactSink)
	ctrl.nativeRT = nativeRT
	ctrl.safeDownloader = safeDL
	ctrl.onToggleCvePack = func(cveID string, enabled bool) {
		nativeRT.ToggleCVE(cveID, enabled)
	}
	ctrl.ReconcileOnStartup(ctx)

	go ctrl.RunControlStream(ctx, client)
	go flushSpoolLoop(ctx, client, certStore.NodeID(), sp)

	log.Printf("sensor-agent running node_id=%s -> hive=%s", certStore.NodeID(), *hiveAddr)
	<-ctx.Done()
}

func enroll(ctx context.Context, store *pki.ClientCertStore, hiveAddr, enrollSNI, token, expectedFP, publicIPv4 string) (*honeypotv1.EnrollNodeResponse, error) {
	if expectedFP == "" {
		return nil, errors.New("--ca-fingerprint is required to pin Root CA during enrollment")
	}
	keyPEM, csrPEM, err := pki.GenerateClientKeyAndCSR("sensor-bootstrap")
	if err != nil {
		return nil, err
	}
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		ServerName:         enrollSNI,
		InsecureSkipVerify: true, // Verified via pinned CA SHA-256 fingerprint before sending join_token
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("server presented no certificates")
			}
			var matchedCA bool
			var caCert *x509.Certificate
			for _, raw := range rawCerts {
				sum := sha256.Sum256(raw)
				if strings.EqualFold(hex.EncodeToString(sum[:]), strings.TrimSpace(expectedFP)) {
					matchedCA = true
					c, err := x509.ParseCertificate(raw)
					if err == nil {
						caCert = c
					}
					break
				}
			}
			if !matchedCA || caCert == nil {
				return errors.New("server certificate chain does not match pinned Hive CA fingerprint")
			}
			leaf, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}
			pool := x509.NewCertPool()
			pool.AddCert(caCert)
			_, err = leaf.Verify(x509.VerifyOptions{
				Roots:     pool,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			})
			return err
		},
	}
	conn, err := grpc.NewClient(hiveAddr, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	client := honeypotv1.NewSensorControlServiceClient(conn)
	resp, err := client.EnrollNode(ctx, &honeypotv1.EnrollNodeRequest{
		JoinToken:    token,
		CsrPem:       csrPEM,
		PublicIpv4:   publicIPv4,
		AgentVersion: "0.1.0",
	})
	if err != nil {
		return nil, err
	}
	rootBlock, err := parsePEMCert(resp.GetRootCaPem())
	if err != nil {
		return nil, fmt.Errorf("invalid root CA PEM: %w", err)
	}
	sum := sha256.Sum256(rootBlock.Raw)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), strings.TrimSpace(expectedFP)) {
		return nil, fmt.Errorf("CA fingerprint mismatch: got %x want %s", sum, expectedFP)
	}
	if err := store.SaveInitial(resp.GetNodeId(), resp.GetRootCaPem(), resp.GetClientCertPem(), keyPEM); err != nil {
		return nil, err
	}
	return resp, nil
}

func parsePEMCert(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM certificate block found")
	}
	return x509.ParseCertificate(block.Bytes)
}

func flushSpoolLoop(ctx context.Context, client honeypotv1.SensorControlServiceClient, nodeID string, sp *spool.BoltSpool) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			req, keys, err := sp.DequeueBatch(nodeID, 2*1024*1024)
			if err != nil || len(keys) == 0 {
				continue
			}
			rpcCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			resp, err := client.PushEventsBatch(rpcCtx, req)
			cancel()
			if err != nil {
				continue
			}
			_ = sp.AckAndQuarantine(keys, resp.GetAckedEventUuids(), resp.GetRejectedDeadletterUuids())
		}
	}
}

func envOr(k, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return fallback
}

func envBool(k string) bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv(k)), "true")
}
