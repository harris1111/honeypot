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
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/harris/honeypot/internal/pki"
	honeypotv1 "github.com/harris/honeypot/proto/gen/honeypot/v1"
)

func main() {
	var (
		stateDir      = flag.String("state-dir", envOr("NGINX_GUARD_STATE_DIR", "/var/lib/honeypot-nginx-guard"), "nginx-guard state directory")
		hiveAddr      = flag.String("hive-addr", envOr("NGINX_GUARD_HIVE_ADDR", "127.0.0.1:9443"), "Hive :9443 ingress host:port")
		hiveSNI       = flag.String("hive-sni", envOr("NGINX_GUARD_HIVE_SNI", "hive.internal"), "Hive mTLS server name")
		enrollSNI     = flag.String("enroll-sni", envOr("NGINX_GUARD_ENROLL_SNI", "enroll.hive.internal"), "Hive enroll SNI")
		joinToken     = flag.String("enroll-token", "", "One-time join token with role=nginx_guard")
		caFingerprint = flag.String("ca-fingerprint", "", "Expected SHA-256 hex fingerprint of Hive Root CA")
		confPath      = flag.String("nginx-conf", envOr("NGINX_GUARD_CONF_PATH", "/etc/nginx/conf.d/honeypot_geo_blocklist.conf"), "Managed Nginx geo blocklist output path")
		pollInterval  = flag.Duration("poll-interval", 15*time.Second, "Feed polling interval")
	)
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	certStore, err := pki.OpenClientCertStore(filepath.Join(*stateDir, "pki"))
	if err != nil {
		log.Fatalf("open cert store: %v", err)
	}
	pubPath := filepath.Join(*stateDir, "feed_ed25519.pub")

	if *joinToken != "" {
		resp, err := enrollGuard(ctx, certStore, *hiveAddr, *enrollSNI, *joinToken, *caFingerprint)
		if err != nil {
			log.Fatalf("nginx-guard enroll failed: %v", err)
		}
		if err := os.WriteFile(pubPath, resp.GetFeedVerifyEd25519Pubkey(), 0o644); err != nil {
			log.Fatalf("save feed pubkey: %v", err)
		}
		log.Printf("Enrolled nginx-guard node_id=%s", certStore.NodeID())
		if flag.NArg() == 0 && !strings.EqualFold(os.Getenv("NGINX_GUARD_RUN_AFTER_ENROLL"), "true") {
			return
		}
	}

	if !certStore.IsEnrolled() {
		log.Fatal("nginx-guard not enrolled; run with --enroll-token and --ca-fingerprint")
	}
	pubKey, err := os.ReadFile(pubPath)
	if err != nil {
		log.Fatalf("read feed_ed25519.pub: %v", err)
	}
	verifier, err := NewFeedVerifier(pubKey, *stateDir)
	if err != nil {
		log.Fatalf("init feed verifier: %v", err)
	}

	tlsCfg, err := certStore.ClientTLSConfig(*hiveSNI)
	if err != nil {
		log.Fatalf("client TLS config: %v", err)
	}
	httpCli := &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}
	writer := NewNginxWriter(*confPath, 60*time.Second)
	poller := NewPoller("https://"+*hiveAddr+"/api/v1/guard/feeds/nginx", httpCli, verifier, writer)

	ticker := time.NewTicker(*pollInterval)
	defer ticker.Stop()

	if rev, reloaded, err := poller.PollOnce(ctx); err == nil {
		log.Printf("nginx-guard initial sync revision=%d reloaded=%v", rev, reloaded)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if rev, reloaded, err := poller.PollOnce(ctx); err != nil {
				log.Printf("nginx-guard poll notice: %v", err)
			} else {
				log.Printf("nginx-guard applied revision=%d reloaded=%v", rev, reloaded)
			}
		}
	}
}

func enrollGuard(ctx context.Context, store *pki.ClientCertStore, hiveAddr, enrollSNI, token, expectedFP string) (*honeypotv1.EnrollNodeResponse, error) {
	if expectedFP == "" {
		return nil, errors.New("--ca-fingerprint required")
	}
	keyPEM, csrPEM, err := pki.GenerateClientKeyAndCSR("nginx-guard-bootstrap")
	if err != nil {
		return nil, err
	}
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		ServerName:         enrollSNI,
		InsecureSkipVerify: true, // Pinned CA SHA-256 fingerprint verified below
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("server presented no certificates")
			}
			var matchedCA *x509.Certificate
			for _, raw := range rawCerts {
				sum := sha256.Sum256(raw)
				if strings.EqualFold(hex.EncodeToString(sum[:]), strings.TrimSpace(expectedFP)) {
					if c, err := x509.ParseCertificate(raw); err == nil {
						matchedCA = c
					}
					break
				}
			}
			if matchedCA == nil {
				return errors.New("hive CA fingerprint mismatch")
			}
			leaf, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}
			pool := x509.NewCertPool()
			pool.AddCert(matchedCA)
			_, err = leaf.Verify(x509.VerifyOptions{
				Roots:     pool,
				DNSName:   enrollSNI,
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

	resp, err := honeypotv1.NewSensorControlServiceClient(conn).EnrollNode(ctx, &honeypotv1.EnrollNodeRequest{
		JoinToken:    token,
		CsrPem:       csrPEM,
		AgentVersion: "0.1.0",
	})
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(resp.GetRootCaPem())
	if block == nil {
		return nil, errors.New("invalid root CA PEM")
	}
	sum := sha256.Sum256(block.Bytes)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), strings.TrimSpace(expectedFP)) {
		return nil, fmt.Errorf("CA fingerprint mismatch")
	}
	if err := store.SaveInitial(resp.GetNodeId(), resp.GetRootCaPem(), resp.GetClientCertPem(), keyPEM); err != nil {
		return nil, err
	}
	return resp, nil
}

func envOr(k, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return fallback
}
