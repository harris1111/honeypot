package netwrap

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDualModeTLSLoopbackAndJA4JA4HCapture(t *testing.T) {
	tm, err := NewTLSManager(context.Background(), TLSManagerConfig{
		StateDir:     t.TempDir(),
		DecoyDomains: []string{"app.example.com", "api.example.com", "php.example.com", "ai.example.com", "admin.example.com", "edge.example.com"},
		EnableACME:   false,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Verify >5 subdomain bundling under root domain example.com
	bundles := tm.SANBundles()
	if len(bundles) != 1 || len(bundles[0]) != 6 {
		t.Fatalf("expected 6 subdomains under example.com collapsed into 1 bundle, got %+v", bundles)
	}

	rawLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ja4Ln := NewJA4Listener(rawLn, 64)
	tlsLn := tls.NewListener(ja4Ln, tm.TLSConfig())
	defer func() { _ = tlsLn.Close() }()

	var mu sync.Mutex
	var captured []struct {
		ja4, ja4h, sni string
	}

	srv := &http.Server{
		ConnContext: WithJA4ConnContext,
		Handler: tm.HTTPChallengeHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			captured = append(captured, struct {
				ja4, ja4h, sni string
			}{
				ja4:  JA4FromContext(r.Context()),
				ja4h: ComputeJA4H(r),
				sni:  SNIFromContext(r.Context()),
			})
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		})),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = srv.Serve(tlsLn) }()
	defer func() { _ = srv.Close() }()

	// 1. Connect to raw IP (127.0.0.1) without SNI -> dynamic self-signed cert
	ipClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp1, err := ipClient.Get("https://" + rawLn.Addr().String() + "/probe")
	if err != nil {
		t.Fatalf("raw IP HTTPS request failed: %v", err)
	}
	_ = resp1.Body.Close()

	// 2. Connect with SNI = "staging.localtest" over loopback
	sniClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:         "staging.localtest",
				InsecureSkipVerify: true,
			},
		},
	}
	req2, _ := http.NewRequest(http.MethodPost, "https://"+rawLn.Addr().String()+"/api/login", nil)
	req2.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req2.Header.Set("Referer", "https://staging.localtest/")
	req2.AddCookie(&http.Cookie{Name: "sid", Value: "abc"})
	resp2, err := sniClient.Do(req2)
	if err != nil {
		t.Fatalf("SNI HTTPS request failed: %v", err)
	}
	_ = resp2.Body.Close()

	mu.Lock()
	defer mu.Unlock()
	if len(captured) != 2 {
		t.Fatalf("expected 2 requests captured, got %d", len(captured))
	}
	if !strings.HasPrefix(captured[0].ja4, "t1") || captured[0].ja4[3] != 'i' {
		t.Fatalf("expected JA4 raw-IP indicator 'i', got %q", captured[0].ja4)
	}
	if !strings.HasPrefix(captured[1].ja4, "t1") || captured[1].ja4[3] != 'd' || captured[1].sni != "staging.localtest" {
		t.Fatalf("expected JA4 domain indicator 'd' with SNI, got %+v", captured[1])
	}
	if !strings.HasPrefix(captured[1].ja4h, "po11cr") {
		t.Fatalf("expected POST HTTP/1.1 cookie+referer JA4H prefix 'po11cr', got %q", captured[1].ja4h)
	}
}
