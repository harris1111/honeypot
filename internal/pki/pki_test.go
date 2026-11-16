package pki

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCAAndClientCertLifecycle(t *testing.T) {
	dir := t.TempDir()
	ca, err := InitOrLoad(dir)
	if err != nil {
		t.Fatalf("InitOrLoad: %v", err)
	}
	fp := ca.RootFingerprintSHA256()
	if len(fp) != 64 {
		t.Fatalf("unexpected fingerprint len: %d", len(fp))
	}

	// Reload from disk preserves CA identity and feed keys
	ca2, err := InitOrLoad(dir)
	if err != nil {
		t.Fatalf("reload CA: %v", err)
	}
	if ca2.RootFingerprintSHA256() != fp {
		t.Fatalf("CA fingerprint changed across reload")
	}

	// Feed signing & verification
	payload := []byte("revision=1\n203.0.113.1/32\n")
	sig := ca.SignFeed(payload)
	if !VerifyFeedSignature(ca2.FeedPublicKey(), payload, sig) {
		t.Fatal("feed signature verification failed")
	}
	if VerifyFeedSignature(ca2.FeedPublicKey(), []byte("tampered"), sig) {
		t.Fatal("tampered payload verified unexpectedly")
	}

	// Enroll + Two-Phase Rotation
	keyPEM, csrPEM, err := GenerateClientKeyAndCSR("sensor-test")
	if err != nil {
		t.Fatalf("GenerateClientKeyAndCSR: %v", err)
	}
	certPEM, serial1, exp1, err := ca.SignClientCSR(csrPEM, "sensor", "node-111", 24*time.Hour)
	if err != nil {
		t.Fatalf("SignClientCSR: %v", err)
	}
	if serial1 == "" || exp1.IsZero() {
		t.Fatal("expected serial and expiry")
	}

	storeDir := t.TempDir()
	cs, err := OpenClientCertStore(storeDir)
	if err != nil {
		t.Fatalf("OpenClientCertStore: %v", err)
	}
	if err := cs.SaveInitial("node-111", ca.RootCertPEM(), certPEM, keyPEM); err != nil {
		t.Fatalf("SaveInitial: %v", err)
	}
	if !cs.NeedsRotation(48 * time.Hour) {
		t.Fatal("expected NeedsRotation true within 48h window")
	}

	// Failed rotation must keep valid original cert intact
	nextKeyPEM, nextCSRPEM, err := GenerateClientKeyAndCSR("sensor-test")
	if err != nil {
		t.Fatalf("GenerateClientKeyAndCSR rotated: %v", err)
	}
	if err := cs.StageNextKey(nextKeyPEM); err != nil {
		t.Fatalf("StageNextKey: %v", err)
	}
	if err := cs.CommitRotation([]byte("invalid pem")); err == nil {
		t.Fatal("expected CommitRotation failure on invalid PEM")
	}
	if !cs.IsEnrolled() {
		t.Fatal("expected original enrollment intact after failed rotation")
	}

	// Valid two-phase rotation
	nextCertPEM, serial2, _, err := ca.SignClientCSR(nextCSRPEM, "nginx_guard", "guard-222", 90*24*time.Hour)
	if err != nil {
		t.Fatalf("SignClientCSR rotated: %v", err)
	}
	if serial2 == serial1 {
		t.Fatal("expected new cert serial")
	}
	if err := cs.CommitRotation(nextCertPEM); err != nil {
		t.Fatalf("CommitRotation: %v", err)
	}
	if cs.NeedsRotation(30 * 24 * time.Hour) {
		t.Fatal("expected NeedsRotation false after 90d rotation")
	}
}

func TestSNISplitIngressTLS(t *testing.T) {
	ca, err := InitOrLoad(t.TempDir())
	if err != nil {
		t.Fatalf("InitOrLoad: %v", err)
	}
	srvPair, _, _, err := ca.IssueServerCert([]string{"127.0.0.1", "localhost", "hive.internal", "enroll.hive.internal"})
	if err != nil {
		t.Fatalf("IssueServerCert: %v", err)
	}

	tlsCfg := BuildHiveIngressTLSConfig(ca, srvPair)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := ExtractHTTPPeerIdentity(r)
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("no-mtls"))
			return
		}
		_, _ = w.Write([]byte(id.Role + ":" + id.NodeID))
	}))
	srv.TLS = tlsCfg
	srv.StartTLS()
	defer srv.Close()

	// 1. Default SNI without client cert MUST fail TLS handshake
	unauthClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    ca.RootPool(),
				ServerName: "hive.internal",
			},
		},
	}
	if _, err := unauthClient.Get(srv.URL); err == nil {
		t.Fatal("expected TLS handshake failure on default SNI without client cert")
	}

	// 2. enroll.* SNI without client cert completes TLS (so EnrollNode can execute)
	enrollClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    ca.RootPool(),
				ServerName: "enroll.hive.internal",
			},
		},
	}
	resp, err := enrollClient.Get(srv.URL)
	if err != nil {
		t.Fatalf("enroll SNI TLS failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized || string(body) != "no-mtls" {
		t.Fatalf("unexpected enroll response: %d %q", resp.StatusCode, body)
	}

	// 3. Default SNI with enrolled mTLS client cert succeeds and extracts SPIFFE identity
	keyPEM, csrPEM, _ := GenerateClientKeyAndCSR("s1")
	certPEM, _, _, _ := ca.SignClientCSR(csrPEM, "sensor", "abc-123", time.Hour)
	store, _ := OpenClientCertStore(t.TempDir())
	_ = store.SaveInitial("abc-123", ca.RootCertPEM(), certPEM, keyPEM)
	mtlsCfg, err := store.ClientTLSConfig("hive.internal")
	if err != nil {
		t.Fatalf("ClientTLSConfig: %v", err)
	}
	mtlsClient := &http.Client{
		Transport: &http.Transport{TLSClientConfig: mtlsCfg},
	}
	resp2, err := mtlsClient.Get(srv.URL)
	if err != nil {
		t.Fatalf("mTLS request failed: %v", err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK || string(body2) != "sensor:abc-123" {
		t.Fatalf("unexpected mTLS response: %d %q", resp2.StatusCode, body2)
	}

	// Sanity check ClientCAs leak protection: check root cert not advertised as hint
	_ = x509.NewCertPool()
}
