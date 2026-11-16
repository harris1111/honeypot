package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/harris/honeypot/internal/guard"
	"github.com/harris/honeypot/internal/pki"
)

func TestFeedVerifierAntiRollbackAndNginxWriterRollback(t *testing.T) {
	ca, err := pki.InitOrLoad(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	stateDir := t.TempDir()
	ver, err := NewFeedVerifier(ca.FeedPublicKey(), stateDir)
	if err != nil {
		t.Fatal(err)
	}

	signFeed := func(rev int64, ips []string) guard.NginxSignedFeed {
		p := guard.FeedPayload{
			Revision:        rev,
			SignedAt:        "2026-11-16T10:00:00Z",
			CloudflareCIDRs: []string{"173.245.48.0/20"},
			BlockedPrefixes: ips,
		}
		raw, _ := json.Marshal(p)
		return guard.NginxSignedFeed{
			PayloadB64:   base64.StdEncoding.EncodeToString(raw),
			SignatureB64: base64.StdEncoding.EncodeToString(ca.SignFeed(raw)),
		}
	}

	// Tampered signature must be rejected
	tampered := signFeed(1, []string{"203.0.113.5/32"})
	tampered.SignatureB64 = base64.StdEncoding.EncodeToString(make([]byte, 64))
	if _, err := ver.Verify(tampered); err == nil {
		t.Fatal("expected tampered Ed25519 signature rejected")
	}

	// Valid revision 5 accepted & committed
	p5, err := ver.Verify(signFeed(5, []string{"203.0.113.5/32"}))
	if err != nil {
		t.Fatalf("expected valid rev 5 accepted: %v", err)
	}
	confPath := filepath.Join(t.TempDir(), "honeypot_geo_blocklist.conf")
	writer := NewNginxWriter(confPath, 60*time.Second)
	writer.testConfigFn = func() error { return nil }
	writer.reloadConfigFn = func() error { return nil }

	reloaded, err := writer.Apply(p5)
	if err != nil || !reloaded {
		t.Fatalf("apply rev 5 failed: reloaded=%v err=%v", reloaded, err)
	}
	if err := ver.CommitRevision(p5.Revision); err != nil {
		t.Fatal(err)
	}

	// Check dual-stack ::ffff: entry present in rendered Nginx config
	cfgBytes, _ := os.ReadFile(confPath)
	if !strings.Contains(string(cfgBytes), "203.0.113.5/32 1;") || !strings.Contains(string(cfgBytes), "::ffff:203.0.113.5/128 1;") {
		t.Fatalf("missing IPv4+dual-stack ::ffff: entries:\n%s", string(cfgBytes))
	}

	// Reopen FeedVerifier from disk -> stale revision 5 or 4 rejected!
	ver2, err := NewFeedVerifier(ca.FeedPublicKey(), stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ver2.Verify(signFeed(5, nil)); err == nil {
		t.Fatal("expected replayed rev 5 rejected after restart")
	}

	// Failed nginx -t must restore previous .conf.bak cleanly!
	writer.testConfigFn = func() error { return errors.New("syntax error") }
	_, err = writer.Apply(guard.FeedPayload{Revision: 6, BlockedPrefixes: []string{"198.51.100.99/32"}})
	if err == nil {
		t.Fatal("expected failed nginx -t error")
	}
	restoredBytes, _ := os.ReadFile(confPath)
	if !strings.Contains(string(restoredBytes), "203.0.113.5/32") || strings.Contains(string(restoredBytes), "198.51.100.99") {
		t.Fatalf("expected rollback to .conf.bak, got:\n%s", string(restoredBytes))
	}
}

func TestLiveNginxAlpineContainerEnforcementAndEmergencyUnban(t *testing.T) {
	if os.Getenv("RUN_INTEGRATION_TESTS") != "1" {
		t.Skip("set RUN_INTEGRATION_TESTS=1 for real nginx:alpine enforcement test")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker binary unavailable")
	}

	tmpDir := t.TempDir()
	_ = os.Chmod(tmpDir, 0o755)
	geoConf := filepath.Join(tmpDir, "honeypot_geo_blocklist.conf")
	mainConf := filepath.Join(tmpDir, "nginx.conf")
	snippetConf := filepath.Join(tmpDir, "honeypot_block_snippet.conf")

	bootBytes, err := os.ReadFile("../../deployments/nginx-guard/honeypot_geo_blocklist.conf.bootstrap")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(geoConf, bootBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	snipBytes, err := os.ReadFile("../../deployments/nginx-guard/honeypot_block_snippet.conf")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(snippetConf, snipBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	nginxMain := `worker_processes 1;
worker_shutdown_timeout 30s;
events { worker_connections 128; }
http {
    include /etc/nginx/honeypot/honeypot_geo_blocklist.conf;
    server {
        listen 80;
        listen [::]:80;
        include /etc/nginx/honeypot/honeypot_block_snippet.conf;
        location / {
            return 200 "OK_ALLOWED\n";
        }
    }
}
`
	if err := os.WriteFile(mainConf, []byte(nginxMain), 0o644); err != nil {
		t.Fatal(err)
	}

	const cname = "honeypot-test-nginx"
	_ = exec.Command("docker", "rm", "-f", cname).Run()
	runCmd := exec.Command("docker", "run", "-d", "--name", cname,
		"-p", "127.0.0.1:18080:80",
		"-v", tmpDir+":/etc/nginx/honeypot:ro",
		"nginx:alpine",
		"nginx", "-g", "daemon off;", "-c", "/etc/nginx/honeypot/nginx.conf",
	)
	if out, err := runCmd.CombinedOutput(); err != nil {
		t.Fatalf("start %s failed: %v\n%s", cname, err, string(out))
	}
	defer func() {
		_ = exec.Command("docker", "rm", "-f", cname).Run()
	}()

	// Wait for nginx:alpine to listen on 127.0.0.1:18080
	var ready bool
	for i := 0; i < 20; i++ {
		if resp, err := http.Get("http://127.0.0.1:18080/"); err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == 200 {
				ready = true
				break
			}
		}
		time.Sleep(150 * time.Millisecond)
	}
	if !ready {
		logs, _ := exec.Command("docker", "logs", cname).CombinedOutput()
		t.Fatalf("honeypot-test-nginx did not become ready with bootstrap config:\n%s", string(logs))
	}

	writer := NewNginxWriter(geoConf, 60*time.Second)
	writer.testConfigFn = func() error {
		out, err := exec.Command("docker", "exec", cname, "nginx", "-t", "-c", "/etc/nginx/honeypot/nginx.conf").CombinedOutput()
		if err != nil {
			return errors.New(string(out))
		}
		return nil
	}
	writer.reloadConfigFn = func() error {
		out, err := exec.Command("docker", "exec", cname, "nginx", "-s", "reload", "-c", "/etc/nginx/honeypot/nginx.conf").CombinedOutput()
		if err != nil {
			return errors.New(string(out))
		}
		return nil
	}

	probeClient := &http.Client{
		Timeout:   2 * time.Second,
		Transport: &http.Transport{DisableKeepAlives: true},
	}

	// Block 198.51.100.45 via trusted Cloudflare CF-Connecting-IP + Docker bridge gateway CIDR trust
	_, err = writer.Apply(guard.FeedPayload{
		Revision:        1,
		SignedAt:        time.Now().UTC().Format(time.RFC3339),
		CloudflareCIDRs: []string{"172.16.0.0/12", "127.0.0.1/32"},
		BlockedPrefixes: []string{"198.51.100.45/32"},
	})
	if err != nil {
		t.Fatalf("apply blocklist inside nginx:alpine failed: %v", err)
	}

	// Spoofed/trusted CF-Connecting-IP = 198.51.100.45 -> poll until reload finishes -> 403 Forbidden!
	var blkStatus int
	var blkErr error
	for i := 0; i < 25; i++ {
		reqBlock, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://127.0.0.1:18080/", nil)
		reqBlock.Header.Set("CF-Connecting-IP", "198.51.100.45")
		respBlk, err := probeClient.Do(reqBlock)
		blkErr = err
		if err == nil {
			blkStatus = respBlk.StatusCode
			_ = respBlk.Body.Close()
			if blkStatus == http.StatusForbidden {
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if blkErr != nil || blkStatus != http.StatusForbidden {
		t.Fatalf("expected 403 for blocked IP via real nginx:alpine, got status=%d err=%v", blkStatus, blkErr)
	}

	// Normal non-blocked IP -> still 200 OK!
	reqOK, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://127.0.0.1:18080/", nil)
	reqOK.Header.Set("CF-Connecting-IP", "93.184.216.34")
	respOK, err := probeClient.Do(reqOK)
	if err != nil || respOK.StatusCode != 200 {
		t.Fatalf("expected 200 for clean IP, got status=%v err=%v", respOK, err)
	}
	_ = respOK.Body.Close()

	// Emergency Unban drops IP from list -> immediate reload (bypassing 60s debounce!) restores 200!
	reloaded, err := writer.Apply(guard.FeedPayload{
		Revision:        2,
		SignedAt:        time.Now().UTC().Format(time.RFC3339),
		CloudflareCIDRs: []string{"172.16.0.0/12", "127.0.0.1/32"},
		BlockedPrefixes: []string{},
	})
	if err != nil || !reloaded {
		t.Fatalf("expected immediate reload on unban, reloaded=%v err=%v", reloaded, err)
	}

	var afterStatus int
	var afterErr error
	for i := 0; i < 25; i++ {
		reqAfter, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://127.0.0.1:18080/", nil)
		reqAfter.Header.Set("CF-Connecting-IP", "198.51.100.45")
		respAfter, err := probeClient.Do(reqAfter)
		afterErr = err
		if err == nil {
			afterStatus = respAfter.StatusCode
			_ = respAfter.Body.Close()
			if afterStatus == http.StatusOK {
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if afterErr != nil || afterStatus != http.StatusOK {
		t.Fatalf("expected 200 immediately after Emergency Unban, got status=%d err=%v", afterStatus, afterErr)
	}
}
