package guard

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/harris/honeypot/internal/pki"
	"github.com/harris/honeypot/internal/policy"
	"github.com/harris/honeypot/internal/store"
)

func TestGuardApproveCloudflareSyncSignedFeedAndRollback(t *testing.T) {
	if os.Getenv("RUN_INTEGRATION_TESTS") != "1" {
		t.Skip("set RUN_INTEGRATION_TESTS=1 for Postgres+Guard test")
	}
	ctx := context.Background()
	pgDSN := envOr("HIVE_POSTGRES_DSN", "postgres://honeypot:honeypot_test_pw@127.0.0.1:15432/honeypot?sslmode=disable")
	pg, err := store.OpenPostgres(ctx, pgDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()

	ca, err := pki.InitOrLoad(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	cfItems := make(map[string]CloudflareListItem)
	cfMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.Method {
		case http.MethodGet:
			var list []CloudflareListItem
			for _, it := range cfItems {
				list = append(list, it)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": list})
		case http.MethodPost:
			var items []struct{ IP, Comment string }
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &items)
			for _, it := range items {
				cfItems[it.IP] = CloudflareListItem{ID: "cf-item-" + it.IP, IP: it.IP}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]string{"operation_id": "op-1"}})
		case http.MethodDelete:
			var body struct {
				Items []struct{ ID string } `json:"items"`
			}
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &body)
			for _, del := range body.Items {
				for k, v := range cfItems {
					if v.ID == del.ID {
						delete(cfItems, k)
					}
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
		}
	}))
	defer cfMock.Close()

	cf := NewCloudflareSync(CloudflareConfig{
		BaseURL:   cfMock.URL,
		APIToken:  "cf-test-tok",
		AccountID: "acc-1",
		ListID:    "list-1",
	})
	mgr := NewManager(ca, pg, cf)

	testIP := "203.0.113.211"
	_, _ = pg.Pool.Exec(ctx, `DELETE FROM guard_decisions WHERE indicator_value = $1`, testIP)

	// Guard against allowlisted or non-IP Nginx targets
	if _, err := mgr.ManualBlock(ctx, "ip", "10.0.0.5", "both", 24, "admin", "test"); !errors.Is(err, policy.ErrProtectedAllowlist) {
		t.Fatalf("expected ErrProtectedAllowlist for RFC1918 block attempt, got %v", err)
	}
	if _, err := mgr.ManualBlock(ctx, "ja4", "t13d_evil", "nginx", 24, "admin", "test"); err == nil {
		t.Fatal("expected error enforcing nginx ip/cidr-only constraint")
	}

	// Valid manual block -> synced to Cloudflare & present in Ed25519-signed Nginx feed
	decID, err := mgr.ManualBlock(ctx, "ip", testIP, "both", 24, "admin", "Confirmed scanner")
	if err != nil {
		t.Fatal(err)
	}
	signed, payload, err := mgr.feedSigner.BuildSignedNginxFeed(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rawJSON, _ := base64.StdEncoding.DecodeString(signed.PayloadB64)
	sig, _ := base64.StdEncoding.DecodeString(signed.SignatureB64)
	if !ed25519.Verify(ca.FeedPublicKey(), rawJSON, sig) {
		t.Fatal("Ed25519 feed signature invalid")
	}
	if !containsStr(payload.BlockedPrefixes, "203.0.113.211/32") {
		t.Fatalf("expected blocked IP in feed, got %v", payload.BlockedPrefixes)
	}

	// Verify Wirefilter builder respects Enterprise JA4 gate and escapes literals
	exprNoEnt := BuildWirefilterExpression(WAFConfig{CloudflareEnterpriseJA4Enabled: false}, []string{"t13d_scanner"})
	if strings.Contains(exprNoEnt, "cf.tls_client_extensions_sha1") {
		t.Fatalf("expected JA4 clause gated off when enterprise=false: %s", exprNoEnt)
	}
	exprEnt := BuildWirefilterExpression(WAFConfig{CloudflareEnterpriseJA4Enabled: true}, []string{"t13d_scanner", `bad"quote`})
	if !strings.Contains(exprEnt, "t13d_scanner") || !strings.Contains(exprEnt, `bad\"quote`) {
		t.Fatalf("unexpected Enterprise WAF expr: %s", exprEnt)
	}

	// Emergency Unban / Rollback -> removes from Cloudflare mock & Nginx feed & marks rolled_back
	if err := mgr.UnbanOrRollback(ctx, decID, "admin", "False positive check"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	_, stillCF := cfItems[testIP]
	mu.Unlock()
	if stillCF {
		t.Fatal("expected UnbanOrRollback to delete item from Cloudflare Custom List")
	}
	_, afterPayload, err := mgr.feedSigner.BuildSignedNginxFeed(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if containsStr(afterPayload.BlockedPrefixes, "203.0.113.211/32") {
		t.Fatalf("expected unbanned IP removed from Nginx feed, still present: %v", afterPayload.BlockedPrefixes)
	}
	var finalStatus string
	_ = pg.Pool.QueryRow(ctx, `SELECT status FROM guard_decisions WHERE id = $1::uuid`, decID).Scan(&finalStatus)
	if finalStatus != "rolled_back" {
		t.Fatalf("expected final status rolled_back, got %q", finalStatus)
	}
}

func containsStr(list []string, target string) bool {
	for _, s := range list {
		if s == target {
			return true
		}
	}
	return false
}

func envOr(k, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return fallback
}
