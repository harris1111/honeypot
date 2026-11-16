package policy

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/harris/honeypot/internal/correlation"
	"github.com/harris/honeypot/internal/store"
)

func TestPolicyEngineAllowlistBenignSuppressionAndZeroAutoBan(t *testing.T) {
	if os.Getenv("RUN_INTEGRATION_TESTS") != "1" {
		t.Skip("set RUN_INTEGRATION_TESTS=1 for Postgres policy tests")
	}
	ctx := context.Background()
	pgDSN := envOr("HIVE_POSTGRES_DSN", "postgres://honeypot:honeypot_test_pw@127.0.0.1:15432/honeypot?sslmode=disable")
	pg, err := store.OpenPostgres(ctx, pgDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()

	// 1. Validate Allowlist + minimum prefix floors (/24 IPv4, /48 IPv6)
	if _, _, err := ValidateTargetAllowed(ctx, pg, "cidr", "173.245.48.0/20"); !errors.Is(err, ErrProtectedAllowlist) {
		t.Fatalf("expected ErrProtectedAllowlist for Cloudflare CIDR, got %v", err)
	}
	if _, _, err := ValidateTargetAllowed(ctx, pg, "cidr", "198.51.0.0/16"); !errors.Is(err, ErrProtectedAllowlist) {
		t.Fatalf("expected ErrProtectedAllowlist for /16 supernet, got %v", err)
	}
	typ, canon, err := ValidateTargetAllowed(ctx, pg, "ip", "2001:db8:abcd:12::99")
	if err != nil || typ != "cidr" || canon != "2001:db8:abcd:12::/64" {
		t.Fatalf("expected IPv6 attacker normalized to /64 cidr, got typ=%s canon=%s err=%v", typ, canon, err)
	}

	eng := NewEngine(pg, nil)

	// 2. KEV hit from malicious/unknown IP -> routes to triage_queue (pending_approval), NEVER auto_enforce!
	attackerIP := "198.51.100.222"
	_, _ = pg.Pool.Exec(ctx, `DELETE FROM guard_decisions WHERE indicator_value = $1`, attackerIP)
	outKEV, err := eng.EvaluateIncident(ctx, correlation.IncidentSnapshot{
		PrimaryIP:               attackerIP,
		RelatedIPs:              []string{attackerIP},
		IsKEV:                   true,
		GreyNoiseClassification: "unknown",
		ConfidenceScore:         95,
	})
	if err != nil {
		t.Fatal(err)
	}
	if outKEV.Action != "triage_queue" || outKEV.DecisionID == "" {
		t.Fatalf("expected KEV routed to triage_queue (zero auto_enforce), got %+v", outKEV)
	}

	// 3. When async GreyNoise classifies the IP as benign -> Priority #1 Ignore rule auto-dismisses pending triage item!
	outBenign, err := eng.EvaluateIncident(ctx, correlation.IncidentSnapshot{
		PrimaryIP:               attackerIP,
		RelatedIPs:              []string{attackerIP},
		IsKEV:                   true,
		GreyNoiseClassification: "benign",
		ConfidenceScore:         95,
	})
	if err != nil || outBenign.Action != "ignore" {
		t.Fatalf("expected Priority 1 Benign rule ignore, got %+v err=%v", outBenign, err)
	}
	var st string
	_ = pg.Pool.QueryRow(ctx, `SELECT status FROM guard_decisions WHERE id = $1::uuid`, outKEV.DecisionID).Scan(&st)
	if st != "rejected" {
		t.Fatalf("expected stale pending decision auto-dismissed (status=rejected), got %q", st)
	}
}

func envOr(k, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return fallback
}
