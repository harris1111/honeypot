package correlation

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/harris/honeypot/internal/canary"
	"github.com/harris/honeypot/internal/store"
	honeypotv1 "github.com/harris/honeypot/proto/gen/honeypot/v1"
)

func TestMultiIPKillChainCanaryKeyCorrelation(t *testing.T) {
	if os.Getenv("RUN_INTEGRATION_TESTS") != "1" {
		t.Skip("set RUN_INTEGRATION_TESTS=1 for Postgres correlation test")
	}
	ctx := context.Background()
	pgDSN := envOr("HIVE_POSTGRES_DSN", "postgres://honeypot:honeypot_test_pw@127.0.0.1:15432/honeypot?sslmode=disable")
	pg, err := store.OpenPostgres(ctx, pgDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()

	signer, _ := canary.NewSigner([]byte("0123456789abcdef0123456789abcdef"))
	seed, err := signer.MintAndStore(ctx, pg, "openai", "", "nx", "nextjs_middleware", "/admin", true)
	if err != nil {
		t.Fatal(err)
	}

	var reEvalCount int
	eng := NewEngine(pg, func(_ context.Context, inc IncidentSnapshot) {
		reEvalCount++
	})

	// IP_1 steals Canary Key K via Next.js CVE-2025-29927
	inc1, err := eng.CorrelateEvent(ctx, &honeypotv1.TelemetryEvent{
		SourceIp:      "198.51.100.11",
		TrapKind:      "webcve",
		CveId:         "CVE-2025-29927",
		CanaryKeyId:   seed.GetCanaryKeyId(),
		SeverityScore: 95,
	})
	if err != nil {
		t.Fatal(err)
	}

	// IP_2 later invokes Chameleon LLM Proxy using the exact stolen Canary Key K
	inc2, err := eng.CorrelateEvent(ctx, &honeypotv1.TelemetryEvent{
		SourceIp:      "203.0.113.22",
		TrapKind:      "llmproxy",
		CveId:         "LLM-CHAMELEON-API",
		CanaryKeyId:   seed.GetCanaryKeyId(),
		SeverityScore: 95,
	})
	if err != nil {
		t.Fatal(err)
	}

	if inc1.ID != inc2.ID {
		t.Fatalf("expected IP_1 and IP_2 merged into 1 incident, got %s vs %s", inc1.ID, inc2.ID)
	}
	if inc2.Severity != "critical" || len(inc2.RelatedIPs) != 2 || len(inc2.TrapKinds) != 2 {
		t.Fatalf("expected critical multi-IP incident, got %+v", inc2)
	}
	if reEvalCount < 2 {
		t.Fatalf("expected policy callback fired on each update, count=%d", reEvalCount)
	}
}

func envOr(k, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return fallback
}
