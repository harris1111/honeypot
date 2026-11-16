package enrichment

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/harris/honeypot/internal/store"
)

func TestIntelClientsCachingGreyNoiseAndHashOnlyVT(t *testing.T) {
	if os.Getenv("RUN_INTEGRATION_TESTS") != "1" {
		t.Skip("set RUN_INTEGRATION_TESTS=1 for Redis-cached enrichment test")
	}
	ctx := context.Background()
	pgDSN := envOr("HIVE_POSTGRES_DSN", "postgres://honeypot:honeypot_test_pw@127.0.0.1:15432/honeypot?sslmode=disable")
	redisAddr := envOr("HIVE_REDIS_ADDR", "127.0.0.1:16379")

	pg, err := store.OpenPostgres(ctx, pgDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	rd, err := store.OpenRedis(ctx, redisAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rd.Close() }()

	testIP := "198.51.100.77"
	_ = rd.Client.Del(ctx, "intel:ip:"+testIP).Err()

	var gnCalls atomic.Int32
	gnMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gnCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"riot":true,"classification":"benign"}`))
	}))
	defer gnMock.Close()

	var vtMethod string
	vtMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vtMethod = r.Method + " " + r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"attributes":{"last_analysis_stats":{"malicious":18,"undetected":42}}}}`))
	}))
	defer vtMock.Close()

	cli := NewClient(pg, rd, OpenGeoResolver("", ""), Config{
		GreyNoiseBaseURL:  gnMock.URL,
		VirusTotalBaseURL: vtMock.URL,
		VirusTotalAPIKey:  "vt-test-key",
	})

	// First call queries mock GreyNoise -> second call hits Redis 24h cache
	res1, err := cli.EnrichIP(ctx, testIP, 80)
	if err != nil || res1.GreyNoise != "benign" {
		t.Fatalf("unexpected first GreyNoise result: %+v err=%v", res1, err)
	}
	res2, err := cli.EnrichIP(ctx, testIP, 80)
	if err != nil || res2.GreyNoise != "benign" || gnCalls.Load() != 1 {
		t.Fatalf("expected Redis cache hit (1 call), calls=%d res2=%+v", gnCalls.Load(), res2)
	}

	// Verify VT enforces strictly GET /api/v3/files/{sha256}
	sha := strings.Repeat("a", 64)
	_ = rd.Client.Del(ctx, "intel:vt:"+sha).Err()
	vtRep, err := cli.EnrichArtifactHash(ctx, sha)
	if err != nil || vtRep.Malicious != 18 || vtMethod != "GET /api/v3/files/"+sha {
		t.Fatalf("unexpected VT hash-only result: %+v method=%q err=%v", vtRep, vtMethod, err)
	}
}

func envOr(k, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return fallback
}

func TestResolveIPGeoPointAndSensorProjection(t *testing.T) {
	vn := ResolveIPGeoPoint("203.113.131.1", "VN")
	if vn.CountryCode != "VN" || vn.Approximate || vn.Lat < 10 || vn.Lon < 100 {
		t.Fatalf("unexpected VN centroid projection: %+v", vn)
	}

	apnic := ResolveIPGeoPoint("1.1.1.1", "")
	if !apnic.Approximate || !strings.HasPrefix(apnic.RegionLabel, "APNIC") {
		t.Fatalf("expected APNIC fallback projection, got %+v", apnic)
	}

	ripe := ResolveIPGeoPoint("185.220.101.4", "")
	if !ripe.Approximate || !strings.HasPrefix(ripe.RegionLabel, "RIPE") {
		t.Fatalf("expected RIPE fallback projection, got %+v", ripe)
	}

	sensor := ResolveSensorGeoPoint("ap-southeast-sg", "")
	if sensor.CountryCode != "SG" || sensor.Approximate {
		t.Fatalf("expected Singapore sensor point, got %+v", sensor)
	}
}
