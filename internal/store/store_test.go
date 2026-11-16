package store

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	honeypotv1 "github.com/harris/honeypot/proto/gen/honeypot/v1"
)

func testPostgresDSN() string {
	if v := os.Getenv("TEST_POSTGRES_DSN"); v != "" {
		return v
	}
	return "postgres://honeypot:honeypot_test_pw@127.0.0.1:15432/honeypot?sslmode=disable"
}

func testRedisAddr() string {
	if v := os.Getenv("TEST_REDIS_ADDR"); v != "" {
		return v
	}
	return "127.0.0.1:16379"
}

func TestPostgresAndRedisIntegration(t *testing.T) {
	if os.Getenv("RUN_INTEGRATION_TESTS") != "1" {
		t.Skip("set RUN_INTEGRATION_TESTS=1 with postgres & redis running")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	pg, err := OpenPostgres(ctx, testPostgresDSN())
	if err != nil {
		t.Fatalf("OpenPostgres: %v", err)
	}
	defer pg.Close()

	rd, err := OpenRedis(ctx, testRedisAddr())
	if err != nil {
		t.Fatalf("OpenRedis: %v", err)
	}
	defer func() { _ = rd.Close() }()

	// 1. Verify all 15 canonical tables + guard_feed_revision_seq exist
	var tblCount int
	err = pg.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM information_schema.tables
		WHERE table_schema = 'public' AND table_name IN (
			'sensor_nodes','node_join_tokens','trap_deployments','protected_allowlist','audit_logs',
			'admin_users','llm_personas','canary_keys','attack_incidents','telemetry_events',
			'ssh_session_replays','llm_conversations','malware_artifacts','policy_rules','guard_decisions'
		)
	`).Scan(&tblCount)
	if err != nil || tblCount != 15 {
		t.Fatalf("expected 15 canonical tables, got %d (err=%v)", tblCount, err)
	}

	rev, err := pg.NextFeedRevision(ctx)
	if err != nil || rev < 1 {
		t.Fatalf("NextFeedRevision: rev=%d err=%v", rev, err)
	}

	// 2. Verify protected_allowlist overlap check (including supernet CIDR overlap!)
	overlaps, err := pg.CheckAllowlistOverlap(ctx, "173.245.0.0/16")
	if err != nil || !overlaps {
		t.Fatalf("expected Cloudflare supernet overlap to return true, got overlaps=%v err=%v", overlaps, err)
	}
	overlapsClean, err := pg.CheckAllowlistOverlap(ctx, "198.51.100.42/32")
	if err != nil || overlapsClean {
		t.Fatalf("expected non-allowlist IP false, got %v err=%v", overlapsClean, err)
	}

	// 3. Atomic join token consumption (cannot be reused!)
	tok := "hpj_test_" + uuid.NewString()
	sum := sha256.Sum256([]byte(tok))
	_, err = pg.CreateJoinToken(ctx, sum[:], "sensor", "test-node-"+uuid.NewString()[:8], "sgp1", time.Hour)
	if err != nil {
		t.Fatalf("CreateJoinToken: %v", err)
	}
	consumed, err := pg.ConsumeJoinToken(ctx, sum[:], "203.0.113.99", "", "v0.1.0", "deadbeef", time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("ConsumeJoinToken: %v", err)
	}
	if _, err := pg.ConsumeJoinToken(ctx, sum[:], "203.0.113.99", "", "v0.1.0", "deadbeef", time.Now().Add(24*time.Hour)); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("expected ErrTokenInvalid on second consumption, got %v", err)
	}

	// Verify node public IP was auto-locked into protected_allowlist
	nodeLocked, err := pg.CheckAllowlistOverlap(ctx, "203.0.113.99/32")
	if err != nil || !nodeLocked {
		t.Fatalf("expected enrolled node public IP to be auto-locked in protected_allowlist")
	}

	// 4. Idempotent telemetry + SSH replay + LLM conversation batch insert
	evID := uuid.NewString()
	repID := uuid.NewString()
	llmID := uuid.NewString()
	req := &honeypotv1.PushEventsBatchRequest{
		NodeId: consumed.NodeID.String(),
		Events: []*honeypotv1.TelemetryEvent{{
			EventUuid:   evID,
			NodeId:      consumed.NodeID.String(),
			SourceIp:    "198.51.100.77",
			DestPort:    443,
			Protocol:    "https",
			TrapKind:    "webcve",
			Persona:     "nextjs-modern",
			CveId:       "CVE-2025-29927",
			IsKev:       false,
			HttpMethod:  "GET",
			HttpPath:    "/admin",
			ObservedAt:  timestamppb.Now(),
		}},
		SshReplays: []*honeypotv1.SshSessionReplay{{
			ReplayUuid:    repID,
			EventUuid:     evID,
			NodeId:        consumed.NodeID.String(),
			SourceIp:      "198.51.100.77",
			Hassh:         "abcdef1234",
			Username:      "root",
			AuthSucceeded: true,
			Commands:      []string{"id", "cat ~/.bash_history"},
			AsciicastV2:   `{"version":2,"width":80,"height":24}`,
			DurationMs:    1200,
			StartedAt:     timestamppb.Now(),
		}},
		LlmConversations: []*honeypotv1.LlmConversation{{
			ConversationUuid: llmID,
			EventUuid:        evID,
			NodeId:           consumed.NodeID.String(),
			SourceIp:         "198.51.100.77",
			ApiDialect:       "openai",
			RequestedModel:   "gpt-4o",
			EmulatedPersona:  "gpt-4o*",
			MessagesJson:     `[{"role":"user","content":"what model are you"}]`,
			DegradedMode:     "slow_tarpit",
			CreatedAt:        timestamppb.Now(),
		}},
	}
	acked, dl, err := pg.InsertEventsBatch(ctx, consumed.NodeID.String(), req)
	if err != nil || len(acked) != 3 || len(dl) != 0 {
		t.Fatalf("InsertEventsBatch: acked=%v dl=%v err=%v", acked, dl, err)
	}
	// Duplicate replay idempotency
	acked2, _, err := pg.InsertEventsBatch(ctx, consumed.NodeID.String(), req)
	if err != nil || len(acked2) != 3 {
		t.Fatalf("duplicate InsertEventsBatch: %v", err)
	}

	// 5. Redis cert state cache & PubSub
	st := NodeCertState{NodeID: consumed.NodeID.String(), CertSerial: "deadbeef", Status: "online"}
	if err := rd.CacheNodeCertState(ctx, st, time.Minute); err != nil {
		t.Fatalf("CacheNodeCertState: %v", err)
	}
	got, hit, err := rd.GetCachedNodeCertState(ctx, st.NodeID)
	if err != nil || !hit || got.CertSerial != "deadbeef" {
		t.Fatalf("GetCachedNodeCertState: got=%+v hit=%v err=%v", got, hit, err)
	}
	ps := rd.SubscribeLiveEvents(ctx)
	defer func() { _ = ps.Close() }()
	if err := rd.PublishLiveEvent(ctx, map[string]any{"event_uuid": evID}); err != nil {
		t.Fatalf("PublishLiveEvent: %v", err)
	}
	msg, err := ps.ReceiveMessage(ctx)
	if err != nil {
		t.Fatalf("ReceiveMessage: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(msg.Payload), &parsed); err != nil || parsed["event_uuid"] != evID {
		t.Fatalf("unexpected PubSub payload: %s", msg.Payload)
	}
}
