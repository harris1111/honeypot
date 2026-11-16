package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/harris/honeypot/internal/canary"
	"github.com/harris/honeypot/internal/pki"
	"github.com/harris/honeypot/internal/spool"
	honeypotv1 "github.com/harris/honeypot/proto/gen/honeypot/v1"
)

func TestSensorControllerDeployCowrieAndReconcile(t *testing.T) {
	stateDir := t.TempDir()
	fakeDocker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/networks/create":
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"Id":"net-1"}`))
		case r.Method == http.MethodPost && r.URL.Path == "/containers/create":
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"Id":"cid-1"}`))
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer fakeDocker.Close()

	certStore, err := pki.OpenClientCertStore(filepath.Join(stateDir, "pki"))
	if err != nil {
		t.Fatal(err)
	}
	sp, err := spool.OpenBoltSpool(filepath.Join(stateDir, "spool.db"), 10*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sp.Close() }()

	st := loadBootstrapState(filepath.Join(stateDir, "bootstrap.json"))
	pool := canary.NewSensorKeyPool()
	pool.AddSeeds([]*honeypotv1.CanaryKeySeed{
		{
			CanaryKeyId:     "can-seed-1",
			KeyPlaintext:    "sk-proj-testkey1234567890",
			ProviderStyle:   "openai",
			PlacementSource: "cowrie_honeyfs",
		},
	})

	ctrl := newSensorController("node-test-1", stateDir, fakeDocker.URL, "https://ai.example", certStore, st, sp, pool, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var frames []*honeypotv1.AgentFrame
	ctrl.handleCommand(ctx, nil, &honeypotv1.HiveCommand{
		CommandId: "cmd-1",
		Payload: &honeypotv1.HiveCommand_DeployTrap{
			DeployTrap: &honeypotv1.DeployTrapCommand{
				DeploymentId:  "dep-cowrie-1",
				TrapKind:      "cowrie",
				ContainerName: "hp-trap-cowrie-1",
				ListenPort:    2222,
				Protocol:      "tcp",
			},
		},
	}, func(f *honeypotv1.AgentFrame) error {
		frames = append(frames, f)
		return nil
	})

	if len(frames) != 1 || !frames[0].GetCommandAck().GetOk() {
		t.Fatalf("expected ok ack frame, got %+v", frames)
	}

	// Simulate Cowrie appending a session connect & login line; tailer should spool into BoltSpool
	cowrieJSON := filepath.Join(stateDir, "traps", "dep-cowrie-1", "var", "log", "cowrie", "cowrie.json")
	if err := os.WriteFile(cowrieJSON, []byte(
		`{"eventid":"cowrie.session.connect","timestamp":"2026-11-16T10:00:00Z","session":"s1","src_ip":"203.0.113.9","dst_port":2222,"protocol":"ssh"}`+"\n"+
			`{"eventid":"cowrie.session.closed","timestamp":"2026-11-16T10:00:02Z","session":"s1","duration":2.0}`+"\n",
	), 0o600); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		cnt, _, _, _ := sp.Stats()
		if cnt >= 2 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	cnt, _, _, err := sp.Stats()
	if err != nil || cnt < 2 {
		t.Fatalf("expected >= 2 spooled records from cowrie tailer, got cnt=%d err=%v", cnt, err)
	}

	// Reload bootstrap state cleanly and verify DesiredTrap persisted across restart
	reloaded := loadBootstrapState(filepath.Join(stateDir, "bootstrap.json"))
	traps := reloaded.SnapshotTraps()
	if len(traps) != 1 || traps[0].DeploymentID != "dep-cowrie-1" || traps[0].DesiredState != "running" {
		t.Fatalf("unexpected persisted trap state: %+v", traps)
	}
}
