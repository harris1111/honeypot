package orchestrator

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/harris/honeypot/internal/canary"
	honeypotv1 "github.com/harris/honeypot/proto/gen/honeypot/v1"
)

func TestEncodeAndVerifyFsPickle(t *testing.T) {
	tree := DefaultCowrieTree(1763280000, map[string]int{
		"/etc/issue":           28,
		"/var/www/app/.env":    180,
		"/root/.bash_history":  95,
	})
	raw := MarshalCowriePickle(tree)
	if len(raw) < 10 || raw[0] != 0x80 || raw[1] != 0x02 {
		t.Fatalf("expected pickle protocol 2 header 0x80 0x02, got %x", raw[:min(4, len(raw))])
	}

	// If python3 is available on host, cross-verify deserialization matches Cowrie tuple structure.
	if py, err := exec.LookPath("python3"); err == nil {
		tmp := filepath.Join(t.TempDir(), "fs.pickle")
		if err := os.WriteFile(tmp, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(py, "-c", `
import pickle, sys
data = pickle.load(open(sys.argv[1], "rb"))
assert isinstance(data, list) and data[0] == "/"
children = {item[0]: item for item in data[7]}
assert "var" in children and "etc" in children
print("PICKLE_OK")
`, tmp)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("python3 pickle verification failed: %v\n%s", err, string(out))
		}
		if !strings.Contains(string(out), "PICKLE_OK") {
			t.Fatalf("unexpected python3 output: %s", string(out))
		}
	}
}

func TestSeedCowrieAndDockerManager(t *testing.T) {
	pool := canary.NewSensorKeyPool()
	pool.AddSeeds([]*honeypotv1.CanaryKeySeed{
		{
			CanaryKeyId:     "c-oai",
			KeyPlaintext:    "sk-proj-honeyfskey1234567890",
			ProviderStyle:   "openai",
			PlacementSource: "cowrie_honeyfs",
		},
		{
			CanaryKeyId:     "c-ant",
			KeyPlaintext:    "sk-ant-api03-honeyfskey123456",
			ProviderStyle:   "anthropic",
			PlacementSource: "cowrie_honeyfs",
		},
	})

	trapsRoot := t.TempDir()
	var seenCalls []string
	var lastCreate map[string]any
	fakeDocker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenCalls = append(seenCalls, r.Method+" "+r.URL.Path)
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/networks/create":
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"Id":"net-1"}`))
		case r.Method == http.MethodPost && r.URL.Path == "/containers/create":
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &lastCreate)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"Id":"cid-cowrie-1"}`))
		case strings.HasPrefix(r.URL.Path, "/containers/") && strings.HasSuffix(r.URL.Path, "/logs"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("cowrie started on 2222"))
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer fakeDocker.Close()

	mgr := NewDockerManager(fakeDocker.URL, trapsRoot, pool)
	cid, err := mgr.DeployTrap(context.Background(), DeploySpec{
		DeploymentID: "dep-1",
		TrapKind:     "cowrie",
		ListenPort:   2222,
		AIGatewayURL: "https://llm-trap.example",
	})
	if err != nil {
		t.Fatalf("DeployTrap failed: %v", err)
	}
	if cid != "cid-cowrie-1" {
		t.Fatalf("unexpected container ID %q", cid)
	}

	envBytes, err := os.ReadFile(filepath.Join(trapsRoot, "dep-1", "honeyfs", "var", "www", "app", ".env"))
	if err != nil {
		t.Fatalf("missing seeded .env: %v", err)
	}
	if !strings.Contains(string(envBytes), "sk-proj-honeyfskey1234567890") || !strings.Contains(string(envBytes), "sk-ant-api03-honeyfskey123456") {
		t.Fatalf("canary keys missing in seeded honeyfs .env: %s", string(envBytes))
	}

	hc, _ := lastCreate["HostConfig"].(map[string]any)
	if hc["ReadonlyRootfs"] != true || hc["Privileged"] != false || hc["NetworkMode"] != "trap_isolated_net" {
		t.Fatalf("container HostConfig violated hardening baseline: %+v", hc)
	}

	logs, err := mgr.FetchLogs(context.Background(), "hp-trap-cowrie-dep-1", 50)
	if err != nil || !strings.Contains(logs, "cowrie started") {
		t.Fatalf("FetchLogs failed: logs=%q err=%v", logs, err)
	}
	if err := mgr.StopTrap(context.Background(), "hp-trap-cowrie-dep-1"); err != nil {
		t.Fatalf("StopTrap failed: %v", err)
	}
	if len(seenCalls) < 4 {
		t.Fatalf("expected docker calls sequence, got %v", seenCalls)
	}

	// Verify Heralding deployment configures multi-port ExposedPorts/PortBindings and non-root heralding.yml
	lastCreate = nil
	hCID, err := mgr.DeployTrap(context.Background(), DeploySpec{
		DeploymentID: "dep-heralding",
		TrapKind:     "heralding",
		ListenPort:   21,
	})
	if err != nil || hCID != "cid-cowrie-1" {
		t.Fatalf("DeployTrap heralding failed: cid=%q err=%v", hCID, err)
	}
	hCfg, err := os.ReadFile(filepath.Join(trapsRoot, "dep-heralding", "heralding-etc", "heralding.yml"))
	if err != nil || !strings.Contains(string(hCfg), "port: 2121") || !strings.Contains(string(hCfg), "port: 2525") {
		t.Fatalf("expected non-root heralding.yml, got err=%v body=%s", err, string(hCfg))
	}
	exp, _ := lastCreate["ExposedPorts"].(map[string]any)
	for _, k := range []string{"2121/tcp", "2525/tcp", "2110/tcp", "2143/tcp"} {
		if _, ok := exp[k]; !ok {
			t.Fatalf("missing ExposedPorts key %s in %+v", k, exp)
		}
	}
}

func TestStagedArtifactSinkDeduplicationAndLogTailer(t *testing.T) {
	var uploads atomic.Int32
	sink, err := NewStagedArtifactSink(t.TempDir(), func(ctx context.Context, meta ArtifactMeta, data []byte) error {
		uploads.Add(1)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte("#!/bin/sh\necho pwn\n")
	sum1, err := sink.Submit(context.Background(), ArtifactMeta{NodeID: "n1", SourceURL: "http://evil/a.sh"}, payload)
	if err != nil {
		t.Fatal(err)
	}
	sum2, err := sink.Submit(context.Background(), ArtifactMeta{NodeID: "n1", SourceURL: "http://evil/b.sh"}, payload)
	if err != nil {
		t.Fatal(err)
	}
	if sum1 != sum2 || uploads.Load() != 1 {
		t.Fatalf("expected SHA256 dedup to 1 upload, got uploads=%d (%s vs %s)", uploads.Load(), sum1, sum2)
	}

	// Test LogTailer bookmark persistence across reopen & truncation reset
	tmp := t.TempDir()
	logPath := filepath.Join(tmp, "cowrie.json")
	bmPath := filepath.Join(tmp, "bookmark.json")
	if err := os.WriteFile(logPath, []byte("{\"a\":1}\n{\"a\":2}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t1 := OpenLogTailer(logPath, bmPath)
	lines, err := t1.ReadNewLines()
	if err != nil || len(lines) != 2 {
		t.Fatalf("first read expected 2 lines, got %v err=%v", lines, err)
	}

	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("{\"a\":3}\n")
	_ = f.Close()

	t2 := OpenLogTailer(logPath, bmPath)
	lines, err = t2.ReadNewLines()
	if err != nil || len(lines) != 1 || lines[0] != `{"a":3}` {
		t.Fatalf("reopened tailer expected line 3 only, got %v err=%v", lines, err)
	}

	// Simulate log rotation / truncation
	if err := os.WriteFile(logPath, []byte("{\"a\":4}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	lines, err = t2.ReadNewLines()
	if err != nil || len(lines) != 1 || lines[0] != `{"a":4}` {
		t.Fatalf("truncated file expected reset read of line 4, got %v err=%v", lines, err)
	}
}
