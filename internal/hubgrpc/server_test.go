package hubgrpc

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/harris/honeypot/internal/pki"
	"github.com/harris/honeypot/internal/store"
	honeypotv1 "github.com/harris/honeypot/proto/gen/honeypot/v1"
)

func TestHubEnrollStreamSpoolAndRevocationIntegration(t *testing.T) {
	if os.Getenv("RUN_INTEGRATION_TESTS") != "1" {
		t.Skip("set RUN_INTEGRATION_TESTS=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	pgDSN := os.Getenv("TEST_POSTGRES_DSN")
	if pgDSN == "" {
		pgDSN = "postgres://honeypot:honeypot_test_pw@127.0.0.1:15432/honeypot?sslmode=disable"
	}
	redisAddr := os.Getenv("TEST_REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "127.0.0.1:16379"
	}

	pg, err := store.OpenPostgres(ctx, pgDSN)
	if err != nil {
		t.Fatalf("OpenPostgres: %v", err)
	}
	defer pg.Close()

	rd, err := store.OpenRedis(ctx, redisAddr)
	if err != nil {
		t.Fatalf("OpenRedis: %v", err)
	}
	defer func() { _ = rd.Close() }()

	ca, err := pki.InitOrLoad(t.TempDir())
	if err != nil {
		t.Fatalf("InitOrLoad: %v", err)
	}
	srvCert, _, _, err := ca.IssueServerCert([]string{"127.0.0.1", "localhost", "hive.internal", "enroll.hive.internal"})
	if err != nil {
		t.Fatalf("IssueServerCert: %v", err)
	}

	hub := NewServer(ca, pg, rd)
	gs := hub.BuildGRPCServer()
	honeypotv1.RegisterSensorControlServiceServer(gs, hub)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", pki.BuildHiveIngressTLSConfig(ca, srvCert))
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	httpSrv := &http.Server{Handler: hub.BuildHTTPMux(gs)}
	go func() { _ = httpSrv.Serve(ln) }()
	defer func() { _ = httpSrv.Close() }()

	addr := ln.Addr().String()
	rawTok, tokHash, err := pki.GenerateJoinToken()
	if err != nil {
		t.Fatalf("GenerateJoinToken: %v", err)
	}
	if _, err := pg.CreateJoinToken(ctx, tokHash, "sensor", "hubtest-"+uuid.NewString()[:6], "sgp1", time.Hour); err != nil {
		t.Fatalf("CreateJoinToken: %v", err)
	}

	// Enroll over enroll.* SNI pinned to CA fingerprint
	fp := ca.RootFingerprintSHA256()
	keyPEM, csrPEM, _ := pki.GenerateClientKeyAndCSR("sensor-bootstrap")
	enrollTLS := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		ServerName:         "enroll.hive.internal",
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			for _, raw := range rawCerts {
				sum := sha256.Sum256(raw)
				if strings.EqualFold(hex.EncodeToString(sum[:]), fp) {
					return nil
				}
			}
			return errors.New("fingerprint mismatch")
		},
	}
	// Dial with explicit target using passthrough resolver
	eConn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(enrollTLS)), grpc.WithContextDialer(func(ctx context.Context, a string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", a)
	}))
	if err != nil {
		t.Fatalf("dial enroll: %v", err)
	}
	eResp, err := honeypotv1.NewSensorControlServiceClient(eConn).EnrollNode(ctx, &honeypotv1.EnrollNodeRequest{
		JoinToken:    rawTok,
		CsrPem:       csrPEM,
		PublicIpv4:   "203.0.113.200",
		AgentVersion: "0.1.0",
	})
	_ = eConn.Close()
	if err != nil {
		t.Fatalf("EnrollNode: %v", err)
	}

	certStore, _ := pki.OpenClientCertStore(t.TempDir())
	if err := certStore.SaveInitial(eResp.GetNodeId(), eResp.GetRootCaPem(), eResp.GetClientCertPem(), keyPEM); err != nil {
		t.Fatalf("SaveInitial: %v", err)
	}

	// Connect over strict mTLS default SNI
	mtlsCfg, _ := certStore.ClientTLSConfig("hive.internal")
	mConn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(mtlsCfg)))
	if err != nil {
		t.Fatalf("dial mtls: %v", err)
	}
	defer func() { _ = mConn.Close() }()
	client := honeypotv1.NewSensorControlServiceClient(mConn)

	// Push batch over mTLS
	evID := uuid.NewString()
	bResp, err := client.PushEventsBatch(ctx, &honeypotv1.PushEventsBatchRequest{
		NodeId: eResp.GetNodeId(),
		Events: []*honeypotv1.TelemetryEvent{{
			EventUuid:  evID,
			NodeId:     eResp.GetNodeId(),
			SourceIp:   "198.51.100.88",
			TrapKind:   "webcve",
			CveId:      "CVE-2024-4577",
			IsKev:      true,
			ObservedAt: timestamppb.Now(),
		}},
	})
	if err != nil || len(bResp.GetAckedEventUuids()) != 1 {
		t.Fatalf("PushEventsBatch: resp=%v err=%v", bResp, err)
	}

	// Revoke node and verify cached/DB rejection happens immediately
	if err := pg.RevokeNode(ctx, eResp.GetNodeId(), "admin"); err != nil {
		t.Fatalf("RevokeNode: %v", err)
	}
	hub.InvalidateCertCache(ctx, eResp.GetNodeId())
	_, err = client.PushEventsBatch(ctx, &honeypotv1.PushEventsBatchRequest{NodeId: eResp.GetNodeId()})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied after node revocation, got %v", err)
	}
}
