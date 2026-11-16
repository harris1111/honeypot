package hubgrpc

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/harris/honeypot/internal/pki"
	"github.com/harris/honeypot/internal/store"
	honeypotv1 "github.com/harris/honeypot/proto/gen/honeypot/v1"
)

const certCacheTTL = 5 * time.Minute

// BatchIngestHook runs asynchronously or synchronously after PushEventsBatch persists events.
type BatchIngestHook func(ctx context.Context, nodeID string, req *honeypotv1.PushEventsBatchRequest)

// CommandAckHook receives command execution acknowledgements and streamed container logs.
type CommandAckHook func(nodeID string, ack *honeypotv1.CommandAck, logChunk *honeypotv1.ContainerLogChunk)

type activeStream struct {
	cmdCh  chan *honeypotv1.HiveCommand
	cancel context.CancelFunc
}

// Server implements SensorControlService over strict mTLS 1.3 with SNI-isolated bootstrap enrollment.
type Server struct {
	honeypotv1.UnimplementedSensorControlServiceServer

	ca    *pki.CA
	pg    *store.Postgres
	redis *store.Redis

	enrollMu       sync.Mutex
	enrollLimiters map[string]*rate.Limiter

	streamsMu sync.RWMutex
	streams   map[string]*activeStream

	// Extension hooks mounted in Phases 4-6
	RelayLLMHandler     func(req *honeypotv1.RelayLLMRequest, stream honeypotv1.SensorControlService_RelayLLMStreamServer) error
	HasArtifactHandler  func(ctx context.Context, req *honeypotv1.HasArtifactRequest) (*honeypotv1.HasArtifactResponse, error)
	UploadArtifactHandler func(stream honeypotv1.SensorControlService_UploadArtifactServer) error
	NginxFeedHandler    http.HandlerFunc
	OnBatchIngested     BatchIngestHook
	OnCommandFrame      CommandAckHook
	InitialCanarySeeder func(ctx context.Context, nodeID string) ([]*honeypotv1.CanaryKeySeed, error)
}

// NewServer constructs a Hive gRPC control server.
func NewServer(ca *pki.CA, pg *store.Postgres, rd *store.Redis) *Server {
	return &Server{
		ca:             ca,
		pg:             pg,
		redis:          rd,
		enrollLimiters: make(map[string]*rate.Limiter),
		streams:        make(map[string]*activeStream),
	}
}

// BuildGRPCServer builds the gRPC Server with 16 MiB message limits and strict mTLS + revocation interceptors.
func (s *Server) BuildGRPCServer() *grpc.Server {
	return grpc.NewServer(
		grpc.MaxRecvMsgSize(16*1024*1024),
		grpc.UnaryInterceptor(s.unaryAuthInterceptor),
		grpc.StreamInterceptor(s.streamAuthInterceptor),
	)
}

// BuildHTTPMux multiplexes gRPC and mTLS-authenticated REST routes (e.g. nginx-guard signed feeds) on :9443.
func (s *Server) BuildHTTPMux(gs *grpc.Server) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 2 && strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
			gs.ServeHTTP(w, r)
			return
		}
		// Reject any unauthenticated non-gRPC call over HTTP (including enroll.* SNI probing REST paths)
		id, ok := pki.ExtractHTTPPeerIdentity(r)
		if !ok {
			http.Error(w, "mTLS client certificate required", http.StatusUnauthorized)
			return
		}
		if err := s.verifyActiveNodeCert(r.Context(), id); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		if r.URL.Path == "/api/v1/guard/feeds/nginx" && s.NginxFeedHandler != nil {
			if id.Role != "nginx_guard" {
				http.Error(w, "nginx_guard role required", http.StatusForbidden)
				return
			}
			s.NginxFeedHandler(w, r)
			return
		}
		http.NotFound(w, r)
	})
}

func (s *Server) unaryAuthInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	if info.FullMethod == "/honeypot.v1.SensorControlService/EnrollNode" {
		return handler(ctx, req)
	}
	id, ok := pki.ExtractGRPCPeerIdentity(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "valid SPIFFE mTLS client certificate required")
	}
	if err := s.verifyActiveNodeCert(ctx, id); err != nil {
		return nil, err
	}
	if info.FullMethod != "/honeypot.v1.SensorControlService/RenewNodeCert" && id.Role != "sensor" {
		return nil, status.Error(codes.PermissionDenied, "sensor role required for sensor RPCs")
	}
	return handler(ctx, req)
}

func (s *Server) streamAuthInterceptor(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	ctx := ss.Context()
	id, ok := pki.ExtractGRPCPeerIdentity(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "valid SPIFFE mTLS client certificate required")
	}
	if err := s.verifyActiveNodeCert(ctx, id); err != nil {
		return err
	}
	if id.Role != "sensor" {
		return status.Error(codes.PermissionDenied, "sensor role required for sensor streams")
	}
	return handler(srv, ss)
}

func (s *Server) verifyActiveNodeCert(ctx context.Context, id pki.PeerIdentity) error {
	if s.redis != nil {
		if cached, hit, err := s.redis.GetCachedNodeCertState(ctx, id.NodeID); err == nil && hit {
			if cached.Status == "revoked" {
				return status.Error(codes.PermissionDenied, "node certificate revoked")
			}
			if cached.CertSerial != id.SerialHex {
				return status.Error(codes.Unauthenticated, "certificate serial superseded")
			}
			return nil
		}
	}
	st, err := s.pg.GetNodeCertState(ctx, id.NodeID)
	if err != nil {
		if errors.Is(err, store.ErrNodeNotFound) {
			return status.Error(codes.Unauthenticated, "unknown node")
		}
		return status.Errorf(codes.Internal, "lookup node state: %v", err)
	}
	if s.redis != nil {
		_ = s.redis.CacheNodeCertState(ctx, st, certCacheTTL)
	}
	if st.Status == "revoked" {
		return status.Error(codes.PermissionDenied, "node certificate revoked")
	}
	if st.CertSerial != id.SerialHex {
		return status.Error(codes.Unauthenticated, "certificate serial superseded")
	}
	return nil
}

// InvalidateCertCache evicts or marks a node's cert state as revoked in Redis immediately.
func (s *Server) InvalidateCertCache(ctx context.Context, nodeID string) {
	if s.redis != nil {
		_ = s.redis.InvalidateNodeCertState(ctx, nodeID)
	}
}

// DisconnectNode closes any open StreamControl stream and caches revocation status immediately.
func (s *Server) DisconnectNode(ctx context.Context, nodeID string) {
	if s.redis != nil {
		_ = s.redis.CacheNodeCertState(ctx, store.NodeCertState{NodeID: nodeID, Status: "revoked"}, certCacheTTL)
	}
	s.streamsMu.Lock()
	if st, ok := s.streams[nodeID]; ok {
		delete(s.streams, nodeID)
		st.cancel()
	}
	s.streamsMu.Unlock()
}

func (s *Server) allowEnrollAttempt(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	s.enrollMu.Lock()
	lim, ok := s.enrollLimiters[host]
	if !ok {
		if len(s.enrollLimiters) > 4096 {
			s.enrollLimiters = make(map[string]*rate.Limiter)
		}
		lim = rate.NewLimiter(rate.Every(2*time.Second), 5)
		s.enrollLimiters[host] = lim
	}
	s.enrollMu.Unlock()
	return lim.Allow()
}

// EnrollNode handles initial one-time join token enrollment on the enroll.* SNI.
func (s *Server) EnrollNode(ctx context.Context, req *honeypotv1.EnrollNodeRequest) (*honeypotv1.EnrollNodeResponse, error) {
	remoteIP := "unknown"
	if pr, ok := peer.FromContext(ctx); ok && pr.Addr != nil {
		remoteIP = pr.Addr.String()
	}
	if !s.allowEnrollAttempt(remoteIP) {
		return nil, status.Error(codes.ResourceExhausted, "enrollment rate limited")
	}
	if strings.TrimSpace(req.GetJoinToken()) == "" || len(req.GetCsrPem()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "join_token and csr_pem required")
	}
	if err := validateCSRBEM(req.GetCsrPem()); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid CSR before token consume: %v", err)
	}
	tokenHash := pki.HashJoinToken(req.GetJoinToken())

	// First atomically consume token using a provisional serial, then update with final signed serial.
	consumed, err := s.pg.ConsumeJoinToken(ctx, tokenHash, req.GetPublicIpv4(), req.GetPublicIpv6(), req.GetAgentVersion(), "pending", time.Now().UTC().Add(90*24*time.Hour))
	if err != nil {
		if errors.Is(err, store.ErrTokenInvalid) {
			return nil, status.Error(codes.PermissionDenied, "join token invalid, expired, or already used")
		}
		return nil, status.Errorf(codes.Internal, "consume join token: %v", err)
	}

	certPEM, serialHex, expiresAt, err := s.ca.SignClientCSR(req.GetCsrPem(), consumed.NodeRole, consumed.NodeID.String(), 90*24*time.Hour)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "sign CSR: %v", err)
	}
	if err := s.pg.UpdateNodeCert(ctx, consumed.NodeID.String(), serialHex, expiresAt); err != nil {
		return nil, status.Errorf(codes.Internal, "persist node cert serial: %v", err)
	}
	s.InvalidateCertCache(ctx, consumed.NodeID.String())
	_ = s.pg.InsertAuditLog(ctx, "system", "node_enrolled", "sensor_node", consumed.NodeID.String(), map[string]any{
		"name":   consumed.IntendedName,
		"role":   consumed.NodeRole,
		"serial": serialHex,
	}, req.GetPublicIpv4())

	allowlist, _ := s.pg.ListAllowlistCIDRs(ctx)
	var seeds []*honeypotv1.CanaryKeySeed
	if s.InitialCanarySeeder != nil && consumed.NodeRole == "sensor" {
		seeds, _ = s.InitialCanarySeeder(ctx, consumed.NodeID.String())
	}

	return &honeypotv1.EnrollNodeResponse{
		NodeId:                    consumed.NodeID.String(),
		NodeRole:                  consumed.NodeRole,
		ClientCertPem:             certPEM,
		RootCaPem:                 s.ca.RootCertPEM(),
		FeedVerifyEd25519Pubkey:   s.ca.FeedPublicKey(),
		AllowlistCidrs:            allowlist,
		CanaryKeys:                seeds,
		CertExpiresAt:             timestamppb.New(expiresAt),
	}, nil
}

// RenewNodeCert handles two-phase certificate rotation for already-enrolled mTLS nodes.
func (s *Server) RenewNodeCert(ctx context.Context, req *honeypotv1.RenewNodeCertRequest) (*honeypotv1.RenewNodeCertResponse, error) {
	id, ok := pki.ExtractGRPCPeerIdentity(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "missing peer identity")
	}
	certPEM, serialHex, expiresAt, err := s.ca.SignClientCSR(req.GetCsrPem(), id.Role, id.NodeID, 90*24*time.Hour)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "sign renewal CSR: %v", err)
	}
	if err := s.pg.UpdateNodeCert(ctx, id.NodeID, serialHex, expiresAt); err != nil {
		return nil, status.Errorf(codes.Internal, "update cert serial: %v", err)
	}
	s.InvalidateCertCache(ctx, id.NodeID)
	_ = s.pg.InsertAuditLog(ctx, id.NodeID, "node_cert_renewed", "sensor_node", id.NodeID, map[string]any{"serial": serialHex}, "")
	return &honeypotv1.RenewNodeCertResponse{
		ClientCertPem: certPEM,
		CertExpiresAt: timestamppb.New(expiresAt),
	}, nil
}

// StreamControl maintains bidirectional heartbeat/command streams for connected Sensor Nodes.
func (s *Server) StreamControl(stream honeypotv1.SensorControlService_StreamControlServer) error {
	id, ok := pki.ExtractGRPCPeerIdentity(stream.Context())
	if !ok {
		return status.Error(codes.Unauthenticated, "missing peer identity")
	}

	sCtx, cancel := context.WithCancel(stream.Context())
	entry := &activeStream{
		cmdCh:  make(chan *honeypotv1.HiveCommand, 64),
		cancel: cancel,
	}
	s.streamsMu.Lock()
	if prev, exists := s.streams[id.NodeID]; exists {
		prev.cancel()
	}
	s.streams[id.NodeID] = entry
	s.streamsMu.Unlock()

	defer func() {
		cancel()
		s.streamsMu.Lock()
		if cur, exists := s.streams[id.NodeID]; exists && cur == entry {
			delete(s.streams, id.NodeID)
		}
		s.streamsMu.Unlock()
	}()

	errCh := make(chan error, 1)
	go func() {
		for {
			select {
			case <-sCtx.Done():
				errCh <- sCtx.Err()
				return
			case cmd := <-entry.cmdCh:
				if err := stream.Send(cmd); err != nil {
					errCh <- err
					return
				}
			}
		}
	}()

	for {
		select {
		case err := <-errCh:
			return err
		case <-sCtx.Done():
			return sCtx.Err()
		default:
		}
		frame, err := stream.Recv()
		if err != nil {
			return err
		}
		switch p := frame.Payload.(type) {
		case *honeypotv1.AgentFrame_Heartbeat:
			_ = s.pg.UpdateNodeHeartbeat(sCtx, id.NodeID, p.Heartbeat)
		case *honeypotv1.AgentFrame_CommandAck:
			if s.OnCommandFrame != nil {
				s.OnCommandFrame(id.NodeID, p.CommandAck, nil)
			}
		case *honeypotv1.AgentFrame_ContainerLog:
			if s.OnCommandFrame != nil {
				s.OnCommandFrame(id.NodeID, nil, p.ContainerLog)
			}
		}
	}
}

// SendCommand dispatches a HiveCommand to an active connected Sensor Node without closing-channel races.
func (s *Server) SendCommand(nodeID string, cmd *honeypotv1.HiveCommand) error {
	if cmd.GetCommandId() == "" {
		cmd.CommandId = randomHex8()
	}
	s.streamsMu.RLock()
	defer s.streamsMu.RUnlock()
	st, ok := s.streams[nodeID]
	if !ok {
		return fmt.Errorf("node %s not connected", nodeID)
	}
	select {
	case st.cmdCh <- cmd:
		return nil
	default:
		return fmt.Errorf("node %s command buffer full", nodeID)
	}
}

func validateCSRBEM(csrPEM []byte) error {
	blk, _ := pem.Decode(csrPEM)
	if blk == nil {
		return errors.New("no PEM CSR block found")
	}
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		return err
	}
	return csr.CheckSignature()
}

// ConnectedNodes returns active node IDs currently holding open control streams.
func (s *Server) ConnectedNodes() []string {
	s.streamsMu.RLock()
	defer s.streamsMu.RUnlock()
	out := make([]string, 0, len(s.streams))
	for k := range s.streams {
		out = append(out, k)
	}
	return out
}

// PushEventsBatch ingests spooled telemetry events, SSH replays, and LLM conversations idempotently.
func (s *Server) PushEventsBatch(ctx context.Context, req *honeypotv1.PushEventsBatchRequest) (*honeypotv1.PushEventsBatchResponse, error) {
	id, ok := pki.ExtractGRPCPeerIdentity(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "missing peer identity")
	}
	acked, deadletter, err := s.pg.InsertEventsBatch(ctx, id.NodeID, req)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "insert events batch: %v", err)
	}
	if s.redis != nil {
		for _, ev := range req.GetEvents() {
			_ = s.redis.PublishLiveEvent(ctx, map[string]any{
				"event_uuid": ev.GetEventUuid(),
				"node_id":    id.NodeID,
				"source_ip":  ev.GetSourceIp(),
				"trap_kind":  ev.GetTrapKind(),
				"persona":    ev.GetPersona(),
				"cve_id":     ev.GetCveId(),
				"is_kev":     ev.GetIsKev(),
				"http_path":  ev.GetHttpPath(),
				"severity":   ev.GetSeverityScore(),
				"observed":   ev.GetObservedAt().AsTime().UTC(),
			})
		}
	}
	if s.OnBatchIngested != nil {
		s.OnBatchIngested(ctx, id.NodeID, req)
	}
	return &honeypotv1.PushEventsBatchResponse{
		AckedEventUuids:         acked,
		RejectedDeadletterUuids: deadletter,
	}, nil
}

// RelayLLMStream delegates to the Phase 4 Hive Chameleon LLM handler.
func (s *Server) RelayLLMStream(req *honeypotv1.RelayLLMRequest, stream honeypotv1.SensorControlService_RelayLLMStreamServer) error {
	if s.RelayLLMHandler == nil {
		return status.Error(codes.Unimplemented, "LLM relay not mounted")
	}
	return s.RelayLLMHandler(req, stream)
}

// HasArtifactSHA256 delegates to Phase 5 Vault dedup handler.
func (s *Server) HasArtifactSHA256(ctx context.Context, req *honeypotv1.HasArtifactRequest) (*honeypotv1.HasArtifactResponse, error) {
	if s.HasArtifactHandler == nil {
		return &honeypotv1.HasArtifactResponse{Exists: false}, nil
	}
	return s.HasArtifactHandler(ctx, req)
}

// UploadArtifact delegates to Phase 5 Vault upload handler.
func (s *Server) UploadArtifact(stream honeypotv1.SensorControlService_UploadArtifactServer) error {
	if s.UploadArtifactHandler == nil {
		return status.Error(codes.Unimplemented, "artifact vault not mounted")
	}
	return s.UploadArtifactHandler(stream)
}

func randomHex8() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// MarshalJSONResponse is a helper for HTTP handlers on :9443.
func MarshalJSONResponse(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
