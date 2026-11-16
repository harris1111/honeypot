package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/harris/honeypot/internal/canary"
	"github.com/harris/honeypot/internal/malware"
	"github.com/harris/honeypot/internal/orchestrator"
	"github.com/harris/honeypot/internal/pki"
	"github.com/harris/honeypot/internal/spool"
	"github.com/harris/honeypot/internal/traps/cowrieparser"
	"github.com/harris/honeypot/internal/traps/heraldingparser"
	honeypotv1 "github.com/harris/honeypot/proto/gen/honeypot/v1"
)

// SensorController manages local traps, log tailing, telemetry enqueueing, and Hive StreamControl RPCs.
type SensorController struct {
	nodeID       string
	stateDir     string
	aiGatewayURL string
	certStore    *pki.ClientCertStore
	state        *SensorBootstrapState
	sp           *spool.BoltSpool
	keyPool      *canary.SensorKeyPool
	dockerMgr    *orchestrator.DockerManager
	artifactSink orchestrator.ArtifactSink

	onToggleCvePack   func(cveID string, enabled bool)
	onNativeTrapCmd   func(ctx context.Context, cmd DesiredTrap) error
	nativeRT          *NativeTrapRuntime
	safeDownloader    *malware.SafeDownloader

	tailersMu sync.Mutex
	tailers   map[string]context.CancelFunc
	statuses  map[string]*honeypotv1.TrapStatus
}

func newSensorController(
	nodeID, stateDir, dockerProxyURL, aiGatewayURL string,
	certStore *pki.ClientCertStore,
	st *SensorBootstrapState,
	sp *spool.BoltSpool,
	pool *canary.SensorKeyPool,
	sink orchestrator.ArtifactSink,
) *SensorController {
	return &SensorController{
		nodeID:       nodeID,
		stateDir:     stateDir,
		aiGatewayURL: aiGatewayURL,
		certStore:    certStore,
		state:        st,
		sp:           sp,
		keyPool:      pool,
		dockerMgr:    orchestrator.NewDockerManager(dockerProxyURL, filepath.Join(stateDir, "traps"), pool),
		artifactSink: sink,
		tailers:      make(map[string]context.CancelFunc),
		statuses:     make(map[string]*honeypotv1.TrapStatus),
	}
}

func (c *SensorController) ReconcileOnStartup(ctx context.Context) {
	for _, dt := range c.state.SnapshotTraps() {
		if dt.DesiredState != "running" {
			continue
		}
		if err := c.startTrap(ctx, dt); err != nil {
			log.Printf("startup reconcile trap %s (%s) error: %v", dt.DeploymentID, dt.TrapKind, err)
		}
	}
}

func (c *SensorController) RunControlStream(ctx context.Context, client honeypotv1.SensorControlServiceClient) {
	for {
		if ctx.Err() != nil {
			return
		}
		if err := c.runOnce(ctx, client); err != nil && ctx.Err() == nil {
			log.Printf("StreamControl disconnected (%v); reconnecting in 3s", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(3 * time.Second):
		}
	}
}

func (c *SensorController) runOnce(ctx context.Context, client honeypotv1.SensorControlServiceClient) error {
	stream, err := client.StreamControl(ctx)
	if err != nil {
		return err
	}
	sendMu := &sync.Mutex{}
	sendFrame := func(f *honeypotv1.AgentFrame) error {
		sendMu.Lock()
		defer sendMu.Unlock()
		return stream.Send(f)
	}

	if err := sendFrame(c.buildHeartbeatFrame()); err != nil {
		return err
	}

	hbCtx, cancelHB := context.WithCancel(ctx)
	defer cancelHB()
	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-hbCtx.Done():
				return
			case <-t.C:
				_ = sendFrame(c.buildHeartbeatFrame())
			}
		}
	}()

	for {
		cmd, err := stream.Recv()
		if err != nil {
			return err
		}
		c.handleCommand(ctx, client, cmd, sendFrame)
	}
}

func (c *SensorController) buildHeartbeatFrame() *honeypotv1.AgentFrame {
	c.tailersMu.Lock()
	traps := make([]*honeypotv1.TrapStatus, 0, len(c.statuses))
	for _, ts := range c.statuses {
		if cloned, ok := proto.Clone(ts).(*honeypotv1.TrapStatus); ok && cloned != nil {
			traps = append(traps, cloned)
		}
	}
	c.tailersMu.Unlock()

	var qItems, qBytes uint64
	if c.sp != nil {
		if items, _, b, err := c.sp.Stats(); err == nil {
			qItems, qBytes = uint64(items), uint64(b)
		}
	}
	return &honeypotv1.AgentFrame{
		NodeId: c.nodeID,
		Payload: &honeypotv1.AgentFrame_Heartbeat{
			Heartbeat: &honeypotv1.NodeHeartbeat{
				AgentVersion:       "0.1.0",
				Traps:              traps,
				SpoolQueuedItems:   qItems,
				SpoolBytes:         qBytes,
				ClockSkewCheckUnix: time.Now().UTC().Unix(),
			},
		},
	}
}

func (c *SensorController) handleCommand(
	ctx context.Context,
	client honeypotv1.SensorControlServiceClient,
	cmd *honeypotv1.HiveCommand,
	sendFrame func(*honeypotv1.AgentFrame) error,
) {
	ack := &honeypotv1.CommandAck{CommandId: cmd.GetCommandId(), Ok: true, Message: "ok"}
	switch p := cmd.Payload.(type) {
	case *honeypotv1.HiveCommand_DeployTrap:
		d := p.DeployTrap
		dt := DesiredTrap{
			DeploymentID:  d.GetDeploymentId(),
			TrapKind:      d.GetTrapKind(),
			ContainerName: d.GetContainerName(),
			Image:         d.GetImage(),
			ListenPort:    d.GetListenPort(),
			Protocol:      d.GetProtocol(),
			ConfigJSON:    d.GetConfigJson(),
			DesiredState:  "running",
		}
		_ = c.state.UpsertDesiredTrap(dt)
		if err := c.startTrap(ctx, dt); err != nil {
			ack.Ok = false
			ack.Message = err.Error()
		}

	case *honeypotv1.HiveCommand_StopTrap:
		s := p.StopTrap
		_ = c.state.SetTrapStateByContainer(s.GetDeploymentId(), s.GetContainerName(), "stopped")
		c.stopTailer(s.GetDeploymentId())
		if c.nativeRT != nil {
			c.nativeRT.StopTrap(s.GetDeploymentId())
		}
		if s.GetContainerName() != "" && strings.HasPrefix(s.GetContainerName(), "hp-trap-") {
			if err := c.dockerMgr.StopTrap(ctx, s.GetContainerName()); err != nil {
				ack.Ok = false
				ack.Message = err.Error()
			}
		}
		c.setTrapStatus(s.GetDeploymentId(), "", s.GetContainerName(), 0, "tcp", "stopped", ack.Message)

	case *honeypotv1.HiveCommand_RestartTrap:
		r := p.RestartTrap
		if r.GetContainerName() != "" {
			if err := c.dockerMgr.RestartTrap(ctx, r.GetContainerName()); err != nil {
				ack.Ok = false
				ack.Message = err.Error()
			}
		}

	case *honeypotv1.HiveCommand_FetchLogs:
		f := p.FetchLogs
		out, err := c.dockerMgr.FetchLogs(ctx, f.GetContainerName(), f.GetTailLines())
		if err != nil {
			ack.Ok = false
			ack.Message = err.Error()
		} else {
			for _, ln := range strings.Split(strings.TrimSpace(out), "\n") {
				if ln == "" {
					continue
				}
				_ = sendFrame(&honeypotv1.AgentFrame{
					NodeId: c.nodeID,
					Payload: &honeypotv1.AgentFrame_ContainerLog{
						ContainerLog: &honeypotv1.ContainerLogChunk{
							CommandId:    cmd.GetCommandId(),
							DeploymentId: f.GetDeploymentId(),
							Line:         ln,
							ObservedAt:   timestamppb.Now(),
						},
					},
				})
			}
		}

	case *honeypotv1.HiveCommand_SyncCanaryKeys:
		c.keyPool.AddSeeds(p.SyncCanaryKeys.GetKeys())
		_ = c.state.UpdateCanarySeeds(c.keyPool.SnapshotSeeds())

	case *honeypotv1.HiveCommand_SyncAllowlist:
		cidrs := p.SyncAllowlist.GetCidrs()
		_ = c.state.UpdateAllowlist(cidrs)
		if c.safeDownloader != nil {
			c.safeDownloader.UpdateBlockedPrefixes(cidrs)
		}

	case *honeypotv1.HiveCommand_ToggleCvePack:
		t := p.ToggleCvePack
		_ = c.state.SetCveToggle(t.GetCveId(), t.GetEnabled())
		if c.onToggleCvePack != nil {
			c.onToggleCvePack(t.GetCveId(), t.GetEnabled())
		}

	case *honeypotv1.HiveCommand_RotateCert:
		if err := c.rotateCert(ctx, client); err != nil {
			ack.Ok = false
			ack.Message = err.Error()
		}
	}

	_ = sendFrame(&honeypotv1.AgentFrame{
		NodeId:  c.nodeID,
		Payload: &honeypotv1.AgentFrame_CommandAck{CommandAck: ack},
	})
}

func (c *SensorController) startTrap(ctx context.Context, dt DesiredTrap) error {
	switch dt.TrapKind {
	case "cowrie", "heralding":
		if _, err := c.dockerMgr.DeployTrap(ctx, dt.toDeploySpec(c.aiGatewayURL)); err != nil {
			c.setTrapStatus(dt.DeploymentID, dt.TrapKind, dt.ContainerName, dt.ListenPort, dt.Protocol, "error", err.Error())
			return err
		}
		if dt.TrapKind == "cowrie" {
			c.ensureCowrieTailer(ctx, dt.DeploymentID, dt.ListenPort)
		} else {
			c.ensureHeraldingTailer(ctx, dt.DeploymentID, dt.ListenPort)
		}
		c.setTrapStatus(dt.DeploymentID, dt.TrapKind, dt.ContainerName, dt.ListenPort, dt.Protocol, "running", "")
		return nil
	default:
		if dt.TrapKind == "infratrap" && c.nativeRT != nil {
			var cfg struct {
				Subtype  string `json:"subtype"`
				BindHost string `json:"bind_host"`
			}
			_ = json.Unmarshal([]byte(dt.ConfigJSON), &cfg)
			if cfg.Subtype == "" {
				cfg.Subtype = inferInfraSubtype(dt.ContainerName, dt.ListenPort)
			}
			if err := c.nativeRT.StartInfraTrap(ctx, dt.DeploymentID, cfg.Subtype, dt.ListenPort, cfg.BindHost); err != nil {
				c.setTrapStatus(dt.DeploymentID, dt.TrapKind, dt.ContainerName, dt.ListenPort, dt.Protocol, "error", err.Error())
				return err
			}
		} else if dt.TrapKind == "llmproxy" && c.nativeRT != nil {
			var cfg struct {
				BindHost string `json:"bind_host"`
			}
			_ = json.Unmarshal([]byte(dt.ConfigJSON), &cfg)
			if err := c.nativeRT.StartLLMProxyPort(dt.DeploymentID, dt.ListenPort, cfg.BindHost); err != nil {
				c.setTrapStatus(dt.DeploymentID, dt.TrapKind, dt.ContainerName, dt.ListenPort, dt.Protocol, "error", err.Error())
				return err
			}
		} else if dt.TrapKind == "webcve" && c.nativeRT != nil {
			addr := fmt.Sprintf(":%d", dt.ListenPort)
			if dt.ListenPort == 443 {
				if err := c.nativeRT.StartWebListeners("", addr); err != nil {
					c.setTrapStatus(dt.DeploymentID, dt.TrapKind, dt.ContainerName, dt.ListenPort, dt.Protocol, "error", err.Error())
					return err
				}
			} else {
				if err := c.nativeRT.StartWebListeners(addr, ""); err != nil {
					c.setTrapStatus(dt.DeploymentID, dt.TrapKind, dt.ContainerName, dt.ListenPort, dt.Protocol, "error", err.Error())
					return err
				}
			}
		} else if c.onNativeTrapCmd != nil {
			return c.onNativeTrapCmd(ctx, dt)
		}
		c.setTrapStatus(dt.DeploymentID, dt.TrapKind, dt.ContainerName, dt.ListenPort, dt.Protocol, "running", "")
		return nil
	}
}

func inferInfraSubtype(name string, port uint32) string {
	ln := strings.ToLower(name)
	switch {
	case strings.Contains(ln, "docker") || port == 2375:
		return "docker"
	case strings.Contains(ln, "k8s") || strings.Contains(ln, "kubelet") || port == 6443 || port == 10250:
		return "k8s"
	case strings.Contains(ln, "redis") || port == 6379:
		return "redis"
	case strings.Contains(ln, "mysql") || port == 3306:
		return "mysql"
	case strings.Contains(ln, "postgres") || port == 5432:
		return "postgres"
	default:
		return ""
	}
}

func (c *SensorController) setTrapStatus(depID, kind, cname string, port uint32, proto, actual, errMsg string) {
	c.tailersMu.Lock()
	defer c.tailersMu.Unlock()
	if prev, ok := c.statuses[depID]; ok && kind == "" {
		prev.ActualState = actual
		prev.ErrorMessage = errMsg
		return
	}
	c.statuses[depID] = &honeypotv1.TrapStatus{
		DeploymentId:  depID,
		TrapKind:      kind,
		ContainerName: cname,
		ListenPort:    port,
		Protocol:      proto,
		ActualState:   actual,
		ErrorMessage:  errMsg,
	}
}

func (c *SensorController) ensureCowrieTailer(parentCtx context.Context, deploymentID string, listenPort uint32) {
	c.tailersMu.Lock()
	if cancel, ok := c.tailers[deploymentID]; ok {
		cancel()
	}
	tCtx, cancel := context.WithCancel(parentCtx)
	c.tailers[deploymentID] = cancel
	c.tailersMu.Unlock()

	logPath := filepath.Join(c.stateDir, "traps", deploymentID, "var", "log", "cowrie", "cowrie.json")
	bmPath := filepath.Join(c.stateDir, "traps", deploymentID, "cowrie.bookmark.json")
	tailer := orchestrator.OpenLogTailer(logPath, bmPath)
	parser := cowrieparser.NewParser(c.nodeID, listenPort, c.keyPool)
	parser.SetTrapBaseDir(filepath.Join(c.stateDir, "traps", deploymentID))

	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-tCtx.Done():
				return
			case <-ticker.C:
				lines, err := tailer.ReadNewLines()
				if err != nil {
					continue
				}
				for _, ln := range lines {
					res, err := parser.ProcessLine(ln)
					if err != nil {
						continue
					}
					for _, ev := range res.Events {
						_ = c.sp.EnqueueEvent(ev)
					}
					if res.Replay != nil {
						_ = c.sp.EnqueueSSHReplay(res.Replay)
					}
					if c.safeDownloader != nil && len(res.Downloads) > 0 {
						for _, dl := range res.Downloads {
							if dl.URL != "" {
								go func(u, ip, evID string) {
									dCtx, cancel := context.WithTimeout(tCtx, 15*time.Second)
									defer cancel()
									_, _ = c.safeDownloader.Fetch(dCtx, u, ip, evID)
								}(dl.URL, dl.SourceIP, dl.EventUUID)
							}
						}
					}
				}
			}
		}
	}()
}

func (c *SensorController) ensureHeraldingTailer(parentCtx context.Context, deploymentID string, defaultPort uint32) {
	c.tailersMu.Lock()
	if cancel, ok := c.tailers[deploymentID]; ok {
		cancel()
	}
	tCtx, cancel := context.WithCancel(parentCtx)
	c.tailers[deploymentID] = cancel
	c.tailersMu.Unlock()

	baseDir := filepath.Join(c.stateDir, "traps", deploymentID)
	authTailer := orchestrator.OpenLogTailer(filepath.Join(baseDir, "heralding", "auth.csv"), filepath.Join(baseDir, "heralding.auth.bookmark.json"))
	sessTailer := orchestrator.OpenLogTailer(filepath.Join(baseDir, "heralding", "log_session.json"), filepath.Join(baseDir, "heralding.session.bookmark.json"))
	parser := heraldingparser.NewParser(c.nodeID, defaultPort)

	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-tCtx.Done():
				return
			case <-ticker.C:
				if lines, err := authTailer.ReadNewLines(); err == nil {
					for _, ln := range lines {
						if ev, err := parser.ParseAuthCSVLine(ln); err == nil && ev != nil {
							_ = c.sp.EnqueueEvent(ev)
						}
					}
				}
				if lines, err := sessTailer.ReadNewLines(); err == nil {
					for _, ln := range lines {
						if ev, err := parser.ParseSessionJSONLine(ln); err == nil && ev != nil {
							_ = c.sp.EnqueueEvent(ev)
						}
					}
				}
			}
		}
	}()
}

func (c *SensorController) stopTailer(deploymentID string) {
	c.tailersMu.Lock()
	defer c.tailersMu.Unlock()
	if cancel, ok := c.tailers[deploymentID]; ok {
		cancel()
		delete(c.tailers, deploymentID)
	}
}

func (c *SensorController) rotateCert(ctx context.Context, client honeypotv1.SensorControlServiceClient) error {
	keyPEM, csrPEM, err := pki.GenerateClientKeyAndCSR(fmt.Sprintf("sensor-%s", c.nodeID))
	if err != nil {
		return err
	}
	if err := c.certStore.StageNextKey(keyPEM); err != nil {
		return err
	}
	resp, err := client.RenewNodeCert(ctx, &honeypotv1.RenewNodeCertRequest{CsrPem: csrPEM})
	if err != nil {
		return err
	}
	return c.certStore.CommitRotation(resp.GetClientCertPem())
}
