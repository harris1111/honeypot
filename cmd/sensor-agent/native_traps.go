package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/harris/honeypot/internal/canary"
	"github.com/harris/honeypot/internal/netwrap"
	"github.com/harris/honeypot/internal/orchestrator"
	"github.com/harris/honeypot/internal/spool"
	"github.com/harris/honeypot/internal/traps/infratrap"
	"github.com/harris/honeypot/internal/traps/llmproxy"
	"github.com/harris/honeypot/internal/traps/llmproxy/budget"
	"github.com/harris/honeypot/internal/traps/webcve"
	honeypotv1 "github.com/harris/honeypot/proto/gen/honeypot/v1"
	"golang.org/x/net/netutil"
)

// NativeTrapRuntime manages in-process Go deception listeners:
// Dual-Mode TLS/JA4 Web CVE multiplexer, Chameleon LLM Proxy, plus toggleable Infra Traps (:2375, :6443/:10250, :6379, :3306, :5432).
type NativeTrapRuntime struct {
	nodeID        string
	stateDir      string
	aiGatewayURL  string
	sp            *spool.BoltSpool
	keyPool       *canary.SensorKeyPool
	artifactSink  orchestrator.ArtifactSink
	webEngine     *webcve.Engine
	webMux        *webcve.Mux
	llmRouter     *llmproxy.Router
	tlsMgr        *netwrap.TLSManager
	onURLsExtract func(ctx context.Context, srcIP, eventUUID string, urls []string)

	mu        sync.Mutex
	listeners map[string]func()
}

func newNativeTrapRuntime(
	ctx context.Context,
	nodeID, stateDir, aiGatewayURL string,
	decoyDomains []string,
	acmeEmail string,
	sp *spool.BoltSpool,
	pool *canary.SensorKeyPool,
	sink orchestrator.ArtifactSink,
) (*NativeTrapRuntime, error) {
	rt := &NativeTrapRuntime{
		nodeID:       nodeID,
		stateDir:     stateDir,
		aiGatewayURL: aiGatewayURL,
		sp:           sp,
		keyPool:      pool,
		artifactSink: sink,
		listeners:    make(map[string]func()),
	}

	var oai, ant, cid string
	if pool != nil {
		if s, ok := pool.PeekBySource("git_lure", "openai"); ok {
			oai = s.GetKeyPlaintext()
			cid = s.GetCanaryKeyId()
		}
		if s, ok := pool.PeekBySource("git_lure", "anthropic"); ok {
			ant = s.GetKeyPlaintext()
		}
	}
	gitLure, err := webcve.NewGitLure(filepath.Join(stateDir, "gitlure"), aiGatewayURL, oai, ant, cid)
	if err != nil {
		log.Printf("git lure init warning: %v", err)
	}

	rt.webEngine, err = webcve.NewEngine(nodeID, aiGatewayURL, pool, sink, rt.handleTrapEvent)
	if err != nil {
		return nil, err
	}
	rt.webMux = webcve.NewMux(rt.webEngine, gitLure, nil, nil)

	tarpit := budget.NewTarpitLimiter(128, 2, 2*time.Second, 60*time.Second)
	rt.llmRouter = llmproxy.NewRouter(nodeID, aiGatewayURL, nil, pool, sp, tarpit, func(uCtx context.Context, srcIP, eventUUID string, urls []string) {
		if rt.onURLsExtract != nil {
			rt.onURLsExtract(uCtx, srcIP, eventUUID, urls)
		}
	})
	rt.webMux.SetLLMHandler(rt.llmRouter)

	rt.tlsMgr, err = netwrap.NewTLSManager(ctx, netwrap.TLSManagerConfig{
		StateDir:     stateDir,
		DecoyDomains: decoyDomains,
		ACMEEmail:    acmeEmail,
		EnableACME:   len(decoyDomains) > 0 && acmeEmail != "",
	})
	if err != nil {
		return nil, err
	}
	return rt, nil
}

func (r *NativeTrapRuntime) handleTrapEvent(ev *honeypotv1.TelemetryEvent, urls []string) {
	if r.sp != nil && ev != nil {
		_ = r.sp.EnqueueEvent(ev)
	}
	if r.onURLsExtract != nil && ev != nil && len(urls) > 0 {
		r.onURLsExtract(context.Background(), ev.GetSourceIp(), ev.GetEventUuid(), urls)
	}
}

func (r *NativeTrapRuntime) SetLLMClient(client honeypotv1.SensorControlServiceClient) {
	tarpit := budget.NewTarpitLimiter(128, 2, 2*time.Second, 60*time.Second)
	r.llmRouter = llmproxy.NewRouter(r.nodeID, r.aiGatewayURL, client, r.keyPool, r.sp, tarpit, func(uCtx context.Context, srcIP, eventUUID string, urls []string) {
		if r.onURLsExtract != nil {
			r.onURLsExtract(uCtx, srcIP, eventUUID, urls)
		}
	})
	r.webMux.SetLLMHandler(r.llmRouter)
}

func (r *NativeTrapRuntime) StartLLMProxyPort(depID string, port uint32, bindHost string) error {
	if bindHost == "" {
		bindHost = "0.0.0.0"
	}
	addr := net.JoinHostPort(bindHost, fmt.Sprintf("%d", port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler:           r.llmRouter,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      15 * time.Second,
	}
	r.registerCloser("infra-"+depID, func() { _ = srv.Close() })
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("llmproxy port %s stopped: %v", addr, err)
		}
	}()
	return nil
}

func (r *NativeTrapRuntime) ToggleCVE(cveID string, enabled bool) bool {
	return r.webEngine.TogglePack(cveID, enabled)
}

func (r *NativeTrapRuntime) SetLLMHandler(h http.Handler) {
	r.webMux.SetLLMHandler(h)
}

func (r *NativeTrapRuntime) StartWebListeners(httpAddr, httpsAddr string) error {
	handler := r.tlsMgr.HTTPChallengeHandler(r.webMux)
	if strings.TrimSpace(httpAddr) != "" {
		ln, err := net.Listen("tcp", httpAddr)
		if err != nil {
			return err
		}
		srv := &http.Server{
			Handler:           handler,
			ReadHeaderTimeout: 5 * time.Second,
			WriteTimeout:      15 * time.Second,
		}
		r.registerCloser("web-http-"+httpAddr, func() { _ = srv.Close() })
		go func() {
			if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("webcve http %s stopped: %v", httpAddr, err)
			}
		}()
	}

	if strings.TrimSpace(httpsAddr) != "" {
		rawLn, err := net.Listen("tcp", httpsAddr)
		if err != nil {
			return err
		}
		ja4Ln := netwrap.NewJA4Listener(rawLn, 2048)
		tlsLn := tls.NewListener(ja4Ln, r.tlsMgr.TLSConfig())
		srv := &http.Server{
			ConnContext:       netwrap.WithJA4ConnContext,
			Handler:           handler,
			ReadHeaderTimeout: 5 * time.Second,
			WriteTimeout:      15 * time.Second,
		}
		r.registerCloser("web-https-"+httpsAddr, func() { _ = srv.Close() })
		go func() {
			if err := srv.Serve(tlsLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("webcve https %s stopped: %v", httpsAddr, err)
			}
		}()
	}
	return nil
}

// StartInfraTrap binds an individual native Go daemon trap (docker, k8s, redis, mysql, postgres).
func (r *NativeTrapRuntime) StartInfraTrap(ctx context.Context, depID, subtype string, port uint32, bindHost string) error {
	if bindHost == "" {
		bindHost = "0.0.0.0"
	}
	addr := net.JoinHostPort(bindHost, fmt.Sprintf("%d", port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	subCtx, cancel := context.WithCancel(ctx)
	key := "infra-" + depID

	switch strings.ToLower(subtype) {
	case "docker":
		limLn := netutil.LimitListener(ln, 512)
		srv := &http.Server{
			Handler:           infratrap.NewDockerAPIHandler(r.nodeID, port, r.handleTrapEvent),
			ReadHeaderTimeout: 5 * time.Second,
			WriteTimeout:      15 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
		r.registerCloser(key, func() { cancel(); _ = srv.Close() })
		go func() { _ = srv.Serve(limLn) }()
	case "k8s", "kubelet":
		var serveLn net.Listener = netutil.LimitListener(ln, 512)
		if port == 6443 || subtype == "k8s" {
			serveLn = tls.NewListener(netwrap.NewJA4Listener(ln, 512), r.tlsMgr.TLSConfig())
		}
		srv := &http.Server{
			ConnContext:       netwrap.WithJA4ConnContext,
			Handler:           infratrap.NewKubernetesHandler(r.nodeID, r.aiGatewayURL, port, r.keyPool, r.handleTrapEvent),
			ReadHeaderTimeout: 5 * time.Second,
			WriteTimeout:      15 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
		r.registerCloser(key, func() { cancel(); _ = srv.Close() })
		go func() { _ = srv.Serve(serveLn) }()
	case "redis":
		r.registerCloser(key, func() { cancel(); _ = ln.Close() })
		go func() { _ = infratrap.ServeRedisRESP(subCtx, ln, r.nodeID, port, r.handleTrapEvent) }()
	case "mysql":
		r.registerCloser(key, func() { cancel(); _ = ln.Close() })
		go func() { _ = infratrap.ServeMySQLTrap(subCtx, ln, r.nodeID, port, r.handleTrapEvent) }()
	case "postgres":
		r.registerCloser(key, func() { cancel(); _ = ln.Close() })
		go func() { _ = infratrap.ServePostgresTrap(subCtx, ln, r.nodeID, port, r.handleTrapEvent) }()
	default:
		cancel()
		_ = ln.Close()
		return fmt.Errorf("unknown native infratrap subtype %q", subtype)
	}
	return nil
}

func (r *NativeTrapRuntime) StopTrap(depID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if stopFn, ok := r.listeners["infra-"+depID]; ok {
		stopFn()
		delete(r.listeners, "infra-"+depID)
	}
}

func (r *NativeTrapRuntime) CloseAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, fn := range r.listeners {
		fn()
		delete(r.listeners, k)
	}
}

func (r *NativeTrapRuntime) registerCloser(k string, fn func()) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if prev, ok := r.listeners[k]; ok {
		prev()
	}
	r.listeners[k] = fn
}
