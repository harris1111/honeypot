package main

import (
	"context"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	var (
		listenAddr      = flag.String("listen", envOr("DOCKER_GUARD_LISTEN", envOr("GUARD_LISTEN_ADDR", "127.0.0.1:23750")), "Listen address (loopback or unix socket only)")
		dockerSock      = flag.String("docker-sock", envOr("DOCKER_SOCK_PATH", envOr("GUARD_DOCKER_SOCKET", "/var/run/docker.sock")), "Upstream Docker Engine Unix socket")
		allowedBindRoot = flag.String("allowed-bind-root", envOr("DOCKER_ALLOWED_BIND_ROOT", envOr("GUARD_ALLOWED_BIND_ROOT", "/var/lib/honeypot-sensor/traps")), "Allowed host path prefix for container binds")
	)
	flag.Parse()

	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", *dockerSock)
		},
	}

	handler := NewGuardHandler(transport, PolicyConfig{AllowedBindRoot: *allowedBindRoot})
	srv := &http.Server{
		Addr:              *listenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		log.Printf("docker-guard-proxy listening on %s -> %s (bindRoot=%s)", *listenAddr, *dockerSock, *allowedBindRoot)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("docker-guard-proxy failed: %v", err)
		}
	}()

	<-ctx.Done()
	sCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(sCtx)
}

func envOr(k, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return fallback
}
