package infratrap

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/harris/honeypot/internal/netwrap"
	"github.com/harris/honeypot/internal/traps/webcve"
)

// NewDockerAPIHandler builds an unauthenticated Docker Engine API :2375 trap handler.
func NewDockerAPIHandler(nodeID string, listenPort uint32, emit EventSink) http.Handler {
	if listenPort == 0 {
		listenPort = 2375
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := stripDockerVersion(r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Server", "Docker/24.0.7 (linux)")

		switch {
		case r.Method == http.MethodGet && path == "/_ping":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("OK"))
			return

		case r.Method == http.MethodGet && path == "/version":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"Version":    "24.0.7",
				"ApiVersion": "1.43",
				"Os":         "linux",
				"Arch":       "amd64",
			})
			return

		case r.Method == http.MethodGet && path == "/containers/json":
			_, _ = w.Write([]byte(`[{"Id":"f81a2c3d4e5f","Names":["/edge-api-worker"],"Image":"node:20-alpine","State":"running"}]`))
			return

		case r.Method == http.MethodPost && path == "/images/create":
			fromImage := r.URL.Query().Get("fromImage")
			_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 64*1024))
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "Downloaded newer image for " + fromImage})
			if emit != nil {
				emit(newInfraEvent(nodeID, r.RemoteAddr, listenPort, "http", "docker-api", "DOCKER-2375-PULL", false, 70, fromImage, "Docker pull attempted: "+fromImage, map[string]any{"image": fromImage}, netwrap.JA4FromContext(r.Context()), netwrap.ComputeJA4H(r)), nil)
			}
			return

		case r.Method == http.MethodPost && path == "/containers/create":
			raw, _ := io.ReadAll(io.LimitReader(r.Body, 512*1024))
			var parsed struct {
				Image      string   `json:"Image"`
				Cmd        []string `json:"Cmd"`
				Entrypoint []string `json:"Entrypoint"`
				HostConfig struct {
					Binds      []string `json:"Binds"`
					Privileged bool     `json:"Privileged"`
				} `json:"HostConfig"`
			}
			_ = json.Unmarshal(raw, &parsed)
			cid := randomContainerID()
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"Id": cid, "Warnings": []string{}})

			urls := webcve.ExtractHTTPURLs(string(raw))
			if emit != nil {
				emit(newInfraEvent(nodeID, r.RemoteAddr, listenPort, "http", "docker-api", "DOCKER-2375-CREATE", false, 95, string(raw), "Exposed Docker API host-escape container create: "+parsed.Image, map[string]any{
					"image":      parsed.Image,
					"cmd":        parsed.Cmd,
					"entrypoint": parsed.Entrypoint,
					"binds":      parsed.HostConfig.Binds,
					"privileged": parsed.HostConfig.Privileged,
					"urls":       urls,
				}, netwrap.JA4FromContext(r.Context()), netwrap.ComputeJA4H(r)), urls)
			}
			return

		case r.Method == http.MethodPost && strings.Contains(path, "/start"):
			w.WriteHeader(http.StatusNoContent)
			return

		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"page not found"}`))
		}
	})
}

func stripDockerVersion(p string) string {
	if strings.HasPrefix(p, "/v") {
		if idx := strings.Index(p[1:], "/"); idx > 0 {
			return p[1+idx:]
		}
	}
	return p
}

func randomContainerID() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
