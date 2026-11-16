package infratrap

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/harris/honeypot/internal/canary"
	"github.com/harris/honeypot/internal/netwrap"
	"github.com/harris/honeypot/internal/traps/webcve"
)

// NewKubernetesHandler builds an unauthenticated Kubernetes API (:6443) and Kubelet (:10250) trap.
func NewKubernetesHandler(nodeID, aiGatewayURL string, listenPort uint32, pool *canary.SensorKeyPool, emit EventSink) http.Handler {
	if listenPort == 0 {
		listenPort = 6443
	}
	if aiGatewayURL == "" {
		aiGatewayURL = "https://ai-proxy.internal-gw.local"
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		oaiKey := "sk-proj-k8ssecret000000000000000000000000000"
		antKey := "sk-ant-api03-k8ssecret00-0000000000000000-000000000000"
		if pool != nil {
			if s, ok := pool.PeekBySource("", "openai"); ok {
				oaiKey = s.GetKeyPlaintext()
			}
			if s, ok := pool.PeekBySource("", "anthropic"); ok {
				antKey = s.GetKeyPlaintext()
			}
		}

		p := r.URL.Path
		switch {
		case p == "/version":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"major":      "1",
				"minor":      "29",
				"gitVersion": "v1.29.4",
				"platform":   "linux/amd64",
			})
			return

		case strings.HasSuffix(p, "/secrets"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"kind":       "SecretList",
				"apiVersion": "v1",
				"items": []map[string]any{
					{
						"metadata": map[string]any{"name": "ai-gateway-credentials", "namespace": "default"},
						"type":     "Opaque",
						"data": map[string]string{
							"OPENAI_BASE_URL":   base64.StdEncoding.EncodeToString([]byte(strings.TrimRight(aiGatewayURL, "/") + "/v1")),
							"OPENAI_API_KEY":    base64.StdEncoding.EncodeToString([]byte(oaiKey)),
							"ANTHROPIC_API_KEY": base64.StdEncoding.EncodeToString([]byte(antKey)),
						},
					},
				},
			})
			if emit != nil {
				emit(newInfraEvent(nodeID, r.RemoteAddr, listenPort, "https", "k8s-api", "K8S-SECRET-DUMP", false, 85, p, "Unauthenticated K8s secret list dumped (canary keys served)", map[string]any{"path": p}, netwrap.JA4FromContext(r.Context()), netwrap.ComputeJA4H(r)), nil)
			}
			return

		case strings.Contains(p, "/pods"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"kind":       "PodList",
				"apiVersion": "v1",
				"items": []map[string]any{
					{"metadata": map[string]any{"name": "llm-worker-7c9f", "namespace": "default"}, "status": map[string]string{"phase": "Running"}},
				},
			})
			return

		case strings.HasPrefix(p, "/run/") || strings.HasPrefix(p, "/exec/"):
			body, _ := io.ReadAll(io.LimitReader(r.Body, 256*1024))
			cmd := r.FormValue("cmd")
			if cmd == "" {
				cmd = strings.TrimSpace(string(body))
			}
			urls := webcve.ExtractHTTPURLs(p + " " + r.URL.RawQuery + " " + cmd)
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("uid=0(root) gid=0(root) groups=0(root)\n"))
			if emit != nil {
				emit(newInfraEvent(nodeID, r.RemoteAddr, listenPort, "https", "kubelet-rce", "KUBELET-UNAUTH-RUN", false, 95, cmd, "Kubelet unauthenticated pod RCE captured", map[string]any{
					"path":    p,
					"command": cmd,
					"urls":    urls,
				}, netwrap.JA4FromContext(r.Context()), netwrap.ComputeJA4H(r)), urls)
			}
			return

		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"kind":"Status","status":"Failure","code":404}`))
		}
	})
}
