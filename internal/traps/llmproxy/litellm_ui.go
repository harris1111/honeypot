package llmproxy

import "net/http"

func (rt *Router) handleLiteLLMUI(w http.ResponseWriter, r *http.Request) {
	rt.recordEndpointProbe(r, "litellm:ui", "LITELLM-UI-PROBE", "Served LiteLLM gateway landing page", "", "")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`<!DOCTYPE html><html><head><title>LiteLLM Enterprise AI Gateway v1.52</title></head><body>
<h1>LiteLLM Internal Model Router</h1>
<p>Unified OpenAI + Anthropic + Local Inference Gateway</p>
<ul><li>OpenAI: /v1/chat/completions</li><li>Anthropic: /v1/messages</li><li>Health: /v1/models</li></ul>
</body></html>`))
}
