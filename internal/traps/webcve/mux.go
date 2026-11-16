package webcve

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Mux routes incoming :80/:443 requests across ACME challenges (outer wrapper),
// Cross-cutting Log4Shell JNDI detection, Git Canary lure, AI Gateway delegation (Phase 4),
// Host/Heuristic Personas (nextjs-modern, php-legacy-cms, java-spring), and 13 YAML CVE packs.
type Mux struct {
	engine     *Engine
	gitLure    *GitLure
	llmHandler http.Handler
	hostMap    map[string]string // optional domain -> persona override
}

// NewMux constructs the Dual-Mode Chameleon Web Multiplexer.
func NewMux(engine *Engine, gitLure *GitLure, llmHandler http.Handler, hostMap map[string]string) *Mux {
	return &Mux{
		engine:     engine,
		gitLure:    gitLure,
		llmHandler: llmHandler,
		hostMap:    hostMap,
	}
}

// SetLLMHandler attaches or replaces the Phase 4 Chameleon LLM & AI-KEV handler.
func (m *Mux) SetLLMHandler(h http.Handler) {
	m.llmHandler = h
}

func (m *Mux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rawURI := rawURIOf(r)

	// Read body bounded up to 2 MiB (covers 1 MiB RSC Flight and 2 MiB Brotli Node2Shell)
	// and restore r.Body so downstream Smart Git HTTP / Phase 4 LLM handlers can read it intact.
	var body []byte
	if r.Body != nil {
		body, _ = io.ReadAll(io.LimitReader(r.Body, maxBrotliBodyBytes))
		r.Body = io.NopCloser(bytes.NewReader(body))
	}

	// 1. Cross-cutting CVE-2021-44228 Log4Shell middleware inspection across headers, raw URI, and body
	if m.engine.IsEnabled("CVE-2021-44228") {
		jndiInputs := []string{
			rawURI,
			r.Header.Get("User-Agent"),
			r.Header.Get("X-Api-Version"),
			r.Header.Get("Referer"),
			r.Header.Get("Authorization"),
			r.Header.Get("Cookie"),
			r.Header.Get("X-Forwarded-For"),
		}
		if len(body) > 0 {
			capBody := body
			if len(capBody) > 64*1024 {
				capBody = capBody[:64*1024]
			}
			jndiInputs = append(jndiInputs, string(capBody))
		}
		if matches := ResolveJNDI(jndiInputs...); len(matches) > 0 {
			spec := m.engine.byID["CVE-2021-44228"]
			m.engine.emit(r, spec, "CVE-2021-44228", "all", true, 98, body, "", "Log4Shell JNDI lookup de-obfuscated", map[string]any{
				"jndi_matches": matches,
			}, nil, "")
		}
	}

	// 2. Real Git Canary Lure (/.git/*)
	if m.gitLure != nil && strings.HasPrefix(r.URL.Path, "/.git") {
		if m.gitLure.ServeGitPath(w, r) {
			oai, _, cid := m.engine.canaryCreds()
			m.engine.emit(r, nil, "CANARY-GIT-LURE", "nextjs-modern", false, 60, nil, "", "Served exposed .git Canary repository path: "+r.URL.Path, map[string]any{
				"git_path":         r.URL.Path,
				"seeded_oai_prefix": oai[:minInt(16, len(oai))],
			}, nil, cid)
			return
		}
	}

	// 3. AI Infrastructure & LLM Deception Gateway routes (Phase 4)
	if m.llmHandler != nil && isAIInfraPath(r.URL.Path) {
		m.llmHandler.ServeHTTP(w, r)
		return
	}

	// 4. Determine Persona (explicit hostname mapping or raw-IP heuristic)
	persona := m.resolvePersona(r, rawURI)

	// 5. Try matching declarative CVE packs deterministically in priority order
	for _, spec := range m.engine.ordered {
		if spec.Handler == "log4shell_jndi" {
			continue // already processed globally above
		}
		if m.engine.tryHandlePack(w, r, spec, rawURI, body, persona) {
			return
		}
	}

	// 6. Direct /.env probe returning seeded Canary keys
	if strings.HasPrefix(r.URL.Path, "/.env") {
		oai, ant, cid := m.engine.canaryCreds()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "NODE_ENV=production\nOPENAI_BASE_URL=%s/v1\nOPENAI_API_KEY=%s\nANTHROPIC_API_KEY=%s\n", m.engine.aiGatewayURL, oai, ant)
		m.engine.emit(r, nil, "CANARY-ENV-PROBE", persona, false, 70, body, "", "Exposed .env Canary probe served", map[string]any{"path": r.URL.Path}, nil, cid)
		return
	}

	// 7. Catch unknown probes carrying suspicious framework headers so zero new exploits go unnoticed
	if isSuspiciousFrameworkProbe(r, rawURI) {
		m.engine.emit(r, nil, "unknown_probe", persona, false, 45, body, "", "Unknown suspicious framework probe captured", map[string]any{
			"raw_uri": rawURI,
		}, ExtractHTTPURLs(string(body)), "")
	}

	// 8. Default realistic landing response based on resolved Persona
	m.serveDefaultPersona(w, persona)
}

func (m *Mux) resolvePersona(r *http.Request, rawURI string) string {
	if m.hostMap != nil {
		host := strings.ToLower(strings.Split(r.Host, ":")[0])
		if p, ok := m.hostMap[host]; ok {
			return p
		}
	}
	lower := strings.ToLower(rawURI)
	switch {
	case strings.Contains(lower, ".php") || strings.Contains(lower, "%ad") || strings.Contains(lower, "_ignition") || strings.Contains(lower, "wp-") || strings.Contains(lower, "xmlrpc") || strings.Contains(lower, "cgi-bin"):
		return "php-legacy-cms"
	case strings.HasPrefix(lower, "/actuator"):
		return "java-spring"
	default:
		return "nextjs-modern"
	}
}

func (m *Mux) serveDefaultPersona(w http.ResponseWriter, persona string) {
	switch persona {
	case "php-legacy-cms":
		w.Header().Set("Server", "Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.2.18")
		w.Header().Set("X-Powered-By", "PHP/8.2.18")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>Apache/2.4.58 (Win64) PHP/8.2.18 Server</p></body></html>"))
	case "java-spring":
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"timestamp":"2026-11-16T09:00:00.000+00:00","status":404,"error":"Not Found","path":"/"}`))
	default:
		w.Header().Set("X-Powered-By", "Next.js")
		w.Header().Set("Vary", "RSC, Next-Router-State-Tree, Next-Router-Prefetch")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Internal Portal</title></head><body><div id="__next">App Portal</div><script id="__NEXT_DATA__" type="application/json">{"buildId":"b4f9c21","runtimeConfig":{"nextVersion":"14.2.15"}}</script><script>self.__next_f=self.__next_f||[];self.__next_f.push([1,"0:[]"])</script></body></html>`))
	}
}

func isAIInfraPath(p string) bool {
	prefixes := []string{
		"/v1/", "/ollama/", "/api/tags", "/api/pull", "/api/show",
		"/api/chat", "/api/generate", "/api/create", "/api/push",
		"/api/v1/validate/code", "/api/v1/files/", "/api/version", "/api/cluster_status",
		"/api/jobs", "/api/job_agent/jobs", "/key/generate", "/user/new", "/model/new",
		"/config/update", "/api/v1/configs", "/api/v1/auths/signin", "/ui",
	}
	for _, pref := range prefixes {
		if p == pref || strings.HasPrefix(p, pref) {
			return true
		}
	}
	return false
}

func isSuspiciousFrameworkProbe(r *http.Request, rawURI string) bool {
	if strings.Contains(strings.ToLower(rawURI), "%ad") {
		return true
	}
	for k := range r.Header {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "x-middleware") || lk == "next-action" || lk == "rsc" {
			return true
		}
	}
	return false
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
