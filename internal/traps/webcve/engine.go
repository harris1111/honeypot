package webcve

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"google.golang.org/protobuf/types/known/timestamppb"
	"gopkg.in/yaml.v3"

	"github.com/harris/honeypot/internal/canary"
	"github.com/harris/honeypot/internal/netwrap"
	"github.com/harris/honeypot/internal/orchestrator"
	"github.com/harris/honeypot/internal/traps/webcve/packs"
	honeypotv1 "github.com/harris/honeypot/proto/gen/honeypot/v1"
)

const (
	maxInlinePayloadBytes = 32 * 1024
	maxBrotliBodyBytes    = 2 * 1024 * 1024
)

var (
	oastHostRe = regexp.MustCompile(`(?i)\b([a-z0-9-]+\.)*(oast\.|interact\.sh|burpcollaborator\.net|dnslog\.cn|canarytokens\.com|requestbin)`)
	spelCmdRe  = regexp.MustCompile(`(?is)(?:getRuntime\(\)\.exec|ProcessBuilder)\s*\(\s*['"]([^'"]+)['"]`)
	xmlValRe   = regexp.MustCompile(`(?is)<value>\s*<string>(.*?)</string>\s*</value>`)
)

// PackSpec defines a YAML-loaded exploit detection rule and metadata.
type PackSpec struct {
	ID             string            `yaml:"id" json:"id"`
	Aliases        []string          `yaml:"aliases" json:"aliases"`
	Persona        string            `yaml:"persona" json:"persona"`
	IsKEV          bool              `yaml:"is_kev" json:"is_kev"`
	Severity       int32             `yaml:"severity" json:"severity"`
	Title          string            `yaml:"title" json:"title"`
	Methods        []string          `yaml:"methods" json:"methods"`
	RawURIRegex    string            `yaml:"raw_uri_regex" json:"raw_uri_regex"`
	HeaderRegex    map[string]string `yaml:"header_regex" json:"header_regex"`
	AnyHeaderKeys  []string          `yaml:"any_header_keys" json:"any_header_keys"`
	BodyRegex      string            `yaml:"body_regex" json:"body_regex"`
	Handler        string            `yaml:"handler" json:"handler"`
	CanaryLure     bool              `yaml:"canary_lure" json:"canary_lure"`
	QuarantineBody bool              `yaml:"quarantine_body" json:"quarantine_body"`
	Enabled        bool              `json:"enabled"`

	uriRe  *regexp.Regexp
	hdrRes map[string]*regexp.Regexp
	bodyRe *regexp.Regexp
}

// EventCallback receives emitted TelemetryEvents and extracted attacker download URLs.
type EventCallback func(ev *honeypotv1.TelemetryEvent, extractedURLs []string)

// Engine evaluates YAML exploit packs deterministically and safely with per-CVE runtime toggles.
type Engine struct {
	mu           sync.RWMutex
	nodeID       string
	aiGatewayURL string
	keyPool      *canary.SensorKeyPool
	artifactSink orchestrator.ArtifactSink
	onEvent      EventCallback

	ordered []*PackSpec
	byID    map[string]*PackSpec
	honeyfs map[string]string
}

// NewEngine loads all 13 embedded YAML packs and initializes virtual honeyfs content.
func NewEngine(nodeID, aiGatewayURL string, pool *canary.SensorKeyPool, sink orchestrator.ArtifactSink, cb EventCallback) (*Engine, error) {
	if aiGatewayURL == "" {
		aiGatewayURL = "https://ai-proxy.internal-gw.local"
	}
	e := &Engine{
		nodeID:       nodeID,
		aiGatewayURL: strings.TrimRight(aiGatewayURL, "/"),
		keyPool:      pool,
		artifactSink: sink,
		onEvent:      cb,
		byID:         make(map[string]*PackSpec),
	}

	entries, err := packs.FS.ReadDir(".")
	if err != nil {
		return nil, fmt.Errorf("read embedded packs: %w", err)
	}
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".yaml") {
			continue
		}
		raw, err := packs.FS.ReadFile(ent.Name())
		if err != nil {
			return nil, err
		}
		var spec PackSpec
		if err := yaml.Unmarshal(raw, &spec); err != nil {
			return nil, fmt.Errorf("parse pack %s: %w", ent.Name(), err)
		}
		if spec.RawURIRegex != "" {
			spec.uriRe, err = regexp.Compile(spec.RawURIRegex)
			if err != nil {
				return nil, fmt.Errorf("compile uri regex %s: %w", ent.Name(), err)
			}
		}
		if spec.BodyRegex != "" {
			spec.bodyRe, err = regexp.Compile(spec.BodyRegex)
			if err != nil {
				return nil, fmt.Errorf("compile body regex %s: %w", ent.Name(), err)
			}
		}
		if len(spec.HeaderRegex) > 0 {
			spec.hdrRes = make(map[string]*regexp.Regexp, len(spec.HeaderRegex))
			for k, pat := range spec.HeaderRegex {
				re, err := regexp.Compile(pat)
				if err != nil {
					return nil, fmt.Errorf("compile header regex %s.%s: %w", ent.Name(), k, err)
				}
				spec.hdrRes[strings.ToLower(k)] = re
			}
		}
		if !containsString(handlerOrder, spec.Handler) {
			// keep deterministic priority below
		}
		spec.Enabled = true
		e.ordered = append(e.ordered, &spec)
		e.byID[spec.ID] = &spec
		for _, alias := range spec.Aliases {
			e.byID[alias] = &spec
		}
	}

	sortPacksByPriority(e.ordered)
	e.refreshHoneyfs()
	return e, nil
}

var handlerOrder = []string{
	"react2shell_flight",
	"nextjs_ssrf",
	"vite_fs_read",
	"node2shell_brotli",
	"nextjs_middleware_bypass",
	"php_cgi_arg_inject",
	"wordpress_multi",
	"phpunit_eval",
	"laravel_ignition",
	"apache_cgi_traversal",
	"php2shell_state",
	"spring_actuator",
	"log4shell_jndi",
}

func sortPacksByPriority(list []*PackSpec) {
	rank := make(map[string]int, len(handlerOrder))
	for i, h := range handlerOrder {
		rank[h] = i
	}
	for i := 0; i < len(list); i++ {
		for j := i + 1; j < len(list); j++ {
			if rank[list[j].Handler] < rank[list[i].Handler] {
				list[i], list[j] = list[j], list[i]
			}
		}
	}
}

func (e *Engine) refreshHoneyfs() {
	oai, ant, _ := e.canaryCreds()
	e.honeyfs = map[string]string{
		"/etc/passwd": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n",
		"/app/.env":   fmt.Sprintf("NODE_ENV=production\nOPENAI_BASE_URL=%s/v1\nOPENAI_API_KEY=%s\nANTHROPIC_API_KEY=%s\n", e.aiGatewayURL, oai, ant),
		"/.env":       fmt.Sprintf("APP_ENV=production\nOPENAI_BASE_URL=%s/v1\nOPENAI_API_KEY=%s\nANTHROPIC_API_KEY=%s\n", e.aiGatewayURL, oai, ant),
	}
}

// TogglePack enables or disables a CVE pack or any of its aliases at runtime.
func (e *Engine) TogglePack(cveID string, enabled bool) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	sp, ok := e.byID[cveID]
	if !ok {
		return false
	}
	sp.Enabled = enabled
	return true
}

// IsEnabled checks if a CVE pack is currently enabled.
func (e *Engine) IsEnabled(cveID string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	sp, ok := e.byID[cveID]
	return ok && sp.Enabled
}

// ListPacks returns a snapshot of all loaded Web CVE packs and their enabled status.
func (e *Engine) ListPacks() []PackSpec {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]PackSpec, 0, len(e.ordered))
	for _, p := range e.ordered {
		out = append(out, *p)
	}
	return out
}

func (e *Engine) canaryCreds() (openaiKey, anthropicKey, canaryID string) {
	openaiKey = "sk-proj-webcanary00000000000000000000000000000"
	anthropicKey = "sk-ant-api03-webcanary0000-0000000000000000-000000000000"
	if e.keyPool != nil {
		if s, ok := e.keyPool.PeekBySource("", "openai"); ok {
			openaiKey = s.GetKeyPlaintext()
			canaryID = s.GetCanaryKeyId()
		}
		if s, ok := e.keyPool.PeekBySource("", "anthropic"); ok {
			anthropicKey = s.GetKeyPlaintext()
			if canaryID == "" {
				canaryID = s.GetCanaryKeyId()
			}
		}
	}
	return
}

func (e *Engine) emit(r *http.Request, spec *PackSpec, cveOverride, personaOverride string, kev bool, score int32, rawBody []byte, artSHA string, summary string, iocs map[string]any, urls []string, canaryID string) {
	if e.onEvent == nil {
		return
	}
	payloadStr := string(rawBody)
	if len(payloadStr) > maxInlinePayloadBytes {
		payloadStr = payloadStr[:maxInlinePayloadBytes]
	}
	if payloadStr == "" {
		payloadStr = r.Method + " " + rawURIOf(r)
	}
	iocBytes, _ := json.Marshal(iocs)

	cveID := cveOverride
	if cveID == "" && spec != nil {
		cveID = spec.ID
	}
	persona := personaOverride
	if persona == "" && spec != nil {
		persona = spec.Persona
	}
	srcIP, srcPort := splitHostPort(r.RemoteAddr)
	if hdrIP := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-For"), ",")[0]); hdrIP != "" && srcIP == "" {
		srcIP = hdrIP
	}

	ev := &honeypotv1.TelemetryEvent{
		EventUuid:         newWebUUID(),
		NodeId:            e.nodeID,
		SourceIp:          srcIP,
		SourcePort:        srcPort,
		DestPort:          listenPortFromReq(r),
		Protocol:          schemeProtocol(r),
		TrapKind:          "webcve",
		Persona:           persona,
		CveId:             cveID,
		IsKev:             kev,
		Ja4:               netwrap.JA4FromContext(r.Context()),
		Ja4H:              netwrap.ComputeJA4H(r),
		HttpMethod:        r.Method,
		HttpHost:          r.Host,
		HttpPath:          rawURIOf(r),
		RawPayload:        payloadStr,
		ArtifactSha256:    artSHA,
		ResponseSummary:   summary,
		ExtractedIocsJson: string(iocBytes),
		CanaryKeyId:       canaryID,
		SeverityScore:     score,
		ObservedAt:        timestamppb.Now(),
	}
	e.onEvent(ev, urls)
}

func (e *Engine) quarantineBytes(ctx context.Context, r *http.Request, data []byte, mimeType string) string {
	if e.artifactSink == nil || len(data) == 0 {
		return ""
	}
	sha, err := e.artifactSink.Submit(ctx, orchestrator.ArtifactMeta{
		NodeID:   e.nodeID,
		MimeType: mimeType,
	}, data)
	if err != nil {
		return ""
	}
	_ = r
	return sha
}

func rawURIOf(r *http.Request) string {
	if r.RequestURI != "" {
		return r.RequestURI
	}
	return r.URL.RequestURI()
}

func (e *Engine) tryHandlePack(w http.ResponseWriter, r *http.Request, spec *PackSpec, rawURI string, body []byte, persona string) bool {
	if spec == nil || !spec.Enabled {
		return false
	}
	oai, ant, cid := e.canaryCreds()

	switch spec.Handler {
	case "nextjs_middleware_bypass":
		subreq := r.Header.Get("X-Middleware-Subrequest")
		if re := spec.hdrRes["x-middleware-subrequest"]; re != nil && re.MatchString(subreq) {
			w.Header().Set("X-Powered-By", "Next.js")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":            "authenticated",
				"user":              "admin@internal.corp",
				"openai_base_url":   e.aiGatewayURL + "/v1",
				"openai_api_key":    oai,
				"anthropic_api_key": ant,
			})
			e.emit(r, spec, spec.ID, "nextjs-modern", spec.IsKEV, spec.Severity, body, "", "Next.js middleware bypass succeeded", map[string]any{
				"x_middleware_subrequest": subreq,
			}, nil, cid)
			return true
		}
		// Missing bypass header -> realistic Next.js middleware redirect to /login (unless carrying Next-Action/RSC)
		if spec.uriRe != nil && spec.uriRe.MatchString(rawURI) && r.Header.Get("Next-Action") == "" && r.Header.Get("RSC") == "" {
			w.Header().Set("X-Powered-By", "Next.js")
			w.Header().Set("x-middleware-rewrite", "/login")
			http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
			return true
		}
		return false

	case "react2shell_flight":
		isNextAction := r.Header.Get("Next-Action") != "" || r.Header.Get("RSC") == "1" || strings.Contains(strings.ToLower(r.Header.Get("Content-Type")), "text/x-component")
		if res, ok := DecodeRSCFlight(body, isNextAction, oai); ok && (len(res.Commands) > 0 || res.IsDoSPattern || strings.Contains(res.NormalizedText, "$@") || strings.Contains(strings.ToLower(res.NormalizedText), "process.")) {
			kev := true
			w.Header().Set("X-Powered-By", "Next.js")
			w.Header().Set("Content-Type", "text/x-component; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(res.ResponseFrame))
			e.emit(r, spec, res.MatchedCVE, "nextjs-modern", kev, 98, []byte(res.NormalizedText), "", "RSC Flight exploit decoded", map[string]any{
				"was_utf16le": res.WasUTF16LE,
				"commands":    res.Commands,
				"urls":        res.ExtractedURLs,
				"is_dos":      res.IsDoSPattern,
			}, res.ExtractedURLs, cid)
			return true
		}
		return false

	case "nextjs_ssrf":
		fwdHost := strings.TrimSpace(r.Header.Get("X-Forwarded-Host"))
		hostDiffers := fwdHost != "" && !strings.EqualFold(fwdHost, r.Host)
		imgURL := ""
		if strings.HasPrefix(rawURI, "/_next/image") {
			if parsed, err := url.Parse(rawURI); err == nil {
				imgURL = parsed.Query().Get("url")
			}
		}
		isOAST := oastHostRe.MatchString(fwdHost) || oastHostRe.MatchString(r.Host) || oastHostRe.MatchString(imgURL)
		if (r.Header.Get("Next-Action") != "" && (hostDiffers || isOAST)) || (imgURL != "" && (strings.HasPrefix(imgURL, "http://") || strings.HasPrefix(imgURL, "https://"))) {
			target := fwdHost
			if target == "" {
				target = imgURL
			}
			w.Header().Set("X-Powered-By", "Next.js")
			w.Header().Set("Location", "/")
			w.WriteHeader(http.StatusSeeOther)
			e.emit(r, spec, spec.ID, "nextjs-modern", spec.IsKEV, spec.Severity, body, "", "Next.js SSRF probe recorded (no dial-out)", map[string]any{
				"ssrf_target":     target,
				"x_forwarded_host": fwdHost,
				"next_image_url":  imgURL,
			}, ExtractHTTPURLs(target), "")
			return true
		}
		return false

	case "vite_fs_read":
		if spec.uriRe == nil || !spec.uriRe.MatchString(rawURI) {
			return false
		}
		cleanPath := strings.SplitN(rawURI, "?", 2)[0]
		fsTarget := strings.TrimPrefix(cleanPath, "/@fs")
		fsTarget = strings.TrimPrefix(fsTarget, "/@id")
		if i := strings.Index(fsTarget, "/etc/passwd"); i >= 0 {
			fsTarget = "/etc/passwd"
		} else if i := strings.Index(fsTarget, ".env"); i >= 0 {
			fsTarget = "/app/.env"
		}
		content, ok := e.honeyfs[fsTarget]
		if !ok {
			content = e.honeyfs["/app/.env"]
		}
		jsLit, _ := json.Marshal(content)
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "export default %s;\n", string(jsLit))
		e.emit(r, spec, spec.ID, "nextjs-modern", spec.IsKEV, spec.Severity, []byte(rawURI), "", "Served virtual honeyfs via Vite @fs lure", map[string]any{
			"requested_fs_path": fsTarget,
		}, nil, cid)
		return true

	case "node2shell_brotli":
		if re := spec.hdrRes["content-encoding"]; re == nil || !re.MatchString(r.Header.Get("Content-Encoding")) {
			return false
		}
		sha := e.quarantineBytes(r.Context(), r, body, "application/x-brotli-probe")
		w.Header().Set("X-Powered-By", "Express")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"ERR_BROTLI_INVALID_PARAM","code":"ERR_BROTLI_INVALID_PARAM"}`))
		e.emit(r, spec, spec.ID, "nextjs-modern", spec.IsKEV, spec.Severity, body, sha, "Node.js Brotli probe quarantined", map[string]any{
			"content_encoding": r.Header.Get("Content-Encoding"),
			"byte_len":         len(body),
		}, ExtractHTTPURLs(string(body)), "")
		return true

	case "php_cgi_arg_inject":
		if spec.uriRe == nil || !spec.uriRe.MatchString(rawURI) {
			return false
		}
		evalRes := EvalPHPSnippet(string(body), true, oai, ant, e.aiGatewayURL)
		w.Header().Set("Server", "Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.2.18")
		w.Header().Set("X-Powered-By", "PHP/8.2.18")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(evalRes.Output))
		e.emit(r, spec, spec.ID, "php-legacy-cms", spec.IsKEV, spec.Severity, body, "", "PHP-CGI %AD argument injection emulated", map[string]any{
			"commands": evalRes.ExecutedCommands,
			"urls":     evalRes.ExtractedURLs,
		}, evalRes.ExtractedURLs, cid)
		return true

	case "php2shell_state":
		if spec.uriRe == nil || !spec.uriRe.MatchString(rawURI) {
			return false
		}
		if spec.bodyRe != nil && !spec.bodyRe.Match(body) && !strings.Contains(strings.ToLower(r.Header.Get("Cookie")), "phpsessid=") {
			return false
		}
		sha := e.quarantineBytes(r.Context(), r, body, "application/octet-stream")
		evalRes := EvalPHPSnippet(string(body), false, oai, ant, e.aiGatewayURL)
		w.Header().Set("X-Powered-By", "PHP/8.3.4")
		w.WriteHeader(http.StatusOK)
		if evalRes.Output != "" {
			_, _ = w.Write([]byte(evalRes.Output))
		} else {
			_, _ = w.Write([]byte("Notice: Unknown: POST Content-Length state validation warning in Unknown on line 0\n"))
		}
		e.emit(r, spec, spec.ID, "php-legacy-cms", spec.IsKEV, spec.Severity, body, sha, "php2shell pre-boot SAPI state probe captured", map[string]any{
			"commands": evalRes.ExecutedCommands,
			"urls":     evalRes.ExtractedURLs,
		}, evalRes.ExtractedURLs, "")
		return true

	case "laravel_ignition":
		if spec.uriRe == nil || !spec.uriRe.MatchString(rawURI) {
			return false
		}
		w.Header().Set("X-Powered-By", "PHP/8.1.27")
		if strings.Contains(strings.ToLower(rawURI), "execute-solution") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		} else {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = fmt.Fprintf(w, "<html><title>Ignition Debug</title><body><pre>APP_ENV=production\nAPP_DEBUG=true\nOPENAI_BASE_URL=%s/v1\nOPENAI_API_KEY=%s\nANTHROPIC_API_KEY=%s\n</pre></body></html>", e.aiGatewayURL, oai, ant)
		}
		e.emit(r, spec, spec.ID, "php-legacy-cms", spec.IsKEV, spec.Severity, body, "", "Laravel Ignition probe captured", map[string]any{
			"raw_uri": rawURI,
			"urls":    ExtractHTTPURLs(string(body)),
		}, ExtractHTTPURLs(string(body)), cid)
		return true

	case "phpunit_eval":
		if spec.uriRe == nil || !spec.uriRe.MatchString(rawURI) {
			return false
		}
		evalRes := EvalPHPSnippet(string(body), false, oai, ant, e.aiGatewayURL)
		w.Header().Set("X-Powered-By", "PHP/7.4.33")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(evalRes.Output))
		e.emit(r, spec, spec.ID, "php-legacy-cms", spec.IsKEV, spec.Severity, body, "", "PHPUnit eval-stdin RCE emulated", map[string]any{
			"commands": evalRes.ExecutedCommands,
			"urls":     evalRes.ExtractedURLs,
		}, evalRes.ExtractedURLs, cid)
		return true

	case "apache_cgi_traversal":
		if spec.uriRe == nil || !spec.uriRe.MatchString(rawURI) {
			return false
		}
		w.Header().Set("Server", "Apache/2.4.49 (Unix)")
		lower := strings.ToLower(rawURI)
		if r.Method == http.MethodPost && strings.Contains(lower, "/bin/sh") {
			cmd := strings.TrimSpace(strings.TrimPrefix(string(body), "echo Content-Type: text/plain; echo;"))
			if cmd == "" {
				cmd = string(body)
			}
			out := SimulateShellCommand(cmd, false)
			if out == "" {
				out = "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n"
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(out))
			urls := ExtractHTTPURLs(string(body))
			e.emit(r, spec, "CVE-2021-42013", "php-legacy-cms", true, spec.Severity, body, "", "Apache CGI RCE traversal captured", map[string]any{
				"command": cmd,
				"urls":    urls,
			}, urls, "")
			return true
		}
		target := "/etc/passwd"
		if strings.Contains(lower, ".env") {
			target = "/app/.env"
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(e.honeyfs[target]))
		e.emit(r, spec, spec.ID, "php-legacy-cms", true, spec.Severity, []byte(rawURI), "", "Apache path traversal read served", map[string]any{
			"target": target,
		}, nil, cid)
		return true

	case "wordpress_multi":
		if spec.uriRe == nil || !spec.uriRe.MatchString(rawURI) {
			return false
		}
		lower := strings.ToLower(rawURI)
		var artSHA string
		urls := ExtractHTTPURLs(string(body))
		if strings.Contains(lower, "wp-file-manager") {
			filename, fileBytes := extractMultipartUpload(r.Header.Get("Content-Type"), body)
			if len(fileBytes) > 0 {
				artSHA = e.quarantineBytes(r.Context(), r, fileBytes, "application/x-php")
			} else {
				artSHA = e.quarantineBytes(r.Context(), r, body, "application/x-php")
			}
			if filename == "" {
				filename = "shell.php"
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"added": []map[string]any{
					{"hash": "l1_dHJhcA", "name": filepath.Base(filename), "mime": "text/x-php", "size": len(fileBytes)},
				},
			})
			e.emit(r, spec, "CVE-2020-25213", "php-legacy-cms", true, 95, body, artSHA, "WP File Manager webshell upload quarantined", map[string]any{
				"filename": filepath.Base(filename),
			}, urls, "")
			return true
		}
		if strings.Contains(lower, "xmlrpc.php") {
			vals := xmlValRe.FindAllStringSubmatch(string(body), 16)
			creds := make([]string, 0, len(vals))
			for _, m := range vals {
				creds = append(creds, m[1])
			}
			w.Header().Set("Content-Type", "text/xml; charset=UTF-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><methodResponse><params><param><value><array><data></data></array></value></param></params></methodResponse>`))
			e.emit(r, spec, spec.ID, "php-legacy-cms", true, 75, body, "", "WordPress XML-RPC brute/pingback logged", map[string]any{
				"xmlrpc_values": creds,
				"urls":          urls,
			}, urls, "")
			return true
		}
		// upgrade-temp-backup staging TOCTOU probe
		if len(body) > 0 {
			artSHA = e.quarantineBytes(r.Context(), r, body, "application/octet-stream")
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"staged"}`))
		e.emit(r, spec, "CVE-2026-119977", "php-legacy-cms", true, spec.Severity, body, artSHA, "WordPress upgrade-temp-backup probe captured", map[string]any{
			"raw_uri": rawURI,
		}, urls, "")
		return true

	case "spring_actuator":
		if spec.uriRe == nil || !spec.uriRe.MatchString(rawURI) {
			return false
		}
		w.Header().Set("Content-Type", "application/json")
		lower := strings.ToLower(rawURI)
		if strings.Contains(lower, "/actuator/env") {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"activeProfiles": []string{"production"},
				"propertySources": []map[string]any{
					{
						"name": "applicationConfig: [classpath:/application-prod.yml]",
						"properties": map[string]any{
							"spring.ai.openai.base-url":    map[string]any{"value": e.aiGatewayURL + "/v1"},
							"spring.ai.openai.api-key":     map[string]any{"value": oai},
							"spring.ai.anthropic.api-key":  map[string]any{"value": ant},
						},
					},
				},
			})
			e.emit(r, spec, spec.ID, "java-spring", true, 85, body, "", "Spring Actuator /env canary credentials served", map[string]any{"uri": rawURI}, nil, cid)
			return true
		}
		var cmds []string
		for _, m := range spelCmdRe.FindAllStringSubmatch(string(body), 8) {
			cmds = append(cmds, m[1])
		}
		urls := ExtractHTTPURLs(string(body))
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"status":"Route created"}`))
		e.emit(r, spec, spec.ID, "java-spring", true, spec.Severity, body, "", "Spring Cloud Gateway SpEL route RCE captured", map[string]any{
			"commands": cmds,
			"urls":     urls,
		}, urls, "")
		return true
	}

	_ = persona
	return false
}

func extractMultipartUpload(contentType string, body []byte) (string, []byte) {
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil || !strings.HasPrefix(strings.ToLower(mediaType), "multipart/") {
		return "", nil
	}
	boundary := params["boundary"]
	if boundary == "" {
		return "", nil
	}
	mr := multipart.NewReader(bytes.NewReader(body), boundary)
	for {
		p, err := mr.NextPart()
		if err != nil {
			break
		}
		fn := p.FileName()
		if fn != "" {
			data, _ := io.ReadAll(io.LimitReader(p, maxBrotliBodyBytes))
			return fn, data
		}
	}
	return "", nil
}

func splitHostPort(addr string) (string, uint32) {
	host := addr
	if i := strings.LastIndex(addr, ":"); i > 0 && !strings.Contains(addr[i:], "]") {
		host = addr[:i]
	}
	host = strings.Trim(host, "[]")
	return host, 0
}

func listenPortFromReq(r *http.Request) uint32 {
	if r.TLS != nil {
		return 443
	}
	return 80
}

func schemeProtocol(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func newWebUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
