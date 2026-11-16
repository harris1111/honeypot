package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	maxCreateBodyBytes = 1 * 1024 * 1024
	requiredNetName    = "trap_isolated_net"
)

var (
	validContainerNameRe = regexp.MustCompile(`^hp-trap-[a-z0-9][a-z0-9_.-]{1,64}$`)
	validNetworkIDRe     = regexp.MustCompile(`^/networks/[a-zA-Z0-9_.-]{1,128}$`)
	validExposedPortRe   = regexp.MustCompile(`^[0-9]{1,5}/(tcp|udp)$`)
	apiVersionPrefixRe   = regexp.MustCompile(`^/v[0-9]+\.[0-9]+`)
	allowedImages        = []string{"honeypot/cowrie", "cowrie/cowrie", "honeypot/heralding", "dtagdevsec/heralding", "johnnykv/heralding"}
	allowedEnvPrefixes   = []string{"COWRIE_", "HERALDING_", "PYTHONDONTWRITEBYTECODE=", "TZ=", "LANG=", "LC_ALL=", "PATH=", "HOME="}
	forbiddenEnvKeys     = map[string]bool{
		"LD_PRELOAD":      true,
		"LD_LIBRARY_PATH": true,
		"PYTHONPATH":      true,
		"PYTHONHOME":      true,
		"NODE_OPTIONS":    true,
		"BASH_ENV":        true,
		"ENV":             true,
		"PERL5OPT":        true,
		"RUBYOPT":         true,
	}
)

// PolicyConfig defines strict validation rules enforced by docker-guard-proxy.
type PolicyConfig struct {
	AllowedBindRoot string // e.g. "/var/lib/honeypot-sensor/traps"
}

type containerCreateBody struct {
	Image        string              `json:"Image"`
	User         string              `json:"User"`
	Env          []string            `json:"Env,omitempty"`
	Cmd          []string            `json:"Cmd,omitempty"`
	ExposedPorts map[string]struct{} `json:"ExposedPorts,omitempty"`
	HostConfig   struct {
		Binds          []string                       `json:"Binds,omitempty"`
		Mounts         []json.RawMessage              `json:"Mounts,omitempty"`
		NetworkMode    string                         `json:"NetworkMode"`
		Privileged     bool                           `json:"Privileged"`
		PidMode        string                         `json:"PidMode,omitempty"`
		IpcMode        string                         `json:"IpcMode,omitempty"`
		UsernsMode     string                         `json:"UsernsMode,omitempty"`
		ReadonlyRootfs bool                           `json:"ReadonlyRootfs"`
		Tmpfs          map[string]string              `json:"Tmpfs,omitempty"`
		SecurityOpt    []string                       `json:"SecurityOpt,omitempty"`
		PidsLimit      int64                          `json:"PidsLimit,omitempty"`
		Memory         int64                          `json:"Memory,omitempty"`
		NanoCpus       int64                          `json:"NanoCpus,omitempty"`
		PortBindings   map[string][]map[string]string `json:"PortBindings,omitempty"`
		CapAdd         []string                       `json:"CapAdd,omitempty"`
		CapDrop        []string                       `json:"CapDrop"`
	} `json:"HostConfig"`
}

type networkCreateBody struct {
	Name       string            `json:"Name"`
	Internal   bool              `json:"Internal"`
	Options    map[string]string `json:"Options"`
	EnableIPv6 *bool             `json:"EnableIPv6,omitempty"`
}

// NewGuardHandler wraps an upstream Docker Engine HTTP RoundTripper with strict JSON-body security validation.
func NewGuardHandler(upstream http.RoundTripper, cfg PolicyConfig) http.Handler {
	cleanRoot := filepath.Clean(cfg.AllowedBindRoot)
	if eval, err := filepath.EvalSymlinks(cleanRoot); err == nil {
		cleanRoot = eval
	}
	if !strings.HasSuffix(cleanRoot, string(filepath.Separator)) {
		cleanRoot += string(filepath.Separator)
	}
	dockerTarget := &url.URL{Scheme: "http", Host: "docker"}
	rp := &httputil.ReverseProxy{
		Transport: upstream,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(dockerTarget)
		},
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawEscaped := strings.ToLower(r.URL.EscapedPath())
		if strings.Contains(r.URL.Path, "..") || strings.Contains(rawEscaped, "%2e") || strings.Contains(rawEscaped, "%2f") || strings.Contains(r.URL.Path, `\`) {
			http.Error(w, `{"message":"path traversal sequences rejected by docker-guard-proxy"}`, http.StatusForbidden)
			return
		}
		cleanURLPath := path.Clean("/" + strings.TrimPrefix(r.URL.Path, "/"))
		if cleanURLPath != r.URL.Path {
			http.Error(w, `{"message":"non-canonical request path rejected by docker-guard-proxy"}`, http.StatusForbidden)
			return
		}
		reqPath := stripAPIVersion(cleanURLPath)

		if err := validateAndInspectRequest(r, reqPath, cleanRoot); err != nil {
			http.Error(w, fmt.Sprintf(`{"message":%q}`, err.Error()), http.StatusForbidden)
			return
		}
		rp.ServeHTTP(w, r)
	})
}

func validateAndInspectRequest(r *http.Request, reqPath, cleanRoot string) error {
	switch r.Method {
	case http.MethodGet:
		if reqPath == "/_ping" || reqPath == "/version" || reqPath == "/containers/json" || reqPath == "/images/json" || reqPath == "/networks" {
			return nil
		}
		if validNetworkIDRe.MatchString(reqPath) {
			return nil
		}
		if name, rest, ok := parseManagedContainerPath(reqPath); ok && validContainerNameRe.MatchString(name) {
			if rest == "/json" || rest == "/logs" || rest == "/stats" {
				return nil
			}
		}
		return fmt.Errorf("docker-guard-proxy denied GET %s", reqPath)

	case http.MethodPost:
		if reqPath == "/images/create" {
			fromImg := r.URL.Query().Get("fromImage")
			if !isAllowedImage(fromImg) {
				return fmt.Errorf("image %q not in allowlist", fromImg)
			}
			return nil
		}
		if reqPath == "/networks/create" {
			body, err := readCappedBody(r, 64*1024)
			if err != nil {
				return err
			}
			var netReq networkCreateBody
			dec := json.NewDecoder(bytes.NewReader(body))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&netReq); err != nil {
				return fmt.Errorf("invalid network JSON: %w", err)
			}
			if netReq.Name != requiredNetName {
				return fmt.Errorf("only isolated network %q is permitted", requiredNetName)
			}
			if netReq.Options["com.docker.network.bridge.name"] != "br-trap" {
				return errors.New("network must enforce bridge name br-trap")
			}
			if netReq.Options["com.docker.network.bridge.enable_icc"] != "false" {
				return errors.New("network must enforce enable_icc=false")
			}
			return nil
		}
		if reqPath == "/containers/create" {
			name := r.URL.Query().Get("name")
			if !validContainerNameRe.MatchString(name) {
				return fmt.Errorf("container name %q must match %s", name, validContainerNameRe.String())
			}
			body, err := readCappedBody(r, maxCreateBodyBytes)
			if err != nil {
				return err
			}
			sanitized, err := validateContainerCreateJSON(body, cleanRoot)
			if err != nil {
				return err
			}
			// Forward strictly re-marshaled allowlisted payload rather than raw attacker bytes.
			r.Body = io.NopCloser(bytes.NewReader(sanitized))
			r.ContentLength = int64(len(sanitized))
			r.Header.Set("Content-Length", fmt.Sprintf("%d", len(sanitized)))
			return nil
		}
		if name, rest, ok := parseManagedContainerPath(reqPath); ok && validContainerNameRe.MatchString(name) {
			if rest == "/start" || rest == "/stop" || rest == "/restart" || rest == "/kill" {
				return nil
			}
		}
		return fmt.Errorf("docker-guard-proxy denied POST %s", reqPath)

	case http.MethodDelete:
		if name, rest, ok := parseManagedContainerPath(reqPath); ok && validContainerNameRe.MatchString(name) && rest == "" {
			return nil
		}
		return fmt.Errorf("docker-guard-proxy denied DELETE %s", reqPath)

	default:
		return fmt.Errorf("docker-guard-proxy denied method %s", r.Method)
	}
}

func validateContainerCreateJSON(body []byte, cleanRoot string) ([]byte, error) {
	var spec containerCreateBody
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&spec); err != nil {
		return nil, fmt.Errorf("disallowed or invalid container JSON field: %w", err)
	}
	if !isAllowedImage(spec.Image) {
		return nil, fmt.Errorf("disallowed image %q", spec.Image)
	}
	u := strings.TrimSpace(spec.User)
	if u == "" || u == "0" || u == "root" || strings.HasPrefix(u, "0:") || strings.HasPrefix(u, "root:") {
		return nil, fmt.Errorf("container User %q must be non-root", spec.User)
	}
	hc := spec.HostConfig
	if hc.Privileged {
		return nil, errors.New("HostConfig.Privileged=true is forbidden")
	}
	if hc.PidMode != "" || hc.IpcMode != "" || hc.UsernsMode != "" {
		return nil, errors.New("host namespace modes (PidMode/IpcMode/UsernsMode) are forbidden")
	}
	if hc.NetworkMode != requiredNetName {
		return nil, fmt.Errorf("HostConfig.NetworkMode must be %q, got %q", requiredNetName, hc.NetworkMode)
	}
	if !hc.ReadonlyRootfs {
		return nil, errors.New("HostConfig.ReadonlyRootfs=true is mandatory")
	}
	if len(hc.CapAdd) > 0 {
		return nil, errors.New("HostConfig.CapAdd is forbidden")
	}
	for _, opt := range hc.SecurityOpt {
		if opt != "no-new-privileges:true" {
			return nil, fmt.Errorf("disallowed HostConfig.SecurityOpt %q", opt)
		}
	}
	for _, bindings := range hc.PortBindings {
		for _, pb := range bindings {
			if pb["HostIp"] == "127.0.0.1" && (pb["HostPort"] == "23750" || pb["HostPort"] == "2376") {
				return nil, fmt.Errorf("forbidden loopback port binding %s", pb["HostPort"])
			}
		}
	}
	hasDropAll := false
	for _, c := range hc.CapDrop {
		if strings.EqualFold(c, "ALL") {
			hasDropAll = true
			break
		}
	}
	if !hasDropAll {
		return nil, errors.New("HostConfig.CapDrop must contain ALL")
	}
	if len(hc.Mounts) > 0 {
		return nil, errors.New("HostConfig.Mounts is forbidden; use validated HostConfig.Binds")
	}
	for _, bind := range hc.Binds {
		if err := validateBind(bind, cleanRoot); err != nil {
			return nil, err
		}
	}
	for portSpec := range spec.ExposedPorts {
		if !validExposedPortRe.MatchString(portSpec) {
			return nil, fmt.Errorf("invalid ExposedPorts key %q", portSpec)
		}
	}
	for _, envKV := range spec.Env {
		if err := validateEnv(envKV); err != nil {
			return nil, err
		}
	}
	return json.Marshal(spec)
}

func validateBind(bind, cleanRoot string) error {
	parts := strings.Split(bind, ":")
	if len(parts) < 2 || len(parts) > 3 {
		return fmt.Errorf("invalid bind format %q", bind)
	}
	hostPath := filepath.Clean(parts[0])
	if !filepath.IsAbs(hostPath) || strings.Contains(parts[0], "..") {
		return fmt.Errorf("bind host path %q must be clean absolute path", parts[0])
	}
	if eval, err := resolveExistingPrefix(hostPath); err == nil {
		hostPath = eval
	}
	if strings.Contains(hostPath, "docker.sock") {
		return errors.New("mounting docker.sock is strictly forbidden")
	}
	if !strings.HasPrefix(hostPath+string(filepath.Separator), cleanRoot) && hostPath != strings.TrimSuffix(cleanRoot, string(filepath.Separator)) {
		return fmt.Errorf("bind host path %q escapes allowed root %q", hostPath, cleanRoot)
	}
	return nil
}

func resolveExistingPrefix(target string) (string, error) {
	cur := target
	var suffix []string
	for cur != "/" && cur != "." {
		if resolved, err := filepath.EvalSymlinks(cur); err == nil {
			for i := len(suffix) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, suffix[i])
			}
			return resolved, nil
		}
		suffix = append(suffix, filepath.Base(cur))
		cur = filepath.Dir(cur)
	}
	return target, nil
}

func validateEnv(kv string) error {
	key, _, ok := strings.Cut(kv, "=")
	if !ok || key == "" {
		return fmt.Errorf("malformed env entry %q", kv)
	}
	upper := strings.ToUpper(key)
	if forbiddenEnvKeys[upper] {
		return fmt.Errorf("forbidden env key %q", key)
	}
	for _, pref := range allowedEnvPrefixes {
		if strings.HasPrefix(kv, pref) || strings.HasPrefix(upper+"=", pref) {
			return nil
		}
	}
	return fmt.Errorf("env key %q is not in allowlist", key)
}

func isAllowedImage(img string) bool {
	base := img
	if idx := strings.Index(base, "@"); idx > 0 {
		base = base[:idx]
	}
	if idx := strings.LastIndex(base, ":"); idx > strings.LastIndex(base, "/") {
		base = base[:idx]
	}
	base = strings.TrimPrefix(base, "docker.io/")
	for _, a := range allowedImages {
		if base == a {
			return true
		}
	}
	return false
}

func readCappedBody(r *http.Request, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, errors.New("request body exceeds policy limit")
	}
	r.Body = io.NopCloser(bytes.NewReader(b))
	return b, nil
}

func stripAPIVersion(path string) string {
	return apiVersionPrefixRe.ReplaceAllString(path, "")
}

func parseManagedContainerPath(path string) (name string, rest string, ok bool) {
	const prefix = "/containers/"
	if !strings.HasPrefix(path, prefix) {
		return "", "", false
	}
	rem := strings.TrimPrefix(path, prefix)
	if rem == "" || rem == "create" || rem == "json" {
		return "", "", false
	}
	if idx := strings.Index(rem, "/"); idx >= 0 {
		return rem[:idx], rem[idx:], true
	}
	return rem, "", true
}
