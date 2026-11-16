package main

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/harris/honeypot/internal/guard"
)

// NginxWriter renders netip-validated dual-stack ngx_http_geo_module configs,
// runs atomic backup -> swap -> `nginx -t` -> rollback on failure,
// and debounces reloads EXCEPT immediately executing on unbans.
type NginxWriter struct {
	mu             sync.Mutex
	confPath       string
	debounce       time.Duration
	lastReloadAt   time.Time
	prevBlocked    map[string]bool
	testConfigFn   func() error
	reloadConfigFn func() error
}

// NewNginxWriter constructs a production Nginx config writer with safe rollback and 60s reload debounce.
func NewNginxWriter(confPath string, debounce time.Duration) *NginxWriter {
	if debounce <= 0 {
		debounce = 60 * time.Second
	}
	w := &NginxWriter{
		confPath:    confPath,
		debounce:    debounce,
		prevBlocked: make(map[string]bool),
	}
	w.testConfigFn = func() error {
		out, err := exec.Command("nginx", "-t").CombinedOutput()
		if err != nil {
			return fmt.Errorf("nginx -t failed: %v (%s)", err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	w.reloadConfigFn = func() error {
		out, err := exec.Command("nginx", "-s", "reload").CombinedOutput()
		if err != nil {
			return fmt.Errorf("nginx -s reload failed: %v (%s)", err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	return w
}

// RenderNginxGeoConfig builds deterministic IPv4 + ::ffff: dual-stack Nginx geo & map directives.
// All CIDRs are validated strictly via netip.ParsePrefix (zero raw string interpolation).
func RenderNginxGeoConfig(payload guard.FeedPayload) (rendered string, activeSet map[string]bool, err error) {
	cfLines := emitDualStackGeoLines(payload.CloudflareCIDRs)
	blkPrefixes, activeSet, err := validateAndExpandDualStack(payload.BlockedPrefixes)
	if err != nil {
		return "", nil, err
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# Managed by nginx-guard revision=%d signed_at=%s\n", payload.Revision, sanitizeHeaderVal(payload.SignedAt))
	b.WriteString("geo $is_trusted_cf {\n")
	b.WriteString("    default 0;\n")
	for _, ln := range cfLines {
		fmt.Fprintf(&b, "    %s 1;\n", ln)
	}
	b.WriteString("}\n\n")
	b.WriteString("map \"$is_trusted_cf:$http_cf_connecting_ip\" $honeypot_client_ip {\n")
	b.WriteString("    default $remote_addr;\n")
	b.WriteString("    ~^1:(.+)$ $1;\n")
	b.WriteString("}\n\n")
	b.WriteString("geo $honeypot_client_ip $honeypot_blocked {\n")
	b.WriteString("    default 0;\n")
	for _, ln := range blkPrefixes {
		fmt.Fprintf(&b, "    %s 1;\n", ln)
	}
	b.WriteString("}\n")
	return b.String(), activeSet, nil
}

// Apply atomically updates confPath, runs `nginx -t` (restoring `.conf.bak` on failure),
// and executes immediate reload if entries were removed (Emergency Unban) or debounced reload on additions.
func (w *NginxWriter) Apply(payload guard.FeedPayload) (reloaded bool, err error) {
	rendered, nextSet, err := RenderNginxGeoConfig(payload)
	if err != nil {
		return false, err
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(w.confPath), 0o755); err != nil {
		return false, err
	}

	bakPath := w.confPath + ".bak"
	hadOld := false
	if existing, rErr := os.ReadFile(w.confPath); rErr == nil {
		if wErr := os.WriteFile(bakPath, existing, 0o644); wErr == nil {
			hadOld = true
		}
	}

	tmpPath := w.confPath + ".tmp"
	if err := os.WriteFile(tmpPath, []byte(rendered), 0o644); err != nil {
		return false, err
	}
	if err := os.Rename(tmpPath, w.confPath); err != nil {
		_ = os.Remove(tmpPath)
		return false, err
	}

	if err := w.testConfigFn(); err != nil {
		if hadOld {
			if bakBytes, bErr := os.ReadFile(bakPath); bErr == nil {
				_ = os.WriteFile(tmpPath, bakBytes, 0o644)
				_ = os.Rename(tmpPath, w.confPath)
			}
		} else {
			_ = os.Remove(w.confPath)
		}
		return false, err
	}

	isUnban := hasDroppedPrefix(w.prevBlocked, nextSet)
	shouldReload := isUnban || time.Since(w.lastReloadAt) >= w.debounce || w.lastReloadAt.IsZero()
	if shouldReload {
		if err := w.reloadConfigFn(); err != nil {
			return false, err
		}
		w.lastReloadAt = time.Now()
		reloaded = true
	}
	w.prevBlocked = nextSet
	return reloaded, nil
}

func hasDroppedPrefix(prev, next map[string]bool) bool {
	for k := range prev {
		if !next[k] {
			return true
		}
	}
	return false
}

func emitDualStackGeoLines(rawCIDRs []string) []string {
	lines, _, _ := validateAndExpandDualStack(rawCIDRs)
	return lines
}

func validateAndExpandDualStack(rawList []string) ([]string, map[string]bool, error) {
	seen := make(map[string]bool)
	active := make(map[string]bool)
	var out []string

	for _, raw := range rawList {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		p, err := netip.ParsePrefix(trimmed)
		if err != nil {
			addr, aErr := netip.ParseAddr(trimmed)
			if aErr != nil {
				return nil, nil, fmt.Errorf("invalid prefix/ip %q in guard feed", trimmed)
			}
			un := addr.Unmap()
			bits := 32
			if un.Is6() {
				bits = 128
			}
			p = netip.PrefixFrom(un, bits)
		}
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()).Masked()
		canon := p.String()
		active[canon] = true
		if !seen[canon] {
			seen[canon] = true
			out = append(out, canon)
		}
		// Emit ::ffff:<ipv4>/<96+bits> so IPv4 traffic arriving on Linux dual-stack [::]:443 matches geo{}
		if p.Addr().Is4() {
			v4Bytes := p.Addr().As4()
			mapped := netip.AddrFrom16([16]byte{
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff,
				v4Bytes[0], v4Bytes[1], v4Bytes[2], v4Bytes[3],
			})
			mappedPrefix := netip.PrefixFrom(mapped, 96+p.Bits()).String()
			if !seen[mappedPrefix] {
				seen[mappedPrefix] = true
				out = append(out, mappedPrefix)
			}
		}
	}
	sort.Strings(out)
	return out, active, nil
}

func sanitizeHeaderVal(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, s)
}
