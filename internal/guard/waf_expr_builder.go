package guard

import (
	"fmt"
	"strings"
)

// WAFConfig gates enterprise-only Cloudflare WAF expression capabilities such as JA4 matching.
type WAFConfig struct {
	CloudflareEnterpriseJA4Enabled bool
	ListName                       string
	ExcludedBrowserJA4Prefixes     []string
}

var defaultBrowserJA4s = map[string]bool{
	"t13d1516h2_8daaf6152771_e5627efa2ab1": true, // Chrome
	"t13d1715h2_5b57614c22b0_5c2c66f702b0": true, // Firefox
	"t13d2014h2_a09f3c656075_14788d8d241b": true, // Safari
}

// BuildWirefilterExpression generates an escaped Cloudflare WAF expression referencing
// the synced custom IP list plus optional non-browser JA4 matcher gated behind Enterprise flag.
func BuildWirefilterExpression(cfg WAFConfig, candidateJA4s []string) string {
	listName := strings.TrimSpace(cfg.ListName)
	if listName == "" {
		listName = "honeypot_blocklist"
	}
	var clauses []string
	clauses = append(clauses, fmt.Sprintf("(ip.src in $%s)", escapeWirefilterIdent(listName)))

	if cfg.CloudflareEnterpriseJA4Enabled && len(candidateJA4s) > 0 {
		var filtered []string
		for _, fp := range candidateJA4s {
			clean := strings.TrimSpace(fp)
			if clean == "" || defaultBrowserJA4s[clean] || isExcludedPrefix(clean, cfg.ExcludedBrowserJA4Prefixes) {
				continue
			}
			filtered = append(filtered, fmt.Sprintf(`"%s"`, escapeWirefilterString(clean)))
		}
		if len(filtered) > 0 {
			clauses = append(clauses, fmt.Sprintf("(cf.tls_client_extensions_sha1 in {%s})", strings.Join(filtered, " ")))
		}
	}

	return strings.Join(clauses, " or ")
}

func isExcludedPrefix(fp string, prefixes []string) bool {
	for _, p := range prefixes {
		if p != "" && strings.HasPrefix(fp, p) {
			return true
		}
	}
	return false
}

func escapeWirefilterIdent(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' {
			b.WriteByte(c)
		}
	}
	return b.String()
}

func escapeWirefilterString(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", "", "\r", "")
	return r.Replace(s)
}
