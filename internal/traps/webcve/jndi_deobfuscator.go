package webcve

import (
	"encoding/base64"
	"net/url"
	"regexp"
	"strings"
)

const maxJNDIDepth = 12

var (
	jndiLookupInnerRe = regexp.MustCompile(`\$\{([^{}]+)\}`)
	jndiProtocolRe    = regexp.MustCompile(`(?i)\bjndi:(ldap[s]?|rmi|dns|iiop|corba)://([^\s"'<>}]+)`)
)

// JNDIMatch represents a de-obfuscated CVE-2021-44228 JNDI injection IOC.
type JNDIMatch struct {
	Raw          string `json:"raw"`
	ResolvedURI  string `json:"resolved_uri"`
	Protocol     string `json:"protocol"`
	CallbackHost string `json:"callback_host"`
}

// ResolveJNDI recursively expands nested Log4j lookup expressions (maxDepth=12)
// across HTTP headers, raw URIs, and body text to extract clean C2 JNDI callbacks.
func ResolveJNDI(inputs ...string) []JNDIMatch {
	seen := make(map[string]struct{})
	var matches []JNDIMatch

	for _, in := range inputs {
		if len(in) == 0 || !strings.Contains(in, "${") {
			continue
		}
		expanded := expandLog4jExpr(in)
		for _, loc := range jndiProtocolRe.FindAllStringSubmatch(expanded, -1) {
			full := loc[0]
			proto := strings.ToLower(loc[1])
			hostPart := strings.SplitN(loc[2], "/", 2)[0]
			if _, dup := seen[full]; dup {
				continue
			}
			seen[full] = struct{}{}
			rawClip := in
			if len(rawClip) > 512 {
				rawClip = rawClip[:512]
			}
			matches = append(matches, JNDIMatch{
				Raw:          rawClip,
				ResolvedURI:  full,
				Protocol:     proto,
				CallbackHost: hostPart,
			})
		}
	}
	return matches
}

func expandLog4jExpr(s string) string {
	// Also test URL-decoded form if encoded
	if dec, err := url.QueryUnescape(s); err == nil && strings.Contains(dec, "${") {
		s = dec
	}
	cur := s
	for depth := 0; depth < maxJNDIDepth; depth++ {
		next := jndiLookupInnerRe.ReplaceAllStringFunc(cur, func(expr string) string {
			inner := expr[2 : len(expr)-1]
			return evalLookupToken(inner)
		})
		if next == cur {
			break
		}
		cur = next
	}
	return cur
}

func evalLookupToken(inner string) string {
	// Handle default fallback syntax like ${::-j}, ${env:VAR:-n}, ${sys:x:-d}
	if idx := strings.Index(inner, ":-"); idx >= 0 {
		return inner[idx+2:]
	}
	if strings.HasPrefix(inner, "::") {
		return inner[2:]
	}
	lowerPrefix, val, hasColon := strings.Cut(inner, ":")
	if !hasColon {
		return ""
	}
	switch strings.ToLower(strings.TrimSpace(lowerPrefix)) {
	case "lower":
		return strings.ToLower(val)
	case "upper":
		return strings.ToUpper(val)
	case "base64":
		if decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(val)); err == nil {
			return string(decoded)
		}
		return val
	case "jndi":
		// Keep outer jndi:... intact once inner lookups resolve
		return "${jndi:" + val + "}"
	default:
		return val
	}
}
