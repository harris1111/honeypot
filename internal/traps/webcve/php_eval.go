package webcve

import (
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html"
	"net/url"
	"regexp"
	"strings"
)

var (
	phpBlockRe     = regexp.MustCompile(`(?is)<\?(?:php|=)\s*(.*?)(?:\?>|$)`)
	phpFnCallRe    = regexp.MustCompile(`(?i)\b(md5|sha1|base64_decode|echo|print|printf|system|exec|shell_exec|passthru)\s*\(\s*(?:'([^']*)'|"([^"]*)")\s*\)`)
	phpEchoBareRe  = regexp.MustCompile(`(?i)\b(?:echo|print)\s+(?:'([^']*)'|"([^"]*)")`)
	phpConcatStrRe = regexp.MustCompile(`(?:'([^']*)'|"([^"]*)")\s*\.\s*(?:'([^']*)'|"([^"]*)")`)
	phpCmdExecRe   = regexp.MustCompile(`(?i)\b(?:system|exec|shell_exec|passthru|proc_open)\s*\(\s*(?:'([^']*)'|"([^"]*)")\s*\)`)
	phpBacktickRe  = regexp.MustCompile("`([^`]+)`")
	phpURLRe       = regexp.MustCompile(`https?://[^\s"'<>|;&` + "`" + `)]+`)
)

// PHPEvalResult holds deterministic simulated output plus extracted attacker URLs/commands.
type PHPEvalResult struct {
	Output           string   `json:"output"`
	ExecutedCommands []string `json:"executed_commands,omitempty"`
	ExtractedURLs    []string `json:"extracted_urls,omitempty"`
	RanPhpInfo       bool     `json:"ran_phpinfo,omitempty"`
}

// EvalPHPSnippet safely evaluates benign probe helpers (`md5`, `sha1`, `base64_decode`, `echo`, `phpinfo`)
// and deterministically simulates shell command outputs without invoking any OS shell or PHP runtime.
func EvalPHPSnippet(body string, isWindows bool, openaiCanary, anthropicCanary, aiGatewayURL string) PHPEvalResult {
	var res PHPEvalResult
	snippet := body
	if matches := phpBlockRe.FindAllStringSubmatch(body, -1); len(matches) > 0 {
		var parts []string
		for _, m := range matches {
			parts = append(parts, m[1])
		}
		snippet = strings.Join(parts, "\n")
	}

	// Collapse simple literal string concatenations such as "hel" . "lo"
	for i := 0; i < 4; i++ {
		next := phpConcatStrRe.ReplaceAllStringFunc(snippet, func(expr string) string {
			m := phpConcatStrRe.FindStringSubmatch(expr)
			if len(m) < 5 {
				return expr
			}
			left := m[1]
			if left == "" {
				left = m[2]
			}
			right := m[3]
			if right == "" {
				right = m[4]
			}
			return `"` + left + right + `"`
		})
		if next == snippet {
			break
		}
		snippet = next
	}

	var out strings.Builder
	if strings.Contains(strings.ToLower(snippet), "phpinfo(") {
		res.RanPhpInfo = true
		out.WriteString(renderFakePhpInfo(openaiCanary, anthropicCanary, aiGatewayURL))
	}

	for _, m := range phpFnCallRe.FindAllStringSubmatch(snippet, -1) {
		fn := strings.ToLower(m[1])
		arg := m[2]
		if arg == "" {
			arg = m[3]
		}
		switch fn {
		case "md5":
			sum := md5.Sum([]byte(arg))
			out.WriteString(hex.EncodeToString(sum[:]))
		case "sha1":
			sum := sha1.Sum([]byte(arg))
			out.WriteString(hex.EncodeToString(sum[:]))
		case "base64_decode":
			if dec, err := base64.StdEncoding.DecodeString(arg); err == nil {
				out.WriteString(string(dec))
			}
		case "echo", "print", "printf":
			out.WriteString(arg)
		case "system", "exec", "shell_exec", "passthru":
			res.ExecutedCommands = append(res.ExecutedCommands, arg)
			out.WriteString(SimulateShellCommand(arg, isWindows))
		}
	}

	// Capture bare `echo "..."` without parentheses if nothing matched inside fn calls for echo
	for _, m := range phpEchoBareRe.FindAllStringSubmatch(snippet, -1) {
		val := m[1]
		if val == "" {
			val = m[2]
		}
		out.WriteString(val)
	}

	for _, m := range phpBacktickRe.FindAllStringSubmatch(snippet, -1) {
		cmd := strings.TrimSpace(m[1])
		if cmd != "" {
			res.ExecutedCommands = append(res.ExecutedCommands, cmd)
			out.WriteString(SimulateShellCommand(cmd, isWindows))
		}
	}

	// Collect any inline shell commands even from indirect calls like `system($_GET['c'])` fallback
	for _, m := range phpCmdExecRe.FindAllStringSubmatch(snippet, -1) {
		cmd := m[1]
		if cmd == "" {
			cmd = m[2]
		}
		if cmd != "" && !containsString(res.ExecutedCommands, cmd) {
			res.ExecutedCommands = append(res.ExecutedCommands, cmd)
		}
	}

	res.ExtractedURLs = ExtractHTTPURLs(body)
	res.Output = out.String()
	return res
}

// SimulateShellCommand produces plausible Linux or Windows command output deterministically.
func SimulateShellCommand(cmd string, isWindows bool) string {
	lc := strings.ToLower(strings.TrimSpace(cmd))
	switch {
	case strings.Contains(lc, "whoami") || lc == "id" || strings.HasPrefix(lc, "id "):
		if isWindows {
			return "nt authority\\system\n"
		}
		return "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n"
	case strings.HasPrefix(lc, "uname"):
		if isWindows {
			return "Windows NT PROD-WEB-01 10.0 build 20348\n"
		}
		return "Linux prod-app-01 6.1.0-21-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.90-1 x86_64 GNU/Linux\n"
	case strings.Contains(lc, "/etc/passwd"):
		return "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
	case strings.Contains(lc, "env") || strings.Contains(lc, "printenv"):
		return "APP_ENV=production\nHOME=/var/www\n"
	case strings.HasPrefix(lc, "echo "):
		return strings.TrimPrefix(cmd, "echo ") + "\n"
	default:
		return ""
	}
}

func renderFakePhpInfo(openaiCanary, anthropicCanary, aiGatewayURL string) string {
	return fmt.Sprintf(
		`<!DOCTYPE html><html><head><title>PHP 8.2.18 - phpinfo()</title></head><body><h1>PHP Version 8.2.18</h1>`+
			`<table><tr><td>OPENAI_BASE_URL</td><td>%s</td></tr>`+
			`<tr><td>OPENAI_API_KEY</td><td>%s</td></tr>`+
			`<tr><td>ANTHROPIC_API_KEY</td><td>%s</td></tr></table></body></html>`,
		html.EscapeString(aiGatewayURL),
		html.EscapeString(openaiCanary),
		html.EscapeString(anthropicCanary),
	)
}

// ExtractHTTPURLs extracts clean validated http/https URLs from arbitrary text/payloads.
func ExtractHTTPURLs(raw string) []string {
	matches := phpURLRe.FindAllString(raw, -1)
	if len(matches) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(matches))
	var out []string
	for _, candidate := range matches {
		candidate = strings.TrimRight(candidate, `.,;:'")]}>`)
		u, err := url.Parse(candidate)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			continue
		}
		if _, dup := seen[candidate]; dup {
			continue
		}
		seen[candidate] = struct{}{}
		out = append(out, candidate)
	}
	return out
}

func containsString(list []string, target string) bool {
	for _, item := range list {
		if item == target {
			return true
		}
	}
	return false
}
