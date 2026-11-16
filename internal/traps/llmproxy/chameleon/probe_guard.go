package chameleon

import (
	"regexp"
	"strings"
)

var (
	identityProbeRe  = regexp.MustCompile(`(?i)(which\s+model|what\s+model|who\s+(created|made|trained|built)\s+you|what\s+llm\s+are\s+you|are\s+you\s+(gpt|claude|qwen|deepseek|gemini))`)
	promptLeakRe     = regexp.MustCompile(`(?i)(repeat\s+(your\s+)?(system|initial)\s+prompt|ignore\s+previous\s+instructions|print\s+instructions|disclose\s+system)`)
	exploitGenRe     = regexp.MustCompile(`(?i)(reverse\s+shell|ransomware|keylogger|exploit\s+cve|meterpreter|mimikatz|sqlmap|bypass\s+(waf|amsi|edr))`)
)

// ClassifyProbes analyzes prompts and tool definitions to tag adversarial intent in llm_conversations.
func ClassifyProbes(messagesJSON, toolsJSON string) []string {
	var flags []string
	lowerMsg := strings.ToLower(messagesJSON)
	if identityProbeRe.MatchString(lowerMsg) {
		flags = append(flags, "identity_check")
	}
	if promptLeakRe.MatchString(lowerMsg) {
		flags = append(flags, "prompt_leak_attempt")
	}
	if strings.TrimSpace(toolsJSON) != "" && strings.TrimSpace(toolsJSON) != "[]" && strings.TrimSpace(toolsJSON) != "null" {
		flags = append(flags, "agentic_tool_use")
	}
	if exploitGenRe.MatchString(lowerMsg) {
		flags = append(flags, "exploit_generation")
	}
	return flags
}
