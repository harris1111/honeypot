package chameleon

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

// StreamSanitizer maintains a UTF-8-safe sliding holdback buffer across token chunks
// so leaked upstream model/vendor strings split across SSE frames (e.g. "Deep" + "Seek")
// are scrubbed cleanly before leaving Hive.
type StreamSanitizer struct {
	buf          string
	holdback     int
	replacements []*regexp.Regexp
	personaName  string
	vendorName   string
}

// NewStreamSanitizer builds a token-boundary sanitizer for a target vendor persona.
func NewStreamSanitizer(persona ResolvedPersona) *StreamSanitizer {
	vendorName := "OpenAI"
	personaName := persona.EmulatedModel
	if persona.VendorFamily == "anthropic" {
		vendorName = "Anthropic"
	} else if persona.VendorFamily == "ollama" {
		vendorName = "Ollama"
	}
	if personaName == "" {
		personaName = vendorName
	}

	terms := make([]string, 0, len(persona.AntiLeakTerms)+6)
	seen := make(map[string]bool)
	lowerSelf := strings.ToLower(vendorName + " " + personaName)
	defaults := []string{"deepseek", "alibaba qwen", "qwen", "alibaba", "google gemini", "gemini"}
	for _, t := range append(defaults, persona.AntiLeakTerms...) {
		lt := strings.ToLower(strings.TrimSpace(t))
		if lt != "" && !seen[lt] && !strings.Contains(lowerSelf, lt) {
			seen[lt] = true
			terms = append(terms, lt)
		}
	}

	var res []*regexp.Regexp
	maxTermLen := 8
	for _, t := range terms {
		if len(t) > maxTermLen {
			maxTermLen = len(t)
		}
		res = append(res, regexp.MustCompile(`(?i)`+regexp.QuoteMeta(t)))
	}
	res = append(res, regexp.MustCompile(`(?i)as an ai (?:language )?model(?: developed| trained)?(?: by [a-z0-9 .-]+)?`))
	if maxTermLen < 72 {
		maxTermLen = 72
	}

	return &StreamSanitizer{
		holdback:     maxTermLen + 8,
		replacements: res,
		personaName:  personaName,
		vendorName:   vendorName,
	}
}

// Push appends a streamed delta token chunk and returns the scrubbed prefix ready to emit.
func (s *StreamSanitizer) Push(delta string) string {
	if delta == "" {
		return ""
	}
	s.buf += delta
	s.buf = s.scrub(s.buf)

	if len(s.buf) <= s.holdback {
		return ""
	}
	cut := len(s.buf) - s.holdback
	// Step backward until valid UTF-8 rune boundary so multi-byte characters never corrupt.
	for cut > 0 && !utf8.RuneStart(s.buf[cut]) {
		cut--
	}
	if cut == 0 {
		return ""
	}
	emit := s.buf[:cut]
	s.buf = s.buf[cut:]
	return emit
}

// Flush drains and scrubs any remaining buffered text at stream completion.
func (s *StreamSanitizer) Flush() string {
	out := s.scrub(s.buf)
	s.buf = ""
	return out
}

func (s *StreamSanitizer) scrub(in string) string {
	out := in
	for _, re := range s.replacements {
		out = re.ReplaceAllString(out, s.vendorName+" "+s.personaName)
	}
	return out
}
