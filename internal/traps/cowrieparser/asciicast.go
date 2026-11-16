package cowrieparser

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

var (
	// Strip OSC (\x1b] ... \x07 or \x1b\\), 8-bit C1 OSC/DCS/APC/PM/SOS, and 7-bit DCS/PM/APC/SOS
	oscDCSAPCRe = regexp.MustCompile(`\x1b(?:\][^\x07\x1b]*(?:\x07|\x1b\\)|[P^_X][^\x1b]*(?:\x1b\\)?)|[\x{0090}\x{0098}\x{009b}\x{009d}\x{009e}\x{009f}][^\x07\x1b\x{009c}]*(?:\x07|\x1b\\|\x{009c})?`)
	// Strip remaining ANSI CSI/single ESC sequences to prevent terminal UI injection on playback.
	csiOtherRe = regexp.MustCompile(`\x1b(?:\[[0-9;?]*[ -/]*[@-~]|[@-Z\\-_])`)
)

// SanitizeTerminalText strips dangerous OSC/DCS/APC/PM/SOS, Unicode C1 controls (U+0080-U+009F),
// and arbitrary ANSI escape sequences so attacker payloads cannot hijack operator terminals during asciicast replay.
func SanitizeTerminalText(raw string) string {
	s := oscDCSAPCRe.ReplaceAllString(raw, "")
	s = csiOtherRe.ReplaceAllString(s, "")

	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == 0x1b || r == 0x7f || (r < 0x20 && r != '\n' && r != '\r' && r != '\t') || (r >= 0x80 && r <= 0x9f) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// CastFrame represents a single timed output frame for asciicast v2.
type CastFrame struct {
	OffsetSec float64
	Data      string
}

// BuildAsciicastV2 renders a valid asciinema v2 (.cast) document with sanitized frames.
func BuildAsciicastV2(startedAt time.Time, width, height int, frames []CastFrame) string {
	if width <= 0 {
		width = 100
	}
	if height <= 0 {
		height = 30
	}
	if startedAt.IsZero() {
		startedAt = time.Now().UTC()
	}

	header := map[string]any{
		"version":   2,
		"width":     width,
		"height":    height,
		"timestamp": startedAt.Unix(),
		"env": map[string]string{
			"TERM":  "xterm-256color",
			"SHELL": "/bin/bash",
		},
	}
	hdrBytes, _ := json.Marshal(header)

	var b strings.Builder
	b.Write(hdrBytes)
	b.WriteByte('\n')

	for _, fr := range frames {
		offset := fr.OffsetSec
		if offset < 0 {
			offset = 0
		}
		clean := SanitizeTerminalText(fr.Data)
		row, _ := json.Marshal([]any{roundMs(offset), "o", clean})
		b.Write(row)
		b.WriteByte('\n')
	}
	return b.String()
}

func roundMs(sec float64) float64 {
	return float64(int64(sec*1000)) / 1000.0
}

// FormatCommandOutput builds a realistic terminal prompt/command output line.
func FormatCommandOutput(username, cmd string) string {
	user := strings.TrimSpace(username)
	if user == "" {
		user = "root"
	}
	prefix := fmt.Sprintf("%s@prod-app-01:~# ", SanitizeTerminalText(user))
	if user != "root" {
		prefix = fmt.Sprintf("%s@prod-app-01:~$ ", SanitizeTerminalText(user))
	}
	return prefix + SanitizeTerminalText(cmd) + "\r\n"
}
