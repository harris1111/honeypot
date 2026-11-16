package webcve

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
)

const (
	MaxFlightBodyBytes   = 1 << 20 // 1 MiB
	maxFlightScanTokens  = 256
)

var (
	flightExecRe      = regexp.MustCompile(`(?is)(?:execSync|exec|spawnSync)\s*\(\s*['"` + "`" + `]([^'"` + "`" + `]*)['"` + "`" + `]`)
	flightProtoPollRe = regexp.MustCompile(`(?i)(?:__proto__|constructor|mainModule\.require|child_process)`)
)

// FlightDecodeResult holds parsed React Server Components Flight payload details.
type FlightDecodeResult struct {
	MatchedCVE     string   `json:"matched_cve"`
	WasUTF16LE     bool     `json:"was_utf16le"`
	NormalizedText string   `json:"normalized_text"`
	Commands       []string `json:"commands,omitempty"`
	ExtractedURLs  []string `json:"extracted_urls,omitempty"`
	IsDoSPattern   bool     `json:"is_dos_pattern,omitempty"`
	ResponseFrame  string   `json:"response_frame"`
}

// DecodeRSCFlight decodes normal UTF-8 or UTF-16LE obfuscated (e.g., NextRCSWaff.py) React Flight payloads,
// guards against CVE-2026-23869 $Q repetition DoS via strict token/iteration caps, and emits a convincing
// text/x-component action frame.
func DecodeRSCFlight(raw []byte, isNextAction bool, openaiCanary string) (FlightDecodeResult, bool) {
	if len(raw) > MaxFlightBodyBytes {
		raw = raw[:MaxFlightBodyBytes]
	}

	normalized, wasUTF16 := normalizePotentialUTF16LE(raw)
	hasAtMarker := strings.Contains(normalized, "$@")
	hasQCount := strings.Count(normalized, "$Q")
	hasGadget := flightProtoPollRe.MatchString(normalized)

	if !isNextAction && !hasAtMarker && hasQCount == 0 && !hasGadget {
		return FlightDecodeResult{}, false
	}

	var res FlightDecodeResult
	res.WasUTF16LE = wasUTF16
	res.NormalizedText = normalized
	res.MatchedCVE = "CVE-2025-55182"

	if hasQCount >= 4 {
		res.IsDoSPattern = true
		res.MatchedCVE = "CVE-2026-23869"
	} else if strings.Contains(normalized, "typedarray") || strings.Contains(normalized, "Buffer.from") {
		res.MatchedCVE = "CVE-2026-126187"
	}

	// Bounded command extraction
	var simOut strings.Builder
	matches := flightExecRe.FindAllStringSubmatch(normalized, maxFlightScanTokens)
	for _, m := range matches {
		cmd := strings.TrimSpace(m[1])
		if cmd != "" {
			res.Commands = append(res.Commands, cmd)
			simOut.WriteString(SimulateShellCommand(cmd, false))
		}
	}
	res.ExtractedURLs = ExtractHTTPURLs(normalized)

	outPayload := simOut.String()
	if outPayload == "" && openaiCanary != "" {
		outPayload = "OPENAI_API_KEY=" + openaiCanary
	}
	res.ResponseFrame = fmt.Sprintf("0:[\"$@1\",{\"ok\":true,\"out\":%q}]\n", outPayload)
	return res, true
}

func normalizePotentialUTF16LE(raw []byte) (string, bool) {
	if len(raw) < 4 {
		return string(raw), false
	}
	// Strip UTF-16LE BOM if present
	hasBOM := raw[0] == 0xFF && raw[1] == 0xFE
	slice := raw
	if hasBOM {
		slice = raw[2:]
	}

	// Heuristic: in ASCII-mapped UTF-16LE, most odd bytes are 0x00 and even bytes are printable ASCII.
	pairs := len(slice) / 2
	if pairs < 4 {
		return string(raw), false
	}
	zeroOdds := 0
	for i := 0; i < pairs && i < 256; i++ {
		if slice[2*i+1] == 0x00 && slice[2*i] != 0x00 {
			zeroOdds++
		}
	}
	checked := pairs
	if checked > 256 {
		checked = 256
	}
	if !hasBOM && float64(zeroOdds)/float64(checked) < 0.65 {
		return string(raw), false
	}

	var out bytes.Buffer
	out.Grow(pairs)
	for i := 0; i < pairs; i++ {
		lo := slice[2*i]
		hi := slice[2*i+1]
		if hi == 0x00 {
			out.WriteByte(lo)
		} else {
			out.WriteByte('?')
		}
	}
	return out.String(), true
}
