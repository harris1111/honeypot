package cowrieparser

import (
	"encoding/binary"
	"strings"
)

const (
	umlOpWrite   int32 = 3
	umlDirOutput int32 = 2
	umlHeaderLen       = 24
)

// ParseUMLTTYLog decodes Cowrie's 24-byte little-endian UML ttylog binary format into asciicast frames.
func ParseUMLTTYLog(raw []byte, maxOutputBytes int) ([]CastFrame, error) {
	if maxOutputBytes <= 0 {
		maxOutputBytes = 256 * 1024
	}
	var frames []CastFrame
	var (
		off        int
		totalBytes int
		hasT0      bool
		t0         float64
		prevCR     bool
	)

	for off+umlHeaderLen <= len(raw) {
		op := int32(binary.LittleEndian.Uint32(raw[off : off+4]))
		// raw[off+4 : off+8] is tty id (unused)
		length := int32(binary.LittleEndian.Uint32(raw[off+8 : off+12]))
		dir := int32(binary.LittleEndian.Uint32(raw[off+12 : off+16]))
		sec := binary.LittleEndian.Uint32(raw[off+16 : off+20])
		usec := binary.LittleEndian.Uint32(raw[off+20 : off+24])
		off += umlHeaderLen

		if length < 0 || int(length) > len(raw)-off {
			break
		}
		payload := raw[off : off+int(length)]
		off += int(length)

		if op != umlOpWrite || dir != umlDirOutput || len(payload) == 0 {
			continue
		}

		clean := SanitizeTerminalText(string(payload))
		if clean == "" {
			continue
		}

		var norm string
		norm, prevCR = normalizeTTYNewlines(clean, prevCR)
		if norm == "" {
			continue
		}
		if totalBytes+len(norm) > maxOutputBytes {
			rem := maxOutputBytes - totalBytes
			if rem <= 0 {
				break
			}
			norm = norm[:rem]
		}
		totalBytes += len(norm)

		ts := float64(sec) + float64(usec)/1e6
		if !hasT0 {
			t0 = ts
			hasT0 = true
		}
		offsetSec := ts - t0
		if offsetSec < 0 {
			offsetSec = 0
		}

		// Coalesce consecutive character echoes within 25ms for compact, smooth playback.
		if n := len(frames); n > 0 && offsetSec-frames[n-1].OffsetSec <= 0.025 && len(frames[n-1].Data)+len(norm) <= 4096 {
			frames[n-1].Data += norm
			continue
		}
		frames = append(frames, CastFrame{
			OffsetSec: offsetSec,
			Data:      norm,
		})
		if totalBytes >= maxOutputBytes {
			break
		}
	}

	return frames, nil
}

func normalizeTTYNewlines(s string, prevEndedCR bool) (string, bool) {
	var b strings.Builder
	b.Grow(len(s) + 8)
	endedCR := prevEndedCR
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == '\r' {
			b.WriteByte('\r')
			endedCR = true
			continue
		}
		if ch == '\n' {
			if !endedCR {
				b.WriteByte('\r')
			}
			b.WriteByte('\n')
			endedCR = false
			continue
		}
		endedCR = false
		b.WriteByte(ch)
	}
	return b.String(), endedCR
}
