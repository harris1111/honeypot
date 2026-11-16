package cowrieparser

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/harris/honeypot/internal/canary"
	honeypotv1 "github.com/harris/honeypot/proto/gen/honeypot/v1"
)

var inlineURLRe = regexp.MustCompile(`https?://[^\s"'<>|;&` + "`" + `]+`)

// FileDownloadNotice identifies an attacker download/upload attempt observed in Cowrie.
type FileDownloadNotice struct {
	SessionID string
	SourceIP  string
	EventUUID string
	URL       string
	Outfile   string
	SHASum    string
}

// ParseResult aggregates telemetry events, finished SSH replays, and download notices from a Cowrie JSON line.
type ParseResult struct {
	Events    []*honeypotv1.TelemetryEvent
	Replay    *honeypotv1.SshSessionReplay
	Downloads []FileDownloadNotice
}

type cowrieRawEvent struct {
	EventID         string   `json:"eventid"`
	Timestamp       string   `json:"timestamp"`
	Session         string   `json:"session"`
	SrcIP           string   `json:"src_ip"`
	SrcPort         uint32   `json:"src_port"`
	DstPort         uint32   `json:"dst_port"`
	Protocol        string   `json:"protocol"`
	Username        string   `json:"username"`
	Password        string   `json:"password"`
	Input           string   `json:"input"`
	Version         string   `json:"version"`
	HASSH           string   `json:"hassh"`
	HASSHAlgorithms string   `json:"hasshAlgorithms"`
	URL             string   `json:"url"`
	Outfile         string   `json:"outfile"`
	SHASum          string   `json:"shasum"`
	Duration        float64  `json:"duration"`
	Message         string   `json:"message"`
	Sensor          string   `json:"sensor"`
	Arch            []string `json:"arch"`
}

type cowrieSession struct {
	SessionID     string
	RootEventUUID string
	SourceIP      string
	SourcePort    uint32
	DestPort      uint32
	Protocol      string
	HASSH         string
	ClientVersion string
	Username      string
	AuthSucceeded bool
	Commands      []string
	Frames        []CastFrame
	StartedAt     time.Time
	LastSeenAt    time.Time
}

// Parser incrementally parses Cowrie JSON log lines into TelemetryEvents, SshSessionReplays, and download notices.
type Parser struct {
	mu          sync.Mutex
	nodeID      string
	defaultPort uint32
	keyPool     *canary.SensorKeyPool
	sessions    map[string]*cowrieSession
}

// NewParser creates a stateful Cowrie NDJSON parser for a Sensor node.
func NewParser(nodeID string, defaultPort uint32, pool *canary.SensorKeyPool) *Parser {
	if defaultPort == 0 {
		defaultPort = 22
	}
	return &Parser{
		nodeID:      nodeID,
		defaultPort: defaultPort,
		keyPool:     pool,
		sessions:    make(map[string]*cowrieSession),
	}
}

// ProcessLine parses a single Cowrie JSON log line and returns resulting events, replays, and file downloads.
func (p *Parser) ProcessLine(line string) (ParseResult, error) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return ParseResult{}, nil
	}
	var raw cowrieRawEvent
	if err := json.Unmarshal([]byte(trimmed), &raw); err != nil {
		return ParseResult{}, fmt.Errorf("decode cowrie event: %w", err)
	}
	if raw.EventID == "" {
		return ParseResult{}, nil
	}

	ts := parseTimestamp(raw.Timestamp)
	p.mu.Lock()
	defer p.mu.Unlock()

	sess := p.getOrCreateSession(raw, ts)
	if !ts.IsZero() && ts.After(sess.LastSeenAt) {
		sess.LastSeenAt = ts
	}

	var out ParseResult
	switch raw.EventID {
	case "cowrie.session.connect":
		sess.Frames = append(sess.Frames, CastFrame{
			OffsetSec: 0,
			Data:      fmt.Sprintf("Connected from %s\r\n", SanitizeTerminalText(raw.SrcIP)),
		})
		out.Events = append(out.Events, p.buildEvent(sess, ts, 25, "session_connect", map[string]any{
			"session": raw.Session,
			"src_ip":  raw.SrcIP,
		}, "", ""))

	case "cowrie.client.version":
		sess.ClientVersion = SanitizeTerminalText(raw.Version)

	case "cowrie.client.kex":
		if raw.HASSH != "" {
			sess.HASSH = strings.TrimSpace(raw.HASSH)
		}

	case "cowrie.login.failed", "cowrie.login.success":
		succeeded := raw.EventID == "cowrie.login.success"
		sess.Username = SanitizeTerminalText(raw.Username)
		if succeeded {
			sess.AuthSucceeded = true
		}
		score := int32(35)
		if succeeded {
			score = 60
		}
		iocs := map[string]any{
			"session":  raw.Session,
			"username": sess.Username,
			"password": SanitizeTerminalText(raw.Password),
			"success":  succeeded,
		}
		ev := p.buildEvent(sess, ts, score, fmt.Sprintf("login %s:%s", sess.Username, map[bool]string{true: "accepted", false: "rejected"}[succeeded]), iocs, trimmed, "")
		out.Events = append(out.Events, ev)

	case "cowrie.command.input", "cowrie.command.failed":
		cleanCmd := SanitizeTerminalText(raw.Input)
		sess.Commands = append(sess.Commands, cleanCmd)
		sess.Frames = append(sess.Frames, CastFrame{
			OffsetSec: ts.Sub(sess.StartedAt).Seconds(),
			Data:      FormatCommandOutput(sess.Username, cleanCmd),
		})

		canaryID := p.detectCanaryInText(cleanCmd)
		urls := extractValidURLs(raw.Input)
		score := int32(65)
		if canaryID != "" {
			score = 90
		} else if len(urls) > 0 {
			score = 80
		}

		iocs := map[string]any{
			"session": raw.Session,
			"command": cleanCmd,
		}
		if len(urls) > 0 {
			iocs["urls"] = urls
		}
		ev := p.buildEvent(sess, ts, score, "ssh command: "+cleanCmd, iocs, cleanCmd, canaryID)
		out.Events = append(out.Events, ev)

		for _, u := range urls {
			out.Downloads = append(out.Downloads, FileDownloadNotice{
				SessionID: sess.SessionID,
				SourceIP:  sess.SourceIP,
				EventUUID: ev.EventUuid,
				URL:       u,
			})
		}

	case "cowrie.session.file_download", "cowrie.session.file_upload":
		score := int32(85)
		iocs := map[string]any{
			"session": raw.Session,
			"url":     raw.URL,
			"outfile": raw.Outfile,
			"shasum":  raw.SHASum,
		}
		ev := p.buildEvent(sess, ts, score, "cowrie artifact capture: "+SanitizeTerminalText(raw.URL), iocs, trimmed, "")
		if len(raw.SHASum) == 64 {
			ev.ArtifactSha256 = strings.ToLower(raw.SHASum)
		}
		out.Events = append(out.Events, ev)
		if raw.URL != "" || raw.Outfile != "" {
			out.Downloads = append(out.Downloads, FileDownloadNotice{
				SessionID: sess.SessionID,
				SourceIP:  sess.SourceIP,
				EventUUID: ev.EventUuid,
				URL:       raw.URL,
				Outfile:   raw.Outfile,
				SHASum:    strings.ToLower(raw.SHASum),
			})
		}

	case "cowrie.session.closed":
		durMs := int64(raw.Duration * 1000)
		if durMs <= 0 && !sess.LastSeenAt.IsZero() && !sess.StartedAt.IsZero() {
			durMs = sess.LastSeenAt.Sub(sess.StartedAt).Milliseconds()
		}
		if durMs < 0 {
			durMs = 0
		}
		cast := BuildAsciicastV2(sess.StartedAt, 100, 30, sess.Frames)
		out.Replay = &honeypotv1.SshSessionReplay{
			ReplayUuid:    newUUIDv4(),
			EventUuid:     sess.RootEventUUID,
			NodeId:        p.nodeID,
			SourceIp:      sess.SourceIP,
			Hassh:         sess.HASSH,
			Username:      sess.Username,
			AuthSucceeded: sess.AuthSucceeded,
			Commands:      append([]string(nil), sess.Commands...),
			AsciicastV2:   cast,
			DurationMs:    durMs,
			StartedAt:     timestamppb.New(sess.StartedAt),
		}
		delete(p.sessions, sess.SessionID)
	}

	return out, nil
}

// ActiveSessions returns the number of currently open SSH/Telnet sessions tracked by the parser.
func (p *Parser) ActiveSessions() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.sessions)
}

func (p *Parser) getOrCreateSession(raw cowrieRawEvent, ts time.Time) *cowrieSession {
	sid := raw.Session
	if sid == "" {
		sid = "anon-" + raw.SrcIP
	}
	if existing, ok := p.sessions[sid]; ok {
		if existing.SourceIP == "" && raw.SrcIP != "" {
			existing.SourceIP = raw.SrcIP
		}
		if existing.DestPort == 0 && raw.DstPort > 0 {
			existing.DestPort = raw.DstPort
		}
		return existing
	}

	dport := raw.DstPort
	if dport == 0 {
		dport = p.defaultPort
	}
	proto := raw.Protocol
	if proto == "" {
		proto = "ssh"
	}
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	s := &cowrieSession{
		SessionID:     sid,
		RootEventUUID: newUUIDv4(),
		SourceIP:      raw.SrcIP,
		SourcePort:    raw.SrcPort,
		DestPort:      dport,
		Protocol:      proto,
		StartedAt:     ts,
		LastSeenAt:    ts,
	}
	p.sessions[sid] = s
	return s
}

func (p *Parser) buildEvent(sess *cowrieSession, ts time.Time, score int32, summary string, iocs map[string]any, payload, canaryID string) *honeypotv1.TelemetryEvent {
	if len(payload) > 32768 {
		payload = payload[:32768]
	}
	iocBytes, _ := json.Marshal(iocs)
	return &honeypotv1.TelemetryEvent{
		EventUuid:         newUUIDv4(),
		NodeId:            p.nodeID,
		SourceIp:          sess.SourceIP,
		SourcePort:        sess.SourcePort,
		DestPort:          sess.DestPort,
		Protocol:          sess.Protocol,
		TrapKind:          "cowrie",
		Persona:           sess.ClientVersion,
		Hassh:             sess.HASSH,
		RawPayload:        payload,
		ResponseSummary:   summary,
		ExtractedIocsJson: string(iocBytes),
		CanaryKeyId:       canaryID,
		SeverityScore:     score,
		ObservedAt:        timestamppb.New(ts),
	}
}

func (p *Parser) detectCanaryInText(text string) string {
	if p.keyPool == nil {
		return ""
	}
	for _, field := range strings.Fields(text) {
		token := strings.Trim(field, `"'(),;`)
		if seed, ok := p.keyPool.LookupToken(token); ok {
			return seed.GetCanaryKeyId()
		}
	}
	return ""
}

func extractValidURLs(text string) []string {
	matches := inlineURLRe.FindAllString(text, -1)
	if len(matches) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(matches))
	var out []string
	for _, raw := range matches {
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			continue
		}
		if _, dup := seen[raw]; dup {
			continue
		}
		seen[raw] = struct{}{}
		out = append(out, raw)
	}
	return out
}

func parseTimestamp(s string) time.Time {
	if s == "" {
		return time.Now().UTC()
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.999999Z"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Now().UTC()
}

func newUUIDv4() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
