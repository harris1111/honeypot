package heraldingparser

import (
	"encoding/csv"
	"encoding/json"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	honeypotv1 "github.com/harris/honeypot/proto/gen/honeypot/v1"
)

// Parser parses Heralding auth.csv and log_session.json lines into normalized TelemetryEvents.
type Parser struct {
	nodeID      string
	defaultPort uint32
}

// NewParser builds a Heralding telemetry parser for one node.
func NewParser(nodeID string, defaultPort uint32) *Parser {
	if defaultPort == 0 {
		defaultPort = 21
	}
	return &Parser{nodeID: nodeID, defaultPort: defaultPort}
}

type heraldingSessionLog struct {
	Timestamp       string  `json:"timestamp"`
	Duration        float64 `json:"duration"`
	SessionID       string  `json:"session_id"`
	SourceIP        string  `json:"source_ip"`
	SourcePort      uint32  `json:"source_port"`
	DestinationPort uint32  `json:"destination_port"`
	Protocol        string  `json:"protocol"`
	NumAuthAttempts int     `json:"num_auth_attempts"`
	SessionEnded    bool    `json:"session_ended"`
}

// ParseAuthCSVLine parses a single line from Heralding's auth.csv.
// Header lines and malformed rows return (nil, nil).
func (p *Parser) ParseAuthCSVLine(line string) (*honeypotv1.TelemetryEvent, error) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return nil, nil
	}
	rec, err := csv.NewReader(strings.NewReader(trimmed)).Read()
	if err != nil || len(rec) < 10 {
		return nil, err
	}
	// CSV header: timestamp,auth_id,session_id,source_ip,source_port,destination_ip,destination_port,protocol,username,password,password_hash
	if strings.EqualFold(strings.TrimSpace(rec[0]), "timestamp") {
		return nil, nil
	}

	srcIP := strings.TrimSpace(rec[3])
	if _, parseErr := netip.ParseAddr(srcIP); parseErr != nil {
		return nil, nil
	}
	srcPort, _ := strconv.ParseUint(strings.TrimSpace(rec[4]), 10, 32)
	dstPortRaw, _ := strconv.ParseUint(strings.TrimSpace(rec[6]), 10, 32)
	proto := strings.ToLower(strings.TrimSpace(rec[7]))
	if proto == "" {
		proto = "ftp"
	}
	dstPort := mapExternalPort(uint32(dstPortRaw), proto, p.defaultPort)
	username := rec[8]
	password := rec[9]

	payload := "user=" + sanitizeInline(username) + " pass=" + sanitizeInline(password)
	if len(payload) > 32768 {
		payload = payload[:32768]
	}
	iocs, _ := json.Marshal(map[string]any{
		"session_id": rec[2],
		"auth_id":    rec[1],
		"protocol":   proto,
		"username":   username,
		"password":   password,
	})

	return &honeypotv1.TelemetryEvent{
		EventUuid:         uuid.NewString(),
		NodeId:            p.nodeID,
		SourceIp:          srcIP,
		SourcePort:        uint32(srcPort),
		DestPort:          dstPort,
		Protocol:          proto,
		TrapKind:          "heralding",
		Persona:           "heralding-" + proto,
		RawPayload:        payload,
		ResponseSummary:   proto + " credential probe captured (user=" + sanitizeInline(username) + ")",
		ExtractedIocsJson: string(iocs),
		SeverityScore:     55,
		ObservedAt:        timestamppb.New(parseHeraldingTime(rec[0])),
	}, nil
}

// ParseSessionJSONLine parses a session_ended line from Heralding's log_session.json
// when num_auth_attempts == 0 so unauthenticated port/banner scanners are also recorded.
func (p *Parser) ParseSessionJSONLine(line string) (*honeypotv1.TelemetryEvent, error) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || !strings.HasPrefix(trimmed, "{") {
		return nil, nil
	}
	var raw heraldingSessionLog
	if err := json.Unmarshal([]byte(trimmed), &raw); err != nil {
		return nil, err
	}
	if raw.NumAuthAttempts > 0 {
		// Credential attempts are captured immediately via auth.csv.
		return nil, nil
	}
	if _, err := netip.ParseAddr(strings.TrimSpace(raw.SourceIP)); err != nil {
		return nil, nil
	}
	proto := strings.ToLower(strings.TrimSpace(raw.Protocol))
	if proto == "" {
		proto = "ftp"
	}
	dstPort := mapExternalPort(raw.DestinationPort, proto, p.defaultPort)
	iocs, _ := json.Marshal(map[string]any{
		"session_id": raw.SessionID,
		"protocol":   proto,
		"duration":   raw.Duration,
	})
	return &honeypotv1.TelemetryEvent{
		EventUuid:         uuid.NewString(),
		NodeId:            p.nodeID,
		SourceIp:          strings.TrimSpace(raw.SourceIP),
		SourcePort:        raw.SourcePort,
		DestPort:          dstPort,
		Protocol:          proto,
		TrapKind:          "heralding",
		Persona:           "heralding-" + proto,
		RawPayload:        trimmed,
		ResponseSummary:   proto + " unauthenticated session probe",
		ExtractedIocsJson: string(iocs),
		SeverityScore:     25,
		ObservedAt:        timestamppb.New(parseHeraldingTime(raw.Timestamp)),
	}, nil
}

func mapExternalPort(internalPort uint32, proto string, fallback uint32) uint32 {
	switch internalPort {
	case 2121:
		return 21
	case 2525:
		return 25
	case 2110:
		return 110
	case 2143:
		return 143
	}
	if internalPort > 0 {
		return internalPort
	}
	switch proto {
	case "ftp":
		return 21
	case "smtp":
		return 25
	case "pop3":
		return 110
	case "imap":
		return 143
	default:
		return fallback
	}
}

func parseHeraldingTime(raw string) time.Time {
	s := strings.TrimSpace(raw)
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05.999999", "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Now().UTC()
}

func sanitizeInline(s string) string {
	return strings.NewReplacer("\r", "", "\n", " ", "\x00", "").Replace(s)
}
