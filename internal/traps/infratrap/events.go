package infratrap

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"google.golang.org/protobuf/types/known/timestamppb"

	honeypotv1 "github.com/harris/honeypot/proto/gen/honeypot/v1"
)

// EventSink receives telemetry events and extracted URLs from native Go protocol traps.
type EventSink func(ev *honeypotv1.TelemetryEvent, urls []string)

func newInfraEvent(nodeID, remoteAddr string, destPort uint32, proto, persona, cveID string, kev bool, score int32, payload, summary string, iocs map[string]any, ja4, ja4h string) *honeypotv1.TelemetryEvent {
	ip, _, _ := net.SplitHostPort(remoteAddr)
	if ip == "" {
		ip = strings.Trim(remoteAddr, "[]")
	}
	if len(payload) > 32768 {
		payload = payload[:32768]
	}
	iocBytes, _ := json.Marshal(iocs)
	return &honeypotv1.TelemetryEvent{
		EventUuid:         randomUUID(),
		NodeId:            nodeID,
		SourceIp:          ip,
		DestPort:          destPort,
		Protocol:          proto,
		TrapKind:          "infratrap",
		Persona:           persona,
		CveId:             cveID,
		IsKev:             kev,
		Ja4:               ja4,
		Ja4H:              ja4h,
		RawPayload:        payload,
		ResponseSummary:   summary,
		ExtractedIocsJson: string(iocBytes),
		SeverityScore:     score,
		ObservedAt:        timestamppb.Now(),
	}
}

func randomUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
