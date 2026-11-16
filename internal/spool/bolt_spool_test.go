package spool

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"

	honeypotv1 "github.com/harris/honeypot/proto/gen/honeypot/v1"
)

func TestBoltSpoolBatchSizeCapEvictionAndDeadLetter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "spool.db")
	// Set small 100 KiB cap so priority eviction triggers predictably in test
	sp, err := OpenBoltSpool(path, 100*1024)
	if err != nil {
		t.Fatalf("OpenBoltSpool: %v", err)
	}
	defer func() { _ = sp.Close() }()

	// Enqueue 15 normal events (~8 KiB each = ~120 KiB) plus 2 high-priority KEV events
	highID1 := uuid.NewString()
	highID2 := uuid.NewString()
	if err := sp.EnqueueEvent(&honeypotv1.TelemetryEvent{
		EventUuid:  highID1,
		SourceIp:   "203.0.113.5",
		TrapKind:   "webcve",
		CveId:      "CVE-2025-55182",
		IsKev:      true,
		RawPayload: strings.Repeat("A", 1024),
	}); err != nil {
		t.Fatalf("enqueue high1: %v", err)
	}

	payloadChunk := strings.Repeat("B", 8*1024)
	for i := 0; i < 14; i++ {
		if err := sp.EnqueueEvent(&honeypotv1.TelemetryEvent{
			EventUuid:     uuid.NewString(),
			SourceIp:      fmt.Sprintf("198.51.100.%d", i+1),
			TrapKind:      "webcve",
			SeverityScore: 10,
			RawPayload:    payloadChunk,
		}); err != nil {
			t.Fatalf("enqueue normal %d: %v", i, err)
		}
	}

	if err := sp.EnqueueEvent(&honeypotv1.TelemetryEvent{
		EventUuid:  highID2,
		SourceIp:   "203.0.113.6",
		TrapKind:   "llmproxy",
		CanaryKeyId: uuid.NewString(),
		RawPayload: strings.Repeat("C", 1024),
	}); err != nil {
		t.Fatalf("enqueue high2: %v", err)
	}

	// Verify byte-capped batch splitting (max 24 KiB per batch)
	seenHigh := map[string]bool{}
	var allKeys map[string][]byte
	req, keys, err := sp.DequeueBatch("node-1", 24*1024)
	if err != nil {
		t.Fatalf("DequeueBatch: %v", err)
	}
	if len(req.Events) == 0 || len(req.Events) > 6 {
		t.Fatalf("expected bounded batch count, got %d", len(req.Events))
	}
	for _, ev := range req.Events {
		seenHigh[ev.GetEventUuid()] = true
	}
	allKeys = keys

	// Ack all except highID1 which we pretend dead-lettered
	var acks []string
	var dl []string
	for id := range allKeys {
		if id == highID1 {
			dl = append(dl, id)
		} else {
			acks = append(acks, id)
		}
	}
	if err := sp.AckAndQuarantine(allKeys, acks, dl); err != nil {
		t.Fatalf("AckAndQuarantine: %v", err)
	}

	// Close & reopen spool to verify durability and dead-letter isolation
	if err := sp.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	sp2, err := OpenBoltSpool(path, 100*1024)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = sp2.Close() }()

	_, dlCount, _, err := sp2.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if dlCount != 1 {
		t.Fatalf("expected 1 dead-letter record, got %d", dlCount)
	}

	// Drain remaining batches and confirm highID2 survived low-priority eviction
	for i := 0; i < 10; i++ {
		r, k, err := sp2.DequeueBatch("node-1", 24*1024)
		if err != nil {
			t.Fatalf("drain DequeueBatch: %v", err)
		}
		if len(k) == 0 {
			break
		}
		var drainAcks []string
		for _, ev := range r.Events {
			seenHigh[ev.GetEventUuid()] = true
			drainAcks = append(drainAcks, ev.GetEventUuid())
		}
		if err := sp2.AckAndQuarantine(k, drainAcks, nil); err != nil {
			t.Fatalf("drain Ack: %v", err)
		}
	}

	if !seenHigh[highID1] || !seenHigh[highID2] {
		t.Fatalf("expected both high-priority KEV/Canary events to be preserved: seen=%v", seenHigh)
	}
}
