package notify

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDispatcherAntiFloodDigestBatching(t *testing.T) {
	var calls atomic.Int32
	var lastPayload string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		lastPayload = string(b)
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	d := NewDispatcher(Config{
		GenericWebhook: srv.URL,
		DigestWindow:   10 * time.Millisecond,
	})
	for i := 0; i < 5; i++ {
		d.Enqueue(AlertEvent{
			RuleKey:  "canary_used",
			Severity: "critical",
			Title:    "Canary Key Triggered",
			SourceIP: "198.51.100.1",
			Details:  "sk-proj reuse",
		})
	}
	sent := d.Flush(context.Background())
	if sent != 1 || calls.Load() != 1 {
		t.Fatalf("expected 5 burst events collapsed into 1 digest webhook call, sent=%d calls=%d", sent, calls.Load())
	}
	if !strings.Contains(lastPayload, "DIGEST x5") {
		t.Fatalf("expected digest summary in payload, got %s", lastPayload)
	}
}
