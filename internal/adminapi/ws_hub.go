package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/redis/go-redis/v9"

	"github.com/harris/honeypot/internal/store"
)

// WSHub streams Redis events:live notifications to connected Admin Console tabs
// in throttled 250ms digest frames with strict Origin CSRF enforcement.
type WSHub struct {
	rd      *redis.Client
	mu      sync.Mutex
	clients map[*wsClient]struct{}
	buffer  []json.RawMessage
}

type wsClient struct {
	conn *websocket.Conn
	send chan []byte
}

func NewWSHub(rd *store.Redis) *WSHub {
	var rc *redis.Client
	if rd != nil {
		rc = rd.Client
	}
	return &WSHub{
		rd:      rc,
		clients: make(map[*wsClient]struct{}),
	}
}

// Run subscribes to Redis events:live and broadcasts throttled batches every 250ms.
func (h *WSHub) Run(ctx context.Context) {
	if h.rd != nil {
		sub := h.rd.Subscribe(ctx, store.LiveEventsChannel)
		defer func() { _ = sub.Close() }()
		ch := sub.Channel()

		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case msg, ok := <-ch:
					if !ok {
						return
					}
					h.mu.Lock()
					if len(h.buffer) < 250 {
						h.buffer = append(h.buffer, json.RawMessage(msg.Payload))
					}
					h.mu.Unlock()
				}
			}
		}()
	}

	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.flushBroadcast()
		}
	}
}

func (h *WSHub) flushBroadcast() {
	h.mu.Lock()
	if len(h.buffer) == 0 {
		h.mu.Unlock()
		return
	}
	batch := h.buffer
	h.buffer = nil
	h.mu.Unlock()

	frame, err := json.Marshal(map[string]any{
		"type":   "telemetry_batch",
		"events": batch,
	})
	if err != nil {
		return
	}

	h.mu.Lock()
	for cl := range h.clients {
		select {
		case cl.send <- frame:
		default:
			// Slow consumer dropped without backpressuring Redis or Postgres ingestion
		}
	}
	h.mu.Unlock()
}

// ServeWS authenticates origin + session cookie and streams batched telemetry events.
func (h *WSHub) ServeWS(auth *AuthManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !isSameOriginWS(r) {
			http.Error(w, "websocket cross-origin forbidden", http.StatusForbidden)
			return
		}
		if _, ok := auth.VerifyRequestSession(r); !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			// Origin already checked explicitly via isSameOriginWS above
			InsecureSkipVerify: true,
		})
		if err != nil {
			return
		}
		cl := &wsClient{conn: conn, send: make(chan []byte, 32)}
		h.mu.Lock()
		h.clients[cl] = struct{}{}
		h.mu.Unlock()

		defer func() {
			h.mu.Lock()
			delete(h.clients, cl)
			h.mu.Unlock()
			_ = conn.CloseNow()
		}()

		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()

		go func() {
			for {
				if _, _, err := conn.Read(ctx); err != nil {
					cancel()
					return
				}
			}
		}()

		for {
			select {
			case <-ctx.Done():
				return
			case msg := <-cl.send:
				wCtx, wCancel := context.WithTimeout(ctx, 5*time.Second)
				err := conn.Write(wCtx, websocket.MessageText, msg)
				wCancel()
				if err != nil {
					return
				}
			}
		}
	}
}

func isSameOriginWS(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}
