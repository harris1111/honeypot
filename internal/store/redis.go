package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	LiveEventsChannel = "events:live"
	nodeCertCachePref = "node:cert:"
)

// Redis wraps go-redis for PubSub live streaming, node cert revocation cache, LLM budgets, and enrichment caches.
type Redis struct {
	Client *redis.Client
}

// OpenRedis creates a verified Redis client from addr/URL.
func OpenRedis(ctx context.Context, addr string) (*Redis, error) {
	var opt *redis.Options
	if len(addr) > 8 && (addr[:8] == "redis://" || addr[:9] == "rediss://") {
		var err error
		opt, err = redis.ParseURL(addr)
		if err != nil {
			return nil, fmt.Errorf("parse redis url: %w", err)
		}
	} else {
		opt = &redis.Options{Addr: addr}
	}
	c := redis.NewClient(opt)
	if err := c.Ping(ctx).Err(); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("ping redis: %w", err)
	}
	return &Redis{Client: c}, nil
}

// Close closes the Redis connection pool.
func (r *Redis) Close() error {
	if r == nil || r.Client == nil {
		return nil
	}
	return r.Client.Close()
}

// PublishLiveEvent broadcasts a summarized event JSON payload to the Admin WebSocket hub.
func (r *Redis) PublishLiveEvent(ctx context.Context, payload any) error {
	if r == nil || r.Client == nil {
		return nil
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return r.Client.Publish(ctx, LiveEventsChannel, string(b)).Err()
}

// SubscribeLiveEvents opens a Redis PubSub subscription for live attack events.
func (r *Redis) SubscribeLiveEvents(ctx context.Context) *redis.PubSub {
	return r.Client.Subscribe(ctx, LiveEventsChannel)
}

// CacheNodeCertState stores node cert serial & status for fast mTLS interceptor validation.
func (r *Redis) CacheNodeCertState(ctx context.Context, st NodeCertState, ttl time.Duration) error {
	if r == nil || r.Client == nil {
		return nil
	}
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return r.Client.Set(ctx, nodeCertCachePref+st.NodeID, string(b), ttl).Err()
}

// GetCachedNodeCertState retrieves cached cert state; returns (state, false, nil) on cache miss.
func (r *Redis) GetCachedNodeCertState(ctx context.Context, nodeID string) (NodeCertState, bool, error) {
	if r == nil || r.Client == nil {
		return NodeCertState{}, false, nil
	}
	val, err := r.Client.Get(ctx, nodeCertCachePref+nodeID).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return NodeCertState{}, false, nil
		}
		return NodeCertState{}, false, err
	}
	var st NodeCertState
	if err := json.Unmarshal([]byte(val), &st); err != nil {
		return NodeCertState{}, false, err
	}
	return st, true, nil
}

// InvalidateNodeCertState removes cached cert state immediately upon revocation or cert rotation.
func (r *Redis) InvalidateNodeCertState(ctx context.Context, nodeID string) error {
	if r == nil || r.Client == nil {
		return nil
	}
	return r.Client.Del(ctx, nodeCertCachePref+nodeID).Err()
}
