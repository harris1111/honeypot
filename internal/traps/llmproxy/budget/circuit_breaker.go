package budget

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// CircuitDecision reports whether a request may dial paid upstream LLM APIs or must degrade at $0.
type CircuitDecision struct {
	AllowedPaid    bool
	DenialReason   string // budget_exceeded | rate_limited | canary_not_eligible
	DailySpentUSD  float64
	DailyBudgetUSD float64
}

// BudgetConfig defines daily USD spend caps, per-CanaryKey token caps, and per-IP RPM limits.
type BudgetConfig struct {
	KeyPrefix         string
	MaxDailyUSD       float64
	MaxKeyTokensDay   int64
	MaxIPRPM          int64
	EstCostPerCallUSD float64
	EstTokensPerCall  int64
}

// Atomic Lua script checking & reserving daily micro-USD budget + per-key daily tokens + per-IP RPM.
// Returns {1, new_usd_micro} on allow, or {0, current_usd_micro, reason} on deny.
var circuitReserveLua = redis.NewScript(`
local usdKey   = KEYS[1]
local tokKey   = KEYS[2]
local rpmKey   = KEYS[3]

local costMicro = tonumber(ARGV[1])
local maxMicro  = tonumber(ARGV[2])
local estTok    = tonumber(ARGV[3])
local maxTok    = tonumber(ARGV[4])
local maxRPM    = tonumber(ARGV[5])

local curMicro = tonumber(redis.call("GET", usdKey) or "0")
if maxMicro >= 0 and (curMicro + costMicro) > maxMicro then
    return {0, curMicro, "budget_exceeded"}
end

local curTok = tonumber(redis.call("GET", tokKey) or "0")
if maxTok > 0 and (curTok + estTok) > maxTok then
    return {0, curMicro, "key_token_cap"}
end

local curRPM = tonumber(redis.call("GET", rpmKey) or "0")
if maxRPM > 0 and (curRPM + 1) > maxRPM then
    return {0, curMicro, "ip_rpm_exceeded"}
end

local nextMicro = redis.call("INCRBY", usdKey, costMicro)
redis.call("EXPIRE", usdKey, 172800)

local nextTok = redis.call("INCRBY", tokKey, estTok)
redis.call("EXPIRE", tokKey, 172800)

local nextRPM = redis.call("INCR", rpmKey)
redis.call("EXPIRE", rpmKey, 120)

return {1, nextMicro, "ok"}
`)

// CircuitBreaker enforces atomic spend and abuse bounds in Redis across all Hive workers.
type CircuitBreaker struct {
	rd  *redis.Client
	cfg BudgetConfig
}

// NewCircuitBreaker constructs a Redis-Lua atomic LLM circuit breaker.
// MaxDailyUSD == 0 disables paid upstream calls strictly ($0 cap); negative defaults to $5.00.
func NewCircuitBreaker(rd *redis.Client, cfg BudgetConfig) *CircuitBreaker {
	if cfg.KeyPrefix == "" {
		cfg.KeyPrefix = "honeypot:llm"
	}
	if cfg.MaxDailyUSD < 0 {
		cfg.MaxDailyUSD = 5.0
	}
	if cfg.MaxKeyTokensDay <= 0 {
		cfg.MaxKeyTokensDay = 100_000
	}
	if cfg.MaxIPRPM <= 0 {
		cfg.MaxIPRPM = 30
	}
	if cfg.EstCostPerCallUSD <= 0 {
		cfg.EstCostPerCallUSD = 0.002 // conservative $0.002 reservation per call
	}
	if cfg.EstTokensPerCall <= 0 {
		cfg.EstTokensPerCall = 512
	}
	return &CircuitBreaker{rd: rd, cfg: cfg}
}

// TryAcquire atomically reserves budget strictly for seeded Canary keys eligible for paid upstream calls.
func (cb *CircuitBreaker) TryAcquire(ctx context.Context, canaryKeyID, placementSource string, paidEligible bool, sourceIP string) (CircuitDecision, error) {
	// Critical Invariant (#1 / #10): Unauthenticated requests or /key/generate llm_pool keys NEVER spend paid upstream USD!
	if !paidEligible || canaryKeyID == "" || placementSource == "llm_pool" {
		return CircuitDecision{
			AllowedPaid:    false,
			DenialReason:   "canary_not_eligible",
			DailyBudgetUSD: cb.cfg.MaxDailyUSD,
		}, nil
	}
	if cb.cfg.MaxDailyUSD <= 0 {
		return CircuitDecision{
			AllowedPaid:    false,
			DenialReason:   "budget_exceeded",
			DailyBudgetUSD: 0,
		}, nil
	}
	if cb.rd == nil {
		return CircuitDecision{AllowedPaid: false, DenialReason: "redis_unavailable", DailyBudgetUSD: cb.cfg.MaxDailyUSD}, nil
	}

	now := time.Now().UTC()
	day := now.Format("2006-01-02")
	minBucket := now.Unix() / 60

	usdKey := cb.cfg.KeyPrefix + ":usd:" + day
	tokKey := fmt.Sprintf("%s:keytok:%s:%s", cb.cfg.KeyPrefix, canaryKeyID, day)
	rpmKey := fmt.Sprintf("%s:rpm:%s:%d", cb.cfg.KeyPrefix, sourceIP, minBucket)

	costMicro := int64(cb.cfg.EstCostPerCallUSD * 1_000_000)
	maxMicro := int64(cb.cfg.MaxDailyUSD * 1_000_000)

	raw, err := circuitReserveLua.Run(ctx, cb.rd, []string{usdKey, tokKey, rpmKey},
		costMicro, maxMicro, cb.cfg.EstTokensPerCall, cb.cfg.MaxKeyTokensDay, cb.cfg.MaxIPRPM).Result()
	if err != nil {
		return CircuitDecision{AllowedPaid: false, DenialReason: "lua_error", DailyBudgetUSD: cb.cfg.MaxDailyUSD}, err
	}
	slice, ok := raw.([]any)
	if !ok || len(slice) < 3 {
		return CircuitDecision{AllowedPaid: false, DenialReason: "unexpected_reply"}, fmt.Errorf("unexpected lua result %T", raw)
	}
	allowedNum, _ := slice[0].(int64)
	curMicro, _ := slice[1].(int64)
	reason, _ := slice[2].(string)

	return CircuitDecision{
		AllowedPaid:    allowedNum == 1,
		DenialReason:   reason,
		DailySpentUSD:  float64(curMicro) / 1_000_000.0,
		DailyBudgetUSD: cb.cfg.MaxDailyUSD,
	}, nil
}

// ReconcileActualCost adjusts daily spend for the reservation day after receiving actual token counts.
func (cb *CircuitBreaker) ReconcileActualCost(ctx context.Context, reservationDay string, actualUSD float64) {
	if cb == nil || cb.rd == nil {
		return
	}
	if reservationDay == "" {
		reservationDay = time.Now().UTC().Format("2006-01-02")
	}
	delta := actualUSD - cb.cfg.EstCostPerCallUSD
	deltaMicro := int64(delta * 1_000_000)
	if deltaMicro == 0 {
		return
	}
	_ = cb.rd.IncrBy(ctx, cb.cfg.KeyPrefix+":usd:"+reservationDay, deltaMicro).Err()
}

// CurrentDailySpentUSD returns today's atomic accumulated spend in USD.
func (cb *CircuitBreaker) CurrentDailySpentUSD(ctx context.Context) float64 {
	if cb == nil || cb.rd == nil {
		return 0
	}
	day := time.Now().UTC().Format("2006-01-02")
	v, _ := cb.rd.Get(ctx, cb.cfg.KeyPrefix+":usd:"+day).Int64()
	return float64(v) / 1_000_000.0
}
