package ratelimit

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// RateLimiter implements sliding-window rate limiting via Redis (Issue #6).
// No in-memory fallback — Redis is a hard dependency.
type RateLimiter struct {
	client     *redis.Client
	maxPerSec  int
	burstLimit int
	window     time.Duration
}

// NewRateLimiter creates a new Redis-backed rate limiter.
func NewRateLimiter(client *redis.Client, maxPerSec, burstLimit int) *RateLimiter {
	return &RateLimiter{
		client:     client,
		maxPerSec:  maxPerSec,
		burstLimit: burstLimit,
		window:     time.Second,
	}
}

// Allow checks if a request from the given key is allowed under the rate limit.
// Uses a sorted set with timestamps as scores for a sliding window approach.
func (r *RateLimiter) Allow(ctx context.Context, key string) (bool, error) {
	now := time.Now()
	windowStart := now.Add(-r.window)

	redisKey := fmt.Sprintf("ratelimit:%s", key)

	pipe := r.client.Pipeline()

	// Remove entries outside the sliding window
	pipe.ZRemRangeByScore(ctx, redisKey, "-inf", fmt.Sprintf("%d", windowStart.UnixNano()))

	// Count entries in the current window
	countCmd := pipe.ZCard(ctx, redisKey)

	// Add current request
	pipe.ZAdd(ctx, redisKey, redis.Z{
		Score:  float64(now.UnixNano()),
		Member: fmt.Sprintf("%d", now.UnixNano()),
	})

	// Set expiry on the key to auto-cleanup
	pipe.Expire(ctx, redisKey, r.window*2)

	_, err := pipe.Exec(ctx)
	if err != nil {
		return false, fmt.Errorf("rate limit check failed: %w", err)
	}

	count := countCmd.Val()
	return count < int64(r.burstLimit), nil
}

// Reset clears the rate limit for a given key.
func (r *RateLimiter) Reset(ctx context.Context, key string) error {
	return r.client.Del(ctx, fmt.Sprintf("ratelimit:%s", key)).Err()
}
