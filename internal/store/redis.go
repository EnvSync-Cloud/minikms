package store

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisStore provides Redis operations for caching and rate limiting.
type RedisStore struct {
	client *redis.Client
}

// NewRedisStore creates a new RedisStore from a connection URL.
func NewRedisStore(ctx context.Context, redisURL string) (*RedisStore, error) {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Redis URL: %w", err)
	}
	// Negative timeouts mean "block forever" in go-redis, and a multi-minute
	// URL timeout would consume the startup budget in one ping. Unset
	// read/write timeouts stay 0 so NewClient keeps its shorter defaults.
	// Context deadlines are ignored unless ContextTimeoutEnabled is set, and
	// the URL has no switch that can turn it back off.
	if opts.DialTimeout <= 0 || opts.DialTimeout > bootPingTimeout {
		opts.DialTimeout = bootPingTimeout
	}
	if opts.ReadTimeout < 0 || opts.ReadTimeout > bootPingTimeout {
		opts.ReadTimeout = bootPingTimeout
	}
	if opts.WriteTimeout < 0 || opts.WriteTimeout > bootPingTimeout {
		opts.WriteTimeout = bootPingTimeout
	}
	opts.ContextTimeoutEnabled = true

	client := redis.NewClient(opts)
	pingCtx, pingCancel := context.WithTimeout(ctx, bootPingTimeout)
	defer pingCancel()
	if err := client.Ping(pingCtx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("failed to ping Redis: %w", err)
	}

	return &RedisStore{client: client}, nil
}

// Client returns the underlying Redis client.
func (s *RedisStore) Client() *redis.Client {
	return s.client
}

// CacheCRL stores a CRL in Redis with a TTL.
func (s *RedisStore) CacheCRL(ctx context.Context, issuerSerial string, crlDER []byte, ttl time.Duration) error {
	key := fmt.Sprintf("crl:%s", issuerSerial)
	return s.client.Set(ctx, key, crlDER, ttl).Err()
}

// GetCachedCRL retrieves a cached CRL from Redis.
func (s *RedisStore) GetCachedCRL(ctx context.Context, issuerSerial string) ([]byte, error) {
	key := fmt.Sprintf("crl:%s", issuerSerial)
	data, err := s.client.Get(ctx, key).Bytes()
	if err == redis.Nil {
		return nil, nil
	}
	return data, err
}

// Close closes the Redis connection.
func (s *RedisStore) Close() error {
	return s.client.Close()
}
