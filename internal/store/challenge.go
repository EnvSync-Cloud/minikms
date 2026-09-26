package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

const SessionChallengeTTL = 60 * time.Second

// ChallengeStore binds a single-use nonce to a certificate serial.
type ChallengeStore interface {
	Put(ctx context.Context, nonce []byte, certSerial string, ttl time.Duration) error
	Consume(ctx context.Context, nonce []byte) (certSerial string, ok bool, err error)
}

func challengeNonceKey(nonce []byte) string {
	sum := sha256.Sum256(nonce)
	return hex.EncodeToString(sum[:])
}

type challengeEntry struct {
	serial    string
	expiresAt time.Time
}

// MemoryChallengeStore is a test fake. Production uses Redis.
type MemoryChallengeStore struct {
	mu      sync.Mutex
	entries map[string]challengeEntry
}

func NewMemoryChallengeStore() *MemoryChallengeStore {
	return &MemoryChallengeStore{entries: make(map[string]challengeEntry)}
}

func (s *MemoryChallengeStore) Put(_ context.Context, nonce []byte, certSerial string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[challengeNonceKey(nonce)] = challengeEntry{
		serial:    certSerial,
		expiresAt: time.Now().Add(ttl),
	}
	return nil
}

func (s *MemoryChallengeStore) Consume(_ context.Context, nonce []byte) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := challengeNonceKey(nonce)
	entry, ok := s.entries[key]
	if !ok {
		return "", false, nil
	}
	delete(s.entries, key)
	if time.Now().After(entry.expiresAt) {
		return "", false, nil
	}
	return entry.serial, true, nil
}

func (s *RedisStore) Put(ctx context.Context, nonce []byte, certSerial string, ttl time.Duration) error {
	return s.client.Set(ctx, "session-challenge:"+challengeNonceKey(nonce), certSerial, ttl).Err()
}

func (s *RedisStore) Consume(ctx context.Context, nonce []byte) (string, bool, error) {
	serial, err := s.client.GetDel(ctx, "session-challenge:"+challengeNonceKey(nonce)).Result()
	if err == redis.Nil {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return serial, true, nil
}
