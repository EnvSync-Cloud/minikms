package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

const sessionChallengeTTL = 60 * time.Second

// ChallengeStore binds a single-use nonce to a certificate serial.
type ChallengeStore interface {
	Put(ctx context.Context, nonce []byte, certSerial string, ttl time.Duration) error
	Consume(ctx context.Context, nonce []byte) (certSerial string, ok bool, err error)
}

type challengeEntry struct {
	serial    string
	expiresAt time.Time
}

// MemoryChallengeStore is for tests and single-replica fallback.
type MemoryChallengeStore struct {
	mu      sync.Mutex
	entries map[string]challengeEntry
}

func NewMemoryChallengeStore() *MemoryChallengeStore {
	return &MemoryChallengeStore{entries: make(map[string]challengeEntry)}
}

func challengeKey(nonce []byte) string {
	sum := sha256.Sum256(nonce)
	return hex.EncodeToString(sum[:])
}

func (s *MemoryChallengeStore) Put(_ context.Context, nonce []byte, certSerial string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[challengeKey(nonce)] = challengeEntry{
		serial:    certSerial,
		expiresAt: time.Now().Add(ttl),
	}
	return nil
}

func (s *MemoryChallengeStore) Consume(_ context.Context, nonce []byte) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := challengeKey(nonce)
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
