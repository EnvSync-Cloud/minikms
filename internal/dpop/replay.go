package dpop

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// ErrReplayed means this proof was already used for a different request, or the call budget is spent.
var ErrReplayed = errors.New("proof already used")

// ErrStore means the shared replay store could not answer. Callers must not accept the call.
var ErrStore = errors.New("replay store unavailable")

// Replay records proof use so two replicas share one budget.
type Replay interface {
	Admit(ctx context.Context, jti, requestID, proofHash string, maxCalls int, ttl time.Duration) error
}

type memoryEntry struct {
	value   string
	count   int
	expires time.Time
}

// MemoryReplay is the in-process store used by tests.
type MemoryReplay struct {
	mu      sync.Mutex
	entries map[string]memoryEntry
	now     func() time.Time
}

func NewMemoryReplay() *MemoryReplay {
	return &MemoryReplay{entries: map[string]memoryEntry{}, now: time.Now}
}

func (m *MemoryReplay) Admit(_ context.Context, jti, requestID, proofHash string, maxCalls int, ttl time.Duration) error {
	if jti == "" || requestID == "" || proofHash == "" || maxCalls <= 0 {
		return ErrReplayed
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	key := "dpop:kms:jti:" + jti
	current, ok := m.entries[key]
	if ok && !current.expires.After(now) {
		ok = false
	}
	value := requestID + "|" + proofHash
	if !ok {
		m.entries[key] = memoryEntry{value: value, count: 1, expires: now.Add(ttl)}
		return nil
	}
	if current.value != value {
		return ErrReplayed
	}
	if current.count >= maxCalls {
		return ErrReplayed
	}
	current.count++
	m.entries[key] = current
	return nil
}

// RedisReplay stores proof use in the shared Redis the server already requires.
type RedisReplay struct {
	client *redis.Client
}

func NewRedisReplay(client *redis.Client) *RedisReplay {
	return &RedisReplay{client: client}
}

func (r *RedisReplay) Admit(ctx context.Context, jti, requestID, proofHash string, maxCalls int, ttl time.Duration) error {
	if r == nil || r.client == nil {
		return ErrStore
	}
	if jti == "" || requestID == "" || proofHash == "" || maxCalls <= 0 {
		return ErrReplayed
	}
	key := "dpop:kms:jti:" + jti
	value := requestID + "|" + proofHash
	ok, err := r.client.SetNX(ctx, key, value, ttl).Result()
	if err != nil {
		return ErrStore
	}
	if ok {
		return nil
	}
	got, err := r.client.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return ErrReplayed
		}
		return ErrStore
	}
	if got != value {
		return ErrReplayed
	}
	countKey := "dpop:kms:cnt:" + jti
	n, err := r.client.Incr(ctx, countKey).Result()
	if err != nil {
		return ErrStore
	}
	if n == 1 {
		if err := r.client.Expire(ctx, countKey, ttl).Err(); err != nil {
			return ErrStore
		}
	}
	// The first SETNX is call 1. Each later INCR is one more call.
	if int(n)+1 > maxCalls {
		return ErrReplayed
	}
	return nil
}
