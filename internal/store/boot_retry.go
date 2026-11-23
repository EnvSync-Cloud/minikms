package store

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"
)

const (
	// BootRetryTimeout is the startup budget for one dependency. Postgres and
	// Redis each get this full interval; time spent waiting for one does not
	// reduce the other.
	BootRetryTimeout = 120 * time.Second
	// BootRetryInitialDelay is the first backoff after a failed ping.
	BootRetryInitialDelay = 500 * time.Millisecond
	// BootRetryMaxDelay caps the exponential backoff between pings.
	BootRetryMaxDelay = 8 * time.Second

	// bootPingTimeout bounds one dial. Without it a black-holed address can
	// sit in a single ping until the whole startup budget is gone.
	bootPingTimeout = 5 * time.Second
)

// retryPolicy controls startup ping retries. Zero values use the boot defaults.
type retryPolicy struct {
	Timeout      time.Duration
	InitialDelay time.Duration
	MaxDelay     time.Duration
	Now          func() time.Time
	Sleep        func(ctx context.Context, d time.Duration) error
	Logf         func(format string, args ...any)
}

func defaultBootRetryPolicy() retryPolicy {
	return retryPolicy{}.normalize()
}

func (p retryPolicy) normalize() retryPolicy {
	if p.Timeout <= 0 {
		p.Timeout = BootRetryTimeout
	}
	if p.InitialDelay <= 0 {
		p.InitialDelay = BootRetryInitialDelay
	}
	if p.MaxDelay <= 0 {
		p.MaxDelay = BootRetryMaxDelay
	}
	if p.MaxDelay < p.InitialDelay {
		p.MaxDelay = p.InitialDelay
	}
	if p.Now == nil {
		p.Now = time.Now
	}
	if p.Sleep == nil {
		p.Sleep = sleepContext
	}
	if p.Logf == nil {
		p.Logf = log.Printf
	}
	return p
}

func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// OpenPostgres connects to Postgres, retrying ping failures for BootRetryTimeout.
// A malformed connection string fails immediately.
func OpenPostgres(ctx context.Context, connString string) (*PostgresStore, error) {
	return openPostgres(ctx, connString, defaultBootRetryPolicy())
}

func openPostgres(ctx context.Context, connString string, policy retryPolicy) (*PostgresStore, error) {
	var opened *PostgresStore
	err := retry(ctx, "PostgreSQL", policy, func(ctx context.Context) error {
		store, err := NewPostgresStore(ctx, connString)
		if err != nil {
			return err
		}
		opened = store
		return nil
	})
	if err != nil {
		return nil, err
	}
	return opened, nil
}

// OpenRedis connects to Redis, retrying ping failures for BootRetryTimeout.
// A malformed connection URL fails immediately.
func OpenRedis(ctx context.Context, redisURL string) (*RedisStore, error) {
	return openRedis(ctx, redisURL, defaultBootRetryPolicy())
}

func openRedis(ctx context.Context, redisURL string, policy retryPolicy) (*RedisStore, error) {
	var opened *RedisStore
	err := retry(ctx, "Redis", policy, func(ctx context.Context) error {
		store, err := NewRedisStore(ctx, redisURL)
		if err != nil {
			return err
		}
		opened = store
		return nil
	})
	if err != nil {
		return nil, err
	}
	return opened, nil
}

// retry calls op until it succeeds or the policy budget elapses. The first
// failure is logged and retried. Configuration errors are returned as-is.
// An attempt is not started once the deadline has passed. op receives the
// caller's context: a successful pool keeps that context, and canceling a
// per-attempt child would close it. The store bounds each ping itself.
func retry(ctx context.Context, name string, policy retryPolicy, op func(context.Context) error) error {
	policy = policy.normalize()
	start := policy.Now()
	deadline := start.Add(policy.Timeout)
	delay := policy.InitialDelay
	var lastErr error

	unavailable := func(err error) error {
		if err == nil {
			return fmt.Errorf("%s unavailable after %s", name, policy.Timeout)
		}
		return fmt.Errorf("%s unavailable after %s: %w", name, policy.Timeout, err)
	}

	for attempt := 1; ; attempt++ {
		if err := ctx.Err(); err != nil {
			if lastErr != nil {
				return fmt.Errorf("%s connect canceled: %w", name, lastErr)
			}
			return err
		}
		if deadline.Sub(policy.Now()) <= 0 {
			return unavailable(lastErr)
		}

		lastErr = op(ctx)
		if lastErr == nil {
			if attempt > 1 {
				policy.Logf("%s connected after %d attempts", name, attempt)
			}
			return nil
		}
		if isPermanentConfigError(lastErr) {
			return lastErr
		}
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("%s connect canceled: %w", name, lastErr)
		}

		remaining := deadline.Sub(policy.Now())
		if remaining <= 0 {
			return unavailable(lastErr)
		}

		sleepFor := delay
		if sleepFor > remaining {
			sleepFor = remaining
		}
		policy.Logf("%s ping failed (attempt %d); retrying in %s", name, attempt, sleepFor.Round(time.Millisecond))
		if err := policy.Sleep(ctx, sleepFor); err != nil {
			return fmt.Errorf("%s connect canceled: %w", name, lastErr)
		}
		if delay < policy.MaxDelay {
			delay *= 2
			if delay > policy.MaxDelay {
				delay = policy.MaxDelay
			}
		}
	}
}

func isPermanentConfigError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.HasPrefix(msg, "failed to parse DB config:") ||
		strings.HasPrefix(msg, "failed to parse Redis URL:")
}
