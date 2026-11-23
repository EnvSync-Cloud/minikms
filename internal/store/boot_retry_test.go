package store

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestBootRetryBudget(t *testing.T) {
	if BootRetryTimeout < 120*time.Second {
		t.Fatalf("BootRetryTimeout = %s, want at least 120s", BootRetryTimeout)
	}
	if BootRetryInitialDelay <= 0 || BootRetryMaxDelay < BootRetryInitialDelay {
		t.Fatalf("backoff initial=%s max=%s", BootRetryInitialDelay, BootRetryMaxDelay)
	}
	policy := defaultBootRetryPolicy()
	if policy.Timeout != BootRetryTimeout || policy.InitialDelay != BootRetryInitialDelay || policy.MaxDelay != BootRetryMaxDelay {
		t.Fatalf("default policy timeout=%s initial=%s max=%s", policy.Timeout, policy.InitialDelay, policy.MaxDelay)
	}
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func TestRetry_ExponentialBackoffUntilTimeout(t *testing.T) {
	clock := &fakeClock{now: time.Unix(0, 0).UTC()}
	var sleeps []time.Duration
	calls := 0
	err := retry(context.Background(), "PostgreSQL", retryPolicy{
		Timeout:      BootRetryTimeout,
		InitialDelay: BootRetryInitialDelay,
		MaxDelay:     BootRetryMaxDelay,
		Now:          clock.Now,
		Sleep: func(ctx context.Context, d time.Duration) error {
			sleeps = append(sleeps, d)
			clock.Advance(d)
			return nil
		},
		Logf: func(string, ...any) {},
	}, func(context.Context) error {
		calls++
		return errors.New("dial tcp: connect: connection refused")
	})
	if err == nil || !strings.Contains(err.Error(), "PostgreSQL unavailable after "+BootRetryTimeout.String()) {
		t.Fatalf("err = %v", err)
	}
	if calls != len(sleeps)+1 {
		t.Fatalf("calls = %d, sleeps = %d", calls, len(sleeps))
	}
	if len(sleeps) < 2 {
		t.Fatalf("sleeps = %v", sleeps)
	}

	var sum time.Duration
	delay := BootRetryInitialDelay
	for i, got := range sleeps {
		sum += got
		want := delay
		last := i == len(sleeps)-1
		if !last && got != want {
			t.Fatalf("sleep %d = %s, want %s", i, got, want)
		}
		if last && (got <= 0 || got > want) {
			t.Fatalf("last sleep = %s, want in (0, %s]", got, want)
		}
		if delay < BootRetryMaxDelay {
			delay *= 2
			if delay > BootRetryMaxDelay {
				delay = BootRetryMaxDelay
			}
		}
	}
	if sum != BootRetryTimeout {
		t.Fatalf("slept %s, want %s", sum, BootRetryTimeout)
	}
	if !clock.Now().Equal(time.Unix(0, 0).UTC().Add(BootRetryTimeout)) {
		t.Fatalf("clock advanced to %s", clock.Now())
	}
}

func TestRetry_SucceedsAfterTransientFailures(t *testing.T) {
	var sleeps []time.Duration
	calls := 0
	var connected string
	err := retry(context.Background(), "Redis", retryPolicy{
		Timeout:      BootRetryTimeout,
		InitialDelay: BootRetryInitialDelay,
		MaxDelay:     BootRetryMaxDelay,
		Now:          func() time.Time { return time.Unix(0, 0) },
		Sleep: func(ctx context.Context, d time.Duration) error {
			sleeps = append(sleeps, d)
			return nil
		},
		Logf: func(format string, args ...any) {
			connected = fmt.Sprintf(format, args...)
		},
	}, func(context.Context) error {
		calls++
		if calls < 3 {
			return errors.New("connection refused")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 3 {
		t.Fatalf("calls = %d, want 3", calls)
	}
	if len(sleeps) != 2 || sleeps[0] != BootRetryInitialDelay || sleeps[1] != BootRetryInitialDelay*2 {
		t.Fatalf("sleeps = %v", sleeps)
	}
	if connected != "Redis connected after 3 attempts" {
		t.Fatalf("log = %q", connected)
	}
}

func TestRetry_ConfigErrorDoesNotRetry(t *testing.T) {
	calls := 0
	err := retry(context.Background(), "PostgreSQL", defaultBootRetryPolicy(), func(context.Context) error {
		calls++
		return fmt.Errorf("failed to parse DB config: %w", errors.New("invalid dsn"))
	})
	if err == nil || !strings.HasPrefix(err.Error(), "failed to parse DB config:") {
		t.Fatalf("err = %v", err)
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want 1", calls)
	}
}

func TestRetry_CanceledContextStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	err := retry(ctx, "Redis", retryPolicy{
		Timeout:      BootRetryTimeout,
		InitialDelay: time.Second,
		MaxDelay:     time.Second,
		Sleep: func(ctx context.Context, d time.Duration) error {
			cancel()
			return ctx.Err()
		},
	}, func(context.Context) error {
		calls++
		return errors.New("connection refused")
	})
	if err == nil || !strings.Contains(err.Error(), "connect canceled") {
		t.Fatalf("err = %v", err)
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want 1", calls)
	}

	cancel()
	calls = 0
	err = retry(ctx, "Redis", defaultBootRetryPolicy(), func(context.Context) error {
		calls++
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if calls != 0 {
		t.Fatalf("canceled retry called op %d times", calls)
	}
}

func TestOpenPostgres_MalformedURLDoesNotRetry(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	_, err := OpenPostgres(ctx, "://")
	if err == nil {
		t.Fatal("expected parse error")
	}
	if errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "unavailable after") {
		t.Fatalf("malformed URL was retried: %v", err)
	}
	if !strings.Contains(err.Error(), "failed to parse DB config") {
		t.Fatalf("err = %v", err)
	}
	if time.Since(start) >= time.Second {
		t.Fatalf("parse failure took %s", time.Since(start))
	}
}

func TestOpenRedis_MalformedURLDoesNotRetry(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := OpenRedis(ctx, "not-a-redis-url")
	if err == nil {
		t.Fatal("expected parse error")
	}
	if errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "unavailable after") {
		t.Fatalf("malformed URL was retried: %v", err)
	}
	if !strings.Contains(err.Error(), "failed to parse Redis URL") {
		t.Fatalf("err = %v", err)
	}
}

func TestOpenPostgres_RefusedPortRetriesUntilDeadline(t *testing.T) {
	assertRefusedRetries(t, func(ctx context.Context, port int, policy retryPolicy) error {
		url := fmt.Sprintf("postgres://minikms_test@127.0.0.1:%d/minikms_test?sslmode=disable", port)
		_, err := openPostgres(ctx, url, policy)
		return err
	}, "PostgreSQL")
}

func TestOpenRedis_RefusedPortRetriesUntilDeadline(t *testing.T) {
	assertRefusedRetries(t, func(ctx context.Context, port int, policy retryPolicy) error {
		url := fmt.Sprintf("redis://127.0.0.1:%d/0", port)
		_, err := openRedis(ctx, url, policy)
		return err
	}, "Redis")
}

func assertRefusedRetries(t *testing.T, open func(context.Context, int, retryPolicy) error, name string) {
	t.Helper()
	port := refusedPort(t)
	const budget = 1500 * time.Millisecond
	var lines []string
	policy := retryPolicy{
		Timeout:      budget,
		InitialDelay: 100 * time.Millisecond,
		MaxDelay:     200 * time.Millisecond,
		Logf: func(format string, args ...any) {
			lines = append(lines, fmt.Sprintf(format, args...))
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	start := time.Now()
	err := open(ctx, port, policy)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected connection error")
	}
	if elapsed < budget {
		t.Fatalf("returned after %s, want at least %s; err=%v", elapsed, budget, err)
	}
	if !strings.Contains(err.Error(), name+" unavailable after") {
		t.Fatalf("err = %v", err)
	}
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, name+" ping failed (attempt 1)") || !strings.Contains(joined, name+" ping failed (attempt 2)") {
		t.Fatalf("retry log:\n%s\nerr=%v", joined, err)
	}
}

func refusedPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}
