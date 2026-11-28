package dpop

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// fixture: two-replica-dpop-replay
// Two servers share one Redis. A proof recorded on replica A is enforced on replica B.
func TestFixtureTwoReplicaReplay(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	replicaA := NewRedisReplay(client)
	replicaB := NewRedisReplay(client)
	ctx := context.Background()
	ttl := time.Minute

	if err := replicaA.Admit(ctx, "proof-jti", "request-1", "hash-1", 16, ttl); err != nil {
		t.Fatal(err)
	}
	if err := replicaB.Admit(ctx, "proof-jti", "request-2", "hash-1", 16, ttl); err != ErrReplayed {
		t.Fatalf("different request id on replica B = %v", err)
	}
	if err := replicaB.Admit(ctx, "proof-jti", "request-1", "hash-2", 16, ttl); err != ErrReplayed {
		t.Fatalf("different proof hash on replica B = %v", err)
	}

	if err := replicaA.Admit(ctx, "budget-jti", "same-request", "same-hash", 2, ttl); err != nil {
		t.Fatal(err)
	}
	if err := replicaB.Admit(ctx, "budget-jti", "same-request", "same-hash", 2, ttl); err != nil {
		t.Fatalf("second replica within budget = %v", err)
	}
	if err := replicaA.Admit(ctx, "budget-jti", "same-request", "same-hash", 2, ttl); err != ErrReplayed {
		t.Fatalf("call past the shared budget = %v", err)
	}

	server.Close()
	if err := replicaB.Admit(ctx, "fresh-jti", "request-1", "hash-1", 16, ttl); err != ErrStore {
		t.Fatalf("unavailable store = %v, want ErrStore", err)
	}
}

func TestProductionReplayIsRedis(t *testing.T) {
	source, err := os.ReadFile("../../cmd/minikms/main.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	if !strings.Contains(text, "dpop.NewRedisReplay(") {
		t.Fatal("production server does not use the shared Redis replay store")
	}
	if strings.Contains(text, "NewMemoryReplay") {
		t.Fatal("production server has an in-memory replay accept path")
	}
}
