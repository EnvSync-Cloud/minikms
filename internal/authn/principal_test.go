package authn_test

import (
	"context"
	"testing"

	"github.com/envsync-cloud/minikms/internal/authn"
)

func TestPrincipalRoundTrip(t *testing.T) {
	want := authn.Principal{TenantID: "org-1", ActorID: "member-1", Role: "admin"}
	ctx := authn.WithPrincipal(context.Background(), want)

	got, ok := authn.FromContext(ctx)
	if !ok {
		t.Fatal("principal missing from context")
	}
	if got != want {
		t.Fatalf("principal = %+v, want %+v", got, want)
	}

	if _, ok := authn.FromContext(context.Background()); ok {
		t.Fatal("empty context reported a principal")
	}
}
