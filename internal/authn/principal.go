// Package authn carries the authenticated caller for a miniKMS RPC.
package authn

import "context"

const (
	// KindUser is a caller bound from a forwarded proof. An empty Kind is the session principal.
	KindUser = "user"
)

// Principal is the caller established by a validated session token.
type Principal struct {
	TenantID string // JWT org_id or org
	ActorID  string // JWT subject, or the forwarded proof subject when Kind is user
	Role     string // JWT role; empty is not an org admin
	Kind     string // KindUser when a forwarded proof was accepted
	JKT      string // thumbprint of the accepted proof key
}

type principalContextKey struct{}

// WithPrincipal returns a context that carries p.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalContextKey{}, p)
}

// FromContext returns the principal stored by WithPrincipal.
func FromContext(ctx context.Context) (Principal, bool) {
	if ctx == nil {
		return Principal{}, false
	}
	p, ok := ctx.Value(principalContextKey{}).(Principal)
	return p, ok
}
