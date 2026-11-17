// Package authn carries the authenticated caller for a miniKMS RPC.
package authn

import "context"

// Principal is the caller established by a validated session token.
type Principal struct {
	TenantID string // JWT org_id
	ActorID  string // JWT subject
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
