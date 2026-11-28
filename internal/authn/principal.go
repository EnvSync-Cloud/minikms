// Package authn carries the authenticated caller for a miniKMS RPC.
package authn

import "context"

const (
	// KindUser is a caller bound from a forwarded proof. An empty Kind is a member session.
	KindUser = "user"
	// KindMachine is a workload token. It is weaker than a user proof: no admin or PKI calls.
	KindMachine = "machine"
	// KindService is the org bootstrap credential or a background job.
	KindService = "service"
)

// Principal is the caller established by a validated session token.
type Principal struct {
	TenantID string // JWT org_id or org
	ActorID  string // JWT subject, or the forwarded proof subject when Kind is user
	Role     string // JWT role; empty is not an org admin
	Kind     string // KindUser when a forwarded proof was accepted
	JKT      string // thumbprint of the accepted proof key
	Scopes   []string
	AppID    string // machine tokens are limited to this app
	EnvID    string // machine tokens are limited to this environment when set
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
