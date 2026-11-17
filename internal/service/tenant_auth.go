package service

import (
	"context"

	"github.com/envsync-cloud/minikms/internal/authn"
)

// authenticatedTenant returns the caller only when the authenticated tenant
// matches the requested tenant. The request tenant is not authority.
func authenticatedTenant(ctx context.Context, requestTenantID string) (authn.Principal, error) {
	principal, ok := authn.FromContext(ctx)
	if !ok {
		return authn.Principal{}, NewDomainError(ErrorUnauthenticated, "authentication required", nil)
	}
	if principal.TenantID != requestTenantID {
		return authn.Principal{}, NewDomainError(ErrorPermissionDenied, "tenant access denied", nil)
	}
	return principal, nil
}
