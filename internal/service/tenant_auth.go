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

// requireScope rejects a caller whose session was not granted scope.
// The check does not depend on the proof mode.
func requireScope(principal authn.Principal, scope string) error {
	for _, granted := range principal.Scopes {
		if granted == scope {
			return nil
		}
	}
	return NewDomainError(ErrorPermissionDenied, scope+" permission required", nil)
}

// requirePrincipal rejects a missing caller. An empty tenant or actor is not
// an authenticated principal.
func requirePrincipal(ctx context.Context) (authn.Principal, error) {
	principal, ok := authn.FromContext(ctx)
	if !ok || principal.TenantID == "" || principal.ActorID == "" {
		return authn.Principal{}, NewDomainError(ErrorUnauthenticated, "authentication required", nil)
	}
	return principal, nil
}

// authorizeMemberSessionAccess allows a member to manage only their own
// sessions. An org admin may manage other members in that same org.
func authorizeMemberSessionAccess(ctx context.Context, memberID, orgID string) (authn.Principal, error) {
	principal, err := requirePrincipal(ctx)
	if err != nil {
		return authn.Principal{}, err
	}
	if err := requireFields(
		requiredField("member_id", memberID),
		requiredField("org_id", orgID),
	); err != nil {
		return authn.Principal{}, err
	}
	if principal.TenantID != orgID {
		return authn.Principal{}, NewDomainError(ErrorPermissionDenied, "tenant access denied", nil)
	}
	if memberID != principal.ActorID && !orgAdminRole(principal.Role) {
		return authn.Principal{}, NewDomainError(ErrorPermissionDenied, "member session access denied", nil)
	}
	return principal, nil
}

func orgAdminRole(role string) bool {
	return role == "admin" || role == "master"
}
