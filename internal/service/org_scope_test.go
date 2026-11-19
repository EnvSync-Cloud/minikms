package service

import (
	"context"
	"testing"
	"time"

	"github.com/envsync-cloud/minikms/internal/auth"
	"github.com/envsync-cloud/minikms/internal/authn"
)

func principalCtx(tenantID, actorID, role string) context.Context {
	return authn.WithPrincipal(context.Background(), authn.Principal{
		TenantID: tenantID,
		ActorID:  actorID,
		Role:     role,
	})
}

func TestListSessions_Unauthenticated(t *testing.T) {
	svc, _, _, _ := setupTestSessionService(t)
	for _, tc := range unauthenticatedCases() {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := svc.ListSessions(tc.ctx, "member-1", "org-a")
			if resp != nil {
				t.Fatal("listed sessions without a principal")
			}
			assertErrorKind(t, err, ErrorUnauthenticated)
		})
	}
}

func TestRevokeMemberSessions_Unauthenticated(t *testing.T) {
	svc, _, _, _ := setupTestSessionService(t)
	for _, tc := range unauthenticatedCases() {
		t.Run(tc.name, func(t *testing.T) {
			count, err := svc.RevokeMemberSessions(tc.ctx, "member-1", "org-a")
			if count != 0 {
				t.Fatalf("revoked %d sessions without a principal", count)
			}
			assertErrorKind(t, err, ErrorUnauthenticated)
		})
	}
}

func TestGetAuditLogs_Unauthenticated(t *testing.T) {
	svc, logger := setupAuditService(t)
	_ = logger.Log(context.Background(), "org-a", "encrypt", "member-1", "org-a secret", "")
	for _, tc := range unauthenticatedCases() {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := svc.GetAuditLogs(tc.ctx, &GetAuditLogsRequest{OrgID: "org-a", Limit: 10})
			if resp != nil {
				t.Fatal("returned audit logs without a principal")
			}
			assertErrorKind(t, err, ErrorUnauthenticated)
		})
	}
}

func TestListSessions_CrossOrgDenied(t *testing.T) {
	svc, _, _, policy := setupTestSessionService(t)
	hash := auth.HashSubject("member-b")
	policy.addToken("org-b", hash, &auth.TokenEntry{JTI: "org-b-session", ExpiresAt: time.Now().Add(time.Hour)})

	resp, err := svc.ListSessions(principalCtx("org-a", "admin-a", "admin"), "member-b", "org-b")
	if resp != nil {
		t.Fatal("listed another org's sessions")
	}
	assertErrorKind(t, err, ErrorPermissionDenied)
}

func TestRevokeMemberSessions_CrossOrgDenied(t *testing.T) {
	svc, _, _, policy := setupTestSessionService(t)
	hash := auth.HashSubject("member-b")
	tokenB := &auth.TokenEntry{JTI: "org-b-session", ExpiresAt: time.Now().Add(time.Hour)}
	policy.addToken("org-b", hash, tokenB)

	count, err := svc.RevokeMemberSessions(principalCtx("org-a", "admin-a", "admin"), "member-b", "org-b")
	if count != 0 {
		t.Fatalf("revoked %d sessions in another org", count)
	}
	assertErrorKind(t, err, ErrorPermissionDenied)
	if tokenB.Revoked {
		t.Fatal("org B session was revoked by an org A caller")
	}
}

func TestGetAuditLogs_CrossOrgDenied(t *testing.T) {
	svc, logger := setupAuditService(t)
	ctx := context.Background()
	_ = logger.Log(ctx, "org-a", "encrypt", "member-a", "org-a entry", "")
	_ = logger.Log(ctx, "org-b", "encrypt", "member-b", "org-b entry", "")

	resp, err := svc.GetAuditLogs(principalCtx("org-a", "member-a", "member"), &GetAuditLogsRequest{
		OrgID:  "org-b",
		Limit:  10,
		Offset: 0,
	})
	if resp != nil {
		t.Fatal("returned audit logs for another org")
	}
	assertErrorKind(t, err, ErrorPermissionDenied)
}

func TestGetAuditLogs_UsesPrincipalTenant(t *testing.T) {
	svc, logger := setupAuditService(t)
	ctx := context.Background()
	_ = logger.Log(ctx, "org-a", "encrypt", "member-a", "org-a entry", "")
	_ = logger.Log(ctx, "org-b", "encrypt", "member-b", "org-b entry", "")

	resp, err := svc.GetAuditLogs(principalCtx("org-a", "member-a", "member"), &GetAuditLogsRequest{
		Limit:  10,
		Offset: 0,
	})
	if err != nil {
		t.Fatalf("GetAuditLogs: %v", err)
	}
	if len(resp.Entries) != 1 || resp.Entries[0].OrgID != "org-a" {
		t.Fatalf("entries = %+v, want only org-a", resp.Entries)
	}
}

func TestListSessions_NonAdminOtherMember(t *testing.T) {
	svc, _, _, policy := setupTestSessionService(t)
	hash := auth.HashSubject("member-b")
	policy.addToken("org-a", hash, &auth.TokenEntry{JTI: "other-member", ExpiresAt: time.Now().Add(time.Hour)})

	for _, role := range []string{"member", ""} {
		t.Run(roleName(role), func(t *testing.T) {
			resp, err := svc.ListSessions(principalCtx("org-a", "member-a", role), "member-b", "org-a")
			if resp != nil {
				t.Fatal("non-admin listed another member's sessions")
			}
			assertErrorKind(t, err, ErrorPermissionDenied)
		})
	}
}

func TestRevokeMemberSessions_NonAdminOtherMember(t *testing.T) {
	svc, _, _, policy := setupTestSessionService(t)
	hash := auth.HashSubject("member-b")
	token := &auth.TokenEntry{JTI: "other-member", ExpiresAt: time.Now().Add(time.Hour)}
	policy.addToken("org-a", hash, token)

	for _, role := range []string{"member", ""} {
		t.Run(roleName(role), func(t *testing.T) {
			count, err := svc.RevokeMemberSessions(principalCtx("org-a", "member-a", role), "member-b", "org-a")
			if count != 0 {
				t.Fatalf("revoked %d sessions", count)
			}
			assertErrorKind(t, err, ErrorPermissionDenied)
		})
	}
	if token.Revoked {
		t.Fatal("non-admin revoked another member's session")
	}
}

func TestListSessions_AdminSameOrgOtherMember(t *testing.T) {
	svc, _, _, policy := setupTestSessionService(t)
	hash := auth.HashSubject("member-b")
	policy.addToken("org-a", hash, &auth.TokenEntry{JTI: "member-b-session", ExpiresAt: time.Now().Add(time.Hour)})
	policy.addToken("org-b", hash, &auth.TokenEntry{JTI: "other-org-session", ExpiresAt: time.Now().Add(time.Hour)})

	resp, err := svc.ListSessions(principalCtx("org-a", "admin-a", "admin"), "member-b", "org-a")
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(resp.Sessions) != 1 || resp.Sessions[0].JTI != "member-b-session" {
		t.Fatalf("sessions = %+v, want only the org-a session", resp.Sessions)
	}
}

func TestRevokeMemberSessions_AdminSameOrgOtherMember(t *testing.T) {
	for _, role := range []string{"admin", "master"} {
		t.Run(role, func(t *testing.T) {
			svc, _, _, policy := setupTestSessionService(t)
			hash := auth.HashSubject("member-b")
			tokenA := &auth.TokenEntry{JTI: "org-a-session", ExpiresAt: time.Now().Add(time.Hour)}
			tokenB := &auth.TokenEntry{JTI: "org-b-session", ExpiresAt: time.Now().Add(time.Hour)}
			policy.addToken("org-a", hash, tokenA)
			policy.addToken("org-b", hash, tokenB)

			count, err := svc.RevokeMemberSessions(principalCtx("org-a", "admin-a", role), "member-b", "org-a")
			if err != nil {
				t.Fatalf("RevokeMemberSessions: %v", err)
			}
			if count != 1 {
				t.Fatalf("count = %d, want 1", count)
			}
			if !tokenA.Revoked {
				t.Fatal("org A session was not revoked")
			}
			if tokenB.Revoked {
				t.Fatal("org B session was revoked")
			}
		})
	}
}

func TestRevokeMemberSessions_MemberRevokesOwn(t *testing.T) {
	svc, _, _, policy := setupTestSessionService(t)
	hash := auth.HashSubject("member-a")
	token := &auth.TokenEntry{JTI: "own-session", ExpiresAt: time.Now().Add(time.Hour)}
	policy.addToken("org-a", hash, token)

	count, err := svc.RevokeMemberSessions(principalCtx("org-a", "member-a", "member"), "member-a", "org-a")
	if err != nil {
		t.Fatalf("RevokeMemberSessions: %v", err)
	}
	if count != 1 || !token.Revoked {
		t.Fatalf("count = %d revoked = %v, want own session revoked", count, token.Revoked)
	}
}

func unauthenticatedCases() []struct {
	name string
	ctx  context.Context
} {
	return []struct {
		name string
		ctx  context.Context
	}{
		{name: "missing", ctx: context.Background()},
		{name: "empty", ctx: authn.WithPrincipal(context.Background(), authn.Principal{})},
		{name: "no_actor", ctx: authn.WithPrincipal(context.Background(), authn.Principal{TenantID: "org-a"})},
		{name: "no_tenant", ctx: authn.WithPrincipal(context.Background(), authn.Principal{ActorID: "member-a"})},
	}
}

func roleName(role string) string {
	if role == "" {
		return "empty_role"
	}
	return role
}
