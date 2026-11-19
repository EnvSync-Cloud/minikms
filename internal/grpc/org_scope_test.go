package grpc

import (
	"context"
	"testing"

	pb "github.com/envsync-cloud/minikms/api/proto/minikms/v1"
	"github.com/envsync-cloud/minikms/internal/authn"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestSessionAdapter_ListSessions_Unauthenticated(t *testing.T) {
	adapter, _ := setupSessionAdapter(t)
	_, err := adapter.ListSessions(context.Background(), &pb.ListSessionsRequest{
		MemberId: "member-1",
		OrgId:    "org-1",
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %v, want Unauthenticated (err=%v)", status.Code(err), err)
	}
}

func TestSessionAdapter_RevokeMemberSessions_Unauthenticated(t *testing.T) {
	adapter, _ := setupSessionAdapter(t)
	_, err := adapter.RevokeMemberSessions(context.Background(), &pb.RevokeMemberSessionsRequest{
		MemberId: "member-1",
		OrgId:    "org-1",
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %v, want Unauthenticated (err=%v)", status.Code(err), err)
	}
}

func TestAuditAdapter_GetAuditLogs_Unauthenticated(t *testing.T) {
	adapter := setupAuditAdapter(t)
	_, err := adapter.GetAuditLogs(context.Background(), &pb.GetAuditLogsRequest{
		OrgId: "org-1",
		Limit: 10,
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %v, want Unauthenticated (err=%v)", status.Code(err), err)
	}
}

func TestSessionAdapter_RevokeMemberSessions_CrossOrg(t *testing.T) {
	adapter, _ := setupSessionAdapter(t)
	ctx := authn.WithPrincipal(context.Background(), authn.Principal{
		TenantID: "org-a",
		ActorID:  "admin-a",
		Role:     "admin",
	})
	_, err := adapter.RevokeMemberSessions(ctx, &pb.RevokeMemberSessionsRequest{
		MemberId: "member-b",
		OrgId:    "org-b",
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied (err=%v)", status.Code(err), err)
	}
}

func TestAuditAdapter_GetAuditLogs_CrossOrg(t *testing.T) {
	adapter := setupAuditAdapter(t)
	ctx := authn.WithPrincipal(context.Background(), authn.Principal{
		TenantID: "org-a",
		ActorID:  "member-a",
		Role:     "member",
	})
	_, err := adapter.GetAuditLogs(ctx, &pb.GetAuditLogsRequest{
		OrgId: "org-b",
		Limit: 10,
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied (err=%v)", status.Code(err), err)
	}
}

func TestSessionAdapter_RevokeMemberSessions_NonAdminOtherMember(t *testing.T) {
	adapter, _ := setupSessionAdapter(t)
	ctx := authn.WithPrincipal(context.Background(), authn.Principal{
		TenantID: "org-a",
		ActorID:  "member-a",
		Role:     "member",
	})
	_, err := adapter.RevokeMemberSessions(ctx, &pb.RevokeMemberSessionsRequest{
		MemberId: "member-b",
		OrgId:    "org-a",
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied (err=%v)", status.Code(err), err)
	}
}

func TestSessionAdapter_ListSessions_CrossOrg(t *testing.T) {
	adapter, _ := setupSessionAdapter(t)
	ctx := authn.WithPrincipal(context.Background(), authn.Principal{
		TenantID: "org-a",
		ActorID:  "admin-a",
		Role:     "admin",
	})
	_, err := adapter.ListSessions(ctx, &pb.ListSessionsRequest{
		MemberId: "member-b",
		OrgId:    "org-b",
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied (err=%v)", status.Code(err), err)
	}
}
