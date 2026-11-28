package intercept

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/envsync-cloud/minikms/api/proto/minikms/v1"
	"github.com/envsync-cloud/minikms/internal/authn"
	"github.com/envsync-cloud/minikms/internal/dpop"
)

func TestFixtureMachineCannotCallPKI(t *testing.T) {
	raw := signToken(t, jwt.MapClaims{
		"jti":  "jti-machine",
		"sub":  "workload",
		"org":  "org-1",
		"kind": authn.KindMachine,
		"app":  "app-1",
		"exp":  time.Now().Add(time.Hour).Unix(),
	})
	checker := &dpop.Checker{Mode: dpop.ModeOff}
	link := &chain{validator: &fakeValidator{scopes: []string{"vault:read"}}, limiter: &fakeLimiter{allow: true}, proofs: checker}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+raw))
	_, err := link.authUnary(ctx, nil, &grpc.UnaryServerInfo{FullMethod: pb.PKIService_IssueMemberCert_FullMethodName}, func(context.Context, any) (any, error) {
		t.Fatal("machine principal reached a PKI method")
		return nil, nil
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %s", status.Code(err))
	}
}

func TestFixtureServiceReadDeniedInEnforce(t *testing.T) {
	raw := signToken(t, jwt.MapClaims{
		"jti":  "jti-service",
		"sub":  "bootstrap-admin-org-1",
		"org":  "org-1",
		"role": "admin",
		"kind": authn.KindService,
		"exp":  time.Now().Add(time.Hour).Unix(),
	})
	off := &dpop.Checker{Mode: dpop.ModeOff}
	link := &chain{validator: &fakeValidator{scopes: []string{"vault:read", "vault:write"}}, limiter: &fakeLimiter{allow: true}, proofs: off}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+raw))
	if _, err := link.authUnary(ctx, nil, &grpc.UnaryServerInfo{FullMethod: pb.KMSService_Decrypt_FullMethodName}, func(context.Context, any) (any, error) {
		return nil, nil
	}); err != nil {
		t.Fatalf("off mode denied a service read: %v", err)
	}
	link.proofs = &dpop.Checker{Mode: dpop.ModeEnforce}
	_, err := link.authUnary(ctx, nil, &grpc.UnaryServerInfo{FullMethod: pb.KMSService_Decrypt_FullMethodName}, func(context.Context, any) (any, error) {
		t.Fatal("service principal read user data in enforce")
		return nil, nil
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %s", status.Code(err))
	}
}
