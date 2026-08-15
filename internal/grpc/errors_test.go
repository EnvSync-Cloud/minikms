package grpc

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/envsync-cloud/minikms/internal/service"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestToStatusError_MappingTable(t *testing.T) {
	secretCause := errors.New("postgres://admin:super-secret@database/internal")

	tests := []struct {
		name        string
		err         error
		wantCode    codes.Code
		wantMessage string
	}{
		{
			name:        "invalid argument",
			err:         service.NewDomainError(service.ErrorInvalidArgument, "tenant_id is required", secretCause),
			wantCode:    codes.InvalidArgument,
			wantMessage: "tenant_id is required",
		},
		{
			name:        "not found",
			err:         service.NewDomainError(service.ErrorNotFound, "vault entry not found", secretCause),
			wantCode:    codes.NotFound,
			wantMessage: "vault entry not found",
		},
		{
			name:        "permission denied",
			err:         service.NewDomainError(service.ErrorPermissionDenied, "organization access denied", secretCause),
			wantCode:    codes.PermissionDenied,
			wantMessage: "organization access denied",
		},
		{
			name:        "failed precondition",
			err:         service.NewDomainError(service.ErrorFailedPrecondition, "organization PKI is not initialized", secretCause),
			wantCode:    codes.FailedPrecondition,
			wantMessage: "organization PKI is not initialized",
		},
		{
			name:        "unauthenticated",
			err:         service.NewDomainError(service.ErrorUnauthenticated, "invalid session token", secretCause),
			wantCode:    codes.Unauthenticated,
			wantMessage: "invalid session token",
		},
		{
			name:        "resource exhausted",
			err:         service.NewDomainError(service.ErrorResourceExhausted, "maximum active sessions reached", secretCause),
			wantCode:    codes.ResourceExhausted,
			wantMessage: "maximum active sessions reached",
		},
		{
			name:        "wrapped domain error",
			err:         fmt.Errorf("service operation failed: %w", service.NewDomainError(service.ErrorNotFound, "certificate not found", secretCause)),
			wantCode:    codes.NotFound,
			wantMessage: "certificate not found",
		},
		{
			name:        "explicit internal error",
			err:         service.NewDomainError(service.ErrorInternal, "database query failed", secretCause),
			wantCode:    codes.Internal,
			wantMessage: "internal server error",
		},
		{
			name:        "unknown error",
			err:         secretCause,
			wantCode:    codes.Internal,
			wantMessage: "internal server error",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := status.Convert(toStatusError(test.err))
			if got.Code() != test.wantCode {
				t.Fatalf("code = %v, want %v", got.Code(), test.wantCode)
			}
			if got.Message() != test.wantMessage {
				t.Fatalf("message = %q, want %q", got.Message(), test.wantMessage)
			}
			if strings.Contains(got.Message(), "super-secret") || strings.Contains(got.Message(), "postgres://") {
				t.Fatalf("gRPC message leaked internal cause: %q", got.Message())
			}
		})
	}
}

func TestToStatusError_Nil(t *testing.T) {
	if err := toStatusError(nil); err != nil {
		t.Fatalf("toStatusError(nil) = %v, want nil", err)
	}
}
