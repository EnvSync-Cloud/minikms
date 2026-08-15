package grpc

import (
	"errors"

	"github.com/envsync-cloud/minikms/internal/service"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var grpcCodeByErrorKind = map[service.ErrorKind]codes.Code{
	service.ErrorInvalidArgument:    codes.InvalidArgument,
	service.ErrorNotFound:           codes.NotFound,
	service.ErrorPermissionDenied:   codes.PermissionDenied,
	service.ErrorFailedPrecondition: codes.FailedPrecondition,
	service.ErrorUnauthenticated:    codes.Unauthenticated,
	service.ErrorResourceExhausted:  codes.ResourceExhausted,
}

// toStatusError converts service errors into client-safe gRPC status errors.
// Unknown errors and domain errors without an explicit public classification
// are deliberately collapsed to a generic Internal response.
func toStatusError(err error) error {
	if err == nil {
		return nil
	}

	var domainErr *service.DomainError
	if errors.As(err, &domainErr) {
		if code, ok := grpcCodeByErrorKind[domainErr.Kind]; ok && domainErr.PublicMessage != "" {
			return status.Error(code, domainErr.PublicMessage)
		}
	}

	return status.Error(codes.Internal, "internal server error")
}
