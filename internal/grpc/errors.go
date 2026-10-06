package grpc

import (
	"errors"
	"strings"

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
	service.ErrorInternal:           codes.Internal,
}

// toStatusError converts service errors into client-safe gRPC status errors.
// Classified domain errors return their public message plus a non-secret cause.
// Unclassified errors stay generic so connection strings and key material never
// leave the process.
func toStatusError(err error) error {
	if err == nil {
		return nil
	}

	var domainErr *service.DomainError
	if errors.As(err, &domainErr) && domainErr.PublicMessage != "" {
		code := codes.Internal
		if mapped, ok := grpcCodeByErrorKind[domainErr.Kind]; ok {
			code = mapped
		}
		return status.Error(code, withSafeCause(domainErr.PublicMessage, domainErr.Cause))
	}

	return status.Error(codes.Internal, "internal server error")
}

func withSafeCause(public string, cause error) string {
	detail := safeDetail(cause)
	if detail == "" || detail == public {
		return public
	}
	return public + ": " + detail
}

func safeDetail(err error) string {
	if err == nil {
		return ""
	}
	message := err.Error()
	if sensitiveDetail(message) {
		if next := errors.Unwrap(err); next != nil && next.Error() != message {
			return safeDetail(next)
		}
		return ""
	}
	if len(message) > 240 {
		return message[:240]
	}
	return message
}

func sensitiveDetail(message string) bool {
	lower := strings.ToLower(message)
	needles := []string{
		"://",
		"password",
		"bearer ",
		"begin ",
		"private key",
		"token=",
	}
	for _, needle := range needles {
		if strings.Contains(lower, needle) {
			return true
		}
	}
	return false
}
