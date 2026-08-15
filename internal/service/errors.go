package service

import "fmt"

// ErrorKind classifies failures independently of any transport protocol.
// Adapters translate these kinds into their protocol-specific status codes.
type ErrorKind string

const (
	ErrorInvalidArgument    ErrorKind = "invalid_argument"
	ErrorNotFound           ErrorKind = "not_found"
	ErrorPermissionDenied   ErrorKind = "permission_denied"
	ErrorFailedPrecondition ErrorKind = "failed_precondition"
	ErrorUnauthenticated    ErrorKind = "unauthenticated"
	ErrorResourceExhausted  ErrorKind = "resource_exhausted"
	ErrorInternal           ErrorKind = "internal"
)

// DomainError carries a client-safe message separately from the internal
// cause. Transport adapters must expose PublicMessage, never Error().
type DomainError struct {
	Kind          ErrorKind
	PublicMessage string
	Cause         error
}

// NewDomainError creates a classified service error. publicMessage must be
// safe to return to an untrusted client and must not contain secret material.
func NewDomainError(kind ErrorKind, publicMessage string, cause error) *DomainError {
	return &DomainError{
		Kind:          kind,
		PublicMessage: publicMessage,
		Cause:         cause,
	}
}

func (e *DomainError) Error() string {
	if e.Cause == nil {
		return e.PublicMessage
	}
	return fmt.Sprintf("%s: %v", e.PublicMessage, e.Cause)
}

func (e *DomainError) Unwrap() error {
	return e.Cause
}

func invalidArgument(message string) error {
	return NewDomainError(ErrorInvalidArgument, message, nil)
}

func internalError(message string, cause error) error {
	return NewDomainError(ErrorInternal, message, cause)
}

func requireFields(fields ...struct {
	name  string
	value string
}) error {
	for _, field := range fields {
		if field.value == "" {
			return invalidArgument(field.name + " is required")
		}
	}
	return nil
}

func requiredField(name, value string) struct {
	name  string
	value string
} {
	return struct {
		name  string
		value string
	}{name: name, value: value}
}
