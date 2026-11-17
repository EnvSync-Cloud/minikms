package service

import (
	"context"

	"github.com/envsync-cloud/minikms/internal/audit"
)

// AuditService handles audit log gRPC operations.
type AuditService struct {
	logger *audit.AuditLogger
	store  audit.AuditStore
}

// NewAuditService creates a new AuditService.
func NewAuditService(logger *audit.AuditLogger, store audit.AuditStore) *AuditService {
	return &AuditService{logger: logger, store: store}
}

// GetAuditLogsRequest represents a request to retrieve audit logs.
type GetAuditLogsRequest struct {
	OrgID  string
	Limit  int
	Offset int
}

// GetAuditLogsResponse represents the result of retrieving audit logs.
type GetAuditLogsResponse struct {
	Entries []*audit.AuditEntry
}

// GetAuditLogs returns audit log entries for the caller's organization.
// There is no platform-admin flag, so the caller-supplied org id is not the
// query tenant. A different org id is denied.
func (s *AuditService) GetAuditLogs(ctx context.Context, req *GetAuditLogsRequest) (*GetAuditLogsResponse, error) {
	if req == nil {
		return nil, invalidArgument("request is required")
	}
	principal, err := requirePrincipal(ctx)
	if err != nil {
		return nil, err
	}
	if req.OrgID != "" && req.OrgID != principal.TenantID {
		return nil, NewDomainError(ErrorPermissionDenied, "tenant access denied", nil)
	}
	if req.Limit <= 0 || req.Limit > 1000 {
		return nil, invalidArgument("limit must be between 1 and 1000")
	}
	if req.Offset < 0 {
		return nil, invalidArgument("offset must not be negative")
	}

	entries, err := s.store.GetEntries(ctx, principal.TenantID, req.Limit, req.Offset)
	if err != nil {
		return nil, internalError("failed to get audit logs", err)
	}
	return &GetAuditLogsResponse{Entries: entries}, nil
}

// VerifyChainRequest represents a request to verify audit chain integrity.
type VerifyChainRequest struct {
	OrgID string
}

// VerifyChainResponse represents the result of chain verification.
type VerifyChainResponse struct {
	Valid bool
}

// VerifyChain verifies the hash chain integrity for an organization.
func (s *AuditService) VerifyChain(ctx context.Context, req *VerifyChainRequest) (*VerifyChainResponse, error) {
	if req == nil {
		return nil, invalidArgument("request is required")
	}
	if err := requireFields(requiredField("org_id", req.OrgID)); err != nil {
		return nil, err
	}

	valid, err := s.store.VerifyChain(ctx, req.OrgID)
	if err != nil {
		return nil, internalError("failed to verify audit chain", err)
	}
	return &VerifyChainResponse{Valid: valid}, nil
}
