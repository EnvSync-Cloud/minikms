package service

import (
	"context"
	"fmt"

	"github.com/envsync/minikms/internal/audit"
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

// GetAuditLogs returns audit log entries for an organization.
func (s *AuditService) GetAuditLogs(ctx context.Context, req *GetAuditLogsRequest) (*GetAuditLogsResponse, error) {
	entries, err := s.store.GetEntries(ctx, req.OrgID, req.Limit, req.Offset)
	if err != nil {
		return nil, fmt.Errorf("failed to get audit logs: %w", err)
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
	valid, err := s.store.VerifyChain(ctx, req.OrgID)
	if err != nil {
		return nil, fmt.Errorf("failed to verify chain: %w", err)
	}
	return &VerifyChainResponse{Valid: valid}, nil
}
