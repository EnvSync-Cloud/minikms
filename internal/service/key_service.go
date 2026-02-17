package service

import (
	"context"
	"fmt"

	"github.com/envsync/minikms/internal/audit"
	"github.com/envsync/minikms/internal/keys"
)

// KeyService handles key lifecycle operations.
type KeyService struct {
	dekManager     *keys.AppDEKManager
	versionManager *keys.KeyVersionManager
	auditLogger    *audit.AuditLogger
}

// NewKeyService creates a new KeyService.
func NewKeyService(dekManager *keys.AppDEKManager, versionManager *keys.KeyVersionManager, auditLogger *audit.AuditLogger) *KeyService {
	return &KeyService{
		dekManager:     dekManager,
		versionManager: versionManager,
		auditLogger:    auditLogger,
	}
}

// CreateDataKeyRequest represents a request to create a new data key for a scope.
type CreateDataKeyRequest struct {
	TenantID string
	ScopeID  string
}

// CreateDataKeyResponse represents the result of creating a data key.
type CreateDataKeyResponse struct {
	KeyVersionID string
	Version      int
}

// CreateDataKey creates a new data encryption key for a scope.
func (s *KeyService) CreateDataKey(ctx context.Context, req *CreateDataKeyRequest) (*CreateDataKeyResponse, error) {
	_, keyVersionID, err := s.dekManager.GetOrCreateDEK(ctx, req.TenantID, req.ScopeID)
	if err != nil {
		return nil, fmt.Errorf("failed to create data key: %w", err)
	}

	s.auditLogger.Log(ctx, req.TenantID, "data_key_created", "system",
		fmt.Sprintf("Data key created for scope %s", req.ScopeID), "")

	return &CreateDataKeyResponse{
		KeyVersionID: keyVersionID,
	}, nil
}

// RotateDataKeyRequest represents a request to rotate a data key.
type RotateDataKeyRequest struct {
	TenantID string
	ScopeID  string
}

// RotateDataKeyResponse represents the result of a key rotation.
type RotateDataKeyResponse struct {
	NewKeyVersionID string
}

// RotateDataKey rotates the data encryption key for a scope.
func (s *KeyService) RotateDataKey(ctx context.Context, req *RotateDataKeyRequest) (*RotateDataKeyResponse, error) {
	newID, err := s.dekManager.RotateDEK(ctx, req.TenantID, req.ScopeID)
	if err != nil {
		return nil, fmt.Errorf("failed to rotate data key: %w", err)
	}

	s.auditLogger.Log(ctx, req.TenantID, "data_key_rotated", "system",
		fmt.Sprintf("Data key rotated for scope %s, new version: %s", req.ScopeID, newID), "")

	return &RotateDataKeyResponse{NewKeyVersionID: newID}, nil
}

// GetKeyInfoRequest represents a request to get key version info.
type GetKeyInfoRequest struct {
	TenantID string
	ScopeID  string
}

// GetKeyInfoResponse represents key version metadata.
type GetKeyInfoResponse struct {
	KeyVersionID    string
	Version         int
	EncryptionCount int64
	MaxEncryptions  int64
	Status          string
}

// GetKeyInfo returns metadata about the active key version.
func (s *KeyService) GetKeyInfo(ctx context.Context, req *GetKeyInfoRequest) (*GetKeyInfoResponse, error) {
	record, err := s.versionManager.GetKeyInfo(ctx, req.TenantID, req.ScopeID)
	if err != nil {
		return nil, err
	}

	return &GetKeyInfoResponse{
		KeyVersionID:    record.ID,
		Version:         record.Version,
		EncryptionCount: record.EncryptionCount,
		MaxEncryptions:  record.MaxEncryptions,
		Status:          record.Status,
	}, nil
}
