package service

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/envsync-cloud/minikms/internal/audit"
	"github.com/envsync-cloud/minikms/internal/crypto"
	"github.com/envsync-cloud/minikms/internal/keys"
)

// KMSService handles encrypt/decrypt operations.
// Callers NEVER see root key or plaintext DEKs — all operations go through this service.
type KMSService struct {
	dekManager  *keys.AppDEKManager
	auditLogger *audit.AuditLogger
}

// NewKMSService creates a new KMSService.
func NewKMSService(dekManager *keys.AppDEKManager, auditLogger *audit.AuditLogger) *KMSService {
	return &KMSService{
		dekManager:  dekManager,
		auditLogger: auditLogger,
	}
}

// EncryptRequest represents a request to encrypt data.
type EncryptRequest struct {
	TenantID  string // maps to org_id in EnvSync
	ScopeID   string // maps to app_id in EnvSync
	Plaintext []byte
	AAD       string // Additional Authenticated Data for context binding
}

// EncryptResponse represents the result of an encryption operation.
type EncryptResponse struct {
	Ciphertext   string // base64-encoded
	KeyVersionID string
}

// Encrypt encrypts plaintext using the scope's active DEK with AAD binding.
func (s *KMSService) Encrypt(ctx context.Context, req *EncryptRequest) (*EncryptResponse, error) {
	dek, keyVersionID, err := s.dekManager.GetOrCreateDEK(ctx, req.TenantID, req.ScopeID)
	if err != nil {
		return nil, fmt.Errorf("failed to get DEK: %w", err)
	}
	defer zeroize(dek)

	ciphertext, err := crypto.Encrypt(dek, req.Plaintext, []byte(req.AAD))
	if err != nil {
		return nil, fmt.Errorf("encryption failed: %w", err)
	}

	// Increment encryption count and check for rotation
	status, err := s.dekManager.IncrementAndCheckRotation(ctx, keyVersionID)
	if err != nil {
		return nil, fmt.Errorf("failed to track encryption: %w", err)
	}

	// Auto-rotate if needed
	if status == crypto.KeyStatusRotatePending {
		go func() {
			_ = s.auditLogger.Log(context.Background(), req.TenantID,
				"key_rotation_pending", "system",
				fmt.Sprintf("Key %s approaching max encryptions for scope %s", keyVersionID, req.ScopeID), "")
		}()
	}

	return &EncryptResponse{
		Ciphertext:   base64.StdEncoding.EncodeToString(ciphertext),
		KeyVersionID: keyVersionID,
	}, nil
}

// DecryptRequest represents a request to decrypt data.
type DecryptRequest struct {
	TenantID     string
	ScopeID      string
	Ciphertext   string // base64-encoded
	AAD          string
	KeyVersionID string
}

// DecryptResponse represents the result of a decryption operation.
type DecryptResponse struct {
	Plaintext []byte
}

// Decrypt decrypts ciphertext using the specified key version with AAD validation.
func (s *KMSService) Decrypt(ctx context.Context, req *DecryptRequest) (*DecryptResponse, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(req.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 ciphertext: %w", err)
	}

	dek, _, err := s.dekManager.GetOrCreateDEK(ctx, req.TenantID, req.ScopeID)
	if err != nil {
		return nil, fmt.Errorf("failed to get DEK: %w", err)
	}
	defer zeroize(dek)

	plaintext, err := crypto.Decrypt(dek, ciphertext, []byte(req.AAD))
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return &DecryptResponse{Plaintext: plaintext}, nil
}

// BatchEncryptRequest represents a batch encryption request.
type BatchEncryptRequest struct {
	TenantID string
	ScopeID  string
	Items    []BatchEncryptItem
}

// BatchEncryptItem represents a single item in a batch encryption request.
type BatchEncryptItem struct {
	Plaintext []byte
	AAD       string
}

// BatchEncryptResponse represents the result of a batch encryption.
type BatchEncryptResponse struct {
	Items []EncryptResponse
}

// BatchEncrypt encrypts multiple items in a single call.
func (s *KMSService) BatchEncrypt(ctx context.Context, req *BatchEncryptRequest) (*BatchEncryptResponse, error) {
	dek, keyVersionID, err := s.dekManager.GetOrCreateDEK(ctx, req.TenantID, req.ScopeID)
	if err != nil {
		return nil, fmt.Errorf("failed to get DEK: %w", err)
	}
	defer zeroize(dek)

	results := make([]EncryptResponse, len(req.Items))
	for i, item := range req.Items {
		ciphertext, err := crypto.Encrypt(dek, item.Plaintext, []byte(item.AAD))
		if err != nil {
			return nil, fmt.Errorf("batch encrypt item %d failed: %w", i, err)
		}
		results[i] = EncryptResponse{
			Ciphertext:   base64.StdEncoding.EncodeToString(ciphertext),
			KeyVersionID: keyVersionID,
		}
	}

	return &BatchEncryptResponse{Items: results}, nil
}

// BatchDecryptRequest represents a batch decryption request.
type BatchDecryptRequest struct {
	TenantID string
	ScopeID  string
	Items    []DecryptRequest
}

// BatchDecryptResponse represents the result of a batch decryption.
type BatchDecryptResponse struct {
	Items []DecryptResponse
}

// BatchDecrypt decrypts multiple items in a single call.
func (s *KMSService) BatchDecrypt(ctx context.Context, req *BatchDecryptRequest) (*BatchDecryptResponse, error) {
	dek, _, err := s.dekManager.GetOrCreateDEK(ctx, req.TenantID, req.ScopeID)
	if err != nil {
		return nil, fmt.Errorf("failed to get DEK: %w", err)
	}
	defer zeroize(dek)

	results := make([]DecryptResponse, len(req.Items))
	for i, item := range req.Items {
		ciphertext, err := base64.StdEncoding.DecodeString(item.Ciphertext)
		if err != nil {
			return nil, fmt.Errorf("batch decrypt item %d: invalid base64: %w", i, err)
		}
		plaintext, err := crypto.Decrypt(dek, ciphertext, []byte(item.AAD))
		if err != nil {
			return nil, fmt.Errorf("batch decrypt item %d failed: %w", i, err)
		}
		results[i] = DecryptResponse{Plaintext: plaintext}
	}

	return &BatchDecryptResponse{Items: results}, nil
}

func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
