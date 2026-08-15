package service

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"

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
	if req == nil {
		return nil, invalidArgument("request is required")
	}
	if err := requireFields(
		requiredField("tenant_id", req.TenantID),
		requiredField("scope_id", req.ScopeID),
	); err != nil {
		return nil, err
	}

	dek, keyVersionID, err := s.dekManager.GetOrCreateDEK(ctx, req.TenantID, req.ScopeID)
	if err != nil {
		return nil, internalError("failed to get DEK", err)
	}
	defer zeroize(dek)

	ciphertext, err := crypto.Encrypt(dek, req.Plaintext, []byte(req.AAD))
	if err != nil {
		return nil, internalError("encryption failed", err)
	}

	// Increment encryption count and check for rotation
	status, err := s.dekManager.IncrementAndCheckRotation(ctx, keyVersionID)
	if err != nil {
		return nil, internalError("failed to track encryption", err)
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
	if req == nil {
		return nil, invalidArgument("request is required")
	}
	if err := requireFields(
		requiredField("tenant_id", req.TenantID),
		requiredField("scope_id", req.ScopeID),
		requiredField("ciphertext", req.Ciphertext),
		requiredField("key_version_id", req.KeyVersionID),
	); err != nil {
		return nil, err
	}

	ciphertext, err := base64.StdEncoding.DecodeString(req.Ciphertext)
	if err != nil {
		return nil, NewDomainError(ErrorInvalidArgument, "ciphertext must be valid base64", err)
	}

	dek, err := s.dekManager.GetDEKByVersion(ctx, req.TenantID, req.ScopeID, req.KeyVersionID)
	if err != nil {
		return nil, classifyKeyVersionError(err)
	}
	defer zeroize(dek)

	plaintext, err := crypto.Decrypt(dek, ciphertext, []byte(req.AAD))
	if err != nil {
		return nil, NewDomainError(ErrorInvalidArgument, "ciphertext could not be decrypted", err)
	}

	_ = s.auditLogger.Log(ctx, req.TenantID, "decrypt", "system",
		fmt.Sprintf("Decrypted data for scope %s with key version %s", req.ScopeID, req.KeyVersionID), "")

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
	if req == nil {
		return nil, invalidArgument("request is required")
	}
	if err := requireFields(
		requiredField("tenant_id", req.TenantID),
		requiredField("scope_id", req.ScopeID),
	); err != nil {
		return nil, err
	}
	if len(req.Items) == 0 {
		return nil, invalidArgument("items must not be empty")
	}

	dek, keyVersionID, err := s.dekManager.GetOrCreateDEK(ctx, req.TenantID, req.ScopeID)
	if err != nil {
		return nil, internalError("failed to get DEK", err)
	}
	defer zeroize(dek)

	results := make([]EncryptResponse, len(req.Items))
	for i, item := range req.Items {
		ciphertext, err := crypto.Encrypt(dek, item.Plaintext, []byte(item.AAD))
		if err != nil {
			return nil, internalError(fmt.Sprintf("batch encrypt item %d failed", i), err)
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
	if req == nil {
		return nil, invalidArgument("request is required")
	}
	if err := requireFields(
		requiredField("tenant_id", req.TenantID),
		requiredField("scope_id", req.ScopeID),
	); err != nil {
		return nil, err
	}
	if len(req.Items) == 0 {
		return nil, invalidArgument("items must not be empty")
	}
	for i, item := range req.Items {
		if item.Ciphertext == "" {
			return nil, invalidArgument(fmt.Sprintf("items[%d].ciphertext is required", i))
		}
		if item.KeyVersionID == "" {
			return nil, invalidArgument(fmt.Sprintf("items[%d].key_version_id is required", i))
		}
	}

	deks := make(map[string][]byte)
	defer func() {
		for _, dek := range deks {
			zeroize(dek)
		}
	}()

	results := make([]DecryptResponse, len(req.Items))
	for i, item := range req.Items {
		dek, ok := deks[item.KeyVersionID]
		if !ok {
			var err error
			dek, err = s.dekManager.GetDEKByVersion(ctx, req.TenantID, req.ScopeID, item.KeyVersionID)
			if err != nil {
				return nil, classifyKeyVersionError(err)
			}
			deks[item.KeyVersionID] = dek
		}

		ciphertext, err := base64.StdEncoding.DecodeString(item.Ciphertext)
		if err != nil {
			return nil, NewDomainError(ErrorInvalidArgument,
				fmt.Sprintf("items[%d].ciphertext must be valid base64", i), err)
		}
		plaintext, err := crypto.Decrypt(dek, ciphertext, []byte(item.AAD))
		if err != nil {
			return nil, NewDomainError(ErrorInvalidArgument,
				fmt.Sprintf("items[%d].ciphertext could not be decrypted", i), err)
		}
		results[i] = DecryptResponse{Plaintext: plaintext}
	}

	keyVersionIDs := make([]string, 0, len(deks))
	for keyVersionID := range deks {
		keyVersionIDs = append(keyVersionIDs, keyVersionID)
	}
	sort.Strings(keyVersionIDs)
	_ = s.auditLogger.Log(ctx, req.TenantID, "batch_decrypt", "system",
		fmt.Sprintf("Decrypted %d items for scope %s with key versions %s",
			len(req.Items), req.ScopeID, strings.Join(keyVersionIDs, ",")), "")

	return &BatchDecryptResponse{Items: results}, nil
}

func classifyKeyVersionError(err error) error {
	switch {
	case errors.Is(err, keys.ErrKeyVersionRequired):
		return NewDomainError(ErrorInvalidArgument, "key_version_id is required", err)
	case errors.Is(err, keys.ErrKeyVersionNotFound):
		return NewDomainError(ErrorNotFound, "key version not found", err)
	default:
		return internalError("failed to get DEK by version", err)
	}
}

func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
