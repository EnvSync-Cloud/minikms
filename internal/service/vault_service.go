package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/envsync-cloud/minikms/internal/audit"
	"github.com/envsync-cloud/minikms/internal/crypto"
	"github.com/envsync-cloud/minikms/internal/keys"
	"github.com/envsync-cloud/minikms/internal/pkistore"
	"github.com/envsync-cloud/minikms/internal/store"
)

// VaultStore abstracts the database operations needed by VaultService.
type VaultStore interface {
	// PKI cert lookups
	GetOrgCA(ctx context.Context, orgID string) (*pkistore.CertRecord, error)
	GetCertificateBySerialWithKey(ctx context.Context, serialNumber string) (*pkistore.CertRecord, error)

	// Org CA wrap lookups
	GetOrgCAWrap(ctx context.Context, orgID, memberID string) (*keys.OrgCAWrapRecord, error)

	// Vault entry CRUD
	WriteVaultEntry(ctx context.Context, entry *store.VaultEntry) error
	GetLatestVaultEntry(ctx context.Context, orgID, scopeID, entryType, key string, envTypeID *string) (*store.VaultEntry, error)
	GetVaultEntryVersion(ctx context.Context, orgID, scopeID, entryType, key string, envTypeID *string, version int) (*store.VaultEntry, error)
	GetNextVaultVersion(ctx context.Context, orgID, scopeID, entryType, key string, envTypeID *string) (int, error)
	SoftDeleteVaultEntry(ctx context.Context, orgID, scopeID, entryType, key string, envTypeID *string) error
	DestroyVaultEntry(ctx context.Context, orgID, scopeID, entryType, key string, envTypeID *string, version int) (int, error)
	ListVaultEntries(ctx context.Context, orgID, scopeID, entryType string, envTypeID *string) ([]store.VaultListItem, error)
	GetVaultEntryHistory(ctx context.Context, orgID, scopeID, entryType, key string, envTypeID *string) ([]*store.VaultEntry, error)
}

// VaultService provides zero-trust secret storage, replacing HashiCorp Vault KV v2.
// It implements the 3-layer encryption pipeline:
//
//	Layer 1: RSA/Hybrid (BYOK) — happens in envsync-api (value arrives pre-encrypted)
//	Layer 2: ECIES with Org CA — happens here on write/read
//	Layer 3: KMS envelope encryption — happens here on write/read
type VaultService struct {
	dekManager     *keys.AppDEKManager
	orgCAWrapMgr   *keys.OrgCAWrapManager
	vaultStore     VaultStore
	auditLogger    *audit.AuditLogger
	sessionService *SessionService
}

// NewVaultService creates a new VaultService.
func NewVaultService(
	dekManager *keys.AppDEKManager,
	orgCAWrapMgr *keys.OrgCAWrapManager,
	vaultStore VaultStore,
	auditLogger *audit.AuditLogger,
	sessionService *SessionService,
) *VaultService {
	return &VaultService{
		dekManager:     dekManager,
		orgCAWrapMgr:   orgCAWrapMgr,
		vaultStore:     vaultStore,
		auditLogger:    auditLogger,
		sessionService: sessionService,
	}
}

// VaultWriteRequest represents a request to write a vault entry.
type VaultWriteRequest struct {
	OrgID     string
	ScopeID   string
	EntryType string
	Key       string
	EnvTypeID *string
	Value     []byte // Layer 1 output (RSA/Hybrid encrypted blob from envsync-api)
	CreatedBy string // member_id
}

// VaultWriteResponse represents the result of a vault write.
type VaultWriteResponse struct {
	ID           string
	Version      int
	KeyVersionID string
}

// Write stores an encrypted value in the vault.
// Encryption pipeline: receives Layer 1 output → applies Layer 2 (ECIES) → applies Layer 3 (KMS envelope).
func (v *VaultService) Write(ctx context.Context, sessionToken string, req *VaultWriteRequest) (*VaultWriteResponse, error) {
	if req == nil {
		return nil, invalidArgument("request is required")
	}
	if err := validateVaultFields(req.OrgID, req.ScopeID, req.EntryType, req.Key, true); err != nil {
		return nil, err
	}

	// Validate session
	_, err := v.authorize(ctx, sessionToken, req.OrgID, "vault:write")
	if err != nil {
		return nil, err
	}

	// Layer 2: ECIES encrypt with Org CA public key
	orgCAPub, err := v.getOrgCAPublicKey(ctx, req.OrgID)
	if err != nil {
		return nil, err
	}

	eciesOutput, err := crypto.ECIESEncrypt(orgCAPub, req.Value, "envsync-ecies-v1", req.OrgID, []byte(req.OrgID))
	if err != nil {
		return nil, internalError("ECIES encryption failed", err)
	}

	// Layer 3: KMS envelope encryption
	dek, keyVersionID, err := v.dekManager.GetOrCreateDEK(ctx, req.OrgID, req.ScopeID)
	if err != nil {
		return nil, internalError("failed to get DEK", err)
	}
	defer zeroize(dek)

	aad := fmt.Sprintf("%s:%s:%s:%s", req.EntryType, req.OrgID, req.ScopeID, req.Key)
	if req.EnvTypeID != nil {
		aad = fmt.Sprintf("%s:%s:%s:%s:%s", req.EntryType, req.OrgID, req.ScopeID, *req.EnvTypeID, req.Key)
	}

	kmsCiphertext, err := crypto.Encrypt(dek, eciesOutput, []byte(aad))
	if err != nil {
		return nil, internalError("KMS encryption failed", err)
	}

	// Get next version
	version, err := v.vaultStore.GetNextVaultVersion(ctx, req.OrgID, req.ScopeID, req.EntryType, req.Key, req.EnvTypeID)
	if err != nil {
		return nil, internalError("failed to get next vault version", err)
	}

	// Store
	entry := &store.VaultEntry{
		OrgID:          req.OrgID,
		ScopeID:        req.ScopeID,
		EntryType:      req.EntryType,
		Key:            req.Key,
		EnvTypeID:      req.EnvTypeID,
		EncryptedValue: kmsCiphertext,
		KeyVersionID:   keyVersionID,
		Version:        version,
		CreatedBy:      &req.CreatedBy,
	}

	if err := v.vaultStore.WriteVaultEntry(ctx, entry); err != nil {
		return nil, internalError("failed to write vault entry", err)
	}

	_ = v.auditLogger.Log(ctx, req.OrgID, "vault_write", req.CreatedBy,
		fmt.Sprintf("Wrote %s/%s/%s v%d", req.ScopeID, req.EntryType, req.Key, version), "")

	return &VaultWriteResponse{
		ID:           entry.ID,
		Version:      version,
		KeyVersionID: keyVersionID,
	}, nil
}

// VaultReadRequest represents a request to read a vault entry.
type VaultReadRequest struct {
	OrgID             string
	ScopeID           string
	EntryType         string
	Key               string
	EnvTypeID         *string
	ClientSideDecrypt bool // true for BYOK, false for managed
}

// VaultReadResponse represents the result of a vault read.
type VaultReadResponse struct {
	ID             string
	OrgID          string
	ScopeID        string
	EntryType      string
	Key            string
	EnvTypeID      *string
	EncryptedValue []byte // Content depends on ClientSideDecrypt flag
	KeyVersionID   string
	Version        int
	CreatedAt      time.Time
	CreatedBy      *string

	// For BYOK client-side decrypt
	MemberWrapEphemeralPub []byte
	MemberWrappedOrgCAKey  []byte
}

// Read retrieves and partially decrypts a vault entry.
// For BYOK: returns KMS-unwrapped ECIES blob + member wrap data for client-side decryption.
// For managed: performs full server-side ECIES unwrap, returns Layer 1 output.
func (v *VaultService) Read(ctx context.Context, sessionToken string, req *VaultReadRequest) (*VaultReadResponse, error) {
	if req == nil {
		return nil, invalidArgument("request is required")
	}
	if err := validateVaultFields(req.OrgID, req.ScopeID, req.EntryType, req.Key, true); err != nil {
		return nil, err
	}

	// Validate session
	session, err := v.authorize(ctx, sessionToken, req.OrgID, "vault:read")
	if err != nil {
		return nil, err
	}

	// Fetch entry
	entry, err := v.vaultStore.GetLatestVaultEntry(ctx, req.OrgID, req.ScopeID, req.EntryType, req.Key, req.EnvTypeID)
	if err != nil {
		return nil, internalError("failed to read vault entry", err)
	}
	if entry == nil {
		return nil, NewDomainError(ErrorNotFound, "vault entry not found", nil)
	}

	return v.decryptEntry(ctx, session, entry, req.ClientSideDecrypt)
}

// VaultReadVersionRequest represents a request to read a specific version.
type VaultReadVersionRequest struct {
	OrgID             string
	ScopeID           string
	EntryType         string
	Key               string
	EnvTypeID         *string
	Version           int
	ClientSideDecrypt bool
}

// ReadVersion retrieves a specific version of a vault entry.
func (v *VaultService) ReadVersion(ctx context.Context, sessionToken string, req *VaultReadVersionRequest) (*VaultReadResponse, error) {
	if req == nil {
		return nil, invalidArgument("request is required")
	}
	if err := validateVaultFields(req.OrgID, req.ScopeID, req.EntryType, req.Key, true); err != nil {
		return nil, err
	}
	if req.Version <= 0 {
		return nil, invalidArgument("version must be greater than zero")
	}

	// Validate session
	session, err := v.authorize(ctx, sessionToken, req.OrgID, "vault:read")
	if err != nil {
		return nil, err
	}

	// Fetch specific version
	entry, err := v.vaultStore.GetVaultEntryVersion(ctx, req.OrgID, req.ScopeID, req.EntryType, req.Key, req.EnvTypeID, req.Version)
	if err != nil {
		return nil, internalError("failed to read vault entry version", err)
	}
	if entry == nil {
		return nil, NewDomainError(ErrorNotFound, "vault entry version not found", nil)
	}

	return v.decryptEntry(ctx, session, entry, req.ClientSideDecrypt)
}

// VaultDeleteRequest represents a soft delete request.
type VaultDeleteRequest struct {
	OrgID     string
	ScopeID   string
	EntryType string
	Key       string
	EnvTypeID *string
}

// Delete performs a soft delete (marks as deleted, recoverable).
func (v *VaultService) Delete(ctx context.Context, sessionToken string, req *VaultDeleteRequest) error {
	if req == nil {
		return invalidArgument("request is required")
	}
	if err := validateVaultFields(req.OrgID, req.ScopeID, req.EntryType, req.Key, true); err != nil {
		return err
	}

	// Validate session
	session, err := v.authorize(ctx, sessionToken, req.OrgID, "vault:delete")
	if err != nil {
		return err
	}

	if err := v.vaultStore.SoftDeleteVaultEntry(ctx, req.OrgID, req.ScopeID, req.EntryType, req.Key, req.EnvTypeID); err != nil {
		return internalError("failed to delete vault entry", err)
	}

	_ = v.auditLogger.Log(ctx, req.OrgID, "vault_delete", session.MemberID,
		fmt.Sprintf("Soft-deleted %s/%s/%s", req.ScopeID, req.EntryType, req.Key), "")

	return nil
}

// VaultDestroyRequest represents a permanent delete request.
type VaultDestroyRequest struct {
	OrgID     string
	ScopeID   string
	EntryType string
	Key       string
	EnvTypeID *string
	Version   int // 0 = destroy all versions
}

// Destroy permanently deletes a vault entry (irrecoverable).
func (v *VaultService) Destroy(ctx context.Context, sessionToken string, req *VaultDestroyRequest) (int, error) {
	if req == nil {
		return 0, invalidArgument("request is required")
	}
	if err := validateVaultFields(req.OrgID, req.ScopeID, req.EntryType, req.Key, true); err != nil {
		return 0, err
	}
	if req.Version < 0 {
		return 0, invalidArgument("version must not be negative")
	}

	// Validate session — require admin role for destroy
	session, err := v.authorize(ctx, sessionToken, req.OrgID, "vault:delete")
	if err != nil {
		return 0, err
	}
	if session.Role != "admin" && session.Role != "master" {
		return 0, NewDomainError(ErrorPermissionDenied, "admin role required", nil)
	}

	count, err := v.vaultStore.DestroyVaultEntry(ctx, req.OrgID, req.ScopeID, req.EntryType, req.Key, req.EnvTypeID, req.Version)
	if err != nil {
		return 0, internalError("failed to destroy vault entry", err)
	}

	_ = v.auditLogger.Log(ctx, req.OrgID, "vault_destroy", session.MemberID,
		fmt.Sprintf("Destroyed %s/%s/%s (count: %d)", req.ScopeID, req.EntryType, req.Key, count), "")

	return count, nil
}

// VaultListRequest represents a list request.
type VaultListRequest struct {
	OrgID     string
	ScopeID   string
	EntryType string
	EnvTypeID *string
}

// VaultListResponse holds the list result.
type VaultListResponse struct {
	Entries []store.VaultListItem
}

// List returns all active keys within a scope.
func (v *VaultService) List(ctx context.Context, sessionToken string, req *VaultListRequest) (*VaultListResponse, error) {
	if req == nil {
		return nil, invalidArgument("request is required")
	}
	if err := validateVaultFields(req.OrgID, req.ScopeID, req.EntryType, "", false); err != nil {
		return nil, err
	}

	// Validate session
	if _, err := v.authorize(ctx, sessionToken, req.OrgID, "vault:read"); err != nil {
		return nil, err
	}

	entries, err := v.vaultStore.ListVaultEntries(ctx, req.OrgID, req.ScopeID, req.EntryType, req.EnvTypeID)
	if err != nil {
		return nil, internalError("failed to list vault entries", err)
	}

	return &VaultListResponse{Entries: entries}, nil
}

// VaultHistoryRequest represents a history request.
type VaultHistoryRequest struct {
	OrgID     string
	ScopeID   string
	EntryType string
	Key       string
	EnvTypeID *string
}

// VaultHistoryResponse holds version history.
type VaultHistoryResponse struct {
	Versions []VaultVersionInfo
}

// VaultVersionInfo describes a single version.
type VaultVersionInfo struct {
	Version      int
	KeyVersionID string
	CreatedAt    time.Time
	CreatedBy    *string
	Deleted      bool
	Destroyed    bool
}

// History returns the version history of a vault entry.
func (v *VaultService) History(ctx context.Context, sessionToken string, req *VaultHistoryRequest) (*VaultHistoryResponse, error) {
	if req == nil {
		return nil, invalidArgument("request is required")
	}
	if err := validateVaultFields(req.OrgID, req.ScopeID, req.EntryType, req.Key, true); err != nil {
		return nil, err
	}

	// Validate session
	if _, err := v.authorize(ctx, sessionToken, req.OrgID, "vault:read"); err != nil {
		return nil, err
	}

	entries, err := v.vaultStore.GetVaultEntryHistory(ctx, req.OrgID, req.ScopeID, req.EntryType, req.Key, req.EnvTypeID)
	if err != nil {
		return nil, internalError("failed to get vault history", err)
	}

	versions := make([]VaultVersionInfo, len(entries))
	for i, e := range entries {
		versions[i] = VaultVersionInfo{
			Version:      e.Version,
			KeyVersionID: e.KeyVersionID,
			CreatedAt:    e.CreatedAt,
			CreatedBy:    e.CreatedBy,
			Deleted:      e.DeletedAt != nil,
			Destroyed:    e.Destroyed,
		}
	}

	return &VaultHistoryResponse{Versions: versions}, nil
}

// --- Internal helpers ---

// getOrgCAPublicKey retrieves the Org CA's public key from the certificates table.
// The public key is always available (stored in the cert) — no session needed for encrypt.
func (v *VaultService) getOrgCAPublicKey(ctx context.Context, orgID string) (*ecdsa.PublicKey, error) {
	certRecord, err := v.vaultStore.GetOrgCA(ctx, orgID)
	if err != nil {
		return nil, internalError("failed to get Org CA certificate", err)
	}
	if certRecord == nil {
		return nil, NewDomainError(ErrorFailedPrecondition, "organization PKI is not initialized", nil)
	}

	block, _ := pem.Decode([]byte(certRecord.CertPEM))
	if block == nil {
		return nil, internalError("invalid stored Org CA PEM", nil)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, internalError("failed to parse stored Org CA certificate", err)
	}

	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, internalError("stored Org CA certificate has an unsupported public key", nil)
	}

	return pub, nil
}

// decryptEntry performs KMS unwrap (Layer 3) and optionally ECIES unwrap (Layer 2).
func (v *VaultService) decryptEntry(ctx context.Context, session *ValidateSessionResponse, entry *store.VaultEntry, clientSideDecrypt bool) (*VaultReadResponse, error) {
	// Layer 3: KMS unwrap
	dek, err := v.dekManager.GetDEKByVersion(ctx, entry.OrgID, entry.ScopeID, entry.KeyVersionID)
	if err != nil {
		if errors.Is(err, keys.ErrKeyVersionNotFound) || errors.Is(err, keys.ErrKeyVersionRequired) {
			return nil, NewDomainError(ErrorFailedPrecondition, "vault entry key version is unavailable", err)
		}
		return nil, internalError("failed to get vault entry key version", err)
	}
	defer zeroize(dek)

	aad := fmt.Sprintf("%s:%s:%s:%s", entry.EntryType, entry.OrgID, entry.ScopeID, entry.Key)
	if entry.EnvTypeID != nil {
		aad = fmt.Sprintf("%s:%s:%s:%s:%s", entry.EntryType, entry.OrgID, entry.ScopeID, *entry.EnvTypeID, entry.Key)
	}

	eciesOutput, err := crypto.Decrypt(dek, entry.EncryptedValue, []byte(aad))
	if err != nil {
		return nil, internalError("KMS decryption failed", err)
	}

	resp := &VaultReadResponse{
		ID:           entry.ID,
		OrgID:        entry.OrgID,
		ScopeID:      entry.ScopeID,
		EntryType:    entry.EntryType,
		Key:          entry.Key,
		EnvTypeID:    entry.EnvTypeID,
		KeyVersionID: entry.KeyVersionID,
		Version:      entry.Version,
		CreatedAt:    entry.CreatedAt,
		CreatedBy:    entry.CreatedBy,
	}

	if clientSideDecrypt {
		// BYOK path: return ECIES blob + member wrap data for client-side decryption
		ephPub, wrappedKey, err := v.orgCAWrapMgr.GetWrapData(ctx, entry.OrgID, session.MemberID)
		if err != nil {
			if errors.Is(err, keys.ErrOrgCAWrapNotFound) || errors.Is(err, keys.ErrOrgCAWrapRevoked) {
				return nil, NewDomainError(ErrorFailedPrecondition, "member key wrapping is not available", err)
			}
			return nil, internalError("failed to get member wrap data", err)
		}

		resp.EncryptedValue = eciesOutput
		resp.MemberWrapEphemeralPub = ephPub
		resp.MemberWrappedOrgCAKey = wrappedKey
	} else {
		// Managed path: server-side ECIES unwrap using member's managed key
		// The server needs the member's private key to unwrap the Org CA key
		orgCAPrivKey, err := v.unwrapOrgCAForManagedMember(ctx, entry.OrgID, session.MemberID)
		if err != nil {
			return nil, err
		}

		// ECIES decrypt
		rsaBlob, err := crypto.ECIESDecrypt(orgCAPrivKey, eciesOutput, "envsync-ecies-v1", entry.OrgID, []byte(entry.OrgID))
		if err != nil {
			return nil, internalError("ECIES decryption failed", err)
		}

		resp.EncryptedValue = rsaBlob // Layer 1 output for envsync-api to handle
	}

	_ = v.auditLogger.Log(ctx, entry.OrgID, "vault_read", session.MemberID,
		fmt.Sprintf("Read %s/%s/%s v%d with key version %s",
			entry.ScopeID, entry.EntryType, entry.Key, entry.Version, entry.KeyVersionID), "")

	return resp, nil
}

// unwrapOrgCAForManagedMember recovers the Org CA private key for a managed member.
// For managed members, the server has access to the member's encrypted private key
// stored in the certificates table.
func (v *VaultService) unwrapOrgCAForManagedMember(ctx context.Context, orgID, memberID string) (*ecdsa.PrivateKey, error) {
	// Get the member's wrap record to find their cert serial
	wrapRecord, err := v.vaultStore.GetOrgCAWrap(ctx, orgID, memberID)
	if err != nil {
		return nil, internalError("failed to get Org CA wrap", err)
	}
	if wrapRecord == nil {
		return nil, NewDomainError(ErrorFailedPrecondition, "member key wrapping is not available", nil)
	}

	// Load member's encrypted private key using the cert serial from the wrap
	certRecord, err := v.vaultStore.GetCertificateBySerialWithKey(ctx, wrapRecord.CertSerial)
	if err != nil {
		return nil, internalError("failed to get member certificate", err)
	}
	if certRecord == nil {
		return nil, NewDomainError(ErrorFailedPrecondition, "managed member key is not available", nil)
	}
	if len(certRecord.EncryptedPrivateKey) == 0 {
		return nil, NewDomainError(ErrorFailedPrecondition, "managed member key is not available", nil)
	}

	// Deserialize the managed member's private key
	memberPrivKey, err := crypto.UnmarshalECPrivateKey(certRecord.EncryptedPrivateKey)
	if err != nil {
		return nil, internalError("failed to decode managed member key", err)
	}

	// Unwrap the Org CA key using the member's private key via the manager
	orgCAKey, err := v.orgCAWrapMgr.UnwrapOrgCA(ctx, orgID, memberID, memberPrivKey)
	if err != nil {
		if errors.Is(err, keys.ErrOrgCAWrapNotFound) || errors.Is(err, keys.ErrOrgCAWrapRevoked) {
			return nil, NewDomainError(ErrorFailedPrecondition, "member key wrapping is not available", err)
		}
		return nil, internalError("failed to unwrap Org CA key", err)
	}

	return orgCAKey, nil
}

func (v *VaultService) authorize(ctx context.Context, sessionToken, orgID, scope string) (*ValidateSessionResponse, error) {
	session, err := v.sessionService.ValidateSessionFromToken(ctx, sessionToken)
	if err != nil {
		return nil, err
	}
	if !HasScope(session, scope) {
		return nil, NewDomainError(ErrorPermissionDenied, scope+" permission required", nil)
	}
	if session.OrgID != orgID {
		return nil, NewDomainError(ErrorPermissionDenied, "organization access denied", nil)
	}
	return session, nil
}

func validateVaultFields(orgID, scopeID, entryType, key string, keyRequired bool) error {
	fields := []struct {
		name  string
		value string
	}{
		requiredField("org_id", orgID),
		requiredField("scope_id", scopeID),
		requiredField("entry_type", entryType),
	}
	if keyRequired {
		fields = append(fields, requiredField("key", key))
	}
	if err := requireFields(fields...); err != nil {
		return err
	}

	switch entryType {
	case "env", "secret", "gpg":
		return nil
	default:
		return invalidArgument("entry_type must be one of env, secret, or gpg")
	}
}
