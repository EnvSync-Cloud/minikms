package keys

import (
	"context"
	"fmt"

	"github.com/envsync/minikms/internal/crypto"
)

// DEKStore defines the interface for persisting encrypted DEKs.
type DEKStore interface {
	// GetActiveKeyVersion returns the currently active key version for an app.
	GetActiveKeyVersion(ctx context.Context, orgID, appID string) (*KeyVersionRecord, error)
	// CreateKeyVersion stores a new encrypted key version.
	CreateKeyVersion(ctx context.Context, record *KeyVersionRecord) error
	// IncrementEncryptionCount atomically increments the encryption count.
	IncrementEncryptionCount(ctx context.Context, keyVersionID string) (int64, error)
	// UpdateKeyStatus updates the key version status.
	UpdateKeyStatus(ctx context.Context, keyVersionID string, status string) error
}

// KeyVersionRecord represents a stored key version.
type KeyVersionRecord struct {
	ID              string
	OrgID           string
	AppID           string
	KeyType         string // "app_dek"
	Version         int
	EncryptedKey    []byte // DEK encrypted with org master key
	EncryptionCount int64
	MaxEncryptions  int64
	Status          string // active, rotate_pending, retired
}

// AppDEKManager manages per-app data encryption keys.
type AppDEKManager struct {
	orgKeyMgr      *OrgKeyManager
	store          DEKStore
	maxEncryptions int64
}

// NewAppDEKManager creates a new AppDEKManager.
func NewAppDEKManager(orgKeyMgr *OrgKeyManager, store DEKStore, maxEncryptions int64) *AppDEKManager {
	if maxEncryptions <= 0 {
		maxEncryptions = crypto.DefaultMaxEncryptions
	}
	return &AppDEKManager{
		orgKeyMgr:      orgKeyMgr,
		store:          store,
		maxEncryptions: maxEncryptions,
	}
}

// GetOrCreateDEK returns the active DEK for an app, creating one if none exists.
// The returned key is the plaintext DEK — callers must handle it securely.
func (m *AppDEKManager) GetOrCreateDEK(ctx context.Context, orgID, appID string) ([]byte, string, error) {
	record, err := m.store.GetActiveKeyVersion(ctx, orgID, appID)
	if err != nil {
		return nil, "", fmt.Errorf("failed to query active key version: %w", err)
	}

	if record != nil {
		dek, err := m.decryptDEK(orgID, record.EncryptedKey)
		if err != nil {
			return nil, "", err
		}
		return dek, record.ID, nil
	}

	return m.createNewDEK(ctx, orgID, appID, 1)
}

// RotateDEK creates a new key version for an app, retiring the current one.
func (m *AppDEKManager) RotateDEK(ctx context.Context, orgID, appID string) (string, error) {
	current, err := m.store.GetActiveKeyVersion(ctx, orgID, appID)
	if err != nil {
		return "", fmt.Errorf("failed to query current key version: %w", err)
	}

	newVersion := 1
	if current != nil {
		if err := m.store.UpdateKeyStatus(ctx, current.ID, string(crypto.KeyStatusRetired)); err != nil {
			return "", fmt.Errorf("failed to retire current key: %w", err)
		}
		newVersion = current.Version + 1
	}

	_, keyVersionID, err := m.createNewDEK(ctx, orgID, appID, newVersion)
	if err != nil {
		return "", err
	}
	return keyVersionID, nil
}

// IncrementAndCheckRotation atomically increments the encryption count and
// returns whether rotation is needed.
func (m *AppDEKManager) IncrementAndCheckRotation(ctx context.Context, keyVersionID string) (crypto.KeyStatus, error) {
	newCount, err := m.store.IncrementEncryptionCount(ctx, keyVersionID)
	if err != nil {
		return "", fmt.Errorf("failed to increment encryption count: %w", err)
	}

	status, err := crypto.CheckEncryptionCount(newCount, m.maxEncryptions)
	if err != nil {
		return "", err
	}

	if status != crypto.KeyStatusActive {
		if err := m.store.UpdateKeyStatus(ctx, keyVersionID, string(status)); err != nil {
			return "", fmt.Errorf("failed to update key status: %w", err)
		}
	}

	return status, nil
}

func (m *AppDEKManager) createNewDEK(ctx context.Context, orgID, appID string, version int) ([]byte, string, error) {
	dek, err := crypto.GenerateKey()
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate DEK: %w", err)
	}

	encryptedDEK, err := m.encryptDEK(orgID, dek)
	if err != nil {
		return nil, "", err
	}

	record := &KeyVersionRecord{
		OrgID:           orgID,
		AppID:           appID,
		KeyType:         "app_dek",
		Version:         version,
		EncryptedKey:    encryptedDEK,
		EncryptionCount: 0,
		MaxEncryptions:  m.maxEncryptions,
		Status:          string(crypto.KeyStatusActive),
	}

	if err := m.store.CreateKeyVersion(ctx, record); err != nil {
		return nil, "", fmt.Errorf("failed to store key version: %w", err)
	}

	return dek, record.ID, nil
}

func (m *AppDEKManager) encryptDEK(orgID string, dek []byte) ([]byte, error) {
	orgKey, err := m.orgKeyMgr.DeriveOrgKey(orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to derive org key: %w", err)
	}
	defer zeroize(orgKey)

	aad := []byte("dek:" + orgID)
	encrypted, err := crypto.Encrypt(orgKey, dek, aad)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt DEK: %w", err)
	}
	return encrypted, nil
}

func (m *AppDEKManager) decryptDEK(orgID string, encryptedDEK []byte) ([]byte, error) {
	orgKey, err := m.orgKeyMgr.DeriveOrgKey(orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to derive org key: %w", err)
	}
	defer zeroize(orgKey)

	aad := []byte("dek:" + orgID)
	dek, err := crypto.Decrypt(orgKey, encryptedDEK, aad)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt DEK: %w", err)
	}
	return dek, nil
}
