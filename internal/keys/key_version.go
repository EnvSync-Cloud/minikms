package keys

import (
	"context"
	"fmt"

	"github.com/envsync/minikms/internal/crypto"
)

// KeyVersionManager provides key version lifecycle operations.
type KeyVersionManager struct {
	store          DEKStore
	maxEncryptions int64
}

// NewKeyVersionManager creates a new KeyVersionManager.
func NewKeyVersionManager(store DEKStore, maxEncryptions int64) *KeyVersionManager {
	if maxEncryptions <= 0 {
		maxEncryptions = crypto.DefaultMaxEncryptions
	}
	return &KeyVersionManager{store: store, maxEncryptions: maxEncryptions}
}

// GetKeyInfo returns metadata about the active key version for an app.
func (m *KeyVersionManager) GetKeyInfo(ctx context.Context, orgID, appID string) (*KeyVersionRecord, error) {
	record, err := m.store.GetActiveKeyVersion(ctx, orgID, appID)
	if err != nil {
		return nil, fmt.Errorf("failed to get key info: %w", err)
	}
	if record == nil {
		return nil, fmt.Errorf("no active key version for org=%s app=%s", orgID, appID)
	}
	// Strip the encrypted key material from the response
	record.EncryptedKey = nil
	return record, nil
}

// ShouldRotate checks if the active key for an app needs rotation.
func (m *KeyVersionManager) ShouldRotate(ctx context.Context, orgID, appID string) (bool, error) {
	record, err := m.store.GetActiveKeyVersion(ctx, orgID, appID)
	if err != nil {
		return false, err
	}
	if record == nil {
		return false, nil
	}

	status, err := crypto.CheckEncryptionCount(record.EncryptionCount, m.maxEncryptions)
	if err != nil {
		return false, err
	}

	return status != crypto.KeyStatusActive, nil
}
