package keys

import (
	"fmt"

	"github.com/envsync-cloud/minikms/internal/crypto"
)

// OrgKeyManager handles org master key derivation via HKDF.
// Org master keys are derived on-demand from the root key and never persisted in plaintext.
type OrgKeyManager struct {
	rootKeyHolder *RootKeyHolder
}

// NewOrgKeyManager creates a new OrgKeyManager.
func NewOrgKeyManager(holder *RootKeyHolder) *OrgKeyManager {
	return &OrgKeyManager{rootKeyHolder: holder}
}

// DeriveOrgKey derives the org master key for the given org ID.
// The key is deterministic: same root key + org ID = same org master key.
func (m *OrgKeyManager) DeriveOrgKey(orgID string) ([]byte, error) {
	if orgID == "" {
		return nil, fmt.Errorf("org ID must not be empty")
	}

	rootKey, err := m.rootKeyHolder.GetKey()
	if err != nil {
		return nil, fmt.Errorf("cannot access root key: %w", err)
	}
	defer zeroize(rootKey)

	orgKey, err := crypto.DeriveOrgMasterKey(rootKey, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to derive org key for %s: %w", orgID, err)
	}
	return orgKey, nil
}

// zeroize overwrites a byte slice with zeros to reduce key material exposure in memory.
func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
