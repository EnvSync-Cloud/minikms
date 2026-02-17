package crypto

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/hkdf"
)

// DefaultHKDFSalt is the default salt for HKDF derivations.
// Override via MINIKMS_HKDF_SALT environment variable for non-EnvSync deployments.
const DefaultHKDFSalt = "envsync-minikms-v1"

// GetHKDFSalt returns the configured HKDF salt, falling back to the default.
func GetHKDFSalt() string {
	if salt := os.Getenv("MINIKMS_HKDF_SALT"); salt != "" {
		return salt
	}
	return DefaultHKDFSalt
}

// DeriveOrgMasterKey derives a 256-bit org master key from the root key using
// full HKDF Extract+Expand. The info parameter is the org ID, ensuring each org
// gets a unique deterministic key.
func DeriveOrgMasterKey(rootKey []byte, orgID string) ([]byte, error) {
	if len(rootKey) == 0 {
		return nil, fmt.Errorf("root key must not be empty")
	}
	if orgID == "" {
		return nil, fmt.Errorf("org ID must not be empty")
	}

	salt := GetHKDFSalt()
	// hkdf.New performs full Extract(salt, IKM) then Expand(PRK, info, L)
	h := hkdf.New(sha256.New, rootKey, []byte(salt), []byte(orgID))
	key := make([]byte, 32) // AES-256 key size
	if _, err := io.ReadFull(h, key); err != nil {
		return nil, fmt.Errorf("HKDF derivation failed: %w", err)
	}
	return key, nil
}

// DeriveSubKey derives a purpose-specific sub-key from a parent key.
// Used for creating separate keys for encryption, signing, etc.
func DeriveSubKey(parentKey []byte, purpose string) ([]byte, error) {
	if len(parentKey) == 0 {
		return nil, fmt.Errorf("parent key must not be empty")
	}
	if purpose == "" {
		return nil, fmt.Errorf("purpose must not be empty")
	}

	salt := GetHKDFSalt()
	h := hkdf.New(sha256.New, parentKey, []byte(salt), []byte(purpose))
	key := make([]byte, 32)
	if _, err := io.ReadFull(h, key); err != nil {
		return nil, fmt.Errorf("HKDF sub-key derivation failed: %w", err)
	}
	return key, nil
}
