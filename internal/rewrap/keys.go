package rewrap

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/envsync-cloud/minikms/internal/crypto"
	"github.com/envsync-cloud/minikms/internal/keys"
)

// LoadCurrentRootKey loads the current root key the same way the server does:
// MINIKMS_ROOT_KEY_FILE or MINIKMS_ROOT_KEY, one source only.
func LoadCurrentRootKey(value, path string) ([]byte, error) {
	keyHex, err := keys.LoadRootKeyHex(value, path)
	if err != nil {
		return nil, err
	}
	key, err := decodeRootKey(keyHex)
	if err != nil {
		return nil, fmt.Errorf("current root key: %w", err)
	}
	return key, nil
}

// LoadNewRootKey loads the replacement root key from a file. The file must
// exist and pass the same permission check as the current root key file.
// The new key is not read from a flag value or an environment variable.
func LoadNewRootKey(path string) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("new root key file is required")
	}
	keyHex, err := keys.LoadRootKeyHex("", path)
	if err != nil {
		return nil, err
	}
	key, err := decodeRootKey(keyHex)
	if err != nil {
		return nil, fmt.Errorf("new root key: %w", err)
	}
	return key, nil
}

func decodeRootKey(keyHex string) ([]byte, error) {
	key, err := hex.DecodeString(strings.TrimSpace(keyHex))
	if err != nil {
		return nil, fmt.Errorf("root key must be hex encoded")
	}
	if len(key) != crypto.AES256KeySize {
		crypto.ZeroizeBytes(key)
		return nil, fmt.Errorf("root key must be 32 bytes")
	}
	return key, nil
}
