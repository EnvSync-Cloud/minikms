package memberkey

import "github.com/envsync-cloud/minikms/internal/keys"

// LoadRootKey loads the root key the same way the server does: exactly one of
// MINIKMS_ROOT_KEY or MINIKMS_ROOT_KEY_FILE, then RootKeyHolder.Load.
// Derivation uses MINIKMS_HKDF_SALT when it is set, matching in-process organization keys.
func LoadRootKey(value, path string) (*keys.OrgKeyManager, error) {
	keyHex, err := keys.LoadRootKeyHex(value, path)
	if err != nil {
		return nil, err
	}
	holder := keys.NewRootKeyHolder()
	if err := holder.Load(keyHex); err != nil {
		return nil, err
	}
	return keys.NewOrgKeyManager(holder), nil
}
