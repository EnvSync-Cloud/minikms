package keys

import (
	"bytes"
	"testing"
)

const testRootKeyHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestOrgKeyManager_DeriveOrgKey(t *testing.T) {
	t.Run("valid derivation", func(t *testing.T) {
		h := NewRootKeyHolder()
		_ = h.Load(testRootKeyHex)
		mgr := NewOrgKeyManager(h)

		key, err := mgr.DeriveOrgKey("org-123")
		if err != nil {
			t.Fatalf("DeriveOrgKey: %v", err)
		}
		if len(key) != 32 {
			t.Fatalf("key length: got %d, want 32", len(key))
		}
	})

	t.Run("deterministic", func(t *testing.T) {
		h := NewRootKeyHolder()
		_ = h.Load(testRootKeyHex)
		mgr := NewOrgKeyManager(h)

		k1, _ := mgr.DeriveOrgKey("org-123")
		k2, _ := mgr.DeriveOrgKey("org-123")
		if !bytes.Equal(k1, k2) {
			t.Fatal("same orgID should produce same key")
		}
	})

	t.Run("different orgs differ", func(t *testing.T) {
		h := NewRootKeyHolder()
		_ = h.Load(testRootKeyHex)
		mgr := NewOrgKeyManager(h)

		k1, _ := mgr.DeriveOrgKey("org-1")
		k2, _ := mgr.DeriveOrgKey("org-2")
		if bytes.Equal(k1, k2) {
			t.Fatal("different orgs should produce different keys")
		}
	})

	t.Run("empty orgID error", func(t *testing.T) {
		h := NewRootKeyHolder()
		_ = h.Load(testRootKeyHex)
		mgr := NewOrgKeyManager(h)

		_, err := mgr.DeriveOrgKey("")
		if err == nil {
			t.Fatal("expected error for empty orgID")
		}
	})

	t.Run("root not loaded error", func(t *testing.T) {
		h := NewRootKeyHolder()
		mgr := NewOrgKeyManager(h)

		_, err := mgr.DeriveOrgKey("org-123")
		if err == nil {
			t.Fatal("expected error when root key not loaded")
		}
	})
}
