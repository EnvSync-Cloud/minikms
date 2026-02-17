package crypto

import (
	"bytes"
	"testing"
)

func TestGetHKDFSalt(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		salt := GetHKDFSalt()
		if salt != DefaultHKDFSalt {
			t.Errorf("got %q, want %q", salt, DefaultHKDFSalt)
		}
	})

	t.Run("custom via env", func(t *testing.T) {
		t.Setenv("MINIKMS_HKDF_SALT", "custom-salt")
		salt := GetHKDFSalt()
		if salt != "custom-salt" {
			t.Errorf("got %q, want %q", salt, "custom-salt")
		}
	})
}

func TestDeriveOrgMasterKey(t *testing.T) {
	rootKey := make([]byte, 32)
	for i := range rootKey {
		rootKey[i] = byte(i)
	}

	t.Run("deterministic", func(t *testing.T) {
		k1, err := DeriveOrgMasterKey(rootKey, "org1")
		if err != nil {
			t.Fatalf("DeriveOrgMasterKey: %v", err)
		}
		k2, err := DeriveOrgMasterKey(rootKey, "org1")
		if err != nil {
			t.Fatalf("DeriveOrgMasterKey: %v", err)
		}
		if !bytes.Equal(k1, k2) {
			t.Fatal("same inputs should produce same key")
		}
	})

	t.Run("32 byte output", func(t *testing.T) {
		k, err := DeriveOrgMasterKey(rootKey, "org1")
		if err != nil {
			t.Fatalf("DeriveOrgMasterKey: %v", err)
		}
		if len(k) != 32 {
			t.Fatalf("got %d bytes, want 32", len(k))
		}
	})

	t.Run("different orgs differ", func(t *testing.T) {
		k1, _ := DeriveOrgMasterKey(rootKey, "org1")
		k2, _ := DeriveOrgMasterKey(rootKey, "org2")
		if bytes.Equal(k1, k2) {
			t.Fatal("different orgs should produce different keys")
		}
	})

	t.Run("different roots differ", func(t *testing.T) {
		rootKey2 := make([]byte, 32)
		for i := range rootKey2 {
			rootKey2[i] = byte(i + 1)
		}
		k1, _ := DeriveOrgMasterKey(rootKey, "org1")
		k2, _ := DeriveOrgMasterKey(rootKey2, "org1")
		if bytes.Equal(k1, k2) {
			t.Fatal("different root keys should produce different org keys")
		}
	})

	t.Run("empty root key error", func(t *testing.T) {
		_, err := DeriveOrgMasterKey(nil, "org1")
		if err == nil {
			t.Fatal("expected error for empty root key")
		}
	})

	t.Run("empty orgID error", func(t *testing.T) {
		_, err := DeriveOrgMasterKey(rootKey, "")
		if err == nil {
			t.Fatal("expected error for empty orgID")
		}
	})
}

func TestDeriveSubKey(t *testing.T) {
	parentKey := make([]byte, 32)
	for i := range parentKey {
		parentKey[i] = byte(i)
	}

	t.Run("deterministic", func(t *testing.T) {
		k1, err := DeriveSubKey(parentKey, "encryption")
		if err != nil {
			t.Fatalf("DeriveSubKey: %v", err)
		}
		k2, err := DeriveSubKey(parentKey, "encryption")
		if err != nil {
			t.Fatalf("DeriveSubKey: %v", err)
		}
		if !bytes.Equal(k1, k2) {
			t.Fatal("same inputs should produce same key")
		}
	})

	t.Run("different purposes differ", func(t *testing.T) {
		k1, _ := DeriveSubKey(parentKey, "encryption")
		k2, _ := DeriveSubKey(parentKey, "signing")
		if bytes.Equal(k1, k2) {
			t.Fatal("different purposes should produce different keys")
		}
	})

	t.Run("empty parent key error", func(t *testing.T) {
		_, err := DeriveSubKey(nil, "encryption")
		if err == nil {
			t.Fatal("expected error for empty parent key")
		}
	})

	t.Run("empty purpose error", func(t *testing.T) {
		_, err := DeriveSubKey(parentKey, "")
		if err == nil {
			t.Fatal("expected error for empty purpose")
		}
	})
}
