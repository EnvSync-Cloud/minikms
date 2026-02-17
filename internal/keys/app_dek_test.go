package keys_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/envsync/minikms/internal/crypto"
	"github.com/envsync/minikms/internal/keys"
	"github.com/envsync/minikms/internal/testutil"
)

const testRootKeyHexDEK = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func setupDEKTest(t *testing.T) (*keys.AppDEKManager, *testutil.MockDEKStore) {
	t.Helper()
	holder := keys.NewRootKeyHolder()
	if err := holder.Load(testRootKeyHexDEK); err != nil {
		t.Fatalf("Load: %v", err)
	}
	orgKeyMgr := keys.NewOrgKeyManager(holder)
	store := testutil.NewMockDEKStore()
	mgr := keys.NewAppDEKManager(orgKeyMgr, store, 100) // low max for testing
	return mgr, store
}

func TestAppDEKManager_GetOrCreateDEK(t *testing.T) {
	ctx := context.Background()

	t.Run("creates new DEK", func(t *testing.T) {
		mgr, _ := setupDEKTest(t)
		dek, kvID, err := mgr.GetOrCreateDEK(ctx, "org1", "app1")
		if err != nil {
			t.Fatalf("GetOrCreateDEK: %v", err)
		}
		if len(dek) != 32 {
			t.Fatalf("DEK length: got %d, want 32", len(dek))
		}
		if kvID == "" {
			t.Fatal("key version ID should not be empty")
		}
	})

	t.Run("returns existing DEK", func(t *testing.T) {
		mgr, _ := setupDEKTest(t)
		dek1, kvID1, _ := mgr.GetOrCreateDEK(ctx, "org1", "app1")
		dek2, kvID2, _ := mgr.GetOrCreateDEK(ctx, "org1", "app1")

		if !bytes.Equal(dek1, dek2) {
			t.Fatal("should return same DEK for same org/app")
		}
		if kvID1 != kvID2 {
			t.Fatal("should return same key version ID")
		}
	})
}

func TestAppDEKManager_RotateDEK(t *testing.T) {
	ctx := context.Background()

	t.Run("first rotation creates new", func(t *testing.T) {
		mgr, _ := setupDEKTest(t)
		_, _, _ = mgr.GetOrCreateDEK(ctx, "org1", "app1")

		newID, err := mgr.RotateDEK(ctx, "org1", "app1")
		if err != nil {
			t.Fatalf("RotateDEK: %v", err)
		}
		if newID == "" {
			t.Fatal("new key version ID should not be empty")
		}
	})

	t.Run("rotation retires old key", func(t *testing.T) {
		mgr, store := setupDEKTest(t)
		_, oldID, _ := mgr.GetOrCreateDEK(ctx, "org1", "app1")

		_, err := mgr.RotateDEK(ctx, "org1", "app1")
		if err != nil {
			t.Fatalf("RotateDEK: %v", err)
		}

		oldRec := store.GetByID(oldID)
		if oldRec != nil && oldRec.Status != string(crypto.KeyStatusRetired) {
			t.Errorf("old key status: got %q, want %q", oldRec.Status, crypto.KeyStatusRetired)
		}
	})
}

func TestAppDEKManager_IncrementAndCheckRotation(t *testing.T) {
	ctx := context.Background()

	t.Run("active status", func(t *testing.T) {
		mgr, _ := setupDEKTest(t)
		_, kvID, _ := mgr.GetOrCreateDEK(ctx, "org1", "app1")

		status, err := mgr.IncrementAndCheckRotation(ctx, kvID)
		if err != nil {
			t.Fatalf("IncrementAndCheckRotation: %v", err)
		}
		if status != crypto.KeyStatusActive {
			t.Errorf("status: got %q, want %q", status, crypto.KeyStatusActive)
		}
	})

	t.Run("rotate pending at 90%", func(t *testing.T) {
		mgr, store := setupDEKTest(t)
		_, kvID, _ := mgr.GetOrCreateDEK(ctx, "org1", "app1")

		store.SetCount(kvID, 89)

		status, err := mgr.IncrementAndCheckRotation(ctx, kvID)
		if err != nil {
			t.Fatalf("IncrementAndCheckRotation: %v", err)
		}
		if status != crypto.KeyStatusRotatePending {
			t.Errorf("status: got %q, want %q", status, crypto.KeyStatusRotatePending)
		}
	})

	t.Run("retired at max", func(t *testing.T) {
		mgr, store := setupDEKTest(t)
		_, kvID, _ := mgr.GetOrCreateDEK(ctx, "org1", "app1")

		store.SetCount(kvID, 99)

		status, err := mgr.IncrementAndCheckRotation(ctx, kvID)
		if err != nil {
			t.Fatalf("IncrementAndCheckRotation: %v", err)
		}
		if status != crypto.KeyStatusRetired {
			t.Errorf("status: got %q, want %q", status, crypto.KeyStatusRetired)
		}
	})
}

func TestAppDEKManager_EncryptDecryptRoundtrip(t *testing.T) {
	ctx := context.Background()
	mgr, _ := setupDEKTest(t)

	dek, _, err := mgr.GetOrCreateDEK(ctx, "org1", "app1")
	if err != nil {
		t.Fatalf("GetOrCreateDEK: %v", err)
	}

	plaintext := []byte("secret data")
	aad := []byte("org1:app1")
	ct, err := crypto.Encrypt(dek, plaintext, aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	dek2, _, _ := mgr.GetOrCreateDEK(ctx, "org1", "app1")
	pt, err := crypto.Decrypt(dek2, ct, aad)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if !bytes.Equal(pt, plaintext) {
		t.Fatal("roundtrip plaintext mismatch")
	}
}
