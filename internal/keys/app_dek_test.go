package keys_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/envsync-cloud/minikms/internal/crypto"
	"github.com/envsync-cloud/minikms/internal/keys"
	"github.com/envsync-cloud/minikms/internal/testutil"
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

func TestGetOrCreateDEK_Concurrent(t *testing.T) {
	ctx := context.Background()
	mgr, _ := setupDEKTest(t)

	const goroutines = 10
	results := make(chan struct {
		dek  []byte
		kvID string
		err  error
	}, goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			dek, kvID, err := mgr.GetOrCreateDEK(ctx, "org-concurrent", "app-concurrent")
			results <- struct {
				dek  []byte
				kvID string
				err  error
			}{dek, kvID, err}
		}()
	}

	var firstDEK []byte
	var firstKVID string
	for i := 0; i < goroutines; i++ {
		r := <-results
		if r.err != nil {
			t.Fatalf("goroutine %d: GetOrCreateDEK: %v", i, r.err)
		}
		if firstDEK == nil {
			firstDEK = r.dek
			firstKVID = r.kvID
		} else {
			if !bytes.Equal(firstDEK, r.dek) {
				t.Error("concurrent calls returned different DEKs")
			}
			if firstKVID != r.kvID {
				t.Error("concurrent calls returned different key version IDs")
			}
		}
	}
}

func TestGetOrCreateDEK_DifferentApps(t *testing.T) {
	ctx := context.Background()
	mgr, _ := setupDEKTest(t)

	dek1, kvID1, err := mgr.GetOrCreateDEK(ctx, "org1", "app-alpha")
	if err != nil {
		t.Fatalf("GetOrCreateDEK app-alpha: %v", err)
	}
	dek2, kvID2, err := mgr.GetOrCreateDEK(ctx, "org1", "app-beta")
	if err != nil {
		t.Fatalf("GetOrCreateDEK app-beta: %v", err)
	}

	if bytes.Equal(dek1, dek2) {
		t.Error("different apps should get different DEKs")
	}
	if kvID1 == kvID2 {
		t.Error("different apps should get different key version IDs")
	}
}

func TestRotateDEK_DuringActiveEncryption(t *testing.T) {
	ctx := context.Background()
	mgr, _ := setupDEKTest(t)

	// Get the initial DEK
	dek1, _, err := mgr.GetOrCreateDEK(ctx, "org1", "app-rotate")
	if err != nil {
		t.Fatalf("GetOrCreateDEK: %v", err)
	}

	// Encrypt with old DEK
	plaintext := []byte("data before rotation")
	aad := []byte("org1:app-rotate")
	ct, err := crypto.Encrypt(dek1, plaintext, aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Rotate
	_, err = mgr.RotateDEK(ctx, "org1", "app-rotate")
	if err != nil {
		t.Fatalf("RotateDEK: %v", err)
	}

	// Old DEK should still decrypt old ciphertext
	pt, err := crypto.Decrypt(dek1, ct, aad)
	if err != nil {
		t.Fatalf("Decrypt with old DEK after rotation: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Error("plaintext mismatch after decryption with old DEK")
	}

	// New DEK should be different
	dek2, _, err := mgr.GetOrCreateDEK(ctx, "org1", "app-rotate")
	if err != nil {
		t.Fatalf("GetOrCreateDEK after rotation: %v", err)
	}
	if bytes.Equal(dek1, dek2) {
		t.Error("rotated DEK should be different from original")
	}
}

func TestIncrementAndCheckRotation_ExactThreshold(t *testing.T) {
	ctx := context.Background()

	t.Run("exactly at 90%", func(t *testing.T) {
		mgr, store := setupDEKTest(t)
		_, kvID, _ := mgr.GetOrCreateDEK(ctx, "org1", "app-thresh90")

		// maxEncryptions=100, 90% = 90, set count to 89 so next increment = 90
		store.SetCount(kvID, 89)

		status, err := mgr.IncrementAndCheckRotation(ctx, kvID)
		if err != nil {
			t.Fatalf("IncrementAndCheckRotation: %v", err)
		}
		if status != crypto.KeyStatusRotatePending {
			t.Errorf("at 90%%: got %q, want %q", status, crypto.KeyStatusRotatePending)
		}
	})

	t.Run("exactly at 100%", func(t *testing.T) {
		mgr, store := setupDEKTest(t)
		_, kvID, _ := mgr.GetOrCreateDEK(ctx, "org1", "app-thresh100")

		// maxEncryptions=100, set count to 99 so next increment = 100
		store.SetCount(kvID, 99)

		status, err := mgr.IncrementAndCheckRotation(ctx, kvID)
		if err != nil {
			t.Fatalf("IncrementAndCheckRotation: %v", err)
		}
		if status != crypto.KeyStatusRetired {
			t.Errorf("at 100%%: got %q, want %q", status, crypto.KeyStatusRetired)
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
