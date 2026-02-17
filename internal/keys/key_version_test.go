package keys_test

import (
	"context"
	"testing"

	"github.com/envsync/minikms/internal/keys"
	"github.com/envsync/minikms/internal/testutil"
)

const testRootKeyHexKV = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestKeyVersionManager_GetKeyInfo(t *testing.T) {
	ctx := context.Background()

	t.Run("exists", func(t *testing.T) {
		holder := keys.NewRootKeyHolder()
		_ = holder.Load(testRootKeyHexKV)
		orgKeyMgr := keys.NewOrgKeyManager(holder)
		store := testutil.NewMockDEKStore()
		dekMgr := keys.NewAppDEKManager(orgKeyMgr, store, 1000)
		vMgr := keys.NewKeyVersionManager(store, 1000)

		_, _, _ = dekMgr.GetOrCreateDEK(ctx, "org1", "app1")

		info, err := vMgr.GetKeyInfo(ctx, "org1", "app1")
		if err != nil {
			t.Fatalf("GetKeyInfo: %v", err)
		}
		if info.OrgID != "org1" {
			t.Errorf("OrgID: got %q, want %q", info.OrgID, "org1")
		}
		if info.EncryptedKey != nil {
			t.Error("EncryptedKey should be stripped from response")
		}
	})

	t.Run("not found", func(t *testing.T) {
		store := testutil.NewMockDEKStore()
		vMgr := keys.NewKeyVersionManager(store, 1000)

		_, err := vMgr.GetKeyInfo(ctx, "org1", "nonexistent")
		if err == nil {
			t.Fatal("expected error for nonexistent key")
		}
	})
}

func TestKeyVersionManager_ShouldRotate(t *testing.T) {
	ctx := context.Background()

	t.Run("active key - no rotation needed", func(t *testing.T) {
		holder := keys.NewRootKeyHolder()
		_ = holder.Load(testRootKeyHexKV)
		orgKeyMgr := keys.NewOrgKeyManager(holder)
		store := testutil.NewMockDEKStore()
		dekMgr := keys.NewAppDEKManager(orgKeyMgr, store, 1000)
		vMgr := keys.NewKeyVersionManager(store, 1000)

		_, _, _ = dekMgr.GetOrCreateDEK(ctx, "org1", "app1")

		shouldRotate, err := vMgr.ShouldRotate(ctx, "org1", "app1")
		if err != nil {
			t.Fatalf("ShouldRotate: %v", err)
		}
		if shouldRotate {
			t.Fatal("fresh key should not need rotation")
		}
	})

	t.Run("key needs rotation", func(t *testing.T) {
		holder := keys.NewRootKeyHolder()
		_ = holder.Load(testRootKeyHexKV)
		orgKeyMgr := keys.NewOrgKeyManager(holder)
		store := testutil.NewMockDEKStore()
		dekMgr := keys.NewAppDEKManager(orgKeyMgr, store, 100)
		vMgr := keys.NewKeyVersionManager(store, 100)

		_, kvID, _ := dekMgr.GetOrCreateDEK(ctx, "org1", "app1")
		store.SetCount(kvID, 95) // 95% of 100

		shouldRotate, err := vMgr.ShouldRotate(ctx, "org1", "app1")
		if err != nil {
			t.Fatalf("ShouldRotate: %v", err)
		}
		if !shouldRotate {
			t.Fatal("key at 95% should need rotation")
		}
	})

	t.Run("no key exists", func(t *testing.T) {
		store := testutil.NewMockDEKStore()
		vMgr := keys.NewKeyVersionManager(store, 1000)

		shouldRotate, err := vMgr.ShouldRotate(ctx, "org1", "nonexistent")
		if err != nil {
			t.Fatalf("ShouldRotate: %v", err)
		}
		if shouldRotate {
			t.Fatal("no key should not need rotation")
		}
	})
}
