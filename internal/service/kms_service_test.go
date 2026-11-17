package service

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/envsync-cloud/minikms/internal/authn"
	"github.com/envsync-cloud/minikms/internal/keys"
	"github.com/envsync-cloud/minikms/internal/testutil"
)

func ctxForTenant(tenantID string) context.Context {
	return authn.WithPrincipal(context.Background(), authn.Principal{
		TenantID: tenantID,
		ActorID:  "session-" + tenantID,
	})
}

func assertErrorKind(t *testing.T, err error, kind ErrorKind) {
	t.Helper()
	var domainErr *DomainError
	if !errors.As(err, &domainErr) {
		t.Fatalf("error = %v, want kind %s", err, kind)
	}
	if domainErr.Kind != kind {
		t.Fatalf("kind = %s, want %s", domainErr.Kind, kind)
	}
}

func setupKMSService(t *testing.T) *KMSService {
	t.Helper()
	_, _, dekMgr, _, auditLogger, _, err := testutil.SetupTestKMSStack(testutil.TestRootKeyHex)
	if err != nil {
		t.Fatalf("SetupTestKMSStack: %v", err)
	}
	return NewKMSService(dekMgr, auditLogger)
}

func TestKMSService_DecryptAfterRotation(t *testing.T) {
	ctx := ctxForTenant("org-rotate")
	_, _, dekMgr, _, auditLogger, auditStore, err := testutil.SetupTestKMSStack(testutil.TestRootKeyHex)
	if err != nil {
		t.Fatalf("SetupTestKMSStack: %v", err)
	}
	svc := NewKMSService(dekMgr, auditLogger)

	encResp, err := svc.Encrypt(ctx, &EncryptRequest{
		TenantID: "org-rotate", ScopeID: "app-rotate",
		Plaintext: []byte("before rotation"), AAD: "rotation-aad",
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	newID, err := dekMgr.RotateDEK(ctx, "org-rotate", "app-rotate")
	if err != nil {
		t.Fatalf("RotateDEK: %v", err)
	}
	if newID == encResp.KeyVersionID {
		t.Fatal("rotation did not create a new key version")
	}

	decResp, err := svc.Decrypt(ctx, &DecryptRequest{
		TenantID: "org-rotate", ScopeID: "app-rotate",
		Ciphertext: encResp.Ciphertext, AAD: "rotation-aad",
		KeyVersionID: encResp.KeyVersionID,
	})
	if err != nil {
		t.Fatalf("Decrypt old ciphertext after rotation: %v", err)
	}
	if !bytes.Equal(decResp.Plaintext, []byte("before rotation")) {
		t.Fatalf("plaintext = %q, want %q", decResp.Plaintext, "before rotation")
	}

	if _, err := svc.Decrypt(ctx, &DecryptRequest{
		TenantID: "org-rotate", ScopeID: "wrong-app",
		Ciphertext: encResp.Ciphertext, AAD: "rotation-aad",
		KeyVersionID: encResp.KeyVersionID,
	}); err == nil {
		t.Fatal("expected wrong-scope key lookup to fail")
	}

	entries, err := auditStore.GetEntries(ctx, "org-rotate", 10, 0)
	if err != nil {
		t.Fatalf("GetEntries: %v", err)
	}
	found := false
	for _, entry := range entries {
		if entry.Action == "decrypt" && strings.Contains(entry.Details, encResp.KeyVersionID) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("missing decrypt audit entry for key version %s", encResp.KeyVersionID)
	}
}

func TestKMSService_EncryptDecrypt(t *testing.T) {
	ctx := ctxForTenant("org1")
	svc := setupKMSService(t)

	t.Run("roundtrip", func(t *testing.T) {
		encResp, err := svc.Encrypt(ctx, &EncryptRequest{
			TenantID:  "org1",
			ScopeID:   "app1",
			Plaintext: []byte("secret data"),
			AAD:       "org1:app1",
		})
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}

		if encResp.Ciphertext == "" {
			t.Fatal("ciphertext should not be empty")
		}
		if encResp.KeyVersionID == "" {
			t.Fatal("key version ID should not be empty")
		}

		decResp, err := svc.Decrypt(ctx, &DecryptRequest{
			TenantID:     "org1",
			ScopeID:      "app1",
			Ciphertext:   encResp.Ciphertext,
			AAD:          "org1:app1",
			KeyVersionID: encResp.KeyVersionID,
		})
		if err != nil {
			t.Fatalf("Decrypt: %v", err)
		}

		if !bytes.Equal(decResp.Plaintext, []byte("secret data")) {
			t.Fatalf("plaintext mismatch: got %q", string(decResp.Plaintext))
		}
	})

	t.Run("valid base64 ciphertext", func(t *testing.T) {
		encResp, _ := svc.Encrypt(ctx, &EncryptRequest{
			TenantID:  "org1",
			ScopeID:   "app1",
			Plaintext: []byte("data"),
			AAD:       "ctx",
		})
		_, err := base64.StdEncoding.DecodeString(encResp.Ciphertext)
		if err != nil {
			t.Fatalf("ciphertext is not valid base64: %v", err)
		}
	})

	t.Run("wrong AAD fails", func(t *testing.T) {
		encResp, _ := svc.Encrypt(ctx, &EncryptRequest{
			TenantID:  "org1",
			ScopeID:   "app1",
			Plaintext: []byte("data"),
			AAD:       "correct-aad",
		})
		_, err := svc.Decrypt(ctx, &DecryptRequest{
			TenantID:     "org1",
			ScopeID:      "app1",
			Ciphertext:   encResp.Ciphertext,
			AAD:          "wrong-aad",
			KeyVersionID: encResp.KeyVersionID,
		})
		if err == nil {
			t.Fatal("expected error with wrong AAD")
		}
	})
}

func TestKMSService_BatchEncryptDecrypt(t *testing.T) {
	ctx := ctxForTenant("org1")
	svc := setupKMSService(t)

	items := []BatchEncryptItem{
		{Plaintext: []byte("secret1"), AAD: "ctx1"},
		{Plaintext: []byte("secret2"), AAD: "ctx2"},
		{Plaintext: []byte("secret3"), AAD: "ctx3"},
	}

	batchEncResp, err := svc.BatchEncrypt(ctx, &BatchEncryptRequest{
		TenantID: "org1",
		ScopeID:  "app1",
		Items:    items,
	})
	if err != nil {
		t.Fatalf("BatchEncrypt: %v", err)
	}

	if len(batchEncResp.Items) != 3 {
		t.Fatalf("expected 3 encrypted items, got %d", len(batchEncResp.Items))
	}

	// Build batch decrypt request
	decItems := make([]DecryptRequest, len(batchEncResp.Items))
	for i, encItem := range batchEncResp.Items {
		decItems[i] = DecryptRequest{
			TenantID:     "org1",
			ScopeID:      "app1",
			Ciphertext:   encItem.Ciphertext,
			AAD:          items[i].AAD,
			KeyVersionID: encItem.KeyVersionID,
		}
	}

	batchDecResp, err := svc.BatchDecrypt(ctx, &BatchDecryptRequest{
		TenantID: "org1",
		ScopeID:  "app1",
		Items:    decItems,
	})
	if err != nil {
		t.Fatalf("BatchDecrypt: %v", err)
	}

	for i, decItem := range batchDecResp.Items {
		if !bytes.Equal(decItem.Plaintext, items[i].Plaintext) {
			t.Errorf("item %d: got %q, want %q", i, string(decItem.Plaintext), string(items[i].Plaintext))
		}
	}
}

func TestKMSService_BatchDecryptMixedVersionsAfterRotation(t *testing.T) {
	ctx := ctxForTenant("org1")
	svc := setupKMSService(t)

	oldResp, err := svc.Encrypt(ctx, &EncryptRequest{
		TenantID: "org1", ScopeID: "mixed", Plaintext: []byte("old"), AAD: "old-aad",
	})
	if err != nil {
		t.Fatalf("Encrypt old item: %v", err)
	}
	if _, err := svc.dekManager.RotateDEK(ctx, "org1", "mixed"); err != nil {
		t.Fatalf("RotateDEK: %v", err)
	}
	newResp, err := svc.Encrypt(ctx, &EncryptRequest{
		TenantID: "org1", ScopeID: "mixed", Plaintext: []byte("new"), AAD: "new-aad",
	})
	if err != nil {
		t.Fatalf("Encrypt new item: %v", err)
	}

	resp, err := svc.BatchDecrypt(ctx, &BatchDecryptRequest{
		TenantID: "org1",
		ScopeID:  "mixed",
		Items: []DecryptRequest{
			{Ciphertext: oldResp.Ciphertext, AAD: "old-aad", KeyVersionID: oldResp.KeyVersionID},
			{Ciphertext: newResp.Ciphertext, AAD: "new-aad", KeyVersionID: newResp.KeyVersionID},
		},
	})
	if err != nil {
		t.Fatalf("BatchDecrypt mixed versions: %v", err)
	}
	if got := string(resp.Items[0].Plaintext); got != "old" {
		t.Fatalf("old plaintext = %q, want old", got)
	}
	if got := string(resp.Items[1].Plaintext); got != "new" {
		t.Fatalf("new plaintext = %q, want new", got)
	}
}

func TestKMSService_BatchDecrypt_InvalidBase64(t *testing.T) {
	ctx := ctxForTenant("org1")
	svc := setupKMSService(t)

	_, err := svc.BatchDecrypt(ctx, &BatchDecryptRequest{
		TenantID: "org1",
		ScopeID:  "app1",
		Items: []DecryptRequest{
			{Ciphertext: "not-valid-base64!!!", AAD: "ctx"},
		},
	})
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestKMSService_MissingPrincipalIsUnauthenticated(t *testing.T) {
	_, _, dekMgr, dekStore, auditLogger, _, err := testutil.SetupTestKMSStack(testutil.TestRootKeyHex)
	if err != nil {
		t.Fatalf("SetupTestKMSStack: %v", err)
	}
	svc := NewKMSService(dekMgr, auditLogger)
	keySvc := NewKeyService(dekMgr, keys.NewKeyVersionManager(dekStore, 1000), auditLogger)
	owner := ctxForTenant("org-a")

	enc, err := svc.Encrypt(owner, &EncryptRequest{
		TenantID: "org-a", ScopeID: "app-a", Plaintext: []byte("org-a-plaintext"), AAD: "org-a-aad",
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	batch, err := svc.BatchEncrypt(owner, &BatchEncryptRequest{
		TenantID: "org-a",
		ScopeID:  "app-a",
		Items:    []BatchEncryptItem{{Plaintext: []byte("batch-plaintext"), AAD: "batch-aad"}},
	})
	if err != nil {
		t.Fatalf("BatchEncrypt: %v", err)
	}

	anon := context.Background()

	t.Run("encrypt", func(t *testing.T) {
		resp, err := svc.Encrypt(anon, &EncryptRequest{
			TenantID: "org-a", ScopeID: "app-a", Plaintext: []byte("x"), AAD: "org-a-aad",
		})
		if resp != nil {
			t.Fatal("encrypted without a principal")
		}
		assertErrorKind(t, err, ErrorUnauthenticated)
	})

	t.Run("decrypt", func(t *testing.T) {
		resp, err := svc.Decrypt(anon, &DecryptRequest{
			TenantID: "org-a", ScopeID: "app-a",
			Ciphertext: enc.Ciphertext, AAD: "org-a-aad", KeyVersionID: enc.KeyVersionID,
		})
		if resp != nil {
			t.Fatal("decrypted without a principal")
		}
		assertErrorKind(t, err, ErrorUnauthenticated)
	})

	t.Run("batch_encrypt", func(t *testing.T) {
		resp, err := svc.BatchEncrypt(anon, &BatchEncryptRequest{
			TenantID: "org-a", ScopeID: "app-a",
			Items: []BatchEncryptItem{{Plaintext: []byte("x"), AAD: "org-a-aad"}},
		})
		if resp != nil {
			t.Fatal("batch encrypted without a principal")
		}
		assertErrorKind(t, err, ErrorUnauthenticated)
	})

	t.Run("batch_decrypt", func(t *testing.T) {
		resp, err := svc.BatchDecrypt(anon, &BatchDecryptRequest{
			TenantID: "org-a",
			ScopeID:  "app-a",
			Items: []DecryptRequest{{
				Ciphertext: batch.Items[0].Ciphertext, AAD: "batch-aad", KeyVersionID: batch.Items[0].KeyVersionID,
			}},
		})
		if resp != nil {
			t.Fatal("batch decrypted without a principal")
		}
		assertErrorKind(t, err, ErrorUnauthenticated)
	})

	t.Run("create_data_key", func(t *testing.T) {
		resp, err := keySvc.CreateDataKey(anon, &CreateDataKeyRequest{TenantID: "org-a", ScopeID: "keys"})
		if resp != nil {
			t.Fatal("created a data key without a principal")
		}
		assertErrorKind(t, err, ErrorUnauthenticated)
	})

	t.Run("rotate_data_key", func(t *testing.T) {
		resp, err := keySvc.RotateDataKey(anon, &RotateDataKeyRequest{TenantID: "org-a", ScopeID: "app-a"})
		if resp != nil {
			t.Fatal("rotated a data key without a principal")
		}
		assertErrorKind(t, err, ErrorUnauthenticated)
	})
}

func TestKMSService_OrgAPrincipalCannotOperateOnOrgB(t *testing.T) {
	_, _, dekMgr, dekStore, auditLogger, _, err := testutil.SetupTestKMSStack(testutil.TestRootKeyHex)
	if err != nil {
		t.Fatalf("SetupTestKMSStack: %v", err)
	}
	svc := NewKMSService(dekMgr, auditLogger)
	keySvc := NewKeyService(dekMgr, keys.NewKeyVersionManager(dekStore, 1000), auditLogger)
	orgA := ctxForTenant("org-a")
	orgB := ctxForTenant("org-b")

	enc, err := svc.Encrypt(orgA, &EncryptRequest{
		TenantID: "org-a", ScopeID: "app-a", Plaintext: []byte("org-a-plaintext"), AAD: "org-a-aad",
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	batch, err := svc.BatchEncrypt(orgA, &BatchEncryptRequest{
		TenantID: "org-a",
		ScopeID:  "app-a",
		Items:    []BatchEncryptItem{{Plaintext: []byte("batch-plaintext"), AAD: "batch-aad"}},
	})
	if err != nil {
		t.Fatalf("BatchEncrypt: %v", err)
	}

	t.Run("encrypt", func(t *testing.T) {
		resp, err := svc.Encrypt(orgA, &EncryptRequest{
			TenantID: "org-b", ScopeID: "app-b", Plaintext: []byte("other-org"), AAD: "org-b-aad",
		})
		if resp != nil {
			t.Fatal("org A principal encrypted for org B")
		}
		assertErrorKind(t, err, ErrorPermissionDenied)
		rec, err := dekStore.GetActiveKeyVersion(context.Background(), "org-b", "app-b")
		if err != nil {
			t.Fatalf("GetActiveKeyVersion: %v", err)
		}
		if rec != nil {
			t.Fatal("request tenant was used to create a data key")
		}
	})

	t.Run("decrypt", func(t *testing.T) {
		resp, err := svc.Decrypt(orgB, &DecryptRequest{
			TenantID: "org-a", ScopeID: "app-a",
			Ciphertext: enc.Ciphertext, AAD: "org-a-aad", KeyVersionID: enc.KeyVersionID,
		})
		if resp != nil {
			t.Fatal("org B principal decrypted org A ciphertext")
		}
		assertErrorKind(t, err, ErrorPermissionDenied)

		resp, err = svc.Decrypt(orgA, &DecryptRequest{
			TenantID: "org-b", ScopeID: "app-a",
			Ciphertext: enc.Ciphertext, AAD: "org-a-aad", KeyVersionID: enc.KeyVersionID,
		})
		if resp != nil {
			t.Fatal("org A principal decrypted by naming org B")
		}
		assertErrorKind(t, err, ErrorPermissionDenied)

		okResp, err := svc.Decrypt(orgA, &DecryptRequest{
			TenantID: "org-a", ScopeID: "app-a",
			Ciphertext: enc.Ciphertext, AAD: "org-a-aad", KeyVersionID: enc.KeyVersionID,
		})
		if err != nil {
			t.Fatalf("owner decrypt: %v", err)
		}
		if string(okResp.Plaintext) != "org-a-plaintext" {
			t.Fatal("owner decrypt did not return the original plaintext")
		}
	})

	t.Run("batch_encrypt", func(t *testing.T) {
		resp, err := svc.BatchEncrypt(orgA, &BatchEncryptRequest{
			TenantID: "org-b", ScopeID: "batch-b",
			Items: []BatchEncryptItem{{Plaintext: []byte("x"), AAD: "b"}},
		})
		if resp != nil {
			t.Fatal("org A principal batch encrypted for org B")
		}
		assertErrorKind(t, err, ErrorPermissionDenied)
	})

	t.Run("batch_decrypt", func(t *testing.T) {
		resp, err := svc.BatchDecrypt(orgB, &BatchDecryptRequest{
			TenantID: "org-a",
			ScopeID:  "app-a",
			Items: []DecryptRequest{{
				Ciphertext: batch.Items[0].Ciphertext, AAD: "batch-aad", KeyVersionID: batch.Items[0].KeyVersionID,
			}},
		})
		if resp != nil {
			t.Fatal("org B principal batch decrypted org A ciphertext")
		}
		assertErrorKind(t, err, ErrorPermissionDenied)
	})

	t.Run("create_data_key", func(t *testing.T) {
		resp, err := keySvc.CreateDataKey(orgA, &CreateDataKeyRequest{TenantID: "org-b", ScopeID: "keys"})
		if resp != nil {
			t.Fatal("org A principal created a data key for org B")
		}
		assertErrorKind(t, err, ErrorPermissionDenied)
	})

	t.Run("rotate_data_key", func(t *testing.T) {
		resp, err := keySvc.RotateDataKey(orgA, &RotateDataKeyRequest{TenantID: "org-b", ScopeID: "app-a"})
		if resp != nil {
			t.Fatal("org A principal rotated a data key for org B")
		}
		assertErrorKind(t, err, ErrorPermissionDenied)
	})
}

func TestKMSService_AuditActorEqualsSessionPrincipal(t *testing.T) {
	_, _, dekMgr, dekStore, auditLogger, auditStore, err := testutil.SetupTestKMSStack(testutil.TestRootKeyHex)
	if err != nil {
		t.Fatalf("SetupTestKMSStack: %v", err)
	}
	svc := NewKMSService(dekMgr, auditLogger)
	keySvc := NewKeyService(dekMgr, keys.NewKeyVersionManager(dekStore, 1000), auditLogger)

	const sessionPrincipal = "session-principal"
	ctx := authn.WithPrincipal(context.Background(), authn.Principal{
		TenantID: "org-a",
		ActorID:  sessionPrincipal,
	})

	enc, err := svc.Encrypt(ctx, &EncryptRequest{
		TenantID: "org-a", ScopeID: "app-a", Plaintext: []byte("audit-plaintext"), AAD: "audit-aad",
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := svc.Decrypt(ctx, &DecryptRequest{
		TenantID: "org-a", ScopeID: "app-a",
		Ciphertext: enc.Ciphertext, AAD: "audit-aad", KeyVersionID: enc.KeyVersionID,
	}); err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	batch, err := svc.BatchEncrypt(ctx, &BatchEncryptRequest{
		TenantID: "org-a",
		ScopeID:  "app-a",
		Items:    []BatchEncryptItem{{Plaintext: []byte("batch"), AAD: "batch-aad"}},
	})
	if err != nil {
		t.Fatalf("BatchEncrypt: %v", err)
	}
	if _, err := svc.BatchDecrypt(ctx, &BatchDecryptRequest{
		TenantID: "org-a",
		ScopeID:  "app-a",
		Items: []DecryptRequest{{
			Ciphertext: batch.Items[0].Ciphertext, AAD: "batch-aad", KeyVersionID: batch.Items[0].KeyVersionID,
		}},
	}); err != nil {
		t.Fatalf("BatchDecrypt: %v", err)
	}
	if _, err := keySvc.CreateDataKey(ctx, &CreateDataKeyRequest{TenantID: "org-a", ScopeID: "key-scope"}); err != nil {
		t.Fatalf("CreateDataKey: %v", err)
	}
	if _, err := keySvc.RotateDataKey(ctx, &RotateDataKeyRequest{TenantID: "org-a", ScopeID: "key-scope"}); err != nil {
		t.Fatalf("RotateDataKey: %v", err)
	}

	entries, err := auditStore.GetEntries(ctx, "org-a", 50, 0)
	if err != nil {
		t.Fatalf("GetEntries: %v", err)
	}
	want := map[string]bool{
		"decrypt":          false,
		"batch_decrypt":    false,
		"data_key_created": false,
		"data_key_rotated": false,
	}
	if len(entries) == 0 {
		t.Fatal("expected audit entries for the session principal")
	}
	for _, entry := range entries {
		if entry.ActorID != sessionPrincipal {
			t.Fatalf("action %s actor = %q, want session principal %q", entry.Action, entry.ActorID, sessionPrincipal)
		}
		want[entry.Action] = true
	}
	for action, found := range want {
		if !found {
			t.Errorf("missing audit action %s recorded as the session principal", action)
		}
	}
}
