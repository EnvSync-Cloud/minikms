package service

import (
	"bytes"
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/envsync-cloud/minikms/internal/testutil"
)

func setupKMSService(t *testing.T) *KMSService {
	t.Helper()
	_, _, dekMgr, _, auditLogger, _, err := testutil.SetupTestKMSStack(testutil.TestRootKeyHex)
	if err != nil {
		t.Fatalf("SetupTestKMSStack: %v", err)
	}
	return NewKMSService(dekMgr, auditLogger)
}

func TestKMSService_DecryptAfterRotation(t *testing.T) {
	ctx := context.Background()
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
	ctx := context.Background()
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
	ctx := context.Background()
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
	ctx := context.Background()
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
	ctx := context.Background()
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
