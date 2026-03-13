package service

import (
	"context"
	"testing"

	"github.com/envsync-cloud/minikms/internal/keys"
	"github.com/envsync-cloud/minikms/internal/testutil"
)

func setupKeyService(t *testing.T) *KeyService {
	t.Helper()
	_, _, dekMgr, dekStore, auditLogger, _, err := testutil.SetupTestKMSStack(testutil.TestRootKeyHex)
	if err != nil {
		t.Fatalf("SetupTestKMSStack: %v", err)
	}
	vMgr := keys.NewKeyVersionManager(dekStore, 1000)
	return NewKeyService(dekMgr, vMgr, auditLogger)
}

func TestKeyService_CreateDataKey(t *testing.T) {
	ctx := context.Background()
	svc := setupKeyService(t)

	resp, err := svc.CreateDataKey(ctx, &CreateDataKeyRequest{
		TenantID: "org1",
		ScopeID:  "app1",
	})
	if err != nil {
		t.Fatalf("CreateDataKey: %v", err)
	}
	if resp.KeyVersionID == "" {
		t.Fatal("KeyVersionID should not be empty")
	}
}

func TestKeyService_RotateDataKey(t *testing.T) {
	ctx := context.Background()
	svc := setupKeyService(t)

	// Create first
	createResp, _ := svc.CreateDataKey(ctx, &CreateDataKeyRequest{
		TenantID: "org1",
		ScopeID:  "app1",
	})

	// Rotate
	rotateResp, err := svc.RotateDataKey(ctx, &RotateDataKeyRequest{
		TenantID: "org1",
		ScopeID:  "app1",
	})
	if err != nil {
		t.Fatalf("RotateDataKey: %v", err)
	}
	if rotateResp.NewKeyVersionID == "" {
		t.Fatal("NewKeyVersionID should not be empty")
	}
	if rotateResp.NewKeyVersionID == createResp.KeyVersionID {
		t.Fatal("rotated key should have different ID")
	}
}

func TestKeyService_GetKeyInfo(t *testing.T) {
	ctx := context.Background()
	svc := setupKeyService(t)

	// Create first
	_, _ = svc.CreateDataKey(ctx, &CreateDataKeyRequest{
		TenantID: "org1",
		ScopeID:  "app1",
	})

	resp, err := svc.GetKeyInfo(ctx, &GetKeyInfoRequest{
		TenantID: "org1",
		ScopeID:  "app1",
	})
	if err != nil {
		t.Fatalf("GetKeyInfo: %v", err)
	}
	if resp.KeyVersionID == "" {
		t.Fatal("KeyVersionID should not be empty")
	}
	if resp.Status != "active" {
		t.Errorf("Status: got %q, want %q", resp.Status, "active")
	}
}
