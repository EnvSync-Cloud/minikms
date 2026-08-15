package escrow_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/envsync-cloud/minikms/internal/audit"
	"github.com/envsync-cloud/minikms/internal/escrow"
	"github.com/envsync-cloud/minikms/internal/testutil"
)

func TestManager_ThresholdRecoveryAndReseal(t *testing.T) {
	ctx := context.Background()
	store := testutil.NewMockEscrowStore()
	auditStore := testutil.NewMockAuditStore()
	manager, err := escrow.NewManager(store, audit.NewAuditLogger(auditStore), bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	secret := testutil.TestRootKeyBytes()
	custodians := []string{"alice", "bob", "carol", "dave", "erin"}
	set, created, err := manager.EnsureSplit(ctx, escrow.RootScope, escrow.KeyTypeRoot, secret, custodians, 3, "bootstrap")
	if err != nil {
		t.Fatalf("EnsureSplit: %v", err)
	}
	if !created || set.Threshold != 3 || set.TotalShares != 5 {
		t.Fatalf("unexpected set: created=%t set=%+v", created, set)
	}

	// Restart/unseal is idempotent and verifies that the configured key and
	// policy still match the generation already distributed to custodians.
	sameSet, created, err := manager.EnsureSplit(ctx, escrow.RootScope, escrow.KeyTypeRoot, secret, custodians, 3, "bootstrap")
	if err != nil || created || sameSet.ID != set.ID {
		t.Fatalf("idempotent EnsureSplit: set=%+v created=%t err=%v", sameSet, created, err)
	}
	wrongSecret := bytes.Repeat([]byte{0xff}, len(secret))
	if _, _, err := manager.EnsureSplit(ctx, escrow.RootScope, escrow.KeyTypeRoot, wrongSecret, custodians, 3, "bootstrap"); err == nil {
		t.Fatal("EnsureSplit accepted a key different from the active escrow generation")
	}

	packages := exportPackages(t, ctx, manager, escrow.RootScope, escrow.KeyTypeRoot, custodians, "admin-1")

	if recovered, _, err := manager.RecoverAndReseal(ctx, escrow.RootScope, escrow.KeyTypeRoot, packages[:2], "admin-1"); err == nil {
		t.Fatalf("K-1 recovery unexpectedly succeeded: %x", recovered)
	}

	recovered, newSet, err := manager.RecoverAndReseal(ctx, escrow.RootScope, escrow.KeyTypeRoot, packages[:3], "admin-1")
	if err != nil {
		t.Fatalf("K-share recovery: %v", err)
	}
	if !bytes.Equal(recovered, secret) {
		t.Fatal("recovered root key does not match the original")
	}
	if newSet.ID == set.ID || newSet.Threshold != set.Threshold || newSet.TotalShares != set.TotalShares {
		t.Fatalf("recovery did not create an equivalent fresh generation: old=%+v new=%+v", set, newSet)
	}
	oldSet := store.EscrowSetByID(set.ID)
	if oldSet.Status != "retired" || oldSet.RecoveredAt == nil {
		t.Fatalf("old set was not retired as recovered: %+v", oldSet)
	}

	if _, _, err := manager.RecoverAndReseal(ctx, escrow.RootScope, escrow.KeyTypeRoot, packages[:3], "admin-1"); err == nil {
		t.Fatal("packages from the retired generation were accepted")
	}

	assertAuditActions(t, auditStore.EntriesForOrg(escrow.RootScope), []string{
		"escrow_split_started",
		"escrow_split_succeeded",
		"escrow_set_verified",
		"escrow_share_export_started",
		"escrow_share_export_succeeded",
		"escrow_recovery_started",
		"escrow_recovery_failed",
		"escrow_recovery_succeeded",
		"escrow_resealed",
	})
	secretHex := hex.EncodeToString(secret)
	for _, entry := range auditStore.EntriesForOrg(escrow.RootScope) {
		if strings.Contains(entry.Details, secretHex) || strings.Contains(entry.Details, string(packages[0])) {
			t.Fatalf("audit entry leaked escrow material: action=%s details=%q", entry.Action, entry.Details)
		}
	}
}

func TestManager_RejectsDuplicateAndTamperedShares(t *testing.T) {
	ctx := context.Background()
	store := testutil.NewMockEscrowStore()
	auditStore := testutil.NewMockAuditStore()
	manager, err := escrow.NewManager(store, audit.NewAuditLogger(auditStore), bytes.Repeat([]byte{0x24}, 32))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	custodians := []string{"one", "two", "three", "four", "five"}
	if _, _, err := manager.EnsureSplit(ctx, "org-1", escrow.KeyTypeOrgCA, []byte("high-entropy-org-ca-key"), custodians, 3, "system"); err != nil {
		t.Fatalf("EnsureSplit: %v", err)
	}
	packages := exportPackages(t, ctx, manager, "org-1", escrow.KeyTypeOrgCA, custodians, "admin-1")

	duplicates := [][]byte{packages[0], packages[0], packages[1]}
	if _, _, err := manager.RecoverAndReseal(ctx, "org-1", escrow.KeyTypeOrgCA, duplicates, "admin-1"); err == nil {
		t.Fatal("duplicate shares were accepted")
	}

	var tampered escrow.SharePackage
	if err := json.Unmarshal(packages[2], &tampered); err != nil {
		t.Fatalf("decode share: %v", err)
	}
	tampered.Share[len(tampered.Share)-1] ^= 0xff
	tamperedBytes, err := json.Marshal(&tampered)
	if err != nil {
		t.Fatalf("encode tampered share: %v", err)
	}
	if _, _, err := manager.RecoverAndReseal(ctx, "org-1", escrow.KeyTypeOrgCA,
		[][]byte{packages[0], packages[1], tamperedBytes}, "admin-1"); err == nil {
		t.Fatal("tampered share was accepted")
	}
}

func TestLoadSealKeyAndCustodianValidation(t *testing.T) {
	keyHex := strings.Repeat("ab", 32)
	key, err := escrow.LoadSealKey(keyHex, "")
	if err != nil || hex.EncodeToString(key) != keyHex {
		t.Fatalf("LoadSealKey(value): key=%x err=%v", key, err)
	}

	keyPath := filepath.Join(t.TempDir(), "escrow-seal-key")
	if err := os.WriteFile(keyPath, []byte(keyHex+"\n"), 0o600); err != nil {
		t.Fatalf("write seal key: %v", err)
	}
	if _, err := escrow.LoadSealKey("", keyPath); err != nil {
		t.Fatalf("LoadSealKey(file): %v", err)
	}
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if _, err := escrow.LoadSealKey("", keyPath); err == nil {
		t.Fatal("LoadSealKey accepted a group/world-readable file")
	}
	if _, err := escrow.LoadSealKey(keyHex, keyPath); err == nil {
		t.Fatal("LoadSealKey accepted two configured sources")
	}

	got, err := escrow.ParseCustodians("alice, bob,carol", 3)
	if err != nil || strings.Join(got, ",") != "alice,bob,carol" {
		t.Fatalf("ParseCustodians: got=%v err=%v", got, err)
	}
	if _, err := escrow.ParseCustodians("alice,alice", 2); err == nil {
		t.Fatal("ParseCustodians accepted duplicate IDs")
	}
	if _, err := escrow.ParseCustodians("alice,bob", 3); err == nil {
		t.Fatal("ParseCustodians accepted the wrong number of IDs")
	}
}

func exportPackages(t *testing.T, ctx context.Context, manager *escrow.Manager, orgID, keyType string, custodians []string, actor string) [][]byte {
	t.Helper()
	packages := make([][]byte, len(custodians))
	for i, custodian := range custodians {
		encoded, err := manager.ExportShare(ctx, orgID, keyType, custodian, actor)
		if err != nil {
			t.Fatalf("ExportShare(%s): %v", custodian, err)
		}
		packages[i] = encoded
	}
	return packages
}

func assertAuditActions(t *testing.T, entries []*audit.AuditEntry, expected []string) {
	t.Helper()
	seen := make(map[string]bool, len(entries))
	for _, entry := range entries {
		seen[entry.Action] = true
	}
	for _, action := range expected {
		if !seen[action] {
			t.Errorf("missing audit action %q; saw %v", action, seen)
		}
	}
}
