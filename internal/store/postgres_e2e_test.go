//go:build e2e

package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/envsync-cloud/minikms/internal/audit"
	"github.com/envsync-cloud/minikms/internal/auth"
	"github.com/envsync-cloud/minikms/internal/keys"
)

func setupPostgresStore(t *testing.T) *PostgresStore {
	t.Helper()
	dbURL := os.Getenv("MINIKMS_DB_URL")
	if dbURL == "" {
		t.Skip("MINIKMS_DB_URL not set, skipping E2E test")
	}
	ctx := context.Background()
	store, err := NewPostgresStore(ctx, dbURL)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func TestPostgres_DEKStore_CRUD(t *testing.T) {
	store := setupPostgresStore(t)
	ctx := context.Background()
	orgID := "e2e-org-" + time.Now().Format("150405")
	appID := "e2e-app"

	// Create
	record := &keys.KeyVersionRecord{
		OrgID:          orgID,
		AppID:          appID,
		KeyType:        "app_dek",
		Version:        1,
		EncryptedKey:   []byte("encrypted-dek-data"),
		MaxEncryptions: 1000,
		Status:         "active",
	}
	err := store.CreateKeyVersion(ctx, record)
	if err != nil {
		t.Fatalf("CreateKeyVersion: %v", err)
	}

	// Get
	got, err := store.GetActiveKeyVersion(ctx, orgID, appID)
	if err != nil {
		t.Fatalf("GetActiveKeyVersion: %v", err)
	}
	if got == nil {
		t.Fatal("expected key version, got nil")
	}
	if got.Version != 1 {
		t.Errorf("Version: got %d, want 1", got.Version)
	}

	// Increment
	count, err := store.IncrementEncryptionCount(ctx, got.ID)
	if err != nil {
		t.Fatalf("IncrementEncryptionCount: %v", err)
	}
	if count != 1 {
		t.Errorf("count: got %d, want 1", count)
	}

	// UpdateStatus
	err = store.UpdateKeyStatus(ctx, got.ID, "retired")
	if err != nil {
		t.Fatalf("UpdateKeyStatus: %v", err)
	}

	// Verify status change
	retired, _ := store.GetActiveKeyVersion(ctx, orgID, appID)
	if retired != nil {
		t.Error("retired key should not be returned as active")
	}
}

func TestPostgres_AuditStore(t *testing.T) {
	store := setupPostgresStore(t)
	ctx := context.Background()
	orgID := "e2e-audit-" + time.Now().Format("150405")

	// GetLatestEntryHash for empty
	hash, err := store.GetLatestEntryHash(ctx, orgID)
	if err != nil {
		t.Fatalf("GetLatestEntryHash: %v", err)
	}
	if hash != audit.GenesisHash {
		t.Errorf("expected GenesisHash, got %q", hash)
	}

	// Insert — truncate to microsecond precision to match PostgreSQL's timestamp resolution
	now := time.Now().UTC().Truncate(time.Microsecond)
	entryHash := audit.ComputeEntryHash(audit.GenesisHash, now, "encrypt", "user1", "data")
	entry := &audit.AuditEntry{
		PreviousHash:   audit.GenesisHash,
		EntryHash:      entryHash,
		Timestamp:      now,
		Action:         "encrypt",
		ActorID:        "user1",
		OrgID:          orgID,
		Details:        "data",
		RequestJWTHash: "jwt-hash",
	}
	err = store.InsertEntry(ctx, entry)
	if err != nil {
		t.Fatalf("InsertEntry: %v", err)
	}

	// GetLatestEntryHash
	latestHash, _ := store.GetLatestEntryHash(ctx, orgID)
	if latestHash != entryHash {
		t.Errorf("latest hash: got %q, want %q", latestHash, entryHash)
	}

	// GetEntries
	entries, err := store.GetEntries(ctx, orgID, 10, 0)
	if err != nil {
		t.Fatalf("GetEntries: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	// VerifyChain
	valid, err := store.VerifyChain(ctx, orgID)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !valid {
		t.Fatal("chain should be valid")
	}
}

func TestPostgres_TokenRegistry(t *testing.T) {
	store := setupPostgresStore(t)
	ctx := context.Background()
	jti := "e2e-jti-" + time.Now().Format("150405")

	// Store
	entry := &auth.TokenEntry{
		JTI:         jti,
		SubjectHash: "subject-hash",
		JWTHash:     "jwt-hash",
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(1 * time.Hour),
		Revoked:     false,
	}
	err := store.StoreToken(ctx, entry)
	if err != nil {
		t.Fatalf("StoreToken: %v", err)
	}

	// Get
	got, err := store.GetToken(ctx, jti)
	if err != nil {
		t.Fatalf("GetToken: %v", err)
	}
	if got == nil {
		t.Fatal("expected token, got nil")
	}
	if got.JTI != jti {
		t.Errorf("JTI: got %q, want %q", got.JTI, jti)
	}

	// Revoke
	err = store.RevokeToken(ctx, jti)
	if err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
	revoked, _ := store.GetToken(ctx, jti)
	if !revoked.Revoked {
		t.Fatal("token should be revoked")
	}

	// CleanupExpired
	err = store.CleanupExpired(ctx)
	if err != nil {
		t.Fatalf("CleanupExpired: %v", err)
	}
}
