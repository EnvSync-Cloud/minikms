//go:build e2e

package store

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/envsync-cloud/minikms/internal/audit"
	"github.com/envsync-cloud/minikms/internal/auth"
	"github.com/envsync-cloud/minikms/internal/escrow"
	"github.com/envsync-cloud/minikms/internal/keys"
	"github.com/envsync-cloud/minikms/internal/pkistore"
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

	// Retired versions remain available by exact ID for historical decrypts.
	byVersion, err := store.GetKeyVersion(ctx, orgID, appID, got.ID)
	if err != nil {
		t.Fatalf("GetKeyVersion: %v", err)
	}
	if byVersion == nil || byVersion.Status != "retired" {
		t.Fatalf("expected retired key version, got %#v", byVersion)
	}

	for _, tc := range []struct {
		name  string
		orgID string
		appID string
	}{
		{name: "wrong org", orgID: orgID + "-other", appID: appID},
		{name: "wrong app", orgID: orgID, appID: appID + "-other"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			record, err := store.GetKeyVersion(ctx, tc.orgID, tc.appID, got.ID)
			if err != nil {
				t.Fatalf("GetKeyVersion: %v", err)
			}
			if record != nil {
				t.Fatalf("ownership-mismatched version should not be returned: %#v", record)
			}
		})
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

func TestPostgres_TokenCertificateStatus(t *testing.T) {
	pg := setupPostgresStore(t)
	ctx := context.Background()
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")
	orgID := "e2e-certbind-" + suffix
	serialLive := suffix + "a1"
	serialRevoked := suffix + "b2"
	serialMissing := suffix + "c3"

	for _, serial := range []string{serialLive, serialRevoked} {
		if err := pg.StoreCertificate(ctx, &pkistore.CertRecord{
			SerialNumber: serial,
			CertType:     "member",
			OrgID:        orgID,
			SubjectCN:    "member",
			CertPEM:      "test-cert",
			Status:       "active",
			IssuedAt:     time.Now().Add(-time.Hour),
			ExpiresAt:    time.Now().Add(24 * time.Hour),
		}); err != nil {
			t.Fatalf("StoreCertificate %s: %v", serial, err)
		}
	}

	sign := func(claims jwt.MapClaims) string {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		raw, err := jwt.NewWithClaims(jwt.SigningMethodES256, claims).SignedString(key)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		return raw
	}
	storeSession := func(jti, serial, raw string) {
		t.Helper()
		if err := pg.StoreToken(ctx, &auth.TokenEntry{
			JTI:         jti,
			SubjectHash: auth.HashSubject(jti),
			JWTHash:     auth.HashJWT(raw),
			IssuedAt:    time.Now(),
			ExpiresAt:   time.Now().Add(time.Hour),
			CertSerial:  serial,
		}); err != nil {
			t.Fatalf("StoreToken %s: %v", jti, err)
		}
	}

	jtiLive := "live-" + serialLive
	jtiRevoked := "revoked-" + serialRevoked
	jtiMissing := "missing-" + serialMissing
	jtiLegacy := "legacy-" + suffix
	rawLive := sign(jwt.MapClaims{"jti": jtiLive, "sub": "member-live", "org": orgID, "cert_serial": serialLive})
	rawRevoked := sign(jwt.MapClaims{"jti": jtiRevoked, "sub": "member-revoked", "org": orgID, "cert_serial": serialRevoked})
	rawMissing := sign(jwt.MapClaims{"jti": jtiMissing, "sub": "member-missing", "org": orgID, "cert_serial": serialMissing})
	rawLegacy := sign(jwt.MapClaims{"jti": jtiLegacy, "sub": "member-legacy", "org": orgID, "cert_serial": ""})
	storeSession(jtiLive, serialLive, rawLive)
	storeSession(jtiRevoked, serialRevoked, rawRevoked)
	storeSession(jtiMissing, serialMissing, rawMissing)
	storeSession(jtiLegacy, "", rawLegacy)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	rawNonCert, err := auth.NewTokenIssuer(key, "minikms-e2e", time.Hour, pg).IssueToken(ctx, "user@example.com", orgID, "admin")
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}
	nonCertClaims := &auth.Claims{}
	if _, _, err := jwt.NewParser().ParseUnverified(rawNonCert, nonCertClaims); err != nil {
		t.Fatalf("ParseUnverified: %v", err)
	}

	v := auth.NewJWTValidator(pg)
	if _, err := v.ValidateByJTI(ctx, jtiLive, rawLive); err != nil {
		t.Fatalf("live certificate: %v", err)
	}
	if _, err := v.ValidateByJTI(ctx, nonCertClaims.ID, rawNonCert); err != nil {
		t.Fatalf("non-cert token: %v", err)
	}
	if _, err := v.ValidateByJTI(ctx, jtiMissing, rawMissing); err == nil || !strings.Contains(err.Error(), "certificate is missing") {
		t.Fatalf("missing certificate err = %v", err)
	}
	if _, err := v.ValidateByJTI(ctx, jtiLegacy, rawLegacy); err == nil || !strings.Contains(err.Error(), "certificate serial is missing") {
		t.Fatalf("empty serial cert-session err = %v", err)
	}

	if err := pg.UpdateCertificateStatus(ctx, serialRevoked, "revoked"); err != nil {
		t.Fatalf("UpdateCertificateStatus: %v", err)
	}
	revokedTok, err := pg.GetToken(ctx, jtiRevoked)
	if err != nil || revokedTok == nil {
		t.Fatalf("GetToken: %v", err)
	}
	if revokedTok.Revoked {
		t.Fatal("certificate status change alone should leave the session row unrevoked")
	}
	if revokedTok.CertSerial != serialRevoked || revokedTok.CertStatus != "revoked" {
		t.Fatalf("lookup serial=%q status=%q", revokedTok.CertSerial, revokedTok.CertStatus)
	}
	if _, err := v.ValidateByJTI(ctx, jtiRevoked, rawRevoked); err == nil || !strings.Contains(err.Error(), "certificate is not active") {
		t.Fatalf("revoked certificate err = %v", err)
	}
	if _, err := v.ValidateByJTI(ctx, jtiLive, rawLive); err != nil {
		t.Fatalf("live certificate after another status change: %v", err)
	}

	if err := pg.RevokeCertificate(ctx, serialMissing, &pkistore.CRLEntryRecord{
		CertSerial:   serialMissing,
		IssuerSerial: "issuer-" + suffix,
		RevokedAt:    time.Now().UTC(),
		Reason:       0,
		CRLNumber:    1,
	}); err == nil {
		t.Fatal("expected error revoking an unknown certificate")
	}
	missingTok, err := pg.GetToken(ctx, jtiMissing)
	if err != nil || missingTok == nil || missingTok.Revoked {
		t.Fatalf("unknown revoke changed token: revoked=%v err=%v", missingTok != nil && missingTok.Revoked, err)
	}
	if crl, err := pg.GetCertRevocationEntry(ctx, serialMissing); err != nil || crl != nil {
		t.Fatalf("unknown revoke wrote a CRL entry: %+v err=%v", crl, err)
	}

	if err := pg.RevokeCertificate(ctx, serialLive, &pkistore.CRLEntryRecord{
		CertSerial:   serialLive,
		IssuerSerial: "issuer-" + suffix,
		RevokedAt:    time.Now().UTC(),
		Reason:       0,
		CRLNumber:    1,
	}); err != nil {
		t.Fatalf("RevokeCertificate: %v", err)
	}
	liveTok, err := pg.GetToken(ctx, jtiLive)
	if err != nil || liveTok == nil || !liveTok.Revoked || liveTok.CertStatus != "revoked" {
		t.Fatalf("session after RevokeCertificate revoked=%v status=%q err=%v", liveTok != nil && liveTok.Revoked, liveTokCertStatus(liveTok), err)
	}
	if _, err := v.ValidateByJTI(ctx, jtiLive, rawLive); err == nil {
		t.Fatal("session for a revoked certificate was accepted")
	}
	still, err := pg.GetToken(ctx, jtiRevoked)
	if err != nil || still == nil || still.Revoked {
		t.Fatal("revoking one serial marked a different session revoked")
	}
	nonCert, err := pg.GetToken(ctx, nonCertClaims.ID)
	if err != nil || nonCert == nil || nonCert.Revoked || nonCert.CertSerial != "" {
		t.Fatalf("non-cert token changed: revoked=%v serial=%q err=%v", nonCert != nil && nonCert.Revoked, nonCertSerial(nonCert), err)
	}
	if _, err := v.ValidateByJTI(ctx, nonCertClaims.ID, rawNonCert); err != nil {
		t.Fatalf("non-cert token after revocation: %v", err)
	}
	legacyTok, err := pg.GetToken(ctx, jtiLegacy)
	if err != nil || legacyTok == nil || legacyTok.Revoked {
		t.Fatal("empty serial row was revoked")
	}
	crl, err := pg.GetCertRevocationEntry(ctx, serialLive)
	if err != nil || crl == nil || crl.CertSerial != serialLive {
		t.Fatalf("crl = %+v err=%v", crl, err)
	}
	cert, err := pg.GetCertificateBySerial(ctx, serialLive)
	if err != nil || cert == nil || cert.Status != "revoked" {
		t.Fatalf("certificate status = %q err=%v", certStatus(cert), err)
	}
}

func liveTokCertStatus(entry *auth.TokenEntry) string {
	if entry == nil {
		return ""
	}
	return entry.CertStatus
}

func nonCertSerial(entry *auth.TokenEntry) string {
	if entry == nil {
		return ""
	}
	return entry.CertSerial
}

func certStatus(rec *pkistore.CertRecord) string {
	if rec == nil {
		return ""
	}
	return rec.Status
}

func TestPostgres_EscrowStoreGenerationReplacement(t *testing.T) {
	pgStore := setupPostgresStore(t)
	ctx := context.Background()
	orgID := "e2e-escrow-" + time.Now().Format("150405.000000")

	first := &escrow.Set{
		ID: "set-1-" + orgID, OrgID: orgID, KeyType: escrow.KeyTypeOrgCA,
		TotalShares: 3, Threshold: 2, SecretHash: bytes.Repeat([]byte{1}, 32),
		Status: "active", CreatedAt: time.Now().UTC(),
	}
	firstShares := []*escrow.Share{
		{ID: "share-1-" + orgID, SetID: first.ID, ShareIndex: 1, EncryptedShare: []byte("cipher-1"), ShareHash: bytes.Repeat([]byte{1}, 32), CustodianID: "alice", CreatedAt: first.CreatedAt},
		{ID: "share-2-" + orgID, SetID: first.ID, ShareIndex: 2, EncryptedShare: []byte("cipher-2"), ShareHash: bytes.Repeat([]byte{2}, 32), CustodianID: "bob", CreatedAt: first.CreatedAt},
		{ID: "share-3-" + orgID, SetID: first.ID, ShareIndex: 3, EncryptedShare: []byte("cipher-3"), ShareHash: bytes.Repeat([]byte{3}, 32), CustodianID: "carol", CreatedAt: first.CreatedAt},
	}
	if err := pgStore.ReplaceEscrowSet(ctx, first, firstShares, ""); err != nil {
		t.Fatalf("ReplaceEscrowSet(first): %v", err)
	}
	got, shares, err := pgStore.GetActiveEscrowSet(ctx, orgID, escrow.KeyTypeOrgCA)
	if err != nil || got == nil || got.ID != first.ID || len(shares) != 3 {
		t.Fatalf("GetActiveEscrowSet: set=%+v shares=%d err=%v", got, len(shares), err)
	}
	if err := pgStore.MarkEscrowShareExported(ctx, first.ID, 1, time.Now().UTC()); err != nil {
		t.Fatalf("MarkEscrowShareExported: %v", err)
	}

	second := &escrow.Set{
		ID: "set-2-" + orgID, OrgID: orgID, KeyType: escrow.KeyTypeOrgCA,
		TotalShares: 3, Threshold: 2, SecretHash: bytes.Repeat([]byte{1}, 32),
		Status: "active", CreatedAt: time.Now().UTC(),
	}
	secondShares := []*escrow.Share{
		{ID: "share-4-" + orgID, SetID: second.ID, ShareIndex: 1, EncryptedShare: []byte("cipher-4"), ShareHash: bytes.Repeat([]byte{4}, 32), CustodianID: "alice", CreatedAt: second.CreatedAt},
		{ID: "share-5-" + orgID, SetID: second.ID, ShareIndex: 2, EncryptedShare: []byte("cipher-5"), ShareHash: bytes.Repeat([]byte{5}, 32), CustodianID: "bob", CreatedAt: second.CreatedAt},
		{ID: "share-6-" + orgID, SetID: second.ID, ShareIndex: 3, EncryptedShare: []byte("cipher-6"), ShareHash: bytes.Repeat([]byte{6}, 32), CustodianID: "carol", CreatedAt: second.CreatedAt},
	}
	if err := pgStore.ReplaceEscrowSet(ctx, second, secondShares, first.ID); err != nil {
		t.Fatalf("ReplaceEscrowSet(recovery): %v", err)
	}
	got, _, err = pgStore.GetActiveEscrowSet(ctx, orgID, escrow.KeyTypeOrgCA)
	if err != nil || got == nil || got.ID != second.ID {
		t.Fatalf("fresh generation is not active: set=%+v err=%v", got, err)
	}
}
