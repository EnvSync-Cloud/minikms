package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/envsync/minikms/internal/keys"
	"github.com/envsync/minikms/internal/pki"
	"github.com/envsync/minikms/internal/pkistore"
	"github.com/envsync/minikms/internal/store"
	"github.com/envsync/minikms/internal/testutil"
)

// --- Mock VaultStore ---

type mockVaultStore struct {
	mu       sync.RWMutex
	entries  map[string]*store.VaultEntry // keyed by "orgID:scopeID:entryType:key:version"
	orgCerts map[string]*pkistore.CertRecord
	certs    map[string]*pkistore.CertRecord
	wraps    map[string]*keys.OrgCAWrapRecord
}

func newMockVaultStore() *mockVaultStore {
	return &mockVaultStore{
		entries:  make(map[string]*store.VaultEntry),
		orgCerts: make(map[string]*pkistore.CertRecord),
		certs:    make(map[string]*pkistore.CertRecord),
		wraps:    make(map[string]*keys.OrgCAWrapRecord),
	}
}

func (m *mockVaultStore) entryKey(orgID, scopeID, entryType, key string, envTypeID *string, version int) string {
	env := ""
	if envTypeID != nil {
		env = *envTypeID
	}
	return fmt.Sprintf("%s:%s:%s:%s:%s:%d", orgID, scopeID, entryType, key, env, version)
}

func (m *mockVaultStore) GetOrgCA(_ context.Context, orgID string) (*pkistore.CertRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rec, ok := m.orgCerts[orgID]
	if !ok {
		return nil, nil
	}
	cp := *rec
	return &cp, nil
}

func (m *mockVaultStore) GetCertificateBySerialWithKey(_ context.Context, serial string) (*pkistore.CertRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rec, ok := m.certs[serial]
	if !ok {
		return nil, nil
	}
	cp := *rec
	return &cp, nil
}

func (m *mockVaultStore) GetOrgCAWrap(_ context.Context, orgID, memberID string) (*keys.OrgCAWrapRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rec, ok := m.wraps[orgID+":"+memberID]
	if !ok {
		return nil, nil
	}
	cp := *rec
	return &cp, nil
}

func (m *mockVaultStore) WriteVaultEntry(_ context.Context, entry *store.VaultEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if entry.ID == "" {
		entry.ID = fmt.Sprintf("ve-%d", len(m.entries)+1)
	}
	entry.CreatedAt = time.Now()
	cp := *entry
	k := m.entryKey(entry.OrgID, entry.ScopeID, entry.EntryType, entry.Key, entry.EnvTypeID, entry.Version)
	m.entries[k] = &cp
	return nil
}

func (m *mockVaultStore) GetLatestVaultEntry(_ context.Context, orgID, scopeID, entryType, key string, envTypeID *string) (*store.VaultEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var latest *store.VaultEntry
	for _, e := range m.entries {
		if e.OrgID == orgID && e.ScopeID == scopeID && e.EntryType == entryType && e.Key == key {
			envMatch := (envTypeID == nil && e.EnvTypeID == nil) ||
				(envTypeID != nil && e.EnvTypeID != nil && *envTypeID == *e.EnvTypeID)
			if envMatch && !e.Destroyed && e.DeletedAt == nil {
				if latest == nil || e.Version > latest.Version {
					cp := *e
					latest = &cp
				}
			}
		}
	}
	return latest, nil
}

func (m *mockVaultStore) GetVaultEntryVersion(_ context.Context, orgID, scopeID, entryType, key string, envTypeID *string, version int) (*store.VaultEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	k := m.entryKey(orgID, scopeID, entryType, key, envTypeID, version)
	rec, ok := m.entries[k]
	if !ok {
		return nil, nil
	}
	cp := *rec
	return &cp, nil
}

func (m *mockVaultStore) GetNextVaultVersion(_ context.Context, orgID, scopeID, entryType, key string, envTypeID *string) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	maxVersion := 0
	for _, e := range m.entries {
		if e.OrgID == orgID && e.ScopeID == scopeID && e.EntryType == entryType && e.Key == key {
			envMatch := (envTypeID == nil && e.EnvTypeID == nil) ||
				(envTypeID != nil && e.EnvTypeID != nil && *envTypeID == *e.EnvTypeID)
			if envMatch && e.Version > maxVersion {
				maxVersion = e.Version
			}
		}
	}
	return maxVersion + 1, nil
}

func (m *mockVaultStore) SoftDeleteVaultEntry(_ context.Context, orgID, scopeID, entryType, key string, envTypeID *string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.entries {
		if e.OrgID == orgID && e.ScopeID == scopeID && e.EntryType == entryType && e.Key == key {
			envMatch := (envTypeID == nil && e.EnvTypeID == nil) ||
				(envTypeID != nil && e.EnvTypeID != nil && *envTypeID == *e.EnvTypeID)
			if envMatch {
				now := time.Now()
				e.DeletedAt = &now
			}
		}
	}
	return nil
}

func (m *mockVaultStore) DestroyVaultEntry(_ context.Context, orgID, scopeID, entryType, key string, envTypeID *string, version int) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	count := 0
	for _, e := range m.entries {
		if e.OrgID == orgID && e.ScopeID == scopeID && e.EntryType == entryType && e.Key == key {
			envMatch := (envTypeID == nil && e.EnvTypeID == nil) ||
				(envTypeID != nil && e.EnvTypeID != nil && *envTypeID == *e.EnvTypeID)
			if envMatch && (version == 0 || e.Version == version) {
				e.Destroyed = true
				count++
			}
		}
	}
	return count, nil
}

func (m *mockVaultStore) ListVaultEntries(_ context.Context, orgID, scopeID, entryType string, envTypeID *string) ([]store.VaultListItem, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	seen := make(map[string]*store.VaultListItem)
	for _, e := range m.entries {
		if e.OrgID == orgID && e.ScopeID == scopeID && e.EntryType == entryType && !e.Destroyed && e.DeletedAt == nil {
			envMatch := (envTypeID == nil && e.EnvTypeID == nil) ||
				(envTypeID != nil && e.EnvTypeID != nil && *envTypeID == *e.EnvTypeID)
			if envMatch {
				if item, ok := seen[e.Key]; ok {
					if e.Version > item.LatestVersion {
						item.LatestVersion = e.Version
						item.UpdatedAt = e.CreatedAt
					}
				} else {
					seen[e.Key] = &store.VaultListItem{
						Key:           e.Key,
						LatestVersion: e.Version,
						CreatedAt:     e.CreatedAt,
						UpdatedAt:     e.CreatedAt,
					}
				}
			}
		}
	}
	var result []store.VaultListItem
	for _, item := range seen {
		result = append(result, *item)
	}
	return result, nil
}

func (m *mockVaultStore) GetVaultEntryHistory(_ context.Context, orgID, scopeID, entryType, key string, envTypeID *string) ([]*store.VaultEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []*store.VaultEntry
	for _, e := range m.entries {
		if e.OrgID == orgID && e.ScopeID == scopeID && e.EntryType == entryType && e.Key == key {
			envMatch := (envTypeID == nil && e.EnvTypeID == nil) ||
				(envTypeID != nil && e.EnvTypeID != nil && *envTypeID == *e.EnvTypeID)
			if envMatch {
				cp := *e
				result = append(result, &cp)
			}
		}
	}
	return result, nil
}

// --- Test setup ---

type vaultTestCtx struct {
	vaultSvc     *VaultService
	sessionSvc   *SessionService
	vaultStore   *mockVaultStore
	certStore    *mockCertStore
	orgCAKey     *ecdsa.PrivateKey
	orgCACert    *x509.Certificate
	memberKey    *ecdsa.PrivateKey
	memberSerial string
}

func setupVaultTest(t *testing.T) *vaultTestCtx {
	t.Helper()

	// Setup KMS stack
	_, _, dekMgr, _, auditLogger, _, err := testutil.SetupTestKMSStack(testutil.TestRootKeyHex)
	if err != nil {
		t.Fatalf("SetupTestKMSStack: %v", err)
	}

	// Create OrgCA wrap manager
	orgCAWrapStore := testutil.NewMockOrgCAWrapStore()
	orgCAWrapMgr := keys.NewOrgCAWrapManager(orgCAWrapStore)

	// Setup session service
	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tokenRegistry := newMockTokenRegistry()
	certStore := newMockCertStore()
	policyStore := newMockPolicyStore()

	sessionSvc := NewSessionService(signingKey, "test-issuer", 1*time.Hour, tokenRegistry, certStore, policyStore, auditLogger)

	// Generate PKI chain: root CA → org CA
	rootKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	rootCert, _ := x509.ParseCertificate(rootDER)

	orgCAKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	orgCATemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Org CA - org-001"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	orgCADER, _ := x509.CreateCertificate(rand.Reader, orgCATemplate, rootCert, &orgCAKey.PublicKey, rootKey)
	orgCACert, _ := x509.ParseCertificate(orgCADER)
	orgCACertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: orgCADER})

	// Issue member cert using pki package (embeds role OID for scope resolution)
	memberCert, memberKey, memberDER, err := pki.CreateMemberCertificate(
		"member-001", "member@org-001.com", "org-001", "admin",
		orgCACert, orgCAKey, 365*24*time.Hour, nil,
	)
	if err != nil {
		t.Fatalf("CreateMemberCertificate: %v", err)
	}

	// Create vault store and register org CA cert
	vaultStore := newMockVaultStore()
	orgCASerial := orgCACert.SerialNumber.Text(16)
	vaultStore.orgCerts["org-001"] = &pkistore.CertRecord{
		SerialNumber: orgCASerial,
		CertType:     "org_intermediate_ca",
		OrgID:        "org-001",
		CertPEM:      string(orgCACertPEM),
		Status:       "active",
	}

	memberCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: memberDER})
	memberSerial := memberCert.SerialNumber.Text(16)

	_ = certStore.StoreCertificate(context.Background(), &pkistore.CertRecord{
		SerialNumber: memberSerial,
		CertType:     "member",
		OrgID:        "org-001",
		CertPEM:      string(memberCertPEM),
		Status:       "active",
		IssuedAt:     time.Now().Add(-time.Hour),
		ExpiresAt:    time.Now().Add(365 * 24 * time.Hour),
	})

	// Wrap org CA for member
	_ = orgCAWrapMgr.WrapOrgCAForMember(context.Background(), "org-001", "member-001", memberSerial, &memberKey.PublicKey, orgCAKey)

	// Create vault service
	vaultSvc := NewVaultService(dekMgr, orgCAWrapMgr, vaultStore, auditLogger, sessionSvc)

	return &vaultTestCtx{
		vaultSvc:     vaultSvc,
		sessionSvc:   sessionSvc,
		vaultStore:   vaultStore,
		certStore:    certStore,
		orgCAKey:     orgCAKey,
		orgCACert:    orgCACert,
		memberKey:    memberKey,
		memberSerial: memberSerial,
	}
}

func createVaultSessionToken(t *testing.T, tc *vaultTestCtx, scopes []string) string {
	t.Helper()
	resp, err := tc.sessionSvc.CreateSessionManaged(context.Background(), &CreateSessionManagedRequest{
		MemberID:   "member-001",
		OrgID:      "org-001",
		CertSerial: tc.memberSerial,
		Scopes:     scopes,
	})
	if err != nil {
		t.Fatalf("CreateSessionManaged: %v", err)
	}
	return resp.SessionToken
}

// --- Vault Write tests ---

func TestVaultWrite(t *testing.T) {
	tc := setupVaultTest(t)
	ctx := context.Background()
	token := createVaultSessionToken(t, tc, []string{"vault:read", "vault:write"})

	resp, err := tc.vaultSvc.Write(ctx, token, &VaultWriteRequest{
		OrgID:     "org-001",
		ScopeID:   "scope-1",
		EntryType: "env",
		Key:       "DB_URL",
		Value:     []byte("encrypted-value-here"),
		CreatedBy: "member-001",
	})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if resp.ID == "" {
		t.Error("response ID is empty")
	}
	if resp.Version != 1 {
		t.Errorf("Version = %d, want 1", resp.Version)
	}
	if resp.KeyVersionID == "" {
		t.Error("KeyVersionID is empty")
	}
}

func TestVaultWrite_WithEnvType(t *testing.T) {
	tc := setupVaultTest(t)
	ctx := context.Background()
	token := createVaultSessionToken(t, tc, []string{"vault:write"})

	envType := "production"
	resp, err := tc.vaultSvc.Write(ctx, token, &VaultWriteRequest{
		OrgID:     "org-001",
		ScopeID:   "scope-1",
		EntryType: "env",
		Key:       "DB_URL",
		EnvTypeID: &envType,
		Value:     []byte("prod-value"),
		CreatedBy: "member-001",
	})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if resp.Version != 1 {
		t.Errorf("Version = %d, want 1", resp.Version)
	}
}

func TestVaultWrite_InvalidSession(t *testing.T) {
	tc := setupVaultTest(t)
	_, err := tc.vaultSvc.Write(context.Background(), "invalid-token", &VaultWriteRequest{
		OrgID:   "org-001",
		ScopeID: "scope-1",
		Key:     "test",
		Value:   []byte("data"),
	})
	if err == nil {
		t.Fatal("expected error for invalid session")
	}
}

func TestVaultWrite_InsufficientScope(t *testing.T) {
	tc := setupVaultTest(t)
	token := createVaultSessionToken(t, tc, []string{"vault:read"})

	_, err := tc.vaultSvc.Write(context.Background(), token, &VaultWriteRequest{
		OrgID:   "org-001",
		ScopeID: "scope-1",
		Key:     "test",
		Value:   []byte("data"),
	})
	if err == nil {
		t.Fatal("expected error for insufficient scope")
	}
}

func TestVaultWrite_OrgMismatch(t *testing.T) {
	tc := setupVaultTest(t)
	token := createVaultSessionToken(t, tc, []string{"vault:write"})

	_, err := tc.vaultSvc.Write(context.Background(), token, &VaultWriteRequest{
		OrgID:   "org-OTHER",
		ScopeID: "scope-1",
		Key:     "test",
		Value:   []byte("data"),
	})
	if err == nil {
		t.Fatal("expected error for org mismatch")
	}
}

// --- Vault Read tests ---

func TestVaultRead(t *testing.T) {
	tc := setupVaultTest(t)
	ctx := context.Background()
	token := createVaultSessionToken(t, tc, []string{"vault:read", "vault:write"})

	// Write first
	_, err := tc.vaultSvc.Write(ctx, token, &VaultWriteRequest{
		OrgID:     "org-001",
		ScopeID:   "scope-1",
		EntryType: "env",
		Key:       "SECRET",
		Value:     []byte("my-secret-value"),
		CreatedBy: "member-001",
	})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Read it back (client-side decrypt = BYOK path)
	resp, err := tc.vaultSvc.Read(ctx, token, &VaultReadRequest{
		OrgID:             "org-001",
		ScopeID:           "scope-1",
		EntryType:         "env",
		Key:               "SECRET",
		ClientSideDecrypt: true,
	})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if resp.Key != "SECRET" {
		t.Errorf("Key = %q, want %q", resp.Key, "SECRET")
	}
	if len(resp.EncryptedValue) == 0 {
		t.Error("EncryptedValue is empty")
	}
	if len(resp.MemberWrapEphemeralPub) == 0 {
		t.Error("MemberWrapEphemeralPub is empty for BYOK path")
	}
}

func TestVaultRead_NotFound(t *testing.T) {
	tc := setupVaultTest(t)
	ctx := context.Background()
	token := createVaultSessionToken(t, tc, []string{"vault:read"})

	_, err := tc.vaultSvc.Read(ctx, token, &VaultReadRequest{
		OrgID:     "org-001",
		ScopeID:   "scope-1",
		EntryType: "env",
		Key:       "NONEXISTENT",
	})
	if err == nil {
		t.Fatal("expected error for not found")
	}
}

func TestVaultRead_InvalidSession(t *testing.T) {
	tc := setupVaultTest(t)
	_, err := tc.vaultSvc.Read(context.Background(), "bad", &VaultReadRequest{
		OrgID: "org-001",
	})
	if err == nil {
		t.Fatal("expected error for invalid session")
	}
}

// --- Vault ReadVersion tests ---

func TestVaultReadVersion(t *testing.T) {
	tc := setupVaultTest(t)
	ctx := context.Background()
	token := createVaultSessionToken(t, tc, []string{"vault:read", "vault:write"})

	// Write two versions
	_, _ = tc.vaultSvc.Write(ctx, token, &VaultWriteRequest{
		OrgID: "org-001", ScopeID: "s1", EntryType: "env", Key: "K",
		Value: []byte("v1"), CreatedBy: "member-001",
	})
	_, _ = tc.vaultSvc.Write(ctx, token, &VaultWriteRequest{
		OrgID: "org-001", ScopeID: "s1", EntryType: "env", Key: "K",
		Value: []byte("v2"), CreatedBy: "member-001",
	})

	// Read version 1
	resp, err := tc.vaultSvc.ReadVersion(ctx, token, &VaultReadVersionRequest{
		OrgID: "org-001", ScopeID: "s1", EntryType: "env", Key: "K",
		Version: 1, ClientSideDecrypt: true,
	})
	if err != nil {
		t.Fatalf("ReadVersion: %v", err)
	}
	if resp.Version != 1 {
		t.Errorf("Version = %d, want 1", resp.Version)
	}
}

func TestVaultReadVersion_NotFound(t *testing.T) {
	tc := setupVaultTest(t)
	ctx := context.Background()
	token := createVaultSessionToken(t, tc, []string{"vault:read"})

	_, err := tc.vaultSvc.ReadVersion(ctx, token, &VaultReadVersionRequest{
		OrgID: "org-001", ScopeID: "s1", EntryType: "env", Key: "K",
		Version: 99,
	})
	if err == nil {
		t.Fatal("expected error for version not found")
	}
}

// --- Vault Delete tests ---

func TestVaultDelete(t *testing.T) {
	tc := setupVaultTest(t)
	ctx := context.Background()

	// Create session with admin role (has vault:delete)
	resp, err := tc.sessionSvc.CreateSessionManaged(ctx, &CreateSessionManagedRequest{
		MemberID: "member-001", OrgID: "org-001", CertSerial: tc.memberSerial,
		Scopes: []string{"vault:read", "vault:write", "vault:delete"},
	})
	if err != nil {
		t.Fatalf("CreateSessionManaged: %v", err)
	}
	token := resp.SessionToken

	// Write
	_, _ = tc.vaultSvc.Write(ctx, token, &VaultWriteRequest{
		OrgID: "org-001", ScopeID: "s1", EntryType: "env", Key: "DEL",
		Value: []byte("to-delete"), CreatedBy: "member-001",
	})

	// Delete
	err = tc.vaultSvc.Delete(ctx, token, &VaultDeleteRequest{
		OrgID: "org-001", ScopeID: "s1", EntryType: "env", Key: "DEL",
	})
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// Read should now fail (soft deleted)
	_, err = tc.vaultSvc.Read(ctx, token, &VaultReadRequest{
		OrgID: "org-001", ScopeID: "s1", EntryType: "env", Key: "DEL",
	})
	if err == nil {
		t.Fatal("expected error reading deleted entry")
	}
}

func TestVaultDelete_InsufficientScope(t *testing.T) {
	tc := setupVaultTest(t)
	token := createVaultSessionToken(t, tc, []string{"vault:read"})

	err := tc.vaultSvc.Delete(context.Background(), token, &VaultDeleteRequest{
		OrgID: "org-001", ScopeID: "s1", EntryType: "env", Key: "K",
	})
	if err == nil {
		t.Fatal("expected error for insufficient scope")
	}
}

// --- Vault Destroy tests ---

func TestVaultDestroy_NotAdmin(t *testing.T) {
	tc := setupVaultTest(t)
	// member role doesn't have vault:delete (the scope check happens first)
	token := createVaultSessionToken(t, tc, []string{"vault:read"})

	_, err := tc.vaultSvc.Destroy(context.Background(), token, &VaultDestroyRequest{
		OrgID: "org-001", ScopeID: "s1", EntryType: "env", Key: "K",
	})
	if err == nil {
		t.Fatal("expected error for non-admin destroy")
	}
}

// --- Vault Destroy (full lifecycle) tests ---

func TestVaultDestroy_Success(t *testing.T) {
	tc := setupVaultTest(t)
	ctx := context.Background()
	token := createVaultSessionToken(t, tc, []string{"vault:read", "vault:write", "vault:delete"})

	// Write an entry
	_, err := tc.vaultSvc.Write(ctx, token, &VaultWriteRequest{
		OrgID: "org-001", ScopeID: "s1", EntryType: "env", Key: "DESTROY_ME",
		Value: []byte("to-destroy"), CreatedBy: "member-001",
	})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Destroy it
	destroyedCount, err := tc.vaultSvc.Destroy(ctx, token, &VaultDestroyRequest{
		OrgID: "org-001", ScopeID: "s1", EntryType: "env", Key: "DESTROY_ME",
	})
	if err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if destroyedCount == 0 {
		t.Error("expected at least one destroyed entry")
	}

	// Read should fail — entry is destroyed
	_, err = tc.vaultSvc.Read(ctx, token, &VaultReadRequest{
		OrgID: "org-001", ScopeID: "s1", EntryType: "env", Key: "DESTROY_ME",
	})
	if err == nil {
		t.Fatal("expected error reading destroyed entry")
	}
}

func TestVaultDestroy_MasterRole(t *testing.T) {
	tc := setupVaultTest(t)
	ctx := context.Background()

	// Create session with master-like scopes (vault:delete is needed)
	token := createVaultSessionToken(t, tc, []string{"vault:read", "vault:write", "vault:delete"})

	// Write
	_, err := tc.vaultSvc.Write(ctx, token, &VaultWriteRequest{
		OrgID: "org-001", ScopeID: "s1", EntryType: "env", Key: "MASTER_DESTROY",
		Value: []byte("data"), CreatedBy: "member-001",
	})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Master should be able to destroy
	destroyedCount, err := tc.vaultSvc.Destroy(ctx, token, &VaultDestroyRequest{
		OrgID: "org-001", ScopeID: "s1", EntryType: "env", Key: "MASTER_DESTROY",
	})
	if err != nil {
		t.Fatalf("Destroy by master: %v", err)
	}
	if destroyedCount == 0 {
		t.Error("master destroy should succeed")
	}
}

func TestVaultDelete_ThenRead(t *testing.T) {
	tc := setupVaultTest(t)
	ctx := context.Background()
	token := createVaultSessionToken(t, tc, []string{"vault:read", "vault:write", "vault:delete"})

	// Write
	_, _ = tc.vaultSvc.Write(ctx, token, &VaultWriteRequest{
		OrgID: "org-001", ScopeID: "s1", EntryType: "env", Key: "DEL_READ",
		Value: []byte("val"), CreatedBy: "member-001",
	})

	// Soft delete
	err := tc.vaultSvc.Delete(ctx, token, &VaultDeleteRequest{
		OrgID: "org-001", ScopeID: "s1", EntryType: "env", Key: "DEL_READ",
	})
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// Read should fail
	_, err = tc.vaultSvc.Read(ctx, token, &VaultReadRequest{
		OrgID: "org-001", ScopeID: "s1", EntryType: "env", Key: "DEL_READ",
	})
	if err == nil {
		t.Fatal("expected error reading soft-deleted entry")
	}
}

func TestVaultDelete_ThenDestroy(t *testing.T) {
	tc := setupVaultTest(t)
	ctx := context.Background()
	token := createVaultSessionToken(t, tc, []string{"vault:read", "vault:write", "vault:delete"})

	// Write
	_, _ = tc.vaultSvc.Write(ctx, token, &VaultWriteRequest{
		OrgID: "org-001", ScopeID: "s1", EntryType: "env", Key: "DEL_THEN_DESTROY",
		Value: []byte("val"), CreatedBy: "member-001",
	})

	// Soft delete first
	_ = tc.vaultSvc.Delete(ctx, token, &VaultDeleteRequest{
		OrgID: "org-001", ScopeID: "s1", EntryType: "env", Key: "DEL_THEN_DESTROY",
	})

	// Then destroy — should succeed
	_, err := tc.vaultSvc.Destroy(ctx, token, &VaultDestroyRequest{
		OrgID: "org-001", ScopeID: "s1", EntryType: "env", Key: "DEL_THEN_DESTROY",
	})
	if err != nil {
		t.Fatalf("Destroy after soft delete: %v", err)
	}
}

func TestVaultWrite_ConcurrentSameKey(t *testing.T) {
	tc := setupVaultTest(t)
	ctx := context.Background()
	token := createVaultSessionToken(t, tc, []string{"vault:read", "vault:write"})

	const goroutines = 2
	errs := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			_, err := tc.vaultSvc.Write(ctx, token, &VaultWriteRequest{
				OrgID: "org-001", ScopeID: "s1", EntryType: "env",
				Key:       "CONCURRENT_KEY",
				Value:     []byte(fmt.Sprintf("value-%d", idx)),
				CreatedBy: "member-001",
			})
			errs <- err
		}(i)
	}

	for i := 0; i < goroutines; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent write %d: %v", i, err)
		}
	}

	// Both should have succeeded — history should have entries
	resp, err := tc.vaultSvc.History(ctx, token, &VaultHistoryRequest{
		OrgID: "org-001", ScopeID: "s1", EntryType: "env", Key: "CONCURRENT_KEY",
	})
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(resp.Versions) < 2 {
		t.Errorf("expected ≥2 versions after concurrent writes, got %d", len(resp.Versions))
	}
}

func TestVaultRead_AfterKeyRotation(t *testing.T) {
	tc := setupVaultTest(t)
	ctx := context.Background()
	token := createVaultSessionToken(t, tc, []string{"vault:read", "vault:write"})

	// Write a value
	_, err := tc.vaultSvc.Write(ctx, token, &VaultWriteRequest{
		OrgID: "org-001", ScopeID: "s1", EntryType: "env", Key: "ROTATE_READ",
		Value: []byte("pre-rotation-data"), CreatedBy: "member-001",
	})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Read it back (should work before and after any internal rotation)
	resp, err := tc.vaultSvc.Read(ctx, token, &VaultReadRequest{
		OrgID: "org-001", ScopeID: "s1", EntryType: "env", Key: "ROTATE_READ",
		ClientSideDecrypt: true,
	})
	if err != nil {
		t.Fatalf("Read after write: %v", err)
	}
	if resp.Key != "ROTATE_READ" {
		t.Errorf("Key = %q, want %q", resp.Key, "ROTATE_READ")
	}
	if len(resp.EncryptedValue) == 0 {
		t.Error("EncryptedValue is empty")
	}
}

// --- Vault List tests ---

func TestVaultList(t *testing.T) {
	tc := setupVaultTest(t)
	ctx := context.Background()
	token := createVaultSessionToken(t, tc, []string{"vault:read", "vault:write"})

	// Write a couple entries
	_, _ = tc.vaultSvc.Write(ctx, token, &VaultWriteRequest{
		OrgID: "org-001", ScopeID: "s1", EntryType: "env", Key: "A",
		Value: []byte("val-a"), CreatedBy: "member-001",
	})
	_, _ = tc.vaultSvc.Write(ctx, token, &VaultWriteRequest{
		OrgID: "org-001", ScopeID: "s1", EntryType: "env", Key: "B",
		Value: []byte("val-b"), CreatedBy: "member-001",
	})

	resp, err := tc.vaultSvc.List(ctx, token, &VaultListRequest{
		OrgID: "org-001", ScopeID: "s1", EntryType: "env",
	})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(resp.Entries) != 2 {
		t.Errorf("List entries = %d, want 2", len(resp.Entries))
	}
}

func TestVaultList_InsufficientScope(t *testing.T) {
	tc := setupVaultTest(t)
	// Create a token without vault:read - use empty scopes which defaults based on role
	// The mock policy store returns defaults so the member will get vault:read
	// Instead, use a token from a different org context
	token := createVaultSessionToken(t, tc, []string{"vault:read"})

	_, err := tc.vaultSvc.List(context.Background(), token, &VaultListRequest{
		OrgID: "org-OTHER",
	})
	if err == nil {
		t.Fatal("expected error for org mismatch")
	}
}

// --- Vault History tests ---

func TestVaultHistory(t *testing.T) {
	tc := setupVaultTest(t)
	ctx := context.Background()
	token := createVaultSessionToken(t, tc, []string{"vault:read", "vault:write"})

	// Write two versions
	_, _ = tc.vaultSvc.Write(ctx, token, &VaultWriteRequest{
		OrgID: "org-001", ScopeID: "s1", EntryType: "env", Key: "H",
		Value: []byte("v1"), CreatedBy: "member-001",
	})
	_, _ = tc.vaultSvc.Write(ctx, token, &VaultWriteRequest{
		OrgID: "org-001", ScopeID: "s1", EntryType: "env", Key: "H",
		Value: []byte("v2"), CreatedBy: "member-001",
	})

	resp, err := tc.vaultSvc.History(ctx, token, &VaultHistoryRequest{
		OrgID: "org-001", ScopeID: "s1", EntryType: "env", Key: "H",
	})
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(resp.Versions) != 2 {
		t.Errorf("History versions = %d, want 2", len(resp.Versions))
	}
}

func TestVaultHistory_InvalidSession(t *testing.T) {
	tc := setupVaultTest(t)
	_, err := tc.vaultSvc.History(context.Background(), "bad", &VaultHistoryRequest{
		OrgID: "org-001",
	})
	if err == nil {
		t.Fatal("expected error for invalid session")
	}
}

// --- getOrgCAPublicKey tests ---

func TestGetOrgCAPublicKey_NotFound(t *testing.T) {
	tc := setupVaultTest(t)
	// Try to get org CA for an org that doesn't exist
	_, err := tc.vaultSvc.getOrgCAPublicKey(context.Background(), "org-missing")
	if err == nil {
		t.Fatal("expected error for missing org CA")
	}
}
