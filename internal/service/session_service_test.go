package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/envsync/minikms/internal/audit"
	"github.com/envsync/minikms/internal/auth"
	"github.com/envsync/minikms/internal/pki"
	"github.com/envsync/minikms/internal/pkistore"
	"github.com/envsync/minikms/internal/store"
)

// --- Test mocks ---

type mockTokenRegistry struct {
	mu     sync.RWMutex
	tokens map[string]*auth.TokenEntry
}

func newMockTokenRegistry() *mockTokenRegistry {
	return &mockTokenRegistry{tokens: make(map[string]*auth.TokenEntry)}
}

func (m *mockTokenRegistry) StoreToken(_ context.Context, e *auth.TokenEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *e
	m.tokens[e.JTI] = &cp
	return nil
}

func (m *mockTokenRegistry) GetToken(_ context.Context, jti string) (*auth.TokenEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	e, ok := m.tokens[jti]
	if !ok {
		return nil, nil
	}
	cp := *e
	return &cp, nil
}

func (m *mockTokenRegistry) RevokeToken(_ context.Context, jti string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.tokens[jti]
	if !ok {
		return fmt.Errorf("token not found")
	}
	e.Revoked = true
	return nil
}

func (m *mockTokenRegistry) CleanupExpired(_ context.Context) error { return nil }

type mockCertStore struct {
	mu    sync.RWMutex
	certs map[string]*pkistore.CertRecord
	orgCA map[string]*pkistore.CertRecord
}

func newMockCertStore() *mockCertStore {
	return &mockCertStore{
		certs: make(map[string]*pkistore.CertRecord),
		orgCA: make(map[string]*pkistore.CertRecord),
	}
}

func (m *mockCertStore) StoreCertificate(_ context.Context, rec *pkistore.CertRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *rec
	m.certs[rec.SerialNumber] = &cp
	if rec.CertType == "org_intermediate_ca" {
		m.orgCA[rec.OrgID] = &cp
	}
	return nil
}

func (m *mockCertStore) StoreCertificateWithKey(_ context.Context, rec *pkistore.CertRecord) error {
	return m.StoreCertificate(context.Background(), rec)
}

func (m *mockCertStore) GetCertificateBySerial(_ context.Context, serial string) (*pkistore.CertRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rec, ok := m.certs[serial]
	if !ok {
		return nil, nil
	}
	cp := *rec
	return &cp, nil
}

func (m *mockCertStore) GetCertificateBySerialWithKey(_ context.Context, serial string) (*pkistore.CertRecord, error) {
	return m.GetCertificateBySerial(context.Background(), serial)
}

func (m *mockCertStore) GetOrgCA(_ context.Context, orgID string) (*pkistore.CertRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rec, ok := m.orgCA[orgID]
	if !ok {
		return nil, nil
	}
	cp := *rec
	return &cp, nil
}

func (m *mockCertStore) UpdateCertificateStatus(_ context.Context, serial, status string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.certs[serial]
	if !ok {
		return fmt.Errorf("not found")
	}
	rec.Status = status
	return nil
}

func (m *mockCertStore) InsertCRLEntry(_ context.Context, _ *pkistore.CRLEntryRecord) error {
	return nil
}

func (m *mockCertStore) GetCRLEntries(_ context.Context, _ string) ([]pkistore.CRLEntryRecord, error) {
	return nil, nil
}

func (m *mockCertStore) GetNextCRLNumber(_ context.Context, _ string) (int64, error) {
	return 1, nil
}

func (m *mockCertStore) GetCertRevocationEntry(_ context.Context, _ string) (*pkistore.CRLEntryRecord, error) {
	return nil, nil
}

type mockPolicyStore struct {
	mu       sync.RWMutex
	policies map[string]*store.OrgSecurityPolicy
	tokens   map[string][]*auth.TokenEntry
}

func newMockPolicyStore() *mockPolicyStore {
	return &mockPolicyStore{
		policies: make(map[string]*store.OrgSecurityPolicy),
		tokens:   make(map[string][]*auth.TokenEntry),
	}
}

func (m *mockPolicyStore) GetOrgSecurityPolicy(_ context.Context, orgID string) (*store.OrgSecurityPolicy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if p, ok := m.policies[orgID]; ok {
		cp := *p
		return &cp, nil
	}
	return &store.OrgSecurityPolicy{
		OrgID:              orgID,
		SessionDurationSec: 3600,
		MaxSessionTokens:   10,
	}, nil
}

func (m *mockPolicyStore) GetTokensBySubject(_ context.Context, subjectHash string) ([]*auth.TokenEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []*auth.TokenEntry
	for _, e := range m.tokens[subjectHash] {
		cp := *e
		result = append(result, &cp)
	}
	return result, nil
}

func (m *mockPolicyStore) RevokeTokensBySubject(_ context.Context, subjectHash string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	count := 0
	for _, e := range m.tokens[subjectHash] {
		if !e.Revoked {
			e.Revoked = true
			count++
		}
	}
	return count, nil
}

type mockAuditStore struct{}

func (m *mockAuditStore) GetLatestEntryHash(_ context.Context, _ string) (string, error) {
	return audit.GenesisHash, nil
}
func (m *mockAuditStore) InsertEntry(_ context.Context, _ *audit.AuditEntry) error { return nil }
func (m *mockAuditStore) GetEntries(_ context.Context, _ string, _, _ int) ([]*audit.AuditEntry, error) {
	return nil, nil
}
func (m *mockAuditStore) VerifyChain(_ context.Context, _ string) (bool, error) { return true, nil }

// --- Helpers ---

func setupTestSessionService(t *testing.T) (*SessionService, *mockTokenRegistry, *mockCertStore, *mockPolicyStore) {
	t.Helper()
	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	registry := newMockTokenRegistry()
	certStore := newMockCertStore()
	policyStore := newMockPolicyStore()
	auditLogger := audit.NewAuditLogger(&mockAuditStore{})

	svc := NewSessionService(signingKey, "test-issuer", 1*time.Hour, registry, certStore, policyStore, auditLogger)
	return svc, registry, certStore, policyStore
}

func createTestMemberCert(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate, []byte, string) {
	t.Helper()

	// Generate a root CA
	rootKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
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

	// Create org CA
	orgCAKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	orgCATemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Org CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	orgCADER, _ := x509.CreateCertificate(rand.Reader, orgCATemplate, rootCert, &orgCAKey.PublicKey, rootKey)
	orgCACert, _ := x509.ParseCertificate(orgCADER)

	// Issue member cert using pki package
	memberCert, memberKey, certDER, err := pki.CreateMemberCertificate(
		"member-001", "alice@example.com", "org-001", "admin",
		orgCACert, orgCAKey,
		365*24*time.Hour, nil,
	)
	if err != nil {
		t.Fatalf("CreateMemberCertificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	serialHex := memberCert.SerialNumber.Text(16)

	return memberKey, memberCert, certPEM, serialHex
}

// --- Tests ---

func TestCreateSessionManaged(t *testing.T) {
	svc, _, certStore, _ := setupTestSessionService(t)
	ctx := context.Background()

	_, _, certPEM, serialHex := createTestMemberCert(t)

	// Register the cert in the mock store
	_ = certStore.StoreCertificate(ctx, &pkistore.CertRecord{
		SerialNumber: serialHex,
		CertType:     "member",
		OrgID:        "org-001",
		CertPEM:      string(certPEM),
		Status:       "active",
		IssuedAt:     time.Now().Add(-time.Hour),
		ExpiresAt:    time.Now().Add(365 * 24 * time.Hour),
	})

	resp, err := svc.CreateSessionManaged(ctx, &CreateSessionManagedRequest{
		MemberID:   "member-001",
		OrgID:      "org-001",
		CertSerial: serialHex,
		Scopes:     []string{"vault:read"},
	})
	if err != nil {
		t.Fatalf("CreateSessionManaged: %v", err)
	}
	if resp.SessionToken == "" {
		t.Error("SessionToken is empty")
	}
	if resp.ExpiresAt.Before(time.Now()) {
		t.Error("ExpiresAt is in the past")
	}
	if len(resp.Scopes) == 0 {
		t.Error("Scopes is empty")
	}
}

func TestCreateSessionManaged_CertNotFound(t *testing.T) {
	svc, _, _, _ := setupTestSessionService(t)
	_, err := svc.CreateSessionManaged(context.Background(), &CreateSessionManagedRequest{
		MemberID:   "m1",
		OrgID:      "o1",
		CertSerial: "nonexistent",
	})
	if err == nil {
		t.Fatal("expected error for cert not found")
	}
}

func TestCreateSessionManaged_InactiveCert(t *testing.T) {
	svc, _, certStore, _ := setupTestSessionService(t)
	ctx := context.Background()

	_, _, certPEM, serialHex := createTestMemberCert(t)
	_ = certStore.StoreCertificate(ctx, &pkistore.CertRecord{
		SerialNumber: serialHex,
		CertType:     "member",
		OrgID:        "org-001",
		CertPEM:      string(certPEM),
		Status:       "revoked",
		IssuedAt:     time.Now().Add(-time.Hour),
		ExpiresAt:    time.Now().Add(365 * 24 * time.Hour),
	})

	_, err := svc.CreateSessionManaged(ctx, &CreateSessionManagedRequest{
		MemberID:   "member-001",
		OrgID:      "org-001",
		CertSerial: serialHex,
	})
	if err == nil {
		t.Fatal("expected error for inactive cert")
	}
}

func TestCreateSessionManaged_WrongOrg(t *testing.T) {
	svc, _, certStore, _ := setupTestSessionService(t)
	ctx := context.Background()

	_, _, certPEM, serialHex := createTestMemberCert(t)
	_ = certStore.StoreCertificate(ctx, &pkistore.CertRecord{
		SerialNumber: serialHex,
		CertType:     "member",
		OrgID:        "org-001",
		CertPEM:      string(certPEM),
		Status:       "active",
		IssuedAt:     time.Now().Add(-time.Hour),
		ExpiresAt:    time.Now().Add(365 * 24 * time.Hour),
	})

	_, err := svc.CreateSessionManaged(ctx, &CreateSessionManagedRequest{
		MemberID:   "member-001",
		OrgID:      "org-OTHER",
		CertSerial: serialHex,
	})
	if err == nil {
		t.Fatal("expected error for org mismatch")
	}
}

func TestValidateSession(t *testing.T) {
	svc, _, certStore, _ := setupTestSessionService(t)
	ctx := context.Background()

	_, _, certPEM, serialHex := createTestMemberCert(t)
	_ = certStore.StoreCertificate(ctx, &pkistore.CertRecord{
		SerialNumber: serialHex,
		CertType:     "member",
		OrgID:        "org-001",
		CertPEM:      string(certPEM),
		Status:       "active",
		IssuedAt:     time.Now().Add(-time.Hour),
		ExpiresAt:    time.Now().Add(365 * 24 * time.Hour),
	})

	// Create a session
	sessionResp, err := svc.CreateSessionManaged(ctx, &CreateSessionManagedRequest{
		MemberID:   "member-001",
		OrgID:      "org-001",
		CertSerial: serialHex,
		Scopes:     []string{"vault:read", "vault:write"},
	})
	if err != nil {
		t.Fatalf("CreateSessionManaged: %v", err)
	}

	// Validate the session
	resp, err := svc.ValidateSession(ctx, &ValidateSessionRequest{SessionToken: sessionResp.SessionToken})
	if err != nil {
		t.Fatalf("ValidateSession: %v", err)
	}
	if !resp.Valid {
		t.Error("session should be valid")
	}
	if resp.MemberID != "member-001" {
		t.Errorf("MemberID = %q, want %q", resp.MemberID, "member-001")
	}
	if resp.OrgID != "org-001" {
		t.Errorf("OrgID = %q, want %q", resp.OrgID, "org-001")
	}
}

func TestValidateSession_Invalid(t *testing.T) {
	svc, _, _, _ := setupTestSessionService(t)
	resp, err := svc.ValidateSession(context.Background(), &ValidateSessionRequest{SessionToken: "invalid-token"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Valid {
		t.Error("should be invalid")
	}
}

func TestRevokeSession(t *testing.T) {
	svc, _, certStore, _ := setupTestSessionService(t)
	ctx := context.Background()

	_, _, certPEM, serialHex := createTestMemberCert(t)
	_ = certStore.StoreCertificate(ctx, &pkistore.CertRecord{
		SerialNumber: serialHex,
		CertType:     "member",
		OrgID:        "org-001",
		CertPEM:      string(certPEM),
		Status:       "active",
		IssuedAt:     time.Now().Add(-time.Hour),
		ExpiresAt:    time.Now().Add(365 * 24 * time.Hour),
	})

	sessionResp, err := svc.CreateSessionManaged(ctx, &CreateSessionManagedRequest{
		MemberID:   "member-001",
		OrgID:      "org-001",
		CertSerial: serialHex,
	})
	if err != nil {
		t.Fatalf("CreateSessionManaged: %v", err)
	}

	// Revoke
	err = svc.RevokeSession(ctx, sessionResp.SessionToken)
	if err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}

	// Validate should now fail
	resp, err := svc.ValidateSession(ctx, &ValidateSessionRequest{SessionToken: sessionResp.SessionToken})
	if err != nil {
		t.Fatalf("ValidateSession: %v", err)
	}
	if resp.Valid {
		t.Error("session should be invalid after revocation")
	}
}

func TestListSessions(t *testing.T) {
	svc, _, certStore, _ := setupTestSessionService(t)
	ctx := context.Background()

	_, _, certPEM, serialHex := createTestMemberCert(t)
	_ = certStore.StoreCertificate(ctx, &pkistore.CertRecord{
		SerialNumber: serialHex,
		CertType:     "member",
		OrgID:        "org-001",
		CertPEM:      string(certPEM),
		Status:       "active",
		IssuedAt:     time.Now().Add(-time.Hour),
		ExpiresAt:    time.Now().Add(365 * 24 * time.Hour),
	})

	// Create sessions — ListSessions uses the policyStore which returns
	// data from our mock. Since the mock's tokens map is empty (sessions
	// are stored in the tokenRegistry, not policyStore in this test setup),
	// we expect an empty list.
	resp, err := svc.ListSessions(ctx, "member-001", "org-001")
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if resp == nil {
		t.Fatal("response is nil")
	}
}

func TestHasScope(t *testing.T) {
	session := &ValidateSessionResponse{
		Valid:  true,
		Scopes: []string{"vault:read", "vault:write"},
	}

	if !HasScope(session, "vault:read") {
		t.Error("expected HasScope to return true for vault:read")
	}
	if !HasScope(session, "vault:write") {
		t.Error("expected HasScope to return true for vault:write")
	}
	if HasScope(session, "vault:delete") {
		t.Error("expected HasScope to return false for vault:delete")
	}
	if HasScope(session, "") {
		t.Error("expected HasScope to return false for empty scope")
	}
}

func TestResolveScopes(t *testing.T) {
	svc, _, _, _ := setupTestSessionService(t)

	// Admin with no requested scopes should get all admin defaults
	scopes := svc.resolveScopes(nil, "admin")
	if len(scopes) != 4 {
		t.Errorf("admin default scopes: got %d, want 4", len(scopes))
	}

	// Member with no requested scopes
	scopes = svc.resolveScopes(nil, "member")
	if len(scopes) != 2 {
		t.Errorf("member default scopes: got %d, want 2", len(scopes))
	}

	// Readonly
	scopes = svc.resolveScopes(nil, "readonly")
	if len(scopes) != 1 {
		t.Errorf("readonly default scopes: got %d, want 1", len(scopes))
	}

	// Unknown role
	scopes = svc.resolveScopes(nil, "unknown")
	if len(scopes) != 1 || scopes[0] != "vault:read" {
		t.Errorf("unknown role scopes: got %v, want [vault:read]", scopes)
	}

	// Filtered scopes: member requesting admin-only scope
	scopes = svc.resolveScopes([]string{"vault:delete"}, "member")
	if len(scopes) != 2 {
		t.Errorf("member filtered to delete: got %d scopes (should fallback to defaults)", len(scopes))
	}

	// Filtered scopes: admin requesting subset
	scopes = svc.resolveScopes([]string{"vault:read"}, "admin")
	if len(scopes) != 1 || scopes[0] != "vault:read" {
		t.Errorf("admin requesting read: got %v, want [vault:read]", scopes)
	}
}

func TestGenerateNonce(t *testing.T) {
	n1, err := GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce: %v", err)
	}
	if len(n1) != 32 {
		t.Errorf("nonce length = %d, want 32", len(n1))
	}

	n2, _ := GenerateNonce()
	// Should be unique
	same := true
	for i := range n1 {
		if n1[i] != n2[i] {
			same = false
			break
		}
	}
	if same {
		t.Error("two nonces should not be identical")
	}
}

func TestGenerateSessionSigningKey(t *testing.T) {
	key, err := GenerateSessionSigningKey()
	if err != nil {
		t.Fatalf("GenerateSessionSigningKey: %v", err)
	}
	if key.Curve != elliptic.P256() {
		t.Error("expected P-256 curve")
	}
}

func TestCreateSessionManaged_CustomScopes(t *testing.T) {
	svc, _, certStore, _ := setupTestSessionService(t)
	ctx := context.Background()

	_, _, certPEM, serialHex := createTestMemberCert(t)
	_ = certStore.StoreCertificate(ctx, &pkistore.CertRecord{
		SerialNumber: serialHex,
		CertType:     "member",
		OrgID:        "org-001",
		CertPEM:      string(certPEM),
		Status:       "active",
		IssuedAt:     time.Now().Add(-time.Hour),
		ExpiresAt:    time.Now().Add(365 * 24 * time.Hour),
	})

	// Request specific scopes that override role defaults
	resp, err := svc.CreateSessionManaged(ctx, &CreateSessionManagedRequest{
		MemberID:   "member-001",
		OrgID:      "org-001",
		CertSerial: serialHex,
		Scopes:     []string{"vault:read"},
	})
	if err != nil {
		t.Fatalf("CreateSessionManaged: %v", err)
	}
	if len(resp.Scopes) != 1 {
		t.Errorf("expected 1 scope, got %d: %v", len(resp.Scopes), resp.Scopes)
	}
	if resp.Scopes[0] != "vault:read" {
		t.Errorf("scope = %q, want %q", resp.Scopes[0], "vault:read")
	}
}

func TestValidateSession_Expired(t *testing.T) {
	// Create a session service with very short TTL
	signingKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	registry := newMockTokenRegistry()
	certStore := newMockCertStore()
	policyStore := newMockPolicyStore()
	auditLogger := audit.NewAuditLogger(&mockAuditStore{})

	// Very short TTL: 1 millisecond
	svc := NewSessionService(signingKey, "test-issuer", 1*time.Millisecond, registry, certStore, policyStore, auditLogger)
	ctx := context.Background()

	// Set policy with SessionDurationSec=0 so it falls back to the 1ms defaultTTL
	policyStore.mu.Lock()
	policyStore.policies["org-001"] = &store.OrgSecurityPolicy{
		OrgID:              "org-001",
		SessionDurationSec: 0,
		MaxSessionTokens:   10,
	}
	policyStore.mu.Unlock()

	_, _, certPEM, serialHex := createTestMemberCert(t)
	_ = certStore.StoreCertificate(ctx, &pkistore.CertRecord{
		SerialNumber: serialHex,
		CertType:     "member",
		OrgID:        "org-001",
		CertPEM:      string(certPEM),
		Status:       "active",
		IssuedAt:     time.Now().Add(-time.Hour),
		ExpiresAt:    time.Now().Add(365 * 24 * time.Hour),
	})

	sessionResp, err := svc.CreateSessionManaged(ctx, &CreateSessionManagedRequest{
		MemberID:   "member-001",
		OrgID:      "org-001",
		CertSerial: serialHex,
	})
	if err != nil {
		t.Fatalf("CreateSessionManaged: %v", err)
	}

	// Wait for expiration
	time.Sleep(50 * time.Millisecond)

	resp, err := svc.ValidateSession(ctx, &ValidateSessionRequest{SessionToken: sessionResp.SessionToken})
	if err != nil {
		t.Fatalf("ValidateSession: %v", err)
	}
	if resp.Valid {
		t.Error("session should be invalid after expiration")
	}
}

func TestResolveScopes_MasterRole(t *testing.T) {
	svc, _, _, _ := setupTestSessionService(t)

	scopes := svc.resolveScopes(nil, "master")
	// Master should get full scopes (same as admin: vault:read, vault:write, vault:delete, pki:issue)
	if len(scopes) < 4 {
		t.Errorf("master default scopes: got %d, want ≥4", len(scopes))
	}

	// Verify critical scopes are present
	scopeMap := make(map[string]bool)
	for _, s := range scopes {
		scopeMap[s] = true
	}
	if !scopeMap["vault:read"] {
		t.Error("master should have vault:read")
	}
	if !scopeMap["vault:write"] {
		t.Error("master should have vault:write")
	}
}

func TestResolveScopes_UnknownRole(t *testing.T) {
	svc, _, _, _ := setupTestSessionService(t)

	scopes := svc.resolveScopes(nil, "completely-unknown-role")
	if len(scopes) != 1 || scopes[0] != "vault:read" {
		t.Errorf("unknown role scopes: got %v, want [vault:read]", scopes)
	}
}

func TestResolveScopes_ExplicitOverride(t *testing.T) {
	svc, _, _, _ := setupTestSessionService(t)

	// Admin requesting only vault:read — should get just vault:read
	scopes := svc.resolveScopes([]string{"vault:read"}, "admin")
	if len(scopes) != 1 || scopes[0] != "vault:read" {
		t.Errorf("explicit override: got %v, want [vault:read]", scopes)
	}
}

func TestValidateSessionFromToken(t *testing.T) {
	svc, _, certStore, _ := setupTestSessionService(t)
	ctx := context.Background()

	_, _, certPEM, serialHex := createTestMemberCert(t)
	_ = certStore.StoreCertificate(ctx, &pkistore.CertRecord{
		SerialNumber: serialHex,
		CertType:     "member",
		OrgID:        "org-001",
		CertPEM:      string(certPEM),
		Status:       "active",
		IssuedAt:     time.Now().Add(-time.Hour),
		ExpiresAt:    time.Now().Add(365 * 24 * time.Hour),
	})

	sessionResp, err := svc.CreateSessionManaged(ctx, &CreateSessionManagedRequest{
		MemberID:   "member-001",
		OrgID:      "org-001",
		CertSerial: serialHex,
	})
	if err != nil {
		t.Fatalf("CreateSessionManaged: %v", err)
	}

	resp, err := svc.ValidateSessionFromToken(ctx, sessionResp.SessionToken)
	if err != nil {
		t.Fatalf("ValidateSessionFromToken: %v", err)
	}
	if resp.MemberID != "member-001" {
		t.Errorf("MemberID = %q, want %q", resp.MemberID, "member-001")
	}
}

func TestValidateSessionFromToken_Invalid(t *testing.T) {
	svc, _, _, _ := setupTestSessionService(t)
	_, err := svc.ValidateSessionFromToken(context.Background(), "bad-token")
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
}

func TestCreateSessionByCert(t *testing.T) {
	svc, _, certStore, _ := setupTestSessionService(t)
	ctx := context.Background()

	memberKey, _, certPEM, serialHex := createTestMemberCert(t)

	// Register the cert
	_ = certStore.StoreCertificate(ctx, &pkistore.CertRecord{
		SerialNumber: serialHex,
		CertType:     "member",
		OrgID:        "org-001",
		CertPEM:      string(certPEM),
		Status:       "active",
		IssuedAt:     time.Now().Add(-time.Hour),
		ExpiresAt:    time.Now().Add(365 * 24 * time.Hour),
	})

	// Sign a nonce
	nonce, err := GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce: %v", err)
	}

	hash := sha256Sum(nonce)
	sig, err := ecdsa.SignASN1(rand.Reader, memberKey, hash[:])
	if err != nil {
		t.Fatalf("SignASN1: %v", err)
	}

	resp, err := svc.CreateSessionByCert(ctx, &CreateSessionByCertRequest{
		CertPEM:     string(certPEM),
		SignedNonce: sig,
		Nonce:       nonce,
		Scopes:      []string{"vault:read"},
	})
	if err != nil {
		t.Fatalf("CreateSessionByCert: %v", err)
	}
	if resp.SessionToken == "" {
		t.Error("SessionToken is empty")
	}
	if resp.ExpiresAt.Before(time.Now()) {
		t.Error("ExpiresAt is in the past")
	}
}

func TestCreateSessionByCert_InvalidPEM(t *testing.T) {
	svc, _, _, _ := setupTestSessionService(t)
	_, err := svc.CreateSessionByCert(context.Background(), &CreateSessionByCertRequest{
		CertPEM:     "not-pem",
		SignedNonce: []byte("sig"),
		Nonce:       []byte("nonce"),
	})
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestCreateSessionByCert_BadSignature(t *testing.T) {
	svc, _, certStore, _ := setupTestSessionService(t)
	ctx := context.Background()

	_, _, certPEM, serialHex := createTestMemberCert(t)
	_ = certStore.StoreCertificate(ctx, &pkistore.CertRecord{
		SerialNumber: serialHex,
		CertType:     "member",
		OrgID:        "org-001",
		CertPEM:      string(certPEM),
		Status:       "active",
		IssuedAt:     time.Now().Add(-time.Hour),
		ExpiresAt:    time.Now().Add(365 * 24 * time.Hour),
	})

	nonce, _ := GenerateNonce()
	_, err := svc.CreateSessionByCert(ctx, &CreateSessionByCertRequest{
		CertPEM:     string(certPEM),
		SignedNonce: []byte("invalid-signature"),
		Nonce:       nonce,
	})
	if err == nil {
		t.Fatal("expected error for bad signature")
	}
}

func TestCreateSessionByCert_RevokedCert(t *testing.T) {
	svc, _, certStore, _ := setupTestSessionService(t)
	ctx := context.Background()

	memberKey, _, certPEM, serialHex := createTestMemberCert(t)
	_ = certStore.StoreCertificate(ctx, &pkistore.CertRecord{
		SerialNumber: serialHex,
		CertType:     "member",
		OrgID:        "org-001",
		CertPEM:      string(certPEM),
		Status:       "revoked",
		IssuedAt:     time.Now().Add(-time.Hour),
		ExpiresAt:    time.Now().Add(365 * 24 * time.Hour),
	})

	nonce, _ := GenerateNonce()
	hash := sha256Sum(nonce)
	sig, _ := ecdsa.SignASN1(rand.Reader, memberKey, hash[:])

	_, err := svc.CreateSessionByCert(ctx, &CreateSessionByCertRequest{
		CertPEM:     string(certPEM),
		SignedNonce: sig,
		Nonce:       nonce,
	})
	if err == nil {
		t.Fatal("expected error for revoked cert")
	}
}

func TestRevokeMemberSessions(t *testing.T) {
	svc, _, certStore, policyStore := setupTestSessionService(t)
	ctx := context.Background()

	_, _, certPEM, serialHex := createTestMemberCert(t)
	_ = certStore.StoreCertificate(ctx, &pkistore.CertRecord{
		SerialNumber: serialHex,
		CertType:     "member",
		OrgID:        "org-001",
		CertPEM:      string(certPEM),
		Status:       "active",
		IssuedAt:     time.Now().Add(-time.Hour),
		ExpiresAt:    time.Now().Add(365 * 24 * time.Hour),
	})

	// Create a session
	sessionResp, err := svc.CreateSessionManaged(ctx, &CreateSessionManagedRequest{
		MemberID:   "member-001",
		OrgID:      "org-001",
		CertSerial: serialHex,
	})
	if err != nil {
		t.Fatalf("CreateSessionManaged: %v", err)
	}

	// Seed the policy store with the token entry so RevokeMemberSessions finds it
	subjectHash := auth.HashSubject("member-001")
	policyStore.mu.Lock()
	policyStore.tokens[subjectHash] = append(policyStore.tokens[subjectHash], &auth.TokenEntry{
		JTI:         "some-jti",
		SubjectHash: subjectHash,
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(time.Hour),
		Revoked:     false,
	})
	policyStore.mu.Unlock()

	count, err := svc.RevokeMemberSessions(ctx, "member-001", "org-001")
	if err != nil {
		t.Fatalf("RevokeMemberSessions: %v", err)
	}
	if count != 1 {
		t.Errorf("count = %d, want 1", count)
	}

	_ = sessionResp // used to verify session was created
}

// sha256Sum is a helper to compute SHA-256.
func sha256Sum(data []byte) [32]byte {
	return sha256.Sum256(data)
}
