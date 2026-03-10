package grpc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	pb "github.com/envsync/minikms/api/proto/minikms/v1"
	"github.com/envsync/minikms/internal/service"
	"github.com/envsync/minikms/internal/testutil"
	"google.golang.org/grpc/metadata"
)

// --- extractSessionToken tests ---

func TestExtractSessionToken_BearerPrefix(t *testing.T) {
	md := metadata.New(map[string]string{
		"authorization": "Bearer my-session-token-123",
	})
	ctx := metadata.NewIncomingContext(context.Background(), md)

	token, err := extractSessionToken(ctx)
	if err != nil {
		t.Fatalf("extractSessionToken: %v", err)
	}
	if token != "my-session-token-123" {
		t.Errorf("token = %q, want %q", token, "my-session-token-123")
	}
}

func TestExtractSessionToken_NoBearerPrefix(t *testing.T) {
	md := metadata.New(map[string]string{
		"authorization": "raw-token",
	})
	ctx := metadata.NewIncomingContext(context.Background(), md)

	token, err := extractSessionToken(ctx)
	if err != nil {
		t.Fatalf("extractSessionToken: %v", err)
	}
	if token != "raw-token" {
		t.Errorf("token = %q, want %q", token, "raw-token")
	}
}

func TestExtractSessionToken_ShortToken(t *testing.T) {
	md := metadata.New(map[string]string{
		"authorization": "short",
	})
	ctx := metadata.NewIncomingContext(context.Background(), md)

	token, err := extractSessionToken(ctx)
	if err != nil {
		t.Fatalf("extractSessionToken: %v", err)
	}
	// Token shorter than 7 chars should be returned as-is (no Bearer prefix)
	if token != "short" {
		t.Errorf("token = %q, want %q", token, "short")
	}
}

func TestExtractSessionToken_MissingMetadata(t *testing.T) {
	_, err := extractSessionToken(context.Background())
	if err == nil {
		t.Fatal("expected error for missing metadata")
	}
}

func TestExtractSessionToken_MissingAuth(t *testing.T) {
	md := metadata.New(map[string]string{
		"other-header": "value",
	})
	ctx := metadata.NewIncomingContext(context.Background(), md)

	_, err := extractSessionToken(ctx)
	if err == nil {
		t.Fatal("expected error for missing authorization header")
	}
}

// --- Constructor tests ---

func TestNewKMSAdapter(t *testing.T) {
	a := NewKMSAdapter(nil, nil)
	if a == nil {
		t.Fatal("NewKMSAdapter returned nil")
	}
}

func TestNewAuditAdapter(t *testing.T) {
	a := NewAuditAdapter(nil)
	if a == nil {
		t.Fatal("NewAuditAdapter returned nil")
	}
}

func TestNewPKIAdapter(t *testing.T) {
	a := NewPKIAdapter(nil)
	if a == nil {
		t.Fatal("NewPKIAdapter returned nil")
	}
	if a.orgCAs == nil {
		t.Fatal("orgCAs map not initialized")
	}
}

func TestNewSessionAdapter(t *testing.T) {
	a := NewSessionAdapter(nil)
	if a == nil {
		t.Fatal("NewSessionAdapter returned nil")
	}
}

func TestNewVaultAdapter(t *testing.T) {
	a := NewVaultAdapter(nil)
	if a == nil {
		t.Fatal("NewVaultAdapter returned nil")
	}
}

// --- KMS Adapter integration tests ---

func setupKMSAdapter(t *testing.T) *KMSAdapter {
	t.Helper()
	_, _, dekMgr, _, auditLogger, _, err := testutil.SetupTestKMSStack(testutil.TestRootKeyHex)
	if err != nil {
		t.Fatalf("SetupTestKMSStack: %v", err)
	}
	kmsSvc := service.NewKMSService(dekMgr, auditLogger)
	keySvc := service.NewKeyService(dekMgr, nil, auditLogger)
	return NewKMSAdapter(kmsSvc, keySvc)
}

func TestKMSAdapter_EncryptDecrypt(t *testing.T) {
	adapter := setupKMSAdapter(t)
	ctx := context.Background()

	// Encrypt
	encResp, err := adapter.Encrypt(ctx, &pb.EncryptRequest{
		TenantId:  "org-1",
		ScopeId:   "app-1",
		Plaintext: []byte("hello world"),
		Aad:       "test-aad",
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if encResp.Ciphertext == "" {
		t.Error("ciphertext is empty")
	}
	if encResp.KeyVersionId == "" {
		t.Error("key version ID is empty")
	}

	// Decrypt
	decResp, err := adapter.Decrypt(ctx, &pb.DecryptRequest{
		TenantId:   "org-1",
		ScopeId:    "app-1",
		Ciphertext: encResp.Ciphertext,
		Aad:        "test-aad",
	})
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(decResp.Plaintext) != "hello world" {
		t.Errorf("plaintext = %q, want %q", string(decResp.Plaintext), "hello world")
	}
}

func TestKMSAdapter_BatchEncryptDecrypt(t *testing.T) {
	adapter := setupKMSAdapter(t)
	ctx := context.Background()

	// Batch encrypt
	batchEncResp, err := adapter.BatchEncrypt(ctx, &pb.BatchEncryptRequest{
		TenantId: "org-1",
		ScopeId:  "app-1",
		Items: []*pb.BatchEncryptItem{
			{Plaintext: []byte("secret1"), Aad: "aad1"},
			{Plaintext: []byte("secret2"), Aad: "aad2"},
		},
	})
	if err != nil {
		t.Fatalf("BatchEncrypt: %v", err)
	}
	if len(batchEncResp.Items) != 2 {
		t.Fatalf("BatchEncrypt returned %d items, want 2", len(batchEncResp.Items))
	}

	// Batch decrypt
	batchDecResp, err := adapter.BatchDecrypt(ctx, &pb.BatchDecryptRequest{
		TenantId: "org-1",
		ScopeId:  "app-1",
		Items: []*pb.BatchDecryptItem{
			{Ciphertext: batchEncResp.Items[0].Ciphertext, Aad: "aad1"},
			{Ciphertext: batchEncResp.Items[1].Ciphertext, Aad: "aad2"},
		},
	})
	if err != nil {
		t.Fatalf("BatchDecrypt: %v", err)
	}
	if len(batchDecResp.Items) != 2 {
		t.Fatalf("BatchDecrypt returned %d items, want 2", len(batchDecResp.Items))
	}
	if string(batchDecResp.Items[0].Plaintext) != "secret1" {
		t.Errorf("item[0] plaintext = %q, want %q", string(batchDecResp.Items[0].Plaintext), "secret1")
	}
	if string(batchDecResp.Items[1].Plaintext) != "secret2" {
		t.Errorf("item[1] plaintext = %q, want %q", string(batchDecResp.Items[1].Plaintext), "secret2")
	}
}

func TestKMSAdapter_CreateDataKey(t *testing.T) {
	adapter := setupKMSAdapter(t)
	ctx := context.Background()

	resp, err := adapter.CreateDataKey(ctx, &pb.CreateDataKeyRequest{
		TenantId: "org-dk",
		ScopeId:  "app-dk",
	})
	if err != nil {
		t.Fatalf("CreateDataKey: %v", err)
	}
	if resp.KeyVersionId == "" {
		t.Error("KeyVersionId is empty")
	}
}

func TestKMSAdapter_ReEncrypt_Unimplemented(t *testing.T) {
	adapter := setupKMSAdapter(t)
	_, err := adapter.ReEncrypt(context.Background(), &pb.ReEncryptRequest{})
	if err == nil {
		t.Fatal("expected unimplemented error")
	}
}

// --- Audit Adapter integration tests ---

func setupAuditAdapter(t *testing.T) *AuditAdapter {
	t.Helper()
	_, _, _, _, auditLogger, auditStore, err := testutil.SetupTestKMSStack(testutil.TestRootKeyHex)
	if err != nil {
		t.Fatalf("SetupTestKMSStack: %v", err)
	}
	auditSvc := service.NewAuditService(auditLogger, auditStore)
	return NewAuditAdapter(auditSvc)
}

func TestAuditAdapter_GetAuditLogs(t *testing.T) {
	adapter := setupAuditAdapter(t)
	ctx := context.Background()

	resp, err := adapter.GetAuditLogs(ctx, &pb.GetAuditLogsRequest{
		OrgId:  "org-1",
		Limit:  10,
		Offset: 0,
	})
	if err != nil {
		t.Fatalf("GetAuditLogs: %v", err)
	}
	if resp == nil {
		t.Fatal("response is nil")
	}
}

func TestAuditAdapter_VerifyChain(t *testing.T) {
	adapter := setupAuditAdapter(t)
	ctx := context.Background()

	resp, err := adapter.VerifyChain(ctx, &pb.VerifyChainRequest{
		OrgId: "org-1",
	})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !resp.Valid {
		t.Error("chain should be valid for empty org")
	}
}

// --- PKI Adapter integration tests ---

func setupPKIAdapter(t *testing.T) *PKIAdapter {
	t.Helper()
	_, _, _, _, auditLogger, _, err := testutil.SetupTestKMSStack(testutil.TestRootKeyHex)
	if err != nil {
		t.Fatalf("SetupTestKMSStack: %v", err)
	}

	certStore := testutil.NewMockPKICertStore()

	// Generate root CA
	rootCert, rootKey, err := generateTestRootCA()
	if err != nil {
		t.Fatalf("generateTestRootCA: %v", err)
	}

	pkiSvc := service.NewPKIService(rootCert, rootKey, auditLogger, certStore)
	return NewPKIAdapter(pkiSvc)
}

func generateTestRootCA() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

func TestPKIAdapter_CreateOrgCA(t *testing.T) {
	adapter := setupPKIAdapter(t)
	ctx := context.Background()

	resp, err := adapter.CreateOrgCA(ctx, &pb.CreateOrgCARequest{
		OrgId:   "org-pki-1",
		OrgName: "Test Org",
	})
	if err != nil {
		t.Fatalf("CreateOrgCA: %v", err)
	}
	if resp.CertPem == "" {
		t.Error("CertPem is empty")
	}
	if resp.SerialHex == "" {
		t.Error("SerialHex is empty")
	}
}

func TestPKIAdapter_IssueMemberCert(t *testing.T) {
	adapter := setupPKIAdapter(t)
	ctx := context.Background()

	// First create org CA
	_, err := adapter.CreateOrgCA(ctx, &pb.CreateOrgCARequest{
		OrgId:   "org-pki-2",
		OrgName: "Test Org 2",
	})
	if err != nil {
		t.Fatalf("CreateOrgCA: %v", err)
	}

	// Then issue member cert
	resp, err := adapter.IssueMemberCert(ctx, &pb.IssueMemberCertRequest{
		MemberId:    "member-1",
		MemberEmail: "alice@example.com",
		OrgId:       "org-pki-2",
		Role:        "admin",
	})
	if err != nil {
		t.Fatalf("IssueMemberCert: %v", err)
	}
	if resp.CertPem == "" {
		t.Error("CertPem is empty")
	}
	if resp.SerialHex == "" {
		t.Error("SerialHex is empty")
	}
}

func TestPKIAdapter_IssueMemberCert_NoOrgCA(t *testing.T) {
	adapter := setupPKIAdapter(t)
	_, err := adapter.IssueMemberCert(context.Background(), &pb.IssueMemberCertRequest{
		MemberId:    "member-1",
		MemberEmail: "alice@example.com",
		OrgId:       "org-nonexistent",
		Role:        "admin",
	})
	if err == nil {
		t.Fatal("expected error for missing org CA")
	}
}

func TestPKIAdapter_GetRootCA(t *testing.T) {
	adapter := setupPKIAdapter(t)
	resp, err := adapter.GetRootCA(context.Background(), &pb.GetRootCARequest{})
	if err != nil {
		t.Fatalf("GetRootCA: %v", err)
	}
	if resp.CertPem == "" {
		t.Error("CertPem is empty")
	}
}

func TestPKIAdapter_RevokeCert(t *testing.T) {
	adapter := setupPKIAdapter(t)
	ctx := context.Background()

	// Create org CA and member cert
	_, _ = adapter.CreateOrgCA(ctx, &pb.CreateOrgCARequest{OrgId: "org-rev", OrgName: "Rev Org"})
	memberResp, _ := adapter.IssueMemberCert(ctx, &pb.IssueMemberCertRequest{
		MemberId: "mem-rev", MemberEmail: "r@x.com", OrgId: "org-rev", Role: "member",
	})

	resp, err := adapter.RevokeCert(ctx, &pb.RevokeCertRequest{
		SerialHex: memberResp.SerialHex,
		OrgId:     "org-rev",
		Reason:    1,
	})
	if err != nil {
		t.Fatalf("RevokeCert: %v", err)
	}
	if !resp.Success {
		t.Error("expected success")
	}
}

func TestPKIAdapter_GetCRL(t *testing.T) {
	adapter := setupPKIAdapter(t)
	ctx := context.Background()

	_, _ = adapter.CreateOrgCA(ctx, &pb.CreateOrgCARequest{OrgId: "org-crl", OrgName: "CRL Org"})

	resp, err := adapter.GetCRL(ctx, &pb.GetCRLRequest{OrgId: "org-crl"})
	if err != nil {
		t.Fatalf("GetCRL: %v", err)
	}
	if len(resp.CrlDer) == 0 {
		t.Error("CRL DER is empty")
	}
}

func TestPKIAdapter_GetCRL_NoOrgCA(t *testing.T) {
	adapter := setupPKIAdapter(t)
	_, err := adapter.GetCRL(context.Background(), &pb.GetCRLRequest{OrgId: "nonexistent"})
	if err == nil {
		t.Fatal("expected error for missing org CA")
	}
}

func TestPKIAdapter_CheckOCSP(t *testing.T) {
	adapter := setupPKIAdapter(t)
	ctx := context.Background()

	_, _ = adapter.CreateOrgCA(ctx, &pb.CreateOrgCARequest{OrgId: "org-ocsp", OrgName: "OCSP Org"})
	memberResp, _ := adapter.IssueMemberCert(ctx, &pb.IssueMemberCertRequest{
		MemberId: "mem-ocsp", MemberEmail: "o@x.com", OrgId: "org-ocsp", Role: "member",
	})

	resp, err := adapter.CheckOCSP(ctx, &pb.CheckOCSPRequest{
		SerialHex: memberResp.SerialHex,
		OrgId:     "org-ocsp",
	})
	if err != nil {
		t.Fatalf("CheckOCSP: %v", err)
	}
	if resp.Status != 0 {
		t.Errorf("expected status 0 (good), got %d", resp.Status)
	}
}

// --- Session Adapter integration tests ---

func setupSessionAdapter(t *testing.T) (*SessionAdapter, *testutil.MockPKICertStore) {
	t.Helper()
	_, _, _, _, auditLogger, _, err := testutil.SetupTestKMSStack(testutil.TestRootKeyHex)
	if err != nil {
		t.Fatalf("SetupTestKMSStack: %v", err)
	}

	signingKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	registry := testutil.NewMockTokenRegistry()
	certStore := testutil.NewMockPKICertStore()
	policyStore := testutil.NewMockPolicyStore()

	sessionSvc := service.NewSessionService(signingKey, "test-issuer", time.Hour, registry, certStore, policyStore, auditLogger)
	return NewSessionAdapter(sessionSvc), certStore
}

func TestSessionAdapter_ValidateSession_Invalid(t *testing.T) {
	adapter, _ := setupSessionAdapter(t)

	resp, err := adapter.ValidateSession(context.Background(), &pb.ValidateSessionRequest{
		SessionToken: "invalid-token",
	})
	if err != nil {
		t.Fatalf("ValidateSession: %v", err)
	}
	if resp.Valid {
		t.Error("should be invalid")
	}
}

func TestSessionAdapter_RevokeSession_Invalid(t *testing.T) {
	adapter, _ := setupSessionAdapter(t)
	_, err := adapter.RevokeSession(context.Background(), &pb.RevokeSessionRequest{
		SessionToken: "invalid-token",
	})
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
}

func TestSessionAdapter_ListSessions(t *testing.T) {
	adapter, _ := setupSessionAdapter(t)

	resp, err := adapter.ListSessions(context.Background(), &pb.ListSessionsRequest{
		MemberId: "member-1",
		OrgId:    "org-1",
	})
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if resp == nil {
		t.Fatal("response is nil")
	}
}

func TestSessionAdapter_CreateSession_NoAuth(t *testing.T) {
	adapter, _ := setupSessionAdapter(t)
	_, err := adapter.CreateSession(context.Background(), &pb.CreateSessionRequest{})
	if err == nil {
		t.Fatal("expected error for missing auth")
	}
}
