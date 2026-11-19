package grpc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	pb "github.com/envsync-cloud/minikms/api/proto/minikms/v1"
	"github.com/envsync-cloud/minikms/internal/audit"
	"github.com/envsync-cloud/minikms/internal/authn"
	"github.com/envsync-cloud/minikms/internal/keys"
	"github.com/envsync-cloud/minikms/internal/service"
	"github.com/envsync-cloud/minikms/internal/store"
	"github.com/envsync-cloud/minikms/internal/testutil"
	ggrpc "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
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
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %v, want %v", status.Code(err), codes.Unauthenticated)
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

func kmsPrincipalCtx(tenantID string) context.Context {
	return authn.WithPrincipal(context.Background(), authn.Principal{
		TenantID: tenantID,
		ActorID:  "session-" + tenantID,
	})
}

func pkiPrincipal(orgID, role string) context.Context {
	return authn.WithPrincipal(context.Background(), authn.Principal{
		TenantID: orgID,
		ActorID:  "actor-" + orgID,
		Role:     role,
	})
}

func TestKMSAdapter_EncryptDecrypt(t *testing.T) {
	adapter := setupKMSAdapter(t)
	ctx := kmsPrincipalCtx("org-1")

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
		TenantId:     "org-1",
		ScopeId:      "app-1",
		Ciphertext:   encResp.Ciphertext,
		Aad:          "test-aad",
		KeyVersionId: encResp.KeyVersionId,
	})
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(decResp.Plaintext) != "hello world" {
		t.Errorf("plaintext = %q, want %q", string(decResp.Plaintext), "hello world")
	}
}

func TestKMSAdapter_ErrorCodes(t *testing.T) {
	adapter := setupKMSAdapter(t)

	tests := []struct {
		name     string
		ctx      context.Context
		request  *pb.DecryptRequest
		wantCode codes.Code
	}{
		{
			name: "validation",
			ctx:  context.Background(),
			request: &pb.DecryptRequest{
				ScopeId: "app-1", Ciphertext: "not-base64", KeyVersionId: "key-1",
			},
			wantCode: codes.InvalidArgument,
		},
		{
			name: "missing principal",
			ctx:  context.Background(),
			request: &pb.DecryptRequest{
				TenantId: "org-1", ScopeId: "app-1", Ciphertext: "AA==", KeyVersionId: "key-1",
			},
			wantCode: codes.Unauthenticated,
		},
		{
			name: "tenant mismatch",
			ctx:  kmsPrincipalCtx("org-a"),
			request: &pb.DecryptRequest{
				TenantId: "org-b", ScopeId: "app-1", Ciphertext: "AA==", KeyVersionId: "key-1",
			},
			wantCode: codes.PermissionDenied,
		},
		{
			name: "missing key version resource",
			ctx:  kmsPrincipalCtx("org-1"),
			request: &pb.DecryptRequest{
				TenantId: "org-1", ScopeId: "app-1", Ciphertext: "AA==", KeyVersionId: "missing",
			},
			wantCode: codes.NotFound,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := adapter.Decrypt(test.ctx, test.request)
			if status.Code(err) != test.wantCode {
				t.Fatalf("code = %v, want %v (error: %v)", status.Code(err), test.wantCode, err)
			}
		})
	}
}

func TestKMSAdapter_BatchEncryptDecrypt(t *testing.T) {
	adapter := setupKMSAdapter(t)
	ctx := kmsPrincipalCtx("org-1")

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
			{Ciphertext: batchEncResp.Items[0].Ciphertext, Aad: "aad1", KeyVersionId: batchEncResp.Items[0].KeyVersionId},
			{Ciphertext: batchEncResp.Items[1].Ciphertext, Aad: "aad2", KeyVersionId: batchEncResp.Items[1].KeyVersionId},
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
	ctx := kmsPrincipalCtx("org-dk")

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
	ctx := authn.WithPrincipal(context.Background(), authn.Principal{
		TenantID: "org-1",
		ActorID:  "actor-org-1",
	})

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
	adapter, _ := setupPKIAdapterWithStore(t)
	return adapter
}

func setupPKIAdapterWithStore(t *testing.T) (*PKIAdapter, *testutil.MockPKICertStore) {
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
	holder := keys.NewRootKeyHolder()
	if err := holder.Load(testutil.TestRootKeyHex); err != nil {
		t.Fatalf("load test root key: %v", err)
	}
	pkiSvc.SetOrgKeyManager(keys.NewOrgKeyManager(holder))
	return NewPKIAdapter(pkiSvc), certStore
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

func TestPKIAdapter_CreateOrgCACSR_ShortOrgID(t *testing.T) {
	adapter := setupPKIAdapter(t)
	ctx := context.Background()

	for _, orgID := range []string{"a", "1234567"} {
		t.Run(orgID, func(t *testing.T) {
			resp, err := adapter.CreateOrgCACSR(ctx, &pb.CreateOrgCACSRRequest{
				OrgId:   orgID,
				OrgName: "Short Org",
			})
			if resp != nil {
				t.Fatalf("response = %+v, want nil", resp)
			}
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("CreateOrgCACSR(%q) code = %v, want InvalidArgument (err=%v)", orgID, status.Code(err), err)
			}
		})
	}
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
	adapter, store := setupPKIAdapterWithStore(t)
	ctx := pkiPrincipal("org-pki-2", "member")

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
	if resp.KeyPem != "" {
		t.Fatal("managed issuance returned KeyPem")
	}
	rec, err := store.GetCertificateBySerialWithKey(ctx, resp.SerialHex)
	if err != nil || rec == nil || len(rec.EncryptedPrivateKey) == 0 {
		t.Fatal("managed member private key was not stored")
	}
}

func TestPKIAdapter_IssueMemberCertAcrossReplicas(t *testing.T) {
	ctx := context.Background()
	certStore := testutil.NewMockPKICertStore()
	rootCert, rootKey, err := generateTestRootCA()
	if err != nil {
		t.Fatalf("generateTestRootCA: %v", err)
	}

	newReplica := func() *PKIAdapter {
		auditLogger := audit.NewAuditLogger(testutil.NewMockAuditStore())
		svc := service.NewPKIService(rootCert, rootKey, auditLogger, certStore)
		holder := keys.NewRootKeyHolder()
		if err := holder.Load(testutil.TestRootKeyHex); err != nil {
			t.Fatalf("load test root key: %v", err)
		}
		svc.SetOrgKeyManager(keys.NewOrgKeyManager(holder))
		return NewPKIAdapter(svc)
	}

	first := newReplica()
	second := newReplica()
	ctx = pkiPrincipal("org-ha-adapter", "admin")
	if _, err := first.CreateOrgCA(ctx, &pb.CreateOrgCARequest{
		OrgId: "org-ha-adapter", OrgName: "HA Adapter Org",
	}); err != nil {
		t.Fatalf("CreateOrgCA on first replica: %v", err)
	}

	resp, err := second.IssueMemberCert(ctx, &pb.IssueMemberCertRequest{
		MemberId: "member-ha", MemberEmail: "ha@example.com",
		OrgId: "org-ha-adapter", Role: "admin",
	})
	if err != nil {
		t.Fatalf("IssueMemberCert on second replica: %v", err)
	}
	if resp.SerialHex == "" || resp.CertPem == "" {
		t.Fatal("second replica did not issue a member certificate")
	}
	if resp.KeyPem != "" {
		t.Fatal("managed issuance returned KeyPem")
	}
}

func TestPKIAdapter_IssueMemberCert_NoOrgCA(t *testing.T) {
	adapter := setupPKIAdapter(t)
	_, err := adapter.IssueMemberCert(pkiPrincipal("org-nonexistent", "admin"), &pb.IssueMemberCertRequest{
		MemberId:    "member-1",
		MemberEmail: "alice@example.com",
		OrgId:       "org-nonexistent",
		Role:        "admin",
	})
	if err == nil {
		t.Fatal("expected error for missing org CA")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("code = %v, want %v", status.Code(err), codes.FailedPrecondition)
	}
}

func TestPKIAdapter_IssueLeafCert(t *testing.T) {
	adapter := setupPKIAdapter(t)
	ctx := context.Background()

	_, err := adapter.CreateOrgCA(ctx, &pb.CreateOrgCARequest{
		OrgId:   "org-leaf-1",
		OrgName: "Leaf Org",
	})
	if err != nil {
		t.Fatalf("CreateOrgCA: %v", err)
	}

	resp, err := adapter.IssueLeafCert(ctx, &pb.IssueLeafCertRequest{
		OrgId:        "org-leaf-1",
		CommonName:   "api.internal",
		DnsSans:      []string{"api.internal", "127.0.0.1"},
		TtlDays:      90,
		KeyAlgorithm: "ECDSA_P256",
	})
	if err != nil {
		t.Fatalf("IssueLeafCert: %v", err)
	}
	if resp.CertPem == "" || resp.KeyPem == "" || resp.SerialHex == "" {
		t.Fatal("leaf cert response is incomplete")
	}
}

func TestPKIAdapter_SignCSR(t *testing.T) {
	adapter := setupPKIAdapter(t)
	ctx := context.Background()

	_, err := adapter.CreateOrgCA(ctx, &pb.CreateOrgCARequest{
		OrgId:   "org-csr-1",
		OrgName: "CSR Org",
	})
	if err != nil {
		t.Fatalf("CreateOrgCA: %v", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "svc.internal"},
		DNSNames: []string{"svc.internal"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	resp, err := adapter.SignCSR(ctx, &pb.SignCSRRequest{
		OrgId:   "org-csr-1",
		CsrPem:  string(csrPEM),
		TtlDays: 30,
	})
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	if resp.CertPem == "" || resp.SerialHex == "" {
		t.Fatal("CSR sign response is incomplete")
	}
}

func TestPKIAdapter_IssueLeafCert_NoOrgCA(t *testing.T) {
	adapter := setupPKIAdapter(t)
	_, err := adapter.IssueLeafCert(context.Background(), &pb.IssueLeafCertRequest{
		OrgId:      "org-missing",
		CommonName: "api.internal",
	})
	if err == nil {
		t.Fatal("expected error for missing org CA")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("code = %v, want %v", status.Code(err), codes.FailedPrecondition)
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
	ctx := pkiPrincipal("org-rev", "admin")

	// Create org CA and member cert
	_, _ = adapter.CreateOrgCA(ctx, &pb.CreateOrgCARequest{OrgId: "org-rev", OrgName: "Rev Org"})
	memberResp, err := adapter.IssueMemberCert(ctx, &pb.IssueMemberCertRequest{
		MemberId: "mem-rev", MemberEmail: "r@x.com", OrgId: "org-rev", Role: "member",
	})
	if err != nil {
		t.Fatalf("IssueMemberCert: %v", err)
	}

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
	ctx := pkiPrincipal("org-ocsp", "admin")

	_, _ = adapter.CreateOrgCA(ctx, &pb.CreateOrgCARequest{OrgId: "org-ocsp", OrgName: "OCSP Org"})
	memberResp, err := adapter.IssueMemberCert(ctx, &pb.IssueMemberCertRequest{
		MemberId: "mem-ocsp", MemberEmail: "o@x.com", OrgId: "org-ocsp", Role: "member",
	})
	if err != nil {
		t.Fatalf("IssueMemberCert: %v", err)
	}

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

func TestPKIAdapter_IssueMemberCert_Unauthenticated(t *testing.T) {
	adapter := setupPKIAdapter(t)
	ctx := context.Background()
	if _, err := adapter.CreateOrgCA(ctx, &pb.CreateOrgCARequest{OrgId: "org-unauth-issue", OrgName: "Unauth Org"}); err != nil {
		t.Fatalf("CreateOrgCA: %v", err)
	}
	resp, err := adapter.IssueMemberCert(ctx, &pb.IssueMemberCertRequest{
		MemberId: "member-1", MemberEmail: "alice@example.com", OrgId: "org-unauth-issue", Role: "master",
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %v, want Unauthenticated (err=%v)", status.Code(err), err)
	}
	if resp != nil && (resp.KeyPem != "" || resp.CertPem != "") {
		t.Fatal("unauthenticated IssueMemberCert returned certificate material")
	}
}

func TestPKIAdapter_RevokeAndInstallRequireAdmin(t *testing.T) {
	adapter := setupPKIAdapter(t)
	member := pkiPrincipal("org-admin-gate", "member")
	if _, err := adapter.RevokeCert(context.Background(), &pb.RevokeCertRequest{OrgId: "org-admin-gate", SerialHex: "aa"}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("unauthenticated RevokeCert code = %v, want Unauthenticated", status.Code(err))
	}
	if _, err := adapter.InstallOrgCA(context.Background(), &pb.InstallOrgCARequest{OrgId: "org-admin-gate", CertPem: "x"}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("unauthenticated InstallOrgCA code = %v, want Unauthenticated", status.Code(err))
	}
	if _, err := adapter.RevokeCert(member, &pb.RevokeCertRequest{OrgId: "org-admin-gate", SerialHex: "aa"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("member RevokeCert code = %v, want PermissionDenied", status.Code(err))
	}
	if _, err := adapter.InstallOrgCA(member, &pb.InstallOrgCARequest{OrgId: "org-admin-gate", CertPem: "x"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("member InstallOrgCA code = %v, want PermissionDenied", status.Code(err))
	}
	otherAdmin := pkiPrincipal("org-other", "admin")
	if _, err := adapter.RevokeCert(otherAdmin, &pb.RevokeCertRequest{OrgId: "org-admin-gate", SerialHex: "aa"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("cross-tenant RevokeCert code = %v, want PermissionDenied", status.Code(err))
	}
	if _, err := adapter.IssueMemberCert(otherAdmin, &pb.IssueMemberCertRequest{
		MemberId: "m", MemberEmail: "a@b.c", OrgId: "org-admin-gate", Role: "member",
	}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("cross-tenant IssueMemberCert code = %v, want PermissionDenied", status.Code(err))
	}
}

func TestPKIAdapter_InstallOrgCA_RejectsUnrootedChain(t *testing.T) {
	adapter := setupPKIAdapter(t)
	ctx := pkiPrincipal("org-install-01", "admin")
	csrResp, err := adapter.CreateOrgCACSR(context.Background(), &pb.CreateOrgCACSRRequest{
		OrgId: "org-install-01", OrgName: "Install Org",
	})
	if err != nil {
		t.Fatalf("CreateOrgCACSR: %v", err)
	}
	foreignCert, foreignKey, err := generateTestRootCA()
	if err != nil {
		t.Fatal(err)
	}
	certPEM := signCSRAsCA(t, csrResp.CsrPem, foreignCert, foreignKey)
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: foreignCert.Raw})
	_, err = adapter.InstallOrgCA(ctx, &pb.InstallOrgCARequest{
		OrgId: "org-install-01", CertPem: certPEM, ChainPem: string(chain),
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument (err=%v)", status.Code(err), err)
	}
	if err == nil || !strings.Contains(err.Error(), "platform root") {
		t.Fatalf("error = %v, want platform root rejection", err)
	}
}

func TestCreateOrgCABootstrapSessionOnce(t *testing.T) {
	adapter, store := setupPKIAdapterWithStore(t)
	issuer := &fakeBootstrapIssuer{token: "dev-bootstrap-token"}
	adapter.SetBootstrapSessionIssuer(issuer)

	lis := bufconn.Listen(1024 * 1024)
	srv := ggrpc.NewServer()
	pb.RegisterPKIServiceServer(srv, adapter)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := ggrpc.NewClient("passthrough:///bufnet",
		ggrpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		ggrpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	client := pb.NewPKIServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var hdr metadata.MD
	resp, err := client.CreateOrgCA(ctx, &pb.CreateOrgCARequest{OrgId: "org-bootstrap-1", OrgName: "Bootstrap Org"}, ggrpc.Header(&hdr))
	if err != nil {
		t.Fatalf("CreateOrgCA: %v", err)
	}
	if strings.Contains(resp.GetCertPem(), "PRIVATE KEY") {
		t.Fatal("CreateOrgCA response contained a private key")
	}
	token := hdr.Get(BootstrapSessionHeader)
	serial := hdr.Get(BootstrapMemberSerialHeader)
	if len(token) != 1 || token[0] != issuer.token || len(serial) != 1 || serial[0] == "" {
		t.Fatalf("bootstrap headers token=%v serial=%v", token, serial)
	}
	if issuer.calls != 1 || issuer.role != "admin" || issuer.orgID != "org-bootstrap-1" {
		t.Fatalf("issuer = %+v", issuer)
	}
	rec, err := store.GetCertificateBySerialWithKey(ctx, serial[0])
	if err != nil || rec == nil || len(rec.EncryptedPrivateKey) == 0 {
		t.Fatal("bootstrap member key was not stored")
	}

	var again metadata.MD
	if _, err := client.CreateOrgCA(ctx, &pb.CreateOrgCARequest{OrgId: "org-bootstrap-1", OrgName: "Bootstrap Org"}, ggrpc.Header(&again)); err != nil {
		t.Fatalf("second CreateOrgCA: %v", err)
	}
	if len(again.Get(BootstrapSessionHeader)) != 0 || issuer.calls != 1 {
		t.Fatalf("existing org minted another session (calls=%d header=%v)", issuer.calls, again.Get(BootstrapSessionHeader))
	}
}

type fakeBootstrapIssuer struct {
	token string
	calls int
	orgID string
	role  string
}

func (f *fakeBootstrapIssuer) IssueBootstrapSession(_ context.Context, memberID, orgID, role, certSerial string) (string, error) {
	f.calls++
	f.orgID = orgID
	f.role = role
	if memberID == "" || certSerial == "" {
		return "", status.Error(codes.InvalidArgument, "missing bootstrap member")
	}
	return f.token, nil
}

func signCSRAsCA(t *testing.T, csrPEM string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) string {
	t.Helper()
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		t.Fatal("csr pem")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	notBefore := parent.NotBefore
	if notBefore.Before(time.Now().Add(-time.Minute)) {
		notBefore = time.Now().Add(-time.Minute)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               csr.Subject,
		NotBefore:             notBefore,
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}, parent, csr.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
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

	sessionSvc := service.NewSessionService(signingKey, "test-issuer", time.Hour, registry, certStore, policyStore, auditLogger, store.NewMemoryChallengeStore())
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
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %v, want %v", status.Code(err), codes.Unauthenticated)
	}
}

func TestSessionAdapter_ListSessions(t *testing.T) {
	adapter, _ := setupSessionAdapter(t)
	ctx := authn.WithPrincipal(context.Background(), authn.Principal{
		TenantID: "org-1",
		ActorID:  "member-1",
		Role:     "member",
	})

	resp, err := adapter.ListSessions(ctx, &pb.ListSessionsRequest{
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
