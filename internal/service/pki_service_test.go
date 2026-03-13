package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/envsync-cloud/minikms/internal/audit"
	"github.com/envsync-cloud/minikms/internal/keys"
	pkiPkg "github.com/envsync-cloud/minikms/internal/pki"
	"github.com/envsync-cloud/minikms/internal/pkistore"
	"github.com/envsync-cloud/minikms/internal/testutil"
)

func setupPKIService(t *testing.T) *PKIService {
	t.Helper()
	rootCert, rootKey, _, err := pkiPkg.CreateRootCA("Test Root CA", 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}
	auditStore := testutil.NewMockAuditStore()
	auditLogger := audit.NewAuditLogger(auditStore)
	return NewPKIService(rootCert, rootKey, auditLogger, nil)
}

func TestPKIService_CreateOrgCA(t *testing.T) {
	ctx := context.Background()
	svc := setupPKIService(t)

	resp, err := svc.CreateOrgCA(ctx, &CreateOrgCARequest{
		OrgID:   "org-123",
		OrgName: "Test Org",
	})
	if err != nil {
		t.Fatalf("CreateOrgCA: %v", err)
	}

	if resp.CertPEM == "" {
		t.Fatal("CertPEM should not be empty")
	}
	if resp.SerialHex == "" {
		t.Fatal("SerialHex should not be empty")
	}

	// Parse the PEM
	block, _ := pem.Decode([]byte(resp.CertPEM))
	if block == nil {
		t.Fatal("failed to decode PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if !cert.IsCA {
		t.Fatal("org CA cert should be a CA")
	}
}

func TestPKIService_IssueMemberCert(t *testing.T) {
	ctx := context.Background()
	svc := setupPKIService(t)

	// Create org CA first
	orgCAResp, _ := svc.CreateOrgCA(ctx, &CreateOrgCARequest{
		OrgID:   "org-123",
		OrgName: "Test Org",
	})

	// Parse org CA cert and key for member cert issuance
	// We need the org CA cert and key, so we create one directly
	rootCert, rootKey, _, _ := pkiPkg.CreateRootCA("Test Root CA", 10*365*24*time.Hour)
	orgCACert, orgCAKey, _, _ := pkiPkg.CreateOrgIntermediateCA(
		"org-123", "Test Org", rootCert, rootKey, 5*365*24*time.Hour,
	)

	_ = orgCAResp // used for initial validation above

	resp, err := svc.IssueMemberCert(ctx, &IssueMemberCertRequest{
		MemberID:    "member-456",
		MemberEmail: "user@example.com",
		OrgID:       "org-123",
		Role:        "admin",
		OrgCACert:   orgCACert,
		OrgCAKey:    orgCAKey,
	})
	if err != nil {
		t.Fatalf("IssueMemberCert: %v", err)
	}

	if resp.CertPEM == "" {
		t.Fatal("CertPEM should not be empty")
	}
	if resp.KeyPEM == "" {
		t.Fatal("KeyPEM should not be empty")
	}
	if resp.SerialHex == "" {
		t.Fatal("SerialHex should not be empty")
	}
}

func TestPKIService_FullChainVerification(t *testing.T) {
	// Build full Root → Org → Member chain and verify trust
	rootCert, rootKey, _, err := pkiPkg.CreateRootCA("Test Root CA", 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}

	auditStore := testutil.NewMockAuditStore()
	auditLogger := audit.NewAuditLogger(auditStore)
	svc := NewPKIService(rootCert, rootKey, auditLogger, nil)
	ctx := context.Background()

	// Create org CA through service
	orgResp, err := svc.CreateOrgCA(ctx, &CreateOrgCARequest{
		OrgID:   "org-test",
		OrgName: "Chain Test Org",
	})
	if err != nil {
		t.Fatalf("CreateOrgCA: %v", err)
	}

	// Parse org cert
	block, _ := pem.Decode([]byte(orgResp.CertPEM))
	orgCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse org cert: %v", err)
	}

	// Verify org cert is signed by root
	if err := orgCert.CheckSignatureFrom(rootCert); err != nil {
		t.Fatalf("org cert not signed by root: %v", err)
	}

	// For member cert, we need the org CA key (which the service doesn't expose),
	// so we create the chain directly for full verification
	orgCACert, orgCAKey, _, _ := pkiPkg.CreateOrgIntermediateCA(
		"org-test", "Chain Test Org", rootCert, rootKey, 5*365*24*time.Hour,
	)

	memberResp, err := svc.IssueMemberCert(ctx, &IssueMemberCertRequest{
		MemberID:    "member-001",
		MemberEmail: "test@example.com",
		OrgID:       "org-test",
		Role:        "viewer",
		OrgCACert:   orgCACert,
		OrgCAKey:    orgCAKey,
	})
	if err != nil {
		t.Fatalf("IssueMemberCert: %v", err)
	}

	// Parse member cert
	block, _ = pem.Decode([]byte(memberResp.CertPEM))
	memberCert, _ := x509.ParseCertificate(block.Bytes)

	// Parse member key
	keyBlock, _ := pem.Decode([]byte(memberResp.KeyPEM))
	memberKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatalf("parse member key: %v", err)
	}

	// Verify member cert is signed by org CA
	if err := memberCert.CheckSignatureFrom(orgCACert); err != nil {
		t.Fatalf("member cert not signed by org CA: %v", err)
	}

	// Verify key matches cert
	pubKey := memberCert.PublicKey.(*ecdsa.PublicKey)
	if !pubKey.Equal(&memberKey.PublicKey) {
		t.Fatal("member key doesn't match cert")
	}
}

// --- Additional PKI tests for coverage ---

func setupPKIWithStore(t *testing.T) (*PKIService, *x509.Certificate, *ecdsa.PrivateKey, *testutil.MockPKICertStore) {
	t.Helper()
	rootCert, rootKey, _, err := pkiPkg.CreateRootCA("Test Root CA", 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}
	auditStore := testutil.NewMockAuditStore()
	auditLogger := audit.NewAuditLogger(auditStore)
	certStore := testutil.NewMockPKICertStore()
	svc := NewPKIService(rootCert, rootKey, auditLogger, certStore)
	return svc, rootCert, rootKey, certStore
}

func TestRootCert(t *testing.T) {
	svc, rootCert, _, _ := setupPKIWithStore(t)
	got := svc.RootCert()
	if got != rootCert {
		t.Fatal("RootCert() should return the root certificate")
	}
}

func TestSetOrgCAWrapManager(t *testing.T) {
	svc, _, _, _ := setupPKIWithStore(t)
	wrapStore := testutil.NewMockOrgCAWrapStore()
	mgr := keys.NewOrgCAWrapManager(wrapStore)
	svc.SetOrgCAWrapManager(mgr)
	if svc.orgCAWrapMgr == nil {
		t.Fatal("orgCAWrapMgr should be set")
	}
}

func TestSetShamirConfig(t *testing.T) {
	svc, _, _, _ := setupPKIWithStore(t)
	svc.SetShamirConfig(7, 4)
	if svc.shamirShares != 7 {
		t.Errorf("shamirShares = %d, want 7", svc.shamirShares)
	}
	if svc.shamirThresh != 4 {
		t.Errorf("shamirThresh = %d, want 4", svc.shamirThresh)
	}
}

func TestRevokeCert(t *testing.T) {
	svc, _, _, certStore := setupPKIWithStore(t)
	ctx := context.Background()

	// Create org CA
	_, orgCACert, orgCAKey, err := svc.CreateOrgCAFull(ctx, &CreateOrgCARequest{
		OrgID: "org-001", OrgName: "Test Org",
	})
	if err != nil {
		t.Fatalf("CreateOrgCAFull: %v", err)
	}

	// Issue member cert
	memberResp, err := svc.IssueMemberCert(ctx, &IssueMemberCertRequest{
		MemberID: "m1", MemberEmail: "m@test.com", OrgID: "org-001",
		Role: "admin", OrgCACert: orgCACert, OrgCAKey: orgCAKey,
	})
	if err != nil {
		t.Fatalf("IssueMemberCert: %v", err)
	}

	// Revoke
	err = svc.RevokeCert(ctx, &RevokeCertRequest{
		SerialHex: memberResp.SerialHex, OrgID: "org-001", Reason: 1,
	})
	if err != nil {
		t.Fatalf("RevokeCert: %v", err)
	}

	// Verify status
	rec, _ := certStore.GetCertificateBySerial(ctx, memberResp.SerialHex)
	if rec == nil || rec.Status != "revoked" {
		t.Error("cert should be revoked")
	}

	// Revoking again should error
	err = svc.RevokeCert(ctx, &RevokeCertRequest{
		SerialHex: memberResp.SerialHex, OrgID: "org-001", Reason: 1,
	})
	if err == nil {
		t.Fatal("expected error revoking already-revoked cert")
	}
}

func TestRevokeCert_NotFound(t *testing.T) {
	svc, _, _, _ := setupPKIWithStore(t)
	err := svc.RevokeCert(context.Background(), &RevokeCertRequest{
		SerialHex: "nonexistent", OrgID: "org-001",
	})
	if err == nil {
		t.Fatal("expected error for cert not found")
	}
}

func TestRevokeCert_WrongOrg(t *testing.T) {
	svc, _, _, _ := setupPKIWithStore(t)
	ctx := context.Background()

	_, orgCACert, orgCAKey, _ := svc.CreateOrgCAFull(ctx, &CreateOrgCARequest{
		OrgID: "org-001", OrgName: "Test Org",
	})
	memberResp, _ := svc.IssueMemberCert(ctx, &IssueMemberCertRequest{
		MemberID: "m1", MemberEmail: "m@test.com", OrgID: "org-001",
		Role: "member", OrgCACert: orgCACert, OrgCAKey: orgCAKey,
	})

	err := svc.RevokeCert(ctx, &RevokeCertRequest{
		SerialHex: memberResp.SerialHex, OrgID: "org-OTHER",
	})
	if err == nil {
		t.Fatal("expected error for wrong org")
	}
}

func TestRevokeCert_NilStore(t *testing.T) {
	auditLogger := audit.NewAuditLogger(&mockAuditStore{})
	svc := NewPKIService(nil, nil, auditLogger, nil)
	err := svc.RevokeCert(context.Background(), &RevokeCertRequest{SerialHex: "abc", OrgID: "org-1"})
	if err == nil {
		t.Fatal("expected error for nil store")
	}
}

func TestGetCRL(t *testing.T) {
	svc, _, _, _ := setupPKIWithStore(t)
	ctx := context.Background()

	_, orgCACert, orgCAKey, _ := svc.CreateOrgCAFull(ctx, &CreateOrgCARequest{
		OrgID: "org-001", OrgName: "Test Org",
	})
	memberResp, _ := svc.IssueMemberCert(ctx, &IssueMemberCertRequest{
		MemberID: "m1", MemberEmail: "m@test.com", OrgID: "org-001",
		Role: "member", OrgCACert: orgCACert, OrgCAKey: orgCAKey,
	})

	// Revoke the cert
	_ = svc.RevokeCert(ctx, &RevokeCertRequest{
		SerialHex: memberResp.SerialHex, OrgID: "org-001", Reason: 1,
	})

	// Generate CRL
	crlResp, err := svc.GetCRL(ctx, &GetCRLRequest{
		OrgID: "org-001", IssuerCert: orgCACert, IssuerKey: orgCAKey,
	})
	if err != nil {
		t.Fatalf("GetCRL: %v", err)
	}
	if len(crlResp.CRLDER) == 0 {
		t.Error("CRL DER is empty")
	}
}

func TestGetCRL_NoOrgCA(t *testing.T) {
	svc, _, _, _ := setupPKIWithStore(t)
	key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	_, err := svc.GetCRL(context.Background(), &GetCRLRequest{
		OrgID: "org-missing", IssuerKey: key,
	})
	if err == nil {
		t.Fatal("expected error for missing org CA")
	}
}

func TestGetCRL_NilStore(t *testing.T) {
	auditLogger := audit.NewAuditLogger(&mockAuditStore{})
	svc := NewPKIService(nil, nil, auditLogger, nil)
	_, err := svc.GetCRL(context.Background(), &GetCRLRequest{OrgID: "o"})
	if err == nil {
		t.Fatal("expected error for nil store")
	}
}

func TestCheckOCSP_Good(t *testing.T) {
	svc, _, _, _ := setupPKIWithStore(t)
	ctx := context.Background()

	_, orgCACert, orgCAKey, _ := svc.CreateOrgCAFull(ctx, &CreateOrgCARequest{
		OrgID: "org-001", OrgName: "Test Org",
	})
	memberResp, _ := svc.IssueMemberCert(ctx, &IssueMemberCertRequest{
		MemberID: "m1", MemberEmail: "m@test.com", OrgID: "org-001",
		Role: "member", OrgCACert: orgCACert, OrgCAKey: orgCAKey,
	})

	ocsp, err := svc.CheckOCSP(ctx, &CheckOCSPRequest{
		SerialHex: memberResp.SerialHex, OrgID: "org-001",
	})
	if err != nil {
		t.Fatalf("CheckOCSP: %v", err)
	}
	if ocsp.Status != 0 {
		t.Errorf("Status = %d, want 0 (good)", ocsp.Status)
	}
}

func TestCheckOCSP_Revoked(t *testing.T) {
	svc, _, _, _ := setupPKIWithStore(t)
	ctx := context.Background()

	_, orgCACert, orgCAKey, _ := svc.CreateOrgCAFull(ctx, &CreateOrgCARequest{
		OrgID: "org-001", OrgName: "Test Org",
	})
	memberResp, _ := svc.IssueMemberCert(ctx, &IssueMemberCertRequest{
		MemberID: "m1", MemberEmail: "m@test.com", OrgID: "org-001",
		Role: "member", OrgCACert: orgCACert, OrgCAKey: orgCAKey,
	})
	_ = svc.RevokeCert(ctx, &RevokeCertRequest{
		SerialHex: memberResp.SerialHex, OrgID: "org-001", Reason: 1,
	})

	ocsp, err := svc.CheckOCSP(ctx, &CheckOCSPRequest{
		SerialHex: memberResp.SerialHex, OrgID: "org-001",
	})
	if err != nil {
		t.Fatalf("CheckOCSP: %v", err)
	}
	if ocsp.Status != 1 {
		t.Errorf("Status = %d, want 1 (revoked)", ocsp.Status)
	}
	if ocsp.RevokedAt == "" {
		t.Error("RevokedAt should not be empty")
	}
}

func TestCheckOCSP_Unknown(t *testing.T) {
	svc, _, _, _ := setupPKIWithStore(t)
	ocsp, err := svc.CheckOCSP(context.Background(), &CheckOCSPRequest{
		SerialHex: "nonexistent", OrgID: "org-001",
	})
	if err != nil {
		t.Fatalf("CheckOCSP: %v", err)
	}
	if ocsp.Status != 2 {
		t.Errorf("Status = %d, want 2 (unknown)", ocsp.Status)
	}
}

func TestCheckOCSP_WrongOrg(t *testing.T) {
	svc, _, _, _ := setupPKIWithStore(t)
	ctx := context.Background()

	_, orgCACert, orgCAKey, _ := svc.CreateOrgCAFull(ctx, &CreateOrgCARequest{
		OrgID: "org-001", OrgName: "Test Org",
	})
	memberResp, _ := svc.IssueMemberCert(ctx, &IssueMemberCertRequest{
		MemberID: "m1", MemberEmail: "m@test.com", OrgID: "org-001",
		Role: "member", OrgCACert: orgCACert, OrgCAKey: orgCAKey,
	})

	ocsp, err := svc.CheckOCSP(ctx, &CheckOCSPRequest{
		SerialHex: memberResp.SerialHex, OrgID: "org-OTHER",
	})
	if err != nil {
		t.Fatalf("CheckOCSP: %v", err)
	}
	if ocsp.Status != 2 {
		t.Errorf("Status = %d, want 2 (unknown) for wrong org", ocsp.Status)
	}
}

func TestCheckOCSP_NilStore(t *testing.T) {
	auditLogger := audit.NewAuditLogger(&mockAuditStore{})
	svc := NewPKIService(nil, nil, auditLogger, nil)
	_, err := svc.CheckOCSP(context.Background(), &CheckOCSPRequest{SerialHex: "abc", OrgID: "o"})
	if err == nil {
		t.Fatal("expected error for nil store")
	}
}

func TestCreateOrgWithWrapping_Managed(t *testing.T) {
	svc, _, _, _ := setupPKIWithStore(t)
	ctx := context.Background()

	wrapStore := testutil.NewMockOrgCAWrapStore()
	mgr := keys.NewOrgCAWrapManager(wrapStore)
	svc.SetOrgCAWrapManager(mgr)

	resp, err := svc.CreateOrgWithWrapping(ctx, &CreateOrgWithWrappingRequest{
		OrgID: "org-new", OrgName: "New Org",
		CreatorMemberID: "creator-001", CreatorEmail: "creator@test.com",
		CreatorRole: "admin",
	})
	if err != nil {
		t.Fatalf("CreateOrgWithWrapping: %v", err)
	}
	if resp.OrgCACertPEM == "" {
		t.Error("OrgCACertPEM is empty")
	}
	if resp.MemberCertPEM == "" {
		t.Error("MemberCertPEM is empty")
	}
	if resp.MemberKeyPEM == "" {
		t.Error("MemberKeyPEM should be set for managed mode")
	}
	if resp.MemberSerial == "" {
		t.Error("MemberSerial is empty")
	}
}

func TestAddMember_NilWrapManager(t *testing.T) {
	svc, _, _, _ := setupPKIWithStore(t)
	_, err := svc.AddMember(context.Background(), &AddMemberRequest{
		OrgID: "org-1", MemberID: "m1", AdminMemberID: "admin-1",
	})
	if err == nil {
		t.Fatal("expected error for nil OrgCAWrapManager")
	}
}

func TestIssueMemberCert_WithStore(t *testing.T) {
	svc, _, _, certStore := setupPKIWithStore(t)
	ctx := context.Background()

	_, orgCACert, orgCAKey, _ := svc.CreateOrgCAFull(ctx, &CreateOrgCARequest{
		OrgID: "org-001", OrgName: "Test Org",
	})

	resp, err := svc.IssueMemberCert(ctx, &IssueMemberCertRequest{
		MemberID: "m1", MemberEmail: "m@test.com", OrgID: "org-001",
		Role: "admin", OrgCACert: orgCACert, OrgCAKey: orgCAKey,
	})
	if err != nil {
		t.Fatalf("IssueMemberCert: %v", err)
	}

	// Verify cert was persisted in store
	rec, _ := certStore.GetCertificateBySerial(ctx, resp.SerialHex)
	if rec == nil {
		t.Fatal("member cert should be stored")
	}
	if rec.Status != "active" {
		t.Errorf("Status = %q, want %q", rec.Status, "active")
	}
	if rec.CertType != "member" {
		t.Errorf("CertType = %q, want %q", rec.CertType, "member")
	}
}

func TestIssueMemberCert_StoresPrivateKey(t *testing.T) {
	svc, _, _, certStore := setupPKIWithStore(t)
	ctx := context.Background()

	_, orgCACert, orgCAKey, _ := svc.CreateOrgCAFull(ctx, &CreateOrgCARequest{
		OrgID: "org-privkey", OrgName: "PrivKey Test Org",
	})

	resp, err := svc.IssueMemberCert(ctx, &IssueMemberCertRequest{
		MemberID: "m1", MemberEmail: "m@test.com", OrgID: "org-privkey",
		Role: "admin", OrgCACert: orgCACert, OrgCAKey: orgCAKey,
	})
	if err != nil {
		t.Fatalf("IssueMemberCert: %v", err)
	}

	// Verify that the stored cert record has EncryptedPrivateKey populated
	rec, _ := certStore.GetCertificateBySerial(ctx, resp.SerialHex)
	if rec == nil {
		t.Fatal("member cert should be stored")
	}
	if len(rec.EncryptedPrivateKey) == 0 {
		t.Error("EncryptedPrivateKey should be populated for managed member certs")
	}
}

func TestIssueMemberCert_PrivateKeyRoundtrip(t *testing.T) {
	svc, _, _, _ := setupPKIWithStore(t)
	ctx := context.Background()

	_, orgCACert, orgCAKey, _ := svc.CreateOrgCAFull(ctx, &CreateOrgCARequest{
		OrgID: "org-roundtrip", OrgName: "Roundtrip Test Org",
	})

	resp, err := svc.IssueMemberCert(ctx, &IssueMemberCertRequest{
		MemberID: "m1", MemberEmail: "roundtrip@test.com", OrgID: "org-roundtrip",
		Role: "member", OrgCACert: orgCACert, OrgCAKey: orgCAKey,
	})
	if err != nil {
		t.Fatalf("IssueMemberCert: %v", err)
	}

	// Parse the returned cert and key PEMs
	certBlock, _ := pem.Decode([]byte(resp.CertPEM))
	if certBlock == nil {
		t.Fatal("failed to decode cert PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	keyBlock, _ := pem.Decode([]byte(resp.KeyPEM))
	if keyBlock == nil {
		t.Fatal("failed to decode key PEM")
	}
	privKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatalf("ParseECPrivateKey: %v", err)
	}

	// Verify the private key matches the cert's public key
	pubKey := cert.PublicKey.(*ecdsa.PublicKey)
	if !pubKey.Equal(&privKey.PublicKey) {
		t.Error("private key does not match certificate public key")
	}
}

func TestCreateOrgWithWrapping_WrapManagerCalled(t *testing.T) {
	svc, _, _, _ := setupPKIWithStore(t)
	ctx := context.Background()

	wrapStore := testutil.NewMockOrgCAWrapStore()
	mgr := keys.NewOrgCAWrapManager(wrapStore)
	svc.SetOrgCAWrapManager(mgr)

	resp, err := svc.CreateOrgWithWrapping(ctx, &CreateOrgWithWrappingRequest{
		OrgID: "org-wrap-check", OrgName: "Wrap Check Org",
		CreatorMemberID: "creator-001", CreatorEmail: "creator@test.com",
		CreatorRole: "admin",
	})
	if err != nil {
		t.Fatalf("CreateOrgWithWrapping: %v", err)
	}
	if resp.MemberSerial == "" {
		t.Error("MemberSerial should be set")
	}

	// Verify the wrap was stored for the creator member
	wrap, err := wrapStore.GetOrgCAWrap(ctx, "org-wrap-check", "creator-001")
	if err != nil {
		t.Fatalf("GetOrgCAWrap: %v", err)
	}
	if wrap == nil {
		t.Error("org CA wrap should exist for creator member")
	}
}

func TestCreateOrgCAFull_Stored(t *testing.T) {
	svc, _, _, certStore := setupPKIWithStore(t)
	ctx := context.Background()

	resp, cert, key, err := svc.CreateOrgCAFull(ctx, &CreateOrgCARequest{
		OrgID: "org-001", OrgName: "Test Org",
	})
	if err != nil {
		t.Fatalf("CreateOrgCAFull: %v", err)
	}
	if resp == nil || cert == nil || key == nil {
		t.Fatal("nil return values")
	}

	// Verify stored in cert store
	rec, _ := certStore.GetOrgCA(ctx, "org-001")
	if rec == nil {
		t.Fatal("org CA should be stored")
	}
	if rec.CertType != "org_intermediate_ca" {
		t.Errorf("CertType = %q, want %q", rec.CertType, "org_intermediate_ca")
	}

	// Verify stored cert is the same as the one stored via serial
	recBySerial, _ := certStore.GetCertificateBySerial(ctx, resp.SerialHex)
	if recBySerial == nil {
		t.Fatal("org CA cert should be stored by serial")
	}
	_ = pkistore.CertRecord{} // verify import is used
}
