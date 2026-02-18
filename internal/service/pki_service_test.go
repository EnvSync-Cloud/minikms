package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/envsync/minikms/internal/audit"
	pkiPkg "github.com/envsync/minikms/internal/pki"
	"github.com/envsync/minikms/internal/testutil"
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
