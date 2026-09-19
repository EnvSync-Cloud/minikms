package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"
	"time"
)

func TestCreateLeafCertificate(t *testing.T) {
	rootCert, rootKey, _, err := CreateRootCA("Test Root CA", 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}
	orgCert, orgKey, _, err := CreateOrgIntermediateCA("org-123", "Test Org", rootCert, rootKey, 5*365*24*time.Hour)
	if err != nil {
		t.Fatalf("CreateOrgIntermediateCA: %v", err)
	}

	cert, keyPEM, _, err := CreateLeafCertificate(
		"api.internal",
		[]string{"api.internal", "127.0.0.1"},
		orgCert, orgKey,
		90*24*time.Hour,
		"ECDSA_P256",
		nil,
	)
	if err != nil {
		t.Fatalf("CreateLeafCertificate: %v", err)
	}
	if cert.IsCA {
		t.Fatal("leaf must not be CA")
	}
	if cert.Subject.CommonName != "api.internal" {
		t.Fatalf("CN: got %q", cert.Subject.CommonName)
	}
	if len(cert.DNSNames) == 0 || cert.DNSNames[0] != "api.internal" {
		t.Fatalf("DNS SAN missing: %v", cert.DNSNames)
	}
	if len(cert.IPAddresses) != 1 {
		t.Fatalf("IP SAN missing: %v", cert.IPAddresses)
	}
	foundServer, foundClient := false, false
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth {
			foundServer = true
		}
		if usage == x509.ExtKeyUsageClientAuth {
			foundClient = true
		}
	}
	if !foundServer || !foundClient {
		t.Fatal("expected server and client auth")
	}
	if err := cert.CheckSignatureFrom(orgCert); err != nil {
		t.Fatalf("not signed by org CA: %v", err)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		t.Fatal("key pem")
	}
}

func TestSignLeafCSR(t *testing.T) {
	rootCert, rootKey, _, err := CreateRootCA("Test Root CA", 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}
	orgCert, orgKey, _, err := CreateOrgIntermediateCA("org-123", "Test Org", rootCert, rootKey, 5*365*24*time.Hour)
	if err != nil {
		t.Fatalf("CreateOrgIntermediateCA: %v", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "svc.internal"},
		DNSNames: []string{"svc.internal", "svc"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	cert, _, err := SignLeafCSR(string(csrPEM), orgCert, orgKey, 30*24*time.Hour, nil)
	if err != nil {
		t.Fatalf("SignLeafCSR: %v", err)
	}
	if cert.Subject.CommonName != "svc.internal" {
		t.Fatalf("CN: %q", cert.Subject.CommonName)
	}
	if len(cert.DNSNames) != 2 {
		t.Fatalf("SANs: %v", cert.DNSNames)
	}
	if err := cert.CheckSignatureFrom(orgCert); err != nil {
		t.Fatal(err)
	}
}

func TestCreateLeafCertificate_UnsupportedAlgorithm(t *testing.T) {
	rootCert, rootKey, _, err := CreateRootCA("Test Root CA", 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}
	orgCert, orgKey, _, err := CreateOrgIntermediateCA("org-123", "Test Org", rootCert, rootKey, 5*365*24*time.Hour)
	if err != nil {
		t.Fatalf("CreateOrgIntermediateCA: %v", err)
	}
	_, _, _, err = CreateLeafCertificate("api.internal", nil, orgCert, orgKey, 0, "RSA_4096", nil)
	if err == nil {
		t.Fatal("expected unsupported algorithm error")
	}
}

func TestSignLeafCSR_InvalidPEM(t *testing.T) {
	rootCert, rootKey, _, err := CreateRootCA("Test Root CA", 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}
	orgCert, orgKey, _, err := CreateOrgIntermediateCA("org-123", "Test Org", rootCert, rootKey, 5*365*24*time.Hour)
	if err != nil {
		t.Fatalf("CreateOrgIntermediateCA: %v", err)
	}
	_, _, err = SignLeafCSR("not-a-csr", orgCert, orgKey, 0, nil)
	if err == nil {
		t.Fatal("expected invalid CSR PEM error")
	}
}
