package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"testing"
	"time"
)

func TestCreateOrgIntermediateCA(t *testing.T) {
	rootCert, rootKey, _, err := CreateRootCA("Test Root CA", 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}

	orgCert, orgKey, orgDER, err := CreateOrgIntermediateCA(
		"org-123", "Test Org", rootCert, rootKey, 5*365*24*time.Hour,
	)
	if err != nil {
		t.Fatalf("CreateOrgIntermediateCA: %v", err)
	}

	t.Run("is CA", func(t *testing.T) {
		if !orgCert.IsCA {
			t.Fatal("intermediate cert should be CA")
		}
	})

	t.Run("MaxPathLen is 1", func(t *testing.T) {
		if orgCert.MaxPathLen != 1 {
			t.Errorf("MaxPathLen: got %d, want 1", orgCert.MaxPathLen)
		}
	})

	t.Run("signed by root", func(t *testing.T) {
		err := orgCert.CheckSignatureFrom(rootCert)
		if err != nil {
			t.Fatalf("not signed by root: %v", err)
		}
	})

	t.Run("P-384 key", func(t *testing.T) {
		if orgKey.Curve != elliptic.P384() {
			t.Fatal("expected P-384 key")
		}
	})

	t.Run("OU contains orgID", func(t *testing.T) {
		found := false
		for _, ou := range orgCert.Subject.OrganizationalUnit {
			if ou == "org-123" {
				found = true
			}
		}
		if !found {
			t.Errorf("OU should contain org-123, got %v", orgCert.Subject.OrganizationalUnit)
		}
	})

	t.Run("OIDOrgID extension present", func(t *testing.T) {
		found := false
		for _, ext := range orgCert.Extensions {
			if ext.Id.Equal(OIDOrgID) {
				var orgID string
				if _, err := asn1.Unmarshal(ext.Value, &orgID); err != nil {
					t.Fatalf("failed to unmarshal OIDOrgID: %v", err)
				}
				if orgID != "org-123" {
					t.Errorf("OIDOrgID: got %q, want %q", orgID, "org-123")
				}
				found = true
			}
		}
		if !found {
			t.Error("OIDOrgID extension not found")
		}
	})

	t.Run("DER roundtrip", func(t *testing.T) {
		parsed, err := x509.ParseCertificate(orgDER)
		if err != nil {
			t.Fatalf("ParseCertificate: %v", err)
		}
		if parsed.Subject.CommonName != orgCert.Subject.CommonName {
			t.Error("DER roundtrip CN mismatch")
		}
	})
}

func TestCreateOrgCACSR_SignedByOfflineRoot(t *testing.T) {
	rootCert, rootKey, _, err := CreateRootCA("Offline Root", 10*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	key, csrPEM, err := CreateOrgCACSR("org-1", "Acme")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(csrPEM)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatal(err)
	}
	serial, err := generateSerialNumber()
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               csr.Subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, rootCert, csr.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.CheckSignatureFrom(rootCert); err != nil {
		t.Fatal(err)
	}
	if !cert.PublicKey.(*ecdsa.PublicKey).Equal(&key.PublicKey) {
		t.Fatal("installed cert key mismatch")
	}
}
