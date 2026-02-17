package pki

import (
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
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

	t.Run("MaxPathLen is 0", func(t *testing.T) {
		if orgCert.MaxPathLen != 0 {
			t.Errorf("MaxPathLen: got %d, want 0", orgCert.MaxPathLen)
		}
		if !orgCert.MaxPathLenZero {
			t.Error("MaxPathLenZero should be true")
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
