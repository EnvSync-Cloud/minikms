package pki

import (
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"testing"
	"time"
)

func TestCreateMemberCertificate(t *testing.T) {
	rootCert, rootKey, _, err := CreateRootCA("Test Root CA", 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}

	orgCert, orgKey, _, err := CreateOrgIntermediateCA(
		"org-123", "Test Org", rootCert, rootKey, 5*365*24*time.Hour,
	)
	if err != nil {
		t.Fatalf("CreateOrgIntermediateCA: %v", err)
	}

	crlDist := []string{"http://crl.example.com/org-123.crl"}
	memberCert, memberKey, memberDER, err := CreateMemberCertificate(
		"member-456", "user@example.com", "org-123", "admin",
		orgCert, orgKey, 365*24*time.Hour, crlDist,
	)
	if err != nil {
		t.Fatalf("CreateMemberCertificate: %v", err)
	}

	t.Run("is not CA", func(t *testing.T) {
		if memberCert.IsCA {
			t.Fatal("member cert should NOT be CA")
		}
	})

	t.Run("ClientAuth ExtKeyUsage", func(t *testing.T) {
		found := false
		for _, usage := range memberCert.ExtKeyUsage {
			if usage == x509.ExtKeyUsageClientAuth {
				found = true
			}
		}
		if !found {
			t.Error("missing ExtKeyUsageClientAuth")
		}
	})

	t.Run("signed by org CA", func(t *testing.T) {
		err := memberCert.CheckSignatureFrom(orgCert)
		if err != nil {
			t.Fatalf("not signed by org CA: %v", err)
		}
	})

	t.Run("P-256 key", func(t *testing.T) {
		if memberKey.Curve != elliptic.P256() {
			t.Fatal("expected P-256 key for member cert")
		}
	})

	t.Run("CN is email", func(t *testing.T) {
		if memberCert.Subject.CommonName != "user@example.com" {
			t.Errorf("CN: got %q, want %q", memberCert.Subject.CommonName, "user@example.com")
		}
	})

	t.Run("CRL distribution points", func(t *testing.T) {
		if len(memberCert.CRLDistributionPoints) == 0 {
			t.Fatal("CRL distribution points should not be empty")
		}
		if memberCert.CRLDistributionPoints[0] != crlDist[0] {
			t.Errorf("CRL dist point: got %q, want %q", memberCert.CRLDistributionPoints[0], crlDist[0])
		}
	})

	t.Run("custom extensions", func(t *testing.T) {
		extMap := make(map[string][]byte)
		for _, ext := range memberCert.Extensions {
			extMap[ext.Id.String()] = ext.Value
		}

		// Check OIDMemberID
		if val, ok := extMap[OIDMemberID.String()]; ok {
			var memberID string
			if _, err := asn1.Unmarshal(val, &memberID); err != nil {
				t.Fatalf("unmarshal MemberID: %v", err)
			}
			if memberID != "member-456" {
				t.Errorf("MemberID: got %q, want %q", memberID, "member-456")
			}
		} else {
			t.Error("OIDMemberID extension not found")
		}

		// Check OIDOrgID
		if val, ok := extMap[OIDOrgID.String()]; ok {
			var orgID string
			if _, err := asn1.Unmarshal(val, &orgID); err != nil {
				t.Fatalf("unmarshal OrgID: %v", err)
			}
			if orgID != "org-123" {
				t.Errorf("OrgID: got %q, want %q", orgID, "org-123")
			}
		} else {
			t.Error("OIDOrgID extension not found")
		}

		// Check OIDRole
		if val, ok := extMap[OIDRole.String()]; ok {
			var role string
			if _, err := asn1.Unmarshal(val, &role); err != nil {
				t.Fatalf("unmarshal Role: %v", err)
			}
			if role != "admin" {
				t.Errorf("Role: got %q, want %q", role, "admin")
			}
		} else {
			t.Error("OIDRole extension not found")
		}
	})

	t.Run("DER roundtrip", func(t *testing.T) {
		parsed, err := x509.ParseCertificate(memberDER)
		if err != nil {
			t.Fatalf("ParseCertificate: %v", err)
		}
		if parsed.Subject.CommonName != memberCert.Subject.CommonName {
			t.Error("DER roundtrip CN mismatch")
		}
	})
}
