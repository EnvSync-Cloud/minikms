package pki

import (
	"crypto/x509"
	"math/big"
	"testing"
	"time"
)

func TestGenerateCRL(t *testing.T) {
	rootCert, rootKey, _, err := CreateRootCA("Test Root CA", 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}

	now := time.Now()

	t.Run("empty CRL", func(t *testing.T) {
		config := CRLConfig{
			Number:     big.NewInt(1),
			ThisUpdate: now,
			NextUpdate: now.Add(24 * time.Hour),
		}
		crlDER, err := GenerateCRL(rootCert, rootKey, nil, config)
		if err != nil {
			t.Fatalf("GenerateCRL: %v", err)
		}
		if len(crlDER) == 0 {
			t.Fatal("CRL should not be empty")
		}

		rl, err := x509.ParseRevocationList(crlDER)
		if err != nil {
			t.Fatalf("ParseRevocationList: %v", err)
		}
		if len(rl.RevokedCertificateEntries) != 0 {
			t.Errorf("expected 0 revoked certs, got %d", len(rl.RevokedCertificateEntries))
		}
	})

	t.Run("CRL with revoked certs", func(t *testing.T) {
		revokedCerts := []RevokedCert{
			{SerialNumber: big.NewInt(100), RevokedAt: now, ReasonCode: 1},
			{SerialNumber: big.NewInt(200), RevokedAt: now, ReasonCode: 4},
		}
		config := CRLConfig{
			Number:     big.NewInt(2),
			ThisUpdate: now,
			NextUpdate: now.Add(24 * time.Hour),
		}
		crlDER, err := GenerateCRL(rootCert, rootKey, revokedCerts, config)
		if err != nil {
			t.Fatalf("GenerateCRL: %v", err)
		}

		rl, err := x509.ParseRevocationList(crlDER)
		if err != nil {
			t.Fatalf("ParseRevocationList: %v", err)
		}
		if len(rl.RevokedCertificateEntries) != 2 {
			t.Errorf("expected 2 revoked certs, got %d", len(rl.RevokedCertificateEntries))
		}
	})

	t.Run("CRL signed by issuer", func(t *testing.T) {
		config := CRLConfig{
			Number:     big.NewInt(3),
			ThisUpdate: now,
			NextUpdate: now.Add(24 * time.Hour),
		}
		crlDER, err := GenerateCRL(rootCert, rootKey, nil, config)
		if err != nil {
			t.Fatalf("GenerateCRL: %v", err)
		}
		rl, err := x509.ParseRevocationList(crlDER)
		if err != nil {
			t.Fatalf("ParseRevocationList: %v", err)
		}
		if err := rl.CheckSignatureFrom(rootCert); err != nil {
			t.Fatalf("CRL not signed by issuer: %v", err)
		}
	})
}

func TestCheckRevocationStatus(t *testing.T) {
	now := time.Now()
	revokedCerts := []RevokedCert{
		{SerialNumber: big.NewInt(100), RevokedAt: now, ReasonCode: 1},
		{SerialNumber: big.NewInt(200), RevokedAt: now, ReasonCode: 4},
	}

	t.Run("revoked", func(t *testing.T) {
		resp := CheckRevocationStatus(big.NewInt(100), revokedCerts)
		if resp.Status != OCSPStatusRevoked {
			t.Errorf("status: got %d, want %d", resp.Status, OCSPStatusRevoked)
		}
		if resp.SerialNumber.Cmp(big.NewInt(100)) != 0 {
			t.Error("serial number mismatch")
		}
	})

	t.Run("good", func(t *testing.T) {
		resp := CheckRevocationStatus(big.NewInt(300), revokedCerts)
		if resp.Status != OCSPStatusGood {
			t.Errorf("status: got %d, want %d", resp.Status, OCSPStatusGood)
		}
	})

	t.Run("empty revocation list", func(t *testing.T) {
		resp := CheckRevocationStatus(big.NewInt(100), nil)
		if resp.Status != OCSPStatusGood {
			t.Errorf("status: got %d, want %d (good)", resp.Status, OCSPStatusGood)
		}
	})
}
