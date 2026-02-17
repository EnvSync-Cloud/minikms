package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"testing"
	"time"
)

func TestCreateRootCA(t *testing.T) {
	cert, key, certDER, err := CreateRootCA("Test Root CA", 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}

	t.Run("is CA", func(t *testing.T) {
		if !cert.IsCA {
			t.Fatal("root cert should be CA")
		}
	})

	t.Run("MaxPathLen is 1", func(t *testing.T) {
		if cert.MaxPathLen != 1 {
			t.Errorf("MaxPathLen: got %d, want 1", cert.MaxPathLen)
		}
	})

	t.Run("KeyUsage CertSign and CRLSign", func(t *testing.T) {
		if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			t.Error("missing KeyUsageCertSign")
		}
		if cert.KeyUsage&x509.KeyUsageCRLSign == 0 {
			t.Error("missing KeyUsageCRLSign")
		}
	})

	t.Run("CommonName", func(t *testing.T) {
		if cert.Subject.CommonName != "Test Root CA" {
			t.Errorf("CN: got %q, want %q", cert.Subject.CommonName, "Test Root CA")
		}
	})

	t.Run("self-signed", func(t *testing.T) {
		err := cert.CheckSignatureFrom(cert)
		if err != nil {
			t.Fatalf("not self-signed: %v", err)
		}
	})

	t.Run("P-384 key", func(t *testing.T) {
		if key.Curve != elliptic.P384() {
			t.Fatalf("expected P-384 key")
		}
	})

	t.Run("serial > 0", func(t *testing.T) {
		if cert.SerialNumber.Sign() <= 0 {
			t.Fatal("serial number should be positive")
		}
	})

	t.Run("DER roundtrip", func(t *testing.T) {
		parsed, err := x509.ParseCertificate(certDER)
		if err != nil {
			t.Fatalf("ParseCertificate: %v", err)
		}
		if parsed.Subject.CommonName != cert.Subject.CommonName {
			t.Error("DER roundtrip CN mismatch")
		}
	})

	t.Run("key matches cert public key", func(t *testing.T) {
		pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			t.Fatal("cert public key is not ECDSA")
		}
		if !pubKey.Equal(&key.PublicKey) {
			t.Fatal("cert public key doesn't match generated key")
		}
	})
}
