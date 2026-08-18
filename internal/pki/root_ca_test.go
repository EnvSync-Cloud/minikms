package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
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

func TestLoadRootCA(t *testing.T) {
	cert, key, certDER, err := CreateRootCA("Shared Root CA", 24*time.Hour)
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	loadedCert, loadedKey, err := LoadRootCA(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("LoadRootCA: %v", err)
	}
	if !loadedCert.Equal(cert) || !loadedKey.PublicKey.Equal(&key.PublicKey) {
		t.Fatal("loaded root CA does not match source material")
	}

	_, otherKey, _, err := CreateRootCA("Other Root CA", 24*time.Hour)
	if err != nil {
		t.Fatalf("CreateRootCA(other): %v", err)
	}
	otherKeyDER, _ := x509.MarshalECPrivateKey(otherKey)
	otherKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: otherKeyDER})
	if _, _, err := LoadRootCA(certPEM, otherKeyPEM); err == nil {
		t.Fatal("LoadRootCA accepted a mismatched private key")
	}
}

func TestLoadRootCAFromSources(t *testing.T) {
	_, key, certDER, err := CreateRootCA("Mounted Root CA", 24*time.Hour)
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	dir := t.TempDir()
	certPath := filepath.Join(dir, "root-ca.crt")
	keyPath := filepath.Join(dir, "root-ca.key")
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	if _, _, err := LoadRootCAFromSources("", certPath, "", keyPath); err != nil {
		t.Fatalf("LoadRootCAFromSources(files): %v", err)
	}
	if _, _, err := LoadRootCAFromSources(string(certPEM), "", string(keyPEM), ""); err != nil {
		t.Fatalf("LoadRootCAFromSources(values): %v", err)
	}
	if err := os.Chmod(keyPath, 0o440); err != nil {
		t.Fatalf("chmod group-readable key: %v", err)
	}
	if _, _, err := LoadRootCAFromSources("", certPath, "", keyPath); err != nil {
		t.Fatalf("LoadRootCAFromSources rejected a protected fsGroup-readable key: %v", err)
	}

	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatalf("chmod key: %v", err)
	}
	if _, _, err := LoadRootCAFromSources("", certPath, "", keyPath); err == nil {
		t.Fatal("LoadRootCAFromSources accepted an exposed private-key file")
	}
	if _, _, err := LoadRootCAFromSources("", "", string(keyPEM), ""); err == nil {
		t.Fatal("LoadRootCAFromSources accepted a missing certificate source")
	}
}
