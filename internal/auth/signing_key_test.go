package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadSessionSigningKey_PKCS8ValueAndFile(t *testing.T) {
	original, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(original)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	fromValue, err := LoadSessionSigningKey(string(keyPEM), "")
	if err != nil {
		t.Fatalf("LoadSessionSigningKey(value): %v", err)
	}

	keyPath := filepath.Join(t.TempDir(), "session-signing-key.pem")
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	fromFile, err := LoadSessionSigningKey("", keyPath)
	if err != nil {
		t.Fatalf("LoadSessionSigningKey(file): %v", err)
	}

	if fromValue.D.Cmp(original.D) != 0 || fromFile.D.Cmp(original.D) != 0 {
		t.Fatal("loaded keys do not match the configured private key")
	}
}

func TestLoadSessionSigningKey_SEC1(t *testing.T) {
	original, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(original)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})

	loaded, err := LoadSessionSigningKey(string(keyPEM), "")
	if err != nil {
		t.Fatalf("LoadSessionSigningKey: %v", err)
	}
	if loaded.D.Cmp(original.D) != 0 {
		t.Fatal("loaded key does not match the configured private key")
	}
}

func TestLoadSessionSigningKey_RejectsInvalidConfiguration(t *testing.T) {
	tests := []struct {
		name    string
		keyPEM  string
		keyFile string
	}{
		{name: "missing"},
		{name: "both sources", keyPEM: "value", keyFile: "file"},
		{name: "not PEM", keyPEM: "not-a-key"},
		{name: "unsupported PEM", keyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("invalid")}))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := LoadSessionSigningKey(tt.keyPEM, tt.keyFile); err == nil {
				t.Fatal("LoadSessionSigningKey should reject invalid configuration")
			}
		})
	}
}

func TestLoadSessionSigningKey_RejectsNonP256Key(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	if _, err := LoadSessionSigningKey(string(keyPEM), ""); err == nil {
		t.Fatal("LoadSessionSigningKey should reject a non-P-256 key")
	}
}
