package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/envsync-cloud/minikms/internal/crypto"
	"github.com/envsync-cloud/minikms/internal/escrow"
)

func TestNormalizeScope(t *testing.T) {
	if scope, err := normalizeScope(escrow.KeyTypeRoot, ""); err != nil || scope != escrow.RootScope {
		t.Fatalf("root scope: scope=%q err=%v", scope, err)
	}
	if scope, err := normalizeScope(escrow.KeyTypeOrgCA, "org-1"); err != nil || scope != "org-1" {
		t.Fatalf("org scope: scope=%q err=%v", scope, err)
	}
	if _, err := normalizeScope(escrow.KeyTypeOrgCA, ""); err == nil {
		t.Fatal("org_ca accepted an empty org ID")
	}
}

func TestCreateExclusiveAndProtectedRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "share.json")
	file, discard, err := createExclusive(path)
	if err != nil {
		t.Fatalf("createExclusive: %v", err)
	}
	if _, err := file.Write([]byte("sensitive")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 600", info.Mode().Perm())
	}
	if got, err := readProtectedFile(path); err != nil || string(got) != "sensitive" {
		t.Fatalf("readProtectedFile: got=%q err=%v", got, err)
	}
	if _, _, err := createExclusive(path); err == nil {
		t.Fatal("createExclusive overwrote an existing file")
	}

	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if _, err := readProtectedFile(path); err == nil {
		t.Fatal("readProtectedFile accepted an overly permissive share file")
	}
	discard()
}

func TestFormatRecoveredKey(t *testing.T) {
	root := make([]byte, 32)
	for i := range root {
		root[i] = byte(i)
	}
	encoded, err := formatRecoveredKey(escrow.KeyTypeRoot, root)
	if err != nil {
		t.Fatalf("format root: %v", err)
	}
	decoded, err := hex.DecodeString(string(encoded[:len(encoded)-1]))
	if err != nil || string(decoded) != string(root) {
		t.Fatalf("root output is not reusable: decoded=%x err=%v", decoded, err)
	}

	orgKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	keyBytes := crypto.MarshalECPrivateKey(orgKey)
	pemBytes, err := formatRecoveredKey(escrow.KeyTypeOrgCA, keyBytes)
	if err != nil {
		t.Fatalf("format org key: %v", err)
	}
	if len(pemBytes) == 0 {
		t.Fatal("org key PEM is empty")
	}
}
