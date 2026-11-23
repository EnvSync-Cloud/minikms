package memberkey

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/envsync-cloud/minikms/internal/crypto"
)

const testRootKeyHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestLoadRootKey(t *testing.T) {
	mgr, err := LoadRootKey(testRootKeyHex, "")
	if err != nil {
		t.Fatalf("LoadRootKey: %v", err)
	}
	key, err := mgr.DeriveOrgKey("org-a")
	if err != nil || len(key) != 32 {
		t.Fatalf("derive len=%d err=%v", len(key), err)
	}
	crypto.ZeroizeBytes(key)

	if _, err := LoadRootKey("", ""); err == nil {
		t.Fatal("accepted a missing root key")
	}
	if _, err := LoadRootKey(testRootKeyHex, "also-set"); err == nil {
		t.Fatal("accepted two root key sources")
	}

	path := filepath.Join(t.TempDir(), "root.key")
	if err := os.WriteFile(path, []byte(testRootKeyHex+"\n"), 0o600); err != nil {
		t.Fatalf("write root key file: %v", err)
	}
	fromFile, err := LoadRootKey("", path)
	if err != nil {
		t.Fatalf("LoadRootKey file: %v", err)
	}
	fileKey, err := fromFile.DeriveOrgKey("org-a")
	if err != nil || len(fileKey) != 32 {
		t.Fatalf("file derive len=%d err=%v", len(fileKey), err)
	}
	crypto.ZeroizeBytes(fileKey)

	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if _, err := LoadRootKey("", path); err == nil {
		t.Fatal("accepted a root key file that is accessible by other users")
	}
}
