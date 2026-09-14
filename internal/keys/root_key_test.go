package keys

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestRootKeyHolder_Load(t *testing.T) {
	validHex := hex.EncodeToString(make([]byte, 32))

	t.Run("valid load", func(t *testing.T) {
		h := NewRootKeyHolder()
		err := h.Load(validHex)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
	})

	t.Run("invalid hex", func(t *testing.T) {
		h := NewRootKeyHolder()
		err := h.Load("not-hex")
		if err == nil {
			t.Fatal("expected error for invalid hex")
		}
	})

	t.Run("wrong length", func(t *testing.T) {
		h := NewRootKeyHolder()
		shortHex := hex.EncodeToString(make([]byte, 16))
		err := h.Load(shortHex)
		if err == nil {
			t.Fatal("expected error for wrong key length")
		}
	})

	t.Run("double load error", func(t *testing.T) {
		h := NewRootKeyHolder()
		_ = h.Load(validHex)
		err := h.Load(validHex)
		if err == nil {
			t.Fatal("expected error for double load")
		}
	})
}

func TestRootKeyHolder_GetKey(t *testing.T) {
	validHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	t.Run("returns copy", func(t *testing.T) {
		h := NewRootKeyHolder()
		_ = h.Load(validHex)
		key1, err := h.GetKey()
		if err != nil {
			t.Fatalf("GetKey: %v", err)
		}
		key2, _ := h.GetKey()

		// Mutate key1 and verify key2 is unaffected
		key1[0] = 0xFF
		if key2[0] == 0xFF {
			t.Fatal("GetKey should return a copy, not a reference")
		}
	})

	t.Run("not loaded error", func(t *testing.T) {
		h := NewRootKeyHolder()
		_, err := h.GetKey()
		if err == nil {
			t.Fatal("expected error when key not loaded")
		}
	})

	t.Run("correct key bytes", func(t *testing.T) {
		h := NewRootKeyHolder()
		_ = h.Load(validHex)
		key, _ := h.GetKey()
		if len(key) != 32 {
			t.Fatalf("key length: got %d, want 32", len(key))
		}
		expected, _ := hex.DecodeString(validHex)
		for i := range key {
			if key[i] != expected[i] {
				t.Fatalf("key byte %d mismatch", i)
			}
		}
	})
}

func TestRootKeyHolder_IsLoaded(t *testing.T) {
	validHex := hex.EncodeToString(make([]byte, 32))

	t.Run("before load", func(t *testing.T) {
		h := NewRootKeyHolder()
		if h.IsLoaded() {
			t.Fatal("should not be loaded before Load()")
		}
	})

	t.Run("after load", func(t *testing.T) {
		h := NewRootKeyHolder()
		_ = h.Load(validHex)
		if !h.IsLoaded() {
			t.Fatal("should be loaded after Load()")
		}
	})
}

func TestLoadRootKeyHex_ValueAndProtectedFile(t *testing.T) {
	value := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	got, err := LoadRootKeyHex(value, "")
	if err != nil || got != value {
		t.Fatalf("LoadRootKeyHex(value): got=%q err=%v", got, err)
	}

	path := filepath.Join(t.TempDir(), "recovered-root-key")
	if err := os.WriteFile(path, []byte(value+"\n"), 0o600); err != nil {
		t.Fatalf("write root key: %v", err)
	}
	got, err = LoadRootKeyHex("", path)
	if err != nil || got != value {
		t.Fatalf("LoadRootKeyHex(file): got=%q err=%v", got, err)
	}
	if err := os.Chmod(path, 0o440); err != nil {
		t.Fatalf("chmod group-readable: %v", err)
	}
	if _, err := LoadRootKeyHex("", path); err != nil {
		t.Fatalf("LoadRootKeyHex rejected a protected fsGroup-readable file: %v", err)
	}

	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if _, err := LoadRootKeyHex("", path); err == nil {
		t.Fatal("LoadRootKeyHex accepted a group/world-readable key file")
	}
	if _, err := LoadRootKeyHex(value, path); err == nil {
		t.Fatal("LoadRootKeyHex accepted two configured sources")
	}
	if _, err := LoadRootKeyHex("", ""); err == nil {
		t.Fatal("LoadRootKeyHex accepted no configured source")
	}
}
