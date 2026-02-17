package keys

import (
	"encoding/hex"
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
