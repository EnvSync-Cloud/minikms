package crypto

import (
	"bytes"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	tests := []struct {
		name      string
		plaintext []byte
		aad       []byte
	}{
		{"empty plaintext", []byte{}, []byte("ctx")},
		{"small plaintext", []byte("hello world"), []byte("org:app")},
		{"large plaintext", bytes.Repeat([]byte("x"), 1<<16), []byte("big")},
		{"with AAD", []byte("secret"), []byte("org1:app1:env:key")},
		{"nil AAD", []byte("secret"), nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ct, err := Encrypt(key, tt.plaintext, tt.aad)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			pt, err := Decrypt(key, ct, tt.aad)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if !bytes.Equal(pt, tt.plaintext) {
				t.Errorf("roundtrip mismatch: got %d bytes, want %d", len(pt), len(tt.plaintext))
			}
		})
	}
}

func TestEncryptDecrypt_WrongAAD(t *testing.T) {
	key, _ := GenerateKey()
	ct, err := Encrypt(key, []byte("data"), []byte("correct-aad"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	_, err = Decrypt(key, ct, []byte("wrong-aad"))
	if err == nil {
		t.Fatal("expected error decrypting with wrong AAD")
	}
}

func TestEncryptDecrypt_WrongKey(t *testing.T) {
	key1, _ := GenerateKey()
	key2, _ := GenerateKey()
	ct, err := Encrypt(key1, []byte("data"), nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	_, err = Decrypt(key2, ct, nil)
	if err == nil {
		t.Fatal("expected error decrypting with wrong key")
	}
}

func TestEncryptDecrypt_TamperedCiphertext(t *testing.T) {
	key, _ := GenerateKey()
	ct, err := Encrypt(key, []byte("data"), nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	ct[len(ct)-1] ^= 0xFF // flip last byte
	_, err = Decrypt(key, ct, nil)
	if err == nil {
		t.Fatal("expected error decrypting tampered ciphertext")
	}
}

func TestDecrypt_TruncatedCiphertext(t *testing.T) {
	key, _ := GenerateKey()
	// Too short: less than nonce + tag
	_, err := Decrypt(key, []byte("short"), nil)
	if err == nil {
		t.Fatal("expected error for truncated ciphertext")
	}
}

func TestEncrypt_InvalidKeySize(t *testing.T) {
	for _, size := range []int{16, 24, 31, 33} {
		t.Run("", func(t *testing.T) {
			key := make([]byte, size)
			_, err := Encrypt(key, []byte("data"), nil)
			if err == nil {
				t.Fatalf("expected error for key size %d", size)
			}
		})
	}
}

func TestDecrypt_InvalidKeySize(t *testing.T) {
	for _, size := range []int{16, 24, 31, 33} {
		t.Run("", func(t *testing.T) {
			key := make([]byte, size)
			_, err := Decrypt(key, make([]byte, 100), nil)
			if err == nil {
				t.Fatalf("expected error for key size %d", size)
			}
		})
	}
}

func TestGenerateKey(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if len(key) != AES256KeySize {
		t.Fatalf("key length: got %d, want %d", len(key), AES256KeySize)
	}

	// Uniqueness
	key2, _ := GenerateKey()
	if bytes.Equal(key, key2) {
		t.Fatal("two generated keys should not be equal")
	}
}

func TestEncrypt_NonceUniqueness(t *testing.T) {
	key, _ := GenerateKey()
	pt := []byte("same plaintext")

	ct1, _ := Encrypt(key, pt, nil)
	ct2, _ := Encrypt(key, pt, nil)

	if bytes.Equal(ct1, ct2) {
		t.Fatal("same plaintext+key should produce different ciphertext due to random nonce")
	}
}
