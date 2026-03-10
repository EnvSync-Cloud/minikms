package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func TestECIESEncryptDecrypt_P384(t *testing.T) {
	// Generate P-384 keypair (used for Org CA)
	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	plaintext := []byte("hello, zero-trust world!")
	salt := "envsync-ecies-v1"
	info := "org-123"
	aad := []byte("org-123")

	// Encrypt
	ciphertext, err := ECIESEncrypt(&privKey.PublicKey, plaintext, salt, info, aad)
	if err != nil {
		t.Fatalf("ECIESEncrypt failed: %v", err)
	}

	if len(ciphertext) <= P384PubKeySize {
		t.Fatalf("ciphertext too short: %d", len(ciphertext))
	}

	// Decrypt
	decrypted, err := ECIESDecrypt(privKey, ciphertext, salt, info, aad)
	if err != nil {
		t.Fatalf("ECIESDecrypt failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Fatalf("decrypted text mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestECIESEncryptDecrypt_LargePayload(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Test with a larger payload (e.g., a full secret value)
	plaintext := make([]byte, 4096)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatalf("failed to generate random plaintext: %v", err)
	}

	ciphertext, err := ECIESEncrypt(&privKey.PublicKey, plaintext, "salt", "info", nil)
	if err != nil {
		t.Fatalf("ECIESEncrypt failed: %v", err)
	}

	decrypted, err := ECIESDecrypt(privKey, ciphertext, "salt", "info", nil)
	if err != nil {
		t.Fatalf("ECIESDecrypt failed: %v", err)
	}

	if len(decrypted) != len(plaintext) {
		t.Fatalf("length mismatch: got %d, want %d", len(decrypted), len(plaintext))
	}
	for i := range plaintext {
		if decrypted[i] != plaintext[i] {
			t.Fatalf("byte mismatch at index %d", i)
		}
	}
}

func TestECIESDecrypt_WrongKey(t *testing.T) {
	privKey1, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	privKey2, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)

	plaintext := []byte("secret data")

	ciphertext, err := ECIESEncrypt(&privKey1.PublicKey, plaintext, "salt", "info", nil)
	if err != nil {
		t.Fatalf("ECIESEncrypt failed: %v", err)
	}

	// Try to decrypt with wrong key
	_, err = ECIESDecrypt(privKey2, ciphertext, "salt", "info", nil)
	if err == nil {
		t.Fatal("expected decryption to fail with wrong key")
	}
}

func TestECIESDecrypt_WrongAAD(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)

	plaintext := []byte("secret data")
	ciphertext, err := ECIESEncrypt(&privKey.PublicKey, plaintext, "salt", "info", []byte("aad1"))
	if err != nil {
		t.Fatalf("ECIESEncrypt failed: %v", err)
	}

	// Try to decrypt with wrong AAD
	_, err = ECIESDecrypt(privKey, ciphertext, "salt", "info", []byte("aad2"))
	if err == nil {
		t.Fatal("expected decryption to fail with wrong AAD")
	}
}

func TestWrapUnwrapKeyForMember(t *testing.T) {
	// Generate member key (P-256) and Org CA key (P-384)
	memberKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate member key: %v", err)
	}

	orgCAKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Org CA key: %v", err)
	}

	// Marshal the Org CA private key
	orgCAPrivBytes := MarshalECPrivateKey(orgCAKey)

	// Wrap
	ephPub, wrappedKey, err := WrapKeyForMember(&memberKey.PublicKey, orgCAPrivBytes)
	if err != nil {
		t.Fatalf("WrapKeyForMember failed: %v", err)
	}

	if len(ephPub) == 0 {
		t.Fatal("ephemeral pub key is empty")
	}
	if len(wrappedKey) == 0 {
		t.Fatal("wrapped key is empty")
	}

	// Unwrap
	unwrapped, err := UnwrapKeyForMember(memberKey, ephPub, wrappedKey)
	if err != nil {
		t.Fatalf("UnwrapKeyForMember failed: %v", err)
	}

	// Verify the unwrapped key matches
	if len(unwrapped) != len(orgCAPrivBytes) {
		t.Fatalf("key length mismatch: got %d, want %d", len(unwrapped), len(orgCAPrivBytes))
	}
	for i := range orgCAPrivBytes {
		if unwrapped[i] != orgCAPrivBytes[i] {
			t.Fatalf("key byte mismatch at index %d", i)
		}
	}
}

func TestWrapUnwrapKeyForMember_WrongKey(t *testing.T) {
	memberKey1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	memberKey2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	orgCAKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)

	orgCAPrivBytes := MarshalECPrivateKey(orgCAKey)

	ephPub, wrappedKey, err := WrapKeyForMember(&memberKey1.PublicKey, orgCAPrivBytes)
	if err != nil {
		t.Fatalf("WrapKeyForMember failed: %v", err)
	}

	// Try to unwrap with wrong member key
	_, err = UnwrapKeyForMember(memberKey2, ephPub, wrappedKey)
	if err == nil {
		t.Fatal("expected unwrap to fail with wrong key")
	}
}

func TestMarshalUnmarshalECPrivateKey_P256(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	data := MarshalECPrivateKey(key)
	recovered, err := UnmarshalECPrivateKey(data)
	if err != nil {
		t.Fatalf("UnmarshalECPrivateKey failed: %v", err)
	}

	if recovered.D.Cmp(key.D) != 0 {
		t.Fatal("recovered key D doesn't match")
	}
	if recovered.PublicKey.X.Cmp(key.PublicKey.X) != 0 {
		t.Fatal("recovered key X doesn't match")
	}
	if recovered.PublicKey.Y.Cmp(key.PublicKey.Y) != 0 {
		t.Fatal("recovered key Y doesn't match")
	}
}

func TestMarshalUnmarshalECPrivateKey_P384(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	data := MarshalECPrivateKey(key)
	recovered, err := UnmarshalECPrivateKey(data)
	if err != nil {
		t.Fatalf("UnmarshalECPrivateKey failed: %v", err)
	}

	if recovered.D.Cmp(key.D) != 0 {
		t.Fatal("recovered key D doesn't match")
	}
	if recovered.PublicKey.X.Cmp(key.PublicKey.X) != 0 {
		t.Fatal("recovered key X doesn't match")
	}
}

func TestECIESEndToEndWithWrapping(t *testing.T) {
	// Simulate the full zero-trust flow:
	// 1. Generate Org CA (P-384)
	// 2. Generate member key (P-256)
	// 3. Wrap Org CA key for member
	// 4. Encrypt data with ECIES using Org CA public key
	// 5. Unwrap Org CA key using member key
	// 6. Decrypt data with ECIES using recovered Org CA private key

	orgCAKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	memberKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Step 3: Wrap
	orgCAPrivBytes := MarshalECPrivateKey(orgCAKey)
	ephPub, wrappedKey, err := WrapKeyForMember(&memberKey.PublicKey, orgCAPrivBytes)
	if err != nil {
		t.Fatalf("wrap failed: %v", err)
	}

	// Step 4: Encrypt (Layer 2: ECIES)
	plaintext := []byte("RSA:encrypted-secret-value")
	eciesOutput, err := ECIESEncrypt(&orgCAKey.PublicKey, plaintext, "envsync-ecies-v1", "org-123", []byte("org-123"))
	if err != nil {
		t.Fatalf("ECIES encrypt failed: %v", err)
	}

	// Step 5: Unwrap
	unwrappedBytes, err := UnwrapKeyForMember(memberKey, ephPub, wrappedKey)
	if err != nil {
		t.Fatalf("unwrap failed: %v", err)
	}

	recoveredOrgCA, err := UnmarshalECPrivateKey(unwrappedBytes)
	if err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	// Step 6: Decrypt (Layer 2: ECIES)
	decrypted, err := ECIESDecrypt(recoveredOrgCA, eciesOutput, "envsync-ecies-v1", "org-123", []byte("org-123"))
	if err != nil {
		t.Fatalf("ECIES decrypt failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Fatalf("decrypted text mismatch: got %q, want %q", decrypted, plaintext)
	}
}
