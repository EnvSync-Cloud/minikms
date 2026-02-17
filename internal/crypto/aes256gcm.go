package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

const (
	// AES256KeySize is the key size for AES-256.
	AES256KeySize = 32
	// GCMNonceSize is the standard nonce size for AES-GCM.
	GCMNonceSize = 12
	// GCMTagSize is the authentication tag size for AES-GCM.
	GCMTagSize = 16
)

// Encrypt encrypts plaintext using AES-256-GCM with Additional Authenticated Data (AAD).
// AAD binds the ciphertext to its context (org_id:app_id:env_type_id:key_name).
// Returns nonce || ciphertext || tag.
func Encrypt(key, plaintext, aad []byte) ([]byte, error) {
	if len(key) != AES256KeySize {
		return nil, fmt.Errorf("key must be %d bytes, got %d", AES256KeySize, len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Seal appends ciphertext+tag to nonce
	ciphertext := gcm.Seal(nonce, nonce, plaintext, aad)
	return ciphertext, nil
}

// Decrypt decrypts ciphertext produced by Encrypt, validating the AAD binding.
// Input format: nonce || ciphertext || tag.
func Decrypt(key, ciphertext, aad []byte) ([]byte, error) {
	if len(key) != AES256KeySize {
		return nil, fmt.Errorf("key must be %d bytes, got %d", AES256KeySize, len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize+GCMTagSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, encrypted := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, encrypted, aad)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (AAD mismatch or tampered data): %w", err)
	}

	return plaintext, nil
}

// GenerateKey generates a cryptographically random AES-256 key.
func GenerateKey() ([]byte, error) {
	key := make([]byte, AES256KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}
	return key, nil
}
