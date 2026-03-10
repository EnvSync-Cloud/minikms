package crypto

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"math/big"

	"golang.org/x/crypto/hkdf"
)

// P384PubKeySize is the uncompressed P-384 public key size (1 + 48 + 48 = 97 bytes).
const P384PubKeySize = 97

// ECIESEncrypt performs ECIES encryption using the recipient's P-384 public key.
// It generates an ephemeral P-384 keypair, performs ECDH, derives a wrapping key
// via HKDF, and encrypts the plaintext with AES-256-GCM.
//
// Output format: ephemeral_pub_bytes (97) || AES-256-GCM ciphertext (nonce || ct || tag)
//
// The salt parameter is used for HKDF domain separation (e.g., "envsync-ecies-v1").
// The info parameter provides additional context binding (e.g., org_id).
// The aad parameter is passed to AES-256-GCM as additional authenticated data.
func ECIESEncrypt(recipientPub *ecdsa.PublicKey, plaintext []byte, salt, info string, aad []byte) ([]byte, error) {
	if recipientPub.Curve != elliptic.P384() {
		return nil, fmt.Errorf("recipient public key must be P-384")
	}

	// Generate ephemeral P-384 keypair
	ephPriv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	// Perform ECDH
	sharedSecret, err := ecdhSharedSecret(ephPriv, recipientPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %w", err)
	}
	defer zeroize(sharedSecret)

	// Derive wrapping key via HKDF-SHA256
	wrappingKey, err := deriveHKDF(sharedSecret, salt, info)
	if err != nil {
		return nil, fmt.Errorf("HKDF derivation failed: %w", err)
	}
	defer zeroize(wrappingKey)

	// Encrypt with AES-256-GCM
	ciphertext, err := Encrypt(wrappingKey, plaintext, aad)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM encrypt failed: %w", err)
	}

	// Serialize ephemeral public key (uncompressed)
	ephPubBytes, err := marshalECPublicKey(&ephPriv.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ephemeral public key: %w", err)
	}

	// Zeroize ephemeral private key
	// Note: Go's ecdsa.PrivateKey doesn't expose raw bytes easily,
	// but the key will be garbage collected
	_ = ephPriv

	// Output: ephemeral_pub || ciphertext
	output := make([]byte, len(ephPubBytes)+len(ciphertext))
	copy(output, ephPubBytes)
	copy(output[len(ephPubBytes):], ciphertext)

	return output, nil
}

// ECIESDecrypt performs ECIES decryption using the recipient's P-384 private key.
// It extracts the ephemeral public key, performs ECDH, derives the wrapping key,
// and decrypts the ciphertext.
//
// Input format: ephemeral_pub_bytes (97) || AES-256-GCM ciphertext
func ECIESDecrypt(recipientPriv *ecdsa.PrivateKey, ciphertext []byte, salt, info string, aad []byte) ([]byte, error) {
	if recipientPriv.Curve != elliptic.P384() {
		return nil, fmt.Errorf("recipient private key must be P-384")
	}

	if len(ciphertext) < P384PubKeySize+GCMNonceSize+GCMTagSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Extract ephemeral public key
	ephPubBytes := ciphertext[:P384PubKeySize]
	encryptedData := ciphertext[P384PubKeySize:]

	ephPub, err := unmarshalECPublicKey(elliptic.P384(), ephPubBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid ephemeral public key: %w", err)
	}

	// Perform ECDH
	sharedSecret, err := ecdhSharedSecret(recipientPriv, ephPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %w", err)
	}
	defer zeroize(sharedSecret)

	// Derive wrapping key via HKDF-SHA256
	wrappingKey, err := deriveHKDF(sharedSecret, salt, info)
	if err != nil {
		return nil, fmt.Errorf("HKDF derivation failed: %w", err)
	}
	defer zeroize(wrappingKey)

	// Decrypt with AES-256-GCM
	plaintext, err := Decrypt(wrappingKey, encryptedData, aad)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM decrypt failed: %w", err)
	}

	return plaintext, nil
}

// WrapKeyForMember wraps the Org CA private key for a specific member using ECDH.
// This creates a per-member wrapped copy that only that member can unwrap.
// The ephemeral key is generated on the same curve as the member's public key
// to ensure ECDH compatibility.
//
// Returns: (ephemeral_pub_bytes, wrapped_key, error)
func WrapKeyForMember(memberPub *ecdsa.PublicKey, orgCAPrivKeyBytes []byte) (ephemeralPub []byte, wrappedKey []byte, err error) {
	// Generate ephemeral keypair on the SAME curve as the member key
	ephPriv, err := ecdsa.GenerateKey(memberPub.Curve, rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	sharedSecret, err := ecdhSharedSecret(ephPriv, memberPub)
	if err != nil {
		return nil, nil, fmt.Errorf("ECDH failed: %w", err)
	}
	defer zeroize(sharedSecret)

	// Derive wrapping key
	wrappingKeyBytes, err := deriveHKDF(sharedSecret, "envsync-orgca-wrap-v1", "")
	if err != nil {
		return nil, nil, fmt.Errorf("HKDF failed: %w", err)
	}
	defer zeroize(wrappingKeyBytes)

	// Wrap the Org CA private key with AES-256-GCM
	wrappedKey, err = Encrypt(wrappingKeyBytes, orgCAPrivKeyBytes, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("wrap failed: %w", err)
	}

	// Serialize ephemeral public key
	ephPubBytes, err := marshalECPublicKey(&ephPriv.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal ephemeral public key: %w", err)
	}

	return ephPubBytes, wrappedKey, nil
}

// UnwrapKeyForMember unwraps the Org CA private key using the member's private key
// and the stored ephemeral public key.
func UnwrapKeyForMember(memberPriv *ecdsa.PrivateKey, ephemeralPub []byte, wrappedKey []byte) ([]byte, error) {
	// Parse ephemeral public key — use the member's curve (ephemeral was generated on same curve)
	ephPub, err := unmarshalECPublicKey(memberPriv.Curve, ephemeralPub)
	if err != nil {
		// Fallback: try other curves
		for _, c := range []elliptic.Curve{elliptic.P256(), elliptic.P384()} {
			ephPub, err = unmarshalECPublicKey(c, ephemeralPub)
			if err == nil {
				break
			}
		}
		if err != nil {
			return nil, fmt.Errorf("invalid ephemeral public key")
		}
	}

	// Perform ECDH
	sharedSecret, err := ecdhSharedSecret(memberPriv, ephPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %w", err)
	}
	defer zeroize(sharedSecret)

	// Derive wrapping key
	wrappingKeyBytes, err := deriveHKDF(sharedSecret, "envsync-orgca-wrap-v1", "")
	if err != nil {
		return nil, fmt.Errorf("HKDF failed: %w", err)
	}
	defer zeroize(wrappingKeyBytes)

	// Unwrap the Org CA private key
	orgCAPrivBytes, err := Decrypt(wrappingKeyBytes, wrappedKey, nil)
	if err != nil {
		return nil, fmt.Errorf("unwrap failed: %w", err)
	}

	return orgCAPrivBytes, nil
}

// ecdhSharedSecret computes a shared secret using ECDH.
func ecdhSharedSecret(priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey) ([]byte, error) {
	pubCurve, err := ecdhCurveFromElliptic(pub.Curve)
	if err != nil {
		return nil, fmt.Errorf("unsupported public key curve")
	}

	// Convert keys to crypto/ecdh types
	ecdhPriv, err := priv.ECDH()
	if err != nil {
		return nil, fmt.Errorf("failed to convert private key: %w", err)
	}

	pubBytes, err := marshalECPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}
	ecdhPub, err := pubCurve.NewPublicKey(pubBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to convert public key: %w", err)
	}

	shared, err := ecdhPriv.ECDH(ecdhPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %w", err)
	}

	return shared, nil
}

// ecdhCurveFromElliptic maps an elliptic.Curve to a crypto/ecdh.Curve.
func ecdhCurveFromElliptic(c elliptic.Curve) (ecdh.Curve, error) {
	switch c {
	case elliptic.P256():
		return ecdh.P256(), nil
	case elliptic.P384():
		return ecdh.P384(), nil
	default:
		return nil, fmt.Errorf("unsupported curve")
	}
}

// marshalECPublicKey serializes an ECDSA public key to uncompressed point format
// using crypto/ecdh, avoiding the deprecated elliptic.Marshal.
func marshalECPublicKey(pub *ecdsa.PublicKey) ([]byte, error) {
	ecdhPub, err := pub.ECDH()
	if err != nil {
		return nil, fmt.Errorf("failed to convert to ECDH public key: %w", err)
	}
	return ecdhPub.Bytes(), nil
}

// unmarshalECPublicKey parses an uncompressed point into an ecdsa.PublicKey,
// using crypto/ecdh for validation instead of the deprecated elliptic.Unmarshal.
func unmarshalECPublicKey(curve elliptic.Curve, data []byte) (*ecdsa.PublicKey, error) {
	ecdhCurve, err := ecdhCurveFromElliptic(curve)
	if err != nil {
		return nil, err
	}

	// Validate the point using crypto/ecdh
	ecdhPub, err := ecdhCurve.NewPublicKey(data)
	if err != nil {
		return nil, fmt.Errorf("invalid public key point: %w", err)
	}

	// Parse X, Y from uncompressed format: 0x04 || X || Y
	raw := ecdhPub.Bytes()
	if len(raw) < 3 || raw[0] != 0x04 {
		return nil, fmt.Errorf("unexpected public key format")
	}
	byteLen := (len(raw) - 1) / 2
	x := new(big.Int).SetBytes(raw[1 : 1+byteLen])
	y := new(big.Int).SetBytes(raw[1+byteLen:])

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

// deriveHKDF derives a 32-byte AES-256 key from a shared secret using HKDF-SHA256.
func deriveHKDF(sharedSecret []byte, salt, info string) ([]byte, error) {
	var saltBytes []byte
	if salt != "" {
		saltBytes = []byte(salt)
	}

	var infoBytes []byte
	if info != "" {
		infoBytes = []byte(info)
	}

	h := hkdf.New(sha256.New, sharedSecret, saltBytes, infoBytes)
	key := make([]byte, AES256KeySize)
	if _, err := io.ReadFull(h, key); err != nil {
		return nil, fmt.Errorf("HKDF derivation failed: %w", err)
	}
	return key, nil
}

// MarshalECPrivateKey serializes an ECDSA private key to raw bytes.
// Format: curve_id (1 byte) || D (padded to curve byte length)
func MarshalECPrivateKey(key *ecdsa.PrivateKey) []byte {
	byteLen := (key.Curve.Params().BitSize + 7) / 8
	var curveID byte
	switch key.Curve {
	case elliptic.P256():
		curveID = 1
	case elliptic.P384():
		curveID = 2
	default:
		curveID = 0
	}
	result := make([]byte, 1+byteLen)
	result[0] = curveID
	key.D.FillBytes(result[1:])
	return result
}

// UnmarshalECPrivateKey deserializes an ECDSA private key from raw bytes.
func UnmarshalECPrivateKey(data []byte) (*ecdsa.PrivateKey, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("data too short")
	}

	curveID := data[0]
	var curve elliptic.Curve
	switch curveID {
	case 1:
		curve = elliptic.P256()
	case 2:
		curve = elliptic.P384()
	default:
		return nil, fmt.Errorf("unsupported curve ID: %d", curveID)
	}

	byteLen := (curve.Params().BitSize + 7) / 8
	if len(data) != 1+byteLen {
		return nil, fmt.Errorf("invalid key length: expected %d, got %d", 1+byteLen, len(data))
	}

	d := new(big.Int).SetBytes(data[1:])
	key := new(ecdsa.PrivateKey)
	key.PublicKey.Curve = curve
	key.D = d
	key.PublicKey.X, key.PublicKey.Y = curve.ScalarBaseMult(d.Bytes())

	return key, nil
}

// zeroize overwrites a byte slice with zeros (unexported for internal use).
func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ZeroizeBytes overwrites a byte slice with zeros (exported for cross-package use).
func ZeroizeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
