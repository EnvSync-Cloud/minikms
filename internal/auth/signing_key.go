package auth

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// LoadSessionSigningKey loads an ES256 private key from either an injected PEM
// value or a mounted secret file. Exactly one source must be configured.
func LoadSessionSigningKey(keyPEM, keyFile string) (*ecdsa.PrivateKey, error) {
	if keyPEM == "" && keyFile == "" {
		return nil, fmt.Errorf("session signing key is not configured")
	}
	if keyPEM != "" && keyFile != "" {
		return nil, fmt.Errorf("configure only one session signing key source")
	}

	keyData := []byte(keyPEM)
	if keyFile != "" {
		var err error
		keyData, err = os.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read session signing key file: %w", err)
		}
	}

	return parseSessionSigningKeyPEM(keyData)
}

func parseSessionSigningKeyPEM(keyData []byte) (*ecdsa.PrivateKey, error) {
	block, rest := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("session signing key must be PEM encoded")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("session signing key PEM contains trailing data")
	}

	var key *ecdsa.PrivateKey
	switch block.Type {
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("invalid PKCS#8 session signing key: %w", err)
		}
		var ok bool
		key, ok = parsed.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("session signing key must be an EC private key")
		}
	case "EC PRIVATE KEY":
		var err error
		key, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("invalid SEC1 session signing key: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported session signing key PEM type %q", block.Type)
	}

	if key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("session signing key must use the P-256 curve")
	}
	return key, nil
}
