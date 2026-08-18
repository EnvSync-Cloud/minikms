package pki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// LoadRootCA validates a shared root CA certificate and private key. Every
// replica must receive the same pair from a durable secret source.
func LoadRootCA(certPEM, keyPEM []byte) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certBlock, certRest := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("root CA certificate must be PEM encoded")
	}
	if len(bytes.TrimSpace(certRest)) != 0 {
		return nil, nil, fmt.Errorf("root CA certificate PEM contains trailing data")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse root CA certificate: %w", err)
	}
	if !cert.IsCA || !cert.BasicConstraintsValid {
		return nil, nil, fmt.Errorf("root CA certificate is not a valid CA")
	}
	if err := cert.CheckSignatureFrom(cert); err != nil {
		return nil, nil, fmt.Errorf("root CA certificate is not self-signed: %w", err)
	}

	keyBlock, keyRest := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("root CA private key must be PEM encoded")
	}
	if len(bytes.TrimSpace(keyRest)) != 0 {
		return nil, nil, fmt.Errorf("root CA private key PEM contains trailing data")
	}

	var key *ecdsa.PrivateKey
	switch keyBlock.Type {
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(keyBlock.Bytes)
	case "PRIVATE KEY":
		var parsed any
		parsed, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err == nil {
			var ok bool
			key, ok = parsed.(*ecdsa.PrivateKey)
			if !ok {
				return nil, nil, fmt.Errorf("root CA private key must be an EC key")
			}
		}
	default:
		return nil, nil, fmt.Errorf("unsupported root CA private key PEM type %q", keyBlock.Type)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("parse root CA private key: %w", err)
	}
	if key.Curve != elliptic.P384() {
		return nil, nil, fmt.Errorf("root CA private key must use the P-384 curve")
	}

	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return nil, nil, fmt.Errorf("root CA certificate and private key do not match")
	}

	return cert, key, nil
}

// CreateRootCA generates a self-signed root CA certificate and key pair.
func CreateRootCA(commonName string, validFor time.Duration) (*x509.Certificate, *ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}

	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, nil, nil, err
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"EnvSync"},
		},
		NotBefore:             now,
		NotAfter:              now.Add(validFor),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1, // Allow one level of intermediate CAs
		MaxPathLenZero:        false,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, nil, err
	}

	return cert, key, certDER, nil
}

func generateSerialNumber() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, serialNumberLimit)
}
