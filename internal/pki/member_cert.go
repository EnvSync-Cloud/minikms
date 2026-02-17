package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"time"
)

// CreateMemberCertificate creates an end-entity member certificate signed by
// the org intermediate CA. This is NOT a CA certificate (IsCA:false).
// Renamed from "sub-CA" per Issue #3 — these are end-entity member certificates.
func CreateMemberCertificate(
	memberID string,
	memberEmail string,
	orgID string,
	role string,
	orgCACert *x509.Certificate,
	orgCAKey *ecdsa.PrivateKey,
	validFor time.Duration,
	crlDistPoints []string,
) (*x509.Certificate, *ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}

	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, nil, nil, err
	}

	memberIDExt, err := asn1.Marshal(memberID)
	if err != nil {
		return nil, nil, nil, err
	}

	roleExt, err := asn1.Marshal(role)
	if err != nil {
		return nil, nil, nil, err
	}

	orgIDExt, err := asn1.Marshal(orgID)
	if err != nil {
		return nil, nil, nil, err
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   memberEmail,
			Organization: []string{"EnvSync"},
		},
		NotBefore:             now,
		NotAfter:              now.Add(validFor),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false, // End-entity certificate, NOT a CA
		CRLDistributionPoints: crlDistPoints,
		ExtraExtensions: []pkix.Extension{
			{Id: OIDMemberID, Value: memberIDExt},
			{Id: OIDOrgID, Value: orgIDExt},
			{Id: OIDRole, Value: roleExt},
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, orgCACert, &key.PublicKey, orgCAKey)
	if err != nil {
		return nil, nil, nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, nil, err
	}

	return cert, key, certDER, nil
}
