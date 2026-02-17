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

// CreateOrgIntermediateCA creates an org-level intermediate CA certificate
// signed by the root CA. This CA has IsCA:true and MaxPathLen:0, meaning
// it can sign end-entity (member) certificates but NOT further sub-CAs.
func CreateOrgIntermediateCA(
	orgID string,
	orgName string,
	rootCert *x509.Certificate,
	rootKey *ecdsa.PrivateKey,
	validFor time.Duration,
) (*x509.Certificate, *ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}

	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, nil, nil, err
	}

	orgIDExtValue, err := asn1.Marshal(orgID)
	if err != nil {
		return nil, nil, nil, err
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   orgName + " Intermediate CA",
			Organization: []string{"EnvSync"},
			OrganizationalUnit: []string{orgID},
		},
		NotBefore:             now,
		NotAfter:              now.Add(validFor),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,    // Cannot sign further CAs
		MaxPathLenZero:        true, // Explicitly zero
		ExtraExtensions: []pkix.Extension{
			{
				Id:    OIDOrgID,
				Value: orgIDExtValue,
			},
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, rootCert, &key.PublicKey, rootKey)
	if err != nil {
		return nil, nil, nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, nil, err
	}

	return cert, key, certDER, nil
}
