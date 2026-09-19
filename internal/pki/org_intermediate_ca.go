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

// CreateOrgIntermediateCA creates an org-level intermediate CA signed by the
// root. MaxPathLen is 1 so the org CA can sign environment issuing CAs.
func CreateOrgIntermediateCA(
	orgID string,
	orgName string,
	rootCert *x509.Certificate,
	rootKey *ecdsa.PrivateKey,
	validFor time.Duration,
) (*x509.Certificate, *ecdsa.PrivateKey, []byte, error) {
	return createIntermediateCA(orgID, orgName+" Intermediate CA", rootCert, rootKey, validFor, 1)
}

// CreateEnvIntermediateCA creates an environment issuing CA signed by the org CA.
// MaxPathLen is 0: it can sign leaves only.
func CreateEnvIntermediateCA(
	orgID string,
	envID string,
	name string,
	orgCert *x509.Certificate,
	orgKey *ecdsa.PrivateKey,
	validFor time.Duration,
) (*x509.Certificate, *ecdsa.PrivateKey, []byte, error) {
	cn := name
	if cn == "" {
		cn = envID + " Environment CA"
	}
	return createIntermediateCA(orgID+":"+envID, cn, orgCert, orgKey, validFor, 0)
}

func createIntermediateCA(
	orgID string,
	commonName string,
	parentCert *x509.Certificate,
	parentKey *ecdsa.PrivateKey,
	validFor time.Duration,
	maxPathLen int,
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
			CommonName:         commonName,
			Organization:       []string{"EnvSync"},
			OrganizationalUnit: []string{orgID},
		},
		NotBefore:             now,
		NotAfter:              now.Add(validFor),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            maxPathLen,
		MaxPathLenZero:        maxPathLen == 0,
		ExtraExtensions: []pkix.Extension{
			{
				Id:    OIDOrgID,
				Value: orgIDExtValue,
			},
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, parentCert, &key.PublicKey, parentKey)
	if err != nil {
		return nil, nil, nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, nil, err
	}

	return cert, key, certDER, nil
}
