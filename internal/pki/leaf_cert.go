package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

func leafValidity(ttl time.Duration) time.Duration {
	if ttl <= 0 {
		return 90 * 24 * time.Hour
	}
	max := 825 * 24 * time.Hour
	if ttl > max {
		return max
	}
	return ttl
}

func splitSANs(sans []string) (dns []string, ips []net.IP, uris []*url.URL) {
	for _, raw := range sans {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		if ip := net.ParseIP(value); ip != nil {
			ips = append(ips, ip)
			continue
		}
		if strings.Contains(value, "://") {
			if parsed, err := url.Parse(value); err == nil && parsed.Scheme != "" && parsed.Host != "" {
				uris = append(uris, parsed)
				continue
			}
		}
		dns = append(dns, value)
	}
	return dns, ips, uris
}

func generateLeafKey(algorithm string) (crypto.Signer, error) {
	switch strings.ToUpper(strings.TrimSpace(algorithm)) {
	case "", "ECDSA_P256", "ECDSA-P256":
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "RSA_2048", "RSA-2048":
		return rsa.GenerateKey(rand.Reader, 2048)
	default:
		return nil, fmt.Errorf("unsupported key algorithm %q", algorithm)
	}
}

func marshalLeafPrivateKey(key crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// CreateLeafCertificate issues a server/client leaf signed by the org CA.
func CreateLeafCertificate(
	commonName string,
	dnsSans []string,
	orgCACert *x509.Certificate,
	orgCAKey *ecdsa.PrivateKey,
	validFor time.Duration,
	keyAlgorithm string,
	crlDistPoints []string,
) (*x509.Certificate, []byte, []byte, error) {
	key, err := generateLeafKey(keyAlgorithm)
	if err != nil {
		return nil, nil, nil, err
	}

	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, nil, nil, err
	}

	dns, ips, uris := splitSANs(dnsSans)
	if commonName != "" && net.ParseIP(commonName) == nil && !strings.Contains(commonName, "://") {
		found := false
		for _, name := range dns {
			if name == commonName {
				found = true
				break
			}
		}
		if !found {
			dns = append([]string{commonName}, dns...)
		}
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"EnvSync"},
		},
		DNSNames:              dns,
		IPAddresses:           ips,
		URIs:                  uris,
		NotBefore:             now,
		NotAfter:              now.Add(leafValidity(validFor)),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		CRLDistributionPoints: crlDistPoints,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, orgCACert, key.Public(), orgCAKey)
	if err != nil {
		return nil, nil, nil, err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, nil, err
	}
	keyPEM, err := marshalLeafPrivateKey(key)
	if err != nil {
		return nil, nil, nil, err
	}
	return cert, keyPEM, certDER, nil
}

// SignLeafCSR signs a client-generated CSR as a leaf (private key never here).
func SignLeafCSR(
	csrPEM string,
	orgCACert *x509.Certificate,
	orgCAKey *ecdsa.PrivateKey,
	validFor time.Duration,
	crlDistPoints []string,
) (*x509.Certificate, []byte, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return nil, nil, fmt.Errorf("csr pem is invalid")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, nil, err
	}

	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, nil, err
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               csr.Subject,
		DNSNames:              csr.DNSNames,
		IPAddresses:           csr.IPAddresses,
		EmailAddresses:        csr.EmailAddresses,
		URIs:                  csr.URIs,
		NotBefore:             now,
		NotAfter:              now.Add(leafValidity(validFor)),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		CRLDistributionPoints: crlDistPoints,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, orgCACert, csr.PublicKey, orgCAKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}
	return cert, certDER, nil
}
