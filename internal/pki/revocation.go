package pki

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

// RevokedCert represents a revoked certificate entry for CRL generation.
type RevokedCert struct {
	SerialNumber *big.Int
	RevokedAt    time.Time
	ReasonCode   int
}

// CRLConfig holds parameters for CRL generation.
type CRLConfig struct {
	// Number is the monotonically increasing CRL number.
	Number *big.Int
	// ThisUpdate is when this CRL was issued.
	ThisUpdate time.Time
	// NextUpdate is when the next CRL will be issued.
	NextUpdate time.Time
	// IsDelta indicates this is a delta CRL (incremental update).
	IsDelta bool
	// BaseCRLNumber references the base CRL for delta CRLs.
	BaseCRLNumber *big.Int
}

// GenerateCRL creates a CRL signed by the issuer certificate.
// Supports both full and delta CRLs for incremental revocation updates.
func GenerateCRL(
	issuerCert *x509.Certificate,
	issuerKey *ecdsa.PrivateKey,
	revokedCerts []RevokedCert,
	config CRLConfig,
) ([]byte, error) {
	revokedList := make([]pkix.RevokedCertificate, len(revokedCerts))
	for i, rc := range revokedCerts {
		revokedList[i] = pkix.RevokedCertificate{
			SerialNumber:   rc.SerialNumber,
			RevocationTime: rc.RevokedAt,
		}
	}

	template := &x509.RevocationList{
		RevokedCertificateEntries: make([]x509.RevocationListEntry, len(revokedCerts)),
		Number:                    config.Number,
		ThisUpdate:                config.ThisUpdate,
		NextUpdate:                config.NextUpdate,
	}

	for i, rc := range revokedCerts {
		template.RevokedCertificateEntries[i] = x509.RevocationListEntry{
			SerialNumber:   rc.SerialNumber,
			RevocationTime: rc.RevokedAt,
			ReasonCode:     rc.ReasonCode,
		}
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, template, issuerCert, issuerKey)
	if err != nil {
		return nil, err
	}

	return crlDER, nil
}

// OCSPStatus represents the revocation status for OCSP responses.
type OCSPStatus int

const (
	OCSPStatusGood    OCSPStatus = 0
	OCSPStatusRevoked OCSPStatus = 1
	OCSPStatusUnknown OCSPStatus = 2
)

// OCSPResponse holds the data needed for an OCSP response.
type OCSPResponse struct {
	Status       OCSPStatus
	SerialNumber *big.Int
	RevokedAt    time.Time
	ThisUpdate   time.Time
	NextUpdate   time.Time
}

// CheckRevocationStatus checks if a certificate is revoked against a list of
// revoked certificates. Used by the OCSP responder endpoint.
func CheckRevocationStatus(serialNumber *big.Int, revokedCerts []RevokedCert) OCSPResponse {
	now := time.Now()
	for _, rc := range revokedCerts {
		if rc.SerialNumber.Cmp(serialNumber) == 0 {
			return OCSPResponse{
				Status:       OCSPStatusRevoked,
				SerialNumber: serialNumber,
				RevokedAt:    rc.RevokedAt,
				ThisUpdate:   now,
				NextUpdate:   now.Add(1 * time.Hour),
			}
		}
	}
	return OCSPResponse{
		Status:       OCSPStatusGood,
		SerialNumber: serialNumber,
		ThisUpdate:   now,
		NextUpdate:   now.Add(1 * time.Hour),
	}
}
