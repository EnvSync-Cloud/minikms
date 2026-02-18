package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/envsync/minikms/internal/audit"
	"github.com/envsync/minikms/internal/pki"
)

// PKIService handles certificate lifecycle gRPC operations.
type PKIService struct {
	rootCert    *x509.Certificate
	rootKey     *ecdsa.PrivateKey
	auditLogger *audit.AuditLogger
	store       PKICertStore
}

// NewPKIService creates a new PKIService.
func NewPKIService(rootCert *x509.Certificate, rootKey *ecdsa.PrivateKey, auditLogger *audit.AuditLogger, store PKICertStore) *PKIService {
	return &PKIService{
		rootCert:    rootCert,
		rootKey:     rootKey,
		auditLogger: auditLogger,
		store:       store,
	}
}

// CreateOrgCARequest represents a request to create an org intermediate CA.
type CreateOrgCARequest struct {
	OrgID   string
	OrgName string
}

// CreateOrgCAResponse represents the result of creating an org CA.
type CreateOrgCAResponse struct {
	CertPEM    string
	SerialHex  string
}

// CreateOrgCAFull creates an org intermediate CA certificate and returns the
// parsed certificate and private key alongside the response. This is used by
// the gRPC adapter to cache the org CA for subsequent IssueMemberCert calls.
func (s *PKIService) CreateOrgCAFull(ctx context.Context, req *CreateOrgCARequest) (*CreateOrgCAResponse, *x509.Certificate, *ecdsa.PrivateKey, error) {
	cert, key, certDER, err := pki.CreateOrgIntermediateCA(
		req.OrgID, req.OrgName,
		s.rootCert, s.rootKey,
		10*365*24*time.Hour, // 10 year validity
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create org CA: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	serialHex := cert.SerialNumber.Text(16)

	// Persist to database
	if s.store != nil {
		_ = s.store.StoreCertificate(ctx, &PKICertRecord{
			SerialNumber: serialHex,
			CertType:     "org_intermediate_ca",
			OrgID:        req.OrgID,
			SubjectCN:    cert.Subject.CommonName,
			CertPEM:      string(certPEM),
			Status:       "active",
			IssuedAt:     cert.NotBefore,
			ExpiresAt:    cert.NotAfter,
		})
	}

	_ = s.auditLogger.Log(ctx, req.OrgID, "org_ca_created", "system",
		fmt.Sprintf("Org intermediate CA created for %s (serial: %s)", req.OrgName, serialHex), "")

	resp := &CreateOrgCAResponse{
		CertPEM:   string(certPEM),
		SerialHex: serialHex,
	}
	return resp, cert, key, nil
}

// CreateOrgCA creates an org intermediate CA certificate.
func (s *PKIService) CreateOrgCA(ctx context.Context, req *CreateOrgCARequest) (*CreateOrgCAResponse, error) {
	resp, _, _, err := s.CreateOrgCAFull(ctx, req)
	return resp, err
}

// RootCert returns the root CA certificate.
func (s *PKIService) RootCert() *x509.Certificate {
	return s.rootCert
}

// IssueMemberCertRequest represents a request to issue a member certificate.
type IssueMemberCertRequest struct {
	MemberID    string
	MemberEmail string
	OrgID       string
	Role        string
	OrgCACert   *x509.Certificate
	OrgCAKey    *ecdsa.PrivateKey
}

// IssueMemberCertResponse represents the result of issuing a member certificate.
type IssueMemberCertResponse struct {
	CertPEM    string
	KeyPEM     string
	SerialHex  string
}

// IssueMemberCert creates a member end-entity certificate.
func (s *PKIService) IssueMemberCert(ctx context.Context, req *IssueMemberCertRequest) (*IssueMemberCertResponse, error) {
	_, memberKey, certDER, err := pki.CreateMemberCertificate(
		req.MemberID, req.MemberEmail, req.OrgID, req.Role,
		req.OrgCACert, req.OrgCAKey,
		365*24*time.Hour, // 1 year validity
		nil,              // CRL distribution points
	)
	if err != nil {
		return nil, fmt.Errorf("failed to issue member cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(memberKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal member key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	cert, _ := x509.ParseCertificate(certDER)
	serialHex := cert.SerialNumber.Text(16)

	// Persist to database
	if s.store != nil {
		_ = s.store.StoreCertificate(ctx, &PKICertRecord{
			SerialNumber: serialHex,
			CertType:     "member",
			OrgID:        req.OrgID,
			SubjectCN:    req.MemberEmail,
			CertPEM:      string(certPEM),
			Status:       "active",
			IssuedAt:     cert.NotBefore,
			ExpiresAt:    cert.NotAfter,
		})
	}

	_ = s.auditLogger.Log(ctx, req.OrgID, "member_cert_issued", req.MemberID,
		fmt.Sprintf("Member certificate issued for %s", req.MemberEmail), "")

	return &IssueMemberCertResponse{
		CertPEM:   string(certPEM),
		KeyPEM:    string(keyPEM),
		SerialHex: serialHex,
	}, nil
}

// --- Revocation, CRL, and OCSP ---

// RevokeCertRequest represents a request to revoke a certificate.
type RevokeCertRequest struct {
	SerialHex string
	OrgID     string
	Reason    int
}

// RevokeCert marks a certificate as revoked and creates a CRL entry.
func (s *PKIService) RevokeCert(ctx context.Context, req *RevokeCertRequest) error {
	if s.store == nil {
		return fmt.Errorf("certificate store not configured")
	}

	// Verify the cert exists and belongs to this org
	cert, err := s.store.GetCertificateBySerial(ctx, req.SerialHex)
	if err != nil {
		return fmt.Errorf("failed to look up certificate: %w", err)
	}
	if cert == nil {
		return fmt.Errorf("certificate %s not found", req.SerialHex)
	}
	if cert.OrgID != req.OrgID {
		return fmt.Errorf("certificate %s does not belong to org %s", req.SerialHex, req.OrgID)
	}
	if cert.Status == "revoked" {
		return fmt.Errorf("certificate %s is already revoked", req.SerialHex)
	}

	// Find the org CA (issuer)
	orgCA, err := s.store.GetOrgCA(ctx, req.OrgID)
	if err != nil {
		return fmt.Errorf("failed to look up org CA: %w", err)
	}
	if orgCA == nil {
		return fmt.Errorf("org CA not found for org %s", req.OrgID)
	}

	// Get next CRL number
	crlNumber, err := s.store.GetNextCRLNumber(ctx, orgCA.SerialNumber)
	if err != nil {
		return fmt.Errorf("failed to get CRL number: %w", err)
	}

	now := time.Now().UTC()

	// Insert CRL entry
	if err := s.store.InsertCRLEntry(ctx, &CRLEntryRecord{
		CertSerial:   req.SerialHex,
		IssuerSerial: orgCA.SerialNumber,
		RevokedAt:    now,
		Reason:       req.Reason,
		CRLNumber:    crlNumber,
		IsDelta:      false,
	}); err != nil {
		return fmt.Errorf("failed to insert CRL entry: %w", err)
	}

	// Update certificate status
	if err := s.store.UpdateCertificateStatus(ctx, req.SerialHex, "revoked"); err != nil {
		return fmt.Errorf("failed to update certificate status: %w", err)
	}

	_ = s.auditLogger.Log(ctx, req.OrgID, "cert_revoked", "system",
		fmt.Sprintf("Certificate revoked: %s (reason: %d)", req.SerialHex, req.Reason), "")

	return nil
}

// GetCRLRequest represents a request to generate a CRL.
type GetCRLRequest struct {
	OrgID      string
	DeltaOnly  bool
	IssuerCert *x509.Certificate
	IssuerKey  *ecdsa.PrivateKey
}

// GetCRLResponse holds the generated CRL data.
type GetCRLResponse struct {
	CRLDER    []byte
	CRLNumber int64
	IsDelta   bool
}

// GetCRL generates a Certificate Revocation List for the given org.
func (s *PKIService) GetCRL(ctx context.Context, req *GetCRLRequest) (*GetCRLResponse, error) {
	if s.store == nil {
		return nil, fmt.Errorf("certificate store not configured")
	}

	// Find the org CA
	orgCA, err := s.store.GetOrgCA(ctx, req.OrgID)
	if err != nil {
		return nil, fmt.Errorf("failed to look up org CA: %w", err)
	}
	if orgCA == nil {
		return nil, fmt.Errorf("org CA not found for org %s", req.OrgID)
	}

	// Get all CRL entries for this issuer
	entries, err := s.store.GetCRLEntries(ctx, orgCA.SerialNumber)
	if err != nil {
		return nil, fmt.Errorf("failed to get CRL entries: %w", err)
	}

	// Convert to pki.RevokedCert
	revokedCerts := make([]pki.RevokedCert, 0, len(entries))
	for _, e := range entries {
		serial := new(big.Int)
		serial.SetString(e.CertSerial, 16)
		revokedCerts = append(revokedCerts, pki.RevokedCert{
			SerialNumber: serial,
			RevokedAt:    e.RevokedAt,
			ReasonCode:   e.Reason,
		})
	}

	// Get CRL number
	crlNumber, err := s.store.GetNextCRLNumber(ctx, orgCA.SerialNumber)
	if err != nil {
		return nil, fmt.Errorf("failed to get CRL number: %w", err)
	}

	now := time.Now().UTC()
	config := pki.CRLConfig{
		Number:     big.NewInt(crlNumber),
		ThisUpdate: now,
		NextUpdate: now.Add(24 * time.Hour),
		IsDelta:    req.DeltaOnly,
	}

	crlDER, err := pki.GenerateCRL(req.IssuerCert, req.IssuerKey, revokedCerts, config)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CRL: %w", err)
	}

	return &GetCRLResponse{
		CRLDER:    crlDER,
		CRLNumber: crlNumber,
		IsDelta:   req.DeltaOnly,
	}, nil
}

// CheckOCSPRequest represents a request to check certificate revocation status.
type CheckOCSPRequest struct {
	SerialHex string
	OrgID     string
}

// CheckOCSPResponse holds the OCSP check result.
type CheckOCSPResponse struct {
	Status    int    // 0=good, 1=revoked, 2=unknown
	RevokedAt string // RFC3339 timestamp, empty if not revoked
}

// CheckOCSP checks the revocation status of a certificate.
func (s *PKIService) CheckOCSP(ctx context.Context, req *CheckOCSPRequest) (*CheckOCSPResponse, error) {
	if s.store == nil {
		return nil, fmt.Errorf("certificate store not configured")
	}

	// Verify the cert exists
	cert, err := s.store.GetCertificateBySerial(ctx, req.SerialHex)
	if err != nil {
		return nil, fmt.Errorf("failed to look up certificate: %w", err)
	}
	if cert == nil || cert.OrgID != req.OrgID {
		return &CheckOCSPResponse{Status: 2, RevokedAt: ""}, nil // unknown
	}

	// Check for revocation entry
	entry, err := s.store.GetCertRevocationEntry(ctx, req.SerialHex)
	if err != nil {
		return nil, fmt.Errorf("failed to check revocation: %w", err)
	}
	if entry != nil {
		return &CheckOCSPResponse{
			Status:    1,
			RevokedAt: entry.RevokedAt.UTC().Format(time.RFC3339),
		}, nil
	}

	return &CheckOCSPResponse{Status: 0, RevokedAt: ""}, nil // good
}
