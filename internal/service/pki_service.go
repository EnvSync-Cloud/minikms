package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/envsync/minikms/internal/audit"
	"github.com/envsync/minikms/internal/pki"
)

// PKIService handles certificate lifecycle gRPC operations.
type PKIService struct {
	rootCert    *x509.Certificate
	rootKey     *ecdsa.PrivateKey
	auditLogger *audit.AuditLogger
}

// NewPKIService creates a new PKIService.
func NewPKIService(rootCert *x509.Certificate, rootKey *ecdsa.PrivateKey, auditLogger *audit.AuditLogger) *PKIService {
	return &PKIService{
		rootCert:    rootCert,
		rootKey:     rootKey,
		auditLogger: auditLogger,
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

// CreateOrgCA creates an org intermediate CA certificate.
func (s *PKIService) CreateOrgCA(ctx context.Context, req *CreateOrgCARequest) (*CreateOrgCAResponse, error) {
	cert, _, certDER, err := pki.CreateOrgIntermediateCA(
		req.OrgID, req.OrgName,
		s.rootCert, s.rootKey,
		10*365*24*time.Hour, // 10 year validity
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create org CA: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	s.auditLogger.Log(ctx, req.OrgID, "org_ca_created", "system",
		fmt.Sprintf("Org intermediate CA created for %s (serial: %s)", req.OrgName, cert.SerialNumber.Text(16)), "")

	return &CreateOrgCAResponse{
		CertPEM:   string(certPEM),
		SerialHex: cert.SerialNumber.Text(16),
	}, nil
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

	s.auditLogger.Log(ctx, req.OrgID, "member_cert_issued", req.MemberID,
		fmt.Sprintf("Member certificate issued for %s", req.MemberEmail), "")

	cert, _ := x509.ParseCertificate(certDER)
	return &IssueMemberCertResponse{
		CertPEM:   string(certPEM),
		KeyPEM:    string(keyPEM),
		SerialHex: cert.SerialNumber.Text(16),
	}, nil
}
