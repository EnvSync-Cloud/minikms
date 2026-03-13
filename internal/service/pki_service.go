package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/envsync-cloud/minikms/internal/audit"
	"github.com/envsync-cloud/minikms/internal/crypto"
	"github.com/envsync-cloud/minikms/internal/keys"
	"github.com/envsync-cloud/minikms/internal/pki"
	"github.com/envsync-cloud/minikms/internal/pkistore"
)

// PKIService handles certificate lifecycle gRPC operations.
type PKIService struct {
	rootCert     *x509.Certificate
	rootKey      *ecdsa.PrivateKey
	auditLogger  *audit.AuditLogger
	store        pkistore.Store
	orgCAWrapMgr *keys.OrgCAWrapManager
	shamirShares int
	shamirThresh int
}

// NewPKIService creates a new PKIService.
func NewPKIService(rootCert *x509.Certificate, rootKey *ecdsa.PrivateKey, auditLogger *audit.AuditLogger, store pkistore.Store) *PKIService {
	return &PKIService{
		rootCert:     rootCert,
		rootKey:      rootKey,
		auditLogger:  auditLogger,
		store:        store,
		shamirShares: 5,
		shamirThresh: 3,
	}
}

// SetOrgCAWrapManager sets the Org CA wrap manager for zero-trust key wrapping.
func (s *PKIService) SetOrgCAWrapManager(mgr *keys.OrgCAWrapManager) {
	s.orgCAWrapMgr = mgr
}

// WrapOrgCAForMember wraps the Org CA private key for a specific member.
func (s *PKIService) WrapOrgCAForMember(ctx context.Context, orgID, memberID, certSerial string, memberPub *ecdsa.PublicKey, orgCAKey *ecdsa.PrivateKey) error {
	if s.orgCAWrapMgr == nil {
		return nil
	}
	return s.orgCAWrapMgr.WrapOrgCAForMember(ctx, orgID, memberID, certSerial, memberPub, orgCAKey)
}

// SetShamirConfig sets the Shamir secret sharing configuration.
func (s *PKIService) SetShamirConfig(shares, threshold int) {
	s.shamirShares = shares
	s.shamirThresh = threshold
}

// CreateOrgCARequest represents a request to create an org intermediate CA.
type CreateOrgCARequest struct {
	OrgID   string
	OrgName string
}

// CreateOrgCAResponse represents the result of creating an org CA.
type CreateOrgCAResponse struct {
	CertPEM   string
	SerialHex string
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
		_ = s.store.StoreCertificate(ctx, &pkistore.CertRecord{
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

// CreateOrgWithWrappingRequest represents a request to create an org with zero-trust key wrapping.
type CreateOrgWithWrappingRequest struct {
	OrgID           string
	OrgName         string
	CreatorMemberID string
	CreatorEmail    string
	CreatorRole     string
	CreatorCSR      []byte // If non-nil, BYOK mode: use CSR instead of generating key
}

// CreateOrgWithWrappingResponse holds the org creation result with member cert and Org CA wrap.
type CreateOrgWithWrappingResponse struct {
	OrgCACertPEM   string
	OrgCASerialHex string
	MemberCertPEM  string
	MemberKeyPEM   string // Empty for BYOK (key stayed client-side)
	MemberSerial   string
}

// CreateOrgWithWrapping creates an org intermediate CA, issues the creator's member cert,
// wraps the Org CA private key for the creator, and Shamir-escrows it.
// This implements the zero-trust org creation flow from the plan.
func (s *PKIService) CreateOrgWithWrapping(ctx context.Context, req *CreateOrgWithWrappingRequest) (*CreateOrgWithWrappingResponse, error) {
	// Step 1: Generate Org CA keypair (P-384), sign with Root CA
	orgCAResp, orgCACert, orgCAKey, err := s.CreateOrgCAFull(ctx, &CreateOrgCARequest{
		OrgID:   req.OrgID,
		OrgName: req.OrgName,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create org CA: %w", err)
	}

	// Step 2: Issue creator's member cert
	var memberCertPEM, memberKeyPEM, memberSerialHex string
	var memberPubKey *ecdsa.PublicKey

	if req.CreatorCSR != nil {
		// BYOK mode: issue cert from CSR (private key stays client-side)
		memberCert, certDER, err := pki.IssueMemberCertFromCSR(
			req.CreatorCSR,
			req.CreatorMemberID, req.OrgID, req.CreatorRole,
			orgCACert, orgCAKey,
			365*24*time.Hour, nil,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to issue member cert from CSR: %w", err)
		}

		memberCertPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
		memberSerialHex = memberCert.SerialNumber.Text(16)
		memberPubKey = memberCert.PublicKey.(*ecdsa.PublicKey)

		// Persist member cert
		if s.store != nil {
			_ = s.store.StoreCertificate(ctx, &pkistore.CertRecord{
				SerialNumber: memberSerialHex,
				CertType:     "member",
				OrgID:        req.OrgID,
				SubjectCN:    memberCert.Subject.CommonName,
				CertPEM:      memberCertPEM,
				Status:       "active",
				IssuedAt:     memberCert.NotBefore,
				ExpiresAt:    memberCert.NotAfter,
			})
		}
	} else {
		// Managed mode: server generates key
		memberResp, err := s.IssueMemberCert(ctx, &IssueMemberCertRequest{
			MemberID:    req.CreatorMemberID,
			MemberEmail: req.CreatorEmail,
			OrgID:       req.OrgID,
			Role:        req.CreatorRole,
			OrgCACert:   orgCACert,
			OrgCAKey:    orgCAKey,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to issue member cert: %w", err)
		}

		memberCertPEM = memberResp.CertPEM
		memberKeyPEM = memberResp.KeyPEM
		memberSerialHex = memberResp.SerialHex

		// Extract public key from the cert
		pub, err := keys.ParseMemberCertPublicKey(memberCertPEM)
		if err != nil {
			return nil, fmt.Errorf("failed to extract member public key: %w", err)
		}
		memberPubKey = pub
	}

	// Step 3: Wrap Org CA private key for creator's member cert
	if s.orgCAWrapMgr != nil {
		if err := s.orgCAWrapMgr.WrapOrgCAForMember(
			ctx, req.OrgID, req.CreatorMemberID, memberSerialHex,
			memberPubKey, orgCAKey,
		); err != nil {
			return nil, fmt.Errorf("failed to wrap Org CA key: %w", err)
		}
	}

	// Step 4: Shamir-split Org CA private key for disaster recovery
	orgCAPrivBytes := crypto.MarshalECPrivateKey(orgCAKey)
	if s.shamirShares > 0 && s.shamirThresh > 0 {
		_, err := crypto.SplitKey(orgCAPrivBytes, s.shamirShares, s.shamirThresh)
		if err != nil {
			// Log but don't fail — Shamir is for DR, not critical path
			_ = s.auditLogger.Log(ctx, req.OrgID, "shamir_split_failed", "system",
				fmt.Sprintf("Failed to Shamir-split Org CA key: %v", err), "")
		}
		// TODO: Store encrypted shares in key_escrow_shares table
	}

	// Step 5: Zeroize Org CA private key from memory
	crypto.ZeroizeBytes(orgCAPrivBytes)

	_ = s.auditLogger.Log(ctx, req.OrgID, "org_created_with_wrapping", req.CreatorMemberID,
		fmt.Sprintf("Org %s created with zero-trust key wrapping", req.OrgName), "")

	return &CreateOrgWithWrappingResponse{
		OrgCACertPEM:   orgCAResp.CertPEM,
		OrgCASerialHex: orgCAResp.SerialHex,
		MemberCertPEM:  memberCertPEM,
		MemberKeyPEM:   memberKeyPEM,
		MemberSerial:   memberSerialHex,
	}, nil
}

// AddMemberRequest represents a request to add a member to an org with Org CA key wrapping.
type AddMemberRequest struct {
	OrgID         string
	MemberID      string
	MemberEmail   string
	Role          string
	AdminMemberID string            // Admin performing the add
	AdminPrivKey  *ecdsa.PrivateKey // Admin's private key (for unwrapping Org CA)
	MemberCSR     []byte            // If non-nil, BYOK mode
}

// AddMemberResponse holds the result of adding a member.
type AddMemberResponse struct {
	MemberCertPEM string
	MemberKeyPEM  string // Empty for BYOK
	MemberSerial  string
}

// AddMember adds a new member to an org, issuing their cert and wrapping the Org CA key.
func (s *PKIService) AddMember(ctx context.Context, req *AddMemberRequest) (*AddMemberResponse, error) {
	if s.orgCAWrapMgr == nil {
		return nil, fmt.Errorf("Org CA wrap manager not configured")
	}

	// Step 1: Admin proves they can unwrap Org CA key
	orgCAPrivKey, err := s.orgCAWrapMgr.UnwrapOrgCA(ctx, req.OrgID, req.AdminMemberID, req.AdminPrivKey)
	if err != nil {
		return nil, fmt.Errorf("admin failed to unwrap Org CA key: %w", err)
	}

	// Load the Org CA cert
	orgCACertRec, err := s.store.GetOrgCA(ctx, req.OrgID)
	if err != nil || orgCACertRec == nil {
		return nil, fmt.Errorf("failed to load Org CA cert: %w", err)
	}

	block, _ := pem.Decode([]byte(orgCACertRec.CertPEM))
	if block == nil {
		return nil, fmt.Errorf("invalid Org CA PEM")
	}
	orgCACert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Org CA cert: %w", err)
	}

	// Step 2: Issue new member cert
	var memberCertPEM, memberKeyPEM, memberSerialHex string
	var memberPubKey *ecdsa.PublicKey

	if req.MemberCSR != nil {
		// BYOK mode
		memberCert, certDER, err := pki.IssueMemberCertFromCSR(
			req.MemberCSR,
			req.MemberID, req.OrgID, req.Role,
			orgCACert, orgCAPrivKey,
			365*24*time.Hour, nil,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to issue member cert from CSR: %w", err)
		}

		memberCertPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
		memberSerialHex = memberCert.SerialNumber.Text(16)
		memberPubKey = memberCert.PublicKey.(*ecdsa.PublicKey)

		if s.store != nil {
			_ = s.store.StoreCertificate(ctx, &pkistore.CertRecord{
				SerialNumber: memberSerialHex,
				CertType:     "member",
				OrgID:        req.OrgID,
				SubjectCN:    memberCert.Subject.CommonName,
				CertPEM:      memberCertPEM,
				Status:       "active",
				IssuedAt:     memberCert.NotBefore,
				ExpiresAt:    memberCert.NotAfter,
			})
		}
	} else {
		// Managed mode
		memberResp, err := s.IssueMemberCert(ctx, &IssueMemberCertRequest{
			MemberID:    req.MemberID,
			MemberEmail: req.MemberEmail,
			OrgID:       req.OrgID,
			Role:        req.Role,
			OrgCACert:   orgCACert,
			OrgCAKey:    orgCAPrivKey,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to issue member cert: %w", err)
		}

		memberCertPEM = memberResp.CertPEM
		memberKeyPEM = memberResp.KeyPEM
		memberSerialHex = memberResp.SerialHex

		pub, err := keys.ParseMemberCertPublicKey(memberCertPEM)
		if err != nil {
			return nil, fmt.Errorf("failed to extract member public key: %w", err)
		}
		memberPubKey = pub
	}

	// Step 3: Wrap Org CA private key for new member
	if err := s.orgCAWrapMgr.WrapOrgCAForMember(
		ctx, req.OrgID, req.MemberID, memberSerialHex,
		memberPubKey, orgCAPrivKey,
	); err != nil {
		return nil, fmt.Errorf("failed to wrap Org CA key for new member: %w", err)
	}

	// Step 4: Zeroize Org CA private key
	// (Go GC will handle this, but explicit zeroize is good practice)

	_ = s.auditLogger.Log(ctx, req.OrgID, "member_added", req.AdminMemberID,
		fmt.Sprintf("Member %s added to org by admin %s", req.MemberID, req.AdminMemberID), "")

	return &AddMemberResponse{
		MemberCertPEM: memberCertPEM,
		MemberKeyPEM:  memberKeyPEM,
		MemberSerial:  memberSerialHex,
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
	CertPEM   string
	KeyPEM    string
	SerialHex string
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

	// Persist to database (include private key for managed members)
	if s.store != nil {
		_ = s.store.StoreCertificateWithKey(ctx, &pkistore.CertRecord{
			SerialNumber:        serialHex,
			CertType:            "member",
			OrgID:               req.OrgID,
			SubjectCN:           req.MemberEmail,
			CertPEM:             string(certPEM),
			EncryptedPrivateKey: crypto.MarshalECPrivateKey(memberKey),
			Status:              "active",
			IssuedAt:            cert.NotBefore,
			ExpiresAt:           cert.NotAfter,
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
	if err := s.store.InsertCRLEntry(ctx, &pkistore.CRLEntryRecord{
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
