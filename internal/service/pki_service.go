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
	"github.com/envsync-cloud/minikms/internal/escrow"
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
	orgKeyMgr    *keys.OrgKeyManager
	orgCAWrapMgr *keys.OrgCAWrapManager
	shamirShares int
	shamirThresh int
	escrowMgr    *escrow.Manager
	custodians   []string
}

// SetOrgKeyManager enables durable encryption of Org CA private keys. The
// encrypted key can then be loaded by any replica from the certificate store.
func (s *PKIService) SetOrgKeyManager(manager *keys.OrgKeyManager) {
	s.orgKeyMgr = manager
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

// SetEscrowManager enables automatic Org CA escrow during org bootstrap.
func (s *PKIService) SetEscrowManager(manager *escrow.Manager, custodians []string) {
	s.escrowMgr = manager
	s.custodians = append([]string(nil), custodians...)
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
// parsed certificate and private key alongside the response.
func (s *PKIService) CreateOrgCAFull(ctx context.Context, req *CreateOrgCARequest) (*CreateOrgCAResponse, *x509.Certificate, *ecdsa.PrivateKey, error) {
	if req == nil {
		return nil, nil, nil, invalidArgument("request is required")
	}
	if err := requireFields(
		requiredField("org_id", req.OrgID),
		requiredField("org_name", req.OrgName),
	); err != nil {
		return nil, nil, nil, err
	}
	if s.rootCert == nil || s.rootKey == nil {
		return nil, nil, nil, NewDomainError(ErrorFailedPrecondition, "root CA is not initialized", nil)
	}
	if s.store != nil && s.orgKeyMgr == nil {
		return nil, nil, nil, NewDomainError(ErrorFailedPrecondition, "durable organization CA storage is not initialized", nil)
	}

	if s.store != nil {
		if locker, ok := s.store.(pkistore.OrgCABootstrapLocker); ok {
			release, err := locker.AcquireOrgCABootstrapLock(ctx, req.OrgID)
			if err != nil {
				return nil, nil, nil, internalError("failed to lock organization CA bootstrap", err)
			}
			defer release()
		}

		if existing, err := s.loadOrgCA(ctx, req.OrgID); err != nil {
			return nil, nil, nil, err
		} else if existing != nil {
			return s.orgCAResult(existing)
		}
	}

	cert, key, certDER, err := pki.CreateOrgIntermediateCA(
		req.OrgID, req.OrgName,
		s.rootCert, s.rootKey,
		10*365*24*time.Hour, // 10 year validity
	)
	if err != nil {
		return nil, nil, nil, internalError("failed to create org CA", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	serialHex := cert.SerialNumber.Text(16)

	// Escrow must complete before the new Org CA is exposed. On restarts,
	// EnsureSplit preserves the generation already distributed to custodians.
	if s.escrowMgr != nil {
		orgCAPrivBytes := crypto.MarshalECPrivateKey(key)
		_, _, escrowErr := s.escrowMgr.EnsureSplit(ctx, req.OrgID, escrow.KeyTypeOrgCA,
			orgCAPrivBytes, s.custodians, s.shamirThresh, "system")
		crypto.ZeroizeBytes(orgCAPrivBytes)
		if escrowErr != nil {
			return nil, nil, nil, fmt.Errorf("failed to escrow org CA key: %w", escrowErr)
		}
	}

	if s.store != nil {
		encryptedKey, err := s.encryptOrgCAKey(req.OrgID, serialHex, key)
		if err != nil {
			return nil, nil, nil, err
		}
		if err := s.store.StoreCertificateWithKey(ctx, &pkistore.CertRecord{
			SerialNumber:        serialHex,
			CertType:            "org_intermediate_ca",
			OrgID:               req.OrgID,
			SubjectCN:           cert.Subject.CommonName,
			CertPEM:             string(certPEM),
			EncryptedPrivateKey: encryptedKey,
			Status:              "active",
			IssuedAt:            cert.NotBefore,
			ExpiresAt:           cert.NotAfter,
		}); err != nil {
			// A replica may have completed bootstrap while this request waited.
			if existing, loadErr := s.loadOrgCA(ctx, req.OrgID); loadErr == nil && existing != nil {
				return s.orgCAResult(existing)
			}
			return nil, nil, nil, internalError("failed to store org CA certificate", err)
		}
	}

	_ = s.auditLogger.Log(ctx, req.OrgID, "org_ca_created", "system",
		fmt.Sprintf("Org intermediate CA created for %s (serial: %s)", req.OrgName, serialHex), "")

	resp := &CreateOrgCAResponse{
		CertPEM:   string(certPEM),
		SerialHex: serialHex,
	}
	return resp, cert, key, nil
}

// LoadOrgCA returns the active Org CA certificate and private key from shared
// durable storage. It never relies on process-local adapter state.
func (s *PKIService) LoadOrgCA(ctx context.Context, orgID string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	if orgID == "" {
		return nil, nil, invalidArgument("org_id is required")
	}
	if s.store == nil || s.orgKeyMgr == nil {
		return nil, nil, NewDomainError(ErrorFailedPrecondition, "durable organization CA storage is not initialized", nil)
	}
	record, err := s.loadOrgCA(ctx, orgID)
	if err != nil {
		return nil, nil, err
	}
	if record == nil {
		return nil, nil, NewDomainError(ErrorFailedPrecondition, "organization CA is not available", nil)
	}
	_, cert, key, err := s.orgCAResult(record)
	return cert, key, err
}

func (s *PKIService) loadOrgCA(ctx context.Context, orgID string) (*pkistore.CertRecord, error) {
	record, err := s.store.GetOrgCA(ctx, orgID)
	if err != nil {
		return nil, internalError("failed to load organization CA", err)
	}
	return record, nil
}

func (s *PKIService) encryptOrgCAKey(orgID, serial string, key *ecdsa.PrivateKey) ([]byte, error) {
	orgKey, err := s.orgKeyMgr.DeriveOrgKey(orgID)
	if err != nil {
		return nil, internalError("failed to derive organization key", err)
	}
	defer crypto.ZeroizeBytes(orgKey)

	keyBytes := crypto.MarshalECPrivateKey(key)
	defer crypto.ZeroizeBytes(keyBytes)
	encrypted, err := crypto.Encrypt(orgKey, keyBytes, []byte(orgCAKeyAAD(orgID, serial)))
	if err != nil {
		return nil, internalError("failed to encrypt organization CA key", err)
	}
	return encrypted, nil
}

func (s *PKIService) decryptOrgCAKey(record *pkistore.CertRecord) (*ecdsa.PrivateKey, error) {
	if len(record.EncryptedPrivateKey) == 0 {
		return nil, NewDomainError(ErrorFailedPrecondition,
			"organization CA private key is not available in durable storage", nil)
	}
	orgKey, err := s.orgKeyMgr.DeriveOrgKey(record.OrgID)
	if err != nil {
		return nil, internalError("failed to derive organization key", err)
	}
	defer crypto.ZeroizeBytes(orgKey)

	keyBytes, err := crypto.Decrypt(orgKey, record.EncryptedPrivateKey,
		[]byte(orgCAKeyAAD(record.OrgID, record.SerialNumber)))
	if err != nil {
		return nil, internalError("failed to decrypt organization CA key", err)
	}
	defer crypto.ZeroizeBytes(keyBytes)
	key, err := crypto.UnmarshalECPrivateKey(keyBytes)
	if err != nil {
		return nil, internalError("failed to decode organization CA key", err)
	}
	return key, nil
}

func (s *PKIService) parseStoredOrgCA(record *pkistore.CertRecord) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	block, rest := pem.Decode([]byte(record.CertPEM))
	if block == nil || len(rest) != 0 {
		return nil, nil, internalError("stored organization CA certificate is invalid", nil)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, internalError("failed to parse organization CA certificate", err)
	}
	key, err := s.decryptOrgCAKey(record)
	if err != nil {
		return nil, nil, err
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return nil, nil, internalError("organization CA certificate and key do not match", nil)
	}
	return cert, key, nil
}

func orgCAKeyAAD(orgID, serial string) string {
	return "org-ca-key:" + orgID + ":" + serial
}

func (s *PKIService) orgCAResult(record *pkistore.CertRecord) (*CreateOrgCAResponse, *x509.Certificate, *ecdsa.PrivateKey, error) {
	cert, key, err := s.parseStoredOrgCA(record)
	if err != nil {
		return nil, nil, nil, err
	}
	return &CreateOrgCAResponse{
		CertPEM:   record.CertPEM,
		SerialHex: record.SerialNumber,
	}, cert, key, nil
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
	if req == nil {
		return nil, invalidArgument("request is required")
	}
	if err := requireFields(
		requiredField("org_id", req.OrgID),
		requiredField("org_name", req.OrgName),
		requiredField("creator_member_id", req.CreatorMemberID),
		requiredField("creator_role", req.CreatorRole),
	); err != nil {
		return nil, err
	}
	if len(req.CreatorCSR) == 0 && req.CreatorEmail == "" {
		return nil, invalidArgument("creator_email is required for managed members")
	}

	// Step 1: Generate Org CA keypair (P-384), sign with Root CA
	orgCAResp, orgCACert, orgCAKey, err := s.CreateOrgCAFull(ctx, &CreateOrgCARequest{
		OrgID:   req.OrgID,
		OrgName: req.OrgName,
	})
	if err != nil {
		return nil, err
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
			return nil, NewDomainError(ErrorInvalidArgument, "creator_csr is invalid", err)
		}

		memberCertPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
		memberSerialHex = memberCert.SerialNumber.Text(16)
		memberPubKey = memberCert.PublicKey.(*ecdsa.PublicKey)

		// Persist member cert
		if s.store != nil {
			if err := s.store.StoreCertificate(ctx, &pkistore.CertRecord{
				SerialNumber: memberSerialHex,
				CertType:     "member",
				OrgID:        req.OrgID,
				SubjectCN:    memberCert.Subject.CommonName,
				CertPEM:      memberCertPEM,
				Status:       "active",
				IssuedAt:     memberCert.NotBefore,
				ExpiresAt:    memberCert.NotAfter,
			}); err != nil {
				return nil, internalError("failed to store creator certificate", err)
			}
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
			return nil, err
		}

		memberCertPEM = memberResp.CertPEM
		memberKeyPEM = memberResp.KeyPEM
		memberSerialHex = memberResp.SerialHex

		// Extract public key from the cert
		pub, err := keys.ParseMemberCertPublicKey(memberCertPEM)
		if err != nil {
			return nil, internalError("failed to extract member public key", err)
		}
		memberPubKey = pub
	}

	// Step 3: Wrap Org CA private key for creator's member cert
	if s.orgCAWrapMgr != nil {
		if err := s.orgCAWrapMgr.WrapOrgCAForMember(
			ctx, req.OrgID, req.CreatorMemberID, memberSerialHex,
			memberPubKey, orgCAKey,
		); err != nil {
			return nil, internalError("failed to wrap Org CA key", err)
		}
	}

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
	if req == nil {
		return nil, invalidArgument("request is required")
	}
	if err := requireFields(
		requiredField("org_id", req.OrgID),
		requiredField("member_id", req.MemberID),
		requiredField("role", req.Role),
		requiredField("admin_member_id", req.AdminMemberID),
	); err != nil {
		return nil, err
	}
	if req.AdminPrivKey == nil {
		return nil, invalidArgument("admin_private_key is required")
	}
	if len(req.MemberCSR) == 0 && req.MemberEmail == "" {
		return nil, invalidArgument("member_email is required for managed members")
	}
	if s.orgCAWrapMgr == nil {
		return nil, NewDomainError(ErrorFailedPrecondition, "Org CA wrapping is not configured", nil)
	}
	if s.store == nil {
		return nil, NewDomainError(ErrorFailedPrecondition, "certificate store is not configured", nil)
	}

	// Step 1: Admin proves they can unwrap Org CA key
	orgCAPrivKey, err := s.orgCAWrapMgr.UnwrapOrgCA(ctx, req.OrgID, req.AdminMemberID, req.AdminPrivKey)
	if err != nil {
		return nil, NewDomainError(ErrorPermissionDenied, "admin key authorization failed", err)
	}

	// Load the Org CA cert
	orgCACertRec, err := s.store.GetOrgCA(ctx, req.OrgID)
	if err != nil {
		return nil, internalError("failed to load Org CA certificate", err)
	}
	if orgCACertRec == nil {
		return nil, NewDomainError(ErrorNotFound, "organization CA not found", nil)
	}

	block, _ := pem.Decode([]byte(orgCACertRec.CertPEM))
	if block == nil {
		return nil, internalError("invalid stored Org CA PEM", nil)
	}
	orgCACert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, internalError("failed to parse stored Org CA certificate", err)
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
			return nil, NewDomainError(ErrorInvalidArgument, "member_csr is invalid", err)
		}

		memberCertPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
		memberSerialHex = memberCert.SerialNumber.Text(16)
		memberPubKey = memberCert.PublicKey.(*ecdsa.PublicKey)

		if s.store != nil {
			if err := s.store.StoreCertificate(ctx, &pkistore.CertRecord{
				SerialNumber: memberSerialHex,
				CertType:     "member",
				OrgID:        req.OrgID,
				SubjectCN:    memberCert.Subject.CommonName,
				CertPEM:      memberCertPEM,
				Status:       "active",
				IssuedAt:     memberCert.NotBefore,
				ExpiresAt:    memberCert.NotAfter,
			}); err != nil {
				return nil, internalError("failed to store member certificate", err)
			}
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
			return nil, err
		}

		memberCertPEM = memberResp.CertPEM
		memberKeyPEM = memberResp.KeyPEM
		memberSerialHex = memberResp.SerialHex

		pub, err := keys.ParseMemberCertPublicKey(memberCertPEM)
		if err != nil {
			return nil, internalError("failed to extract member public key", err)
		}
		memberPubKey = pub
	}

	// Step 3: Wrap Org CA private key for new member
	if err := s.orgCAWrapMgr.WrapOrgCAForMember(
		ctx, req.OrgID, req.MemberID, memberSerialHex,
		memberPubKey, orgCAPrivKey,
	); err != nil {
		return nil, internalError("failed to wrap Org CA key for new member", err)
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
	if req == nil {
		return nil, invalidArgument("request is required")
	}
	if err := requireFields(
		requiredField("member_id", req.MemberID),
		requiredField("member_email", req.MemberEmail),
		requiredField("org_id", req.OrgID),
		requiredField("role", req.Role),
	); err != nil {
		return nil, err
	}
	if req.OrgCACert == nil || req.OrgCAKey == nil {
		return nil, NewDomainError(ErrorFailedPrecondition, "organization CA is not available", nil)
	}

	_, memberKey, certDER, err := pki.CreateMemberCertificate(
		req.MemberID, req.MemberEmail, req.OrgID, req.Role,
		req.OrgCACert, req.OrgCAKey,
		365*24*time.Hour, // 1 year validity
		nil,              // CRL distribution points
	)
	if err != nil {
		return nil, internalError("failed to issue member certificate", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(memberKey)
	if err != nil {
		return nil, internalError("failed to marshal member key", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	cert, _ := x509.ParseCertificate(certDER)
	serialHex := cert.SerialNumber.Text(16)

	// Persist to database (include private key for managed members)
	if s.store != nil {
		if err := s.store.StoreCertificateWithKey(ctx, &pkistore.CertRecord{
			SerialNumber:        serialHex,
			CertType:            "member",
			OrgID:               req.OrgID,
			SubjectCN:           req.MemberEmail,
			CertPEM:             string(certPEM),
			EncryptedPrivateKey: crypto.MarshalECPrivateKey(memberKey),
			Status:              "active",
			IssuedAt:            cert.NotBefore,
			ExpiresAt:           cert.NotAfter,
		}); err != nil {
			return nil, internalError("failed to store member certificate", err)
		}
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
	if req == nil {
		return invalidArgument("request is required")
	}
	if err := requireFields(
		requiredField("serial_hex", req.SerialHex),
		requiredField("org_id", req.OrgID),
	); err != nil {
		return err
	}
	if !validSerialHex(req.SerialHex) {
		return invalidArgument("serial_hex must be hexadecimal")
	}
	if req.Reason < 0 || req.Reason > 10 {
		return invalidArgument("reason must be between 0 and 10")
	}
	if s.store == nil {
		return NewDomainError(ErrorFailedPrecondition, "certificate store is not configured", nil)
	}

	// Verify the cert exists and belongs to this org
	cert, err := s.store.GetCertificateBySerial(ctx, req.SerialHex)
	if err != nil {
		return internalError("failed to look up certificate", err)
	}
	if cert == nil {
		return NewDomainError(ErrorNotFound, "certificate not found", nil)
	}
	if cert.OrgID != req.OrgID {
		return NewDomainError(ErrorPermissionDenied, "certificate organization access denied", nil)
	}
	if cert.Status == "revoked" {
		return NewDomainError(ErrorFailedPrecondition, "certificate is already revoked", nil)
	}

	// Find the org CA (issuer)
	orgCA, err := s.store.GetOrgCA(ctx, req.OrgID)
	if err != nil {
		return internalError("failed to look up organization CA", err)
	}
	if orgCA == nil {
		return NewDomainError(ErrorFailedPrecondition, "organization CA is not available", nil)
	}

	// Get next CRL number
	crlNumber, err := s.store.GetNextCRLNumber(ctx, orgCA.SerialNumber)
	if err != nil {
		return internalError("failed to get CRL number", err)
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
		return internalError("failed to insert CRL entry", err)
	}

	// Update certificate status
	if err := s.store.UpdateCertificateStatus(ctx, req.SerialHex, "revoked"); err != nil {
		return internalError("failed to update certificate status", err)
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
	if req == nil {
		return nil, invalidArgument("request is required")
	}
	if err := requireFields(requiredField("org_id", req.OrgID)); err != nil {
		return nil, err
	}
	if req.IssuerCert == nil || req.IssuerKey == nil {
		return nil, NewDomainError(ErrorFailedPrecondition, "organization CA signing key is not available", nil)
	}
	if s.store == nil {
		return nil, NewDomainError(ErrorFailedPrecondition, "certificate store is not configured", nil)
	}

	// Find the org CA
	orgCA, err := s.store.GetOrgCA(ctx, req.OrgID)
	if err != nil {
		return nil, internalError("failed to look up organization CA", err)
	}
	if orgCA == nil {
		return nil, NewDomainError(ErrorNotFound, "organization CA not found", nil)
	}

	// Get all CRL entries for this issuer
	entries, err := s.store.GetCRLEntries(ctx, orgCA.SerialNumber)
	if err != nil {
		return nil, internalError("failed to get CRL entries", err)
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
		return nil, internalError("failed to get CRL number", err)
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
		return nil, internalError("failed to generate CRL", err)
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
	if req == nil {
		return nil, invalidArgument("request is required")
	}
	if err := requireFields(
		requiredField("serial_hex", req.SerialHex),
		requiredField("org_id", req.OrgID),
	); err != nil {
		return nil, err
	}
	if s.store == nil {
		return nil, NewDomainError(ErrorFailedPrecondition, "certificate store is not configured", nil)
	}

	// Verify the cert exists
	cert, err := s.store.GetCertificateBySerial(ctx, req.SerialHex)
	if err != nil {
		return nil, internalError("failed to look up certificate", err)
	}
	if cert == nil || cert.OrgID != req.OrgID {
		return &CheckOCSPResponse{Status: 2, RevokedAt: ""}, nil // unknown
	}

	// Check for revocation entry
	entry, err := s.store.GetCertRevocationEntry(ctx, req.SerialHex)
	if err != nil {
		return nil, internalError("failed to check revocation", err)
	}
	if entry != nil {
		return &CheckOCSPResponse{
			Status:    1,
			RevokedAt: entry.RevokedAt.UTC().Format(time.RFC3339),
		}, nil
	}

	return &CheckOCSPResponse{Status: 0, RevokedAt: ""}, nil // good
}

func validSerialHex(serial string) bool {
	value, ok := new(big.Int).SetString(serial, 16)
	return ok && value.Sign() >= 0
}
