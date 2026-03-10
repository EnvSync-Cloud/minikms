package pkistore

import (
	"context"
	"time"
)

// CertRecord represents a certificate row in the certificates table.
type CertRecord struct {
	ID                  string
	SerialNumber        string
	CertType            string // root_ca, org_intermediate_ca, member
	OrgID               string
	SubjectCN           string
	CertPEM             string
	EncryptedPrivateKey []byte // For managed members: encrypted private key bytes
	Status              string // active, revoked, expired
	IssuedAt            time.Time
	ExpiresAt           time.Time
}

// CRLEntryRecord represents a row in the crl_entries table.
type CRLEntryRecord struct {
	CertSerial   string
	IssuerSerial string
	RevokedAt    time.Time
	Reason       int
	CRLNumber    int64
	IsDelta      bool
}

// Store abstracts database operations for PKI certificate lifecycle.
type Store interface {
	StoreCertificate(ctx context.Context, rec *CertRecord) error
	StoreCertificateWithKey(ctx context.Context, rec *CertRecord) error
	GetCertificateBySerial(ctx context.Context, serialNumber string) (*CertRecord, error)
	GetCertificateBySerialWithKey(ctx context.Context, serialNumber string) (*CertRecord, error)
	GetOrgCA(ctx context.Context, orgID string) (*CertRecord, error)
	UpdateCertificateStatus(ctx context.Context, serialNumber, status string) error
	InsertCRLEntry(ctx context.Context, entry *CRLEntryRecord) error
	GetCRLEntries(ctx context.Context, issuerSerial string) ([]CRLEntryRecord, error)
	GetNextCRLNumber(ctx context.Context, issuerSerial string) (int64, error)
	GetCertRevocationEntry(ctx context.Context, serialNumber string) (*CRLEntryRecord, error)
}
