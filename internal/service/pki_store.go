package service

import (
	"context"
	"time"
)

// PKICertRecord represents a certificate row in the certificates table.
type PKICertRecord struct {
	ID           string
	SerialNumber string
	CertType     string // root_ca, org_intermediate_ca, member
	OrgID        string
	SubjectCN    string
	CertPEM      string
	Status       string // active, revoked, expired
	IssuedAt     time.Time
	ExpiresAt    time.Time
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

// PKICertStore abstracts database operations for PKI certificate lifecycle.
type PKICertStore interface {
	StoreCertificate(ctx context.Context, rec *PKICertRecord) error
	GetCertificateBySerial(ctx context.Context, serialNumber string) (*PKICertRecord, error)
	GetOrgCA(ctx context.Context, orgID string) (*PKICertRecord, error)
	UpdateCertificateStatus(ctx context.Context, serialNumber, status string) error
	InsertCRLEntry(ctx context.Context, entry *CRLEntryRecord) error
	GetCRLEntries(ctx context.Context, issuerSerial string) ([]CRLEntryRecord, error)
	GetNextCRLNumber(ctx context.Context, issuerSerial string) (int64, error)
	GetCertRevocationEntry(ctx context.Context, serialNumber string) (*CRLEntryRecord, error)
}
