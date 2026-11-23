package rewrap

import "context"

// CertTypeOrgIntermediateCA is the certificate cert_type sealed with the
// organization master key. Active organization intermediate CAs, pending
// organization CA CSRs, and environment CAs are all stored with this type.
const CertTypeOrgIntermediateCA = "org_intermediate_ca"

// CertTypeMember is the certificate cert_type for managed member keys.
const CertTypeMember = "member"

// OrgKeySealedCertTypes returns the organization CA cert_type allowlist.
// Those rows are listed and updated with organization CA associated data.
// Member rows are listed separately.
func OrgKeySealedCertTypes() []string {
	return []string{CertTypeOrgIntermediateCA}
}

// KeyVersionRow is one key_versions ciphertext. It is sealed with AAD dek:<org_id>.
type KeyVersionRow struct {
	ID           string
	OrgID        string
	EncryptedKey []byte
}

// CertificateRow is one certificate ciphertext selected for rewrap.
// Organization CA rows use AAD org-ca-key:<org_id>:<serial_number>.
// Member-key envelopes use AAD member-key:<org_id>:<serial_number>.
type CertificateRow struct {
	ID                  string
	OrgID               string
	SerialNumber        string
	CertType            string
	EncryptedPrivateKey []byte
}

// Store is the database surface used by a root-key rewrap.
type Store interface {
	// HasActiveRootEscrow reports whether an active escrow set exists for the
	// root key. Implementations must not read share bytes.
	HasActiveRootEscrow(ctx context.Context) (bool, error)
	// Begin starts one transaction. When readOnly is set the transaction is
	// read-only and row locks are not taken.
	Begin(ctx context.Context, readOnly bool) (Tx, error)
}

// Tx is one rewrap transaction. Updates stay uncommitted until Commit.
type Tx interface {
	ListKeyVersions(ctx context.Context) ([]KeyVersionRow, error)
	ListCertificates(ctx context.Context, certTypes []string) ([]CertificateRow, error)
	// ListMemberKeys returns every member certificate, including rows with no key material.
	ListMemberKeys(ctx context.Context) ([]CertificateRow, error)
	UpdateKeyVersion(ctx context.Context, id string, encryptedKey []byte) error
	UpdateCertificate(ctx context.Context, id string, encryptedPrivateKey []byte) error
	ReadKeyVersion(ctx context.Context, id string) ([]byte, error)
	ReadCertificate(ctx context.Context, id string) ([]byte, error)
	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
}
