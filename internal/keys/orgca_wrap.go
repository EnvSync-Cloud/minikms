package keys

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/envsync/minikms/internal/crypto"
)

// OrgCAWrapRecord represents a per-member wrapped Org CA private key.
type OrgCAWrapRecord struct {
	ID           string
	OrgID        string
	MemberID     string
	CertSerial   string
	EphemeralPub []byte // ECDH ephemeral public key bytes (uncompressed)
	WrappedKey   []byte // AES-256-GCM encrypted Org CA private key
	CreatedAt    time.Time
	RevokedAt    *time.Time
}

// OrgCAWrapStore defines the interface for persisting Org CA wraps.
type OrgCAWrapStore interface {
	StoreOrgCAWrap(ctx context.Context, record *OrgCAWrapRecord) error
	GetOrgCAWrap(ctx context.Context, orgID, memberID string) (*OrgCAWrapRecord, error)
	GetOrgCAWraps(ctx context.Context, orgID string) ([]*OrgCAWrapRecord, error)
	RevokeOrgCAWrap(ctx context.Context, orgID, memberID string) error
}

// OrgCAWrapManager manages per-member wrapping of Org CA private keys.
type OrgCAWrapManager struct {
	store OrgCAWrapStore
}

// NewOrgCAWrapManager creates a new OrgCAWrapManager.
func NewOrgCAWrapManager(store OrgCAWrapStore) *OrgCAWrapManager {
	return &OrgCAWrapManager{store: store}
}

// WrapOrgCAForMember wraps the Org CA private key for a specific member.
// This creates a per-member ECDH-wrapped copy stored in the database.
func (m *OrgCAWrapManager) WrapOrgCAForMember(
	ctx context.Context,
	orgID string,
	memberID string,
	certSerial string,
	memberPub *ecdsa.PublicKey,
	orgCAPrivKey *ecdsa.PrivateKey,
) error {
	// Serialize Org CA private key
	orgCAPrivBytes := crypto.MarshalECPrivateKey(orgCAPrivKey)
	defer crypto.ZeroizeBytes(orgCAPrivBytes)

	// Wrap for member
	ephPub, wrappedKey, err := crypto.WrapKeyForMember(memberPub, orgCAPrivBytes)
	if err != nil {
		return fmt.Errorf("failed to wrap Org CA key for member %s: %w", memberID, err)
	}

	// Store the wrap
	record := &OrgCAWrapRecord{
		OrgID:        orgID,
		MemberID:     memberID,
		CertSerial:   certSerial,
		EphemeralPub: ephPub,
		WrappedKey:   wrappedKey,
		CreatedAt:    time.Now().UTC(),
	}

	if err := m.store.StoreOrgCAWrap(ctx, record); err != nil {
		return fmt.Errorf("failed to store Org CA wrap: %w", err)
	}

	return nil
}

// UnwrapOrgCA recovers the Org CA private key using a member's private key.
// This is used during decryption operations to get the Org CA key needed for ECIES.
func (m *OrgCAWrapManager) UnwrapOrgCA(
	ctx context.Context,
	orgID string,
	memberID string,
	memberPrivKey *ecdsa.PrivateKey,
) (*ecdsa.PrivateKey, error) {
	// Get the member's wrap record
	wrap, err := m.store.GetOrgCAWrap(ctx, orgID, memberID)
	if err != nil {
		return nil, fmt.Errorf("failed to get Org CA wrap: %w", err)
	}
	if wrap == nil {
		return nil, fmt.Errorf("no Org CA wrap found for member %s in org %s", memberID, orgID)
	}
	if wrap.RevokedAt != nil {
		return nil, fmt.Errorf("Org CA wrap for member %s has been revoked", memberID)
	}

	// Unwrap
	orgCAPrivBytes, err := crypto.UnwrapKeyForMember(memberPrivKey, wrap.EphemeralPub, wrap.WrappedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap Org CA key: %w", err)
	}
	defer crypto.ZeroizeBytes(orgCAPrivBytes)

	// Deserialize Org CA private key
	orgCAPrivKey, err := crypto.UnmarshalECPrivateKey(orgCAPrivBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal Org CA key: %w", err)
	}

	return orgCAPrivKey, nil
}

// RewrapOrgCAForNewMember wraps the Org CA private key for a new member.
// This requires an existing member to unwrap first, then re-wrap for the new member.
func (m *OrgCAWrapManager) RewrapOrgCAForNewMember(
	ctx context.Context,
	orgID string,
	existingMemberID string,
	existingMemberPrivKey *ecdsa.PrivateKey,
	newMemberID string,
	newCertSerial string,
	newMemberPub *ecdsa.PublicKey,
) error {
	// Unwrap using existing member's key
	orgCAPrivKey, err := m.UnwrapOrgCA(ctx, orgID, existingMemberID, existingMemberPrivKey)
	if err != nil {
		return fmt.Errorf("failed to unwrap Org CA key: %w", err)
	}

	// Wrap for new member
	if err := m.WrapOrgCAForMember(ctx, orgID, newMemberID, newCertSerial, newMemberPub, orgCAPrivKey); err != nil {
		return fmt.Errorf("failed to wrap Org CA key for new member: %w", err)
	}

	return nil
}

// GetWrapData returns the raw wrap data for client-side unwrapping (BYOK flow).
// The client uses this to perform ECDH and unwrap the Org CA key locally.
func (m *OrgCAWrapManager) GetWrapData(
	ctx context.Context,
	orgID string,
	memberID string,
) (ephemeralPub []byte, wrappedKey []byte, err error) {
	wrap, err := m.store.GetOrgCAWrap(ctx, orgID, memberID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get Org CA wrap: %w", err)
	}
	if wrap == nil {
		return nil, nil, fmt.Errorf("no Org CA wrap found for member %s in org %s", memberID, orgID)
	}
	if wrap.RevokedAt != nil {
		return nil, nil, fmt.Errorf("Org CA wrap for member %s has been revoked", memberID)
	}

	return wrap.EphemeralPub, wrap.WrappedKey, nil
}

// ParseMemberCertPublicKey extracts the ECDSA public key from a PEM-encoded certificate.
func ParseMemberCertPublicKey(certPEM string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("certificate does not contain an ECDSA public key")
	}

	return pub, nil
}
