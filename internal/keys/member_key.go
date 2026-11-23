package keys

import (
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/envsync-cloud/minikms/internal/crypto"
)

const (
	// MemberKeyWrapped means the blob opens with MemberKeyAAD.
	MemberKeyWrapped = "wrapped"
	// MemberKeyRaw means the blob does not open with MemberKeyAAD and parses
	// as the previous member-key encoding.
	MemberKeyRaw = "raw"
	// MemberKeyEmpty means the row has no member key material.
	MemberKeyEmpty = "empty"
	// MemberKeyFailed means the blob is neither an envelope nor the previous encoding.
	MemberKeyFailed = "failed"
)

var (
	// ErrMemberKeyUnavailable means the certificate row has no member key material.
	ErrMemberKeyUnavailable = errors.New("managed member key is not available")

	// ErrMemberKeyEnvelope means the member-key envelope could not be opened.
	ErrMemberKeyEnvelope = errors.New("managed member key envelope could not be opened")

	// ErrMemberKeyLegacyDisabled means the row is not a member-key envelope and
	// legacy member-key read is disabled.
	// TODO: remove the legacy member-key read path after the member-key wrap backfill check passes.
	ErrMemberKeyLegacyDisabled = errors.New("managed member key envelope could not be opened; legacy member-key read is disabled")
)

// MemberKeyAAD binds managed member key material to its organization and certificate serial.
// The format is member-key:<orgID>:<serial>. It is distinct from the organization CA
// associated data org-ca-key:<orgID>:<serial>. A later root-key rewrap of organization
// master-key envelopes needs to re-seal blobs that use this associated data.
func MemberKeyAAD(orgID, serial string) string {
	return "member-key:" + orgID + ":" + serial
}

// ClassifyMemberKeyMaterial reports whether blob is a member-key envelope, the
// previous member-key encoding, empty, or unrecognized.
// Wrapped and raw results include key bytes that the caller must zeroize.
// Wrapped means the blob opens with MemberKeyAAD under orgKey. Raw means it does
// not open and parses as the previous encoding.
func ClassifyMemberKeyMaterial(orgKey, blob []byte, orgID, serial string) (string, []byte) {
	if len(blob) == 0 {
		return MemberKeyEmpty, nil
	}
	plain, err := crypto.Decrypt(orgKey, blob, []byte(MemberKeyAAD(orgID, serial)))
	if err == nil {
		return MemberKeyWrapped, plain
	}
	if _, err := crypto.UnmarshalECPrivateKey(blob); err == nil {
		return MemberKeyRaw, append([]byte(nil), blob...)
	}
	return MemberKeyFailed, nil
}

// OpenMemberPrivateKey opens managed member key material sealed with MemberKeyAAD.
// When allowLegacy is set and the envelope does not open, the previous encoding is accepted.
// Key bytes are zeroized after the key is parsed.
// TODO: remove the legacy member-key read path after the member-key wrap backfill check passes.
func OpenMemberPrivateKey(mgr *OrgKeyManager, orgID, serial string, blob []byte, allowLegacy bool) (*ecdsa.PrivateKey, error) {
	if mgr == nil {
		return nil, fmt.Errorf("organization key manager is not configured")
	}
	if len(blob) == 0 {
		return nil, ErrMemberKeyUnavailable
	}
	orgKey, err := mgr.DeriveOrgKey(orgID)
	if err != nil {
		crypto.ZeroizeBytes(orgKey)
		return nil, ErrMemberKeyEnvelope
	}
	defer zeroize(orgKey)

	kind, keyBytes := ClassifyMemberKeyMaterial(orgKey, blob, orgID, serial)
	defer crypto.ZeroizeBytes(keyBytes)
	switch kind {
	case MemberKeyWrapped:
		key, err := crypto.UnmarshalECPrivateKey(keyBytes)
		if err != nil {
			return nil, ErrMemberKeyEnvelope
		}
		return key, nil
	case MemberKeyRaw:
		if !allowLegacy {
			return nil, ErrMemberKeyLegacyDisabled
		}
		key, err := crypto.UnmarshalECPrivateKey(keyBytes)
		if err != nil {
			return nil, ErrMemberKeyEnvelope
		}
		return key, nil
	case MemberKeyEmpty:
		return nil, ErrMemberKeyUnavailable
	default:
		return nil, ErrMemberKeyEnvelope
	}
}
