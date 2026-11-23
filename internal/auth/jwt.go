package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TokenRegistry defines the interface for token storage and lookup.
// Stores ONLY jti + hash — full JWT is never persisted (Issue #5, #12).
type TokenRegistry interface {
	// StoreToken stores token metadata (jti, subject_hash, jwt_hash, expiry).
	StoreToken(ctx context.Context, entry *TokenEntry) error
	// GetToken retrieves a token entry by jti.
	// When the row has cert_serial, CertStatus is the certificates.status
	// seen by that lookup. An empty CertStatus means the certificate row is absent.
	GetToken(ctx context.Context, jti string) (*TokenEntry, error)
	// RevokeToken marks a token as revoked by jti.
	RevokeToken(ctx context.Context, jti string) error
	// CleanupExpired removes expired token entries.
	CleanupExpired(ctx context.Context) error
}

// TokenEntry is stored in the token_registry table.
// The full JWT is NEVER stored — only its hash for validation.
type TokenEntry struct {
	JTI         string
	SubjectHash string // SHA-256 of subject identifier
	JWTHash     string // SHA-256 of the full JWT string
	IssuedAt    time.Time
	ExpiresAt   time.Time
	Revoked     bool
	CertSerial  string // certificate serial stored for this session; empty for the non-cert token class
	// CertStatus is filled by lookup from certificates.status. It is not a token_registry column.
	// Empty means the lookup found no certificate row.
	CertStatus string
	Scopes     []string // granted scopes
}

var (
	errCertificateMissing        = errors.New("certificate is missing")
	errCertificateInactive       = errors.New("certificate is not active")
	errCertificateSerialMissing  = errors.New("certificate serial is missing")
	errCertificateSerialMismatch = errors.New("certificate serial does not match")
)

// JWTValidator validates JWTs by jti + hash lookup (Issue #5, #12).
// Steps: parse JWT -> extract jti -> lookup in DB -> verify jwt_hash matches.
type JWTValidator struct {
	registry TokenRegistry
}

// NewJWTValidator creates a new JWTValidator.
func NewJWTValidator(registry TokenRegistry) *JWTValidator {
	return &JWTValidator{registry: registry}
}

// HashJWT computes SHA-256 of the raw JWT string for storage/comparison.
func HashJWT(rawJWT string) string {
	h := sha256.Sum256([]byte(rawJWT))
	return hex.EncodeToString(h[:])
}

// HashSubject computes SHA-256 of the subject identifier.
func HashSubject(subject string) string {
	h := sha256.Sum256([]byte(subject))
	return hex.EncodeToString(h[:])
}

// ValidateByJTI validates a JWT by looking up its jti and comparing the hash.
// Cert-session tokens are also checked against the certificate status from that lookup.
// Returns the token entry if valid, error if invalid, revoked, expired, or the
// certificate is revoked or missing.
func (v *JWTValidator) ValidateByJTI(ctx context.Context, jti string, rawJWT string) (*TokenEntry, error) {
	entry, err := v.registry.GetToken(ctx, jti)
	if err != nil {
		return nil, fmt.Errorf("token lookup failed: %w", err)
	}
	if entry == nil {
		return nil, fmt.Errorf("token not found")
	}
	if entry.Revoked {
		return nil, fmt.Errorf("token has been revoked")
	}
	if time.Now().After(entry.ExpiresAt) {
		return nil, fmt.Errorf("token has expired")
	}

	presentedHash := HashJWT(rawJWT)
	if presentedHash != entry.JWTHash {
		return nil, fmt.Errorf("token hash mismatch")
	}
	if err := certificateBindingError(entry, rawJWT); err != nil {
		return nil, err
	}

	return entry, nil
}

// certificateBindingError reads the serial and status populated by token lookup.
//
// A row with cert_serial is accepted only when that certificate exists and its
// status is active. A JWT that carries a cert_serial claim but whose row has an
// empty serial is rejected. Rows with an empty serial and no cert_serial claim
// are the non-cert token class and are left unchanged.
func certificateBindingError(entry *TokenEntry, rawJWT string) error {
	presented, isSession := presentedSessionCertSerial(rawJWT)
	if entry.CertSerial == "" {
		if isSession {
			return errCertificateSerialMissing
		}
		return nil
	}
	if entry.CertStatus == "" {
		return errCertificateMissing
	}
	if entry.CertStatus != "active" {
		return errCertificateInactive
	}
	if isSession && presented != entry.CertSerial {
		return errCertificateSerialMismatch
	}
	return nil
}

// presentedSessionCertSerial reports the cert_serial claim when the JWT has one.
// The claim marks a cert-session token even when the value is empty.
func presentedSessionCertSerial(rawJWT string) (string, bool) {
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(rawJWT, claims); err != nil {
		return "", false
	}
	raw, ok := claims["cert_serial"]
	if !ok {
		return "", false
	}
	serial, ok := raw.(string)
	if !ok {
		return "", true
	}
	return serial, true
}

// Revoke revokes a token by its jti.
func (v *JWTValidator) Revoke(ctx context.Context, jti string) error {
	return v.registry.RevokeToken(ctx, jti)
}
