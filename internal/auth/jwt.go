package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// TokenRegistry defines the interface for token storage and lookup.
// Stores ONLY jti + hash — full JWT is never persisted (Issue #5, #12).
type TokenRegistry interface {
	// StoreToken stores token metadata (jti, subject_hash, jwt_hash, expiry).
	StoreToken(ctx context.Context, entry *TokenEntry) error
	// GetToken retrieves a token entry by jti.
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
}

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
// Returns the token entry if valid, error if invalid/revoked/expired.
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

	return entry, nil
}

// Revoke revokes a token by its jti.
func (v *JWTValidator) Revoke(ctx context.Context, jti string) error {
	return v.registry.RevokeToken(ctx, jti)
}
