package auth

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// TokenIssuer issues JWTs for authenticated clients.
// There is NO refresh token mechanism (Issue #4) — clients must re-authenticate
// via certificate chain when their token expires.
type TokenIssuer struct {
	signingKey *ecdsa.PrivateKey
	issuer     string
	ttl        time.Duration
	registry   TokenRegistry
}

// NewTokenIssuer creates a new TokenIssuer.
func NewTokenIssuer(signingKey *ecdsa.PrivateKey, issuer string, ttl time.Duration, registry TokenRegistry) *TokenIssuer {
	return &TokenIssuer{
		signingKey: signingKey,
		issuer:     issuer,
		ttl:        ttl,
		registry:   registry,
	}
}

// Claims represents the JWT claims for a miniKMS token.
type Claims struct {
	jwt.RegisteredClaims
	OrgID  string `json:"org_id,omitempty"`
	Role   string `json:"role,omitempty"`
}

// IssueToken creates a new signed JWT for the given subject.
// The JWT hash is stored in the registry — the full JWT is NOT stored.
func (t *TokenIssuer) IssueToken(ctx context.Context, subject, orgID, role string) (string, error) {
	jti := uuid.New().String()
	now := time.Now()

	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			Subject:   subject,
			Issuer:    t.issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(t.ttl)),
		},
		OrgID: orgID,
		Role:  role,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	signedToken, err := token.SignedString(t.signingKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	entry := &TokenEntry{
		JTI:         jti,
		SubjectHash: HashSubject(subject),
		JWTHash:     HashJWT(signedToken),
		IssuedAt:    now,
		ExpiresAt:   now.Add(t.ttl),
		Revoked:     false,
	}

	if err := t.registry.StoreToken(ctx, entry); err != nil {
		return "", fmt.Errorf("failed to store token entry: %w", err)
	}

	return signedToken, nil
}
