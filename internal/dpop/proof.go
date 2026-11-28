// Package dpop checks a forwarded proof on user-data calls.
// The check uses only server configuration. Call metadata cannot select a mode.
package dpop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const proofType = "dpop+jwt"

// Proof is a signature-checked DPoP proof bound to one access token.
type Proof struct {
	JTI   string
	HTM   string
	HTU   string
	JKT   string
	Hash  string
	Token string
}

type proofClaims struct {
	jwt.RegisteredClaims
	HTM string `json:"htm"`
	HTU string `json:"htu"`
	ATH string `json:"ath"`
}

type accessClaims struct {
	jwt.RegisteredClaims
	CNF struct {
		JKT string `json:"jkt"`
	} `json:"cnf"`
}

// VerifyAccessToken checks the access token and returns its subject and cnf.jkt.
func VerifyAccessToken(raw string, keyfunc jwt.Keyfunc, issuer, audience string, now time.Time) (string, string, error) {
	if raw == "" || keyfunc == nil {
		return "", "", errors.New("access token is missing")
	}
	claims := &accessClaims{}
	opts := []jwt.ParserOption{
		jwt.WithValidMethods([]string{"RS256", "ES256"}),
		jwt.WithTimeFunc(func() time.Time { return now }),
		jwt.WithExpirationRequired(),
	}
	if issuer != "" {
		opts = append(opts, jwt.WithIssuer(issuer))
	}
	if audience != "" {
		opts = append(opts, jwt.WithAudience(audience))
	}
	if _, err := jwt.ParseWithClaims(raw, claims, keyfunc, opts...); err != nil {
		return "", "", fmt.Errorf("access token: %w", err)
	}
	if claims.Subject == "" || claims.CNF.JKT == "" {
		return "", "", errors.New("access token is missing sub or cnf.jkt")
	}
	return claims.Subject, claims.CNF.JKT, nil
}

// VerifyProof checks an ES256 proof and binds it to the access token bytes.
// A proof signed by a different key, or a changed proof, fails here.
func VerifyProof(raw, accessToken string, now time.Time, maxAge time.Duration) (Proof, error) {
	if raw == "" || accessToken == "" {
		return Proof{}, errors.New("proof is missing")
	}
	claims := &proofClaims{}
	token, err := jwt.ParseWithClaims(raw, claims, func(token *jwt.Token) (any, error) {
		if token.Method == nil || token.Method.Alg() != jwt.SigningMethodES256.Alg() {
			return nil, errors.New("proof alg is not ES256")
		}
		if typ, _ := token.Header["typ"].(string); typ != proofType {
			return nil, errors.New("proof typ is not dpop+jwt")
		}
		pub, err := publicKeyFromJWK(token.Header["jwk"])
		if err != nil {
			return nil, err
		}
		return pub, nil
	}, jwt.WithoutClaimsValidation())
	if err != nil || token == nil || !token.Valid {
		return Proof{}, fmt.Errorf("proof: %w", err)
	}
	jkt, err := thumbprintFromJWK(token.Header["jwk"])
	if err != nil {
		return Proof{}, err
	}
	if claims.ID == "" || claims.IssuedAt == nil {
		return Proof{}, errors.New("proof is missing jti or iat")
	}
	age := now.Sub(claims.IssuedAt.Time)
	if age < 0 {
		age = -age
	}
	if maxAge <= 0 || age > maxAge {
		return Proof{}, errors.New("proof is outside the freshness window")
	}
	sum := sha256.Sum256([]byte(accessToken))
	ath := base64.RawURLEncoding.EncodeToString(sum[:])
	if claims.ATH == "" || claims.ATH != ath {
		return Proof{}, errors.New("proof is not bound to the access token")
	}
	if claims.HTM == "" || claims.HTU == "" {
		return Proof{}, errors.New("proof is missing htm or htu")
	}
	proofHash := sha256.Sum256([]byte(raw))
	return Proof{
		JTI:   claims.ID,
		HTM:   claims.HTM,
		HTU:   claims.HTU,
		JKT:   jkt,
		Hash:  base64.RawURLEncoding.EncodeToString(proofHash[:]),
		Token: raw,
	}, nil
}

func publicKeyFromJWK(raw any) (*ecdsa.PublicKey, error) {
	x, y, err := jwkCoordinates(raw)
	if err != nil {
		return nil, err
	}
	xb, err := base64.RawURLEncoding.DecodeString(x)
	if err != nil {
		return nil, fmt.Errorf("jwk x: %w", err)
	}
	yb, err := base64.RawURLEncoding.DecodeString(y)
	if err != nil {
		return nil, fmt.Errorf("jwk y: %w", err)
	}
	if len(xb) != 32 || len(yb) != 32 {
		return nil, errors.New("jwk coordinates are not P-256")
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xb),
		Y:     new(big.Int).SetBytes(yb),
	}, nil
}

func thumbprintFromJWK(raw any) (string, error) {
	x, y, err := jwkCoordinates(raw)
	if err != nil {
		return "", err
	}
	// RFC 7638: lexicographic required members, no whitespace.
	canonical := fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}`, x, y)
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

func jwkCoordinates(raw any) (string, string, error) {
	fields, ok := jwkMap(raw)
	if !ok {
		return "", "", errors.New("proof jwk is missing")
	}
	if fields["kty"] != "EC" || fields["crv"] != "P-256" {
		return "", "", errors.New("proof jwk is not P-256")
	}
	if _, private := fields["d"]; private {
		return "", "", errors.New("proof jwk must be public")
	}
	x, _ := fields["x"].(string)
	y, _ := fields["y"].(string)
	if x == "" || y == "" {
		return "", "", errors.New("proof jwk is missing coordinates")
	}
	// Canonical thumbprint uses unpadded base64url.
	xb, err := base64.RawURLEncoding.DecodeString(x)
	if err != nil {
		return "", "", fmt.Errorf("jwk x: %w", err)
	}
	yb, err := base64.RawURLEncoding.DecodeString(y)
	if err != nil {
		return "", "", fmt.Errorf("jwk y: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(xb), base64.RawURLEncoding.EncodeToString(yb), nil
}

func jwkMap(raw any) (map[string]any, bool) {
	switch fields := raw.(type) {
	case map[string]any:
		return fields, true
	case map[string]string:
		out := make(map[string]any, len(fields))
		for key, value := range fields {
			out[key] = value
		}
		return out, true
	default:
		return nil, false
	}
}
