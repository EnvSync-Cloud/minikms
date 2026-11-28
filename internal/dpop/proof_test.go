package dpop

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestOriginalProofMatchesToken(t *testing.T) {
	now := time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)
	dpopKey := mustP256(t)
	accessKey := mustRSA(t)
	token := signAccess(t, accessKey, jwkThumb(t, dpopKey), now)
	proof := signProof(t, dpopKey, token, "GET", "https://api.envsync.cloud/api/secrets", now)

	sub, jkt, err := VerifyAccessToken(token, rsaKeyfunc(accessKey), "https://atrium.envsync.cloud", "envsync-api", now)
	if err != nil {
		t.Fatal(err)
	}
	checked, err := VerifyProof(proof, token, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if checked.JKT != jkt || sub == "" {
		t.Fatalf("binding sub=%q jkt=%q proof=%q", sub, jkt, checked.JKT)
	}
}

func TestMutatedProofRejected(t *testing.T) {
	now := time.Now()
	dpopKey := mustP256(t)
	accessKey := mustRSA(t)
	token := signAccess(t, accessKey, jwkThumb(t, dpopKey), now)
	proof := signProof(t, dpopKey, token, "GET", "https://api.envsync.cloud/api/secrets", now)
	mutated := proof[:len(proof)-2] + flip(proof[len(proof)-2:])
	if _, err := VerifyProof(mutated, token, now, time.Minute); err == nil {
		t.Fatal("mutated proof was accepted")
	}
}

func TestOtherKeyRejected(t *testing.T) {
	now := time.Now()
	userKey := mustP256(t)
	otherKey := mustP256(t)
	accessKey := mustRSA(t)
	token := signAccess(t, accessKey, jwkThumb(t, userKey), now)
	proof := signProof(t, otherKey, token, "GET", "https://api.envsync.cloud/api/secrets", now)
	checked, err := VerifyProof(proof, token, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	_, jkt, err := VerifyAccessToken(token, rsaKeyfunc(accessKey), "https://atrium.envsync.cloud", "envsync-api", now)
	if err != nil {
		t.Fatal(err)
	}
	if checked.JKT == jkt {
		t.Fatal("a different signing key matched the token thumbprint")
	}
}

func TestReplayBudget(t *testing.T) {
	store := NewMemoryReplay()
	ctx := context.Background()
	if err := store.Admit(ctx, "jti", "req", "hash", 2, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := store.Admit(ctx, "jti", "req", "hash", 2, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := store.Admit(ctx, "jti", "req", "hash", 2, time.Minute); err != ErrReplayed {
		t.Fatalf("third call = %v", err)
	}
	if err := store.Admit(ctx, "jti", "other", "hash", 2, time.Minute); err != ErrReplayed {
		t.Fatalf("different request = %v", err)
	}
}

func mustP256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func mustRSA(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func rsaKeyfunc(key *rsa.PrivateKey) jwt.Keyfunc {
	return func(token *jwt.Token) (any, error) {
		return &key.PublicKey, nil
	}
}

func signAccess(t *testing.T, key *rsa.PrivateKey, jkt string, now time.Time) string {
	t.Helper()
	claims := accessClaims{RegisteredClaims: jwt.RegisteredClaims{
		Subject:   "user-1",
		Issuer:    "https://atrium.envsync.cloud",
		Audience:  jwt.ClaimStrings{"envsync-api"},
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		IssuedAt:  jwt.NewNumericDate(now),
	}}
	claims.CNF.JKT = jkt
	raw, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func signProof(t *testing.T, key *ecdsa.PrivateKey, accessToken, htm, htu string, now time.Time) string {
	t.Helper()
	x, y := jwkXY(key)
	sum := sha256.Sum256([]byte(accessToken))
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, proofClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:       "proof-jti",
			IssuedAt: jwt.NewNumericDate(now),
		},
		HTM: htm,
		HTU: htu,
		ATH: base64.RawURLEncoding.EncodeToString(sum[:]),
	})
	tok.Header["typ"] = proofType
	tok.Header["jwk"] = map[string]string{"kty": "EC", "crv": "P-256", "x": x, "y": y}
	raw, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func jwkThumb(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	x, y := jwkXY(key)
	thumb, err := thumbprintFromJWK(map[string]any{"kty": "EC", "crv": "P-256", "x": x, "y": y})
	if err != nil {
		t.Fatal(err)
	}
	return thumb
}

func jwkXY(key *ecdsa.PrivateKey) (string, string) {
	x := make([]byte, 32)
	y := make([]byte, 32)
	key.X.FillBytes(x)
	key.Y.FillBytes(y)
	return base64.RawURLEncoding.EncodeToString(x), base64.RawURLEncoding.EncodeToString(y)
}

func flip(tail string) string {
	buf := []byte(tail)
	buf[0] ^= 0x1
	return string(buf)
}
