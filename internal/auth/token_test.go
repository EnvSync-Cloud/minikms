package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestTokenIssuer_IssueToken(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	reg := newMockRegistry()
	issuer := NewTokenIssuer(key, "minikms-test", 1*time.Hour, reg)

	signedToken, err := issuer.IssueToken(context.Background(), "user@test.com", "org1", "admin")
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}

	if signedToken == "" {
		t.Fatal("token should not be empty")
	}

	// Parse and verify with public key
	parsed, err := jwt.ParseWithClaims(signedToken, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return &key.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("ParseWithClaims: %v", err)
	}

	claims, ok := parsed.Claims.(*Claims)
	if !ok {
		t.Fatal("failed to cast claims")
	}

	if claims.Subject != "user@test.com" {
		t.Errorf("subject: got %q, want %q", claims.Subject, "user@test.com")
	}
	if claims.OrgID != "org1" {
		t.Errorf("org_id: got %q, want %q", claims.OrgID, "org1")
	}
	if claims.Role != "admin" {
		t.Errorf("role: got %q, want %q", claims.Role, "admin")
	}
	if claims.Issuer != "minikms-test" {
		t.Errorf("issuer: got %q, want %q", claims.Issuer, "minikms-test")
	}
	if claims.ID == "" {
		t.Error("JTI should not be empty")
	}
}

func TestTokenIssuer_IssueToken_StoresHash(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	reg := newMockRegistry()
	issuer := NewTokenIssuer(key, "minikms", 1*time.Hour, reg)

	signedToken, err := issuer.IssueToken(context.Background(), "user@test.com", "org1", "admin")
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}

	expectedHash := HashJWT(signedToken)

	// Find the stored token
	if len(reg.tokens) != 1 {
		t.Fatalf("expected 1 stored token, got %d", len(reg.tokens))
	}

	for _, entry := range reg.tokens {
		if entry.JWTHash != expectedHash {
			t.Errorf("stored hash: got %q, want %q", entry.JWTHash, expectedHash)
		}
		if entry.SubjectHash != HashSubject("user@test.com") {
			t.Error("stored subject hash doesn't match")
		}
	}
}

func TestTokenIssuer_IssueToken_UniqueJTI(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	reg := newMockRegistry()
	issuer := NewTokenIssuer(key, "minikms", 1*time.Hour, reg)

	token1, _ := issuer.IssueToken(context.Background(), "user1", "org1", "admin")
	token2, _ := issuer.IssueToken(context.Background(), "user2", "org1", "admin")

	// Parse JTIs
	parser := jwt.NewParser()
	claims1 := &Claims{}
	claims2 := &Claims{}
	if _, _, err := parser.ParseUnverified(token1, claims1); err != nil {
		t.Fatalf("ParseUnverified token1: %v", err)
	}
	if _, _, err := parser.ParseUnverified(token2, claims2); err != nil {
		t.Fatalf("ParseUnverified token2: %v", err)
	}

	if claims1.ID == claims2.ID {
		t.Fatal("two tokens should have different JTIs")
	}
}
