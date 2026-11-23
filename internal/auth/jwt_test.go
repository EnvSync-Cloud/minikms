package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestHashJWT(t *testing.T) {
	t.Run("deterministic", func(t *testing.T) {
		h1 := HashJWT("token-string-1")
		h2 := HashJWT("token-string-1")
		if h1 != h2 {
			t.Fatal("same input should produce same hash")
		}
	})

	t.Run("different inputs differ", func(t *testing.T) {
		h1 := HashJWT("token-1")
		h2 := HashJWT("token-2")
		if h1 == h2 {
			t.Fatal("different inputs should produce different hash")
		}
	})

	t.Run("64 hex chars", func(t *testing.T) {
		h := HashJWT("some-jwt-string")
		if len(h) != 64 {
			t.Fatalf("hash length: got %d, want 64", len(h))
		}
	})
}

func TestHashSubject(t *testing.T) {
	t.Run("deterministic", func(t *testing.T) {
		h1 := HashSubject("user@example.com")
		h2 := HashSubject("user@example.com")
		if h1 != h2 {
			t.Fatal("same input should produce same hash")
		}
	})

	t.Run("different inputs differ", func(t *testing.T) {
		h1 := HashSubject("user1@example.com")
		h2 := HashSubject("user2@example.com")
		if h1 == h2 {
			t.Fatal("different inputs should produce different hash")
		}
	})

	t.Run("64 hex chars", func(t *testing.T) {
		h := HashSubject("subject")
		if len(h) != 64 {
			t.Fatalf("hash length: got %d, want 64", len(h))
		}
	})
}

func TestValidateByJTI(t *testing.T) {
	ctx := context.Background()

	t.Run("valid token", func(t *testing.T) {
		reg := newMockRegistry()
		rawJWT := "valid-jwt-token"
		reg.tokens["jti-1"] = &TokenEntry{
			JTI:       "jti-1",
			JWTHash:   HashJWT(rawJWT),
			ExpiresAt: time.Now().Add(1 * time.Hour),
			Revoked:   false,
		}
		v := NewJWTValidator(reg)
		entry, err := v.ValidateByJTI(ctx, "jti-1", rawJWT)
		if err != nil {
			t.Fatalf("ValidateByJTI: %v", err)
		}
		if entry.JTI != "jti-1" {
			t.Errorf("got JTI %q, want %q", entry.JTI, "jti-1")
		}
	})

	t.Run("not found", func(t *testing.T) {
		reg := newMockRegistry()
		v := NewJWTValidator(reg)
		_, err := v.ValidateByJTI(ctx, "nonexistent", "token")
		if err == nil {
			t.Fatal("expected error for not found token")
		}
	})

	t.Run("revoked", func(t *testing.T) {
		reg := newMockRegistry()
		reg.tokens["jti-2"] = &TokenEntry{
			JTI:       "jti-2",
			JWTHash:   HashJWT("token"),
			ExpiresAt: time.Now().Add(1 * time.Hour),
			Revoked:   true,
		}
		v := NewJWTValidator(reg)
		_, err := v.ValidateByJTI(ctx, "jti-2", "token")
		if err == nil {
			t.Fatal("expected error for revoked token")
		}
	})

	t.Run("expired", func(t *testing.T) {
		reg := newMockRegistry()
		reg.tokens["jti-3"] = &TokenEntry{
			JTI:       "jti-3",
			JWTHash:   HashJWT("token"),
			ExpiresAt: time.Now().Add(-1 * time.Hour),
			Revoked:   false,
		}
		v := NewJWTValidator(reg)
		_, err := v.ValidateByJTI(ctx, "jti-3", "token")
		if err == nil {
			t.Fatal("expected error for expired token")
		}
	})

	t.Run("hash mismatch", func(t *testing.T) {
		reg := newMockRegistry()
		reg.tokens["jti-4"] = &TokenEntry{
			JTI:       "jti-4",
			JWTHash:   HashJWT("original-token"),
			ExpiresAt: time.Now().Add(1 * time.Hour),
			Revoked:   false,
		}
		v := NewJWTValidator(reg)
		_, err := v.ValidateByJTI(ctx, "jti-4", "different-token")
		if err == nil {
			t.Fatal("expected error for hash mismatch")
		}
	})
}

func TestValidateByJTI_RevokedCertificate(t *testing.T) {
	raw := signTestJWT(t, jwt.MapClaims{
		"jti":         "jti-revoked-cert",
		"sub":         "member-1",
		"org":         "org-1",
		"cert_serial": "aa11",
	})
	reg := newMockRegistry()
	reg.tokens["jti-revoked-cert"] = &TokenEntry{
		JTI:        "jti-revoked-cert",
		JWTHash:    HashJWT(raw),
		ExpiresAt:  time.Now().Add(time.Hour),
		Revoked:    false,
		CertSerial: "aa11",
		CertStatus: "revoked",
	}
	_, err := NewJWTValidator(reg).ValidateByJTI(context.Background(), "jti-revoked-cert", raw)
	if !errors.Is(err, errCertificateInactive) {
		t.Fatalf("err = %v, want certificate inactive", err)
	}
}

func TestValidateByJTI_MissingCertificate(t *testing.T) {
	raw := signTestJWT(t, jwt.MapClaims{
		"jti":         "jti-missing-cert",
		"sub":         "member-1",
		"org":         "org-1",
		"cert_serial": "bb22",
	})
	reg := newMockRegistry()
	reg.tokens["jti-missing-cert"] = &TokenEntry{
		JTI:        "jti-missing-cert",
		JWTHash:    HashJWT(raw),
		ExpiresAt:  time.Now().Add(time.Hour),
		Revoked:    false,
		CertSerial: "bb22",
	}
	_, err := NewJWTValidator(reg).ValidateByJTI(context.Background(), "jti-missing-cert", raw)
	if !errors.Is(err, errCertificateMissing) {
		t.Fatalf("err = %v, want missing certificate", err)
	}
}

func TestValidateByJTI_CertSessionWithoutSerial(t *testing.T) {
	raw := signTestJWT(t, jwt.MapClaims{
		"jti":         "jti-legacy-session",
		"sub":         "member-1",
		"org":         "org-1",
		"cert_serial": "",
	})
	reg := newMockRegistry()
	reg.tokens["jti-legacy-session"] = &TokenEntry{
		JTI:       "jti-legacy-session",
		JWTHash:   HashJWT(raw),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	_, err := NewJWTValidator(reg).ValidateByJTI(context.Background(), "jti-legacy-session", raw)
	if !errors.Is(err, errCertificateSerialMissing) {
		t.Fatalf("err = %v, want missing certificate serial", err)
	}
}

func TestValidateByJTI_NonCertTokenWithoutSerial(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	reg := newMockRegistry()
	issuer := NewTokenIssuer(key, "minikms", time.Hour, reg)
	raw, err := issuer.IssueToken(context.Background(), "user@example.com", "org-1", "admin")
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}
	claims := &Claims{}
	if _, _, err := jwt.NewParser().ParseUnverified(raw, claims); err != nil {
		t.Fatalf("ParseUnverified: %v", err)
	}
	entry, err := NewJWTValidator(reg).ValidateByJTI(context.Background(), claims.ID, raw)
	if err != nil {
		t.Fatalf("ValidateByJTI: %v", err)
	}
	if entry.CertSerial != "" || entry.CertStatus != "" {
		t.Fatalf("non-cert token serial=%q status=%q", entry.CertSerial, entry.CertStatus)
	}
}

func TestValidateByJTI_ActiveCertificate(t *testing.T) {
	raw := signTestJWT(t, jwt.MapClaims{
		"jti":         "jti-active-cert",
		"sub":         "member-1",
		"org":         "org-1",
		"cert_serial": "cc33",
	})
	reg := newMockRegistry()
	reg.tokens["jti-active-cert"] = &TokenEntry{
		JTI:        "jti-active-cert",
		JWTHash:    HashJWT(raw),
		ExpiresAt:  time.Now().Add(time.Hour),
		CertSerial: "cc33",
		CertStatus: "active",
	}
	entry, err := NewJWTValidator(reg).ValidateByJTI(context.Background(), "jti-active-cert", raw)
	if err != nil {
		t.Fatalf("ValidateByJTI: %v", err)
	}
	if entry.CertSerial != "cc33" || entry.CertStatus != "active" {
		t.Fatalf("serial=%q status=%q", entry.CertSerial, entry.CertStatus)
	}
}

func TestValidateByJTI_CertSerialMismatch(t *testing.T) {
	raw := signTestJWT(t, jwt.MapClaims{
		"jti":         "jti-mismatch",
		"sub":         "member-1",
		"org":         "org-1",
		"cert_serial": "ffff",
	})
	reg := newMockRegistry()
	reg.tokens["jti-mismatch"] = &TokenEntry{
		JTI:        "jti-mismatch",
		JWTHash:    HashJWT(raw),
		ExpiresAt:  time.Now().Add(time.Hour),
		CertSerial: "cc33",
		CertStatus: "active",
	}
	_, err := NewJWTValidator(reg).ValidateByJTI(context.Background(), "jti-mismatch", raw)
	if !errors.Is(err, errCertificateSerialMismatch) {
		t.Fatalf("err = %v, want serial mismatch", err)
	}
}

func TestTokenLookup_RevokedAndMissingCertificate(t *testing.T) {
	ctx := context.Background()
	reg := newMockRegistry()
	reg.certs = map[string]string{
		"live": "active",
		"dead": "revoked",
	}
	liveRaw := signTestJWT(t, jwt.MapClaims{"jti": "lookup-live", "sub": "m", "org": "org", "cert_serial": "live"})
	deadRaw := signTestJWT(t, jwt.MapClaims{"jti": "lookup-dead", "sub": "m", "org": "org", "cert_serial": "dead"})
	goneRaw := signTestJWT(t, jwt.MapClaims{"jti": "lookup-gone", "sub": "m", "org": "org", "cert_serial": "gone"})
	reg.tokens["lookup-live"] = &TokenEntry{JTI: "lookup-live", JWTHash: HashJWT(liveRaw), ExpiresAt: time.Now().Add(time.Hour), CertSerial: "live"}
	reg.tokens["lookup-dead"] = &TokenEntry{JTI: "lookup-dead", JWTHash: HashJWT(deadRaw), ExpiresAt: time.Now().Add(time.Hour), Revoked: false, CertSerial: "dead"}
	reg.tokens["lookup-gone"] = &TokenEntry{JTI: "lookup-gone", JWTHash: HashJWT(goneRaw), ExpiresAt: time.Now().Add(time.Hour), CertSerial: "gone"}

	v := NewJWTValidator(reg)
	live, err := v.ValidateByJTI(ctx, "lookup-live", liveRaw)
	if err != nil {
		t.Fatalf("active certificate: %v", err)
	}
	if live.CertStatus != "active" {
		t.Fatalf("lookup status = %q, want active", live.CertStatus)
	}
	if _, err := v.ValidateByJTI(ctx, "lookup-dead", deadRaw); !errors.Is(err, errCertificateInactive) {
		t.Fatalf("revoked certificate err = %v", err)
	}
	if _, err := v.ValidateByJTI(ctx, "lookup-gone", goneRaw); !errors.Is(err, errCertificateMissing) {
		t.Fatalf("missing certificate err = %v", err)
	}
	if reg.tokens["lookup-dead"].CertStatus != "" {
		t.Fatal("lookup wrote certificate status back onto the stored row")
	}
}

func TestRevoke(t *testing.T) {
	reg := newMockRegistry()
	reg.tokens["jti-1"] = &TokenEntry{
		JTI:     "jti-1",
		Revoked: false,
	}
	v := NewJWTValidator(reg)
	err := v.Revoke(context.Background(), "jti-1")
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if !reg.tokens["jti-1"].Revoked {
		t.Fatal("token should be revoked")
	}
}

func signTestJWT(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	raw, err := jwt.NewWithClaims(jwt.SigningMethodES256, claims).SignedString(key)
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}
	return raw
}

// In-package mock for TokenRegistry.
// certs, when set, is the certificate status join: serial -> status.
// A serial absent from the map is a missing certificate.
type mockRegistry struct {
	tokens map[string]*TokenEntry
	certs  map[string]string
}

func newMockRegistry() *mockRegistry {
	return &mockRegistry{tokens: make(map[string]*TokenEntry)}
}

func (m *mockRegistry) StoreToken(_ context.Context, entry *TokenEntry) error {
	m.tokens[entry.JTI] = entry
	return nil
}

func (m *mockRegistry) GetToken(_ context.Context, jti string) (*TokenEntry, error) {
	entry, ok := m.tokens[jti]
	if !ok {
		return nil, nil
	}
	cp := *entry
	if m.certs != nil && cp.CertSerial != "" {
		if status, found := m.certs[cp.CertSerial]; found {
			cp.CertStatus = status
		} else {
			cp.CertStatus = ""
		}
	}
	return &cp, nil
}

func (m *mockRegistry) RevokeToken(_ context.Context, jti string) error {
	entry, ok := m.tokens[jti]
	if !ok {
		return fmt.Errorf("not found")
	}
	entry.Revoked = true
	return nil
}

func (m *mockRegistry) CleanupExpired(_ context.Context) error {
	return nil
}
