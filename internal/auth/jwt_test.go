package auth

import (
	"context"
	"fmt"
	"testing"
	"time"
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

// In-package mock for TokenRegistry
type mockRegistry struct {
	tokens map[string]*TokenEntry
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
	return entry, nil
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
