package dpop

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestJWKSRefreshesUnknownKidOnce(t *testing.T) {
	keyA := mustTestRSA(t)
	keyB := mustTestRSA(t)
	var hits atomic.Int32
	current := "a"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		key := keyA
		kid := current
		if current == "b" {
			key = keyB
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{jwk(kid, key)}})
	}))
	defer server.Close()
	set := NewJWKS(server.URL)

	if _, err := set.Keyfunc(tokenWithKid("a")); err != nil {
		t.Fatal(err)
	}
	if _, err := set.Keyfunc(tokenWithKid("a")); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 1 {
		t.Fatalf("cached kid fetches = %d", hits.Load())
	}
	current = "b"
	if _, err := set.Keyfunc(tokenWithKid("b")); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 2 {
		t.Fatalf("unknown kid fetches = %d", hits.Load())
	}
	if _, err := set.Keyfunc(tokenWithKid("missing")); err == nil {
		t.Fatal("missing kid was accepted")
	}
	afterMiss := hits.Load()
	if _, err := set.Keyfunc(tokenWithKid("missing")); err == nil {
		t.Fatal("missing kid was accepted during backoff")
	}
	if hits.Load() != afterMiss {
		t.Fatalf("backoff fetches = %d, want %d", hits.Load(), afterMiss)
	}
}

func tokenWithKid(kid string) *jwt.Token {
	return &jwt.Token{Header: map[string]any{"kid": kid}}
}

func mustTestRSA(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func jwk(kid string, key *rsa.PrivateKey) map[string]string {
	return map[string]string{
		"kty": "RSA",
		"kid": kid,
		"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(bigEndian(key.E)),
	}
}

func bigEndian(value int) []byte {
	if value == 0 {
		return []byte{0}
	}
	var buf [8]byte
	i := len(buf)
	for value > 0 {
		i--
		buf[i] = byte(value)
		value >>= 8
	}
	return buf[i:]
}
