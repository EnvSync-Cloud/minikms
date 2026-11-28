package dpop

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWKS fetches RSA verification keys for access tokens.
type JWKS struct {
	url    string
	client *http.Client
	mu     sync.Mutex
	keys   map[string]*rsa.PublicKey
	at     time.Time
}

func NewJWKS(rawURL string) *JWKS {
	return &JWKS{url: rawURL, client: &http.Client{Timeout: 5 * time.Second}}
}

// Keyfunc is a jwt.Keyfunc backed by the cached set.
func (j *JWKS) Keyfunc(token *jwt.Token) (any, error) {
	if j == nil {
		return nil, errors.New("jwks is not configured")
	}
	if err := j.refresh(false); err != nil && len(j.keys) == 0 {
		return nil, err
	}
	kid, _ := token.Header["kid"].(string)
	j.mu.Lock()
	defer j.mu.Unlock()
	if kid != "" {
		if key, ok := j.keys[kid]; ok {
			return key, nil
		}
	}
	if len(j.keys) == 1 {
		for _, key := range j.keys {
			return key, nil
		}
	}
	return nil, errors.New("jwks key not found")
}

func (j *JWKS) refresh(force bool) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if !force && j.keys != nil && time.Since(j.at) < 10*time.Minute {
		return nil
	}
	response, err := j.client.Get(j.url)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks status %s", response.Status)
	}
	var document struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(response.Body).Decode(&document); err != nil {
		return err
	}
	keys := make(map[string]*rsa.PublicKey, len(document.Keys))
	for i, item := range document.Keys {
		if item.Kty != "RSA" || item.N == "" || item.E == "" {
			continue
		}
		pub, err := rsaPublic(item.N, item.E)
		if err != nil {
			return err
		}
		kid := item.Kid
		if kid == "" {
			kid = fmt.Sprintf("key-%d", i)
		}
		keys[kid] = pub
	}
	if len(keys) == 0 {
		return errors.New("jwks contained no rsa keys")
	}
	j.keys = keys
	j.at = time.Now()
	return nil
}

func rsaPublic(nB64, eB64 string) (*rsa.PublicKey, error) {
	nb, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil {
		return nil, err
	}
	eb, err := base64.RawURLEncoding.DecodeString(eB64)
	if err != nil {
		return nil, err
	}
	e := 0
	for _, b := range eb {
		e = e<<8 | int(b)
	}
	if e == 0 {
		return nil, errors.New("jwks exponent is empty")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: e}, nil
}

// SplitOrigins splits a comma-separated origin list.
func SplitOrigins(raw string) []string {
	if raw == "" {
		return nil
	}
	var out []string
	start := 0
	for i := 0; i <= len(raw); i++ {
		if i == len(raw) || raw[i] == ',' {
			item := trimSpace(raw[start:i])
			if item != "" {
				out = append(out, item)
			}
			start = i + 1
		}
	}
	return out
}

func trimSpace(raw string) string {
	for len(raw) > 0 && (raw[0] == ' ' || raw[0] == '\t') {
		raw = raw[1:]
	}
	for len(raw) > 0 && (raw[len(raw)-1] == ' ' || raw[len(raw)-1] == '\t') {
		raw = raw[:len(raw)-1]
	}
	return raw
}
