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

const (
	jwksTTL     = 10 * time.Minute
	jwksBackoff = 5 * time.Second
)

// JWKS fetches RSA verification keys for access tokens.
// The network call is outside the cache lock, and one refresh is shared by concurrent callers.
type JWKS struct {
	url        string
	client     *http.Client
	mu         sync.Mutex
	keys       map[string]*rsa.PublicKey
	freshUntil time.Time
	retryAfter time.Time
	inflight   chan struct{}
	lastErr    error
}

func NewJWKS(rawURL string) *JWKS {
	return &JWKS{url: rawURL, client: &http.Client{Timeout: 5 * time.Second}}
}

// Keyfunc is a jwt.Keyfunc backed by the cached set.
// A known key is returned from the cache. An unknown kid triggers one refresh.
func (j *JWKS) Keyfunc(token *jwt.Token) (any, error) {
	if j == nil {
		return nil, errors.New("jwks is not configured")
	}
	kid, _ := token.Header["kid"].(string)
	if key, fresh := j.lookup(kid); fresh {
		return key, nil
	}
	if err := j.refresh(kid); err != nil {
		if key, _ := j.lookup(kid); key != nil {
			return key, nil
		}
		return nil, err
	}
	if key, _ := j.lookup(kid); key != nil {
		return key, nil
	}
	return nil, errors.New("jwks key not found")
}

func (j *JWKS) lookup(kid string) (*rsa.PublicKey, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	key, ok := j.keys[kid]
	if kid == "" && len(j.keys) == 1 {
		for _, only := range j.keys {
			key = only
			ok = true
		}
	}
	if !ok {
		return nil, false
	}
	return key, time.Now().Before(j.freshUntil)
}

func (j *JWKS) refresh(kid string) error {
	j.mu.Lock()
	for {
		if _, ok := j.keys[kid]; ok && kid != "" && time.Now().Before(j.freshUntil) {
			j.mu.Unlock()
			return nil
		}
		if j.inflight != nil {
			wait := j.inflight
			j.mu.Unlock()
			<-wait
			j.mu.Lock()
			continue
		}
		now := time.Now()
		stale := j.keys == nil || !now.Before(j.freshUntil)
		unknown := kid != "" && (j.keys == nil || j.keys[kid] == nil)
		if !stale && !unknown {
			j.mu.Unlock()
			return nil
		}
		if now.Before(j.retryAfter) {
			err := j.lastErr
			j.mu.Unlock()
			if err != nil {
				return err
			}
			return errors.New("jwks key not found")
		}
		j.inflight = make(chan struct{})
		wait := j.inflight
		j.mu.Unlock()

		keys, err := j.fetch()

		j.mu.Lock()
		if err != nil {
			j.retryAfter = time.Now().Add(jwksBackoff)
			j.lastErr = err
		} else {
			j.keys = keys
			j.freshUntil = time.Now().Add(jwksTTL)
			j.lastErr = nil
			if kid != "" {
				if _, found := keys[kid]; !found {
					j.retryAfter = time.Now().Add(jwksBackoff)
				}
			}
		}
		close(wait)
		j.inflight = nil
		j.mu.Unlock()
		return err
	}
}

func (j *JWKS) fetch() (map[string]*rsa.PublicKey, error) {
	response, err := j.client.Get(j.url)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks status %s", response.Status)
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
		return nil, err
	}
	keys := make(map[string]*rsa.PublicKey, len(document.Keys))
	for i, item := range document.Keys {
		if item.Kty != "RSA" || item.N == "" || item.E == "" {
			continue
		}
		pub, err := rsaPublic(item.N, item.E)
		if err != nil {
			return nil, err
		}
		kid := item.Kid
		if kid == "" {
			kid = fmt.Sprintf("key-%d", i)
		}
		keys[kid] = pub
	}
	if len(keys) == 0 {
		return nil, errors.New("jwks contained no rsa keys")
	}
	return keys, nil
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
