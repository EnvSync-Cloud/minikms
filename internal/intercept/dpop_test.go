package intercept

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
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/envsync-cloud/minikms/api/proto/minikms/v1"
	"github.com/envsync-cloud/minikms/internal/authn"
	"github.com/envsync-cloud/minikms/internal/dpop"
)

func TestEnforceAcceptsOriginalProofOnly(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	userKey := newP256(t)
	accessKey := newRSA(t)
	token := accessToken(t, accessKey, thumbprint(t, userKey), now)
	original := dpopProof(t, userKey, token, "GET", "https://api.envsync.cloud/api/secrets", now)
	checker := enforceChecker(t, accessKey, now)

	principal := callDecrypt(t, checker, original, token, "x-envsync-dpop-mode", "off", "dpop-skip", "1")
	if principal.Kind != authn.KindUser || principal.ActorID != "user-1" || principal.Role != "" {
		t.Fatalf("principal = %+v", principal)
	}

	mutated := original[:len(original)-2] + flipTail(original[len(original)-2:])
	if code := callDecryptCode(t, checker, mutated, token); code != codes.Unauthenticated {
		t.Fatalf("mutated proof code = %s", code)
	}

	minted := dpopProof(t, newP256(t), token, "GET", "https://api.envsync.cloud/api/secrets", now)
	if code := callDecryptCode(t, checker, minted, token); code != codes.Unauthenticated {
		t.Fatalf("minted proof code = %s", code)
	}
}

func TestEnforceRequiresRequestID(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	userKey := newP256(t)
	accessKey := newRSA(t)
	token := accessToken(t, accessKey, thumbprint(t, userKey), now)
	proof := dpopProof(t, userKey, token, "GET", "https://api.envsync.cloud/api/secrets", now)
	checker := enforceChecker(t, accessKey, now)
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"authorization", "Bearer "+signToken(t, bearerClaims{
			RegisteredClaims: jwt.RegisteredClaims{ID: "sess-2", Subject: "session-actor"},
			OrgID:            "org-1",
		}),
		"x-envsync-dpop", proof,
		"x-envsync-access-token", token,
	))
	link := &chain{validator: &fakeValidator{}, proofs: checker}
	_, err := link.authUnary(ctx, &pb.DecryptRequest{}, &grpc.UnaryServerInfo{FullMethod: pb.KMSService_Decrypt_FullMethodName}, func(context.Context, any) (any, error) {
		return nil, nil
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("missing request id code = %s", status.Code(err))
	}
}

func TestOffModeIgnoresProofMetadata(t *testing.T) {
	checker := &dpop.Checker{Mode: dpop.ModeOff}
	ctx := sessionContext(t, metadata.Pairs("x-envsync-dpop-mode", "enforce"))
	link := &chain{validator: &fakeValidator{}, proofs: checker}
	var got authn.Principal
	_, err := link.authUnary(ctx, &pb.DecryptRequest{}, &grpc.UnaryServerInfo{FullMethod: pb.KMSService_Decrypt_FullMethodName}, func(ctx context.Context, _ any) (any, error) {
		got, _ = authn.FromContext(ctx)
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.ActorID != "session-actor" || got.Kind != "" {
		t.Fatalf("off mode changed the session principal: %+v", got)
	}
}

func TestMonitorDoesNotBlock(t *testing.T) {
	now := time.Now()
	accessKey := newRSA(t)
	checker := enforceChecker(t, accessKey, now)
	checker.Mode = dpop.ModeMonitor
	if code := callDecryptCode(t, checker, "not-a-proof", "not-a-token"); code != codes.OK {
		t.Fatalf("monitor code = %s", code)
	}
}

func enforceChecker(t *testing.T, accessKey *rsa.PrivateKey, now time.Time) *dpop.Checker {
	t.Helper()
	return &dpop.Checker{
		Mode:           dpop.ModeEnforce,
		Issuer:         "https://atrium.envsync.cloud",
		Audience:       "envsync-api",
		AllowedOrigins: []string{"https://api.envsync.cloud"},
		MaxAge:         time.Minute,
		MaxCalls:       16,
		Keyfunc: func(*jwt.Token) (any, error) {
			return &accessKey.PublicKey, nil
		},
		Replay: dpop.NewMemoryReplay(),
		Now:    func() time.Time { return now },
	}
}

func callDecrypt(t *testing.T, checker *dpop.Checker, proof, token string, extra ...string) authn.Principal {
	t.Helper()
	ctx := incomingProof(t, proof, token, extra...)
	link := &chain{validator: &fakeValidator{}, proofs: checker}
	var got authn.Principal
	_, err := link.authUnary(ctx, &pb.DecryptRequest{}, &grpc.UnaryServerInfo{FullMethod: pb.KMSService_Decrypt_FullMethodName}, func(ctx context.Context, _ any) (any, error) {
		var ok bool
		got, ok = authn.FromContext(ctx)
		if !ok {
			t.Fatal("missing principal")
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func callDecryptCode(t *testing.T, checker *dpop.Checker, proof, token string) codes.Code {
	t.Helper()
	ctx := incomingProof(t, proof, token)
	link := &chain{validator: &fakeValidator{}, proofs: checker}
	_, err := link.authUnary(ctx, &pb.DecryptRequest{}, &grpc.UnaryServerInfo{FullMethod: pb.KMSService_Decrypt_FullMethodName}, func(context.Context, any) (any, error) {
		return nil, nil
	})
	return status.Code(err)
}

func incomingProof(t *testing.T, proof, token string, extra ...string) context.Context {
	t.Helper()
	pairs := []string{
		"authorization", "Bearer " + signToken(t, bearerClaims{
			RegisteredClaims: jwt.RegisteredClaims{ID: "sess", Subject: "session-actor"},
			OrgID:            "org-1",
			Role:             "admin",
		}),
		"x-envsync-dpop", proof,
		"x-envsync-access-token", token,
		"x-envsync-org", "org-1",
		"x-envsync-request-id", "req-1",
	}
	pairs = append(pairs, extra...)
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs(pairs...))
}

func sessionContext(t *testing.T, md metadata.MD) context.Context {
	t.Helper()
	md.Set("authorization", "Bearer "+signToken(t, bearerClaims{
		RegisteredClaims: jwt.RegisteredClaims{ID: "sess", Subject: "session-actor"},
		OrgID:            "org-1",
	}))
	return metadata.NewIncomingContext(context.Background(), md)
}

func newP256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func newRSA(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func accessToken(t *testing.T, key *rsa.PrivateKey, jkt string, now time.Time) string {
	t.Helper()
	claims := jwt.MapClaims{
		"sub": "user-1",
		"iss": "https://atrium.envsync.cloud",
		"aud": "envsync-api",
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(),
		"cnf": map[string]string{"jkt": jkt},
	}
	raw, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func dpopProof(t *testing.T, key *ecdsa.PrivateKey, accessToken, htm, htu string, now time.Time) string {
	t.Helper()
	x, y := coordinates(key)
	sum := sha256.Sum256([]byte(accessToken))
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"jti": "proof-jti",
		"htm": htm,
		"htu": htu,
		"iat": now.Unix(),
		"ath": base64.RawURLEncoding.EncodeToString(sum[:]),
	})
	tok.Header["typ"] = "dpop+jwt"
	tok.Header["jwk"] = map[string]string{"kty": "EC", "crv": "P-256", "x": x, "y": y}
	raw, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func thumbprint(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	x, y := coordinates(key)
	canonical := `{"crv":"P-256","kty":"EC","x":"` + x + `","y":"` + y + `"}`
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func coordinates(key *ecdsa.PrivateKey) (string, string) {
	x := make([]byte, 32)
	y := make([]byte, 32)
	key.X.FillBytes(x)
	key.Y.FillBytes(y)
	return base64.RawURLEncoding.EncodeToString(x), base64.RawURLEncoding.EncodeToString(y)
}

func flipTail(tail string) string {
	buf := []byte(tail)
	buf[0] ^= 0x1
	return string(buf)
}
