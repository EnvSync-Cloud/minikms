package intercept

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	pb "github.com/envsync-cloud/minikms/api/proto/minikms/v1"
	"github.com/envsync-cloud/minikms/internal/auth"
	"github.com/envsync-cloud/minikms/internal/authn"
)

func TestAnonymousKMSEncryptUnauthenticated(t *testing.T) {
	lim := &fakeLimiter{allow: true}
	val := &fakeValidator{}
	conn := newTestConn(t, val, lim, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := pb.NewKMSServiceClient(conn).Encrypt(ctx, &pb.EncryptRequest{})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("Encrypt code = %v, want Unauthenticated (err=%v)", status.Code(err), err)
	}
	if val.calls() != 0 {
		t.Fatalf("validator calls = %d, want 0", val.calls())
	}
	if keys := lim.snapshot(); len(keys) != 0 {
		t.Fatalf("rate limiter keys = %v, want none before auth succeeds", keys)
	}

	c := &chain{validator: val, limiter: lim}
	called := false
	_, err = c.authUnary(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: pb.KMSService_Encrypt_FullMethodName}, func(context.Context, any) (any, error) {
		called = true
		return nil, nil
	})
	if called {
		t.Fatal("auth interceptor called the Encrypt handler")
	}
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("auth interceptor code = %v, want Unauthenticated", status.Code(err))
	}
}

func TestPreAuthMethodsNotRejectedByAuth(t *testing.T) {
	lim := &fakeLimiter{allow: true}
	val := &fakeValidator{err: errRejected}
	conn := newTestConn(t, val, lim, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	healthResp, err := healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{})
	if err != nil {
		t.Fatalf("Health/Check: %v", err)
	}
	if healthResp.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("Health/Check status = %v, want SERVING", healthResp.GetStatus())
	}

	_, err = pb.NewSessionServiceClient(conn).IssueSessionChallenge(ctx, &pb.IssueSessionChallengeRequest{})
	if status.Code(err) == codes.Unauthenticated {
		t.Fatal("IssueSessionChallenge rejected by auth")
	}
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("IssueSessionChallenge code = %v, want Unimplemented from handler", status.Code(err))
	}

	_, err = pb.NewSessionServiceClient(conn).CreateSession(ctx, &pb.CreateSessionRequest{})
	if status.Code(err) == codes.Unauthenticated {
		t.Fatal("CreateSession (CreateSessionByCert) rejected by auth")
	}
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("CreateSession code = %v, want Unimplemented from handler", status.Code(err))
	}
	if val.calls() != 0 {
		t.Fatalf("validator calls = %d, want 0 for pre-auth methods", val.calls())
	}
	if got := len(lim.snapshot()); got != 3 {
		t.Fatalf("rate limiter calls = %d, want 3", got)
	}

	c := &chain{validator: val, limiter: lim}
	for _, method := range []string{
		healthpb.Health_Check_FullMethodName,
		pb.SessionService_IssueSessionChallenge_FullMethodName,
		pb.SessionService_CreateSession_FullMethodName,
	} {
		called := false
		_, err := c.authUnary(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: method}, func(ctx context.Context, _ any) (any, error) {
			called = true
			if _, ok := authn.FromContext(ctx); ok {
				t.Fatalf("%s attached a principal without a session", method)
			}
			return "ok", nil
		})
		if err != nil || !called {
			t.Fatalf("%s auth interceptor err=%v called=%v", method, err, called)
		}
	}
}

func TestHealthWatchRequiresSession(t *testing.T) {
	conn := newTestConn(t, &fakeValidator{}, &fakeLimiter{allow: true}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := healthpb.NewHealthClient(conn).Watch(ctx, &healthpb.HealthCheckRequest{})
	if err != nil {
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("Watch code = %v, want Unauthenticated", status.Code(err))
		}
		return
	}
	_, err = stream.Recv()
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("Watch Recv code = %v, want Unauthenticated (err=%v)", status.Code(err), err)
	}
}

func TestProtectedMethodsRequireSession(t *testing.T) {
	conn := newTestConn(t, &fakeValidator{}, &fakeLimiter{allow: true}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cases := []struct {
		name string
		call func() error
	}{
		{"Decrypt", func() error {
			_, err := pb.NewKMSServiceClient(conn).Decrypt(ctx, &pb.DecryptRequest{})
			return err
		}},
		{"CreateOrgCA", func() error {
			_, err := pb.NewPKIServiceClient(conn).CreateOrgCA(ctx, &pb.CreateOrgCARequest{})
			return err
		}},
		{"GetAuditLogs", func() error {
			_, err := pb.NewAuditServiceClient(conn).GetAuditLogs(ctx, &pb.GetAuditLogsRequest{})
			return err
		}},
		{"VaultRead", func() error {
			_, err := pb.NewVaultServiceClient(conn).Read(ctx, &pb.VaultReadRequest{})
			return err
		}},
		{"ValidateSession", func() error {
			_, err := pb.NewSessionServiceClient(conn).ValidateSession(ctx, &pb.ValidateSessionRequest{})
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call()
			if status.Code(err) != codes.Unauthenticated {
				t.Fatalf("code = %v, want Unauthenticated (err=%v)", status.Code(err), err)
			}
		})
	}
}

func TestAuthInterceptorSetsPrincipal(t *testing.T) {
	raw := signToken(t, auth.Claims{
		RegisteredClaims: jwt.RegisteredClaims{ID: "jti-org", Subject: "actor-org"},
		OrgID:            "tenant-org",
	})
	sessionRaw := signToken(t, jwt.MapClaims{
		"jti": "jti-session",
		"sub": "actor-session",
		"org": "tenant-session",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	gotCh := make(chan authn.Principal, 1)
	val := &fakeValidator{}
	lim := &fakeLimiter{allow: true}
	conn := newTestConn(t, val, lim, func(s *grpc.Server) {
		s.RegisterService(&grpc.ServiceDesc{
			ServiceName: "test.Capture",
			Methods: []grpc.MethodDesc{{
				MethodName: "Call",
				Handler: func(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
					if err := dec(new(pb.EncryptRequest)); err != nil {
						return nil, err
					}
					info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/test.Capture/Call"}
					handler := func(ctx context.Context, req any) (any, error) {
						p, ok := authn.FromContext(ctx)
						if !ok {
							return nil, status.Error(codes.Internal, "missing principal")
						}
						gotCh <- p
						return &pb.EncryptResponse{Ciphertext: "ok"}, nil
					}
					return interceptor(ctx, new(pb.EncryptRequest), info, handler)
				},
			}},
		}, nil)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	authCtx := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+raw)
	var out pb.EncryptResponse
	if err := conn.Invoke(authCtx, "/test.Capture/Call", &pb.EncryptRequest{}, &out); err != nil {
		t.Fatalf("authenticated call: %v", err)
	}
	var got authn.Principal
	select {
	case got = <-gotCh:
	default:
		t.Fatal("principal was not stored")
	}
	if got != (authn.Principal{TenantID: "tenant-org", ActorID: "actor-org"}) {
		t.Fatalf("principal = %+v", got)
	}
	if keys := lim.snapshot(); len(keys) != 1 || keys[0] != "p:tenant-org:actor-org" {
		t.Fatalf("rate limit keys = %v", keys)
	}
	if val.lastJTI() != "jti-org" || val.lastRaw() != raw {
		t.Fatalf("validator saw jti=%q raw match=%v", val.lastJTI(), val.lastRaw() == raw)
	}

	c := &chain{validator: val, limiter: lim}
	inCtx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", sessionRaw))
	_, err := c.authUnary(inCtx, nil, &grpc.UnaryServerInfo{FullMethod: pb.KMSService_Encrypt_FullMethodName}, func(ctx context.Context, _ any) (any, error) {
		p, ok := authn.FromContext(ctx)
		if !ok {
			t.Fatal("missing principal")
		}
		if p != (authn.Principal{TenantID: "tenant-session", ActorID: "actor-session"}) {
			t.Fatalf("session principal = %+v", p)
		}
		return nil, nil
	})
	if err != nil {
		t.Fatalf("session org claim: %v", err)
	}
}

func TestAuthInterceptorRejectsInvalidSession(t *testing.T) {
	raw := signToken(t, auth.Claims{
		RegisteredClaims: jwt.RegisteredClaims{ID: "jti-bad", Subject: "actor"},
		OrgID:            "tenant",
	})
	val := &fakeValidator{err: errRejected}
	c := &chain{validator: val}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+raw))
	called := false
	_, err := c.authUnary(ctx, nil, &grpc.UnaryServerInfo{FullMethod: pb.KMSService_Decrypt_FullMethodName}, func(context.Context, any) (any, error) {
		called = true
		return nil, nil
	})
	if called {
		t.Fatal("handler called for invalid session")
	}
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %v, want Unauthenticated", status.Code(err))
	}
}

func TestRateLimitReturnsResourceExhausted(t *testing.T) {
	conn := newTestConn(t, &fakeValidator{}, &fakeLimiter{allow: false}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{})
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("Health/Check code = %v, want ResourceExhausted (err=%v)", status.Code(err), err)
	}
}

func TestRateLimitErrorUnavailable(t *testing.T) {
	conn := newTestConn(t, &fakeValidator{}, &fakeLimiter{allow: true, err: errRejected}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("Health/Check code = %v, want Unavailable (err=%v)", status.Code(err), err)
	}
}

func TestRecoveryCatchesPanic(t *testing.T) {
	raw := signToken(t, auth.Claims{
		RegisteredClaims: jwt.RegisteredClaims{ID: "jti-panic", Subject: "actor"},
		OrgID:            "tenant",
	})
	conn := newTestConn(t, &fakeValidator{}, &fakeLimiter{allow: true}, func(s *grpc.Server) {
		s.RegisterService(&grpc.ServiceDesc{
			ServiceName: "test.Panic",
			Methods: []grpc.MethodDesc{{
				MethodName: "Call",
				Handler: func(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
					if err := dec(new(pb.EncryptRequest)); err != nil {
						return nil, err
					}
					info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/test.Panic/Call"}
					handler := func(context.Context, any) (any, error) {
						panic("handler panic")
					}
					return interceptor(ctx, new(pb.EncryptRequest), info, handler)
				},
			}},
		}, nil)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	authCtx := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+raw)
	var out pb.EncryptResponse
	err := conn.Invoke(authCtx, "/test.Panic/Call", &pb.EncryptRequest{}, &out)
	if status.Code(err) != codes.Internal {
		t.Fatalf("panic code = %v, want Internal (err=%v)", status.Code(err), err)
	}
	if err != nil && strings.Contains(err.Error(), "handler panic") {
		t.Fatalf("panic text leaked to client: %v", err)
	}

	c := &chain{}
	_, err = c.recoverUnary(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/test.Panic/Call"}, func(context.Context, any) (any, error) {
		panic("handler panic")
	})
	if status.Code(err) != codes.Internal {
		t.Fatalf("unary recovery code = %v, want Internal", status.Code(err))
	}
	err = c.recoverStream(nil, &fakeStream{ctx: context.Background()}, &grpc.StreamServerInfo{FullMethod: healthpb.Health_Watch_FullMethodName}, func(any, grpc.ServerStream) error {
		panic("stream panic")
	})
	if status.Code(err) != codes.Internal {
		t.Fatalf("stream recovery code = %v, want Internal", status.Code(err))
	}
}

func TestRecoveryWrapsAuthPanic(t *testing.T) {
	raw := signToken(t, auth.Claims{
		RegisteredClaims: jwt.RegisteredClaims{ID: "jti-auth-panic", Subject: "actor"},
		OrgID:            "tenant",
	})
	conn := newTestConn(t, panicValidator{}, &fakeLimiter{allow: true}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	authCtx := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+raw)
	_, err := pb.NewKMSServiceClient(conn).Encrypt(authCtx, &pb.EncryptRequest{})
	if status.Code(err) != codes.Internal {
		t.Fatalf("code = %v, want Internal (err=%v)", status.Code(err), err)
	}
	if strings.Contains(err.Error(), "validator panic") {
		t.Fatalf("panic text leaked to client: %v", err)
	}
}

var errRejected = status.Error(codes.PermissionDenied, "rejected")

type fakeValidator struct {
	mu  sync.Mutex
	err error
	n   int
	jti string
	raw string
}

func (f *fakeValidator) ValidateByJTI(_ context.Context, jti, raw string) (*auth.TokenEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	f.jti = jti
	f.raw = raw
	if f.err != nil {
		return nil, f.err
	}
	return &auth.TokenEntry{JTI: jti}, nil
}

func (f *fakeValidator) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.n
}

func (f *fakeValidator) lastJTI() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.jti
}

func (f *fakeValidator) lastRaw() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.raw
}

type panicValidator struct{}

func (panicValidator) ValidateByJTI(context.Context, string, string) (*auth.TokenEntry, error) {
	panic("validator panic")
}

type fakeLimiter struct {
	mu    sync.Mutex
	allow bool
	err   error
	keys  []string
}

func (f *fakeLimiter) Allow(_ context.Context, key string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keys = append(f.keys, key)
	if f.err != nil {
		return false, f.err
	}
	return f.allow, nil
}

func (f *fakeLimiter) snapshot() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.keys))
	copy(out, f.keys)
	return out
}

type fakeStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *fakeStream) Context() context.Context {
	if s.ctx == nil {
		return context.Background()
	}
	return s.ctx
}

func newTestConn(t *testing.T, v TokenValidator, l Limiter, extra func(*grpc.Server)) *grpc.ClientConn {
	t.Helper()
	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer(ServerOptions(v, l)...)
	pb.RegisterKMSServiceServer(srv, &pb.UnimplementedKMSServiceServer{})
	pb.RegisterPKIServiceServer(srv, &pb.UnimplementedPKIServiceServer{})
	pb.RegisterAuditServiceServer(srv, &pb.UnimplementedAuditServiceServer{})
	pb.RegisterVaultServiceServer(srv, &pb.UnimplementedVaultServiceServer{})
	pb.RegisterSessionServiceServer(srv, &pb.UnimplementedSessionServiceServer{})
	hs := health.NewServer()
	hs.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(srv, hs)
	if extra != nil {
		extra(srv)
	}
	go func() { _ = srv.Serve(lis) }()

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		srv.Stop()
		_ = lis.Close()
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	t.Cleanup(srv.Stop)
	t.Cleanup(func() { _ = lis.Close() })
	return conn
}

func signToken(t *testing.T, claims jwt.Claims) string {
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
