// Package intercept installs the miniKMS gRPC server interceptor chain.
package intercept

import (
	"context"
	"errors"
	"log"
	"net"
	"runtime/debug"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	pb "github.com/envsync-cloud/minikms/api/proto/minikms/v1"
	"github.com/envsync-cloud/minikms/internal/auth"
	"github.com/envsync-cloud/minikms/internal/authn"
)

// TokenValidator is the session check performed for protected RPCs.
// *auth.JWTValidator implements it.
type TokenValidator interface {
	ValidateByJTI(ctx context.Context, jti, rawJWT string) (*auth.TokenEntry, error)
}

// Limiter is the shared Redis rate limiter.
// *ratelimit.RateLimiter implements it.
type Limiter interface {
	Allow(ctx context.Context, key string) (bool, error)
}

// ServerOptions returns server options for the interceptor chain.
// Unary and stream order is recovery (outer), then auth, then rate limit.
func ServerOptions(validator TokenValidator, limiter Limiter) []grpc.ServerOption {
	c := &chain{validator: validator, limiter: limiter}
	return []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(c.recoverUnary, c.authUnary, c.rateUnary),
		grpc.ChainStreamInterceptor(c.recoverStream, c.authStream, c.rateStream),
	}
}

type chain struct {
	validator TokenValidator
	limiter   Limiter
}

// bearerClaims accepts auth.Claims (org_id) and session tokens (org).
type bearerClaims struct {
	jwt.RegisteredClaims
	OrgID string `json:"org_id,omitempty"`
	Org   string `json:"org,omitempty"`
}

func (c bearerClaims) tenantID() string {
	if c.OrgID != "" {
		return c.OrgID
	}
	return c.Org
}

func isPreAuth(fullMethod string) bool {
	switch fullMethod {
	case healthpb.Health_Check_FullMethodName,
		pb.SessionService_IssueSessionChallenge_FullMethodName,
		// CreateSession is the proto RPC that performs CreateSessionByCert.
		pb.SessionService_CreateSession_FullMethodName:
		return true
	default:
		return false
	}
}

func (c *chain) recoverUnary(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("grpc panic recovered method=%s\n%s", info.FullMethod, debug.Stack())
			resp = nil
			err = status.Error(codes.Internal, "internal server error")
		}
	}()
	return handler(ctx, req)
}

func (c *chain) recoverStream(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) (err error) {
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("grpc panic recovered method=%s\n%s", info.FullMethod, debug.Stack())
			err = status.Error(codes.Internal, "internal server error")
		}
	}()
	return handler(srv, ss)
}

func (c *chain) authUnary(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	ctx, err := c.authenticate(ctx, info.FullMethod)
	if err != nil {
		return nil, err
	}
	return handler(ctx, req)
}

func (c *chain) authStream(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	ctx, err := c.authenticate(ss.Context(), info.FullMethod)
	if err != nil {
		return err
	}
	return handler(srv, &contextStream{ServerStream: ss, ctx: ctx})
}

func (c *chain) rateUnary(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	if err := c.allow(ctx, info.FullMethod); err != nil {
		return nil, err
	}
	return handler(ctx, req)
}

func (c *chain) rateStream(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	if err := c.allow(ss.Context(), info.FullMethod); err != nil {
		return err
	}
	return handler(srv, ss)
}

func (c *chain) authenticate(ctx context.Context, fullMethod string) (context.Context, error) {
	if isPreAuth(fullMethod) {
		return ctx, nil
	}
	raw, err := bearerToken(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "unauthenticated")
	}
	claims, err := parseBearerClaims(raw)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "unauthenticated")
	}
	jti := claims.ID
	tenantID := claims.tenantID()
	actorID := claims.Subject
	if jti == "" || tenantID == "" || actorID == "" {
		return nil, status.Error(codes.Unauthenticated, "unauthenticated")
	}
	if c.validator == nil {
		return nil, status.Error(codes.Unauthenticated, "unauthenticated")
	}
	entry, err := c.validator.ValidateByJTI(ctx, jti, raw)
	if err != nil || entry == nil {
		return nil, status.Error(codes.Unauthenticated, "unauthenticated")
	}
	return authn.WithPrincipal(ctx, authn.Principal{TenantID: tenantID, ActorID: actorID}), nil
}

func bearerToken(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", errors.New("missing metadata")
	}
	vals := md.Get("authorization")
	if len(vals) == 0 {
		return "", errors.New("missing authorization")
	}
	token := strings.TrimSpace(vals[0])
	if len(token) >= 7 && strings.EqualFold(token[:7], "bearer ") {
		token = strings.TrimSpace(token[7:])
	}
	if token == "" {
		return "", errors.New("empty authorization")
	}
	return token, nil
}

func parseBearerClaims(raw string) (*bearerClaims, error) {
	claims := &bearerClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(raw, claims); err != nil {
		return nil, err
	}
	return claims, nil
}

func (c *chain) allow(ctx context.Context, fullMethod string) error {
	if c.limiter == nil {
		return status.Error(codes.Unavailable, "rate limiter unavailable")
	}
	allowed, err := c.limiter.Allow(ctx, rateKey(ctx))
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return status.FromContextError(err).Err()
		}
		log.Printf("grpc rate limit check failed method=%s", fullMethod)
		return status.Error(codes.Unavailable, "rate limiter unavailable")
	}
	if !allowed {
		return status.Error(codes.ResourceExhausted, "rate limit exceeded")
	}
	return nil
}

// rateKey is one bucket per authenticated principal, otherwise per client IP.
func rateKey(ctx context.Context) string {
	if p, ok := authn.FromContext(ctx); ok && p.TenantID != "" && p.ActorID != "" {
		return "p:" + p.TenantID + ":" + p.ActorID
	}
	pr, ok := peer.FromContext(ctx)
	if !ok || pr.Addr == nil {
		return "anonymous"
	}
	host, _, err := net.SplitHostPort(pr.Addr.String())
	if err != nil || host == "" {
		return "ip:" + pr.Addr.String()
	}
	return "ip:" + host
}

type contextStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *contextStream) Context() context.Context { return s.ctx }
