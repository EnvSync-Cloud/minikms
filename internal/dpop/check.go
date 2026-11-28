package dpop

import (
	"context"
	"errors"
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/envsync-cloud/minikms/api/proto/minikms/v1"
	"github.com/envsync-cloud/minikms/internal/authn"
)

const (
	metaDPoP        = "x-envsync-dpop"
	metaAccessToken = "x-envsync-access-token"
	metaRequestID   = "x-envsync-request-id"
	metaOrg         = "x-envsync-org"
)

// Mode is the server floor. off < monitor < enforce.
type Mode string

const (
	ModeOff     Mode = "off"
	ModeMonitor Mode = "monitor"
	ModeEnforce Mode = "enforce"
)

// ParseMode accepts only the three server modes.
func ParseMode(raw string) (Mode, error) {
	switch Mode(raw) {
	case "", ModeOff:
		return ModeOff, nil
	case ModeMonitor, ModeEnforce:
		return Mode(raw), nil
	default:
		return "", errors.New("dpop mode must be off, monitor, or enforce")
	}
}

// Checker verifies a forwarded proof. Mode comes from Options, never from metadata.
type Checker struct {
	Mode           Mode
	Issuer         string
	Audience       string
	AllowedOrigins []string
	MaxAge         time.Duration
	MaxCalls       int
	Keyfunc        jwt.Keyfunc
	Replay         Replay
	Now            func() time.Time
}

// Apply checks user-data calls. Other methods keep the session principal.
// monitor records a failure and still calls the handler. enforce rejects it.
func (c *Checker) Apply(ctx context.Context, fullMethod string) (context.Context, error) {
	if c == nil || c.Mode == ModeOff || !userDataMethod(fullMethod) {
		return ctx, nil
	}
	next, reason, err := c.evaluate(ctx, fullMethod)
	if err == nil {
		return next, nil
	}
	log.Printf("dpop check method=%s result=%s", fullMethod, reason)
	if c.Mode == ModeMonitor {
		return ctx, nil
	}
	if errors.Is(err, ErrStore) {
		return nil, status.Error(codes.Unavailable, "unauthenticated")
	}
	return nil, status.Error(codes.Unauthenticated, "unauthenticated")
}

func (c *Checker) evaluate(ctx context.Context, fullMethod string) (context.Context, string, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	access := metaFirst(md, metaAccessToken)
	proofRaw := metaFirst(md, metaDPoP)
	now := time.Now()
	if c.Now != nil {
		now = c.Now()
	}
	sub, jkt, err := VerifyAccessToken(access, c.Keyfunc, c.Issuer, c.Audience, now)
	if err != nil {
		return ctx, "token", err
	}
	proof, err := VerifyProof(proofRaw, access, now, c.MaxAge)
	if err != nil {
		return ctx, "proof", err
	}
	if proof.JKT != jkt {
		return ctx, "binding", errors.New("proof key does not match the access token")
	}
	if !htmAllows(proof.HTM, fullMethod) {
		return ctx, "htm", errors.New("proof htm does not allow this method")
	}
	if !originAllowed(proof.HTU, c.AllowedOrigins) {
		return ctx, "htu", errors.New("proof htu origin is not allowed")
	}
	principal, ok := authn.FromContext(ctx)
	if !ok || principal.TenantID == "" {
		return ctx, "session", errors.New("session principal is missing")
	}
	if org := metaFirst(md, metaOrg); org != "" && org != principal.TenantID {
		return ctx, "org", errors.New("org metadata does not match the session tenant")
	}
	requestID := metaFirst(md, metaRequestID)
	if requestID == "" {
		return ctx, "request", errors.New("request id is missing")
	}
	if c.Replay == nil {
		return ctx, "store", ErrStore
	}
	if err := c.Replay.Admit(ctx, proof.JTI, requestID, proof.Hash, c.MaxCalls, c.MaxAge*2); err != nil {
		if errors.Is(err, ErrReplayed) {
			return ctx, "replay", err
		}
		return ctx, "store", ErrStore
	}
	principal.ActorID = sub
	principal.Role = ""
	principal.Kind = authn.KindUser
	principal.JKT = proof.JKT
	return authn.WithPrincipal(ctx, principal), "", nil
}

func userDataMethod(fullMethod string) bool {
	switch fullMethod {
	case pb.KMSService_Encrypt_FullMethodName,
		pb.KMSService_Decrypt_FullMethodName,
		pb.KMSService_BatchEncrypt_FullMethodName,
		pb.KMSService_BatchDecrypt_FullMethodName,
		pb.VaultService_Read_FullMethodName,
		pb.VaultService_ReadVersion_FullMethodName,
		pb.VaultService_List_FullMethodName,
		pb.VaultService_History_FullMethodName,
		pb.VaultService_Write_FullMethodName,
		pb.VaultService_Delete_FullMethodName,
		pb.VaultService_Destroy_FullMethodName:
		return true
	default:
		return false
	}
}

func htmAllows(htm, fullMethod string) bool {
	read := false
	write := false
	del := false
	switch strings.ToUpper(htm) {
	case "GET", "HEAD":
		read = true
	case "POST", "PUT", "PATCH":
		read = true
		write = true
	case "DELETE":
		read = true
		del = true
	default:
		return false
	}
	switch fullMethod {
	case pb.KMSService_Decrypt_FullMethodName,
		pb.KMSService_BatchDecrypt_FullMethodName,
		pb.VaultService_Read_FullMethodName,
		pb.VaultService_ReadVersion_FullMethodName,
		pb.VaultService_List_FullMethodName,
		pb.VaultService_History_FullMethodName:
		return read
	case pb.KMSService_Encrypt_FullMethodName,
		pb.KMSService_BatchEncrypt_FullMethodName,
		pb.VaultService_Write_FullMethodName:
		return write
	case pb.VaultService_Delete_FullMethodName,
		pb.VaultService_Destroy_FullMethodName:
		return del
	default:
		return false
	}
}

func originAllowed(htu string, allowed []string) bool {
	parsed, err := url.Parse(htu)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return false
	}
	origin := parsed.Scheme + "://" + parsed.Host
	for _, item := range allowed {
		if item == origin {
			return true
		}
	}
	return false
}

func metaFirst(md metadata.MD, key string) string {
	if len(md.Get(key)) == 0 {
		return ""
	}
	return md.Get(key)[0]
}
