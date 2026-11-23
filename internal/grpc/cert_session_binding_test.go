package grpc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"net"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	ggrpc "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	pb "github.com/envsync-cloud/minikms/api/proto/minikms/v1"
	"github.com/envsync-cloud/minikms/internal/audit"
	"github.com/envsync-cloud/minikms/internal/auth"
	"github.com/envsync-cloud/minikms/internal/intercept"
	"github.com/envsync-cloud/minikms/internal/keys"
	"github.com/envsync-cloud/minikms/internal/pki"
	"github.com/envsync-cloud/minikms/internal/service"
	"github.com/envsync-cloud/minikms/internal/store"
	"github.com/envsync-cloud/minikms/internal/testutil"
)

// TestFixture_RevokedCertSessionDenied_LiveCertSessionAllowed issues a session
// for a certificate, revokes that certificate, and checks the next RPC.
// A session for a certificate that stays active still succeeds.
func TestFixture_RevokedCertSessionDenied_LiveCertSessionAllowed(t *testing.T) {
	const orgID = "org-cert-session"
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	rootCert, rootKey, _, err := pki.CreateRootCA("Fixture Root", 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}
	holder := keys.NewRootKeyHolder()
	if err := holder.Load(testutil.TestRootKeyHex); err != nil {
		t.Fatalf("load root key: %v", err)
	}
	auditLogger := audit.NewAuditLogger(testutil.NewMockAuditStore())
	certStore := testutil.NewMockPKICertStore()
	registry := testutil.NewMockTokenRegistry()
	certStore.BindTokenRevoker(registry)
	registry.BindCertificateStatus(func(ctx context.Context, serial string) (string, bool, error) {
		rec, err := certStore.GetCertificateBySerial(ctx, serial)
		if err != nil || rec == nil {
			return "", false, err
		}
		return rec.Status, true, nil
	})

	pkiSvc := service.NewPKIService(rootCert, rootKey, auditLogger, certStore)
	pkiSvc.SetOrgKeyManager(keys.NewOrgKeyManager(holder))
	_, orgCert, orgKey, _, err := pkiSvc.CreateOrgCAFull(ctx, &service.CreateOrgCARequest{
		OrgID: orgID, OrgName: "Cert Session Org",
	})
	if err != nil {
		t.Fatalf("CreateOrgCAFull: %v", err)
	}
	adminIssued, err := pkiSvc.IssueMemberCert(ctx, &service.IssueMemberCertRequest{
		MemberID: "admin-1", MemberEmail: "admin-1@example.com", OrgID: orgID,
		Role: "admin", OrgCACert: orgCert, OrgCAKey: orgKey,
	})
	if err != nil {
		t.Fatalf("issue admin cert: %v", err)
	}
	memberIssued, err := pkiSvc.IssueMemberCert(ctx, &service.IssueMemberCertRequest{
		MemberID: "member-1", MemberEmail: "member-1@example.com", OrgID: orgID,
		Role: "member", OrgCACert: orgCert, OrgCAKey: orgKey,
	})
	if err != nil {
		t.Fatalf("issue member cert: %v", err)
	}

	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	sessionSvc := service.NewSessionService(
		signingKey, "minikms", time.Hour, registry, certStore,
		testutil.NewMockPolicyStore(), auditLogger, store.NewMemoryChallengeStore(),
	)
	conn := startCertBindingServer(t, auth.NewJWTValidator(registry), NewPKIAdapter(pkiSvc), NewSessionAdapter(sessionSvc))
	sessions := pb.NewSessionServiceClient(conn)
	pkiClient := pb.NewPKIServiceClient(conn)

	adminToken := issueCertSession(t, sessions, adminIssued.CertPEM, adminIssued.KeyPEM, adminIssued.SerialHex)
	memberToken := issueCertSession(t, sessions, memberIssued.CertPEM, memberIssued.KeyPEM, memberIssued.SerialHex)

	if statusCode, err := ocspStatus(ctx, pkiClient, adminToken, orgID, adminIssued.SerialHex); err != nil || statusCode != 0 {
		t.Fatalf("admin session before revoke: status=%d err=%v", statusCode, err)
	}
	if statusCode, err := ocspStatus(ctx, pkiClient, memberToken, orgID, memberIssued.SerialHex); err != nil || statusCode != 0 {
		t.Fatalf("member session before revoke: status=%d err=%v", statusCode, err)
	}

	revokeResp, err := pkiClient.RevokeCert(bearerCtx(ctx, adminToken), &pb.RevokeCertRequest{
		SerialHex: memberIssued.SerialHex,
		OrgId:     orgID,
		Reason:    0,
	})
	if err != nil || !revokeResp.GetSuccess() {
		t.Fatalf("RevokeCert: success=%v err=%v", revokeResp.GetSuccess(), err)
	}

	memberEntry, err := registry.GetToken(ctx, tokenJTI(t, memberToken))
	if err != nil || memberEntry == nil || !memberEntry.Revoked || memberEntry.CertStatus != "revoked" {
		t.Fatalf("revoked session lookup = %+v err=%v", memberEntry, err)
	}
	adminEntry, err := registry.GetToken(ctx, tokenJTI(t, adminToken))
	if err != nil || adminEntry == nil || adminEntry.Revoked || adminEntry.CertStatus != "active" {
		t.Fatalf("live session lookup = %+v err=%v", adminEntry, err)
	}

	_, err = pkiClient.CheckOCSP(bearerCtx(ctx, memberToken), &pb.CheckOCSPRequest{
		SerialHex: memberIssued.SerialHex,
		OrgId:     orgID,
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("revoked cert session code = %v, want Unauthenticated", status.Code(err))
	}

	if statusCode, err := ocspStatus(ctx, pkiClient, adminToken, orgID, adminIssued.SerialHex); err != nil || statusCode != 0 {
		t.Fatalf("live cert session after revoke: status=%d err=%v", statusCode, err)
	}
}

type allowAllLimiter struct{}

func (allowAllLimiter) Allow(context.Context, string) (bool, error) { return true, nil }

func startCertBindingServer(t *testing.T, validator *auth.JWTValidator, pkiServer pb.PKIServiceServer, sessionServer pb.SessionServiceServer) *ggrpc.ClientConn {
	t.Helper()
	lis := bufconn.Listen(1024 * 1024)
	srv := ggrpc.NewServer(intercept.ServerOptions(validator, allowAllLimiter{})...)
	pb.RegisterPKIServiceServer(srv, pkiServer)
	pb.RegisterSessionServiceServer(srv, sessionServer)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := ggrpc.NewClient("passthrough:///bufnet",
		ggrpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		ggrpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc client: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	t.Cleanup(func() { _ = lis.Close() })
	return conn
}

func issueCertSession(t *testing.T, sessions pb.SessionServiceClient, certPEM, keyPEM, serial string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	challenge, err := sessions.IssueSessionChallenge(ctx, &pb.IssueSessionChallengeRequest{CertSerial: serial})
	if err != nil {
		t.Fatalf("IssueSessionChallenge: %v", err)
	}
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		t.Fatal("member key pem")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse member key: %v", err)
	}
	sum := sha256.Sum256(challenge.Nonce)
	sig, err := ecdsa.SignASN1(rand.Reader, key, sum[:])
	if err != nil {
		t.Fatalf("sign challenge: %v", err)
	}
	created, err := sessions.CreateSession(ctx, &pb.CreateSessionRequest{
		CertAuth: &pb.CertAuth{
			CertPem:     certPEM,
			SignedNonce: sig,
			Nonce:       challenge.Nonce,
		},
	})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if created.GetSessionToken() == "" {
		t.Fatal("session token is empty")
	}
	return created.GetSessionToken()
}

func bearerCtx(ctx context.Context, raw string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+raw)
}

func ocspStatus(ctx context.Context, client pb.PKIServiceClient, raw, orgID, serial string) (int32, error) {
	resp, err := client.CheckOCSP(bearerCtx(ctx, raw), &pb.CheckOCSPRequest{
		SerialHex: serial,
		OrgId:     orgID,
	})
	if err != nil {
		return 0, err
	}
	return resp.GetStatus(), nil
}

func tokenJTI(t *testing.T, raw string) string {
	t.Helper()
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(raw, claims); err != nil {
		t.Fatalf("parse session: %v", err)
	}
	jti, _ := claims["jti"].(string)
	if jti == "" {
		t.Fatal("session jti is empty")
	}
	return jti
}
