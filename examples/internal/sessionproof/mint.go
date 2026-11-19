package sessionproof

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	pb "github.com/envsync-cloud/minikms/api/proto/minikms/v1"
	"github.com/envsync-cloud/minikms/internal/grpc"
	ggrpc "google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func ParseMemberKey(keyPEM string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return nil, fmt.Errorf("invalid member key pem")
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("member key is not ecdsa")
	}
	return key, nil
}

func SignNonce(key *ecdsa.PrivateKey, nonce []byte) ([]byte, error) {
	hash := sha256.Sum256(nonce)
	return ecdsa.SignASN1(rand.Reader, key, hash[:])
}

// OpenOrgSession creates an organization and returns the one-time admin session.
// The managed member private key stays on the server.
func OpenOrgSession(ctx context.Context, pki pb.PKIServiceClient, orgID, orgName string) (token, memberSerial string, err error) {
	var hdr metadata.MD
	if _, err = pki.CreateOrgCA(ctx, &pb.CreateOrgCARequest{OrgId: orgID, OrgName: orgName}, ggrpc.Header(&hdr)); err != nil {
		return "", "", err
	}
	token = headerFirst(hdr, grpc.BootstrapSessionHeader)
	memberSerial = headerFirst(hdr, grpc.BootstrapMemberSerialHeader)
	if token == "" || memberSerial == "" {
		return "", "", fmt.Errorf("organization bootstrap did not open a session")
	}
	return token, memberSerial, nil
}

func headerFirst(md metadata.MD, key string) string {
	vals := md.Get(key)
	if len(vals) == 0 {
		return ""
	}
	return vals[0]
}

func Mint(ctx context.Context, sessions pb.SessionServiceClient, certPEM, keyPEM, serial string, scopes []string) (string, error) {
	key, err := ParseMemberKey(keyPEM)
	if err != nil {
		return "", err
	}
	challenge, err := sessions.IssueSessionChallenge(ctx, &pb.IssueSessionChallengeRequest{CertSerial: serial})
	if err != nil {
		return "", fmt.Errorf("IssueSessionChallenge: %w", err)
	}
	sig, err := SignNonce(key, challenge.Nonce)
	if err != nil {
		return "", err
	}
	session, err := sessions.CreateSession(ctx, &pb.CreateSessionRequest{
		CertAuth: &pb.CertAuth{
			CertPem:     certPEM,
			SignedNonce: sig,
			Nonce:       challenge.Nonce,
		},
		Scopes: scopes,
	})
	if err != nil {
		return "", fmt.Errorf("CreateSession: %w", err)
	}
	return session.SessionToken, nil
}
