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
