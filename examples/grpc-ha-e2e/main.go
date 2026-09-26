package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	pb "github.com/envsync-cloud/minikms/api/proto/minikms/v1"
	"github.com/envsync-cloud/minikms/examples/internal/sessionproof"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	first := connect(envOrDefault("MINIKMS_ADDR_1", "localhost:50051"))
	defer first.Close()
	second := connect(envOrDefault("MINIKMS_ADDR_2", "localhost:50052"))
	defer second.Close()

	verifyKMSAcrossReplicas(ctx, first, second)
	verifyVaultSessionAcrossReplicas(ctx, first, second)
	fmt.Println("two-replica KMS and vault session flows passed")
}

func connect(address string) *grpc.ClientConn {
	conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("connect to %s: %v", address, err)
	}
	return conn
}

func verifyKMSAcrossReplicas(ctx context.Context, first, second grpc.ClientConnInterface) {
	writer := pb.NewKMSServiceClient(first)
	reader := pb.NewKMSServiceClient(second)
	plaintext := []byte("ha-kms-roundtrip")

	encrypted, err := writer.Encrypt(ctx, &pb.EncryptRequest{
		TenantId: "org-ha-e2e", ScopeId: "app-ha-e2e",
		Plaintext: plaintext, Aad: "ha:kms",
	})
	if err != nil {
		log.Fatalf("encrypt through replica 1: %v", err)
	}
	decrypted, err := reader.Decrypt(ctx, &pb.DecryptRequest{
		TenantId: "org-ha-e2e", ScopeId: "app-ha-e2e",
		Ciphertext: encrypted.Ciphertext, Aad: "ha:kms", KeyVersionId: encrypted.KeyVersionId,
	})
	if err != nil {
		log.Fatalf("decrypt through replica 2: %v", err)
	}
	if string(decrypted.Plaintext) != string(plaintext) {
		log.Fatalf("cross-replica KMS mismatch: got %q", decrypted.Plaintext)
	}
}

func verifyVaultSessionAcrossReplicas(ctx context.Context, first, second grpc.ClientConnInterface) {
	const (
		orgID    = "org-ha-vault"
		memberID = "member-ha-vault"
	)

	pkiFirst := pb.NewPKIServiceClient(first)
	pkiSecond := pb.NewPKIServiceClient(second)
	if _, err := pkiFirst.CreateOrgCA(ctx, &pb.CreateOrgCARequest{
		OrgId: orgID, OrgName: "HA Vault Organization",
	}); err != nil {
		log.Fatalf("create Org CA through replica 1: %v", err)
	}
	member, err := pkiSecond.IssueMemberCert(ctx, &pb.IssueMemberCertRequest{
		MemberId: memberID, MemberEmail: "ha-vault@example.com", OrgId: orgID, Role: "admin",
	})
	if err != nil {
		log.Fatalf("issue member certificate through replica 2: %v", err)
	}

	sessions := pb.NewSessionServiceClient(first)
	token, err := sessionproof.Mint(ctx, sessions, member.CertPem, member.KeyPem, member.SerialHex, []string{"vault:read", "vault:write"})
	if err != nil {
		log.Fatalf("create session through replica 1: %v", err)
	}

	authorized := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
	layerOne := []byte("layer-one-client-ciphertext")
	vaultFirst := pb.NewVaultServiceClient(first)
	vaultSecond := pb.NewVaultServiceClient(second)
	if _, err := vaultFirst.Write(authorized, &pb.VaultWriteRequest{
		OrgId: orgID, ScopeId: "app-ha-vault", EntryType: "secret",
		Key: "DATABASE_URL", Value: layerOne, CreatedBy: memberID,
	}); err != nil {
		log.Fatalf("vault write through replica 1: %v", err)
	}
	read, err := vaultSecond.Read(authorized, &pb.VaultReadRequest{
		OrgId: orgID, ScopeId: "app-ha-vault", EntryType: "secret",
		Key: "DATABASE_URL", ClientSideDecrypt: false,
	})
	if err != nil {
		log.Fatalf("vault read through replica 2: %v", err)
	}
	if string(read.EncryptedValue) != string(layerOne) {
		log.Fatalf("cross-replica vault mismatch: got %q", read.EncryptedValue)
	}

	sessions2 := pb.NewSessionServiceClient(second)
	if _, err := sessions2.ValidateSession(ctx, &pb.ValidateSessionRequest{SessionToken: token}); err != nil {
		log.Fatalf("validate session on replica 2: %v", err)
	}

	if _, err := sessions.RevokeSession(ctx, &pb.RevokeSessionRequest{SessionToken: token}); err != nil {
		log.Fatalf("revoke session on replica 1: %v", err)
	}
	if _, err := vaultSecond.Read(authorized, &pb.VaultReadRequest{
		OrgId: orgID, ScopeId: "app-ha-vault", EntryType: "secret", Key: "DATABASE_URL",
	}); err == nil {
		log.Fatal("vault read after revoke succeeded on replica 2")
	} else if status.Code(err) != codes.Unauthenticated && status.Code(err) != codes.PermissionDenied {
		log.Fatalf("vault read after revoke: %v", err)
	}

	if _, err := pkiFirst.RevokeCert(ctx, &pb.RevokeCertRequest{SerialHex: member.SerialHex, OrgId: orgID}); err != nil {
		log.Fatalf("revoke member cert: %v", err)
	}
	if _, err := sessionproof.Mint(ctx, sessions, member.CertPem, member.KeyPem, member.SerialHex, []string{"vault:read"}); err == nil {
		log.Fatal("session minted for revoked member cert")
	}
}

func envOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
