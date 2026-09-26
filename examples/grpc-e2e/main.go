package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"crypto/rand"
	"crypto/x509"
	"encoding/pem"

	pb "github.com/envsync-cloud/minikms/api/proto/minikms/v1"
	"github.com/envsync-cloud/minikms/examples/internal/sessionproof"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func main() {
	// --- Configuration ---
	minikmsAddr := envOrDefault("MINIKMS_ADDR", "localhost:50051")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// --- 1. Connect to miniKMS gRPC ---
	fmt.Println("=== 1. Connect to miniKMS ===")
	conn, err := grpc.NewClient(minikmsAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("Failed to connect to miniKMS: %v", err)
	}
	defer conn.Close()

	kms := pb.NewKMSServiceClient(conn)
	pkiClient := pb.NewPKIServiceClient(conn)
	auditClient := pb.NewAuditServiceClient(conn)
	sessions := pb.NewSessionServiceClient(conn)
	vault := pb.NewVaultServiceClient(conn)
	fmt.Printf("  Connected to miniKMS at %s\n", minikmsAddr)

	tenantID := "org-test-001"
	scopeID := "app-test-001"

	// --- 2. CreateDataKey ---
	fmt.Println("\n=== 2. CreateDataKey ===")
	keyResp, err := kms.CreateDataKey(ctx, &pb.CreateDataKeyRequest{
		TenantId: tenantID,
		ScopeId:  scopeID,
	})
	if err != nil {
		log.Fatalf("CreateDataKey: %v", err)
	}
	fmt.Printf("  KeyVersionID: %s\n", keyResp.KeyVersionId)

	// --- 3. Encrypt secrets via miniKMS ---
	fmt.Println("\n=== 3. Encrypt Secrets via miniKMS ===")
	secrets := []struct {
		name      string
		plaintext string
		aad       string
	}{
		{"DB_PASSWORD", "super-secret-db-password", "env:production"},
		{"API_KEY", "sk-live-abc123xyz", "env:production"},
		{"JWT_SECRET", "jwt-hmac-secret-key-very-long", "env:production"},
	}

	type encryptedSecret struct {
		ciphertext   string
		keyVersionID string
		aad          string
	}
	encryptedMap := make(map[string]encryptedSecret)

	for _, s := range secrets {
		encResp, err := kms.Encrypt(ctx, &pb.EncryptRequest{
			TenantId:  tenantID,
			ScopeId:   scopeID,
			Plaintext: []byte(s.plaintext),
			Aad:       s.aad,
		})
		if err != nil {
			log.Fatalf("Encrypt %s: %v", s.name, err)
		}
		encryptedMap[s.name] = encryptedSecret{
			ciphertext:   encResp.Ciphertext,
			keyVersionID: encResp.KeyVersionId,
			aad:          s.aad,
		}
		fmt.Printf("  %s encrypted (key: %s)\n", s.name, encResp.KeyVersionId)
	}

	// --- 4. Decrypt via miniKMS (roundtrip verification) ---
	fmt.Println("\n=== 4. Decrypt via miniKMS (roundtrip verification) ===")
	for _, s := range secrets {
		enc := encryptedMap[s.name]
		decResp, err := kms.Decrypt(ctx, &pb.DecryptRequest{
			TenantId:     tenantID,
			ScopeId:      scopeID,
			Ciphertext:   enc.ciphertext,
			Aad:          enc.aad,
			KeyVersionId: enc.keyVersionID,
		})
		if err != nil {
			log.Fatalf("Decrypt %s: %v", s.name, err)
		}
		if string(decResp.Plaintext) != s.plaintext {
			log.Fatalf("Roundtrip mismatch for %s: got %q, want %q",
				s.name, string(decResp.Plaintext), s.plaintext)
		}
		fmt.Printf("  %s: roundtrip OK\n", s.name)
	}

	// --- 5. Key Rotation ---
	fmt.Println("\n=== 5. RotateDataKey ===")
	rotResp, err := kms.RotateDataKey(ctx, &pb.RotateDataKeyRequest{
		TenantId: tenantID,
		ScopeId:  scopeID,
	})
	if err != nil {
		log.Fatalf("RotateDataKey: %v", err)
	}
	fmt.Printf("  New KeyVersionID: %s\n", rotResp.NewKeyVersionId)

	// Encrypt + decrypt with rotated key
	newPlaintext := "post-rotation-secret-value"
	newAAD := "env:production"
	encNew, err := kms.Encrypt(ctx, &pb.EncryptRequest{
		TenantId:  tenantID,
		ScopeId:   scopeID,
		Plaintext: []byte(newPlaintext),
		Aad:       newAAD,
	})
	if err != nil {
		log.Fatalf("Encrypt after rotation: %v", err)
	}
	fmt.Printf("  Encrypted with rotated key: %s\n", encNew.KeyVersionId)

	decRotated, err := kms.Decrypt(ctx, &pb.DecryptRequest{
		TenantId:     tenantID,
		ScopeId:      scopeID,
		Ciphertext:   encNew.Ciphertext,
		Aad:          newAAD,
		KeyVersionId: encNew.KeyVersionId,
	})
	if err != nil {
		log.Fatalf("Decrypt rotated: %v", err)
	}
	if string(decRotated.Plaintext) != newPlaintext {
		log.Fatalf("Rotated roundtrip mismatch: got %q, want %q",
			string(decRotated.Plaintext), newPlaintext)
	}
	fmt.Printf("  Rotated secret roundtrip OK\n")

	// --- 6. PKI: CreateOrgCA + IssueMemberCert ---
	fmt.Println("\n=== 6. PKI ===")
	caResp, err := pkiClient.CreateOrgCA(ctx, &pb.CreateOrgCARequest{
		OrgId:   tenantID,
		OrgName: "Test Organization",
	})
	if err != nil {
		log.Fatalf("CreateOrgCA: %v", err)
	}
	fmt.Printf("  Org CA serial: %s\n", caResp.SerialHex)

	memberResp, err := pkiClient.IssueMemberCert(ctx, &pb.IssueMemberCertRequest{
		MemberId:    "user-001",
		MemberEmail: "alice@example.com",
		OrgId:       tenantID,
		Role:        "admin",
	})
	if err != nil {
		log.Fatalf("IssueMemberCert: %v", err)
	}
	fmt.Printf("  Member cert serial: %s\n", memberResp.SerialHex)

	rootCAResp, err := pkiClient.GetRootCA(ctx, &pb.GetRootCARequest{})
	if err != nil {
		log.Fatalf("GetRootCA: %v", err)
	}
	fmt.Printf("  Root CA PEM length: %d bytes\n", len(rootCAResp.CertPem))

	// --- 7. Audit: GetAuditLogs + VerifyChain ---
	fmt.Println("\n=== 7. Audit ===")
	logsResp, err := auditClient.GetAuditLogs(ctx, &pb.GetAuditLogsRequest{
		OrgId:  tenantID,
		Limit:  10,
		Offset: 0,
	})
	if err != nil {
		log.Fatalf("GetAuditLogs: %v", err)
	}
	fmt.Printf("  Found %d audit entries\n", len(logsResp.Entries))
	for _, e := range logsResp.Entries {
		fmt.Printf("    [%s] %s by %s\n", e.Timestamp, e.Action, e.ActorId)
	}

	verifyResp, err := auditClient.VerifyChain(ctx, &pb.VerifyChainRequest{
		OrgId: tenantID,
	})
	if err != nil {
		log.Fatalf("VerifyChain: %v", err)
	}
	fmt.Printf("  Chain valid: %v\n", verifyResp.Valid)

	fmt.Println("\n=== 8. Tenant isolation and AAD ===")
	encA, err := kms.Encrypt(ctx, &pb.EncryptRequest{
		TenantId: tenantID, ScopeId: scopeID, Plaintext: []byte("org-a-secret"), Aad: "env:prod",
	})
	if err != nil {
		log.Fatalf("Encrypt org A: %v", err)
	}
	if _, err := kms.Decrypt(ctx, &pb.DecryptRequest{
		TenantId: "org-other", ScopeId: scopeID, Ciphertext: encA.Ciphertext, Aad: "env:prod", KeyVersionId: encA.KeyVersionId,
	}); err == nil {
		log.Fatal("org-other decrypted org-test-001 ciphertext")
	}
	fmt.Println("  cross-tenant decrypt rejected")
	if _, err := kms.Decrypt(ctx, &pb.DecryptRequest{
		TenantId: tenantID, ScopeId: scopeID, Ciphertext: encA.Ciphertext, Aad: "env:staging", KeyVersionId: encA.KeyVersionId,
	}); err == nil {
		log.Fatal("wrong AAD decrypt succeeded")
	}
	fmt.Println("  wrong AAD decrypt rejected")

	fmt.Println("\n=== 9. Env CA + leaf ===")
	envCA, err := pkiClient.CreateEnvCA(ctx, &pb.CreateEnvCARequest{
		OrgId: tenantID, EnvId: "env-prod", Name: "production",
	})
	if err != nil {
		log.Fatalf("CreateEnvCA: %v", err)
	}
	fmt.Printf("  Env CA serial: %s\n", envCA.SerialHex)
	leaf, err := pkiClient.IssueLeafCert(ctx, &pb.IssueLeafCertRequest{
		OrgId: tenantID, CommonName: "svc.test.local", DnsSans: []string{"svc.test.local"}, TtlDays: 30, KeyAlgorithm: "ECDSA_P256",
	})
	if err != nil {
		log.Fatalf("IssueLeafCert: %v", err)
	}
	block, _ := pem.Decode([]byte(leaf.CertPem))
	if block == nil {
		log.Fatal("leaf cert pem")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		log.Fatalf("parse leaf: %v", err)
	}
	fmt.Printf("  Leaf serial: %s\n", leaf.SerialHex)

	fmt.Println("\n=== 10. Session proof + vault ===")
	token, err := sessionproof.Mint(ctx, sessions, memberResp.CertPem, memberResp.KeyPem, memberResp.SerialHex, []string{"vault:read", "vault:write"})
	if err != nil {
		log.Fatalf("Mint session: %v", err)
	}
	authCtx := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
	if _, err := vault.Write(authCtx, &pb.VaultWriteRequest{
		OrgId: tenantID, ScopeId: scopeID, EntryType: "secret", Key: "SESSION_OK", Value: []byte("ok"), CreatedBy: "user-001",
	}); err != nil {
		log.Fatalf("vault write: %v", err)
	}
	if _, err := vault.Read(authCtx, &pb.VaultReadRequest{
		OrgId: tenantID, ScopeId: scopeID, EntryType: "secret", Key: "SESSION_OK",
	}); err != nil {
		log.Fatalf("vault read: %v", err)
	}
	fmt.Println("  vault roundtrip with cert-proof session OK")

	fmt.Println("\n=== 11. Session negatives ===")
	if _, err := sessions.CreateSession(ctx, &pb.CreateSessionRequest{Scopes: []string{"vault:read"}}); err == nil {
		log.Fatal("CreateSession without cert_auth succeeded")
	} else if status.Code(err) != codes.InvalidArgument {
		log.Fatalf("CreateSession missing cert_auth: got %v", err)
	}
	fmt.Println("  missing cert_auth rejected")

	key, err := sessionproof.ParseMemberKey(memberResp.KeyPem)
	if err != nil {
		log.Fatal(err)
	}
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	sig, err := sessionproof.SignNonce(key, raw)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := sessions.CreateSession(ctx, &pb.CreateSessionRequest{
		CertAuth: &pb.CertAuth{CertPem: memberResp.CertPem, SignedNonce: sig, Nonce: raw},
	}); err == nil {
		log.Fatal("unissued nonce CreateSession succeeded")
	}
	fmt.Println("  unissued nonce rejected")

	ch, err := sessions.IssueSessionChallenge(ctx, &pb.IssueSessionChallengeRequest{CertSerial: memberResp.SerialHex})
	if err != nil {
		log.Fatalf("challenge: %v", err)
	}
	replaySig, err := sessionproof.SignNonce(key, ch.Nonce)
	if err != nil {
		log.Fatal(err)
	}
	req := &pb.CreateSessionRequest{CertAuth: &pb.CertAuth{CertPem: memberResp.CertPem, SignedNonce: replaySig, Nonce: ch.Nonce}}
	if _, err := sessions.CreateSession(ctx, req); err != nil {
		log.Fatalf("first challenge CreateSession: %v", err)
	}
	if _, err := sessions.CreateSession(ctx, req); err == nil {
		log.Fatal("replayed challenge succeeded")
	}
	fmt.Println("  replay rejected")

	fmt.Println("\n=== All tests passed! ===")
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
