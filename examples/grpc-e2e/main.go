package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	pb "github.com/envsync-cloud/minikms/api/proto/minikms/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
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
			TenantId:   tenantID,
			ScopeId:    scopeID,
			Ciphertext: enc.ciphertext,
			Aad:        enc.aad,
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
		TenantId:   tenantID,
		ScopeId:    scopeID,
		Ciphertext: encNew.Ciphertext,
		Aad:        newAAD,
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

	fmt.Println("\n=== All tests passed! ===")
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
