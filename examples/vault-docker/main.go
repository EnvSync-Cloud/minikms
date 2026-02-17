package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	vaultapi "github.com/hashicorp/vault/api"

	pb "github.com/envsync/minikms/api/proto/minikms/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	// --- Configuration ---
	minikmsAddr := envOrDefault("MINIKMS_ADDR", "localhost:50051")
	vaultAddr := envOrDefault("VAULT_ADDR", "http://localhost:8200")
	vaultToken := envOrDefault("VAULT_TOKEN", "test-root-token")

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

	// --- 2. Connect to HashiCorp Vault ---
	fmt.Println("\n=== 2. Connect to Vault ===")
	vaultCfg := vaultapi.DefaultConfig()
	vaultCfg.Address = vaultAddr
	vault, err := vaultapi.NewClient(vaultCfg)
	if err != nil {
		log.Fatalf("Failed to create Vault client: %v", err)
	}
	vault.SetToken(vaultToken)

	// Verify Vault is reachable
	health, err := vault.Sys().Health()
	if err != nil {
		log.Fatalf("Vault health check failed: %v", err)
	}
	fmt.Printf("  Connected to Vault at %s (version: %s, sealed: %v)\n",
		vaultAddr, health.Version, health.Sealed)

	tenantID := "org-test-001"
	scopeID := "app-test-001"

	// --- 3. CreateDataKey ---
	fmt.Println("\n=== 3. CreateDataKey ===")
	keyResp, err := kms.CreateDataKey(ctx, &pb.CreateDataKeyRequest{
		TenantId: tenantID,
		ScopeId:  scopeID,
	})
	if err != nil {
		log.Fatalf("CreateDataKey: %v", err)
	}
	fmt.Printf("  KeyVersionID: %s\n", keyResp.KeyVersionId)

	// --- 4. Encrypt secrets via miniKMS ---
	fmt.Println("\n=== 4. Encrypt Secrets via miniKMS ===")
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
		Ciphertext   string `json:"ciphertext"`
		KeyVersionID string `json:"key_version_id"`
		AAD          string `json:"aad"`
	}
	encryptedMap := make(map[string]interface{})

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
		encryptedMap[s.name] = map[string]interface{}{
			"ciphertext":     encResp.Ciphertext,
			"key_version_id": encResp.KeyVersionId,
			"aad":            s.aad,
		}
		fmt.Printf("  %s encrypted (key: %s)\n", s.name, encResp.KeyVersionId)
	}

	// --- 5. Store ciphertexts in Vault KV v2 ---
	fmt.Println("\n=== 5. Store Ciphertexts in Vault ===")
	kvPath := "secret/data/myapp/env"
	_, err = vault.Logical().Write(kvPath, map[string]interface{}{
		"data": encryptedMap,
	})
	if err != nil {
		log.Fatalf("Vault write: %v", err)
	}
	fmt.Printf("  Stored %d encrypted secrets at %s\n", len(encryptedMap), kvPath)

	// --- 6. Retrieve ciphertexts from Vault KV v2 ---
	fmt.Println("\n=== 6. Retrieve Ciphertexts from Vault ===")
	vaultSecret, err := vault.Logical().Read(kvPath)
	if err != nil {
		log.Fatalf("Vault read: %v", err)
	}
	if vaultSecret == nil || vaultSecret.Data == nil {
		log.Fatalf("Vault read returned nil data")
	}

	data, ok := vaultSecret.Data["data"].(map[string]interface{})
	if !ok {
		log.Fatalf("Vault data is not a map")
	}
	fmt.Printf("  Retrieved %d secrets from Vault\n", len(data))

	// --- 7. Decrypt via miniKMS and verify roundtrip ---
	fmt.Println("\n=== 7. Decrypt via miniKMS (roundtrip verification) ===")
	for _, s := range secrets {
		entry, ok := data[s.name].(map[string]interface{})
		if !ok {
			log.Fatalf("Missing or invalid entry for %s", s.name)
		}

		ciphertext := entry["ciphertext"].(string)
		aad := entry["aad"].(string)

		decResp, err := kms.Decrypt(ctx, &pb.DecryptRequest{
			TenantId:   tenantID,
			ScopeId:    scopeID,
			Ciphertext: ciphertext,
			Aad:        aad,
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

	// --- 8. Key Rotation + new secret via Vault ---
	fmt.Println("\n=== 8. RotateDataKey + Store Rotated Secret in Vault ===")
	rotResp, err := kms.RotateDataKey(ctx, &pb.RotateDataKeyRequest{
		TenantId: tenantID,
		ScopeId:  scopeID,
	})
	if err != nil {
		log.Fatalf("RotateDataKey: %v", err)
	}
	fmt.Printf("  New KeyVersionID: %s\n", rotResp.NewKeyVersionId)

	// Encrypt a new secret with the rotated key
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

	// Store rotated secret in a separate Vault path
	rotatedPath := "secret/data/myapp/rotated"
	_, err = vault.Logical().Write(rotatedPath, map[string]interface{}{
		"data": map[string]interface{}{
			"ROTATION_SECRET": map[string]interface{}{
				"ciphertext":     encNew.Ciphertext,
				"key_version_id": encNew.KeyVersionId,
				"aad":            newAAD,
			},
		},
	})
	if err != nil {
		log.Fatalf("Vault write (rotated): %v", err)
	}
	fmt.Printf("  Stored rotated secret at %s\n", rotatedPath)

	// Retrieve and decrypt
	rotatedSecret, err := vault.Logical().Read(rotatedPath)
	if err != nil {
		log.Fatalf("Vault read (rotated): %v", err)
	}
	rotatedData := rotatedSecret.Data["data"].(map[string]interface{})
	rotEntry := rotatedData["ROTATION_SECRET"].(map[string]interface{})

	decRotated, err := kms.Decrypt(ctx, &pb.DecryptRequest{
		TenantId:   tenantID,
		ScopeId:    scopeID,
		Ciphertext: rotEntry["ciphertext"].(string),
		Aad:        rotEntry["aad"].(string),
	})
	if err != nil {
		log.Fatalf("Decrypt rotated: %v", err)
	}
	if string(decRotated.Plaintext) != newPlaintext {
		log.Fatalf("Rotated roundtrip mismatch: got %q, want %q",
			string(decRotated.Plaintext), newPlaintext)
	}
	fmt.Printf("  Rotated secret roundtrip OK\n")

	// --- 9. PKI: CreateOrgCA + IssueMemberCert ---
	fmt.Println("\n=== 9. PKI ===")
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

	// --- 10. Audit: GetAuditLogs + VerifyChain ---
	fmt.Println("\n=== 10. Audit ===")
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
