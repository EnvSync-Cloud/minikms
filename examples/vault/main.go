// Package main demonstrates the full miniKMS vault API end-to-end
// using in-memory stores. No external dependencies required.
package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"time"

	"github.com/envsync/minikms/internal/keys"
	"github.com/envsync/minikms/internal/pki"
	"github.com/envsync/minikms/internal/service"
	"github.com/envsync/minikms/internal/testutil"
)

func main() {
	fmt.Println("========================================")
	fmt.Println("  miniKMS Vault API Demo")
	fmt.Println("========================================")
	fmt.Println()

	ctx := context.Background()

	// --- Initialize the full vault stack ---
	fmt.Println("[Setup] Initializing vault stack with in-memory stores...")
	_, _, dekMgr, dekStore, auditLogger, auditStore, err := testutil.SetupTestKMSStack(testutil.TestRootKeyHex)
	if err != nil {
		log.Fatalf("SetupTestKMSStack: %v", err)
	}

	versionMgr := keys.NewKeyVersionManager(dekStore, 1000)

	kmsSvc := service.NewKMSService(dekMgr, auditLogger)
	keySvc := service.NewKeyService(dekMgr, versionMgr, auditLogger)
	auditSvc := service.NewAuditService(auditLogger, auditStore)

	rootCert, rootKey, _, err := pki.CreateRootCA("Demo Root CA", 10*365*24*time.Hour)
	if err != nil {
		log.Fatalf("CreateRootCA: %v", err)
	}
	pkiSvc := service.NewPKIService(rootCert, rootKey, auditLogger, nil)

	fmt.Println("[Setup] Stack initialized: KMSService, KeyService, AuditService, PKIService")
	fmt.Println()

	// ===========================================
	// 1. Encrypt Secrets
	// ===========================================
	fmt.Println("--- 1. Encrypt Secrets ---")
	tenantID := "acme-corp"
	scopeID := "production"

	secrets := map[string]string{
		"DB_PASSWORD": "super-secret-db-pass-2024",
		"API_KEY":     "ak_live_xyz789abc",
		"JWT_SECRET":  "jwt-hmac-secret-key-very-long",
	}

	type encResult struct {
		ciphertext   string
		keyVersionID string
	}
	encrypted := make(map[string]encResult)

	for name, value := range secrets {
		aad := fmt.Sprintf("%s:%s:%s", tenantID, scopeID, name)
		resp, err := kmsSvc.Encrypt(ctx, &service.EncryptRequest{
			TenantID:  tenantID,
			ScopeID:   scopeID,
			Plaintext: []byte(value),
			AAD:       aad,
		})
		if err != nil {
			log.Fatalf("Encrypt %s: %v", name, err)
		}
		encrypted[name] = encResult{ciphertext: resp.Ciphertext, keyVersionID: resp.KeyVersionID}
		fmt.Printf("  Encrypted %-12s -> ciphertext=%s... (key=%s)\n",
			name, resp.Ciphertext[:20], resp.KeyVersionID)
	}
	fmt.Println()

	// ===========================================
	// 2. Decrypt Secrets
	// ===========================================
	fmt.Println("--- 2. Decrypt Secrets ---")
	for name, enc := range encrypted {
		aad := fmt.Sprintf("%s:%s:%s", tenantID, scopeID, name)
		resp, err := kmsSvc.Decrypt(ctx, &service.DecryptRequest{
			TenantID:     tenantID,
			ScopeID:      scopeID,
			Ciphertext:   enc.ciphertext,
			AAD:          aad,
			KeyVersionID: enc.keyVersionID,
		})
		if err != nil {
			log.Fatalf("Decrypt %s: %v", name, err)
		}
		fmt.Printf("  Decrypted %-12s -> %q\n", name, string(resp.Plaintext))
	}
	fmt.Println()

	// ===========================================
	// 3. Tenant Isolation
	// ===========================================
	fmt.Println("--- 3. Tenant Isolation ---")
	otherTenant := "globex-inc"
	// Try decrypting acme-corp's secret with globex-inc's context
	for name, enc := range encrypted {
		aad := fmt.Sprintf("%s:%s:%s", tenantID, scopeID, name)
		_, err := kmsSvc.Decrypt(ctx, &service.DecryptRequest{
			TenantID:     otherTenant,
			ScopeID:      scopeID,
			Ciphertext:   enc.ciphertext,
			AAD:          aad,
			KeyVersionID: enc.keyVersionID,
		})
		if err != nil {
			fmt.Printf("  Cross-tenant decrypt %-12s -> BLOCKED (expected): %v\n", name, err)
		} else {
			fmt.Printf("  Cross-tenant decrypt %-12s -> UNEXPECTED SUCCESS\n", name)
		}
		break // One example is sufficient
	}
	fmt.Println()

	// ===========================================
	// 4. Key Rotation
	// ===========================================
	fmt.Println("--- 4. Key Rotation ---")
	keyInfo, err := keySvc.GetKeyInfo(ctx, &service.GetKeyInfoRequest{
		TenantID: tenantID,
		ScopeID:  scopeID,
	})
	if err != nil {
		log.Fatalf("GetKeyInfo: %v", err)
	}
	fmt.Printf("  Before rotation: key=%s, encryptions=%d\n", keyInfo.KeyVersionID, keyInfo.EncryptionCount)

	rotateResp, err := keySvc.RotateDataKey(ctx, &service.RotateDataKeyRequest{
		TenantID: tenantID,
		ScopeID:  scopeID,
	})
	if err != nil {
		log.Fatalf("RotateDataKey: %v", err)
	}
	fmt.Printf("  Rotated: new key=%s\n", rotateResp.NewKeyVersionID)

	// Encrypt with new key
	newResp, err := kmsSvc.Encrypt(ctx, &service.EncryptRequest{
		TenantID:  tenantID,
		ScopeID:   scopeID,
		Plaintext: []byte("post-rotation-secret"),
		AAD:       fmt.Sprintf("%s:%s:NEW", tenantID, scopeID),
	})
	if err != nil {
		log.Fatalf("Encrypt after rotation: %v", err)
	}
	fmt.Printf("  Encrypted with new key: version=%s\n", newResp.KeyVersionID)

	// Decrypt with new key
	decResp, err := kmsSvc.Decrypt(ctx, &service.DecryptRequest{
		TenantID:     tenantID,
		ScopeID:      scopeID,
		Ciphertext:   newResp.Ciphertext,
		AAD:          fmt.Sprintf("%s:%s:NEW", tenantID, scopeID),
		KeyVersionID: newResp.KeyVersionID,
	})
	if err != nil {
		log.Fatalf("Decrypt after rotation: %v", err)
	}
	fmt.Printf("  Decrypted with new key: %q\n", string(decResp.Plaintext))
	fmt.Println()

	// ===========================================
	// 5. Batch Operations
	// ===========================================
	fmt.Println("--- 5. Batch Operations ---")
	batchTenant := "batch-demo"
	batchScope := "staging"

	items := make([]service.BatchEncryptItem, 5)
	for i := 0; i < 5; i++ {
		items[i] = service.BatchEncryptItem{
			Plaintext: []byte(fmt.Sprintf("batch-secret-%d", i)),
			AAD:       fmt.Sprintf("%s:%s:VAR_%d", batchTenant, batchScope, i),
		}
	}

	batchEncResp, err := kmsSvc.BatchEncrypt(ctx, &service.BatchEncryptRequest{
		TenantID: batchTenant,
		ScopeID:  batchScope,
		Items:    items,
	})
	if err != nil {
		log.Fatalf("BatchEncrypt: %v", err)
	}
	fmt.Printf("  Batch encrypted %d items (all using key=%s)\n",
		len(batchEncResp.Items), batchEncResp.Items[0].KeyVersionID)

	// Batch decrypt
	decItems := make([]service.DecryptRequest, len(batchEncResp.Items))
	for i, enc := range batchEncResp.Items {
		decItems[i] = service.DecryptRequest{
			TenantID:     batchTenant,
			ScopeID:      batchScope,
			Ciphertext:   enc.Ciphertext,
			AAD:          items[i].AAD,
			KeyVersionID: enc.KeyVersionID,
		}
	}

	batchDecResp, err := kmsSvc.BatchDecrypt(ctx, &service.BatchDecryptRequest{
		TenantID: batchTenant,
		ScopeID:  batchScope,
		Items:    decItems,
	})
	if err != nil {
		log.Fatalf("BatchDecrypt: %v", err)
	}

	for i, dec := range batchDecResp.Items {
		fmt.Printf("  [%d] %q\n", i, string(dec.Plaintext))
	}
	fmt.Println()

	// ===========================================
	// 6. PKI Certificate Chain
	// ===========================================
	fmt.Println("--- 6. PKI Certificate Chain ---")
	orgID := "pki-demo-org"

	// Create org intermediate CA
	orgCAResp, err := pkiSvc.CreateOrgCA(ctx, &service.CreateOrgCARequest{
		OrgID:   orgID,
		OrgName: "Demo Organization",
	})
	if err != nil {
		log.Fatalf("CreateOrgCA: %v", err)
	}
	fmt.Printf("  Org CA created: serial=%s\n", orgCAResp.SerialHex)

	// For member cert issuance, create an org CA with key access
	orgCACert, orgCAKey, _, err := pki.CreateOrgIntermediateCA(
		orgID, "Demo Organization",
		rootCert, rootKey,
		10*365*24*time.Hour,
	)
	if err != nil {
		log.Fatalf("CreateOrgIntermediateCA: %v", err)
	}
	fmt.Printf("  Org CA: IsCA=%v, MaxPathLen=%d\n", orgCACert.IsCA, orgCACert.MaxPathLen)

	// Issue member cert
	memberResp, err := pkiSvc.IssueMemberCert(ctx, &service.IssueMemberCertRequest{
		MemberID:    "member-alice",
		MemberEmail: "alice@demo-org.com",
		OrgID:       orgID,
		Role:        "admin",
		OrgCACert:   orgCACert,
		OrgCAKey:    orgCAKey,
	})
	if err != nil {
		log.Fatalf("IssueMemberCert: %v", err)
	}
	fmt.Printf("  Member cert issued: serial=%s\n", memberResp.SerialHex)

	// Verify chain
	memberBlock, _ := pem.Decode([]byte(memberResp.CertPEM))
	memberCert, _ := x509.ParseCertificate(memberBlock.Bytes)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)
	intermediatePool := x509.NewCertPool()
	intermediatePool.AddCert(orgCACert)

	chains, err := memberCert.Verify(x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: intermediatePool,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		log.Fatalf("Chain verification failed: %v", err)
	}
	fmt.Printf("  Chain verified: depth=%d (member -> org CA -> root)\n", len(chains[0]))
	fmt.Println()

	// ===========================================
	// 7. Audit Trail
	// ===========================================
	fmt.Println("--- 7. Audit Trail ---")

	// Collect audit logs for the main tenant
	auditResp, err := auditSvc.GetAuditLogs(ctx, &service.GetAuditLogsRequest{
		OrgID:  tenantID,
		Limit:  20,
		Offset: 0,
	})
	if err != nil {
		log.Fatalf("GetAuditLogs: %v", err)
	}
	fmt.Printf("  Found %d audit entries for tenant %q:\n", len(auditResp.Entries), tenantID)
	for i, entry := range auditResp.Entries {
		fmt.Printf("    [%d] action=%s, actor=%s, time=%s\n",
			i, entry.Action, entry.ActorID, entry.Timestamp.Format(time.RFC3339))
	}

	// Verify chain integrity
	chainResp, err := auditSvc.VerifyChain(ctx, &service.VerifyChainRequest{
		OrgID: tenantID,
	})
	if err != nil {
		log.Fatalf("VerifyChain: %v", err)
	}
	fmt.Printf("  Audit chain integrity: valid=%v\n", chainResp.Valid)

	// Also check the PKI org's audit
	pkiAuditResp, err := auditSvc.GetAuditLogs(ctx, &service.GetAuditLogsRequest{
		OrgID:  orgID,
		Limit:  20,
		Offset: 0,
	})
	if err != nil {
		log.Fatalf("GetAuditLogs (PKI): %v", err)
	}
	fmt.Printf("  Found %d audit entries for PKI org %q:\n", len(pkiAuditResp.Entries), orgID)
	for i, entry := range pkiAuditResp.Entries {
		fmt.Printf("    [%d] action=%s, actor=%s\n", i, entry.Action, entry.ActorID)
	}

	fmt.Println()
	fmt.Println("========================================")
	fmt.Println("  Demo Complete")
	fmt.Println("========================================")
}
