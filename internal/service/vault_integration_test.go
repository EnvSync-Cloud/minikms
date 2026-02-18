package service

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"
	"time"

	"github.com/envsync/minikms/internal/audit"
	"github.com/envsync/minikms/internal/keys"
	"github.com/envsync/minikms/internal/pki"
	"github.com/envsync/minikms/internal/testutil"
)

// integrationStack holds the full in-memory service stack for integration tests.
type integrationStack struct {
	kmsSvc   *KMSService
	keySvc   *KeyService
	auditSvc *AuditService
	pkiSvc   *PKIService

	rootCert   *x509.Certificate
	rootKey    interface{} // *ecdsa.PrivateKey, stored as interface to avoid import
	dekStore   *testutil.MockDEKStore
	auditStore *testutil.MockAuditStore
}

// setupIntegrationStack wires up the full vault stack using in-memory mocks.
// No external dependencies required — runs with plain `go test`.
func setupIntegrationStack(t *testing.T) *integrationStack {
	t.Helper()

	_, _, dekMgr, dekStore, auditLogger, auditStore, err := testutil.SetupTestKMSStack(testutil.TestRootKeyHex)
	if err != nil {
		t.Fatalf("SetupTestKMSStack: %v", err)
	}

	versionMgr := keys.NewKeyVersionManager(dekStore, 1000)

	kmsSvc := NewKMSService(dekMgr, auditLogger)
	keySvc := NewKeyService(dekMgr, versionMgr, auditLogger)
	auditSvc := NewAuditService(auditLogger, auditStore)

	rootCert, rootKey, _, err := pki.CreateRootCA("Integration Test Root CA", 10*365*24*time.Hour)
	if err != nil {
		t.Fatalf("CreateRootCA: %v", err)
	}
	pkiSvc := NewPKIService(rootCert, rootKey, auditLogger, nil)

	return &integrationStack{
		kmsSvc:     kmsSvc,
		keySvc:     keySvc,
		auditSvc:   auditSvc,
		pkiSvc:     pkiSvc,
		rootCert:   rootCert,
		rootKey:    rootKey,
		dekStore:   dekStore,
		auditStore: auditStore,
	}
}

func TestVaultIntegration_FullSecretLifecycle(t *testing.T) {
	stack := setupIntegrationStack(t)
	ctx := context.Background()

	type tenant struct {
		id     string
		scopes []string
	}

	tenants := []tenant{
		{id: "tenant-alpha", scopes: []string{"production", "staging"}},
		{id: "tenant-beta", scopes: []string{"production", "staging"}},
	}

	secrets := map[string]string{
		"DB_PASSWORD": "super-secret-db-pass-2024",
		"API_KEY":     "ak_live_xyz789abc",
		"JWT_SECRET":  "jwt-hmac-secret-key-very-long",
	}

	type encResult struct {
		ciphertext   string
		keyVersionID string
	}
	encrypted := make(map[string]map[string]map[string]encResult)

	// Step 1: Encrypt secrets for 2 tenants x 2 scopes each
	t.Run("encrypt_secrets", func(t *testing.T) {
		for _, tn := range tenants {
			encrypted[tn.id] = make(map[string]map[string]encResult)
			for _, scope := range tn.scopes {
				encrypted[tn.id][scope] = make(map[string]encResult)
				for name, value := range secrets {
					aad := fmt.Sprintf("%s:%s:%s", tn.id, scope, name)
					resp, err := stack.kmsSvc.Encrypt(ctx, &EncryptRequest{
						TenantID:  tn.id,
						ScopeID:   scope,
						Plaintext: []byte(value),
						AAD:       aad,
					})
					if err != nil {
						t.Fatalf("Encrypt %s/%s/%s: %v", tn.id, scope, name, err)
					}
					if resp.Ciphertext == "" || resp.KeyVersionID == "" {
						t.Fatalf("empty response for %s/%s/%s", tn.id, scope, name)
					}
					encrypted[tn.id][scope][name] = encResult{
						ciphertext:   resp.Ciphertext,
						keyVersionID: resp.KeyVersionID,
					}
				}
			}
		}
	})

	// Step 2: Decrypt all secrets and verify plaintext roundtrip
	t.Run("decrypt_secrets", func(t *testing.T) {
		for _, tn := range tenants {
			for _, scope := range tn.scopes {
				for name, expectedValue := range secrets {
					aad := fmt.Sprintf("%s:%s:%s", tn.id, scope, name)
					enc := encrypted[tn.id][scope][name]
					resp, err := stack.kmsSvc.Decrypt(ctx, &DecryptRequest{
						TenantID:     tn.id,
						ScopeID:      scope,
						Ciphertext:   enc.ciphertext,
						AAD:          aad,
						KeyVersionID: enc.keyVersionID,
					})
					if err != nil {
						t.Fatalf("Decrypt %s/%s/%s: %v", tn.id, scope, name, err)
					}
					if !bytes.Equal(resp.Plaintext, []byte(expectedValue)) {
						t.Errorf("plaintext mismatch for %s/%s/%s: got %q, want %q",
							tn.id, scope, name, string(resp.Plaintext), expectedValue)
					}
				}
			}
		}
	})

	// Step 3: Cross-tenant isolation — decrypt tenant-alpha's ciphertext with tenant-beta's context must fail
	t.Run("cross_tenant_isolation", func(t *testing.T) {
		alpha := tenants[0]
		beta := tenants[1]

		for name := range secrets {
			enc := encrypted[alpha.id]["production"][name]
			aad := fmt.Sprintf("%s:%s:%s", alpha.id, "production", name)

			_, err := stack.kmsSvc.Decrypt(ctx, &DecryptRequest{
				TenantID:     beta.id,
				ScopeID:      "production",
				Ciphertext:   enc.ciphertext,
				AAD:          aad,
				KeyVersionID: enc.keyVersionID,
			})
			if err == nil {
				t.Errorf("expected cross-tenant decryption to fail for secret %s", name)
			}
		}
	})

	// Step 4: Cross-scope isolation — decrypt production ciphertext with staging scope must fail
	t.Run("cross_scope_isolation", func(t *testing.T) {
		tn := tenants[0]

		for name := range secrets {
			enc := encrypted[tn.id]["production"][name]
			aad := fmt.Sprintf("%s:%s:%s", tn.id, "production", name)

			_, err := stack.kmsSvc.Decrypt(ctx, &DecryptRequest{
				TenantID:     tn.id,
				ScopeID:      "staging",
				Ciphertext:   enc.ciphertext,
				AAD:          aad,
				KeyVersionID: enc.keyVersionID,
			})
			if err == nil {
				t.Errorf("expected cross-scope decryption to fail for secret %s", name)
			}
		}
	})

	// Step 5: AAD tampering — decrypt with wrong AAD must fail
	t.Run("aad_tampering", func(t *testing.T) {
		tn := tenants[0]
		scope := "production"

		for name := range secrets {
			enc := encrypted[tn.id][scope][name]

			_, err := stack.kmsSvc.Decrypt(ctx, &DecryptRequest{
				TenantID:     tn.id,
				ScopeID:      scope,
				Ciphertext:   enc.ciphertext,
				AAD:          "tampered-aad",
				KeyVersionID: enc.keyVersionID,
			})
			if err == nil {
				t.Errorf("expected AAD tampering to fail for secret %s", name)
			}
		}
	})
}

func TestVaultIntegration_KeyRotationContinuity(t *testing.T) {
	stack := setupIntegrationStack(t)
	ctx := context.Background()

	tenantID := "rotation-tenant"
	scopeID := "app-1"

	// Step 1: Encrypt secrets under version 1
	type storedSecret struct {
		name       string
		plaintext  string
		ciphertext string
		keyVersion string
		aad        string
	}

	origSecrets := make([]storedSecret, 5)
	for i := 0; i < 5; i++ {
		name := fmt.Sprintf("SECRET_%d", i)
		value := fmt.Sprintf("value-%d-original", i)
		aad := fmt.Sprintf("%s:%s:%s", tenantID, scopeID, name)

		resp, err := stack.kmsSvc.Encrypt(ctx, &EncryptRequest{
			TenantID:  tenantID,
			ScopeID:   scopeID,
			Plaintext: []byte(value),
			AAD:       aad,
		})
		if err != nil {
			t.Fatalf("Encrypt SECRET_%d: %v", i, err)
		}
		origSecrets[i] = storedSecret{
			name:       name,
			plaintext:  value,
			ciphertext: resp.Ciphertext,
			keyVersion: resp.KeyVersionID,
			aad:        aad,
		}
	}

	initialKeyVersionID := origSecrets[0].keyVersion

	// Step 2: Rotate key
	rotateResp, err := stack.keySvc.RotateDataKey(ctx, &RotateDataKeyRequest{
		TenantID: tenantID,
		ScopeID:  scopeID,
	})
	if err != nil {
		t.Fatalf("RotateDataKey: %v", err)
	}

	if rotateResp.NewKeyVersionID == initialKeyVersionID {
		t.Fatal("new key version ID should differ from initial")
	}

	// Step 3: Encrypt new secrets — verify they use the new key version
	newResp, err := stack.kmsSvc.Encrypt(ctx, &EncryptRequest{
		TenantID:  tenantID,
		ScopeID:   scopeID,
		Plaintext: []byte("new-secret-after-rotation"),
		AAD:       fmt.Sprintf("%s:%s:NEW_SECRET", tenantID, scopeID),
	})
	if err != nil {
		t.Fatalf("Encrypt after rotation: %v", err)
	}
	if newResp.KeyVersionID != rotateResp.NewKeyVersionID {
		t.Errorf("new encryption should use rotated key: got %s, want %s",
			newResp.KeyVersionID, rotateResp.NewKeyVersionID)
	}

	// Step 4: Decrypt new secrets — verify they work
	decResp, err := stack.kmsSvc.Decrypt(ctx, &DecryptRequest{
		TenantID:     tenantID,
		ScopeID:      scopeID,
		Ciphertext:   newResp.Ciphertext,
		AAD:          fmt.Sprintf("%s:%s:NEW_SECRET", tenantID, scopeID),
		KeyVersionID: newResp.KeyVersionID,
	})
	if err != nil {
		t.Fatalf("Decrypt new secret after rotation: %v", err)
	}
	if !bytes.Equal(decResp.Plaintext, []byte("new-secret-after-rotation")) {
		t.Errorf("plaintext mismatch: got %q", string(decResp.Plaintext))
	}

	// Step 5: Verify audit log contains data_key_rotated action
	auditResp, err := stack.auditSvc.GetAuditLogs(ctx, &GetAuditLogsRequest{
		OrgID:  tenantID,
		Limit:  50,
		Offset: 0,
	})
	if err != nil {
		t.Fatalf("GetAuditLogs: %v", err)
	}

	foundRotation := false
	for _, entry := range auditResp.Entries {
		if entry.Action == "data_key_rotated" {
			foundRotation = true
			break
		}
	}
	if !foundRotation {
		t.Error("expected audit log entry with action 'data_key_rotated'")
	}
}

func TestVaultIntegration_BatchOperations(t *testing.T) {
	stack := setupIntegrationStack(t)
	ctx := context.Background()

	tenantID := "batch-tenant"
	scopeID := "batch-app"

	// Step 1: Batch-encrypt 10 items
	items := make([]BatchEncryptItem, 10)
	expectedValues := make([]string, 10)
	for i := 0; i < 10; i++ {
		name := fmt.Sprintf("ENV_VAR_%d", i)
		value := fmt.Sprintf("value-%d-batch", i)
		items[i] = BatchEncryptItem{
			Plaintext: []byte(value),
			AAD:       fmt.Sprintf("%s:%s:%s", tenantID, scopeID, name),
		}
		expectedValues[i] = value
	}

	batchEncResp, err := stack.kmsSvc.BatchEncrypt(ctx, &BatchEncryptRequest{
		TenantID: tenantID,
		ScopeID:  scopeID,
		Items:    items,
	})
	if err != nil {
		t.Fatalf("BatchEncrypt: %v", err)
	}
	if len(batchEncResp.Items) != 10 {
		t.Fatalf("expected 10 encrypted items, got %d", len(batchEncResp.Items))
	}

	// Step 2: Batch-decrypt all 10
	decItems := make([]DecryptRequest, 10)
	for i, encItem := range batchEncResp.Items {
		decItems[i] = DecryptRequest{
			TenantID:     tenantID,
			ScopeID:      scopeID,
			Ciphertext:   encItem.Ciphertext,
			AAD:          items[i].AAD,
			KeyVersionID: encItem.KeyVersionID,
		}
	}

	batchDecResp, err := stack.kmsSvc.BatchDecrypt(ctx, &BatchDecryptRequest{
		TenantID: tenantID,
		ScopeID:  scopeID,
		Items:    decItems,
	})
	if err != nil {
		t.Fatalf("BatchDecrypt: %v", err)
	}

	// Step 3: Verify all plaintexts match
	for i, decItem := range batchDecResp.Items {
		if !bytes.Equal(decItem.Plaintext, []byte(expectedValues[i])) {
			t.Errorf("item %d: got %q, want %q", i, string(decItem.Plaintext), expectedValues[i])
		}
	}

	// Step 4: Verify all share the same key version
	firstKeyVersion := batchEncResp.Items[0].KeyVersionID
	for i, item := range batchEncResp.Items {
		if item.KeyVersionID != firstKeyVersion {
			t.Errorf("item %d has different KeyVersionID: got %s, want %s",
				i, item.KeyVersionID, firstKeyVersion)
		}
	}
}

func TestVaultIntegration_AuditChainIntegrity(t *testing.T) {
	stack := setupIntegrationStack(t)
	ctx := context.Background()

	tenantID := "audit-tenant"
	scopeID := "audit-app"

	// Step 1: Perform sequence of operations (key creation via encrypt, rotation)
	// 3 encrypts (first one implicitly creates the key)
	for i := 0; i < 3; i++ {
		_, err := stack.kmsSvc.Encrypt(ctx, &EncryptRequest{
			TenantID:  tenantID,
			ScopeID:   scopeID,
			Plaintext: []byte(fmt.Sprintf("secret-%d", i)),
			AAD:       fmt.Sprintf("%s:%s:secret_%d", tenantID, scopeID, i),
		})
		if err != nil {
			t.Fatalf("Encrypt %d: %v", i, err)
		}
	}

	// 1 rotation
	_, err := stack.keySvc.RotateDataKey(ctx, &RotateDataKeyRequest{
		TenantID: tenantID,
		ScopeID:  scopeID,
	})
	if err != nil {
		t.Fatalf("RotateDataKey: %v", err)
	}

	// 2 more encrypts after rotation
	for i := 3; i < 5; i++ {
		_, err := stack.kmsSvc.Encrypt(ctx, &EncryptRequest{
			TenantID:  tenantID,
			ScopeID:   scopeID,
			Plaintext: []byte(fmt.Sprintf("secret-%d", i)),
			AAD:       fmt.Sprintf("%s:%s:secret_%d", tenantID, scopeID, i),
		})
		if err != nil {
			t.Fatalf("Encrypt %d: %v", i, err)
		}
	}

	// Step 2: Retrieve audit logs
	auditResp, err := stack.auditSvc.GetAuditLogs(ctx, &GetAuditLogsRequest{
		OrgID:  tenantID,
		Limit:  100,
		Offset: 0,
	})
	if err != nil {
		t.Fatalf("GetAuditLogs: %v", err)
	}

	// Step 3: Verify chain integrity
	chainResp, err := stack.auditSvc.VerifyChain(ctx, &VerifyChainRequest{
		OrgID: tenantID,
	})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !chainResp.Valid {
		t.Fatal("audit chain should be valid")
	}

	// Step 4: Verify expected action types present
	if len(auditResp.Entries) < 1 {
		t.Errorf("expected at least 1 audit entry, got %d", len(auditResp.Entries))
	}

	actions := make(map[string]int)
	for _, entry := range auditResp.Entries {
		actions[entry.Action]++
	}
	if actions["data_key_rotated"] < 1 {
		t.Error("expected at least one 'data_key_rotated' audit entry")
	}
}

func TestVaultIntegration_PKICertificateChain(t *testing.T) {
	stack := setupIntegrationStack(t)
	ctx := context.Background()

	orgID := "pki-test-org"

	// Step 1: Create Root CA (already done in setupIntegrationStack, but verify it exists)
	if stack.rootCert == nil {
		t.Fatal("root CA certificate should not be nil")
	}
	if !stack.rootCert.IsCA {
		t.Fatal("root certificate should be a CA")
	}

	// Step 2: Create Org Intermediate CA via PKIService.CreateOrgCA
	orgCAResp, err := stack.pkiSvc.CreateOrgCA(ctx, &CreateOrgCARequest{
		OrgID:   orgID,
		OrgName: "PKI Integration Test Org",
	})
	if err != nil {
		t.Fatalf("CreateOrgCA: %v", err)
	}

	block, _ := pem.Decode([]byte(orgCAResp.CertPEM))
	if block == nil {
		t.Fatal("failed to decode org CA PEM")
	}
	orgCACert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate org CA: %v", err)
	}

	// Verify org CA properties
	if !orgCACert.IsCA {
		t.Fatal("org CA certificate should have IsCA=true")
	}
	if orgCACert.MaxPathLen != 0 {
		t.Errorf("org CA MaxPathLen: got %d, want 0", orgCACert.MaxPathLen)
	}

	// Step 3: Create a separate org CA with key access for member cert issuance
	// (PKIService.CreateOrgCA doesn't return the private key)
	orgCACert2, orgCAKey2, _, err := pki.CreateOrgIntermediateCA(
		orgID, "PKI Integration Test Org",
		stack.pkiSvc.rootCert, stack.pkiSvc.rootKey,
		10*365*24*time.Hour,
	)
	if err != nil {
		t.Fatalf("CreateOrgIntermediateCA: %v", err)
	}

	// Step 4: Issue member cert via PKIService.IssueMemberCert
	memberResp, err := stack.pkiSvc.IssueMemberCert(ctx, &IssueMemberCertRequest{
		MemberID:    "member-001",
		MemberEmail: "alice@integration-test.com",
		OrgID:       orgID,
		Role:        "admin",
		OrgCACert:   orgCACert2,
		OrgCAKey:    orgCAKey2,
	})
	if err != nil {
		t.Fatalf("IssueMemberCert: %v", err)
	}

	memberBlock, _ := pem.Decode([]byte(memberResp.CertPEM))
	if memberBlock == nil {
		t.Fatal("failed to decode member cert PEM")
	}
	memberCert, err := x509.ParseCertificate(memberBlock.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate member: %v", err)
	}

	// Step 5: Verify cert properties
	if memberCert.IsCA {
		t.Fatal("member certificate should not be a CA")
	}

	hasDigitalSignature := memberCert.KeyUsage&x509.KeyUsageDigitalSignature != 0
	if !hasDigitalSignature {
		t.Error("member cert should have DigitalSignature key usage")
	}

	// Step 6: Verify full cert chain: member -> org CA -> root
	rootPool := x509.NewCertPool()
	rootPool.AddCert(stack.pkiSvc.rootCert)

	intermediatePool := x509.NewCertPool()
	intermediatePool.AddCert(orgCACert2)

	chains, err := memberCert.Verify(x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: intermediatePool,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		t.Fatalf("member cert verification failed: %v", err)
	}
	if len(chains) == 0 {
		t.Fatal("expected at least one valid certificate chain")
	}

	// Verify chain depth: member -> org CA -> root = 3
	chain := chains[0]
	if len(chain) != 3 {
		t.Errorf("expected chain length 3 (member -> org CA -> root), got %d", len(chain))
	}
}

// Ensure unused imports don't cause compilation errors.
var _ = audit.GenesisHash
