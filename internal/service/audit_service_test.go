package service

import (
	"context"
	"testing"

	"github.com/envsync/minikms/internal/audit"
	"github.com/envsync/minikms/internal/testutil"
)

func setupAuditService(t *testing.T) (*AuditService, *audit.AuditLogger) {
	t.Helper()
	auditStore := testutil.NewMockAuditStore()
	auditLogger := audit.NewAuditLogger(auditStore)
	svc := NewAuditService(auditLogger, auditStore)
	return svc, auditLogger
}

func TestAuditService_GetAuditLogs(t *testing.T) {
	ctx := context.Background()
	svc, logger := setupAuditService(t)

	// Insert some audit entries
	_ = logger.Log(ctx, "org1", "encrypt", "user1", "encrypted secret", "")
	_ = logger.Log(ctx, "org1", "decrypt", "user1", "decrypted secret", "")
	_ = logger.Log(ctx, "org1", "rotate", "system", "rotated key", "")

	t.Run("with limit", func(t *testing.T) {
		resp, err := svc.GetAuditLogs(ctx, &GetAuditLogsRequest{
			OrgID:  "org1",
			Limit:  2,
			Offset: 0,
		})
		if err != nil {
			t.Fatalf("GetAuditLogs: %v", err)
		}
		if len(resp.Entries) != 2 {
			t.Fatalf("expected 2 entries, got %d", len(resp.Entries))
		}
	})

	t.Run("with offset", func(t *testing.T) {
		resp, err := svc.GetAuditLogs(ctx, &GetAuditLogsRequest{
			OrgID:  "org1",
			Limit:  10,
			Offset: 1,
		})
		if err != nil {
			t.Fatalf("GetAuditLogs: %v", err)
		}
		if len(resp.Entries) != 2 {
			t.Fatalf("expected 2 entries (offset 1 of 3), got %d", len(resp.Entries))
		}
	})
}

func TestAuditService_VerifyChain(t *testing.T) {
	ctx := context.Background()

	t.Run("valid chain", func(t *testing.T) {
		svc, logger := setupAuditService(t)
		_ = logger.Log(ctx, "org1", "encrypt", "user1", "data1", "")
		_ = logger.Log(ctx, "org1", "decrypt", "user1", "data2", "")

		resp, err := svc.VerifyChain(ctx, &VerifyChainRequest{OrgID: "org1"})
		if err != nil {
			t.Fatalf("VerifyChain: %v", err)
		}
		if !resp.Valid {
			t.Fatal("valid chain should verify")
		}
	})

	t.Run("empty chain is valid", func(t *testing.T) {
		svc, _ := setupAuditService(t)
		resp, err := svc.VerifyChain(ctx, &VerifyChainRequest{OrgID: "nonexistent"})
		if err != nil {
			t.Fatalf("VerifyChain: %v", err)
		}
		if !resp.Valid {
			t.Fatal("empty chain should be valid")
		}
	})
}
