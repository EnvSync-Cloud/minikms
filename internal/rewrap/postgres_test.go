package rewrap

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/envsync-cloud/minikms/internal/escrow"
)

func TestTxOptions(t *testing.T) {
	readOnly := txOptions(true)
	if readOnly.AccessMode != pgx.ReadOnly {
		t.Fatalf("read-only access mode %q", readOnly.AccessMode)
	}
	readWrite := txOptions(false)
	if readWrite.AccessMode != pgx.ReadWrite {
		t.Fatalf("read-write access mode %q", readWrite.AccessMode)
	}
}

func TestListSQL(t *testing.T) {
	keyRead := keyVersionListSQL(false)
	keyWrite := keyVersionListSQL(true)
	if strings.Contains(keyRead, "FOR UPDATE") {
		t.Fatal("read-only key version query locks rows")
	}
	if !strings.Contains(keyWrite, "FOR UPDATE") {
		t.Fatal("key version query missing FOR UPDATE")
	}
	if strings.Contains(strings.ToLower(keyWrite), "status") {
		t.Fatal("key version query filters status")
	}

	certRead, err := certificateListSQL(false, 1)
	if err != nil {
		t.Fatal(err)
	}
	certWrite, err := certificateListSQL(true, 2)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(certRead, "FOR UPDATE") {
		t.Fatal("read-only certificate query locks rows")
	}
	if !strings.Contains(certRead, "IN ($1)") || !strings.Contains(certRead, "encrypted_private_key IS NOT NULL") {
		t.Fatalf("certificate query = %s", certRead)
	}
	if !strings.Contains(certWrite, "IN ($1, $2)") || !strings.Contains(certWrite, "FOR UPDATE") {
		t.Fatalf("certificate update query = %s", certWrite)
	}
	if strings.Contains(strings.ToLower(certRead), "status") || strings.Contains(strings.ToLower(certWrite), "status") {
		t.Fatal("certificate query filters status")
	}
	for _, query := range []string{keyRead, keyWrite, certRead, certWrite} {
		for _, table := range []string{"vault_entries", "org_ca_wraps", "key_escrow_shares"} {
			if strings.Contains(query, table) {
				t.Fatalf("query references %s", table)
			}
		}
	}
	if _, err := certificateListSQL(false, 0); err == nil {
		t.Fatal("empty allowlist produced SQL")
	}

	memberRead := memberListSQL(false)
	memberWrite := memberListSQL(true)
	if !strings.Contains(memberRead, "cert_type = 'member'") || strings.Contains(memberRead, "IS NOT NULL") {
		t.Fatalf("member query = %s", memberRead)
	}
	if strings.Contains(memberRead, "FOR UPDATE") || !strings.Contains(memberWrite, "FOR UPDATE") {
		t.Fatal("member query lock mode is wrong")
	}
	if strings.Contains(strings.ToLower(memberRead), "status") {
		t.Fatal("member query filters status")
	}
	for _, query := range []string{memberRead, memberWrite} {
		for _, table := range []string{"vault_entries", "org_ca_wraps", "key_escrow_shares"} {
			if strings.Contains(query, table) {
				t.Fatalf("query references %s", table)
			}
		}
	}
}

func TestNewPostgresStore_InvalidURLOmitsConnectionString(t *testing.T) {
	const token = "db-setting-9f3c2a"
	conn := "postgresql://operator@db/minikms?password=" + token + "&connect_timeout=not-a-duration"
	_, err := NewPostgresStore(context.Background(), conn)
	if err == nil {
		t.Fatal("expected an invalid connection string to fail")
	}
	msg := err.Error()
	if strings.Contains(msg, token) || strings.Contains(msg, "operator@") || strings.Contains(msg, "password=") || strings.Contains(msg, "connect_timeout") {
		t.Fatal("parse error included connection string details")
	}
	const want = "connect to PostgreSQL: MINIKMS_DB_URL is not a valid connection string"
	if msg != want {
		t.Fatalf("parse error = %q", msg)
	}
}

func TestMutationSQL(t *testing.T) {
	if !strings.Contains(updateKeyVersionSQL, "updated_at = NOW()") {
		t.Fatal("key version update does not set updated_at")
	}
	if strings.Contains(updateKeyVersionSQL, "encryption_count") {
		t.Fatal("key version update changes encryption_count")
	}
	if strings.Contains(updateCertificateSQL, "updated_at") || strings.Contains(updateCertificateSQL, "cert_pem") {
		t.Fatal("certificate update rewrites columns other than the ciphertext")
	}
	if !strings.Contains(updateCertificateSQL, "encrypted_private_key") {
		t.Fatal("certificate update does not set encrypted_private_key")
	}
}

func TestActiveRootEscrowSQL(t *testing.T) {
	if strings.Contains(activeRootEscrowSQL, "encrypted_share") || strings.Contains(activeRootEscrowSQL, "secret_hash") {
		t.Fatal("escrow check reads share material")
	}
	if !strings.Contains(activeRootEscrowSQL, "status = 'active'") {
		t.Fatal("escrow check does not require an active set")
	}
	if escrow.RootScope != "_root" || escrow.KeyTypeRoot != "root" {
		t.Fatal("root escrow identity changed")
	}
}
