package rewrap

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/envsync-cloud/minikms/internal/escrow"
)

const (
	activeRootEscrowSQL = `SELECT EXISTS (
    SELECT 1 FROM key_escrow_sets
    WHERE org_id = $1 AND key_type = $2 AND status = 'active'
)`

	updateKeyVersionSQL = `UPDATE key_versions
SET encrypted_key = $1, updated_at = NOW()
WHERE id = $2`

	updateCertificateSQL = `UPDATE certificates
SET encrypted_private_key = $1
WHERE id = $2`

	readKeyVersionSQL  = `SELECT encrypted_key FROM key_versions WHERE id = $1`
	readCertificateSQL = `SELECT encrypted_private_key FROM certificates WHERE id = $1`
)

// PostgresStore implements Store with pgx against the miniKMS schema.
// Escrow share rows, vault_entries, and org_ca_wraps are not updated.
type PostgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore opens a pool and checks the connection.
func NewPostgresStore(ctx context.Context, connString string) (*PostgresStore, error) {
	if strings.TrimSpace(connString) == "" {
		return nil, fmt.Errorf("database URL is required")
	}
	config, err := pgxpool.ParseConfig(connString)
	if err != nil {
		return nil, fmt.Errorf("connect to PostgreSQL: %w", err)
	}
	config.MaxConns = 4
	config.MinConns = 0
	config.MaxConnLifetime = 30 * time.Minute
	config.MaxConnIdleTime = 5 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("connect to PostgreSQL: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connect to PostgreSQL: %w", err)
	}
	return &PostgresStore{pool: pool}, nil
}

// Close closes the pool.
func (s *PostgresStore) Close() {
	if s != nil && s.pool != nil {
		s.pool.Close()
	}
}

// HasActiveRootEscrow reports an active root-key escrow set. It selects no share bytes.
func (s *PostgresStore) HasActiveRootEscrow(ctx context.Context) (bool, error) {
	var active bool
	err := s.pool.QueryRow(ctx, activeRootEscrowSQL, escrow.RootScope, escrow.KeyTypeRoot).Scan(&active)
	if err != nil {
		return false, fmt.Errorf("check root escrow set: %w", err)
	}
	return active, nil
}

// Begin starts a read-only or read-write transaction.
func (s *PostgresStore) Begin(ctx context.Context, readOnly bool) (Tx, error) {
	tx, err := s.pool.BeginTx(ctx, txOptions(readOnly))
	if err != nil {
		return nil, fmt.Errorf("begin rewrap transaction: %w", err)
	}
	return &postgresTx{tx: tx, forUpdate: !readOnly}, nil
}

func txOptions(readOnly bool) pgx.TxOptions {
	if readOnly {
		return pgx.TxOptions{AccessMode: pgx.ReadOnly}
	}
	return pgx.TxOptions{AccessMode: pgx.ReadWrite}
}

type postgresTx struct {
	tx        pgx.Tx
	forUpdate bool
}

func (t *postgresTx) ListKeyVersions(ctx context.Context) ([]KeyVersionRow, error) {
	rows, err := t.tx.Query(ctx, keyVersionListSQL(t.forUpdate))
	if err != nil {
		return nil, fmt.Errorf("list key versions: %w", err)
	}
	defer rows.Close()

	var out []KeyVersionRow
	for rows.Next() {
		var row KeyVersionRow
		if err := rows.Scan(&row.ID, &row.OrgID, &row.EncryptedKey); err != nil {
			return nil, fmt.Errorf("scan key version: %w", err)
		}
		row.EncryptedKey = cloneBytes(row.EncryptedKey)
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list key versions: %w", err)
	}
	return out, nil
}

func (t *postgresTx) ListCertificates(ctx context.Context, certTypes []string) ([]CertificateRow, error) {
	query, err := certificateListSQL(t.forUpdate, len(certTypes))
	if err != nil {
		return nil, err
	}
	args := make([]any, len(certTypes))
	for i, certType := range certTypes {
		args[i] = certType
	}
	rows, err := t.tx.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list certificates: %w", err)
	}
	defer rows.Close()

	var out []CertificateRow
	for rows.Next() {
		var row CertificateRow
		if err := rows.Scan(&row.ID, &row.OrgID, &row.SerialNumber, &row.CertType, &row.EncryptedPrivateKey); err != nil {
			return nil, fmt.Errorf("scan certificate: %w", err)
		}
		row.EncryptedPrivateKey = cloneBytes(row.EncryptedPrivateKey)
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list certificates: %w", err)
	}
	return out, nil
}

func (t *postgresTx) UpdateKeyVersion(ctx context.Context, id string, encryptedKey []byte) error {
	tag, err := t.tx.Exec(ctx, updateKeyVersionSQL, encryptedKey, id)
	if err != nil {
		return fmt.Errorf("update key version: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("update key version matched %d rows", tag.RowsAffected())
	}
	return nil
}

func (t *postgresTx) UpdateCertificate(ctx context.Context, id string, encryptedPrivateKey []byte) error {
	tag, err := t.tx.Exec(ctx, updateCertificateSQL, encryptedPrivateKey, id)
	if err != nil {
		return fmt.Errorf("update certificate: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("update certificate matched %d rows", tag.RowsAffected())
	}
	return nil
}

func (t *postgresTx) ReadKeyVersion(ctx context.Context, id string) ([]byte, error) {
	var ciphertext []byte
	if err := t.tx.QueryRow(ctx, readKeyVersionSQL, id).Scan(&ciphertext); err != nil {
		return nil, fmt.Errorf("reread key version: %w", err)
	}
	return cloneBytes(ciphertext), nil
}

func (t *postgresTx) ReadCertificate(ctx context.Context, id string) ([]byte, error) {
	var ciphertext []byte
	if err := t.tx.QueryRow(ctx, readCertificateSQL, id).Scan(&ciphertext); err != nil {
		return nil, fmt.Errorf("reread certificate: %w", err)
	}
	return cloneBytes(ciphertext), nil
}

func (t *postgresTx) Commit(ctx context.Context) error {
	return t.tx.Commit(ctx)
}

func (t *postgresTx) Rollback(ctx context.Context) error {
	err := t.tx.Rollback(ctx)
	if errors.Is(err, pgx.ErrTxClosed) {
		return nil
	}
	return err
}

func keyVersionListSQL(forUpdate bool) string {
	query := `SELECT id, org_id, encrypted_key
FROM key_versions
ORDER BY id`
	if forUpdate {
		query += "\nFOR UPDATE"
	}
	return query
}

func certificateListSQL(forUpdate bool, typeCount int) (string, error) {
	if typeCount < 1 {
		return "", fmt.Errorf("certificate allowlist is empty")
	}
	placeholders := make([]string, typeCount)
	for i := range placeholders {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
	}
	query := fmt.Sprintf(`SELECT id, COALESCE(org_id, ''), serial_number, cert_type, encrypted_private_key
FROM certificates
WHERE cert_type IN (%s)
  AND encrypted_private_key IS NOT NULL
ORDER BY id`, strings.Join(placeholders, ", "))
	if forUpdate {
		query += "\nFOR UPDATE"
	}
	return query, nil
}

func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	return append([]byte(nil), b...)
}

var (
	_ Store = (*PostgresStore)(nil)
	_ Tx    = (*postgresTx)(nil)
)
