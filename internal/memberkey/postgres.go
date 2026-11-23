package memberkey

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const listCertificatesSQL = `SELECT id, serial_number, cert_type, COALESCE(org_id, ''), status, expires_at, encrypted_private_key
FROM certificates
ORDER BY serial_number, id`

const updateMemberKeySQL = `UPDATE certificates
SET encrypted_private_key = $1
WHERE id = $2 AND cert_type = 'member' AND encrypted_private_key = $3`

const readMemberKeySQL = `SELECT encrypted_private_key
FROM certificates
WHERE id = $1 AND cert_type = 'member'`

// PostgresStore reads and updates certificate rows for member key wrapping.
type PostgresStore struct {
	pool *pgxpool.Pool
}

var (
	_ Store = (*PostgresStore)(nil)
	_ Tx    = (*postgresTx)(nil)
)

// NewPostgresStore opens a pool and checks the connection.
func NewPostgresStore(ctx context.Context, connString string) (*PostgresStore, error) {
	if strings.TrimSpace(connString) == "" {
		return nil, fmt.Errorf("MINIKMS_DB_URL is required")
	}
	config, err := pgxpool.ParseConfig(connString)
	if err != nil {
		// The parser error includes the connection string, so return a fixed message.
		return nil, fmt.Errorf("connect to PostgreSQL: MINIKMS_DB_URL is not a valid connection string")
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

// Begin starts a read-only or read-write transaction.
// A read-write transaction locks certificate rows for a stable snapshot.
// Only member rows are updated.
func (s *PostgresStore) Begin(ctx context.Context, readOnly bool) (Tx, error) {
	tx, err := s.pool.BeginTx(ctx, txOptions(readOnly))
	if err != nil {
		return nil, fmt.Errorf("begin member key wrap transaction: %w", err)
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

func (t *postgresTx) ListCertificates(ctx context.Context) ([]Row, error) {
	rows, err := t.tx.Query(ctx, listSQL(t.forUpdate))
	if err != nil {
		return nil, fmt.Errorf("list certificates: %w", err)
	}
	defer rows.Close()

	var out []Row
	for rows.Next() {
		var row Row
		var key []byte
		if err := rows.Scan(&row.ID, &row.SerialNumber, &row.CertType, &row.OrgID, &row.Status, &row.ExpiresAt, &key); err != nil {
			return nil, fmt.Errorf("list certificates: %w", err)
		}
		row.EncryptedPrivateKey = cloneBytes(key)
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list certificates: %w", err)
	}
	return out, nil
}

func (t *postgresTx) UpdateMemberKey(ctx context.Context, id string, previous, wrapped []byte) error {
	tag, err := t.tx.Exec(ctx, updateMemberKeySQL, wrapped, id, previous)
	if err != nil {
		return fmt.Errorf("update member key: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("member key row was not updated")
	}
	return nil
}

func (t *postgresTx) ReadMemberKey(ctx context.Context, id string) ([]byte, error) {
	var key []byte
	if err := t.tx.QueryRow(ctx, readMemberKeySQL, id).Scan(&key); err != nil {
		return nil, fmt.Errorf("reread member key: %w", err)
	}
	return cloneBytes(key), nil
}

func (t *postgresTx) Commit(ctx context.Context) error {
	return t.tx.Commit(ctx)
}

func (t *postgresTx) Rollback(ctx context.Context) error {
	err := t.tx.Rollback(ctx)
	if err == nil || errors.Is(err, pgx.ErrTxClosed) {
		return nil
	}
	return err
}

func listSQL(forUpdate bool) string {
	if !forUpdate {
		return listCertificatesSQL
	}
	return listCertificatesSQL + "\nFOR UPDATE"
}
