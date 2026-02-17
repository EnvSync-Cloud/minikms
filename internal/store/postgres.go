package store

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/envsync/minikms/internal/audit"
	"github.com/envsync/minikms/internal/auth"
	"github.com/envsync/minikms/internal/keys"
)

// PostgresStore implements all store interfaces using PostgreSQL via pgx.
type PostgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore creates a new PostgresStore with a connection pool.
func NewPostgresStore(ctx context.Context, connString string) (*PostgresStore, error) {
	config, err := pgxpool.ParseConfig(connString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DB config: %w", err)
	}

	config.MaxConns = 20
	config.MinConns = 5
	config.MaxConnLifetime = 30 * time.Minute
	config.MaxConnIdleTime = 5 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &PostgresStore{pool: pool}, nil
}

// Close closes the connection pool.
func (s *PostgresStore) Close() {
	s.pool.Close()
}

// --- DEKStore interface implementation ---

func (s *PostgresStore) GetActiveKeyVersion(ctx context.Context, orgID, appID string) (*keys.KeyVersionRecord, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id, org_id, app_id, key_type, version, encrypted_key, encryption_count, max_encryptions, status
		 FROM key_versions
		 WHERE org_id = $1 AND app_id = $2 AND status = 'active'
		 ORDER BY version DESC LIMIT 1`,
		orgID, appID)

	var r keys.KeyVersionRecord
	err := row.Scan(&r.ID, &r.OrgID, &r.AppID, &r.KeyType, &r.Version,
		&r.EncryptedKey, &r.EncryptionCount, &r.MaxEncryptions, &r.Status)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *PostgresStore) CreateKeyVersion(ctx context.Context, record *keys.KeyVersionRecord) error {
	record.ID = uuid.New().String()
	_, err := s.pool.Exec(ctx,
		`INSERT INTO key_versions (id, org_id, app_id, key_type, version, encrypted_key, encryption_count, max_encryptions, status, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW())`,
		record.ID, record.OrgID, record.AppID, record.KeyType, record.Version,
		record.EncryptedKey, record.EncryptionCount, record.MaxEncryptions, record.Status)
	return err
}

func (s *PostgresStore) IncrementEncryptionCount(ctx context.Context, keyVersionID string) (int64, error) {
	var newCount int64
	err := s.pool.QueryRow(ctx,
		`UPDATE key_versions SET encryption_count = encryption_count + 1, updated_at = NOW()
		 WHERE id = $1
		 RETURNING encryption_count`,
		keyVersionID).Scan(&newCount)
	return newCount, err
}

func (s *PostgresStore) UpdateKeyStatus(ctx context.Context, keyVersionID string, status string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE key_versions SET status = $1, updated_at = NOW() WHERE id = $2`,
		status, keyVersionID)
	return err
}

// --- TokenRegistry interface implementation ---

func (s *PostgresStore) StoreToken(ctx context.Context, entry *auth.TokenEntry) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO token_registry (jti, subject_hash, jwt_hash, issued_at, expires_at, revoked)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		entry.JTI, entry.SubjectHash, entry.JWTHash, entry.IssuedAt, entry.ExpiresAt, entry.Revoked)
	return err
}

func (s *PostgresStore) GetToken(ctx context.Context, jti string) (*auth.TokenEntry, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT jti, subject_hash, jwt_hash, issued_at, expires_at, revoked
		 FROM token_registry WHERE jti = $1`, jti)

	var e auth.TokenEntry
	err := row.Scan(&e.JTI, &e.SubjectHash, &e.JWTHash, &e.IssuedAt, &e.ExpiresAt, &e.Revoked)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &e, nil
}

func (s *PostgresStore) RevokeToken(ctx context.Context, jti string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE token_registry SET revoked = true WHERE jti = $1`, jti)
	return err
}

func (s *PostgresStore) CleanupExpired(ctx context.Context) error {
	_, err := s.pool.Exec(ctx,
		`DELETE FROM token_registry WHERE expires_at < NOW()`)
	return err
}

// --- AuditStore interface implementation ---

func (s *PostgresStore) GetLatestEntryHash(ctx context.Context, orgID string) (string, error) {
	var hash string
	err := s.pool.QueryRow(ctx,
		`SELECT entry_hash FROM kms_audit_log
		 WHERE org_id = $1
		 ORDER BY timestamp DESC LIMIT 1`,
		orgID).Scan(&hash)
	if err == pgx.ErrNoRows {
		return audit.GenesisHash, nil
	}
	if err != nil {
		return "", err
	}
	return hash, nil
}

func (s *PostgresStore) InsertEntry(ctx context.Context, entry *audit.AuditEntry) error {
	entry.ID = uuid.New().String()
	_, err := s.pool.Exec(ctx,
		`INSERT INTO kms_audit_log (id, previous_hash, entry_hash, timestamp, action, actor_id, org_id, details, request_jwt_hash)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		entry.ID, entry.PreviousHash, entry.EntryHash, entry.Timestamp,
		entry.Action, entry.ActorID, entry.OrgID, entry.Details, entry.RequestJWTHash)
	return err
}

func (s *PostgresStore) GetEntries(ctx context.Context, orgID string, limit, offset int) ([]*audit.AuditEntry, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, previous_hash, entry_hash, timestamp, action, actor_id, org_id, details, request_jwt_hash
		 FROM kms_audit_log
		 WHERE org_id = $1
		 ORDER BY timestamp DESC
		 LIMIT $2 OFFSET $3`,
		orgID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []*audit.AuditEntry
	for rows.Next() {
		var e audit.AuditEntry
		if err := rows.Scan(&e.ID, &e.PreviousHash, &e.EntryHash, &e.Timestamp,
			&e.Action, &e.ActorID, &e.OrgID, &e.Details, &e.RequestJWTHash); err != nil {
			return nil, err
		}
		entries = append(entries, &e)
	}
	return entries, rows.Err()
}

func (s *PostgresStore) VerifyChain(ctx context.Context, orgID string) (bool, error) {
	entries, err := s.GetEntries(ctx, orgID, 10000, 0)
	if err != nil {
		return false, err
	}
	if len(entries) == 0 {
		return true, nil
	}
	valid, _ := audit.VerifyChainIntegrity(entries)
	return valid, nil
}
