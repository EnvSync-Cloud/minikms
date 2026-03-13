package store

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/envsync-cloud/minikms/internal/audit"
	"github.com/envsync-cloud/minikms/internal/auth"
	"github.com/envsync-cloud/minikms/internal/keys"
	"github.com/envsync-cloud/minikms/internal/pkistore"
)

// --- VaultEntry types ---

// VaultEntry represents a row in the vault_entries table.
type VaultEntry struct {
	ID             string
	OrgID          string
	ScopeID        string
	EntryType      string
	Key            string
	EnvTypeID      *string
	EncryptedValue []byte
	KeyVersionID   string
	Version        int
	CreatedAt      time.Time
	DeletedAt      *time.Time
	Destroyed      bool
	CreatedBy      *string
}

// VaultListItem represents a summary entry for vault listing.
type VaultListItem struct {
	Key           string
	LatestVersion int
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// OrgSecurityPolicy represents a row in the org_security_policy table.
type OrgSecurityPolicy struct {
	OrgID              string
	RequireBYOK        bool
	SessionDurationSec int
	MaxSessionTokens   int
	RequireMFAForAdmin bool
	ShamirThreshold    int
	ShamirTotalShares  int
}

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
		`INSERT INTO token_registry (jti, subject_hash, jwt_hash, issued_at, expires_at, revoked, cert_serial, scopes)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		entry.JTI, entry.SubjectHash, entry.JWTHash, entry.IssuedAt, entry.ExpiresAt, entry.Revoked, entry.CertSerial, entry.Scopes)
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
		e.Timestamp = e.Timestamp.UTC()
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

// --- PKICertStore interface implementation ---

func (s *PostgresStore) StoreCertificate(ctx context.Context, rec *pkistore.CertRecord) error {
	rec.ID = uuid.New().String()
	_, err := s.pool.Exec(ctx,
		`INSERT INTO certificates (id, serial_number, cert_type, org_id, subject_cn, cert_pem, status, issued_at, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		rec.ID, rec.SerialNumber, rec.CertType, rec.OrgID, rec.SubjectCN, rec.CertPEM, rec.Status, rec.IssuedAt, rec.ExpiresAt)
	return err
}

func (s *PostgresStore) GetCertificateBySerial(ctx context.Context, serialNumber string) (*pkistore.CertRecord, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id, serial_number, cert_type, org_id, subject_cn, cert_pem, status, issued_at, expires_at
		 FROM certificates WHERE serial_number = $1`, serialNumber)

	var r pkistore.CertRecord
	err := row.Scan(&r.ID, &r.SerialNumber, &r.CertType, &r.OrgID, &r.SubjectCN, &r.CertPEM, &r.Status, &r.IssuedAt, &r.ExpiresAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *PostgresStore) StoreCertificateWithKey(ctx context.Context, rec *pkistore.CertRecord) error {
	rec.ID = uuid.New().String()
	_, err := s.pool.Exec(ctx,
		`INSERT INTO certificates (id, serial_number, cert_type, org_id, subject_cn, cert_pem, encrypted_private_key, status, issued_at, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		rec.ID, rec.SerialNumber, rec.CertType, rec.OrgID, rec.SubjectCN, rec.CertPEM,
		rec.EncryptedPrivateKey, rec.Status, rec.IssuedAt, rec.ExpiresAt)
	return err
}

func (s *PostgresStore) GetCertificateBySerialWithKey(ctx context.Context, serialNumber string) (*pkistore.CertRecord, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id, serial_number, cert_type, org_id, subject_cn, cert_pem, encrypted_private_key, status, issued_at, expires_at
		 FROM certificates WHERE serial_number = $1`, serialNumber)

	var r pkistore.CertRecord
	err := row.Scan(&r.ID, &r.SerialNumber, &r.CertType, &r.OrgID, &r.SubjectCN, &r.CertPEM,
		&r.EncryptedPrivateKey, &r.Status, &r.IssuedAt, &r.ExpiresAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *PostgresStore) GetOrgCA(ctx context.Context, orgID string) (*pkistore.CertRecord, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id, serial_number, cert_type, org_id, subject_cn, cert_pem, status, issued_at, expires_at
		 FROM certificates
		 WHERE org_id = $1 AND cert_type = 'org_intermediate_ca' AND status = 'active'
		 ORDER BY created_at DESC LIMIT 1`, orgID)

	var r pkistore.CertRecord
	err := row.Scan(&r.ID, &r.SerialNumber, &r.CertType, &r.OrgID, &r.SubjectCN, &r.CertPEM, &r.Status, &r.IssuedAt, &r.ExpiresAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *PostgresStore) UpdateCertificateStatus(ctx context.Context, serialNumber, status string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE certificates SET status = $1 WHERE serial_number = $2`,
		status, serialNumber)
	return err
}

func (s *PostgresStore) InsertCRLEntry(ctx context.Context, entry *pkistore.CRLEntryRecord) error {
	id := uuid.New().String()
	_, err := s.pool.Exec(ctx,
		`INSERT INTO crl_entries (id, cert_serial, issuer_serial, revoked_at, reason, crl_number, is_delta)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		id, entry.CertSerial, entry.IssuerSerial, entry.RevokedAt, entry.Reason, entry.CRLNumber, entry.IsDelta)
	return err
}

func (s *PostgresStore) GetCRLEntries(ctx context.Context, issuerSerial string) ([]pkistore.CRLEntryRecord, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT cert_serial, issuer_serial, revoked_at, reason, crl_number, is_delta
		 FROM crl_entries WHERE issuer_serial = $1 ORDER BY revoked_at`, issuerSerial)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []pkistore.CRLEntryRecord
	for rows.Next() {
		var e pkistore.CRLEntryRecord
		if err := rows.Scan(&e.CertSerial, &e.IssuerSerial, &e.RevokedAt, &e.Reason, &e.CRLNumber, &e.IsDelta); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

func (s *PostgresStore) GetNextCRLNumber(ctx context.Context, issuerSerial string) (int64, error) {
	var maxNum *int64
	err := s.pool.QueryRow(ctx,
		`SELECT MAX(crl_number) FROM crl_entries WHERE issuer_serial = $1`, issuerSerial).Scan(&maxNum)
	if err != nil {
		return 1, nil
	}
	if maxNum == nil {
		return 1, nil
	}
	return *maxNum + 1, nil
}

func (s *PostgresStore) GetCertRevocationEntry(ctx context.Context, serialNumber string) (*pkistore.CRLEntryRecord, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT cert_serial, issuer_serial, revoked_at, reason, crl_number, is_delta
		 FROM crl_entries WHERE cert_serial = $1 LIMIT 1`, serialNumber)

	var e pkistore.CRLEntryRecord
	err := row.Scan(&e.CertSerial, &e.IssuerSerial, &e.RevokedAt, &e.Reason, &e.CRLNumber, &e.IsDelta)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// --- VaultStore interface implementation ---

// WriteVaultEntry inserts a new version of a vault entry.
func (s *PostgresStore) WriteVaultEntry(ctx context.Context, entry *VaultEntry) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO vault_entries (org_id, scope_id, entry_type, key, env_type_id, encrypted_value, key_version_id, version, created_by)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		entry.OrgID, entry.ScopeID, entry.EntryType, entry.Key, entry.EnvTypeID,
		entry.EncryptedValue, entry.KeyVersionID, entry.Version, entry.CreatedBy)
	return err
}

// GetLatestVaultEntry returns the latest non-deleted, non-destroyed version of a vault entry.
func (s *PostgresStore) GetLatestVaultEntry(ctx context.Context, orgID, scopeID, entryType, key string, envTypeID *string) (*VaultEntry, error) {
	var row pgx.Row
	if envTypeID != nil {
		row = s.pool.QueryRow(ctx,
			`SELECT id, org_id, scope_id, entry_type, key, env_type_id, encrypted_value, key_version_id, version, created_at, deleted_at, destroyed, created_by
			 FROM vault_entries
			 WHERE org_id = $1 AND scope_id = $2 AND entry_type = $3 AND key = $4 AND env_type_id = $5
			   AND destroyed = FALSE AND deleted_at IS NULL
			 ORDER BY version DESC LIMIT 1`,
			orgID, scopeID, entryType, key, *envTypeID)
	} else {
		row = s.pool.QueryRow(ctx,
			`SELECT id, org_id, scope_id, entry_type, key, env_type_id, encrypted_value, key_version_id, version, created_at, deleted_at, destroyed, created_by
			 FROM vault_entries
			 WHERE org_id = $1 AND scope_id = $2 AND entry_type = $3 AND key = $4 AND env_type_id IS NULL
			   AND destroyed = FALSE AND deleted_at IS NULL
			 ORDER BY version DESC LIMIT 1`,
			orgID, scopeID, entryType, key)
	}

	var e VaultEntry
	err := row.Scan(&e.ID, &e.OrgID, &e.ScopeID, &e.EntryType, &e.Key, &e.EnvTypeID,
		&e.EncryptedValue, &e.KeyVersionID, &e.Version, &e.CreatedAt, &e.DeletedAt, &e.Destroyed, &e.CreatedBy)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// GetVaultEntryVersion returns a specific version of a vault entry.
func (s *PostgresStore) GetVaultEntryVersion(ctx context.Context, orgID, scopeID, entryType, key string, envTypeID *string, version int) (*VaultEntry, error) {
	var row pgx.Row
	if envTypeID != nil {
		row = s.pool.QueryRow(ctx,
			`SELECT id, org_id, scope_id, entry_type, key, env_type_id, encrypted_value, key_version_id, version, created_at, deleted_at, destroyed, created_by
			 FROM vault_entries
			 WHERE org_id = $1 AND scope_id = $2 AND entry_type = $3 AND key = $4 AND env_type_id = $5 AND version = $6
			   AND destroyed = FALSE`,
			orgID, scopeID, entryType, key, *envTypeID, version)
	} else {
		row = s.pool.QueryRow(ctx,
			`SELECT id, org_id, scope_id, entry_type, key, env_type_id, encrypted_value, key_version_id, version, created_at, deleted_at, destroyed, created_by
			 FROM vault_entries
			 WHERE org_id = $1 AND scope_id = $2 AND entry_type = $3 AND key = $4 AND env_type_id IS NULL AND version = $5
			   AND destroyed = FALSE`,
			orgID, scopeID, entryType, key, version)
	}

	var e VaultEntry
	err := row.Scan(&e.ID, &e.OrgID, &e.ScopeID, &e.EntryType, &e.Key, &e.EnvTypeID,
		&e.EncryptedValue, &e.KeyVersionID, &e.Version, &e.CreatedAt, &e.DeletedAt, &e.Destroyed, &e.CreatedBy)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// GetNextVaultVersion returns the next version number for a vault entry.
func (s *PostgresStore) GetNextVaultVersion(ctx context.Context, orgID, scopeID, entryType, key string, envTypeID *string) (int, error) {
	var maxVersion *int
	var err error
	if envTypeID != nil {
		err = s.pool.QueryRow(ctx,
			`SELECT MAX(version) FROM vault_entries
			 WHERE org_id = $1 AND scope_id = $2 AND entry_type = $3 AND key = $4 AND env_type_id = $5`,
			orgID, scopeID, entryType, key, *envTypeID).Scan(&maxVersion)
	} else {
		err = s.pool.QueryRow(ctx,
			`SELECT MAX(version) FROM vault_entries
			 WHERE org_id = $1 AND scope_id = $2 AND entry_type = $3 AND key = $4 AND env_type_id IS NULL`,
			orgID, scopeID, entryType, key).Scan(&maxVersion)
	}
	if err != nil {
		return 1, nil
	}
	if maxVersion == nil {
		return 1, nil
	}
	return *maxVersion + 1, nil
}

// SoftDeleteVaultEntry marks a vault entry as deleted (recoverable).
func (s *PostgresStore) SoftDeleteVaultEntry(ctx context.Context, orgID, scopeID, entryType, key string, envTypeID *string) error {
	var err error
	if envTypeID != nil {
		_, err = s.pool.Exec(ctx,
			`UPDATE vault_entries SET deleted_at = NOW()
			 WHERE org_id = $1 AND scope_id = $2 AND entry_type = $3 AND key = $4 AND env_type_id = $5
			   AND destroyed = FALSE AND deleted_at IS NULL`,
			orgID, scopeID, entryType, key, *envTypeID)
	} else {
		_, err = s.pool.Exec(ctx,
			`UPDATE vault_entries SET deleted_at = NOW()
			 WHERE org_id = $1 AND scope_id = $2 AND entry_type = $3 AND key = $4 AND env_type_id IS NULL
			   AND destroyed = FALSE AND deleted_at IS NULL`,
			orgID, scopeID, entryType, key)
	}
	return err
}

// DestroyVaultEntry permanently deletes vault entry versions.
// If version is 0, destroys all versions.
func (s *PostgresStore) DestroyVaultEntry(ctx context.Context, orgID, scopeID, entryType, key string, envTypeID *string, version int) (int, error) {
	var result int64
	var err error

	if version == 0 {
		// Destroy all versions
		if envTypeID != nil {
			tag, e := s.pool.Exec(ctx,
				`UPDATE vault_entries SET destroyed = TRUE, encrypted_value = '\x00'
				 WHERE org_id = $1 AND scope_id = $2 AND entry_type = $3 AND key = $4 AND env_type_id = $5
				   AND destroyed = FALSE`,
				orgID, scopeID, entryType, key, *envTypeID)
			result = tag.RowsAffected()
			err = e
		} else {
			tag, e := s.pool.Exec(ctx,
				`UPDATE vault_entries SET destroyed = TRUE, encrypted_value = '\x00'
				 WHERE org_id = $1 AND scope_id = $2 AND entry_type = $3 AND key = $4 AND env_type_id IS NULL
				   AND destroyed = FALSE`,
				orgID, scopeID, entryType, key)
			result = tag.RowsAffected()
			err = e
		}
	} else {
		// Destroy specific version
		if envTypeID != nil {
			tag, e := s.pool.Exec(ctx,
				`UPDATE vault_entries SET destroyed = TRUE, encrypted_value = '\x00'
				 WHERE org_id = $1 AND scope_id = $2 AND entry_type = $3 AND key = $4 AND env_type_id = $5 AND version = $6
				   AND destroyed = FALSE`,
				orgID, scopeID, entryType, key, *envTypeID, version)
			result = tag.RowsAffected()
			err = e
		} else {
			tag, e := s.pool.Exec(ctx,
				`UPDATE vault_entries SET destroyed = TRUE, encrypted_value = '\x00'
				 WHERE org_id = $1 AND scope_id = $2 AND entry_type = $3 AND key = $4 AND env_type_id IS NULL AND version = $5
				   AND destroyed = FALSE`,
				orgID, scopeID, entryType, key, version)
			result = tag.RowsAffected()
			err = e
		}
	}

	if err != nil {
		return 0, err
	}
	return int(result), nil
}

// ListVaultEntries returns all active keys within a scope.
func (s *PostgresStore) ListVaultEntries(ctx context.Context, orgID, scopeID, entryType string, envTypeID *string) ([]VaultListItem, error) {
	var rows pgx.Rows
	var err error
	if envTypeID != nil {
		rows, err = s.pool.Query(ctx,
			`SELECT key, MAX(version) as latest_version, MIN(created_at) as created_at, MAX(created_at) as updated_at
			 FROM vault_entries
			 WHERE org_id = $1 AND scope_id = $2 AND entry_type = $3 AND env_type_id = $4
			   AND destroyed = FALSE AND deleted_at IS NULL
			 GROUP BY key
			 ORDER BY key`,
			orgID, scopeID, entryType, *envTypeID)
	} else {
		rows, err = s.pool.Query(ctx,
			`SELECT key, MAX(version) as latest_version, MIN(created_at) as created_at, MAX(created_at) as updated_at
			 FROM vault_entries
			 WHERE org_id = $1 AND scope_id = $2 AND entry_type = $3 AND env_type_id IS NULL
			   AND destroyed = FALSE AND deleted_at IS NULL
			 GROUP BY key
			 ORDER BY key`,
			orgID, scopeID, entryType)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []VaultListItem
	for rows.Next() {
		var item VaultListItem
		if err := rows.Scan(&item.Key, &item.LatestVersion, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// GetVaultEntryHistory returns all versions of a vault entry (for history).
func (s *PostgresStore) GetVaultEntryHistory(ctx context.Context, orgID, scopeID, entryType, key string, envTypeID *string) ([]*VaultEntry, error) {
	var rows pgx.Rows
	var err error
	if envTypeID != nil {
		rows, err = s.pool.Query(ctx,
			`SELECT id, org_id, scope_id, entry_type, key, env_type_id, key_version_id, version, created_at, deleted_at, destroyed, created_by
			 FROM vault_entries
			 WHERE org_id = $1 AND scope_id = $2 AND entry_type = $3 AND key = $4 AND env_type_id = $5
			 ORDER BY version DESC`,
			orgID, scopeID, entryType, key, *envTypeID)
	} else {
		rows, err = s.pool.Query(ctx,
			`SELECT id, org_id, scope_id, entry_type, key, env_type_id, key_version_id, version, created_at, deleted_at, destroyed, created_by
			 FROM vault_entries
			 WHERE org_id = $1 AND scope_id = $2 AND entry_type = $3 AND key = $4 AND env_type_id IS NULL
			 ORDER BY version DESC`,
			orgID, scopeID, entryType, key)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []*VaultEntry
	for rows.Next() {
		var e VaultEntry
		if err := rows.Scan(&e.ID, &e.OrgID, &e.ScopeID, &e.EntryType, &e.Key, &e.EnvTypeID,
			&e.KeyVersionID, &e.Version, &e.CreatedAt, &e.DeletedAt, &e.Destroyed, &e.CreatedBy); err != nil {
			return nil, err
		}
		entries = append(entries, &e)
	}
	return entries, rows.Err()
}

// --- OrgCAWrapStore interface implementation ---

func (s *PostgresStore) StoreOrgCAWrap(ctx context.Context, record *keys.OrgCAWrapRecord) error {
	record.ID = uuid.New().String()
	_, err := s.pool.Exec(ctx,
		`INSERT INTO org_ca_wraps (id, org_id, member_id, cert_serial, ephemeral_pub, wrapped_key, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		record.ID, record.OrgID, record.MemberID, record.CertSerial,
		record.EphemeralPub, record.WrappedKey, record.CreatedAt)
	return err
}

func (s *PostgresStore) GetOrgCAWrap(ctx context.Context, orgID, memberID string) (*keys.OrgCAWrapRecord, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id, org_id, member_id, cert_serial, ephemeral_pub, wrapped_key, created_at, revoked_at
		 FROM org_ca_wraps
		 WHERE org_id = $1 AND member_id = $2 AND revoked_at IS NULL
		 LIMIT 1`, orgID, memberID)

	var r keys.OrgCAWrapRecord
	err := row.Scan(&r.ID, &r.OrgID, &r.MemberID, &r.CertSerial,
		&r.EphemeralPub, &r.WrappedKey, &r.CreatedAt, &r.RevokedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *PostgresStore) GetOrgCAWraps(ctx context.Context, orgID string) ([]*keys.OrgCAWrapRecord, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, org_id, member_id, cert_serial, ephemeral_pub, wrapped_key, created_at, revoked_at
		 FROM org_ca_wraps
		 WHERE org_id = $1 AND revoked_at IS NULL`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []*keys.OrgCAWrapRecord
	for rows.Next() {
		var r keys.OrgCAWrapRecord
		if err := rows.Scan(&r.ID, &r.OrgID, &r.MemberID, &r.CertSerial,
			&r.EphemeralPub, &r.WrappedKey, &r.CreatedAt, &r.RevokedAt); err != nil {
			return nil, err
		}
		records = append(records, &r)
	}
	return records, rows.Err()
}

func (s *PostgresStore) RevokeOrgCAWrap(ctx context.Context, orgID, memberID string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE org_ca_wraps SET revoked_at = NOW()
		 WHERE org_id = $1 AND member_id = $2 AND revoked_at IS NULL`,
		orgID, memberID)
	return err
}

// --- OrgSecurityPolicy interface implementation ---

func (s *PostgresStore) GetOrgSecurityPolicy(ctx context.Context, orgID string) (*OrgSecurityPolicy, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT org_id, require_byok, session_duration_sec, max_session_tokens, require_mfa_for_admin, shamir_threshold, shamir_total_shares
		 FROM org_security_policy WHERE org_id = $1`, orgID)

	var p OrgSecurityPolicy
	err := row.Scan(&p.OrgID, &p.RequireBYOK, &p.SessionDurationSec, &p.MaxSessionTokens,
		&p.RequireMFAForAdmin, &p.ShamirThreshold, &p.ShamirTotalShares)
	if err == pgx.ErrNoRows {
		// Return defaults
		return &OrgSecurityPolicy{
			OrgID:              orgID,
			RequireBYOK:        false,
			SessionDurationSec: 28800,
			MaxSessionTokens:   10,
			RequireMFAForAdmin: true,
			ShamirThreshold:    3,
			ShamirTotalShares:  5,
		}, nil
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (s *PostgresStore) UpsertOrgSecurityPolicy(ctx context.Context, policy *OrgSecurityPolicy) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO org_security_policy (org_id, require_byok, session_duration_sec, max_session_tokens, require_mfa_for_admin, shamir_threshold, shamir_total_shares, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
		 ON CONFLICT (org_id) DO UPDATE SET
		   require_byok = EXCLUDED.require_byok,
		   session_duration_sec = EXCLUDED.session_duration_sec,
		   max_session_tokens = EXCLUDED.max_session_tokens,
		   require_mfa_for_admin = EXCLUDED.require_mfa_for_admin,
		   shamir_threshold = EXCLUDED.shamir_threshold,
		   shamir_total_shares = EXCLUDED.shamir_total_shares,
		   updated_at = NOW()`,
		policy.OrgID, policy.RequireBYOK, policy.SessionDurationSec, policy.MaxSessionTokens,
		policy.RequireMFAForAdmin, policy.ShamirThreshold, policy.ShamirTotalShares)
	return err
}

// --- Extended TokenRegistry for session tokens ---

// GetTokensBySubject returns all active tokens for a given subject hash.
func (s *PostgresStore) GetTokensBySubject(ctx context.Context, subjectHash string) ([]*auth.TokenEntry, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT jti, subject_hash, jwt_hash, issued_at, expires_at, revoked
		 FROM token_registry
		 WHERE subject_hash = $1 AND expires_at > NOW()
		 ORDER BY issued_at DESC`, subjectHash)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []*auth.TokenEntry
	for rows.Next() {
		var e auth.TokenEntry
		if err := rows.Scan(&e.JTI, &e.SubjectHash, &e.JWTHash, &e.IssuedAt, &e.ExpiresAt, &e.Revoked); err != nil {
			return nil, err
		}
		entries = append(entries, &e)
	}
	return entries, rows.Err()
}

// RevokeTokensBySubject revokes all active tokens for a given subject hash.
func (s *PostgresStore) RevokeTokensBySubject(ctx context.Context, subjectHash string) (int, error) {
	tag, err := s.pool.Exec(ctx,
		`UPDATE token_registry SET revoked = TRUE
		 WHERE subject_hash = $1 AND revoked = FALSE AND expires_at > NOW()`,
		subjectHash)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}
