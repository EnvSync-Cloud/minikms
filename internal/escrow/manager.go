package escrow

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/envsync-cloud/minikms/internal/audit"
	"github.com/envsync-cloud/minikms/internal/crypto"
)

const (
	// KeyTypeRoot identifies the symmetric root key used by the KMS hierarchy.
	KeyTypeRoot = "root"
	// KeyTypeOrgCA identifies an organization intermediate CA private key.
	KeyTypeOrgCA = "org_ca"
	// RootScope is the audit and storage scope used for root-key escrow.
	RootScope = "_root"

	packageVersion = 1
	sealKeySize    = 32
)

// Set describes one generation of escrow shares for a key.
type Set struct {
	ID          string
	OrgID       string
	KeyType     string
	TotalShares int
	Threshold   int
	SecretHash  []byte
	Status      string
	CreatedAt   time.Time
	RecoveredAt *time.Time
}

// Share is an encrypted-at-rest share belonging to an escrow set.
type Share struct {
	ID             string
	SetID          string
	ShareIndex     int
	EncryptedShare []byte
	ShareHash      []byte
	CustodianID    string
	CreatedAt      time.Time
	ExportedAt     *time.Time
}

// Store persists escrow generations and their encrypted shares.
type Store interface {
	GetActiveEscrowSet(ctx context.Context, orgID, keyType string) (*Set, []*Share, error)
	ReplaceEscrowSet(ctx context.Context, set *Set, shares []*Share, recoveredSetID string) error
	MarkEscrowShareExported(ctx context.Context, setID string, shareIndex int, exportedAt time.Time) error
}

// SharePackage is the portable file handed to one custodian. Share contains
// sensitive plaintext share material; callers must only write it to a 0600 file.
type SharePackage struct {
	Version     int    `json:"version"`
	SetID       string `json:"set_id"`
	OrgID       string `json:"org_id"`
	KeyType     string `json:"key_type"`
	CustodianID string `json:"custodian_id"`
	ShareIndex  int    `json:"share_index"`
	TotalShares int    `json:"total_shares"`
	Threshold   int    `json:"threshold"`
	Share       []byte `json:"share"`
}

// Manager coordinates share creation, protected storage, export, recovery, and
// re-sealing. The seal key must be independent from every key being escrowed.
type Manager struct {
	store       Store
	auditLogger *audit.AuditLogger
	sealKey     []byte
}

// NewManager creates an escrow manager using a dedicated AES-256 seal key.
func NewManager(store Store, auditLogger *audit.AuditLogger, sealKey []byte) (*Manager, error) {
	if store == nil {
		return nil, fmt.Errorf("escrow store is required")
	}
	if auditLogger == nil {
		return nil, fmt.Errorf("audit logger is required")
	}
	if len(sealKey) != sealKeySize {
		return nil, fmt.Errorf("escrow seal key must be %d bytes", sealKeySize)
	}

	keyCopy := append([]byte(nil), sealKey...)
	return &Manager{store: store, auditLogger: auditLogger, sealKey: keyCopy}, nil
}

// LoadSealKey loads a 32-byte hex seal key from exactly one configured source.
func LoadSealKey(value, path string) ([]byte, error) {
	if value == "" && path == "" {
		return nil, fmt.Errorf("escrow seal key is not configured")
	}
	if value != "" && path != "" {
		return nil, fmt.Errorf("configure only one escrow seal key source")
	}

	keyHex := strings.TrimSpace(value)
	if path != "" {
		info, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("stat escrow seal key file: %w", err)
		}
		if info.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("escrow seal key file permissions must be 0600 or stricter")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read escrow seal key file: %w", err)
		}
		keyHex = strings.TrimSpace(string(data))
		crypto.ZeroizeBytes(data)
	}

	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("escrow seal key must be hex encoded: %w", err)
	}
	if len(key) != sealKeySize {
		crypto.ZeroizeBytes(key)
		return nil, fmt.Errorf("escrow seal key must be %d bytes", sealKeySize)
	}
	return key, nil
}

// ParseCustodians validates a comma-separated, ordered custodian list.
func ParseCustodians(value string, totalShares int) ([]string, error) {
	parts := strings.Split(value, ",")
	custodians := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		id := strings.TrimSpace(part)
		if id == "" {
			return nil, fmt.Errorf("custodian IDs must not be empty")
		}
		if _, ok := seen[id]; ok {
			return nil, fmt.Errorf("duplicate custodian ID %q", id)
		}
		seen[id] = struct{}{}
		custodians = append(custodians, id)
	}
	if len(custodians) != totalShares {
		return nil, fmt.Errorf("configured %d custodians, expected %d", len(custodians), totalShares)
	}
	return custodians, nil
}

// EnsureSplit creates the first active share set for a key. It is idempotent so
// process restarts do not silently invalidate shares already held by custodians.
func (m *Manager) EnsureSplit(ctx context.Context, orgID, keyType string, secret []byte, custodians []string, threshold int, actorID string) (*Set, bool, error) {
	if err := validateSplit(orgID, keyType, secret, custodians, threshold, actorID); err != nil {
		m.logFailure(ctx, auditScope(orgID, keyType), "escrow_split_failed", actorID, "invalid escrow split request")
		return nil, false, err
	}
	existing, records, err := m.store.GetActiveEscrowSet(ctx, orgID, keyType)
	if err != nil {
		m.logFailure(ctx, auditScope(orgID, keyType), "escrow_split_failed", actorID, "share lookup failed")
		return nil, false, fmt.Errorf("load active escrow set: %w", err)
	}
	if existing != nil {
		if !hashMatches(secret, existing.SecretHash) {
			m.logFailure(ctx, auditScope(orgID, keyType), "escrow_split_failed", actorID, "active set key mismatch")
			return nil, false, fmt.Errorf("active escrow set protects a different key")
		}
		if existing.Threshold != threshold || existing.TotalShares != len(custodians) {
			m.logFailure(ctx, auditScope(orgID, keyType), "escrow_split_failed", actorID, "active set policy mismatch")
			return nil, false, fmt.Errorf("active escrow policy is %d-of-%d; explicit rotation is required to change it",
				existing.Threshold, existing.TotalShares)
		}
		if !sameCustodians(records, custodians) {
			m.logFailure(ctx, auditScope(orgID, keyType), "escrow_split_failed", actorID, "active set custodian mismatch")
			return nil, false, fmt.Errorf("active escrow custodians differ; explicit rotation is required to change them")
		}
		if err := m.auditLogger.Log(ctx, auditScope(orgID, keyType), "escrow_set_verified", actorID,
			fmt.Sprintf("set_id=%s key_type=%s total=%d threshold=%d", existing.ID, keyType, existing.TotalShares, existing.Threshold), ""); err != nil {
			return nil, false, fmt.Errorf("audit escrow set verification: %w", err)
		}
		return existing, false, nil
	}

	set, err := m.split(ctx, orgID, keyType, secret, custodians, threshold, actorID, "")
	return set, err == nil, err
}

// Split rotates a key to a new share generation without reconstructing it.
func (m *Manager) Split(ctx context.Context, orgID, keyType string, secret []byte, custodians []string, threshold int, actorID string) (*Set, error) {
	return m.split(ctx, orgID, keyType, secret, custodians, threshold, actorID, "")
}

func (m *Manager) split(ctx context.Context, orgID, keyType string, secret []byte, custodians []string, threshold int, actorID, recoveredSetID string) (*Set, error) {
	if err := validateSplit(orgID, keyType, secret, custodians, threshold, actorID); err != nil {
		m.logFailure(ctx, auditScope(orgID, keyType), "escrow_split_failed", actorID, "invalid escrow split request")
		return nil, err
	}

	details := fmt.Sprintf("key_type=%s total=%d threshold=%d", keyType, len(custodians), threshold)
	if err := m.auditLogger.Log(ctx, auditScope(orgID, keyType), "escrow_split_started", actorID, details, ""); err != nil {
		return nil, fmt.Errorf("audit escrow split: %w", err)
	}

	set, records, err := m.buildSet(orgID, keyType, secret, custodians, threshold)
	if err != nil {
		m.logFailure(ctx, auditScope(orgID, keyType), "escrow_split_failed", actorID, "share generation failed")
		return nil, err
	}
	defer zeroizeShareRecords(records)

	if err := m.store.ReplaceEscrowSet(ctx, set, records, recoveredSetID); err != nil {
		m.logFailure(ctx, auditScope(orgID, keyType), "escrow_split_failed", actorID, "share persistence failed")
		return nil, fmt.Errorf("store escrow set: %w", err)
	}
	if err := m.auditLogger.Log(ctx, auditScope(orgID, keyType), "escrow_split_succeeded", actorID,
		fmt.Sprintf("set_id=%s %s", set.ID, details), ""); err != nil {
		return nil, fmt.Errorf("audit completed escrow split: %w", err)
	}
	return set, nil
}

func (m *Manager) buildSet(orgID, keyType string, secret []byte, custodians []string, threshold int) (*Set, []*Share, error) {
	rawShares, err := crypto.SplitKey(secret, len(custodians), threshold)
	if err != nil {
		return nil, nil, fmt.Errorf("split escrow key: %w", err)
	}
	defer func() {
		for _, share := range rawShares {
			crypto.ZeroizeBytes(share)
		}
	}()

	now := time.Now().UTC()
	secretHash := sha256.Sum256(secret)
	set := &Set{
		ID:          uuid.NewString(),
		OrgID:       orgID,
		KeyType:     keyType,
		TotalShares: len(custodians),
		Threshold:   threshold,
		SecretHash:  append([]byte(nil), secretHash[:]...),
		Status:      "active",
		CreatedAt:   now,
	}

	records := make([]*Share, len(rawShares))
	for i, rawShare := range rawShares {
		shareHash := sha256.Sum256(rawShare)
		aad := shareAAD(set.ID, orgID, keyType, i+1, custodians[i])
		encrypted, err := crypto.Encrypt(m.sealKey, rawShare, aad)
		if err != nil {
			zeroizeShareRecords(records)
			return nil, nil, fmt.Errorf("encrypt escrow share %d: %w", i+1, err)
		}
		records[i] = &Share{
			ID:             uuid.NewString(),
			SetID:          set.ID,
			ShareIndex:     i + 1,
			EncryptedShare: encrypted,
			ShareHash:      append([]byte(nil), shareHash[:]...),
			CustodianID:    custodians[i],
			CreatedAt:      now,
		}
	}
	return set, records, nil
}

// ExportShare returns one plaintext share package for secure delivery to its
// named custodian. The package is never written or logged by the manager.
func (m *Manager) ExportShare(ctx context.Context, orgID, keyType, custodianID, actorID string) ([]byte, error) {
	if actorID == "" || custodianID == "" {
		return nil, fmt.Errorf("actor ID and custodian ID are required")
	}
	scope := auditScope(orgID, keyType)
	if err := m.auditLogger.Log(ctx, scope, "escrow_share_export_started", actorID,
		fmt.Sprintf("key_type=%s custodian_id=%s", keyType, custodianID), ""); err != nil {
		return nil, fmt.Errorf("audit escrow export: %w", err)
	}

	set, records, err := m.store.GetActiveEscrowSet(ctx, orgID, keyType)
	if err != nil {
		m.logFailure(ctx, scope, "escrow_share_export_failed", actorID, "share lookup failed")
		return nil, fmt.Errorf("load active escrow set: %w", err)
	}
	if set == nil {
		m.logFailure(ctx, scope, "escrow_share_export_failed", actorID, "active share set not found")
		return nil, fmt.Errorf("active escrow set not found")
	}

	var record *Share
	for _, candidate := range records {
		if candidate.CustodianID == custodianID {
			record = candidate
			break
		}
	}
	if record == nil {
		m.logFailure(ctx, scope, "escrow_share_export_failed", actorID, "custodian not found")
		return nil, fmt.Errorf("custodian %q does not own a share in the active set", custodianID)
	}

	rawShare, err := crypto.Decrypt(m.sealKey, record.EncryptedShare,
		shareAAD(set.ID, orgID, keyType, record.ShareIndex, record.CustodianID))
	if err != nil {
		m.logFailure(ctx, scope, "escrow_share_export_failed", actorID, "share decryption failed")
		return nil, fmt.Errorf("decrypt escrow share: %w", err)
	}
	defer crypto.ZeroizeBytes(rawShare)
	if !hashMatches(rawShare, record.ShareHash) {
		m.logFailure(ctx, scope, "escrow_share_export_failed", actorID, "share integrity check failed")
		return nil, fmt.Errorf("escrow share integrity check failed")
	}

	encoded, err := json.Marshal(&SharePackage{
		Version:     packageVersion,
		SetID:       set.ID,
		OrgID:       orgID,
		KeyType:     keyType,
		CustodianID: record.CustodianID,
		ShareIndex:  record.ShareIndex,
		TotalShares: set.TotalShares,
		Threshold:   set.Threshold,
		Share:       rawShare,
	})
	if err != nil {
		return nil, fmt.Errorf("encode escrow share package: %w", err)
	}

	exportedAt := time.Now().UTC()
	if err := m.store.MarkEscrowShareExported(ctx, set.ID, record.ShareIndex, exportedAt); err != nil {
		crypto.ZeroizeBytes(encoded)
		m.logFailure(ctx, scope, "escrow_share_export_failed", actorID, "export marker failed")
		return nil, fmt.Errorf("mark escrow share exported: %w", err)
	}
	if err := m.auditLogger.Log(ctx, scope, "escrow_share_export_succeeded", actorID,
		fmt.Sprintf("set_id=%s share_index=%d custodian_id=%s", set.ID, record.ShareIndex, custodianID), ""); err != nil {
		crypto.ZeroizeBytes(encoded)
		return nil, fmt.Errorf("audit completed escrow export: %w", err)
	}
	return encoded, nil
}

// RecoverAndReseal validates a threshold of custodian packages, reconstructs
// the key, and immediately creates a fresh share generation. The returned key
// is internal sensitive material and must be zeroized by the caller.
func (m *Manager) RecoverAndReseal(ctx context.Context, orgID, keyType string, encodedPackages [][]byte, actorID string) ([]byte, *Set, error) {
	if actorID == "" {
		return nil, nil, fmt.Errorf("actor ID is required")
	}
	scope := auditScope(orgID, keyType)
	if err := m.auditLogger.Log(ctx, scope, "escrow_recovery_started", actorID,
		fmt.Sprintf("key_type=%s submitted_shares=%d", keyType, len(encodedPackages)), ""); err != nil {
		return nil, nil, fmt.Errorf("audit escrow recovery: %w", err)
	}

	set, records, err := m.store.GetActiveEscrowSet(ctx, orgID, keyType)
	if err != nil {
		return m.recoveryError(ctx, scope, actorID, "share lookup failed", fmt.Errorf("load active escrow set: %w", err))
	}
	if set == nil {
		return m.recoveryError(ctx, scope, actorID, "active share set not found", fmt.Errorf("active escrow set not found"))
	}
	if len(encodedPackages) < set.Threshold {
		return m.recoveryError(ctx, scope, actorID, "threshold not met",
			fmt.Errorf("need at least %d shares, got %d", set.Threshold, len(encodedPackages)))
	}

	recordByIndex := make(map[int]*Share, len(records))
	for _, record := range records {
		recordByIndex[record.ShareIndex] = record
	}

	rawShares := make([][]byte, 0, len(encodedPackages))
	defer func() {
		for _, share := range rawShares {
			crypto.ZeroizeBytes(share)
		}
	}()
	seenIndexes := make(map[int]struct{}, len(encodedPackages))
	seenCustodians := make(map[string]struct{}, len(encodedPackages))
	for _, encoded := range encodedPackages {
		var pkg SharePackage
		if err := json.Unmarshal(encoded, &pkg); err != nil {
			return m.recoveryError(ctx, scope, actorID, "malformed share package", fmt.Errorf("decode share package: %w", err))
		}
		if err := validatePackage(&pkg, set, orgID, keyType); err != nil {
			crypto.ZeroizeBytes(pkg.Share)
			return m.recoveryError(ctx, scope, actorID, "share metadata mismatch", err)
		}
		if _, duplicate := seenIndexes[pkg.ShareIndex]; duplicate {
			crypto.ZeroizeBytes(pkg.Share)
			return m.recoveryError(ctx, scope, actorID, "duplicate share", fmt.Errorf("duplicate share index %d", pkg.ShareIndex))
		}
		if _, duplicate := seenCustodians[pkg.CustodianID]; duplicate {
			crypto.ZeroizeBytes(pkg.Share)
			return m.recoveryError(ctx, scope, actorID, "duplicate custodian", fmt.Errorf("duplicate custodian %q", pkg.CustodianID))
		}
		record := recordByIndex[pkg.ShareIndex]
		if record == nil || record.CustodianID != pkg.CustodianID || !hashMatches(pkg.Share, record.ShareHash) {
			crypto.ZeroizeBytes(pkg.Share)
			return m.recoveryError(ctx, scope, actorID, "share integrity check failed", fmt.Errorf("share %d is not valid for the active set", pkg.ShareIndex))
		}
		seenIndexes[pkg.ShareIndex] = struct{}{}
		seenCustodians[pkg.CustodianID] = struct{}{}
		rawShares = append(rawShares, pkg.Share)
	}

	recovered, err := crypto.CombineShares(rawShares)
	if err != nil {
		return m.recoveryError(ctx, scope, actorID, "share combination failed", fmt.Errorf("combine escrow shares: %w", err))
	}
	if !hashMatches(recovered, set.SecretHash) {
		crypto.ZeroizeBytes(recovered)
		return m.recoveryError(ctx, scope, actorID, "recovered key integrity check failed", fmt.Errorf("recovered key failed integrity verification"))
	}

	custodians := make([]string, len(records))
	sort.Slice(records, func(i, j int) bool { return records[i].ShareIndex < records[j].ShareIndex })
	for i, record := range records {
		custodians[i] = record.CustodianID
	}
	newSet, newRecords, err := m.buildSet(orgID, keyType, recovered, custodians, set.Threshold)
	if err != nil {
		crypto.ZeroizeBytes(recovered)
		return m.recoveryError(ctx, scope, actorID, "re-seal generation failed", err)
	}
	defer zeroizeShareRecords(newRecords)
	if err := m.store.ReplaceEscrowSet(ctx, newSet, newRecords, set.ID); err != nil {
		crypto.ZeroizeBytes(recovered)
		return m.recoveryError(ctx, scope, actorID, "re-seal persistence failed", fmt.Errorf("store re-sealed escrow set: %w", err))
	}

	if err := m.auditLogger.Log(ctx, scope, "escrow_recovery_succeeded", actorID,
		fmt.Sprintf("recovered_set_id=%s shares_used=%d", set.ID, len(rawShares)), ""); err != nil {
		crypto.ZeroizeBytes(recovered)
		return nil, nil, fmt.Errorf("audit completed escrow recovery: %w", err)
	}
	if err := m.auditLogger.Log(ctx, scope, "escrow_resealed", actorID,
		fmt.Sprintf("previous_set_id=%s new_set_id=%s total=%d threshold=%d", set.ID, newSet.ID, newSet.TotalShares, newSet.Threshold), ""); err != nil {
		crypto.ZeroizeBytes(recovered)
		return nil, nil, fmt.Errorf("audit escrow re-seal: %w", err)
	}
	return recovered, newSet, nil
}

func (m *Manager) recoveryError(ctx context.Context, scope, actorID, reason string, err error) ([]byte, *Set, error) {
	m.logFailure(ctx, scope, "escrow_recovery_failed", actorID, reason)
	return nil, nil, err
}

func (m *Manager) logFailure(ctx context.Context, scope, action, actorID, details string) {
	_ = m.auditLogger.Log(ctx, scope, action, actorID, details, "")
}

func validateSplit(orgID, keyType string, secret []byte, custodians []string, threshold int, actorID string) error {
	if actorID == "" {
		return fmt.Errorf("actor ID is required")
	}
	if err := validateScope(orgID, keyType); err != nil {
		return err
	}
	if len(secret) == 0 {
		return fmt.Errorf("key must not be empty")
	}
	if threshold < 2 || threshold > len(custodians) {
		return fmt.Errorf("threshold must be between 2 and %d", len(custodians))
	}
	if len(custodians) > 255 {
		return fmt.Errorf("total shares must be at most 255")
	}
	seen := make(map[string]struct{}, len(custodians))
	for _, custodian := range custodians {
		if strings.TrimSpace(custodian) == "" {
			return fmt.Errorf("custodian IDs must not be empty")
		}
		if _, ok := seen[custodian]; ok {
			return fmt.Errorf("duplicate custodian ID %q", custodian)
		}
		seen[custodian] = struct{}{}
	}
	return nil
}

func validateScope(orgID, keyType string) error {
	switch keyType {
	case KeyTypeRoot:
		if orgID != RootScope {
			return fmt.Errorf("root escrow must use scope %q", RootScope)
		}
	case KeyTypeOrgCA:
		if orgID == "" || orgID == RootScope {
			return fmt.Errorf("org CA escrow requires an org ID")
		}
	default:
		return fmt.Errorf("unsupported escrow key type %q", keyType)
	}
	return nil
}

func validatePackage(pkg *SharePackage, set *Set, orgID, keyType string) error {
	if pkg.Version != packageVersion {
		return fmt.Errorf("unsupported share package version %d", pkg.Version)
	}
	if pkg.SetID != set.ID || pkg.OrgID != orgID || pkg.KeyType != keyType {
		return fmt.Errorf("share package belongs to a different escrow set")
	}
	if pkg.TotalShares != set.TotalShares || pkg.Threshold != set.Threshold {
		return fmt.Errorf("share package policy does not match the active escrow set")
	}
	if pkg.ShareIndex < 1 || pkg.ShareIndex > set.TotalShares || len(pkg.Share) < 2 || int(pkg.Share[0]) != pkg.ShareIndex {
		return fmt.Errorf("invalid share index")
	}
	if pkg.CustodianID == "" {
		return fmt.Errorf("share package has no custodian")
	}
	return nil
}

func shareAAD(setID, orgID, keyType string, index int, custodianID string) []byte {
	return []byte(fmt.Sprintf("envsync-escrow-v1\x00%s\x00%s\x00%s\x00%d\x00%s", setID, orgID, keyType, index, custodianID))
}

func auditScope(orgID, keyType string) string {
	if keyType == KeyTypeRoot {
		return RootScope
	}
	return orgID
}

func hashMatches(value, expected []byte) bool {
	actual := sha256.Sum256(value)
	return len(expected) == sha256.Size && subtle.ConstantTimeCompare(actual[:], expected) == 1
}

func zeroizeShareRecords(records []*Share) {
	for _, record := range records {
		if record != nil {
			crypto.ZeroizeBytes(record.EncryptedShare)
		}
	}
}

func sameCustodians(records []*Share, custodians []string) bool {
	if len(records) != len(custodians) {
		return false
	}
	byIndex := make(map[int]string, len(records))
	for _, record := range records {
		byIndex[record.ShareIndex] = record.CustodianID
	}
	for i, custodian := range custodians {
		if byIndex[i+1] != custodian {
			return false
		}
	}
	return true
}
