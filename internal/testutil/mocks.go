package testutil

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/envsync-cloud/minikms/internal/audit"
	"github.com/envsync-cloud/minikms/internal/auth"
	"github.com/envsync-cloud/minikms/internal/crypto"
	"github.com/envsync-cloud/minikms/internal/escrow"
	"github.com/envsync-cloud/minikms/internal/keys"
	"github.com/envsync-cloud/minikms/internal/pkistore"
	"github.com/envsync-cloud/minikms/internal/store"
)

// MockDEKStore is an in-memory implementation of keys.DEKStore for testing.
type MockDEKStore struct {
	mu      sync.RWMutex
	records map[string]*keys.KeyVersionRecord // keyed by "orgID:appID"
	byID    map[string]*keys.KeyVersionRecord // keyed by ID
}

func NewMockDEKStore() *MockDEKStore {
	return &MockDEKStore{
		records: make(map[string]*keys.KeyVersionRecord),
		byID:    make(map[string]*keys.KeyVersionRecord),
	}
}

func (m *MockDEKStore) GetActiveKeyVersion(_ context.Context, orgID, appID string) (*keys.KeyVersionRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	key := orgID + ":" + appID
	rec, ok := m.records[key]
	if !ok {
		return nil, nil
	}
	// Return a copy
	cp := *rec
	cpKey := make([]byte, len(rec.EncryptedKey))
	copy(cpKey, rec.EncryptedKey)
	cp.EncryptedKey = cpKey
	return &cp, nil
}

func (m *MockDEKStore) GetKeyVersion(_ context.Context, orgID, appID, keyVersionID string) (*keys.KeyVersionRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rec, ok := m.byID[keyVersionID]
	if !ok || rec.OrgID != orgID || rec.AppID != appID || rec.KeyType != "app_dek" {
		return nil, nil
	}
	cp := *rec
	cpKey := make([]byte, len(rec.EncryptedKey))
	copy(cpKey, rec.EncryptedKey)
	cp.EncryptedKey = cpKey
	return &cp, nil
}

func (m *MockDEKStore) CreateKeyVersion(_ context.Context, record *keys.KeyVersionRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if record.ID == "" {
		record.ID = fmt.Sprintf("kv-%d", len(m.byID)+1)
	}
	key := record.OrgID + ":" + record.AppID
	// Enforce unique active constraint (simulates idx_key_versions_active)
	if existing, ok := m.records[key]; ok && existing.Status == string(crypto.KeyStatusActive) && record.Status == string(crypto.KeyStatusActive) {
		return fmt.Errorf("duplicate key value violates unique constraint \"idx_key_versions_active\"")
	}
	// Store a copy
	cp := *record
	cpKey := make([]byte, len(record.EncryptedKey))
	copy(cpKey, record.EncryptedKey)
	cp.EncryptedKey = cpKey
	m.records[key] = &cp
	m.byID[record.ID] = m.records[key]
	return nil
}

func (m *MockDEKStore) IncrementEncryptionCount(_ context.Context, keyVersionID string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.byID[keyVersionID]
	if !ok {
		return 0, fmt.Errorf("key version not found: %s", keyVersionID)
	}
	rec.EncryptionCount++
	return rec.EncryptionCount, nil
}

func (m *MockDEKStore) UpdateKeyStatus(_ context.Context, keyVersionID string, status string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.byID[keyVersionID]
	if !ok {
		return fmt.Errorf("key version not found: %s", keyVersionID)
	}
	rec.Status = status
	// If retiring, remove from active records
	if status == string(crypto.KeyStatusRetired) {
		key := rec.OrgID + ":" + rec.AppID
		if active, ok := m.records[key]; ok && active.ID == keyVersionID {
			delete(m.records, key)
		}
	}
	return nil
}

// GetByID returns a record by its ID (test helper, not part of DEKStore interface).
func (m *MockDEKStore) GetByID(id string) *keys.KeyVersionRecord {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rec, ok := m.byID[id]
	if !ok {
		return nil
	}
	cp := *rec
	return &cp
}

// SetCount sets the encryption count for a key version (test helper).
func (m *MockDEKStore) SetCount(id string, count int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if rec, ok := m.byID[id]; ok {
		rec.EncryptionCount = count
	}
}

// MockAuditStore is an in-memory implementation of audit.AuditStore for testing.
type MockAuditStore struct {
	mu      sync.RWMutex
	entries map[string][]*audit.AuditEntry // keyed by orgID
}

func NewMockAuditStore() *MockAuditStore {
	return &MockAuditStore{
		entries: make(map[string][]*audit.AuditEntry),
	}
}

func (m *MockAuditStore) GetLatestEntryHash(_ context.Context, orgID string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	entries := m.entries[orgID]
	if len(entries) == 0 {
		return audit.GenesisHash, nil
	}
	return entries[len(entries)-1].EntryHash, nil
}

func (m *MockAuditStore) InsertEntry(_ context.Context, entry *audit.AuditEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if entry.ID == "" {
		entry.ID = fmt.Sprintf("ae-%d", len(m.entries[entry.OrgID])+1)
	}
	m.entries[entry.OrgID] = append(m.entries[entry.OrgID], entry)
	return nil
}

func (m *MockAuditStore) GetEntries(_ context.Context, orgID string, limit, offset int) ([]*audit.AuditEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	all := m.entries[orgID]
	if offset >= len(all) {
		return nil, nil
	}
	end := offset + limit
	if end > len(all) {
		end = len(all)
	}
	// Return in reverse chronological order (newest first)
	result := make([]*audit.AuditEntry, end-offset)
	for i := 0; i < len(result); i++ {
		result[i] = all[len(all)-1-offset-i]
	}
	return result, nil
}

func (m *MockAuditStore) VerifyChain(_ context.Context, orgID string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	entries := m.entries[orgID]
	if len(entries) == 0 {
		return true, nil
	}
	// Entries are stored chronologically; GetEntries returns reverse order
	// VerifyChainIntegrity expects newest-first, so reverse
	reversed := make([]*audit.AuditEntry, len(entries))
	for i, e := range entries {
		reversed[len(entries)-1-i] = e
	}
	valid, _ := audit.VerifyChainIntegrity(reversed)
	return valid, nil
}

// EntriesForOrg returns copies of the audit entries in chronological order.
func (m *MockAuditStore) EntriesForOrg(orgID string) []*audit.AuditEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	entries := m.entries[orgID]
	result := make([]*audit.AuditEntry, len(entries))
	for i, entry := range entries {
		copyEntry := *entry
		result[i] = &copyEntry
	}
	return result
}

// MockEscrowStore is an in-memory implementation of escrow.Store.
type MockEscrowStore struct {
	mu       sync.RWMutex
	sets     map[string]*escrow.Set
	shares   map[string][]*escrow.Share
	activeID map[string]string
}

func NewMockEscrowStore() *MockEscrowStore {
	return &MockEscrowStore{
		sets:     make(map[string]*escrow.Set),
		shares:   make(map[string][]*escrow.Share),
		activeID: make(map[string]string),
	}
}

func (m *MockEscrowStore) GetActiveEscrowSet(_ context.Context, orgID, keyType string) (*escrow.Set, []*escrow.Share, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	id := m.activeID[orgID+":"+keyType]
	if id == "" {
		return nil, nil, nil
	}
	return cloneEscrowSet(m.sets[id]), cloneEscrowShares(m.shares[id]), nil
}

func (m *MockEscrowStore) ReplaceEscrowSet(_ context.Context, set *escrow.Set, shares []*escrow.Share, recoveredSetID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := set.OrgID + ":" + set.KeyType
	currentID := m.activeID[key]
	if recoveredSetID != "" && currentID != recoveredSetID {
		return fmt.Errorf("active recovered escrow set changed during recovery")
	}
	if currentID != "" {
		current := m.sets[currentID]
		current.Status = "retired"
		if recoveredSetID != "" {
			now := time.Now().UTC()
			current.RecoveredAt = &now
		}
	}
	setCopy := cloneEscrowSet(set)
	m.sets[set.ID] = setCopy
	m.shares[set.ID] = cloneEscrowShares(shares)
	m.activeID[key] = set.ID
	return nil
}

func (m *MockEscrowStore) MarkEscrowShareExported(_ context.Context, setID string, shareIndex int, exportedAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, share := range m.shares[setID] {
		if share.ShareIndex == shareIndex {
			timestamp := exportedAt
			share.ExportedAt = &timestamp
			return nil
		}
	}
	return fmt.Errorf("escrow share not found")
}

// EscrowSetByID returns a copy of any generation for assertions.
func (m *MockEscrowStore) EscrowSetByID(id string) *escrow.Set {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return cloneEscrowSet(m.sets[id])
}

// EscrowSharesBySet returns copies of a generation's encrypted shares.
func (m *MockEscrowStore) EscrowSharesBySet(id string) []*escrow.Share {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return cloneEscrowShares(m.shares[id])
}

func cloneEscrowSet(set *escrow.Set) *escrow.Set {
	if set == nil {
		return nil
	}
	copySet := *set
	copySet.SecretHash = append([]byte(nil), set.SecretHash...)
	if set.RecoveredAt != nil {
		timestamp := *set.RecoveredAt
		copySet.RecoveredAt = &timestamp
	}
	return &copySet
}

func cloneEscrowShares(shares []*escrow.Share) []*escrow.Share {
	result := make([]*escrow.Share, len(shares))
	for i, share := range shares {
		copyShare := *share
		copyShare.EncryptedShare = append([]byte(nil), share.EncryptedShare...)
		copyShare.ShareHash = append([]byte(nil), share.ShareHash...)
		if share.ExportedAt != nil {
			timestamp := *share.ExportedAt
			copyShare.ExportedAt = &timestamp
		}
		result[i] = &copyShare
	}
	return result
}

// MockTokenRegistry is an in-memory implementation of auth.TokenRegistry for testing.
type MockTokenRegistry struct {
	mu     sync.RWMutex
	tokens map[string]*auth.TokenEntry // keyed by JTI
}

func NewMockTokenRegistry() *MockTokenRegistry {
	return &MockTokenRegistry{
		tokens: make(map[string]*auth.TokenEntry),
	}
}

func (m *MockTokenRegistry) StoreToken(_ context.Context, entry *auth.TokenEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *entry
	m.tokens[entry.JTI] = &cp
	return nil
}

func (m *MockTokenRegistry) GetToken(_ context.Context, jti string) (*auth.TokenEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	entry, ok := m.tokens[jti]
	if !ok {
		return nil, nil
	}
	cp := *entry
	return &cp, nil
}

func (m *MockTokenRegistry) RevokeToken(_ context.Context, jti string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.tokens[jti]
	if !ok {
		return fmt.Errorf("token not found: %s", jti)
	}
	entry.Revoked = true
	return nil
}

func (m *MockTokenRegistry) CleanupExpired(_ context.Context) error {
	return nil
}

// SetupTestKMSStack wires up a full KMS stack with in-memory mocks for testing.
// rootKeyHex must be a valid 64-char hex string (32 bytes).
func SetupTestKMSStack(rootKeyHex string) (
	*keys.RootKeyHolder,
	*keys.OrgKeyManager,
	*keys.AppDEKManager,
	*MockDEKStore,
	*audit.AuditLogger,
	*MockAuditStore,
	error,
) {
	holder := keys.NewRootKeyHolder()
	if err := holder.Load(rootKeyHex); err != nil {
		return nil, nil, nil, nil, nil, nil, fmt.Errorf("failed to load root key: %w", err)
	}

	orgKeyMgr := keys.NewOrgKeyManager(holder)
	dekStore := NewMockDEKStore()
	dekMgr := keys.NewAppDEKManager(orgKeyMgr, dekStore, 1000) // low max for testing

	auditStore := NewMockAuditStore()
	auditLogger := audit.NewAuditLogger(auditStore)

	return holder, orgKeyMgr, dekMgr, dekStore, auditLogger, auditStore, nil
}

// MockPKICertStore is an in-memory implementation of pkistore.Store for testing.
type MockPKICertStore struct {
	mu    sync.RWMutex
	certs map[string]*CertRecord // keyed by serial
	orgCA map[string]*CertRecord // keyed by orgID
	crls  map[string][]CRLEntryRecord
}

// CertRecord mirrors pkistore.CertRecord to avoid circular imports.
type CertRecord = pkistore.CertRecord

// CRLEntryRecord mirrors pkistore.CRLEntryRecord.
type CRLEntryRecord = pkistore.CRLEntryRecord

func NewMockPKICertStore() *MockPKICertStore {
	return &MockPKICertStore{
		certs: make(map[string]*CertRecord),
		orgCA: make(map[string]*CertRecord),
		crls:  make(map[string][]CRLEntryRecord),
	}
}

func (m *MockPKICertStore) StoreCertificate(_ context.Context, rec *CertRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *rec
	m.certs[rec.SerialNumber] = &cp
	if rec.CertType == "org_intermediate_ca" {
		m.orgCA[rec.OrgID] = &cp
	}
	return nil
}

func (m *MockPKICertStore) StoreCertificateWithKey(_ context.Context, rec *CertRecord) error {
	return m.StoreCertificate(context.Background(), rec)
}

func (m *MockPKICertStore) GetCertificateBySerial(_ context.Context, serial string) (*CertRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rec, ok := m.certs[serial]
	if !ok {
		return nil, nil
	}
	cp := *rec
	return &cp, nil
}

func (m *MockPKICertStore) GetCertificateBySerialWithKey(_ context.Context, serial string) (*CertRecord, error) {
	return m.GetCertificateBySerial(context.Background(), serial)
}

func (m *MockPKICertStore) GetOrgCA(_ context.Context, orgID string) (*CertRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rec, ok := m.orgCA[orgID]
	if !ok {
		return nil, nil
	}
	cp := *rec
	return &cp, nil
}

func (m *MockPKICertStore) UpdateCertificateStatus(_ context.Context, serial, status string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.certs[serial]
	if !ok {
		return fmt.Errorf("cert not found: %s", serial)
	}
	rec.Status = status
	return nil
}

func (m *MockPKICertStore) InsertCRLEntry(_ context.Context, entry *CRLEntryRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.crls[entry.IssuerSerial] = append(m.crls[entry.IssuerSerial], *entry)
	return nil
}

func (m *MockPKICertStore) GetCRLEntries(_ context.Context, issuerSerial string) ([]CRLEntryRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.crls[issuerSerial], nil
}

func (m *MockPKICertStore) GetNextCRLNumber(_ context.Context, _ string) (int64, error) {
	return 1, nil
}

func (m *MockPKICertStore) GetCertRevocationEntry(_ context.Context, serial string) (*CRLEntryRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, entries := range m.crls {
		for _, e := range entries {
			if e.CertSerial == serial {
				cp := e
				return &cp, nil
			}
		}
	}
	return nil, nil
}

// MockOrgCAWrapStore is an in-memory implementation of keys.OrgCAWrapStore for testing.
type MockOrgCAWrapStore struct {
	mu    sync.RWMutex
	wraps map[string]*keys.OrgCAWrapRecord // keyed by "orgID:memberID"
}

func NewMockOrgCAWrapStore() *MockOrgCAWrapStore {
	return &MockOrgCAWrapStore{
		wraps: make(map[string]*keys.OrgCAWrapRecord),
	}
}

func (m *MockOrgCAWrapStore) StoreOrgCAWrap(_ context.Context, record *keys.OrgCAWrapRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := record.OrgID + ":" + record.MemberID
	if record.ID == "" {
		record.ID = fmt.Sprintf("wrap-%d", len(m.wraps)+1)
	}
	cp := *record
	m.wraps[key] = &cp
	return nil
}

func (m *MockOrgCAWrapStore) GetOrgCAWrap(_ context.Context, orgID, memberID string) (*keys.OrgCAWrapRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	key := orgID + ":" + memberID
	rec, ok := m.wraps[key]
	if !ok {
		return nil, nil
	}
	cp := *rec
	return &cp, nil
}

func (m *MockOrgCAWrapStore) GetOrgCAWraps(_ context.Context, orgID string) ([]*keys.OrgCAWrapRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []*keys.OrgCAWrapRecord
	for k, v := range m.wraps {
		if len(k) > len(orgID) && k[:len(orgID)+1] == orgID+":" {
			cp := *v
			result = append(result, &cp)
		}
	}
	return result, nil
}

func (m *MockOrgCAWrapStore) RevokeOrgCAWrap(_ context.Context, orgID, memberID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := orgID + ":" + memberID
	rec, ok := m.wraps[key]
	if !ok {
		return fmt.Errorf("wrap not found: %s", key)
	}
	now := time.Now()
	rec.RevokedAt = &now
	return nil
}

// MockPolicyStore provides the methods SessionService needs from store.PostgresStore.
type MockPolicyStore struct {
	mu       sync.RWMutex
	policies map[string]*OrgSecurityPolicy
	tokens   map[string][]*auth.TokenEntry // keyed by subjectHash
}

// OrgSecurityPolicy mirrors store.OrgSecurityPolicy to avoid circular imports.
type OrgSecurityPolicy = store.OrgSecurityPolicy

func NewMockPolicyStore() *MockPolicyStore {
	return &MockPolicyStore{
		policies: make(map[string]*OrgSecurityPolicy),
		tokens:   make(map[string][]*auth.TokenEntry),
	}
}

func (m *MockPolicyStore) GetOrgSecurityPolicy(_ context.Context, orgID string) (*OrgSecurityPolicy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.policies[orgID]
	if !ok {
		return &OrgSecurityPolicy{
			OrgID:              orgID,
			SessionDurationSec: 28800,
			MaxSessionTokens:   10,
		}, nil
	}
	cp := *p
	return &cp, nil
}

func (m *MockPolicyStore) GetTokensBySubject(_ context.Context, subjectHash string) ([]*auth.TokenEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	entries := m.tokens[subjectHash]
	result := make([]*auth.TokenEntry, len(entries))
	for i, e := range entries {
		cp := *e
		result[i] = &cp
	}
	return result, nil
}

func (m *MockPolicyStore) RevokeTokensBySubject(_ context.Context, subjectHash string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	count := 0
	for _, e := range m.tokens[subjectHash] {
		if !e.Revoked {
			e.Revoked = true
			count++
		}
	}
	return count, nil
}

// TestRootKeyHex is a fixed 256-bit key for deterministic testing.
const TestRootKeyHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// TestRootKeyBytes returns the decoded bytes of TestRootKeyHex.
func TestRootKeyBytes() []byte {
	b, _ := hex.DecodeString(TestRootKeyHex)
	return b
}
