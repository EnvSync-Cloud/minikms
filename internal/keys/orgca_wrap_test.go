package keys

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/envsync-cloud/minikms/internal/crypto"
)

// testOrgCAWrapStore is a minimal in-memory OrgCAWrapStore for unit tests.
type testOrgCAWrapStore struct {
	mu    sync.RWMutex
	wraps map[string]*OrgCAWrapRecord
}

func newTestOrgCAWrapStore() *testOrgCAWrapStore {
	return &testOrgCAWrapStore{wraps: make(map[string]*OrgCAWrapRecord)}
}

func (s *testOrgCAWrapStore) StoreOrgCAWrap(_ context.Context, rec *OrgCAWrapRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := rec.OrgID + ":" + rec.MemberID
	if rec.ID == "" {
		rec.ID = fmt.Sprintf("wrap-%d", len(s.wraps)+1)
	}
	cp := *rec
	s.wraps[key] = &cp
	return nil
}

func (s *testOrgCAWrapStore) GetOrgCAWrap(_ context.Context, orgID, memberID string) (*OrgCAWrapRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.wraps[orgID+":"+memberID]
	if !ok {
		return nil, nil
	}
	cp := *rec
	return &cp, nil
}

func (s *testOrgCAWrapStore) GetOrgCAWraps(_ context.Context, orgID string) ([]*OrgCAWrapRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*OrgCAWrapRecord
	for k, v := range s.wraps {
		if len(k) > len(orgID) && k[:len(orgID)+1] == orgID+":" {
			cp := *v
			result = append(result, &cp)
		}
	}
	return result, nil
}

func (s *testOrgCAWrapStore) RevokeOrgCAWrap(_ context.Context, orgID, memberID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := orgID + ":" + memberID
	rec, ok := s.wraps[key]
	if !ok {
		return fmt.Errorf("wrap not found")
	}
	now := time.Now()
	rec.RevokedAt = &now
	return nil
}

func generateTestKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return key
}

func TestWrapUnwrapOrgCA_Roundtrip(t *testing.T) {
	store := newTestOrgCAWrapStore()
	mgr := NewOrgCAWrapManager(store)
	ctx := context.Background()

	orgID := "org-001"
	memberID := "member-001"
	certSerial := "abc123"

	// Generate Org CA key (P-384) and member key (P-384)
	orgCAKey := generateTestKey(t, elliptic.P384())
	memberKey := generateTestKey(t, elliptic.P384())

	// Wrap
	err := mgr.WrapOrgCAForMember(ctx, orgID, memberID, certSerial, &memberKey.PublicKey, orgCAKey)
	if err != nil {
		t.Fatalf("WrapOrgCAForMember: %v", err)
	}

	// Verify stored
	rec, err := store.GetOrgCAWrap(ctx, orgID, memberID)
	if err != nil {
		t.Fatalf("GetOrgCAWrap: %v", err)
	}
	if rec == nil {
		t.Fatal("wrap record not stored")
	}
	if rec.CertSerial != certSerial {
		t.Errorf("CertSerial = %q, want %q", rec.CertSerial, certSerial)
	}

	// Unwrap
	recoveredKey, err := mgr.UnwrapOrgCA(ctx, orgID, memberID, memberKey)
	if err != nil {
		t.Fatalf("UnwrapOrgCA: %v", err)
	}

	// Verify keys match
	origBytes := crypto.MarshalECPrivateKey(orgCAKey)
	recoveredBytes := crypto.MarshalECPrivateKey(recoveredKey)
	if len(origBytes) != len(recoveredBytes) {
		t.Fatalf("key length mismatch: %d vs %d", len(origBytes), len(recoveredBytes))
	}
	for i := range origBytes {
		if origBytes[i] != recoveredBytes[i] {
			t.Fatalf("key bytes differ at index %d", i)
		}
	}
}

func TestWrapUnwrapOrgCA_P256(t *testing.T) {
	store := newTestOrgCAWrapStore()
	mgr := NewOrgCAWrapManager(store)
	ctx := context.Background()

	orgCAKey := generateTestKey(t, elliptic.P384())
	memberKey := generateTestKey(t, elliptic.P256())

	err := mgr.WrapOrgCAForMember(ctx, "org-1", "mem-1", "serial-1", &memberKey.PublicKey, orgCAKey)
	if err != nil {
		t.Fatalf("WrapOrgCAForMember: %v", err)
	}

	recovered, err := mgr.UnwrapOrgCA(ctx, "org-1", "mem-1", memberKey)
	if err != nil {
		t.Fatalf("UnwrapOrgCA: %v", err)
	}

	if recovered.D.Cmp(orgCAKey.D) != 0 {
		t.Error("recovered key D does not match original")
	}
}

func TestRewrapOrgCAForNewMember(t *testing.T) {
	store := newTestOrgCAWrapStore()
	mgr := NewOrgCAWrapManager(store)
	ctx := context.Background()

	orgID := "org-002"
	orgCAKey := generateTestKey(t, elliptic.P384())
	existingMemberKey := generateTestKey(t, elliptic.P384())
	newMemberKey := generateTestKey(t, elliptic.P384())

	// Wrap for existing member
	err := mgr.WrapOrgCAForMember(ctx, orgID, "existing", "serial-e", &existingMemberKey.PublicKey, orgCAKey)
	if err != nil {
		t.Fatalf("WrapOrgCAForMember: %v", err)
	}

	// Rewrap for new member
	err = mgr.RewrapOrgCAForNewMember(ctx, orgID, "existing", existingMemberKey, "new-member", "serial-n", &newMemberKey.PublicKey)
	if err != nil {
		t.Fatalf("RewrapOrgCAForNewMember: %v", err)
	}

	// New member should be able to unwrap
	recovered, err := mgr.UnwrapOrgCA(ctx, orgID, "new-member", newMemberKey)
	if err != nil {
		t.Fatalf("UnwrapOrgCA for new member: %v", err)
	}

	if recovered.D.Cmp(orgCAKey.D) != 0 {
		t.Error("new member recovered key does not match original Org CA key")
	}
}

func TestUnwrapOrgCA_NotFound(t *testing.T) {
	store := newTestOrgCAWrapStore()
	mgr := NewOrgCAWrapManager(store)
	ctx := context.Background()

	memberKey := generateTestKey(t, elliptic.P384())

	_, err := mgr.UnwrapOrgCA(ctx, "org-x", "member-x", memberKey)
	if err == nil {
		t.Fatal("expected error for missing wrap record")
	}
}

func TestUnwrapOrgCA_Revoked(t *testing.T) {
	store := newTestOrgCAWrapStore()
	mgr := NewOrgCAWrapManager(store)
	ctx := context.Background()

	orgCAKey := generateTestKey(t, elliptic.P384())
	memberKey := generateTestKey(t, elliptic.P384())

	err := mgr.WrapOrgCAForMember(ctx, "org-r", "mem-r", "serial-r", &memberKey.PublicKey, orgCAKey)
	if err != nil {
		t.Fatalf("WrapOrgCAForMember: %v", err)
	}

	// Revoke
	err = store.RevokeOrgCAWrap(ctx, "org-r", "mem-r")
	if err != nil {
		t.Fatalf("RevokeOrgCAWrap: %v", err)
	}

	_, err = mgr.UnwrapOrgCA(ctx, "org-r", "mem-r", memberKey)
	if err == nil {
		t.Fatal("expected error for revoked wrap")
	}
}

func TestGetWrapData(t *testing.T) {
	store := newTestOrgCAWrapStore()
	mgr := NewOrgCAWrapManager(store)
	ctx := context.Background()

	orgCAKey := generateTestKey(t, elliptic.P384())
	memberKey := generateTestKey(t, elliptic.P384())

	err := mgr.WrapOrgCAForMember(ctx, "org-w", "mem-w", "serial-w", &memberKey.PublicKey, orgCAKey)
	if err != nil {
		t.Fatalf("WrapOrgCAForMember: %v", err)
	}

	ephPub, wrappedKey, err := mgr.GetWrapData(ctx, "org-w", "mem-w")
	if err != nil {
		t.Fatalf("GetWrapData: %v", err)
	}
	if len(ephPub) == 0 {
		t.Error("ephemeralPub is empty")
	}
	if len(wrappedKey) == 0 {
		t.Error("wrappedKey is empty")
	}
}

func TestGetWrapData_NotFound(t *testing.T) {
	store := newTestOrgCAWrapStore()
	mgr := NewOrgCAWrapManager(store)
	ctx := context.Background()

	_, _, err := mgr.GetWrapData(ctx, "org-x", "mem-x")
	if err == nil {
		t.Fatal("expected error for missing wrap")
	}
}

func TestGetWrapData_Revoked(t *testing.T) {
	store := newTestOrgCAWrapStore()
	mgr := NewOrgCAWrapManager(store)
	ctx := context.Background()

	orgCAKey := generateTestKey(t, elliptic.P384())
	memberKey := generateTestKey(t, elliptic.P384())

	err := mgr.WrapOrgCAForMember(ctx, "org-rv", "mem-rv", "serial-rv", &memberKey.PublicKey, orgCAKey)
	if err != nil {
		t.Fatalf("WrapOrgCAForMember: %v", err)
	}
	_ = store.RevokeOrgCAWrap(ctx, "org-rv", "mem-rv")

	_, _, err = mgr.GetWrapData(ctx, "org-rv", "mem-rv")
	if err == nil {
		t.Fatal("expected error for revoked wrap")
	}
}

func TestWrapOrgCA_ConcurrentMembers(t *testing.T) {
	store := newTestOrgCAWrapStore()
	mgr := NewOrgCAWrapManager(store)
	ctx := context.Background()

	orgCAKey := generateTestKey(t, elliptic.P384())

	const numMembers = 5
	errs := make(chan error, numMembers)

	for i := range numMembers {
		go func(idx int) {
			memberKey := generateTestKey(t, elliptic.P384())
			memberID := fmt.Sprintf("member-%03d", idx)
			certSerial := fmt.Sprintf("serial-%03d", idx)
			err := mgr.WrapOrgCAForMember(ctx, "org-concurrent", memberID, certSerial, &memberKey.PublicKey, orgCAKey)
			errs <- err
		}(i)
	}

	for range numMembers {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent WrapOrgCAForMember: %v", err)
		}
	}

	// Verify all wraps are stored
	wraps, err := store.GetOrgCAWraps(ctx, "org-concurrent")
	if err != nil {
		t.Fatalf("GetOrgCAWraps: %v", err)
	}
	if len(wraps) != numMembers {
		t.Errorf("expected %d wraps, got %d", numMembers, len(wraps))
	}
}

func TestRewrapOrgCA_PreviousRevoked(t *testing.T) {
	store := newTestOrgCAWrapStore()
	mgr := NewOrgCAWrapManager(store)
	ctx := context.Background()

	orgID := "org-rewrap"
	orgCAKey := generateTestKey(t, elliptic.P384())
	member1Key := generateTestKey(t, elliptic.P384())
	member2Key := generateTestKey(t, elliptic.P384())

	// Wrap for member 1
	err := mgr.WrapOrgCAForMember(ctx, orgID, "member-1", "serial-1", &member1Key.PublicKey, orgCAKey)
	if err != nil {
		t.Fatalf("WrapOrgCAForMember: %v", err)
	}

	// Wrap for member 2 (first time)
	err = mgr.WrapOrgCAForMember(ctx, orgID, "member-2", "serial-2a", &member2Key.PublicKey, orgCAKey)
	if err != nil {
		t.Fatalf("WrapOrgCAForMember (member-2 first): %v", err)
	}

	// Revoke member 2's wrap
	err = store.RevokeOrgCAWrap(ctx, orgID, "member-2")
	if err != nil {
		t.Fatalf("RevokeOrgCAWrap: %v", err)
	}

	// Verify member 2's wrap is revoked
	wrap, _ := store.GetOrgCAWrap(ctx, orgID, "member-2")
	if wrap == nil || wrap.RevokedAt == nil {
		t.Fatal("member-2 wrap should be revoked")
	}

	// Rewrap for member 2 with new key (overwrites the revoked wrap)
	newMember2Key := generateTestKey(t, elliptic.P384())
	err = mgr.WrapOrgCAForMember(ctx, orgID, "member-2", "serial-2b", &newMember2Key.PublicKey, orgCAKey)
	if err != nil {
		t.Fatalf("WrapOrgCAForMember (member-2 rewrap): %v", err)
	}

	// New member 2 should be able to unwrap
	recovered, err := mgr.UnwrapOrgCA(ctx, orgID, "member-2", newMember2Key)
	if err != nil {
		t.Fatalf("UnwrapOrgCA (member-2 rewrap): %v", err)
	}
	if recovered.D.Cmp(orgCAKey.D) != 0 {
		t.Error("rewrapped key does not match original")
	}
}

func TestParseMemberCertPublicKey(t *testing.T) {
	// Generate a self-signed cert for testing
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))

	pub, err := ParseMemberCertPublicKey(certPEM)
	if err != nil {
		t.Fatalf("ParseMemberCertPublicKey: %v", err)
	}
	if pub.X.Cmp(key.PublicKey.X) != 0 || pub.Y.Cmp(key.PublicKey.Y) != 0 {
		t.Error("parsed public key does not match original")
	}
}

func TestParseMemberCertPublicKey_InvalidPEM(t *testing.T) {
	_, err := ParseMemberCertPublicKey("not-a-pem")
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestParseMemberCertPublicKey_InvalidCert(t *testing.T) {
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("invalid")}))
	_, err := ParseMemberCertPublicKey(certPEM)
	if err == nil {
		t.Fatal("expected error for invalid cert")
	}
}
