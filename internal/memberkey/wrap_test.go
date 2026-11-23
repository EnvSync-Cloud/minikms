package memberkey

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/envsync-cloud/minikms/internal/crypto"
	"github.com/envsync-cloud/minikms/internal/keys"
)

func TestParseMode(t *testing.T) {
	mode, err := ParseMode(nil, io.Discard)
	if err != nil || mode != ModeDryRun {
		t.Fatalf("default mode = %v err=%v", mode, err)
	}
	mode, err = ParseMode([]string{"--check"}, io.Discard)
	if err != nil || mode != ModeCheck {
		t.Fatalf("check mode = %v err=%v", mode, err)
	}
	mode, err = ParseMode([]string{"--confirm"}, io.Discard)
	if err != nil || mode != ModeConfirm {
		t.Fatalf("confirm mode = %v err=%v", mode, err)
	}
	if _, err := ParseMode([]string{"--check", "--confirm"}, io.Discard); err == nil {
		t.Fatal("accepted --check and --confirm together")
	}
	if _, err := ParseMode([]string{"extra"}, io.Discard); err == nil {
		t.Fatal("accepted an unexpected argument")
	}

	var stderr bytes.Buffer
	_, err = ParseMode([]string{"-h"}, &stderr)
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("help error = %v", err)
	}
	usage := stderr.String()
	for _, phrase := range []string{"expires_at", "active", "MINIKMS_DB_URL", "MINIKMS_ROOT_KEY", "MINIKMS_HKDF_SALT", "--check", "--confirm"} {
		if !strings.Contains(usage, phrase) {
			t.Fatalf("usage missing %q", phrase)
		}
	}
}

func TestRowActive(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	if !rowActive("active", now.Add(time.Second), now) {
		t.Fatal("active row expiring after the run time was not active")
	}
	if rowActive("active", now, now) {
		t.Fatal("active row expiring at the run time counted as active")
	}
	if rowActive("active", now.Add(-time.Second), now) {
		t.Fatal("active row expiring before the run time counted as active")
	}
	for _, status := range []string{"revoked", "expired", "pending", "disabled"} {
		if rowActive(status, now.Add(time.Hour), now) {
			t.Fatalf("status %s counted as active", status)
		}
	}
}

func TestMemberKeyBackfill_DryRunCounts(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	fx := newBackfillFixture(t, now)
	before := fx.store.snapshot()

	var stdout bytes.Buffer
	if err := Run(context.Background(), fx.store, fx.mgr, ModeDryRun, now, &stdout); err != nil {
		t.Fatalf("dry run: %v", err)
	}
	requireNoMaterial(t, "dry-run report", stdout.String(), fx.idents, fx.materials)
	if stdout.String() != `{"to_wrap":2,"to_wrap_active":1,"to_wrap_non_active":1,"already_wrapped":2,"already_wrapped_active":1,"already_wrapped_non_active":1,"empty":1,"skipped_non_member":2,"failed":0}`+"\n" {
		t.Fatalf("dry-run report = %s", stdout.String())
	}
	if fx.store.updateCalls != 0 {
		t.Fatalf("dry run updated %d rows", fx.store.updateCalls)
	}
	if !fx.store.sameBlobs(before) {
		t.Fatal("dry run changed stored key material")
	}

	stdout.Reset()
	if err := Run(context.Background(), fx.store, fx.mgr, ModeCheck, now, &stdout); err != nil {
		t.Fatalf("check: %v", err)
	}
	requireNoMaterial(t, "check report", stdout.String(), fx.idents, fx.materials)
	if stdout.String() != `{"raw_member":2,"wrapped_member":2,"empty_member":1,"skipped_non_member":2,"failed":0}`+"\n" {
		t.Fatalf("check report = %s", stdout.String())
	}
	if !fx.store.sameBlobs(before) {
		t.Fatal("check changed stored key material")
	}
}

func TestMemberKeyBackfill_ConfirmCheckAndRerun(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	fx := newBackfillFixture(t, now)
	before := fx.store.snapshot()

	var stdout bytes.Buffer
	if err := Run(context.Background(), fx.store, fx.mgr, ModeConfirm, now, &stdout); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	requireNoMaterial(t, "confirm report", stdout.String(), fx.idents, fx.materials)
	wantConfirm := `{"to_wrap":2,"to_wrap_active":1,"to_wrap_non_active":1,"already_wrapped":2,"already_wrapped_active":1,"already_wrapped_non_active":1,"empty":1,"skipped_non_member":2,"failed":0}` + "\n"
	if stdout.String() != wantConfirm {
		t.Fatalf("confirm report = %s", stdout.String())
	}
	if fx.store.updateCalls != 2 {
		t.Fatalf("confirm updates = %d, want 2", fx.store.updateCalls)
	}

	for _, id := range []string{"raw-active", "raw-revoked"} {
		if bytes.Equal(fx.store.blob(id), before[id]) {
			t.Fatalf("row %s was not wrapped", id)
		}
		opened, err := keys.OpenMemberPrivateKey(fx.mgr, fx.orgOf[id], fx.serialOf[id], fx.store.blob(id), false)
		if err != nil {
			t.Fatalf("open wrapped %s: %v", id, err)
		}
		if !opened.PublicKey.Equal(&fx.keys[id].PublicKey) {
			t.Fatalf("wrapped %s does not match the member key", id)
		}
	}
	for _, id := range []string{"wrapped-active", "wrapped-expired", "org-ca", "leaf", "empty-member"} {
		if !bytes.Equal(fx.store.blob(id), before[id]) {
			t.Fatalf("row %s changed", id)
		}
	}

	wrapped := fx.store.snapshot()
	fx.store.updateCalls = 0
	stdout.Reset()
	if err := Run(context.Background(), fx.store, fx.mgr, ModeConfirm, now, &stdout); err != nil {
		t.Fatalf("second confirm: %v", err)
	}
	wantRerun := `{"to_wrap":0,"to_wrap_active":0,"to_wrap_non_active":0,"already_wrapped":4,"already_wrapped_active":2,"already_wrapped_non_active":2,"empty":1,"skipped_non_member":2,"failed":0}` + "\n"
	if stdout.String() != wantRerun {
		t.Fatalf("second confirm report = %s", stdout.String())
	}
	if fx.store.updateCalls != 0 {
		t.Fatalf("second confirm updates = %d", fx.store.updateCalls)
	}
	if !fx.store.sameBlobs(wrapped) {
		t.Fatal("second confirm changed stored key material")
	}

	stdout.Reset()
	if err := Run(context.Background(), fx.store, fx.mgr, ModeCheck, now, &stdout); err != nil {
		t.Fatalf("check after confirm: %v", err)
	}
	if stdout.String() != `{"raw_member":0,"wrapped_member":4,"empty_member":1,"skipped_non_member":2,"failed":0}`+"\n" {
		t.Fatalf("check after confirm = %s", stdout.String())
	}

	fx.store.updateCalls = 0
	err := Run(context.Background(), fx.store, fx.mgr, ModeConfirm, now, failWriter{})
	if err == nil || !strings.Contains(err.Error(), "member key wrap committed but the report could not be written") {
		t.Fatalf("report failure = %v", err)
	}
	requireNoMaterial(t, "report failure", err.Error(), fx.idents, fx.materials)
	if !fx.store.sameBlobs(wrapped) {
		t.Fatal("report failure changed stored key material")
	}
}

func TestMemberKeyEnvelope_CatchesLegacyAndCorruptBlob(t *testing.T) {
	mgr := testBackfillManager(t)
	key := newECKey(t)
	raw := crypto.MarshalECPrivateKey(key)
	t.Cleanup(func() { crypto.ZeroizeBytes(raw) })

	kind, plain := keys.ClassifyMemberKeyMaterial(mustOrgKey(t, mgr, "org-alpha"), raw, "org-alpha", "legacy-serial")
	crypto.ZeroizeBytes(plain)
	if kind != keys.MemberKeyRaw {
		t.Fatalf("legacy encoding classified as %s", kind)
	}
	if _, err := keys.OpenMemberPrivateKey(mgr, "org-alpha", "legacy-serial", raw, false); !errors.Is(err, keys.ErrMemberKeyLegacyDisabled) {
		t.Fatalf("legacy read error = %v", err)
	} else {
		requireNoMaterial(t, "legacy read error", err.Error(), []string{"legacy-serial"}, [][]byte{raw})
	}

	corrupt := []byte{0xff, 0x00, 0x01}
	kind, _ = keys.ClassifyMemberKeyMaterial(mustOrgKey(t, mgr, "org-alpha"), corrupt, "org-alpha", "corrupt-serial")
	if kind != keys.MemberKeyFailed {
		t.Fatalf("corrupt blob classified as %s", kind)
	}
	if _, err := keys.OpenMemberPrivateKey(mgr, "org-alpha", "corrupt-serial", corrupt, true); !errors.Is(err, keys.ErrMemberKeyEnvelope) {
		t.Fatalf("corrupt open error = %v", err)
	} else {
		requireNoMaterial(t, "corrupt open error", err.Error(), []string{"corrupt-serial"}, [][]byte{corrupt, raw})
	}

	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	future := now.Add(24 * time.Hour)
	orgCA := []byte("org-ca-marker")
	store := newMemStore([]Row{
		{
			ID: "raw-member", SerialNumber: "serial-raw-member", CertType: "member",
			OrgID: "org-alpha", Status: "active", ExpiresAt: future, EncryptedPrivateKey: bytes.Clone(raw),
		},
		{
			ID: "corrupt-member", SerialNumber: "serial-corrupt-member", CertType: "member",
			OrgID: "org-alpha", Status: "active", ExpiresAt: future, EncryptedPrivateKey: bytes.Clone(corrupt),
		},
		{
			ID: "org-ca", SerialNumber: "serial-org-ca", CertType: "org_intermediate_ca",
			OrgID: "org-alpha", Status: "active", ExpiresAt: future, EncryptedPrivateKey: bytes.Clone(orgCA),
		},
	})
	before := store.snapshot()
	idents := []string{"serial-raw-member", "serial-corrupt-member", "serial-org-ca", "org-alpha", "raw-member", "corrupt-member"}
	materials := [][]byte{raw, corrupt, orgCA}

	var stdout bytes.Buffer
	if err := Run(context.Background(), store, mgr, ModeDryRun, now, &stdout); err != nil {
		t.Fatalf("dry run: %v", err)
	}
	requireNoMaterial(t, "dry-run report", stdout.String(), idents, materials)
	if stdout.String() != `{"to_wrap":1,"to_wrap_active":1,"to_wrap_non_active":0,"already_wrapped":0,"already_wrapped_active":0,"already_wrapped_non_active":0,"empty":0,"skipped_non_member":1,"failed":1}`+"\n" {
		t.Fatalf("dry-run report = %s", stdout.String())
	}
	if !store.sameBlobs(before) || store.updateCalls != 0 {
		t.Fatal("dry run changed rows")
	}

	stdout.Reset()
	err := Run(context.Background(), store, mgr, ModeConfirm, now, &stdout)
	if !errors.Is(err, ErrClassificationFailed) {
		t.Fatalf("confirm error = %v", err)
	}
	requireNoMaterial(t, "confirm error", err.Error(), idents, materials)
	if stdout.Len() != 0 {
		t.Fatal("failed confirm wrote a report")
	}
	if store.updateCalls != 0 || !store.sameBlobs(before) {
		t.Fatal("failed confirm changed stored key material")
	}

	stdout.Reset()
	if err := Run(context.Background(), store, mgr, ModeCheck, now, &stdout); err != nil {
		t.Fatalf("check: %v", err)
	}
	if stdout.String() != `{"raw_member":1,"wrapped_member":0,"empty_member":0,"skipped_non_member":1,"failed":1}`+"\n" {
		t.Fatalf("check report = %s", stdout.String())
	}

	t.Run("verify mismatch rolls back", func(t *testing.T) {
		orgKey, err := mgr.DeriveOrgKey("org-alpha")
		if err != nil {
			t.Fatal(err)
		}
		anchor, err := crypto.Encrypt(orgKey, raw, []byte(keys.MemberKeyAAD("org-alpha", "serial-anchor")))
		crypto.ZeroizeBytes(orgKey)
		if err != nil {
			t.Fatal(err)
		}
		onlyRaw := newMemStore([]Row{
			{
				ID: "anchor", SerialNumber: "serial-anchor", CertType: "member",
				OrgID: "org-alpha", Status: "active", ExpiresAt: future, EncryptedPrivateKey: anchor,
			},
			{
				ID: "raw-member", SerialNumber: "serial-raw-member", CertType: "member",
				OrgID: "org-alpha", Status: "active", ExpiresAt: future, EncryptedPrivateKey: bytes.Clone(raw),
			},
			{
				ID: "org-ca", SerialNumber: "serial-org-ca", CertType: "org_intermediate_ca",
				OrgID: "org-alpha", Status: "active", ExpiresAt: future, EncryptedPrivateKey: bytes.Clone(orgCA),
			},
		})
		base := onlyRaw.snapshot()
		flaky := &flipReadStore{memStore: onlyRaw}
		err = Run(context.Background(), flaky, mgr, ModeConfirm, now, io.Discard)
		if !errors.Is(err, ErrVerifyFailed) {
			t.Fatalf("verify error = %v", err)
		}
		requireNoMaterial(t, "verify error", err.Error(), idents, materials)
		if !onlyRaw.sameBlobs(base) {
			t.Fatal("verify failure committed wrapped rows")
		}
	})
}

type backfillFixture struct {
	store     *memStore
	mgr       *keys.OrgKeyManager
	keys      map[string]*ecdsa.PrivateKey
	orgOf     map[string]string
	serialOf  map[string]string
	idents    []string
	materials [][]byte
}

func newBackfillFixture(t *testing.T, now time.Time) *backfillFixture {
	t.Helper()
	mgr := testBackfillManager(t)
	future := now.Add(48 * time.Hour)
	past := now.Add(-time.Hour)

	type spec struct {
		id       string
		serial   string
		certType string
		orgID    string
		status   string
		expires  time.Time
		kind     string
	}
	specs := []spec{
		{id: "raw-active", serial: "serial-raw-active", certType: "member", orgID: "org-alpha", status: "active", expires: future, kind: "raw"},
		{id: "raw-revoked", serial: "serial-raw-revoked", certType: "member", orgID: "org-alpha", status: "revoked", expires: future, kind: "raw"},
		{id: "wrapped-active", serial: "serial-wrapped-active", certType: "member", orgID: "org-beta", status: "active", expires: future, kind: "wrapped"},
		{id: "wrapped-expired", serial: "serial-wrapped-expired", certType: "member", orgID: "org-beta", status: "active", expires: past, kind: "wrapped"},
		{id: "empty-member", serial: "serial-empty-member", certType: "member", orgID: "org-alpha", status: "active", expires: future, kind: "empty"},
		{id: "org-ca", serial: "serial-org-ca", certType: "org_intermediate_ca", orgID: "org-alpha", status: "active", expires: future, kind: "marker"},
		{id: "leaf", serial: "serial-leaf", certType: "leaf", orgID: "org-beta", status: "active", expires: future, kind: "marker"},
	}

	fx := &backfillFixture{
		mgr:      mgr,
		keys:     map[string]*ecdsa.PrivateKey{},
		orgOf:    map[string]string{},
		serialOf: map[string]string{},
	}
	rows := make([]Row, 0, len(specs))
	for _, spec := range specs {
		fx.orgOf[spec.id] = spec.orgID
		fx.serialOf[spec.id] = spec.serial
		fx.idents = append(fx.idents, spec.id, spec.serial, spec.orgID)
		row := Row{
			ID: spec.id, SerialNumber: spec.serial, CertType: spec.certType,
			OrgID: spec.orgID, Status: spec.status, ExpiresAt: spec.expires,
		}
		switch spec.kind {
		case "raw":
			key := newECKey(t)
			raw := crypto.MarshalECPrivateKey(key)
			fx.keys[spec.id] = key
			fx.materials = append(fx.materials, raw)
			row.EncryptedPrivateKey = raw
		case "wrapped":
			key := newECKey(t)
			fx.keys[spec.id] = key
			row.EncryptedPrivateKey = sealMember(t, mgr, spec.orgID, spec.serial, key)
			fx.materials = append(fx.materials, bytes.Clone(row.EncryptedPrivateKey))
		case "marker":
			row.EncryptedPrivateKey = []byte(spec.certType + "-marker")
			fx.materials = append(fx.materials, bytes.Clone(row.EncryptedPrivateKey))
		case "empty":
		default:
			t.Fatalf("unknown fixture kind %s", spec.kind)
		}
		rows = append(rows, row)
	}
	fx.store = newMemStore(rows)
	return fx
}

func testBackfillManager(t *testing.T) *keys.OrgKeyManager {
	t.Helper()
	holder := keys.NewRootKeyHolder()
	if err := holder.Load(testRootKeyHex); err != nil {
		t.Fatalf("load root key: %v", err)
	}
	return keys.NewOrgKeyManager(holder)
}

func mustOrgKey(t *testing.T, mgr *keys.OrgKeyManager, orgID string) []byte {
	t.Helper()
	orgKey, err := mgr.DeriveOrgKey(orgID)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	t.Cleanup(func() { crypto.ZeroizeBytes(orgKey) })
	return orgKey
}

func newECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func sealMember(t *testing.T, mgr *keys.OrgKeyManager, orgID, serial string, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	orgKey, err := mgr.DeriveOrgKey(orgID)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	defer crypto.ZeroizeBytes(orgKey)
	raw := crypto.MarshalECPrivateKey(key)
	defer crypto.ZeroizeBytes(raw)
	sealed, err := crypto.Encrypt(orgKey, raw, []byte(keys.MemberKeyAAD(orgID, serial)))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return sealed
}

func requireNoMaterial(t *testing.T, label, text string, idents []string, materials [][]byte) {
	t.Helper()
	for _, ident := range idents {
		if ident != "" && strings.Contains(text, ident) {
			t.Fatalf("%s included a row identifier", label)
		}
	}
	for _, material := range materials {
		if len(material) == 0 {
			continue
		}
		if strings.Contains(text, string(material)) || strings.Contains(text, hex.EncodeToString(material)) {
			t.Fatalf("%s included key material", label)
		}
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) {
	return 0, errors.New("report destination unavailable")
}

type memStore struct {
	mu          sync.Mutex
	rows        []Row
	updateCalls int
}

func newMemStore(rows []Row) *memStore {
	copied := make([]Row, len(rows))
	for i, row := range rows {
		copied[i] = row
		copied[i].EncryptedPrivateKey = bytes.Clone(row.EncryptedPrivateKey)
	}
	return &memStore{rows: copied}
}

func (s *memStore) Begin(_ context.Context, readOnly bool) (Tx, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := make([]Row, len(s.rows))
	for i, row := range s.rows {
		snap[i] = row
		snap[i].EncryptedPrivateKey = bytes.Clone(row.EncryptedPrivateKey)
	}
	return &memTx{store: s, rows: snap, readOnly: readOnly}, nil
}

func (s *memStore) snapshot() map[string][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string][]byte, len(s.rows))
	for _, row := range s.rows {
		out[row.ID] = bytes.Clone(row.EncryptedPrivateKey)
	}
	return out
}

func (s *memStore) blob(id string) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, row := range s.rows {
		if row.ID == id {
			return bytes.Clone(row.EncryptedPrivateKey)
		}
	}
	return nil
}

func (s *memStore) sameBlobs(before map[string][]byte) bool {
	after := s.snapshot()
	if len(after) != len(before) {
		return false
	}
	for id, blob := range before {
		if !bytes.Equal(after[id], blob) {
			return false
		}
	}
	return true
}

type memTx struct {
	store    *memStore
	rows     []Row
	readOnly bool
	done     bool
}

func (t *memTx) ListCertificates(context.Context) ([]Row, error) {
	out := make([]Row, len(t.rows))
	for i, row := range t.rows {
		out[i] = row
		out[i].EncryptedPrivateKey = bytes.Clone(row.EncryptedPrivateKey)
	}
	return out, nil
}

func (t *memTx) UpdateMemberKey(_ context.Context, id string, previous, wrapped []byte) error {
	if t.readOnly {
		return errors.New("read-only transaction")
	}
	for i, row := range t.rows {
		if row.ID != id {
			continue
		}
		if row.CertType != certTypeMember || !bytes.Equal(row.EncryptedPrivateKey, previous) {
			return errors.New("member key row was not updated")
		}
		t.rows[i].EncryptedPrivateKey = bytes.Clone(wrapped)
		t.store.mu.Lock()
		t.store.updateCalls++
		t.store.mu.Unlock()
		return nil
	}
	return errors.New("member key row was not updated")
}

func (t *memTx) ReadMemberKey(_ context.Context, id string) ([]byte, error) {
	for _, row := range t.rows {
		if row.ID == id && row.CertType == certTypeMember {
			return bytes.Clone(row.EncryptedPrivateKey), nil
		}
	}
	return nil, errors.New("member key row was not read")
}

func (t *memTx) Commit(context.Context) error {
	if t.done {
		return errors.New("transaction closed")
	}
	t.done = true
	if t.readOnly {
		return errors.New("read-only transaction")
	}
	t.store.mu.Lock()
	defer t.store.mu.Unlock()
	published := make([]Row, len(t.rows))
	for i, row := range t.rows {
		published[i] = row
		published[i].EncryptedPrivateKey = bytes.Clone(row.EncryptedPrivateKey)
	}
	t.store.rows = published
	return nil
}

func (t *memTx) Rollback(context.Context) error {
	t.done = true
	return nil
}

type flipReadStore struct {
	*memStore
}

func (s *flipReadStore) Begin(ctx context.Context, readOnly bool) (Tx, error) {
	tx, err := s.memStore.Begin(ctx, readOnly)
	if err != nil {
		return nil, err
	}
	return &flipReadTx{Tx: tx}, nil
}

type flipReadTx struct {
	Tx
}

func (t *flipReadTx) ReadMemberKey(ctx context.Context, id string) ([]byte, error) {
	blob, err := t.Tx.ReadMemberKey(ctx, id)
	if err != nil {
		return nil, err
	}
	if len(blob) > 0 {
		blob[len(blob)-1] ^= 0xff
	}
	return blob, nil
}
