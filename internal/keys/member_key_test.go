package keys

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/envsync-cloud/minikms/internal/crypto"
)

func TestMemberKeyAAD(t *testing.T) {
	got := MemberKeyAAD("org", "abc")
	if got != "member-key:org:abc" {
		t.Fatalf("AAD = %q, want member-key:org:abc", got)
	}
	if got == "org-ca-key:org:abc" {
		t.Fatal("member key associated data matches organization CA associated data")
	}
}

func TestClassifyMemberKeyMaterial(t *testing.T) {
	mgr := testMemberOrgManager(t)
	orgKey := testDerive(t, mgr, "org-1")
	defer crypto.ZeroizeBytes(orgKey)

	key := testECKey(t)
	raw := crypto.MarshalECPrivateKey(key)
	defer crypto.ZeroizeBytes(raw)

	sealed, err := crypto.Encrypt(orgKey, raw, []byte(MemberKeyAAD("org-1", "serial-1")))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	kind, plain := ClassifyMemberKeyMaterial(orgKey, sealed, "org-1", "serial-1")
	defer crypto.ZeroizeBytes(plain)
	if kind != MemberKeyWrapped || !bytes.Equal(plain, raw) {
		t.Fatalf("wrapped classification = %s", kind)
	}

	orgCAAAD := []byte("org-ca-key:org-1:serial-1")
	if opened, err := crypto.Decrypt(orgKey, sealed, orgCAAAD); err == nil {
		crypto.ZeroizeBytes(opened)
		t.Fatal("member key envelope opened with organization CA associated data")
	}

	kind, plain = ClassifyMemberKeyMaterial(orgKey, raw, "org-1", "serial-1")
	defer crypto.ZeroizeBytes(plain)
	if kind != MemberKeyRaw || !bytes.Equal(plain, raw) {
		t.Fatalf("legacy classification = %s", kind)
	}

	kind, plain = ClassifyMemberKeyMaterial(orgKey, nil, "org-1", "serial-1")
	if kind != MemberKeyEmpty || plain != nil {
		t.Fatalf("empty classification = %s", kind)
	}

	kind, _ = ClassifyMemberKeyMaterial(orgKey, []byte{0xff, 0x00, 0x01}, "org-1", "serial-1")
	if kind != MemberKeyFailed {
		t.Fatalf("corrupt classification = %s", kind)
	}
}

func TestOpenMemberPrivateKey(t *testing.T) {
	mgr := testMemberOrgManager(t)
	key := testECKey(t)
	raw := crypto.MarshalECPrivateKey(key)
	defer crypto.ZeroizeBytes(raw)

	orgKey := testDerive(t, mgr, "org-1")
	defer crypto.ZeroizeBytes(orgKey)
	sealed, err := crypto.Encrypt(orgKey, raw, []byte(MemberKeyAAD("org-1", "serial-1")))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	opened, err := OpenMemberPrivateKey(mgr, "org-1", "serial-1", sealed, false)
	if err != nil {
		t.Fatalf("open envelope: %v", err)
	}
	if !opened.PublicKey.Equal(&key.PublicKey) {
		t.Fatal("opened member key does not match")
	}

	legacy, err := OpenMemberPrivateKey(mgr, "org-1", "serial-1", raw, true)
	if err != nil {
		t.Fatalf("open legacy: %v", err)
	}
	if !legacy.PublicKey.Equal(&key.PublicKey) {
		t.Fatal("legacy member key does not match")
	}

	_, err = OpenMemberPrivateKey(mgr, "org-1", "serial-1", raw, false)
	if !errors.Is(err, ErrMemberKeyLegacyDisabled) {
		t.Fatalf("legacy disabled error = %v", err)
	}
	if strings.Contains(err.Error(), "serial-1") || containsMaterial(err.Error(), raw) {
		t.Fatal("legacy disabled error included key material or a serial")
	}

	_, err = OpenMemberPrivateKey(mgr, "org-1", "serial-1", []byte{0xff, 0x00, 0x01}, true)
	if !errors.Is(err, ErrMemberKeyEnvelope) {
		t.Fatalf("corrupt blob error = %v", err)
	}

	garbage, err := crypto.Encrypt(orgKey, []byte("not-a-key"), []byte(MemberKeyAAD("org-1", "serial-2")))
	if err != nil {
		t.Fatalf("seal garbage: %v", err)
	}
	_, err = OpenMemberPrivateKey(mgr, "org-1", "serial-2", garbage, true)
	if !errors.Is(err, ErrMemberKeyEnvelope) {
		t.Fatalf("inner encoding error = %v", err)
	}

	_, err = OpenMemberPrivateKey(nil, "org-1", "serial-1", sealed, true)
	if err == nil || !strings.Contains(err.Error(), "organization key manager is not configured") {
		t.Fatalf("nil manager error = %v", err)
	}

	_, err = OpenMemberPrivateKey(mgr, "org-1", "serial-1", nil, true)
	if !errors.Is(err, ErrMemberKeyUnavailable) {
		t.Fatalf("empty blob error = %v", err)
	}

	_, err = OpenMemberPrivateKey(mgr, "", "serial-1", raw, true)
	if !errors.Is(err, ErrMemberKeyEnvelope) {
		t.Fatalf("missing org error = %v", err)
	}
	if strings.Contains(err.Error(), "serial-1") || containsMaterial(err.Error(), raw) {
		t.Fatal("derive failure included key material or a serial")
	}
}

func testMemberOrgManager(t *testing.T) *OrgKeyManager {
	t.Helper()
	holder := NewRootKeyHolder()
	if err := holder.Load(testRootKeyHex); err != nil {
		t.Fatalf("load root key: %v", err)
	}
	return NewOrgKeyManager(holder)
}

func testDerive(t *testing.T, mgr *OrgKeyManager, orgID string) []byte {
	t.Helper()
	orgKey, err := mgr.DeriveOrgKey(orgID)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	return orgKey
}

func testECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func containsMaterial(text string, material []byte) bool {
	if len(material) == 0 {
		return false
	}
	return strings.Contains(text, string(material)) || strings.Contains(text, hex.EncodeToString(material))
}
