package rewrap_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"crypto/ecdsa"
	"crypto/elliptic"

	"github.com/envsync-cloud/minikms/internal/crypto"
	"github.com/envsync-cloud/minikms/internal/keys"
	"github.com/envsync-cloud/minikms/internal/rewrap"
)

func TestAllowlist(t *testing.T) {
	types := rewrap.OrgKeySealedCertTypes()
	if len(types) != 1 || types[0] != "org_intermediate_ca" {
		t.Fatalf("allowlist = %v", types)
	}
	if rewrap.CertTypeOrgIntermediateCA != "org_intermediate_ca" {
		t.Fatalf("cert type = %s", rewrap.CertTypeOrgIntermediateCA)
	}
	if rewrap.CertTypeMember != "member" {
		t.Fatalf("member cert type = %s", rewrap.CertTypeMember)
	}
	for _, typ := range types {
		if typ == rewrap.CertTypeMember {
			t.Fatal("member rows are on the organization CA allowlist")
		}
	}
}

func TestDryRunZeroInScopeRowsReportsTotalScanned(t *testing.T) {
	f := newFixture(t)
	delete(f.store.kvs, "kv1")
	delete(f.store.kvs, "kv2")
	delete(f.store.kvs, "kv3")
	delete(f.store.certs, "ca1")
	delete(f.store.certs, "ca2")
	delete(f.store.certs, f.memberID)
	out, err := f.run(t, true)
	if err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	want := fmt.Sprintf("mode=dry-run orgs=0\ntotal scanned=0\nkey_versions scanned=0 rewrapped=0 failed=0\ncertificates cert_type=%s scanned=0 rewrapped=0 failed=0\nmember_wrapped_rewrapped=0 member_legacy_skipped=0 member_empty_skipped=0 member_failed=0\n", rewrap.CertTypeOrgIntermediateCA)
	if out != want {
		t.Fatalf("report:\n%s", out)
	}
	if f.store.read[f.memberID] || f.store.read[f.leafID] {
		t.Fatal("out-of-scope certificate was read")
	}
	if f.store.updates != 0 || f.store.commits != 0 {
		t.Fatalf("writes recorded updates=%d commits=%d", f.store.updates, f.store.commits)
	}
}

func TestRewrapDryRun(t *testing.T) {
	f := newFixture(t)
	before := f.store.snapshot()
	out, err := f.run(t, true)
	if err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	if out != wantReport("dry-run", 3, 0, 2, 0, 1, 0, 0, 0) {
		t.Fatalf("report:\n%s", out)
	}
	assertNoKeyHex(t, out, f.oldKey, f.newKey)
	assertSame(t, f.store, before)
	if f.store.updates != 0 || f.store.commits != 0 {
		t.Fatalf("writes recorded updates=%d commits=%d", f.store.updates, f.store.commits)
	}
	if f.store.rollbacks != 1 {
		t.Fatalf("rollbacks = %d", f.store.rollbacks)
	}
	if len(f.store.begins) != 1 || !f.store.begins[0] {
		t.Fatalf("begins = %v, want one read-only transaction", f.store.begins)
	}
	assertScope(t, f, true)
}

func TestRewrapCommit(t *testing.T) {
	f := newFixture(t)
	leafBefore := f.store.ciphertext(f.leafID)
	out, err := f.run(t, false)
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	if out != wantReport("commit", 3, 0, 2, 0, 1, 0, 0, 0) {
		t.Fatalf("report:\n%s", out)
	}
	assertNoKeyHex(t, out, f.oldKey, f.newKey)
	if f.store.updates != 6 || f.store.commits != 1 || f.store.rollbacks != 0 {
		t.Fatalf("updates=%d commits=%d rollbacks=%d", f.store.updates, f.store.commits, f.store.rollbacks)
	}
	if len(f.store.begins) != 1 || f.store.begins[0] {
		t.Fatalf("begins = %v, want one read-write transaction", f.store.begins)
	}
	assertScope(t, f, true)
	if !bytes.Equal(f.store.ciphertext(f.leafID), leafBefore) {
		t.Fatal("out-of-scope certificate bytes changed")
	}

	for id, plain := range f.plains {
		ct := f.store.ciphertext(id)
		if bytes.Equal(ct, f.original[id]) {
			t.Fatalf("%s ciphertext was not rewritten", id)
		}
		got := mustOpen(t, f.newKey, f.orgOf[id], ct, f.aads[id])
		if !bytes.Equal(got, plain) {
			t.Fatalf("%s plaintext mismatch", id)
		}
		crypto.ZeroizeBytes(got)
		mustNotOpen(t, f.oldKey, f.orgOf[id], ct, f.aads[id])
	}
}

func TestRewrapMemberKeys(t *testing.T) {
	t.Run("dry-run writes nothing", func(t *testing.T) {
		f := newMemberMix(t)
		before := f.store.snapshot()
		out, err := f.run(t, true)
		if err != nil {
			t.Fatalf("dry-run: %v", err)
		}
		if out != wantReport("dry-run", 3, 0, 2, 0, 1, 1, 1, 0) {
			t.Fatalf("report:\n%s", out)
		}
		assertSame(t, f.store, before)
		if f.store.updates != 0 || f.store.commits != 0 {
			t.Fatalf("writes recorded updates=%d commits=%d", f.store.updates, f.store.commits)
		}
	})

	t.Run("commit rotates envelope and leaves legacy and empty", func(t *testing.T) {
		f := newMemberMix(t)
		legacyBefore := f.store.ciphertext("mem-legacy")
		emptyBefore := f.store.ciphertext("mem-empty")
		leafBefore := f.store.ciphertext(f.leafID)
		orgCABefore := f.store.ciphertext("ca1")
		out, err := f.run(t, false)
		if err != nil {
			t.Fatalf("commit: %v", err)
		}
		if out != wantReport("commit", 3, 0, 2, 0, 1, 1, 1, 0) {
			t.Fatalf("report:\n%s", out)
		}
		if f.store.updates != 6 || f.store.commits != 1 {
			t.Fatalf("updates=%d commits=%d", f.store.updates, f.store.commits)
		}
		if !bytes.Equal(f.store.ciphertext("mem-legacy"), legacyBefore) {
			t.Fatal("legacy member row changed")
		}
		if !bytes.Equal(f.store.ciphertext("mem-empty"), emptyBefore) || len(emptyBefore) != 0 {
			t.Fatal("empty member row changed")
		}
		if !bytes.Equal(f.store.ciphertext(f.leafID), leafBefore) {
			t.Fatal("leaf row changed")
		}
		if bytes.Equal(f.store.ciphertext("ca1"), orgCABefore) {
			t.Fatal("organization CA row was not rewrapped")
		}
		memberCT := f.store.ciphertext(f.memberID)
		if bytes.Equal(memberCT, f.original[f.memberID]) {
			t.Fatal("member envelope was not rewrapped")
		}
		got := mustOpen(t, f.newKey, f.orgOf[f.memberID], memberCT, f.aads[f.memberID])
		if !bytes.Equal(got, f.plains[f.memberID]) {
			t.Fatal("member envelope did not open with the new root key")
		}
		crypto.ZeroizeBytes(got)
		mustNotOpen(t, f.oldKey, f.orgOf[f.memberID], memberCT, f.aads[f.memberID])
		mustNotOpen(t, f.newKey, f.orgOf[f.memberID], memberCT, []byte("org-ca-key:"+f.orgOf[f.memberID]+":mem-serial"))
	})

	t.Run("failed member aborts", func(t *testing.T) {
		for _, dryRun := range []bool{true, false} {
			f := newMemberMix(t)
			f.store.certs["mem-bad"] = rewrap.CertificateRow{
				ID:                  "mem-bad",
				OrgID:               "org-c",
				SerialNumber:        "bad-serial",
				CertType:            rewrap.CertTypeMember,
				EncryptedPrivateKey: []byte{0xff, 0x00, 0x01},
			}
			before := f.store.snapshot()
			out, err := f.run(t, dryRun)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), "could not be decrypted") {
				t.Fatalf("err = %v", err)
			}
			if strings.Contains(out, "bad-serial") || strings.Contains(err.Error(), "bad-serial") {
				t.Fatal("failure report included a serial")
			}
			mode := "commit"
			if dryRun {
				mode = "dry-run"
			}
			if out != wantReport(mode, 0, 0, 0, 0, 0, 1, 1, 1) {
				t.Fatalf("report:\n%s", out)
			}
			assertSame(t, f.store, before)
			if f.store.updates != 0 || f.store.commits != 0 {
				t.Fatalf("writes recorded updates=%d commits=%d", f.store.updates, f.store.commits)
			}
		}
	})
}

func newMemberMix(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t)
	f.addMemberLegacy(t, "mem-legacy", "org-c", "legacy-serial")
	f.store.certs["mem-empty"] = rewrap.CertificateRow{
		ID:           "mem-empty",
		OrgID:        "org-c",
		SerialNumber: "empty-serial",
		CertType:     rewrap.CertTypeMember,
	}
	return f
}

func (f *fixture) addMemberLegacy(t *testing.T, id, orgID, serial string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	blob := crypto.MarshalECPrivateKey(key)
	f.store.certs[id] = rewrap.CertificateRow{
		ID:                  id,
		OrgID:               orgID,
		SerialNumber:        serial,
		CertType:            rewrap.CertTypeMember,
		EncryptedPrivateKey: blob,
	}
}

func TestOutputOmitsKeyHex(t *testing.T) {
	dry := newFixture(t)
	dryOut, err := dry.run(t, true)
	if err != nil {
		t.Fatal(err)
	}
	assertNoKeyHex(t, dryOut, dry.oldKey, dry.newKey)

	committed := newFixture(t)
	commitOut, err := committed.run(t, false)
	if err != nil {
		t.Fatal(err)
	}
	assertNoKeyHex(t, commitOut, committed.oldKey, committed.newKey)

	aborted := newFixture(t)
	aborted.corrupt("kv2")
	abortOut, abortErr := aborted.run(t, false)
	if abortErr == nil {
		t.Fatal("expected decrypt failure")
	}
	assertNoKeyHex(t, abortOut+"\n"+abortErr.Error(), aborted.oldKey, aborted.newKey)
}

func TestRewrapAbortsWhenRowCannotDecrypt(t *testing.T) {
	for _, dryRun := range []bool{false, true} {
		name := "commit"
		if dryRun {
			name = "dry-run"
		}
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.corrupt("kv2")
			base := f.store.snapshot()
			out, err := f.run(t, dryRun)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), "could not be decrypted") || !strings.Contains(err.Error(), "1") {
				t.Fatalf("err = %v", err)
			}
			mode := "commit"
			if dryRun {
				mode = "dry-run"
			}
			if out != wantReport(mode, 0, 1, 0, 0, 0, 0, 0, 0) {
				t.Fatalf("report:\n%s", out)
			}
			assertNoKeyHex(t, out+"\n"+err.Error(), f.oldKey, f.newKey)
			assertSame(t, f.store, base)
			if f.store.updates != 0 || f.store.commits != 0 {
				t.Fatalf("writes recorded updates=%d commits=%d", f.store.updates, f.store.commits)
			}
			got := mustOpen(t, f.oldKey, f.orgOf["kv1"], f.store.ciphertext("kv1"), f.aads["kv1"])
			if !bytes.Equal(got, f.plains["kv1"]) {
				t.Fatal("kv1 changed")
			}
			crypto.ZeroizeBytes(got)
			mustNotOpen(t, f.newKey, f.orgOf["kv1"], f.store.ciphertext("kv1"), f.aads["kv1"])
			if !f.store.read["ca1"] || !f.store.read[f.memberID] || f.store.read[f.leafID] {
				t.Fatal("certificate read set is wrong")
			}
		})
	}
}

func TestRewrapRefusesSameKey(t *testing.T) {
	key := randomBytes(t, 32)
	t.Cleanup(func() { crypto.ZeroizeBytes(key) })
	copyKey := append([]byte(nil), key...)
	t.Cleanup(func() { crypto.ZeroizeBytes(copyKey) })

	for _, dryRun := range []bool{true, false} {
		var buf bytes.Buffer
		err := rewrap.Run(context.Background(), denyStore{}, rewrap.Options{
			OldKey:  key,
			NewKey:  copyKey,
			DryRun:  dryRun,
			Confirm: true,
		}, &buf)
		if !errors.Is(err, rewrap.ErrSameRootKey) {
			t.Fatalf("dry-run=%t err=%v", dryRun, err)
		}
		if buf.Len() != 0 {
			t.Fatal("same-key refusal produced output")
		}
		assertNoKeyHex(t, err.Error(), key)
	}
}

func TestRewrapRefusesActiveRootEscrow(t *testing.T) {
	for _, dryRun := range []bool{true, false} {
		f := newFixture(t)
		f.store.active = true
		before := f.store.snapshot()
		out, err := f.run(t, dryRun)
		if !errors.Is(err, rewrap.ErrActiveRootEscrow) {
			t.Fatalf("dry-run=%t err=%v", dryRun, err)
		}
		msg := err.Error()
		if strings.Contains(msg, "re-split") || strings.Contains(msg, "resplit") {
			t.Fatalf("err tells the operator to re-split: %v", err)
		}
		for _, phrase := range []string{
			"does not support deployments with an active root escrow set",
			"without changing data",
			"out of scope",
		} {
			if !strings.Contains(msg, phrase) {
				t.Fatalf("err = %q, missing %q", msg, phrase)
			}
		}
		if out != "" {
			t.Fatalf("output = %q", out)
		}
		if len(f.store.begins) != 0 || f.store.updates != 0 || f.store.commits != 0 {
			t.Fatal("transaction or write started")
		}
		assertSame(t, f.store, before)
		assertNoKeyHex(t, err.Error(), f.oldKey, f.newKey)
	}
}

func TestCommitOutcomeUnknown(t *testing.T) {
	commitErr := errors.New("commit acknowledgement lost")

	t.Run("commit", func(t *testing.T) {
		f := newFixture(t)
		before := f.store.snapshot()
		f.store.commitErr = commitErr
		out, err := f.run(t, false)
		if !errors.Is(err, rewrap.ErrCommitOutcomeUnknown) {
			t.Fatalf("err=%v", err)
		}
		if !errors.Is(err, commitErr) {
			t.Fatalf("commit error not wrapped: %v", err)
		}
		if errors.Is(err, rewrap.ErrCommittedReportFailed) {
			t.Fatal("uncertain commit reported as committed")
		}
		assertUnknownCommitGuidance(t, err.Error())
		if out != "" {
			t.Fatalf("report written despite uncertain commit: %q", out)
		}
		if f.store.commits != 0 || f.store.updates == 0 {
			t.Fatalf("commits=%d updates=%d", f.store.commits, f.store.updates)
		}
		assertSame(t, f.store, before)
	})

	t.Run("dry-run", func(t *testing.T) {
		f := newFixture(t)
		f.store.commitErr = commitErr
		if _, err := f.run(t, true); err != nil {
			t.Fatalf("dry-run err=%v", err)
		}
		if f.store.commits != 0 {
			t.Fatal("dry-run committed")
		}
	})

	t.Run("decrypt failure", func(t *testing.T) {
		f := newFixture(t)
		f.corrupt("kv2")
		_, err := f.run(t, false)
		if err == nil || errors.Is(err, rewrap.ErrCommitOutcomeUnknown) {
			t.Fatalf("err=%v", err)
		}
	})
}

func TestReportWriteFailure(t *testing.T) {
	sinkErr := errors.New("report sink failed")

	t.Run("commit", func(t *testing.T) {
		f := newFixture(t)
		err := rewrap.Run(context.Background(), f.store, rewrap.Options{
			OldKey:  f.oldKey,
			NewKey:  f.newKey,
			DryRun:  false,
			Confirm: true,
		}, failWriter{err: sinkErr})
		if !errors.Is(err, rewrap.ErrCommittedReportFailed) {
			t.Fatalf("err=%v", err)
		}
		if !errors.Is(err, sinkErr) {
			t.Fatalf("write error not wrapped: %v", err)
		}
		msg := err.Error()
		if !strings.Contains(msg, "COMMITTED") || !strings.Contains(msg, "miniKMS must now be started with the new root key") {
			t.Fatalf("err=%v", err)
		}
		assertNoKeyHex(t, msg, f.oldKey, f.newKey)
		if f.store.commits != 1 || f.store.updates == 0 {
			t.Fatalf("commits=%d updates=%d", f.store.commits, f.store.updates)
		}
		for id, plain := range f.plains {
			ct := f.store.ciphertext(id)
			if bytes.Equal(ct, f.original[id]) {
				t.Fatalf("%s was not committed", id)
			}
			got := mustOpen(t, f.newKey, f.orgOf[id], ct, f.aads[id])
			if !bytes.Equal(got, plain) {
				t.Fatalf("%s plaintext mismatch after commit", id)
			}
			crypto.ZeroizeBytes(got)
			mustNotOpen(t, f.oldKey, f.orgOf[id], ct, f.aads[id])
		}
	})

	t.Run("dry-run", func(t *testing.T) {
		f := newFixture(t)
		before := f.store.snapshot()
		err := rewrap.Run(context.Background(), f.store, rewrap.Options{
			OldKey: f.oldKey,
			NewKey: f.newKey,
			DryRun: true,
		}, failWriter{err: sinkErr})
		if err == nil {
			t.Fatal("expected report write error")
		}
		if errors.Is(err, rewrap.ErrCommittedReportFailed) {
			t.Fatal("dry-run report failure reported as committed")
		}
		if !errors.Is(err, sinkErr) {
			t.Fatalf("err=%v", err)
		}
		if strings.Contains(err.Error(), "COMMITTED") {
			t.Fatalf("dry-run err=%v", err)
		}
		assertNoKeyHex(t, err.Error(), f.oldKey, f.newKey)
		if f.store.commits != 0 || f.store.updates != 0 {
			t.Fatalf("commits=%d updates=%d", f.store.commits, f.store.updates)
		}
		assertSame(t, f.store, before)
	})

	t.Run("decrypt failure", func(t *testing.T) {
		f := newFixture(t)
		f.corrupt("kv2")
		before := f.store.snapshot()
		err := rewrap.Run(context.Background(), f.store, rewrap.Options{
			OldKey:  f.oldKey,
			NewKey:  f.newKey,
			DryRun:  false,
			Confirm: true,
		}, failWriter{err: sinkErr})
		if err == nil {
			t.Fatal("expected report write error")
		}
		if errors.Is(err, rewrap.ErrCommittedReportFailed) {
			t.Fatal("rolled-back rewrap reported as committed")
		}
		if !errors.Is(err, sinkErr) {
			t.Fatalf("err=%v", err)
		}
		assertNoKeyHex(t, err.Error(), f.oldKey, f.newKey)
		if f.store.commits != 0 || f.store.updates != 0 {
			t.Fatalf("commits=%d updates=%d", f.store.commits, f.store.updates)
		}
		assertSame(t, f.store, before)
	})
}

type failWriter struct {
	err error
}

func (w failWriter) Write([]byte) (int, error) {
	return 0, w.err
}

func TestRewrapRefusesUnconfirmedWrite(t *testing.T) {
	oldKey := randomBytes(t, 32)
	newKey := randomBytes(t, 32)
	t.Cleanup(func() {
		crypto.ZeroizeBytes(oldKey)
		crypto.ZeroizeBytes(newKey)
	})
	var buf bytes.Buffer
	err := rewrap.Run(context.Background(), denyStore{}, rewrap.Options{
		OldKey: oldKey,
		NewKey: newKey,
		DryRun: false,
	}, &buf)
	if !errors.Is(err, rewrap.ErrConfirmRequired) {
		t.Fatalf("err=%v", err)
	}
	if buf.Len() != 0 {
		t.Fatal("unconfirmed run produced output")
	}
	assertNoKeyHex(t, err.Error(), oldKey, newKey)
}

func TestLoadNewRootKey(t *testing.T) {
	key := bytes.Repeat([]byte{0x5a}, 32)
	other := bytes.Repeat([]byte{0xab}, 32)
	t.Cleanup(func() {
		crypto.ZeroizeBytes(key)
		crypto.ZeroizeBytes(other)
	})
	keyHex := hex.EncodeToString(key)
	t.Setenv("MINIKMS_ROOT_KEY", hex.EncodeToString(other))
	t.Setenv("MINIKMS_NEW_ROOT_KEY", hex.EncodeToString(other))

	if _, err := rewrap.LoadNewRootKey(""); err == nil {
		t.Fatal("empty path accepted")
	}
	missing := filepath.Join(t.TempDir(), "missing.key")
	_, err := rewrap.LoadNewRootKey(missing)
	if err == nil {
		t.Fatal("missing file accepted")
	}
	assertNoKeyHex(t, err.Error(), key, other)

	path := filepath.Join(t.TempDir(), "new.key")
	if err := os.WriteFile(path, []byte(keyHex+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := rewrap.LoadNewRootKey(path); err == nil {
		t.Fatal("loose permissions accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := rewrap.LoadNewRootKey(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { crypto.ZeroizeBytes(got) })
	if subtle.ConstantTimeCompare(got, key) != 1 {
		t.Fatal("new key bytes mismatch")
	}
	if subtle.ConstantTimeCompare(got, other) == 1 {
		t.Fatal("new key followed an environment variable")
	}

	bad := filepath.Join(t.TempDir(), "bad.key")
	if err := os.WriteFile(bad, []byte("zzzz\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := rewrap.LoadNewRootKey(bad); err == nil {
		t.Fatal("invalid hex accepted")
	}
	shortPath := filepath.Join(t.TempDir(), "short.key")
	if err := os.WriteFile(shortPath, []byte(hex.EncodeToString(key[:16])+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := rewrap.LoadNewRootKey(shortPath); err == nil {
		t.Fatal("short key accepted")
	}
}

func TestLoadCurrentRootKey(t *testing.T) {
	key := randomBytes(t, 32)
	t.Cleanup(func() { crypto.ZeroizeBytes(key) })
	keyHex := hex.EncodeToString(key)
	got, err := rewrap.LoadCurrentRootKey(keyHex, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { crypto.ZeroizeBytes(got) })
	if subtle.ConstantTimeCompare(got, key) != 1 {
		t.Fatal("current key bytes mismatch")
	}

	path := filepath.Join(t.TempDir(), "current.key")
	if err := os.WriteFile(path, []byte(keyHex+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := rewrap.LoadCurrentRootKey(keyHex, path); err == nil {
		t.Fatal("two sources accepted")
	}
	if _, err := rewrap.LoadCurrentRootKey("", ""); err == nil {
		t.Fatal("empty source accepted")
	}
}

func wantReport(mode string, kvRewrapped, kvFailed, certRewrapped, certFailed, memberRewrapped, memberLegacy, memberEmpty, memberFailed int) string {
	return fmt.Sprintf("mode=%s orgs=3\ntotal scanned=6\nkey_versions scanned=3 rewrapped=%d failed=%d\ncertificates cert_type=%s scanned=2 rewrapped=%d failed=%d\nmember_wrapped_rewrapped=%d member_legacy_skipped=%d member_empty_skipped=%d member_failed=%d\n",
		mode, kvRewrapped, kvFailed, rewrap.CertTypeOrgIntermediateCA, certRewrapped, certFailed,
		memberRewrapped, memberLegacy, memberEmpty, memberFailed)
}

func assertUnknownCommitGuidance(t *testing.T, text string) {
	t.Helper()
	if !strings.Contains(strings.ToLower(text), "keep minikms stopped") {
		t.Fatalf("text=%q missing keep miniKMS stopped", text)
	}
	for _, phrase := range []string{
		"distinct trial key",
		"MINIKMS_ROOT_KEY_FILE",
		"--new-key-file",
		"Check A",
		"Check B",
		"conclusive only if it exits 0",
		"reports zero failures",
		"scanned at least one in-scope row",
		"key_versions + certificates scanned + opened member-key envelopes > 0",
		"total scanned",
		"the commit did not land",
		"the commit landed",
		"both checks scan zero rows",
		"neither is conclusive",
		"the outcome stays unknown",
		"restore from the pre-rotation DB dump with the old key",
		"or investigate",
		"Delete the trial key file afterwards",
	} {
		if !strings.Contains(text, phrase) {
			t.Fatalf("text=%q missing %q", text, phrase)
		}
	}
	for _, phrase := range []string{
		"otherwise it did not",
		"any different file",
		"Only if Check A exits 0 with zero failures",
		"Only if Check B exits 0 with zero failures",
	} {
		if strings.Contains(text, phrase) {
			t.Fatalf("text=%q contains %q", text, phrase)
		}
	}
}

func assertNoKeyHex(t *testing.T, text string, keys ...[]byte) {
	t.Helper()
	lower := strings.ToLower(text)
	for _, key := range keys {
		encoded := hex.EncodeToString(key)
		if encoded != "" && strings.Contains(lower, encoded) {
			t.Fatal("output contains root key hex")
		}
	}
}

func assertSame(t *testing.T, store *memStore, before map[string][]byte) {
	t.Helper()
	after := store.snapshot()
	if len(after) != len(before) {
		t.Fatal("row set changed")
	}
	for id, ct := range before {
		if !bytes.Equal(after[id], ct) {
			t.Fatalf("row %s was written", id)
		}
	}
}

func assertScope(t *testing.T, f *fixture, readInScope bool) {
	t.Helper()
	if readInScope && (!f.store.read["ca1"] || !f.store.read["ca2"] || !f.store.read[f.memberID]) {
		t.Fatal("in-scope certificates were not read")
	}
	if f.store.read[f.leafID] {
		t.Fatal("out-of-scope certificate was read")
	}
	if len(f.store.listedTypes) != 1 || f.store.listedTypes[0] != rewrap.CertTypeOrgIntermediateCA {
		t.Fatalf("listed types = %v", f.store.listedTypes)
	}
}

func mustOpen(t *testing.T, root []byte, orgID string, ciphertext, aad []byte) []byte {
	t.Helper()
	orgKey, err := crypto.DeriveOrgMasterKey(root, orgID)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	t.Cleanup(func() { crypto.ZeroizeBytes(orgKey) })
	plain, err := crypto.Decrypt(orgKey, ciphertext, aad)
	if err != nil {
		t.Fatal("decrypt failed")
	}
	return plain
}

func mustNotOpen(t *testing.T, root []byte, orgID string, ciphertext, aad []byte) {
	t.Helper()
	orgKey, err := crypto.DeriveOrgMasterKey(root, orgID)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	t.Cleanup(func() { crypto.ZeroizeBytes(orgKey) })
	plain, err := crypto.Decrypt(orgKey, ciphertext, aad)
	crypto.ZeroizeBytes(plain)
	if err == nil {
		t.Fatal("decrypt succeeded")
	}
}

func mustSeal(t *testing.T, root []byte, orgID string, plain, aad []byte) []byte {
	t.Helper()
	orgKey, err := crypto.DeriveOrgMasterKey(root, orgID)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	defer crypto.ZeroizeBytes(orgKey)
	ciphertext, err := crypto.Encrypt(orgKey, plain, aad)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	return ciphertext
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	return buf
}

type fixture struct {
	oldKey   []byte
	newKey   []byte
	store    *memStore
	plains   map[string][]byte
	aads     map[string][]byte
	orgOf    map[string]string
	original map[string][]byte
	memberID string
	leafID   string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	oldKey, newKey := twoKeys(t)
	f := &fixture{
		oldKey:   oldKey,
		newKey:   newKey,
		store:    newMemStore(),
		plains:   map[string][]byte{},
		aads:     map[string][]byte{},
		orgOf:    map[string]string{},
		original: map[string][]byte{},
		memberID: "mem1",
		leafID:   "leaf1",
	}
	t.Cleanup(func() {
		crypto.ZeroizeBytes(f.oldKey)
		crypto.ZeroizeBytes(f.newKey)
		for _, plain := range f.plains {
			crypto.ZeroizeBytes(plain)
		}
	})
	f.addKV(t, "kv1", "org-a")
	f.addKV(t, "kv2", "org-a")
	f.addKV(t, "kv3", "org-b")
	f.addCert(t, "ca1", "org-a", "11aa", rewrap.CertTypeOrgIntermediateCA, true)
	f.addCert(t, "ca2", "org-b", "pending-orgb0001", rewrap.CertTypeOrgIntermediateCA, true)
	f.addMemberEnvelope(t, f.memberID, "org-c", "mem-serial")
	f.addCert(t, f.leafID, "org-d", "leaf-serial", "leaf", false)
	return f
}

func twoKeys(t *testing.T) ([]byte, []byte) {
	t.Helper()
	for {
		oldKey := randomBytes(t, 32)
		newKey := randomBytes(t, 32)
		if subtle.ConstantTimeCompare(oldKey, newKey) != 1 {
			return oldKey, newKey
		}
		crypto.ZeroizeBytes(oldKey)
		crypto.ZeroizeBytes(newKey)
	}
}

func (f *fixture) addKV(t *testing.T, id, orgID string) {
	t.Helper()
	plain := randomBytes(t, 32)
	aad := []byte("dek:" + orgID)
	ct := mustSeal(t, f.oldKey, orgID, plain, aad)
	f.store.kvs[id] = rewrap.KeyVersionRow{ID: id, OrgID: orgID, EncryptedKey: ct}
	f.plains[id] = plain
	f.aads[id] = aad
	f.orgOf[id] = orgID
	f.original[id] = append([]byte(nil), ct...)
}

func (f *fixture) addMemberEnvelope(t *testing.T, id, orgID, serial string) {
	t.Helper()
	plain := randomBytes(t, 32)
	aad := []byte(keys.MemberKeyAAD(orgID, serial))
	ct := mustSeal(t, f.oldKey, orgID, plain, aad)
	f.store.certs[id] = rewrap.CertificateRow{
		ID:                  id,
		OrgID:               orgID,
		SerialNumber:        serial,
		CertType:            rewrap.CertTypeMember,
		EncryptedPrivateKey: ct,
	}
	f.plains[id] = plain
	f.aads[id] = aad
	f.orgOf[id] = orgID
	f.original[id] = append([]byte(nil), ct...)
}

func (f *fixture) addCert(t *testing.T, id, orgID, serial, certType string, seal bool) {
	t.Helper()
	var ct []byte
	if seal {
		plain := randomBytes(t, 48)
		aad := []byte("org-ca-key:" + orgID + ":" + serial)
		ct = mustSeal(t, f.oldKey, orgID, plain, aad)
		f.plains[id] = plain
		f.aads[id] = aad
		f.orgOf[id] = orgID
		f.original[id] = append([]byte(nil), ct...)
	} else {
		ct = []byte("out-of-scope:" + id)
	}
	f.store.certs[id] = rewrap.CertificateRow{
		ID:                  id,
		OrgID:               orgID,
		SerialNumber:        serial,
		CertType:            certType,
		EncryptedPrivateKey: ct,
	}
}

func (f *fixture) corrupt(id string) {
	row := f.store.kvs[id]
	row.EncryptedKey = []byte("not-ciphertext")
	f.store.kvs[id] = row
}

func (f *fixture) run(t *testing.T, dryRun bool) (string, error) {
	t.Helper()
	var buf bytes.Buffer
	err := rewrap.Run(context.Background(), f.store, rewrap.Options{
		OldKey:  f.oldKey,
		NewKey:  f.newKey,
		DryRun:  dryRun,
		Confirm: !dryRun,
	}, &buf)
	assertNoKeyHex(t, buf.String(), f.oldKey, f.newKey)
	if err != nil {
		assertNoKeyHex(t, err.Error(), f.oldKey, f.newKey)
	}
	return buf.String(), err
}

type denyStore struct{}

func (denyStore) HasActiveRootEscrow(context.Context) (bool, error) {
	return false, errors.New("store used")
}

func (denyStore) Begin(context.Context, bool) (rewrap.Tx, error) {
	return nil, errors.New("store used")
}

type memStore struct {
	kvs         map[string]rewrap.KeyVersionRow
	certs       map[string]rewrap.CertificateRow
	read        map[string]bool
	listedTypes []string
	active      bool
	begins      []bool
	updates     int
	commits     int
	rollbacks   int
	commitErr   error
}

func newMemStore() *memStore {
	return &memStore{
		kvs:   map[string]rewrap.KeyVersionRow{},
		certs: map[string]rewrap.CertificateRow{},
		read:  map[string]bool{},
	}
}

func (s *memStore) HasActiveRootEscrow(ctx context.Context) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return s.active, nil
}

func (s *memStore) Begin(ctx context.Context, readOnly bool) (rewrap.Tx, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.begins = append(s.begins, readOnly)
	return &memTx{
		store:       s,
		readOnly:    readOnly,
		kvs:         cloneKeyVersions(s.kvs),
		certs:       cloneCerts(s.certs),
		kvOverlay:   map[string][]byte{},
		certOverlay: map[string][]byte{},
	}, nil
}

func (s *memStore) ciphertext(id string) []byte {
	if row, ok := s.kvs[id]; ok {
		return append([]byte(nil), row.EncryptedKey...)
	}
	if row, ok := s.certs[id]; ok {
		return append([]byte(nil), row.EncryptedPrivateKey...)
	}
	return nil
}

func (s *memStore) snapshot() map[string][]byte {
	out := make(map[string][]byte, len(s.kvs)+len(s.certs))
	for id := range s.kvs {
		out[id] = s.ciphertext(id)
	}
	for id := range s.certs {
		out[id] = s.ciphertext(id)
	}
	return out
}

type memTx struct {
	store       *memStore
	readOnly    bool
	kvs         map[string]rewrap.KeyVersionRow
	certs       map[string]rewrap.CertificateRow
	kvOverlay   map[string][]byte
	certOverlay map[string][]byte
	closed      bool
}

func (t *memTx) ListKeyVersions(context.Context) ([]rewrap.KeyVersionRow, error) {
	ids := sortedIDs(t.kvs)
	out := make([]rewrap.KeyVersionRow, 0, len(ids))
	for _, id := range ids {
		row := t.kvs[id]
		row.EncryptedKey = append([]byte(nil), row.EncryptedKey...)
		out = append(out, row)
	}
	return out, nil
}

func (t *memTx) ListCertificates(_ context.Context, certTypes []string) ([]rewrap.CertificateRow, error) {
	if len(certTypes) == 0 {
		return nil, fmt.Errorf("certificate allowlist is empty")
	}
	t.store.listedTypes = append([]string(nil), certTypes...)
	allowed := make(map[string]struct{}, len(certTypes))
	for _, certType := range certTypes {
		allowed[certType] = struct{}{}
	}
	ids := make([]string, 0, len(t.certs))
	for id := range t.certs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var out []rewrap.CertificateRow
	for _, id := range ids {
		row := t.certs[id]
		if _, ok := allowed[row.CertType]; !ok {
			continue
		}
		t.store.read[id] = true
		row.EncryptedPrivateKey = append([]byte(nil), row.EncryptedPrivateKey...)
		out = append(out, row)
	}
	return out, nil
}

func (t *memTx) ListMemberKeys(context.Context) ([]rewrap.CertificateRow, error) {
	ids := make([]string, 0, len(t.certs))
	for id := range t.certs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var out []rewrap.CertificateRow
	for _, id := range ids {
		row := t.certs[id]
		if row.CertType != rewrap.CertTypeMember {
			continue
		}
		t.store.read[id] = true
		row.EncryptedPrivateKey = append([]byte(nil), row.EncryptedPrivateKey...)
		out = append(out, row)
	}
	return out, nil
}

func (t *memTx) UpdateKeyVersion(_ context.Context, id string, encryptedKey []byte) error {
	t.store.updates++
	if _, ok := t.kvs[id]; !ok {
		return fmt.Errorf("key version not in transaction")
	}
	t.kvOverlay[id] = append([]byte(nil), encryptedKey...)
	return nil
}

func (t *memTx) UpdateCertificate(_ context.Context, id string, encryptedPrivateKey []byte) error {
	t.store.updates++
	row, ok := t.certs[id]
	if !ok {
		return fmt.Errorf("certificate not in transaction")
	}
	if row.CertType != rewrap.CertTypeOrgIntermediateCA && row.CertType != rewrap.CertTypeMember {
		return fmt.Errorf("refusing update outside allowlist")
	}
	t.certOverlay[id] = append([]byte(nil), encryptedPrivateKey...)
	return nil
}

func (t *memTx) ReadKeyVersion(_ context.Context, id string) ([]byte, error) {
	if ct, ok := t.kvOverlay[id]; ok {
		return append([]byte(nil), ct...), nil
	}
	row, ok := t.kvs[id]
	if !ok {
		return nil, fmt.Errorf("key version not in transaction")
	}
	return append([]byte(nil), row.EncryptedKey...), nil
}

func (t *memTx) ReadCertificate(_ context.Context, id string) ([]byte, error) {
	if ct, ok := t.certOverlay[id]; ok {
		return append([]byte(nil), ct...), nil
	}
	row, ok := t.certs[id]
	if !ok {
		return nil, fmt.Errorf("certificate not in transaction")
	}
	return append([]byte(nil), row.EncryptedPrivateKey...), nil
}

func (t *memTx) Commit(context.Context) error {
	if t.closed {
		return fmt.Errorf("transaction is closed")
	}
	if t.store.commitErr != nil {
		return t.store.commitErr
	}
	if t.readOnly {
		t.closed = true
		return fmt.Errorf("read-only transaction cannot commit")
	}
	for id, ct := range t.kvOverlay {
		row := t.store.kvs[id]
		row.EncryptedKey = append([]byte(nil), ct...)
		t.store.kvs[id] = row
	}
	for id, ct := range t.certOverlay {
		row := t.store.certs[id]
		row.EncryptedPrivateKey = append([]byte(nil), ct...)
		t.store.certs[id] = row
	}
	t.closed = true
	t.store.commits++
	return nil
}

func (t *memTx) Rollback(context.Context) error {
	if t.closed {
		return nil
	}
	t.closed = true
	t.store.rollbacks++
	return nil
}

func cloneKeyVersions(in map[string]rewrap.KeyVersionRow) map[string]rewrap.KeyVersionRow {
	out := make(map[string]rewrap.KeyVersionRow, len(in))
	for id, row := range in {
		row.EncryptedKey = append([]byte(nil), row.EncryptedKey...)
		out[id] = row
	}
	return out
}

func cloneCerts(in map[string]rewrap.CertificateRow) map[string]rewrap.CertificateRow {
	out := make(map[string]rewrap.CertificateRow, len(in))
	for id, row := range in {
		row.EncryptedPrivateKey = append([]byte(nil), row.EncryptedPrivateKey...)
		out[id] = row
	}
	return out
}

func sortedIDs(rows map[string]rewrap.KeyVersionRow) []string {
	ids := make([]string, 0, len(rows))
	for id := range rows {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

var _ rewrap.Store = (*memStore)(nil)
var _ rewrap.Tx = (*memTx)(nil)
