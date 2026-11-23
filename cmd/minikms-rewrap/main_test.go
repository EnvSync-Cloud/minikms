package main

import (
	"bytes"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/envsync-cloud/minikms/internal/crypto"
	"github.com/envsync-cloud/minikms/internal/rewrap"
)

func TestHandleExitCodes(t *testing.T) {
	writeErr := errors.New("report sink failed")
	committed := fmt.Errorf("%w: %w", rewrap.ErrCommittedReportFailed, writeErr)

	var stderr bytes.Buffer
	if code := handle(committed, &stderr); code != 3 {
		t.Fatalf("committed code=%d stderr=%q", code, stderr.String())
	}
	text := stderr.String()
	if !strings.Contains(text, "minikms-rewrap:") || !strings.Contains(text, "COMMITTED") || !strings.Contains(text, "miniKMS must now be started with the new root key") {
		t.Fatalf("stderr=%q", text)
	}
	assertNoHex(t, text, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")

	stderr.Reset()
	if code := handle(writeErr, &stderr); code != 1 {
		t.Fatalf("write code=%d stderr=%q", code, stderr.String())
	}
	if strings.Contains(stderr.String(), "COMMITTED") {
		t.Fatalf("plain write error looks committed: %q", stderr.String())
	}

	stderr.Reset()
	unknown := fmt.Errorf("%w: %w", rewrap.ErrCommitOutcomeUnknown, writeErr)
	if code := handle(unknown, &stderr); code != 4 {
		t.Fatalf("unknown code=%d stderr=%q", code, stderr.String())
	}
	unknownText := stderr.String()
	if !strings.Contains(unknownText, "minikms-rewrap:") {
		t.Fatalf("stderr=%q", unknownText)
	}
	assertUnknownCommitGuidance(t, unknownText)
	if strings.Contains(unknownText, "COMMITTED") || strings.Contains(unknownText, "must now be started with the new root key") {
		t.Fatalf("unknown outcome looks committed: %q", unknownText)
	}
	assertNoHex(t, unknownText, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")

	if exitCode(writeErr) != 1 || exitCode(committed) != 3 || exitCode(unknown) != 4 {
		t.Fatalf("exit codes 1/3/4 = %d %d %d", exitCode(writeErr), exitCode(committed), exitCode(unknown))
	}
	if exitCode(nil) != 0 || exitCode(flag.ErrHelp) != 0 || exitCode(rewrap.ErrCommitOutcomeUnknown) != 4 {
		t.Fatal("exitCode mapping mismatch")
	}

	stderr.Reset()
	if code := handle(nil, &stderr); code != 0 || stderr.Len() != 0 {
		t.Fatalf("nil code=%d stderr=%q", code, stderr.String())
	}
	if code := handle(flag.ErrHelp, &stderr); code != 0 || stderr.Len() != 0 {
		t.Fatalf("help code=%d stderr=%q", code, stderr.String())
	}
}

func TestParseFlagsDefaults(t *testing.T) {
	dryRun, confirm, path, err := parseFlags([]string{"--new-key-file", "root.key"}, io.Discard)
	if err != nil || !dryRun || confirm || path != "root.key" {
		t.Fatalf("dry=%t confirm=%t path=%q err=%v", dryRun, confirm, path, err)
	}
	dryRun, confirm, path, err = parseFlags([]string{"--new-key-file", "root.key", "--dry-run=false", "--confirm"}, io.Discard)
	if err != nil || dryRun || !confirm || path != "root.key" {
		t.Fatalf("dry=%t confirm=%t path=%q err=%v", dryRun, confirm, path, err)
	}
	var help bytes.Buffer
	if _, _, _, err := parseFlags([]string{"-h"}, &help); !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("help err=%v", err)
	}
	usage := help.String()
	if !strings.Contains(usage, "Exit status 1") || !strings.Contains(usage, "not committed") {
		t.Fatalf("usage missing status 1: %s", usage)
	}
	if !strings.Contains(usage, "Exit status 4") || !strings.Contains(usage, "unknown") {
		t.Fatalf("usage missing status 4: %s", usage)
	}
	if !strings.Contains(usage, "Member-key envelopes") || !strings.Contains(usage, "previous encoding") {
		t.Fatalf("usage missing member-key scope: %s", usage)
	}
	assertUnknownCommitGuidance(t, usage)
}

func TestExecuteRefusesBeforeDatabase(t *testing.T) {
	current := bytes.Repeat([]byte{0x11}, 32)
	replacement := bytes.Repeat([]byte{0x22}, 32)
	t.Cleanup(func() {
		crypto.ZeroizeBytes(current)
		crypto.ZeroizeBytes(replacement)
	})
	currentHex := hex.EncodeToString(current)
	t.Setenv("MINIKMS_ROOT_KEY", currentHex)
	t.Setenv("MINIKMS_ROOT_KEY_FILE", "")
	t.Setenv("MINIKMS_DB_URL", "postgres://should-not-connect")

	var stdout bytes.Buffer
	missing := filepath.Join(t.TempDir(), "missing.key")
	err := execute([]string{"--new-key-file", missing}, &stdout, io.Discard)
	if err == nil {
		t.Fatal("missing file accepted")
	}
	if strings.Contains(err.Error(), "should-not-connect") || strings.Contains(err.Error(), "MINIKMS_DB_URL") {
		t.Fatal("missing file reached the database")
	}
	assertNoHex(t, err.Error()+stdout.String(), currentHex, hex.EncodeToString(replacement))

	same := filepath.Join(t.TempDir(), "same.key")
	if err := os.WriteFile(same, []byte(currentHex+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	err = execute([]string{"--new-key-file", same, "--dry-run=false", "--confirm"}, &stdout, io.Discard)
	if !errors.Is(err, rewrap.ErrSameRootKey) {
		t.Fatalf("err=%v", err)
	}
	assertNoHex(t, err.Error()+stdout.String(), currentHex)

	next := filepath.Join(t.TempDir(), "next.key")
	if err := os.WriteFile(next, []byte(hex.EncodeToString(replacement)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	err = execute([]string{"--new-key-file", next, "--dry-run=false"}, &stdout, io.Discard)
	if !errors.Is(err, rewrap.ErrConfirmRequired) {
		t.Fatalf("err=%v", err)
	}
	if strings.Contains(err.Error(), "should-not-connect") {
		t.Fatal("unconfirmed run reached the database")
	}
	assertNoHex(t, err.Error()+stdout.String(), currentHex, hex.EncodeToString(replacement))

	loaded, err := rewrap.LoadNewRootKey(next)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { crypto.ZeroizeBytes(loaded) })
	if subtle.ConstantTimeCompare(loaded, replacement) != 1 {
		t.Fatal("replacement file was not loaded")
	}
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

func assertNoHex(t *testing.T, text string, hexs ...string) {
	t.Helper()
	lower := strings.ToLower(text)
	for _, encoded := range hexs {
		if encoded != "" && strings.Contains(lower, encoded) {
			t.Fatal("output contains root key hex")
		}
	}
}
