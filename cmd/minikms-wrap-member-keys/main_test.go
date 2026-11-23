package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/envsync-cloud/minikms/internal/testutil"
)

func TestRun_FlagParsing(t *testing.T) {
	tests := []struct {
		name string
		args []string
		code int
	}{
		{name: "help", args: []string{"-h"}, code: 0},
		{name: "help long", args: []string{"--help"}, code: 0},
		{name: "check and confirm", args: []string{"--check", "--confirm"}, code: 2},
		{name: "extra arg", args: []string{"--check", "extra"}, code: 2},
		{name: "unknown flag", args: []string{"--dry-run"}, code: 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(tt.args, &stdout, &stderr)
			if code != tt.code {
				t.Fatalf("exit = %d, want %d", code, tt.code)
			}
			if stdout.Len() != 0 {
				t.Fatal("stdout was not empty")
			}
			if tt.code == 2 && !strings.HasPrefix(stderr.String(), "minikms-wrap-member-keys: ") {
				t.Fatal("error was not prefixed")
			}
		})
	}
}

func TestRun_MissingRootKey(t *testing.T) {
	t.Setenv("MINIKMS_ROOT_KEY", "")
	t.Setenv("MINIKMS_ROOT_KEY_FILE", "")
	var stdout, stderr bytes.Buffer
	code := run(nil, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if stdout.Len() != 0 {
		t.Fatal("stdout was not empty")
	}
	if !strings.HasPrefix(stderr.String(), "minikms-wrap-member-keys: ") {
		t.Fatal("error was not prefixed")
	}
	if strings.Contains(stderr.String(), testutil.TestRootKeyHex) {
		t.Fatal("stderr included root key material")
	}
}

func TestRun_MissingDatabaseDoesNotPrintRootKey(t *testing.T) {
	t.Setenv("MINIKMS_ROOT_KEY", testutil.TestRootKeyHex)
	t.Setenv("MINIKMS_ROOT_KEY_FILE", "")
	t.Setenv("MINIKMS_DB_URL", "")
	var stdout, stderr bytes.Buffer
	code := run([]string{"--check"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	combined := stdout.String() + stderr.String()
	if strings.Contains(combined, testutil.TestRootKeyHex) {
		t.Fatal("command output included root key material")
	}
	if !strings.HasPrefix(stderr.String(), "minikms-wrap-member-keys: ") {
		t.Fatal("error was not prefixed")
	}
}
