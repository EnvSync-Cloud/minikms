package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunBumpOneInvocation(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "VERSION")
	if err := os.WriteFile(path, []byte("0.2.0\n"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	var stdout bytes.Buffer
	if err := run([]string{"-file", path, "rc"}, &stdout); err != nil {
		t.Fatalf("run: %v", err)
	}
	if stdout.String() != "0.2.0-rc.1\n" {
		t.Fatalf("stdout = %q", stdout.String())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(raw) != "0.2.0-rc.1\n" {
		t.Fatalf("VERSION = %q", raw)
	}

	stdout.Reset()
	if err := run([]string{"-file", path, "0.3.0"}, &stdout); err != nil {
		t.Fatalf("explicit: %v", err)
	}
	if stdout.String() != "0.3.0\n" {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestRunBumpRejectsExtraSpec(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "VERSION")
	if err := os.WriteFile(path, []byte("0.2.0\n"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	err := run([]string{"-file", path, "rc", "patch"}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected an error for two specs")
	}
	raw, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("read: %v", readErr)
	}
	if string(raw) != "0.2.0\n" {
		t.Fatalf("VERSION changed to %q", raw)
	}
}

func TestRunTagsAndVerify(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	err := run([]string{
		"tags",
		"-tag", "v0.2.0-rc.1",
		"-image", "ghcr.io/acme/minikms",
		"-sha", "abc1234",
	}, &stdout)
	if err != nil {
		t.Fatalf("tags: %v", err)
	}
	got := stdout.String()
	if !strings.HasPrefix(got, "prerelease=true\n") {
		t.Fatalf("stdout = %q", got)
	}
	if strings.Contains(got, ":latest\n") || strings.Contains(got, ":stable\n") {
		t.Fatalf("rc tags moved a floating tag:\n%s", got)
	}
	if !strings.Contains(got, "tags<<EOF\n") || !strings.HasSuffix(got, "EOF\n") {
		t.Fatalf("stdout = %q", got)
	}

	stdout.Reset()
	err = run([]string{
		"tags",
		"-tag", "v0.2.0",
		"-image", "ghcr.io/acme/minikms",
		"-sha", "abc1234",
	}, &stdout)
	if err != nil {
		t.Fatalf("stable tags: %v", err)
	}
	got = stdout.String()
	if !strings.Contains(got, "prerelease=false\n") ||
		!strings.Contains(got, "ghcr.io/acme/minikms:latest\n") ||
		!strings.Contains(got, "ghcr.io/acme/minikms:stable\n") {
		t.Fatalf("stable stdout = %q", got)
	}

	path := filepath.Join(t.TempDir(), "VERSION")
	if err := os.WriteFile(path, []byte("0.2.0\n"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := run([]string{"verify", "-tag", "v0.2.0", "-file", path}, &bytes.Buffer{}); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := run([]string{"verify", "-tag", "v0.2.0-rc.1", "-file", path}, &bytes.Buffer{}); err == nil {
		t.Fatal("verify accepted a mismatched tag")
	}
	if err := run([]string{"verify", "-tag", "0.1.0", "-file", path}, &bytes.Buffer{}); err == nil {
		t.Fatal("verify accepted an unprefixed tag")
	}
}

func TestRunUsage(t *testing.T) {
	t.Parallel()

	if err := run(nil, &bytes.Buffer{}); err == nil {
		t.Fatal("expected a usage error")
	}
	var stdout bytes.Buffer
	if err := run([]string{"-h"}, &stdout); err != nil {
		t.Fatalf("help: %v", err)
	}
	if !strings.Contains(stdout.String(), "release-bump tags") {
		t.Fatalf("help = %q", stdout.String())
	}
	if err := run([]string{"tags"}, &bytes.Buffer{}); err == nil {
		t.Fatal("tags without flags succeeded")
	}
	if err := run([]string{"verify"}, &bytes.Buffer{}); err == nil {
		t.Fatal("verify without a tag succeeded")
	}
}
