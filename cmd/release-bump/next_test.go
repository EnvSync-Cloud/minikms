package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/envsync-cloud/minikms/internal/release"
)

func TestNormalizeLabel(t *testing.T) {
	t.Parallel()

	valid := []struct {
		in   string
		want string
	}{
		{in: "", want: ""},
		{in: "  ", want: ""},
		{in: "release:patch", want: "release:patch"},
		{in: " release:minor ", want: "release:minor"},
		{in: "release:major", want: "release:major"},
	}
	for _, tc := range valid {
		got, err := normalizeLabel(tc.in)
		if err != nil {
			t.Fatalf("normalizeLabel(%q): %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("normalizeLabel(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	for _, in := range []string{"minor", "release:foo", "release:minor:extra", "Release:minor"} {
		if _, err := normalizeLabel(in); err == nil {
			t.Fatalf("normalizeLabel(%q) succeeded", in)
		}
	}
}

func TestClassifyTags(t *testing.T) {
	t.Parallel()

	list := strings.Join([]string{
		"0.1.0",
		"0.1.0-rc.3",
		"v0.9.0",
		"v0.10.0",
		"v0.10.0-rc.2",
		"v0.2.0-rc.1",
		"v1.0.0-alpha",
		"v0.10.0-rc.1",
		"not-a-tag",
		"",
	}, "\n")
	stable, rcTags := classifyTags(list)
	if stable != "v0.10.0" {
		t.Fatalf("stable = %q, want v0.10.0", stable)
	}
	wantRC := []string{"v0.10.0-rc.2", "v0.2.0-rc.1", "v0.10.0-rc.1"}
	if strings.Join(rcTags, ",") != strings.Join(wantRC, ",") {
		t.Fatalf("rc tags = %#v, want %#v", rcTags, wantRC)
	}

	stable, rcTags = classifyTags("0.1.0\n")
	if stable != "" || len(rcTags) != 0 {
		t.Fatalf("legacy tag classified as stable=%q rc=%#v", stable, rcTags)
	}

	stable, rcTags = classifyTags("v0.2.0-rc.4\nv0.2.0-rc.10\n")
	if stable != "" {
		t.Fatalf("stable = %q, want none", stable)
	}
	if len(rcTags) != 2 {
		t.Fatalf("rc tags = %#v", rcTags)
	}
}

func TestSplitNullMessages(t *testing.T) {
	t.Parallel()

	if splitNullMessages("") != nil {
		t.Fatal("empty log produced messages")
	}
	if splitNullMessages("\x00\x00") != nil {
		t.Fatal("blank separators produced messages")
	}

	log := "feat: one\n\nbody line\n\x00\x00fix(api): two\n\x00"
	got := splitNullMessages(log)
	if len(got) != 2 {
		t.Fatalf("messages = %#v", got)
	}
	if got[0] != "feat: one\n\nbody line" {
		t.Fatalf("first = %q", got[0])
	}
	if got[1] != "fix(api): two" {
		t.Fatalf("second = %q", got[1])
	}

	leading := splitNullMessages("\x00\nfeat: x")
	if len(leading) != 1 || leading[0] != "feat: x" {
		t.Fatalf("leading newline record = %#v", leading)
	}
	next, err := release.NextRC(release.NextInput{
		Version:   "0.2.0",
		StableTag: "v0.2.0",
		Commits:   leading,
	})
	if err != nil {
		t.Fatalf("NextRC: %v", err)
	}
	if next != "0.3.0-rc.1" {
		t.Fatalf("leading newline record classified as %q, want feat minor 0.3.0-rc.1", next)
	}
}

func TestRunNextRejectsLabelBeforeGit(t *testing.T) {
	t.Parallel()

	err := run([]string{"next", "-label", "release:foo"}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected an invalid label error")
	}
	if !strings.Contains(err.Error(), "invalid release label") {
		t.Fatalf("error = %v", err)
	}
}

func TestRunNextUsage(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	if err := run([]string{"next", "-h"}, &stdout); err != nil {
		t.Fatalf("help: %v", err)
	}
	if !strings.Contains(stdout.String(), "release-bump next") {
		t.Fatalf("help = %q", stdout.String())
	}
	err := run([]string{"next", "0.2.0"}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("next accepted a positional argument")
	}
}
