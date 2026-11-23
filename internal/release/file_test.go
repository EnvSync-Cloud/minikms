package release

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestVersionFileRoundTrip(t *testing.T) {
	t.Parallel()

	t.Run("write_read_round_trip", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "VERSION")
		if err := WriteVersionFile(path, "0.2.0-rc.1"); err != nil {
			t.Fatalf("WriteVersionFile: %v", err)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if string(raw) != "0.2.0-rc.1\n" {
			t.Fatalf("raw = %q", raw)
		}
		got, err := ReadVersionFile(path)
		if err != nil {
			t.Fatalf("ReadVersionFile: %v", err)
		}
		if got != "0.2.0-rc.1" {
			t.Fatalf("got %q", got)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if info.Mode().Perm() != 0o644 {
			t.Fatalf("mode = %o, want 644", info.Mode().Perm())
		}
	})

	t.Run("bump_file_round_trip", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "VERSION")
		if err := os.WriteFile(path, []byte("0.2.0\n"), 0o644); err != nil {
			t.Fatalf("seed: %v", err)
		}
		got, err := BumpFile(path, "rc")
		if err != nil {
			t.Fatalf("first bump: %v", err)
		}
		if got != "0.2.0-rc.1" {
			t.Fatalf("first bump = %q", got)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if string(raw) != "0.2.0-rc.1\n" {
			t.Fatalf("raw after rc = %q", raw)
		}
		got, err = BumpFile(path, "rc")
		if err != nil || got != "0.2.0-rc.2" {
			t.Fatalf("second bump = %q, err = %v", got, err)
		}
		got, err = BumpFile(path, "stable")
		if err != nil || got != "0.2.0" {
			t.Fatalf("stable = %q, err = %v", got, err)
		}
		raw, err = os.ReadFile(path)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if string(raw) != "0.2.0\n" {
			t.Fatalf("raw after stable = %q", raw)
		}
	})

	t.Run("stable_error_keeps_file", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "VERSION")
		original := []byte("0.2.0\n")
		if err := os.WriteFile(path, original, 0o644); err != nil {
			t.Fatalf("seed: %v", err)
		}
		if _, err := BumpFile(path, "stable"); !errors.Is(err, ErrAlreadyStable) {
			t.Fatalf("err = %v, want ErrAlreadyStable", err)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if !bytes.Equal(raw, original) {
			t.Fatalf("file changed to %q", raw)
		}
	})

	t.Run("reject_invalid_write", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "VERSION")
		if err := WriteVersionFile(path, "v0.2.0"); err == nil {
			t.Fatal("WriteVersionFile accepted a v prefix")
		}
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("stat err = %v, want not exist", err)
		}
	})

	t.Run("read_trims_space", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "VERSION")
		if err := os.WriteFile(path, []byte("\n  0.2.0-rc.3\r\n"), 0o644); err != nil {
			t.Fatalf("seed: %v", err)
		}
		got, err := ReadVersionFile(path)
		if err != nil {
			t.Fatalf("ReadVersionFile: %v", err)
		}
		if got != "0.2.0-rc.3" {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("reject_invalid_file", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "VERSION")
		if err := os.WriteFile(path, []byte("0.2.0-rc.0\n"), 0o644); err != nil {
			t.Fatalf("seed: %v", err)
		}
		if _, err := ReadVersionFile(path); err == nil {
			t.Fatal("ReadVersionFile accepted rc.0")
		}
	})
}

func TestVerifyTag(t *testing.T) {
	t.Parallel()

	t.Run("matches_stable", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "VERSION")
		if err := os.WriteFile(path, []byte("0.2.0\n"), 0o644); err != nil {
			t.Fatalf("seed: %v", err)
		}
		if err := VerifyTag(path, "v0.2.0"); err != nil {
			t.Fatalf("VerifyTag: %v", err)
		}
	})

	t.Run("matches_rc", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "VERSION")
		if err := os.WriteFile(path, []byte("0.2.0-rc.1\n"), 0o644); err != nil {
			t.Fatalf("seed: %v", err)
		}
		if err := VerifyTag(path, "v0.2.0-rc.1"); err != nil {
			t.Fatalf("VerifyTag: %v", err)
		}
	})

	t.Run("mismatch", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "VERSION")
		if err := os.WriteFile(path, []byte("0.2.0\n"), 0o644); err != nil {
			t.Fatalf("seed: %v", err)
		}
		if err := VerifyTag(path, "v0.2.0-rc.1"); err == nil {
			t.Fatal("VerifyTag matched a different version")
		}
	})

	t.Run("unprefixed_0.1.0", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "VERSION")
		if err := os.WriteFile(path, []byte("0.1.0\n"), 0o644); err != nil {
			t.Fatalf("seed: %v", err)
		}
		if err := VerifyTag(path, "0.1.0"); err == nil {
			t.Fatal("VerifyTag accepted an unprefixed tag")
		}
	})
}

func TestRepoVersionFile(t *testing.T) {
	t.Parallel()

	t.Run("version_file_is_0.2.0", func(t *testing.T) {
		t.Parallel()
		_, file, _, ok := runtime.Caller(0)
		if !ok {
			t.Fatal("runtime.Caller failed")
		}
		path := filepath.Join(filepath.Dir(file), "..", "..", "VERSION")
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read VERSION: %v", err)
		}
		if string(raw) != "0.2.0\n" {
			t.Fatalf("VERSION = %q, want 0.2.0 plus newline", raw)
		}
		got, err := ReadVersionFile(path)
		if err != nil {
			t.Fatalf("ReadVersionFile: %v", err)
		}
		if got != "0.2.0" {
			t.Fatalf("parsed VERSION = %q", got)
		}
	})
}
