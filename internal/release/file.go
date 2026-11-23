package release

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ReadVersionFile reads path, trims surrounding whitespace, and returns the
// canonical version. The file must contain X.Y.Z or X.Y.Z-rc.N.
func ReadVersionFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	version, err := Parse(strings.TrimSpace(string(data)))
	if err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	return version.String(), nil
}

// WriteVersionFile replaces path with the canonical version and a trailing
// newline.
func WriteVersionFile(path, version string) error {
	parsed, err := Parse(version)
	if err != nil {
		return err
	}
	return writeVersion(path, parsed)
}

// BumpFile reads the version at path, applies spec, and writes the result
// back in that same call. It returns the new version.
func BumpFile(path, spec string) (string, error) {
	current, err := ReadVersionFile(path)
	if err != nil {
		return "", err
	}
	next, err := Bump(current, spec)
	if err != nil {
		return "", err
	}
	parsed, err := Parse(next)
	if err != nil {
		return "", err
	}
	if err := writeVersion(path, parsed); err != nil {
		return "", err
	}
	return next, nil
}

// VerifyTag reports whether the version stored in path equals tag without its
// leading v. tag must be vX.Y.Z or vX.Y.Z-rc.N.
func VerifyTag(path, tag string) error {
	want, err := versionFromGitTag(tag)
	if err != nil {
		return err
	}
	got, err := ReadVersionFile(path)
	if err != nil {
		return err
	}
	if got != want.String() {
		return fmt.Errorf("version file %s has %s, tag %s requires %s", path, got, tag, want.String())
	}
	return nil
}

func writeVersion(path string, version Version) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".version-*")
	if err != nil {
		return fmt.Errorf("create temp version file: %w", err)
	}
	tmpName := tmp.Name()
	success := false
	defer func() {
		if !success {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write([]byte(version.String() + "\n")); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write version: %w", err)
	}
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod version: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close version: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replace version file: %w", err)
	}
	success = true
	return nil
}
