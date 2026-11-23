package release

import (
	"errors"
	"fmt"
	"math"
	"strings"
)

// ErrAlreadyStable is returned when spec "stable" is applied to a version
// that has no rc suffix.
var ErrAlreadyStable = errors.New("version is already stable")

// Version is a miniKMS release version. RC is 0 when the version is stable.
type Version struct {
	Major uint64
	Minor uint64
	Patch uint64
	RC    uint64
}

// String returns X.Y.Z or X.Y.Z-rc.N.
func (v Version) String() string {
	if v.RC == 0 {
		return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
	}
	return fmt.Sprintf("%d.%d.%d-rc.%d", v.Major, v.Minor, v.Patch, v.RC)
}

// Stable reports whether v has no rc suffix.
func (v Version) Stable() bool {
	return v.RC == 0
}

// Parse validates s as X.Y.Z or X.Y.Z-rc.N.
func Parse(s string) (Version, error) {
	v, ok := parseVersion(s)
	if !ok {
		return Version{}, fmt.Errorf("invalid version %q", s)
	}
	return v, nil
}

// Bump applies spec to current and returns the canonical next version.
// See the package documentation for the exact spec semantics.
func Bump(current, spec string) (string, error) {
	cur, err := Parse(current)
	if err != nil {
		return "", fmt.Errorf("current version: %w", err)
	}
	next, err := bumpVersion(cur, spec)
	if err != nil {
		return "", err
	}
	return next.String(), nil
}

func bumpVersion(cur Version, spec string) (Version, error) {
	switch spec {
	case "patch":
		patch, err := inc(cur.Patch)
		if err != nil {
			return Version{}, fmt.Errorf("patch: %w", err)
		}
		return Version{Major: cur.Major, Minor: cur.Minor, Patch: patch}, nil
	case "minor":
		minor, err := inc(cur.Minor)
		if err != nil {
			return Version{}, fmt.Errorf("minor: %w", err)
		}
		return Version{Major: cur.Major, Minor: minor}, nil
	case "major":
		major, err := inc(cur.Major)
		if err != nil {
			return Version{}, fmt.Errorf("major: %w", err)
		}
		return Version{Major: major}, nil
	case "rc":
		rc := uint64(1)
		if cur.RC != 0 {
			var err error
			rc, err = inc(cur.RC)
			if err != nil {
				return Version{}, fmt.Errorf("rc: %w", err)
			}
		}
		return Version{Major: cur.Major, Minor: cur.Minor, Patch: cur.Patch, RC: rc}, nil
	case "stable":
		if cur.RC == 0 {
			return Version{}, fmt.Errorf("stable: %w", ErrAlreadyStable)
		}
		return Version{Major: cur.Major, Minor: cur.Minor, Patch: cur.Patch}, nil
	default:
		next, err := Parse(spec)
		if err != nil {
			return Version{}, fmt.Errorf("invalid spec %q", spec)
		}
		return next, nil
	}
}

func inc(n uint64) (uint64, error) {
	if n == math.MaxUint64 {
		return 0, errors.New("component overflow")
	}
	return n + 1, nil
}

func parseVersion(s string) (Version, bool) {
	if s == "" {
		return Version{}, false
	}
	core := s
	rcPart := ""
	if dash := strings.IndexByte(s, '-'); dash >= 0 {
		core = s[:dash]
		rcPart = s[dash+1:]
	}
	major, minor, patch, ok := splitCore(core)
	if !ok {
		return Version{}, false
	}
	if rcPart == "" {
		return Version{Major: major, Minor: minor, Patch: patch}, true
	}
	rc, ok := parseRC(rcPart)
	if !ok {
		return Version{}, false
	}
	return Version{Major: major, Minor: minor, Patch: patch, RC: rc}, true
}

func splitCore(core string) (uint64, uint64, uint64, bool) {
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return 0, 0, 0, false
	}
	major, ok := parseNum(parts[0], true)
	if !ok {
		return 0, 0, 0, false
	}
	minor, ok := parseNum(parts[1], true)
	if !ok {
		return 0, 0, 0, false
	}
	patch, ok := parseNum(parts[2], true)
	if !ok {
		return 0, 0, 0, false
	}
	return major, minor, patch, true
}

func parseRC(pre string) (uint64, bool) {
	rest, ok := strings.CutPrefix(pre, "rc.")
	if !ok {
		return 0, false
	}
	return parseNum(rest, false)
}

func parseNum(s string, allowZero bool) (uint64, bool) {
	if s == "" {
		return 0, false
	}
	if s[0] == '0' && len(s) > 1 {
		return 0, false
	}
	if !allowZero && s == "0" {
		return 0, false
	}
	var n uint64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		d := uint64(c - '0')
		if n > (math.MaxUint64-d)/10 {
			return 0, false
		}
		n = n*10 + d
	}
	if !allowZero && n == 0 {
		return 0, false
	}
	return n, true
}
