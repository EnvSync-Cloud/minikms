package release

import (
	"fmt"
	"strings"
)

// bumpLevel is the conventional-commit rank used to choose the next rc line.
// bumpNone keeps the base core and is used only when no stable tag exists.
type bumpLevel int

const (
	bumpNone bumpLevel = iota
	bumpPatch
	bumpMinor
	bumpMajor
)

// NextInput is the pure input to NextRC. It does not read git or the filesystem.
type NextInput struct {
	// Version is the VERSION file contents, X.Y.Z or X.Y.Z-rc.N.
	Version string
	// StableTag is the last stable tag, vX.Y.Z, or empty when none exists.
	// A value without a leading v, including the legacy 0.1.0 tag, is ignored.
	StableTag string
	// RCTags are existing tags. Only vX.Y.Z-rc.N participates; other names are ignored.
	RCTags []string
	// Commits are messages since the last stable tag. When StableTag is empty
	// the caller may pass the full history; those messages do not move the line,
	// because that history is already reflected in Version.
	Commits []string
	// Label is an optional release:patch, release:minor, or release:major.
	// A recognized label replaces the level chosen from commits.
	Label string
}

// NextRC returns the next release candidate, X.Y.Z-rc.N, with no leading v.
//
// With no stable v-tag, the line is the X.Y.Z core of Version, so the first
// result is that core with -rc.1. An existing rc on that core increments N.
// Commit messages are not a bump source in that bootstrap state.
//
// With a stable tag, feat selects minor, fix, perf, and revert select patch,
// and a BREAKING CHANGE footer or a type! subject selects major. No matching
// commit selects patch. The chosen level bumps the stable core.
//
// An existing rc line higher than that candidate is kept and its N is
// incremented. A candidate on a new higher core starts at rc.1. The result
// never uses a core below Version or below an existing rc tag.
func NextRC(in NextInput) (string, error) {
	current, err := Parse(strings.TrimSpace(in.Version))
	if err != nil {
		return "", fmt.Errorf("current version: %w", err)
	}
	stable, hasStable, err := parseStableTag(in.StableTag)
	if err != nil {
		return "", err
	}
	rcTags := parseRCTags(in.RCTags)
	level, err := selectLevel(hasStable, in.Commits, in.Label)
	if err != nil {
		return "", err
	}

	base := current
	base.RC = 0
	if hasStable {
		base = stable
		base.RC = 0
	}
	candidate, err := candidateCore(base, level)
	if err != nil {
		return "", err
	}

	line := candidate
	if coreHigher(current, line) {
		line = Version{Major: current.Major, Minor: current.Minor, Patch: current.Patch}
	}
	for _, tag := range rcTags {
		if coreHigher(tag, line) {
			line = Version{Major: tag.Major, Minor: tag.Minor, Patch: tag.Patch}
		}
	}

	nextN, err := nextRCNumber(maxRCOn(line, current, rcTags))
	if err != nil {
		return "", err
	}
	line.RC = nextN
	return line.String(), nil
}

func parseStableTag(tag string) (Version, bool, error) {
	tag = strings.TrimSpace(tag)
	if tag == "" || !strings.HasPrefix(tag, "v") {
		return Version{}, false, nil
	}
	version, err := versionFromGitTag(tag)
	if err != nil || !version.Stable() {
		return Version{}, false, fmt.Errorf("invalid stable tag %q", tag)
	}
	return version, true, nil
}

func parseRCTags(tags []string) []Version {
	parsed := make([]Version, 0, len(tags))
	for _, tag := range tags {
		tag = strings.TrimSpace(tag)
		if tag == "" || !strings.HasPrefix(tag, "v") {
			continue
		}
		version, err := versionFromGitTag(tag)
		if err != nil || version.Stable() {
			continue
		}
		parsed = append(parsed, version)
	}
	return parsed
}

func selectLevel(hasStable bool, commits []string, label string) (bumpLevel, error) {
	label = strings.TrimSpace(label)
	if label != "" {
		return levelFromLabel(label)
	}
	if !hasStable {
		return bumpNone, nil
	}
	level := bumpPatch
	for _, message := range commits {
		got, ok := levelFromMessage(message)
		if ok && got > level {
			level = got
		}
	}
	return level, nil
}

func levelFromLabel(label string) (bumpLevel, error) {
	switch label {
	case "release:patch":
		return bumpPatch, nil
	case "release:minor":
		return bumpMinor, nil
	case "release:major":
		return bumpMajor, nil
	default:
		return 0, fmt.Errorf("invalid release label %q", label)
	}
}

func levelFromMessage(message string) (bumpLevel, bool) {
	subject, _, _ := strings.Cut(message, "\n")
	subject = strings.TrimRight(subject, "\r")
	typ, bang, ok := conventionalSubject(subject)
	if hasBreakingFooter(message) || (ok && bang) {
		return bumpMajor, true
	}
	if !ok {
		return 0, false
	}
	switch typ {
	case "feat":
		return bumpMinor, true
	case "fix", "perf", "revert":
		return bumpPatch, true
	default:
		return 0, false
	}
}

func conventionalSubject(subject string) (typ string, bang bool, ok bool) {
	if subject == "" || !isAlpha(subject[0]) {
		return "", false, false
	}
	i := 0
	for i < len(subject) && isAlpha(subject[i]) {
		i++
	}
	typ = subject[:i]
	if i < len(subject) && subject[i] == '(' {
		end := strings.IndexByte(subject[i:], ')')
		if end <= 0 {
			return "", false, false
		}
		i += end + 1
	}
	if i < len(subject) && subject[i] == '!' {
		bang = true
		i++
	}
	if i >= len(subject) || subject[i] != ':' {
		return "", false, false
	}
	return typ, bang, true
}

func hasBreakingFooter(message string) bool {
	for _, line := range strings.Split(message, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(line, "BREAKING CHANGE:") || strings.HasPrefix(line, "BREAKING-CHANGE:") {
			return true
		}
	}
	return false
}

func isAlpha(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func candidateCore(base Version, level bumpLevel) (Version, error) {
	base.RC = 0
	switch level {
	case bumpNone:
		return base, nil
	case bumpPatch:
		return bumpVersion(base, "patch")
	case bumpMinor:
		return bumpVersion(base, "minor")
	case bumpMajor:
		return bumpVersion(base, "major")
	default:
		return Version{}, fmt.Errorf("unknown bump level %d", level)
	}
}

func coreHigher(left, right Version) bool {
	if left.Major != right.Major {
		return left.Major > right.Major
	}
	if left.Minor != right.Minor {
		return left.Minor > right.Minor
	}
	return left.Patch > right.Patch
}

func maxRCOn(core, current Version, tags []Version) uint64 {
	maxN := uint64(0)
	if sameCore(current, core) && current.RC > maxN {
		maxN = current.RC
	}
	for _, tag := range tags {
		if sameCore(tag, core) && tag.RC > maxN {
			maxN = tag.RC
		}
	}
	return maxN
}

func sameCore(left, right Version) bool {
	return left.Major == right.Major && left.Minor == right.Minor && left.Patch == right.Patch
}

func nextRCNumber(maxSeen uint64) (uint64, error) {
	if maxSeen == 0 {
		return 1, nil
	}
	return inc(maxSeen)
}
