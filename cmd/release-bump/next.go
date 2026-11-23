package main

import (
	"bytes"
	"fmt"
	"io"
	"os/exec"
	"strings"

	"github.com/envsync-cloud/minikms/internal/release"
)

func runNext(args []string, stdout io.Writer) error {
	fs := newFlagSet("next")
	file := fs.String("file", "VERSION", "version file path")
	labelFlag := fs.String("label", "", "optional release:patch, release:minor, or release:major")
	if err := parseFlags(fs, args, stdout); err != nil {
		return ignoreHelp(err)
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments\n%s", usageText)
	}
	label, err := normalizeLabel(*labelFlag)
	if err != nil {
		return err
	}
	version, err := release.ReadVersionFile(*file)
	if err != nil {
		return err
	}
	tagList, err := gitOutput("tag", "--list", "v*")
	if err != nil {
		return err
	}
	stable, rcTags := classifyTags(tagList)
	logArgs := []string{"log", "--format=%B%x00"}
	if stable != "" {
		logArgs = []string{"log", stable + "..HEAD", "--format=%B%x00"}
	}
	logOut, err := gitOutput(logArgs...)
	if err != nil {
		return err
	}
	next, err := release.NextRC(release.NextInput{
		Version:   version,
		StableTag: stable,
		RCTags:    rcTags,
		Commits:   splitNullMessages(logOut),
		Label:     label,
	})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, next)
	return err
}

func gitOutput(args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			return "", fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
		}
		return "", fmt.Errorf("git %s: %s", strings.Join(args, " "), msg)
	}
	return string(out), nil
}

// normalizeLabel accepts an empty label or release:patch, release:minor, or release:major.
func normalizeLabel(label string) (string, error) {
	label = strings.TrimSpace(label)
	switch label {
	case "", "release:patch", "release:minor", "release:major":
		return label, nil
	default:
		return "", fmt.Errorf("invalid release label %q", label)
	}
}

// classifyTags splits git tag --list output. The stable result is the highest
// vX.Y.Z. rc tags are every vX.Y.Z-rc.N. Names without a leading v are ignored.
func classifyTags(list string) (stable string, rcTags []string) {
	var best release.Version
	haveStable := false
	for _, line := range strings.Split(list, "\n") {
		tag := strings.TrimSpace(line)
		rest, ok := strings.CutPrefix(tag, "v")
		if !ok || rest == tag {
			continue
		}
		version, err := release.Parse(rest)
		if err != nil {
			continue
		}
		if version.Stable() {
			if !haveStable || versionHigher(version, best) {
				best = version
				stable = tag
				haveStable = true
			}
			continue
		}
		rcTags = append(rcTags, tag)
	}
	return stable, rcTags
}

func versionHigher(left, right release.Version) bool {
	if left.Major != right.Major {
		return left.Major > right.Major
	}
	if left.Minor != right.Minor {
		return left.Minor > right.Minor
	}
	if left.Patch != right.Patch {
		return left.Patch > right.Patch
	}
	return left.RC > right.RC
}

// splitNullMessages splits git log --format=%B%x00 output into commit messages.
func splitNullMessages(log string) []string {
	if log == "" {
		return nil
	}
	parts := strings.Split(log, "\x00")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimRight(part, "\r\n")
		if strings.TrimSpace(part) == "" {
			continue
		}
		out = append(out, part)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
