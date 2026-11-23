// Command release-bump updates VERSION and prints image tags for a git tag.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/envsync-cloud/minikms/internal/release"
)

var errHelp = errors.New("help")

const usageText = `release-bump [-file VERSION] <spec>
release-bump tags -tag <git-tag> -image <image> -sha <short-sha>
release-bump verify -tag <git-tag> [-file VERSION]

spec is patch, minor, major, rc, stable, or an explicit X.Y.Z or X.Y.Z-rc.N.
The bump form rewrites the version file and prints the new version.
tags prints prerelease=<true|false> and a tags<<EOF block for GITHUB_OUTPUT.
verify succeeds when the version file equals the tag without the leading v.`

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "release-bump: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("missing arguments\n%s", usageText)
	}
	switch args[0] {
	case "tags":
		return runTags(args[1:], stdout)
	case "verify":
		return runVerify(args[1:], stdout)
	case "-h", "--help", "help":
		_, err := fmt.Fprintln(stdout, usageText)
		return err
	default:
		return runBump(args, stdout)
	}
}

func runBump(args []string, stdout io.Writer) error {
	fs := newFlagSet("bump")
	file := fs.String("file", "VERSION", "version file path")
	if err := parseFlags(fs, args, stdout); err != nil {
		return ignoreHelp(err)
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("expected one version spec\n%s", usageText)
	}
	next, err := release.BumpFile(*file, fs.Arg(0))
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, next)
	return err
}

func runTags(args []string, stdout io.Writer) error {
	fs := newFlagSet("tags")
	tag := fs.String("tag", "", "git tag, vX.Y.Z or vX.Y.Z-rc.N")
	image := fs.String("image", "", "image repository without a tag")
	sha := fs.String("sha", "", "7 to 40 hexadecimal characters")
	if err := parseFlags(fs, args, stdout); err != nil {
		return ignoreHelp(err)
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments\n%s", usageText)
	}
	if *tag == "" || *image == "" || *sha == "" {
		return errors.New("-tag, -image, and -sha are required")
	}
	plan, err := release.ImageTags(*tag, *image, *sha)
	if err != nil {
		return err
	}
	_, err = fmt.Fprint(stdout, release.FormatGitHubOutput(plan))
	return err
}

func runVerify(args []string, stdout io.Writer) error {
	fs := newFlagSet("verify")
	file := fs.String("file", "VERSION", "version file path")
	tag := fs.String("tag", "", "git tag, vX.Y.Z or vX.Y.Z-rc.N")
	if err := parseFlags(fs, args, stdout); err != nil {
		return ignoreHelp(err)
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments\n%s", usageText)
	}
	if *tag == "" {
		return errors.New("-tag is required")
	}
	return release.VerifyTag(*file, *tag)
}

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

func parseFlags(fs *flag.FlagSet, args []string, stdout io.Writer) error {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			if _, werr := fmt.Fprintln(stdout, usageText); werr != nil {
				return werr
			}
			return errHelp
		}
		return err
	}
	return nil
}

func ignoreHelp(err error) error {
	if errors.Is(err, errHelp) {
		return nil
	}
	return err
}
