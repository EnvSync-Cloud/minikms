// Package release owns the miniKMS version and container tag rules.
//
// A version is X.Y.Z or X.Y.Z-rc.N. X, Y, and Z are non-negative integers
// written without leading zeros; 0 itself is allowed. N is an integer greater
// than or equal to 1, also without a leading zero. Parse rejects every other
// form, including a leading v, build metadata, and any pre-release other than
// rc.N.
//
// Bump(current, spec) accepts these specs:
//
//   - patch, minor, and major always compute a stable version from the X.Y.Z
//     core of current. An rc suffix is not finalized in place. patch increments
//     Z, minor increments Y and sets Z to 0, and major increments X and sets Y
//     and Z to 0. patch on 0.2.0 yields 0.2.1. patch on 0.2.0-rc.1 yields
//     0.2.1, not 0.2.0.
//   - An explicit X.Y.Z or X.Y.Z-rc.N replaces current with that version. The
//     new value does not have to be greater than current.
//   - rc on stable X.Y.Z yields X.Y.Z-rc.1. rc on X.Y.Z-rc.N yields
//     X.Y.Z-rc.(N+1). rc does not increment the numeric core.
//   - stable on X.Y.Z-rc.N yields X.Y.Z. stable on an already stable version
//     returns ErrAlreadyStable.
//
// ImageTags classifies a git tag. The tag must be vX.Y.Z or vX.Y.Z-rc.N. Any
// other tag, including an unprefixed 0.1.0, is an error. vX.Y.Z-rc.N is a
// prerelease and produces image:X.Y.Z-rc.N and image:sha-<short>, and never
// image:latest or image:stable. vX.Y.Z produces image:X.Y.Z, image:X.Y,
// image:latest, image:stable, and image:sha-<short>.
//
// FormatGitHubOutput renders that plan as prerelease=<true|false> followed by
// a tags<<EOF block for $GITHUB_OUTPUT.
package release
