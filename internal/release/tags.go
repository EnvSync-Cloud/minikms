package release

import (
	"fmt"
	"strings"
)

// ImagePlan is the container tags for one git tag.
type ImagePlan struct {
	Prerelease bool
	Tags       []string
}

// ImageTags classifies tag and returns the image references to publish.
// shortSHA is 7 to 40 hexadecimal characters and is copied after "sha-".
// image is the repository prefix without a tag, such as ghcr.io/org/minikms.
// Uppercase letters are rejected.
func ImageTags(tag, image, shortSHA string) (ImagePlan, error) {
	if err := validateImage(image); err != nil {
		return ImagePlan{}, err
	}
	if err := validateShortSHA(shortSHA); err != nil {
		return ImagePlan{}, err
	}
	version, err := versionFromGitTag(tag)
	if err != nil {
		return ImagePlan{}, err
	}
	shaTag := image + ":sha-" + shortSHA
	if !version.Stable() {
		return ImagePlan{
			Prerelease: true,
			Tags: []string{
				image + ":" + version.String(),
				shaTag,
			},
		}, nil
	}
	minor := fmt.Sprintf("%s:%d.%d", image, version.Major, version.Minor)
	return ImagePlan{
		Prerelease: false,
		Tags: []string{
			image + ":" + version.String(),
			minor,
			image + ":latest",
			image + ":stable",
			shaTag,
		},
	}, nil
}

// FormatGitHubOutput renders plan for a GitHub Actions $GITHUB_OUTPUT file.
//
//	prerelease=<true|false>
//	tags<<EOF
//	<image>:<tag>
//	EOF
func FormatGitHubOutput(plan ImagePlan) string {
	var b strings.Builder
	fmt.Fprintf(&b, "prerelease=%t\n", plan.Prerelease)
	b.WriteString("tags<<EOF\n")
	for _, tag := range plan.Tags {
		b.WriteString(tag)
		b.WriteByte('\n')
	}
	b.WriteString("EOF\n")
	return b.String()
}

func versionFromGitTag(tag string) (Version, error) {
	rest, ok := strings.CutPrefix(tag, "v")
	if !ok {
		return Version{}, fmt.Errorf("invalid git tag %q", tag)
	}
	version, err := Parse(rest)
	if err != nil {
		return Version{}, fmt.Errorf("invalid git tag %q", tag)
	}
	return version, nil
}

func validateImage(image string) error {
	if image == "" || strings.ContainsAny(image, " \t\r\n") || image != strings.ToLower(image) {
		return fmt.Errorf("invalid image %q", image)
	}
	return nil
}

func validateShortSHA(shortSHA string) error {
	if len(shortSHA) < 7 || len(shortSHA) > 40 {
		return fmt.Errorf("invalid short sha %q", shortSHA)
	}
	for _, c := range shortSHA {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		default:
			return fmt.Errorf("invalid short sha %q", shortSHA)
		}
	}
	return nil
}
