package release

import (
	"slices"
	"strings"
	"testing"
)

func TestImageTags(t *testing.T) {
	t.Parallel()

	const (
		image = "ghcr.io/acme/minikms"
		sha   = "abc1234"
	)

	t.Run("rc_tag_never_latest_or_stable", func(t *testing.T) {
		t.Parallel()
		plan, err := ImageTags("v0.2.0-rc.1", image, sha)
		if err != nil {
			t.Fatalf("ImageTags: %v", err)
		}
		if !plan.Prerelease {
			t.Fatal("prerelease = false, want true")
		}
		want := []string{
			image + ":0.2.0-rc.1",
			image + ":sha-" + sha,
		}
		if !slices.Equal(plan.Tags, want) {
			t.Fatalf("tags = %#v, want %#v", plan.Tags, want)
		}
		assertNoFloatingTags(t, plan.Tags)

		for _, tag := range []string{"v0.2.0-rc.2", "v1.0.0-rc.10"} {
			extra, err := ImageTags(tag, image, sha)
			if err != nil {
				t.Fatalf("ImageTags(%s): %v", tag, err)
			}
			if !extra.Prerelease || len(extra.Tags) != 2 {
				t.Fatalf("ImageTags(%s) = %+v", tag, extra)
			}
			assertNoFloatingTags(t, extra.Tags)
		}
	})

	t.Run("stable_tag_moves_latest_and_stable", func(t *testing.T) {
		t.Parallel()
		plan, err := ImageTags("v0.2.0", image, sha)
		if err != nil {
			t.Fatalf("ImageTags: %v", err)
		}
		if plan.Prerelease {
			t.Fatal("prerelease = true, want false")
		}
		want := []string{
			image + ":0.2.0",
			image + ":0.2",
			image + ":latest",
			image + ":stable",
			image + ":sha-" + sha,
		}
		if !slices.Equal(plan.Tags, want) {
			t.Fatalf("tags = %#v, want %#v", plan.Tags, want)
		}
	})

	t.Run("stable_minor_line_is_major_minor", func(t *testing.T) {
		t.Parallel()
		plan, err := ImageTags("v1.4.5", "localhost:5000/minikms", "abcdef0")
		if err != nil {
			t.Fatalf("ImageTags: %v", err)
		}
		want := []string{
			"localhost:5000/minikms:1.4.5",
			"localhost:5000/minikms:1.4",
			"localhost:5000/minikms:latest",
			"localhost:5000/minikms:stable",
			"localhost:5000/minikms:sha-abcdef0",
		}
		if plan.Prerelease || !slices.Equal(plan.Tags, want) {
			t.Fatalf("plan = %+v", plan)
		}
	})

	t.Run("prefixed_v0.1.0_is_stable_tag", func(t *testing.T) {
		t.Parallel()
		plan, err := ImageTags("v0.1.0", image, sha)
		if err != nil {
			t.Fatalf("ImageTags: %v", err)
		}
		if plan.Prerelease || !slices.Contains(plan.Tags, image+":latest") || !slices.Contains(plan.Tags, image+":stable") {
			t.Fatalf("plan = %+v", plan)
		}
	})

	invalid := []struct {
		name string
		tag  string
		img  string
		sha  string
	}{
		{name: "unprefixed_0.1.0", tag: "0.1.0", img: image, sha: sha},
		{name: "missing_patch", tag: "v0.2", img: image, sha: sha},
		{name: "rc_zero", tag: "v0.2.0-rc.0", img: image, sha: sha},
		{name: "leading_zero", tag: "v01.2.3", img: image, sha: sha},
		{name: "empty_tag", tag: "", img: image, sha: sha},
		{name: "empty_image", tag: "v0.2.0", img: "", sha: sha},
		{name: "uppercase_image", tag: "v0.2.0", img: "ghcr.io/EnvSync-Cloud/minikms", sha: sha},
		{name: "image_whitespace", tag: "v0.2.0", img: "ghcr.io/acme/minikms ", sha: sha},
		{name: "short_sha_too_short", tag: "v0.2.0", img: image, sha: "abc123"},
		{name: "short_sha_too_long", tag: "v0.2.0", img: image, sha: strings.Repeat("a", 41)},
		{name: "short_sha_prefix", tag: "v0.2.0", img: image, sha: "sha-abc1234"},
		{name: "empty_sha", tag: "v0.2.0", img: image, sha: ""},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := ImageTags(tc.tag, tc.img, tc.sha); err == nil {
				t.Fatalf("ImageTags(%q, %q, %q) succeeded", tc.tag, tc.img, tc.sha)
			}
		})
	}

	t.Run("uppercase_short_sha_preserved", func(t *testing.T) {
		t.Parallel()
		plan, err := ImageTags("v0.2.0-rc.1", image, "ABCDEF0")
		if err != nil {
			t.Fatalf("ImageTags: %v", err)
		}
		want := image + ":sha-ABCDEF0"
		if !slices.Contains(plan.Tags, want) {
			t.Fatalf("tags = %#v, missing %s", plan.Tags, want)
		}
	})

	t.Run("full_sha_accepted", func(t *testing.T) {
		t.Parallel()
		full := strings.Repeat("ab", 20)
		if _, err := ImageTags("v0.2.0", image, full); err != nil {
			t.Fatalf("ImageTags full sha: %v", err)
		}
	})
}

func TestFormatGitHubOutput(t *testing.T) {
	t.Parallel()

	t.Run("rc_block", func(t *testing.T) {
		t.Parallel()
		plan, err := ImageTags("v0.2.0-rc.1", "ghcr.io/acme/minikms", "abc1234")
		if err != nil {
			t.Fatalf("ImageTags: %v", err)
		}
		got := FormatGitHubOutput(plan)
		want := "" +
			"prerelease=true\n" +
			"tags<<EOF\n" +
			"ghcr.io/acme/minikms:0.2.0-rc.1\n" +
			"ghcr.io/acme/minikms:sha-abc1234\n" +
			"EOF\n"
		if got != want {
			t.Fatalf("output =\n%s\nwant =\n%s", got, want)
		}
	})

	t.Run("stable_block", func(t *testing.T) {
		t.Parallel()
		plan, err := ImageTags("v0.2.0", "ghcr.io/acme/minikms", "abc1234")
		if err != nil {
			t.Fatalf("ImageTags: %v", err)
		}
		got := FormatGitHubOutput(plan)
		want := "" +
			"prerelease=false\n" +
			"tags<<EOF\n" +
			"ghcr.io/acme/minikms:0.2.0\n" +
			"ghcr.io/acme/minikms:0.2\n" +
			"ghcr.io/acme/minikms:latest\n" +
			"ghcr.io/acme/minikms:stable\n" +
			"ghcr.io/acme/minikms:sha-abc1234\n" +
			"EOF\n"
		if got != want {
			t.Fatalf("output =\n%s\nwant =\n%s", got, want)
		}
	})
}

func assertNoFloatingTags(t *testing.T, tags []string) {
	t.Helper()
	for _, tag := range tags {
		base := tag[strings.LastIndex(tag, ":")+1:]
		if base == "latest" || base == "stable" {
			t.Fatalf("tag %q moves latest or stable", tag)
		}
	}
}
