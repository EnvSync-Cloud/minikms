package release

import "testing"

func TestNextRC(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		in      NextInput
		want    string
		wantErr bool
	}{
		{
			name: "bootstrap_first_rc_is_0.2.0-rc.1",
			in: NextInput{
				Version: "0.2.0\n",
				Commits: []string{
					"feat: historical work already reflected in VERSION",
					"fix: historical patch",
				},
			},
			want: "0.2.0-rc.1",
		},
		{
			name: "second_merge_increments_rc",
			in: NextInput{
				Version: "0.2.0",
				RCTags:  []string{"v0.2.0-rc.1"},
				Commits: []string{"fix: typo in a comment"},
			},
			want: "0.2.0-rc.2",
		},
		{
			name: "feat_raises_line_to_next_minor_rc1",
			in: NextInput{
				Version:   "0.2.0-rc.2",
				StableTag: "v0.2.0",
				RCTags:    []string{"v0.2.0-rc.1", "v0.2.0-rc.2"},
				Commits:   []string{"feat(api): export audit events", "fix: nil check"},
			},
			want: "0.3.0-rc.1",
		},
		{
			name: "fix_after_stable_is_patch_rc1",
			in: NextInput{
				Version:   "0.2.0",
				StableTag: "v0.2.0",
				Commits:   []string{"fix(store): reject a nil key"},
			},
			want: "0.2.1-rc.1",
		},
		{
			name: "perf_after_stable_is_patch_rc1",
			in: NextInput{
				Version:   "0.2.0",
				StableTag: "v0.2.0",
				Commits:   []string{"perf(crypto): reuse the cipher"},
			},
			want: "0.2.1-rc.1",
		},
		{
			name: "revert_after_stable_is_patch_rc1",
			in: NextInput{
				Version:   "0.2.0",
				StableTag: "v0.2.0",
				Commits:   []string{"revert: undo the cache change"},
			},
			want: "0.2.1-rc.1",
		},
		{
			name: "breaking_is_major",
			in: NextInput{
				Version:   "0.2.0",
				StableTag: "v0.2.0",
				Commits: []string{
					"refactor: drop the v1 API\n\nBREAKING CHANGE: clients must send the new header",
				},
			},
			want: "1.0.0-rc.1",
		},
		{
			name: "type_bang_is_major",
			in: NextInput{
				Version:   "0.2.0",
				StableTag: "v0.2.0",
				Commits:   []string{"chore!: remove the legacy flag"},
			},
			want: "1.0.0-rc.1",
		},
		{
			name: "breaking_hyphen_footer_is_major",
			in: NextInput{
				Version:   "0.2.0",
				StableTag: "v0.2.0",
				Commits:   []string{"fix: protocol\r\n\r\nBREAKING-CHANGE: frame layout"},
			},
			want: "1.0.0-rc.1",
		},
		{
			name: "chore_after_stable_is_patch_rc1",
			in: NextInput{
				Version:   "0.2.0",
				StableTag: "v0.2.0",
				Commits:   []string{"chore: regenerate protobuf"},
			},
			want: "0.2.1-rc.1",
		},
		{
			name: "label_override_minor",
			in: NextInput{
				Version:   "0.2.0",
				StableTag: "v0.2.0",
				Commits:   []string{"feat!: remove the old api"},
				Label:     "release:minor",
			},
			want: "0.3.0-rc.1",
		},
		{
			name: "never_lowers_line",
			in: NextInput{
				Version:   "0.3.0-rc.1",
				StableTag: "v0.2.0",
				RCTags:    []string{"v0.3.0-rc.1"},
				Commits:   []string{"fix: typo"},
				Label:     "release:patch",
			},
			want: "0.3.0-rc.2",
		},
		{
			name: "legacy_unprefixed_tag_ignored",
			in: NextInput{
				Version:   "0.2.0",
				StableTag: "0.1.0",
				RCTags:    []string{"0.1.0", "0.1.0-rc.3"},
				Commits:   []string{"feat: old history"},
			},
			want: "0.2.0-rc.1",
		},
		{
			name:    "invalid_label",
			in:      NextInput{Version: "0.2.0", Label: "minor"},
			wantErr: true,
		},
		{
			name:    "invalid_version",
			in:      NextInput{Version: "v0.2.0"},
			wantErr: true,
		},
		{
			name:    "rc_tag_is_not_a_stable_tag",
			in:      NextInput{Version: "0.2.0", StableTag: "v0.2.0-rc.1"},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := NextRC(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("NextRC() = %q, want error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("NextRC(): %v", err)
			}
			if got != tc.want {
				t.Fatalf("NextRC() = %q, want %q", got, tc.want)
			}
		})
	}
}
