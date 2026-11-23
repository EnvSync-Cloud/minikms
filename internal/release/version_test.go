package release

import (
	"errors"
	"math"
	"strconv"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	t.Parallel()

	valid := []struct {
		name string
		in   string
	}{
		{name: "stable_0.2.0", in: "0.2.0"},
		{name: "rc_0.2.0", in: "0.2.0-rc.1"},
		{name: "rc_multi_digit", in: "1.2.3-rc.10"},
		{name: "all_zero_core", in: "0.0.0"},
		{name: "large_component", in: "10.20.30"},
	}
	for _, tc := range valid {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := Parse(tc.in)
			if err != nil {
				t.Fatalf("Parse(%q): %v", tc.in, err)
			}
			if got.String() != tc.in {
				t.Fatalf("Parse(%q) = %s", tc.in, got)
			}
		})
	}

	invalid := []string{
		"",
		"v0.2.0",
		"01.2.3",
		"1.02.3",
		"1.2.03",
		"1.2.3-rc.01",
		"1.2.3-rc.0",
		"1.2",
		"1.2.3.4",
		"1.2.3-alpha",
		"1.2.3-alpha.1",
		"1.2.3-rc",
		"1.2.3-rc.",
		"1.2.3-RC.1",
		"1.2.3+meta",
		"1.2.3-rc.1+meta",
		"0.2.0 ",
		"0.2.0\n",
		"v0.2.0-rc.1",
		"-1.2.3",
		"1.2.3-rc.1.2",
		"0.2.0-",
	}
	for _, in := range invalid {
		t.Run("invalid_"+fixtureName(in), func(t *testing.T) {
			t.Parallel()
			if _, err := Parse(in); err == nil {
				t.Fatalf("Parse(%q) succeeded", in)
			}
		})
	}
}

func TestBump(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		current   string
		spec      string
		want      string
		wantErr   bool
		stableErr bool
	}{
		{name: "start_0.2.0_to_rc1", current: "0.2.0", spec: "rc", want: "0.2.0-rc.1"},
		{name: "rc1_to_rc2", current: "0.2.0-rc.1", spec: "rc", want: "0.2.0-rc.2"},
		{name: "rc9_to_rc10", current: "0.2.0-rc.9", spec: "rc", want: "0.2.0-rc.10"},
		{name: "rc_to_stable_drops_rc", current: "0.2.0-rc.2", spec: "stable", want: "0.2.0"},
		{name: "explicit_set_stable", current: "0.2.0-rc.1", spec: "1.4.5", want: "1.4.5"},
		{name: "explicit_set_rc", current: "0.2.0", spec: "0.3.0-rc.4", want: "0.3.0-rc.4"},
		{name: "explicit_set_same", current: "0.2.0", spec: "0.2.0", want: "0.2.0"},
		{name: "stable_patch", current: "0.2.0", spec: "patch", want: "0.2.1"},
		{name: "stable_minor", current: "0.2.0", spec: "minor", want: "0.3.0"},
		{name: "stable_major", current: "0.2.0", spec: "major", want: "1.0.0"},
		{name: "semver_patch", current: "1.2.3", spec: "patch", want: "1.2.4"},
		{name: "semver_minor", current: "1.2.3", spec: "minor", want: "1.3.0"},
		{name: "semver_major", current: "1.2.3", spec: "major", want: "2.0.0"},
		{name: "rc_patch_does_not_finalize", current: "0.2.0-rc.1", spec: "patch", want: "0.2.1"},
		{name: "rc_minor_bumps_core", current: "0.2.0-rc.1", spec: "minor", want: "0.3.0"},
		{name: "rc_major_bumps_core", current: "0.2.0-rc.4", spec: "major", want: "1.0.0"},
		{name: "stable_on_stable", current: "0.2.0", spec: "stable", wantErr: true, stableErr: true},
		{name: "invalid_spec", current: "0.2.0", spec: "nope", wantErr: true},
		{name: "invalid_spec_case", current: "0.2.0", spec: "RC", wantErr: true},
		{name: "invalid_current", current: "v0.2.0", spec: "patch", wantErr: true},
		{name: "invalid_explicit_leading_zero", current: "0.2.0", spec: "0.2.01", wantErr: true},
		{name: "invalid_explicit_rc_zero", current: "0.2.0", spec: "0.2.0-rc.0", wantErr: true},
		{name: "invalid_explicit_v_prefix", current: "0.2.0", spec: "v0.3.0", wantErr: true},
		{name: "invalid_empty_spec", current: "0.2.0", spec: "", wantErr: true},
	}
	max := strconv.FormatUint(math.MaxUint64, 10)
	tests = append(tests,
		struct {
			name      string
			current   string
			spec      string
			want      string
			wantErr   bool
			stableErr bool
		}{name: "patch_overflow", current: "0.0." + max, spec: "patch", wantErr: true},
		struct {
			name      string
			current   string
			spec      string
			want      string
			wantErr   bool
			stableErr bool
		}{name: "rc_overflow", current: "0.0.1-rc." + max, spec: "rc", wantErr: true},
	)

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := Bump(tc.current, tc.spec)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Bump(%q, %q) = %q, want error", tc.current, tc.spec, got)
				}
				if tc.stableErr && !errors.Is(err, ErrAlreadyStable) {
					t.Fatalf("Bump error = %v, want ErrAlreadyStable", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Bump(%q, %q): %v", tc.current, tc.spec, err)
			}
			if got != tc.want {
				t.Fatalf("Bump(%q, %q) = %q, want %q", tc.current, tc.spec, got, tc.want)
			}
		})
	}
}

func fixtureName(in string) string {
	if in == "" {
		return "empty"
	}
	replacer := strings.NewReplacer(
		" ", "space",
		"\n", "newline",
		".", "_",
		"-", "_",
		"+", "plus",
	)
	return replacer.Replace(in)
}
