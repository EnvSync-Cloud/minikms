package release

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestReleaseBumpWorkflowFile(t *testing.T) {
	t.Parallel()

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	path := filepath.Join(filepath.Dir(file), "..", "..", ".github", "workflows", "release-bump.yml")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read workflow: %v", err)
	}
	text := string(body)
	on := workflowOnBlock(t, text)
	if strings.Contains(text, "pull_request_target") {
		t.Fatal("workflow must not use pull_request_target")
	}
	if !strings.Contains(on, "push:") || !strings.Contains(on, "branches: [dev]") {
		t.Fatalf("on block must push to dev:\n%s", on)
	}
	if !strings.Contains(on, "workflow_dispatch:") {
		t.Fatalf("on block = %q", on)
	}
	if !strings.Contains(text, "group: release-bump-dev") {
		t.Fatal("missing concurrency group release-bump-dev")
	}
	if !strings.Contains(text, "queue: max") {
		t.Fatal("concurrency queue must be max")
	}
	if !strings.Contains(text, "cancel-in-progress: false") {
		t.Fatal("concurrency cancel-in-progress must be false")
	}
	if strings.Contains(text, "cancel-in-progress: true") {
		t.Fatal("concurrency cancel-in-progress must be false")
	}
	guard := workflowNamedStep(t, text, "name: Guard")
	if !strings.Contains(guard, "Release-Version:") {
		t.Fatal("guard does not check the Release-Version marker")
	}
	if !strings.Contains(guard, "bump commit from the release app; skipping") {
		t.Fatal("guard missing the release-app skip notice")
	}
}

func workflowOnBlock(t *testing.T, text string) string {
	t.Helper()
	lines := strings.Split(text, "\n")
	start := -1
	for i, line := range lines {
		if line == "on:" {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatal("workflow has no on: block")
	}
	var b strings.Builder
	b.WriteString(lines[start])
	b.WriteByte('\n')
	for _, line := range lines[start+1:] {
		if line != "" && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			break
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

func workflowNamedStep(t *testing.T, text, nameLine string) string {
	t.Helper()
	idx := strings.Index(text, "\n      - "+nameLine+"\n")
	if idx < 0 {
		t.Fatalf("workflow has no step %s", nameLine)
	}
	rest := text[idx+1:]
	next := strings.Index(rest[1:], "\n      - name:")
	if next < 0 {
		t.Fatalf("step %s has no following step", nameLine)
	}
	return rest[:next+1]
}
