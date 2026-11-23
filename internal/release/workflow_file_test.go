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
	if strings.Contains(on, "push:") {
		t.Fatalf("on block contains a push: trigger:\n%s", on)
	}
	if strings.Contains(text, "push:") {
		t.Fatal("workflow file contains a push: trigger")
	}
	if !strings.Contains(on, "pull_request_target:") || !strings.Contains(on, "workflow_dispatch:") {
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
