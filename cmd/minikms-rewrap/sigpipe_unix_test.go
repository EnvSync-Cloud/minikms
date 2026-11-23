//go:build unix

package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"testing"
)

func TestClosedStdoutReturnsEPIPE(t *testing.T) {
	if os.Getenv("MINIKMS_REWRAP_SIGPIPE_CHILD") == "1" {
		ignoreSIGPIPE()
		_, err := os.Stdout.Write([]byte("mode=commit orgs=0\n"))
		if errors.Is(err, syscall.EPIPE) {
			os.Exit(0)
		}
		_, _ = fmt.Fprintf(os.Stderr, "write err=%v\n", err)
		os.Exit(2)
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestClosedStdoutReturnsEPIPE$")
	cmd.Env = append(os.Environ(), "MINIKMS_REWRAP_SIGPIPE_CHILD=1")
	cmd.Stdout = w
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err = cmd.Run()
	if cerr := w.Close(); cerr != nil {
		t.Fatalf("close pipe: %v", cerr)
	}
	if err != nil {
		if len(stderr.Bytes()) > 0 {
			t.Fatalf("closed stdout killed the process or write failed: %v stderr=%s", err, stderr.Bytes())
		}
		t.Fatalf("closed stdout killed the process or write failed: %v", err)
	}
}
