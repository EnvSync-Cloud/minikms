//go:build unix

package main

import (
	"os/signal"
	"syscall"
)

// ignoreSIGPIPE stops a closed stdout or stderr from killing the process.
// The write returns EPIPE, so a committed rewrap still reports
// ErrCommittedReportFailed. Successful writes are unchanged.
func ignoreSIGPIPE() {
	signal.Ignore(syscall.SIGPIPE)
}
