//go:build !unix

package main

// ignoreSIGPIPE is a no-op where the platform has no SIGPIPE.
func ignoreSIGPIPE() {}
