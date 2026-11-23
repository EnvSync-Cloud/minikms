//go:build !unix

package main

// ignoreSIGPIPE is a no-op where the platform has no SIGPIPE.
// A closed pipe write already returns an error on these systems.
func ignoreSIGPIPE() {}
