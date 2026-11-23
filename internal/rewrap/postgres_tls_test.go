package rewrap

import (
	"strings"
	"testing"
)

func TestValidateDBTLSMode(t *testing.T) {
	if err := validateDBTLSMode("postgres://db/minikms?sslmode=verify-full"); err != nil {
		t.Fatal(err)
	}
	if err := validateDBTLSMode("postgres://db/minikms?sslmode=disable"); err != nil {
		t.Fatal(err)
	}
	err := validateDBTLSMode("postgres://user:secret@db/minikms?sslmode=prefer")
	if err == nil {
		t.Fatal("prefer was accepted")
	}
	if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "postgres://") {
		t.Fatalf("error included the connection string: %s", err.Error())
	}
}
