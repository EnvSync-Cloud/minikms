package memberkey

import "testing"

func TestValidateDBTLSMode(t *testing.T) {
	for _, conn := range []string{
		"postgres://db/minikms?sslmode=verify-full",
		"host=db sslmode=disable",
		"postgres://db/minikms?sslmode=verify-ca",
	} {
		if err := validateDBTLSMode(conn); err != nil {
			t.Fatalf("%s: %v", conn, err)
		}
	}
	for _, conn := range []string{
		"postgres://db/minikms",
		"postgres://db/minikms?sslmode=prefer",
		"postgres://db/minikms?sslmode=require",
	} {
		if err := validateDBTLSMode(conn); err == nil {
			t.Fatalf("%s was accepted", conn)
		}
	}
}
