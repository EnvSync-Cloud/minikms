package memberkey

import (
	"context"
	"strings"
	"testing"
)

func TestNewPostgresStore_InvalidURLOmitsConnectionString(t *testing.T) {
	const token = "db-setting-9f3c2a"
	conn := "postgresql://operator@db/minikms?sslmode=verify-full&password=" + token + "&connect_timeout=not-a-duration"
	_, err := NewPostgresStore(context.Background(), conn)
	if err == nil {
		t.Fatal("expected an invalid connection string to fail")
	}
	msg := err.Error()
	if strings.Contains(msg, token) || strings.Contains(msg, "operator@") || strings.Contains(msg, "password=") || strings.Contains(msg, "connect_timeout") {
		t.Fatal("parse error included connection string details")
	}
	const want = "connect to PostgreSQL: MINIKMS_DB_URL is not a valid connection string"
	if msg != want {
		t.Fatalf("parse error = %q", msg)
	}
}
