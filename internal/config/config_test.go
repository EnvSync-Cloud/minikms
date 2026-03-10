package config

import (
	"os"
	"testing"
)

func TestLoad_Defaults(t *testing.T) {
	// Set only required env vars
	t.Setenv("MINIKMS_DB_URL", "postgres://localhost/test")
	t.Setenv("MINIKMS_REDIS_URL", "redis://localhost:6379/0")
	t.Setenv("MINIKMS_ROOT_KEY", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.GRPCAddr != "0.0.0.0:50051" {
		t.Errorf("GRPCAddr = %q, want %q", cfg.GRPCAddr, "0.0.0.0:50051")
	}
	if cfg.DBUrl != "postgres://localhost/test" {
		t.Errorf("DBUrl = %q, want %q", cfg.DBUrl, "postgres://localhost/test")
	}
	if cfg.RedisURL != "redis://localhost:6379/0" {
		t.Errorf("RedisURL = %q, want %q", cfg.RedisURL, "redis://localhost:6379/0")
	}
	if cfg.TLSEnabled {
		t.Errorf("TLSEnabled = true, want false")
	}
	if cfg.RateLimitPerSecond != 100 {
		t.Errorf("RateLimitPerSecond = %d, want 100", cfg.RateLimitPerSecond)
	}
	if cfg.RateLimitBurst != 200 {
		t.Errorf("RateLimitBurst = %d, want 200", cfg.RateLimitBurst)
	}
	if cfg.MaxEncryptionsPerKey != 1073741824 {
		t.Errorf("MaxEncryptionsPerKey = %d, want 1073741824", cfg.MaxEncryptionsPerKey)
	}
	if cfg.HKDFSalt != "envsync-minikms-v1" {
		t.Errorf("HKDFSalt = %q, want %q", cfg.HKDFSalt, "envsync-minikms-v1")
	}
	if cfg.ShamirTotalShares != 5 {
		t.Errorf("ShamirTotalShares = %d, want 5", cfg.ShamirTotalShares)
	}
	if cfg.ShamirThreshold != 3 {
		t.Errorf("ShamirThreshold = %d, want 3", cfg.ShamirThreshold)
	}
}

func TestLoad_CustomValues(t *testing.T) {
	t.Setenv("MINIKMS_DB_URL", "postgres://custom/db")
	t.Setenv("MINIKMS_REDIS_URL", "redis://custom:6380/1")
	t.Setenv("MINIKMS_ROOT_KEY", "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
	t.Setenv("MINIKMS_GRPC_ADDR", "127.0.0.1:9090")
	t.Setenv("MINIKMS_TLS_ENABLED", "true")
	t.Setenv("MINIKMS_TLS_CERT", "/path/to/cert.pem")
	t.Setenv("MINIKMS_TLS_KEY", "/path/to/key.pem")
	t.Setenv("MINIKMS_RATE_LIMIT_PER_SECOND", "50")
	t.Setenv("MINIKMS_RATE_LIMIT_BURST", "100")
	t.Setenv("MINIKMS_MAX_ENCRYPTIONS_PER_KEY", "500000")
	t.Setenv("MINIKMS_HKDF_SALT", "custom-salt")
	t.Setenv("MINIKMS_SHAMIR_TOTAL_SHARES", "7")
	t.Setenv("MINIKMS_SHAMIR_THRESHOLD", "4")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.GRPCAddr != "127.0.0.1:9090" {
		t.Errorf("GRPCAddr = %q, want %q", cfg.GRPCAddr, "127.0.0.1:9090")
	}
	if !cfg.TLSEnabled {
		t.Errorf("TLSEnabled = false, want true")
	}
	if cfg.TLSCert != "/path/to/cert.pem" {
		t.Errorf("TLSCert = %q, want %q", cfg.TLSCert, "/path/to/cert.pem")
	}
	if cfg.TLSKey != "/path/to/key.pem" {
		t.Errorf("TLSKey = %q, want %q", cfg.TLSKey, "/path/to/key.pem")
	}
	if cfg.RateLimitPerSecond != 50 {
		t.Errorf("RateLimitPerSecond = %d, want 50", cfg.RateLimitPerSecond)
	}
	if cfg.MaxEncryptionsPerKey != 500000 {
		t.Errorf("MaxEncryptionsPerKey = %d, want 500000", cfg.MaxEncryptionsPerKey)
	}
	if cfg.HKDFSalt != "custom-salt" {
		t.Errorf("HKDFSalt = %q, want %q", cfg.HKDFSalt, "custom-salt")
	}
	if cfg.ShamirTotalShares != 7 {
		t.Errorf("ShamirTotalShares = %d, want 7", cfg.ShamirTotalShares)
	}
	if cfg.ShamirThreshold != 4 {
		t.Errorf("ShamirThreshold = %d, want 4", cfg.ShamirThreshold)
	}
}

func TestLoad_MissingRequired(t *testing.T) {
	// Clear all MINIKMS_ env vars
	for _, env := range os.Environ() {
		if len(env) > 8 && env[:8] == "MINIKMS_" {
			key := env
			for i, c := range env {
				if c == '=' {
					key = env[:i]
					break
				}
			}
			os.Unsetenv(key)
		}
	}

	_, err := Load()
	if err == nil {
		t.Fatal("Load() should error when required vars are missing")
	}
}
