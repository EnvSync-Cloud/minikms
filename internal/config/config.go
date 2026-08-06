package config

import (
	"fmt"

	"github.com/kelseyhightower/envconfig"
)

// Config holds all miniKMS configuration loaded from environment variables.
type Config struct {
	GRPCAddr string `envconfig:"MINIKMS_GRPC_ADDR" default:"0.0.0.0:50051"`
	DBUrl    string `envconfig:"MINIKMS_DB_URL" required:"true"`
	RedisURL string `envconfig:"MINIKMS_REDIS_URL" required:"true"`
	RootKey  string `envconfig:"MINIKMS_ROOT_KEY" required:"true"`

	// Session JWT signing key. Configure exactly one source. The direct value
	// must contain PEM; the file variant is recommended for production secrets.
	SessionSigningKey     string `envconfig:"MINIKMS_SESSION_SIGNING_KEY"`
	SessionSigningKeyFile string `envconfig:"MINIKMS_SESSION_SIGNING_KEY_FILE"`

	TLSEnabled bool   `envconfig:"MINIKMS_TLS_ENABLED" default:"false"`
	TLSCert    string `envconfig:"MINIKMS_TLS_CERT"`
	TLSKey     string `envconfig:"MINIKMS_TLS_KEY"`

	// Rate limiting
	RateLimitPerSecond int `envconfig:"MINIKMS_RATE_LIMIT_PER_SECOND" default:"100"`
	RateLimitBurst     int `envconfig:"MINIKMS_RATE_LIMIT_BURST" default:"200"`

	// Key rotation
	MaxEncryptionsPerKey int64 `envconfig:"MINIKMS_MAX_ENCRYPTIONS_PER_KEY" default:"1073741824"` // 2^30

	// HKDF salt for key derivation (override to make miniKMS instance-specific)
	HKDFSalt string `envconfig:"MINIKMS_HKDF_SALT" default:"envsync-minikms-v1"`

	// Shamir defaults
	ShamirTotalShares int `envconfig:"MINIKMS_SHAMIR_TOTAL_SHARES" default:"5"`
	ShamirThreshold   int `envconfig:"MINIKMS_SHAMIR_THRESHOLD" default:"3"`
}

// Load reads config from environment variables.
func Load() (*Config, error) {
	var cfg Config
	if err := envconfig.Process("", &cfg); err != nil {
		return nil, err
	}
	if cfg.SessionSigningKey == "" && cfg.SessionSigningKeyFile == "" {
		return nil, fmt.Errorf("one of MINIKMS_SESSION_SIGNING_KEY or MINIKMS_SESSION_SIGNING_KEY_FILE is required")
	}
	if cfg.SessionSigningKey != "" && cfg.SessionSigningKeyFile != "" {
		return nil, fmt.Errorf("MINIKMS_SESSION_SIGNING_KEY and MINIKMS_SESSION_SIGNING_KEY_FILE are mutually exclusive")
	}
	return &cfg, nil
}
