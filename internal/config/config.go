package config

import "github.com/kelseyhightower/envconfig"

// Config holds all miniKMS configuration loaded from environment variables.
type Config struct {
	GRPCAddr    string `envconfig:"MINIKMS_GRPC_ADDR" default:"0.0.0.0:50051"`
	DBUrl       string `envconfig:"MINIKMS_DB_URL" required:"true"`
	RedisURL    string `envconfig:"MINIKMS_REDIS_URL" required:"true"`
	RootKey     string `envconfig:"MINIKMS_ROOT_KEY"`
	RootKeyFile string `envconfig:"MINIKMS_ROOT_KEY_FILE"`

	// Session JWT signing key sources. Source selection and key validation are
	// handled by the auth loader.
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

	// Escrow is opt-in because its seal key must come from an independent HSM or
	// secret-manager entry, never from the root key being protected.
	EscrowEnabled     bool   `envconfig:"MINIKMS_ESCROW_ENABLED" default:"false"`
	EscrowSealKey     string `envconfig:"MINIKMS_ESCROW_SEAL_KEY"`
	EscrowSealKeyFile string `envconfig:"MINIKMS_ESCROW_SEAL_KEY_FILE"`
	EscrowCustodians  string `envconfig:"MINIKMS_ESCROW_CUSTODIANS" default:"custodian-1,custodian-2,custodian-3,custodian-4,custodian-5"`
}

// Load reads config from environment variables.
func Load() (*Config, error) {
	var cfg Config
	if err := envconfig.Process("", &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
