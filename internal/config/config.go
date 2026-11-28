package config

import (
	"fmt"

	"github.com/kelseyhightower/envconfig"
)

// Config holds all miniKMS configuration loaded from environment variables.
type Config struct {
	GRPCAddr       string `envconfig:"MINIKMS_GRPC_ADDR" default:"0.0.0.0:50051"`
	DBUrl          string `envconfig:"MINIKMS_DB_URL" required:"true"`
	RedisURL       string `envconfig:"MINIKMS_REDIS_URL" required:"true"`
	RootKey        string `envconfig:"MINIKMS_ROOT_KEY"`
	RootKeyFile    string `envconfig:"MINIKMS_ROOT_KEY_FILE"`
	RootCACert     string `envconfig:"MINIKMS_ROOT_CA_CERT"`
	RootCACertFile string `envconfig:"MINIKMS_ROOT_CA_CERT_FILE"`
	RootCAKey      string `envconfig:"MINIKMS_ROOT_CA_KEY"`
	RootCAKeyFile  string `envconfig:"MINIKMS_ROOT_CA_KEY_FILE"`

	// Session JWT signing key sources. Source selection and key validation are
	// handled by the auth loader.
	SessionSigningKey     string `envconfig:"MINIKMS_SESSION_SIGNING_KEY"`
	SessionSigningKeyFile string `envconfig:"MINIKMS_SESSION_SIGNING_KEY_FILE"`

	TLSEnabled bool `envconfig:"MINIKMS_TLS_ENABLED" default:"false"`
	// AllowInsecure permits a plaintext listener for local development only.
	AllowInsecure bool `envconfig:"MINIKMS_ALLOW_INSECURE" default:"false"`
	// ReflectionEnabled registers gRPC server reflection when explicitly set.
	ReflectionEnabled bool   `envconfig:"MINIKMS_REFLECTION_ENABLED" default:"false"`
	TLSCert           string `envconfig:"MINIKMS_TLS_CERT"`
	TLSKey            string `envconfig:"MINIKMS_TLS_KEY"`
	TLSCAFile         string `envconfig:"MINIKMS_TLS_CA_FILE"`

	// Rate limiting
	RateLimitPerSecond int `envconfig:"MINIKMS_RATE_LIMIT_PER_SECOND" default:"100"`
	RateLimitBurst     int `envconfig:"MINIKMS_RATE_LIMIT_BURST" default:"200"`

	// Key rotation
	MaxEncryptionsPerKey int64 `envconfig:"MINIKMS_MAX_ENCRYPTIONS_PER_KEY" default:"1073741824"` // 2^30

	// HKDF salt for key derivation (override to make miniKMS instance-specific)
	HKDFSalt string `envconfig:"MINIKMS_HKDF_SALT" default:"envsync-minikms-v1"`

	// MemberKeyLegacyRead allows opening managed member key rows that are not yet
	// stored as member-key envelopes. It stays enabled until the wrap-member-keys
	// backfill check passes.
	// TODO: remove the legacy member-key read path after the member-key wrap backfill check passes.
	MemberKeyLegacyRead bool `envconfig:"MINIKMS_MEMBER_KEY_LEGACY_READ" default:"true"`

	// Shamir defaults
	ShamirTotalShares int `envconfig:"MINIKMS_SHAMIR_TOTAL_SHARES" default:"5"`
	ShamirThreshold   int `envconfig:"MINIKMS_SHAMIR_THRESHOLD" default:"3"`

	// Escrow is opt-in because its seal key must come from an independent HSM or
	// secret-manager entry, never from the root key being protected.
	EscrowEnabled     bool   `envconfig:"MINIKMS_ESCROW_ENABLED" default:"false"`
	EscrowSealKey     string `envconfig:"MINIKMS_ESCROW_SEAL_KEY"`
	EscrowSealKeyFile string `envconfig:"MINIKMS_ESCROW_SEAL_KEY_FILE"`
	EscrowCustodians  string `envconfig:"MINIKMS_ESCROW_CUSTODIANS" default:"custodian-1,custodian-2,custodian-3,custodian-4,custodian-5"`

	// Forwarded-proof check. off is the standalone default. monitor and enforce
	// require the issuer, JWKS, audience, and allowed htu origins.
	DPoPMode              string `envconfig:"MINIKMS_DPOP_MODE" default:"off"`
	DPoPIssuer            string `envconfig:"MINIKMS_DPOP_ISSUER"`
	DPoPJWKSURL           string `envconfig:"MINIKMS_DPOP_JWKS_URL"`
	DPoPAudience          string `envconfig:"MINIKMS_DPOP_AUDIENCE"`
	DPoPAllowedHTUOrigins string `envconfig:"MINIKMS_DPOP_ALLOWED_HTU_ORIGINS"`
	DPoPMaxProofAgeSec    int    `envconfig:"MINIKMS_DPOP_MAX_PROOF_AGE_SEC" default:"60"`
	DPoPMaxCallsPerProof  int    `envconfig:"MINIKMS_DPOP_MAX_CALLS_PER_PROOF" default:"16"`
}

// Load reads config from environment variables.
func Load() (*Config, error) {
	var cfg Config
	if err := envconfig.Process("", &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// MayServePlaintext reports whether the process may listen without TLS.
// Plaintext is allowed only when AllowInsecure is set and TLS is disabled.
// Startup without TLS and without AllowInsecure fails this check.
func (c Config) MayServePlaintext() bool {
	return !c.TLSEnabled && c.AllowInsecure
}

// ValidateDPoP rejects a monitor or enforce floor that cannot verify tokens.
func (c Config) ValidateDPoP() error {
	switch c.DPoPMode {
	case "", "off":
		return nil
	case "monitor", "enforce":
		if c.DPoPIssuer == "" || c.DPoPJWKSURL == "" || c.DPoPAudience == "" || c.DPoPAllowedHTUOrigins == "" {
			return fmt.Errorf("MINIKMS_DPOP_MODE=%s requires MINIKMS_DPOP_ISSUER, MINIKMS_DPOP_JWKS_URL, MINIKMS_DPOP_AUDIENCE, and MINIKMS_DPOP_ALLOWED_HTU_ORIGINS", c.DPoPMode)
		}
		if c.DPoPMaxProofAgeSec <= 0 || c.DPoPMaxCallsPerProof <= 0 {
			return fmt.Errorf("dpop freshness window and call budget must be positive")
		}
		return nil
	default:
		return fmt.Errorf("MINIKMS_DPOP_MODE must be off, monitor, or enforce")
	}
}
