package crypto

import "fmt"

// DefaultMaxEncryptions is the default limit before mandatory key rotation (2^30).
const DefaultMaxEncryptions int64 = 1 << 30

// KeyStatus represents the lifecycle state of a key version.
type KeyStatus string

const (
	KeyStatusActive        KeyStatus = "active"
	KeyStatusRotatePending KeyStatus = "rotate_pending"
	KeyStatusRetired       KeyStatus = "retired"
)

// CheckEncryptionCount evaluates whether a key version needs rotation based on
// its current encryption count and the configured maximum.
func CheckEncryptionCount(currentCount, maxEncryptions int64) (KeyStatus, error) {
	if currentCount < 0 {
		return "", fmt.Errorf("encryption count cannot be negative")
	}
	if maxEncryptions <= 0 {
		return "", fmt.Errorf("max encryptions must be positive")
	}

	if currentCount >= maxEncryptions {
		return KeyStatusRetired, nil
	}

	// At 90% of max, signal rotation is pending
	threshold := int64(float64(maxEncryptions) * 0.9)
	if currentCount >= threshold {
		return KeyStatusRotatePending, nil
	}

	return KeyStatusActive, nil
}
