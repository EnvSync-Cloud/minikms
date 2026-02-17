package keys

import (
	"encoding/hex"
	"fmt"
	"sync"
)

// RootKeyHolder is the ONLY component that has access to the root key.
// It is loaded once at startup from environment/HSM and held in memory.
// No other component should ever access the root key directly.
type RootKeyHolder struct {
	mu      sync.RWMutex
	rootKey []byte
	loaded  bool
}

var (
	instance *RootKeyHolder
	once     sync.Once
)

// NewRootKeyHolder creates a new RootKeyHolder instance (for testing).
// Production code should use GetRootKeyHolder() for the singleton.
func NewRootKeyHolder() *RootKeyHolder {
	return &RootKeyHolder{}
}

// GetRootKeyHolder returns the singleton RootKeyHolder instance.
func GetRootKeyHolder() *RootKeyHolder {
	once.Do(func() {
		instance = &RootKeyHolder{}
	})
	return instance
}

// Load initializes the root key from a hex-encoded string (from env var or HSM).
// This must be called exactly once at startup.
func (h *RootKeyHolder) Load(rootKeyHex string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.loaded {
		return fmt.Errorf("root key already loaded")
	}

	key, err := hex.DecodeString(rootKeyHex)
	if err != nil {
		return fmt.Errorf("invalid root key hex: %w", err)
	}

	if len(key) != 32 {
		return fmt.Errorf("root key must be 32 bytes (256-bit), got %d bytes", len(key))
	}

	h.rootKey = key
	h.loaded = true
	return nil
}

// GetKey returns a copy of the root key. Only internal key derivation functions
// should call this — never expose to external callers.
func (h *RootKeyHolder) GetKey() ([]byte, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if !h.loaded {
		return nil, fmt.Errorf("root key not loaded")
	}

	// Return a copy to prevent external mutation
	keyCopy := make([]byte, len(h.rootKey))
	copy(keyCopy, h.rootKey)
	return keyCopy, nil
}

// IsLoaded returns whether the root key has been loaded.
func (h *RootKeyHolder) IsLoaded() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.loaded
}
