package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// GenesisHash is the previous_hash for the first entry in the audit chain.
const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// AuditEntry represents a hash-chained audit log entry (Issue #11).
type AuditEntry struct {
	ID            string
	PreviousHash  string
	EntryHash     string
	Timestamp     time.Time
	Action        string
	ActorID       string
	OrgID         string
	Details       string
	RequestJWTHash string // SHA-256 of the JWT used for this request (Issue #12)
}

// AuditStore defines the interface for audit log persistence.
type AuditStore interface {
	// GetLatestEntryHash returns the entry_hash of the most recent audit entry for an org.
	// Returns GenesisHash if no entries exist.
	GetLatestEntryHash(ctx context.Context, orgID string) (string, error)
	// InsertEntry stores a new audit entry.
	InsertEntry(ctx context.Context, entry *AuditEntry) error
	// GetEntries returns audit entries for an org, ordered by timestamp desc.
	GetEntries(ctx context.Context, orgID string, limit, offset int) ([]*AuditEntry, error)
	// VerifyChain verifies the hash chain integrity for an org.
	VerifyChain(ctx context.Context, orgID string) (bool, error)
}

// AuditLogger creates hash-chained audit log entries.
type AuditLogger struct {
	store AuditStore
}

// NewAuditLogger creates a new AuditLogger.
func NewAuditLogger(store AuditStore) *AuditLogger {
	return &AuditLogger{store: store}
}

// Log creates a new hash-chained audit entry.
// entry_hash = SHA256(previous_hash || timestamp || action || actor_id || details)
func (l *AuditLogger) Log(ctx context.Context, orgID, action, actorID, details, requestJWTHash string) error {
	previousHash, err := l.store.GetLatestEntryHash(ctx, orgID)
	if err != nil {
		return fmt.Errorf("failed to get latest entry hash: %w", err)
	}
	if previousHash == "" {
		previousHash = GenesisHash
	}

	now := time.Now().UTC()
	entryHash := ComputeEntryHash(previousHash, now, action, actorID, details)

	entry := &AuditEntry{
		PreviousHash:   previousHash,
		EntryHash:      entryHash,
		Timestamp:      now,
		Action:         action,
		ActorID:        actorID,
		OrgID:          orgID,
		Details:        details,
		RequestJWTHash: requestJWTHash,
	}

	if err := l.store.InsertEntry(ctx, entry); err != nil {
		return fmt.Errorf("failed to insert audit entry: %w", err)
	}

	return nil
}

// ComputeEntryHash computes the hash for an audit entry.
// hash = SHA256(previous_hash + timestamp + action + actor_id + details)
func ComputeEntryHash(previousHash string, timestamp time.Time, action, actorID, details string) string {
	data := previousHash + timestamp.Format(time.RFC3339Nano) + action + actorID + details
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}

// VerifyChainIntegrity verifies the hash chain integrity for audit entries.
func VerifyChainIntegrity(entries []*AuditEntry) (bool, int) {
	for i := len(entries) - 1; i >= 0; i-- {
		expected := ComputeEntryHash(
			entries[i].PreviousHash,
			entries[i].Timestamp,
			entries[i].Action,
			entries[i].ActorID,
			entries[i].Details,
		)
		if expected != entries[i].EntryHash {
			return false, i
		}

		// Verify chain linkage (except for the oldest entry)
		if i < len(entries)-1 {
			if entries[i].PreviousHash != entries[i+1].EntryHash {
				return false, i
			}
		}
	}
	return true, -1
}
