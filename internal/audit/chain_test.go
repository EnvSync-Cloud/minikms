package audit

import (
	"context"
	"testing"
	"time"
)

func TestComputeEntryHash(t *testing.T) {
	ts := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	t.Run("deterministic", func(t *testing.T) {
		h1 := ComputeEntryHash(GenesisHash, ts, "encrypt", "user1", "details")
		h2 := ComputeEntryHash(GenesisHash, ts, "encrypt", "user1", "details")
		if h1 != h2 {
			t.Fatal("same inputs should produce same hash")
		}
	})

	t.Run("different inputs differ", func(t *testing.T) {
		h1 := ComputeEntryHash(GenesisHash, ts, "encrypt", "user1", "details1")
		h2 := ComputeEntryHash(GenesisHash, ts, "encrypt", "user1", "details2")
		if h1 == h2 {
			t.Fatal("different inputs should produce different hash")
		}
	})

	t.Run("64 hex chars", func(t *testing.T) {
		h := ComputeEntryHash(GenesisHash, ts, "action", "actor", "details")
		if len(h) != 64 {
			t.Fatalf("hash length: got %d, want 64", len(h))
		}
	})
}

func TestVerifyChainIntegrity(t *testing.T) {
	t.Run("empty chain", func(t *testing.T) {
		valid, idx := VerifyChainIntegrity(nil)
		if !valid {
			t.Fatal("empty chain should be valid")
		}
		if idx != -1 {
			t.Fatalf("index should be -1 for valid chain, got %d", idx)
		}
	})

	t.Run("single entry", func(t *testing.T) {
		ts := time.Now().UTC()
		hash := ComputeEntryHash(GenesisHash, ts, "action", "actor", "details")
		entries := []*AuditEntry{
			{
				PreviousHash: GenesisHash,
				EntryHash:    hash,
				Timestamp:    ts,
				Action:       "action",
				ActorID:      "actor",
				Details:      "details",
			},
		}
		valid, idx := VerifyChainIntegrity(entries)
		if !valid {
			t.Fatalf("single valid entry should be valid, failed at %d", idx)
		}
	})

	t.Run("three entry valid chain", func(t *testing.T) {
		entries := buildChain(3)
		// Reverse for newest-first order
		reversed := make([]*AuditEntry, len(entries))
		for i, e := range entries {
			reversed[len(entries)-1-i] = e
		}
		valid, idx := VerifyChainIntegrity(reversed)
		if !valid {
			t.Fatalf("valid 3-entry chain should pass, failed at %d", idx)
		}
	})

	t.Run("tampered hash detected", func(t *testing.T) {
		entries := buildChain(3)
		reversed := make([]*AuditEntry, len(entries))
		for i, e := range entries {
			reversed[len(entries)-1-i] = e
		}
		reversed[1].EntryHash = "tampered"
		valid, _ := VerifyChainIntegrity(reversed)
		if valid {
			t.Fatal("tampered hash should be detected")
		}
	})

	t.Run("broken linkage detected", func(t *testing.T) {
		entries := buildChain(3)
		reversed := make([]*AuditEntry, len(entries))
		for i, e := range entries {
			reversed[len(entries)-1-i] = e
		}
		reversed[0].PreviousHash = "wrong-link"
		// Recompute the entry hash with wrong previous hash
		reversed[0].EntryHash = ComputeEntryHash(
			"wrong-link", reversed[0].Timestamp, reversed[0].Action, reversed[0].ActorID, reversed[0].Details,
		)
		valid, _ := VerifyChainIntegrity(reversed)
		if valid {
			t.Fatal("broken linkage should be detected")
		}
	})
}

func TestAuditLogger_Log(t *testing.T) {
	store := &mockStore{entries: make(map[string][]*AuditEntry)}
	logger := NewAuditLogger(store)
	ctx := context.Background()

	// First entry uses GenesisHash
	err := logger.Log(ctx, "org1", "encrypt", "user1", "encrypted data", "jwt-hash-1")
	if err != nil {
		t.Fatalf("Log: %v", err)
	}

	entries := store.entries["org1"]
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].PreviousHash != GenesisHash {
		t.Errorf("first entry should have GenesisHash as PreviousHash")
	}
	if entries[0].EntryHash == "" {
		t.Error("entry hash should not be empty")
	}

	// Second entry chains from first
	err = logger.Log(ctx, "org1", "decrypt", "user1", "decrypted data", "jwt-hash-2")
	if err != nil {
		t.Fatalf("Log: %v", err)
	}

	entries = store.entries["org1"]
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[1].PreviousHash != entries[0].EntryHash {
		t.Error("second entry should chain from first")
	}
}

// Helper functions

func buildChain(n int) []*AuditEntry {
	entries := make([]*AuditEntry, n)
	prevHash := GenesisHash
	for i := 0; i < n; i++ {
		ts := time.Now().UTC().Add(time.Duration(i) * time.Second)
		hash := ComputeEntryHash(prevHash, ts, "action", "actor", "details")
		entries[i] = &AuditEntry{
			PreviousHash: prevHash,
			EntryHash:    hash,
			Timestamp:    ts,
			Action:       "action",
			ActorID:      "actor",
			Details:      "details",
		}
		prevHash = hash
	}
	return entries
}

// Simple in-package mock for audit store
type mockStore struct {
	entries map[string][]*AuditEntry
}

func (m *mockStore) GetLatestEntryHash(_ context.Context, orgID string) (string, error) {
	entries := m.entries[orgID]
	if len(entries) == 0 {
		return GenesisHash, nil
	}
	return entries[len(entries)-1].EntryHash, nil
}

func (m *mockStore) InsertEntry(_ context.Context, entry *AuditEntry) error {
	m.entries[entry.OrgID] = append(m.entries[entry.OrgID], entry)
	return nil
}

func (m *mockStore) GetEntries(_ context.Context, orgID string, limit, offset int) ([]*AuditEntry, error) {
	all := m.entries[orgID]
	if offset >= len(all) {
		return nil, nil
	}
	end := offset + limit
	if end > len(all) {
		end = len(all)
	}
	return all[offset:end], nil
}

func (m *mockStore) VerifyChain(_ context.Context, orgID string) (bool, error) {
	entries := m.entries[orgID]
	if len(entries) == 0 {
		return true, nil
	}
	reversed := make([]*AuditEntry, len(entries))
	for i, e := range entries {
		reversed[len(entries)-1-i] = e
	}
	valid, _ := VerifyChainIntegrity(reversed)
	return valid, nil
}
