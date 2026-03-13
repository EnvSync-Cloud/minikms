// Package main demonstrates basic miniKMS cryptographic operations
// without requiring any external dependencies (no DB, no Redis).
package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/envsync-cloud/minikms/internal/crypto"
	"github.com/envsync-cloud/minikms/internal/keys"
)

func main() {
	fmt.Println("=== miniKMS Basic Encrypt/Decrypt Demo ===")
	fmt.Println()

	// 1. Generate and load a root key
	rootKey, err := crypto.GenerateKey()
	if err != nil {
		log.Fatalf("Failed to generate root key: %v", err)
	}
	rootKeyHex := hex.EncodeToString(rootKey)
	fmt.Printf("1. Generated root key: %s...%s\n", rootKeyHex[:8], rootKeyHex[56:])

	holder := keys.NewRootKeyHolder()
	if err := holder.Load(rootKeyHex); err != nil {
		log.Fatalf("Failed to load root key: %v", err)
	}
	fmt.Println("   Root key loaded into RootKeyHolder")

	// 2. Derive org master key via HKDF
	orgID := "org-acme-corp"
	orgKey, err := crypto.DeriveOrgMasterKey(rootKey, orgID)
	if err != nil {
		log.Fatalf("Failed to derive org key: %v", err)
	}
	fmt.Printf("2. Derived org master key for %q: %s...\n", orgID, hex.EncodeToString(orgKey[:8]))

	// Show determinism: same inputs = same key
	orgKey2, _ := crypto.DeriveOrgMasterKey(rootKey, orgID)
	fmt.Printf("   Deterministic check: %v\n", hex.EncodeToString(orgKey) == hex.EncodeToString(orgKey2))

	// 3. Generate a DEK and encrypt/decrypt data
	dek, err := crypto.GenerateKey()
	if err != nil {
		log.Fatalf("Failed to generate DEK: %v", err)
	}
	fmt.Printf("3. Generated DEK: %s...\n", hex.EncodeToString(dek[:8]))

	plaintext := []byte("DATABASE_URL=postgres://user:s3cret@db:5432/myapp")
	aad := []byte(orgID + ":app-backend:production:DATABASE_URL")
	fmt.Printf("   Plaintext: %q\n", string(plaintext))
	fmt.Printf("   AAD: %q\n", string(aad))

	ciphertext, err := crypto.Encrypt(dek, plaintext, aad)
	if err != nil {
		log.Fatalf("Encrypt failed: %v", err)
	}
	fmt.Printf("   Ciphertext: %s... (%d bytes)\n", hex.EncodeToString(ciphertext[:16]), len(ciphertext))

	decrypted, err := crypto.Decrypt(dek, ciphertext, aad)
	if err != nil {
		log.Fatalf("Decrypt failed: %v", err)
	}
	fmt.Printf("   Decrypted: %q\n", string(decrypted))
	fmt.Printf("   Roundtrip OK: %v\n", string(decrypted) == string(plaintext))

	// 4. Envelope encryption: wrap DEK with org master key
	fmt.Println()
	fmt.Println("4. Envelope Encryption (wrapping DEK with org master key)")
	wrappedDEK, err := crypto.Encrypt(orgKey, dek, []byte("dek:"+orgID))
	if err != nil {
		log.Fatalf("Failed to wrap DEK: %v", err)
	}
	fmt.Printf("   Wrapped DEK: %s... (%d bytes)\n", hex.EncodeToString(wrappedDEK[:16]), len(wrappedDEK))

	unwrappedDEK, err := crypto.Decrypt(orgKey, wrappedDEK, []byte("dek:"+orgID))
	if err != nil {
		log.Fatalf("Failed to unwrap DEK: %v", err)
	}
	fmt.Printf("   Unwrap OK: %v\n", hex.EncodeToString(unwrappedDEK) == hex.EncodeToString(dek))

	// 5. Shamir Secret Sharing of root key
	fmt.Println()
	fmt.Println("5. Shamir Secret Sharing (3-of-5 split of root key)")
	shares, err := crypto.SplitKey(rootKey, 5, 3)
	if err != nil {
		log.Fatalf("SplitKey failed: %v", err)
	}
	for i, share := range shares {
		fmt.Printf("   Share %d: %s... (%d bytes)\n", i+1, hex.EncodeToString(share[:8]), len(share))
	}

	// Reconstruct with shares 1, 3, 5
	subset := [][]byte{shares[0], shares[2], shares[4]}
	reconstructed, err := crypto.CombineShares(subset)
	if err != nil {
		log.Fatalf("CombineShares failed: %v", err)
	}
	fmt.Printf("   Reconstructed from shares {1,3,5}: %v\n",
		hex.EncodeToString(reconstructed) == rootKeyHex)

	// Reconstruct with shares 2, 4, 5
	subset2 := [][]byte{shares[1], shares[3], shares[4]}
	reconstructed2, err := crypto.CombineShares(subset2)
	if err != nil {
		log.Fatalf("CombineShares failed: %v", err)
	}
	fmt.Printf("   Reconstructed from shares {2,4,5}: %v\n",
		hex.EncodeToString(reconstructed2) == rootKeyHex)

	fmt.Println()
	fmt.Println("=== Demo Complete ===")
}
