package crypto

import (
	"bytes"
	"testing"
)

func TestShamirSplitCombine(t *testing.T) {
	tests := []struct {
		name      string
		keyLen    int
		total     int
		threshold int
	}{
		{"3-of-5 32-byte key", 32, 5, 3},
		{"2-of-3 32-byte key", 32, 3, 2},
		{"5-of-5 32-byte key", 32, 5, 5},
		{"3-of-5 single byte", 1, 5, 3},
		{"3-of-5 64-byte key", 64, 5, 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := make([]byte, tt.keyLen)
			for i := range key {
				key[i] = byte(i + 1)
			}

			shares, err := SplitKey(key, tt.total, tt.threshold)
			if err != nil {
				t.Fatalf("SplitKey: %v", err)
			}

			if len(shares) != tt.total {
				t.Fatalf("got %d shares, want %d", len(shares), tt.total)
			}

			// Use exactly threshold shares to reconstruct
			reconstructed, err := CombineShares(shares[:tt.threshold])
			if err != nil {
				t.Fatalf("CombineShares: %v", err)
			}

			if !bytes.Equal(reconstructed, key) {
				t.Fatalf("reconstructed key doesn't match original")
			}
		})
	}
}

func TestShamirSplitCombine_AllSubsets(t *testing.T) {
	key := []byte("test-secret-key!")
	shares, err := SplitKey(key, 5, 3)
	if err != nil {
		t.Fatalf("SplitKey: %v", err)
	}

	// Test all C(5,3) = 10 subsets
	for i := 0; i < 5; i++ {
		for j := i + 1; j < 5; j++ {
			for k := j + 1; k < 5; k++ {
				subset := [][]byte{shares[i], shares[j], shares[k]}
				reconstructed, err := CombineShares(subset)
				if err != nil {
					t.Fatalf("CombineShares(%d,%d,%d): %v", i, j, k, err)
				}
				if !bytes.Equal(reconstructed, key) {
					t.Errorf("subset (%d,%d,%d) failed to reconstruct", i, j, k)
				}
			}
		}
	}
}

func TestSplitKey_Errors(t *testing.T) {
	key := make([]byte, 32)

	tests := []struct {
		name      string
		key       []byte
		total     int
		threshold int
	}{
		{"totalShares < 2", key, 1, 1},
		{"threshold < 2", key, 5, 1},
		{"threshold > total", key, 3, 5},
		{"empty key", []byte{}, 5, 3},
		{"totalShares > 255", key, 256, 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := SplitKey(tt.key, tt.total, tt.threshold)
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestGF256Arithmetic(t *testing.T) {
	t.Run("add is XOR", func(t *testing.T) {
		if gf256Add(0x53, 0xCA) != (0x53 ^ 0xCA) {
			t.Fatal("add should be XOR")
		}
	})

	t.Run("add self is zero", func(t *testing.T) {
		if gf256Add(0x42, 0x42) != 0 {
			t.Fatal("a + a should be 0 in GF(256)")
		}
	})

	t.Run("mul identity", func(t *testing.T) {
		for a := byte(0); a < 255; a++ {
			if gf256Mul(a, 1) != a {
				t.Fatalf("a * 1 should be a, got %d for a=%d", gf256Mul(a, 1), a)
			}
		}
	})

	t.Run("mul zero", func(t *testing.T) {
		for a := byte(0); a < 255; a++ {
			if gf256Mul(a, 0) != 0 {
				t.Fatalf("a * 0 should be 0 for a=%d", a)
			}
		}
	})

	t.Run("inverse", func(t *testing.T) {
		for a := byte(1); a != 0; a++ {
			inv := gf256Inv(a)
			if gf256Mul(a, inv) != 1 {
				t.Fatalf("a * inv(a) should be 1 for a=%d, inv=%d, got %d", a, inv, gf256Mul(a, inv))
			}
		}
	})

	t.Run("inv(0) is 0", func(t *testing.T) {
		if gf256Inv(0) != 0 {
			t.Fatal("inv(0) should be 0")
		}
	})
}
