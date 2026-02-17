package crypto

import (
	"crypto/rand"
	"fmt"
)

// SplitKey splits a secret key into n shares requiring threshold shares to reconstruct.
// Uses Shamir's Secret Sharing over GF(256) for key escrow / disaster recovery.
func SplitKey(key []byte, totalShares, threshold int) ([][]byte, error) {
	if totalShares < 2 {
		return nil, fmt.Errorf("total shares must be >= 2, got %d", totalShares)
	}
	if threshold < 2 {
		return nil, fmt.Errorf("threshold must be >= 2, got %d", threshold)
	}
	if threshold > totalShares {
		return nil, fmt.Errorf("threshold (%d) must be <= total shares (%d)", threshold, totalShares)
	}
	if len(key) == 0 {
		return nil, fmt.Errorf("key must not be empty")
	}
	if totalShares > 255 {
		return nil, fmt.Errorf("total shares must be <= 255")
	}

	// Each share is: [x-coordinate (1 byte)] || [y-values for each secret byte]
	shares := make([][]byte, totalShares)
	for i := range shares {
		shares[i] = make([]byte, len(key)+1)
		shares[i][0] = byte(i + 1) // x-coordinate (1-indexed)
	}

	// For each byte of the secret, generate a random polynomial and evaluate at each x
	for byteIdx, secretByte := range key {
		// Generate random coefficients for polynomial: f(x) = secret + a1*x + a2*x^2 + ...
		coefficients := make([]byte, threshold)
		coefficients[0] = secretByte
		if _, err := rand.Read(coefficients[1:]); err != nil {
			return nil, fmt.Errorf("failed to generate random coefficients: %w", err)
		}

		// Evaluate polynomial at each x-coordinate
		for i := 0; i < totalShares; i++ {
			x := byte(i + 1)
			shares[i][byteIdx+1] = evaluatePolynomial(coefficients, x)
		}
	}

	return shares, nil
}

// CombineShares reconstructs a secret from a set of Shamir shares.
// Requires at least threshold shares to succeed.
func CombineShares(shares [][]byte) ([]byte, error) {
	if len(shares) < 2 {
		return nil, fmt.Errorf("need at least 2 shares to reconstruct, got %d", len(shares))
	}

	// All shares must be the same length
	shareLen := len(shares[0])
	for i, s := range shares {
		if len(s) != shareLen {
			return nil, fmt.Errorf("share %d has length %d, expected %d", i, len(s), shareLen)
		}
	}

	secretLen := shareLen - 1 // First byte is x-coordinate
	secret := make([]byte, secretLen)

	// Extract x-coordinates
	xCoords := make([]byte, len(shares))
	for i, s := range shares {
		xCoords[i] = s[0]
	}

	// For each byte position, use Lagrange interpolation to recover f(0)
	for byteIdx := 0; byteIdx < secretLen; byteIdx++ {
		yCoords := make([]byte, len(shares))
		for i, s := range shares {
			yCoords[i] = s[byteIdx+1]
		}
		secret[byteIdx] = lagrangeInterpolate(xCoords, yCoords)
	}

	return secret, nil
}

// evaluatePolynomial evaluates a polynomial at x in GF(256).
func evaluatePolynomial(coefficients []byte, x byte) byte {
	result := byte(0)
	xPower := byte(1)

	for _, coeff := range coefficients {
		result = gf256Add(result, gf256Mul(coeff, xPower))
		xPower = gf256Mul(xPower, x)
	}
	return result
}

// lagrangeInterpolate recovers f(0) using Lagrange interpolation in GF(256).
func lagrangeInterpolate(xCoords, yCoords []byte) byte {
	result := byte(0)

	for i := 0; i < len(xCoords); i++ {
		basis := byte(1)
		for j := 0; j < len(xCoords); j++ {
			if i == j {
				continue
			}
			// basis *= x_j / (x_j - x_i) evaluated at x=0
			// At x=0: (0 - x_j) / (x_i - x_j) = x_j / (x_j - x_i)
			num := xCoords[j]
			den := gf256Add(xCoords[j], xCoords[i]) // subtraction = addition in GF(256)
			basis = gf256Mul(basis, gf256Mul(num, gf256Inv(den)))
		}
		result = gf256Add(result, gf256Mul(yCoords[i], basis))
	}
	return result
}

// GF(256) arithmetic using the irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11B)

func gf256Add(a, b byte) byte {
	return a ^ b
}

func gf256Mul(a, b byte) byte {
	var result byte
	for b > 0 {
		if b&1 != 0 {
			result ^= a
		}
		highBit := a & 0x80
		a <<= 1
		if highBit != 0 {
			a ^= 0x1B // reduction by x^8 + x^4 + x^3 + x + 1
		}
		b >>= 1
	}
	return result
}

func gf256Inv(a byte) byte {
	if a == 0 {
		return 0
	}
	// Use Fermat's little theorem: a^(-1) = a^(254) in GF(256)
	result := a
	for i := 0; i < 6; i++ {
		result = gf256Mul(result, result)
		result = gf256Mul(result, a)
	}
	result = gf256Mul(result, result)
	return result
}
