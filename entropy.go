package passval

import (
	"math"
	"unicode"
)

// calculateEntropy computes the Shannon entropy bits of a password
// based on the character pool size and length.
func calculateEntropy(password string) float64 {
	if len(password) == 0 {
		return 0
	}

	poolSize := effectivePoolSize(password)
	if poolSize <= 1 {
		return 0
	}

	// Entropy = length * log2(poolSize)
	return float64(len(password)) * math.Log2(float64(poolSize))
}

// effectivePoolSize determines the character pool based on what types
// of characters are actually present in the password.
func effectivePoolSize(password string) int {
	hasLower := false
	hasUpper := false
	hasDigit := false
	hasSymbol := false

	for _, r := range password {
		switch {
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsDigit(r):
			hasDigit = true
		default:
			hasSymbol = true
		}
	}

	pool := 0
	if hasLower {
		pool += 26
	}
	if hasUpper {
		pool += 26
	}
	if hasDigit {
		pool += 10
	}
	if hasSymbol {
		pool += 33 // common printable symbols
	}
	return pool
}

// entropyToScore maps entropy bits to a 0-100 score using a logarithmic curve
// with diminishing returns after ~60 bits.
//
// Curve: score = 100 * (1 - e^(-entropy / k))
// where k controls the inflection point. With k=40:
//   - 20 bits  → ~39
//   - 40 bits  → ~63
//   - 60 bits  → ~78
//   - 80 bits  → ~86
//   - 100 bits → ~92
//   - 128 bits → ~96
func entropyToScore(entropy float64) int {
	if entropy <= 0 {
		return 0
	}

	const k = 40.0 // controls curve shape — lower = faster saturation

	score := 100.0 * (1.0 - math.Exp(-entropy/k))

	s := int(math.Round(score))
	if s > 100 {
		s = 100
	}
	if s < 0 {
		s = 0
	}
	return s
}
