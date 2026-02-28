package passval

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
	"unicode"
)

// PenaltyDetail describes a single penalty applied during validation.
type PenaltyDetail struct {
	Rule   string  // e.g. "repeated_chars", "common_password", "keyboard_pattern"
	Factor float64 // multiplicative factor applied (e.g. 0.5)
	Desc   string  // human-readable description
}

// ValidationError holds all penalty details when validation fails or penalties are applied.
type ValidationError struct {
	Penalties []PenaltyDetail
	RuleFails []string // e.g. "missing uppercase", "too short"
}

func (e *ValidationError) Error() string {
	var parts []string
	for _, r := range e.RuleFails {
		parts = append(parts, fmt.Sprintf("rule: %s", r))
	}
	for _, p := range e.Penalties {
		parts = append(parts, fmt.Sprintf("penalty(%s, x%.2f): %s", p.Rule, p.Factor, p.Desc))
	}
	return strings.Join(parts, "; ")
}

// PasswordValidator holds the configuration for password validation and generation.
type PasswordValidator struct {
	MinLength      int
	MaxLength      int
	RequireLower   bool
	RequireUpper   bool
	RequireNumbers bool
	RequireSymbols bool
	Complexity     int // minimum complexity score 0-100

	dict *dictionary
}

// NewPasswordValidator creates a new validator with the given rules.
// complexity is the minimum acceptable score on a 0-100 scale.
func NewPasswordValidator(min, max int, lower, upper, numbers, symbols bool, complexity int) *PasswordValidator {
	return NewPasswordValidatorWithDict(min, max, lower, upper, numbers, symbols, complexity, "")
}

// NewPasswordValidatorWithDict creates a new validator with custom dictionary data.
// If customDict is empty, uses the embedded sample dictionary.
// customDict should be a string with one password per line.
func NewPasswordValidatorWithDict(min, max int, lower, upper, numbers, symbols bool, complexity int, customDict string) *PasswordValidator {
	if complexity < 0 {
		complexity = 0
	}
	if complexity > 100 {
		complexity = 100
	}
	if min < 1 {
		min = 1
	}
	if max < min {
		max = min
	}

	var dict *dictionary
	if customDict != "" {
		dict = loadDictionary(customDict)
	} else {
		dict = globalDict
	}

	v := &PasswordValidator{
		MinLength:      min,
		MaxLength:      max,
		RequireLower:   lower,
		RequireUpper:   upper,
		RequireNumbers: numbers,
		RequireSymbols: symbols,
		Complexity:     complexity,
		dict:           dict,
	}
	return v
}

// Validate returns whether the password passes all rules and the computed complexity score (0-100).
func (v *PasswordValidator) Validate(password string) (bool, int) {
	pass, score, _ := v.validate(password)
	return pass, score
}

// ValidateVerbose returns pass/fail, the complexity score, and a *ValidationError
// detailing which rules failed and which penalties were applied.
// error is nil only if the password passes all rules AND meets the complexity threshold.
func (v *PasswordValidator) ValidateVerbose(password string) (bool, int, error) {
	pass, score, vErr := v.validate(password)
	if pass {
		return true, score, nil
	}
	return false, score, vErr
}

func (v *PasswordValidator) validate(password string) (bool, int, *ValidationError) {
	vErr := &ValidationError{}

	// --- Rule checks ---
	if len(password) < v.MinLength {
		vErr.RuleFails = append(vErr.RuleFails, fmt.Sprintf("too short: minimum %d characters", v.MinLength))
	}
	if len(password) > v.MaxLength {
		vErr.RuleFails = append(vErr.RuleFails, fmt.Sprintf("too long: maximum %d characters", v.MaxLength))
	}

	hasLower, hasUpper, hasNumber, hasSymbol := charClasses(password)

	if v.RequireLower && !hasLower {
		vErr.RuleFails = append(vErr.RuleFails, "missing lowercase letter")
	}
	if v.RequireUpper && !hasUpper {
		vErr.RuleFails = append(vErr.RuleFails, "missing uppercase letter")
	}
	if v.RequireNumbers && !hasNumber {
		vErr.RuleFails = append(vErr.RuleFails, "missing number")
	}
	if v.RequireSymbols && !hasSymbol {
		vErr.RuleFails = append(vErr.RuleFails, "missing symbol")
	}

	// --- Entropy + penalties ---
	entropy := calculateEntropy(password)
	score := entropyToScore(entropy)

	penalties := detectPenalties(password, v.dict)
	for _, p := range penalties {
		score = int(float64(score) * p.Factor)
		vErr.Penalties = append(vErr.Penalties, p)
	}

	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	rulesPass := len(vErr.RuleFails) == 0
	complexityPass := score >= v.Complexity
	pass := rulesPass && complexityPass

	if !complexityPass {
		vErr.RuleFails = append(vErr.RuleFails, fmt.Sprintf("complexity %d below threshold %d", score, v.Complexity))
	}

	return pass, score, vErr
}

// Generate creates a random password that satisfies all configured rules and the complexity threshold.
// It retries until a valid password is produced (max 1000 attempts).
func (v *PasswordValidator) Generate() (string, error) {
	const maxAttempts = 1000

	for i := 0; i < maxAttempts; i++ {
		pwd := v.generateCandidate()
		if pass, _ := v.Validate(pwd); pass {
			return pwd, nil
		}
	}
	return "", fmt.Errorf("failed to generate a valid password after %d attempts", maxAttempts)
}

func (v *PasswordValidator) generateCandidate() string {
	// Pick a length between min and max, biased toward longer for higher complexity
	length := v.MinLength
	if v.MaxLength > v.MinLength {
		diff := v.MaxLength - v.MinLength
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(diff+1)))
		length = v.MinLength + int(n.Int64())
	}

	// Build the charset
	const (
		lowerChars  = "abcdefghijklmnopqrstuvwxyz"
		upperChars  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		numberChars = "0123456789"
		symbolChars = "!@#$%^&*()-_=+[]{}|;:',.<>?/`~"
	)

	var charset string
	var required []string

	if v.RequireLower {
		charset += lowerChars
		required = append(required, lowerChars)
	}
	if v.RequireUpper {
		charset += upperChars
		required = append(required, upperChars)
	}
	if v.RequireNumbers {
		charset += numberChars
		required = append(required, numberChars)
	}
	if v.RequireSymbols {
		charset += symbolChars
		required = append(required, symbolChars)
	}

	// If no requirements, use all
	if charset == "" {
		charset = lowerChars + upperChars + numberChars + symbolChars
	}

	pwd := make([]byte, length)

	// Fill required characters first at random positions
	positions := make([]int, length)
	for i := range positions {
		positions[i] = i
	}
	// Shuffle positions
	for i := len(positions) - 1; i > 0; i-- {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		j := int(n.Int64())
		positions[i], positions[j] = positions[j], positions[i]
	}

	pos := 0
	for _, req := range required {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(req))))
		pwd[positions[pos]] = req[int(n.Int64())]
		pos++
	}

	// Fill remaining positions
	for ; pos < length; pos++ {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		pwd[positions[pos]] = charset[int(n.Int64())]
	}

	return string(pwd)
}

func charClasses(password string) (lower, upper, number, symbol bool) {
	for _, r := range password {
		switch {
		case unicode.IsLower(r):
			lower = true
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsDigit(r):
			number = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			symbol = true
		}
	}
	return
}
