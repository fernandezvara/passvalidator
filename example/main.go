package main

import (
	"fmt"
	"math"
	"strings"

	passval "github.com/fernandezvara/passvalidator"
)

func main() {
	fmt.Println("Password Validation Examples")
	fmt.Println("==========================")
	fmt.Println()

	// Example 1: Basic usage with embedded dictionary
	fmt.Println("1. Basic Usage (Embedded Dictionary)")
	fmt.Println("-----------------------------------")
	v1 := passval.NewPasswordValidator(8, 64, true, true, true, true, 60)

	pass, score, err := v1.ValidateVerbose("password")
	fmt.Printf("Password: `password`\n")
	fmt.Printf("Result: Pass=%v, Score=%d\n", pass, score)
	if err != nil {
		fmt.Printf("Details: %s\n", err.Error())
	}
	fmt.Println()

	// Example 2: Custom dictionary
	fmt.Println("2. Custom Dictionary Usage")
	fmt.Println("---------------------------")
	customDict := `password
123456
qwerty
admin
letmein
welcome
monkey
dragon
master
sunshine
superman
michael
george
jennifer
harley
rangers`

	v2 := passval.NewPasswordValidatorWithDict(8, 64, true, true, true, true, 60, customDict)

	pass, score, err = v2.ValidateVerbose("superman123!")
	fmt.Printf("Password: `superman123!`\n")
	fmt.Printf("Result: Pass=%v, Score=%d\n", pass, score)
	if err != nil {
		fmt.Printf("Details: %s\n", err.Error())
	}
	fmt.Println()

	// Example 3: Comprehensive table (like README examples)
	fmt.Println("3. Comprehensive Validation Table")
	fmt.Println("=================================")
	fmt.Println()

	fmt.Println("| Password                     | Raw Score | After Penalties | Why")
	fmt.Println("|------------------------------|-----------|-----------------|----")

	testCases := []struct {
		password string
		expected string
	}{
		{"password", "Common password (x0.1) + dictionary (x0.2)"},
		{"p@ssw0rd", "Leet-speak match (x0.15) + dictionary (x0.2)"},
		{"qwerty", "Keyboard pattern (x0.4) + common password (x0.1) + sequence (x0.7)"},
		{"aaaaaa", "Repeated (x0.4 x 0.5) + common password (x0.1)"},
		{"Xk9$mP2!vLq", "No penalties"},
		{"12345678", "Sequential numbers + common password"},
		{"abcdefg", "Sequential letters + dictionary"},
		{"P@ssword123", "Dictionary + sequential numbers"},
		{"admin2023!", "Common word + year pattern"},
		{"letmein!!", "Common phrase"},
		{"Abc123!", "Sequential pattern + dictionary"},
		{"MyDogName1", "Personal pattern + missing symbol"},
		{"Summer2024$", "Season + year + dictionary"},
		{"!@#$%^&*", "Symbols only + sequential pattern"},
		{"aB3!aB3!", "Repeated pattern"},
		{"correcthorsebatterystaple", "Diceware style (no symbols)"},
		{"Tr0ub4dor&3", "XKCD pattern with leet"},
		{"p@ssw0rd123", "Leet + sequential numbers"},
		{"keyboardcat", "Keyboard word"},
		{"11111111", "All same number + repeated"},
		{"password123", "Common password + sequential numbers"},
	}

	for _, tc := range testCases {
		// Get verbose validation to see penalties
		pass, score, err := v1.ValidateVerbose(tc.password)

		// Calculate raw score without penalties
		rawScore := calculateRawScore(tc.password)

		var why string
		if err != nil {
			// Extract penalty details from error
			penalties := extractPenalties(err.Error())
			why = penalties
			if !pass {
				why += " [FAIL]"
			}
		} else {
			why = "No penalties"
		}

		// Format the table row with proper spacing
		fmt.Printf("| %-28s | ~%-7d | ~%-13d | %s\n",
			"`"+tc.password+"`", rawScore, score, why)
	}
}

// calculateRawScore estimates the raw entropy score without penalties
func calculateRawScore(password string) int {
	// Use the same logic as the library for consistency
	hasLower := false
	hasUpper := false
	hasDigit := false
	hasSymbol := false

	for _, r := range password {
		switch {
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= '0' && r <= '9':
			hasDigit = true
		default:
			hasSymbol = true
		}
	}

	poolSize := 0
	if hasLower {
		poolSize += 26
	}
	if hasUpper {
		poolSize += 26
	}
	if hasDigit {
		poolSize += 10
	}
	if hasSymbol {
		poolSize += 33
	}

	if poolSize <= 1 {
		return 0
	}

	// Calculate entropy: length * log2(poolSize)
	entropy := float64(len(password)) * math.Log2(float64(poolSize))

	// Map to score using the same formula as the library
	const k = 40.0
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

// extractPenalties formats the penalty details from the error message
func extractPenalties(errMsg string) string {
	parts := strings.Split(errMsg, "; ")
	var penalties []string

	for _, part := range parts {
		if strings.Contains(part, "penalty(") {
			// Extract penalty info
			start := strings.Index(part, "penalty(") + 8
			end := strings.Index(part, "): ")
			if start > 7 && end > start {
				penaltyType := part[start:end]

				// Format penalty description
				if strings.Contains(penaltyType, "common_password") {
					penalties = append(penalties, "Common password")
				} else if strings.Contains(penaltyType, "repeated_chars") {
					penalties = append(penalties, "Repeated chars")
				} else if strings.Contains(penaltyType, "sequential_chars") {
					penalties = append(penalties, "Sequential pattern")
				} else if strings.Contains(penaltyType, "keyboard_pattern") {
					penalties = append(penalties, "Keyboard pattern")
				} else if strings.Contains(penaltyType, "dictionary_substring") {
					penalties = append(penalties, "Dictionary word")
				}
			}
		} else if strings.Contains(part, "rule:") {
			// Extract rule failures
			rule := strings.TrimPrefix(part, "rule: ")
			if strings.Contains(rule, "too short") || strings.Contains(rule, "too long") {
				penalties = append(penalties, "Length issue")
			} else if strings.Contains(rule, "missing") {
				penalties = append(penalties, "Missing "+strings.TrimPrefix(rule, "missing "))
			} else if strings.Contains(rule, "complexity") {
				// Skip complexity failure as it's implied by low score
			} else {
				penalties = append(penalties, rule)
			}
		}
	}

	if len(penalties) == 0 {
		return "No penalties"
	}

	return strings.Join(penalties, " + ")
}
