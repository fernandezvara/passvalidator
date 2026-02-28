package passval

import (
	"fmt"
	"strings"
	"unicode"
)

// detectPenalties analyzes a password and returns all applicable multiplicative penalties.
func detectPenalties(password string, dict *dictionary) []PenaltyDetail {
	var penalties []PenaltyDetail

	lower := strings.ToLower(password)

	// 1. Common password (exact match or leet-normalized)
	if p := penaltyCommonPassword(lower, dict); p != nil {
		penalties = append(penalties, *p)
	}

	// 2. Repeated characters
	if p := penaltyRepeatedChars(lower); p != nil {
		penalties = append(penalties, *p)
	}

	// 3. Sequential characters (abc, 123, etc.)
	if p := penaltySequentialChars(lower); p != nil {
		penalties = append(penalties, *p)
	}

	// 4. Keyboard patterns (qwerty, asdf, etc.)
	if p := penaltyKeyboardPatterns(lower); p != nil {
		penalties = append(penalties, *p)
	}

	// 5. Dictionary substring detection (leet-normalized)
	if p := penaltyDictionarySubstring(lower, dict); p != nil {
		penalties = append(penalties, *p)
	}

	return penalties
}

// --- Common password (exact match) ---

func penaltyCommonPassword(lower string, dict *dictionary) *PenaltyDetail {
	if dict == nil {
		return nil
	}

	// Check exact match
	if dict.contains(lower) {
		return &PenaltyDetail{
			Rule:   "common_password",
			Factor: 0.1, // devastating penalty
			Desc:   "password is in the common passwords list",
		}
	}

	// Check leet-speak normalized variants
	variants := leetVariants(lower)
	for _, v := range variants {
		if dict.contains(v) {
			return &PenaltyDetail{
				Rule:   "common_password_leet",
				Factor: 0.15,
				Desc:   fmt.Sprintf("password matches common password via leet-speak (%s)", v),
			}
		}
	}

	return nil
}

// --- Repeated characters ---

func penaltyRepeatedChars(lower string) *PenaltyDetail {
	if len(lower) < 3 {
		return nil
	}

	maxRepeat := 1
	current := 1
	for i := 1; i < len(lower); i++ {
		if lower[i] == lower[i-1] {
			current++
			if current > maxRepeat {
				maxRepeat = current
			}
		} else {
			current = 1
		}
	}

	// Also check ratio of unique chars to total length
	unique := make(map[rune]bool)
	for _, r := range lower {
		unique[r] = true
	}
	uniqueRatio := float64(len(unique)) / float64(len(lower))

	var factor float64 = 1.0
	var reasons []string

	if maxRepeat >= 4 {
		factor *= 0.4
		reasons = append(reasons, fmt.Sprintf("%d consecutive repeated characters", maxRepeat))
	} else if maxRepeat >= 3 {
		factor *= 0.6
		reasons = append(reasons, fmt.Sprintf("%d consecutive repeated characters", maxRepeat))
	}

	if uniqueRatio < 0.4 {
		factor *= 0.5
		reasons = append(reasons, fmt.Sprintf("low character diversity (%.0f%% unique)", uniqueRatio*100))
	} else if uniqueRatio < 0.6 {
		factor *= 0.7
		reasons = append(reasons, fmt.Sprintf("moderate character diversity (%.0f%% unique)", uniqueRatio*100))
	}

	if factor < 1.0 {
		return &PenaltyDetail{
			Rule:   "repeated_chars",
			Factor: factor,
			Desc:   strings.Join(reasons, "; "),
		}
	}
	return nil
}

// --- Sequential characters ---

func penaltySequentialChars(lower string) *PenaltyDetail {
	if len(lower) < 3 {
		return nil
	}

	maxSeq := 1
	current := 1
	for i := 1; i < len(lower); i++ {
		diff := int(lower[i]) - int(lower[i-1])
		if diff == 1 || diff == -1 {
			current++
			if current > maxSeq {
				maxSeq = current
			}
		} else {
			current = 1
		}
	}

	if maxSeq >= 5 {
		return &PenaltyDetail{
			Rule:   "sequential_chars",
			Factor: 0.3,
			Desc:   fmt.Sprintf("long sequential pattern detected (%d chars)", maxSeq),
		}
	}
	if maxSeq >= 4 {
		return &PenaltyDetail{
			Rule:   "sequential_chars",
			Factor: 0.5,
			Desc:   fmt.Sprintf("sequential pattern detected (%d chars)", maxSeq),
		}
	}
	if maxSeq >= 3 {
		return &PenaltyDetail{
			Rule:   "sequential_chars",
			Factor: 0.7,
			Desc:   fmt.Sprintf("short sequential pattern detected (%d chars)", maxSeq),
		}
	}

	return nil
}

// --- Keyboard patterns ---

var keyboardRows = []string{
	"qwertyuiop",
	"asdfghjkl",
	"zxcvbnm",
	"1234567890",
	// Common diagonal / patterns
	"qazwsx",
	"edcrfv",
	"tgbyhn",
	"yujm",
}

func penaltyKeyboardPatterns(lower string) *PenaltyDetail {
	bestMatch := 0

	for _, row := range keyboardRows {
		match := longestCommonSubstringLen(lower, row)
		if match > bestMatch {
			bestMatch = match
		}
		// Also check reversed row
		rev := reverseString(row)
		match = longestCommonSubstringLen(lower, rev)
		if match > bestMatch {
			bestMatch = match
		}
	}

	if bestMatch >= 6 {
		return &PenaltyDetail{
			Rule:   "keyboard_pattern",
			Factor: 0.2,
			Desc:   fmt.Sprintf("long keyboard pattern detected (%d chars)", bestMatch),
		}
	}
	if bestMatch >= 5 {
		return &PenaltyDetail{
			Rule:   "keyboard_pattern",
			Factor: 0.4,
			Desc:   fmt.Sprintf("keyboard pattern detected (%d chars)", bestMatch),
		}
	}
	if bestMatch >= 4 {
		return &PenaltyDetail{
			Rule:   "keyboard_pattern",
			Factor: 0.6,
			Desc:   fmt.Sprintf("short keyboard pattern detected (%d chars)", bestMatch),
		}
	}

	return nil
}

// --- Dictionary substring (leet-normalized) ---

func penaltyDictionarySubstring(lower string, dict *dictionary) *PenaltyDetail {
	if dict == nil {
		return nil
	}

	// Check if any common password >= 4 chars is a substring of the password
	normalized := leetNormalize(lower)

	longestMatch := ""
	for _, word := range dict.words {
		if len(word) < 4 {
			continue
		}
		if strings.Contains(lower, word) || strings.Contains(normalized, word) {
			if len(word) > len(longestMatch) {
				longestMatch = word
			}
		}
	}

	if longestMatch == "" {
		return nil
	}

	ratio := float64(len(longestMatch)) / float64(len(lower))

	if ratio >= 0.8 {
		// Password is mostly a dictionary word with minor additions
		return &PenaltyDetail{
			Rule:   "dictionary_substring",
			Factor: 0.2,
			Desc:   fmt.Sprintf("password is mostly the dictionary word '%s'", longestMatch),
		}
	}
	if ratio >= 0.5 {
		return &PenaltyDetail{
			Rule:   "dictionary_substring",
			Factor: 0.5,
			Desc:   fmt.Sprintf("password contains dictionary word '%s'", longestMatch),
		}
	}
	if ratio >= 0.3 {
		return &PenaltyDetail{
			Rule:   "dictionary_substring",
			Factor: 0.7,
			Desc:   fmt.Sprintf("password contains dictionary word '%s'", longestMatch),
		}
	}

	return nil
}

// --- Helpers ---

func longestCommonSubstringLen(a, b string) int {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}

	maxLen := 0
	// Simple O(n*m) approach — fine for short strings (passwords)
	for i := 0; i < len(a); i++ {
		for j := 0; j < len(b); j++ {
			k := 0
			for i+k < len(a) && j+k < len(b) && a[i+k] == b[j+k] {
				k++
			}
			if k > maxLen {
				maxLen = k
			}
		}
	}
	return maxLen
}

func reverseString(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

// stripNonAlpha removes non-letter characters for dictionary matching.
func stripNonAlpha(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsLetter(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}
