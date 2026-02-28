package passval

import "strings"

// leetMap maps leet-speak characters to their possible letter equivalents.
// Some characters map to multiple letters (ambiguous).
var leetMap = map[rune][]rune{
	'@': {'a'},
	'4': {'a'},
	'8': {'b'},
	'(': {'c'},
	'{': {'c'},
	'3': {'e'},
	'6': {'g'},
	'#': {'h'},
	'!': {'i'},
	'1': {'i', 'l'},
	'|': {'i', 'l'},
	'0': {'o'},
	'9': {'g', 'q'},
	'5': {'s'},
	'$': {'s'},
	'7': {'t'},
	'+': {'t'},
	'2': {'z'},
	'%': {'x'},
}

// leetNormalize performs a single-pass normalization of leet-speak,
// picking the first mapping for each character. This covers the most common cases.
func leetNormalize(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if replacements, ok := leetMap[r]; ok {
			b.WriteRune(replacements[0]) // take first/most common mapping
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// leetVariants generates multiple normalized versions of the input
// by considering ambiguous mappings (e.g. '1' → 'i' or 'l').
// Returns up to ~4 variants to keep it manageable.
func leetVariants(s string) []string {
	// Start with the basic normalization
	primary := leetNormalize(s)
	variants := map[string]bool{primary: true}

	// Find ambiguous positions (chars with multiple mappings)
	type ambiguity struct {
		pos     int
		options []rune
	}
	var ambiguities []ambiguity

	runes := []rune(s)
	for i, r := range runes {
		if replacements, ok := leetMap[r]; ok && len(replacements) > 1 {
			ambiguities = append(ambiguities, ambiguity{pos: i, options: replacements})
		}
	}

	// Generate variants for first 2 ambiguities (avoids explosion)
	limit := len(ambiguities)
	if limit > 2 {
		limit = 2
	}

	if limit > 0 {
		// Generate combinations
		combos := [][]rune{{}}
		for i := 0; i < limit; i++ {
			var newCombos [][]rune
			for _, combo := range combos {
				for _, opt := range ambiguities[i].options {
					newCombo := make([]rune, len(combo)+1)
					copy(newCombo, combo)
					newCombo[len(combo)] = opt
					newCombos = append(newCombos, newCombo)
				}
			}
			combos = newCombos
		}

		for _, combo := range combos {
			result := make([]rune, len(runes))
			// Start with primary normalization
			for i, r := range runes {
				if replacements, ok := leetMap[r]; ok {
					result[i] = replacements[0]
				} else {
					result[i] = r
				}
			}
			// Apply ambiguous choices
			for i := 0; i < limit; i++ {
				result[ambiguities[i].pos] = combo[i]
			}
			variants[string(result)] = true
		}
	}

	out := make([]string, 0, len(variants))
	for v := range variants {
		out = append(out, v)
	}
	return out
}
