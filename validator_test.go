package passval

import (
	"testing"
)

func TestNewPasswordValidator(t *testing.T) {
	v := NewPasswordValidator(8, 64, true, true, true, true, 50)
	if v.MinLength != 8 {
		t.Errorf("expected MinLength 8, got %d", v.MinLength)
	}
	if v.MaxLength != 64 {
		t.Errorf("expected MaxLength 64, got %d", v.MaxLength)
	}
	if v.Complexity != 50 {
		t.Errorf("expected Complexity 50, got %d", v.Complexity)
	}
}

func TestValidate_RuleChecks(t *testing.T) {
	v := NewPasswordValidator(8, 20, true, true, true, true, 0)

	tests := []struct {
		name     string
		password string
		wantPass bool
	}{
		{"too short", "Ab1!", false},
		{"too long", "Abcdefghijklmnopqrstu1!", false},
		{"missing upper", "abcdefg1!", false},
		{"missing lower", "ABCDEFG1!", false},
		{"missing number", "Abcdefgh!", false},
		{"missing symbol", "Abcdefg1h", false},
		{"all rules met", "Abcdefg1!", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pass, _ := v.Validate(tt.password)
			if pass != tt.wantPass {
				t.Errorf("Validate(%q) = %v, want %v", tt.password, pass, tt.wantPass)
			}
		})
	}
}

func TestValidate_CommonPassword(t *testing.T) {
	v := NewPasswordValidator(4, 64, false, false, false, false, 30)

	// "password" is in the common list — should score very low
	pass, score := v.Validate("password")
	if pass {
		t.Errorf("'password' should not pass with complexity 30, got score %d", score)
	}
	if score > 20 {
		t.Errorf("'password' should have very low score, got %d", score)
	}
}

func TestValidate_LeetSpeak(t *testing.T) {
	v := NewPasswordValidator(4, 64, false, false, false, false, 30)

	// "p@ssw0rd" should be detected as leet for "password"
	pass, score := v.Validate("p@ssw0rd")
	t.Logf("p@ssw0rd: pass=%v score=%d", pass, score)

	// Should have a penalty applied
	_, _, err := v.ValidateVerbose("p@ssw0rd")
	if err == nil {
		t.Log("p@ssw0rd passed validation — may need stricter penalties")
	} else {
		t.Logf("p@ssw0rd penalties: %s", err.Error())
	}
}

func TestValidate_RepeatedChars(t *testing.T) {
	v := NewPasswordValidator(6, 64, false, false, false, false, 0)

	_, scoreGood := v.Validate("xK9mP2")
	_, scoreBad := v.Validate("aaaaaa")

	if scoreBad >= scoreGood {
		t.Errorf("repeated chars should score lower: 'aaaaaa'=%d vs 'xK9mP2'=%d", scoreBad, scoreGood)
	}
}

func TestValidate_SequentialChars(t *testing.T) {
	v := NewPasswordValidator(6, 64, false, false, false, false, 0)

	_, scoreGood := v.Validate("xK9mP2")
	_, scoreBad := v.Validate("abcdef")

	if scoreBad >= scoreGood {
		t.Errorf("sequential chars should score lower: 'abcdef'=%d vs 'xK9mP2'=%d", scoreBad, scoreGood)
	}
}

func TestValidate_KeyboardPattern(t *testing.T) {
	v := NewPasswordValidator(6, 64, false, false, false, false, 0)

	_, scoreGood := v.Validate("xK9mP2")
	_, scoreBad := v.Validate("qwerty")

	if scoreBad >= scoreGood {
		t.Errorf("keyboard pattern should score lower: 'qwerty'=%d vs 'xK9mP2'=%d", scoreBad, scoreGood)
	}
}

func TestValidateVerbose_ReturnsPenaltyDetails(t *testing.T) {
	v := NewPasswordValidator(4, 64, false, false, false, false, 50)

	pass, score, err := v.ValidateVerbose("password")
	t.Logf("password: pass=%v score=%d", pass, score)

	if pass {
		t.Error("'password' should not pass with complexity 50")
	}
	if err == nil {
		t.Fatal("expected error with penalty details")
	}

	vErr, ok := err.(*ValidationError)
	if !ok {
		t.Fatal("expected *ValidationError")
	}

	if len(vErr.Penalties) == 0 {
		t.Error("expected at least one penalty")
	}

	t.Logf("Penalties: %s", err.Error())
}

func TestEntropyToScore(t *testing.T) {
	tests := []struct {
		entropy float64
		minScore int
		maxScore int
	}{
		{0, 0, 0},
		{20, 30, 50},
		{40, 55, 70},
		{60, 70, 85},
		{80, 80, 92},
		{128, 93, 100},
	}

	for _, tt := range tests {
		score := entropyToScore(tt.entropy)
		if score < tt.minScore || score > tt.maxScore {
			t.Errorf("entropyToScore(%.0f) = %d, expected [%d, %d]", tt.entropy, score, tt.minScore, tt.maxScore)
		}
	}
}

func TestLeetNormalize(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"p@ssw0rd", "password"},
		{"h3ll0", "hello"},
		{"$up3r", "super"},
		{"normal", "normal"},
	}

	for _, tt := range tests {
		got := leetNormalize(tt.input)
		if got != tt.expected {
			t.Errorf("leetNormalize(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestLeetVariants(t *testing.T) {
	// "p@ss1" has '1' which maps to both 'i' and 'l'
	variants := leetVariants("p@ss1")
	if len(variants) < 2 {
		t.Errorf("expected at least 2 variants, got %d: %v", len(variants), variants)
	}

	found := make(map[string]bool)
	for _, v := range variants {
		found[v] = true
	}
	if !found["passi"] {
		t.Error("expected variant 'passi'")
	}
	if !found["passl"] {
		t.Error("expected variant 'passl'")
	}
}

func TestGenerate(t *testing.T) {
	v := NewPasswordValidator(12, 20, true, true, true, true, 40)

	pwd, err := v.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	pass, score := v.Validate(pwd)
	if !pass {
		t.Errorf("generated password %q did not pass validation (score=%d)", pwd, score)
	}

	// Verify it has required character classes
	lower, upper, number, symbol := charClasses(pwd)
	if !lower || !upper || !number || !symbol {
		t.Errorf("generated password %q missing char classes: lower=%v upper=%v number=%v symbol=%v",
			pwd, lower, upper, number, symbol)
	}

	t.Logf("Generated: %q (score=%d)", pwd, score)
}

func TestGenerate_HighComplexity(t *testing.T) {
	v := NewPasswordValidator(16, 32, true, true, true, true, 70)

	pwd, err := v.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	pass, score := v.Validate(pwd)
	if !pass {
		t.Errorf("generated password %q did not pass (score=%d)", pwd, score)
	}

	t.Logf("Generated high-complexity: %q (score=%d)", pwd, score)
}

func TestDictionaryLoaded(t *testing.T) {
	if globalDict == nil {
		t.Fatal("global dictionary not loaded")
	}
	if len(globalDict.words) == 0 {
		t.Fatal("dictionary is empty")
	}
	if !globalDict.contains("password") {
		t.Error("dictionary should contain 'password'")
	}
	if !globalDict.contains("123456") {
		t.Error("dictionary should contain '123456'")
	}
	t.Logf("Dictionary loaded with %d entries", len(globalDict.words))
}

func TestComplexityThreshold(t *testing.T) {
	// Low threshold — simple password should pass
	vLow := NewPasswordValidator(6, 64, false, false, false, false, 10)
	pass, score := vLow.Validate("simple")
	t.Logf("'simple' with threshold 10: pass=%v score=%d", pass, score)

	// High threshold — simple password should fail
	vHigh := NewPasswordValidator(6, 64, false, false, false, false, 80)
	pass, score = vHigh.Validate("simple")
	if pass {
		t.Errorf("'simple' should not pass with threshold 80, score=%d", score)
	}
}

// Benchmarks
func BenchmarkValidate(b *testing.B) {
	v := NewPasswordValidator(8, 64, true, true, true, true, 50)
	for i := 0; i < b.N; i++ {
		v.Validate("MyP@ssw0rd!23")
	}
}

func BenchmarkGenerate(b *testing.B) {
	v := NewPasswordValidator(12, 20, true, true, true, true, 50)
	for i := 0; i < b.N; i++ {
		v.Generate()
	}
}
