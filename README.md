# passval — Password Complexity Validator for Go

A comprehensive Go library for password validation and generation that combines **Shannon entropy-based scoring** with **aggressive pattern detection** and **leet-speak awareness** to provide robust password security assessment.

## What This Library Does

### Core Validation
- **Entropy calculation** using Shannon's mathematical formula: `length × log₂(pool_size)`
- **Character class analysis** (lowercase, uppercase, digits, symbols) with effective pool size determination
- **Configurable rules** for minimum/maximum length and required character types
- **Complexity scoring** on a 0-100 scale with logarithmic curve mapping

### Pattern Detection & Penalties
The library applies **multiplicative penalties** for common password weaknesses:

- **Common passwords**: Exact matches and leet-speak variants (×0.1-0.15 penalty)
- **Repeated characters**: Consecutive repeats and low character diversity (×0.4-0.7 penalty)
- **Sequential patterns**: ABC, 123, etc. sequences (×0.3-0.7 penalty)
- **Keyboard patterns**: QWERTY, ASDF rows and diagonals (×0.2-0.6 penalty)
- **Dictionary substrings**: Contains common words (×0.2-0.7 penalty based on ratio)

### Advanced Features
- **Leet-speak normalization**: Detects `@`→`a`, `4`→`a`, `0`→`o`, `1`→`i/l`, etc.
- **Multiple leet variants**: Handles ambiguous mappings for comprehensive detection
- **Embedded dictionary**: Fast O(1) lookup
- **Verbose validation**: Detailed penalty breakdown for debugging/user feedback
- **Password generation**: Creates compliant passwords with auto-retry until complexity threshold met

### Security Assessment
- **Entropy-based scoring**: 40+ bits vulnerable, 60+ bits nation-state resistant, 80+ bits practically unbreakable
- **Multiplicative penalty stacking**: Multiple weaknesses compound the score reduction
- **Real-world threat modeling**: Accounts for dictionary attacks, pattern recognition, and common substitutions

## Shannon Entropy: The Foundation

This library is built on **Shannon entropy** - the mathematical measure of information uncertainty. For passwords, entropy quantifies how unpredictable a password is against brute-force attacks.

### Entropy Calculation

The entropy is calculated using the formula:

```
Entropy (bits) = length × log₂(pool_size)
```

Where:
- **length**: password character count
- **pool_size**: effective character set size based on actual character classes used

### Character Pool Sizes

| Character Class | Pool Size | Characters |
|---|---|---|
| Lowercase letters | 26 | a-z |
| Uppercase letters | 26 | A-Z |
| Digits | 10 | 0-9 |
| Symbols | 33 | !@#$%^&*()-_=+[]{}|;:',.<>?/`~ |

**Example calculations:**
- `password8` (8 chars, lowercase only): 8 × log₂(26) = **37.6 bits**
- `Passw0rd!` (8 chars, all 4 classes): 8 × log₂(95) = **52.6 bits**
- `Xk9$mP2!vLq` (12 chars, all 4 classes): 12 × log₂(95) = **78.9 bits**

### Why Entropy Matters

- **40 bits**: Vulnerable to dedicated hardware attacks
- **60 bits**: Resistant to nation-state capabilities  
- **80 bits**: Practically unbreakable with current technology
- **128 bits**: Beyond foreseeable computational limits

## Scoring

The entropy bits are mapped to a 0-100 score using a logarithmic curve with diminishing returns:

| Entropy (bits) | Score |
|---|---|
| 20 | ~39 |
| 40 | ~63 |
| 60 | ~78 |
| 80 | ~86 |
| 100 | ~92 |
| 128 | ~96 |

The curve formula: `score = 100 × (1 - e^(-entropy/40))`

Penalties are **multiplicative** and stack. Examples:

| Password | Raw Score | After Penalties | Why |
|---|---|---|---|
| `password` | ~61 | ~1 | Missing uppercase letter + Missing number + Missing symbol + Common password + Dictionary word |
| `p@ssw0rd` | ~71 | ~2 | Missing uppercase letter + Common password + Dictionary word |
| `password123` | ~76 | ~10 | Missing uppercase letter + Missing symbol + Sequential pattern + Dictionary word |
| `qwerty` | ~51 | ~12 | Length issue + Missing uppercase letter + Missing number + Missing symbol + Common password + Keyboard pattern + Dictionary word |
| `aaaaaa` | ~51 | ~0 | Length issue + Missing uppercase letter + Missing number + Missing symbol + Common password + Repeated chars + Dictionary word |
| `Xk9$mP2!vLq` | ~84 | ~84 | No penalties |

## API

### `NewPasswordValidator(min, max int, lower, upper, numbers, symbols bool, complexity int) *PasswordValidator`
Creates a validator with the embedded sample dictionary.

### `NewPasswordValidatorWithDict(min, max int, lower, upper, numbers, symbols bool, complexity int, customDict string) *PasswordValidator`
Creates a validator with custom dictionary data. If `customDict` is empty, uses the embedded sample dictionary. The `customDict` should be a string with one password per line.

### `Validate(password string) (bool, int)`
Returns pass/fail and complexity score.

### `ValidateVerbose(password string) (bool, int, error)`
Returns pass/fail, score, and `*ValidationError` with penalty details. Error is `nil` on pass.

### `Generate() (string, error)`
Generates a random password meeting all rules. Retries up to 1000 times.


## Setup — Replace the Dictionary

The included `data/common_passwords.txt` is a **sample (~350 entries)**. 
You can replace it with the full 10k list (MIT license) or with your own list: 

```bash
# example: replace with the full 10k list
curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt \
  -o /path/to/your/custom-passwords.txt
```

## Usage

### Basic Usage (with embedded sample dictionary) - not recommended for production

```go
package main

import (
    "fmt"
    "github.com/fernandezvara/passvalidator"
)

func main() {
    // Create validator: min=8, max=64, require lower+upper+numbers+symbols, complexity >= 60
    v := passval.NewPasswordValidator(8, 64, true, true, true, true, 60)

    // Simple validation
    pass, score := v.Validate("MyP@ssw0rd!23")
    fmt.Printf("Pass: %v, Score: %d\n", pass, score)

    // Verbose validation (with penalty details)
    pass, score, err := v.ValidateVerbose("password123")
    fmt.Printf("Pass: %v, Score: %d\n", pass, score)
    if err != nil {
        fmt.Printf("Details: %s\n", err.Error())
    }

    // Generate a compliant password
    pwd, err := v.Generate()
    if err != nil {
        panic(err)
    }
    fmt.Printf("Generated: %s\n", pwd)
}
```

### Custom Dictionary Usage

```go
package main

import (
    "fmt"
    "github.com/fernandezvara/passvalidator"
)

func main() {
    // Custom dictionary data (one password per line)
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
princess
football
baseball
shadow
superman
michael
george
jennifer
harley
rangers`

    // Create validator with custom dictionary
    v := passval.NewPasswordValidatorWithDict(8, 64, true, true, true, true, 60, customDict)

    // Test against custom dictionary
    pass, score, err := v.ValidateVerbose("superman123!")
    if err != nil {
        fmt.Printf("Custom dictionary detected: %s\n", err.Error())
    }
    fmt.Printf("Pass: %v, Score: %d\n", pass, score)
}
```

### Loading Dictionary from File

```go
package main

import (
    "fmt"
    "os"
    "github.com/fernandezvara/passvalidator"
)

func main() {
    // Read dictionary from local file
    dictData, err := os.ReadFile("/path/to/your/custom-passwords.txt")
    if err != nil {
        panic(err)
    }

    // Create validator with loaded dictionary
    v := passval.NewPasswordValidatorWithDict(8, 64, true, true, true, true, 60, string(dictData))

    // Test validation
    pass, score := v.Validate("MySecureP@ssw0rd!2024")
    fmt.Printf("Pass: %v, Score: %d\n", pass, score)
}
```

### Loading Dictionary from Embedded File

```go
package main

import (
    _ "embed"
    "fmt"
    "github.com/fernandezvara/passvalidator"
)

//go:embed data/my-custom-passwords.txt
var customDictData string

func main() {
    // Create validator with embedded dictionary
    v := passval.NewPasswordValidatorWithDict(8, 64, true, true, true, true, 60, customDictData)

    // Test validation
    pass, score := v.Validate("MySecureP@ssw0rd!2024")
    fmt.Printf("Pass: %v, Score: %d\n", pass, score)
}
```



## Performance

```
BenchmarkValidate    ~14μs/op    497 B/op
BenchmarkGenerate   ~539μs/op   2629 B/op
```

## License

MIT