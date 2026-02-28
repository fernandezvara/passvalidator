package passval

import (
	_ "embed"
	"strings"
)

//go:embed data/common_passwords.txt
var commonPasswordsData string

// dictionary holds the common passwords set for fast lookup.
type dictionary struct {
	set   map[string]bool
	words []string // for substring iteration
}

// globalDict is initialized at package load time.
var globalDict *dictionary

func init() {
	globalDict = loadDictionary(commonPasswordsData)
}

func loadDictionary(data string) *dictionary {
	lines := strings.Split(data, "\n")
	d := &dictionary{
		set: make(map[string]bool, len(lines)),
	}
	for _, line := range lines {
		word := strings.TrimSpace(strings.ToLower(line))
		if word == "" {
			continue
		}
		d.set[word] = true
		d.words = append(d.words, word)
	}
	return d
}

// contains checks if the exact word is in the dictionary.
func (d *dictionary) contains(word string) bool {
	return d.set[word]
}
