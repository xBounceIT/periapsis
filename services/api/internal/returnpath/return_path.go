// Package returnpath validates stored same-origin browser return paths.
package returnpath

import (
	"net/url"
	"path"
	"strings"
	"unicode"
	"unicode/utf8"
)

const maximumBytes = 2_048

// Valid accepts a canonical absolute path with an optional query, never an
// absolute URL or a browser network-path reference. It validates without
// rewriting the value so a stored ceremony keeps its exact return-path binding.
func Valid(value string) bool {
	if value == "" || len(value) > maximumBytes || !utf8.ValidString(value) || value[0] != '/' {
		return false
	}
	// Browsers treat both //host and /\host as an external authority.
	if len(value) > 1 && (value[1] == '/' || value[1] == '\\') {
		return false
	}
	if strings.ContainsRune(value, '\\') || containsControl(value) {
		return false
	}
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || parsed.User != nil || parsed.Fragment != "" ||
		parsed.RawPath != "" || parsed.Path == "" || strings.Contains(parsed.Path, "//") ||
		path.Clean(parsed.Path) != parsed.Path || parsed.String() != value {
		return false
	}
	// Canonical escapes such as %5C and %0A leave RawPath empty. Check the
	// decoded path as well, without decoding again or treating query data as a URL.
	return utf8.ValidString(parsed.Path) && !strings.ContainsRune(parsed.Path, '\\') && !containsControl(parsed.Path)
}

func containsControl(value string) bool {
	for _, character := range value {
		if unicode.IsControl(character) {
			return true
		}
	}
	return false
}
