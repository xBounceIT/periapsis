package identity

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	ldap "github.com/go-ldap/ldap/v3"
)

// ErrInvalidLDAPGroupMatcher combines malformed rule configuration and
// malformed runtime group identities so callers cannot turn matcher details
// into a directory-data oracle.
var ErrInvalidLDAPGroupMatcher = errors.New("invalid LDAP group matcher")

// LDAPGroupMatcherKind is the closed v1 matching surface.
type LDAPGroupMatcherKind uint8

const (
	LDAPGroupMatcherExactDN LDAPGroupMatcherKind = iota + 1
	LDAPGroupMatcherExactCN
	LDAPGroupMatcherRegex
)

// LDAPGroupCaseMode is explicit; its zero value fails closed.
type LDAPGroupCaseMode uint8

const (
	LDAPGroupCaseSensitive LDAPGroupCaseMode = iota + 1
	LDAPGroupCaseInsensitive
)

const (
	// Keep exact-DN mappings aligned with the canonical DN grammar and the
	// OpenAPI/DB 2,048-character / 8,192-byte contract.
	maximumLDAPGroupCanonicalDNBytes    = maximumLDAPDNBytes
	maximumLDAPGroupMatcherPatternBytes = 512
	maximumLDAPGroupCNCharacters        = 512
)

// LDAPGroupMatcherSpec is validated once when a mapping-rule epoch is
// published. Pattern is a parsed DN, a decoded CN value, or a Go/RE2 pattern
// according to Kind.
type LDAPGroupMatcherSpec struct {
	Kind     LDAPGroupMatcherKind
	CaseMode LDAPGroupCaseMode
	Pattern  string
}

func (spec LDAPGroupMatcherSpec) String() string {
	return fmt.Sprintf(
		"identity.LDAPGroupMatcherSpec{kind:%d,caseMode:%d,pattern:[REDACTED]}",
		spec.Kind, spec.CaseMode,
	)
}
func (spec LDAPGroupMatcherSpec) GoString() string { return spec.String() }

// CompiledLDAPGroupMatcher retains only parsed/compiled forms. It is immutable
// after construction and its zero value cannot match.
type CompiledLDAPGroupMatcher struct {
	kind     LDAPGroupMatcherKind
	caseMode LDAPGroupCaseMode
	exactDN  *ldap.DN
	exactCN  string
	regex    *regexp.Regexp
}

// String redacts the configured directory identifier or expression.
func (matcher CompiledLDAPGroupMatcher) String() string {
	return fmt.Sprintf(
		"identity.CompiledLDAPGroupMatcher{kind:%d,caseMode:%d,pattern:[REDACTED]}",
		matcher.kind,
		matcher.caseMode,
	)
}

func (matcher CompiledLDAPGroupMatcher) GoString() string { return matcher.String() }

func (matcher CompiledLDAPGroupMatcher) valid() bool {
	if matcher.caseMode != LDAPGroupCaseSensitive && matcher.caseMode != LDAPGroupCaseInsensitive {
		return false
	}
	switch matcher.kind {
	case LDAPGroupMatcherExactDN:
		return matcher.exactDN != nil
	case LDAPGroupMatcherExactCN:
		return matcher.exactCN != ""
	case LDAPGroupMatcherRegex:
		return matcher.regex != nil
	default:
		return false
	}
}

// CompileLDAPGroupMatcher validates and compiles one mapping matcher. Regexes
// are full-string and bounded; user-supplied inline flags are rejected so the
// explicit CaseMode remains authoritative.
func CompileLDAPGroupMatcher(spec LDAPGroupMatcherSpec) (CompiledLDAPGroupMatcher, error) {
	if spec.CaseMode != LDAPGroupCaseSensitive && spec.CaseMode != LDAPGroupCaseInsensitive {
		return CompiledLDAPGroupMatcher{}, ErrInvalidLDAPGroupMatcher
	}
	switch spec.Kind {
	case LDAPGroupMatcherExactDN:
		dn, err := ParseLDAPDistinguishedName(spec.Pattern)
		if err != nil || len(dn.value) > maximumLDAPGroupCanonicalDNBytes || dn.dn == nil {
			return CompiledLDAPGroupMatcher{}, ErrInvalidLDAPGroupMatcher
		}
		return CompiledLDAPGroupMatcher{
			kind: spec.Kind, caseMode: spec.CaseMode, exactDN: dn.dn,
		}, nil
	case LDAPGroupMatcherExactCN:
		if !validLDAPGroupMatcherText(
			spec.Pattern,
			maximumLDAPGroupCNCharacters,
			maximumLDAPGroupMatcherPatternBytes,
		) {
			return CompiledLDAPGroupMatcher{}, ErrInvalidLDAPGroupMatcher
		}
		return CompiledLDAPGroupMatcher{
			kind: spec.Kind, caseMode: spec.CaseMode, exactCN: spec.Pattern,
		}, nil
	case LDAPGroupMatcherRegex:
		if !validLDAPGroupMatcherText(
			spec.Pattern,
			maximumLDAPGroupMatcherPatternBytes,
			maximumLDAPGroupMatcherPatternBytes,
		) || ldapRegexContainsInlineFlags(spec.Pattern) {
			return CompiledLDAPGroupMatcher{}, ErrInvalidLDAPGroupMatcher
		}
		expression := `\A(?:` + spec.Pattern + `)\z`
		if spec.CaseMode == LDAPGroupCaseInsensitive {
			expression = `\A(?i:(?:` + spec.Pattern + `))\z`
		}
		compiled, err := regexp.Compile(expression)
		if err != nil {
			return CompiledLDAPGroupMatcher{}, ErrInvalidLDAPGroupMatcher
		}
		return CompiledLDAPGroupMatcher{
			kind: spec.Kind, caseMode: spec.CaseMode, regex: compiled,
		}, nil
	default:
		return CompiledLDAPGroupMatcher{}, ErrInvalidLDAPGroupMatcher
	}
}

// Match evaluates a canonical parsed group DN. It returns an error for an
// invalid compiled matcher, an oversized group identity, or an ambiguous leaf
// CN; those observations must not be treated as a clean non-match.
func (matcher CompiledLDAPGroupMatcher) Match(group LDAPDistinguishedName) (bool, error) {
	if !matcher.valid() || !group.valid || group.dn == nil || group.dn.String() != group.value ||
		len(group.value) > maximumLDAPGroupCanonicalDNBytes {
		return false, ErrInvalidLDAPGroupMatcher
	}
	switch matcher.kind {
	case LDAPGroupMatcherExactDN:
		if matcher.exactDN == nil {
			return false, ErrInvalidLDAPGroupMatcher
		}
		if matcher.caseMode == LDAPGroupCaseSensitive {
			return matcher.exactDN.Equal(group.dn), nil
		}
		if matcher.caseMode == LDAPGroupCaseInsensitive {
			return matcher.exactDN.EqualFold(group.dn), nil
		}
	case LDAPGroupMatcherExactCN:
		if matcher.exactCN == "" ||
			(matcher.caseMode != LDAPGroupCaseSensitive && matcher.caseMode != LDAPGroupCaseInsensitive) {
			return false, ErrInvalidLDAPGroupMatcher
		}
		cn, present, err := ldapLeafCN(group.dn)
		if err != nil {
			return false, err
		}
		if !present {
			return false, nil
		}
		if matcher.caseMode == LDAPGroupCaseSensitive {
			return cn == matcher.exactCN, nil
		}
		return strings.EqualFold(cn, matcher.exactCN), nil
	case LDAPGroupMatcherRegex:
		if matcher.regex == nil ||
			(matcher.caseMode != LDAPGroupCaseSensitive && matcher.caseMode != LDAPGroupCaseInsensitive) {
			return false, ErrInvalidLDAPGroupMatcher
		}
		return matcher.regex.MatchString(group.value), nil
	}
	return false, ErrInvalidLDAPGroupMatcher
}

func ldapLeafCN(dn *ldap.DN) (string, bool, error) {
	if dn == nil || len(dn.RDNs) == 0 || dn.RDNs[0] == nil {
		return "", false, ErrInvalidLDAPGroupMatcher
	}
	var value string
	count := 0
	for _, attribute := range dn.RDNs[0].Attributes {
		if attribute == nil {
			return "", false, ErrInvalidLDAPGroupMatcher
		}
		if strings.EqualFold(attribute.Type, "cn") {
			count++
			value = attribute.Value
		}
	}
	if count > 1 {
		return "", false, ErrInvalidLDAPGroupMatcher
	}
	return value, count == 1, nil
}

func validLDAPGroupMatcherText(value string, maximumCharacters, maximumBytes int) bool {
	if value == "" || len(value) > maximumBytes || !utf8.ValidString(value) ||
		utf8.RuneCountInString(value) > maximumCharacters {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

// ldapRegexContainsInlineFlags recognizes unescaped flag groups outside
// character classes. Non-capturing and named groups remain available.
func ldapRegexContainsInlineFlags(value string) bool {
	escaped := false
	inClass := false
	for index := 0; index < len(value); index++ {
		character := value[index]
		if escaped {
			escaped = false
			continue
		}
		if character == '\\' {
			escaped = true
			continue
		}
		if character == '[' {
			inClass = true
			continue
		}
		if character == ']' && inClass {
			inClass = false
			continue
		}
		if inClass || character != '(' || index+2 >= len(value) || value[index+1] != '?' {
			continue
		}
		next := value[index+2]
		if next == ':' || next == 'P' || next == '<' {
			continue
		}
		if next == 'i' || next == 'm' || next == 's' || next == 'U' || next == '-' {
			return true
		}
	}
	return false
}
