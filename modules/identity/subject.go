package identity

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/cases"
)

const (
	maximumCanonicalSubjectBytes  = 4 * 1024
	subjectAliasSchema            = "periapsis/identity/external-subject-alias/v1"
	oidcSubjectPrefix             = "periapsis/oidc-subject/v1\x00"
	maximumOIDCIssuerBytes        = 2 * 1024
	maximumOIDCSubjectBytes       = 1024
	samlSubjectPrefix             = "periapsis/saml-subject/v1\x00"
	maximumSAMLSubjectSourceBytes = 64
	maximumSAMLSubjectNameBytes   = 512
	maximumSAMLSubjectFormatBytes = 512
	maximumSAMLSubjectValueBytes  = 4 * 1024
)

// ErrInvalidSubject combines invalid formats, values, and provider contexts so
// rejection paths never reflect the subject value.
var ErrInvalidSubject = errors.New("invalid immutable subject")

// SubjectFormat records the canonical byte semantics fixed by the provider.
type SubjectFormat uint8

const (
	ADObjectGUIDSubject SubjectFormat = iota + 1
	EntryUUIDSubject
	UTF8ExactSubject
	UTF8CaseFoldSubject
)

// Subject is an immutable canonical identity value. Its bytes stay private to
// this package so callers cannot accidentally persist plaintext lookup keys.
type Subject struct {
	format SubjectFormat
	value  []byte
}

// Format returns the canonicalization profile, not the subject bytes.
func (s Subject) Format() SubjectFormat {
	return s.format
}

// String redacts the canonical bytes while preserving the non-secret format
// for diagnostics.
func (s Subject) String() string {
	return "identity.Subject{format:" + strconv.Itoa(int(s.format)) + ",value:[REDACTED]}"
}

// GoString provides the same redaction for %#v formatting.
func (s Subject) GoString() string {
	return s.String()
}

// Clear releases the caller-owned canonical bytes after aliasing, encryption,
// or comparison. Copies of Subject share the same backing bytes, so their
// customer value is zeroed too; callers must not reuse copies after Clear.
func (s *Subject) Clear() {
	if s == nil {
		return
	}
	clear(s.value)
	s.value = nil
	s.format = 0
}

// CanonicalADObjectGUID accepts exactly the 16 raw bytes returned by Active
// Directory. It does not apply textual GUID byte-order transformations.
func CanonicalADObjectGUID(value []byte) (Subject, error) {
	if len(value) != 16 || allZero(value) {
		return Subject{}, ErrInvalidSubject
	}
	return Subject{format: ADObjectGUIDSubject, value: append([]byte(nil), value...)}, nil
}

// CanonicalEntryUUID parses the canonical RFC 4122 8-4-4-4-12 textual form and
// stores its 16 network-order bytes. Hexadecimal digits are case-insensitive.
func CanonicalEntryUUID(value string) (Subject, error) {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return Subject{}, ErrInvalidSubject
	}
	decoded := make([]byte, 16)
	for sourceIndex, destinationIndex := 0, 0; sourceIndex < len(value); {
		if sourceIndex == 8 || sourceIndex == 13 || sourceIndex == 18 || sourceIndex == 23 {
			sourceIndex++
			continue
		}
		high, highOK := hexadecimalNibble(value[sourceIndex])
		low, lowOK := hexadecimalNibble(value[sourceIndex+1])
		if !highOK || !lowOK {
			clear(decoded)
			return Subject{}, ErrInvalidSubject
		}
		decoded[destinationIndex] = high<<4 | low
		sourceIndex += 2
		destinationIndex++
	}
	version := decoded[6] >> 4
	if allZero(decoded) || decoded[8]&0xc0 != 0x80 || version < 1 || version > 5 {
		clear(decoded)
		return Subject{}, ErrInvalidSubject
	}
	return Subject{format: EntryUUIDSubject, value: decoded}, nil
}

// CanonicalUTF8Exact copies valid, non-empty UTF-8 without normalization or
// case conversion.
func CanonicalUTF8Exact(value []byte) (Subject, error) {
	if !validCustomSubject(value) {
		return Subject{}, ErrInvalidSubject
	}
	return Subject{format: UTF8ExactSubject, value: append([]byte(nil), value...)}, nil
}

// CanonicalUTF8CaseFold applies Unicode default case folding without Unicode
// normalization. The post-fold value must remain within the subject bound.
func CanonicalUTF8CaseFold(value []byte) (Subject, error) {
	if !validCustomSubject(value) {
		return Subject{}, ErrInvalidSubject
	}
	folded := []byte(cases.Fold().String(string(value)))
	if !validCustomSubject(folded) {
		clear(folded)
		return Subject{}, ErrInvalidSubject
	}
	return Subject{format: UTF8CaseFoldSubject, value: folded}, nil
}

// CanonicalOIDCIssuerSubject preserves the exact (issuer, sub) tuple in one
// provider-qualified subject. Both inputs reject controls, so the versioned
// NUL separator is unambiguous; neither value is normalized or case-folded.
func CanonicalOIDCIssuerSubject(issuer, subject string) (Subject, error) {
	if !validFederatedSubjectComponent(issuer, maximumOIDCIssuerBytes) ||
		!validFederatedSubjectComponent(subject, maximumOIDCSubjectBytes) {
		return Subject{}, ErrInvalidSubject
	}
	value := make([]byte, 0, len(oidcSubjectPrefix)+len(issuer)+1+len(subject))
	value = append(value, oidcSubjectPrefix...)
	value = append(value, issuer...)
	value = append(value, 0)
	value = append(value, subject...)
	if !validCustomSubject(value) {
		clear(value)
		return Subject{}, ErrInvalidSubject
	}
	return Subject{format: UTF8ExactSubject, value: value}, nil
}

// CanonicalSAMLSubjectTuple preserves the exact immutable SAML identity tuple
// (issuer, source, name, format, value) in the tenant and direct-platform
// planners. Decimal length framing makes tuple boundaries unambiguous without
// normalizing or case-folding any component.
func CanonicalSAMLSubjectTuple(issuer, source, name, format, value string) (Subject, error) {
	if !validSAMLSubjectComponent(issuer, maximumOIDCIssuerBytes) ||
		!validSAMLSubjectComponent(source, maximumSAMLSubjectSourceBytes) ||
		!validSAMLSubjectComponent(name, maximumSAMLSubjectNameBytes) ||
		!validSAMLSubjectComponent(format, maximumSAMLSubjectFormatBytes) ||
		!validSAMLSubjectComponent(value, maximumSAMLSubjectValueBytes) {
		return Subject{}, ErrInvalidSubject
	}
	fields := [...]string{issuer, source, name, format, value}
	capacity := len(samlSubjectPrefix)
	for _, field := range fields {
		capacity += len(strconv.Itoa(len(field))) + 1 + len(field)
	}
	canonical := make([]byte, 0, capacity)
	canonical = append(canonical, samlSubjectPrefix...)
	for _, field := range fields {
		canonical = strconv.AppendInt(canonical, int64(len(field)), 10)
		canonical = append(canonical, ':')
		canonical = append(canonical, field...)
	}
	if !validCustomSubject(canonical) {
		clear(canonical)
		return Subject{}, ErrInvalidSubject
	}
	return Subject{format: UTF8ExactSubject, value: canonical}, nil
}

func validSAMLSubjectComponent(value string, maximum int) bool {
	if value == "" || len(value) > maximum || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validFederatedSubjectComponent(value string, maximum int) bool {
	if value == "" || len(value) > maximum || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || character == '\u061c' ||
			character == '\u200e' || character == '\u200f' ||
			character >= '\u202a' && character <= '\u202e' ||
			character >= '\u2066' && character <= '\u2069' {
			return false
		}
	}
	return true
}

func validCustomSubject(value []byte) bool {
	return len(value) > 0 && len(value) <= maximumCanonicalSubjectBytes && utf8.Valid(value)
}

func hexadecimalNibble(value byte) (byte, bool) {
	switch {
	case value >= '0' && value <= '9':
		return value - '0', true
	case value >= 'a' && value <= 'f':
		return value - 'a' + 10, true
	case value >= 'A' && value <= 'F':
		return value - 'A' + 10, true
	default:
		return 0, false
	}
}

func allZero(value []byte) bool {
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined == 0
}

// SubjectAlias is a provider-qualified, versioned database lookup value.
type SubjectAlias struct {
	KeyVersion int16
	Digest     [sha256.Size]byte
}

func (alias SubjectAlias) String() string {
	return "identity.SubjectAlias{keyVersion:" + strconv.Itoa(int(alias.KeyVersion)) + ",digest:[REDACTED]}"
}
func (alias SubjectAlias) GoString() string { return alias.String() }

// SubjectAliases computes one deterministic HMAC-SHA-256 lookup alias for
// every retained key. Results are sorted by key version. Provider context and
// subject format are authenticated into the digest, preventing cross-provider
// correlation and cross-format reinterpretation.
func (k Keyring) SubjectAliases(context ProviderContext, subject Subject) ([]SubjectAlias, error) {
	if err := validateProviderContext(context); err != nil || !validCanonicalSubject(subject) {
		return nil, ErrInvalidSubject
	}
	message := subjectAliasMessage(context, subject)
	defer clear(message)

	versions := k.Versions()
	if len(versions) < 1 {
		return nil, ErrInvalidKeyring
	}
	aliases := make([]SubjectAlias, 0, len(versions))
	for _, version := range versions {
		keysForVersion, exists := k.keys[version]
		if !exists {
			return nil, ErrInvalidKeyring
		}
		aliasKey := keysForVersion.subjectAlias
		mac := hmac.New(sha256.New, aliasKey[:])
		_, _ = mac.Write(message)
		digestBytes := mac.Sum(nil)
		clear(aliasKey[:])
		clearVersionKey(&keysForVersion)
		var digest [sha256.Size]byte
		copy(digest[:], digestBytes)
		clear(digestBytes)
		aliases = append(aliases, SubjectAlias{KeyVersion: version, Digest: digest})
		clear(digest[:])
	}
	return aliases, nil
}

func validCanonicalSubject(subject Subject) bool {
	switch subject.format {
	case ADObjectGUIDSubject, EntryUUIDSubject:
		return len(subject.value) == 16 && !allZero(subject.value)
	case UTF8ExactSubject, UTF8CaseFoldSubject:
		return validCustomSubject(subject.value)
	default:
		return false
	}
}

func subjectAliasMessage(context ProviderContext, subject Subject) []byte {
	message := make([]byte, 0, 128+len(subject.value))
	message = appendTypedField(message, fieldSchema, []byte(subjectAliasSchema))
	message = appendProviderContext(message, context)
	message = appendTypedField(message, fieldSubjectFormat, []byte{byte(subject.format)})
	message = appendTypedField(message, fieldSubjectValue, subject.value)
	return message
}
