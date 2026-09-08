package contacts

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	maximumKeyBytes           = 64
	maximumNameBytes          = 160
	maximumFunctionBytes      = 160
	maximumPhoneBytes         = 64
	maximumEmailBytes         = 320
	maximumDescriptionBytes   = 2 * 1024
	maximumTags               = 100
	maximumCategories         = 64
	maximumWindows            = 64
	maximumRuleDepth          = 8
	maximumRuleNodes          = 128
	maximumPredicateValues    = 64
	maximumGroupMembers       = 10_000
	maximumResolutionContacts = 10_000
)

var (
	ErrInvalidID        = errors.New("invalid contact entity id")
	ErrInvalidKey       = errors.New("invalid contact key")
	ErrInvalidContact   = errors.New("invalid customer contact")
	ErrVersionConflict  = errors.New("contact version conflict")
	ErrInvalidGroup     = errors.New("invalid customer contact group")
	ErrInvalidRule      = errors.New("invalid recipient rule")
	ErrInvalidTarget    = errors.New("invalid recipient target")
	ErrResolutionDenied = errors.New("recipient resolution denied")
	ErrResolutionDrift  = errors.New("recipient resolution input drift")
)

// EntityID is a validated RFC 9562 UUIDv7 and is safe as a map key.
type EntityID struct{ value [16]byte }

func NewEntityID(value [16]byte) (EntityID, error) {
	if value[6]>>4 != 7 || value[8]&0xc0 != 0x80 {
		return EntityID{}, ErrInvalidID
	}
	return EntityID{value: value}, nil
}

func ParseEntityID(value string) (EntityID, error) {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return EntityID{}, ErrInvalidID
	}
	var raw [16]byte
	write := 0
	for read := 0; read < len(value); {
		if value[read] == '-' {
			read++
			continue
		}
		if read+1 >= len(value) || write >= len(raw) {
			return EntityID{}, ErrInvalidID
		}
		high, highOK := hexadecimalNibble(value[read])
		low, lowOK := hexadecimalNibble(value[read+1])
		if !highOK || !lowOK {
			return EntityID{}, ErrInvalidID
		}
		raw[write] = high<<4 | low
		write++
		read += 2
	}
	if write != len(raw) {
		return EntityID{}, ErrInvalidID
	}
	return NewEntityID(raw)
}

func hexadecimalNibble(value byte) (byte, bool) {
	switch {
	case value >= '0' && value <= '9':
		return value - '0', true
	case value >= 'a' && value <= 'f':
		return value - 'a' + 10, true
	default:
		return 0, false
	}
}

func (id EntityID) Bytes() [16]byte { return id.value }

func (id EntityID) String() string {
	v := id.value
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", v[0:4], v[4:6], v[6:8], v[8:10], v[10:16])
}

func validEntityID(value EntityID) bool {
	return value.value[6]>>4 == 7 && value.value[8]&0xc0 == 0x80
}

func compareEntityID(left, right EntityID) int {
	return bytes.Compare(left.value[:], right.value[:])
}

// Key is a small canonical ASCII identifier used for tags, categories, class,
// and recipient-rule paths. It avoids locale-dependent equality and ordering.
type Key struct{ value string }

func NewKey(value string) (Key, error) {
	if !validKey(value) {
		return Key{}, ErrInvalidKey
	}
	return Key{value: value}, nil
}

func (key Key) String() string { return key.value }

func validKey(value string) bool {
	if len(value) == 0 || len(value) > maximumKeyBytes || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' ||
			character == '_' || character == '-' || character == '.' {
			continue
		}
		return false
	}
	return true
}

type Email struct{ canonical string }

func NewEmail(value string) (Email, error) {
	canonical := strings.ToLower(value)
	if value != strings.TrimSpace(value) || len(canonical) < 3 || len(canonical) > maximumEmailBytes ||
		!utf8.ValidString(canonical) || !validEmailShape(canonical) {
		return Email{}, ErrInvalidContact
	}
	return Email{canonical: canonical}, nil
}

func (email Email) String() string { return email.canonical }

func validEmail(value Email) bool { return validEmailShape(value.canonical) }

func validEmailShape(value string) bool {
	if !isASCII(value) || strings.Count(value, "@") != 1 {
		return false
	}
	local, domain, _ := strings.Cut(value, "@")
	if len(local) == 0 || len(local) > 64 || len(domain) == 0 || len(domain) > 255 ||
		local[0] == '.' || local[len(local)-1] == '.' || strings.Contains(local, "..") {
		return false
	}
	for _, character := range local {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' ||
			strings.ContainsRune("!#$%&'*+-/=?^_`{|}~.", character) {
			continue
		}
		return false
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func isASCII(value string) bool {
	for index := range len(value) {
		if value[index] > unicode.MaxASCII {
			return false
		}
	}
	return true
}

func canonicalKeys(values []Key, maximum int) ([]Key, bool) {
	if len(values) > maximum {
		return nil, false
	}
	result := slices.Clone(values)
	for _, value := range result {
		if !validKey(value.value) {
			return nil, false
		}
	}
	slices.SortFunc(result, func(left, right Key) int { return strings.Compare(left.value, right.value) })
	for index := 1; index < len(result); index++ {
		if result[index-1] == result[index] {
			return nil, false
		}
	}
	return result, true
}

func canonicalIDs(values []EntityID, maximum int) ([]EntityID, bool) {
	if len(values) > maximum {
		return nil, false
	}
	result := slices.Clone(values)
	for _, value := range result {
		if !validEntityID(value) {
			return nil, false
		}
	}
	slices.SortFunc(result, compareEntityID)
	for index := 1; index < len(result); index++ {
		if result[index-1] == result[index] {
			return nil, false
		}
	}
	return result, true
}

func validText(value string, maximum int, optional bool) bool {
	if value == "" {
		return optional
	}
	if len(value) > maximum || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || directionalControl(character) {
			return false
		}
	}
	return true
}

func directionalControl(character rune) bool {
	return character == '\u200e' || character == '\u200f' ||
		character >= '\u202a' && character <= '\u202e' ||
		character >= '\u2066' && character <= '\u2069'
}

var contactLanguagePattern = regexp.MustCompile(`^[a-z]{2,3}(-[A-Z][a-z]{3})?(-([A-Z]{2}|[0-9]{3}))?$`)

func validLanguage(value string) bool { return contactLanguagePattern.MatchString(value) }

func validTimezone(value string) bool {
	if len(value) < 1 || len(value) > 64 || value == "Local" || strings.HasPrefix(value, "/") ||
		strings.Contains(value, "\\") || strings.Contains(value, "..") {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || strings.ContainsRune("_+-/", character) {
			continue
		}
		return false
	}
	_, err := time.LoadLocation(value)
	return err == nil
}

func validInstant(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond()%1_000 == 0
}

func parseBoundedInteger(value string, minimum, maximum int) (int, bool) {
	parsed, err := strconv.Atoi(value)
	return parsed, err == nil && parsed >= minimum && parsed <= maximum && strconv.Itoa(parsed) == value
}
