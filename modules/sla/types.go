package sla

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var (
	ErrInvalidID       = errors.New("invalid SLA entity id")
	ErrInvalidCalendar = errors.New("invalid SLA business calendar")
	ErrCalendarRange   = errors.New("SLA calendar computation exceeds supported range")
	ErrInvalidPolicy   = errors.New("invalid SLA policy")
	ErrAmbiguousPolicy = errors.New("multiple SLA policies have equal precedence")
	ErrInvalidMetric   = errors.New("invalid SLA metric")
	ErrMetricConflict  = errors.New("SLA metric version conflict")
	ErrInvalidEvent    = errors.New("invalid SLA event")
	ErrInvalidOverride = errors.New("invalid SLA override")
	ErrOverrideDenied  = errors.New("SLA override denied")
	ErrEngineCanceled  = errors.New("SLA engine evaluation canceled")
)

const (
	maximumVersion      = uint64(math.MaxInt64)
	maximumKeyBytes     = 64
	maximumLabelBytes   = 256
	maximumDescription  = 8 * 1024
	maximumCalendarDays = 36_600
)

type EntityID struct {
	value [16]byte
}

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

type Key struct {
	value string
}

func NewKey(value string) (Key, error) {
	if !validKey(value) {
		return Key{}, ErrInvalidPolicy
	}
	return Key{value: value}, nil
}

func (key Key) String() string { return key.value }

func validKey(value string) bool {
	if len(value) < 2 || len(value) > maximumKeyBytes || value[0] < 'a' || value[0] > 'z' {
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
	last := value[len(value)-1]
	return last >= 'a' && last <= 'z' || last >= '0' && last <= '9'
}

func validText(value string, maximum int, optional bool, multiline bool) bool {
	if value == "" {
		return optional
	}
	if len(value) > maximum || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if multiline && (character == '\n' || character == '\t') {
			continue
		}
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

func validInstant(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Year() >= 1970 && value.Year() <= 9999 &&
		value.Nanosecond()%1_000 == 0
}
