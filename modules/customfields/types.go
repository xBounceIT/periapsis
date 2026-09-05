package customfields

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maximumKeyBytes           = 64
	maximumLabelBytes         = 256
	maximumDescriptionBytes   = 8 * 1024
	maximumOptions            = 512
	maximumTransitionKeys     = 128
	maximumPatternBytes       = 512
	maximumJSONBytes          = 64 * 1024
	maximumJSONDepth          = 32
	maximumJSONValues         = 4_096
	maximumDefinitionVersion  = uint64(math.MaxInt64)
	maximumCanonicalTextBytes = 64 * 1024
)

var (
	ErrInvalidID               = errors.New("invalid custom-field entity id")
	ErrInvalidDefinition       = errors.New("invalid custom-field definition")
	ErrDefinitionConflict      = errors.New("custom-field definition version conflict")
	ErrMigrationRequired       = errors.New("explicit custom-field value migration required")
	ErrInvalidLayout           = errors.New("invalid custom-field layout")
	ErrInvalidValidationInput  = errors.New("invalid custom-field validation input")
	ErrValidationContextDenied = errors.New("custom-field edit context denied")
)

// EntityID is an RFC 9562 UUIDv7. Restricting identifiers at the domain edge
// preserves sortable IDs and prevents ambiguous textual representations.
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
		return Key{}, ErrInvalidDefinition
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

type ObjectType string

const (
	ObjectAlert ObjectType = "alert"
	ObjectCase  ObjectType = "case"
)

func validObjectType(value ObjectType) bool {
	return value == ObjectAlert || value == ObjectCase
}

type DataType string

const (
	TypeShortText       DataType = "short_text"
	TypeLongText        DataType = "long_text"
	TypeInteger         DataType = "integer"
	TypeDecimal         DataType = "decimal"
	TypeBoolean         DataType = "boolean"
	TypeDate            DataType = "date"
	TypeDateTime        DataType = "datetime"
	TypeDuration        DataType = "duration"
	TypeSingleSelect    DataType = "single_select"
	TypeMultiSelect     DataType = "multi_select"
	TypeURL             DataType = "url"
	TypeEmail           DataType = "email"
	TypeIP              DataType = "ip"
	TypeCIDR            DataType = "cidr"
	TypeUser            DataType = "user"
	TypeOperatorTeam    DataType = "operator_team"
	TypeCustomerContact DataType = "customer_contact"
	TypeAssetReference  DataType = "asset_reference"
	TypeIOCReference    DataType = "ioc_reference"
	TypeStructuredJSON  DataType = "structured_json"
)

func validDataType(value DataType) bool {
	switch value {
	case TypeShortText, TypeLongText, TypeInteger, TypeDecimal, TypeBoolean,
		TypeDate, TypeDateTime, TypeDuration, TypeSingleSelect, TypeMultiSelect,
		TypeURL, TypeEmail, TypeIP, TypeCIDR, TypeUser, TypeOperatorTeam,
		TypeCustomerContact, TypeAssetReference, TypeIOCReference, TypeStructuredJSON:
		return true
	default:
		return false
	}
}

func isReferenceType(value DataType) bool {
	switch value {
	case TypeUser, TypeOperatorTeam, TypeCustomerContact, TypeAssetReference, TypeIOCReference:
		return true
	default:
		return false
	}
}

type Audience string

const (
	AudienceCustomer Audience = "customer"
	AudienceOperator Audience = "operator"
	AudienceSystem   Audience = "system"
)

func validAudience(value Audience) bool {
	return value == AudienceCustomer || value == AudienceOperator || value == AudienceSystem
}

type WritePhase string

const (
	PhaseCreate     WritePhase = "create"
	PhaseUpdate     WritePhase = "update"
	PhaseTransition WritePhase = "transition"
	PhaseBulkImport WritePhase = "bulk_import"
)

func validWritePhase(value WritePhase) bool {
	return value == PhaseCreate || value == PhaseUpdate || value == PhaseTransition || value == PhaseBulkImport
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
