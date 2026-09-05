package dfir

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var (
	ErrInvalidID             = errors.New("invalid DFIR entity id")
	ErrInvalidIndicator      = errors.New("invalid indicator")
	ErrInvalidAsset          = errors.New("invalid asset")
	ErrInvalidEvidence       = errors.New("invalid evidence")
	ErrEvidenceConflict      = errors.New("evidence version conflict")
	ErrEvidenceRetention     = errors.New("evidence is retained or under legal hold")
	ErrInvalidTimelineEvent  = errors.New("invalid timeline event")
	ErrInvalidRelationship   = errors.New("invalid relationship")
	ErrInvalidAttachment     = errors.New("invalid attachment")
	ErrInvalidTask           = errors.New("invalid task")
	ErrTaskConflict          = errors.New("task version conflict")
	ErrInvalidStorageObject  = errors.New("invalid storage object")
	ErrStorageObjectConflict = errors.New("storage object version conflict")
	ErrStorageObjectRetained = errors.New("storage object is retained or under legal hold")
)

const (
	// MaximumResourceVersion is the largest revision that can cross the
	// OpenAPI/JSON boundary without losing integer precision. Mutations require
	// an expected revision strictly below this ceiling so the increment remains
	// exact for every client.
	MaximumResourceVersion = uint64(9_007_199_254_740_991)
	// MaximumCustodyEvents bounds immutable evidence receipt projections while
	// preserving a deterministic, shared Case and Alert custody ABI.
	MaximumCustodyEvents             = uint64(1_000)
	maximumAggregateVersion          = MaximumResourceVersion
	maximumIndicatorValueBytes       = 8 * 1024
	maximumIndicatorDescriptionBytes = 16 * 1024
	maximumIndicatorSourceBytes      = 512
	maximumIndicatorTags             = 256
	maximumIndicatorTagBytes         = 64
	maximumEnrichmentBytes           = 64 * 1024
	maximumEnrichmentDepth           = 32
	maximumEnrichmentValues          = 4_096
	maximumStorageObjectBytes        = int64(5_000_000_000)
)

// EntityID is a validated RFC 9562 UUIDv7. It deliberately has no parser that
// accepts ambiguous text spellings at this domain boundary.
type EntityID struct {
	value [16]byte
}

func NewEntityID(value [16]byte) (EntityID, error) {
	if value[6]>>4 != 7 || value[8]&0xc0 != 0x80 {
		return EntityID{}, ErrInvalidID
	}
	return EntityID{value: value}, nil
}

func (id EntityID) Bytes() [16]byte { return id.value }

func (id EntityID) String() string {
	v := id.value
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", v[0:4], v[4:6], v[6:8], v[8:10], v[10:16])
}

func validEntityID(id EntityID) bool {
	return id.value[6]>>4 == 7 && id.value[8]&0xc0 == 0x80
}

func compareEntityID(left, right EntityID) int {
	return bytes.Compare(left.value[:], right.value[:])
}

func validBoundedText(value string, maximum int, optional bool) bool {
	if value == "" {
		return optional
	}
	if len(value) > maximum || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character == '\n' || character == '\t' {
			continue
		}
		if unicode.IsControl(character) || isDirectionalControl(character) {
			return false
		}
	}
	return true
}

func validSingleLineText(value string, maximum int, optional bool) bool {
	return validBoundedText(value, maximum, optional) && !strings.ContainsAny(value, "\n\t")
}

func isDirectionalControl(character rune) bool {
	return character == '\u200e' || character == '\u200f' ||
		character >= '\u202a' && character <= '\u202e' ||
		character >= '\u2066' && character <= '\u2069'
}

func validInstant(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond()%1_000 == 0
}

func canonicalTags(values []string) ([]string, bool) {
	if len(values) > maximumIndicatorTags {
		return nil, false
	}
	result := slices.Clone(values)
	for _, value := range result {
		if !validTag(value) {
			return nil, false
		}
	}
	slices.Sort(result)
	for index := 1; index < len(result); index++ {
		if result[index-1] == result[index] {
			return nil, false
		}
	}
	return result, true
}

func validTag(value string) bool {
	if len(value) == 0 || len(value) > maximumIndicatorTagBytes || value[0] < 'a' || value[0] > 'z' {
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
