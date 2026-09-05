package identityprovider

import (
	"errors"
	"strings"
	"testing"
)

func TestLDAPMappingCursorRoundTripsTheCompleteOrderingTuple(t *testing.T) {
	mappingID := mustAdministrationUUIDv7(t)
	cursor, err := NewMappingCursor(42, mappingID)
	if err != nil {
		t.Fatalf("NewMappingCursor() error = %v", err)
	}
	encoded, err := EncodeMappingCursor(cursor)
	if err != nil {
		t.Fatalf("EncodeMappingCursor() error = %v", err)
	}
	if len(encoded) != LDAPMappingCursorLength || strings.ContainsAny(encoded, "+/=") {
		t.Fatalf("encoded cursor = %q", encoded)
	}
	decoded, err := DecodeMappingCursor(encoded)
	if err != nil {
		t.Fatalf("DecodeMappingCursor() error = %v", err)
	}
	if decoded != cursor {
		t.Fatalf("decoded cursor = %#v, want %#v", decoded, cursor)
	}
}

func TestLDAPMappingCursorRejectsMalformedOrNonCanonicalValues(t *testing.T) {
	valid, err := EncodeMappingCursor(MappingCursor{Priority: 1, ID: mustAdministrationUUIDv7(t)})
	if err != nil {
		t.Fatalf("EncodeMappingCursor() error = %v", err)
	}
	for name, value := range map[string]string{
		"empty":        "",
		"wrong length": valid[:len(valid)-1],
		"padding":      valid[:len(valid)-1] + "=",
		"alphabet":     strings.Repeat("+", LDAPMappingCursorLength),
		"version":      "Ag" + valid[2:],
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeMappingCursor(value); !errors.Is(err, ErrInvalidMappingCursor) {
				t.Fatalf("DecodeMappingCursor(%q) error = %v", value, err)
			}
		})
	}
	if _, err := EncodeMappingCursor(MappingCursor{Priority: -1, ID: mustAdministrationUUIDv7(t)}); !errors.Is(err, ErrInvalidMappingCursor) {
		t.Fatalf("negative priority error = %v", err)
	}
}
