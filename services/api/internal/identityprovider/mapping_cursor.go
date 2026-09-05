package identityprovider

import (
	"encoding/base64"
	"encoding/binary"
	"errors"

	"github.com/google/uuid"
)

const (
	ldapMappingCursorVersion = byte(1)
	ldapMappingCursorBytes   = 1 + 4 + 16
	LDAPMappingCursorLength  = 28
)

var ErrInvalidMappingCursor = errors.New("invalid LDAP mapping cursor")

// MappingCursor captures the complete mutable ordering tuple returned by a
// mapping page. It is opaque on the wire and is not authorization evidence.
type MappingCursor struct {
	Priority int
	ID       uuid.UUID
}

func NewMappingCursor(priority int, mappingID uuid.UUID) (MappingCursor, error) {
	value := MappingCursor{Priority: priority, ID: mappingID}
	if !validMappingCursor(value) {
		return MappingCursor{}, ErrInvalidMappingCursor
	}
	return value, nil
}

func EncodeMappingCursor(value MappingCursor) (string, error) {
	if !validMappingCursor(value) {
		return "", ErrInvalidMappingCursor
	}
	var payload [ldapMappingCursorBytes]byte
	payload[0] = ldapMappingCursorVersion
	binary.BigEndian.PutUint32(payload[1:5], uint32(value.Priority))
	copy(payload[5:], value.ID[:])
	encoded := base64.RawURLEncoding.EncodeToString(payload[:])
	if len(encoded) != LDAPMappingCursorLength {
		return "", ErrInvalidMappingCursor
	}
	return encoded, nil
}

func DecodeMappingCursor(encoded string) (MappingCursor, error) {
	if len(encoded) != LDAPMappingCursorLength {
		return MappingCursor{}, ErrInvalidMappingCursor
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(payload) != ldapMappingCursorBytes ||
		payload[0] != ldapMappingCursorVersion ||
		base64.RawURLEncoding.EncodeToString(payload) != encoded {
		return MappingCursor{}, ErrInvalidMappingCursor
	}
	value := MappingCursor{
		Priority: int(binary.BigEndian.Uint32(payload[1:5])),
		ID:       uuid.UUID(payload[5:]),
	}
	if !validMappingCursor(value) {
		return MappingCursor{}, ErrInvalidMappingCursor
	}
	return value, nil
}

func validMappingCursor(value MappingCursor) bool {
	return value.Priority >= 0 && value.Priority <= maximumLDAPAdministrationPriority &&
		validUUIDv7(value.ID)
}
