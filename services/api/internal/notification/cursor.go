package notification

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	notificationCursorSchema       = "periapsis/notification/admin-cursor/hmac-sha256/message/v1"
	notificationCursorPayloadLimit = 384
	notificationCursorTagBytes     = sha256.Size
)

type CursorKind string

const (
	CursorKindRules      CursorKind = "rules"
	CursorKindTemplates  CursorKind = "templates"
	CursorKindDeliveries CursorKind = "deliveries"
	CursorKindWebhooks   CursorKind = "webhooks"
)

type CursorPosition struct {
	CreatedAt time.Time
	ID        uuid.UUID
}

type notificationCursorPayload struct {
	Kind       CursorKind `json:"k"`
	TenantID   uuid.UUID  `json:"t"`
	Filter     string     `json:"f"`
	CreatedAt  time.Time  `json:"c"`
	ID         uuid.UUID  `json:"i"`
	KeyVersion int16      `json:"v"`
}

// EncodeCursor creates a bounded opaque token whose stable ordering tuple is
// bound to the exact tenant, resource inventory, and normalized list filter.
func (k Keyring) EncodeCursor(kind CursorKind, tenantID uuid.UUID, filter string, position CursorPosition) (string, error) {
	if !validCursorBinding(kind, tenantID, filter, position) {
		return "", ErrInvalidCursor
	}
	key, exists := k.cursorKeys[k.activeVersion]
	if !exists {
		return "", ErrInvalidKeyring
	}
	payload, err := json.Marshal(notificationCursorPayload{
		Kind: kind, TenantID: tenantID, Filter: filter,
		CreatedAt: position.CreatedAt.UTC().Truncate(time.Microsecond), ID: position.ID,
		KeyVersion: k.activeVersion,
	})
	if err != nil || len(payload) > notificationCursorPayloadLimit {
		clear(key[:])
		return "", ErrInvalidCursor
	}
	tag := notificationCursorMAC(key, payload)
	clear(key[:])
	envelope := make([]byte, 2+len(payload)+len(tag))
	binary.BigEndian.PutUint16(envelope[:2], uint16(len(payload)))
	copy(envelope[2:], payload)
	copy(envelope[2+len(payload):], tag)
	token := "n1." + base64.RawURLEncoding.EncodeToString(envelope)
	clear(tag)
	clear(envelope)
	if len(token) > maximumNotificationCursor || !cursorPattern.MatchString(token) {
		return "", ErrInvalidCursor
	}
	return token, nil
}

// DecodeCursor verifies the MAC before accepting any ordering data and then
// checks the caller-provided binding in constant-time where secrets are
// involved. All malformed and cross-context tokens fail identically.
func (k Keyring) DecodeCursor(token string, kind CursorKind, tenantID uuid.UUID, filter string) (CursorPosition, error) {
	if len(token) > maximumNotificationCursor || !cursorPattern.MatchString(token) || !validCursorKind(kind) ||
		!validUUIDv7(tenantID) || !validCursorFilter(filter) {
		return CursorPosition{}, ErrInvalidCursor
	}
	envelope, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(token, "n1."))
	if err != nil || len(envelope) < 2+notificationCursorTagBytes {
		clear(envelope)
		return CursorPosition{}, ErrInvalidCursor
	}
	payloadLength := int(binary.BigEndian.Uint16(envelope[:2]))
	if payloadLength < 1 || payloadLength > notificationCursorPayloadLimit || len(envelope) != 2+payloadLength+notificationCursorTagBytes {
		clear(envelope)
		return CursorPosition{}, ErrInvalidCursor
	}
	payload := envelope[2 : 2+payloadLength]
	tag := envelope[2+payloadLength:]
	var claimed notificationCursorPayload
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&claimed); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		clear(envelope)
		return CursorPosition{}, ErrInvalidCursor
	}
	key, exists := k.cursorKeys[claimed.KeyVersion]
	if !exists {
		clear(envelope)
		return CursorPosition{}, ErrInvalidCursor
	}
	expectedTag := notificationCursorMAC(key, payload)
	clear(key[:])
	validTag := hmac.Equal(tag, expectedTag)
	clear(expectedTag)
	if !validTag || claimed.Kind != kind || claimed.TenantID != tenantID || claimed.Filter != filter ||
		!validCursorBinding(claimed.Kind, claimed.TenantID, claimed.Filter, CursorPosition{CreatedAt: claimed.CreatedAt, ID: claimed.ID}) {
		clear(envelope)
		return CursorPosition{}, ErrInvalidCursor
	}
	position := CursorPosition{CreatedAt: claimed.CreatedAt.UTC().Truncate(time.Microsecond), ID: claimed.ID}
	clear(envelope)
	return position, nil
}

func notificationCursorMAC(key notificationCursorKey, payload []byte) []byte {
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte(notificationCursorSchema))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(payload)
	return mac.Sum(nil)
}

func validCursorBinding(kind CursorKind, tenantID uuid.UUID, filter string, position CursorPosition) bool {
	return validCursorKind(kind) && validUUIDv7(tenantID) && validCursorFilter(filter) &&
		validInstant(position.CreatedAt) && validUUIDv7(position.ID)
}

func validCursorKind(kind CursorKind) bool {
	return kind == CursorKindRules || kind == CursorKindTemplates || kind == CursorKindDeliveries || kind == CursorKindWebhooks
}

func validCursorFilter(filter string) bool {
	return len(filter) <= 128 && validText(filter, 0, 128, false)
}
