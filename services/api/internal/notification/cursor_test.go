package notification

import (
	"bytes"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestNotificationCursorRoundTripAndExactBinding(t *testing.T) {
	keyring := testKeyring(t)
	tenantID := mustV7(t)
	position := CursorPosition{CreatedAt: validInstantFixture(), ID: mustV7(t)}
	token, err := keyring.EncodeCursor(CursorKindDeliveries, tenantID, "dead_lettered,delivered", position)
	if err != nil {
		t.Fatalf("EncodeCursor() error = %v", err)
	}
	if len(token) > maximumNotificationCursor || !cursorPattern.MatchString(token) {
		t.Fatalf("invalid token shape: %q", token)
	}
	got, err := keyring.DecodeCursor(token, CursorKindDeliveries, tenantID, "dead_lettered,delivered")
	if err != nil || got != position {
		t.Fatalf("DecodeCursor() = %#v, %v", got, err)
	}

	bindings := []struct {
		kind   CursorKind
		tenant uuid.UUID
		filter string
	}{
		{CursorKindRules, tenantID, "dead_lettered,delivered"},
		{CursorKindDeliveries, mustV7(t), "dead_lettered,delivered"},
		{CursorKindDeliveries, tenantID, "delivered"},
	}
	for _, binding := range bindings {
		if _, err := keyring.DecodeCursor(token, binding.kind, binding.tenant, binding.filter); !errors.Is(err, ErrInvalidCursor) {
			t.Fatalf("cross-context cursor accepted: %#v", binding)
		}
	}

	tampered := []byte(token)
	index := len(tampered) / 2
	if tampered[index] == 'A' {
		tampered[index] = 'B'
	} else {
		tampered[index] = 'A'
	}
	if _, err := keyring.DecodeCursor(string(tampered), CursorKindDeliveries, tenantID, "dead_lettered,delivered"); !errors.Is(err, ErrInvalidCursor) {
		t.Fatal("tampered cursor accepted")
	}
}

func TestNotificationCursorRetainsOldRotationKeys(t *testing.T) {
	root1 := bytes.Repeat([]byte{0x11}, notificationRootKeyBytes)
	root2 := bytes.Repeat([]byte{0x22}, notificationRootKeyBytes)
	old, err := NewKeyring(1, map[int16][]byte{1: root1})
	if err != nil {
		t.Fatal(err)
	}
	tenantID := mustV7(t)
	position := CursorPosition{CreatedAt: validInstantFixture(), ID: mustV7(t)}
	token, err := old.EncodeCursor(CursorKindRules, tenantID, "", position)
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := NewKeyring(2, map[int16][]byte{1: root1, 2: root2})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := rotated.DecodeCursor(token, CursorKindRules, tenantID, ""); err != nil || got != position {
		t.Fatalf("rotated DecodeCursor() = %#v, %v", got, err)
	}
}
