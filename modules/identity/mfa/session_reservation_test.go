package mfa

import (
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

func TestSessionReservationIsConstructorOnlyBoundedAndRedacted(t *testing.T) {
	now := time.Date(2026, 8, 26, 10, 0, 0, 123_456_000, time.UTC)
	input := SessionMaterial{
		SessionID: sessionUUIDv7(1), FamilyID: sessionUUIDv7(2),
		TokenDigest: sha256.Sum256([]byte("token")), CSRFDigest: sha256.Sum256([]byte("csrf")),
		AuthenticationMethod: SessionAuthenticationPasskey,
		IdleExpiresAt:        now.Add(time.Hour).Truncate(time.Millisecond),
		AbsoluteExpiresAt:    now.Add(24 * time.Hour).Truncate(time.Millisecond),
	}
	reservation, err := NewSessionReservation(input, now)
	if err != nil || !reservation.ValidAt(now) || reservation.SessionID() != input.SessionID ||
		reservation.FamilyID() != input.FamilyID || reservation.TokenDigest() != input.TokenDigest ||
		reservation.CSRFDigest() != input.CSRFDigest {
		t.Fatalf("reservation mismatch: %#v, %v", reservation, err)
	}
	for _, secret := range []string{"token", "csrf", "01000000"} {
		if strings.Contains(reservation.String(), secret) || strings.Contains(reservation.GoString(), secret) {
			t.Fatalf("reservation formatting exposed material: %q", secret)
		}
	}
}

func TestSessionReservationRejectsHostileInputs(t *testing.T) {
	now := time.Date(2026, 8, 26, 10, 0, 0, 0, time.UTC)
	valid := SessionMaterial{
		SessionID: sessionUUIDv7(1), FamilyID: sessionUUIDv7(2),
		TokenDigest: sha256.Sum256([]byte("token")), CSRFDigest: sha256.Sum256([]byte("csrf")),
		AuthenticationMethod: SessionAuthenticationTOTP,
		IdleExpiresAt:        now.Add(time.Hour), AbsoluteExpiresAt: now.Add(24 * time.Hour),
	}
	tests := map[string]func(*SessionMaterial){
		"non v7 session":    func(value *SessionMaterial) { value.SessionID[6] = 0 },
		"non rfc family":    func(value *SessionMaterial) { value.FamilyID[8] = 0 },
		"same identifiers":  func(value *SessionMaterial) { value.FamilyID = value.SessionID },
		"zero token":        func(value *SessionMaterial) { value.TokenDigest = [sha256.Size]byte{} },
		"same digests":      func(value *SessionMaterial) { value.CSRFDigest = value.TokenDigest },
		"unknown method":    func(value *SessionMaterial) { value.AuthenticationMethod = "provider" },
		"idle too long":     func(value *SessionMaterial) { value.IdleExpiresAt = now.Add(25 * time.Hour) },
		"absolute too long": func(value *SessionMaterial) { value.AbsoluteExpiresAt = now.Add(32 * 24 * time.Hour) },
		"expiry inversion":  func(value *SessionMaterial) { value.AbsoluteExpiresAt = now.Add(30 * time.Minute) },
		"sub-ms idle deadline": func(value *SessionMaterial) {
			value.IdleExpiresAt = value.IdleExpiresAt.Add(time.Microsecond)
		},
		"sub-ms absolute deadline": func(value *SessionMaterial) {
			value.AbsoluteExpiresAt = value.AbsoluteExpiresAt.Add(time.Microsecond)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			input := valid
			mutate(&input)
			if _, err := NewSessionReservation(input, now); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}

func sessionUUIDv7(seed byte) identity.EntityID {
	value := identity.EntityID{seed}
	value[6] = 0x70
	value[8] = 0x80
	return value
}
