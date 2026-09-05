package authentication

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
)

func TestReserveMFASessionCreatesAndRotatesBoundedRedactedMaterial(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	service := newAuthenticationServiceAt(
		t, &repositoryStub{}, &passwordEngineStub{}, totpEngineStub{},
		digest("bootstrap-authority-value-000000"), now,
	)

	primary, err := service.ReserveMFASession(nil, mfa.SessionAuthenticationPasskey)
	if err != nil {
		t.Fatalf("ReserveMFASession(primary) error = %v", err)
	}
	tokenDigest := primary.Reservation.TokenDigest()
	csrfDigest := primary.Reservation.CSRFDigest()
	if primary.Reservation.SessionID() == primary.Reservation.FamilyID() ||
		primary.Reservation.AuthenticationMethod() != mfa.SessionAuthenticationPasskey ||
		primary.Reservation.IdleExpiresAt() != now.Add(30*time.Minute) ||
		primary.Reservation.AbsoluteExpiresAt() != now.Add(8*time.Hour) {
		t.Fatalf("primary reservation is invalid: %#v", primary)
	}
	if got := primary.String(); got != "authentication.MFASessionReservation{material:[REDACTED]}" {
		t.Fatalf("reservation formatting leaked material: %q", got)
	}
	copyOfPrimary := primary
	material, ok := copyOfPrimary.Consume()
	if !ok || len(material.SessionToken) != 43 || len(material.CSRFToken) != 43 ||
		bytes.Equal(material.SessionToken, material.CSRFToken) ||
		!bytes.Equal(tokenDigest[:], digest(string(material.SessionToken))) ||
		!bytes.Equal(csrfDigest[:], digest(string(material.CSRFToken))) {
		t.Fatalf("consumed browser material is invalid: %#v", material)
	}
	if _, second := primary.Consume(); second {
		t.Fatal("a copied reservation consumed browser material twice")
	}
	tokenAlias := material.SessionToken
	csrfAlias := material.CSRFToken
	material.Destroy()
	if !allZero(tokenAlias) || !allZero(csrfAlias) {
		t.Fatal("Destroy() did not zero consumed browser material")
	}

	familyID := uuid.Must(uuid.NewV7())
	absoluteExpiry := now.Add(12 * time.Minute)
	current := &Session{
		ID: uuid.Must(uuid.NewV7()), RotationFamilyID: familyID,
		AbsoluteExpiresAt: absoluteExpiry,
	}
	rotated, err := service.ReserveMFASession(current, mfa.SessionAuthenticationTOTP)
	if err != nil {
		t.Fatalf("ReserveMFASession(rotation) error = %v", err)
	}
	if uuid.UUID(rotated.Reservation.FamilyID()) != familyID ||
		rotated.Reservation.AbsoluteExpiresAt() != absoluteExpiry ||
		rotated.Reservation.IdleExpiresAt() != absoluteExpiry {
		t.Fatalf("rotation extended or changed the family: %#v", rotated)
	}
	rotated.Destroy()
	if _, ok := rotated.Consume(); ok {
		t.Fatal("destroyed rotation still exposed browser material")
	}
}

func TestMFASessionReservationDefensivelyCopiesBrowserMaterial(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	token := []byte(validTestToken(0x31))
	csrf := []byte(validTestToken(0x32))
	reservation, err := mfa.NewSessionReservation(mfa.SessionMaterial{
		SessionID:   identity.EntityID(uuid.Must(uuid.NewV7())),
		FamilyID:    identity.EntityID(uuid.Must(uuid.NewV7())),
		TokenDigest: sha256.Sum256(token), CSRFDigest: sha256.Sum256(csrf),
		AuthenticationMethod: mfa.SessionAuthenticationOIDC,
		IdleExpiresAt:        now.Add(time.Hour), AbsoluteExpiresAt: now.Add(8 * time.Hour),
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	owned, err := NewMFASessionReservation(reservation, token, csrf)
	if err != nil {
		t.Fatal(err)
	}
	clear(token)
	clear(csrf)
	material, ok := owned.Consume()
	if !ok || !validOpaqueTokenBytes(material.SessionToken) || !validOpaqueTokenBytes(material.CSRFToken) {
		t.Fatal("caller mutation changed the owned browser material")
	}
	tokenAlias, csrfAlias := material.SessionToken, material.CSRFToken
	material.Destroy()
	if !allZero(tokenAlias) || !allZero(csrfAlias) {
		t.Fatal("destroy did not zero defensively copied browser material")
	}
}

func TestOpaqueCredentialValidatorsRejectAllZeroEntropy(t *testing.T) {
	zero := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	if validOpaqueToken(zero) || validOpaqueTokenBytes([]byte(zero)) {
		t.Fatal("canonical all-zero credential was accepted")
	}
}

func allZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}

func TestReserveMFASessionRejectsInvalidMethodsAndStaleAnchors(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	service := newAuthenticationServiceAt(
		t, &repositoryStub{}, &passwordEngineStub{}, totpEngineStub{},
		digest("bootstrap-authority-value-000000"), now,
	)
	if _, err := service.ReserveMFASession(nil, mfa.SessionAuthenticationMethod("kerberos")); err == nil {
		t.Fatal("ReserveMFASession accepted an unsupported method")
	}
	if _, err := service.ReserveMFASession(&Session{
		ID: uuid.Must(uuid.NewV7()), RotationFamilyID: uuid.Must(uuid.NewV7()),
		AbsoluteExpiresAt: now,
	}, mfa.SessionAuthenticationTOTP); err == nil {
		t.Fatal("ReserveMFASession accepted an expired anchor")
	}
}
