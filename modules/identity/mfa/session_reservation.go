package mfa

import (
	"crypto/sha256"
	"fmt"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

const (
	maximumSessionIdleLifetime     = 24 * time.Hour
	maximumSessionAbsoluteLifetime = 31 * 24 * time.Hour
)

// SessionAuthenticationMethod is the closed, persisted method for a newly
// created or rotated session. It never contains provider claims or factor
// material.
type SessionAuthenticationMethod string

const (
	SessionAuthenticationPasskey  SessionAuthenticationMethod = "passkey"
	SessionAuthenticationTOTP     SessionAuthenticationMethod = "totp"
	SessionAuthenticationRecovery SessionAuthenticationMethod = "recovery_code"
	SessionAuthenticationOIDC     SessionAuthenticationMethod = "oidc"
	SessionAuthenticationSAML     SessionAuthenticationMethod = "saml"
	SessionAuthenticationLDAP     SessionAuthenticationMethod = "ldap"
)

// SessionMaterial contains only caller-reserved identifiers and digests. Raw
// bearer and CSRF material must never cross this boundary.
type SessionMaterial struct {
	SessionID            identity.EntityID
	FamilyID             identity.EntityID
	TokenDigest          [sha256.Size]byte
	CSRFDigest           [sha256.Size]byte
	AuthenticationMethod SessionAuthenticationMethod
	IdleExpiresAt        time.Time
	AbsoluteExpiresAt    time.Time
}

func (material SessionMaterial) String() string {
	return fmt.Sprintf("mfa.SessionMaterial{method:%q,material:[REDACTED]}", material.AuthenticationMethod)
}
func (material SessionMaterial) GoString() string { return material.String() }

// SessionReservation is constructor-only session material for one atomic MFA
// commit. Its String forms deliberately expose no identifiers or digests.
type SessionReservation struct {
	sessionID            identity.EntityID
	familyID             identity.EntityID
	tokenDigest          [sha256.Size]byte
	csrfDigest           [sha256.Size]byte
	authenticationMethod SessionAuthenticationMethod
	idleExpiresAt        time.Time
	absoluteExpiresAt    time.Time
}

func NewSessionReservation(input SessionMaterial, issuedAt time.Time) (SessionReservation, error) {
	if !validSessionUUIDv7(input.SessionID) || !validSessionUUIDv7(input.FamilyID) ||
		input.SessionID == input.FamilyID ||
		input.TokenDigest == ([sha256.Size]byte{}) || input.CSRFDigest == ([sha256.Size]byte{}) ||
		input.TokenDigest == input.CSRFDigest || !validSessionAuthenticationMethod(input.AuthenticationMethod) ||
		!validSessionObservedInstant(issuedAt) || !validSessionDeadline(input.IdleExpiresAt) ||
		!validSessionDeadline(input.AbsoluteExpiresAt) || !input.IdleExpiresAt.After(issuedAt) ||
		input.AbsoluteExpiresAt.Before(input.IdleExpiresAt) ||
		input.IdleExpiresAt.After(issuedAt.Add(maximumSessionIdleLifetime)) ||
		input.AbsoluteExpiresAt.After(issuedAt.Add(maximumSessionAbsoluteLifetime)) {
		return SessionReservation{}, ErrSessionRejected
	}
	return SessionReservation{
		sessionID: input.SessionID, familyID: input.FamilyID,
		tokenDigest: input.TokenDigest, csrfDigest: input.CSRFDigest,
		authenticationMethod: input.AuthenticationMethod,
		idleExpiresAt:        input.IdleExpiresAt.UTC(), absoluteExpiresAt: input.AbsoluteExpiresAt.UTC(),
	}, nil
}

func validSessionUUIDv7(value identity.EntityID) bool {
	return value[6]>>4 == 7 && value[8]&0xc0 == 0x80
}

func (reservation SessionReservation) SessionID() identity.EntityID   { return reservation.sessionID }
func (reservation SessionReservation) FamilyID() identity.EntityID    { return reservation.familyID }
func (reservation SessionReservation) TokenDigest() [sha256.Size]byte { return reservation.tokenDigest }
func (reservation SessionReservation) CSRFDigest() [sha256.Size]byte  { return reservation.csrfDigest }
func (reservation SessionReservation) AuthenticationMethod() SessionAuthenticationMethod {
	return reservation.authenticationMethod
}
func (reservation SessionReservation) IdleExpiresAt() time.Time { return reservation.idleExpiresAt }
func (reservation SessionReservation) AbsoluteExpiresAt() time.Time {
	return reservation.absoluteExpiresAt
}
func (reservation SessionReservation) IsZero() bool { return reservation == SessionReservation{} }

func (reservation SessionReservation) ValidAt(issuedAt time.Time) bool {
	if reservation.IsZero() {
		return false
	}
	rebuilt, err := NewSessionReservation(SessionMaterial{
		SessionID: reservation.sessionID, FamilyID: reservation.familyID,
		TokenDigest: reservation.tokenDigest, CSRFDigest: reservation.csrfDigest,
		AuthenticationMethod: reservation.authenticationMethod,
		IdleExpiresAt:        reservation.idleExpiresAt, AbsoluteExpiresAt: reservation.absoluteExpiresAt,
	}, issuedAt)
	return err == nil && rebuilt == reservation
}

func (reservation SessionReservation) String() string {
	return fmt.Sprintf("mfa.SessionReservation{method:%q,material:[REDACTED]}", reservation.authenticationMethod)
}
func (reservation SessionReservation) GoString() string { return reservation.String() }

func validSessionAuthenticationMethod(value SessionAuthenticationMethod) bool {
	switch value {
	case SessionAuthenticationPasskey, SessionAuthenticationTOTP, SessionAuthenticationRecovery,
		SessionAuthenticationOIDC, SessionAuthenticationSAML, SessionAuthenticationLDAP:
		return true
	default:
		return false
	}
}

func validSessionObservedInstant(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond()%int(time.Microsecond) == 0
}

func validSessionDeadline(value time.Time) bool {
	return validSessionObservedInstant(value) && value.Nanosecond()%int(time.Millisecond) == 0
}
