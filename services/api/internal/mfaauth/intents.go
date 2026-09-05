package mfaauth

import (
	"crypto/sha256"
	"fmt"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/modules/identity/webauthn"
)

type AuditKind string

const (
	AuditPasskeyEnrolled      AuditKind = "mfa.passkey_enrolled"
	AuditPasskeyAuthenticated AuditKind = "mfa.passkey_authenticated"
	AuditPasskeyStepUp        AuditKind = "mfa.passkey_step_up_completed"
	AuditPasskeyCloneDetected AuditKind = "mfa.passkey_clone_suspected"
	AuditTOTPEnrolled         AuditKind = "mfa.totp_enrolled"
	AuditRecoveryCreated      AuditKind = "mfa.recovery_codes_created"
	AuditRecoveryRegenerated  AuditKind = "mfa.recovery_codes_regenerated"
)

type AuditIntent struct {
	Kind            AuditKind
	TenantID        identity.EntityID
	UserID          identity.EntityID
	Action          string
	OccurredAt      time.Time
	PolicyRevisions []identity.AssurancePolicyRevision
}

func (intent AuditIntent) String() string {
	return fmt.Sprintf("mfaauth.AuditIntent{kind:%s,policies:%d,subject:[REDACTED]}",
		intent.Kind, len(intent.PolicyRevisions))
}
func (intent AuditIntent) GoString() string { return intent.String() }

type SessionMutation uint8

const (
	SessionCreate SessionMutation = iota + 1
	SessionRotate
	SessionConsumeContinuation
	SessionRetainContinuation
	// SessionRevoke denies new authority and revokes a pinned live anchor when
	// one exists. Primary authentication has no anchor and creates no session.
	SessionRevoke
)

type SessionIntent struct {
	Mutation                  SessionMutation
	ExpectedSessionID         identity.EntityID
	ExpectedFamilyID          identity.EntityID
	ExpectedContinuationID    identity.EntityID
	ExpectedAnchorVersion     uint64
	ExpectedIdentityEpoch     uint64
	ExpectedAnchorExpiry      time.Time
	Audience                  string
	Requirement               identity.EffectiveAssuranceRequirement
	RecoveryRestricted        bool
	Reservation               mfa.SessionReservation
	ContinuationReceiptDigest [sha256.Size]byte `json:"-"`
}

func (intent SessionIntent) String() string {
	return fmt.Sprintf("mfaauth.SessionIntent{mutation:%d,recovery_restricted:%t,anchor:[REDACTED]}",
		intent.Mutation, intent.RecoveryRestricted)
}
func (intent SessionIntent) GoString() string { return intent.String() }

func passkeyIntents(
	binding webauthn.CeremonyBinding,
	at time.Time,
	cloneSuspected bool,
	reservation mfa.SessionReservation,
	continuationID identity.EntityID,
	receiptDigest [sha256.Size]byte,
) (AuditIntent, SessionIntent, bool) {
	if !reservation.IsZero() && reservation.AuthenticationMethod() != mfa.SessionAuthenticationPasskey {
		return AuditIntent{}, SessionIntent{}, false
	}
	auditKind := AuditPasskeyAuthenticated
	mutation := SessionCreate
	switch binding.Purpose {
	case webauthn.PurposeRegistration:
		auditKind = AuditPasskeyEnrolled
		if binding.SessionID != (identity.EntityID{}) {
			mutation = SessionRotate
		} else {
			mutation = SessionRetainContinuation
		}
	case webauthn.PurposePrimaryAuthentication:
		mutation = SessionCreate
	case webauthn.PurposeContinuationAuthentication:
		auditKind = AuditPasskeyStepUp
		mutation = SessionConsumeContinuation
	case webauthn.PurposeStepUpAuthentication:
		auditKind = AuditPasskeyStepUp
		mutation = SessionRotate
	default:
		return AuditIntent{}, SessionIntent{}, false
	}
	if cloneSuspected {
		if binding.Purpose == webauthn.PurposeRegistration {
			return AuditIntent{}, SessionIntent{}, false
		}
		auditKind = AuditPasskeyCloneDetected
		mutation = SessionRevoke
	}
	audit := AuditIntent{
		Kind: auditKind, TenantID: binding.TenantID, UserID: binding.UserID,
		Action: binding.Action, OccurredAt: at,
		PolicyRevisions: append([]identity.AssurancePolicyRevision(nil), binding.Requirement.PolicyRevisions...),
	}
	session := SessionIntent{
		Mutation: mutation, ExpectedSessionID: binding.SessionID,
		ExpectedFamilyID: binding.SessionFamilyID, ExpectedContinuationID: binding.ContinuationID,
		ExpectedAnchorVersion: binding.AnchorVersion, ExpectedIdentityEpoch: binding.IdentityEpoch,
		ExpectedAnchorExpiry: binding.AnchorExpiresAt, Audience: binding.Audience,
		Requirement:               cloneRequirement(binding.Requirement),
		Reservation:               reservation,
		ContinuationReceiptDigest: receiptDigest,
	}
	return audit, session, validPasskeyCompletionPossession(binding, continuationID, receiptDigest) &&
		validSessionReservationForIntent(session, at)
}

func validSessionReservationForIntent(intent SessionIntent, issuedAt time.Time) bool {
	zero := identity.EntityID{}
	zeroDigest := [sha256.Size]byte{}
	switch intent.Mutation {
	case SessionCreate:
		return intent.ExpectedSessionID == zero && intent.ExpectedFamilyID == zero &&
			intent.ExpectedContinuationID == zero && intent.ContinuationReceiptDigest == zeroDigest &&
			intent.Reservation.ValidAt(issuedAt)
	case SessionRotate:
		return intent.ExpectedSessionID != zero && intent.ExpectedFamilyID != zero &&
			intent.ExpectedContinuationID == zero && intent.ContinuationReceiptDigest == zeroDigest &&
			intent.Reservation.ValidAt(issuedAt) &&
			intent.Reservation.SessionID() != intent.ExpectedSessionID &&
			intent.Reservation.FamilyID() == intent.ExpectedFamilyID
	case SessionConsumeContinuation:
		return intent.ExpectedSessionID == zero && intent.ExpectedFamilyID == zero &&
			intent.ExpectedContinuationID != zero && intent.ContinuationReceiptDigest != zeroDigest &&
			intent.Reservation.ValidAt(issuedAt)
	case SessionRetainContinuation:
		return intent.ExpectedSessionID == zero && intent.ExpectedFamilyID == zero &&
			intent.ExpectedContinuationID != zero && intent.ContinuationReceiptDigest != zeroDigest &&
			intent.Reservation.IsZero()
	case SessionRevoke:
		if !intent.Reservation.IsZero() {
			return false
		}
		if intent.ExpectedContinuationID != zero {
			return intent.ExpectedSessionID == zero && intent.ExpectedFamilyID == zero &&
				intent.ContinuationReceiptDigest != zeroDigest
		}
		return intent.ContinuationReceiptDigest == zeroDigest
	default:
		return false
	}
}

func validPasskeyCompletionPossession(
	binding webauthn.CeremonyBinding,
	continuationID identity.EntityID,
	receiptDigest [sha256.Size]byte,
) bool {
	zeroID := identity.EntityID{}
	zeroDigest := [sha256.Size]byte{}
	if binding.ContinuationID != zeroID {
		return continuationID == binding.ContinuationID && receiptDigest != zeroDigest &&
			(binding.Purpose == webauthn.PurposeContinuationAuthentication ||
				binding.Purpose == webauthn.PurposeRegistration)
	}
	return continuationID == zeroID && receiptDigest == zeroDigest
}
