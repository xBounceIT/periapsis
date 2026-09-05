package mfaauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"sync/atomic"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
)

// CompletionArtifactKind is the closed set of one-use browser artifacts that
// can cross the MFA completion boundary. The identifiers remain opaque here;
// their concrete UUID/32-byte representation is validated by the constructor.
type CompletionArtifactKind string

const (
	CompletionArtifactTOTPEnrollment         CompletionArtifactKind = "totp_enrollment"
	CompletionArtifactStepUp                 CompletionArtifactKind = "step_up_challenge"
	CompletionArtifactWebAuthnRegistration   CompletionArtifactKind = "webauthn_registration"
	CompletionArtifactWebAuthnAuthentication CompletionArtifactKind = "webauthn_authentication"
)

type CompletionFactorKind string

const (
	CompletionFactorTOTP     CompletionFactorKind = "totp"
	CompletionFactorRecovery CompletionFactorKind = "recovery_code"
	CompletionFactorPasskey  CompletionFactorKind = "passkey"
)

type CompletionFlow string

const (
	CompletionFlowPrimary      CompletionFlow = "primary"
	CompletionFlowSession      CompletionFlow = "session"
	CompletionFlowContinuation CompletionFlow = "continuation"
)

type CompletionReservationDisposition string

const (
	CompletionReservationNone   CompletionReservationDisposition = "none"
	CompletionReservationCreate CompletionReservationDisposition = "create"
	CompletionReservationRotate CompletionReservationDisposition = "rotate"
)

// CompletionSessionSource is the already-authenticated source tuple supplied
// by HTTP. It is a comparison pin only; the protected completion resolver is
// still authoritative and must return this exact live tuple.
type CompletionSessionSource struct {
	TenantID             identity.EntityID
	UserID               identity.EntityID
	SessionID            identity.EntityID
	SessionFamilyID      identity.EntityID
	AuthenticationMethod string
	AbsoluteExpiresAt    time.Time
}

func (source CompletionSessionSource) String() string {
	return "mfaauth.CompletionSessionSource{source:[REDACTED]}"
}
func (source CompletionSessionSource) GoString() string { return source.String() }

// CompletionTicketRequest contains the browser-selected artifact and factor.
// Raw browser material is reduced to a digest before persistence resolution.
type CompletionTicketRequest struct {
	Admission                 AdmissionContext
	ArtifactKind              CompletionArtifactKind
	ArtifactID                []byte `json:"-"`
	BrowserHandle             []byte `json:"-"`
	FactorKind                CompletionFactorKind
	FactorID                  []byte `json:"-"`
	ContinuationID            identity.EntityID
	ContinuationReceiptDigest [sha256.Size]byte `json:"-"`
	SessionSource             *CompletionSessionSource
}

func (request CompletionTicketRequest) String() string {
	return fmt.Sprintf("mfaauth.CompletionTicketRequest{artifact:%q,factor:%q,material:[REDACTED]}",
		request.ArtifactKind, request.FactorKind)
}
func (request CompletionTicketRequest) GoString() string { return request.String() }

// CompletionTicketLookup is the digest-only request accepted by the protected
// persistence resolver. RequestedAt is an application observation; LoadedAt in
// the result must be the database-effective observation at or after it.
type CompletionTicketLookup struct {
	ArtifactKind              CompletionArtifactKind
	ArtifactID                []byte
	BrowserDigest             [sha256.Size]byte
	FactorKind                CompletionFactorKind
	FactorID                  []byte
	ContinuationID            identity.EntityID
	ContinuationReceiptDigest [sha256.Size]byte
	SessionSource             *CompletionSessionSource
	RequestedAt               time.Time
}

func (lookup CompletionTicketLookup) String() string {
	return fmt.Sprintf("mfaauth.CompletionTicketLookup{artifact:%q,factor:%q,material:[REDACTED]}",
		lookup.ArtifactKind, lookup.FactorKind)
}
func (lookup CompletionTicketLookup) GoString() string { return lookup.String() }

// CompletionTicketResolutionInput is the strict, redacted projection returned
// by the protected artifact resolver. ReservationAuthenticationMethod is the
// method the transaction ABI expects on newly reserved material; the result
// method can differ when a typed upstream primary is preserved.
type CompletionTicketResolutionInput struct {
	LoadedAt                        time.Time
	ArtifactKind                    CompletionArtifactKind
	ArtifactID                      []byte
	BrowserDigest                   [sha256.Size]byte
	FactorKind                      CompletionFactorKind
	FactorID                        []byte
	Flow                            CompletionFlow
	TenantID                        identity.EntityID
	UserID                          identity.EntityID
	IdentityEpoch                   uint64
	ResolvedUserID                  identity.EntityID
	ResolvedIdentityEpoch           uint64
	SessionID                       identity.EntityID
	SessionFamilyID                 identity.EntityID
	ContinuationID                  identity.EntityID
	AnchorVersion                   uint64
	AnchorExpiresAt                 time.Time
	Action                          string
	Audience                        string
	ContinuationReceiptDigest       [sha256.Size]byte `json:"-"`
	ReservationDisposition          CompletionReservationDisposition
	ReservationAuthenticationMethod mfa.SessionAuthenticationMethod
	ResultAuthenticationMethod      string
	SourceSessionID                 identity.EntityID
	SourceSessionFamilyID           identity.EntityID
	SourceSessionVersion            uint64
	SourceAbsoluteExpiresAt         time.Time
}

// CompletionTicketSource performs one receipt-aware, action-specific live
// resolution without mutating the artifact. Implementations must never fall
// back to an unbound or legacy resolver.
type CompletionTicketSource interface {
	ResolveMFACompletion(context.Context, CompletionTicketLookup) (CompletionTicketResolutionInput, error)
}

type completionTicketState struct {
	used       atomic.Bool
	resolution CompletionTicketResolutionInput
}

// CompletionTicket is a copy-safe, single-use capability. A zero value is
// invalid; every copy shares the same atomic consume state.
type CompletionTicket struct {
	state *completionTicketState
}

func (ticket CompletionTicket) String() string {
	configured := ticket.state != nil
	return fmt.Sprintf("mfaauth.CompletionTicket{configured:%t,material:[REDACTED]}", configured)
}
func (ticket CompletionTicket) GoString() string { return ticket.String() }

// CompletionReservationPlan is the only part of a prepared ticket exposed to
// HTTP. It contains no receipt, browser digest, factor identifier, policy, or
// source version. The source version remains sealed in the ticket: for a
// session-revalidation continuation, the receipt-aware claim and terminal
// consumer re-lock the immutable server-side continuation provenance before
// applying the reserved successor. It must not be copied into a browser-owned
// completion payload.
type CompletionReservationPlan struct {
	Disposition                CompletionReservationDisposition
	IssuedAt                   time.Time
	AuthenticationMethod       mfa.SessionAuthenticationMethod
	ResultAuthenticationMethod string
	SourceSessionID            identity.EntityID
	SourceSessionFamilyID      identity.EntityID
	SourceAbsoluteExpiresAt    time.Time
}

func (plan CompletionReservationPlan) String() string {
	return fmt.Sprintf("mfaauth.CompletionReservationPlan{disposition:%q,method:%q,source:[REDACTED]}",
		plan.Disposition, plan.AuthenticationMethod)
}
func (plan CompletionReservationPlan) GoString() string { return plan.String() }

func (ticket CompletionTicket) ReservationPlan() (CompletionReservationPlan, bool) {
	if ticket.state == nil || ticket.state.used.Load() {
		return CompletionReservationPlan{}, false
	}
	value := ticket.state.resolution
	return CompletionReservationPlan{
		Disposition: value.ReservationDisposition, IssuedAt: value.LoadedAt,
		AuthenticationMethod:       value.ReservationAuthenticationMethod,
		ResultAuthenticationMethod: value.ResultAuthenticationMethod,
		SourceSessionID:            value.SourceSessionID, SourceSessionFamilyID: value.SourceSessionFamilyID,
		SourceAbsoluteExpiresAt: value.SourceAbsoluteExpiresAt,
	}, true
}

type completionTicketGrant struct {
	resolution CompletionTicketResolutionInput
}

func (ticket CompletionTicket) consume(
	artifactKind CompletionArtifactKind,
	artifactID []byte,
	browserHandle []byte,
	factorKind CompletionFactorKind,
	factorID []byte,
	reservation mfa.SessionReservation,
) (completionTicketGrant, bool) {
	if ticket.state == nil || !ticket.state.used.CompareAndSwap(false, true) {
		return completionTicketGrant{}, false
	}
	resolution := cloneCompletionResolution(ticket.state.resolution)
	if resolution.ArtifactKind != artifactKind || !bytes.Equal(resolution.ArtifactID, artifactID) ||
		resolution.BrowserDigest != sha256.Sum256(browserHandle) || resolution.FactorKind != factorKind ||
		!bytes.Equal(resolution.FactorID, factorID) || !validCompletionReservation(resolution, reservation) {
		return completionTicketGrant{}, false
	}
	return completionTicketGrant{resolution: resolution}, true
}

func (ticket CompletionTicket) consumePrepared(reservation mfa.SessionReservation) (completionTicketGrant, bool) {
	if ticket.state == nil || !ticket.state.used.CompareAndSwap(false, true) {
		return completionTicketGrant{}, false
	}
	resolution := cloneCompletionResolution(ticket.state.resolution)
	if !validCompletionReservation(resolution, reservation) {
		return completionTicketGrant{}, false
	}
	return completionTicketGrant{resolution: resolution}, true
}

func (ticket CompletionTicket) consumeWithoutFactor(
	artifactKind CompletionArtifactKind,
	artifactID []byte,
	browserHandle []byte,
	factorKind CompletionFactorKind,
	reservation mfa.SessionReservation,
) (completionTicketGrant, bool) {
	if ticket.state == nil || !ticket.state.used.CompareAndSwap(false, true) {
		return completionTicketGrant{}, false
	}
	resolution := cloneCompletionResolution(ticket.state.resolution)
	if resolution.ArtifactKind != artifactKind || !bytes.Equal(resolution.ArtifactID, artifactID) ||
		resolution.BrowserDigest != sha256.Sum256(browserHandle) || resolution.FactorKind != factorKind ||
		!validCompletionReservation(resolution, reservation) {
		return completionTicketGrant{}, false
	}
	return completionTicketGrant{resolution: resolution}, true
}

func validCompletionReservation(
	resolution CompletionTicketResolutionInput,
	reservation mfa.SessionReservation,
) bool {
	switch resolution.ReservationDisposition {
	case CompletionReservationNone:
		return reservation.IsZero()
	case CompletionReservationCreate:
		return reservation.ValidAt(resolution.LoadedAt) &&
			reservation.AuthenticationMethod() == resolution.ReservationAuthenticationMethod &&
			resolution.SourceSessionID == (identity.EntityID{}) &&
			resolution.SourceSessionFamilyID == (identity.EntityID{}) &&
			resolution.SourceSessionVersion == 0 && resolution.SourceAbsoluteExpiresAt.IsZero()
	case CompletionReservationRotate:
		return reservation.ValidAt(resolution.LoadedAt) &&
			reservation.AuthenticationMethod() == resolution.ReservationAuthenticationMethod &&
			reservation.SessionID() != resolution.SourceSessionID &&
			reservation.FamilyID() == resolution.SourceSessionFamilyID &&
			reservation.AbsoluteExpiresAt().Equal(resolution.SourceAbsoluteExpiresAt)
	default:
		return false
	}
}

type CompletionTicketOptions struct {
	Source           CompletionTicketSource
	Admissions       AdmissionGate
	Now              func() time.Time
	OperationTimeout time.Duration
}

type CompletionTicketIssuer struct {
	source           CompletionTicketSource
	admissions       AdmissionGate
	now              func() time.Time
	operationTimeout time.Duration
}

func NewCompletionTicketIssuer(options CompletionTicketOptions) (*CompletionTicketIssuer, error) {
	if options.Source == nil || options.Admissions == nil ||
		options.OperationTimeout < minimumOperationTimeout || options.OperationTimeout > maximumOperationTimeout ||
		options.OperationTimeout%time.Microsecond != 0 {
		return nil, ErrInvalidInput
	}
	if options.Now == nil {
		options.Now = func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }
	}
	return &CompletionTicketIssuer{
		source: options.Source, admissions: options.Admissions,
		now: options.Now, operationTimeout: options.OperationTimeout,
	}, nil
}

func (issuer *CompletionTicketIssuer) Prepare(
	ctx context.Context,
	request CompletionTicketRequest,
) (CompletionTicket, error) {
	operationContext, cancel, err := operation(ctx, issuer.operationTimeout)
	if err != nil {
		return CompletionTicket{}, err
	}
	defer cancel()
	requestedAt := issuer.currentTime()
	if err := admit(operationContext, issuer.admissions, request.Admission, requestedAt); err != nil {
		return CompletionTicket{}, err
	}
	lookup, ok := completionLookup(request, requestedAt)
	if !ok {
		return CompletionTicket{}, ErrInvalidInput
	}
	resolution, err := issuer.source.ResolveMFACompletion(operationContext, lookup)
	if err != nil {
		return CompletionTicket{}, ErrAuthentication
	}
	if !validCompletionResolution(lookup, resolution, issuer.operationTimeout) {
		return CompletionTicket{}, ErrAuthentication
	}
	return CompletionTicket{state: &completionTicketState{resolution: cloneCompletionResolution(resolution)}}, nil
}

func (issuer *CompletionTicketIssuer) currentTime() time.Time {
	if issuer == nil || issuer.now == nil {
		return time.Time{}
	}
	return issuer.now().UTC().Truncate(time.Microsecond)
}

func completionLookup(request CompletionTicketRequest, requestedAt time.Time) (CompletionTicketLookup, bool) {
	if !validInstant(requestedAt) || !validCompletionArtifactID(request.ArtifactKind, request.ArtifactID) ||
		!validOpaque(request.BrowserHandle) || !validCompletionFactor(request.ArtifactKind, request.FactorKind, request.FactorID) {
		return CompletionTicketLookup{}, false
	}
	zeroID := identity.EntityID{}
	zeroDigest := [sha256.Size]byte{}
	if request.ContinuationID == zeroID != (request.ContinuationReceiptDigest == zeroDigest) {
		return CompletionTicketLookup{}, false
	}
	if request.SessionSource != nil {
		if request.ContinuationID != zeroID || !validCompletionSessionSource(*request.SessionSource) {
			return CompletionTicketLookup{}, false
		}
		copySource := *request.SessionSource
		request.SessionSource = &copySource
	}
	return CompletionTicketLookup{
		ArtifactKind: request.ArtifactKind, ArtifactID: append([]byte(nil), request.ArtifactID...),
		BrowserDigest: sha256.Sum256(request.BrowserHandle), FactorKind: request.FactorKind,
		FactorID: append([]byte(nil), request.FactorID...), ContinuationID: request.ContinuationID,
		ContinuationReceiptDigest: request.ContinuationReceiptDigest, SessionSource: request.SessionSource,
		RequestedAt: requestedAt,
	}, true
}

func validCompletionResolution(
	lookup CompletionTicketLookup,
	value CompletionTicketResolutionInput,
	operationTimeout time.Duration,
) bool {
	if !validInstant(value.LoadedAt) || value.LoadedAt.Before(lookup.RequestedAt) ||
		value.LoadedAt.After(lookup.RequestedAt.Add(5*time.Minute+operationTimeout)) ||
		value.ArtifactKind != lookup.ArtifactKind || !bytes.Equal(value.ArtifactID, lookup.ArtifactID) ||
		value.BrowserDigest != lookup.BrowserDigest || value.FactorKind != lookup.FactorKind ||
		!validResolvedCompletionFactor(value.ArtifactKind, value.FactorKind, value.FactorID) ||
		len(lookup.FactorID) != 0 && !bytes.Equal(value.FactorID, lookup.FactorID) ||
		value.TenantID == (identity.EntityID{}) ||
		!validPublicText(value.Action, 256) || !validPublicText(value.Audience, 256) {
		return false
	}
	zeroID := identity.EntityID{}
	zeroDigest := [sha256.Size]byte{}
	switch value.Flow {
	case CompletionFlowPrimary:
		if lookup.SessionSource != nil || lookup.ContinuationID != zeroID ||
			lookup.ContinuationReceiptDigest != zeroDigest || value.SessionID != zeroID ||
			value.SessionFamilyID != zeroID || value.ContinuationID != zeroID ||
			value.ContinuationReceiptDigest != zeroDigest || value.ReservationDisposition != CompletionReservationCreate ||
			value.ArtifactKind != CompletionArtifactWebAuthnAuthentication || value.AnchorVersion != 0 ||
			!value.AnchorExpiresAt.IsZero() || value.UserID == zeroID != (value.IdentityEpoch == 0) ||
			value.ResolvedUserID == zeroID || !validStoredVersion(value.ResolvedIdentityEpoch) ||
			value.UserID != zeroID && (value.UserID != value.ResolvedUserID ||
				value.IdentityEpoch != value.ResolvedIdentityEpoch) ||
			value.ResultAuthenticationMethod != string(mfa.SessionAuthenticationPasskey) {
			return false
		}
	case CompletionFlowSession:
		if value.UserID == zeroID || !validStoredVersion(value.IdentityEpoch) ||
			value.ResolvedUserID != value.UserID || value.ResolvedIdentityEpoch != value.IdentityEpoch ||
			!validStoredSuccessorVersion(value.AnchorVersion) || !validDeadline(value.AnchorExpiresAt) ||
			!value.AnchorExpiresAt.After(value.LoadedAt) || lookup.SessionSource == nil || lookup.ContinuationID != zeroID ||
			lookup.ContinuationReceiptDigest != zeroDigest || value.SessionID != lookup.SessionSource.SessionID ||
			value.SessionFamilyID != lookup.SessionSource.SessionFamilyID || value.ContinuationID != zeroID ||
			value.ContinuationReceiptDigest != zeroDigest || value.ReservationDisposition != CompletionReservationRotate ||
			value.TenantID != lookup.SessionSource.TenantID || value.UserID != lookup.SessionSource.UserID ||
			value.SourceSessionID != lookup.SessionSource.SessionID ||
			value.SourceSessionFamilyID != lookup.SessionSource.SessionFamilyID ||
			value.SourceSessionVersion != value.AnchorVersion ||
			!value.SourceAbsoluteExpiresAt.Equal(lookup.SessionSource.AbsoluteExpiresAt) ||
			value.ResultAuthenticationMethod != lookup.SessionSource.AuthenticationMethod ||
			!validResultAuthenticationMethod(value.ResultAuthenticationMethod) {
			return false
		}
	case CompletionFlowContinuation:
		if value.UserID == zeroID || !validStoredVersion(value.IdentityEpoch) ||
			value.ResolvedUserID != value.UserID || value.ResolvedIdentityEpoch != value.IdentityEpoch ||
			!validStoredSuccessorVersion(value.AnchorVersion) || !validDeadline(value.AnchorExpiresAt) ||
			!value.AnchorExpiresAt.After(value.LoadedAt) || lookup.SessionSource != nil || lookup.ContinuationID == zeroID ||
			lookup.ContinuationID != value.ContinuationID || lookup.ContinuationReceiptDigest == zeroDigest ||
			value.ContinuationReceiptDigest != lookup.ContinuationReceiptDigest || value.SessionID != zeroID ||
			value.SessionFamilyID != zeroID || value.ReservationDisposition != CompletionReservationNone &&
			!validResultAuthenticationMethod(value.ResultAuthenticationMethod) {
			return false
		}
	default:
		return false
	}
	return validCompletionResolutionReservation(value)
}

func validCompletionResolutionReservation(value CompletionTicketResolutionInput) bool {
	expectedMethod, hasExpectedMethod := completionReservationMethod(value.FactorKind)
	switch value.ReservationDisposition {
	case CompletionReservationNone:
		enrollment := value.ArtifactKind == CompletionArtifactTOTPEnrollment &&
			value.FactorKind == CompletionFactorTOTP ||
			value.ArtifactKind == CompletionArtifactWebAuthnRegistration &&
				value.FactorKind == CompletionFactorPasskey
		return enrollment &&
			value.Flow == CompletionFlowContinuation && value.ReservationAuthenticationMethod == "" &&
			value.ResultAuthenticationMethod == "" &&
			value.SourceSessionID == (identity.EntityID{}) && value.SourceSessionFamilyID == (identity.EntityID{}) &&
			value.SourceSessionVersion == 0 && value.SourceAbsoluteExpiresAt.IsZero()
	case CompletionReservationCreate:
		return hasExpectedMethod && value.ReservationAuthenticationMethod == expectedMethod &&
			value.SourceSessionID == (identity.EntityID{}) && value.SourceSessionFamilyID == (identity.EntityID{}) &&
			value.SourceSessionVersion == 0 && value.SourceAbsoluteExpiresAt.IsZero()
	case CompletionReservationRotate:
		return hasExpectedMethod && value.ReservationAuthenticationMethod == expectedMethod &&
			value.SourceSessionID != (identity.EntityID{}) && value.SourceSessionFamilyID != (identity.EntityID{}) &&
			value.SourceSessionID != value.SourceSessionFamilyID && validStoredSuccessorVersion(value.SourceSessionVersion) &&
			validDeadline(value.SourceAbsoluteExpiresAt) && value.SourceAbsoluteExpiresAt.After(value.LoadedAt)
	default:
		return false
	}
}

func completionReservationMethod(kind CompletionFactorKind) (mfa.SessionAuthenticationMethod, bool) {
	switch kind {
	case CompletionFactorTOTP:
		return mfa.SessionAuthenticationTOTP, true
	case CompletionFactorRecovery:
		return mfa.SessionAuthenticationRecovery, true
	case CompletionFactorPasskey:
		return mfa.SessionAuthenticationPasskey, true
	default:
		return "", false
	}
}

func validCompletionArtifactID(kind CompletionArtifactKind, value []byte) bool {
	switch kind {
	case CompletionArtifactTOTPEnrollment:
		return len(value) == len(identity.EntityID{}) && validUUIDv7Bytes(value)
	case CompletionArtifactStepUp, CompletionArtifactWebAuthnRegistration,
		CompletionArtifactWebAuthnAuthentication:
		return len(value) == sha256.Size && !allZeroMaterial(value)
	default:
		return false
	}
}

func validCompletionFactor(artifact CompletionArtifactKind, kind CompletionFactorKind, id []byte) bool {
	switch artifact {
	case CompletionArtifactTOTPEnrollment:
		return kind == CompletionFactorTOTP && len(id) == 0
	case CompletionArtifactStepUp:
		if kind == CompletionFactorRecovery {
			return len(id) == 0
		}
		return kind == CompletionFactorTOTP && len(id) == len(identity.EntityID{}) && validUUIDv7Bytes(id)
	case CompletionArtifactWebAuthnRegistration, CompletionArtifactWebAuthnAuthentication:
		return kind == CompletionFactorPasskey && len(id) > 0 && len(id) <= maximumCredentialBytes
	default:
		return false
	}
}

func validResolvedCompletionFactor(artifact CompletionArtifactKind, kind CompletionFactorKind, id []byte) bool {
	switch artifact {
	case CompletionArtifactTOTPEnrollment:
		return kind == CompletionFactorTOTP && len(id) == len(identity.EntityID{}) && validUUIDv7Bytes(id)
	case CompletionArtifactStepUp:
		return (kind == CompletionFactorTOTP || kind == CompletionFactorRecovery) &&
			len(id) == len(identity.EntityID{}) && validUUIDv7Bytes(id)
	case CompletionArtifactWebAuthnRegistration, CompletionArtifactWebAuthnAuthentication:
		return kind == CompletionFactorPasskey && len(id) > 0 && len(id) <= maximumCredentialBytes
	default:
		return false
	}
}

func validCompletionSessionSource(value CompletionSessionSource) bool {
	return value.TenantID != (identity.EntityID{}) && value.UserID != (identity.EntityID{}) &&
		validUUIDv7Bytes(value.SessionID[:]) && validUUIDv7Bytes(value.SessionFamilyID[:]) &&
		value.SessionID != value.SessionFamilyID && validDeadline(value.AbsoluteExpiresAt) &&
		validResultAuthenticationMethod(value.AuthenticationMethod)
}

func validReservationAuthenticationMethod(value mfa.SessionAuthenticationMethod) bool {
	switch value {
	case mfa.SessionAuthenticationPasskey, mfa.SessionAuthenticationTOTP, mfa.SessionAuthenticationRecovery,
		mfa.SessionAuthenticationOIDC, mfa.SessionAuthenticationSAML:
		return true
	default:
		return false
	}
}

func validResultAuthenticationMethod(value string) bool {
	switch value {
	case "bootstrap_totp", string(mfa.SessionAuthenticationPasskey), string(mfa.SessionAuthenticationTOTP),
		string(mfa.SessionAuthenticationRecovery), string(mfa.SessionAuthenticationOIDC),
		string(mfa.SessionAuthenticationSAML), string(mfa.SessionAuthenticationLDAP):
		return true
	default:
		return false
	}
}

func validUUIDv7Bytes(value []byte) bool {
	return len(value) == len(identity.EntityID{}) && value[6]>>4 == 7 && value[8]&0xc0 == 0x80 &&
		!allZeroMaterial(value)
}

func cloneCompletionResolution(value CompletionTicketResolutionInput) CompletionTicketResolutionInput {
	value.ArtifactID = append([]byte(nil), value.ArtifactID...)
	value.FactorID = append([]byte(nil), value.FactorID...)
	return value
}
