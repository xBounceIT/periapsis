package mfaauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
)

const (
	minimumEnrollmentTTL = time.Minute
	maximumEnrollmentTTL = 15 * time.Minute
	minimumRecoveryCodes = 8
	maximumRecoveryCodes = 16
	maximumMFAKeyVersion = uint32(32_767)
)

type FactorEnrollmentSource interface {
	ResolveFactorEnrollment(context.Context, AuthorityLookup) (AuthoritySnapshot, error)
}

// TOTPEnrollmentMaterialSource owns maintained TOTP provisioning, keyring
// encryption, and CSPRNG-backed one-time handles. The application never
// implements those primitives itself.
type TOTPEnrollmentMaterialSource interface {
	NewTOTPEnrollmentMaterial(context.Context, identity.EntityID, identity.EntityID) (TOTPEnrollmentMaterial, error)
}

type TOTPEnrollmentMaterial struct {
	EnrollmentID    identity.EntityID
	FactorID        identity.EntityID
	BrowserHandle   []byte `json:"-"`
	BrowserDigest   [sha256.Size]byte
	ProtectedSecret mfa.ProtectedTOTPSecret `json:"-"`
	DisplaySecret   []byte                  `json:"-"`
	ProvisioningURI []byte                  `json:"-"`
}

func (material TOTPEnrollmentMaterial) String() string {
	return "mfaauth.TOTPEnrollmentMaterial{material:[REDACTED]}"
}
func (material TOTPEnrollmentMaterial) GoString() string { return material.String() }

func (material *TOTPEnrollmentMaterial) destroy() {
	if material == nil {
		return
	}
	clear(material.BrowserHandle)
	clear(material.ProtectedSecret.Ciphertext)
	clear(material.DisplaySecret)
	clear(material.ProvisioningURI)
	material.ProvisioningURI = nil
}

type StartTOTPEnrollmentWrite struct {
	EnrollmentID    identity.EntityID
	FactorID        identity.EntityID
	BrowserDigest   [sha256.Size]byte
	Binding         mfa.StepUpBinding
	PolicyPins      []mfa.PolicyApplication
	ProtectedSecret mfa.ProtectedTOTPSecret `json:"-"`
	CreatedAt       time.Time
	ExpiresAt       time.Time
}

func (request StartTOTPEnrollmentWrite) String() string {
	return "mfaauth.StartTOTPEnrollmentWrite{material:[REDACTED]}"
}
func (request StartTOTPEnrollmentWrite) GoString() string { return request.String() }

type ClaimTOTPEnrollmentRequest struct {
	EnrollmentID              identity.EntityID
	BrowserDigest             [sha256.Size]byte
	ClaimedAt                 time.Time
	ContinuationReceiptDigest [sha256.Size]byte `json:"-"`
}

func (request ClaimTOTPEnrollmentRequest) String() string {
	return "mfaauth.ClaimTOTPEnrollmentRequest{proof:[REDACTED]}"
}
func (request ClaimTOTPEnrollmentRequest) GoString() string { return request.String() }

type ClaimedTOTPEnrollment struct {
	EnrollmentID    identity.EntityID
	FactorID        identity.EntityID
	Version         uint64
	BrowserDigest   [sha256.Size]byte
	Binding         mfa.StepUpBinding
	ProtectedSecret mfa.ProtectedTOTPSecret `json:"-"`
	CreatedAt       time.Time
	ExpiresAt       time.Time
	ClaimedAt       time.Time
}

func (claim ClaimedTOTPEnrollment) String() string {
	return fmt.Sprintf("mfaauth.ClaimedTOTPEnrollment{version:%d,material:[REDACTED]}", claim.Version)
}
func (claim ClaimedTOTPEnrollment) GoString() string { return claim.String() }

type CompleteTOTPEnrollmentWrite struct {
	EnrollmentID    identity.EntityID
	ExpectedVersion uint64
	FactorID        identity.EntityID
	Binding         mfa.StepUpBinding
	AcceptedCounter int64
	CompletedAt     time.Time
	Audit           AuditIntent
	Session         SessionIntent
}

func (request CompleteTOTPEnrollmentWrite) String() string {
	return "mfaauth.CompleteTOTPEnrollmentWrite{proof:[REDACTED]}"
}
func (request CompleteTOTPEnrollmentWrite) GoString() string { return request.String() }

type TOTPEnrollmentApplyResult struct {
	TenantID               identity.EntityID
	UserID                 identity.EntityID
	IdentityEpoch          uint64
	FactorID               identity.EntityID
	FactorSecurityRevision int64
	AuditID                identity.EntityID
	Mutation               SessionMutation
	NewSessionID           identity.EntityID
	NewSessionFamilyID     identity.EntityID
	RetainedContinuationID identity.EntityID
	SessionVersion         uint64
	RecoveryRestricted     bool
}

func (result TOTPEnrollmentApplyResult) String() string {
	return fmt.Sprintf("mfaauth.TOTPEnrollmentApplyResult{mutation:%d,sessionVersion:%d,subject:[REDACTED]}",
		result.Mutation, result.SessionVersion)
}
func (result TOTPEnrollmentApplyResult) GoString() string { return result.String() }

type FailTOTPEnrollmentWrite struct {
	EnrollmentID    identity.EntityID
	ExpectedVersion uint64
	FailedAt        time.Time
}

// TOTPEnrollmentStore owns one-time claim, attempt exhaustion, factor create,
// session transition, and audit. Complete must commit all success effects in
// one transaction; Fail must terminally reject the claimed enrollment and
// update its shared lockout meter atomically.
type TOTPEnrollmentStore interface {
	StartTOTPEnrollment(context.Context, StartTOTPEnrollmentWrite) error
	ClaimTOTPEnrollment(context.Context, ClaimTOTPEnrollmentRequest) (ClaimedTOTPEnrollment, error)
	CompleteTOTPEnrollment(context.Context, CompleteTOTPEnrollmentWrite) (TOTPEnrollmentApplyResult, error)
	FailTOTPEnrollment(context.Context, FailTOTPEnrollmentWrite) error
}

type RecoveryCodeDigest [sha256.Size]byte

type RecoveryCodeMaterial struct {
	Code   []byte `json:"-"`
	Digest RecoveryCodeDigest
}

func (material RecoveryCodeMaterial) String() string {
	return "mfaauth.RecoveryCodeMaterial{material:[REDACTED]}"
}
func (material RecoveryCodeMaterial) GoString() string { return material.String() }

type RecoveryCodeBatch struct {
	SetID            identity.EntityID
	DigestKeyVersion uint32
	Codes            []RecoveryCodeMaterial
}

func (batch RecoveryCodeBatch) String() string {
	return fmt.Sprintf("mfaauth.RecoveryCodeBatch{count:%d,material:[REDACTED]}", len(batch.Codes))
}
func (batch RecoveryCodeBatch) GoString() string { return batch.String() }

type RecoveryCodeGenerator interface {
	GenerateRecoveryCodes(context.Context, RecoveryCodeGenerationRequest) (RecoveryCodeBatch, error)
}

type RecoveryCodeGenerationRequest struct {
	TenantID identity.EntityID
	UserID   identity.EntityID
	Count    int
}

func (request RecoveryCodeGenerationRequest) String() string {
	return fmt.Sprintf("mfaauth.RecoveryCodeGenerationRequest{count:%d,subject:[REDACTED]}", request.Count)
}
func (request RecoveryCodeGenerationRequest) GoString() string { return request.String() }

type ReplaceRecoveryCodesWrite struct {
	NewSetID           identity.EntityID
	DigestKeyVersion   uint32
	ExpectedSetID      identity.EntityID
	ExpectedSetVersion uint64
	Binding            mfa.StepUpBinding
	Digests            []RecoveryCodeDigest
	GeneratedAt        time.Time
	Audit              AuditIntent
	Session            SessionIntent
}

func (request ReplaceRecoveryCodesWrite) String() string {
	return fmt.Sprintf("mfaauth.ReplaceRecoveryCodesWrite{count:%d,material:[REDACTED]}", len(request.Digests))
}
func (request ReplaceRecoveryCodesWrite) GoString() string { return request.String() }

type RecoveryCodesApplyResult struct {
	TenantID           identity.EntityID
	UserID             identity.EntityID
	IdentityEpoch      uint64
	SetID              identity.EntityID
	SetVersion         uint64
	AuditID            identity.EntityID
	NewSessionID       identity.EntityID
	NewSessionFamilyID identity.EntityID
	SessionVersion     uint64
}

func (result RecoveryCodesApplyResult) String() string {
	return fmt.Sprintf("mfaauth.RecoveryCodesApplyResult{setVersion:%d,sessionVersion:%d,subject:[REDACTED]}",
		result.SetVersion, result.SessionVersion)
}
func (result RecoveryCodesApplyResult) GoString() string { return result.String() }

type RecoveryCodeStore interface {
	ReplaceRecoveryCodes(context.Context, ReplaceRecoveryCodesWrite) (RecoveryCodesApplyResult, error)
}

type FactorEnrollmentOptions struct {
	Source            FactorEnrollmentSource
	Admissions        AdmissionGate
	TOTP              TOTPEnrollmentMaterialSource
	TOTPVerifier      mfa.TOTPVerifier
	TOTPStore         TOTPEnrollmentStore
	Recovery          RecoveryCodeGenerator
	RecoveryStore     RecoveryCodeStore
	Now               func() time.Time
	EnrollmentTTL     time.Duration
	RecoveryCodeCount int
	OperationTimeout  time.Duration
}

type FactorEnrollment struct {
	source            FactorEnrollmentSource
	admissions        AdmissionGate
	totp              TOTPEnrollmentMaterialSource
	totpVerifier      mfa.TOTPVerifier
	totpStore         TOTPEnrollmentStore
	recovery          RecoveryCodeGenerator
	recoveryStore     RecoveryCodeStore
	now               func() time.Time
	enrollmentTTL     time.Duration
	recoveryCodeCount int
	operationTimeout  time.Duration
}

func NewFactorEnrollment(options FactorEnrollmentOptions) (*FactorEnrollment, error) {
	if options.Source == nil || options.Admissions == nil || options.TOTP == nil || options.TOTPVerifier == nil ||
		options.TOTPStore == nil || options.Recovery == nil || options.RecoveryStore == nil ||
		options.EnrollmentTTL < minimumEnrollmentTTL || options.EnrollmentTTL > maximumEnrollmentTTL ||
		options.RecoveryCodeCount < minimumRecoveryCodes || options.RecoveryCodeCount > maximumRecoveryCodes ||
		options.OperationTimeout < minimumOperationTimeout || options.OperationTimeout > maximumOperationTimeout ||
		options.OperationTimeout%time.Microsecond != 0 {
		return nil, ErrInvalidInput
	}
	if options.Now == nil {
		options.Now = func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }
	}
	return &FactorEnrollment{
		source: options.Source, admissions: options.Admissions, totp: options.TOTP,
		totpVerifier: options.TOTPVerifier, totpStore: options.TOTPStore,
		recovery: options.Recovery, recoveryStore: options.RecoveryStore, now: options.Now,
		enrollmentTTL: options.EnrollmentTTL, recoveryCodeCount: options.RecoveryCodeCount,
		operationTimeout: options.OperationTimeout,
	}, nil
}

type TOTPEnrollmentStartArtifact struct {
	enrollmentID  identity.EntityID
	factorID      identity.EntityID
	browserHandle []byte
	displaySecret []byte
	uri           []byte
	expiresAt     time.Time
}

func (artifact TOTPEnrollmentStartArtifact) EnrollmentID() identity.EntityID {
	return artifact.enrollmentID
}
func (artifact TOTPEnrollmentStartArtifact) FactorID() identity.EntityID { return artifact.factorID }
func (artifact TOTPEnrollmentStartArtifact) BrowserHandle() []byte {
	return append([]byte(nil), artifact.browserHandle...)
}
func (artifact TOTPEnrollmentStartArtifact) DisplaySecret() []byte {
	return append([]byte(nil), artifact.displaySecret...)
}
func (artifact TOTPEnrollmentStartArtifact) ProvisioningURI() string { return string(artifact.uri) }
func (artifact TOTPEnrollmentStartArtifact) ExpiresAt() time.Time    { return artifact.expiresAt }
func (artifact TOTPEnrollmentStartArtifact) String() string {
	return "mfaauth.TOTPEnrollmentStartArtifact{material:[REDACTED]}"
}
func (artifact TOTPEnrollmentStartArtifact) GoString() string { return artifact.String() }

// Destroy clears the one-time enrollment material once the transport has
// serialized it. Callers remain responsible for clearing copies they made.
func (artifact *TOTPEnrollmentStartArtifact) Destroy() {
	if artifact == nil {
		return
	}
	clear(artifact.browserHandle)
	clear(artifact.displaySecret)
	clear(artifact.uri)
	artifact.browserHandle = nil
	artifact.displaySecret = nil
	artifact.uri = nil
}

func (service *FactorEnrollment) StartTOTP(
	ctx context.Context,
	lookup AuthorityLookup,
) (TOTPEnrollmentStartArtifact, error) {
	operationContext, cancel, err := service.operation(ctx)
	if err != nil {
		return TOTPEnrollmentStartArtifact{}, err
	}
	defer cancel()
	now := service.currentTime()
	if err := admit(operationContext, service.admissions, lookup.Admission, now); err != nil {
		return TOTPEnrollmentStartArtifact{}, err
	}
	if !validAuthorityLookup(lookup) {
		return TOTPEnrollmentStartArtifact{}, ErrInvalidInput
	}
	resolution := lookup
	resolution.evaluatedAt = now
	authority, err := service.source.ResolveFactorEnrollment(operationContext, resolution)
	if err != nil || !authority.matches(resolution) || !authority.loadedAt.Equal(now) || !authority.enrollmentAllowed() {
		return TOTPEnrollmentStartArtifact{}, ErrDenied
	}
	material, err := service.totp.NewTOTPEnrollmentMaterial(operationContext, authority.tenantID, authority.userID)
	if err != nil {
		return TOTPEnrollmentStartArtifact{}, ErrUnavailable
	}
	defer material.destroy()
	if !validTOTPEnrollmentMaterial(material) {
		return TOTPEnrollmentStartArtifact{}, ErrUnavailable
	}
	expiresAt := now.Add(service.enrollmentTTL).Truncate(time.Millisecond)
	if authority.anchorExpiresAt.Before(expiresAt) {
		expiresAt = authority.anchorExpiresAt
	}
	protectedSecret := cloneProtectedSecret(material.ProtectedSecret)
	defer clear(protectedSecret.Ciphertext)
	if err := service.totpStore.StartTOTPEnrollment(operationContext, StartTOTPEnrollmentWrite{
		EnrollmentID: material.EnrollmentID, FactorID: material.FactorID,
		BrowserDigest: material.BrowserDigest, Binding: authority.binding(),
		PolicyPins:      append([]mfa.PolicyApplication(nil), authority.resolved.Applications...),
		ProtectedSecret: protectedSecret, CreatedAt: now, ExpiresAt: expiresAt,
	}); err != nil {
		return TOTPEnrollmentStartArtifact{}, ErrUnavailable
	}
	return TOTPEnrollmentStartArtifact{
		enrollmentID: material.EnrollmentID, factorID: material.FactorID,
		browserHandle: append([]byte(nil), material.BrowserHandle...),
		displaySecret: append([]byte(nil), material.DisplaySecret...),
		uri:           append([]byte(nil), material.ProvisioningURI...),
		expiresAt:     expiresAt,
	}, nil
}

type FinishTOTPEnrollmentCommand struct {
	Ticket  CompletionTicket
	Code    []byte `json:"-"`
	Session mfa.SessionReservation
}

func (command FinishTOTPEnrollmentCommand) String() string {
	return "mfaauth.FinishTOTPEnrollmentCommand{proof:[REDACTED]}"
}
func (command FinishTOTPEnrollmentCommand) GoString() string { return command.String() }

func (service *FactorEnrollment) FinishTOTP(
	ctx context.Context,
	command FinishTOTPEnrollmentCommand,
) (TOTPEnrollmentApplyResult, error) {
	operationContext, cancel, err := service.operation(ctx)
	if err != nil {
		return TOTPEnrollmentApplyResult{}, err
	}
	defer cancel()
	grant, ok := command.Ticket.consumePrepared(command.Session)
	if !ok || grant.resolution.ArtifactKind != CompletionArtifactTOTPEnrollment ||
		grant.resolution.FactorKind != CompletionFactorTOTP || len(grant.resolution.ArtifactID) != len(identity.EntityID{}) ||
		!validUUIDv7Bytes(grant.resolution.FactorID) || !validTOTPCode(command.Code) {
		return TOTPEnrollmentApplyResult{}, ErrAuthentication
	}
	var enrollmentID identity.EntityID
	copy(enrollmentID[:], grant.resolution.ArtifactID)
	code := append([]byte(nil), command.Code...)
	defer clear(code)
	claimed, err := service.totpStore.ClaimTOTPEnrollment(operationContext, ClaimTOTPEnrollmentRequest{
		EnrollmentID: enrollmentID, BrowserDigest: grant.resolution.BrowserDigest,
		ClaimedAt:                 grant.resolution.LoadedAt,
		ContinuationReceiptDigest: grant.resolution.ContinuationReceiptDigest,
	})
	defer clear(claimed.ProtectedSecret.Ciphertext)
	postClaim := service.currentTime()
	if err != nil || !validClaimedTOTPEnrollment(
		claimed, enrollmentID, grant.resolution.BrowserDigest, grant.resolution.LoadedAt,
		postClaim, service.operationTimeout,
	) || !sameEnrollmentTicketAuthority(grant.resolution, claimed.Binding) ||
		!bytes.Equal(grant.resolution.FactorID, claimed.FactorID[:]) {
		return TOTPEnrollmentApplyResult{}, ErrAuthentication
	}
	if !validEnrollmentCompletionPossession(claimed.Binding, grant.resolution.ContinuationID,
		grant.resolution.ContinuationReceiptDigest) {
		service.failTOTP(ctx, claimed)
		return TOTPEnrollmentApplyResult{}, ErrAuthentication
	}
	completedAt := laterMFATime(claimed.ClaimedAt, postClaim)
	protectedSecret := cloneProtectedSecret(claimed.ProtectedSecret)
	defer clear(protectedSecret.Ciphertext)
	proof, err := service.totpVerifier.VerifyTOTP(operationContext, mfa.TOTPVerificationRequest{
		TenantID: claimed.Binding.TenantID, UserID: claimed.Binding.UserID, FactorID: claimed.FactorID,
		Secret: protectedSecret, Code: code, At: completedAt,
	})
	if err != nil || proof.Counter < 0 {
		service.failTOTP(ctx, claimed)
		return TOTPEnrollmentApplyResult{}, ErrAuthentication
	}
	audit, session, intentsOK := factorEnrollmentIntents(
		claimed.Binding, AuditTOTPEnrolled, completedAt, command.Session,
		grant.resolution.ContinuationReceiptDigest,
	)
	if !intentsOK {
		return TOTPEnrollmentApplyResult{}, ErrInvalidInput
	}
	result, err := service.totpStore.CompleteTOTPEnrollment(operationContext, CompleteTOTPEnrollmentWrite{
		EnrollmentID: claimed.EnrollmentID, ExpectedVersion: claimed.Version, FactorID: claimed.FactorID,
		Binding: claimed.Binding, AcceptedCounter: proof.Counter, CompletedAt: completedAt, Audit: audit, Session: session,
	})
	if err != nil || !validTOTPEnrollmentResult(claimed, result) {
		return TOTPEnrollmentApplyResult{}, ErrAuthentication
	}
	return result, nil
}

type RecoveryCodesArtifact struct {
	setID              identity.EntityID
	codes              [][]byte
	newSessionID       identity.EntityID
	newSessionFamilyID identity.EntityID
	sessionVersion     uint64
}

func (artifact RecoveryCodesArtifact) SetID() identity.EntityID { return artifact.setID }
func (artifact RecoveryCodesArtifact) Codes() [][]byte          { return cloneBytes2D(artifact.codes) }
func (artifact RecoveryCodesArtifact) NewSessionID() identity.EntityID {
	return artifact.newSessionID
}
func (artifact RecoveryCodesArtifact) NewSessionFamilyID() identity.EntityID {
	return artifact.newSessionFamilyID
}
func (artifact RecoveryCodesArtifact) SessionVersion() uint64 { return artifact.sessionVersion }
func (artifact RecoveryCodesArtifact) String() string {
	return fmt.Sprintf("mfaauth.RecoveryCodesArtifact{count:%d,sessionVersion:%d,material:[REDACTED]}",
		len(artifact.codes), artifact.sessionVersion)
}
func (artifact RecoveryCodesArtifact) GoString() string { return artifact.String() }

// Destroy clears the plaintext recovery codes after their one-time display.
func (artifact *RecoveryCodesArtifact) Destroy() {
	if artifact == nil {
		return
	}
	for index := range artifact.codes {
		clear(artifact.codes[index])
	}
	artifact.codes = nil
}

type RegenerateRecoveryCodesCommand struct {
	Lookup  AuthorityLookup
	Session mfa.SessionReservation
}

func (command RegenerateRecoveryCodesCommand) String() string {
	return "mfaauth.RegenerateRecoveryCodesCommand{material:[REDACTED]}"
}
func (command RegenerateRecoveryCodesCommand) GoString() string { return command.String() }

func (service *FactorEnrollment) RegenerateRecoveryCodes(
	ctx context.Context,
	command RegenerateRecoveryCodesCommand,
) (RecoveryCodesArtifact, error) {
	operationContext, cancel, err := service.operation(ctx)
	if err != nil {
		return RecoveryCodesArtifact{}, err
	}
	defer cancel()
	now := service.currentTime()
	lookup := command.Lookup
	if err := admit(operationContext, service.admissions, lookup.Admission, now); err != nil {
		return RecoveryCodesArtifact{}, err
	}
	if !validAuthorityLookup(lookup) {
		return RecoveryCodesArtifact{}, ErrInvalidInput
	}
	resolution := lookup
	resolution.evaluatedAt = now
	authority, err := service.source.ResolveFactorEnrollment(operationContext, resolution)
	if err != nil || !authority.matches(resolution) || !authority.loadedAt.Equal(now) ||
		authority.flow != mfa.FlowExistingSession ||
		authority.anchorRecoveryRestricted || !authority.freshLocalMFA() {
		return RecoveryCodesArtifact{}, ErrDenied
	}
	batch, err := service.recovery.GenerateRecoveryCodes(operationContext, RecoveryCodeGenerationRequest{
		TenantID: authority.tenantID, UserID: authority.userID, Count: service.recoveryCodeCount,
	})
	if err != nil {
		return RecoveryCodesArtifact{}, ErrUnavailable
	}
	defer destroyRecoveryBatch(&batch)
	if !validRecoveryBatch(batch, service.recoveryCodeCount) || batch.SetID == authority.recoverySetID {
		return RecoveryCodesArtifact{}, ErrUnavailable
	}
	digests := make([]RecoveryCodeDigest, len(batch.Codes))
	codes := make([][]byte, len(batch.Codes))
	for index := range batch.Codes {
		digests[index] = batch.Codes[index].Digest
		codes[index] = append([]byte(nil), batch.Codes[index].Code...)
	}
	auditKind := AuditRecoveryCreated
	if authority.recoveryAvailable {
		auditKind = AuditRecoveryRegenerated
	}
	audit, session, intentsOK := factorEnrollmentIntents(
		authority.binding(), auditKind, now, command.Session, [sha256.Size]byte{},
	)
	if !intentsOK {
		for index := range codes {
			clear(codes[index])
		}
		return RecoveryCodesArtifact{}, ErrInvalidInput
	}
	result, err := service.recoveryStore.ReplaceRecoveryCodes(operationContext, ReplaceRecoveryCodesWrite{
		NewSetID: batch.SetID, DigestKeyVersion: batch.DigestKeyVersion, ExpectedSetID: authority.recoverySetID,
		ExpectedSetVersion: authority.recoverySetVersion, Binding: authority.binding(),
		Digests: digests, GeneratedAt: now, Audit: audit, Session: session,
	})
	if err != nil || result.TenantID != authority.tenantID || result.UserID != authority.userID ||
		result.IdentityEpoch != authority.identityEpoch || result.SetID != batch.SetID ||
		!validStoredVersion(result.SetVersion) ||
		result.AuditID == (identity.EntityID{}) || result.NewSessionID == (identity.EntityID{}) ||
		result.NewSessionID == authority.sessionID || result.NewSessionFamilyID != authority.sessionFamilyID ||
		!validStoredVersion(result.SessionVersion) || result.SessionVersion <= authority.anchorVersion {
		for index := range codes {
			clear(codes[index])
		}
		return RecoveryCodesArtifact{}, ErrAuthentication
	}
	return RecoveryCodesArtifact{
		setID: batch.SetID, codes: codes, newSessionID: result.NewSessionID,
		newSessionFamilyID: result.NewSessionFamilyID, sessionVersion: result.SessionVersion,
	}, nil
}

func (service *FactorEnrollment) failTOTP(ctx context.Context, claimed ClaimedTOTPEnrollment) {
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), service.operationTimeout)
	defer cancel()
	_ = service.totpStore.FailTOTPEnrollment(cleanup, FailTOTPEnrollmentWrite{
		EnrollmentID: claimed.EnrollmentID, ExpectedVersion: claimed.Version,
		FailedAt: laterMFATime(claimed.ClaimedAt, service.currentTime()),
	})
}

func factorEnrollmentIntents(
	binding mfa.StepUpBinding,
	kind AuditKind,
	at time.Time,
	reservation mfa.SessionReservation,
	continuationReceiptDigest [sha256.Size]byte,
) (AuditIntent, SessionIntent, bool) {
	if kind == AuditTOTPEnrolled && binding.Flow != mfa.FlowPostPrimaryContinuation &&
		reservation.AuthenticationMethod() != mfa.SessionAuthenticationTOTP ||
		(kind == AuditRecoveryCreated || kind == AuditRecoveryRegenerated) &&
			reservation.AuthenticationMethod() == mfa.SessionAuthenticationRecovery {
		return AuditIntent{}, SessionIntent{}, false
	}
	mutation := SessionRotate
	if binding.Flow == mfa.FlowPostPrimaryContinuation {
		mutation = SessionRetainContinuation
	}
	audit := AuditIntent{
		Kind: kind, TenantID: binding.TenantID, UserID: binding.UserID, Action: binding.Action,
		OccurredAt: at, PolicyRevisions: append([]identity.AssurancePolicyRevision(nil), binding.Requirement.PolicyRevisions...),
	}
	session := SessionIntent{
		Mutation: mutation, ExpectedSessionID: binding.SessionID, ExpectedFamilyID: binding.SessionFamilyID,
		ExpectedContinuationID: binding.ContinuationID, ExpectedAnchorVersion: binding.AnchorVersion,
		ExpectedIdentityEpoch: binding.IdentityEpoch, ExpectedAnchorExpiry: binding.AnchorExpiresAt,
		Audience: binding.Audience, Requirement: cloneRequirement(binding.Requirement), Reservation: reservation,
		ContinuationReceiptDigest: continuationReceiptDigest,
	}
	return audit, session, validSessionReservationForIntent(session, at)
}

func validEnrollmentCompletionPossession(
	binding mfa.StepUpBinding,
	continuationID identity.EntityID,
	receiptDigest [sha256.Size]byte,
) bool {
	zeroID := identity.EntityID{}
	zeroDigest := [sha256.Size]byte{}
	switch binding.Flow {
	case mfa.FlowExistingSession:
		return continuationID == zeroID && receiptDigest == zeroDigest
	case mfa.FlowPostPrimaryContinuation:
		return continuationID == binding.ContinuationID && continuationID != zeroID && receiptDigest != zeroDigest
	default:
		return false
	}
}

func validTOTPEnrollmentMaterial(material TOTPEnrollmentMaterial) bool {
	return material.EnrollmentID != (identity.EntityID{}) && material.FactorID != (identity.EntityID{}) &&
		material.EnrollmentID != material.FactorID && validOpaque(material.BrowserHandle) &&
		material.BrowserDigest == sha256.Sum256(material.BrowserHandle) && material.BrowserDigest != ([sha256.Size]byte{}) &&
		material.ProtectedSecret.KeyVersion > 0 && material.ProtectedSecret.KeyVersion <= maximumMFAKeyVersion &&
		len(material.ProtectedSecret.Ciphertext) >= 16 &&
		len(material.ProtectedSecret.Ciphertext) <= 16*1024 && validBase32Secret(material.DisplaySecret) &&
		validProvisioningURI(material.ProvisioningURI, material.DisplaySecret)
}

func validBase32Secret(value []byte) bool {
	if len(value) < 16 || len(value) > 256 {
		return false
	}
	encoding := base32.StdEncoding.WithPadding(base32.NoPadding)
	decoded, err := encoding.DecodeString(string(value))
	if err != nil || len(decoded) < 10 || encoding.EncodeToString(decoded) != string(value) {
		clear(decoded)
		return false
	}
	clear(decoded)
	return true
}

func validProvisioningURI(raw []byte, displaySecret []byte) bool {
	if len(raw) == 0 || len(raw) > 4*1024 || !utf8.Valid(raw) {
		return false
	}
	value := string(raw)
	if strings.IndexFunc(value, func(character rune) bool {
		return unicode.IsControl(character) || unicode.In(character, unicode.Cf)
	}) >= 0 {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "otpauth" || parsed.Host != "totp" || parsed.User != nil ||
		parsed.Opaque != "" || len(parsed.Path) < 2 || parsed.Path[0] != '/' || parsed.RawPath != "" ||
		parsed.ForceQuery || parsed.RawQuery == "" || parsed.Fragment != "" || parsed.String() != value {
		return false
	}
	if !validPublicText(strings.TrimPrefix(parsed.Path, "/"), 1_024) {
		return false
	}
	query, err := url.ParseQuery(parsed.RawQuery)
	if err != nil || len(query["secret"]) != 1 || query["secret"][0] != string(displaySecret) {
		return false
	}
	for key, values := range query {
		if !validPublicText(key, 64) || len(values) != 1 || !validPublicText(values[0], 512) {
			return false
		}
	}
	return true
}

func validClaimedTOTPEnrollment(
	value ClaimedTOTPEnrollment,
	id identity.EntityID,
	browserDigest [sha256.Size]byte,
	requestedAt time.Time,
	postClaim time.Time,
	operationTimeout time.Duration,
) bool {
	return value.EnrollmentID == id && value.BrowserDigest == browserDigest &&
		value.BrowserDigest != ([sha256.Size]byte{}) && value.FactorID != (identity.EntityID{}) && value.Version >= 2 &&
		validStoredSuccessorVersion(value.Version) &&
		validInstant(value.CreatedAt) && validDeadline(value.ExpiresAt) && validInstant(value.ClaimedAt) &&
		value.ExpiresAt.After(value.CreatedAt) && !value.ClaimedAt.Before(requestedAt) &&
		!value.ClaimedAt.After(requestedAt.Add(5*time.Minute+operationTimeout)) &&
		!postClaim.Before(requestedAt) && !value.ClaimedAt.Before(value.CreatedAt) && value.ClaimedAt.Before(value.ExpiresAt) &&
		value.ProtectedSecret.KeyVersion > 0 && value.ProtectedSecret.KeyVersion <= maximumMFAKeyVersion &&
		len(value.ProtectedSecret.Ciphertext) >= 16 &&
		len(value.ProtectedSecret.Ciphertext) <= 16*1024 && validEnrollmentBinding(value.Binding, value.ClaimedAt)
}

func sameEnrollmentTicketAuthority(resolution CompletionTicketResolutionInput, binding mfa.StepUpBinding) bool {
	return binding.TenantID == resolution.TenantID && binding.UserID == resolution.UserID &&
		binding.IdentityEpoch == resolution.IdentityEpoch && binding.SessionID == resolution.SessionID &&
		binding.SessionFamilyID == resolution.SessionFamilyID && binding.ContinuationID == resolution.ContinuationID &&
		binding.AnchorVersion == resolution.AnchorVersion && binding.AnchorExpiresAt.Equal(resolution.AnchorExpiresAt) &&
		binding.Action == resolution.Action && binding.Audience == resolution.Audience
}

func laterMFATime(left, right time.Time) time.Time {
	if right.After(left) {
		return right
	}
	return left
}

func validEnrollmentBinding(binding mfa.StepUpBinding, now time.Time) bool {
	if binding.TenantID == (identity.EntityID{}) || binding.UserID == (identity.EntityID{}) ||
		!validStoredVersion(binding.IdentityEpoch) || !validStoredSuccessorVersion(binding.AnchorVersion) ||
		!validDeadline(binding.AnchorExpiresAt) ||
		!binding.AnchorExpiresAt.After(now) || !validPublicText(binding.Action, 256) ||
		!validPublicText(binding.Audience, 256) ||
		len(binding.BaselineEvidence) == 0 || !validPolicyRevisions(binding.Requirement.PolicyRevisions) ||
		!validEvidenceRevisions(binding.BaselineEvidence) ||
		identity.EvaluateAssurance(now, binding.Requirement, binding.BaselineEvidence, true) == identity.AssuranceDenied {
		return false
	}
	switch binding.Flow {
	case mfa.FlowExistingSession:
		return binding.SessionID != (identity.EntityID{}) && binding.SessionFamilyID != (identity.EntityID{}) &&
			binding.ContinuationID == (identity.EntityID{}) &&
			(!binding.AnchorRecoveryRestricted || hasLiveRecoveryEvidence(now, binding.BaselineEvidence))
	case mfa.FlowPostPrimaryContinuation:
		return binding.SessionID == (identity.EntityID{}) && binding.SessionFamilyID == (identity.EntityID{}) &&
			binding.ContinuationID != (identity.EntityID{}) && !binding.AnchorRecoveryRestricted
	default:
		return false
	}
}

func validTOTPEnrollmentResult(claimed ClaimedTOTPEnrollment, result TOTPEnrollmentApplyResult) bool {
	zero := identity.EntityID{}
	if result.TenantID != claimed.Binding.TenantID || result.UserID != claimed.Binding.UserID ||
		result.IdentityEpoch != claimed.Binding.IdentityEpoch || result.FactorID != claimed.FactorID ||
		!validStoredRevision(result.FactorSecurityRevision) || result.AuditID == zero || result.RecoveryRestricted ||
		!validStoredVersion(result.SessionVersion) {
		return false
	}
	if claimed.Binding.Flow == mfa.FlowExistingSession {
		return result.Mutation == SessionRotate && result.NewSessionID != zero &&
			result.NewSessionID != claimed.Binding.SessionID &&
			result.NewSessionFamilyID == claimed.Binding.SessionFamilyID &&
			result.RetainedContinuationID == zero && result.SessionVersion > claimed.Binding.AnchorVersion
	}
	return result.Mutation == SessionRetainContinuation && result.NewSessionID == zero &&
		result.NewSessionFamilyID == zero && result.RetainedContinuationID == claimed.Binding.ContinuationID &&
		result.SessionVersion > claimed.Binding.AnchorVersion
}

func validRecoveryBatch(batch RecoveryCodeBatch, expected int) bool {
	if batch.SetID == (identity.EntityID{}) || batch.DigestKeyVersion == 0 ||
		batch.DigestKeyVersion > maximumMFAKeyVersion || len(batch.Codes) != expected {
		return false
	}
	seenCodes := make(map[string]struct{}, len(batch.Codes))
	seenDigests := make(map[RecoveryCodeDigest]struct{}, len(batch.Codes))
	for _, material := range batch.Codes {
		if len(material.Code) < 16 || len(material.Code) > 128 ||
			material.Digest == (RecoveryCodeDigest{}) || !printableASCII(material.Code) {
			return false
		}
		code := string(material.Code)
		if _, duplicate := seenCodes[code]; duplicate {
			return false
		}
		if _, duplicate := seenDigests[material.Digest]; duplicate {
			return false
		}
		seenCodes[code] = struct{}{}
		seenDigests[material.Digest] = struct{}{}
	}
	return true
}

func printableASCII(value []byte) bool {
	if len(value) == 0 || value[0] == ' ' || value[len(value)-1] == ' ' {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func destroyRecoveryBatch(batch *RecoveryCodeBatch) {
	if batch == nil {
		return
	}
	for index := range batch.Codes {
		clear(batch.Codes[index].Code)
	}
	batch.Codes = nil
}

func cloneProtectedSecret(value mfa.ProtectedTOTPSecret) mfa.ProtectedTOTPSecret {
	return mfa.ProtectedTOTPSecret{KeyVersion: value.KeyVersion, Ciphertext: append([]byte(nil), value.Ciphertext...)}
}

func validOpaque(value []byte) bool {
	if len(value) != base64.RawURLEncoding.EncodedLen(32) {
		return false
	}
	decoded := make([]byte, 32)
	count, err := base64.RawURLEncoding.Strict().Decode(decoded, value)
	valid := err == nil && count == 32 && !allZeroMaterial(decoded) &&
		base64.RawURLEncoding.EncodeToString(decoded) == string(value)
	clear(decoded)
	return valid
}

func allZeroMaterial(value []byte) bool {
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined == 0
}

func validTOTPCode(value []byte) bool {
	if len(value) < 6 || len(value) > 8 {
		return false
	}
	return slices.IndexFunc(value, func(character byte) bool { return character < '0' || character > '9' }) < 0
}

func (service *FactorEnrollment) operation(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if service == nil || service.source == nil || service.admissions == nil || service.totp == nil ||
		service.totpVerifier == nil || service.totpStore == nil || service.recovery == nil || service.recoveryStore == nil {
		return nil, nil, ErrInvalidInput
	}
	return operation(ctx, service.operationTimeout)
}

func (service *FactorEnrollment) currentTime() time.Time {
	if service == nil || service.now == nil {
		return time.Time{}
	}
	return service.now().UTC().Truncate(time.Microsecond)
}
