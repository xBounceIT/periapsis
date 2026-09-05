package mfaauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"sync/atomic"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/modules/identity/webauthn"
)

type PasskeyKernel interface {
	StartRegistration(context.Context, webauthn.RegistrationStartRequest) (webauthn.StartArtifact, error)
	StartAuthentication(context.Context, webauthn.AuthenticationStartRequest) (webauthn.StartArtifact, error)
	FinishRegistrationWithConsumer(context.Context, webauthn.RegistrationResponse, webauthn.RegistrationConsumer) (webauthn.RegistrationArtifact, error)
	FinishAuthenticationWithConsumer(context.Context, webauthn.AuthenticationResponse, webauthn.AuthenticationConsumer) (webauthn.AuthenticationArtifact, error)
}

type ApplyOutcome uint8

const (
	ApplyCommitted ApplyOutcome = iota + 1
	ApplyReplayRejected
	ApplyStale
	ApplyDenied
)

type PasskeyRegistrationApply struct {
	Completion  webauthn.RegistrationCompletion
	DisplayName string
	Audit       AuditIntent
	Session     SessionIntent
}

func (request PasskeyRegistrationApply) String() string {
	return fmt.Sprintf("mfaauth.PasskeyRegistrationApply{audit:%q,session:%q,material:[REDACTED]}",
		request.Audit.String(), request.Session.String())
}
func (request PasskeyRegistrationApply) GoString() string { return request.String() }

type PasskeyAuthenticationApply struct {
	Completion webauthn.AuthenticationCompletion
	Audit      AuditIntent
	Session    SessionIntent
}

func (request PasskeyAuthenticationApply) String() string {
	return fmt.Sprintf("mfaauth.PasskeyAuthenticationApply{audit:%q,session:%q,material:[REDACTED]}",
		request.Audit.String(), request.Session.String())
}
func (request PasskeyAuthenticationApply) GoString() string { return request.String() }

type PasskeyRegistrationApplyResult struct {
	Outcome                ApplyOutcome
	Credential             webauthn.Credential
	AuditID                identity.EntityID
	Mutation               SessionMutation
	NewSessionID           identity.EntityID
	NewSessionFamilyID     identity.EntityID
	RetainedContinuationID identity.EntityID
	SessionVersion         uint64
	RecoveryRestricted     bool
}

func (result PasskeyRegistrationApplyResult) String() string {
	return fmt.Sprintf("mfaauth.PasskeyRegistrationApplyResult{outcome:%d,mutation:%d,sessionVersion:%d,material:[REDACTED]}",
		result.Outcome, result.Mutation, result.SessionVersion)
}
func (result PasskeyRegistrationApplyResult) GoString() string { return result.String() }

type PasskeyAuthenticationApplyResult struct {
	Outcome                ApplyOutcome
	Credential             webauthn.AuthenticationApplyResult
	TenantID               identity.EntityID
	UserID                 identity.EntityID
	IdentityEpoch          uint64
	AuditID                identity.EntityID
	Mutation               SessionMutation
	NewSessionID           identity.EntityID
	NewSessionFamilyID     identity.EntityID
	ConsumedContinuationID identity.EntityID
	RevokedAnchorID        identity.EntityID
	SessionVersion         uint64
	RecoveryRestricted     bool
}

func (result PasskeyAuthenticationApplyResult) String() string {
	return fmt.Sprintf("mfaauth.PasskeyAuthenticationApplyResult{outcome:%d,mutation:%d,sessionVersion:%d,material:[REDACTED]}",
		result.Outcome, result.Mutation, result.SessionVersion)
}
func (result PasskeyAuthenticationApplyResult) GoString() string { return result.String() }

// PasskeyTransaction is the protected writer. It must recheck ceremony,
// credential, anchor, RP/policy revisions, then mutate credential/session and
// append audit in one transaction. Non-committed outcomes create no authority.
type PasskeyTransaction interface {
	CompletePasskeyRegistration(context.Context, PasskeyRegistrationApply) (PasskeyRegistrationApplyResult, error)
	CompletePasskeyAuthentication(context.Context, PasskeyAuthenticationApply) (PasskeyAuthenticationApplyResult, error)
}

type PasskeyOptions struct {
	Plans            PasskeyPlanSource
	Admissions       AdmissionGate
	Kernel           PasskeyKernel
	Transactions     PasskeyTransaction
	Now              func() time.Time
	OperationTimeout time.Duration
}

type Passkey struct {
	plans            PasskeyPlanSource
	admissions       AdmissionGate
	kernel           PasskeyKernel
	transactions     PasskeyTransaction
	now              func() time.Time
	operationTimeout time.Duration
}

func NewPasskey(options PasskeyOptions) (*Passkey, error) {
	if options.Plans == nil || options.Admissions == nil || options.Kernel == nil || options.Transactions == nil ||
		options.OperationTimeout < minimumOperationTimeout || options.OperationTimeout > maximumOperationTimeout ||
		options.OperationTimeout%time.Microsecond != 0 {
		return nil, ErrInvalidInput
	}
	if options.Now == nil {
		options.Now = func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }
	}
	return &Passkey{
		plans: options.Plans, admissions: options.Admissions, kernel: options.Kernel,
		transactions: options.Transactions, now: options.Now, operationTimeout: options.OperationTimeout,
	}, nil
}

func (service *Passkey) String() string {
	return fmt.Sprintf("mfaauth.Passkey{configured:%t}", service != nil && service.kernel != nil)
}
func (service *Passkey) GoString() string { return service.String() }

func (service *Passkey) StartRegistration(
	ctx context.Context,
	lookup PasskeyLookup,
) (webauthn.StartArtifact, error) {
	operationContext, cancel, err := service.operation(ctx)
	if err != nil {
		return webauthn.StartArtifact{}, err
	}
	defer cancel()
	now := service.currentTime()
	if err := admit(operationContext, service.admissions, lookup.Admission, now); err != nil {
		return webauthn.StartArtifact{}, err
	}
	if !validPasskeyLookup(lookup, true) {
		return webauthn.StartArtifact{}, ErrInvalidInput
	}
	resolution := lookup
	resolution.evaluatedAt = now
	plan, err := service.plans.ResolvePasskeyRegistration(operationContext, resolution)
	if err != nil || !plan.matches(resolution) {
		return webauthn.StartArtifact{}, ErrDenied
	}
	artifact, err := service.kernel.StartRegistration(operationContext, plan.request)
	if err != nil {
		if errors.Is(err, webauthn.ErrCeremonyPersistence) {
			return webauthn.StartArtifact{}, ErrUnavailable
		}
		return webauthn.StartArtifact{}, ErrAuthentication
	}
	if !validPasskeyStart(artifact, plan.request.Binding, plan.request.RP, plan.request.Policy, 0,
		plan.request.UserHandle, plan.request.ExcludeCredentialIDs, now) {
		return webauthn.StartArtifact{}, ErrAuthentication
	}
	return artifact, nil
}

func (service *Passkey) StartAuthentication(
	ctx context.Context,
	lookup PasskeyLookup,
) (webauthn.StartArtifact, error) {
	operationContext, cancel, err := service.operation(ctx)
	if err != nil {
		return webauthn.StartArtifact{}, err
	}
	defer cancel()
	now := service.currentTime()
	if err := admit(operationContext, service.admissions, lookup.Admission, now); err != nil {
		return webauthn.StartArtifact{}, err
	}
	if !validPasskeyLookup(lookup, false) {
		return webauthn.StartArtifact{}, ErrInvalidInput
	}
	resolution := lookup
	resolution.evaluatedAt = now
	plan, err := service.plans.ResolvePasskeyAuthentication(operationContext, resolution)
	if err != nil || !plan.matches(resolution) {
		return webauthn.StartArtifact{}, ErrDenied
	}
	artifact, err := service.kernel.StartAuthentication(operationContext, plan.request)
	if err != nil {
		if errors.Is(err, webauthn.ErrCeremonyPersistence) {
			return webauthn.StartArtifact{}, ErrUnavailable
		}
		return webauthn.StartArtifact{}, ErrAuthentication
	}
	if !validPasskeyStart(artifact, plan.request.Binding, plan.request.RP, plan.request.Policy, plan.request.Mode,
		plan.request.UserHandle, plan.request.AllowedCredentialIDs, now) {
		return webauthn.StartArtifact{}, ErrAuthentication
	}
	return artifact, nil
}

type FinishPasskeyRegistrationCommand struct {
	Ticket      CompletionTicket
	DisplayName string
	Response    webauthn.RegistrationResponse
	Session     mfa.SessionReservation
}

func (command FinishPasskeyRegistrationCommand) String() string {
	return "mfaauth.FinishPasskeyRegistrationCommand{material:[REDACTED]}"
}
func (command FinishPasskeyRegistrationCommand) GoString() string { return command.String() }

type PasskeyRegistrationResult struct {
	Registration webauthn.RegistrationArtifact
	Apply        PasskeyRegistrationApplyResult
}

func (result PasskeyRegistrationResult) String() string {
	return fmt.Sprintf("mfaauth.PasskeyRegistrationResult{outcome:%d,sessionVersion:%d,material:[REDACTED]}",
		result.Apply.Outcome, result.Apply.SessionVersion)
}
func (result PasskeyRegistrationResult) GoString() string { return result.String() }

func (service *Passkey) FinishRegistration(
	ctx context.Context,
	command FinishPasskeyRegistrationCommand,
) (PasskeyRegistrationResult, error) {
	operationContext, cancel, err := service.operation(ctx)
	if err != nil {
		return PasskeyRegistrationResult{}, err
	}
	defer cancel()
	if !validPublicText(command.DisplayName, 120) {
		return PasskeyRegistrationResult{}, ErrInvalidInput
	}
	grant, ok := command.Ticket.consume(
		CompletionArtifactWebAuthnRegistration, command.Response.CeremonyID[:], command.Response.BrowserHandle,
		CompletionFactorPasskey, command.Response.CredentialID, command.Session,
	)
	if !ok {
		return PasskeyRegistrationResult{}, ErrAuthentication
	}
	command.Response.ContinuationReceiptDigest = grant.resolution.ContinuationReceiptDigest
	consumer := &registrationConsumer{
		transactions: service.transactions, displayName: command.DisplayName, session: command.Session,
		authority: grant.resolution,
	}
	artifact, err := service.kernel.FinishRegistrationWithConsumer(operationContext, command.Response, consumer)
	if err != nil {
		return PasskeyRegistrationResult{}, consumer.publicError()
	}
	if !consumer.called.Load() || !validRegistrationApply(consumer.completion, consumer.result, command.Session) ||
		!validRegistrationArtifact(artifact, consumer.result.Credential) {
		return PasskeyRegistrationResult{}, ErrAuthentication
	}
	return PasskeyRegistrationResult{Registration: artifact, Apply: cloneRegistrationResult(consumer.result)}, nil
}

type FinishPasskeyAuthenticationCommand struct {
	Ticket   CompletionTicket
	Response webauthn.AuthenticationResponse
	Session  mfa.SessionReservation
}

func (command FinishPasskeyAuthenticationCommand) String() string {
	return "mfaauth.FinishPasskeyAuthenticationCommand{material:[REDACTED]}"
}
func (command FinishPasskeyAuthenticationCommand) GoString() string { return command.String() }

type PasskeyAuthenticationResult struct {
	Authentication webauthn.AuthenticationArtifact
	Apply          PasskeyAuthenticationApplyResult
}

func (result PasskeyAuthenticationResult) String() string {
	return fmt.Sprintf("mfaauth.PasskeyAuthenticationResult{outcome:%d,sessionVersion:%d,material:[REDACTED]}",
		result.Apply.Outcome, result.Apply.SessionVersion)
}
func (result PasskeyAuthenticationResult) GoString() string { return result.String() }

func (service *Passkey) FinishAuthentication(
	ctx context.Context,
	command FinishPasskeyAuthenticationCommand,
) (PasskeyAuthenticationResult, error) {
	operationContext, cancel, err := service.operation(ctx)
	if err != nil {
		return PasskeyAuthenticationResult{}, err
	}
	defer cancel()
	grant, ok := command.Ticket.consume(
		CompletionArtifactWebAuthnAuthentication, command.Response.CeremonyID[:], command.Response.BrowserHandle,
		CompletionFactorPasskey, command.Response.CredentialID, command.Session,
	)
	if !ok {
		return PasskeyAuthenticationResult{}, ErrAuthentication
	}
	command.Response.ContinuationReceiptDigest = grant.resolution.ContinuationReceiptDigest
	consumer := &authenticationConsumer{
		transactions: service.transactions, session: command.Session,
		authority: grant.resolution,
	}
	artifact, err := service.kernel.FinishAuthenticationWithConsumer(operationContext, command.Response, consumer)
	if err != nil {
		return PasskeyAuthenticationResult{}, consumer.publicError()
	}
	if !consumer.called.Load() || !validAuthenticationApply(consumer.completion, consumer.result, command.Session) ||
		!validAuthenticationArtifact(artifact, consumer.completion, consumer.result) {
		return PasskeyAuthenticationResult{}, ErrAuthentication
	}
	return PasskeyAuthenticationResult{Authentication: artifact, Apply: consumer.result}, nil
}

type registrationConsumer struct {
	transactions PasskeyTransaction
	displayName  string
	session      mfa.SessionReservation
	authority    CompletionTicketResolutionInput
	called       atomic.Bool
	completion   webauthn.RegistrationCompletion
	result       PasskeyRegistrationApplyResult
	err          error
	unavailable  bool
}

func (consumer *registrationConsumer) CompleteRegistration(
	ctx context.Context,
	completion webauthn.RegistrationCompletion,
) (webauthn.Credential, error) {
	if consumer == nil || consumer.transactions == nil || !consumer.called.CompareAndSwap(false, true) {
		return webauthn.Credential{}, ErrAuthentication
	}
	expected := cloneRegistrationCompletion(completion)
	consumer.completion = cloneRegistrationCompletion(expected)
	audit, session, ok := passkeyIntents(
		expected.Binding, expected.CompletedAt, false, consumer.session,
		consumer.authority.ContinuationID, consumer.authority.ContinuationReceiptDigest,
	)
	if !ok || !validPublicText(consumer.displayName, 120) || !validRegistrationCompletion(expected) {
		consumer.err = ErrAuthentication
		return webauthn.Credential{}, consumer.err
	}
	if !samePasskeyTicketBinding(consumer.authority, expected.Binding) {
		consumer.err = ErrAuthentication
		return webauthn.Credential{}, consumer.err
	}
	result, err := consumer.transactions.CompletePasskeyRegistration(ctx, PasskeyRegistrationApply{
		Completion: cloneRegistrationCompletion(expected), DisplayName: consumer.displayName,
		Audit: audit, Session: session,
	})
	consumer.result, consumer.err = cloneRegistrationResult(result), err
	consumer.unavailable = err != nil
	if err != nil || result.Outcome != ApplyCommitted || !validRegistrationApply(expected, result, consumer.session) {
		return webauthn.Credential{}, ErrAuthentication
	}
	return cloneCredential(result.Credential), nil
}

func (consumer *registrationConsumer) publicError() error {
	if consumer != nil && consumer.unavailable {
		return ErrUnavailable
	}
	return ErrAuthentication
}

type authenticationConsumer struct {
	transactions PasskeyTransaction
	session      mfa.SessionReservation
	authority    CompletionTicketResolutionInput
	called       atomic.Bool
	completion   webauthn.AuthenticationCompletion
	result       PasskeyAuthenticationApplyResult
	err          error
	unavailable  bool
}

func (consumer *authenticationConsumer) CompleteAuthentication(
	ctx context.Context,
	completion webauthn.AuthenticationCompletion,
) (webauthn.AuthenticationApplyResult, error) {
	if consumer == nil || consumer.transactions == nil || !consumer.called.CompareAndSwap(false, true) {
		return webauthn.AuthenticationApplyResult{}, ErrAuthentication
	}
	expected := cloneAuthenticationCompletion(completion)
	consumer.completion = cloneAuthenticationCompletion(expected)
	cloneSuspected := expected.CounterDisposition == webauthn.CounterCloneSuspected
	intentReservation := consumer.session
	if cloneSuspected {
		// A suspected clone revokes the pinned authority and intentionally
		// discards the browser credential that was reserved before proof
		// verification.
		intentReservation = mfa.SessionReservation{}
	}
	audit, session, ok := passkeyIntents(
		expected.Binding, expected.CompletedAt, cloneSuspected, intentReservation,
		consumer.authority.ContinuationID, consumer.authority.ContinuationReceiptDigest,
	)
	if !ok || expected.Binding.Purpose == webauthn.PurposeRegistration ||
		!validAuthenticationCompletion(expected, cloneSuspected) {
		consumer.err = ErrAuthentication
		return webauthn.AuthenticationApplyResult{}, consumer.err
	}
	if !samePasskeyTicketBinding(consumer.authority, expected.Binding) {
		consumer.err = ErrAuthentication
		return webauthn.AuthenticationApplyResult{}, consumer.err
	}
	if expected.ResolvedUserID != consumer.authority.ResolvedUserID ||
		expected.ExpectedIdentityEpoch != consumer.authority.ResolvedIdentityEpoch {
		consumer.err = ErrAuthentication
		return webauthn.AuthenticationApplyResult{}, consumer.err
	}
	audit.UserID = expected.ResolvedUserID
	session.ExpectedIdentityEpoch = expected.ExpectedIdentityEpoch
	result, err := consumer.transactions.CompletePasskeyAuthentication(ctx, PasskeyAuthenticationApply{
		Completion: cloneAuthenticationCompletion(expected), Audit: audit, Session: session,
	})
	consumer.result, consumer.err = result, err
	consumer.unavailable = err != nil
	if err != nil || result.Outcome != ApplyCommitted || !validAuthenticationApply(expected, result, consumer.session) {
		return webauthn.AuthenticationApplyResult{}, ErrAuthentication
	}
	return result.Credential, nil
}

func samePasskeyTicketBinding(resolution CompletionTicketResolutionInput, binding webauthn.CeremonyBinding) bool {
	return binding.TenantID == resolution.TenantID && binding.UserID == resolution.UserID &&
		binding.IdentityEpoch == resolution.IdentityEpoch && binding.SessionID == resolution.SessionID &&
		binding.SessionFamilyID == resolution.SessionFamilyID && binding.ContinuationID == resolution.ContinuationID &&
		binding.AnchorVersion == resolution.AnchorVersion && binding.AnchorExpiresAt.Equal(resolution.AnchorExpiresAt) &&
		binding.Action == resolution.Action && binding.Audience == resolution.Audience
}

func (consumer *authenticationConsumer) publicError() error {
	if consumer != nil && consumer.unavailable {
		return ErrUnavailable
	}
	return ErrAuthentication
}

func validRegistrationCompletion(value webauthn.RegistrationCompletion) bool {
	zero := identity.EntityID{}
	if !validInstant(value.CompletedAt) || !validPasskeyBinding(value.Binding, value.CompletedAt) ||
		value.Binding.Purpose != webauthn.PurposeRegistration || value.Credential.TenantID != value.Binding.TenantID ||
		value.Credential.UserID != value.Binding.UserID || value.Credential.IdentityEpoch != value.Binding.IdentityEpoch ||
		value.Credential.Version != 1 || value.Credential.SecurityRevision != 1 ||
		value.Credential.Status != webauthn.CredentialActive || !value.Credential.UserVerification ||
		len(value.Credential.ID) == 0 || len(value.Credential.PublicKey) == 0 || value.Credential.TenantID == zero {
		return false
	}
	decision := identity.EvaluateAssurance(value.CompletedAt, value.Binding.Requirement,
		value.Binding.BaselineEvidence, true)
	return decision == identity.AssuranceSatisfied && value.Binding.Requirement.Level >= identity.AssuranceMFA ||
		value.Binding.ContinuationID != zero && !value.Binding.AnchorRecoveryRestricted &&
			decision == identity.AssuranceEnrollmentOnly ||
		value.Binding.SessionID != zero && value.Binding.AnchorRecoveryRestricted &&
			decision == identity.AssuranceStepUpRequired &&
			hasLiveRecoveryEvidence(value.CompletedAt, value.Binding.BaselineEvidence)
}

func validAuthenticationCompletion(value webauthn.AuthenticationCompletion, cloneSuspected bool) bool {
	if !validInstant(value.CompletedAt) || !validPasskeyBinding(value.Binding, value.CompletedAt) ||
		value.Binding.Purpose == webauthn.PurposeRegistration || len(value.CredentialID) == 0 ||
		value.ResolvedUserID == (identity.EntityID{}) || value.ExpectedIdentityEpoch == 0 ||
		(value.Binding.UserID != (identity.EntityID{}) &&
			(value.ResolvedUserID != value.Binding.UserID || value.ExpectedIdentityEpoch != value.Binding.IdentityEpoch)) ||
		!validStoredVersion(value.ExpectedCredentialVersion) || value.ExpectedCredentialVersion == maximumStoredVersion ||
		!validStoredVersion(value.ExpectedSecurityRevision) ||
		value.ExpectedSecurityRevision > value.ExpectedCredentialVersion ||
		value.ExpectedBackedUp && !value.ExpectedBackupEligible || value.BackedUp && !value.BackupEligible ||
		cloneSuspected != (value.CounterDisposition == webauthn.CounterCloneSuspected) ||
		webauthn.EvaluateSignCount(value.ExpectedSignCount, value.ObservedSignCount) != value.CounterDisposition {
		return false
	}
	if cloneSuspected {
		return true
	}
	evidence, ok := passkeyEvidence(value)
	if !ok {
		return false
	}
	combined := append(cloneEvidence(value.Binding.BaselineEvidence), evidence)
	return identity.EvaluateAssurance(value.CompletedAt, value.Binding.Requirement, combined, false) ==
		identity.AssuranceSatisfied
}

func validRegistrationArtifact(
	artifact webauthn.RegistrationArtifact,
	credential webauthn.Credential,
) bool {
	return artifact.TenantID == credential.TenantID && artifact.UserID == credential.UserID &&
		artifact.IdentityEpoch == credential.IdentityEpoch && artifact.CredentialVersion == credential.Version &&
		artifact.Discoverable == credential.Discoverable && artifact.BackupEligible == credential.BackupEligible &&
		artifact.BackedUp == credential.BackedUp && slices.Equal(artifact.Transports, credential.Transports)
}

func validAuthenticationArtifact(
	artifact webauthn.AuthenticationArtifact,
	completion webauthn.AuthenticationCompletion,
	result PasskeyAuthenticationApplyResult,
) bool {
	evidence, ok := passkeyEvidence(completion)
	return ok && artifact.TenantID == result.TenantID && artifact.UserID == result.UserID &&
		artifact.IdentityEpoch == completion.ExpectedIdentityEpoch &&
		artifact.CredentialVersion == result.Credential.CredentialVersion &&
		artifact.CredentialDigest == sha256.Sum256(completion.CredentialID) &&
		sameEvidence([]identity.AssuranceEvidence{artifact.Evidence}, []identity.AssuranceEvidence{evidence}) &&
		artifact.CounterUnsupported == (completion.CounterDisposition == webauthn.CounterUnsupported) &&
		artifact.BackupStateChanged == (completion.ExpectedBackupEligible != completion.BackupEligible ||
			completion.ExpectedBackedUp != completion.BackedUp)
}

func passkeyEvidence(value webauthn.AuthenticationCompletion) (identity.AssuranceEvidence, bool) {
	revisionValue, ok := passkeySecurityRevision(value)
	if !ok {
		return identity.AssuranceEvidence{}, false
	}
	revision := int64(revisionValue)
	level := identity.AssuranceMFA
	if value.Binding.Purpose == webauthn.PurposePrimaryAuthentication {
		level = identity.AssurancePrimary
	}
	if value.UserVerified {
		level = identity.AssurancePhishingResistant
	}
	return identity.AssuranceEvidence{
		Level: level, Kind: identity.AssuranceEvidenceFactor,
		Source: identity.AssuranceSource{Local: true}, AuthenticatedAt: value.CompletedAt,
		FactorRevision: &revision,
	}, true
}

func validPasskeyBinding(value webauthn.CeremonyBinding, now time.Time) bool {
	zero := identity.EntityID{}
	if value.TenantID == zero || !validPublicText(value.Action, 256) || !validPublicText(value.Audience, 256) ||
		identity.EvaluateAssurance(now, value.Requirement, nil, false) == identity.AssuranceDenied ||
		evidenceFromFuture(now, value.BaselineEvidence) {
		return false
	}
	if value.AnchorRecoveryRestricted && !hasLiveRecoveryEvidence(now, value.BaselineEvidence) {
		return false
	}
	baselineRequirement := identity.EffectiveAssuranceRequirement{
		Level:           identity.AssurancePrimary,
		PolicyRevisions: []identity.AssurancePolicyRevision{{PolicyID: identity.EntityID{1}, Revision: 1}},
	}
	if identity.EvaluateAssurance(now, baselineRequirement, value.BaselineEvidence, false) == identity.AssuranceDenied {
		return false
	}
	switch value.Purpose {
	case webauthn.PurposePrimaryAuthentication:
		return value.SessionID == zero && value.SessionFamilyID == zero && value.ContinuationID == zero &&
			!value.AnchorRecoveryRestricted && value.AnchorVersion == 0 && value.AnchorExpiresAt.IsZero() &&
			len(value.BaselineEvidence) == 0 &&
			(value.UserID == zero && value.IdentityEpoch == 0 ||
				value.UserID != zero && validStoredVersion(value.IdentityEpoch))
	case webauthn.PurposeRegistration:
		if value.UserID == zero || !validStoredVersion(value.IdentityEpoch) || !validStoredVersion(value.AnchorVersion) ||
			!validDeadline(value.AnchorExpiresAt) || !value.AnchorExpiresAt.After(now) ||
			len(value.BaselineEvidence) == 0 {
			return false
		}
		sessionAnchor := value.SessionID != zero && value.SessionFamilyID != zero && value.ContinuationID == zero
		continuationAnchor := value.SessionID == zero && value.SessionFamilyID == zero && value.ContinuationID != zero
		return sessionAnchor && (!value.AnchorRecoveryRestricted ||
			hasLiveRecoveryEvidence(now, value.BaselineEvidence)) ||
			continuationAnchor && !value.AnchorRecoveryRestricted
	case webauthn.PurposeContinuationAuthentication:
		return !value.AnchorRecoveryRestricted && value.UserID != zero && validStoredVersion(value.IdentityEpoch) &&
			value.SessionID == zero &&
			value.SessionFamilyID == zero && value.ContinuationID != zero && validStoredVersion(value.AnchorVersion) &&
			validDeadline(value.AnchorExpiresAt) && value.AnchorExpiresAt.After(now) && len(value.BaselineEvidence) > 0
	case webauthn.PurposeStepUpAuthentication:
		return value.UserID != zero && validStoredVersion(value.IdentityEpoch) && value.SessionID != zero &&
			value.SessionFamilyID != zero && value.ContinuationID == zero && validStoredVersion(value.AnchorVersion) &&
			validDeadline(value.AnchorExpiresAt) && value.AnchorExpiresAt.After(now) && len(value.BaselineEvidence) > 0
	default:
		return false
	}
}

func validRegistrationApply(
	completion webauthn.RegistrationCompletion,
	result PasskeyRegistrationApplyResult,
	reservation mfa.SessionReservation,
) bool {
	zero := identity.EntityID{}
	if result.Outcome != ApplyCommitted || result.AuditID == zero || result.Mutation == 0 ||
		result.RecoveryRestricted ||
		result.Credential.TenantID != completion.Binding.TenantID || result.Credential.UserID != completion.Binding.UserID {
		return false
	}
	if completion.Binding.SessionID != zero {
		return result.Mutation == SessionRotate && result.NewSessionID != zero &&
			result.NewSessionID != completion.Binding.SessionID &&
			!reservation.IsZero() && result.NewSessionID == reservation.SessionID() &&
			result.NewSessionFamilyID == reservation.FamilyID() &&
			result.NewSessionFamilyID == completion.Binding.SessionFamilyID &&
			result.RetainedContinuationID == zero && validStoredVersion(result.SessionVersion) &&
			result.SessionVersion > completion.Binding.AnchorVersion
	}
	return result.Mutation == SessionRetainContinuation && result.NewSessionID == zero &&
		result.NewSessionFamilyID == zero && reservation.IsZero() &&
		result.RetainedContinuationID == completion.Binding.ContinuationID &&
		validStoredVersion(result.SessionVersion) && result.SessionVersion > completion.Binding.AnchorVersion
}

func validAuthenticationApply(
	completion webauthn.AuthenticationCompletion,
	result PasskeyAuthenticationApplyResult,
	reservation mfa.SessionReservation,
) bool {
	zero := identity.EntityID{}
	if result.Outcome != ApplyCommitted || result.AuditID == zero || result.RecoveryRestricted ||
		result.TenantID != completion.Binding.TenantID ||
		result.UserID == zero || result.UserID != completion.ResolvedUserID ||
		result.IdentityEpoch != completion.ExpectedIdentityEpoch ||
		!validAuthenticationCredentialMutation(completion, result.Credential) {
		return false
	}
	if completion.CounterDisposition == webauthn.CounterCloneSuspected {
		if result.Mutation != SessionRevoke || result.NewSessionID != zero || result.NewSessionFamilyID != zero ||
			result.ConsumedContinuationID != zero {
			return false
		}
		if completion.Binding.Purpose == webauthn.PurposePrimaryAuthentication {
			return result.RevokedAnchorID == zero && result.SessionVersion == 0
		}
		expectedAnchor := completion.Binding.SessionID
		if completion.Binding.Purpose == webauthn.PurposeContinuationAuthentication {
			expectedAnchor = completion.Binding.ContinuationID
		}
		return result.RevokedAnchorID == expectedAnchor && validStoredVersion(result.SessionVersion) &&
			result.SessionVersion > completion.Binding.AnchorVersion
	}
	if result.RevokedAnchorID != zero || result.NewSessionID == zero || result.NewSessionFamilyID == zero ||
		reservation.IsZero() || result.NewSessionID != reservation.SessionID() ||
		result.NewSessionFamilyID != reservation.FamilyID() || !validStoredVersion(result.SessionVersion) {
		return false
	}
	switch completion.Binding.Purpose {
	case webauthn.PurposePrimaryAuthentication:
		return result.Mutation == SessionCreate && result.ConsumedContinuationID == zero
	case webauthn.PurposeContinuationAuthentication:
		return result.Mutation == SessionConsumeContinuation &&
			result.ConsumedContinuationID == completion.Binding.ContinuationID &&
			result.SessionVersion > completion.Binding.AnchorVersion
	case webauthn.PurposeStepUpAuthentication:
		return result.Mutation == SessionRotate && result.NewSessionID != completion.Binding.SessionID &&
			result.NewSessionFamilyID == completion.Binding.SessionFamilyID && result.ConsumedContinuationID == zero &&
			result.SessionVersion > completion.Binding.AnchorVersion
	default:
		return false
	}
}

func validAuthenticationCredentialMutation(
	completion webauthn.AuthenticationCompletion,
	result webauthn.AuthenticationApplyResult,
) bool {
	expectedSecurityRevision, ok := passkeySecurityRevision(completion)
	if !ok || result.CredentialVersion != completion.ExpectedCredentialVersion+1 ||
		result.SecurityRevision != expectedSecurityRevision || result.SecurityRevision > result.CredentialVersion ||
		result.BackupEligible != completion.BackupEligible || result.BackedUp != completion.BackedUp {
		return false
	}
	switch completion.CounterDisposition {
	case webauthn.CounterUnsupported:
		return completion.ExpectedSignCount == 0 && result.Status == webauthn.CredentialActive && result.SignCount == 0
	case webauthn.CounterAdvance:
		return result.Status == webauthn.CredentialActive && result.SignCount == completion.ObservedSignCount
	case webauthn.CounterCloneSuspected:
		return result.Status == webauthn.CredentialCloneSuspected && result.SignCount == completion.ExpectedSignCount
	default:
		return false
	}
}

func passkeySecurityRevision(value webauthn.AuthenticationCompletion) (uint64, bool) {
	if !validStoredVersion(value.ExpectedCredentialVersion) || value.ExpectedCredentialVersion == maximumStoredVersion ||
		!validStoredVersion(value.ExpectedSecurityRevision) ||
		value.ExpectedSecurityRevision > value.ExpectedCredentialVersion ||
		value.ExpectedBackedUp && !value.ExpectedBackupEligible || value.BackedUp && !value.BackupEligible {
		return 0, false
	}
	revision := value.ExpectedSecurityRevision
	if value.CounterDisposition == webauthn.CounterCloneSuspected ||
		value.ExpectedBackupEligible != value.BackupEligible || value.ExpectedBackedUp != value.BackedUp {
		revision++
	}
	return revision, validStoredVersion(revision) && revision <= value.ExpectedCredentialVersion+1
}

func cloneRegistrationResult(value PasskeyRegistrationApplyResult) PasskeyRegistrationApplyResult {
	value.Credential = cloneCredential(value.Credential)
	return value
}

func cloneCredential(value webauthn.Credential) webauthn.Credential {
	value.ID = append([]byte(nil), value.ID...)
	value.PublicKey = append([]byte(nil), value.PublicKey...)
	value.Transports = append([]webauthn.CredentialTransport(nil), value.Transports...)
	return value
}

func cloneRegistrationCompletion(value webauthn.RegistrationCompletion) webauthn.RegistrationCompletion {
	value.Binding = cloneCeremonyBinding(value.Binding)
	value.Credential = cloneCredential(value.Credential)
	return value
}

func cloneAuthenticationCompletion(value webauthn.AuthenticationCompletion) webauthn.AuthenticationCompletion {
	value.Binding = cloneCeremonyBinding(value.Binding)
	value.CredentialID = append([]byte(nil), value.CredentialID...)
	return value
}

func cloneCeremonyBinding(value webauthn.CeremonyBinding) webauthn.CeremonyBinding {
	value.Requirement = cloneRequirement(value.Requirement)
	value.BaselineEvidence = cloneEvidence(value.BaselineEvidence)
	return value
}

func validPasskeyStart(
	artifact webauthn.StartArtifact,
	expected webauthn.CeremonyBinding,
	expectedRP webauthn.RelyingParty,
	expectedPolicy webauthn.CeremonyPolicy,
	expectedMode webauthn.AuthenticationMode,
	expectedUserHandle []byte,
	expectedCredentialIDs [][]byte,
	now time.Time,
) bool {
	binding := artifact.Binding()
	rp := artifact.RelyingParty()
	challenge := artifact.Challenge()
	if artifact.CeremonyID() == (webauthn.CeremonyID{}) || len(challenge) != 32 || allZeroMaterial(challenge) ||
		!validOpaque(artifact.BrowserHandle()) || !artifact.ExpiresAt().After(now) ||
		!sameCeremonyBinding(binding, expected) || rp.ID() != expectedRP.ID() ||
		rp.Revision() != expectedRP.Revision() || !slices.Equal(rp.Origins(), expectedRP.Origins()) ||
		artifact.Policy() != expectedPolicy || artifact.Mode() != expectedMode ||
		!bytes.Equal(artifact.UserHandle(), expectedUserHandle) ||
		!sameByteSlices(artifact.CredentialIDs(), expectedCredentialIDs) {
		return false
	}
	return expected.AnchorExpiresAt.IsZero() || !artifact.ExpiresAt().After(expected.AnchorExpiresAt)
}

func sameByteSlices(left, right [][]byte) bool {
	return slices.EqualFunc(left, right, bytes.Equal)
}

func sameCeremonyBinding(left, right webauthn.CeremonyBinding) bool {
	if left.Purpose != right.Purpose || left.TenantID != right.TenantID || left.UserID != right.UserID ||
		left.IdentityEpoch != right.IdentityEpoch ||
		left.SessionID != right.SessionID || left.SessionFamilyID != right.SessionFamilyID ||
		left.ContinuationID != right.ContinuationID || left.AnchorVersion != right.AnchorVersion ||
		!left.AnchorExpiresAt.Equal(right.AnchorExpiresAt) || left.Action != right.Action || left.Audience != right.Audience ||
		left.AnchorRecoveryRestricted != right.AnchorRecoveryRestricted ||
		left.Requirement.Level != right.Requirement.Level ||
		left.Requirement.LocalRequired != right.Requirement.LocalRequired ||
		left.Requirement.Freshness != right.Requirement.Freshness ||
		len(left.Requirement.PolicyRevisions) != len(right.Requirement.PolicyRevisions) ||
		!sameEvidence(left.BaselineEvidence, right.BaselineEvidence) {
		return false
	}
	for index := range left.Requirement.PolicyRevisions {
		if left.Requirement.PolicyRevisions[index] != right.Requirement.PolicyRevisions[index] {
			return false
		}
	}
	if left.Requirement.EnrollmentDeadline == nil || right.Requirement.EnrollmentDeadline == nil {
		return left.Requirement.EnrollmentDeadline == nil && right.Requirement.EnrollmentDeadline == nil
	}
	return left.Requirement.EnrollmentDeadline.Equal(*right.Requirement.EnrollmentDeadline)
}

func sameEvidence(left, right []identity.AssuranceEvidence) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].Level != right[index].Level || left[index].Kind != right[index].Kind ||
			left[index].Source != right[index].Source || !left[index].AuthenticatedAt.Equal(right[index].AuthenticatedAt) ||
			!sameOptionalTime(left[index].ExpiresAt, right[index].ExpiresAt) ||
			!sameOptionalInt64(left[index].FactorRevision, right[index].FactorRevision) ||
			!sameOptionalInt64(left[index].TrustRuleRevision, right[index].TrustRuleRevision) {
			return false
		}
	}
	return true
}

func sameOptionalTime(left, right *time.Time) bool {
	return left == nil && right == nil || left != nil && right != nil && left.Equal(*right)
}

func sameOptionalInt64(left, right *int64) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func (service *Passkey) operation(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if service == nil || service.plans == nil || service.admissions == nil ||
		service.kernel == nil || service.transactions == nil {
		return nil, nil, ErrInvalidInput
	}
	return operation(ctx, service.operationTimeout)
}

func (service *Passkey) currentTime() time.Time {
	if service == nil || service.now == nil {
		return time.Time{}
	}
	return service.now().UTC().Truncate(time.Microsecond)
}
