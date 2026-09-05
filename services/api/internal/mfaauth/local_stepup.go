package mfaauth

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
)

type LocalStepUpKernel interface {
	Start(context.Context, mfa.StepUpStartRequest) (mfa.StepUpStartArtifact, error)
	CompleteTOTP(context.Context, mfa.TOTPCompletionRequest) (mfa.StepUpArtifact, error)
	CompleteRecovery(context.Context, mfa.RecoveryCompletionRequest) (mfa.StepUpArtifact, error)
}

type LocalStepUpSource interface {
	ResolveLocalStepUp(context.Context, AuthorityLookup) (AuthoritySnapshot, error)
}

type LocalStepUpOptions struct {
	Source           LocalStepUpSource
	Admissions       AdmissionGate
	Kernel           LocalStepUpKernel
	Now              func() time.Time
	OperationTimeout time.Duration
}

type LocalStepUp struct {
	source           LocalStepUpSource
	admissions       AdmissionGate
	kernel           LocalStepUpKernel
	now              func() time.Time
	operationTimeout time.Duration
}

func NewLocalStepUp(options LocalStepUpOptions) (*LocalStepUp, error) {
	if options.Source == nil || options.Admissions == nil || options.Kernel == nil ||
		options.OperationTimeout < minimumOperationTimeout || options.OperationTimeout > maximumOperationTimeout ||
		options.OperationTimeout%time.Microsecond != 0 {
		return nil, ErrInvalidInput
	}
	if options.Now == nil {
		options.Now = func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }
	}
	return &LocalStepUp{
		source: options.Source, admissions: options.Admissions, kernel: options.Kernel,
		now: options.Now, operationTimeout: options.OperationTimeout,
	}, nil
}

func (service *LocalStepUp) String() string {
	return fmt.Sprintf("mfaauth.LocalStepUp{configured:%t}", service != nil && service.kernel != nil)
}
func (service *LocalStepUp) GoString() string { return service.String() }

type StartLocalStepUpCommand struct {
	Lookup AuthorityLookup
}

// LocalStepUpStartArtifact keeps the browser-bound kernel capability together
// with the exact live TOTP inventory used to create it. Factor identifiers are
// selectors only, never authority; the completion transaction still resolves
// and validates the selected factor under the challenge's pinned tenant and
// user binding.
type LocalStepUpStartArtifact struct {
	artifact      mfa.StepUpStartArtifact
	totpFactorIDs []identity.EntityID
}

func (artifact LocalStepUpStartArtifact) ChallengeID() mfa.ChallengeID {
	return artifact.artifact.ChallengeID()
}

func (artifact LocalStepUpStartArtifact) BrowserHandle() []byte {
	return artifact.artifact.BrowserHandle()
}

func (artifact LocalStepUpStartArtifact) ExpiresAt() time.Time {
	return artifact.artifact.ExpiresAt()
}

func (artifact LocalStepUpStartArtifact) AllowedFactors() []mfa.FactorKind {
	return artifact.artifact.AllowedFactors()
}

func (artifact LocalStepUpStartArtifact) Binding() mfa.StepUpBinding {
	return artifact.artifact.Binding()
}

func (artifact LocalStepUpStartArtifact) TOTPFactorIDs() []identity.EntityID {
	return append([]identity.EntityID(nil), artifact.totpFactorIDs...)
}

func (artifact LocalStepUpStartArtifact) String() string {
	return "mfaauth.LocalStepUpStartArtifact{artifacts:[REDACTED]}"
}

func (artifact LocalStepUpStartArtifact) GoString() string { return artifact.String() }

func (artifact *LocalStepUpStartArtifact) Destroy() {
	if artifact == nil {
		return
	}
	artifact.artifact.Destroy()
	clear(artifact.totpFactorIDs)
	artifact.totpFactorIDs = nil
}

func (service *LocalStepUp) Start(
	ctx context.Context,
	command StartLocalStepUpCommand,
) (LocalStepUpStartArtifact, error) {
	operationContext, cancel, err := service.operation(ctx)
	if err != nil {
		return LocalStepUpStartArtifact{}, err
	}
	defer cancel()
	now := service.currentTime()
	if err := admit(operationContext, service.admissions, command.Lookup.Admission, now); err != nil {
		return LocalStepUpStartArtifact{}, err
	}
	if !validAuthorityLookup(command.Lookup) {
		return LocalStepUpStartArtifact{}, ErrInvalidInput
	}
	resolution := command.Lookup
	resolution.evaluatedAt = now
	snapshot, err := service.source.ResolveLocalStepUp(operationContext, resolution)
	if err != nil || !snapshot.matches(resolution) || !snapshot.loadedAt.Equal(now) {
		return LocalStepUpStartArtifact{}, ErrDenied
	}
	switch snapshot.decision() {
	case identity.AssuranceStepUpRequired, identity.AssuranceEnrollmentOnly:
	case identity.AssuranceSatisfied, identity.AssuranceEnrollmentEnded, identity.AssuranceDenied:
		return LocalStepUpStartArtifact{}, ErrDenied
	default:
		return LocalStepUpStartArtifact{}, ErrDenied
	}
	factors := make([]mfa.FactorKind, 0, 2)
	if len(snapshot.totpFactorIDs) > 0 {
		factors = append(factors, mfa.FactorTOTP)
	}
	if snapshot.recoveryAvailable {
		factors = append(factors, mfa.FactorRecoveryCode)
	}
	if len(factors) == 0 {
		return LocalStepUpStartArtifact{}, ErrDenied
	}
	artifact, err := service.kernel.Start(operationContext, mfa.StepUpStartRequest{
		Binding: snapshot.binding(), AllowedFactors: factors,
	})
	if err != nil {
		if errors.Is(err, mfa.ErrStepUpPersistence) {
			return LocalStepUpStartArtifact{}, ErrUnavailable
		}
		return LocalStepUpStartArtifact{}, ErrAuthentication
	}
	if artifact.ChallengeID() == (mfa.ChallengeID{}) || !validOpaque(artifact.BrowserHandle()) ||
		!artifact.ExpiresAt().After(now) || artifact.ExpiresAt().After(snapshot.anchorExpiresAt) ||
		!slices.Equal(artifact.AllowedFactors(), factors) ||
		!sameStepUpBinding(artifact.Binding(), snapshot.binding()) {
		return LocalStepUpStartArtifact{}, ErrAuthentication
	}
	return LocalStepUpStartArtifact{
		artifact:      artifact,
		totpFactorIDs: append([]identity.EntityID(nil), snapshot.totpFactorIDs...),
	}, nil
}

func sameStepUpBinding(left, right mfa.StepUpBinding) bool {
	return left.Flow == right.Flow && left.TenantID == right.TenantID && left.UserID == right.UserID &&
		left.IdentityEpoch == right.IdentityEpoch && left.SessionID == right.SessionID &&
		left.SessionFamilyID == right.SessionFamilyID && left.ContinuationID == right.ContinuationID &&
		left.AnchorVersion == right.AnchorVersion && left.AnchorExpiresAt.Equal(right.AnchorExpiresAt) &&
		left.AnchorRecoveryRestricted == right.AnchorRecoveryRestricted &&
		left.Action == right.Action && left.Audience == right.Audience &&
		sameRequirement(left.Requirement, right.Requirement) &&
		sameEvidence(left.BaselineEvidence, right.BaselineEvidence)
}

func sameRequirement(left, right identity.EffectiveAssuranceRequirement) bool {
	if left.Level != right.Level || left.LocalRequired != right.LocalRequired || left.Freshness != right.Freshness ||
		!slices.Equal(left.PolicyRevisions, right.PolicyRevisions) {
		return false
	}
	return sameOptionalTime(left.EnrollmentDeadline, right.EnrollmentDeadline)
}

type CompleteTOTPCommand struct {
	Ticket  CompletionTicket
	Code    []byte `json:"-"`
	Session mfa.SessionReservation
}

func (command CompleteTOTPCommand) String() string {
	return "mfaauth.CompleteTOTPCommand{proof:[REDACTED]}"
}
func (command CompleteTOTPCommand) GoString() string { return command.String() }

func (service *LocalStepUp) CompleteTOTP(
	ctx context.Context,
	command CompleteTOTPCommand,
) (mfa.StepUpArtifact, error) {
	operationContext, cancel, err := service.operation(ctx)
	if err != nil {
		return mfa.StepUpArtifact{}, err
	}
	defer cancel()
	grant, ok := command.Ticket.consumePrepared(command.Session)
	if !ok || grant.resolution.ArtifactKind != CompletionArtifactStepUp ||
		grant.resolution.FactorKind != CompletionFactorTOTP || len(grant.resolution.ArtifactID) != len(mfa.ChallengeID{}) ||
		!validUUIDv7Bytes(grant.resolution.FactorID) {
		return mfa.StepUpArtifact{}, ErrAuthentication
	}
	var challengeID mfa.ChallengeID
	copy(challengeID[:], grant.resolution.ArtifactID)
	var factorID identity.EntityID
	copy(factorID[:], grant.resolution.FactorID)
	code := append([]byte(nil), command.Code...)
	defer clear(code)
	artifact, err := service.kernel.CompleteTOTP(operationContext, mfa.TOTPCompletionRequest{
		ChallengeID: challengeID, BrowserDigest: grant.resolution.BrowserDigest, FactorID: factorID, Code: code,
		ExpectedBinding: stepUpCompletionBinding(grant.resolution),
		Session:         command.Session, ContinuationID: grant.resolution.ContinuationID,
		ContinuationReceiptDigest: grant.resolution.ContinuationReceiptDigest,
	})
	if err != nil {
		return mfa.StepUpArtifact{}, ErrAuthentication
	}
	if !validLocalStepUpArtifact(
		artifact, grant.resolution.LoadedAt.Add(-service.operationTimeout), service.currentTime(), false,
	) || !sameCompletionArtifactAuthority(grant.resolution, artifact) {
		return mfa.StepUpArtifact{}, ErrAuthentication
	}
	return artifact, nil
}

type CompleteRecoveryCommand struct {
	Ticket  CompletionTicket
	Code    []byte `json:"-"`
	Session mfa.SessionReservation
}

func (command CompleteRecoveryCommand) String() string {
	return "mfaauth.CompleteRecoveryCommand{proof:[REDACTED]}"
}
func (command CompleteRecoveryCommand) GoString() string { return command.String() }

func (service *LocalStepUp) CompleteRecovery(
	ctx context.Context,
	command CompleteRecoveryCommand,
) (mfa.StepUpArtifact, error) {
	operationContext, cancel, err := service.operation(ctx)
	if err != nil {
		return mfa.StepUpArtifact{}, err
	}
	defer cancel()
	grant, ok := command.Ticket.consumePrepared(command.Session)
	if !ok || grant.resolution.ArtifactKind != CompletionArtifactStepUp ||
		grant.resolution.FactorKind != CompletionFactorRecovery || len(grant.resolution.ArtifactID) != len(mfa.ChallengeID{}) ||
		!validUUIDv7Bytes(grant.resolution.FactorID) {
		return mfa.StepUpArtifact{}, ErrAuthentication
	}
	var challengeID mfa.ChallengeID
	copy(challengeID[:], grant.resolution.ArtifactID)
	var recoverySetID identity.EntityID
	copy(recoverySetID[:], grant.resolution.FactorID)
	code := append([]byte(nil), command.Code...)
	defer clear(code)
	artifact, err := service.kernel.CompleteRecovery(operationContext, mfa.RecoveryCompletionRequest{
		ChallengeID: challengeID, BrowserDigest: grant.resolution.BrowserDigest, Code: code,
		ExpectedSetID:   recoverySetID,
		ExpectedBinding: stepUpCompletionBinding(grant.resolution),
		Session:         command.Session, ContinuationID: grant.resolution.ContinuationID,
		ContinuationReceiptDigest: grant.resolution.ContinuationReceiptDigest,
	})
	if err != nil {
		return mfa.StepUpArtifact{}, ErrAuthentication
	}
	if !validLocalStepUpArtifact(
		artifact, grant.resolution.LoadedAt.Add(-service.operationTimeout), service.currentTime(), true,
	) || !sameCompletionArtifactAuthority(grant.resolution, artifact) {
		return mfa.StepUpArtifact{}, ErrAuthentication
	}
	return artifact, nil
}

func validLocalStepUpArtifact(artifact mfa.StepUpArtifact, notBefore, now time.Time, recovery bool) bool {
	zero := identity.EntityID{}
	evidence := artifact.NewEvidence
	if artifact.TenantID == zero || artifact.UserID == zero || !validStoredVersion(artifact.IdentityEpoch) ||
		!validPublicText(artifact.Action, 256) || !validPublicText(artifact.Audience, 256) ||
		artifact.NewSessionID == zero || artifact.NewSessionFamilyID == zero ||
		!validStoredVersion(artifact.SessionVersion) ||
		artifact.RecoveryRestricted != recovery || evidence.Level != identity.AssuranceMFA ||
		evidence.Source != (identity.AssuranceSource{Local: true}) || !validInstant(evidence.AuthenticatedAt) ||
		evidence.AuthenticatedAt.Before(notBefore) || evidence.AuthenticatedAt.After(now) ||
		evidence.FactorRevision == nil || !validStoredRevision(*evidence.FactorRevision) ||
		evidence.ExpiresAt != nil || evidence.TrustRuleRevision != nil {
		return false
	}
	expectedKind := identity.AssuranceEvidenceFactor
	if recovery {
		expectedKind = identity.AssuranceEvidenceRecovery
	}
	if evidence.Kind != expectedKind {
		return false
	}
	if artifact.ContinuationID != zero {
		return artifact.SessionID == zero && artifact.SessionFamilyID == zero
	}
	return artifact.SessionID != zero && artifact.SessionFamilyID != zero &&
		artifact.NewSessionID != artifact.SessionID && artifact.NewSessionFamilyID == artifact.SessionFamilyID
}

func sameCompletionArtifactAuthority(resolution CompletionTicketResolutionInput, artifact mfa.StepUpArtifact) bool {
	return artifact.TenantID == resolution.TenantID && artifact.UserID == resolution.UserID &&
		artifact.IdentityEpoch == resolution.IdentityEpoch && artifact.SessionID == resolution.SessionID &&
		artifact.SessionFamilyID == resolution.SessionFamilyID && artifact.ContinuationID == resolution.ContinuationID &&
		artifact.Action == resolution.Action && artifact.Audience == resolution.Audience
}

func stepUpCompletionBinding(resolution CompletionTicketResolutionInput) mfa.StepUpCompletionBinding {
	flow := mfa.StepUpFlow(0)
	if resolution.Flow == CompletionFlowSession {
		flow = mfa.FlowExistingSession
	} else if resolution.Flow == CompletionFlowContinuation {
		flow = mfa.FlowPostPrimaryContinuation
	}
	return mfa.StepUpCompletionBinding{
		Flow: flow, TenantID: resolution.TenantID, UserID: resolution.UserID,
		IdentityEpoch: resolution.IdentityEpoch, SessionID: resolution.SessionID,
		SessionFamilyID: resolution.SessionFamilyID, ContinuationID: resolution.ContinuationID,
		AnchorVersion: resolution.AnchorVersion, AnchorExpiresAt: resolution.AnchorExpiresAt,
		Action: resolution.Action, Audience: resolution.Audience,
	}
}

func (service *LocalStepUp) operation(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if service == nil || service.source == nil || service.admissions == nil || service.kernel == nil {
		return nil, nil, ErrInvalidInput
	}
	return operation(ctx, service.operationTimeout)
}

func (service *LocalStepUp) currentTime() time.Time {
	if service == nil || service.now == nil {
		return time.Time{}
	}
	return service.now().UTC().Truncate(time.Microsecond)
}
