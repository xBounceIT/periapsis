package platformsamlauth

import (
	"context"
	"crypto/sha256"
	"fmt"
	"reflect"
	"slices"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
)

// DirectSAMLSessionAuthorityLookup is the already-resolved, tenantless
// identity presented by the session-cookie boundary. Audit attribution is
// explicit because every revalidation decision is an audited mutation.
type DirectSAMLSessionAuthorityLookup struct {
	SessionID            identity.EntityID
	UserID               identity.EntityID
	AuthenticationMethod string
	Audience             string
	Audit                AuditContext
}

func (lookup DirectSAMLSessionAuthorityLookup) String() string {
	return fmt.Sprintf(
		"platformsamlauth.DirectSAMLSessionAuthorityLookup{session:%t,user:%t,method:%q,audience:%q,audit:%q,authority:direct_platform_saml,material:[REDACTED]}",
		lookup.SessionID != (identity.EntityID{}), lookup.UserID != (identity.EntityID{}),
		lookup.AuthenticationMethod, lookup.Audience, lookup.Audit.String(),
	)
}

func (lookup DirectSAMLSessionAuthorityLookup) GoString() string { return lookup.String() }

func (lookup DirectSAMLSessionRevalidationRecoveryLookup) String() string {
	return fmt.Sprintf(
		"platformsamlauth.DirectSAMLSessionRevalidationRecoveryLookup{command:%q,authority:direct_platform_saml,material:[REDACTED]}",
		lookup.Command.String(),
	)
}

func (lookup DirectSAMLSessionRevalidationRecoveryLookup) GoString() string { return lookup.String() }

func (result DirectSAMLSessionRevalidationRecoveryResult) String() string {
	return fmt.Sprintf(
		"platformsamlauth.DirectSAMLSessionRevalidationRecoveryResult{matched:%t,result:%q,authority:direct_platform_saml,material:[REDACTED]}",
		result.Matched, result.Result.String(),
	)
}

func (result DirectSAMLSessionRevalidationRecoveryResult) GoString() string { return result.String() }

// DirectSAMLSessionAuthorityOutcome either grants current authority or owns a
// committed browser transition. Rotations and step-up continuations never
// grant authority to the credential that triggered revalidation.
type DirectSAMLSessionAuthorityOutcome struct {
	SessionID      identity.EntityID
	UserID         identity.EntityID
	Decision       mfa.SessionDecision
	Reason         mfa.SessionReason
	AllowAuthority bool
	AllowIdleTouch bool
	NewSessionID   identity.EntityID
	ContinuationID identity.EntityID
	ExpiresAt      time.Time
	Credential     *BrowserCredential
	Delivery       *DirectSAMLSessionDeliveryFinalizer
}

func (outcome DirectSAMLSessionAuthorityOutcome) String() string {
	return fmt.Sprintf(
		"platformsamlauth.DirectSAMLSessionAuthorityOutcome{session:%t,user:%t,decision:%q,reason:%q,authority:%t,idleTouch:%t,newSession:%t,continuation:%t,expires:%t,credential:%t,delivery:%t,protocol:saml,material:[REDACTED]}",
		outcome.SessionID != (identity.EntityID{}), outcome.UserID != (identity.EntityID{}),
		outcome.Decision, outcome.Reason, outcome.AllowAuthority, outcome.AllowIdleTouch,
		outcome.NewSessionID != (identity.EntityID{}), outcome.ContinuationID != (identity.EntityID{}),
		!outcome.ExpiresAt.IsZero(), outcome.Credential != nil, outcome.Delivery != nil,
	)
}

func (outcome DirectSAMLSessionAuthorityOutcome) GoString() string { return outcome.String() }

type DirectSAMLSessionAuthorityOptions struct {
	Store            DirectSAMLSessionRevalidationStore
	Credentials      CredentialIssuer
	Now              func() time.Time
	OperationTimeout time.Duration
	RecoveryTimeout  time.Duration
}

// DirectSAMLSessionAuthority is the request-time authority and transition
// boundary for physically separate direct-platform SAML sessions.
type DirectSAMLSessionAuthorityService struct {
	store            DirectSAMLSessionRevalidationStore
	credentials      CredentialIssuer
	now              func() time.Time
	operationTimeout time.Duration
	recoveryTimeout  time.Duration
}

func NewDirectSAMLSessionAuthority(
	options DirectSAMLSessionAuthorityOptions,
) (*DirectSAMLSessionAuthorityService, error) {
	if directSAMLSessionNil(options.Store) || directSAMLSessionNil(options.Credentials) ||
		options.OperationTimeout < minimumOperationTimeout ||
		options.OperationTimeout > maximumOperationTimeout ||
		options.OperationTimeout%time.Microsecond != 0 ||
		options.RecoveryTimeout < minimumRecoveryTimeout ||
		options.RecoveryTimeout > maximumRecoveryTimeout ||
		options.RecoveryTimeout%time.Microsecond != 0 {
		return nil, ErrInvalidOptions
	}
	if options.Now == nil {
		options.Now = func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }
	}
	return &DirectSAMLSessionAuthorityService{
		store: options.Store, credentials: options.Credentials, now: options.Now,
		operationTimeout: options.OperationTimeout, recoveryTimeout: options.RecoveryTimeout,
	}, nil
}

func (authority *DirectSAMLSessionAuthorityService) String() string {
	return fmt.Sprintf(
		"platformsamlauth.DirectSAMLSessionAuthority{configured:%t,authority:direct_platform_saml}",
		authority != nil && !directSAMLSessionNil(authority.store) &&
			!directSAMLSessionNil(authority.credentials) && authority.now != nil,
	)
}

func (authority *DirectSAMLSessionAuthorityService) GoString() string { return authority.String() }

func (authority *DirectSAMLSessionAuthorityService) RevalidateDirectPlatformSession(
	ctx context.Context,
	lookup DirectSAMLSessionAuthorityLookup,
) (DirectSAMLSessionAuthorityOutcome, error) {
	if authority == nil || directSAMLSessionNil(authority.store) ||
		directSAMLSessionNil(authority.credentials) || authority.now == nil ||
		!validDirectSAMLSessionAuthorityLookup(lookup) {
		return DirectSAMLSessionAuthorityOutcome{}, ErrAuthenticationDenied
	}
	operation, cancel, observedAt, ok := authority.operation(ctx)
	if !ok {
		return DirectSAMLSessionAuthorityOutcome{}, ErrAuthenticationUnavailable
	}
	defer cancel()
	persistenceLookup := DirectSAMLSessionRevalidationLookup{
		SessionID: lookup.SessionID, ObservedAt: observedAt,
	}
	snapshot, err := authority.load(operation, persistenceLookup)
	if err != nil || operation.Err() != nil {
		return DirectSAMLSessionAuthorityOutcome{}, ErrAuthenticationUnavailable
	}
	if !validDirectSAMLSessionSnapshot(snapshot, lookup, observedAt) {
		return DirectSAMLSessionAuthorityOutcome{}, ErrAuthenticationDenied
	}
	decision, reason := evaluateDirectSAMLSession(snapshot, observedAt)
	reservation, command, err := authority.command(snapshot, lookup.Audit, observedAt, decision, reason)
	if reservation != nil {
		defer reservation.Destroy()
	}
	if err != nil {
		return DirectSAMLSessionAuthorityOutcome{}, err
	}
	result, certain := authority.applyWithRecovery(operation, ctx, command, snapshot.Session.UserID)
	if certain && (result.Category == DirectSAMLSessionRevalidationStale ||
		result.Category == DirectSAMLSessionRevalidationReplay) {
		return DirectSAMLSessionAuthorityOutcome{}, ErrAuthenticationDenied
	}
	if !certain {
		if decision != mfa.SessionRotate && decision != mfa.SessionStepUp {
			return DirectSAMLSessionAuthorityOutcome{}, ErrAuthenticationUnavailable
		}
		result = syntheticDirectSAMLSessionResult(command, snapshot.Session.UserID)
		return authority.failedTransitionOutcome(command, result), ErrAuthenticationUnavailable
	}
	base := DirectSAMLSessionAuthorityOutcome{
		SessionID: command.SessionID, UserID: result.UserID,
		Decision: command.Decision, Reason: command.Reason,
	}
	switch decision {
	case mfa.SessionUsable:
		base.AllowAuthority = true
		base.AllowIdleTouch = true
		return base, nil
	case mfa.SessionRevoke, mfa.SessionDeny:
		return base, ErrAuthenticationDenied
	case mfa.SessionRotate, mfa.SessionStepUp:
		return authority.transitionOutcome(base, reservation, command, result)
	default:
		return DirectSAMLSessionAuthorityOutcome{}, ErrAuthenticationUnavailable
	}
}

func (authority *DirectSAMLSessionAuthorityService) operation(
	ctx context.Context,
) (context.Context, context.CancelFunc, time.Time, bool) {
	if ctx == nil || ctx.Err() != nil || authority.operationTimeout <= 0 {
		return nil, nil, time.Time{}, false
	}
	now := authority.now().UTC().Truncate(time.Microsecond)
	if !validInstant(now) {
		return nil, nil, time.Time{}, false
	}
	operation, cancel := context.WithTimeout(ctx, authority.operationTimeout)
	return operation, cancel, now, true
}

func (authority *DirectSAMLSessionAuthorityService) load(
	ctx context.Context,
	lookup DirectSAMLSessionRevalidationLookup,
) (DirectSAMLSessionRevalidationSnapshot, error) {
	var lastErr error
	for range 2 {
		returned, err := authority.store.LoadDirectSAMLSessionForRevalidation(ctx, lookup)
		owned := cloneDirectSAMLSessionSnapshot(returned)
		if err == nil {
			return owned, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	return DirectSAMLSessionRevalidationSnapshot{}, lastErr
}

func (authority *DirectSAMLSessionAuthorityService) command(
	snapshot DirectSAMLSessionRevalidationSnapshot,
	audit AuditContext,
	observedAt time.Time,
	decision mfa.SessionDecision,
	reason mfa.SessionReason,
) (*CredentialReservation, DirectSAMLSessionRevalidationCommand, error) {
	var reservation *CredentialReservation
	request := CredentialRequest{IssuedAt: observedAt}
	switch decision {
	case mfa.SessionRotate:
		request.Disposition = ImmediateSession
		request.Rotation = &SessionRotationAnchor{
			SessionID: snapshot.Session.SessionID, FamilyID: snapshot.Session.RotationFamilyID,
			AbsoluteExpiresAt: snapshot.Session.AbsoluteExpiresAt,
		}
	case mfa.SessionStepUp:
		if snapshot.Authority.StepUpTOTP == nil {
			return nil, DirectSAMLSessionRevalidationCommand{}, ErrAuthenticationDenied
		}
		request.Disposition = TOTPContinuation
		selection := *snapshot.Authority.StepUpTOTP
		request.TOTP = &selection
	case mfa.SessionUsable, mfa.SessionRevoke, mfa.SessionDeny:
	default:
		return nil, DirectSAMLSessionRevalidationCommand{}, ErrAuthenticationDenied
	}
	if decision == mfa.SessionRotate || decision == mfa.SessionStepUp {
		var err error
		reservation, err = authority.credentials.ReserveDirectSAMLCredential(request)
		if err != nil || reservation == nil || !reservation.validFor(request) ||
			!validDirectSAMLSessionTransitionReservation(snapshot, decision, reservation, observedAt) {
			if reservation != nil {
				reservation.Destroy()
			}
			return nil, DirectSAMLSessionRevalidationCommand{}, ErrAuthenticationUnavailable
		}
	}
	command := DirectSAMLSessionRevalidationCommand{
		SessionID: snapshot.Session.SessionID, ExpectedVersion: snapshot.Session.CurrentVersion,
		Decision: decision, Reason: reason, ObservedAt: observedAt, Audit: audit,
	}
	if reservation != nil {
		command.Session = reservation.Session()
		command.Continuation = reservation.Continuation()
	}
	command.RequestDigest = directSAMLSessionCommandDigest(command)
	if !validDirectSAMLSessionCommand(command) {
		if reservation != nil {
			reservation.Destroy()
		}
		return nil, DirectSAMLSessionRevalidationCommand{}, ErrAuthenticationDenied
	}
	return reservation, command, nil
}

func (authority *DirectSAMLSessionAuthorityService) applyWithRecovery(
	operation context.Context,
	original context.Context,
	command DirectSAMLSessionRevalidationCommand,
	expectedUserID identity.EntityID,
) (DirectSAMLSessionRevalidationResult, bool) {
	for range 2 {
		result, err := authority.store.ApplyDirectSAMLSessionRevalidation(operation, command)
		if err == nil && (validDirectSAMLSessionResult(result, command, expectedUserID) ||
			validDirectSAMLSessionFailureResult(result, command, expectedUserID)) {
			return result, true
		}
		if operation.Err() != nil {
			break
		}
	}
	for range 2 {
		recovery, cancel := context.WithTimeout(detachedContext(original), authority.recoveryTimeout)
		recovered, err := authority.store.RecoverDirectSAMLSessionRevalidationApply(
			recovery, DirectSAMLSessionRevalidationRecoveryLookup{Command: command},
		)
		cancel()
		if err == nil {
			if recovered.Matched && validDirectSAMLSessionResult(recovered.Result, command, expectedUserID) {
				return recovered.Result, true
			}
			return DirectSAMLSessionRevalidationResult{}, false
		}
	}
	return DirectSAMLSessionRevalidationResult{}, false
}

func (authority *DirectSAMLSessionAuthorityService) transitionOutcome(
	base DirectSAMLSessionAuthorityOutcome,
	reservation *CredentialReservation,
	command DirectSAMLSessionRevalidationCommand,
	result DirectSAMLSessionRevalidationResult,
) (DirectSAMLSessionAuthorityOutcome, error) {
	finalizer := newDirectSAMLSessionDeliveryFinalizer(
		authority.store, authority.now, authority.recoveryTimeout, command, result,
	)
	base.NewSessionID = result.NewSessionID
	base.ContinuationID = result.ContinuationID
	base.ExpiresAt = directSAMLSessionTransitionExpiry(command)
	base.Delivery = finalizer
	if reservation == nil {
		return base, ErrAuthenticationUnavailable
	}
	credential, released := reservation.release(result.NewSessionID, result.ContinuationID)
	if !released || credential == nil {
		if credential != nil {
			credential.Destroy()
		}
		return base, ErrAuthenticationUnavailable
	}
	base.Credential = credential
	return base, nil
}

func (authority *DirectSAMLSessionAuthorityService) failedTransitionOutcome(
	command DirectSAMLSessionRevalidationCommand,
	result DirectSAMLSessionRevalidationResult,
) DirectSAMLSessionAuthorityOutcome {
	return DirectSAMLSessionAuthorityOutcome{
		SessionID: command.SessionID, UserID: result.UserID,
		Decision: command.Decision, Reason: command.Reason,
		NewSessionID: result.NewSessionID, ContinuationID: result.ContinuationID,
		ExpiresAt: directSAMLSessionTransitionExpiry(command),
		Delivery: newDirectSAMLSessionDeliveryFinalizer(
			authority.store, authority.now, authority.recoveryTimeout, command, result,
		),
	}
}

func validDirectSAMLSessionAuthorityLookup(lookup DirectSAMLSessionAuthorityLookup) bool {
	return validUUIDv7(lookup.SessionID) && validUUIDv7(lookup.UserID) &&
		lookup.SessionID != lookup.UserID &&
		lookup.AuthenticationMethod == DirectSAMLSessionMethod &&
		lookup.Audience == DirectSAMLSessionAudience && validAuditContext(lookup.Audit)
}

func validDirectSAMLSessionSnapshot(
	snapshot DirectSAMLSessionRevalidationSnapshot,
	lookup DirectSAMLSessionAuthorityLookup,
	observedAt time.Time,
) bool {
	session := snapshot.Session
	authority := snapshot.Authority
	if session.SessionID != lookup.SessionID || session.UserID != lookup.UserID ||
		!validUUIDv7(session.SessionID) || !validUUIDv7(session.RotationFamilyID) ||
		!validUUIDv7(session.UserID) || session.SessionID == session.RotationFamilyID ||
		session.SessionID == session.UserID || session.RotationFamilyID == session.UserID ||
		session.ActiveTenantID != nil || session.Authority != DirectSAMLSessionAuthority ||
		session.AuthenticationMethod != lookup.AuthenticationMethod || session.Audience != lookup.Audience ||
		session.PrimaryKind != DirectSAMLSessionPrimaryKind || session.SAMLStateCount != 1 ||
		session.SAMLProvenanceCount != 1 || session.OIDCStateCount != 0 ||
		session.TenantProvenanceCount != 0 || session.ProviderEvidenceCount != 1 ||
		session.TOTPEvidenceCount < 0 || session.TOTPEvidenceCount > 1 ||
		session.CurrentVersion < 1 || session.CurrentVersion > DirectSAMLSessionMaximumVersion ||
		!validRevision(session.UserAuthenticationRevision) || !validInstant(session.IssuedAt) ||
		!validInstant(session.IdleExpiresAt) || !validInstant(session.AbsoluteExpiresAt) ||
		session.IssuedAt.After(observedAt) || !session.IdleExpiresAt.After(session.IssuedAt) ||
		!session.AbsoluteExpiresAt.After(session.IssuedAt) || session.IdleExpiresAt.After(session.AbsoluteExpiresAt) {
		return false
	}
	if !validUUIDv7(authority.ProviderID) || !validUUIDv7(authority.ExternalIdentityID) ||
		authority.ProviderID == authority.ExternalIdentityID ||
		authority.ProviderKind != DirectSAMLSessionProviderKind ||
		!validDirectSAMLSessionAccountMode(authority.AccountMode) ||
		!validUUIDv7(authority.IdentityCurrentProviderID) ||
		!validUUIDv7(authority.IdentityCurrentUserID) ||
		!validUUIDv7(authority.AliasCurrentProviderID) ||
		!validUUIDv7(authority.AliasCurrentIdentityID) ||
		!validDirectSAMLSessionAuthorityRevisions(authority) ||
		session.UserAuthenticationRevision != authority.PinnedUserAuthenticationRevision ||
		!validDirectSAMLSessionRequirement(authority.PlatformFloor, authority.CurrentPlatformFloorID,
			authority.CurrentPlatformFloorRevision) ||
		!validDirectSAMLSessionTOTPSelection(authority.StepUpTOTP) ||
		authority.StepUpTOTP != nil && directSAMLSessionCoreID(
			authority.StepUpTOTP.FactorID, session, authority,
		) {
		return false
	}
	return validDirectSAMLSessionEvidence(snapshot, observedAt) &&
		validDirectSAMLSessionPolicyPins(snapshot.PolicyPins, authority)
}

func validDirectSAMLSessionAuthorityRevisions(value DirectSAMLSessionAuthorityFacts) bool {
	revisions := [...]uint64{
		value.PinnedProviderRevision, value.CurrentProviderRevision,
		value.PinnedLoginPolicyRevision, value.CurrentLoginPolicyRevision,
		value.PinnedConfigurationRevision, value.CurrentConfigurationRevision,
		value.PinnedSecurityRevision, value.CurrentSecurityRevision,
		value.PinnedPlanRevision, value.CurrentPlanRevision,
		value.PinnedAssurancePolicyRevision, value.CurrentAssurancePolicyRevision,
		value.PinnedMetadataRevision, value.CurrentMetadataRevision,
		value.PinnedSPKeyRevision, value.CurrentSPKeyRevision,
		value.PinnedUserAuthenticationRevision, value.CurrentUserAuthenticationRevision,
		value.PinnedIdentityRevision, value.CurrentIdentityRevision,
		value.PinnedPlatformAuthorityRevision, value.CurrentPlatformAuthorityRevision,
		value.PinnedPlatformFloorRevision, value.CurrentPlatformFloorRevision,
	}
	for _, revision := range revisions {
		if !validRevision(revision) {
			return false
		}
	}
	if value.PinnedProviderRevision > DirectSAMLSessionMaximumVersion ||
		value.CurrentProviderRevision > DirectSAMLSessionMaximumVersion ||
		value.PinnedIdentityRevision > DirectSAMLSessionMaximumVersion ||
		value.CurrentIdentityRevision > DirectSAMLSessionMaximumVersion ||
		value.PinnedAliasKeyVersion < 1 || value.CurrentAliasKeyVersion < 1 ||
		value.PinnedAliasKeyVersion > 32_767 || value.CurrentAliasKeyVersion > 32_767 ||
		value.PinnedMetadataDigest == ([sha256.Size]byte{}) ||
		value.CurrentMetadataDigest == ([sha256.Size]byte{}) ||
		value.PinnedConfigurationDigest == ([sha256.Size]byte{}) ||
		value.CurrentConfigurationDigest == ([sha256.Size]byte{}) ||
		!validUUIDv7(value.PinnedPlatformAuthorityID) ||
		!validUUIDv7(value.CurrentPlatformAuthorityID) ||
		!validUUIDv7(value.PinnedPlatformFloorID) || !validUUIDv7(value.CurrentPlatformFloorID) {
		return false
	}
	return true
}

func validDirectSAMLSessionRequirement(
	requirement identity.EffectiveAssuranceRequirement,
	currentFloorID identity.EntityID,
	currentFloorRevision uint64,
) bool {
	if len(requirement.PolicyRevisions) != 1 ||
		requirement.PolicyRevisions[0].PolicyID != currentFloorID ||
		requirement.PolicyRevisions[0].Revision != int64(currentFloorRevision) {
		return false
	}
	decision := identity.EvaluateAssurance(time.Unix(1, 0).UTC(), requirement, nil, false)
	return decision == identity.AssuranceStepUpRequired || decision == identity.AssuranceEnrollmentOnly ||
		decision == identity.AssuranceEnrollmentEnded
}

func validDirectSAMLSessionTOTPSelection(selection *TOTPSelection) bool {
	return selection == nil || validUUIDv7(selection.FactorID) && validRevision(selection.Revision)
}

func validDirectSAMLSessionEvidence(
	snapshot DirectSAMLSessionRevalidationSnapshot,
	observedAt time.Time,
) bool {
	if len(snapshot.Evidence) < 1 || len(snapshot.Evidence) > DirectSAMLSessionMaximumEvidence ||
		len(snapshot.FactorAuthorities) > 1 || len(snapshot.TrustAuthorities) > 1 {
		return false
	}
	providerCount, factorCount := 0, 0
	seen := make(map[identity.EntityID]struct{}, len(snapshot.Evidence))
	for index, evidence := range snapshot.Evidence {
		if !validUUIDv7(evidence.ID) || !validUUIDv7(evidence.UserID) ||
			evidence.UserID != snapshot.Session.UserID || !validDirectSAMLSessionEvidenceLevel(evidence.Level) ||
			!validInstant(evidence.AuthenticatedAt) || !validOptionalDirectSAMLSessionInstant(evidence.ExpiresAt) ||
			evidence.AuthenticatedAt.After(snapshot.Session.IssuedAt) ||
			evidence.ExpiresAt != nil && !evidence.ExpiresAt.After(evidence.AuthenticatedAt) ||
			snapshot.Authority.EvidenceFresh && evidence.ExpiresAt != nil && !evidence.ExpiresAt.After(observedAt) ||
			index > 0 && !directSAMLSessionEvidenceLess(snapshot.Evidence[index-1], evidence) {
			return false
		}
		if _, duplicate := seen[evidence.ID]; duplicate {
			return false
		}
		if directSAMLSessionCoreID(evidence.ID, snapshot.Session, snapshot.Authority) {
			return false
		}
		seen[evidence.ID] = struct{}{}
		switch evidence.Kind {
		case DirectSAMLSessionEvidenceProvider:
			providerCount++
			if evidence.PlatformProviderID == nil || evidence.ExternalIdentityID == nil ||
				*evidence.PlatformProviderID != snapshot.Authority.ProviderID ||
				*evidence.ExternalIdentityID != snapshot.Authority.ExternalIdentityID ||
				evidence.TOTPCredentialID != nil || evidence.FactorRevision != nil || evidence.ExpiresAt == nil {
				return false
			}
			trusted := evidence.Level != identity.AssurancePrimary
			if trusted != (evidence.TrustRuleID != nil) || trusted != (evidence.TrustRuleRevision != nil) ||
				trusted && (!validUUIDv7(*evidence.TrustRuleID) || !validRevision(*evidence.TrustRuleRevision)) {
				return false
			}
		case DirectSAMLSessionEvidenceTOTP:
			factorCount++
			if evidence.Level != identity.AssuranceMFA || evidence.PlatformProviderID != nil ||
				evidence.ExternalIdentityID != nil || evidence.TOTPCredentialID == nil ||
				evidence.FactorRevision == nil || !validUUIDv7(*evidence.TOTPCredentialID) ||
				!validRevision(*evidence.FactorRevision) || evidence.TrustRuleID != nil ||
				evidence.TrustRuleRevision != nil {
				return false
			}
			if directSAMLSessionCoreID(*evidence.TOTPCredentialID, snapshot.Session, snapshot.Authority) {
				return false
			}
		default:
			return false
		}
	}
	if providerCount != 1 || factorCount > 1 ||
		providerCount != snapshot.Session.ProviderEvidenceCount ||
		factorCount != snapshot.Session.TOTPEvidenceCount ||
		factorCount != len(snapshot.FactorAuthorities) {
		return false
	}
	provider := directSAMLSessionProviderEvidence(snapshot.Evidence)
	if provider == nil {
		return false
	}
	wantTrust := 0
	if provider.Level != identity.AssurancePrimary {
		wantTrust = 1
	}
	return len(snapshot.TrustAuthorities) == wantTrust &&
		validDirectSAMLSessionFactorAuthorities(snapshot.FactorAuthorities, snapshot.Evidence, observedAt) &&
		validDirectSAMLSessionTrustAuthorities(snapshot.TrustAuthorities, *provider)
}

func validDirectSAMLSessionFactorAuthorities(
	authorities []DirectSAMLSessionFactorAuthority,
	evidence []DirectSAMLSessionEvidence,
	observedAt time.Time,
) bool {
	for _, authority := range authorities {
		if !validUUIDv7(authority.EvidenceID) || !validUUIDv7(authority.EvidenceUserID) ||
			!validUUIDv7(authority.TOTPCredentialID) || !validRevision(authority.PinnedSecurityRevision) ||
			!validUUIDv7(authority.CurrentUserID) || !validRevision(authority.CurrentSecurityRevision) ||
			authority.ConfirmedAt == nil || !validInstant(*authority.ConfirmedAt) ||
			authority.ConfirmedAt.After(observedAt) || !validOptionalDirectSAMLSessionInstant(authority.DisabledAt) ||
			authority.DisabledAt != nil && authority.DisabledAt.Before(*authority.ConfirmedAt) {
			return false
		}
		matches := 0
		for _, proof := range evidence {
			if proof.Kind == DirectSAMLSessionEvidenceTOTP && proof.ID == authority.EvidenceID &&
				proof.UserID == authority.EvidenceUserID && proof.TOTPCredentialID != nil &&
				*proof.TOTPCredentialID == authority.TOTPCredentialID && proof.FactorRevision != nil &&
				*proof.FactorRevision == authority.PinnedSecurityRevision {
				matches++
			}
		}
		if matches != 1 {
			return false
		}
	}
	return true
}

func validDirectSAMLSessionTrustAuthorities(
	authorities []DirectSAMLSessionTrustAuthority,
	evidence DirectSAMLSessionEvidence,
) bool {
	for _, authority := range authorities {
		if !validUUIDv7(authority.EvidenceID) || !validUUIDv7(authority.TrustRuleID) ||
			!validRevision(authority.PinnedRevision) || !validUUIDv7(authority.CurrentProviderID) ||
			authority.CurrentProviderKind != DirectSAMLSessionProviderKind ||
			!validRevision(authority.CurrentRevision) ||
			!validDirectSAMLSessionEvidenceLevel(authority.CurrentLevel) ||
			!validOptionalDirectSAMLSessionInstant(authority.RetiredAt) ||
			evidence.TrustRuleID == nil || evidence.TrustRuleRevision == nil ||
			authority.EvidenceID != evidence.ID || authority.TrustRuleID != *evidence.TrustRuleID ||
			authority.PinnedRevision != *evidence.TrustRuleRevision {
			return false
		}
	}
	return true
}

func validDirectSAMLSessionPolicyPins(
	pins []DirectSAMLSessionPolicyPin,
	authority DirectSAMLSessionAuthorityFacts,
) bool {
	if len(pins) != DirectSAMLSessionMaximumPolicies {
		return false
	}
	wanted := map[DirectSAMLSessionPolicyKind]DirectSAMLSessionPolicyPin{
		DirectSAMLSessionPolicyLogin: {
			Kind: DirectSAMLSessionPolicyLogin, ID: authority.ProviderID,
			Revision: authority.PinnedLoginPolicyRevision,
		},
		DirectSAMLSessionPolicyAssurance: {
			Kind: DirectSAMLSessionPolicyAssurance, ID: authority.ProviderID,
			Revision: authority.PinnedAssurancePolicyRevision,
		},
		DirectSAMLSessionPolicyPlatformFloor: {
			Kind: DirectSAMLSessionPolicyPlatformFloor, ID: authority.PinnedPlatformFloorID,
			Revision: authority.PinnedPlatformFloorRevision,
		},
	}
	for index, pin := range pins {
		if !validUUIDv7(pin.ID) || !validRevision(pin.Revision) ||
			index > 0 && !directSAMLSessionPolicyPinLess(pins[index-1], pin) {
			return false
		}
		expected, exists := wanted[pin.Kind]
		if !exists || pin != expected {
			return false
		}
		delete(wanted, pin.Kind)
	}
	return len(wanted) == 0
}

func evaluateDirectSAMLSession(
	snapshot DirectSAMLSessionRevalidationSnapshot,
	observedAt time.Time,
) (mfa.SessionDecision, mfa.SessionReason) {
	session := snapshot.Session
	authority := snapshot.Authority
	if !observedAt.Before(session.IdleExpiresAt) || !observedAt.Before(session.AbsoluteExpiresAt) {
		return mfa.SessionRevoke, mfa.SessionReasonExpired
	}
	if !directSAMLSessionProviderEvidenceCurrent(snapshot, observedAt) {
		return mfa.SessionRevoke, mfa.SessionReasonExpired
	}
	if !session.Active || !session.RotationFamilyLive || !authority.ProviderEnabled ||
		!authority.PlatformLoginLive || !authority.UserActive || !authority.IdentityLive ||
		!authority.SubjectAliasLive || !authority.ConfigurationLive || !authority.MetadataLive ||
		!authority.SPKeyLive || !authority.PlatformAuthorityLive || !authority.PlatformFloorLive ||
		authority.AccountMode != DirectSAMLSessionAccountExisting {
		return mfa.SessionRevoke, mfa.SessionReasonLifecycle
	}
	if authority.PinnedUserAuthenticationRevision != authority.CurrentUserAuthenticationRevision ||
		authority.PinnedPlatformAuthorityID != authority.CurrentPlatformAuthorityID ||
		authority.PinnedPlatformAuthorityRevision != authority.CurrentPlatformAuthorityRevision {
		return mfa.SessionRevoke, mfa.SessionReasonIdentityEpoch
	}
	if authority.IdentityCurrentProviderID != authority.ProviderID ||
		authority.IdentityCurrentUserID != session.UserID ||
		authority.AliasCurrentProviderID != authority.ProviderID ||
		authority.AliasCurrentIdentityID != authority.ExternalIdentityID ||
		!directSAMLSessionPrimaryPinsCurrent(authority) {
		return mfa.SessionRevoke, mfa.SessionReasonPrimaryDrift
	}
	if !authority.FactorEvidenceLive || !directSAMLSessionFactorsCurrent(snapshot) {
		return mfa.SessionRevoke, mfa.SessionReasonFactorDrift
	}
	if !authority.TrustEvidenceLive || !directSAMLSessionTrustCurrent(snapshot) {
		return mfa.SessionRevoke, mfa.SessionReasonTrustDrift
	}
	if session.CurrentVersion == DirectSAMLSessionMaximumVersion {
		return mfa.SessionDeny, mfa.SessionReasonMalformed
	}
	satisfied := authority.EvidenceFresh && directSAMLSessionEvidenceSatisfiesFloor(snapshot, observedAt)
	if session.RecoveryRestricted {
		if directSAMLSessionCanStepUp(authority) {
			return mfa.SessionStepUp, mfa.SessionReasonRecoveryRestricted
		}
		return mfa.SessionDeny, mfa.SessionReasonRecoveryRestricted
	}
	if !satisfied {
		if directSAMLSessionCanStepUp(authority) {
			return mfa.SessionStepUp, mfa.SessionReasonAssuranceInsufficient
		}
		return mfa.SessionDeny, mfa.SessionReasonAssuranceInsufficient
	}
	if !directSAMLSessionPoliciesCurrent(authority) {
		return mfa.SessionRotate, mfa.SessionReasonPolicyRefresh
	}
	return mfa.SessionUsable, mfa.SessionReasonCurrent
}

func directSAMLSessionPrimaryPinsCurrent(value DirectSAMLSessionAuthorityFacts) bool {
	return value.PinnedProviderRevision == value.CurrentProviderRevision &&
		value.PinnedLoginPolicyRevision == value.CurrentLoginPolicyRevision &&
		value.PinnedConfigurationRevision == value.CurrentConfigurationRevision &&
		value.PinnedSecurityRevision == value.CurrentSecurityRevision &&
		value.PinnedPlanRevision == value.CurrentPlanRevision &&
		value.PinnedMetadataRevision == value.CurrentMetadataRevision &&
		value.PinnedSPKeyRevision == value.CurrentSPKeyRevision &&
		value.PinnedIdentityRevision == value.CurrentIdentityRevision &&
		value.PinnedAliasKeyVersion == value.CurrentAliasKeyVersion &&
		value.PinnedMetadataDigest == value.CurrentMetadataDigest &&
		value.PinnedConfigurationDigest == value.CurrentConfigurationDigest
}

func directSAMLSessionPoliciesCurrent(value DirectSAMLSessionAuthorityFacts) bool {
	return value.PolicyPinsExact &&
		value.PinnedAssurancePolicyRevision == value.CurrentAssurancePolicyRevision &&
		value.PinnedPlatformFloorID == value.CurrentPlatformFloorID &&
		value.PinnedPlatformFloorRevision == value.CurrentPlatformFloorRevision
}

func directSAMLSessionFactorsCurrent(snapshot DirectSAMLSessionRevalidationSnapshot) bool {
	for _, authority := range snapshot.FactorAuthorities {
		if authority.EvidenceUserID != snapshot.Session.UserID ||
			authority.CurrentUserID != snapshot.Session.UserID ||
			authority.PinnedSecurityRevision != authority.CurrentSecurityRevision ||
			authority.DisabledAt != nil {
			return false
		}
		matched := false
		for _, evidence := range snapshot.Evidence {
			if evidence.ID == authority.EvidenceID && evidence.Kind == DirectSAMLSessionEvidenceTOTP {
				matched = authority.ConfirmedAt != nil && !authority.ConfirmedAt.After(evidence.AuthenticatedAt)
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func directSAMLSessionTrustCurrent(snapshot DirectSAMLSessionRevalidationSnapshot) bool {
	provider := directSAMLSessionProviderEvidence(snapshot.Evidence)
	if provider == nil {
		return false
	}
	if provider.Level == identity.AssurancePrimary {
		return len(snapshot.TrustAuthorities) == 0
	}
	if len(snapshot.TrustAuthorities) != 1 {
		return false
	}
	current := snapshot.TrustAuthorities[0]
	return provider.TrustRuleID != nil && provider.TrustRuleRevision != nil &&
		current.TrustRuleID == *provider.TrustRuleID &&
		current.PinnedRevision == *provider.TrustRuleRevision &&
		current.CurrentProviderID == snapshot.Authority.ProviderID &&
		current.CurrentProviderKind == DirectSAMLSessionProviderKind &&
		current.PinnedRevision == current.CurrentRevision &&
		current.CurrentLevel == provider.Level && current.Enabled && current.RetiredAt == nil
}

func directSAMLSessionEvidenceSatisfiesFloor(
	snapshot DirectSAMLSessionRevalidationSnapshot,
	observedAt time.Time,
) bool {
	requirement := snapshot.Authority.PlatformFloor
	for _, evidence := range snapshot.Evidence {
		if evidence.AuthenticatedAt.After(observedAt) ||
			evidence.ExpiresAt != nil && !evidence.ExpiresAt.After(observedAt) ||
			requirement.Freshness > 0 && observedAt.Sub(evidence.AuthenticatedAt) > requirement.Freshness ||
			requirement.LocalRequired && evidence.Kind != DirectSAMLSessionEvidenceTOTP {
			continue
		}
		if evidence.Level >= requirement.Level {
			return true
		}
	}
	return false
}

func directSAMLSessionProviderEvidenceCurrent(
	snapshot DirectSAMLSessionRevalidationSnapshot,
	observedAt time.Time,
) bool {
	provider := directSAMLSessionProviderEvidence(snapshot.Evidence)
	return provider != nil && provider.ExpiresAt != nil && provider.ExpiresAt.After(observedAt)
}

func directSAMLSessionCanStepUp(value DirectSAMLSessionAuthorityFacts) bool {
	return value.StepUpTOTP != nil && validDirectSAMLSessionTOTPSelection(value.StepUpTOTP) &&
		value.PlatformFloor.Level <= identity.AssuranceMFA
}

func validDirectSAMLSessionTransitionReservation(
	snapshot DirectSAMLSessionRevalidationSnapshot,
	decision mfa.SessionDecision,
	reservation *CredentialReservation,
	issuedAt time.Time,
) bool {
	if reservation == nil {
		return false
	}
	switch decision {
	case mfa.SessionRotate:
		session := reservation.Session()
		return !session.IsZero() && reservation.Continuation().IsZero() &&
			session.AuthenticationMethod() == mfa.SessionAuthenticationSAML &&
			session.ValidAt(issuedAt.Truncate(time.Millisecond)) &&
			session.SessionID() != snapshot.Session.SessionID &&
			session.SessionID() != snapshot.Session.UserID &&
			session.SessionID() != snapshot.Authority.ProviderID &&
			session.SessionID() != snapshot.Authority.ExternalIdentityID &&
			session.FamilyID() == snapshot.Session.RotationFamilyID &&
			session.AbsoluteExpiresAt().Equal(snapshot.Session.AbsoluteExpiresAt)
	case mfa.SessionStepUp:
		continuation := reservation.Continuation()
		return reservation.Session().IsZero() && !continuation.IsZero() &&
			continuation.ValidAt(issuedAt) && snapshot.Authority.StepUpTOTP != nil &&
			continuation.FactorID() == snapshot.Authority.StepUpTOTP.FactorID &&
			continuation.FactorRevision() == snapshot.Authority.StepUpTOTP.Revision &&
			continuation.ContinuationID() != snapshot.Session.SessionID &&
			continuation.ContinuationID() != snapshot.Session.UserID &&
			!continuation.ExpiresAt().After(snapshot.Session.AbsoluteExpiresAt)
	default:
		return false
	}
}

func validDirectSAMLSessionCommand(command DirectSAMLSessionRevalidationCommand) bool {
	if !validUUIDv7(command.SessionID) || command.ExpectedVersion < 1 ||
		command.ExpectedVersion > DirectSAMLSessionMaximumVersion || !validInstant(command.ObservedAt) ||
		!validAuditContext(command.Audit) ||
		command.RequestDigest == (DirectSAMLSessionRevalidationRequestDigest{}) ||
		command.RequestDigest != directSAMLSessionCommandDigest(command) {
		return false
	}
	if command.ExpectedVersion == DirectSAMLSessionMaximumVersion &&
		(command.Decision == mfa.SessionUsable || command.Decision == mfa.SessionStepUp) {
		return false
	}
	switch command.Decision {
	case mfa.SessionUsable:
		return command.Reason == mfa.SessionReasonCurrent && command.Session.IsZero() &&
			command.Continuation.IsZero()
	case mfa.SessionRotate:
		return command.Reason == mfa.SessionReasonPolicyRefresh &&
			validDirectSAMLSessionCommandSession(command.Session, command.ObservedAt) &&
			command.Session.SessionID() != command.SessionID &&
			command.Session.FamilyID() != command.SessionID && command.Continuation.IsZero()
	case mfa.SessionStepUp:
		return (command.Reason == mfa.SessionReasonAssuranceInsufficient ||
			command.Reason == mfa.SessionReasonRecoveryRestricted) && command.Session.IsZero() &&
			command.Continuation.ValidAt(command.ObservedAt) &&
			command.Continuation.ContinuationID() != command.SessionID &&
			command.Continuation.FactorID() != command.SessionID
	case mfa.SessionRevoke:
		return directSAMLSessionRevocationReason(command.Reason) && command.Session.IsZero() &&
			command.Continuation.IsZero()
	case mfa.SessionDeny:
		return (command.Reason == mfa.SessionReasonMalformed ||
			command.Reason == mfa.SessionReasonAssuranceInsufficient ||
			command.Reason == mfa.SessionReasonRecoveryRestricted) && command.Session.IsZero() &&
			command.Continuation.IsZero()
	default:
		return false
	}
}

func validDirectSAMLSessionCommandSession(session mfa.SessionReservation, issuedAt time.Time) bool {
	return !session.IsZero() && session.AuthenticationMethod() == mfa.SessionAuthenticationSAML &&
		session.ValidAt(issuedAt.Truncate(time.Millisecond))
}

func directSAMLSessionRevocationReason(reason mfa.SessionReason) bool {
	switch reason {
	case mfa.SessionReasonExpired, mfa.SessionReasonLifecycle, mfa.SessionReasonIdentityEpoch,
		mfa.SessionReasonPrimaryDrift, mfa.SessionReasonFactorDrift, mfa.SessionReasonTrustDrift:
		return true
	default:
		return false
	}
}

func validDirectSAMLSessionResult(
	result DirectSAMLSessionRevalidationResult,
	command DirectSAMLSessionRevalidationCommand,
	expectedUserID identity.EntityID,
) bool {
	if !result.Applied ||
		(result.Category != DirectSAMLSessionRevalidationSuccess &&
			result.Category != DirectSAMLSessionRevalidationAlreadyApplied) ||
		result.Decision != command.Decision || result.SessionID != command.SessionID ||
		result.UserID != expectedUserID || !validUUIDv7(result.UserID) || result.UserID == result.SessionID ||
		result.ExpectedVersion != command.ExpectedVersion ||
		!result.AppliedAt.Equal(command.ObservedAt) {
		return false
	}
	switch command.Decision {
	case mfa.SessionUsable:
		return result.NewVersion == command.ExpectedVersion+1 &&
			result.NewSessionID == (identity.EntityID{}) && result.ContinuationID == (identity.EntityID{})
	case mfa.SessionRotate:
		return result.NewVersion == 0 && result.NewSessionID == command.Session.SessionID() &&
			validUUIDv7(result.NewSessionID) && result.ContinuationID == (identity.EntityID{})
	case mfa.SessionStepUp:
		return result.NewVersion == command.ExpectedVersion+1 &&
			result.NewSessionID == (identity.EntityID{}) &&
			result.ContinuationID == command.Continuation.ContinuationID() && validUUIDv7(result.ContinuationID)
	case mfa.SessionRevoke, mfa.SessionDeny:
		return result.NewVersion == 0 && result.NewSessionID == (identity.EntityID{}) &&
			result.ContinuationID == (identity.EntityID{})
	default:
		return false
	}
}

func validDirectSAMLSessionFailureResult(
	result DirectSAMLSessionRevalidationResult,
	command DirectSAMLSessionRevalidationCommand,
	expectedUserID identity.EntityID,
) bool {
	return !result.Applied &&
		(result.Category == DirectSAMLSessionRevalidationStale ||
			result.Category == DirectSAMLSessionRevalidationReplay) &&
		result.Decision == command.Decision && result.SessionID == command.SessionID &&
		result.UserID == expectedUserID && validUUIDv7(result.UserID) && result.UserID != result.SessionID &&
		result.ExpectedVersion == command.ExpectedVersion &&
		result.NewVersion == 0 && result.NewSessionID == (identity.EntityID{}) &&
		result.ContinuationID == (identity.EntityID{}) && result.AppliedAt.IsZero()
}

func syntheticDirectSAMLSessionResult(
	command DirectSAMLSessionRevalidationCommand,
	userID identity.EntityID,
) DirectSAMLSessionRevalidationResult {
	result := DirectSAMLSessionRevalidationResult{
		Applied: true, Category: DirectSAMLSessionRevalidationSuccess,
		Decision: command.Decision, SessionID: command.SessionID, UserID: userID,
		ExpectedVersion: command.ExpectedVersion, AppliedAt: command.ObservedAt,
	}
	if command.Decision == mfa.SessionRotate {
		result.NewSessionID = command.Session.SessionID()
	}
	if command.Decision == mfa.SessionStepUp {
		result.NewVersion = command.ExpectedVersion + 1
		result.ContinuationID = command.Continuation.ContinuationID()
	}
	return result
}

func directSAMLSessionCommandDigest(
	command DirectSAMLSessionRevalidationCommand,
) DirectSAMLSessionRevalidationRequestDigest {
	digest := sha256.New()
	writeDigestField(digest, []byte(DirectSAMLSessionRequestDigestV1))
	writeDigestField(digest, []byte(DirectSAMLSessionAuthority))
	writeDigestField(digest, []byte(DirectSAMLSessionMethod))
	writeDigestField(digest, []byte(DirectSAMLSessionAudience))
	writeDigestField(digest, command.SessionID[:])
	writeDigestUint64(digest, command.ExpectedVersion)
	writeDigestField(digest, []byte(command.Decision))
	writeDigestField(digest, []byte(command.Reason))
	writeDigestTime(digest, command.ObservedAt)
	writeSessionDigest(digest, command.Session)
	writeContinuationDigest(digest, command.Continuation)
	writeDigestField(digest, command.Audit.RequestID[:])
	writeDigestField(digest, command.Audit.CorrelationID[:])
	writeDigestField(digest, command.Audit.RemoteAddress.AsSlice())
	writeDigestField(digest, []byte(command.Audit.UserAgent))
	var result DirectSAMLSessionRevalidationRequestDigest
	copy(result[:], digest.Sum(nil))
	return result
}

func directSAMLSessionTransitionExpiry(command DirectSAMLSessionRevalidationCommand) time.Time {
	if command.Decision == mfa.SessionRotate {
		return command.Session.AbsoluteExpiresAt()
	}
	if command.Decision == mfa.SessionStepUp {
		return command.Continuation.ExpiresAt()
	}
	return time.Time{}
}

func directSAMLSessionEvidenceLess(left, right DirectSAMLSessionEvidence) bool {
	if left.Kind != right.Kind {
		return left.Kind < right.Kind
	}
	return slices.Compare(left.ID[:], right.ID[:]) < 0
}

func directSAMLSessionPolicyPinLess(left, right DirectSAMLSessionPolicyPin) bool {
	if left.Kind != right.Kind {
		return left.Kind < right.Kind
	}
	return slices.Compare(left.ID[:], right.ID[:]) < 0
}

func directSAMLSessionProviderEvidence(values []DirectSAMLSessionEvidence) *DirectSAMLSessionEvidence {
	for index := range values {
		if values[index].Kind == DirectSAMLSessionEvidenceProvider {
			return &values[index]
		}
	}
	return nil
}

func validDirectSAMLSessionEvidenceLevel(level identity.AssuranceLevel) bool {
	return level >= identity.AssurancePrimary && level <= identity.AssurancePhishingResistant
}

func validDirectSAMLSessionAccountMode(mode DirectSAMLSessionAccountMode) bool {
	return mode == DirectSAMLSessionAccountExisting || mode == DirectSAMLSessionAccountDisabled
}

func directSAMLSessionCoreID(
	value identity.EntityID,
	session DirectSAMLSessionState,
	authority DirectSAMLSessionAuthorityFacts,
) bool {
	return value == session.SessionID || value == session.RotationFamilyID || value == session.UserID ||
		value == authority.ProviderID || value == authority.ExternalIdentityID ||
		value == authority.PinnedPlatformAuthorityID || value == authority.CurrentPlatformAuthorityID ||
		value == authority.PinnedPlatformFloorID || value == authority.CurrentPlatformFloorID
}

func validOptionalDirectSAMLSessionInstant(value *time.Time) bool {
	return value == nil || validInstant(*value)
}

func cloneDirectSAMLSessionSnapshot(
	value DirectSAMLSessionRevalidationSnapshot,
) DirectSAMLSessionRevalidationSnapshot {
	value.Session.ActiveTenantID = cloneDirectSAMLSessionEntityID(value.Session.ActiveTenantID)
	value.Authority.PlatformFloor = cloneRequirement(value.Authority.PlatformFloor)
	if value.Authority.StepUpTOTP != nil {
		copyValue := *value.Authority.StepUpTOTP
		value.Authority.StepUpTOTP = &copyValue
	}
	value.Evidence = append([]DirectSAMLSessionEvidence(nil), value.Evidence...)
	for index := range value.Evidence {
		evidence := &value.Evidence[index]
		evidence.PlatformProviderID = cloneDirectSAMLSessionEntityID(evidence.PlatformProviderID)
		evidence.ExternalIdentityID = cloneDirectSAMLSessionEntityID(evidence.ExternalIdentityID)
		evidence.TOTPCredentialID = cloneDirectSAMLSessionEntityID(evidence.TOTPCredentialID)
		evidence.FactorRevision = cloneDirectSAMLSessionRevision(evidence.FactorRevision)
		evidence.TrustRuleID = cloneDirectSAMLSessionEntityID(evidence.TrustRuleID)
		evidence.TrustRuleRevision = cloneDirectSAMLSessionRevision(evidence.TrustRuleRevision)
		evidence.ExpiresAt = cloneDirectSAMLSessionTime(evidence.ExpiresAt)
	}
	value.FactorAuthorities = append([]DirectSAMLSessionFactorAuthority(nil), value.FactorAuthorities...)
	for index := range value.FactorAuthorities {
		value.FactorAuthorities[index].ConfirmedAt = cloneDirectSAMLSessionTime(
			value.FactorAuthorities[index].ConfirmedAt,
		)
		value.FactorAuthorities[index].DisabledAt = cloneDirectSAMLSessionTime(
			value.FactorAuthorities[index].DisabledAt,
		)
	}
	value.TrustAuthorities = append([]DirectSAMLSessionTrustAuthority(nil), value.TrustAuthorities...)
	for index := range value.TrustAuthorities {
		value.TrustAuthorities[index].RetiredAt = cloneDirectSAMLSessionTime(
			value.TrustAuthorities[index].RetiredAt,
		)
	}
	value.PolicyPins = append([]DirectSAMLSessionPolicyPin(nil), value.PolicyPins...)
	return value
}

func cloneDirectSAMLSessionEntityID(value *identity.EntityID) *identity.EntityID {
	if value == nil {
		return nil
	}
	copyValue := *value
	return &copyValue
}

func cloneDirectSAMLSessionRevision(value *uint64) *uint64 {
	if value == nil {
		return nil
	}
	copyValue := *value
	return &copyValue
}

func cloneDirectSAMLSessionTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copyValue := *value
	return &copyValue
}

func directSAMLSessionNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

var _ interface {
	RevalidateDirectPlatformSession(context.Context, DirectSAMLSessionAuthorityLookup) (DirectSAMLSessionAuthorityOutcome, error)
} = (*DirectSAMLSessionAuthorityService)(nil)
