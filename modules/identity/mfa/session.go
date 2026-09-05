package mfa

import (
	"bytes"
	"fmt"
	"slices"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

type PrimaryProvenanceKind uint8

const (
	PrimaryLocalCredential PrimaryProvenanceKind = iota + 1
	PrimaryPasskey
	PrimaryTenantProvider
	PrimaryPlatformProviderBinding
)

// PrimaryProvenance is the exact normalized source row pinned by a session.
// Provider subject/claims and WebAuthn material never enter this projection.
type PrimaryProvenance struct {
	Kind                     PrimaryProvenanceKind
	PrimaryID                identity.EntityID
	PrimaryRevision          int64
	Provider                 identity.ProviderContext
	BindingID                identity.EntityID
	ExternalIdentityID       identity.EntityID
	SessionInvalidationEpoch uint64
	AuthenticatedAt          time.Time
}

// LocalEvidenceReference is physically typed so equal UUID bytes in distinct
// credential tables can never alias during session revalidation.
type LocalEvidenceReference struct {
	LocalCredentialID    identity.EntityID
	TOTPFactorID         identity.EntityID
	WebAuthnCredentialID identity.EntityID
	RecoveryCodeSetID    identity.EntityID
}

type SessionEvidence struct {
	Reference LocalEvidenceReference
	Evidence  identity.AssuranceEvidence
}

// SessionSnapshot contains only server-side provenance. It is not a cookie projection.
type SessionSnapshot struct {
	SessionID          identity.EntityID
	RotationFamilyID   identity.EntityID
	Version            uint64
	TenantID           identity.EntityID
	UserID             identity.EntityID
	IdentityEpoch      uint64
	RecoveryRestricted bool
	Primary            PrimaryProvenance
	Evidence           []SessionEvidence
	PolicyRevisions    []identity.AssurancePolicyRevision
	IssuedAt           time.Time
	IdleExpiresAt      time.Time
	AbsoluteExpiresAt  time.Time
}

func (s SessionSnapshot) String() string {
	return fmt.Sprintf("mfa.SessionSnapshot{version:%d,primary:%d,evidence:%d,provenance:[REDACTED]}",
		s.Version, s.Primary.Kind, len(s.Evidence))
}
func (s SessionSnapshot) GoString() string { return s.String() }

type FactorState struct {
	Reference LocalEvidenceReference
	Revision  int64
	Active    bool
}

type TrustRuleState struct {
	Provider  identity.ProviderContext
	BindingID identity.EntityID
	Revision  int64
	Active    bool
}

// LiveSessionProjection must be loaded before an idle touch or RBAC decision.
type LiveSessionProjection struct {
	TenantID                 identity.EntityID
	UserID                   identity.EntityID
	Audience                 string
	SessionActive            bool
	RotationFamilyActive     bool
	UserActive               bool
	TenantActive             bool
	MembershipActive         bool
	IdentityEpoch            uint64
	PrimaryActive            bool
	PrimaryRevision          int64
	SessionInvalidationEpoch uint64
	Factors                  []FactorState
	TrustRules               []TrustRuleState
	Requirement              identity.EffectiveAssuranceRequirement
}

type SessionDecision string

const (
	SessionUsable SessionDecision = "usable"
	SessionRotate SessionDecision = "rotate"
	SessionStepUp SessionDecision = "step_up"
	SessionRevoke SessionDecision = "revoke"
	SessionDeny   SessionDecision = "deny"
)

type SessionReason string

const (
	SessionReasonCurrent               SessionReason = "current"
	SessionReasonPolicyRefresh         SessionReason = "policy_refresh"
	SessionReasonAssuranceInsufficient SessionReason = "assurance_insufficient"
	SessionReasonLifecycle             SessionReason = "lifecycle"
	SessionReasonIdentityEpoch         SessionReason = "identity_epoch"
	SessionReasonPrimaryDrift          SessionReason = "primary_drift"
	SessionReasonFactorDrift           SessionReason = "factor_drift"
	SessionReasonTrustDrift            SessionReason = "trust_drift"
	SessionReasonRecoveryRestricted    SessionReason = "recovery_restricted"
	SessionReasonExpired               SessionReason = "expired"
	SessionReasonMalformed             SessionReason = "malformed"
)

type SessionRevalidation struct {
	Decision       SessionDecision
	Reason         SessionReason
	AllowAuthority bool
	AllowIdleTouch bool
	Requirement    identity.EffectiveAssuranceRequirement
}

// RevalidateSession performs lifecycle and provenance checks before assurance.
// Identity/trust/factor drift revokes; a policy increase creates a restricted
// step-up, while a still-satisfied policy revision rotates the session pins.
func RevalidateSession(now time.Time, session SessionSnapshot, live LiveSessionProjection) SessionRevalidation {
	if !validMFATime(now) || !validSessionSnapshot(now, session) || !validLiveProjection(now, session, live) {
		return sessionResult(SessionDeny, SessionReasonMalformed, live.Requirement)
	}
	if !now.Before(session.IdleExpiresAt) || !now.Before(session.AbsoluteExpiresAt) {
		return sessionResult(SessionRevoke, SessionReasonExpired, live.Requirement)
	}
	if !live.SessionActive || !live.RotationFamilyActive || !live.UserActive || !live.TenantActive ||
		!live.MembershipActive || !live.PrimaryActive {
		return sessionResult(SessionRevoke, SessionReasonLifecycle, live.Requirement)
	}
	if live.IdentityEpoch != session.IdentityEpoch {
		return sessionResult(SessionRevoke, SessionReasonIdentityEpoch, live.Requirement)
	}
	if live.PrimaryRevision != session.Primary.PrimaryRevision ||
		live.SessionInvalidationEpoch != session.Primary.SessionInvalidationEpoch {
		return sessionResult(SessionRevoke, SessionReasonPrimaryDrift, live.Requirement)
	}
	if !allFactorEvidenceCurrent(session.Evidence, live.Factors) {
		return sessionResult(SessionRevoke, SessionReasonFactorDrift, live.Requirement)
	}
	if !allTrustEvidenceCurrent(session.Primary, session.Evidence, live.TrustRules) {
		return sessionResult(SessionRevoke, SessionReasonTrustDrift, live.Requirement)
	}
	// Recovery proves account control only for a narrow recovery workflow. It
	// never grants ordinary authority even when the baseline policy is primary.
	if session.RecoveryRestricted {
		return sessionResult(SessionStepUp, SessionReasonRecoveryRestricted, live.Requirement)
	}
	evidence := make([]identity.AssuranceEvidence, len(session.Evidence))
	for index := range session.Evidence {
		evidence[index] = session.Evidence[index].Evidence
	}
	assurance := identity.EvaluateAssurance(now, live.Requirement, evidence, false)
	if assurance == identity.AssuranceDenied {
		return sessionResult(SessionDeny, SessionReasonMalformed, live.Requirement)
	}
	policyCurrent := slices.Equal(session.PolicyRevisions, live.Requirement.PolicyRevisions)
	if assurance != identity.AssuranceSatisfied {
		return sessionResult(SessionStepUp, SessionReasonAssuranceInsufficient, live.Requirement)
	}
	if !policyCurrent {
		return sessionResult(SessionRotate, SessionReasonPolicyRefresh, live.Requirement)
	}
	result := sessionResult(SessionUsable, SessionReasonCurrent, live.Requirement)
	result.AllowAuthority = true
	result.AllowIdleTouch = true
	return result
}

func sessionResult(decision SessionDecision, reason SessionReason,
	requirement identity.EffectiveAssuranceRequirement,
) SessionRevalidation {
	return SessionRevalidation{
		Decision: decision, Reason: reason,
		Requirement: cloneRequirement(requirement),
	}
}

func validSessionSnapshot(now time.Time, value SessionSnapshot) bool {
	zero := identity.EntityID{}
	if value.SessionID == zero || value.RotationFamilyID == zero || !validStoredVersion(value.Version) ||
		value.TenantID == zero || value.UserID == zero || !validStoredVersion(value.IdentityEpoch) ||
		!validPrimary(value.TenantID, value.Primary) || value.Primary.AuthenticatedAt.After(now) ||
		len(value.Evidence) == 0 || len(value.Evidence) > 1024 ||
		!validMFATime(value.IssuedAt) || !validMFADeadline(value.IdleExpiresAt) ||
		!validMFADeadline(value.AbsoluteExpiresAt) || value.IssuedAt.After(now) ||
		!value.IdleExpiresAt.After(value.IssuedAt) || !value.AbsoluteExpiresAt.After(value.IssuedAt) ||
		!validPolicyPins(value.PolicyRevisions) {
		return false
	}
	evidence := make([]identity.AssuranceEvidence, len(value.Evidence))
	seenFactors := make(map[localEvidenceKey]struct{}, len(value.Evidence))
	for index, item := range value.Evidence {
		evidence[index] = item.Evidence
		if item.Evidence.Source.Local {
			key, valid := validLocalEvidenceReference(value.Primary, item)
			if !valid {
				return false
			}
			if _, duplicate := seenFactors[key]; duplicate {
				return false
			}
			seenFactors[key] = struct{}{}
		} else {
			if item.Reference != (LocalEvidenceReference{}) ||
				(value.Primary.Kind != PrimaryTenantProvider && value.Primary.Kind != PrimaryPlatformProviderBinding) ||
				item.Evidence.Source.ProviderID != value.Primary.Provider.ProviderID ||
				item.Evidence.Source.BindingID != value.Primary.BindingID {
				return false
			}
		}
	}
	return validEvidence(now, evidence)
}

func validPrimary(tenantID identity.EntityID, value PrimaryProvenance) bool {
	zero := identity.EntityID{}
	if value.PrimaryID == zero || !validStoredRevision(value.PrimaryRevision) ||
		!validStoredVersion(value.SessionInvalidationEpoch) ||
		!validMFATime(value.AuthenticatedAt) {
		return false
	}
	switch value.Kind {
	case PrimaryLocalCredential, PrimaryPasskey:
		return value.Provider == (identity.ProviderContext{}) && value.BindingID == zero && value.ExternalIdentityID == zero
	case PrimaryTenantProvider:
		return value.Provider.Scope == identity.TenantProviderScope && value.Provider.TenantID == tenantID &&
			value.Provider.ProviderID != zero && value.BindingID != zero && value.ExternalIdentityID != zero
	case PrimaryPlatformProviderBinding:
		return value.Provider.Scope == identity.PlatformProviderScope && value.Provider.TenantID == zero &&
			value.Provider.ProviderID != zero && value.BindingID != zero && value.ExternalIdentityID != zero
	default:
		return false
	}
}

func validLiveProjection(now time.Time, session SessionSnapshot, value LiveSessionProjection) bool {
	if value.TenantID != session.TenantID || value.UserID != session.UserID || !validAudience(value.Audience) ||
		!validStoredVersion(value.IdentityEpoch) || !validStoredRevision(value.PrimaryRevision) ||
		!validStoredVersion(value.SessionInvalidationEpoch) ||
		!validRequirement(now, value.Requirement) || !validFactorStates(value.Factors) ||
		!validTrustStates(value.TrustRules) {
		return false
	}
	// A local session cannot gain provider trust rows through a malformed join;
	// provider rows may legitimately coexist for unrelated evidence only if none
	// are supplied to this exact projection.
	if (session.Primary.Kind == PrimaryLocalCredential || session.Primary.Kind == PrimaryPasskey) &&
		len(value.TrustRules) != 0 {
		return false
	}
	return true
}

func validPolicyPins(values []identity.AssurancePolicyRevision) bool {
	if len(values) == 0 || len(values) > 1024 {
		return false
	}
	zero := identity.EntityID{}
	for index, value := range values {
		if value.PolicyID == zero || !validStoredRevision(value.Revision) || index > 0 &&
			bytes.Compare(value.PolicyID[:], values[index-1].PolicyID[:]) <= 0 {
			return false
		}
	}
	return true
}

func validFactorStates(values []FactorState) bool {
	if len(values) > 1024 {
		return false
	}
	seen := make(map[localEvidenceKey]struct{}, len(values))
	for _, value := range values {
		key, valid := localReferenceKey(value.Reference, 0)
		if !valid || !validStoredRevision(value.Revision) {
			return false
		}
		if _, duplicate := seen[key]; duplicate {
			return false
		}
		seen[key] = struct{}{}
	}
	return true
}

func validTrustStates(values []TrustRuleState) bool {
	if len(values) > 1024 {
		return false
	}
	seen := make(map[trustKey]struct{}, len(values))
	zero := identity.EntityID{}
	for _, value := range values {
		if value.Provider.ProviderID == zero || !validStoredRevision(value.Revision) {
			return false
		}
		switch value.Provider.Scope {
		case identity.TenantProviderScope:
			if value.Provider.TenantID == zero || value.BindingID == zero {
				return false
			}
		case identity.PlatformProviderScope:
			if value.Provider.TenantID != zero {
				return false
			}
		default:
			return false
		}
		key := trustKey{provider: value.Provider, bindingID: value.BindingID}
		if _, duplicate := seen[key]; duplicate {
			return false
		}
		seen[key] = struct{}{}
	}
	return true
}

type trustKey struct {
	provider  identity.ProviderContext
	bindingID identity.EntityID
}

type localEvidenceKind uint8

const (
	localEvidenceCredential localEvidenceKind = iota + 1
	localEvidenceTOTP
	localEvidenceWebAuthn
	localEvidenceRecovery
)

type localEvidenceKey struct {
	kind localEvidenceKind
	id   identity.EntityID
}

func localReferenceKey(reference LocalEvidenceReference, evidenceKind identity.AssuranceEvidenceKind) (localEvidenceKey, bool) {
	zero := identity.EntityID{}
	result := localEvidenceKey{}
	count := 0
	set := func(kind localEvidenceKind, id identity.EntityID) {
		if id != zero {
			count++
			result = localEvidenceKey{kind: kind, id: id}
		}
	}
	set(localEvidenceCredential, reference.LocalCredentialID)
	set(localEvidenceTOTP, reference.TOTPFactorID)
	set(localEvidenceWebAuthn, reference.WebAuthnCredentialID)
	set(localEvidenceRecovery, reference.RecoveryCodeSetID)
	if count != 1 {
		return localEvidenceKey{}, false
	}
	if evidenceKind == 0 {
		return result, true
	}
	if result.kind == localEvidenceRecovery {
		return result, evidenceKind == identity.AssuranceEvidenceRecovery
	}
	return result, evidenceKind == identity.AssuranceEvidenceFactor
}

func validLocalEvidenceReference(primary PrimaryProvenance, evidence SessionEvidence) (localEvidenceKey, bool) {
	key, valid := localReferenceKey(evidence.Reference, evidence.Evidence.Kind)
	if !valid {
		return localEvidenceKey{}, false
	}
	switch key.kind {
	case localEvidenceCredential:
		valid = primary.Kind == PrimaryLocalCredential && key.id == primary.PrimaryID &&
			evidence.Evidence.Level == identity.AssurancePrimary
	case localEvidenceTOTP:
		valid = evidence.Evidence.Level == identity.AssuranceMFA
	case localEvidenceWebAuthn:
		valid = evidence.Evidence.Level != identity.AssurancePrimary ||
			primary.Kind == PrimaryPasskey && key.id == primary.PrimaryID
	case localEvidenceRecovery:
		valid = evidence.Evidence.Level == identity.AssuranceMFA
	default:
		valid = false
	}
	return key, valid
}

func allFactorEvidenceCurrent(evidence []SessionEvidence, states []FactorState) bool {
	byID := make(map[localEvidenceKey]FactorState, len(states))
	for _, state := range states {
		key, _ := localReferenceKey(state.Reference, 0)
		byID[key] = state
	}
	for _, item := range evidence {
		if !item.Evidence.Source.Local {
			continue
		}
		key, valid := localReferenceKey(item.Reference, item.Evidence.Kind)
		state, exists := byID[key]
		if !valid || !exists || !state.Active || item.Evidence.FactorRevision == nil ||
			state.Revision != *item.Evidence.FactorRevision {
			return false
		}
	}
	return true
}

func allTrustEvidenceCurrent(primary PrimaryProvenance, evidence []SessionEvidence, states []TrustRuleState) bool {
	byKey := make(map[trustKey]TrustRuleState, len(states))
	for _, state := range states {
		byKey[trustKey{provider: state.Provider, bindingID: state.BindingID}] = state
	}
	for _, item := range evidence {
		if item.Evidence.Source.Local {
			continue
		}
		state, exists := byKey[trustKey{provider: primary.Provider, bindingID: primary.BindingID}]
		if !exists || !state.Active || item.Evidence.TrustRuleRevision == nil ||
			state.Revision != *item.Evidence.TrustRuleRevision {
			return false
		}
	}
	return true
}
