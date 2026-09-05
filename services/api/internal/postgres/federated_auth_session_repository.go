package postgres

import (
	"context"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
)

const (
	loadFederatedSessionRevalidationSQL  = `select app.load_federated_session_revalidation_v1($1::jsonb)`
	applyFederatedSessionRevalidationSQL = `select app.apply_federated_session_revalidation_v1($1::jsonb)`
)

type federatedSessionLookupWire struct {
	SessionID            string    `json:"sessionId"`
	TenantID             string    `json:"tenantId"`
	Audience             string    `json:"audience"`
	AuthenticationMethod string    `json:"authenticationMethod"`
	ObservedAt           time.Time `json:"observedAt"`
}

type federatedSessionProjectionWire struct {
	Lookup               federatedSessionLookupWire   `json:"lookup"`
	AuthenticationMethod string                       `json:"authenticationMethod"`
	Snapshot             federatedSessionSnapshotWire `json:"snapshot"`
	Live                 federatedLiveSessionWire     `json:"live"`
}

type federatedSessionSnapshotWire struct {
	SessionID          string                         `json:"sessionId"`
	RotationFamilyID   string                         `json:"rotationFamilyId"`
	Version            uint64                         `json:"version"`
	TenantID           string                         `json:"tenantId"`
	UserID             string                         `json:"userId"`
	IdentityEpoch      uint64                         `json:"identityEpoch"`
	RecoveryRestricted bool                           `json:"recoveryRestricted"`
	Primary            federatedPrimaryProvenanceWire `json:"primary"`
	Evidence           []federatedSessionEvidenceWire `json:"evidence"`
	PolicyRevisions    []policyRevisionWire           `json:"policyRevisions"`
	IssuedAt           time.Time                      `json:"issuedAt"`
	IdleExpiresAt      time.Time                      `json:"idleExpiresAt"`
	AbsoluteExpiresAt  time.Time                      `json:"absoluteExpiresAt"`
}

type federatedPrimaryProvenanceWire struct {
	Kind                     string                        `json:"kind"`
	PrimaryID                string                        `json:"primaryId"`
	PrimaryRevision          int64                         `json:"primaryRevision"`
	Provider                 *federatedProviderBindingWire `json:"provider,omitempty"`
	Admission                *federatedTenantAdmissionWire `json:"admission,omitempty"`
	ExternalIdentityID       string                        `json:"externalIdentityId,omitempty"`
	SessionInvalidationEpoch uint64                        `json:"sessionInvalidationEpoch"`
	AuthenticatedAt          time.Time                     `json:"authenticatedAt"`
}

type federatedLocalEvidenceReferenceWire struct {
	LocalCredentialID    string `json:"localCredentialId,omitempty"`
	TOTPFactorID         string `json:"totpFactorId,omitempty"`
	WebAuthnCredentialID string `json:"webauthnCredentialId,omitempty"`
	RecoveryCodeSetID    string `json:"recoveryCodeSetId,omitempty"`
}

type federatedSessionEvidenceWire struct {
	Reference federatedLocalEvidenceReferenceWire `json:"reference"`
	Evidence  assuranceEvidenceWire               `json:"evidence"`
}

type federatedFactorStateWire struct {
	Reference federatedLocalEvidenceReferenceWire `json:"reference"`
	Revision  int64                               `json:"revision"`
	Active    bool                                `json:"active"`
}

type federatedTrustRuleStateWire struct {
	Provider  federatedProviderBindingWire  `json:"provider"`
	Admission *federatedTenantAdmissionWire `json:"admission,omitempty"`
	Revision  int64                         `json:"revision"`
	Active    bool                          `json:"active"`
}

type federatedLiveSessionWire struct {
	TenantID                 string                        `json:"tenantId"`
	UserID                   string                        `json:"userId"`
	Audience                 string                        `json:"audience"`
	SessionActive            bool                          `json:"sessionActive"`
	RotationFamilyActive     bool                          `json:"rotationFamilyActive"`
	UserActive               bool                          `json:"userActive"`
	TenantActive             bool                          `json:"tenantActive"`
	MembershipActive         bool                          `json:"membershipActive"`
	IdentityEpoch            uint64                        `json:"identityEpoch"`
	PrimaryActive            bool                          `json:"primaryActive"`
	PrimaryRevision          int64                         `json:"primaryRevision"`
	SessionInvalidationEpoch uint64                        `json:"sessionInvalidationEpoch"`
	Factors                  []federatedFactorStateWire    `json:"factors"`
	TrustRules               []federatedTrustRuleStateWire `json:"trustRules"`
	Requirement              assuranceRequirementWire      `json:"requirement"`
}

type federatedSessionMutationWire struct {
	SessionID            string                           `json:"sessionId"`
	TenantID             string                           `json:"tenantId"`
	UserID               string                           `json:"userId"`
	Audience             string                           `json:"audience"`
	AuthenticationMethod string                           `json:"authenticationMethod"`
	ExpectedVersion      uint64                           `json:"expectedVersion"`
	ObservedAt           time.Time                        `json:"observedAt"`
	Decision             string                           `json:"decision"`
	Reason               string                           `json:"reason"`
	Requirement          assuranceRequirementWire         `json:"requirement"`
	Session              *federatedSessionReservationWire `json:"session,omitempty"`
	Continuation         *federatedContinuationWire       `json:"continuation,omitempty"`
}

type federatedSessionMutationResultWire struct {
	SessionID       string `json:"sessionId"`
	TenantID        string `json:"tenantId"`
	ExpectedVersion uint64 `json:"expectedVersion"`
	Decision        string `json:"decision"`
	Applied         bool   `json:"applied"`
	NewSessionID    string `json:"newSessionId,omitempty"`
	ContinuationID  string `json:"continuationId,omitempty"`
}

var _ federatedauth.SessionStore = (*FederatedAuthRepository)(nil)

func (repository *FederatedAuthRepository) LoadSessionForRevalidation(
	ctx context.Context,
	lookup federatedauth.SessionLookup,
) (federatedauth.SessionProjection, error) {
	wire, err := federatedSessionLookupToWire(lookup)
	if err != nil {
		return federatedauth.SessionProjection{}, errFederatedAuthPersistence
	}
	var response federatedSessionProjectionWire
	if err := repository.queryJSON(ctx, loadFederatedSessionRevalidationSQL, wire, &response); err != nil {
		return federatedauth.SessionProjection{}, err
	}
	return federatedSessionProjectionFromWire(response, wire)
}

func (repository *FederatedAuthRepository) ApplySessionRevalidation(
	ctx context.Context,
	mutation federatedauth.SessionMutation,
) (federatedauth.SessionMutationResult, error) {
	wire, err := federatedSessionMutationToWire(mutation)
	if err != nil {
		return federatedauth.SessionMutationResult{}, errFederatedAuthPersistence
	}
	defer clearFederatedSessionMutationWire(&wire)
	var response federatedSessionMutationResultWire
	if err := repository.queryJSON(ctx, applyFederatedSessionRevalidationSQL, wire, &response); err != nil {
		return federatedauth.SessionMutationResult{}, err
	}
	return federatedSessionMutationResultFromWire(response, wire)
}

func federatedSessionLookupToWire(lookup federatedauth.SessionLookup) (federatedSessionLookupWire, error) {
	if entityIDWire(lookup.SessionID) == "" || entityIDWire(lookup.TenantID) == "" ||
		!validFederatedPublicText(lookup.Audience, 256) ||
		!validFederatedAuthenticationMethod(string(lookup.AuthenticationMethod)) ||
		!validFederatedDatabaseTime(lookup.ObservedAt) {
		return federatedSessionLookupWire{}, errFederatedAuthPersistence
	}
	return federatedSessionLookupWire{
		SessionID: entityIDWire(lookup.SessionID), TenantID: entityIDWire(lookup.TenantID), Audience: lookup.Audience,
		AuthenticationMethod: string(lookup.AuthenticationMethod), ObservedAt: lookup.ObservedAt,
	}, nil
}

func federatedSessionProjectionFromWire(
	value federatedSessionProjectionWire,
	wanted federatedSessionLookupWire,
) (federatedauth.SessionProjection, error) {
	if value.Lookup != wanted || !validFederatedAuthenticationMethod(value.AuthenticationMethod) ||
		value.AuthenticationMethod != wanted.AuthenticationMethod {
		return federatedauth.SessionProjection{}, errFederatedAuthPersistence
	}
	snapshot, err := federatedSessionSnapshotFromWire(value.Snapshot)
	if err != nil {
		return federatedauth.SessionProjection{}, err
	}
	live, err := federatedLiveSessionFromWire(value.Live)
	if err != nil || entityIDWire(snapshot.SessionID) != wanted.SessionID || entityIDWire(snapshot.TenantID) != wanted.TenantID ||
		entityIDWire(live.TenantID) != wanted.TenantID || live.UserID != snapshot.UserID || live.Audience != wanted.Audience {
		return federatedauth.SessionProjection{}, errFederatedAuthPersistence
	}
	return federatedauth.SessionProjection{
		Snapshot: snapshot, Live: live,
		AuthenticationMethod: federatedauth.AuthenticationMethod(value.AuthenticationMethod),
	}, nil
}

func federatedSessionSnapshotFromWire(value federatedSessionSnapshotWire) (mfa.SessionSnapshot, error) {
	ids, err := parseFederatedEntityIDs(
		value.SessionID, value.RotationFamilyID, value.TenantID, value.UserID,
	)
	issuedAt, validIssued := canonicalFederatedDatabaseTimeFromWire(value.IssuedAt)
	idleExpiresAt, validIdle := canonicalFederatedDatabaseTimeFromWire(value.IdleExpiresAt)
	absoluteExpiresAt, validAbsolute := canonicalFederatedDatabaseTimeFromWire(value.AbsoluteExpiresAt)
	if err != nil || !validFederatedRevision(value.Version) || !validFederatedRevision(value.IdentityEpoch) ||
		!validIssued || !validIdle || !validAbsolute || !idleExpiresAt.After(issuedAt) ||
		!absoluteExpiresAt.After(issuedAt) || len(value.Evidence) == 0 || len(value.Evidence) > 1024 ||
		len(value.PolicyRevisions) == 0 || len(value.PolicyRevisions) > 1024 {
		return mfa.SessionSnapshot{}, errFederatedAuthPersistence
	}
	primary, err := federatedPrimaryFromWire(value.Primary, ids[2])
	if err != nil {
		return mfa.SessionSnapshot{}, err
	}
	evidence := make([]mfa.SessionEvidence, len(value.Evidence))
	for index, item := range value.Evidence {
		reference, referenceErr := federatedLocalEvidenceReferenceFromWire(item.Reference, true)
		items, evidenceErr := evidenceFromWire([]assuranceEvidenceWire{item.Evidence})
		if referenceErr != nil || evidenceErr != nil || len(items) != 1 || !canonicalizeFederatedEvidence(&items[0]) {
			return mfa.SessionSnapshot{}, errFederatedAuthPersistence
		}
		evidence[index] = mfa.SessionEvidence{Reference: reference, Evidence: items[0]}
	}
	policy := make([]identity.AssurancePolicyRevision, len(value.PolicyRevisions))
	for index, revision := range value.PolicyRevisions {
		identifier, parseErr := parseEntityIDWire(revision.PolicyID, false)
		if parseErr != nil || revision.Revision < 1 || index > 0 && value.PolicyRevisions[index-1].PolicyID >= revision.PolicyID {
			return mfa.SessionSnapshot{}, errFederatedAuthPersistence
		}
		policy[index] = identity.AssurancePolicyRevision{PolicyID: identifier, Revision: revision.Revision}
	}
	return mfa.SessionSnapshot{
		SessionID: ids[0], RotationFamilyID: ids[1], Version: value.Version,
		TenantID: ids[2], UserID: ids[3], IdentityEpoch: value.IdentityEpoch,
		RecoveryRestricted: value.RecoveryRestricted, Primary: primary, Evidence: evidence,
		PolicyRevisions: policy, IssuedAt: issuedAt, IdleExpiresAt: idleExpiresAt, AbsoluteExpiresAt: absoluteExpiresAt,
	}, nil
}

func federatedPrimaryFromWire(
	value federatedPrimaryProvenanceWire,
	tenantID identity.EntityID,
) (mfa.PrimaryProvenance, error) {
	primaryID, err := parseEntityIDWire(value.PrimaryID, false)
	authenticatedAt, validTime := canonicalFederatedDatabaseTimeFromWire(value.AuthenticatedAt)
	if err != nil || value.PrimaryRevision < 1 || !validFederatedRevision(value.SessionInvalidationEpoch) || !validTime {
		return mfa.PrimaryProvenance{}, errFederatedAuthPersistence
	}
	result := mfa.PrimaryProvenance{
		PrimaryID: primaryID, PrimaryRevision: value.PrimaryRevision,
		SessionInvalidationEpoch: value.SessionInvalidationEpoch, AuthenticatedAt: authenticatedAt,
	}
	switch value.Kind {
	case "local_credential":
		result.Kind = mfa.PrimaryLocalCredential
	case "passkey":
		result.Kind = mfa.PrimaryPasskey
	case "tenant_provider", "platform_provider_binding":
		if value.Provider == nil {
			return mfa.PrimaryProvenance{}, errFederatedAuthPersistence
		}
		provider, _, bindingID, providerErr := providerTenantAdmissionFromWire(
			*value.Provider, value.Admission, tenantID,
		)
		externalID, externalErr := parseEntityIDWire(value.ExternalIdentityID, false)
		if providerErr != nil || externalErr != nil ||
			value.Kind == "tenant_provider" && provider.Scope != identity.TenantProviderScope ||
			value.Kind == "platform_provider_binding" && provider.Scope != identity.PlatformProviderScope {
			return mfa.PrimaryProvenance{}, errFederatedAuthPersistence
		}
		if value.Kind == "tenant_provider" {
			result.Kind = mfa.PrimaryTenantProvider
		} else {
			result.Kind = mfa.PrimaryPlatformProviderBinding
		}
		result.Provider, result.BindingID, result.ExternalIdentityID = provider, bindingID, externalID
	default:
		return mfa.PrimaryProvenance{}, errFederatedAuthPersistence
	}
	if (result.Kind == mfa.PrimaryLocalCredential || result.Kind == mfa.PrimaryPasskey) &&
		(value.Provider != nil || value.Admission != nil || value.ExternalIdentityID != "") {
		return mfa.PrimaryProvenance{}, errFederatedAuthPersistence
	}
	return result, nil
}

func federatedLiveSessionFromWire(value federatedLiveSessionWire) (mfa.LiveSessionProjection, error) {
	ids, err := parseFederatedEntityIDs(value.TenantID, value.UserID)
	requirement, requirementErr := requirementFromWire(value.Requirement)
	if err != nil || requirementErr != nil || !validFederatedRevision(value.IdentityEpoch) ||
		value.PrimaryRevision < 1 || !validFederatedRevision(value.SessionInvalidationEpoch) ||
		!validFederatedPublicText(value.Audience, 256) || len(value.Factors) > 1024 || len(value.TrustRules) > 1024 ||
		!canonicalizeFederatedRequirement(&requirement) {
		return mfa.LiveSessionProjection{}, errFederatedAuthPersistence
	}
	factors := make([]mfa.FactorState, len(value.Factors))
	for index, factor := range value.Factors {
		reference, referenceErr := federatedLocalEvidenceReferenceFromWire(factor.Reference, false)
		if referenceErr != nil || factor.Revision < 1 {
			return mfa.LiveSessionProjection{}, errFederatedAuthPersistence
		}
		factors[index] = mfa.FactorState{Reference: reference, Revision: factor.Revision, Active: factor.Active}
	}
	trust := make([]mfa.TrustRuleState, len(value.TrustRules))
	for index, rule := range value.TrustRules {
		provider, _, bindingID, providerErr := providerTenantAdmissionFromWire(
			rule.Provider, rule.Admission, ids[0],
		)
		if providerErr != nil || rule.Revision < 1 {
			return mfa.LiveSessionProjection{}, errFederatedAuthPersistence
		}
		trust[index] = mfa.TrustRuleState{Provider: provider, BindingID: bindingID, Revision: rule.Revision, Active: rule.Active}
	}
	return mfa.LiveSessionProjection{
		TenantID: ids[0], UserID: ids[1], Audience: value.Audience,
		SessionActive: value.SessionActive, RotationFamilyActive: value.RotationFamilyActive,
		UserActive: value.UserActive, TenantActive: value.TenantActive, MembershipActive: value.MembershipActive,
		IdentityEpoch: value.IdentityEpoch, PrimaryActive: value.PrimaryActive, PrimaryRevision: value.PrimaryRevision,
		SessionInvalidationEpoch: value.SessionInvalidationEpoch,
		Factors:                  factors, TrustRules: trust, Requirement: requirement,
	}, nil
}

func federatedSessionMutationToWire(value federatedauth.SessionMutation) (federatedSessionMutationWire, error) {
	requirement, err := requirementToWire(value.Requirement)
	if err != nil || entityIDWire(value.SessionID) == "" || entityIDWire(value.TenantID) == "" ||
		entityIDWire(value.UserID) == "" || !validFederatedPublicText(value.Audience, 256) ||
		!validFederatedAuthenticationMethod(string(value.AuthenticationMethod)) ||
		!validFederatedSuccessorRevision(value.ExpectedVersion) || !validFederatedDatabaseTime(value.ObservedAt) ||
		!validFederatedSessionDecisionReason(value.Decision, value.Reason) {
		return federatedSessionMutationWire{}, errFederatedAuthPersistence
	}
	wire := federatedSessionMutationWire{
		SessionID: entityIDWire(value.SessionID), TenantID: entityIDWire(value.TenantID), UserID: entityIDWire(value.UserID),
		Audience: value.Audience, AuthenticationMethod: string(value.AuthenticationMethod),
		ExpectedVersion: value.ExpectedVersion, ObservedAt: value.ObservedAt,
		Decision: string(value.Decision), Reason: string(value.Reason), Requirement: requirement,
	}
	switch value.Decision {
	case mfa.SessionRotate:
		if !value.Continuation.IsZero() || !value.Session.ValidAt(value.ObservedAt.Truncate(time.Millisecond)) ||
			string(value.Session.AuthenticationMethod()) != string(value.AuthenticationMethod) {
			return federatedSessionMutationWire{}, errFederatedAuthPersistence
		}
		wire.Session = federatedApplySessionReservationToWire(value.Session)
	case mfa.SessionStepUp:
		if !value.Session.IsZero() || !value.Continuation.ValidAt(value.ObservedAt) {
			return federatedSessionMutationWire{}, errFederatedAuthPersistence
		}
		wire.Continuation = continuationReservationToWire(value.Continuation)
	default:
		if !value.Session.IsZero() || !value.Continuation.IsZero() {
			return federatedSessionMutationWire{}, errFederatedAuthPersistence
		}
	}
	return wire, nil
}

func federatedSessionMutationResultFromWire(
	value federatedSessionMutationResultWire,
	wanted federatedSessionMutationWire,
) (federatedauth.SessionMutationResult, error) {
	if value.SessionID != wanted.SessionID || value.TenantID != wanted.TenantID ||
		value.ExpectedVersion != wanted.ExpectedVersion || value.Decision != wanted.Decision {
		return federatedauth.SessionMutationResult{}, errFederatedAuthPersistence
	}
	if !value.Applied {
		if value.NewSessionID != "" || value.ContinuationID != "" {
			return federatedauth.SessionMutationResult{}, errFederatedAuthPersistence
		}
		return federatedauth.SessionMutationResult{}, nil
	}
	result := federatedauth.SessionMutationResult{Applied: true}
	var err error
	switch mfa.SessionDecision(wanted.Decision) {
	case mfa.SessionRotate:
		if wanted.Session == nil || value.NewSessionID != wanted.Session.SessionID || value.ContinuationID != "" {
			return federatedauth.SessionMutationResult{}, errFederatedAuthPersistence
		}
		result.NewSessionID, err = parseEntityIDWire(value.NewSessionID, false)
	case mfa.SessionStepUp:
		if wanted.Continuation == nil || value.NewSessionID != "" ||
			value.ContinuationID != wanted.Continuation.ContinuationID {
			return federatedauth.SessionMutationResult{}, errFederatedAuthPersistence
		}
		result.ContinuationID, err = parseEntityIDWire(value.ContinuationID, false)
	case mfa.SessionUsable, mfa.SessionRevoke, mfa.SessionDeny:
		if value.NewSessionID != "" || value.ContinuationID != "" {
			return federatedauth.SessionMutationResult{}, errFederatedAuthPersistence
		}
	default:
		err = errFederatedAuthPersistence
	}
	if err != nil {
		return federatedauth.SessionMutationResult{}, errFederatedAuthPersistence
	}
	return result, nil
}

func federatedLocalEvidenceReferenceFromWire(
	value federatedLocalEvidenceReferenceWire,
	optional bool,
) (mfa.LocalEvidenceReference, error) {
	values := []string{value.LocalCredentialID, value.TOTPFactorID, value.WebAuthnCredentialID, value.RecoveryCodeSetID}
	present := 0
	result := mfa.LocalEvidenceReference{}
	for index, item := range values {
		if item == "" {
			continue
		}
		present++
		identifier, err := parseEntityIDWire(item, false)
		if err != nil {
			return mfa.LocalEvidenceReference{}, errFederatedAuthPersistence
		}
		switch index {
		case 0:
			result.LocalCredentialID = identifier
		case 1:
			result.TOTPFactorID = identifier
		case 2:
			result.WebAuthnCredentialID = identifier
		case 3:
			result.RecoveryCodeSetID = identifier
		}
	}
	if present > 1 || !optional && present != 1 {
		return mfa.LocalEvidenceReference{}, errFederatedAuthPersistence
	}
	return result, nil
}

func parseFederatedEntityIDs(values ...string) ([]identity.EntityID, error) {
	result := make([]identity.EntityID, len(values))
	for index, value := range values {
		identifier, err := parseEntityIDWire(value, false)
		if err != nil {
			return nil, errFederatedAuthPersistence
		}
		result[index] = identifier
	}
	return result, nil
}

func canonicalizeFederatedEvidence(value *identity.AssuranceEvidence) bool {
	if value == nil {
		return false
	}
	authenticatedAt, valid := canonicalFederatedDatabaseTimeFromWire(value.AuthenticatedAt)
	if !valid {
		return false
	}
	value.AuthenticatedAt = authenticatedAt
	if value.ExpiresAt != nil {
		expiresAt, validExpiry := canonicalFederatedDatabaseTimeFromWire(*value.ExpiresAt)
		if !validExpiry {
			return false
		}
		value.ExpiresAt = &expiresAt
	}
	return true
}

func canonicalizeFederatedRequirement(value *identity.EffectiveAssuranceRequirement) bool {
	if value == nil {
		return false
	}
	if value.EnrollmentDeadline != nil {
		deadline, valid := canonicalFederatedDatabaseTimeFromWire(*value.EnrollmentDeadline)
		if !valid {
			return false
		}
		value.EnrollmentDeadline = &deadline
	}
	return true
}

func validFederatedAuthenticationMethod(value string) bool {
	switch federatedauth.AuthenticationMethod(value) {
	case federatedauth.AuthenticationMethodOIDC, federatedauth.AuthenticationMethodSAML,
		federatedauth.AuthenticationMethodPasskey, federatedauth.AuthenticationMethodLDAP:
		return true
	default:
		return false
	}
}

func validFederatedSessionDecisionReason(decision mfa.SessionDecision, reason mfa.SessionReason) bool {
	switch decision {
	case mfa.SessionUsable:
		return reason == mfa.SessionReasonCurrent
	case mfa.SessionRotate:
		return reason == mfa.SessionReasonPolicyRefresh
	case mfa.SessionStepUp:
		return reason == mfa.SessionReasonAssuranceInsufficient || reason == mfa.SessionReasonRecoveryRestricted
	case mfa.SessionRevoke:
		switch reason {
		case mfa.SessionReasonLifecycle, mfa.SessionReasonIdentityEpoch, mfa.SessionReasonPrimaryDrift,
			mfa.SessionReasonFactorDrift, mfa.SessionReasonTrustDrift, mfa.SessionReasonExpired:
			return true
		default:
			return false
		}
	case mfa.SessionDeny:
		return reason == mfa.SessionReasonMalformed
	default:
		return false
	}
}

func clearFederatedSessionMutationWire(value *federatedSessionMutationWire) {
	if value == nil {
		return
	}
	if value.Session != nil {
		clear(value.Session.TokenDigest)
		clear(value.Session.CSRFDigest)
	}
	if value.Continuation != nil {
		clear(value.Continuation.ReceiptDigest)
	}
	*value = federatedSessionMutationWire{}
}
