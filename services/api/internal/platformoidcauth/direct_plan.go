package platformoidcauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedoidc"
)

const (
	maximumDirectSubjectAliases = 16
	maximumDirectTOTPFactors    = 64
	maximumUUIDUnixMilliseconds = uint64(253_402_300_799_999)
)

var ErrDirectAuthenticationDenied = errors.New("direct platform OIDC authentication denied")

type DirectAuthenticationDisposition string

const (
	DirectAuthenticationImmediateSession DirectAuthenticationDisposition = "immediate_session"
	DirectAuthenticationTOTPContinuation DirectAuthenticationDisposition = "totp_continuation"
)

// DirectPlatformPlanningLookup contains only provider authority, exact
// transaction revisions, and provider-qualified subject aliases. Raw issuer,
// subject, claims, profile, email, and groups never cross this source port.
type DirectPlatformPlanningLookup struct {
	TransactionID           federatedoidc.TransactionID
	ClaimAttemptID          federatedoidc.TransactionID
	ObservedAt              time.Time
	Pins                    DirectOIDCConfigurationPins
	Provider                identity.ProviderContext
	SubjectFormat           identity.SubjectFormat
	SubjectAliases          []identity.SubjectAlias
	ProviderRevision        uint64
	PlatformLoginRevision   uint64
	ConfigurationRevision   uint64
	SecurityRevision        uint64
	AssurancePolicyRevision uint64
}

func (lookup DirectPlatformPlanningLookup) String() string {
	return fmt.Sprintf(
		"platformoidcauth.DirectPlatformPlanningLookup{transaction:%t,claimAttempt:%t,observed:%t,pins:%q,providerRevision:%t,loginRevision:%t,configurationRevision:%t,securityRevision:%t,assuranceRevision:%t,subjectFormat:%d,aliases:%d,subject:[REDACTED]}",
		validTransactionID(lookup.TransactionID), validTransactionID(lookup.ClaimAttemptID),
		!lookup.ObservedAt.IsZero(), lookup.Pins.String(),
		lookup.ProviderRevision != 0, lookup.PlatformLoginRevision != 0,
		lookup.ConfigurationRevision != 0, lookup.SecurityRevision != 0,
		lookup.AssurancePolicyRevision != 0, lookup.SubjectFormat, len(lookup.SubjectAliases),
	)
}

func (lookup DirectPlatformPlanningLookup) GoString() string { return lookup.String() }

// DirectPlatformIdentityMatch is one prelinked platform identity selected by
// an exact alias. The adapter returns a slice so ambiguity is observable and
// denied rather than hidden behind LIMIT 1.
type DirectPlatformIdentityMatch struct {
	ProviderID                 identity.EntityID
	ExternalIdentityID         identity.EntityID
	UserID                     identity.EntityID
	Alias                      identity.SubjectAlias
	IdentityRevision           uint64
	UserAuthenticationRevision uint64
	IdentityLive               bool
	AliasLive                  bool
	UserActive                 bool
}

func (match DirectPlatformIdentityMatch) String() string {
	return fmt.Sprintf(
		"platformoidcauth.DirectPlatformIdentityMatch{provider:%t,identity:%t,user:%t,alias:%q,identityRevision:%t,userAuthenticationRevision:%t,live:%t}",
		match.ProviderID != (identity.EntityID{}), match.ExternalIdentityID != (identity.EntityID{}),
		match.UserID != (identity.EntityID{}), match.Alias.String(), match.IdentityRevision != 0,
		match.UserAuthenticationRevision != 0,
		match.IdentityLive && match.AliasLive && match.UserActive,
	)
}

func (match DirectPlatformIdentityMatch) GoString() string { return match.String() }

// DirectPlatformTOTPFactor is a deliberately narrow platform-account factor
// projection. It cannot represent enrollment, recovery, WebAuthn, or a
// tenant-bound MFA challenge.
type DirectPlatformTOTPFactor struct {
	FactorID    identity.EntityID
	UserID      identity.EntityID
	Revision    uint64
	Active      bool
	ConfirmedAt *time.Time
}

func (factor DirectPlatformTOTPFactor) String() string {
	return fmt.Sprintf(
		"platformoidcauth.DirectPlatformTOTPFactor{id:%t,user:%t,revision:%t,active:%t,confirmed:%t}",
		factor.FactorID != (identity.EntityID{}), factor.UserID != (identity.EntityID{}),
		factor.Revision != 0, factor.Active, factor.ConfirmedAt != nil,
	)
}

func (factor DirectPlatformTOTPFactor) GoString() string { return factor.String() }

// DirectPlatformPlanningState is one immutable, provider-global snapshot.
// Matches must contain exactly one live prelinked identity. TrustRules and
// LiveConfirmedTOTPFactors are adapter-owned slices and are cloned before any
// validation or ordering.
type DirectPlatformPlanningState struct {
	Provider                 identity.ProviderContext
	ProviderRevision         uint64
	PlatformLoginRevision    uint64
	ConfigurationRevision    uint64
	SecurityRevision         uint64
	PlanRevision             uint64
	AssurancePolicyRevision  uint64
	ProviderEnabled          bool
	PlatformLoginLive        bool
	ConfigurationLive        bool
	AssurancePolicyLive      bool
	AccountMode              AccountMode
	Matches                  []DirectPlatformIdentityMatch
	TrustRules               []DirectOIDCTrustRule
	PlatformFloor            identity.EffectiveAssuranceRequirement
	LiveConfirmedTOTPFactors []DirectPlatformTOTPFactor
}

func (state DirectPlatformPlanningState) String() string {
	return fmt.Sprintf(
		"platformoidcauth.DirectPlatformPlanningState{providerRevision:%t,loginRevision:%t,configurationRevision:%t,securityRevision:%t,planRevision:%t,assuranceRevision:%t,enabled:%t,mode:%q,matches:%d,trustRules:%d,platformPolicies:%d,totpFactors:%d}",
		state.ProviderRevision != 0, state.PlatformLoginRevision != 0,
		state.ConfigurationRevision != 0, state.SecurityRevision != 0,
		state.PlanRevision != 0, state.AssurancePolicyRevision != 0,
		state.ProviderEnabled && state.PlatformLoginLive && state.ConfigurationLive && state.AssurancePolicyLive,
		state.AccountMode, len(state.Matches), len(state.TrustRules),
		len(state.PlatformFloor.PolicyRevisions), len(state.LiveConfirmedTOTPFactors),
	)
}

func (state DirectPlatformPlanningState) GoString() string { return state.String() }

type DirectPlatformPlanningStateSource interface {
	LoadDirectPlatformPlanningState(context.Context, DirectPlatformPlanningLookup) (DirectPlatformPlanningState, error)
}

type DirectAuthenticationPlannerOptions struct {
	Source  DirectPlatformPlanningStateSource
	Keyring identity.Keyring
}

type DirectAuthenticationPlanner struct {
	source  DirectPlatformPlanningStateSource
	keyring identity.Keyring
}

func NewDirectAuthenticationPlanner(options DirectAuthenticationPlannerOptions) (*DirectAuthenticationPlanner, error) {
	if options.Source == nil || options.Keyring.ActiveVersion() < 1 {
		return nil, ErrDirectAuthenticationDenied
	}
	return &DirectAuthenticationPlanner{source: options.Source, keyring: options.Keyring}, nil
}

func (planner *DirectAuthenticationPlanner) String() string {
	return fmt.Sprintf(
		"platformoidcauth.DirectAuthenticationPlanner{configured:%t}",
		planner != nil && planner.source != nil && planner.keyring.ActiveVersion() > 0,
	)
}

func (planner *DirectAuthenticationPlanner) GoString() string { return planner.String() }

// DirectSubjectObservation carries only encrypted subject material plus all
// current aliases. Apply can observe the existing identity and add aliases
// for retained key versions without ever receiving plaintext subject bytes.
type DirectSubjectObservation struct {
	ExternalIdentityID identity.EntityID
	SubjectFormat      identity.SubjectFormat
	Aliases            []identity.SubjectAlias
	Envelope           identity.ExternalSubjectEnvelope
}

func (subject DirectSubjectObservation) String() string {
	return fmt.Sprintf(
		"platformoidcauth.DirectSubjectObservation{identity:%t,format:%d,aliases:%d,envelope:%q,subject:[REDACTED]}",
		subject.ExternalIdentityID != (identity.EntityID{}), subject.SubjectFormat,
		len(subject.Aliases), subject.Envelope.String(),
	)
}

func (subject DirectSubjectObservation) GoString() string { return subject.String() }

type DirectTOTPContinuation struct {
	FactorID identity.EntityID
	Revision uint64
}

func (continuation DirectTOTPContinuation) String() string {
	return fmt.Sprintf(
		"platformoidcauth.DirectTOTPContinuation{factor:%t,revision:%t}",
		continuation.FactorID != (identity.EntityID{}), continuation.Revision != 0,
	)
}

func (continuation DirectTOTPContinuation) GoString() string { return continuation.String() }

// DirectAuthenticationPlan contains no role, group, profile, email, or
// account-creation consequence. Every mutable authority used by a later
// apply is revision-pinned here.
type DirectAuthenticationPlan struct {
	Disposition                DirectAuthenticationDisposition
	Completion                 federatedoidc.TransactionCompletion
	Provider                   identity.ProviderContext
	UserID                     identity.EntityID
	ExternalIdentityID         identity.EntityID
	ProviderRevision           uint64
	PlatformLoginRevision      uint64
	ConfigurationRevision      uint64
	SecurityRevision           uint64
	PlanRevision               uint64
	AssurancePolicyRevision    uint64
	UserAuthenticationRevision uint64
	IdentityRevision           uint64
	MatchedAliasKeyVersion     int16
	Subject                    DirectSubjectObservation
	Evidence                   []identity.AssuranceEvidence
	SelectedAssurance          DirectSelectedAssurance
	PlatformFloor              identity.EffectiveAssuranceRequirement
	TOTP                       *DirectTOTPContinuation
	ValidUntil                 time.Time
}

func (plan DirectAuthenticationPlan) String() string {
	return fmt.Sprintf(
		"platformoidcauth.DirectAuthenticationPlan{disposition:%q,user:%t,identity:%t,providerRevision:%t,loginRevision:%t,configurationRevision:%t,securityRevision:%t,planRevision:%t,assuranceRevision:%t,userAuthenticationRevision:%t,identityRevision:%t,aliasKeyVersion:%t,evidence:%d,selectedAssurance:%q,totp:%t,validUntil:%t,subject:%q}",
		plan.Disposition, plan.UserID != (identity.EntityID{}), plan.ExternalIdentityID != (identity.EntityID{}),
		plan.ProviderRevision != 0, plan.PlatformLoginRevision != 0, plan.ConfigurationRevision != 0,
		plan.SecurityRevision != 0, plan.PlanRevision != 0, plan.AssurancePolicyRevision != 0,
		plan.UserAuthenticationRevision != 0, plan.IdentityRevision != 0, plan.MatchedAliasKeyVersion > 0,
		len(plan.Evidence), plan.SelectedAssurance.String(),
		plan.TOTP != nil, !plan.ValidUntil.IsZero(), plan.Subject.String(),
	)
}

func (plan DirectAuthenticationPlan) GoString() string { return plan.String() }

type directAuthenticationFacts struct {
	Completion      federatedoidc.TransactionCompletion
	ClaimAttemptID  federatedoidc.TransactionID
	ObservedAt      time.Time
	Issuer          string
	Subject         string
	IssuedAt        time.Time
	AuthenticatedAt time.Time
	ValidUntil      time.Time
	Scalars         []federatedoidc.NamedScalar
	Profiles        []federatedoidc.ProfileValue
	Groups          []string
	ACR             string
	AMR             []string
}

// Plan consumes the opaque result of the OIDC protocol kernel. Callers cannot
// construct a non-zero VerifiedAuthentication outside federatedoidc, and this
// boundary additionally requires its explicit direct-platform ceremony pins.
func (planner *DirectAuthenticationPlanner) Plan(
	ctx context.Context,
	request DirectOIDCTrustPlanRequest,
) (DirectAuthenticationPlan, error) {
	proof := request.Proof
	if proof == nil {
		return DirectAuthenticationPlan{}, ErrDirectAuthenticationDenied
	}
	completion := proof.Completion()
	completionPins, direct := directConfigurationPinsFromTransaction(completion.Pins)
	if !direct || !validTransactionID(request.TransactionID) ||
		!validTransactionID(request.ClaimAttemptID) || !validInstant(request.ObservedAt) ||
		!validDirectOIDCConfigurationPins(request.Pins) || completion.ID != request.TransactionID ||
		!sameDirectOIDCConfigurationPins(completionPins, request.Pins) {
		return DirectAuthenticationPlan{}, ErrDirectAuthenticationDenied
	}
	claims := proof.Claims()
	facts := directAuthenticationFacts{
		Completion: completion, ClaimAttemptID: request.ClaimAttemptID, ObservedAt: request.ObservedAt,
		Issuer: proof.Issuer(), Subject: proof.Subject(),
		IssuedAt: proof.IssuedAt(), AuthenticatedAt: proof.AuthenticatedAt(), ValidUntil: proof.ExpiresAt(),
		Scalars: claims.Scalars(), Profiles: claims.Profiles(), Groups: claims.Groups(),
		ACR: claims.ACR(), AMR: claims.AMR(),
	}
	return planner.plan(ctx, request.ObservedAt, facts)
}

func (planner *DirectAuthenticationPlanner) plan(
	ctx context.Context,
	now time.Time,
	facts directAuthenticationFacts,
) (DirectAuthenticationPlan, error) {
	if planner == nil || planner.source == nil || planner.keyring.ActiveVersion() < 1 ||
		ctx == nil || ctx.Err() != nil || !validDirectAuthenticationFacts(now, facts) {
		return DirectAuthenticationPlan{}, ErrDirectAuthenticationDenied
	}

	subject, err := identity.CanonicalOIDCIssuerSubject(facts.Issuer, facts.Subject)
	if err != nil {
		return DirectAuthenticationPlan{}, ErrDirectAuthenticationDenied
	}
	defer subject.Clear()
	transactionPins := facts.Completion.Pins
	pins, direct := directConfigurationPinsFromTransaction(transactionPins)
	if !direct || !validDirectOIDCConfigurationPins(pins) {
		return DirectAuthenticationPlan{}, ErrDirectAuthenticationDenied
	}
	aliases, err := planner.keyring.SubjectAliases(pins.Provider, subject)
	if err != nil {
		return DirectAuthenticationPlan{}, ErrDirectAuthenticationDenied
	}
	lookup := DirectPlatformPlanningLookup{
		TransactionID: facts.Completion.ID, ClaimAttemptID: facts.ClaimAttemptID,
		ObservedAt: now, Pins: pins,
		Provider: pins.Provider, SubjectFormat: subject.Format(), SubjectAliases: aliases,
		ProviderRevision: pins.ProviderRevision, PlatformLoginRevision: pins.PlatformLoginRevision,
		ConfigurationRevision: pins.ConfigurationRevision, SecurityRevision: pins.SecurityRevision,
		AssurancePolicyRevision: pins.AssurancePolicyRevision,
	}
	if !validDirectPlatformPlanningLookup(lookup) {
		return DirectAuthenticationPlan{}, ErrDirectAuthenticationDenied
	}

	state, loadErr := planner.source.LoadDirectPlatformPlanningState(ctx, cloneDirectPlatformPlanningLookup(lookup))
	state = cloneDirectPlatformPlanningState(state)
	if loadErr != nil || ctx.Err() != nil || !validDirectPlatformPlanningState(now, state, lookup) {
		return DirectAuthenticationPlan{}, ErrDirectAuthenticationDenied
	}
	match := state.Matches[0]
	evidence, selectedAssurance, ok := directProviderEvidence(
		pins.Provider.ProviderID, state.SecurityRevision, facts.AuthenticatedAt, facts.ValidUntil,
		cloneDirectOIDCTrustRules(state.TrustRules), facts.ACR, append([]string(nil), facts.AMR...),
	)
	if !ok || !validDirectSelectedAssurance(selectedAssurance) {
		return DirectAuthenticationPlan{}, ErrDirectAuthenticationDenied
	}

	disposition := DirectAuthenticationDisposition("")
	var continuation *DirectTOTPContinuation
	switch identity.EvaluateAssurance(now, state.PlatformFloor, evidence, false) {
	case identity.AssuranceSatisfied:
		disposition = DirectAuthenticationImmediateSession
	case identity.AssuranceStepUpRequired:
		factor, found := directTOTPContinuationFactor(now, state.PlatformFloor, evidence, match.UserID, state.LiveConfirmedTOTPFactors)
		if !found {
			return DirectAuthenticationPlan{}, ErrDirectAuthenticationDenied
		}
		disposition = DirectAuthenticationTOTPContinuation
		continuation = &DirectTOTPContinuation{FactorID: factor.FactorID, Revision: factor.Revision}
	default:
		return DirectAuthenticationPlan{}, ErrDirectAuthenticationDenied
	}

	envelope, err := planner.keyring.EncryptExternalSubject(identity.ExternalSubjectContext{
		Provider: pins.Provider, ExternalIdentityID: match.ExternalIdentityID,
	}, subject)
	if err != nil {
		return DirectAuthenticationPlan{}, ErrDirectAuthenticationDenied
	}
	observation := DirectSubjectObservation{
		ExternalIdentityID: match.ExternalIdentityID, SubjectFormat: subject.Format(),
		Aliases: append([]identity.SubjectAlias(nil), aliases...), Envelope: envelope,
	}
	return DirectAuthenticationPlan{
		Disposition: disposition, Completion: facts.Completion, Provider: pins.Provider,
		UserID: match.UserID, ExternalIdentityID: match.ExternalIdentityID,
		ProviderRevision: state.ProviderRevision, PlatformLoginRevision: state.PlatformLoginRevision,
		ConfigurationRevision: state.ConfigurationRevision, SecurityRevision: state.SecurityRevision,
		PlanRevision: state.PlanRevision, AssurancePolicyRevision: state.AssurancePolicyRevision,
		UserAuthenticationRevision: match.UserAuthenticationRevision,
		IdentityRevision:           match.IdentityRevision,
		MatchedAliasKeyVersion:     match.Alias.KeyVersion, Subject: observation,
		Evidence: cloneDirectEvidence(evidence), SelectedAssurance: cloneDirectSelectedAssurance(selectedAssurance),
		PlatformFloor: cloneDirectRequirement(state.PlatformFloor),
		TOTP:          continuation, ValidUntil: facts.ValidUntil,
	}, nil
}

func validDirectAuthenticationFacts(now time.Time, facts directAuthenticationFacts) bool {
	pins := facts.Completion.Pins
	loginRevision, direct := pins.DirectPlatformLogin()
	return validInstant(now) && direct && loginRevision == pins.PlatformLoginRevision &&
		validTransactionID(facts.ClaimAttemptID) && validInstant(facts.ObservedAt) &&
		facts.ObservedAt.Equal(now) &&
		validDirectProvider(pins.Provider) && validTransactionID(facts.Completion.ID) &&
		validDirectRevision(facts.Completion.ExpectedVersion) && validInstant(facts.Completion.CompletedAt) &&
		!facts.Completion.CompletedAt.After(now) &&
		validInstant(facts.IssuedAt) && validInstant(facts.AuthenticatedAt) &&
		validInstant(facts.ValidUntil) && !facts.AuthenticatedAt.After(now) &&
		facts.ValidUntil.After(now) && facts.ValidUntil.After(facts.AuthenticatedAt) &&
		validDirectRevision(pins.ProviderRevision) && validDirectRevision(pins.PlatformLoginRevision) &&
		validDirectRevision(pins.ConfigurationRevision) && validDirectRevision(pins.SecurityRevision) &&
		validDirectRevision(pins.PlanRevision) && validDirectRevision(pins.AssurancePolicyRevision) &&
		validDirectEntityID(pins.PlatformFloorPolicyID) && validDirectRevision(pins.PlatformFloorRevision) &&
		validDirectRevision(pins.ClientSecretRevision) &&
		validDirectRevision(pins.DiscoveryRevision) && pins.DiscoveryDigest != ([sha256.Size]byte{}) &&
		validDirectRevision(pins.JWKSRevision) && pins.JWKSDigest != ([sha256.Size]byte{}) &&
		len(facts.Scalars) == 0 && len(facts.Profiles) == 0 && len(facts.Groups) == 0
}

func validDirectPlatformPlanningLookup(lookup DirectPlatformPlanningLookup) bool {
	return validTransactionID(lookup.TransactionID) && validTransactionID(lookup.ClaimAttemptID) &&
		validInstant(lookup.ObservedAt) && validDirectOIDCConfigurationPins(lookup.Pins) &&
		lookup.Provider == lookup.Pins.Provider && lookup.ProviderRevision == lookup.Pins.ProviderRevision &&
		lookup.PlatformLoginRevision == lookup.Pins.PlatformLoginRevision &&
		lookup.ConfigurationRevision == lookup.Pins.ConfigurationRevision &&
		lookup.SecurityRevision == lookup.Pins.SecurityRevision &&
		lookup.AssurancePolicyRevision == lookup.Pins.AssurancePolicyRevision &&
		validDirectProvider(lookup.Provider) && lookup.SubjectFormat == identity.UTF8ExactSubject &&
		validDirectSubjectAliases(lookup.SubjectAliases) && validDirectRevision(lookup.ProviderRevision) &&
		validDirectRevision(lookup.PlatformLoginRevision) && validDirectRevision(lookup.ConfigurationRevision) &&
		validDirectRevision(lookup.SecurityRevision) && validDirectRevision(lookup.AssurancePolicyRevision)
}

func validDirectPlatformPlanningState(
	now time.Time,
	state DirectPlatformPlanningState,
	lookup DirectPlatformPlanningLookup,
) bool {
	if state.Provider != lookup.Provider || state.ProviderRevision != lookup.ProviderRevision ||
		state.PlatformLoginRevision != lookup.PlatformLoginRevision ||
		state.ConfigurationRevision != lookup.ConfigurationRevision ||
		state.SecurityRevision != lookup.SecurityRevision ||
		state.AssurancePolicyRevision != lookup.AssurancePolicyRevision ||
		state.PlanRevision != lookup.Pins.PlanRevision || !state.ProviderEnabled || !state.PlatformLoginLive ||
		!state.ConfigurationLive || !state.AssurancePolicyLive || state.AccountMode != AccountModeExistingIdentity ||
		len(state.Matches) != 1 || !validDirectOIDCTrustRules(state.TrustRules) ||
		!validDirectPinnedPlatformFloor(state.PlatformFloor, lookup.Pins) {
		return false
	}
	match := state.Matches[0]
	if match.ProviderID != lookup.Provider.ProviderID || !validDirectEntityID(match.ExternalIdentityID) ||
		!validDirectEntityID(match.UserID) || !match.IdentityLive || !match.AliasLive || !match.UserActive ||
		!validDirectRevision(match.IdentityRevision) ||
		!validDirectRevision(match.UserAuthenticationRevision) ||
		!directSubjectAliasPresent(lookup.SubjectAliases, match.Alias) {
		return false
	}
	return validDirectTOTPFactors(now, match.UserID, state.LiveConfirmedTOTPFactors)
}

func directTOTPContinuationFactor(
	now time.Time,
	requirement identity.EffectiveAssuranceRequirement,
	evidence []identity.AssuranceEvidence,
	userID identity.EntityID,
	factors []DirectPlatformTOTPFactor,
) (DirectPlatformTOTPFactor, bool) {
	factors = cloneDirectTOTPFactors(factors)
	if requirement.Level > identity.AssuranceMFA || !validDirectTOTPFactors(now, userID, factors) || len(factors) == 0 {
		return DirectPlatformTOTPFactor{}, false
	}
	slices.SortFunc(factors, func(left, right DirectPlatformTOTPFactor) int {
		return bytes.Compare(left.FactorID[:], right.FactorID[:])
	})
	selected := factors[0]
	revision := int64(selected.Revision)
	hypothetical := identity.AssuranceEvidence{
		Level: identity.AssuranceMFA, Kind: identity.AssuranceEvidenceFactor,
		Source: identity.AssuranceSource{Local: true}, AuthenticatedAt: now,
		FactorRevision: &revision,
	}
	candidate := append(cloneDirectEvidence(evidence), hypothetical)
	if identity.EvaluateAssurance(now, requirement, candidate, false) != identity.AssuranceSatisfied {
		return DirectPlatformTOTPFactor{}, false
	}
	return selected, true
}

func cloneDirectPlatformPlanningLookup(value DirectPlatformPlanningLookup) DirectPlatformPlanningLookup {
	value.SubjectAliases = append([]identity.SubjectAlias(nil), value.SubjectAliases...)
	return value
}

func cloneDirectPlatformPlanningState(value DirectPlatformPlanningState) DirectPlatformPlanningState {
	value.Matches = append([]DirectPlatformIdentityMatch(nil), value.Matches...)
	value.TrustRules = cloneDirectOIDCTrustRules(value.TrustRules)
	value.PlatformFloor = cloneDirectRequirement(value.PlatformFloor)
	value.LiveConfirmedTOTPFactors = cloneDirectTOTPFactors(value.LiveConfirmedTOTPFactors)
	return value
}

func cloneDirectRequirement(value identity.EffectiveAssuranceRequirement) identity.EffectiveAssuranceRequirement {
	value.PolicyRevisions = append([]identity.AssurancePolicyRevision(nil), value.PolicyRevisions...)
	if value.EnrollmentDeadline != nil {
		copyValue := *value.EnrollmentDeadline
		value.EnrollmentDeadline = &copyValue
	}
	return value
}

func cloneDirectTOTPFactors(values []DirectPlatformTOTPFactor) []DirectPlatformTOTPFactor {
	result := append([]DirectPlatformTOTPFactor(nil), values...)
	for index := range result {
		if values[index].ConfirmedAt != nil {
			copyValue := *values[index].ConfirmedAt
			result[index].ConfirmedAt = &copyValue
		}
	}
	return result
}

func cloneDirectEvidence(values []identity.AssuranceEvidence) []identity.AssuranceEvidence {
	result := append([]identity.AssuranceEvidence(nil), values...)
	for index := range result {
		if values[index].ExpiresAt != nil {
			copyValue := *values[index].ExpiresAt
			result[index].ExpiresAt = &copyValue
		}
		if values[index].FactorRevision != nil {
			copyValue := *values[index].FactorRevision
			result[index].FactorRevision = &copyValue
		}
		if values[index].TrustRuleRevision != nil {
			copyValue := *values[index].TrustRuleRevision
			result[index].TrustRuleRevision = &copyValue
		}
	}
	return result
}

func cloneDirectSelectedAssurance(value DirectSelectedAssurance) DirectSelectedAssurance {
	if value.TrustRuleID != nil {
		copyValue := *value.TrustRuleID
		value.TrustRuleID = &copyValue
	}
	if value.TrustRuleRevision != nil {
		copyValue := *value.TrustRuleRevision
		value.TrustRuleRevision = &copyValue
	}
	return value
}

func validDirectSubjectAliases(values []identity.SubjectAlias) bool {
	if len(values) < 1 || len(values) > maximumDirectSubjectAliases {
		return false
	}
	for index, alias := range values {
		if alias.KeyVersion < 1 || alias.Digest == ([sha256.Size]byte{}) ||
			index > 0 && values[index-1].KeyVersion >= alias.KeyVersion {
			return false
		}
	}
	return true
}

func directSubjectAliasPresent(values []identity.SubjectAlias, wanted identity.SubjectAlias) bool {
	for _, value := range values {
		if value.KeyVersion == wanted.KeyVersion &&
			subtle.ConstantTimeCompare(value.Digest[:], wanted.Digest[:]) == 1 {
			return true
		}
	}
	return false
}

func validDirectTOTPFactors(now time.Time, userID identity.EntityID, values []DirectPlatformTOTPFactor) bool {
	if len(values) > maximumDirectTOTPFactors {
		return false
	}
	seen := make(map[identity.EntityID]struct{}, len(values))
	for _, value := range values {
		if !validDirectEntityID(value.FactorID) || value.UserID != userID || !value.Active ||
			!validDirectRevision(value.Revision) || value.ConfirmedAt == nil ||
			!validInstant(*value.ConfirmedAt) || value.ConfirmedAt.After(now) {
			return false
		}
		if _, duplicate := seen[value.FactorID]; duplicate {
			return false
		}
		seen[value.FactorID] = struct{}{}
	}
	return true
}

func validDirectRequirementIDs(value identity.EffectiveAssuranceRequirement) bool {
	for _, revision := range value.PolicyRevisions {
		if !validDirectEntityID(revision.PolicyID) {
			return false
		}
	}
	return true
}

func validDirectProvider(provider identity.ProviderContext) bool {
	return provider.Scope == identity.PlatformProviderScope && provider.TenantID == (identity.EntityID{}) &&
		validDirectEntityID(provider.ProviderID)
}

func validDirectRevision(value uint64) bool {
	return value > 0 && value <= uint64(maximumExactRevision)
}

func validTransactionID(value federatedoidc.TransactionID) bool {
	return value != (federatedoidc.TransactionID{})
}

func validDirectEntityID(value identity.EntityID) bool {
	if value == (identity.EntityID{}) || value[6]>>4 != 7 || value[8]&0xc0 != 0x80 {
		return false
	}
	milliseconds := uint64(value[0])<<40 | uint64(value[1])<<32 |
		uint64(value[2])<<24 | uint64(value[3])<<16 |
		uint64(value[4])<<8 | uint64(value[5])
	return milliseconds <= maximumUUIDUnixMilliseconds && binary.BigEndian.Uint64(value[8:]) != 0
}
