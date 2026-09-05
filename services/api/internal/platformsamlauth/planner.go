package platformsamlauth

import (
	"bytes"
	"context"
	"crypto/subtle"
	"fmt"
	"slices"
	"strings"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
)

const (
	maximumSubjectAliases = 16
	maximumTrustRules     = 64
	maximumTOTPFactors    = 64
)

type PlannerOptions struct {
	Source  PlanningStateSource
	Keyring identity.Keyring
}

// Planner selects only one already-linked, live platform identity and one
// already-authorized protected platform authority. Assertion attributes can
// never create an identity, assign a role, or influence authorization.
type Planner struct {
	source  PlanningStateSource
	keyring identity.Keyring
}

func NewPlanner(options PlannerOptions) (*Planner, error) {
	if options.Source == nil || options.Keyring.ActiveVersion() < 1 {
		return nil, ErrInvalidOptions
	}
	return &Planner{source: options.Source, keyring: options.Keyring}, nil
}

func (planner *Planner) String() string {
	return fmt.Sprintf(
		"platformsamlauth.Planner{configured:%t}",
		planner != nil && planner.source != nil && planner.keyring.ActiveVersion() > 0,
	)
}

func (planner *Planner) GoString() string { return planner.String() }

func (planner *Planner) plan(
	ctx context.Context,
	consumption Consumption,
	pins DirectSAMLPins,
	configuration federatedsaml.Configuration,
	observedAt time.Time,
) (AuthenticationPlan, error) {
	if planner == nil || planner.source == nil || planner.keyring.ActiveVersion() < 1 ||
		ctx == nil || ctx.Err() != nil || !validInstant(observedAt) ||
		!validConsumptionForConfiguration(consumption, pins, configuration, observedAt) {
		return AuthenticationPlan{}, ErrAuthenticationDenied
	}
	proof := consumption.Authentication
	subject, err := identity.CanonicalSAMLSubjectTuple(
		proof.Issuer, string(proof.SubjectSource), proof.SubjectName, proof.SubjectFormat, proof.SubjectValue,
	)
	if err != nil {
		return AuthenticationPlan{}, ErrAuthenticationDenied
	}
	defer subject.Clear()
	aliases, err := planner.keyring.SubjectAliases(pins.Protocol.Provider, subject)
	if err != nil {
		return AuthenticationPlan{}, ErrAuthenticationDenied
	}
	lookup := PlanningLookup{
		TransactionID: consumption.TransactionID, ObservedAt: observedAt, Pins: pins,
		SubjectFormat: subject.Format(), SubjectAliases: append([]identity.SubjectAlias(nil), aliases...),
	}
	if !validPlanningLookup(lookup) {
		return AuthenticationPlan{}, ErrAuthenticationDenied
	}
	state, err := planner.source.LoadDirectSAMLPlanningState(ctx, clonePlanningLookup(lookup))
	state = clonePlanningState(state)
	if err != nil {
		return AuthenticationPlan{}, ErrAuthenticationUnavailable
	}
	if ctx.Err() != nil {
		return AuthenticationPlan{}, ErrAuthenticationUnavailable
	}
	if !validPlanningState(observedAt, state, lookup, configuration) {
		return AuthenticationPlan{}, ErrAuthenticationDenied
	}
	match := state.Matches[0]
	evidence, selected, ok := directSAMLEvidence(
		pins.Protocol.Provider.ProviderID, pins.Protocol.SecurityRevision,
		proof.AuthenticatedAt, proof.ValidUntil, state.TrustRules, proof.AuthnContext,
	)
	if !ok {
		return AuthenticationPlan{}, ErrAuthenticationDenied
	}

	disposition := Disposition("")
	var selectedTOTP *TOTPSelection
	switch identity.EvaluateAssurance(observedAt, state.PlatformFloor, evidence, false) {
	case identity.AssuranceSatisfied:
		disposition = ImmediateSession
	case identity.AssuranceStepUpRequired:
		factor, found := selectTOTPFactor(
			observedAt, state.PlatformFloor, evidence, match.UserID, state.LiveConfirmedTOTPFactors,
		)
		if !found {
			return AuthenticationPlan{}, ErrAuthenticationDenied
		}
		disposition = TOTPContinuation
		selectedTOTP = &TOTPSelection{FactorID: factor.FactorID, Revision: factor.Revision}
	default:
		return AuthenticationPlan{}, ErrAuthenticationDenied
	}

	envelope, err := planner.keyring.EncryptExternalSubject(identity.ExternalSubjectContext{
		Provider: pins.Protocol.Provider, ExternalIdentityID: match.ExternalIdentityID,
	}, subject)
	if err != nil {
		return AuthenticationPlan{}, ErrAuthenticationUnavailable
	}
	observation := SubjectObservation{
		ExternalIdentityID: match.ExternalIdentityID, SubjectFormat: subject.Format(),
		Aliases: append([]identity.SubjectAlias(nil), aliases...), Envelope: envelope,
	}
	return AuthenticationPlan{
		Disposition: disposition, Pins: pins,
		Provenance: Provenance{
			Provider: pins.Protocol.Provider, ProviderKind: ProviderKindSAML,
			ExternalIdentityID: match.ExternalIdentityID, UserID: match.UserID,
			IdentityRevision:           match.IdentityRevision,
			UserAuthenticationRevision: match.UserAuthenticationRevision,
			PlatformAuthorityID:        match.PlatformAuthorityID,
			PlatformAuthorityRevision:  match.PlatformAuthorityRevision,
			MatchedAliasKeyVersion:     match.Alias.KeyVersion,
			Issuer:                     proof.Issuer, AuthnContext: proof.AuthnContext,
			AuthenticatedAt: proof.AuthenticatedAt, ValidUntil: proof.ValidUntil,
			SelectedAssurance: selected,
		},
		Subject: observation, Evidence: cloneEvidence(evidence),
		PlatformFloor: cloneRequirement(state.PlatformFloor), TOTP: selectedTOTP,
	}, nil
}

func directSAMLEvidence(
	providerID identity.EntityID,
	securityRevision uint64,
	authenticatedAt time.Time,
	validUntil time.Time,
	rules []TrustRule,
	authnContext string,
) ([]identity.AssuranceEvidence, SelectedAssurance, bool) {
	if !validUUIDv7(providerID) || !validRevision(securityRevision) || !validInstant(authenticatedAt) ||
		!validInstant(validUntil) || !validUntil.After(authenticatedAt) ||
		!validTrustRules(rules) || !validText(authnContext, 4*1024, false) {
		return nil, SelectedAssurance{}, false
	}
	security := int64(securityRevision)
	primaryExpiry := validUntil
	evidence := []identity.AssuranceEvidence{{
		Level: identity.AssurancePrimary, Kind: identity.AssuranceEvidenceFactor,
		Source:          identity.AssuranceSource{DirectPlatform: true, ProviderID: providerID},
		AuthenticatedAt: authenticatedAt, ExpiresAt: &primaryExpiry, TrustRuleRevision: &security,
	}}
	selected := SelectedAssurance{Level: identity.AssurancePrimary, AuthenticatedAt: authenticatedAt}
	for _, rule := range rules {
		if !rule.Enabled || rule.ClassRef != authnContext {
			continue
		}
		expiresAt := authenticatedAt.Add(rule.MaximumAuthenticationAge)
		if validUntil.Before(expiresAt) {
			expiresAt = validUntil
		}
		if !validInstant(expiresAt) || !expiresAt.After(authenticatedAt) {
			return nil, SelectedAssurance{}, false
		}
		revision := int64(rule.Revision)
		evidence = append(evidence, identity.AssuranceEvidence{
			Level: rule.Level, Kind: identity.AssuranceEvidenceFactor,
			Source:          identity.AssuranceSource{DirectPlatform: true, ProviderID: providerID},
			AuthenticatedAt: authenticatedAt, ExpiresAt: &expiresAt, TrustRuleRevision: &revision,
		})
		ruleID := rule.RuleID
		ruleRevision := rule.Revision
		selected = SelectedAssurance{
			Level: rule.Level, AuthenticatedAt: authenticatedAt,
			TrustRuleID: &ruleID, TrustRuleRevision: &ruleRevision,
		}
		break
	}
	return evidence, selected, true
}

func selectTOTPFactor(
	now time.Time,
	requirement identity.EffectiveAssuranceRequirement,
	evidence []identity.AssuranceEvidence,
	userID identity.EntityID,
	factors []TOTPFactor,
) (TOTPFactor, bool) {
	factors = cloneTOTPFactors(factors)
	if requirement.Level > identity.AssuranceMFA || !validTOTPFactors(now, userID, factors) || len(factors) == 0 {
		return TOTPFactor{}, false
	}
	slices.SortFunc(factors, func(left, right TOTPFactor) int {
		return bytes.Compare(left.FactorID[:], right.FactorID[:])
	})
	selected := factors[0]
	revision := int64(selected.Revision)
	hypothetical := identity.AssuranceEvidence{
		Level: identity.AssuranceMFA, Kind: identity.AssuranceEvidenceFactor,
		Source: identity.AssuranceSource{Local: true}, AuthenticatedAt: now, FactorRevision: &revision,
	}
	if identity.EvaluateAssurance(
		now, requirement, append(cloneEvidence(evidence), hypothetical), false,
	) != identity.AssuranceSatisfied {
		return TOTPFactor{}, false
	}
	return selected, true
}

func validPlanningLookup(lookup PlanningLookup) bool {
	return lookup.TransactionID != (federatedsaml.TransactionID{}) && validInstant(lookup.ObservedAt) &&
		validDirectSAMLPins(lookup.Pins) && lookup.SubjectFormat == identity.UTF8ExactSubject &&
		validSubjectAliases(lookup.SubjectAliases)
}

func validPlanningState(
	now time.Time,
	state PlanningState,
	lookup PlanningLookup,
	configuration federatedsaml.Configuration,
) bool {
	if state.Pins != lookup.Pins || state.ProviderKind != ProviderKindSAML || !state.ProviderEnabled ||
		!state.PlatformLoginLive || !state.ConfigurationLive || !state.AssurancePolicyLive ||
		len(state.Matches) != 1 || !validTrustRules(state.TrustRules) ||
		!trustRulesMatchConfiguration(state.TrustRules, configuration.TrustRules) ||
		!validPinnedFloor(state.PlatformFloor, lookup.Pins) {
		return false
	}
	match := state.Matches[0]
	if match.ProviderID != lookup.Pins.Protocol.Provider.ProviderID ||
		!validUUIDv7(match.ExternalIdentityID) || !validUUIDv7(match.UserID) ||
		!validRevision(match.IdentityRevision) || !validRevision(match.UserAuthenticationRevision) ||
		!validUUIDv7(match.PlatformAuthorityID) || !validRevision(match.PlatformAuthorityRevision) ||
		!match.IdentityLive || !match.AliasLive || !match.UserActive || !match.ProtectedPlatformAuthorityLive ||
		!subjectAliasPresent(lookup.SubjectAliases, match.Alias) {
		return false
	}
	return validTOTPFactors(now, match.UserID, state.LiveConfirmedTOTPFactors)
}

func validTrustRules(rules []TrustRule) bool {
	if len(rules) > maximumTrustRules {
		return false
	}
	seenIDs := make(map[identity.EntityID]struct{}, len(rules))
	seenClasses := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		if !validUUIDv7(rule.RuleID) || !validRevision(rule.Revision) || !rule.Enabled ||
			!validText(rule.ClassRef, 4*1024, false) ||
			(rule.Level != identity.AssuranceMFA && rule.Level != identity.AssurancePhishingResistant) ||
			rule.MaximumAuthenticationAge < time.Minute || rule.MaximumAuthenticationAge > 24*time.Hour ||
			rule.MaximumAuthenticationAge%time.Second != 0 {
			return false
		}
		if _, duplicate := seenIDs[rule.RuleID]; duplicate {
			return false
		}
		if _, duplicate := seenClasses[rule.ClassRef]; duplicate {
			return false
		}
		seenIDs[rule.RuleID] = struct{}{}
		seenClasses[rule.ClassRef] = struct{}{}
	}
	return true
}

func trustRulesMatchConfiguration(rules []TrustRule, configured []federatedsaml.AuthnContextTrustRule) bool {
	if len(rules) != len(configured) {
		return false
	}
	left := append([]TrustRule(nil), rules...)
	right := append([]federatedsaml.AuthnContextTrustRule(nil), configured...)
	slices.SortFunc(left, func(a, b TrustRule) int { return strings.Compare(a.ClassRef, b.ClassRef) })
	slices.SortFunc(right, func(a, b federatedsaml.AuthnContextTrustRule) int {
		return strings.Compare(a.ClassRef, b.ClassRef)
	})
	for index := range left {
		if left[index].ClassRef != right[index].ClassRef || left[index].Level != right[index].Level ||
			left[index].Revision != uint64(right[index].Revision) ||
			left[index].MaximumAuthenticationAge != right[index].MaxAge {
			return false
		}
	}
	return true
}

func validTOTPFactors(now time.Time, userID identity.EntityID, factors []TOTPFactor) bool {
	if !validUUIDv7(userID) || len(factors) > maximumTOTPFactors {
		return false
	}
	seen := make(map[identity.EntityID]struct{}, len(factors))
	for _, factor := range factors {
		if !validUUIDv7(factor.FactorID) || factor.UserID != userID || !validRevision(factor.Revision) ||
			!factor.Active || factor.ConfirmedAt == nil || !validInstant(*factor.ConfirmedAt) || factor.ConfirmedAt.After(now) {
			return false
		}
		if _, duplicate := seen[factor.FactorID]; duplicate {
			return false
		}
		seen[factor.FactorID] = struct{}{}
	}
	return true
}

func validPinnedFloor(requirement identity.EffectiveAssuranceRequirement, pins DirectSAMLPins) bool {
	if len(requirement.PolicyRevisions) != 1 || requirement.PolicyRevisions[0].PolicyID != pins.PlatformFloorPolicyID ||
		requirement.PolicyRevisions[0].Revision != int64(pins.PlatformFloorPolicyRevision) {
		return false
	}
	// EvaluateAssurance is also the canonical structural validator. A fresh,
	// empty provider evidence set must never accidentally satisfy the floor.
	decision := identity.EvaluateAssurance(time.Unix(1, 0).UTC(), requirement, nil, false)
	return decision == identity.AssuranceStepUpRequired || decision == identity.AssuranceEnrollmentOnly ||
		decision == identity.AssuranceEnrollmentEnded
}

func validSubjectAliases(aliases []identity.SubjectAlias) bool {
	if len(aliases) < 1 || len(aliases) > maximumSubjectAliases {
		return false
	}
	for index, alias := range aliases {
		if alias.KeyVersion < 1 || alias.Digest == ([32]byte{}) ||
			index > 0 && aliases[index-1].KeyVersion >= alias.KeyVersion {
			return false
		}
	}
	return true
}

func subjectAliasPresent(aliases []identity.SubjectAlias, wanted identity.SubjectAlias) bool {
	for _, alias := range aliases {
		if alias.KeyVersion == wanted.KeyVersion && subtle.ConstantTimeCompare(alias.Digest[:], wanted.Digest[:]) == 1 {
			return true
		}
	}
	return false
}

func validSelectedAssurance(value SelectedAssurance) bool {
	if !validInstant(value.AuthenticatedAt) {
		return false
	}
	if value.Level == identity.AssurancePrimary {
		return value.TrustRuleID == nil && value.TrustRuleRevision == nil
	}
	return (value.Level == identity.AssuranceMFA || value.Level == identity.AssurancePhishingResistant) &&
		value.TrustRuleID != nil && validUUIDv7(*value.TrustRuleID) && value.TrustRuleRevision != nil &&
		validRevision(*value.TrustRuleRevision)
}
