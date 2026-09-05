package postgres

import (
	"context"
	"crypto/sha256"
	"slices"
	"strings"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/services/api/internal/platformsamlauth"
)

const (
	loadPlatformSAMLPlanningStateSQL     = `select app.load_platform_saml_planning_state_v1($1::jsonb)`
	maximumPlatformSAMLPlanningWireBytes = 1024 * 1024
)

type platformSAMLSubjectAliasWire struct {
	KeyVersion int16  `json:"keyVersion"`
	Digest     []byte `json:"digest"`
}

type platformSAMLPlanningLookupWire struct {
	TransactionID  []byte                         `json:"transactionId"`
	ObservedAt     time.Time                      `json:"observedAt"`
	Pins           platformSAMLDirectPinsWire     `json:"pins"`
	SubjectFormat  identity.SubjectFormat         `json:"subjectFormat"`
	SubjectAliases []platformSAMLSubjectAliasWire `json:"subjectAliases"`
}

type platformSAMLIdentityMatchWire struct {
	ProviderID                     string                       `json:"providerId"`
	ExternalIdentityID             string                       `json:"externalIdentityId"`
	UserID                         string                       `json:"userId"`
	Alias                          platformSAMLSubjectAliasWire `json:"alias"`
	IdentityRevision               uint64                       `json:"identityRevision"`
	UserAuthenticationRevision     uint64                       `json:"userAuthenticationRevision"`
	PlatformAuthorityID            string                       `json:"platformAuthorityId"`
	PlatformAuthorityRevision      uint64                       `json:"platformAuthorityRevision"`
	IdentityLive                   bool                         `json:"identityLive"`
	AliasLive                      bool                         `json:"aliasLive"`
	UserActive                     bool                         `json:"userActive"`
	ProtectedPlatformAuthorityLive bool                         `json:"protectedPlatformAuthorityLive"`
}

type platformSAMLTOTPFactorWire struct {
	FactorID    string     `json:"factorId"`
	UserID      string     `json:"userId"`
	Revision    uint64     `json:"revision"`
	Active      bool       `json:"active"`
	ConfirmedAt *time.Time `json:"confirmedAt"`
}

type platformSAMLPlanningStateWire struct {
	Pins                     platformSAMLDirectPinsWire      `json:"pins"`
	ProviderKind             string                          `json:"providerKind"`
	ProviderEnabled          bool                            `json:"providerEnabled"`
	PlatformLoginLive        bool                            `json:"platformLoginLive"`
	ConfigurationLive        bool                            `json:"configurationLive"`
	AssurancePolicyLive      bool                            `json:"assurancePolicyLive"`
	Matches                  []platformSAMLIdentityMatchWire `json:"matches"`
	TrustRules               []platformSAMLTrustRuleWire     `json:"trustRules"`
	PlatformFloor            assurancePolicyWire             `json:"platformFloor"`
	LiveConfirmedTOTPFactors []platformSAMLTOTPFactorWire    `json:"liveConfirmedTotpFactors"`
}

var _ platformsamlauth.PlanningStateSource = (*FederatedAuthRepository)(nil)

func (repository *FederatedAuthRepository) LoadDirectSAMLPlanningState(
	ctx context.Context,
	lookup platformsamlauth.PlanningLookup,
) (platformsamlauth.PlanningState, error) {
	wire, err := platformSAMLPlanningLookupToWire(lookup)
	if err != nil {
		return platformsamlauth.PlanningState{}, errPlatformSAMLPersistence
	}
	defer clearPlatformSAMLPlanningLookupWire(&wire)
	var response platformSAMLPlanningStateWire
	defer clearPlatformSAMLPlanningStateWire(&response)
	if err = repository.queryJSONWithResponseLimit(
		ctx, loadPlatformSAMLPlanningStateSQL, wire, &response, maximumPlatformSAMLPlanningWireBytes,
	); err != nil || ctx.Err() != nil {
		return platformsamlauth.PlanningState{}, errPlatformSAMLPersistence
	}
	return platformSAMLPlanningStateFromWire(response, lookup)
}

func platformSAMLPlanningLookupToWire(
	lookup platformsamlauth.PlanningLookup,
) (platformSAMLPlanningLookupWire, error) {
	pins, err := platformSAMLDirectPinsToWire(lookup.Pins)
	if err != nil || lookup.TransactionID == ([sha256.Size]byte{}) ||
		!validPlatformSAMLInstant(lookup.ObservedAt) || lookup.SubjectFormat != identity.UTF8ExactSubject ||
		len(lookup.SubjectAliases) < 1 || len(lookup.SubjectAliases) > 16 {
		return platformSAMLPlanningLookupWire{}, errPlatformSAMLPersistence
	}
	aliases := make([]platformSAMLSubjectAliasWire, len(lookup.SubjectAliases))
	for index, alias := range lookup.SubjectAliases {
		if alias.KeyVersion < 1 || alias.Digest == ([sha256.Size]byte{}) ||
			index > 0 && lookup.SubjectAliases[index-1].KeyVersion >= alias.KeyVersion {
			clearPlatformSAMLSubjectAliasesWire(aliases)
			return platformSAMLPlanningLookupWire{}, errPlatformSAMLPersistence
		}
		aliases[index] = platformSAMLSubjectAliasWire{
			KeyVersion: alias.KeyVersion, Digest: append([]byte(nil), alias.Digest[:]...),
		}
	}
	return platformSAMLPlanningLookupWire{
		TransactionID: append([]byte(nil), lookup.TransactionID[:]...), ObservedAt: lookup.ObservedAt,
		Pins: pins, SubjectFormat: lookup.SubjectFormat, SubjectAliases: aliases,
	}, nil
}

func platformSAMLPlanningStateFromWire(
	wire platformSAMLPlanningStateWire,
	lookup platformsamlauth.PlanningLookup,
) (platformsamlauth.PlanningState, error) {
	pins, err := platformSAMLDirectPinsFromWire(wire.Pins)
	floor, floorErr := assurancePolicyFromWire(wire.PlatformFloor)
	if err != nil || floorErr != nil || pins != lookup.Pins || wire.ProviderKind != platformsamlauth.ProviderKindSAML ||
		!wire.ProviderEnabled || !wire.PlatformLoginLive || !wire.ConfigurationLive || !wire.AssurancePolicyLive ||
		len(wire.Matches) != 1 || len(wire.TrustRules) > 64 || len(wire.LiveConfirmedTOTPFactors) > 32 {
		return platformsamlauth.PlanningState{}, errPlatformSAMLPersistence
	}
	if floor.ID != lookup.Pins.PlatformFloorPolicyID || floor.Revision < 1 ||
		uint64(floor.Revision) != lookup.Pins.PlatformFloorPolicyRevision {
		return platformsamlauth.PlanningState{}, errPlatformSAMLPersistence
	}
	requirement, requirementErr := identity.CombineAssurancePolicies([]identity.AssurancePolicy{floor})
	if requirementErr != nil {
		return platformsamlauth.PlanningState{}, errPlatformSAMLPersistence
	}
	matches := make([]platformsamlauth.IdentityMatch, len(wire.Matches))
	for index, match := range wire.Matches {
		providerID, providerErr := parseEntityIDWire(match.ProviderID, false)
		externalID, externalErr := parseEntityIDWire(match.ExternalIdentityID, false)
		userID, userErr := parseEntityIDWire(match.UserID, false)
		authorityID, authorityErr := parseEntityIDWire(match.PlatformAuthorityID, false)
		if providerErr != nil || externalErr != nil || userErr != nil || authorityErr != nil ||
			providerID != lookup.Pins.Protocol.Provider.ProviderID || !validPlatformSAMLRevision(match.IdentityRevision) ||
			!validPlatformSAMLRevision(match.UserAuthenticationRevision) ||
			!validPlatformSAMLRevision(match.PlatformAuthorityRevision) || !match.IdentityLive || !match.AliasLive ||
			!match.UserActive || !match.ProtectedPlatformAuthorityLive || match.Alias.KeyVersion < 1 ||
			len(match.Alias.Digest) != sha256.Size {
			return platformsamlauth.PlanningState{}, errPlatformSAMLPersistence
		}
		var aliasDigest [sha256.Size]byte
		copy(aliasDigest[:], match.Alias.Digest)
		alias := identity.SubjectAlias{KeyVersion: match.Alias.KeyVersion, Digest: aliasDigest}
		if !slices.Contains(lookup.SubjectAliases, alias) {
			return platformsamlauth.PlanningState{}, errPlatformSAMLPersistence
		}
		matches[index] = platformsamlauth.IdentityMatch{
			ProviderID: providerID, ExternalIdentityID: externalID, UserID: userID, Alias: alias,
			IdentityRevision: match.IdentityRevision, UserAuthenticationRevision: match.UserAuthenticationRevision,
			PlatformAuthorityID: authorityID, PlatformAuthorityRevision: match.PlatformAuthorityRevision,
			IdentityLive: true, AliasLive: true, UserActive: true, ProtectedPlatformAuthorityLive: true,
		}
	}
	trustRules := make([]platformsamlauth.TrustRule, len(wire.TrustRules))
	seenClasses := make(map[string]struct{}, len(wire.TrustRules))
	for index, rule := range wire.TrustRules {
		ruleID, ruleErr := parseEntityIDWire(firstPlatformSAMLNonempty(rule.RuleID, rule.ID), false)
		level, levelErr := assuranceLevelFromWire(rule.Level)
		if ruleErr != nil || levelErr != nil || !rule.Enabled || !validPlatformSAMLRevision(rule.Revision) ||
			strings.TrimSpace(rule.ClassRef) != rule.ClassRef || rule.ClassRef == "" ||
			rule.MaximumAuthenticationAgeSeconds < 60 || rule.MaximumAuthenticationAgeSeconds > 86400 {
			return platformsamlauth.PlanningState{}, errPlatformSAMLPersistence
		}
		if _, duplicate := seenClasses[rule.ClassRef]; duplicate {
			return platformsamlauth.PlanningState{}, errPlatformSAMLPersistence
		}
		seenClasses[rule.ClassRef] = struct{}{}
		trustRules[index] = platformsamlauth.TrustRule{
			RuleID: ruleID, Revision: rule.Revision, Enabled: true, ClassRef: rule.ClassRef,
			Level: level, MaximumAuthenticationAge: time.Duration(rule.MaximumAuthenticationAgeSeconds) * time.Second,
		}
	}
	factors := make([]platformsamlauth.TOTPFactor, len(wire.LiveConfirmedTOTPFactors))
	for index, factor := range wire.LiveConfirmedTOTPFactors {
		factorID, factorErr := parseEntityIDWire(factor.FactorID, false)
		userID, userErr := parseEntityIDWire(factor.UserID, false)
		if factorErr != nil || userErr != nil || !factor.Active || factor.ConfirmedAt == nil ||
			!validPlatformSAMLRevision(factor.Revision) {
			return platformsamlauth.PlanningState{}, errPlatformSAMLPersistence
		}
		confirmedAt := platformSAMLUTC(*factor.ConfirmedAt)
		if !validPlatformSAMLInstant(confirmedAt) || confirmedAt.After(lookup.ObservedAt) {
			return platformsamlauth.PlanningState{}, errPlatformSAMLPersistence
		}
		factors[index] = platformsamlauth.TOTPFactor{
			FactorID: factorID, UserID: userID, Revision: factor.Revision, Active: true, ConfirmedAt: &confirmedAt,
		}
	}
	return platformsamlauth.PlanningState{
		Pins: pins, ProviderKind: wire.ProviderKind, ProviderEnabled: true, PlatformLoginLive: true,
		ConfigurationLive: true, AssurancePolicyLive: true, Matches: matches, TrustRules: trustRules,
		PlatformFloor: requirement, LiveConfirmedTOTPFactors: factors,
	}, nil
}

func firstPlatformSAMLNonempty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func clearPlatformSAMLSubjectAliasesWire(values []platformSAMLSubjectAliasWire) {
	for index := range values {
		clear(values[index].Digest)
	}
}

func clearPlatformSAMLPlanningLookupWire(value *platformSAMLPlanningLookupWire) {
	if value == nil {
		return
	}
	clear(value.TransactionID)
	clearPlatformSAMLProtocolPinsWire(&value.Pins.Protocol)
	clearPlatformSAMLSubjectAliasesWire(value.SubjectAliases)
	*value = platformSAMLPlanningLookupWire{}
}

func clearPlatformSAMLPlanningStateWire(value *platformSAMLPlanningStateWire) {
	if value == nil {
		return
	}
	clearPlatformSAMLProtocolPinsWire(&value.Pins.Protocol)
	for index := range value.Matches {
		clear(value.Matches[index].Alias.Digest)
	}
	*value = platformSAMLPlanningStateWire{}
}
