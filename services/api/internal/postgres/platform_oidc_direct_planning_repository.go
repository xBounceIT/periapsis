package postgres

import (
	"context"
	"slices"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/services/api/internal/platformoidcauth"
)

const (
	resolvePlatformOIDCDirectIdentitySQL = `select app.resolve_platform_oidc_authentication_v1($1::jsonb)`
	loadPlatformOIDCDirectTrustSQL       = `select app.load_platform_oidc_trust_snapshot_v1($1::jsonb)`
	loadPlatformOIDCDirectPlanningSQL    = `select app.load_platform_oidc_planning_state_v1($1::jsonb)`

	maximumPlatformOIDCDirectPlanningWireBytes = 256 * 1024
	maximumPlatformOIDCDirectTrustRules        = 1_024
	maximumPlatformOIDCDirectTrustValues       = 128
)

type platformOIDCDirectSubjectAliasWire struct {
	KeyVersion int16  `json:"keyVersion"`
	Digest     []byte `json:"digest"`
}

type platformOIDCDirectResolveLookupWire struct {
	TransactionID  []byte                             `json:"transactionId"`
	ClaimAttemptID []byte                             `json:"claimAttemptId"`
	Provider       federatedProviderBindingWire       `json:"provider"`
	SubjectAlias   platformOIDCDirectSubjectAliasWire `json:"subjectAlias"`
	ObservedAt     time.Time                          `json:"observedAt"`
}

type platformOIDCDirectResolveWire struct {
	Provider                   federatedProviderBindingWire `json:"provider"`
	ExternalIdentityID         string                       `json:"externalIdentityId"`
	UserID                     string                       `json:"userId"`
	IdentityVersion            uint64                       `json:"identityVersion"`
	AliasKeyVersion            int16                        `json:"aliasKeyVersion"`
	UserAuthenticationRevision uint64                       `json:"userAuthenticationRevision"`
	AccountMode                string                       `json:"accountMode"`
	Pins                       platformOIDCDirectPinsWire   `json:"pins"`
}

type platformOIDCDirectPinnedLookupWire struct {
	Provider federatedProviderBindingWire `json:"provider"`
	Pins     platformOIDCDirectPinsWire   `json:"pins"`
}

type platformOIDCDirectTrustRuleWire struct {
	ID                              string   `json:"id"`
	Revision                        uint64   `json:"revision"`
	Level                           string   `json:"level"`
	ExactValue                      *string  `json:"exactValue"`
	RequiredValues                  []string `json:"requiredValues"`
	MaximumAuthenticationAgeSeconds int64    `json:"maximumAuthenticationAgeSeconds"`
}

type platformOIDCDirectTrustWire struct {
	Provider                federatedProviderBindingWire      `json:"provider"`
	AssurancePolicyRevision uint64                            `json:"assurancePolicyRevision"`
	Rules                   []platformOIDCDirectTrustRuleWire `json:"rules"`
}

type platformOIDCDirectPlanningLookupWire struct {
	TransactionID              []byte    `json:"transactionId"`
	ClaimAttemptID             []byte    `json:"claimAttemptId"`
	ExternalIdentityID         string    `json:"externalIdentityId"`
	UserID                     string    `json:"userId"`
	IdentityVersion            uint64    `json:"identityVersion"`
	AliasKeyVersion            int16     `json:"aliasKeyVersion"`
	UserAuthenticationRevision uint64    `json:"userAuthenticationRevision"`
	ObservedAt                 time.Time `json:"observedAt"`
}

type platformOIDCDirectSelectedTOTPWire struct {
	ID               string    `json:"id"`
	UserID           string    `json:"userId"`
	SecurityRevision uint64    `json:"securityRevision"`
	Active           bool      `json:"active"`
	ConfirmedAt      time.Time `json:"confirmedAt"`
}

type platformOIDCDirectPlanningWire struct {
	Provider                   federatedProviderBindingWire        `json:"provider"`
	ExternalIdentityID         string                              `json:"externalIdentityId"`
	UserID                     string                              `json:"userId"`
	IdentityVersion            uint64                              `json:"identityVersion"`
	AliasKeyVersion            int16                               `json:"aliasKeyVersion"`
	UserAuthenticationRevision uint64                              `json:"userAuthenticationRevision"`
	ProviderRevision           uint64                              `json:"providerRevision"`
	LoginPolicyRevision        uint64                              `json:"loginPolicyRevision"`
	ConfigurationRevision      uint64                              `json:"configurationRevision"`
	SecurityRevision           uint64                              `json:"securityRevision"`
	PlanRevision               uint64                              `json:"planRevision"`
	AssurancePolicyRevision    uint64                              `json:"assurancePolicyRevision"`
	PlatformFloor              assurancePolicyWire                 `json:"platformFloor"`
	AccountMode                string                              `json:"accountMode"`
	RequiresLocalTOTP          bool                                `json:"requiresLocalTotp"`
	SelectedTOTP               *platformOIDCDirectSelectedTOTPWire `json:"selectedTotp"`
}

type platformOIDCDirectResolvedIdentity struct {
	match platformoidcauth.DirectPlatformIdentityMatch
	pins  platformoidcauth.DirectOIDCConfigurationPins
}

var _ platformoidcauth.DirectPlatformPlanningStateSource = (*FederatedAuthRepository)(nil)

func (repository *FederatedAuthRepository) LoadDirectPlatformPlanningState(
	ctx context.Context,
	lookup platformoidcauth.DirectPlatformPlanningLookup,
) (platformoidcauth.DirectPlatformPlanningState, error) {
	if repository == nil || repository.queryer == nil || ctx == nil || ctx.Err() != nil ||
		!validPlatformOIDCDirectPlanningLookup(lookup) {
		return platformoidcauth.DirectPlatformPlanningState{}, errFederatedAuthPersistence
	}
	resolved, err := repository.resolvePlatformOIDCDirectIdentity(ctx, lookup)
	if err != nil || ctx.Err() != nil {
		return platformoidcauth.DirectPlatformPlanningState{}, errFederatedAuthPersistence
	}
	trust, err := repository.loadPlatformOIDCDirectTrust(ctx, lookup.Pins)
	if err != nil || ctx.Err() != nil {
		clearPlatformOIDCDirectTrustRules(trust)
		return platformoidcauth.DirectPlatformPlanningState{}, errFederatedAuthPersistence
	}
	state, err := repository.loadPlatformOIDCDirectPlanning(ctx, lookup, resolved, trust)
	clearPlatformOIDCDirectTrustRules(trust)
	if err != nil || ctx.Err() != nil {
		return platformoidcauth.DirectPlatformPlanningState{}, errFederatedAuthPersistence
	}
	return state, nil
}

func (repository *FederatedAuthRepository) resolvePlatformOIDCDirectIdentity(
	ctx context.Context,
	lookup platformoidcauth.DirectPlatformPlanningLookup,
) (platformOIDCDirectResolvedIdentity, error) {
	pinsWire, err := platformOIDCDirectPinsToWire(lookup.Pins)
	if err != nil {
		return platformOIDCDirectResolvedIdentity{}, errFederatedAuthPersistence
	}
	defer func() {
		clear(pinsWire.DiscoveryDigest)
		clear(pinsWire.JWKSDigest)
	}()
	var selected *platformOIDCDirectResolvedIdentity
	for _, alias := range lookup.SubjectAliases {
		wire := platformOIDCDirectResolveLookupWire{
			TransactionID:  append([]byte(nil), lookup.TransactionID[:]...),
			ClaimAttemptID: append([]byte(nil), lookup.ClaimAttemptID[:]...), Provider: pinsWire.Provider,
			SubjectAlias: platformOIDCDirectSubjectAliasWire{
				KeyVersion: alias.KeyVersion, Digest: append([]byte(nil), alias.Digest[:]...),
			},
			ObservedAt: lookup.ObservedAt,
		}
		var response *platformOIDCDirectResolveWire
		queryErr := repository.queryBoundedJSON(
			ctx, resolvePlatformOIDCDirectIdentitySQL, wire, &response,
			maximumPlatformOIDCDirectPlanningWireBytes,
		)
		clearPlatformOIDCDirectResolveLookupWire(&wire)
		if queryErr != nil || ctx.Err() != nil {
			if response != nil {
				clearPlatformOIDCDirectResolveWire(response)
			}
			return platformOIDCDirectResolvedIdentity{}, errFederatedAuthPersistence
		}
		if response == nil {
			continue
		}
		candidate, conversionErr := platformOIDCDirectResolveFromWire(*response, alias, lookup)
		clearPlatformOIDCDirectResolveWire(response)
		if conversionErr != nil {
			return platformOIDCDirectResolvedIdentity{}, errFederatedAuthPersistence
		}
		if selected == nil {
			copyCandidate := candidate
			selected = &copyCandidate
			continue
		}
		if !samePlatformOIDCDirectResolvedAuthority(*selected, candidate) {
			return platformOIDCDirectResolvedIdentity{}, errFederatedAuthPersistence
		}
		// Prefer the newest retained-key alias that already names the same
		// immutable identity. This maximizes the useful pin without hiding an
		// identity collision across aliases.
		if candidate.match.Alias.KeyVersion > selected.match.Alias.KeyVersion {
			copyCandidate := candidate
			selected = &copyCandidate
		}
	}
	if selected == nil {
		return platformOIDCDirectResolvedIdentity{}, errFederatedAuthPersistence
	}
	return *selected, nil
}

func (repository *FederatedAuthRepository) loadPlatformOIDCDirectTrust(
	ctx context.Context,
	pins platformoidcauth.DirectOIDCConfigurationPins,
) ([]platformoidcauth.DirectOIDCTrustRule, error) {
	pinsWire, err := platformOIDCDirectPinsToWire(pins)
	if err != nil {
		return nil, errFederatedAuthPersistence
	}
	wire := platformOIDCDirectPinnedLookupWire{Provider: pinsWire.Provider, Pins: pinsWire}
	defer clearPlatformOIDCDirectPinnedLookupWire(&wire)
	var response platformOIDCDirectTrustWire
	defer clearPlatformOIDCDirectTrustWire(&response)
	if err = repository.queryBoundedJSON(
		ctx, loadPlatformOIDCDirectTrustSQL, wire, &response,
		maximumPlatformOIDCDirectPlanningWireBytes,
	); err != nil || ctx.Err() != nil {
		return nil, errFederatedAuthPersistence
	}
	provider, binding, providerErr := providerBindingFromWire(response.Provider, true)
	if providerErr != nil || binding != (identity.EntityID{}) || provider != pins.Provider ||
		response.AssurancePolicyRevision != pins.AssurancePolicyRevision ||
		len(response.Rules) > maximumPlatformOIDCDirectTrustRules {
		return nil, errFederatedAuthPersistence
	}
	rules := make([]platformoidcauth.DirectOIDCTrustRule, len(response.Rules))
	seen := make(map[identity.EntityID]struct{}, len(response.Rules))
	for index := range response.Rules {
		rule, conversionErr := platformOIDCDirectTrustRuleFromWire(response.Rules[index])
		if conversionErr != nil {
			clearPlatformOIDCDirectTrustRules(rules)
			return nil, errFederatedAuthPersistence
		}
		if _, duplicate := seen[rule.RuleID]; duplicate {
			clearPlatformOIDCDirectTrustRules(rules)
			return nil, errFederatedAuthPersistence
		}
		seen[rule.RuleID] = struct{}{}
		rules[index] = rule
	}
	return rules, nil
}

func (repository *FederatedAuthRepository) loadPlatformOIDCDirectPlanning(
	ctx context.Context,
	lookup platformoidcauth.DirectPlatformPlanningLookup,
	resolved platformOIDCDirectResolvedIdentity,
	trust []platformoidcauth.DirectOIDCTrustRule,
) (platformoidcauth.DirectPlatformPlanningState, error) {
	wire := platformOIDCDirectPlanningLookupWire{
		TransactionID:      append([]byte(nil), lookup.TransactionID[:]...),
		ClaimAttemptID:     append([]byte(nil), lookup.ClaimAttemptID[:]...),
		ExternalIdentityID: entityIDWire(resolved.match.ExternalIdentityID),
		UserID:             entityIDWire(resolved.match.UserID), IdentityVersion: resolved.match.IdentityRevision,
		AliasKeyVersion:            resolved.match.Alias.KeyVersion,
		UserAuthenticationRevision: resolved.match.UserAuthenticationRevision,
		ObservedAt:                 lookup.ObservedAt,
	}
	defer clearPlatformOIDCDirectPlanningLookupWire(&wire)
	var response platformOIDCDirectPlanningWire
	if err := repository.queryBoundedJSON(
		ctx, loadPlatformOIDCDirectPlanningSQL, wire, &response,
		maximumPlatformOIDCDirectPlanningWireBytes,
	); err != nil || ctx.Err() != nil {
		return platformoidcauth.DirectPlatformPlanningState{}, errFederatedAuthPersistence
	}
	return platformOIDCDirectPlanningFromWire(response, lookup, resolved, trust)
}

func platformOIDCDirectResolveFromWire(
	wire platformOIDCDirectResolveWire,
	alias identity.SubjectAlias,
	lookup platformoidcauth.DirectPlatformPlanningLookup,
) (platformOIDCDirectResolvedIdentity, error) {
	provider, binding, providerErr := providerBindingFromWire(wire.Provider, true)
	externalID, externalErr := parseFederatedEntityIDWire(wire.ExternalIdentityID, false)
	userID, userErr := parseFederatedEntityIDWire(wire.UserID, false)
	pins, pinsErr := platformOIDCDirectPinsFromWire(wire.Pins)
	if providerErr != nil || externalErr != nil || userErr != nil || pinsErr != nil ||
		binding != (identity.EntityID{}) || provider != lookup.Provider || pins != lookup.Pins ||
		wire.AccountMode != string(platformoidcauth.AccountModeExistingIdentity) ||
		wire.AliasKeyVersion != alias.KeyVersion || !validFederatedRevision(wire.IdentityVersion) ||
		!validFederatedRevision(wire.UserAuthenticationRevision) || externalID == userID {
		return platformOIDCDirectResolvedIdentity{}, errFederatedAuthPersistence
	}
	return platformOIDCDirectResolvedIdentity{
		match: platformoidcauth.DirectPlatformIdentityMatch{
			ProviderID: provider.ProviderID, ExternalIdentityID: externalID, UserID: userID,
			Alias: alias, IdentityRevision: wire.IdentityVersion,
			UserAuthenticationRevision: wire.UserAuthenticationRevision,
			IdentityLive:               true, AliasLive: true, UserActive: true,
		},
		pins: pins,
	}, nil
}

func platformOIDCDirectPlanningFromWire(
	wire platformOIDCDirectPlanningWire,
	lookup platformoidcauth.DirectPlatformPlanningLookup,
	resolved platformOIDCDirectResolvedIdentity,
	trust []platformoidcauth.DirectOIDCTrustRule,
) (platformoidcauth.DirectPlatformPlanningState, error) {
	provider, binding, providerErr := providerBindingFromWire(wire.Provider, true)
	externalID, externalErr := parseFederatedEntityIDWire(wire.ExternalIdentityID, false)
	userID, userErr := parseFederatedEntityIDWire(wire.UserID, false)
	floor, floorErr := assurancePolicyFromWire(wire.PlatformFloor)
	if providerErr != nil || externalErr != nil || userErr != nil || floorErr != nil ||
		binding != (identity.EntityID{}) || provider != lookup.Provider || provider != resolved.pins.Provider ||
		externalID != resolved.match.ExternalIdentityID || userID != resolved.match.UserID ||
		wire.IdentityVersion != resolved.match.IdentityRevision ||
		wire.AliasKeyVersion != resolved.match.Alias.KeyVersion ||
		wire.UserAuthenticationRevision != resolved.match.UserAuthenticationRevision ||
		wire.ProviderRevision != lookup.Pins.ProviderRevision ||
		wire.LoginPolicyRevision != lookup.Pins.PlatformLoginRevision ||
		wire.ConfigurationRevision != lookup.Pins.ConfigurationRevision ||
		wire.SecurityRevision != lookup.Pins.SecurityRevision || wire.PlanRevision != lookup.Pins.PlanRevision ||
		wire.AssurancePolicyRevision != lookup.Pins.AssurancePolicyRevision ||
		floor.ID != lookup.Pins.PlatformFloorPolicyID || floor.Revision < 1 ||
		uint64(floor.Revision) != lookup.Pins.PlatformFloorPolicyRevision ||
		wire.AccountMode != string(platformoidcauth.AccountModeExistingIdentity) ||
		wire.RequiresLocalTOTP != floor.LocalRequired {
		return platformoidcauth.DirectPlatformPlanningState{}, errFederatedAuthPersistence
	}
	requirement, err := identity.CombineAssurancePolicies([]identity.AssurancePolicy{floor})
	if err != nil {
		return platformoidcauth.DirectPlatformPlanningState{}, errFederatedAuthPersistence
	}
	factors := []platformoidcauth.DirectPlatformTOTPFactor(nil)
	if wire.SelectedTOTP != nil {
		factorID, factorErr := parseFederatedEntityIDWire(wire.SelectedTOTP.ID, false)
		factorUserID, factorUserErr := parseFederatedEntityIDWire(wire.SelectedTOTP.UserID, false)
		confirmedAt, confirmedOK := canonicalFederatedDatabaseTimeFromWire(wire.SelectedTOTP.ConfirmedAt)
		if factorErr != nil || factorUserErr != nil || factorUserID != userID || factorID == userID ||
			!wire.SelectedTOTP.Active || !validFederatedRevision(wire.SelectedTOTP.SecurityRevision) ||
			!confirmedOK || confirmedAt.After(lookup.ObservedAt) {
			return platformoidcauth.DirectPlatformPlanningState{}, errFederatedAuthPersistence
		}
		factors = []platformoidcauth.DirectPlatformTOTPFactor{{
			FactorID: factorID, UserID: userID, Revision: wire.SelectedTOTP.SecurityRevision,
			Active: true, ConfirmedAt: &confirmedAt,
		}}
	}
	return platformoidcauth.DirectPlatformPlanningState{
		Provider: provider, ProviderRevision: wire.ProviderRevision,
		PlatformLoginRevision: wire.LoginPolicyRevision,
		ConfigurationRevision: wire.ConfigurationRevision, SecurityRevision: wire.SecurityRevision,
		PlanRevision: wire.PlanRevision, AssurancePolicyRevision: wire.AssurancePolicyRevision,
		ProviderEnabled: true, PlatformLoginLive: true, ConfigurationLive: true, AssurancePolicyLive: true,
		AccountMode: platformoidcauth.AccountModeExistingIdentity,
		Matches:     []platformoidcauth.DirectPlatformIdentityMatch{resolved.match},
		TrustRules:  clonePlatformOIDCDirectTrustRules(trust), PlatformFloor: requirement,
		LiveConfirmedTOTPFactors: factors,
	}, nil
}

func platformOIDCDirectTrustRuleFromWire(
	wire platformOIDCDirectTrustRuleWire,
) (platformoidcauth.DirectOIDCTrustRule, error) {
	ruleID, err := parseFederatedEntityIDWire(wire.ID, false)
	if err != nil || !validFederatedRevision(wire.Revision) ||
		wire.MaximumAuthenticationAgeSeconds < 1 ||
		wire.MaximumAuthenticationAgeSeconds > int64((30*24*time.Hour)/time.Second) ||
		len(wire.RequiredValues) > maximumPlatformOIDCDirectTrustValues ||
		wire.ExactValue == nil && len(wire.RequiredValues) == 0 ||
		wire.ExactValue != nil && !validFederatedTrustValue(*wire.ExactValue) ||
		!slices.IsSorted(wire.RequiredValues) || hasAdjacentFederatedTrustDuplicate(wire.RequiredValues) {
		return platformoidcauth.DirectOIDCTrustRule{}, errFederatedAuthPersistence
	}
	for _, value := range wire.RequiredValues {
		if !validFederatedTrustValue(value) {
			return platformoidcauth.DirectOIDCTrustRule{}, errFederatedAuthPersistence
		}
	}
	level := identity.AssuranceLevel(0)
	switch wire.Level {
	case "mfa":
		level = identity.AssuranceMFA
	case "phishing_resistant":
		level = identity.AssurancePhishingResistant
	default:
		return platformoidcauth.DirectOIDCTrustRule{}, errFederatedAuthPersistence
	}
	rule := platformoidcauth.DirectOIDCTrustRule{
		RuleID: ruleID, Revision: wire.Revision, Enabled: true, Level: level,
		RequiredAMR:              append([]string(nil), wire.RequiredValues...),
		MaximumAuthenticationAge: time.Duration(wire.MaximumAuthenticationAgeSeconds) * time.Second,
	}
	if wire.ExactValue != nil {
		value := *wire.ExactValue
		rule.ACR = &value
	}
	return rule, nil
}

func validPlatformOIDCDirectPlanningLookup(lookup platformoidcauth.DirectPlatformPlanningLookup) bool {
	if !validOpaque32(lookup.TransactionID[:]) || !validOpaque32(lookup.ClaimAttemptID[:]) ||
		lookup.TransactionID == lookup.ClaimAttemptID || !validFederatedDatabaseTime(lookup.ObservedAt) ||
		lookup.Provider != lookup.Pins.Provider || lookup.SubjectFormat != identity.UTF8ExactSubject ||
		lookup.ProviderRevision != lookup.Pins.ProviderRevision ||
		lookup.PlatformLoginRevision != lookup.Pins.PlatformLoginRevision ||
		lookup.ConfigurationRevision != lookup.Pins.ConfigurationRevision ||
		lookup.SecurityRevision != lookup.Pins.SecurityRevision ||
		lookup.AssurancePolicyRevision != lookup.Pins.AssurancePolicyRevision ||
		len(lookup.SubjectAliases) < 1 || len(lookup.SubjectAliases) > 16 {
		return false
	}
	pins, err := platformOIDCDirectPinsToWire(lookup.Pins)
	if err != nil {
		return false
	}
	defer func() {
		clear(pins.DiscoveryDigest)
		clear(pins.JWKSDigest)
	}()
	for index, alias := range lookup.SubjectAliases {
		if alias.KeyVersion < 1 || !validPlatformOIDCDigest(alias.Digest[:]) ||
			index > 0 && lookup.SubjectAliases[index-1].KeyVersion >= alias.KeyVersion {
			return false
		}
	}
	return true
}

func samePlatformOIDCDirectResolvedAuthority(
	left, right platformOIDCDirectResolvedIdentity,
) bool {
	return left.match.ProviderID == right.match.ProviderID &&
		left.match.ExternalIdentityID == right.match.ExternalIdentityID && left.match.UserID == right.match.UserID &&
		left.match.IdentityRevision == right.match.IdentityRevision &&
		left.match.UserAuthenticationRevision == right.match.UserAuthenticationRevision && left.pins == right.pins
}

func clonePlatformOIDCDirectTrustRules(
	values []platformoidcauth.DirectOIDCTrustRule,
) []platformoidcauth.DirectOIDCTrustRule {
	result := append([]platformoidcauth.DirectOIDCTrustRule(nil), values...)
	for index := range result {
		result[index].RequiredAMR = append([]string(nil), values[index].RequiredAMR...)
		if values[index].ACR != nil {
			value := *values[index].ACR
			result[index].ACR = &value
		}
	}
	return result
}

func clearPlatformOIDCDirectTrustRules(values []platformoidcauth.DirectOIDCTrustRule) {
	for index := range values {
		if values[index].ACR != nil {
			*values[index].ACR = ""
		}
		clear(values[index].RequiredAMR)
	}
}

func clearPlatformOIDCDirectResolveLookupWire(value *platformOIDCDirectResolveLookupWire) {
	if value == nil {
		return
	}
	clear(value.TransactionID)
	clear(value.ClaimAttemptID)
	clear(value.SubjectAlias.Digest)
	*value = platformOIDCDirectResolveLookupWire{}
}

func clearPlatformOIDCDirectResolveWire(value *platformOIDCDirectResolveWire) {
	if value == nil {
		return
	}
	clear(value.Pins.DiscoveryDigest)
	clear(value.Pins.JWKSDigest)
	*value = platformOIDCDirectResolveWire{}
}

func clearPlatformOIDCDirectPinnedLookupWire(value *platformOIDCDirectPinnedLookupWire) {
	if value == nil {
		return
	}
	clear(value.Pins.DiscoveryDigest)
	clear(value.Pins.JWKSDigest)
	*value = platformOIDCDirectPinnedLookupWire{}
}

func clearPlatformOIDCDirectTrustWire(value *platformOIDCDirectTrustWire) {
	if value == nil {
		return
	}
	for index := range value.Rules {
		if value.Rules[index].ExactValue != nil {
			*value.Rules[index].ExactValue = ""
		}
		clear(value.Rules[index].RequiredValues)
	}
	*value = platformOIDCDirectTrustWire{}
}

func clearPlatformOIDCDirectPlanningLookupWire(value *platformOIDCDirectPlanningLookupWire) {
	if value == nil {
		return
	}
	clear(value.TransactionID)
	clear(value.ClaimAttemptID)
	*value = platformOIDCDirectPlanningLookupWire{}
}
