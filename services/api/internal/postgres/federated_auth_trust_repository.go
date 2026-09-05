package postgres

import (
	"context"
	"slices"
	"time"
	"unicode"
	"unicode/utf8"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
)

const (
	loadOIDCTrustSnapshotSQL = `select app.load_oidc_trust_snapshot_v1($1::jsonb)`

	maximumFederatedTrustRules      = 1_024
	maximumFederatedTrustAMRValues  = 128
	maximumFederatedTrustValueBytes = 4 * 1_024
)

type oidcTrustLookupWire struct {
	TenantID                string                        `json:"tenantId"`
	Provider                federatedProviderBindingWire  `json:"provider"`
	Admission               *federatedTenantAdmissionWire `json:"admission,omitempty"`
	ProviderRevision        uint64                        `json:"providerRevision"`
	BindingRevision         uint64                        `json:"bindingRevision"`
	SecurityRevision        uint64                        `json:"securityRevision"`
	AssurancePolicyRevision uint64                        `json:"assurancePolicyRevision"`
}

type oidcTrustRuleWire struct {
	RuleID                   string   `json:"ruleId"`
	Revision                 uint64   `json:"revision"`
	Enabled                  bool     `json:"enabled"`
	Level                    string   `json:"level"`
	ACR                      *string  `json:"acr"`
	RequiredAMR              []string `json:"requiredAmr"`
	MaximumAuthenticationAge int64    `json:"maximumAuthenticationAgeSeconds"`
}

type oidcTrustSnapshotWire struct {
	Lookup oidcTrustLookupWire `json:"lookup"`
	Rules  []oidcTrustRuleWire `json:"rules"`
}

var _ federatedauth.OIDCTrustSnapshotSource = (*FederatedAuthRepository)(nil)

func (repository *FederatedAuthRepository) LoadOIDCTrustSnapshot(
	ctx context.Context,
	lookup federatedauth.OIDCTrustLookup,
) (federatedauth.OIDCTrustSnapshot, error) {
	wire, err := oidcTrustLookupToWire(lookup)
	if err != nil {
		return federatedauth.OIDCTrustSnapshot{}, errFederatedAuthPersistence
	}
	var response oidcTrustSnapshotWire
	defer clearOIDCTrustSnapshotWire(&response)
	if err := repository.queryJSON(ctx, loadOIDCTrustSnapshotSQL, wire, &response); err != nil {
		return federatedauth.OIDCTrustSnapshot{}, err
	}
	return oidcTrustSnapshotFromWire(response, lookup)
}

func oidcTrustLookupToWire(lookup federatedauth.OIDCTrustLookup) (oidcTrustLookupWire, error) {
	if lookup.TenantID == (identity.EntityID{}) || lookup.BindingID == (identity.EntityID{}) ||
		!validFederatedRevision(lookup.ProviderRevision) || !validFederatedRevision(lookup.BindingRevision) ||
		!validFederatedRevision(lookup.SecurityRevision) || !validFederatedRevision(lookup.AssurancePolicyRevision) {
		return oidcTrustLookupWire{}, errFederatedAuthPersistence
	}
	tenantID, err := requiredFederatedEntityIDWire(lookup.TenantID)
	if err != nil {
		return oidcTrustLookupWire{}, errFederatedAuthPersistence
	}
	explicit := identity.TenantAdmissionContext{}
	if lookup.Provider.Scope == identity.PlatformProviderScope {
		explicit = identity.TenantAdmissionContext{TenantID: lookup.TenantID, BindingID: lookup.BindingID}
	}
	provider, admission, err := providerTenantAdmissionToWire(
		lookup.Provider, lookup.TenantID, lookup.BindingID, explicit,
	)
	if err != nil {
		return oidcTrustLookupWire{}, errFederatedAuthPersistence
	}
	return oidcTrustLookupWire{
		TenantID: tenantID, Provider: provider, Admission: admission, ProviderRevision: lookup.ProviderRevision,
		BindingRevision: lookup.BindingRevision, SecurityRevision: lookup.SecurityRevision,
		AssurancePolicyRevision: lookup.AssurancePolicyRevision,
	}, nil
}

func oidcTrustLookupFromWire(wire oidcTrustLookupWire) (federatedauth.OIDCTrustLookup, error) {
	tenantID, err := parseFederatedEntityIDWire(wire.TenantID, false)
	if err != nil {
		return federatedauth.OIDCTrustLookup{}, errFederatedAuthPersistence
	}
	provider, _, binding, err := providerTenantAdmissionFromWire(wire.Provider, wire.Admission, tenantID)
	if err != nil ||
		binding == (identity.EntityID{}) || !validFederatedRevision(wire.ProviderRevision) ||
		!validFederatedRevision(wire.BindingRevision) || !validFederatedRevision(wire.SecurityRevision) ||
		!validFederatedRevision(wire.AssurancePolicyRevision) {
		return federatedauth.OIDCTrustLookup{}, errFederatedAuthPersistence
	}
	return federatedauth.OIDCTrustLookup{
		TenantID: tenantID, Provider: provider, BindingID: binding,
		ProviderRevision: wire.ProviderRevision, BindingRevision: wire.BindingRevision,
		SecurityRevision: wire.SecurityRevision, AssurancePolicyRevision: wire.AssurancePolicyRevision,
	}, nil
}

func oidcTrustSnapshotFromWire(
	wire oidcTrustSnapshotWire,
	wanted federatedauth.OIDCTrustLookup,
) (federatedauth.OIDCTrustSnapshot, error) {
	lookup, err := oidcTrustLookupFromWire(wire.Lookup)
	if err != nil || lookup != wanted || len(wire.Rules) > maximumFederatedTrustRules {
		return federatedauth.OIDCTrustSnapshot{}, errFederatedAuthPersistence
	}
	rules := make([]federatedauth.OIDCTrustRule, len(wire.Rules))
	seen := make(map[identity.EntityID]struct{}, len(wire.Rules))
	for index := range wire.Rules {
		rule, ruleErr := oidcTrustRuleFromWire(wire.Rules[index])
		if ruleErr != nil {
			return federatedauth.OIDCTrustSnapshot{}, errFederatedAuthPersistence
		}
		if _, duplicate := seen[rule.RuleID]; duplicate {
			return federatedauth.OIDCTrustSnapshot{}, errFederatedAuthPersistence
		}
		seen[rule.RuleID] = struct{}{}
		rules[index] = rule
	}
	return federatedauth.OIDCTrustSnapshot{OIDCTrustLookup: lookup, Rules: rules}, nil
}

func oidcTrustRuleFromWire(wire oidcTrustRuleWire) (federatedauth.OIDCTrustRule, error) {
	ruleID, err := parseFederatedEntityIDWire(wire.RuleID, false)
	level := identity.AssuranceLevel(0)
	switch wire.Level {
	case "mfa":
		level = identity.AssuranceMFA
	case "phishing_resistant":
		level = identity.AssurancePhishingResistant
	default:
		return federatedauth.OIDCTrustRule{}, errFederatedAuthPersistence
	}
	if err != nil || !validFederatedRevision(wire.Revision) ||
		wire.MaximumAuthenticationAge < 1 || wire.MaximumAuthenticationAge > int64((30*24*time.Hour)/time.Second) ||
		len(wire.RequiredAMR) > maximumFederatedTrustAMRValues ||
		wire.ACR == nil && len(wire.RequiredAMR) == 0 ||
		wire.ACR != nil && !validFederatedTrustValue(*wire.ACR) ||
		!slices.IsSorted(wire.RequiredAMR) || hasAdjacentFederatedTrustDuplicate(wire.RequiredAMR) {
		return federatedauth.OIDCTrustRule{}, errFederatedAuthPersistence
	}
	for _, value := range wire.RequiredAMR {
		if !validFederatedTrustValue(value) {
			return federatedauth.OIDCTrustRule{}, errFederatedAuthPersistence
		}
	}
	rule := federatedauth.OIDCTrustRule{
		RuleID: ruleID, Revision: wire.Revision, Enabled: wire.Enabled, Level: level,
		RequiredAMR:              append([]string(nil), wire.RequiredAMR...),
		MaximumAuthenticationAge: time.Duration(wire.MaximumAuthenticationAge) * time.Second,
	}
	if wire.ACR != nil {
		value := *wire.ACR
		rule.ACR = &value
	}
	return rule, nil
}

func validFederatedTrustValue(value string) bool {
	if value == "" || len(value) > maximumFederatedTrustValueBytes || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || character == '\u200e' || character == '\u200f' ||
			character >= '\u202a' && character <= '\u202e' || character >= '\u2066' && character <= '\u2069' {
			return false
		}
	}
	return true
}

func hasAdjacentFederatedTrustDuplicate(values []string) bool {
	for index := 1; index < len(values); index++ {
		if values[index-1] == values[index] {
			return true
		}
	}
	return false
}

func clearOIDCTrustSnapshotWire(value *oidcTrustSnapshotWire) {
	if value == nil {
		return
	}
	for index := range value.Rules {
		if value.Rules[index].ACR != nil {
			*value.Rules[index].ACR = ""
		}
		clear(value.Rules[index].RequiredAMR)
	}
}
