package federatedauth

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"time"
	"unicode"
	"unicode/utf8"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

const (
	maximumOIDCTrustRules       = 1_024
	maximumOIDCTrustAMRValues   = 128
	maximumOIDCTrustValueBytes  = 4 * 1_024
	maximumOIDCTrustEvidenceAge = 30 * 24 * time.Hour
)

// OIDCTrustLookup carries only immutable identifiers and exact transaction
// revisions. Raw ACR/AMR values never cross the persistence boundary.
type OIDCTrustLookup struct {
	TenantID                identity.EntityID
	Provider                identity.ProviderContext
	BindingID               identity.EntityID
	ProviderRevision        uint64
	BindingRevision         uint64
	SecurityRevision        uint64
	AssurancePolicyRevision uint64
}

func (lookup OIDCTrustLookup) String() string {
	return fmt.Sprintf(
		"federatedauth.OIDCTrustLookup{providerRevision:%t,bindingRevision:%t,securityRevision:%t,policyRevision:%t}",
		lookup.ProviderRevision != 0, lookup.BindingRevision != 0, lookup.SecurityRevision != 0,
		lookup.AssurancePolicyRevision != 0,
	)
}
func (lookup OIDCTrustLookup) GoString() string { return lookup.String() }

// OIDCTrustRule is one exact, case-sensitive trust rule. At least one ACR or
// AMR condition is required; an ordinary provider primary proof is added by
// the application independently and cannot be upgraded by an empty rule.
type OIDCTrustRule struct {
	RuleID                   identity.EntityID
	Revision                 uint64
	Enabled                  bool
	Level                    identity.AssuranceLevel
	ACR                      *string  `json:"-"`
	RequiredAMR              []string `json:"-"`
	MaximumAuthenticationAge time.Duration
}

func (rule OIDCTrustRule) String() string {
	return fmt.Sprintf(
		"federatedauth.OIDCTrustRule{revision:%t,enabled:%t,level:%d,acr:%t,requiredAMR:%d,maxAge:%s,material:[REDACTED]}",
		rule.Revision != 0, rule.Enabled, rule.Level, rule.ACR != nil, len(rule.RequiredAMR),
		rule.MaximumAuthenticationAge,
	)
}
func (rule OIDCTrustRule) GoString() string { return rule.String() }

// OIDCTrustSnapshot is loaded under tenant RLS from the exact transaction
// pins. Every echoed revision is rechecked before any claim value is matched.
type OIDCTrustSnapshot struct {
	OIDCTrustLookup
	Rules []OIDCTrustRule
}

func (snapshot OIDCTrustSnapshot) String() string {
	return fmt.Sprintf("federatedauth.OIDCTrustSnapshot{lookup:%q,rules:%d}", snapshot.OIDCTrustLookup, len(snapshot.Rules))
}
func (snapshot OIDCTrustSnapshot) GoString() string { return snapshot.String() }

type OIDCTrustSnapshotSource interface {
	LoadOIDCTrustSnapshot(context.Context, OIDCTrustLookup) (OIDCTrustSnapshot, error)
}

// PinnedOIDCTrustResolver converts exact configured IdP evidence into the
// normalized assurance facts consumed by the shared MFA kernel.
type PinnedOIDCTrustResolver struct {
	source OIDCTrustSnapshotSource
}

func NewPinnedOIDCTrustResolver(source OIDCTrustSnapshotSource) (*PinnedOIDCTrustResolver, error) {
	if source == nil {
		return nil, ErrInvalidOptions
	}
	return &PinnedOIDCTrustResolver{source: source}, nil
}

func (resolver *PinnedOIDCTrustResolver) String() string {
	return fmt.Sprintf("federatedauth.PinnedOIDCTrustResolver{configured:%t}", resolver != nil && resolver.source != nil)
}
func (resolver *PinnedOIDCTrustResolver) GoString() string { return resolver.String() }

func (resolver *PinnedOIDCTrustResolver) ResolveOIDCAssurance(
	ctx context.Context,
	request OIDCTrustRequest,
) ([]identity.AssuranceEvidence, error) {
	if resolver == nil || resolver.source == nil || ctx == nil || ctx.Err() != nil || !validOIDCTrustLookupRequest(request) {
		return nil, ErrAuthentication
	}
	lookup := OIDCTrustLookup{
		TenantID: request.TenantID, Provider: request.Provider, BindingID: request.BindingID,
		ProviderRevision: request.ProviderRevision, BindingRevision: request.BindingRevision,
		SecurityRevision: request.SecurityRevision, AssurancePolicyRevision: request.AssurancePolicyRevision,
	}
	snapshot, err := resolver.source.LoadOIDCTrustSnapshot(ctx, lookup)
	rules := cloneOIDCTrustRules(snapshot.Rules)
	if err != nil || ctx.Err() != nil || snapshot.OIDCTrustLookup != lookup || !validOIDCTrustRules(rules) {
		return nil, ErrAuthentication
	}
	// The exact policy snapshot is always rechecked, even when IdP evidence is
	// unusable. Malformed, duplicated, or over-limit evidence is never trusted,
	// but does not invalidate the already verified primary OIDC proof.
	if !validOIDCTrustClaimEvidence(request) {
		return nil, nil
	}
	slices.SortFunc(rules, compareOIDCTrustRule)
	evidence := make([]identity.AssuranceEvidence, 0, len(rules))
	for _, rule := range rules {
		if !rule.Enabled || !oidcTrustRuleMatches(rule, request.ACR, request.AMR) {
			continue
		}
		expiresAt := request.AuthenticatedAt.Add(rule.MaximumAuthenticationAge)
		if request.ValidUntil.Before(expiresAt) {
			expiresAt = request.ValidUntil
		}
		if !validInstant(expiresAt) || !expiresAt.After(request.AuthenticatedAt) {
			return nil, ErrAuthentication
		}
		// Session revalidation loads one live trust snapshot per exact
		// provider/binding. Pin every matched rule result to that immutable
		// snapshot revision; persisting individual rule revisions would make two
		// simultaneously matched rules impossible to revalidate against the one
		// live snapshot without either dropping evidence or weakening the check.
		revision := int64(request.SecurityRevision)
		evidence = append(evidence, identity.AssuranceEvidence{
			Level: rule.Level, Kind: identity.AssuranceEvidenceFactor,
			Source:          identity.AssuranceSource{ProviderID: request.Provider.ProviderID, BindingID: request.BindingID},
			AuthenticatedAt: request.AuthenticatedAt, ExpiresAt: &expiresAt, TrustRuleRevision: &revision,
		})
	}
	return evidence, nil
}

func validOIDCTrustLookupRequest(request OIDCTrustRequest) bool {
	admission, validAdmission := oidcTrustAdmission(request)
	return validAdmission && admission.TenantID == request.TenantID && admission.BindingID == request.BindingID &&
		validDatabaseRevision(request.ProviderRevision) &&
		validDatabaseRevision(request.BindingRevision) && validDatabaseRevision(request.SecurityRevision) &&
		validDatabaseRevision(request.AssurancePolicyRevision) && validInstant(request.AuthenticatedAt) &&
		validInstant(request.ValidUntil) && request.ValidUntil.After(request.AuthenticatedAt)
}

func oidcTrustAdmission(request OIDCTrustRequest) (identity.TenantAdmissionContext, bool) {
	admission := request.Admission
	if admission == (identity.TenantAdmissionContext{}) && request.Provider.Scope == identity.TenantProviderScope {
		admission = identity.TenantAdmissionContext{TenantID: request.TenantID, BindingID: request.BindingID}
	}
	return admission, validTenantAdmission(request.Provider, admission)
}

func validOIDCTrustClaimEvidence(request OIDCTrustRequest) bool {
	if len(request.AMR) > maximumOIDCTrustAMRValues || request.ACR != "" && !validOIDCTrustValue(request.ACR) {
		return false
	}
	return sortedUniqueOIDCTrustValues(request.AMR)
}

func cloneOIDCTrustRules(values []OIDCTrustRule) []OIDCTrustRule {
	result := append([]OIDCTrustRule(nil), values...)
	for index := range result {
		result[index].RequiredAMR = append([]string(nil), values[index].RequiredAMR...)
		if values[index].ACR != nil {
			copyValue := *values[index].ACR
			result[index].ACR = &copyValue
		}
	}
	return result
}

func validOIDCTrustRules(rules []OIDCTrustRule) bool {
	if len(rules) > maximumOIDCTrustRules {
		return false
	}
	seen := make(map[identity.EntityID]struct{}, len(rules))
	for _, rule := range rules {
		if rule.RuleID == (identity.EntityID{}) || !validDatabaseRevision(rule.Revision) ||
			(rule.Level != identity.AssuranceMFA && rule.Level != identity.AssurancePhishingResistant) ||
			rule.MaximumAuthenticationAge < time.Second ||
			rule.MaximumAuthenticationAge > maximumOIDCTrustEvidenceAge ||
			rule.MaximumAuthenticationAge%time.Second != 0 || len(rule.RequiredAMR) > maximumOIDCTrustAMRValues ||
			rule.ACR == nil && len(rule.RequiredAMR) == 0 ||
			rule.ACR != nil && !validOIDCTrustValue(*rule.ACR) || !sortedUniqueOIDCTrustValues(rule.RequiredAMR) {
			return false
		}
		if _, duplicate := seen[rule.RuleID]; duplicate {
			return false
		}
		seen[rule.RuleID] = struct{}{}
	}
	return true
}

func oidcTrustRuleMatches(rule OIDCTrustRule, acr string, amr []string) bool {
	if rule.ACR != nil && *rule.ACR != acr {
		return false
	}
	for _, required := range rule.RequiredAMR {
		if _, present := slices.BinarySearch(amr, required); !present {
			return false
		}
	}
	return true
}

func sortedUniqueOIDCTrustValues(values []string) bool {
	for index, value := range values {
		if !validOIDCTrustValue(value) || index > 0 && values[index-1] >= value {
			return false
		}
	}
	return true
}

func validOIDCTrustValue(value string) bool {
	if value == "" || len(value) > maximumOIDCTrustValueBytes || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || isFederatedDirectionalControl(character) {
			return false
		}
	}
	return true
}

func isFederatedDirectionalControl(character rune) bool {
	return character == '\u200e' || character == '\u200f' ||
		character >= '\u202a' && character <= '\u202e' ||
		character >= '\u2066' && character <= '\u2069'
}

func validDatabaseRevision(value uint64) bool {
	return value > 0 && value <= maximumJSONSafeRevision
}

func validDatabaseSuccessorRevision(value uint64) bool {
	return value > 0 && value < maximumJSONSafeRevision
}

func compareOIDCTrustRule(left, right OIDCTrustRule) int {
	return bytes.Compare(left.RuleID[:], right.RuleID[:])
}
