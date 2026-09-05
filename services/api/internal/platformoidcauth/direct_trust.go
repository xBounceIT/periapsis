package platformoidcauth

import (
	"bytes"
	"fmt"
	"slices"
	"time"
	"unicode"
	"unicode/utf8"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

const (
	maximumDirectOIDCTrustRules       = 1_024
	maximumDirectOIDCTrustAMRValues   = 128
	maximumDirectOIDCTrustValueBytes  = 4 * 1_024
	maximumDirectOIDCTrustEvidenceAge = 30 * 24 * time.Hour
)

// DirectOIDCTrustRule is one exact, case-sensitive platform-provider trust
// rule. Empty rules cannot upgrade the mandatory primary provider evidence.
type DirectOIDCTrustRule struct {
	RuleID                   identity.EntityID
	Revision                 uint64
	Enabled                  bool
	Level                    identity.AssuranceLevel
	ACR                      *string  `json:"-"`
	RequiredAMR              []string `json:"-"`
	MaximumAuthenticationAge time.Duration
}

func (rule DirectOIDCTrustRule) String() string {
	return fmt.Sprintf(
		"platformoidcauth.DirectOIDCTrustRule{revision:%t,enabled:%t,level:%d,acr:%t,requiredAMR:%d,maxAge:%s,material:[REDACTED]}",
		rule.Revision != 0, rule.Enabled, rule.Level, rule.ACR != nil,
		len(rule.RequiredAMR), rule.MaximumAuthenticationAge,
	)
}

func (rule DirectOIDCTrustRule) GoString() string { return rule.String() }

// DirectSelectedAssurance is the exact single assurance object accepted by
// the future direct apply ABI. Primary has both trust fields absent; an
// elevated result pins the exact matched rule row rather than the containing
// security snapshot revision.
type DirectSelectedAssurance struct {
	Level             identity.AssuranceLevel
	AuthenticatedAt   time.Time
	TrustRuleID       *identity.EntityID
	TrustRuleRevision *uint64
}

func (assurance DirectSelectedAssurance) String() string {
	return fmt.Sprintf(
		"platformoidcauth.DirectSelectedAssurance{level:%d,authenticated:%t,trustRule:%t,trustRevision:%t}",
		assurance.Level, !assurance.AuthenticatedAt.IsZero(), assurance.TrustRuleID != nil,
		assurance.TrustRuleRevision != nil,
	)
}

func (assurance DirectSelectedAssurance) GoString() string { return assurance.String() }

type directTrustCandidate struct {
	rule      DirectOIDCTrustRule
	expiresAt time.Time
}

func directProviderEvidence(
	providerID identity.EntityID,
	securityRevision uint64,
	authenticatedAt time.Time,
	validUntil time.Time,
	rules []DirectOIDCTrustRule,
	acr string,
	amr []string,
) ([]identity.AssuranceEvidence, DirectSelectedAssurance, bool) {
	if !validDirectEntityID(providerID) || !validDirectRevision(securityRevision) ||
		!validInstant(authenticatedAt) || !validInstant(validUntil) ||
		!validUntil.After(authenticatedAt) || !validDirectOIDCTrustRules(rules) {
		return nil, DirectSelectedAssurance{}, false
	}

	revision := int64(securityRevision)
	primaryExpiry := validUntil
	evidence := []identity.AssuranceEvidence{{
		Level: identity.AssurancePrimary, Kind: identity.AssuranceEvidenceFactor,
		Source:          identity.AssuranceSource{DirectPlatform: true, ProviderID: providerID},
		AuthenticatedAt: authenticatedAt, ExpiresAt: &primaryExpiry, TrustRuleRevision: &revision,
	}}
	selected := DirectSelectedAssurance{Level: identity.AssurancePrimary, AuthenticatedAt: authenticatedAt}
	// The protocol kernel treats malformed optional ACR/AMR as absent trust
	// evidence. Preserve that fail-closed downgrade while retaining the already
	// verified primary proof.
	if !validDirectOIDCTrustClaimEvidence(acr, amr) {
		return evidence, selected, true
	}

	slices.SortFunc(rules, compareDirectOIDCTrustRule)
	var selectedTrust *directTrustCandidate
	for _, rule := range rules {
		if !rule.Enabled || !directOIDCTrustRuleMatches(rule, acr, amr) {
			continue
		}
		expiresAt := authenticatedAt.Add(rule.MaximumAuthenticationAge)
		if validUntil.Before(expiresAt) {
			expiresAt = validUntil
		}
		if !validInstant(expiresAt) || !expiresAt.After(authenticatedAt) {
			return nil, DirectSelectedAssurance{}, false
		}
		trustRevision := int64(rule.Revision)
		evidence = append(evidence, identity.AssuranceEvidence{
			Level: rule.Level, Kind: identity.AssuranceEvidenceFactor,
			Source:          identity.AssuranceSource{DirectPlatform: true, ProviderID: providerID},
			AuthenticatedAt: authenticatedAt, ExpiresAt: &expiresAt,
			TrustRuleRevision: &trustRevision,
		})
		candidate := directTrustCandidate{rule: rule, expiresAt: expiresAt}
		if selectedTrust == nil || strongerDirectTrustCandidate(candidate, *selectedTrust) {
			copyCandidate := candidate
			selectedTrust = &copyCandidate
		}
	}
	if selectedTrust != nil {
		ruleID := selectedTrust.rule.RuleID
		ruleRevision := selectedTrust.rule.Revision
		selected = DirectSelectedAssurance{
			Level: selectedTrust.rule.Level, AuthenticatedAt: authenticatedAt,
			TrustRuleID: &ruleID, TrustRuleRevision: &ruleRevision,
		}
	}
	return evidence, selected, true
}

func strongerDirectTrustCandidate(left, right directTrustCandidate) bool {
	if left.rule.Level != right.rule.Level {
		return left.rule.Level > right.rule.Level
	}
	if !left.expiresAt.Equal(right.expiresAt) {
		return left.expiresAt.Before(right.expiresAt)
	}
	return bytes.Compare(left.rule.RuleID[:], right.rule.RuleID[:]) < 0
}

func validDirectSelectedAssurance(value DirectSelectedAssurance) bool {
	if !validInstant(value.AuthenticatedAt) {
		return false
	}
	if value.Level == identity.AssurancePrimary {
		return value.TrustRuleID == nil && value.TrustRuleRevision == nil
	}
	return (value.Level == identity.AssuranceMFA || value.Level == identity.AssurancePhishingResistant) &&
		value.TrustRuleID != nil && validDirectEntityID(*value.TrustRuleID) &&
		value.TrustRuleRevision != nil && validDirectRevision(*value.TrustRuleRevision)
}

func cloneDirectOIDCTrustRules(values []DirectOIDCTrustRule) []DirectOIDCTrustRule {
	result := append([]DirectOIDCTrustRule(nil), values...)
	for index := range result {
		result[index].RequiredAMR = append([]string(nil), values[index].RequiredAMR...)
		if values[index].ACR != nil {
			copyValue := *values[index].ACR
			result[index].ACR = &copyValue
		}
	}
	return result
}

func validDirectOIDCTrustRules(rules []DirectOIDCTrustRule) bool {
	if len(rules) > maximumDirectOIDCTrustRules {
		return false
	}
	seen := make(map[identity.EntityID]struct{}, len(rules))
	for _, rule := range rules {
		if !validDirectEntityID(rule.RuleID) || !validDirectRevision(rule.Revision) ||
			(rule.Level != identity.AssuranceMFA && rule.Level != identity.AssurancePhishingResistant) ||
			rule.MaximumAuthenticationAge < time.Second ||
			rule.MaximumAuthenticationAge > maximumDirectOIDCTrustEvidenceAge ||
			rule.MaximumAuthenticationAge%time.Second != 0 ||
			len(rule.RequiredAMR) > maximumDirectOIDCTrustAMRValues ||
			rule.ACR == nil && len(rule.RequiredAMR) == 0 ||
			rule.ACR != nil && !validDirectOIDCTrustValue(*rule.ACR) ||
			!sortedUniqueDirectOIDCTrustValues(rule.RequiredAMR) {
			return false
		}
		if _, duplicate := seen[rule.RuleID]; duplicate {
			return false
		}
		seen[rule.RuleID] = struct{}{}
	}
	return true
}

func validDirectOIDCTrustClaimEvidence(acr string, amr []string) bool {
	return len(amr) <= maximumDirectOIDCTrustAMRValues &&
		(acr == "" || validDirectOIDCTrustValue(acr)) &&
		sortedUniqueDirectOIDCTrustValues(amr)
}

func directOIDCTrustRuleMatches(rule DirectOIDCTrustRule, acr string, amr []string) bool {
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

func sortedUniqueDirectOIDCTrustValues(values []string) bool {
	for index, value := range values {
		if !validDirectOIDCTrustValue(value) || index > 0 && values[index-1] >= value {
			return false
		}
	}
	return true
}

func validDirectOIDCTrustValue(value string) bool {
	if value == "" || len(value) > maximumDirectOIDCTrustValueBytes || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || directOIDCDirectionalControl(character) {
			return false
		}
	}
	return true
}

func directOIDCDirectionalControl(character rune) bool {
	return character == '\u200e' || character == '\u200f' ||
		character >= '\u202a' && character <= '\u202e' ||
		character >= '\u2066' && character <= '\u2069'
}

func compareDirectOIDCTrustRule(left, right DirectOIDCTrustRule) int {
	return bytes.Compare(left.RuleID[:], right.RuleID[:])
}
