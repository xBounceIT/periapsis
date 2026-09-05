package platformoidcauth

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

func TestDirectProviderEvidenceUsesOnlyExactConfiguredTrust(t *testing.T) {
	providerID := directTestEntityID(1)
	authenticatedAt := directTestNow.Add(-2 * time.Minute)
	validUntil := directTestNow.Add(time.Hour)
	exactACR := "urn:example:mfa"
	wrongCase := "urn:example:MFA"
	rules := []DirectOIDCTrustRule{
		{
			RuleID: directTestEntityID(7), Revision: 1, Enabled: true,
			Level: identity.AssuranceMFA, ACR: &exactACR, RequiredAMR: []string{"mfa"},
			MaximumAuthenticationAge: 10 * time.Minute,
		},
		{
			RuleID: directTestEntityID(8), Revision: 2, Enabled: true,
			Level: identity.AssurancePhishingResistant, ACR: &wrongCase,
			MaximumAuthenticationAge: 10 * time.Minute,
		},
		{
			RuleID: directTestEntityID(9), Revision: 3, Enabled: false,
			Level: identity.AssurancePhishingResistant, RequiredAMR: []string{"hwk"},
			MaximumAuthenticationAge: 10 * time.Minute,
		},
	}

	evidence, selected, ok := directProviderEvidence(
		providerID, 14, authenticatedAt, validUntil,
		cloneDirectOIDCTrustRules(rules), exactACR, []string{"hwk", "mfa", "pwd"},
	)
	if !ok || len(evidence) != 2 {
		t.Fatalf("directProviderEvidence() = %#v, %#v, %t", evidence, selected, ok)
	}
	if evidence[0].Level != identity.AssurancePrimary || evidence[1].Level != identity.AssuranceMFA {
		t.Fatalf("evidence levels = %#v", evidence)
	}
	for index, value := range evidence {
		wantRevision := int64(14)
		if index == 1 {
			wantRevision = 1
		}
		if value.Source.Local || !value.Source.DirectPlatform || value.Source.ProviderID != providerID ||
			value.Source.BindingID != (identity.EntityID{}) || value.TrustRuleRevision == nil ||
			*value.TrustRuleRevision != wantRevision {
			t.Fatalf("evidence[%d] = %#v", index, value)
		}
	}
	wantTrustedExpiry := authenticatedAt.Add(10 * time.Minute)
	if evidence[1].ExpiresAt == nil || !evidence[1].ExpiresAt.Equal(wantTrustedExpiry) {
		t.Fatalf("trusted expiry = %v, want %v", evidence[1].ExpiresAt, wantTrustedExpiry)
	}
	if selected.Level != identity.AssuranceMFA || selected.TrustRuleID == nil ||
		*selected.TrustRuleID != directTestEntityID(7) || selected.TrustRuleRevision == nil ||
		*selected.TrustRuleRevision != 1 {
		t.Fatalf("selected assurance = %#v", selected)
	}
}

func TestDirectProviderEvidenceMalformedOptionalClaimsDegradeToPrimary(t *testing.T) {
	acr := "urn:example:mfa"
	rules := []DirectOIDCTrustRule{{
		RuleID: directTestEntityID(7), Revision: 1, Enabled: true,
		Level: identity.AssuranceMFA, ACR: &acr, RequiredAMR: []string{"mfa"},
		MaximumAuthenticationAge: 10 * time.Minute,
	}}
	tests := map[string]struct {
		acr string
		amr []string
	}{
		"control in ACR":        {acr: "urn:\nexample:mfa", amr: []string{"mfa"}},
		"unsorted AMR":          {acr: acr, amr: []string{"pwd", "mfa"}},
		"duplicate AMR":         {acr: acr, amr: []string{"mfa", "mfa"}},
		"directional AMR":       {acr: acr, amr: []string{"mfa\u202e"}},
		"case mismatch is safe": {acr: "urn:example:MFA", amr: []string{"mfa"}},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			evidence, selected, ok := directProviderEvidence(
				directTestEntityID(1), 14, directTestNow.Add(-time.Minute), directTestNow.Add(time.Hour),
				cloneDirectOIDCTrustRules(rules), test.acr, test.amr,
			)
			if !ok || len(evidence) != 1 || evidence[0].Level != identity.AssurancePrimary {
				t.Fatalf("directProviderEvidence() = %#v, %#v, %t", evidence, selected, ok)
			}
			if selected.Level != identity.AssurancePrimary || selected.TrustRuleID != nil ||
				selected.TrustRuleRevision != nil {
				t.Fatalf("primary selection = %#v", selected)
			}
		})
	}
}

func TestDirectProviderEvidenceSelectsStrongestThenStrictestThenLowestRuleID(t *testing.T) {
	authenticatedAt := directTestNow.Add(-time.Minute)
	rules := []DirectOIDCTrustRule{
		{RuleID: directTestEntityID(9), Revision: 9, Enabled: true, Level: identity.AssuranceMFA, RequiredAMR: []string{"mfa"}, MaximumAuthenticationAge: 5 * time.Minute},
		{RuleID: directTestEntityID(8), Revision: 8, Enabled: true, Level: identity.AssurancePhishingResistant, RequiredAMR: []string{"mfa"}, MaximumAuthenticationAge: 10 * time.Minute},
		{RuleID: directTestEntityID(7), Revision: 7, Enabled: true, Level: identity.AssurancePhishingResistant, RequiredAMR: []string{"mfa"}, MaximumAuthenticationAge: 5 * time.Minute},
		{RuleID: directTestEntityID(6), Revision: 6, Enabled: true, Level: identity.AssurancePhishingResistant, RequiredAMR: []string{"mfa"}, MaximumAuthenticationAge: 5 * time.Minute},
	}

	for name, candidateRules := range map[string][]DirectOIDCTrustRule{
		"source order": cloneDirectOIDCTrustRules(rules),
		"reverse order": func() []DirectOIDCTrustRule {
			value := cloneDirectOIDCTrustRules(rules)
			slices.Reverse(value)
			return value
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			evidence, selected, ok := directProviderEvidence(
				directTestEntityID(1), 14, authenticatedAt, directTestNow.Add(time.Hour),
				candidateRules, "", []string{"mfa"},
			)
			if !ok || len(evidence) != 5 || selected.Level != identity.AssurancePhishingResistant ||
				selected.TrustRuleID == nil || *selected.TrustRuleID != directTestEntityID(6) ||
				selected.TrustRuleRevision == nil || *selected.TrustRuleRevision != 6 {
				t.Fatalf("selection = %#v, evidence=%#v, ok=%t", selected, evidence, ok)
			}
		})
	}
}

func TestDirectProviderEvidenceRejectsMalformedTrustSnapshots(t *testing.T) {
	acr := "urn:example:mfa"
	valid := DirectOIDCTrustRule{
		RuleID: directTestEntityID(7), Revision: 1, Enabled: true,
		Level: identity.AssuranceMFA, ACR: &acr, MaximumAuthenticationAge: time.Minute,
	}
	tests := map[string][]DirectOIDCTrustRule{
		"zero rule ID":     {func() DirectOIDCTrustRule { value := valid; value.RuleID = identity.EntityID{}; return value }()},
		"future rule ID":   {func() DirectOIDCTrustRule { value := valid; value.RuleID = directFutureEntityID(); return value }()},
		"zero revision":    {func() DirectOIDCTrustRule { value := valid; value.Revision = 0; return value }()},
		"unknown level":    {func() DirectOIDCTrustRule { value := valid; value.Level = 99; return value }()},
		"empty conditions": {func() DirectOIDCTrustRule { value := valid; value.ACR = nil; return value }()},
		"subsecond max age": {func() DirectOIDCTrustRule {
			value := valid
			value.MaximumAuthenticationAge = time.Second + time.Nanosecond
			return value
		}()},
		"duplicate rule IDs": {valid, valid},
	}

	for name, rules := range tests {
		t.Run(name, func(t *testing.T) {
			if evidence, selected, ok := directProviderEvidence(
				directTestEntityID(1), 14, directTestNow.Add(-time.Minute), directTestNow.Add(time.Hour),
				rules, acr, []string{"mfa"},
			); ok || evidence != nil || selected != (DirectSelectedAssurance{}) {
				t.Fatalf("directProviderEvidence() = %#v, %#v, %t", evidence, selected, ok)
			}
		})
	}
}

func TestCloneDirectOIDCTrustRulesOwnsNestedAdapterSlices(t *testing.T) {
	acr := "urn:example:mfa"
	source := []DirectOIDCTrustRule{{ACR: &acr, RequiredAMR: []string{"mfa"}}}
	cloned := cloneDirectOIDCTrustRules(source)
	*source[0].ACR = "mutated"
	source[0].RequiredAMR[0] = "mutated"
	if cloned[0].ACR == nil || *cloned[0].ACR != "urn:example:mfa" || cloned[0].RequiredAMR[0] != "mfa" {
		t.Fatalf("clone retained adapter storage: %#v", cloned)
	}
}

func TestDirectOIDCTrustFormattingRedactsExactEvidence(t *testing.T) {
	canary := "trust-canary@example.test"
	rule := DirectOIDCTrustRule{ACR: &canary, RequiredAMR: []string{canary}}
	for _, rendered := range []string{fmt.Sprint(rule), fmt.Sprintf("%#v", rule)} {
		if strings.Contains(rendered, canary) {
			t.Fatalf("format leaked exact evidence: %s", rendered)
		}
	}
}
