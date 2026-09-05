package identity

import (
	"fmt"
	"slices"
	"testing"
	"time"
)

func TestCombineAssurancePoliciesIsMonotonicAndOrderIndependent(t *testing.T) {
	deadlineEarly := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	deadlineLate := deadlineEarly.Add(24 * time.Hour)
	policies := []AssurancePolicy{
		{ID: EntityID{14}, Revision: 14, Level: AssuranceMFA, Freshness: 12 * time.Hour, EnrollmentDeadline: &deadlineLate},
		{ID: EntityID{7}, Revision: 7, Level: AssurancePhishingResistant, LocalRequired: true, Freshness: time.Hour},
		{ID: EntityID{22}, Revision: 22, Level: AssurancePrimary, Freshness: 0, EnrollmentDeadline: &deadlineEarly},
	}

	first, err := CombineAssurancePolicies(policies)
	if err != nil {
		t.Fatalf("CombineAssurancePolicies() error = %v", err)
	}
	slices.Reverse(policies)
	second, err := CombineAssurancePolicies(policies)
	if err != nil {
		t.Fatalf("CombineAssurancePolicies(reversed) error = %v", err)
	}
	if first.Level != AssurancePhishingResistant || !first.LocalRequired || first.Freshness != time.Hour ||
		first.EnrollmentDeadline == nil || !first.EnrollmentDeadline.Equal(deadlineEarly) ||
		!slices.Equal(first.PolicyRevisions, []AssurancePolicyRevision{
			{PolicyID: EntityID{7}, Revision: 7},
			{PolicyID: EntityID{14}, Revision: 14},
			{PolicyID: EntityID{22}, Revision: 22},
		}) {
		t.Fatalf("combined requirement = %#v", first)
	}
	if first.Level != second.Level || first.LocalRequired != second.LocalRequired ||
		first.Freshness != second.Freshness || !first.EnrollmentDeadline.Equal(*second.EnrollmentDeadline) ||
		!slices.Equal(first.PolicyRevisions, second.PolicyRevisions) {
		t.Fatalf("order-dependent result: %#v != %#v", first, second)
	}
}

func TestCombineAssurancePoliciesRejectsUnknownOrConflictingSnapshots(t *testing.T) {
	for name, policies := range map[string][]AssurancePolicy{
		"empty":         nil,
		"missing id":    {{Revision: 1, Level: AssurancePrimary}},
		"unknown level": {{ID: EntityID{1}, Revision: 1, Level: 99}},
		"duplicate":     {{ID: EntityID{1}, Revision: 1, Level: AssurancePrimary}, {ID: EntityID{1}, Revision: 2, Level: AssuranceMFA}},
		"negative age":  {{ID: EntityID{1}, Revision: 1, Level: AssuranceMFA, Freshness: -time.Second}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := CombineAssurancePolicies(policies); err == nil {
				t.Fatal("malformed policy snapshot was accepted")
			}
		})
	}
}

func TestEvaluateAssuranceRequiresExactLocalFreshEvidence(t *testing.T) {
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	requirement := EffectiveAssuranceRequirement{
		Level: AssurancePhishingResistant, LocalRequired: true, Freshness: 10 * time.Minute,
		PolicyRevisions: []AssurancePolicyRevision{
			{PolicyID: EntityID{3}, Revision: 3},
			{PolicyID: EntityID{8}, Revision: 8},
		},
	}
	trustRevision := int64(4)
	factorRevision := int64(7)
	provider := AssuranceEvidence{
		Level: AssurancePhishingResistant, Kind: AssuranceEvidenceFactor,
		Source:          AssuranceSource{ProviderID: EntityID{1}, BindingID: EntityID{2}},
		AuthenticatedAt: now.Add(-time.Minute), TrustRuleRevision: &trustRevision,
	}
	if got := EvaluateAssurance(now, requirement, []AssuranceEvidence{provider}, false); got != AssuranceStepUpRequired {
		t.Fatalf("provider decision = %q", got)
	}
	local := AssuranceEvidence{
		Level: AssurancePhishingResistant, Kind: AssuranceEvidenceFactor,
		Source: AssuranceSource{Local: true}, AuthenticatedAt: now.Add(-time.Minute),
		FactorRevision: &factorRevision,
	}
	if got := EvaluateAssurance(now, requirement, []AssuranceEvidence{local}, false); got != AssuranceSatisfied {
		t.Fatalf("local decision = %q", got)
	}
	local.AuthenticatedAt = now.Add(-11 * time.Minute)
	if got := EvaluateAssurance(now, requirement, []AssuranceEvidence{local}, false); got != AssuranceStepUpRequired {
		t.Fatalf("stale decision = %q", got)
	}
}

func TestEvaluateAssuranceRestrictsRecoveryAndEnrollmentGrace(t *testing.T) {
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	factorRevision := int64(2)
	recovery := AssuranceEvidence{
		Level: AssurancePhishingResistant, Kind: AssuranceEvidenceRecovery,
		Source: AssuranceSource{Local: true}, AuthenticatedAt: now,
		FactorRevision: &factorRevision,
	}
	deadline := now.Add(time.Hour)
	requirement := EffectiveAssuranceRequirement{
		Level: AssurancePhishingResistant, EnrollmentDeadline: &deadline,
		PolicyRevisions: []AssurancePolicyRevision{{PolicyID: EntityID{1}, Revision: 1}},
	}
	if got := EvaluateAssurance(now, requirement, []AssuranceEvidence{recovery}, true); got != AssuranceEnrollmentOnly {
		t.Fatalf("recovery decision = %q", got)
	}
	if got := EvaluateAssurance(deadline, requirement, nil, true); got != AssuranceEnrollmentEnded {
		t.Fatalf("expired grace decision = %q", got)
	}
	mfaRequirement := requirement
	mfaRequirement.Level = AssuranceMFA
	mfaRequirement.EnrollmentDeadline = nil
	if got := EvaluateAssurance(now, mfaRequirement, []AssuranceEvidence{recovery}, false); got != AssuranceStepUpRequired {
		t.Fatalf("ordinary recovery decision = %q", got)
	}
}

func TestEvaluateAssuranceDeniesMalformedEvidenceInsteadOfIgnoringIt(t *testing.T) {
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	requirement := EffectiveAssuranceRequirement{
		Level:           AssurancePrimary,
		PolicyRevisions: []AssurancePolicyRevision{{PolicyID: EntityID{1}, Revision: 1}},
	}
	malformed := AssuranceEvidence{
		Level: AssurancePrimary, Kind: AssuranceEvidenceFactor,
		Source: AssuranceSource{Local: true, ProviderID: EntityID{1}}, AuthenticatedAt: now,
	}
	factorRevision := int64(1)
	valid := AssuranceEvidence{
		Level: AssurancePrimary, Kind: AssuranceEvidenceFactor,
		Source: AssuranceSource{Local: true}, AuthenticatedAt: now, FactorRevision: &factorRevision,
	}
	if got := EvaluateAssurance(now, requirement, []AssuranceEvidence{valid, malformed}, false); got != AssuranceDenied {
		t.Fatalf("decision = %q", got)
	}
}

func TestEvaluateAssuranceClosesLocalTenantAndDirectProviderProvenance(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	requirement := EffectiveAssuranceRequirement{
		Level:           AssurancePrimary,
		PolicyRevisions: []AssurancePolicyRevision{{PolicyID: EntityID{9}, Revision: 1}},
	}
	factorRevision := int64(4)
	trustRevision := int64(7)
	providerID := EntityID{1}
	bindingID := EntityID{2}

	tests := []struct {
		name           string
		source         AssuranceSource
		factorRevision *int64
		trustRevision  *int64
		want           AssuranceDecision
	}{
		{name: "local", source: AssuranceSource{Local: true}, factorRevision: &factorRevision, want: AssuranceSatisfied},
		{name: "tenant provider", source: AssuranceSource{ProviderID: providerID, BindingID: bindingID}, trustRevision: &trustRevision, want: AssuranceSatisfied},
		{name: "direct platform provider", source: AssuranceSource{DirectPlatform: true, ProviderID: providerID}, trustRevision: &trustRevision, want: AssuranceSatisfied},
		{name: "zero authority", source: AssuranceSource{}, trustRevision: &trustRevision, want: AssuranceDenied},
		{name: "local with direct discriminator", source: AssuranceSource{Local: true, DirectPlatform: true}, factorRevision: &factorRevision, want: AssuranceDenied},
		{name: "local with provider", source: AssuranceSource{Local: true, ProviderID: providerID}, factorRevision: &factorRevision, want: AssuranceDenied},
		{name: "local with binding", source: AssuranceSource{Local: true, BindingID: bindingID}, factorRevision: &factorRevision, want: AssuranceDenied},
		{name: "local with direct provider", source: AssuranceSource{Local: true, DirectPlatform: true, ProviderID: providerID}, factorRevision: &factorRevision, want: AssuranceDenied},
		{name: "tenant provider without provider", source: AssuranceSource{BindingID: bindingID}, trustRevision: &trustRevision, want: AssuranceDenied},
		{name: "tenant provider without binding", source: AssuranceSource{ProviderID: providerID}, trustRevision: &trustRevision, want: AssuranceDenied},
		{name: "direct without provider", source: AssuranceSource{DirectPlatform: true}, trustRevision: &trustRevision, want: AssuranceDenied},
		{name: "direct with binding", source: AssuranceSource{DirectPlatform: true, ProviderID: providerID, BindingID: bindingID}, trustRevision: &trustRevision, want: AssuranceDenied},
		{name: "local with trust revision", source: AssuranceSource{Local: true}, trustRevision: &trustRevision, want: AssuranceDenied},
		{name: "tenant with factor revision", source: AssuranceSource{ProviderID: providerID, BindingID: bindingID}, factorRevision: &factorRevision, want: AssuranceDenied},
		{name: "direct with factor revision", source: AssuranceSource{DirectPlatform: true, ProviderID: providerID}, factorRevision: &factorRevision, want: AssuranceDenied},
		{name: "direct without trust revision", source: AssuranceSource{DirectPlatform: true, ProviderID: providerID}, want: AssuranceDenied},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			evidence := AssuranceEvidence{
				Level: AssurancePrimary, Kind: AssuranceEvidenceFactor, Source: test.source,
				AuthenticatedAt: now, FactorRevision: test.factorRevision, TrustRuleRevision: test.trustRevision,
			}
			if got := EvaluateAssurance(now, requirement, []AssuranceEvidence{evidence}, false); got != test.want {
				t.Fatalf("EvaluateAssurance() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestEvaluateAssuranceExhaustsAssuranceSourceAuthorityMatrix(t *testing.T) {
	now := time.Date(2026, 8, 30, 13, 0, 0, 0, time.UTC)
	requirement := EffectiveAssuranceRequirement{
		Level:           AssurancePrimary,
		PolicyRevisions: []AssurancePolicyRevision{{PolicyID: EntityID{11}, Revision: 1}},
	}
	factorRevision := int64(2)
	trustRevision := int64(3)

	for _, local := range []bool{false, true} {
		for _, direct := range []bool{false, true} {
			for _, hasProvider := range []bool{false, true} {
				for _, hasBinding := range []bool{false, true} {
					name := fmt.Sprintf("local=%t/direct=%t/provider=%t/binding=%t", local, direct, hasProvider, hasBinding)
					t.Run(name, func(t *testing.T) {
						source := AssuranceSource{Local: local, DirectPlatform: direct}
						if hasProvider {
							source.ProviderID = EntityID{1}
						}
						if hasBinding {
							source.BindingID = EntityID{2}
						}
						validLocal := local && !direct && !hasProvider && !hasBinding
						validTenant := !local && !direct && hasProvider && hasBinding
						validDirect := !local && direct && hasProvider && !hasBinding
						evidence := AssuranceEvidence{
							Level: AssurancePrimary, Kind: AssuranceEvidenceFactor,
							Source: source, AuthenticatedAt: now,
						}
						if validLocal {
							evidence.FactorRevision = &factorRevision
						} else {
							evidence.TrustRuleRevision = &trustRevision
						}
						want := AssuranceDenied
						if validLocal || validTenant || validDirect {
							want = AssuranceSatisfied
						}
						if got := EvaluateAssurance(now, requirement, []AssuranceEvidence{evidence}, false); got != want {
							t.Fatalf("EvaluateAssurance() = %q, want %q", got, want)
						}
					})
				}
			}
		}
	}
}
