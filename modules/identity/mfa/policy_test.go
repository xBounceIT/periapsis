package mfa

import (
	"errors"
	"slices"
	"testing"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

func TestResolvePolicyUsesExplicitPrecedenceAndMonotonicCombination(t *testing.T) {
	deadline := mfaTestNow.Add(24 * time.Hour)
	context := PolicyContext{
		TenantID: mfaID(1), RoleIDs: []identity.EntityID{mfaID(20)},
		SecurityGroupIDs: []identity.EntityID{mfaID(10)}, Action: "case.export",
	}
	policies := []ScopedPolicy{
		{Scope: PolicyAction, TenantID: mfaID(1), Action: "case.export", Policy: identity.AssurancePolicy{
			ID: mfaID(50), Revision: 5, Level: identity.AssurancePhishingResistant, Freshness: 10 * time.Minute,
		}},
		{Scope: PolicyRole, TenantID: mfaID(1), TargetID: mfaID(20), Policy: identity.AssurancePolicy{
			ID: mfaID(40), Revision: 4, Level: identity.AssuranceMFA, LocalRequired: true,
		}},
		{Scope: PolicySecurityGroup, TenantID: mfaID(1), TargetID: mfaID(10), Policy: identity.AssurancePolicy{
			ID: mfaID(30), Revision: 3, Level: identity.AssuranceMFA, Freshness: time.Hour,
		}},
		{Scope: PolicyTenantBaseline, TenantID: mfaID(1), Policy: identity.AssurancePolicy{
			ID: mfaID(20), Revision: 2, Level: identity.AssurancePrimary, EnrollmentDeadline: &deadline,
		}},
		{Scope: PolicyPlatformFloor, Policy: identity.AssurancePolicy{
			ID: mfaID(10), Revision: 1, Level: identity.AssuranceMFA,
		}},
	}
	resolved, err := ResolvePolicy(context, policies)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Requirement.Level != identity.AssurancePhishingResistant || !resolved.Requirement.LocalRequired ||
		resolved.Requirement.Freshness != 10*time.Minute || resolved.Requirement.EnrollmentDeadline == nil ||
		!resolved.Requirement.EnrollmentDeadline.Equal(deadline) {
		t.Fatalf("requirement = %#v", resolved.Requirement)
	}
	wantOrder := []PolicyScope{
		PolicyPlatformFloor, PolicyTenantBaseline, PolicySecurityGroup, PolicyRole, PolicyAction,
	}
	gotOrder := make([]PolicyScope, len(resolved.Applications))
	for index := range resolved.Applications {
		gotOrder[index] = resolved.Applications[index].Scope
	}
	if !slices.Equal(gotOrder, wantOrder) {
		t.Fatalf("precedence = %v", gotOrder)
	}

	slices.Reverse(policies)
	reversed, err := ResolvePolicy(context, policies)
	if err != nil || reversed.Requirement.Level != resolved.Requirement.Level ||
		!slices.Equal(reversed.Applications, resolved.Applications) {
		t.Fatalf("order-dependent policy = %#v, %v", reversed, err)
	}
}

func TestResolvePolicyRejectsUnknownTargetsAndConflicts(t *testing.T) {
	base := ScopedPolicy{
		Scope: PolicyTenantBaseline, TenantID: mfaID(1),
		Policy: identity.AssurancePolicy{ID: mfaID(1), Revision: 1, Level: identity.AssurancePrimary},
	}
	context := PolicyContext{TenantID: mfaID(1), RoleIDs: []identity.EntityID{mfaID(3)}, Action: "case.read"}
	tests := map[string][]ScopedPolicy{
		"missing baseline": {{
			Scope:  PolicyPlatformFloor,
			Policy: identity.AssurancePolicy{ID: mfaID(2), Revision: 1, Level: identity.AssurancePrimary},
		}},
		"cross tenant": {{
			Scope: PolicyTenantBaseline, TenantID: mfaID(9),
			Policy: identity.AssurancePolicy{ID: mfaID(2), Revision: 1, Level: identity.AssurancePrimary},
		}},
		"unknown role": {base, {
			Scope: PolicyRole, TenantID: mfaID(1), TargetID: mfaID(4),
			Policy: identity.AssurancePolicy{ID: mfaID(2), Revision: 1, Level: identity.AssuranceMFA},
		}},
		"wrong action": {base, {
			Scope: PolicyAction, TenantID: mfaID(1), Action: "case.delete",
			Policy: identity.AssurancePolicy{ID: mfaID(2), Revision: 1, Level: identity.AssuranceMFA},
		}},
		"duplicate target": {base, {
			Scope: PolicyTenantBaseline, TenantID: mfaID(1),
			Policy: identity.AssurancePolicy{ID: mfaID(2), Revision: 1, Level: identity.AssuranceMFA},
		}},
	}
	for name, policies := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ResolvePolicy(context, policies); !errors.Is(err, ErrInvalidPolicySet) {
				t.Fatalf("got %v", err)
			}
		})
	}
}
