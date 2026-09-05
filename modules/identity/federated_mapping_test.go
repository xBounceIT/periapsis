package identity

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

func TestFederatedAndLDAPAdaptersShareExactPlanningConsequences(t *testing.T) {
	ldapSnapshot := mappingSnapshot(t)
	ldapObservation := mappingObservation(
		t, true, LDAPAccountActive, "cn=SOC-L2,ou=Groups,dc=example,dc=com",
	)
	ldapPlan, err := PlanLDAPMapping(ldapObservation, ldapSnapshot)
	if err != nil {
		t.Fatalf("PlanLDAPMapping() error = %v", err)
	}

	matcher, err := CompileFederatedMappingMatcher(FederatedMappingMatcherSpec{
		Kind: FederatedMappingGroupEquals, Value: "incident-response-members",
	})
	if err != nil {
		t.Fatal(err)
	}
	federatedSnapshot := federatedSnapshotFromLDAP(ldapSnapshot, matcher)
	subject, _ := CanonicalUTF8Exact([]byte("immutable-federated-subject"))
	displayName := "Private Display Name"
	federatedObservation, err := NewFederatedMappingObservation(FederatedMappingObservationInput{
		Subject: subject, Profile: LDAPProfileValues{DisplayName: &displayName},
		Groups: []string{"incident-response-members"}, Complete: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	federatedPlan, err := PlanFederatedMapping(federatedObservation, federatedSnapshot)
	if err != nil {
		t.Fatalf("PlanFederatedMapping() error = %v", err)
	}
	if federatedPlan.Disposition() != ldapPlan.Disposition() || federatedPlan.Reason() != ldapPlan.Reason() ||
		federatedPlan.IdentityAction() != ldapPlan.IdentityAction() ||
		federatedPlan.ProviderAccessAction() != ldapPlan.ProviderAccessAction() ||
		!slices.Equal(federatedPlan.MatchedRuleIDs(), ldapPlan.MatchedRuleIDs()) ||
		!slices.Equal(federatedPlan.ProspectiveSecurityGroupIDs(), ldapPlan.ProspectiveSecurityGroupIDs()) ||
		!slices.Equal(federatedPlan.ProspectiveRoleIDs(), ldapPlan.ProspectiveRoleIDs()) ||
		!slices.Equal(federatedPlan.ProspectiveOperatorTeamAssignments(), ldapPlan.ProspectiveOperatorTeamAssignments()) ||
		!slices.Equal(federatedPlan.Changes(), ldapPlan.Changes()) {
		t.Fatalf("adapter drift:\nLDAP=%s\nfederated=%s", ldapPlan, federatedPlan)
	}
	ldapDisplay, ldapPresent, ldapErr := ldapPlan.RevealProfileField(LDAPProfileDisplayName)
	federatedDisplay, federatedPresent, federatedErr := federatedPlan.RevealProfileField(LDAPProfileDisplayName)
	if ldapErr != nil || federatedErr != nil || ldapPresent != federatedPresent || ldapDisplay != federatedDisplay {
		t.Fatalf("profile drift: LDAP=%q,%t,%v federated=%q,%t,%v",
			ldapDisplay, ldapPresent, ldapErr, federatedDisplay, federatedPresent, federatedErr)
	}
}

func TestFederatedAndLDAPAdaptersRemainEquivalentAcrossAdmissionBoundaries(t *testing.T) {
	tests := []struct {
		name     string
		matched  bool
		complete bool
		mutate   func(*LDAPPlanningSnapshot)
	}{
		{name: "mapped create", matched: true, complete: true},
		{name: "incomplete observation", matched: true, complete: false},
		{name: "no match authoritative revoke", complete: true},
		{
			name: "provider access only", complete: true,
			mutate: func(snapshot *LDAPPlanningSnapshot) {
				snapshot.NoMatchPolicy = LDAPNoMatchProviderAccessOnly
			},
		},
		{
			name: "existing identity JIT disabled", matched: true, complete: true,
			mutate: func(snapshot *LDAPPlanningSnapshot) {
				snapshot.JITMode = LDAPJITDisabled
				snapshot.ProviderAccess.ExternalIdentityExists = true
				snapshot.ProviderAccess.UserActive = true
				snapshot.ProviderAccess.TenantMembershipExists = true
				snapshot.ProviderAccess.TenantMembershipActive = true
				snapshot.ProviderAccess.AccessGrantLive = true
			},
		},
		{
			name: "existing identity required", matched: true, complete: true,
			mutate: func(snapshot *LDAPPlanningSnapshot) {
				snapshot.JITMode = LDAPJITExistingIdentity
			},
		},
		{
			name: "assignment inactive", matched: true, complete: true,
			mutate: func(snapshot *LDAPPlanningSnapshot) {
				snapshot.LiveAssignments[0].Live = false
			},
		},
		{
			name: "delegation exceeded", matched: true, complete: true,
			mutate: func(snapshot *LDAPPlanningSnapshot) {
				snapshot.Delegation = snapshot.Delegation[:1]
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ldapSnapshot := mappingSnapshot(t)
			if test.mutate != nil {
				test.mutate(&ldapSnapshot)
			}
			ldapGroups := []string{"cn=OTHER,ou=Groups,dc=example,dc=com"}
			federatedGroups := []string{"other"}
			if test.matched {
				ldapGroups = []string{"cn=SOC-L2,ou=Groups,dc=example,dc=com"}
				federatedGroups = []string{"incident-response-members"}
			}
			ldapObservation := mappingObservation(t, test.complete, LDAPAccountActive, ldapGroups...)
			ldapPlan, ldapErr := PlanLDAPMapping(ldapObservation, ldapSnapshot)

			matcher, err := CompileFederatedMappingMatcher(FederatedMappingMatcherSpec{
				Kind: FederatedMappingGroupEquals, Value: "incident-response-members",
			})
			if err != nil {
				t.Fatal(err)
			}
			federatedSnapshot := federatedSnapshotFromLDAP(ldapSnapshot, matcher)
			subject, err := CanonicalUTF8Exact([]byte("immutable-federated-subject"))
			if err != nil {
				t.Fatal(err)
			}
			displayName := "Private Display Name"
			federatedObservation, err := NewFederatedMappingObservation(FederatedMappingObservationInput{
				Subject: subject, Profile: LDAPProfileValues{DisplayName: &displayName},
				Groups: federatedGroups, Complete: test.complete,
			})
			if err != nil {
				t.Fatal(err)
			}
			federatedPlan, federatedErr := PlanFederatedMapping(federatedObservation, federatedSnapshot)
			assertProviderMappingPlansEquivalent(t, ldapPlan, ldapErr, federatedPlan, federatedErr)
		})
	}
}

func TestFederatedMatchersAreTypedExactAndNeverRequireDN(t *testing.T) {
	groupMatcher, err := CompileFederatedMappingMatcher(FederatedMappingMatcherSpec{
		Kind: FederatedMappingGroupEquals, Value: "not a DN / exact group",
	})
	if err != nil {
		t.Fatal(err)
	}
	scalarMatcher, err := CompileFederatedMappingMatcher(FederatedMappingMatcherSpec{
		Kind: FederatedMappingScalarEquals, ClaimName: "department", Value: "DFIR",
	})
	if err != nil {
		t.Fatal(err)
	}
	subject, _ := CanonicalUTF8Exact([]byte("subject"))
	observation, err := NewFederatedMappingObservation(FederatedMappingObservationInput{
		Subject: subject,
		Scalars: []FederatedMappingScalar{{Name: "department", Value: "DFIR"}},
		Groups:  []string{"not a DN / exact group"}, Complete: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, matcher := range map[string]CompiledFederatedMappingMatcher{
		"group": groupMatcher, "scalar": scalarMatcher,
	} {
		matched, matchErr := matcher.match(observation)
		if matchErr != nil || !matched {
			t.Fatalf("%s match = %t, %v", name, matched, matchErr)
		}
	}
	caseChanged, _ := CompileFederatedMappingMatcher(FederatedMappingMatcherSpec{
		Kind: FederatedMappingGroupEquals, Value: "Not a DN / exact group",
	})
	if matched, matchErr := caseChanged.match(observation); matchErr != nil || matched {
		t.Fatalf("case-changed group match = %t, %v", matched, matchErr)
	}
}

func TestFederatedMappingFailsClosedForMalformedMatchersAndObservations(t *testing.T) {
	for name, spec := range map[string]FederatedMappingMatcherSpec{
		"unknown kind":   {Kind: 99, Value: "value"},
		"group claim":    {Kind: FederatedMappingGroupEquals, ClaimName: "groups", Value: "value"},
		"scalar no name": {Kind: FederatedMappingScalarEquals, Value: "value"},
		"directional":    {Kind: FederatedMappingGroupEquals, Value: "group\u202evalue"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := CompileFederatedMappingMatcher(spec); !errors.Is(err, ErrInvalidFederatedPlanningSnapshot) {
				t.Fatalf("CompileFederatedMappingMatcher() error = %v", err)
			}
		})
	}
	subject, _ := CanonicalUTF8Exact([]byte("subject"))
	for name, input := range map[string]FederatedMappingObservationInput{
		"duplicate scalar": {
			Subject: subject, Scalars: []FederatedMappingScalar{{Name: "department", Value: "one"}, {Name: "department", Value: "two"}},
			Complete: true,
		},
		"control group": {Subject: subject, Groups: []string{"group\nprivate"}, Complete: true},
		"zero subject":  {Groups: []string{"group"}, Complete: true},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewFederatedMappingObservation(input); !errors.Is(err, ErrInvalidFederatedMappingObservation) {
				t.Fatalf("NewFederatedMappingObservation() error = %v", err)
			}
		})
	}
}

func TestFederatedMappingNoMatchDeniesWithoutIdentityOrAccess(t *testing.T) {
	matcher, _ := CompileFederatedMappingMatcher(FederatedMappingMatcherSpec{
		Kind: FederatedMappingScalarEquals, ClaimName: "department", Value: "DFIR",
	})
	ldapSnapshot := minimalMappingSnapshot()
	ldapSnapshot.SecurityGroups = []LDAPSecurityGroupPolicy{{SecurityGroupID: testID(0x51)}}
	federatedSnapshot := federatedSnapshotFromLDAP(ldapSnapshot, matcher)
	federatedSnapshot.Rules = []FederatedMappingRule{{
		RuleID: testID(0x41), RuleEpochID: testID(0x42), SourceID: testID(0x43),
		Revision: 1, Enabled: true, Matcher: matcher, Mode: LDAPReconciliationAuthoritative,
		SecurityGroupID: testID(0x51),
	}}
	subject, _ := CanonicalUTF8Exact([]byte("subject"))
	observation, _ := NewFederatedMappingObservation(FederatedMappingObservationInput{
		Subject: subject, Scalars: []FederatedMappingScalar{{Name: "department", Value: "Finance"}}, Complete: true,
	})
	plan, err := PlanFederatedMapping(observation, federatedSnapshot)
	if err != nil || plan.Disposition() != LDAPPlanDenied || plan.Reason() != LDAPPlanReasonNoMapping ||
		plan.IdentityAction() != LDAPIdentityNoChange ||
		plan.ProviderAccessAction() != LDAPProviderAccessNoChange || len(plan.Changes()) != 0 {
		t.Fatalf("PlanFederatedMapping() = %s, %v", plan, err)
	}
}

func TestFederatedMappingFormattingRedactsClaimsAndProfile(t *testing.T) {
	matcher, _ := CompileFederatedMappingMatcher(FederatedMappingMatcherSpec{
		Kind: FederatedMappingScalarEquals, ClaimName: "private-claim-name", Value: "private-claim-value",
	})
	subject, _ := CanonicalUTF8Exact([]byte("private-subject"))
	profile := "private-profile"
	observation, _ := NewFederatedMappingObservation(FederatedMappingObservationInput{
		Subject: subject, Profile: LDAPProfileValues{DisplayName: &profile},
		Scalars: []FederatedMappingScalar{{Name: "private-claim-name", Value: "private-claim-value"}},
		Groups:  []string{"private-group"}, Complete: true,
	})
	formatted := fmt.Sprintf("%v|%+v|%#v|%s|%s", matcher, matcher, matcher, observation, FederatedMappingRule{
		Matcher: matcher, AdministrativeNote: "private-note",
	})
	for _, canary := range []string{
		"private-subject", "private-profile", "private-claim-name", "private-claim-value", "private-group", "private-note",
	} {
		if strings.Contains(formatted, canary) {
			t.Fatalf("format leaked %q: %s", canary, formatted)
		}
	}
}

func TestCloneFederatedPlanningSnapshotOwnsNestedPolicyState(t *testing.T) {
	matcher, err := CompileFederatedMappingMatcher(FederatedMappingMatcherSpec{
		Kind: FederatedMappingGroupEquals, Value: "incident-response-members",
	})
	if err != nil {
		t.Fatal(err)
	}
	original := federatedSnapshotFromLDAP(mappingSnapshot(t), matcher)
	clone := CloneFederatedPlanningSnapshot(original)

	original.Rules[0].RoleIDs[0] = testID(0xe1)
	original.Rules[0].OperatorTeam.TeamID = testID(0xe2)
	original.SecurityGroups[0].ActiveRoleIDs[0] = testID(0xe3)
	original.RolePolicies[0].Policy[0].Permission = "case.delete"
	original.ExistingEffectiveRoleIDs[0] = testID(0xe4)
	original.LiveOwnedEdges[0].SourceID = testID(0xe5)

	if clone.Rules[0].RoleIDs[0] == original.Rules[0].RoleIDs[0] ||
		clone.Rules[0].OperatorTeam.TeamID == original.Rules[0].OperatorTeam.TeamID ||
		clone.SecurityGroups[0].ActiveRoleIDs[0] == original.SecurityGroups[0].ActiveRoleIDs[0] ||
		clone.RolePolicies[0].Policy[0] == original.RolePolicies[0].Policy[0] ||
		clone.ExistingEffectiveRoleIDs[0] == original.ExistingEffectiveRoleIDs[0] ||
		clone.LiveOwnedEdges[0] == original.LiveOwnedEdges[0] {
		t.Fatal("cloned federated planning snapshot retained mutable source storage")
	}
}

func federatedSnapshotFromLDAP(
	snapshot LDAPPlanningSnapshot,
	matcher CompiledFederatedMappingMatcher,
) FederatedPlanningSnapshot {
	result := FederatedPlanningSnapshot{
		TenantID: snapshot.TenantID, Provider: snapshot.Provider, BindingID: snapshot.BindingID,
		ConfigurationRevision: snapshot.ConfigurationRevision, RuleSetRevision: snapshot.RuleSetRevision,
		AuthorizationRevision: snapshot.AuthorizationRevision, JITMode: snapshot.JITMode,
		NoMatchPolicy: snapshot.NoMatchPolicy, EffectiveUntil: snapshot.EffectiveUntil,
		ProviderAccess: snapshot.ProviderAccess, SecurityGroups: snapshot.SecurityGroups,
		LiveAssignments: snapshot.LiveAssignments, RolePolicies: snapshot.RolePolicies,
		ExistingEffectiveRoleIDs: snapshot.ExistingEffectiveRoleIDs, Delegation: snapshot.Delegation,
		LiveOwnedEdges: snapshot.LiveOwnedEdges,
	}
	for _, rule := range snapshot.Rules {
		result.Rules = append(result.Rules, FederatedMappingRule{
			RuleID: rule.RuleID, RuleEpochID: rule.RuleEpochID, SourceID: rule.SourceID,
			Revision: rule.Revision, Priority: rule.Priority, Enabled: rule.Enabled, Matcher: matcher,
			Mode: rule.Mode, SecurityGroupID: rule.SecurityGroupID, RoleIDs: rule.RoleIDs,
			OperatorTeam: rule.OperatorTeam, AdministrativeNote: rule.AdministrativeNote,
		})
	}
	return result
}

func assertProviderMappingPlansEquivalent(
	t *testing.T,
	ldapPlan LDAPMappingPlan,
	ldapErr error,
	federatedPlan FederatedMappingPlan,
	federatedErr error,
) {
	t.Helper()
	if (ldapErr == nil) != (federatedErr == nil) ||
		ldapPlan.Disposition() != federatedPlan.Disposition() || ldapPlan.Reason() != federatedPlan.Reason() ||
		ldapPlan.IdentityAction() != federatedPlan.IdentityAction() ||
		ldapPlan.ProviderAccessAction() != federatedPlan.ProviderAccessAction() ||
		!slices.Equal(ldapPlan.MatchedRuleIDs(), federatedPlan.MatchedRuleIDs()) ||
		!slices.Equal(ldapPlan.ProspectiveSecurityGroupIDs(), federatedPlan.ProspectiveSecurityGroupIDs()) ||
		!slices.Equal(ldapPlan.ProspectiveRoleIDs(), federatedPlan.ProspectiveRoleIDs()) ||
		!slices.Equal(ldapPlan.ProspectiveOperatorTeamAssignments(), federatedPlan.ProspectiveOperatorTeamAssignments()) ||
		!slices.Equal(ldapPlan.Changes(), federatedPlan.Changes()) ||
		!equalProviderMappingProfiles(ldapPlan, federatedPlan) {
		t.Fatalf("adapter drift:\nLDAP=%s error=%v\nfederated=%s error=%v", ldapPlan, ldapErr, federatedPlan, federatedErr)
	}
}

func equalProviderMappingProfiles(ldapPlan LDAPMappingPlan, federatedPlan FederatedMappingPlan) bool {
	for _, field := range []LDAPProfileField{
		LDAPProfileFirstName, LDAPProfileLastName, LDAPProfileDisplayName,
		LDAPProfileUsername, LDAPProfileAlternateUsername, LDAPProfileEmail,
	} {
		ldapValue, ldapPresent, ldapErr := ldapPlan.RevealProfileField(field)
		federatedValue, federatedPresent, federatedErr := federatedPlan.RevealProfileField(field)
		if ldapErr != nil || federatedErr != nil || ldapPresent != federatedPresent || ldapValue != federatedValue {
			return false
		}
	}
	return true
}
