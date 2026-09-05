package identity

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestPlanLDAPMappingCombinesEveryMatchAndReconcilesExactSources(t *testing.T) {
	observation := mappingObservation(t, true, LDAPAccountActive,
		"cn=SOC-L2,ou=Groups,dc=example,dc=com",
		"cn=Unrelated,ou=Groups,dc=example,dc=com",
	)
	snapshot := mappingSnapshot(t)
	plan, err := PlanLDAPMapping(observation, snapshot)
	if err != nil {
		t.Fatalf("PlanLDAPMapping() error = %v", err)
	}
	if plan.Disposition() != LDAPPlanAdmitted || plan.Reason() != LDAPPlanReasonMapped {
		t.Fatalf("plan = %s", plan)
	}
	if plan.IdentityAction() != LDAPIdentityCreateUserAndExternalIdentity ||
		plan.ProviderAccessAction() != LDAPProviderAccessEnsure {
		t.Fatalf("identity/access actions = %d/%d", plan.IdentityAction(), plan.ProviderAccessAction())
	}
	wantRuleIDs := []EntityID{testID(0x31), testID(0x41)}
	if got := plan.MatchedRuleIDs(); !slicesEqualEntityIDs(got, wantRuleIDs) {
		t.Fatalf("matched rules = %x", got)
	}
	if got := plan.ProspectiveSecurityGroupIDs(); len(got) != 1 || got[0] != testID(0x51) {
		t.Fatalf("prospective groups = %x", got)
	}
	if got := plan.ProspectiveRoleIDs(); !slicesEqualEntityIDs(got, []EntityID{testID(0x61), testID(0x62), testID(0x63)}) {
		t.Fatalf("prospective roles = %x", got)
	}
	if got := plan.ProspectiveOperatorTeamAssignments(); len(got) != 1 ||
		got[0] != (LDAPOperatorTeamTarget{TeamID: testID(0x71), AssignmentEpochID: testID(0x72)}) {
		t.Fatalf("prospective team assignments = %x", got)
	}

	changes := plan.Changes()
	if len(changes) != 6 {
		t.Fatalf("changes = %#v", changes)
	}
	counts := map[LDAPMappingChangeOperation]int{}
	for _, change := range changes {
		counts[change.Operation]++
		if change.SourceID != testID(0x33) && change.SourceID != testID(0x43) {
			t.Fatalf("change lost source provenance: %#v", change)
		}
	}
	if counts[LDAPMappingEnsure] != 4 || counts[LDAPMappingRefresh] != 1 || counts[LDAPMappingRevoke] != 1 {
		t.Fatalf("change counts = %#v", counts)
	}
	for _, change := range changes {
		if change.SourceID == testID(0x33) && change.Operation == LDAPMappingRevoke {
			t.Fatalf("additive source revoked an absent edge: %#v", change)
		}
	}

	changes[0] = LDAPMappingChange{}
	if plan.Changes()[0] == (LDAPMappingChange{}) {
		t.Fatal("Changes returned mutable planner storage")
	}
	profile, present, revealErr := plan.RevealProfileField(LDAPProfileDisplayName)
	if revealErr != nil || !present || profile != "Private Display Name" {
		t.Fatalf("profile = %q, %t, %v", profile, present, revealErr)
	}
}

func TestPlanLDAPMappingNoMatchAndJITPoliciesFailClosed(t *testing.T) {
	observation := mappingObservation(t, true, LDAPAccountActive)
	base := minimalMappingSnapshot()
	tests := []struct {
		name        string
		mutate      func(*LDAPPlanningSnapshot)
		reason      LDAPPlanReason
		disposition LDAPPlanDisposition
		identity    LDAPIdentityPlanAction
		access      LDAPProviderAccessPlanAction
	}{
		{
			name: "deny no mapping", reason: LDAPPlanReasonNoMapping, disposition: LDAPPlanDenied,
		},
		{
			name:   "provider access only",
			mutate: func(snapshot *LDAPPlanningSnapshot) { snapshot.NoMatchPolicy = LDAPNoMatchProviderAccessOnly },
			reason: LDAPPlanReasonProviderAccessOnly, disposition: LDAPPlanAdmitted,
			identity: LDAPIdentityCreateUserAndExternalIdentity, access: LDAPProviderAccessEnsure,
		},
		{
			name: "existing identity required",
			mutate: func(snapshot *LDAPPlanningSnapshot) {
				snapshot.JITMode = LDAPJITExistingIdentity
				snapshot.NoMatchPolicy = LDAPNoMatchProviderAccessOnly
			},
			reason: LDAPPlanReasonExistingIdentityRequired, disposition: LDAPPlanDenied,
		},
		{
			name: "jit disabled without complete existing path",
			mutate: func(snapshot *LDAPPlanningSnapshot) {
				snapshot.JITMode = LDAPJITDisabled
				snapshot.NoMatchPolicy = LDAPNoMatchProviderAccessOnly
			},
			reason: LDAPPlanReasonJITDisabled, disposition: LDAPPlanDenied,
		},
		{
			name: "jit disabled existing live path",
			mutate: func(snapshot *LDAPPlanningSnapshot) {
				snapshot.JITMode = LDAPJITDisabled
				snapshot.NoMatchPolicy = LDAPNoMatchProviderAccessOnly
				snapshot.ProviderAccess.ExternalIdentityExists = true
				snapshot.ProviderAccess.UserActive = true
				snapshot.ProviderAccess.TenantMembershipExists = true
				snapshot.ProviderAccess.TenantMembershipActive = true
				snapshot.ProviderAccess.AccessGrantLive = true
			},
			reason: LDAPPlanReasonProviderAccessOnly, disposition: LDAPPlanAdmitted,
		},
		{
			name: "linked local identity disabled",
			mutate: func(snapshot *LDAPPlanningSnapshot) {
				snapshot.NoMatchPolicy = LDAPNoMatchProviderAccessOnly
				snapshot.ProviderAccess.ExternalIdentityExists = true
			},
			reason: LDAPPlanReasonLocalIdentityDisabled, disposition: LDAPPlanDenied,
		},
		{
			name: "linked tenant membership inactive",
			mutate: func(snapshot *LDAPPlanningSnapshot) {
				snapshot.NoMatchPolicy = LDAPNoMatchProviderAccessOnly
				snapshot.ProviderAccess.ExternalIdentityExists = true
				snapshot.ProviderAccess.UserActive = true
				snapshot.ProviderAccess.TenantMembershipExists = true
			},
			reason: LDAPPlanReasonTenantMembershipInactive, disposition: LDAPPlanDenied,
		},
		{
			name: "active linked membership needs current provider access",
			mutate: func(snapshot *LDAPPlanningSnapshot) {
				snapshot.NoMatchPolicy = LDAPNoMatchProviderAccessOnly
				snapshot.ProviderAccess.ExternalIdentityExists = true
				snapshot.ProviderAccess.UserActive = true
				snapshot.ProviderAccess.TenantMembershipExists = true
				snapshot.ProviderAccess.TenantMembershipActive = true
			},
			reason: LDAPPlanReasonProviderAccessOnly, disposition: LDAPPlanAdmitted,
			access: LDAPProviderAccessEnsure,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := base
			if test.mutate != nil {
				test.mutate(&snapshot)
			}
			plan, err := PlanLDAPMapping(observation, snapshot)
			if err != nil {
				t.Fatalf("PlanLDAPMapping() error = %v", err)
			}
			if plan.Reason() != test.reason || plan.Disposition() != test.disposition ||
				plan.IdentityAction() != test.identity || plan.ProviderAccessAction() != test.access ||
				len(plan.Changes()) != 0 {
				t.Fatalf("plan = %s, identity/access = %d/%d", plan, plan.IdentityAction(), plan.ProviderAccessAction())
			}
		})
	}
}

func TestPlanLDAPMappingDeniedNoMatchReturnsOnlyProvenAuthoritativeRevocations(t *testing.T) {
	observation := mappingObservation(t, true, LDAPAccountActive,
		"cn=Different,ou=Groups,dc=example,dc=com",
	)
	snapshot := mappingSnapshot(t)
	plan, err := PlanLDAPMapping(observation, snapshot)
	if err != nil || plan.Disposition() != LDAPPlanDenied || plan.Reason() != LDAPPlanReasonNoMapping {
		t.Fatalf("plan = %s, error = %v", plan, err)
	}
	changes := plan.Changes()
	if len(changes) != 2 {
		t.Fatalf("denied changes = %#v", changes)
	}
	for _, change := range changes {
		if change.Operation != LDAPMappingRevoke || change.SourceID != testID(0x43) {
			t.Fatalf("denied plan returned a non-authoritative or non-revoke change: %#v", change)
		}
	}
	if plan.IdentityAction() != LDAPIdentityNoChange ||
		plan.ProviderAccessAction() != LDAPProviderAccessNoChange ||
		len(plan.ProspectiveRoleIDs()) != 0 {
		t.Fatalf("denied plan proposed admission state: %s", plan)
	}

	incomplete := mappingObservation(t, false, LDAPAccountActive,
		"cn=Different,ou=Groups,dc=example,dc=com",
	)
	partialPlan, err := PlanLDAPMapping(incomplete, snapshot)
	if err != nil || partialPlan.Reason() != LDAPPlanReasonIncompleteObservation || len(partialPlan.Changes()) != 0 {
		t.Fatalf("incomplete plan = %s, changes = %#v, error = %v", partialPlan, partialPlan.Changes(), err)
	}
}

func TestPlanLDAPMappingRejectsIncompleteAndDisabledObservationsWithoutChanges(t *testing.T) {
	for _, test := range []struct {
		name       string
		complete   bool
		account    LDAPAccountState
		wantReason LDAPPlanReason
	}{
		{"incomplete", false, LDAPAccountActive, LDAPPlanReasonIncompleteObservation},
		{"disabled", true, LDAPAccountDisabled, LDAPPlanReasonAccountDisabled},
	} {
		t.Run(test.name, func(t *testing.T) {
			plan, err := PlanLDAPMapping(
				mappingObservation(t, test.complete, test.account, "cn=SOC-L2,ou=Groups,dc=example,dc=com"),
				mappingSnapshot(t),
			)
			if err != nil || plan.Disposition() != LDAPPlanDenied || plan.Reason() != test.wantReason ||
				plan.IdentityAction() != LDAPIdentityNoChange || plan.ProviderAccessAction() != LDAPProviderAccessNoChange ||
				len(plan.Changes()) != 0 {
				t.Fatalf("plan = %s, error = %v", plan, err)
			}
		})
	}
}

func TestPlanLDAPMappingEnforcesExactAndLifetimeBoundedDelegation(t *testing.T) {
	observation := mappingObservation(t, true, LDAPAccountActive, "cn=SOC-L2,ou=Groups,dc=example,dc=com")
	deadline := time.Unix(2_000_000_000, 0).UTC()

	t.Run("wrong exact scope", func(t *testing.T) {
		snapshot := mappingSnapshot(t)
		snapshot.EffectiveUntil = &deadline
		for index := range snapshot.Delegation {
			if snapshot.Delegation[index].Tuple == (LDAPPermissionTuple{Permission: "alert.read", Scope: LDAPScopeTenant}) {
				snapshot.Delegation[index].Tuple.Scope = LDAPScopeOwn
			}
		}
		plan, err := PlanLDAPMapping(observation, snapshot)
		if err != nil || plan.Reason() != LDAPPlanReasonDelegationExceeded || plan.Disposition() != LDAPPlanDenied {
			t.Fatalf("plan = %s, error = %v", plan, err)
		}
	})

	t.Run("shorter lifetime", func(t *testing.T) {
		snapshot := mappingSnapshot(t)
		snapshot.EffectiveUntil = &deadline
		short := deadline.Add(-time.Second)
		for index := range snapshot.Delegation {
			snapshot.Delegation[index].NotAfter = &short
		}
		plan, err := PlanLDAPMapping(observation, snapshot)
		if err != nil || plan.Reason() != LDAPPlanReasonDelegationExceeded {
			t.Fatalf("plan = %s, error = %v", plan, err)
		}
	})

	t.Run("exact boundary", func(t *testing.T) {
		snapshot := mappingSnapshot(t)
		snapshot.EffectiveUntil = &deadline
		for index := range snapshot.Delegation {
			exact := deadline
			snapshot.Delegation[index].NotAfter = &exact
		}
		plan, err := PlanLDAPMapping(observation, snapshot)
		if err != nil || plan.Disposition() != LDAPPlanAdmitted {
			t.Fatalf("plan = %s, error = %v", plan, err)
		}
	})

	t.Run("inert role requires no invented authority", func(t *testing.T) {
		matcher, _ := CompileLDAPGroupMatcher(LDAPGroupMatcherSpec{
			Kind: LDAPGroupMatcherExactCN, CaseMode: LDAPGroupCaseSensitive, Pattern: "SOC-L2",
		})
		snapshot := minimalMappingSnapshot()
		snapshot.Rules = []LDAPMappingRule{{
			RuleID: testID(0x21), RuleEpochID: testID(0x22), SourceID: testID(0x23),
			Revision: 1, Enabled: true, Matcher: matcher, Mode: LDAPReconciliationAuthoritative,
			SecurityGroupID: testID(0x24), RoleIDs: []EntityID{testID(0x25)},
		}}
		snapshot.SecurityGroups = []LDAPSecurityGroupPolicy{{SecurityGroupID: testID(0x24)}}
		snapshot.RolePolicies = []LDAPRolePolicy{{RoleID: testID(0x25)}}
		plan, err := PlanLDAPMapping(observation, snapshot)
		if err != nil || plan.Disposition() != LDAPPlanAdmitted {
			t.Fatalf("plan = %s, error = %v", plan, err)
		}
	})
}

func TestPlanLDAPMappingRequiresLiveExactOperatorTeamEpoch(t *testing.T) {
	observation := mappingObservation(t, true, LDAPAccountActive, "cn=SOC-L2,ou=Groups,dc=example,dc=com")
	for _, mutate := range []func(*LDAPPlanningSnapshot){
		func(snapshot *LDAPPlanningSnapshot) { snapshot.LiveAssignments = nil },
		func(snapshot *LDAPPlanningSnapshot) { snapshot.LiveAssignments[0].Live = false },
		func(snapshot *LDAPPlanningSnapshot) { snapshot.LiveAssignments[0].AssignmentEpochID = testID(0x73) },
	} {
		snapshot := mappingSnapshot(t)
		mutate(&snapshot)
		plan, err := PlanLDAPMapping(observation, snapshot)
		if err != nil || plan.Disposition() != LDAPPlanDenied || plan.Reason() != LDAPPlanReasonAssignmentInactive {
			t.Fatalf("plan = %s, error = %v", plan, err)
		}
	}
}

func TestPlanLDAPDeprovisionRequiresCompleteSourceAndPreservesAdditiveEdges(t *testing.T) {
	base := mappingSnapshot(t)
	base.ProviderAccess.ExternalIdentityExists = true
	base.ProviderAccess.UserActive = true
	base.ProviderAccess.TenantMembershipExists = true
	base.ProviderAccess.TenantMembershipActive = true
	base.ProviderAccess.AccessGrantLive = true

	tests := []struct {
		name        string
		input       LDAPDeprovisionInput
		reason      LDAPPlanReason
		access      LDAPProviderAccessPlanAction
		revocations int
	}{
		{
			name: "incomplete source cannot remove",
			input: LDAPDeprovisionInput{
				Policy: LDAPDeprovisionImmediate,
			},
			reason: LDAPPlanReasonIncompleteObservation,
		},
		{
			name: "explicit retain",
			input: LDAPDeprovisionInput{
				Policy: LDAPDeprovisionRetain, SourceComplete: true, GraceElapsed: true,
			},
			reason: LDAPPlanReasonDeprovisionRetained,
		},
		{
			name: "grace pending",
			input: LDAPDeprovisionInput{
				Policy: LDAPDeprovisionGrace, SourceComplete: true,
			},
			reason: LDAPPlanReasonDeprovisionGracePending,
		},
		{
			name: "immediate suspends access and revokes authoritative mappings",
			input: LDAPDeprovisionInput{
				Policy: LDAPDeprovisionImmediate, SourceComplete: true,
			},
			reason: LDAPPlanReasonDeprovisioned, access: LDAPProviderAccessSuspend, revocations: 2,
		},
		{
			name: "elapsed grace suspends access and revokes authoritative mappings",
			input: LDAPDeprovisionInput{
				Policy: LDAPDeprovisionGrace, SourceComplete: true, GraceElapsed: true,
			},
			reason: LDAPPlanReasonDeprovisioned, access: LDAPProviderAccessSuspend, revocations: 2,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan, err := PlanLDAPDeprovision(base, test.input)
			if err != nil || plan.Disposition() != LDAPPlanDenied || plan.Reason() != test.reason ||
				plan.ProviderAccessAction() != test.access || plan.IdentityAction() != LDAPIdentityNoChange ||
				len(plan.Changes()) != test.revocations {
				t.Fatalf("plan = %s, access = %d, changes = %#v, error = %v", plan, plan.ProviderAccessAction(), plan.Changes(), err)
			}
			for _, change := range plan.Changes() {
				if change.Operation != LDAPMappingRevoke || change.SourceID != testID(0x43) {
					t.Fatalf("deprovision touched additive/foreign source: %#v", change)
				}
			}
		})
	}
}

func TestPlanLDAPDeprovisionChecksSymmetricDelegationAndClosedPolicy(t *testing.T) {
	snapshot := mappingSnapshot(t)
	snapshot.Delegation = nil
	plan, err := PlanLDAPDeprovision(snapshot, LDAPDeprovisionInput{
		Policy: LDAPDeprovisionImmediate, SourceComplete: true,
	})
	if err != nil || plan.Reason() != LDAPPlanReasonDelegationExceeded || len(plan.Changes()) != 0 {
		t.Fatalf("plan = %s, error = %v", plan, err)
	}
	if plan, err = PlanLDAPDeprovision(snapshot, LDAPDeprovisionInput{Policy: 99, SourceComplete: true}); !errors.Is(err, ErrInvalidLDAPPlanningSnapshot) || !isZeroLDAPMappingPlan(plan) {
		t.Fatalf("unknown policy plan = %#v, error = %v", plan, err)
	}
}

func TestPlanLDAPMappingRejectsMalformedOrIncompleteSnapshots(t *testing.T) {
	observation := mappingObservation(t, true, LDAPAccountActive, "cn=SOC-L2,ou=Groups,dc=example,dc=com")
	tests := []struct {
		name   string
		mutate func(*LDAPPlanningSnapshot)
	}{
		{"zero tenant", func(snapshot *LDAPPlanningSnapshot) { snapshot.TenantID = EntityID{} }},
		{"cross tenant provider", func(snapshot *LDAPPlanningSnapshot) { snapshot.Provider.TenantID = testID(0xf1) }},
		{"zero revision", func(snapshot *LDAPPlanningSnapshot) { snapshot.AuthorizationRevision = 0 }},
		{"unknown jit", func(snapshot *LDAPPlanningSnapshot) { snapshot.JITMode = 99 }},
		{"unknown no match", func(snapshot *LDAPPlanningSnapshot) { snapshot.NoMatchPolicy = 99 }},
		{"active user without identity", func(snapshot *LDAPPlanningSnapshot) { snapshot.ProviderAccess.UserActive = true }},
		{"active membership without membership", func(snapshot *LDAPPlanningSnapshot) {
			snapshot.ProviderAccess.ExternalIdentityExists = true
			snapshot.ProviderAccess.UserActive = true
			snapshot.ProviderAccess.TenantMembershipActive = true
		}},
		{"live access without identity", func(snapshot *LDAPPlanningSnapshot) { snapshot.ProviderAccess.AccessGrantLive = true }},
		{"missing complete group policy", func(snapshot *LDAPPlanningSnapshot) { snapshot.SecurityGroups = snapshot.SecurityGroups[1:] }},
		{"missing role policy", func(snapshot *LDAPPlanningSnapshot) { snapshot.RolePolicies = snapshot.RolePolicies[1:] }},
		{"duplicate source", func(snapshot *LDAPPlanningSnapshot) { snapshot.Rules[1].SourceID = snapshot.Rules[0].SourceID }},
		{"unknown current source", func(snapshot *LDAPPlanningSnapshot) { snapshot.LiveOwnedEdges[0].SourceID = testID(0xf2) }},
		{"wrong current epoch", func(snapshot *LDAPPlanningSnapshot) { snapshot.LiveOwnedEdges[0].RuleEpochID = testID(0xf3) }},
		{"platform tuple", func(snapshot *LDAPPlanningSnapshot) {
			snapshot.RolePolicies[0].Policy[0].Scope = LDAPPermissionScope("platform")
		}},
		{"invalid permission", func(snapshot *LDAPPlanningSnapshot) { snapshot.RolePolicies[0].Policy[0].Permission = "alert..read" }},
		{"zero matcher", func(snapshot *LDAPPlanningSnapshot) { snapshot.Rules[0].Matcher = CompiledLDAPGroupMatcher{} }},
		{"missing current group projection", func(snapshot *LDAPPlanningSnapshot) { snapshot.SecurityGroups = snapshot.SecurityGroups[:1] }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := mappingSnapshot(t)
			test.mutate(&snapshot)
			plan, err := PlanLDAPMapping(observation, snapshot)
			if !errors.Is(err, ErrInvalidLDAPPlanningSnapshot) || !isZeroLDAPMappingPlan(plan) {
				t.Fatalf("plan = %#v, error = %v", plan, err)
			}
		})
	}
	if plan, err := PlanLDAPMapping(LDAPObservation{}, mappingSnapshot(t)); !errors.Is(err, ErrInvalidLDAPPlanningSnapshot) || !isZeroLDAPMappingPlan(plan) {
		t.Fatalf("zero observation plan = %#v, error = %v", plan, err)
	}
}

func TestLDAPMappingFormattingRedactsProfileMatcherAndAdministrativeNote(t *testing.T) {
	matcher, _ := CompileLDAPGroupMatcher(LDAPGroupMatcherSpec{
		Kind: LDAPGroupMatcherExactDN, CaseMode: LDAPGroupCaseSensitive,
		Pattern: "cn=Secret-Directory-Group,dc=example,dc=com",
	})
	rule := LDAPMappingRule{
		Revision: 1, Priority: 1, Enabled: true, Matcher: matcher,
		Mode: LDAPReconciliationAuthoritative, AdministrativeNote: "Private administrative note",
	}
	formattedRule := fmt.Sprintf("%v|%+v|%#v|%s|%q", rule, rule, rule, rule, rule)
	if strings.Contains(formattedRule, "Secret-Directory-Group") || strings.Contains(formattedRule, "Private administrative note") {
		t.Fatalf("formatted rule exposed mapping data: %s", formattedRule)
	}

	observation := mappingObservation(t, true, LDAPAccountActive, "cn=SOC-L2,ou=Groups,dc=example,dc=com")
	plan, err := PlanLDAPMapping(observation, mappingSnapshot(t))
	if err != nil {
		t.Fatalf("PlanLDAPMapping() error = %v", err)
	}
	formattedPlan := fmt.Sprintf("%v|%+v|%#v|%s|%q", plan, plan, plan, plan, plan)
	if strings.Contains(formattedPlan, "Private Display Name") || strings.Contains(formattedPlan, "SOC-L2") {
		t.Fatalf("formatted plan exposed directory data: %s", formattedPlan)
	}
}

func mappingSnapshot(t *testing.T) LDAPPlanningSnapshot {
	t.Helper()
	exactCN, err := CompileLDAPGroupMatcher(LDAPGroupMatcherSpec{
		Kind: LDAPGroupMatcherExactCN, CaseMode: LDAPGroupCaseSensitive, Pattern: "SOC-L2",
	})
	if err != nil {
		t.Fatal(err)
	}
	regex, err := CompileLDAPGroupMatcher(LDAPGroupMatcherSpec{
		Kind: LDAPGroupMatcherRegex, CaseMode: LDAPGroupCaseSensitive,
		Pattern: `cn=SOC-L2,ou=Groups,dc=example,dc=com`,
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := minimalMappingSnapshot()
	snapshot.Rules = []LDAPMappingRule{
		{
			RuleID: testID(0x41), RuleEpochID: testID(0x42), SourceID: testID(0x43),
			Revision: 3, Priority: 20, Enabled: true, Matcher: exactCN,
			Mode: LDAPReconciliationAuthoritative, SecurityGroupID: testID(0x51),
			RoleIDs:      []EntityID{testID(0x62)},
			OperatorTeam: &LDAPOperatorTeamTarget{TeamID: testID(0x71), AssignmentEpochID: testID(0x72)},
		},
		{
			RuleID: testID(0x31), RuleEpochID: testID(0x32), SourceID: testID(0x33),
			Revision: 7, Priority: 10, Enabled: true, Matcher: regex,
			Mode: LDAPReconciliationAdditive, SecurityGroupID: testID(0x51),
			RoleIDs: []EntityID{testID(0x61)},
		},
	}
	snapshot.SecurityGroups = []LDAPSecurityGroupPolicy{
		{SecurityGroupID: testID(0x51), ActiveRoleIDs: []EntityID{testID(0x63)}},
		{SecurityGroupID: testID(0x52), ActiveRoleIDs: []EntityID{testID(0x64)}},
	}
	snapshot.LiveAssignments = []LDAPOperatorTeamAssignment{{
		TeamID: testID(0x71), AssignmentEpochID: testID(0x72), Live: true,
	}}
	snapshot.RolePolicies = []LDAPRolePolicy{
		{RoleID: testID(0x61), Policy: []LDAPPermissionTuple{{Permission: "alert.read", Scope: LDAPScopeTenant}}},
		{RoleID: testID(0x62), Policy: []LDAPPermissionTuple{{Permission: "case.claim", Scope: LDAPScopeOperatorTeam}}},
		{RoleID: testID(0x63), Policy: []LDAPPermissionTuple{{Permission: "case.read", Scope: LDAPScopeTenant}}},
		{RoleID: testID(0x64), Policy: []LDAPPermissionTuple{{Permission: "alert.read", Scope: LDAPScopeOwn}}},
	}
	snapshot.ExistingEffectiveRoleIDs = []EntityID{testID(0x63)}
	snapshot.Delegation = []LDAPDelegationGrant{
		{Tuple: LDAPPermissionTuple{Permission: "alert.read", Scope: LDAPScopeTenant}},
		{Tuple: LDAPPermissionTuple{Permission: "case.claim", Scope: LDAPScopeOperatorTeam}},
		{Tuple: LDAPPermissionTuple{Permission: "case.read", Scope: LDAPScopeTenant}},
		{Tuple: LDAPPermissionTuple{Permission: "alert.read", Scope: LDAPScopeOwn}},
	}
	snapshot.LiveOwnedEdges = []LDAPOwnedMappingEdge{
		{
			SourceID: testID(0x33), RuleEpochID: testID(0x32),
			Key: LDAPMappingEdgeKey{Kind: LDAPSecurityGroupMembershipEdge, PrimaryID: testID(0x52)},
		},
		{
			SourceID: testID(0x43), RuleEpochID: testID(0x42),
			Key: LDAPMappingEdgeKey{Kind: LDAPSecurityGroupMembershipEdge, PrimaryID: testID(0x51)},
		},
		{
			SourceID: testID(0x43), RuleEpochID: testID(0x42),
			Key: LDAPMappingEdgeKey{Kind: LDAPSecurityGroupMembershipEdge, PrimaryID: testID(0x52)},
		},
	}
	return snapshot
}

func minimalMappingSnapshot() LDAPPlanningSnapshot {
	tenantID := testID(0x11)
	return LDAPPlanningSnapshot{
		TenantID:  tenantID,
		Provider:  ProviderContext{Scope: TenantProviderScope, TenantID: tenantID, ProviderID: testID(0x12)},
		BindingID: testID(0x13), ConfigurationRevision: 2, RuleSetRevision: 3, AuthorizationRevision: 4,
		JITMode: LDAPJITCreate, NoMatchPolicy: LDAPNoMatchDeny,
		ProviderAccess: LDAPProviderAccessState{SourceID: testID(0x14), AccessEpochID: testID(0x15)},
	}
}

func mappingObservation(
	t *testing.T,
	complete bool,
	account LDAPAccountState,
	groups ...string,
) LDAPObservation {
	t.Helper()
	subject, _ := CanonicalUTF8Exact([]byte("private-mapping-subject"))
	username, _ := NewLDAPUsername("private-login-name")
	userDN, _ := ParseLDAPDistinguishedName("uid=private-login-name,dc=example,dc=com")
	displayName := "Private Display Name"
	parsedGroups := make([]LDAPDistinguishedName, 0, len(groups))
	for _, group := range groups {
		parsed, err := ParseLDAPDistinguishedName(group)
		if err != nil {
			t.Fatalf("ParseLDAPDistinguishedName(%q) error = %v", group, err)
		}
		parsedGroups = append(parsedGroups, parsed)
	}
	observation, err := NewLDAPObservation(LDAPObservationInput{
		Subject: subject, UserDN: userDN, LoginUsername: username,
		Profile: LDAPProfileValues{DisplayName: &displayName}, Groups: parsedGroups,
		AccountState: account, Complete: complete,
	})
	if err != nil {
		t.Fatalf("NewLDAPObservation() error = %v", err)
	}
	return observation
}

func slicesEqualEntityIDs(left, right []EntityID) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func isZeroLDAPMappingPlan(plan LDAPMappingPlan) bool {
	return plan.Disposition() == 0 && plan.Reason() == "" &&
		plan.IdentityAction() == LDAPIdentityNoChange &&
		plan.ProviderAccessAction() == LDAPProviderAccessNoChange &&
		len(plan.MatchedRuleIDs()) == 0 && len(plan.ProspectiveSecurityGroupIDs()) == 0 &&
		len(plan.ProspectiveRoleIDs()) == 0 && len(plan.ProspectiveOperatorTeamAssignments()) == 0 &&
		len(plan.Changes()) == 0
}
