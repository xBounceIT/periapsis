package mfa

import (
	"errors"
	"slices"
	"testing"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

func TestNormalizeAdministrationTargetKeepsPlatformAndTenantScopesDisjoint(t *testing.T) {
	tenantID := mfaID(1)
	valid := []struct {
		name     string
		tenantID identity.EntityID
		target   AdministrationTarget
	}{
		{name: "platform", target: AdministrationTarget{Scope: PolicyPlatformFloor}},
		{name: "tenant", tenantID: tenantID, target: AdministrationTarget{Scope: PolicyTenantBaseline, TenantID: tenantID}},
		{name: "role", tenantID: tenantID, target: AdministrationTarget{Scope: PolicyRole, TenantID: tenantID, RoleID: mfaID(2)}},
		{name: "group", tenantID: tenantID, target: AdministrationTarget{Scope: PolicySecurityGroup, TenantID: tenantID, SecurityGroupID: mfaID(3)}},
		{name: "action", tenantID: tenantID, target: AdministrationTarget{Scope: PolicyAction, TenantID: tenantID, Action: "case.export"}},
	}
	for _, test := range valid {
		t.Run(test.name, func(t *testing.T) {
			got, err := NormalizeAdministrationTarget(test.target, test.tenantID)
			if err != nil || got != test.target {
				t.Fatalf("target = %#v, %v", got, err)
			}
		})
	}

	invalid := []struct {
		name     string
		tenantID identity.EntityID
		target   AdministrationTarget
	}{
		{name: "tenant body cannot target platform", tenantID: tenantID, target: AdministrationTarget{Scope: PolicyPlatformFloor}},
		{name: "platform cannot smuggle tenant", target: AdministrationTarget{Scope: PolicyPlatformFloor, TenantID: tenantID}},
		{name: "tenant mismatch", tenantID: tenantID, target: AdministrationTarget{Scope: PolicyTenantBaseline, TenantID: mfaID(9)}},
		{name: "two discriminators", tenantID: tenantID, target: AdministrationTarget{Scope: PolicyRole, TenantID: tenantID, RoleID: mfaID(2), Action: "case.export"}},
		{name: "empty action", tenantID: tenantID, target: AdministrationTarget{Scope: PolicyAction, TenantID: tenantID}},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NormalizeAdministrationTarget(test.target, test.tenantID); !errors.Is(err, ErrInvalidPolicyAdministration) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestPolicyRequirementUsesIntegralSecondsAndMonotonicStrength(t *testing.T) {
	deadline := mfaTestNow.Add(24 * time.Hour)
	value, err := NormalizePolicyRequirement(PolicyRequirement{
		Level: identity.AssuranceMFA, LocalRequired: true,
		Freshness: 5 * time.Minute, EnrollmentDeadline: &deadline,
	})
	if err != nil || value.EnrollmentDeadline == &deadline {
		t.Fatalf("normalized = %#v, %v", value, err)
	}
	if _, err := NormalizePolicyRequirement(PolicyRequirement{
		Level: identity.AssuranceMFA, Freshness: time.Second + time.Nanosecond,
	}); !errors.Is(err, ErrInvalidPolicyAdministration) {
		t.Fatalf("sub-second freshness error = %v", err)
	}
	if !RequirementAtLeast(
		PolicyRequirement{Level: identity.AssurancePhishingResistant, LocalRequired: true, Freshness: time.Minute, EnrollmentDeadline: &deadline},
		PolicyRequirement{Level: identity.AssuranceMFA, Freshness: 5 * time.Minute},
	) {
		t.Fatal("stronger requirement was rejected")
	}
	if RequirementAtLeast(
		PolicyRequirement{Level: identity.AssurancePrimary},
		PolicyRequirement{Level: identity.AssuranceMFA},
	) {
		t.Fatal("weaker requirement was accepted")
	}
}

func TestNormalizePolicySimulationContextRejectsDuplicatesAndSortsPins(t *testing.T) {
	context, err := NormalizePolicySimulationContext(PolicySimulationContext{
		RoleIDs:          []identity.EntityID{mfaID(3), mfaID(2)},
		SecurityGroupIDs: []identity.EntityID{mfaID(5), mfaID(4)}, Action: "case.export",
	})
	if err != nil || !slices.Equal(context.RoleIDs, []identity.EntityID{mfaID(2), mfaID(3)}) ||
		!slices.Equal(context.SecurityGroupIDs, []identity.EntityID{mfaID(4), mfaID(5)}) {
		t.Fatalf("context = %#v, %v", context, err)
	}
	if _, err := NormalizePolicySimulationContext(PolicySimulationContext{
		RoleIDs: []identity.EntityID{mfaID(2), mfaID(2)}, Action: "case.export",
	}); !errors.Is(err, ErrInvalidPolicyAdministration) {
		t.Fatalf("duplicate context error = %v", err)
	}
}

func TestValidatePolicyRecoverySafetyRequiresCanonicalNonPIIReasons(t *testing.T) {
	if err := ValidatePolicyRecoverySafety(PolicyRecoverySafety{
		Safe: true, EligibleDirectAdministrators: 2, ReadyDirectAdministrators: 1,
	}); err != nil {
		t.Fatal(err)
	}
	unsafe := PolicyRecoverySafety{
		EligibleDirectAdministrators: 1,
		ReasonCodes:                  []PolicyRecoveryReason{RecoveryNoReadyLocalMFA},
	}
	if err := ValidatePolicyRecoverySafety(unsafe); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePolicyRecoverySafety(PolicyRecoverySafety{
		EligibleDirectAdministrators: 3,
		ReasonCodes: []PolicyRecoveryReason{
			RecoveryNoReadyLocalMFA,
			RecoveryNoReadyLocalPhishingResistant,
			RecoveryNoReadyLocalPrimary,
		},
	}); err != nil {
		t.Fatalf("heterogeneous reasons error = %v", err)
	}
	unsafe.ReasonCodes = []PolicyRecoveryReason{"administrator@example.test"}
	if err := ValidatePolicyRecoverySafety(unsafe); !errors.Is(err, ErrInvalidPolicyAdministration) {
		t.Fatalf("unknown reason error = %v", err)
	}
	for name, poisoned := range map[string]PolicyRecoverySafety{
		"ready but unsafe": {
			EligibleDirectAdministrators: 2, ReadyDirectAdministrators: 1,
		},
		"wrong no eligible": {
			EligibleDirectAdministrators: 1,
			ReasonCodes:                  []PolicyRecoveryReason{RecoveryNoEligibleDirectAdministrator},
		},
		"noncanonical reasons": {
			EligibleDirectAdministrators: 2,
			ReasonCodes: []PolicyRecoveryReason{
				RecoveryNoReadyLocalPrimary, RecoveryNoReadyLocalMFA,
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidatePolicyRecoverySafety(poisoned); !errors.Is(err, ErrInvalidPolicyAdministration) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestValidatePolicyDocumentAcceptsHistoricalReplayProjection(t *testing.T) {
	document := PolicyDocument{
		ID: mfaID(1), Revision: 1,
		Target:      AdministrationTarget{Scope: PolicyPlatformFloor},
		Requirement: PolicyRequirement{Level: identity.AssuranceMFA},
		Status:      PolicyLive, CreatedAt: mfaTestNow,
	}
	if err := ValidatePolicyDocument(document, identity.EntityID{}); err != nil {
		t.Fatal(err)
	}
	// A live historical document is a valid idempotency receipt even if the
	// current chain has since advanced or retired.
	document.Revision = int64(maximumStoredVersion)
	if err := ValidatePolicyDocument(document, identity.EntityID{}); err != nil {
		t.Fatal(err)
	}
}

func TestValidatePolicySimulationRecomputesExactContextBoundFold(t *testing.T) {
	tenantID := mfaID(1)
	roleID := mfaID(2)
	groupID := mfaID(3)
	contextValue := PolicySimulationContext{
		RoleIDs: []identity.EntityID{roleID}, SecurityGroupIDs: []identity.EntityID{groupID},
		Action: "case.export",
	}
	baseline := PolicyRequirement{Level: identity.AssuranceMFA, Freshness: 10 * time.Minute}
	candidate := PolicyRequirement{
		Level: identity.AssurancePhishingResistant, LocalRequired: true, Freshness: 5 * time.Minute,
	}
	effective := candidate
	value := PolicySimulation{
		Operation: PolicyPublish,
		Target: AdministrationTarget{
			Scope: PolicyRole, TenantID: tenantID, RoleID: roleID,
		},
		Context: &contextValue,
		Candidate: &PolicySimulationCandidate{
			Target:      AdministrationTarget{Scope: PolicyRole, TenantID: tenantID, RoleID: roleID},
			Requirement: candidate,
		},
		Effective: PolicyEffectiveSimulation{
			Requirement: &effective,
			Sources: []PolicySimulationSource{
				{
					Source: PolicySimulationCurrentSource, PolicyID: mfaID(10), Revision: 1,
					Target:      AdministrationTarget{Scope: PolicyPlatformFloor},
					Requirement: PolicyRequirement{Level: identity.AssurancePrimary},
				},
				{
					Source: PolicySimulationCurrentSource, PolicyID: mfaID(11), Revision: 2,
					Target:      AdministrationTarget{Scope: PolicyTenantBaseline, TenantID: tenantID},
					Requirement: baseline,
				},
				{
					Source: PolicySimulationCurrentSource, PolicyID: mfaID(12), Revision: 1,
					Target: AdministrationTarget{
						Scope: PolicySecurityGroup, TenantID: tenantID, SecurityGroupID: groupID,
					},
					Requirement: PolicyRequirement{Level: identity.AssurancePrimary},
				},
				{
					Source:      PolicySimulationCandidateSource,
					Target:      AdministrationTarget{Scope: PolicyRole, TenantID: tenantID, RoleID: roleID},
					Requirement: candidate,
				},
			},
		},
		Recovery: PolicyRecoverySafety{Safe: true, EligibleDirectAdministrators: 2, ReadyDirectAdministrators: 1},
	}
	if err := ValidatePolicySimulation(value, tenantID); err != nil {
		t.Fatal(err)
	}

	wrongFold := ClonePolicySimulation(value)
	wrongFold.Effective.Requirement.Level = identity.AssuranceMFA
	if err := ValidatePolicySimulation(wrongFold, tenantID); !errors.Is(err, ErrInvalidPolicyAdministration) {
		t.Fatalf("wrong fold error = %v", err)
	}

	crossContext := ClonePolicySimulation(value)
	crossContext.Effective.Sources[3].Target.RoleID = mfaID(9)
	crossContext.Candidate.Target.RoleID = mfaID(9)
	crossContext.Target.RoleID = mfaID(9)
	if err := ValidatePolicySimulation(crossContext, tenantID); !errors.Is(err, ErrInvalidPolicyAdministration) {
		t.Fatalf("cross-context error = %v", err)
	}

	missingBaseline := ClonePolicySimulation(value)
	missingBaseline.Effective.Sources = append(
		missingBaseline.Effective.Sources[:1],
		missingBaseline.Effective.Sources[2:]...,
	)
	if err := ValidatePolicySimulation(missingBaseline, tenantID); !errors.Is(err, ErrInvalidPolicyAdministration) {
		t.Fatalf("missing baseline error = %v", err)
	}
}

func TestPolicyAdministrationTimestampsAreMillisecondPrecision(t *testing.T) {
	document := PolicyDocument{
		ID: mfaID(1), Revision: 1,
		Target:      AdministrationTarget{Scope: PolicyPlatformFloor},
		Requirement: PolicyRequirement{Level: identity.AssuranceMFA},
		Status:      PolicyLive, CreatedAt: mfaTestNow.Add(time.Microsecond),
	}
	if err := ValidatePolicyDocument(document, identity.EntityID{}); !errors.Is(err, ErrInvalidPolicyAdministration) {
		t.Fatalf("sub-millisecond instant error = %v", err)
	}
	document.CreatedAt = mfaTestNow
	deadline := mfaTestNow
	document.Requirement.EnrollmentDeadline = &deadline
	if err := ValidatePolicyDocument(document, identity.EntityID{}); !errors.Is(err, ErrInvalidPolicyAdministration) {
		t.Fatalf("non-future stored deadline error = %v", err)
	}
}
