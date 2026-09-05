package platformoidcauth

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

func TestPlanTenantSwitchAdmissionReturnsExactRotationPins(t *testing.T) {
	now, snapshot := validTenantSwitchSnapshot(t)

	plan, err := PlanTenantSwitchAdmission(now, snapshot)
	if err != nil {
		t.Fatalf("PlanTenantSwitchAdmission() error = %v", err)
	}
	if plan.SourceSessionID != snapshot.Source.SessionID ||
		plan.RotationFamilyID != snapshot.Source.RotationFamilyID ||
		plan.ExpectedSessionVersion != snapshot.Source.ExpectedVersion ||
		plan.UserID != snapshot.Source.UserID || plan.ProviderID != snapshot.Source.ProviderID ||
		plan.ExternalIdentityID != snapshot.Source.ExternalIdentityID ||
		plan.TargetTenantID != snapshot.Target.Tenant.ID ||
		plan.MembershipID != snapshot.Target.Membership.ID ||
		plan.BindingID != snapshot.Target.Binding.ID ||
		plan.AccessEpochID != snapshot.Target.AccessEpoch.ID ||
		plan.AccessSourceID != snapshot.Target.AccessSource.ID ||
		plan.AccessGrantID != snapshot.Target.AccessGrant.ID {
		t.Fatalf("PlanTenantSwitchAdmission() identifiers = %#v", plan)
	}
	if !plan.AbsoluteExpiresAt.Equal(snapshot.Source.AbsoluteExpiresAt) {
		t.Fatalf("absolute expiry = %v, want %v", plan.AbsoluteExpiresAt, snapshot.Source.AbsoluteExpiresAt)
	}
	if plan.ProviderRevision != 11 || plan.SecurityRevision != 12 ||
		plan.PlatformLoginRevision != 13 ||
		plan.IdentityRevision != 14 || plan.SubjectAliasKeyVersion != 15 || plan.TenantVersion != 21 ||
		plan.BindingVersion != 22 || plan.MappingRevision != 23 ||
		plan.AuthorizationRevision != 24 ||
		plan.AccessEpochVersion != 26 || plan.AccessGrantVersion != 27 {
		t.Fatalf("PlanTenantSwitchAdmission() revisions = %#v", plan)
	}
}

func TestPlanTenantSwitchAdmissionRejectsSourceDrift(t *testing.T) {
	tests := map[string]func(*TenantSwitchSnapshot){
		"non-RFC session id": func(value *TenantSwitchSnapshot) {
			value.Source.SessionID[8] = (value.Source.SessionID[8] & 0x1f) | 0xc0
		},
		"tenant scoped source": func(value *TenantSwitchSnapshot) {
			id := value.Target.Tenant.ID
			value.Source.ActiveTenantID = &id
		},
		"wrong authentication method": func(value *TenantSwitchSnapshot) {
			value.Source.AuthenticationMethod = "saml"
		},
		"wrong primary kind": func(value *TenantSwitchSnapshot) {
			value.Source.PrimaryKind = "tenant_platform_provider"
		},
		"missing direct state": func(value *TenantSwitchSnapshot) {
			value.Source.DirectStateCount = 0
		},
		"duplicate direct provenance": func(value *TenantSwitchSnapshot) {
			value.Source.DirectProvenanceCount = 2
		},
		"tenant provenance present": func(value *TenantSwitchSnapshot) {
			value.Source.TenantProvenanceCount = 1
		},
		"stale session CAS": func(value *TenantSwitchSnapshot) { value.Source.CurrentVersion++ },
		"revoked session":   func(value *TenantSwitchSnapshot) { value.Source.SessionActive = false },
		"expired idle deadline": func(value *TenantSwitchSnapshot) {
			value.Source.IdleExpiresAt = testSwitchNow
		},
		"revoked family":        func(value *TenantSwitchSnapshot) { value.Source.RotationFamilyLive = false },
		"user suspended":        func(value *TenantSwitchSnapshot) { value.Source.UserActive = false },
		"provider disabled":     func(value *TenantSwitchSnapshot) { value.Source.ProviderEnabled = false },
		"direct login disabled": func(value *TenantSwitchSnapshot) { value.Source.PlatformLoginLive = false },
		"account mode disabled": func(value *TenantSwitchSnapshot) { value.Source.AccountMode = "disabled" },
		"account creation mode": func(value *TenantSwitchSnapshot) { value.Source.AccountMode = "create" },
		"retired identity":      func(value *TenantSwitchSnapshot) { value.Source.IdentityLive = false },
		"retired alias":         func(value *TenantSwitchSnapshot) { value.Source.SubjectAliasLive = false },
		"provider revision drift": func(value *TenantSwitchSnapshot) {
			value.Source.Revisions.Provider.Current++
		},
		"security revision drift": func(value *TenantSwitchSnapshot) {
			value.Source.Revisions.Security.Current++
		},
		"platform login revision drift": func(value *TenantSwitchSnapshot) {
			value.Source.Revisions.PlatformLogin.Current++
		},
		"identity revision drift": func(value *TenantSwitchSnapshot) {
			value.Source.Revisions.ExternalIdentity.Current++
		},
		"alias key drift": func(value *TenantSwitchSnapshot) {
			value.Source.Revisions.SubjectAliasKey.Current++
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			now, snapshot := validTenantSwitchSnapshot(t)
			mutate(&snapshot)
			assertTenantSwitchDenied(t, now, snapshot)
		})
	}
}

func TestPlanTenantSwitchAdmissionRejectsOutOfRangeClock(t *testing.T) {
	_, snapshot := validTenantSwitchSnapshot(t)
	assertTenantSwitchDenied(
		t,
		time.Date(1969, time.December, 31, 23, 59, 59, 0, time.UTC),
		snapshot,
	)
}

func TestPlanTenantSwitchAdmissionRejectsMissingLiveAuthority(t *testing.T) {
	tests := map[string]func(*TenantSwitchSnapshot){
		"tenant execution disabled": func(value *TenantSwitchSnapshot) {
			value.Target.TenantExecutionLive = false
		},
		"tenant suspended":    func(value *TenantSwitchSnapshot) { value.Target.Tenant.Active = false },
		"membership inactive": func(value *TenantSwitchSnapshot) { value.Target.Membership.Active = false },
		"binding disabled":    func(value *TenantSwitchSnapshot) { value.Target.Binding.Enabled = false },
		"epoch ended":         func(value *TenantSwitchSnapshot) { value.Target.AccessEpoch.Live = false },
		"source retired":      func(value *TenantSwitchSnapshot) { value.Target.AccessSource.Live = false },
		"source not authoritative": func(value *TenantSwitchSnapshot) {
			value.Target.AccessSource.Authoritative = false
		},
		"source wrong family": func(value *TenantSwitchSnapshot) {
			value.Target.AccessSource.PlatformProvider = false
		},
		"identity retired": func(value *TenantSwitchSnapshot) { value.Target.ExternalIdentity.Live = false },
		"alias retired":    func(value *TenantSwitchSnapshot) { value.Target.SubjectAlias.Live = false },
		"grant ended":      func(value *TenantSwitchSnapshot) { value.Target.AccessGrant.Live = false },
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			now, snapshot := validTenantSwitchSnapshot(t)
			mutate(&snapshot)
			assertTenantSwitchDenied(t, now, snapshot)
		})
	}
}

func TestPlanTenantSwitchAdmissionRejectsCrossAuthorityEdges(t *testing.T) {
	tests := map[string]func(*TenantSwitchSnapshot){
		"membership user": func(value *TenantSwitchSnapshot) {
			value.Target.Membership.UserID = testSwitchID(t)
		},
		"binding provider": func(value *TenantSwitchSnapshot) {
			value.Target.Binding.ProviderID = testSwitchID(t)
		},
		"epoch binding": func(value *TenantSwitchSnapshot) {
			value.Target.AccessEpoch.BindingID = testSwitchID(t)
		},
		"binding current epoch": func(value *TenantSwitchSnapshot) {
			value.Target.Binding.CurrentAccessEpochID = testSwitchID(t)
		},
		"source epoch": func(value *TenantSwitchSnapshot) {
			value.Target.AccessSource.ID = testSwitchID(t)
		},
		"identity user": func(value *TenantSwitchSnapshot) {
			value.Target.ExternalIdentity.UserID = testSwitchID(t)
		},
		"identity revision": func(value *TenantSwitchSnapshot) {
			value.Target.ExternalIdentity.Version++
		},
		"alias identity": func(value *TenantSwitchSnapshot) {
			value.Target.SubjectAlias.ExternalIdentityID = testSwitchID(t)
		},
		"grant membership": func(value *TenantSwitchSnapshot) {
			value.Target.AccessGrant.MembershipID = testSwitchID(t)
		},
		"grant binding": func(value *TenantSwitchSnapshot) {
			value.Target.AccessGrant.BindingID = testSwitchID(t)
		},
		"grant identity": func(value *TenantSwitchSnapshot) {
			value.Target.AccessGrant.ExternalIdentityID = testSwitchID(t)
		},
		"grant access source": func(value *TenantSwitchSnapshot) {
			value.Target.AccessGrant.AccessSourceID = testSwitchID(t)
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			now, snapshot := validTenantSwitchSnapshot(t)
			mutate(&snapshot)
			assertTenantSwitchDenied(t, now, snapshot)
		})
	}
}

func TestTenantSwitchAssuranceCarriesOnlyExactProviderProof(t *testing.T) {
	now, snapshot := validTenantSwitchSnapshot(t)
	admission, err := PlanTenantSwitchAdmission(now, snapshot)
	if err != nil {
		t.Fatalf("PlanTenantSwitchAdmission() error = %v", err)
	}
	policyID := testSwitchID(t)
	requirement := identity.EffectiveAssuranceRequirement{
		Level: identity.AssurancePrimary,
		PolicyRevisions: []identity.AssurancePolicyRevision{{
			PolicyID: identity.EntityID(policyID), Revision: 3,
		}},
	}
	evidence := tenantSwitchProviderEvidence(
		t, admission, identity.AssurancePrimary, now.Add(-time.Minute), nil,
	)
	if !TenantSwitchAssuranceSatisfied(now, admission, evidence, requirement) {
		t.Fatal("exact primary provider proof was denied")
	}

	trustRuleID := testSwitchID(t)
	trustRevision := int64(7)
	evidence = tenantSwitchProviderEvidence(
		t, admission, identity.AssuranceMFA, now.Add(-time.Minute), nil,
	)
	evidence[0].TrustRuleID = &trustRuleID
	evidence[0].TrustRuleRevision = &trustRevision
	evidence = append(evidence, tenantSwitchTOTPEvidence(t, admission, now.Add(-30*time.Second)))
	requirement.Level = identity.AssuranceMFA
	if !TenantSwitchAssuranceSatisfied(now, admission, evidence, requirement) {
		t.Fatal("exact trusted provider MFA proof was denied when an unrelated local proof was present")
	}
}

func TestTenantSwitchAssuranceDoesNotRelabelPlatformTOTPAsTenantProof(t *testing.T) {
	now, snapshot := validTenantSwitchSnapshot(t)
	admission, err := PlanTenantSwitchAdmission(now, snapshot)
	if err != nil {
		t.Fatalf("PlanTenantSwitchAdmission() error = %v", err)
	}
	policyID := testSwitchID(t)
	requirement := identity.EffectiveAssuranceRequirement{
		Level: identity.AssuranceMFA,
		PolicyRevisions: []identity.AssurancePolicyRevision{{
			PolicyID: identity.EntityID(policyID), Revision: 4,
		}},
	}
	evidence := tenantSwitchProviderEvidence(
		t, admission, identity.AssurancePrimary, now.Add(-time.Minute), nil,
	)
	evidence = append(evidence, tenantSwitchTOTPEvidence(t, admission, now.Add(-30*time.Second)))
	if TenantSwitchAssuranceSatisfied(now, admission, evidence, requirement) {
		t.Fatal("platform TOTP was relabeled as tenant provider MFA")
	}

	trustRuleID := testSwitchID(t)
	trustRevision := int64(9)
	evidence = tenantSwitchProviderEvidence(
		t, admission, identity.AssurancePhishingResistant, now.Add(-time.Minute), nil,
	)
	evidence[0].TrustRuleID = &trustRuleID
	evidence[0].TrustRuleRevision = &trustRevision
	evidence = append(evidence, tenantSwitchTOTPEvidence(t, admission, now.Add(-30*time.Second)))
	requirement.Level = identity.AssurancePhishingResistant
	requirement.LocalRequired = true
	if TenantSwitchAssuranceSatisfied(now, admission, evidence, requirement) {
		t.Fatal("global TOTP satisfied a tenant-local phishing-resistant policy")
	}
}

func TestTenantSwitchAssuranceRejectsStaleExpiredOrMalformedProviderProof(t *testing.T) {
	now, snapshot := validTenantSwitchSnapshot(t)
	admission, err := PlanTenantSwitchAdmission(now, snapshot)
	if err != nil {
		t.Fatalf("PlanTenantSwitchAdmission() error = %v", err)
	}
	policyID := testSwitchID(t)
	requirement := identity.EffectiveAssuranceRequirement{
		Level: identity.AssurancePrimary, Freshness: time.Minute,
		PolicyRevisions: []identity.AssurancePolicyRevision{{
			PolicyID: identity.EntityID(policyID), Revision: 5,
		}},
	}

	for name, mutate := range map[string]func(*[]DirectSessionEvidence, *TenantSwitchAdmission){
		"stale": func(values *[]DirectSessionEvidence, _ *TenantSwitchAdmission) {
			(*values)[0].AuthenticatedAt = now.Add(-time.Minute - time.Microsecond)
		},
		"expired": func(values *[]DirectSessionEvidence, _ *TenantSwitchAdmission) {
			expiresAt := now
			(*values)[0].ExpiresAt = &expiresAt
		},
		"wrong provider": func(values *[]DirectSessionEvidence, _ *TenantSwitchAdmission) {
			identifier := testSwitchID(t)
			(*values)[0].PlatformProviderID = &identifier
		},
		"duplicate evidence": func(values *[]DirectSessionEvidence, _ *TenantSwitchAdmission) {
			*values = append(*values, (*values)[0])
		},
		"expired admission": func(_ *[]DirectSessionEvidence, value *TenantSwitchAdmission) {
			value.AbsoluteExpiresAt = now
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidateAdmission := admission
			candidateEvidence := tenantSwitchProviderEvidence(
				t, admission, identity.AssurancePrimary, now.Add(-time.Minute), nil,
			)
			mutate(&candidateEvidence, &candidateAdmission)
			if TenantSwitchAssuranceSatisfied(now, candidateAdmission, candidateEvidence, requirement) {
				t.Fatal("invalid tenant switch assurance was accepted")
			}
		})
	}
}

var testSwitchNow = time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC)

func validTenantSwitchSnapshot(t *testing.T) (time.Time, TenantSwitchSnapshot) {
	t.Helper()
	sessionID := testSwitchID(t)
	familyID := testSwitchID(t)
	userID := testSwitchID(t)
	providerID := testSwitchID(t)
	identityID := testSwitchID(t)
	tenantID := testSwitchID(t)
	membershipID := testSwitchID(t)
	bindingID := testSwitchID(t)
	epochID := testSwitchID(t)
	sourceID := testSwitchID(t)
	grantID := testSwitchID(t)

	return testSwitchNow, TenantSwitchSnapshot{
		Source: PlatformSessionAuthority{
			SessionID: sessionID, RotationFamilyID: familyID, UserID: userID,
			ProviderID: providerID, ExternalIdentityID: identityID,
			AuthenticationMethod: "oidc", PrimaryKind: "platform_provider",
			DirectStateCount: 1, DirectProvenanceCount: 1,
			ExpectedVersion: 7, CurrentVersion: 7,
			IdleExpiresAt:     testSwitchNow.Add(15 * time.Minute),
			AbsoluteExpiresAt: testSwitchNow.Add(time.Hour),
			SessionActive:     true, RotationFamilyLive: true, UserActive: true,
			ProviderEnabled: true, PlatformLoginLive: true,
			AccountMode: AccountModeExistingIdentity, IdentityLive: true,
			SubjectAliasLive: true,
			Revisions: PlatformSessionRevisions{
				Provider:         ExactRevision{Pinned: 11, Current: 11},
				Security:         ExactRevision{Pinned: 12, Current: 12},
				PlatformLogin:    ExactRevision{Pinned: 13, Current: 13},
				ExternalIdentity: ExactRevision{Pinned: 14, Current: 14},
				SubjectAliasKey:  ExactRevision{Pinned: 15, Current: 15},
			},
		},
		Target: TargetTenantAuthority{
			TenantExecutionLive: true,
			Tenant:              LiveTenant{ID: tenantID, Version: 21, Active: true},
			Membership: LiveMembership{
				ID: membershipID, TenantID: tenantID, UserID: userID, Active: true,
			},
			Binding: LivePlatformBinding{
				ID: bindingID, TenantID: tenantID, ProviderID: providerID, Version: 22,
				MappingRevision: 23, AuthorizationRevision: 24,
				CurrentAccessEpochID: epochID, Enabled: true,
			},
			AccessEpoch: LiveAccessEpoch{
				ID: epochID, TenantID: tenantID, BindingID: bindingID, ProviderID: providerID,
				SourceID: sourceID, Version: 26, Live: true,
			},
			AccessSource: LiveAccessSource{
				ID: sourceID, TenantID: tenantID, PlatformProvider: true,
				Authoritative: true, Live: true,
			},
			ExternalIdentity: LiveExternalIdentity{
				ID: identityID, ProviderID: providerID, UserID: userID, Version: 14, Live: true,
			},
			SubjectAlias: LiveSubjectAlias{
				ExternalIdentityID: identityID, KeyVersion: 15, Live: true,
			},
			AccessGrant: LiveAccessGrant{
				ID: grantID, TenantID: tenantID, ProviderID: providerID, BindingID: bindingID,
				AccessEpochID: epochID, AccessSourceID: sourceID, ExternalIdentityID: identityID,
				MembershipID: membershipID, UserID: userID, Version: 27, Live: true,
			},
		},
	}
}

func assertTenantSwitchDenied(t *testing.T, now time.Time, snapshot TenantSwitchSnapshot) {
	t.Helper()
	plan, err := PlanTenantSwitchAdmission(now, snapshot)
	if !errors.Is(err, ErrTenantSwitchDenied) {
		t.Fatalf("PlanTenantSwitchAdmission() = %#v, %v; want denial", plan, err)
	}
	if plan != (TenantSwitchAdmission{}) {
		t.Fatalf("denied plan leaked authority = %#v", plan)
	}
}

func testSwitchID(t *testing.T) uuid.UUID {
	t.Helper()
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("uuid.NewV7() error = %v", err)
	}
	return id
}

func tenantSwitchProviderEvidence(
	t *testing.T,
	admission TenantSwitchAdmission,
	level identity.AssuranceLevel,
	authenticatedAt time.Time,
	expiresAt *time.Time,
) []DirectSessionEvidence {
	t.Helper()
	providerID := admission.ProviderID
	externalIdentityID := admission.ExternalIdentityID
	return []DirectSessionEvidence{{
		ID: testSwitchID(t), UserID: admission.UserID,
		Kind: DirectSessionEvidencePlatformProvider, Level: level,
		PlatformProviderID: &providerID, ExternalIdentityID: &externalIdentityID,
		AuthenticatedAt: authenticatedAt, ExpiresAt: expiresAt,
	}}
}

func tenantSwitchTOTPEvidence(
	t *testing.T,
	admission TenantSwitchAdmission,
	authenticatedAt time.Time,
) DirectSessionEvidence {
	t.Helper()
	totpID := testSwitchID(t)
	revision := int64(11)
	return DirectSessionEvidence{
		ID: testSwitchID(t), UserID: admission.UserID,
		Kind: DirectSessionEvidenceTOTP, Level: identity.AssuranceMFA,
		TOTPCredentialID: &totpID, FactorRevision: &revision,
		AuthenticatedAt: authenticatedAt,
	}
}
