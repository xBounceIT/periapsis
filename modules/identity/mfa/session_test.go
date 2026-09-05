package mfa

import (
	"testing"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

func localSessionFixture() (SessionSnapshot, LiveSessionProjection) {
	primaryRevision := int64(3)
	mfaRevision := int64(7)
	policyPins := []identity.AssurancePolicyRevision{{PolicyID: mfaID(10), Revision: 2}}
	requirement := identity.EffectiveAssuranceRequirement{
		Level: identity.AssuranceMFA, Freshness: time.Hour,
		PolicyRevisions: append([]identity.AssurancePolicyRevision(nil), policyPins...),
	}
	session := SessionSnapshot{
		SessionID: mfaID(1), RotationFamilyID: mfaID(2), Version: 5,
		TenantID: mfaID(3), UserID: mfaID(4), IdentityEpoch: 11,
		Primary: PrimaryProvenance{
			Kind: PrimaryLocalCredential, PrimaryID: mfaID(5), PrimaryRevision: 9,
			SessionInvalidationEpoch: 4, AuthenticatedAt: mfaTestNow.Add(-10 * time.Minute),
		},
		Evidence: []SessionEvidence{
			{Reference: LocalEvidenceReference{LocalCredentialID: mfaID(5)}, Evidence: identity.AssuranceEvidence{
				Level: identity.AssurancePrimary, Kind: identity.AssuranceEvidenceFactor,
				Source: identity.AssuranceSource{Local: true}, AuthenticatedAt: mfaTestNow.Add(-10 * time.Minute),
				FactorRevision: &primaryRevision,
			}},
			{Reference: LocalEvidenceReference{TOTPFactorID: mfaID(6)}, Evidence: identity.AssuranceEvidence{
				Level: identity.AssuranceMFA, Kind: identity.AssuranceEvidenceFactor,
				Source: identity.AssuranceSource{Local: true}, AuthenticatedAt: mfaTestNow.Add(-5 * time.Minute),
				FactorRevision: &mfaRevision,
			}},
		},
		PolicyRevisions: policyPins, IssuedAt: mfaTestNow.Add(-10 * time.Minute),
		IdleExpiresAt: mfaTestNow.Add(time.Hour), AbsoluteExpiresAt: mfaTestNow.Add(8 * time.Hour),
	}
	live := LiveSessionProjection{
		TenantID: session.TenantID, UserID: session.UserID, Audience: "case.read",
		SessionActive: true, RotationFamilyActive: true, UserActive: true, TenantActive: true,
		MembershipActive: true, IdentityEpoch: 11, PrimaryActive: true, PrimaryRevision: 9,
		SessionInvalidationEpoch: 4,
		Factors: []FactorState{
			{Reference: LocalEvidenceReference{LocalCredentialID: mfaID(5)}, Revision: 3, Active: true},
			{Reference: LocalEvidenceReference{TOTPFactorID: mfaID(6)}, Revision: 7, Active: true},
		},
		Requirement: requirement,
	}
	return session, live
}

func TestRevalidateSessionAllowsAuthorityAndIdleTouchOnlyAfterAllChecks(t *testing.T) {
	session, live := localSessionFixture()
	result := RevalidateSession(mfaTestNow, session, live)
	if result.Decision != SessionUsable || result.Reason != SessionReasonCurrent ||
		!result.AllowAuthority || !result.AllowIdleTouch {
		t.Fatalf("result = %#v", result)
	}
}

func TestRecoveryRestrictedSessionNeverGrantsOrdinaryAuthority(t *testing.T) {
	session, live := localSessionFixture()
	session.RecoveryRestricted = true
	result := RevalidateSession(mfaTestNow, session, live)
	if result.Decision != SessionStepUp || result.Reason != SessionReasonRecoveryRestricted ||
		result.AllowAuthority || result.AllowIdleTouch {
		t.Fatalf("result = %#v", result)
	}

	live.PrimaryRevision++
	result = RevalidateSession(mfaTestNow, session, live)
	if result.Decision != SessionRevoke || result.Reason != SessionReasonPrimaryDrift {
		t.Fatalf("recovery restriction masked revocation: %#v", result)
	}
}

func TestRevalidateSessionPolicyDriftStepsUpOrRotatesPins(t *testing.T) {
	session, live := localSessionFixture()
	live.Requirement.Level = identity.AssurancePhishingResistant
	live.Requirement.PolicyRevisions[0].Revision++
	result := RevalidateSession(mfaTestNow, session, live)
	if result.Decision != SessionStepUp || result.AllowAuthority || result.AllowIdleTouch ||
		result.Reason != SessionReasonAssuranceInsufficient {
		t.Fatalf("raised policy result = %#v", result)
	}

	session, live = localSessionFixture()
	live.Requirement.PolicyRevisions[0].Revision++
	result = RevalidateSession(mfaTestNow, session, live)
	if result.Decision != SessionRotate || result.AllowAuthority || result.AllowIdleTouch ||
		result.Reason != SessionReasonPolicyRefresh {
		t.Fatalf("satisfied policy drift = %#v", result)
	}
}

func TestRevalidateSessionRevokesIdentityPrimaryFactorAndLifecycleDrift(t *testing.T) {
	tests := map[string]struct {
		mutate func(*SessionSnapshot, *LiveSessionProjection)
		reason SessionReason
	}{
		"identity epoch":      {func(_ *SessionSnapshot, live *LiveSessionProjection) { live.IdentityEpoch++ }, SessionReasonIdentityEpoch},
		"primary revision":    {func(_ *SessionSnapshot, live *LiveSessionProjection) { live.PrimaryRevision++ }, SessionReasonPrimaryDrift},
		"invalidation epoch":  {func(_ *SessionSnapshot, live *LiveSessionProjection) { live.SessionInvalidationEpoch++ }, SessionReasonPrimaryDrift},
		"factor revision":     {func(_ *SessionSnapshot, live *LiveSessionProjection) { live.Factors[1].Revision++ }, SessionReasonFactorDrift},
		"factor revoked":      {func(_ *SessionSnapshot, live *LiveSessionProjection) { live.Factors[1].Active = false }, SessionReasonFactorDrift},
		"user disabled":       {func(_ *SessionSnapshot, live *LiveSessionProjection) { live.UserActive = false }, SessionReasonLifecycle},
		"membership inactive": {func(_ *SessionSnapshot, live *LiveSessionProjection) { live.MembershipActive = false }, SessionReasonLifecycle},
		"family revoked":      {func(_ *SessionSnapshot, live *LiveSessionProjection) { live.RotationFamilyActive = false }, SessionReasonLifecycle},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			session, live := localSessionFixture()
			test.mutate(&session, &live)
			result := RevalidateSession(mfaTestNow, session, live)
			if result.Decision != SessionRevoke || result.Reason != test.reason ||
				result.AllowAuthority || result.AllowIdleTouch {
				t.Fatalf("result = %#v", result)
			}
		})
	}
}

func TestRevalidateProviderTrustRequiresOneExactLiveSnapshot(t *testing.T) {
	session, live := localSessionFixture()
	provider := identity.ProviderContext{
		Scope: identity.TenantProviderScope, TenantID: session.TenantID, ProviderID: mfaID(30),
	}
	session.Primary = PrimaryProvenance{
		Kind: PrimaryTenantProvider, PrimaryID: mfaID(31), PrimaryRevision: 9,
		Provider: provider, BindingID: mfaID(32), ExternalIdentityID: mfaID(33),
		SessionInvalidationEpoch: 4, AuthenticatedAt: mfaTestNow.Add(-10 * time.Minute),
	}
	trustRevision := int64(5)
	session.Evidence = []SessionEvidence{
		{Evidence: identity.AssuranceEvidence{
			Level: identity.AssuranceMFA, Kind: identity.AssuranceEvidenceFactor,
			Source:          identity.AssuranceSource{ProviderID: provider.ProviderID, BindingID: mfaID(32)},
			AuthenticatedAt: mfaTestNow.Add(-5 * time.Minute), TrustRuleRevision: &trustRevision,
		}},
		{Evidence: identity.AssuranceEvidence{
			Level: identity.AssurancePrimary, Kind: identity.AssuranceEvidenceFactor,
			Source:          identity.AssuranceSource{ProviderID: provider.ProviderID, BindingID: mfaID(32)},
			AuthenticatedAt: mfaTestNow.Add(-10 * time.Minute), TrustRuleRevision: &trustRevision,
		}},
	}
	live.Factors = nil
	live.TrustRules = []TrustRuleState{{
		Provider: provider, BindingID: mfaID(32), Revision: 5, Active: true,
	}}
	if result := RevalidateSession(mfaTestNow, session, live); result.Decision != SessionUsable {
		t.Fatalf("exact trust = %#v", result)
	}
	live.TrustRules[0].Revision++
	if result := RevalidateSession(mfaTestNow, session, live); result.Decision != SessionRevoke ||
		result.Reason != SessionReasonTrustDrift {
		t.Fatalf("trust drift = %#v", result)
	}
}

func TestRevalidateSessionFreshnessAndExpiryBoundaries(t *testing.T) {
	session, live := localSessionFixture()
	live.Requirement.Freshness = 5 * time.Minute
	// The exact age boundary remains fresh.
	result := RevalidateSession(mfaTestNow, session, live)
	if result.Decision != SessionUsable {
		t.Fatalf("exact freshness = %#v", result)
	}
	result = RevalidateSession(mfaTestNow.Add(time.Millisecond), session, live)
	if result.Decision != SessionStepUp || result.AllowIdleTouch {
		t.Fatalf("stale evidence = %#v", result)
	}

	session, live = localSessionFixture()
	result = RevalidateSession(session.IdleExpiresAt, session, live)
	if result.Decision != SessionRevoke || result.Reason != SessionReasonExpired {
		t.Fatalf("idle expiry = %#v", result)
	}
}

func TestRevalidateSessionMalformedInputsDenyFailClosed(t *testing.T) {
	tests := map[string]func(*SessionSnapshot, *LiveSessionProjection){
		"duplicate evidence factor": func(session *SessionSnapshot, _ *LiveSessionProjection) {
			session.Evidence[1].Reference = session.Evidence[0].Reference
		},
		"mixed evidence reference": func(session *SessionSnapshot, _ *LiveSessionProjection) {
			session.Evidence[1].Reference.WebAuthnCredentialID = mfaID(7)
		},
		"substituted primary credential": func(session *SessionSnapshot, _ *LiveSessionProjection) {
			session.Evidence[0].Reference.LocalCredentialID = mfaID(99)
		},
		"TOTP cannot assert primary": func(session *SessionSnapshot, _ *LiveSessionProjection) {
			session.Evidence[1].Evidence.Level = identity.AssurancePrimary
		},
		"step-up passkey cannot replace primary provenance": func(session *SessionSnapshot, _ *LiveSessionProjection) {
			session.Evidence[1].Reference = LocalEvidenceReference{WebAuthnCredentialID: mfaID(7)}
			session.Evidence[1].Evidence.Level = identity.AssurancePrimary
		},
		"recovery kind with TOTP reference": func(session *SessionSnapshot, _ *LiveSessionProjection) {
			session.Evidence[1].Evidence.Kind = identity.AssuranceEvidenceRecovery
		},
		"unsorted policy pins": func(session *SessionSnapshot, _ *LiveSessionProjection) {
			session.PolicyRevisions = append(session.PolicyRevisions,
				identity.AssurancePolicyRevision{PolicyID: mfaID(1), Revision: 1})
		},
		"future issue": func(session *SessionSnapshot, _ *LiveSessionProjection) {
			session.IssuedAt = mfaTestNow.Add(time.Minute)
		},
		"future primary": func(session *SessionSnapshot, _ *LiveSessionProjection) {
			session.Primary.AuthenticatedAt = mfaTestNow.Add(time.Minute)
		},
		"session version outside bigint": func(session *SessionSnapshot, _ *LiveSessionProjection) {
			session.Version = maximumStoredVersion + 1
		},
		"identity epoch outside bigint": func(session *SessionSnapshot, _ *LiveSessionProjection) {
			session.IdentityEpoch = maximumStoredVersion + 1
		},
		"primary invalidation epoch outside bigint": func(session *SessionSnapshot, _ *LiveSessionProjection) {
			session.Primary.SessionInvalidationEpoch = maximumStoredVersion + 1
		},
		"cross tenant projection": func(_ *SessionSnapshot, live *LiveSessionProjection) {
			live.TenantID = mfaID(99)
		},
		"missing audience": func(_ *SessionSnapshot, live *LiveSessionProjection) {
			live.Audience = ""
		},
		"duplicate live factor": func(_ *SessionSnapshot, live *LiveSessionProjection) {
			live.Factors = append(live.Factors, live.Factors[0])
		},
		"mixed live factor reference": func(_ *SessionSnapshot, live *LiveSessionProjection) {
			live.Factors[1].Reference.RecoveryCodeSetID = mfaID(8)
		},
		"live identity epoch outside bigint": func(_ *SessionSnapshot, live *LiveSessionProjection) {
			live.IdentityEpoch = maximumStoredVersion + 1
		},
		"malformed requirement": func(_ *SessionSnapshot, live *LiveSessionProjection) {
			live.Requirement.PolicyRevisions = nil
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			session, live := localSessionFixture()
			mutate(&session, &live)
			result := RevalidateSession(mfaTestNow, session, live)
			if result.Decision != SessionDeny || result.AllowAuthority || result.AllowIdleTouch {
				t.Fatalf("result = %#v", result)
			}
		})
	}
}
