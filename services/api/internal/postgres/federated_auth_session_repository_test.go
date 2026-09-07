package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
)

func TestFederatedAuthRepositoryLoadsAndCommitsExactSessionRevalidation(t *testing.T) {
	lookup, projectionWire, projection := postgresFederatedSessionFixture(t)
	mutation := federatedauth.SessionMutation{
		SessionID: lookup.SessionID, TenantID: lookup.TenantID, UserID: projection.Snapshot.UserID,
		Audience: lookup.Audience, AuthenticationMethod: projection.AuthenticationMethod,
		ExpectedVersion: projection.Snapshot.Version, ObservedAt: postgresFederatedSessionNow,
		Decision: mfa.SessionUsable, Reason: mfa.SessionReasonCurrent, Requirement: projection.Live.Requirement,
	}
	queries := make([]string, 0, 2)
	repository := &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(
		_ context.Context,
		query string,
		arguments ...any,
	) pgx.Row {
		queries = append(queries, query)
		if len(arguments) != 1 {
			t.Fatalf("%s args=%d", query, len(arguments))
		}
		var response any
		switch query {
		case loadFederatedSessionRevalidationSQL:
			var request federatedSessionLookupWire
			if err := json.Unmarshal(arguments[0].([]byte), &request); err != nil ||
				request.SessionID != entityIDWire(lookup.SessionID) || request.TenantID != entityIDWire(lookup.TenantID) ||
				request.Audience != lookup.Audience || request.AuthenticationMethod != string(lookup.AuthenticationMethod) ||
				!request.ObservedAt.Equal(lookup.ObservedAt) {
				t.Fatalf("load request = %#v, %v", request, err)
			}
			response = projectionWire
		case applyFederatedSessionRevalidationSQL:
			var request federatedSessionMutationWire
			if err := json.Unmarshal(arguments[0].([]byte), &request); err != nil ||
				request.SessionID != entityIDWire(mutation.SessionID) || request.Decision != string(mutation.Decision) ||
				request.Session != nil || request.Continuation != nil {
				t.Fatalf("mutation request = %#v, %v", request, err)
			}
			response = federatedSessionMutationResultWire{
				SessionID: request.SessionID, TenantID: request.TenantID,
				ExpectedVersion: request.ExpectedVersion, Decision: request.Decision, Applied: true,
			}
		default:
			t.Fatalf("unexpected query %q", query)
		}
		encoded, err := json.Marshal(response)
		if err != nil {
			t.Fatal(err)
		}
		return federatedAuthJSONRow(encoded)
	}}}

	loaded, err := repository.LoadSessionForRevalidation(context.Background(), lookup)
	if err != nil || loaded.AuthenticationMethod != federatedauth.AuthenticationMethodOIDC ||
		loaded.Snapshot.SessionID != lookup.SessionID || loaded.Live.Audience != lookup.Audience ||
		len(loaded.Snapshot.Evidence) != 1 || len(loaded.Live.TrustRules) != 1 {
		t.Fatalf("LoadSessionForRevalidation() = %s / %s, %v", loaded.Snapshot, loaded.Live.Audience, err)
	}
	result, err := repository.ApplySessionRevalidation(context.Background(), mutation)
	if err != nil || !result.Applied || result.NewSessionID != (identity.EntityID{}) ||
		result.ContinuationID != (identity.EntityID{}) {
		t.Fatalf("ApplySessionRevalidation() = %+v, %v", result, err)
	}
	if len(queries) != 2 || queries[0] != loadFederatedSessionRevalidationSQL ||
		queries[1] != applyFederatedSessionRevalidationSQL {
		t.Fatalf("queries = %v", queries)
	}
}

func TestLDAPSessionRevalidationDecodesItsAuthorizationRevision(t *testing.T) {
	for _, scenario := range []struct {
		name     string
		revision uint64
		omit     bool
		oidc     bool
		unknown  bool
		allowed  bool
	}{
		{name: "live LDAP revision", revision: 1, allowed: true},
		{name: "JSON-safe maximum", revision: uint64(maximumMFAJSONSafeInteger), allowed: true},
		{name: "missing LDAP revision", omit: true},
		{name: "zero LDAP revision"},
		{name: "overflowing LDAP revision", revision: uint64(maximumMFAJSONSafeInteger) + 1},
		{name: "LDAP field on OIDC", revision: 1, oidc: true},
		{name: "unknown fields remain rejected", revision: 1, unknown: true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			lookup, wire, _ := postgresFederatedSessionFixture(t)
			if !scenario.oidc {
				lookup.AuthenticationMethod = federatedauth.AuthenticationMethodLDAP
				wire.AuthenticationMethod = string(lookup.AuthenticationMethod)
				wire.Lookup.AuthenticationMethod = string(lookup.AuthenticationMethod)
			}
			if !scenario.omit {
				wire.Live.AuthorizationRevision = &scenario.revision
			}
			encoded, err := json.Marshal(wire)
			if err != nil {
				t.Fatal(err)
			}
			if scenario.unknown {
				var document map[string]any
				if err = json.Unmarshal(encoded, &document); err != nil {
					t.Fatal(err)
				}
				document["unexpected"] = true
				encoded, err = json.Marshal(document)
				if err != nil {
					t.Fatal(err)
				}
			}
			repository := &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(
				_ context.Context, query string, _ ...any,
			) pgx.Row {
				if query != loadFederatedSessionRevalidationSQL {
					t.Fatalf("unexpected query %q", query)
				}
				return federatedAuthJSONRow(encoded)
			}}}
			projection, err := repository.LoadSessionForRevalidation(context.Background(), lookup)
			if (err == nil) != scenario.allowed {
				t.Fatalf("LoadSessionForRevalidation() error = %v, allowed = %t", err, scenario.allowed)
			}
			if scenario.allowed && (projection.AuthenticationMethod != lookup.AuthenticationMethod ||
				projection.Snapshot.SessionID != lookup.SessionID) {
				t.Fatal("LDAP session identity changed during decoding")
			}
		})
	}
}

func TestFederatedSessionProjectionSeparatesPlatformAdmission(t *testing.T) {
	lookup, wire, projection := postgresPlatformFederatedSessionFixture(t)
	primary := projection.Snapshot.Primary
	if primary.Kind != mfa.PrimaryPlatformProviderBinding || primary.Provider.Scope != identity.PlatformProviderScope ||
		primary.Provider.TenantID != (identity.EntityID{}) || primary.BindingID == (identity.EntityID{}) ||
		len(projection.Live.TrustRules) != 1 || projection.Live.TrustRules[0].BindingID != primary.BindingID {
		t.Fatalf("platform session projection = %s", projection.Snapshot)
	}
	encoded, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(encoded) || wire.Snapshot.Primary.Admission == nil ||
		wire.Snapshot.Primary.Provider.BindingID != "" || wire.Live.TrustRules[0].Admission == nil {
		t.Fatalf("platform session wire = %s", encoded)
	}

	missing := cloneFederatedSessionProjectionWire(t, wire)
	missing.Snapshot.Primary.Admission = nil
	wanted, err := federatedSessionLookupToWire(lookup)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := federatedSessionProjectionFromWire(missing, wanted); !errors.Is(err, errFederatedAuthPersistence) {
		t.Fatalf("platform primary without admission accepted: %v", err)
	}
	crossTenant := cloneFederatedSessionProjectionWire(t, wire)
	crossTenant.Live.TrustRules[0].Admission.TenantID = federatedEntityIDString(t, postgresFederatedID(199))
	if _, err := federatedSessionProjectionFromWire(crossTenant, wanted); !errors.Is(err, errFederatedAuthPersistence) {
		t.Fatalf("cross-tenant platform trust evidence accepted: %v", err)
	}
}

func TestFederatedSessionLookupRequiresCanonicalRequestTime(t *testing.T) {
	lookup, _, _ := postgresFederatedSessionFixture(t)
	for name, observedAt := range map[string]time.Time{
		"missing":         {},
		"non UTC":         lookup.ObservedAt.In(time.FixedZone("test", 3600)),
		"sub microsecond": lookup.ObservedAt.Add(time.Nanosecond),
	} {
		t.Run(name, func(t *testing.T) {
			candidate := lookup
			candidate.ObservedAt = observedAt
			if _, err := federatedSessionLookupToWire(candidate); !errors.Is(err, errFederatedAuthPersistence) {
				t.Fatalf("non-canonical lookup time accepted: %s: %v", observedAt, err)
			}
		})
	}
}

func TestFederatedSessionRepositoryRejectsProjectionAndCASEchoDrift(t *testing.T) {
	lookup, valid, projection := postgresFederatedSessionFixture(t)
	for name, mutate := range map[string]func(*federatedSessionProjectionWire){
		"lookup tenant drift": func(value *federatedSessionProjectionWire) {
			value.Lookup.TenantID = federatedEntityIDString(t, postgresFederatedID(160))
		},
		"unknown method": func(value *federatedSessionProjectionWire) { value.AuthenticationMethod = "password" },
		"session tenant drift": func(value *federatedSessionProjectionWire) {
			value.Snapshot.TenantID = federatedEntityIDString(t, postgresFederatedID(161))
		},
		"live user drift": func(value *federatedSessionProjectionWire) {
			value.Live.UserID = federatedEntityIDString(t, postgresFederatedID(162))
		},
		"factor amplification": func(value *federatedSessionProjectionWire) {
			value.Live.Factors = make([]federatedFactorStateWire, 1025)
		},
		"unknown primary": func(value *federatedSessionProjectionWire) { value.Snapshot.Primary.Kind = "api_key" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := cloneFederatedSessionProjectionWire(t, valid)
			mutate(&candidate)
			wanted, err := federatedSessionLookupToWire(lookup)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := federatedSessionProjectionFromWire(candidate, wanted); !errors.Is(err, errFederatedAuthPersistence) {
				t.Fatalf("hostile projection accepted: %v", err)
			}
		})
	}

	mutation := federatedauth.SessionMutation{
		SessionID: lookup.SessionID, TenantID: lookup.TenantID, UserID: projection.Snapshot.UserID,
		Audience: lookup.Audience, AuthenticationMethod: projection.AuthenticationMethod,
		ExpectedVersion: projection.Snapshot.Version, ObservedAt: postgresFederatedSessionNow,
		Decision: mfa.SessionRotate, Reason: mfa.SessionReasonPolicyRefresh,
		Requirement: projection.Live.Requirement,
		Session:     postgresRotatedSessionReservation(t, projection.Snapshot),
	}
	wire, err := federatedSessionMutationToWire(mutation)
	if err != nil {
		t.Fatal(err)
	}
	defer clearFederatedSessionMutationWire(&wire)
	validResult := federatedSessionMutationResultWire{
		SessionID: wire.SessionID, TenantID: wire.TenantID, ExpectedVersion: wire.ExpectedVersion,
		Decision: wire.Decision, Applied: true, NewSessionID: wire.Session.SessionID,
	}
	for name, mutate := range map[string]func(*federatedSessionMutationResultWire){
		"version echo drift": func(value *federatedSessionMutationResultWire) { value.ExpectedVersion++ },
		"decision drift":     func(value *federatedSessionMutationResultWire) { value.Decision = string(mfa.SessionUsable) },
		"session substitution": func(value *federatedSessionMutationResultWire) {
			value.NewSessionID = federatedEntityIDString(t, postgresFederatedID(163))
		},
		"CAS loser with result": func(value *federatedSessionMutationResultWire) { value.Applied = false },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := validResult
			mutate(&candidate)
			if _, err := federatedSessionMutationResultFromWire(candidate, wire); !errors.Is(err, errFederatedAuthPersistence) {
				t.Fatalf("drifted CAS response accepted: %v", err)
			}
		})
	}
}

func TestFederatedSessionMutationRejectsImpossibleDecisionReasonPairs(t *testing.T) {
	_, _, projection := postgresFederatedSessionFixture(t)
	base := federatedauth.SessionMutation{
		SessionID: projection.Snapshot.SessionID, TenantID: projection.Snapshot.TenantID,
		UserID: projection.Snapshot.UserID, Audience: "api",
		AuthenticationMethod: projection.AuthenticationMethod, ExpectedVersion: projection.Snapshot.Version,
		ObservedAt: postgresFederatedSessionNow, Requirement: projection.Live.Requirement,
	}
	for name, pair := range map[string]struct {
		decision mfa.SessionDecision
		reason   mfa.SessionReason
	}{
		"usable policy refresh": {mfa.SessionUsable, mfa.SessionReasonPolicyRefresh},
		"rotate current":        {mfa.SessionRotate, mfa.SessionReasonCurrent},
		"step up lifecycle":     {mfa.SessionStepUp, mfa.SessionReasonLifecycle},
		"revoke malformed":      {mfa.SessionRevoke, mfa.SessionReasonMalformed},
		"deny expired":          {mfa.SessionDeny, mfa.SessionReasonExpired},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := base
			candidate.Decision, candidate.Reason = pair.decision, pair.reason
			if _, err := federatedSessionMutationToWire(candidate); !errors.Is(err, errFederatedAuthPersistence) {
				t.Fatalf("impossible pair accepted: %s/%s: %v", pair.decision, pair.reason, err)
			}
		})
	}
}

var postgresFederatedSessionNow = time.Date(2026, time.August, 26, 19, 0, 0, 0, time.UTC)

func postgresFederatedSessionFixture(
	t *testing.T,
) (federatedauth.SessionLookup, federatedSessionProjectionWire, federatedauth.SessionProjection) {
	t.Helper()
	tenantID, userID := postgresFederatedID(150), postgresFederatedID(151)
	provider := identity.ProviderContext{
		Scope: identity.TenantProviderScope, TenantID: tenantID, ProviderID: postgresFederatedID(152),
	}
	bindingID, externalID := postgresFederatedID(153), postgresFederatedID(154)
	trustRevision := int64(4)
	expiresAt := postgresFederatedSessionNow.Add(time.Hour)
	evidence := identity.AssuranceEvidence{
		Level: identity.AssurancePrimary, Kind: identity.AssuranceEvidenceFactor,
		Source:          identity.AssuranceSource{ProviderID: provider.ProviderID, BindingID: bindingID},
		AuthenticatedAt: postgresFederatedSessionNow.Add(-time.Minute), ExpiresAt: &expiresAt,
		TrustRuleRevision: &trustRevision,
	}
	evidenceWire, err := evidenceToWire([]identity.AssuranceEvidence{evidence})
	if err != nil {
		t.Fatal(err)
	}
	policy := identity.AssurancePolicyRevision{PolicyID: postgresFederatedID(155), Revision: 3}
	requirement := identity.EffectiveAssuranceRequirement{
		Level: identity.AssurancePrimary, PolicyRevisions: []identity.AssurancePolicyRevision{policy},
	}
	requirementWire, err := requirementToWire(requirement)
	if err != nil {
		t.Fatal(err)
	}
	providerWire, err := providerBindingToWire(provider, bindingID, false)
	if err != nil {
		t.Fatal(err)
	}
	lookup := federatedauth.SessionLookup{
		SessionID: postgresFederatedID(156), TenantID: tenantID, Audience: "api",
		AuthenticationMethod: federatedauth.AuthenticationMethodOIDC,
		ObservedAt:           postgresFederatedSessionNow,
	}
	lookupWire, err := federatedSessionLookupToWire(lookup)
	if err != nil {
		t.Fatal(err)
	}
	wire := federatedSessionProjectionWire{
		Lookup: lookupWire, AuthenticationMethod: string(federatedauth.AuthenticationMethodOIDC),
		Snapshot: federatedSessionSnapshotWire{
			SessionID: lookupWire.SessionID, RotationFamilyID: federatedEntityIDString(t, postgresFederatedID(157)),
			Version: 5, TenantID: lookupWire.TenantID, UserID: federatedEntityIDString(t, userID), IdentityEpoch: 2,
			Primary: federatedPrimaryProvenanceWire{
				Kind: "tenant_provider", PrimaryID: federatedEntityIDString(t, externalID), PrimaryRevision: 4,
				Provider: &providerWire, ExternalIdentityID: federatedEntityIDString(t, externalID),
				SessionInvalidationEpoch: 6, AuthenticatedAt: postgresFederatedSessionNow.Add(-time.Minute),
			},
			Evidence:        []federatedSessionEvidenceWire{{Evidence: evidenceWire[0]}},
			PolicyRevisions: []policyRevisionWire{{PolicyID: federatedEntityIDString(t, policy.PolicyID), Revision: policy.Revision}},
			IssuedAt:        postgresFederatedSessionNow.Add(-time.Minute), IdleExpiresAt: postgresFederatedSessionNow.Add(time.Hour),
			AbsoluteExpiresAt: postgresFederatedSessionNow.Add(8 * time.Hour),
		},
		Live: federatedLiveSessionWire{
			TenantID: lookupWire.TenantID, UserID: federatedEntityIDString(t, userID), Audience: lookup.Audience,
			SessionActive: true, RotationFamilyActive: true, UserActive: true, TenantActive: true, MembershipActive: true,
			IdentityEpoch: 2, PrimaryActive: true, PrimaryRevision: 4, SessionInvalidationEpoch: 6,
			TrustRules:  []federatedTrustRuleStateWire{{Provider: providerWire, Revision: trustRevision, Active: true}},
			Requirement: requirementWire,
		},
	}
	projection, err := federatedSessionProjectionFromWire(wire, lookupWire)
	if err != nil {
		t.Fatal(err)
	}
	return lookup, wire, projection
}

func postgresPlatformFederatedSessionFixture(
	t *testing.T,
) (federatedauth.SessionLookup, federatedSessionProjectionWire, federatedauth.SessionProjection) {
	t.Helper()
	lookup, wire, _ := postgresFederatedSessionFixture(t)
	provider := identity.ProviderContext{
		Scope: identity.PlatformProviderScope, ProviderID: postgresFederatedID(152),
	}
	admission := identity.TenantAdmissionContext{TenantID: lookup.TenantID, BindingID: postgresFederatedID(153)}
	providerWire, admissionWire, err := providerTenantAdmissionToWire(
		provider, lookup.TenantID, admission.BindingID, admission,
	)
	if err != nil {
		t.Fatal(err)
	}
	wire.Snapshot.Primary.Kind = "platform_provider_binding"
	wire.Snapshot.Primary.Provider = &providerWire
	wire.Snapshot.Primary.Admission = admissionWire
	wire.Live.TrustRules[0].Provider = providerWire
	wire.Live.TrustRules[0].Admission = admissionWire
	wanted, err := federatedSessionLookupToWire(lookup)
	if err != nil {
		t.Fatal(err)
	}
	projection, err := federatedSessionProjectionFromWire(wire, wanted)
	if err != nil {
		t.Fatal(err)
	}
	return lookup, wire, projection
}

func postgresRotatedSessionReservation(t *testing.T, snapshot mfa.SessionSnapshot) mfa.SessionReservation {
	t.Helper()
	token := [32]byte{1}
	csrf := [32]byte{2}
	reservation, err := mfa.NewSessionReservation(mfa.SessionMaterial{
		SessionID: postgresFederatedID(159), FamilyID: snapshot.RotationFamilyID,
		TokenDigest: token, CSRFDigest: csrf, AuthenticationMethod: mfa.SessionAuthenticationOIDC,
		IdleExpiresAt: postgresFederatedSessionNow.Add(time.Hour), AbsoluteExpiresAt: snapshot.AbsoluteExpiresAt,
	}, postgresFederatedSessionNow)
	if err != nil {
		t.Fatal(err)
	}
	return reservation
}

func cloneFederatedSessionProjectionWire(
	t *testing.T,
	value federatedSessionProjectionWire,
) federatedSessionProjectionWire {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var result federatedSessionProjectionWire
	if err := json.Unmarshal(encoded, &result); err != nil {
		t.Fatal(err)
	}
	return result
}
