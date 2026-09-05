package platformoidcauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedoidc"
)

var directTestNow = time.Date(2026, time.August, 30, 14, 0, 0, 0, time.UTC)

type directPlanningStateSourceFunc func(
	context.Context,
	DirectPlatformPlanningLookup,
) (DirectPlatformPlanningState, error)

func (function directPlanningStateSourceFunc) LoadDirectPlatformPlanningState(
	ctx context.Context,
	lookup DirectPlatformPlanningLookup,
) (DirectPlatformPlanningState, error) {
	return function(ctx, lookup)
}

func TestDirectAuthenticationPlannerBuildsPrelinkedImmediateSessionWithProtectedObservation(t *testing.T) {
	keyring := directTestKeyring(t)
	facts := validDirectAuthenticationFactsFixture()
	var observed DirectPlatformPlanningLookup
	planner := directTestPlanner(t, keyring, func(_ context.Context, lookup DirectPlatformPlanningLookup) (DirectPlatformPlanningState, error) {
		observed = cloneDirectPlatformPlanningLookup(lookup)
		return validDirectPlanningStateFixture(lookup), nil
	})

	plan, err := planner.plan(context.Background(), directTestNow, facts)
	if err != nil {
		t.Fatalf("plan() error = %v", err)
	}
	state := validDirectPlanningStateFixture(observed)
	match := state.Matches[0]
	if plan.Disposition != DirectAuthenticationImmediateSession || plan.TOTP != nil ||
		plan.UserID != match.UserID || plan.ExternalIdentityID != match.ExternalIdentityID ||
		plan.Provider != observed.Provider || plan.Completion != facts.Completion {
		t.Fatalf("plan identity/disposition = %#v", plan)
	}
	if plan.ProviderRevision != 11 || plan.PlatformLoginRevision != 12 ||
		plan.ConfigurationRevision != 13 || plan.SecurityRevision != 14 || plan.PlanRevision != 19 ||
		plan.AssurancePolicyRevision != 15 || plan.UserAuthenticationRevision != 22 ||
		plan.IdentityRevision != 21 ||
		plan.MatchedAliasKeyVersion != observed.SubjectAliases[0].KeyVersion {
		t.Fatalf("plan revisions = %#v", plan)
	}
	if len(plan.Evidence) != 2 {
		t.Fatalf("evidence = %#v, want mandatory primary plus trusted MFA", plan.Evidence)
	}
	for index, evidence := range plan.Evidence {
		wantRevision := int64(14)
		if index == 1 {
			wantRevision = 1
		}
		if evidence.Source.Local || !evidence.Source.DirectPlatform ||
			evidence.Source.ProviderID != observed.Provider.ProviderID ||
			evidence.Source.BindingID != (identity.EntityID{}) || evidence.TrustRuleRevision == nil ||
			*evidence.TrustRuleRevision != wantRevision {
			t.Fatalf("evidence[%d] provenance = %#v", index, evidence)
		}
	}
	if plan.Evidence[0].Level != identity.AssurancePrimary || plan.Evidence[1].Level != identity.AssuranceMFA {
		t.Fatalf("evidence levels = %#v", plan.Evidence)
	}
	if plan.SelectedAssurance.Level != identity.AssuranceMFA ||
		plan.SelectedAssurance.TrustRuleID == nil || *plan.SelectedAssurance.TrustRuleID != directTestEntityID(6) ||
		plan.SelectedAssurance.TrustRuleRevision == nil || *plan.SelectedAssurance.TrustRuleRevision != 1 {
		t.Fatalf("selected assurance = %#v", plan.SelectedAssurance)
	}
	if plan.Subject.SubjectFormat != identity.UTF8ExactSubject ||
		plan.Subject.ExternalIdentityID != match.ExternalIdentityID ||
		!slices.Equal(plan.Subject.Aliases, observed.SubjectAliases) ||
		plan.Subject.Envelope.KeyVersion != keyring.ActiveVersion() {
		t.Fatalf("protected subject = %#v", plan.Subject)
	}
	decrypted, err := keyring.DecryptExternalSubject(identity.ExternalSubjectContext{
		Provider: observed.Provider, ExternalIdentityID: match.ExternalIdentityID,
	}, plan.Subject.Envelope)
	if err != nil {
		t.Fatalf("DecryptExternalSubject() error = %v", err)
	}
	decryptedAliases, err := keyring.SubjectAliases(observed.Provider, decrypted)
	decrypted.Clear()
	if err != nil || !slices.Equal(decryptedAliases, observed.SubjectAliases) {
		t.Fatalf("decrypted aliases = %#v, %v", decryptedAliases, err)
	}
}

func TestDirectAuthenticationPlannerReturnsOnlyConfirmedTOTPStepUp(t *testing.T) {
	keyring := directTestKeyring(t)
	facts := validDirectAuthenticationFactsFixture()
	facts.ACR = "urn:untrusted"
	planner := directTestPlanner(t, keyring, func(_ context.Context, lookup DirectPlatformPlanningLookup) (DirectPlatformPlanningState, error) {
		state := validDirectPlanningStateFixture(lookup)
		state.PlatformFloor.LocalRequired = true
		return state, nil
	})

	plan, err := planner.plan(context.Background(), directTestNow, facts)
	if err != nil {
		t.Fatalf("plan() error = %v", err)
	}
	if plan.Disposition != DirectAuthenticationTOTPContinuation || plan.TOTP == nil ||
		plan.TOTP.FactorID != directTestEntityID(5) || plan.TOTP.Revision != 23 || len(plan.Evidence) != 1 {
		t.Fatalf("TOTP plan = %#v", plan)
	}
	if plan.Evidence[0].Level != identity.AssurancePrimary || !plan.Evidence[0].Source.DirectPlatform {
		t.Fatalf("primary evidence = %#v", plan.Evidence)
	}
	if plan.SelectedAssurance.Level != identity.AssurancePrimary ||
		plan.SelectedAssurance.TrustRuleID != nil || plan.SelectedAssurance.TrustRuleRevision != nil {
		t.Fatalf("primary selected assurance = %#v", plan.SelectedAssurance)
	}
}

func TestDirectAuthenticationPlannerRejectsEveryNonDirectOrProjectedProof(t *testing.T) {
	keyring := directTestKeyring(t)
	tests := map[string]func(*directAuthenticationFacts){
		"tenant authority": func(value *directAuthenticationFacts) {
			value.Completion.Pins.Authority = federatedoidc.TenantCeremonyAuthority
		},
		"tenant provider": func(value *directAuthenticationFacts) {
			value.Completion.Pins.Provider.Scope = identity.TenantProviderScope
			value.Completion.Pins.Provider.TenantID = directTestEntityID(9)
		},
		"direct fake tenant": func(value *directAuthenticationFacts) {
			value.Completion.Pins.Provider.TenantID = directTestEntityID(9)
		},
		"direct binding": func(value *directAuthenticationFacts) {
			value.Completion.Pins.BindingID = directTestEntityID(9)
		},
		"direct binding revision": func(value *directAuthenticationFacts) {
			value.Completion.Pins.BindingRevision = 1
		},
		"direct mapping revision": func(value *directAuthenticationFacts) {
			value.Completion.Pins.MappingRevision = 1
		},
		"direct authorization revision": func(value *directAuthenticationFacts) {
			value.Completion.Pins.AuthorizationRevision = 1
		},
		"zero login revision": func(value *directAuthenticationFacts) {
			value.Completion.Pins.PlatformLoginRevision = 0
		},
		"scalar projection": func(value *directAuthenticationFacts) {
			value.Scalars = []federatedoidc.NamedScalar{{Name: "department", Value: "operations"}}
		},
		"profile projection": func(value *directAuthenticationFacts) {
			value.Profiles = []federatedoidc.ProfileValue{{Field: federatedoidc.ProfileEmail, Value: "operator@example.test"}}
		},
		"group projection": func(value *directAuthenticationFacts) {
			value.Groups = []string{"administrators"}
		},
		"expired proof": func(value *directAuthenticationFacts) {
			value.ValidUntil = directTestNow
		},
		"future authentication": func(value *directAuthenticationFacts) {
			value.AuthenticatedAt = directTestNow.Add(time.Second)
		},
		"future completion": func(value *directAuthenticationFacts) {
			value.Completion.CompletedAt = directTestNow.Add(time.Second)
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			calls := 0
			planner := directTestPlanner(t, keyring, func(_ context.Context, lookup DirectPlatformPlanningLookup) (DirectPlatformPlanningState, error) {
				calls++
				return validDirectPlanningStateFixture(lookup), nil
			})
			facts := validDirectAuthenticationFactsFixture()
			mutate(&facts)
			assertDirectPlanDenied(t, planner, facts)
			if calls != 0 {
				t.Fatalf("malformed proof reached state source %d times", calls)
			}
		})
	}
}

func TestDirectAuthenticationPlannerRejectsStateDriftAmbiguityAndCreation(t *testing.T) {
	keyring := directTestKeyring(t)
	tests := map[string]func(*DirectPlatformPlanningState, DirectPlatformPlanningLookup){
		"provider disabled": func(value *DirectPlatformPlanningState, _ DirectPlatformPlanningLookup) {
			value.ProviderEnabled = false
		},
		"login disabled": func(value *DirectPlatformPlanningState, _ DirectPlatformPlanningLookup) {
			value.PlatformLoginLive = false
		},
		"configuration disabled": func(value *DirectPlatformPlanningState, _ DirectPlatformPlanningLookup) {
			value.ConfigurationLive = false
		},
		"assurance disabled": func(value *DirectPlatformPlanningState, _ DirectPlatformPlanningLookup) {
			value.AssurancePolicyLive = false
		},
		"create mode": func(value *DirectPlatformPlanningState, _ DirectPlatformPlanningLookup) {
			value.AccountMode = "create"
		},
		"JIT-shaped missing match": func(value *DirectPlatformPlanningState, _ DirectPlatformPlanningLookup) {
			value.Matches = nil
		},
		"ambiguous aliases": func(value *DirectPlatformPlanningState, _ DirectPlatformPlanningLookup) {
			value.Matches = append(value.Matches, value.Matches[0])
		},
		"retired identity": func(value *DirectPlatformPlanningState, _ DirectPlatformPlanningLookup) {
			value.Matches[0].IdentityLive = false
		},
		"retired alias": func(value *DirectPlatformPlanningState, _ DirectPlatformPlanningLookup) {
			value.Matches[0].AliasLive = false
		},
		"suspended user": func(value *DirectPlatformPlanningState, _ DirectPlatformPlanningLookup) {
			value.Matches[0].UserActive = false
		},
		"email-shaped alias mismatch": func(value *DirectPlatformPlanningState, _ DirectPlatformPlanningLookup) {
			value.Matches[0].Alias.Digest[0] ^= 0xff
		},
		"provider revision drift": func(value *DirectPlatformPlanningState, _ DirectPlatformPlanningLookup) {
			value.ProviderRevision++
		},
		"login revision drift": func(value *DirectPlatformPlanningState, _ DirectPlatformPlanningLookup) {
			value.PlatformLoginRevision++
		},
		"configuration revision drift": func(value *DirectPlatformPlanningState, _ DirectPlatformPlanningLookup) {
			value.ConfigurationRevision++
		},
		"security revision drift": func(value *DirectPlatformPlanningState, _ DirectPlatformPlanningLookup) {
			value.SecurityRevision++
		},
		"assurance revision drift": func(value *DirectPlatformPlanningState, _ DirectPlatformPlanningLookup) {
			value.AssurancePolicyRevision++
		},
		"missing plan revision": func(value *DirectPlatformPlanningState, _ DirectPlatformPlanningLookup) {
			value.PlanRevision = 0
		},
		"missing user-auth revision": func(value *DirectPlatformPlanningState, _ DirectPlatformPlanningLookup) {
			value.Matches[0].UserAuthenticationRevision = 0
		},
		"missing identity revision": func(value *DirectPlatformPlanningState, _ DirectPlatformPlanningLookup) {
			value.Matches[0].IdentityRevision = 0
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			planner := directTestPlanner(t, keyring, func(_ context.Context, lookup DirectPlatformPlanningLookup) (DirectPlatformPlanningState, error) {
				state := validDirectPlanningStateFixture(lookup)
				mutate(&state, lookup)
				return state, nil
			})
			assertDirectPlanDenied(t, planner, validDirectAuthenticationFactsFixture())
		})
	}
}

func TestDirectAuthenticationPlannerRequiresLiveConfirmedTOTPAndSatisfiableFloor(t *testing.T) {
	keyring := directTestKeyring(t)
	tests := map[string]func(*DirectPlatformPlanningState){
		"no TOTP": func(value *DirectPlatformPlanningState) {
			value.LiveConfirmedTOTPFactors = nil
		},
		"unconfirmed TOTP": func(value *DirectPlatformPlanningState) {
			value.LiveConfirmedTOTPFactors[0].ConfirmedAt = nil
		},
		"inactive TOTP": func(value *DirectPlatformPlanningState) {
			value.LiveConfirmedTOTPFactors[0].Active = false
		},
		"TOTP for another user": func(value *DirectPlatformPlanningState) {
			value.LiveConfirmedTOTPFactors[0].UserID = directTestEntityID(10)
		},
		"future confirmation": func(value *DirectPlatformPlanningState) {
			future := directTestNow.Add(time.Second)
			value.LiveConfirmedTOTPFactors[0].ConfirmedAt = &future
		},
		"duplicate TOTP": func(value *DirectPlatformPlanningState) {
			value.LiveConfirmedTOTPFactors = append(value.LiveConfirmedTOTPFactors, value.LiveConfirmedTOTPFactors[0])
		},
		"phishing-resistant floor": func(value *DirectPlatformPlanningState) {
			value.PlatformFloor.Level = identity.AssurancePhishingResistant
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			planner := directTestPlanner(t, keyring, func(_ context.Context, lookup DirectPlatformPlanningLookup) (DirectPlatformPlanningState, error) {
				state := validDirectPlanningStateFixture(lookup)
				state.PlatformFloor.LocalRequired = true
				mutate(&state)
				return state, nil
			})
			facts := validDirectAuthenticationFactsFixture()
			facts.ACR = "urn:untrusted"
			assertDirectPlanDenied(t, planner, facts)
		})
	}
}

func TestDirectAuthenticationPlannerEnforcesUUIDv7VariantAndTimeBounds(t *testing.T) {
	keyring := directTestKeyring(t)
	tests := map[string]func(*directAuthenticationFacts, *DirectPlatformPlanningState){
		"provider v4": func(facts *directAuthenticationFacts, _ *DirectPlatformPlanningState) {
			facts.Completion.Pins.Provider.ProviderID[6] = 0x40
		},
		"provider non-RFC variant": func(facts *directAuthenticationFacts, _ *DirectPlatformPlanningState) {
			facts.Completion.Pins.Provider.ProviderID[8] = 0xc0
		},
		"provider after year 9999": func(facts *directAuthenticationFacts, _ *DirectPlatformPlanningState) {
			facts.Completion.Pins.Provider.ProviderID = directFutureEntityID()
		},
		"user v4": func(_ *directAuthenticationFacts, state *DirectPlatformPlanningState) {
			state.Matches[0].UserID[6] = 0x40
			state.LiveConfirmedTOTPFactors[0].UserID = state.Matches[0].UserID
		},
		"identity non-RFC variant": func(_ *directAuthenticationFacts, state *DirectPlatformPlanningState) {
			state.Matches[0].ExternalIdentityID[8] = 0xc0
		},
		"policy after year 9999": func(_ *directAuthenticationFacts, state *DirectPlatformPlanningState) {
			state.PlatformFloor.PolicyRevisions[0].PolicyID = directFutureEntityID()
		},
		"factor v4": func(_ *directAuthenticationFacts, state *DirectPlatformPlanningState) {
			state.LiveConfirmedTOTPFactors[0].FactorID[6] = 0x40
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			facts := validDirectAuthenticationFactsFixture()
			planner := directTestPlanner(t, keyring, func(_ context.Context, lookup DirectPlatformPlanningLookup) (DirectPlatformPlanningState, error) {
				state := validDirectPlanningStateFixture(lookup)
				mutate(&facts, &state)
				return state, nil
			})
			// Provider mutations must happen before lookup construction.
			if strings.HasPrefix(name, "provider ") {
				mutate(&facts, &DirectPlatformPlanningState{})
			}
			assertDirectPlanDenied(t, planner, facts)
		})
	}
}

func TestDirectAuthenticationPlannerClonesLookupBeforeCallingUntrustedSource(t *testing.T) {
	keyring := directTestKeyring(t)
	planner := directTestPlanner(t, keyring, func(_ context.Context, lookup DirectPlatformPlanningLookup) (DirectPlatformPlanningState, error) {
		original := lookup.SubjectAliases[0]
		lookup.SubjectAliases[0].Digest = [sha256.Size]byte{}
		state := validDirectPlanningStateFixture(lookup)
		state.Matches[0].Alias = original
		return state, nil
	})

	plan, err := planner.plan(context.Background(), directTestNow, validDirectAuthenticationFactsFixture())
	if err != nil || plan.Disposition != DirectAuthenticationImmediateSession {
		t.Fatalf("plan() = %#v, %v; source mutated caller-owned aliases", plan, err)
	}
}

func TestDirectAuthenticationPlannerFormattingNeverLeaksClaimsOrSubject(t *testing.T) {
	canary := "direct-subject-canary@example.test"
	acr := "urn:acr:" + canary
	alias := identity.SubjectAlias{KeyVersion: 1, Digest: sha256.Sum256([]byte(canary))}
	confirmed := directTestNow
	lookup := DirectPlatformPlanningLookup{SubjectAliases: []identity.SubjectAlias{alias}}
	rule := DirectOIDCTrustRule{ACR: &acr, RequiredAMR: []string{"amr-" + canary}}
	match := DirectPlatformIdentityMatch{Alias: alias}
	factor := DirectPlatformTOTPFactor{ConfirmedAt: &confirmed}
	state := DirectPlatformPlanningState{Matches: []DirectPlatformIdentityMatch{match}, TrustRules: []DirectOIDCTrustRule{rule}}
	plan := DirectAuthenticationPlan{Subject: DirectSubjectObservation{Aliases: []identity.SubjectAlias{alias}}}

	for name, value := range map[string]any{
		"lookup": lookup, "rule": rule, "match": match, "factor": factor,
		"state": state, "plan": plan, "subject": plan.Subject,
	} {
		for _, rendered := range []string{fmt.Sprint(value), fmt.Sprintf("%#v", value)} {
			if strings.Contains(rendered, canary) {
				t.Fatalf("%s formatting leaked canary: %s", name, rendered)
			}
		}
	}
}

func TestDirectAuthenticationPlannerPublicBoundaryRejectsUnverifiedValues(t *testing.T) {
	keyring := directTestKeyring(t)
	calls := 0
	planner := directTestPlanner(t, keyring, func(_ context.Context, lookup DirectPlatformPlanningLookup) (DirectPlatformPlanningState, error) {
		calls++
		return validDirectPlanningStateFixture(lookup), nil
	})
	for name, proof := range map[string]*federatedoidc.VerifiedAuthentication{
		"nil":  nil,
		"zero": {},
	} {
		t.Run(name, func(t *testing.T) {
			plan, err := planner.Plan(context.Background(), DirectOIDCTrustPlanRequest{
				ObservedAt: directTestNow, Proof: proof,
			})
			if !errors.Is(err, ErrDirectAuthenticationDenied) || !reflect.DeepEqual(plan, DirectAuthenticationPlan{}) {
				t.Fatalf("Plan() = %#v, %v", plan, err)
			}
		})
	}
	if calls != 0 {
		t.Fatalf("unverified values reached source %d times", calls)
	}
}

func validDirectAuthenticationFactsFixture() directAuthenticationFacts {
	transactionID := federatedoidc.TransactionID{1, 2, 3}
	discoveryDigest := sha256.Sum256([]byte("direct-discovery"))
	jwksDigest := sha256.Sum256([]byte("direct-jwks"))
	return directAuthenticationFacts{
		ClaimAttemptID: federatedoidc.TransactionID{4, 5, 6}, ObservedAt: directTestNow,
		Completion: federatedoidc.TransactionCompletion{
			ID: transactionID, ExpectedVersion: 2, CompletedAt: directTestNow,
			ReturnPath: "/platform",
			Pins: federatedoidc.TransactionPins{
				Authority: federatedoidc.DirectPlatformCeremonyAuthority,
				Provider: identity.ProviderContext{
					Scope: identity.PlatformProviderScope, ProviderID: directTestEntityID(1),
				},
				ProviderRevision: 11, PlatformLoginRevision: 12, ConfigurationRevision: 13,
				SecurityRevision: 14, PlanRevision: 19, AssurancePolicyRevision: 15,
				PlatformFloorPolicyID: directTestEntityID(4), PlatformFloorRevision: 15,
				ClientSecretRevision: 16,
				DiscoveryRevision:    17, DiscoveryDigest: discoveryDigest,
				JWKSRevision: 18, JWKSDigest: jwksDigest,
			},
		},
		Issuer: "https://login.example.test/Platform", Subject: "Exact-Subject-01",
		IssuedAt: directTestNow.Add(-time.Minute), AuthenticatedAt: directTestNow.Add(-2 * time.Minute),
		ValidUntil: directTestNow.Add(time.Hour), ACR: "urn:example:mfa", AMR: []string{"mfa", "pwd"},
	}
}

func validDirectPlanningStateFixture(lookup DirectPlatformPlanningLookup) DirectPlatformPlanningState {
	acr := "urn:example:mfa"
	confirmedAt := directTestNow.Add(-24 * time.Hour)
	userID := directTestEntityID(3)
	return DirectPlatformPlanningState{
		Provider: lookup.Provider, ProviderRevision: lookup.ProviderRevision,
		PlatformLoginRevision: lookup.PlatformLoginRevision,
		ConfigurationRevision: lookup.ConfigurationRevision, SecurityRevision: lookup.SecurityRevision,
		PlanRevision: lookup.Pins.PlanRevision, AssurancePolicyRevision: lookup.AssurancePolicyRevision,
		ProviderEnabled: true, PlatformLoginLive: true, ConfigurationLive: true,
		AssurancePolicyLive: true, AccountMode: AccountModeExistingIdentity,
		Matches: []DirectPlatformIdentityMatch{{
			ProviderID: lookup.Provider.ProviderID, ExternalIdentityID: directTestEntityID(2), UserID: userID,
			Alias: lookup.SubjectAliases[0], IdentityRevision: 21,
			UserAuthenticationRevision: 22, IdentityLive: true, AliasLive: true, UserActive: true,
		}},
		TrustRules: []DirectOIDCTrustRule{{
			RuleID: directTestEntityID(6), Revision: 1, Enabled: true,
			Level: identity.AssuranceMFA, ACR: &acr, RequiredAMR: []string{"mfa"},
			MaximumAuthenticationAge: 10 * time.Minute,
		}},
		PlatformFloor: identity.EffectiveAssuranceRequirement{
			Level: identity.AssuranceMFA,
			PolicyRevisions: []identity.AssurancePolicyRevision{{
				PolicyID: lookup.Pins.PlatformFloorPolicyID,
				Revision: int64(lookup.Pins.PlatformFloorPolicyRevision),
			}},
		},
		LiveConfirmedTOTPFactors: []DirectPlatformTOTPFactor{{
			FactorID: directTestEntityID(5), UserID: userID, Revision: 23,
			Active: true, ConfirmedAt: &confirmedAt,
		}},
	}
}

func directTestPlanner(
	t *testing.T,
	keyring identity.Keyring,
	source directPlanningStateSourceFunc,
) *DirectAuthenticationPlanner {
	t.Helper()
	planner, err := NewDirectAuthenticationPlanner(DirectAuthenticationPlannerOptions{Source: source, Keyring: keyring})
	if err != nil {
		t.Fatalf("NewDirectAuthenticationPlanner() error = %v", err)
	}
	return planner
}

func directTestKeyring(t *testing.T) identity.Keyring {
	t.Helper()
	keyring, err := identity.NewKeyring(2, map[int16][]byte{
		1: bytes.Repeat([]byte{0x31}, 32),
		2: bytes.Repeat([]byte{0x52}, 32),
	})
	if err != nil {
		t.Fatalf("identity.NewKeyring() error = %v", err)
	}
	return keyring
}

func assertDirectPlanDenied(
	t *testing.T,
	planner *DirectAuthenticationPlanner,
	facts directAuthenticationFacts,
) {
	t.Helper()
	plan, err := planner.plan(context.Background(), directTestNow, facts)
	if !errors.Is(err, ErrDirectAuthenticationDenied) {
		t.Fatalf("plan() = %#v, %v; want denial", plan, err)
	}
	if !reflect.DeepEqual(plan, DirectAuthenticationPlan{}) {
		t.Fatalf("denied plan leaked authority = %#v", plan)
	}
}

func directTestEntityID(marker byte) identity.EntityID {
	milliseconds := uint64(directTestNow.UnixMilli())
	encoded := [8]byte{}
	binary.BigEndian.PutUint64(encoded[:], milliseconds)
	result := identity.EntityID{}
	copy(result[0:6], encoded[2:])
	result[6] = 0x70
	result[7] = marker
	result[8] = 0x80
	result[15] = marker
	return result
}

func directFutureEntityID() identity.EntityID {
	milliseconds := maximumUUIDUnixMilliseconds + 1
	encoded := [8]byte{}
	binary.BigEndian.PutUint64(encoded[:], milliseconds)
	result := identity.EntityID{}
	copy(result[0:6], encoded[2:])
	result[6] = 0x70
	result[8] = 0x80
	result[15] = 1
	return result
}
