package postgres

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedoidc"
	"github.com/periapsis-im/periapsis/services/api/internal/platformoidcauth"
)

type platformOIDCDirectRuntimePlanningFixture struct {
	now                time.Time
	pins               platformoidcauth.DirectOIDCConfigurationPins
	lookup             platformoidcauth.DirectPlatformPlanningLookup
	externalIdentityID identity.EntityID
	userID             identity.EntityID
	factorID           identity.EntityID
	resolve            platformOIDCDirectResolveWire
	trust              platformOIDCDirectTrustWire
	planning           platformOIDCDirectPlanningWire
}

func newPlatformOIDCDirectRuntimePlanningFixture(t *testing.T) platformOIDCDirectRuntimePlanningFixture {
	t.Helper()
	now := time.Date(2026, time.August, 30, 15, 10, 0, 456_000_000, time.UTC)
	pins := platformOIDCDirectRuntimePinsFixture()
	pinsWire := platformOIDCDirectRuntimePinsWireFixture(t, pins)
	firstAlias := identity.SubjectAlias{KeyVersion: 1, Digest: platformOIDCDirectBytes(33)}
	secondAlias := identity.SubjectAlias{KeyVersion: 2, Digest: platformOIDCDirectBytes(73)}
	externalIdentityID := platformOIDCDirectRuntimeEntityID("000000000131")
	userID := platformOIDCDirectRuntimeEntityID("000000000132")
	factorID := platformOIDCDirectRuntimeEntityID("000000000133")
	trustRuleID := entityIDWire(platformOIDCDirectRuntimeEntityID("000000000134"))
	acr := "urn:periapsis:test:mfa"
	confirmedAt := now.Add(-24 * time.Hour)
	return platformOIDCDirectRuntimePlanningFixture{
		now: now, pins: pins,
		lookup: platformoidcauth.DirectPlatformPlanningLookup{
			TransactionID:  federatedoidc.TransactionID(platformOIDCDirectBytes(3)),
			ClaimAttemptID: federatedoidc.TransactionID(platformOIDCDirectBytes(43)),
			ObservedAt:     now, Pins: pins, Provider: pins.Provider, SubjectFormat: identity.UTF8ExactSubject,
			SubjectAliases:   []identity.SubjectAlias{firstAlias, secondAlias},
			ProviderRevision: pins.ProviderRevision, PlatformLoginRevision: pins.PlatformLoginRevision,
			ConfigurationRevision: pins.ConfigurationRevision, SecurityRevision: pins.SecurityRevision,
			AssurancePolicyRevision: pins.AssurancePolicyRevision,
		},
		externalIdentityID: externalIdentityID, userID: userID, factorID: factorID,
		resolve: platformOIDCDirectResolveWire{
			Provider: pinsWire.Provider, ExternalIdentityID: entityIDWire(externalIdentityID),
			UserID: entityIDWire(userID), IdentityVersion: 12, AliasKeyVersion: secondAlias.KeyVersion,
			UserAuthenticationRevision: 13, AccountMode: string(platformoidcauth.AccountModeExistingIdentity),
			Pins: pinsWire,
		},
		trust: platformOIDCDirectTrustWire{
			Provider: pinsWire.Provider, AssurancePolicyRevision: pins.AssurancePolicyRevision,
			Rules: []platformOIDCDirectTrustRuleWire{{
				ID: trustRuleID, Revision: 14, Level: "mfa", ExactValue: &acr,
				RequiredValues: []string{"otp"}, MaximumAuthenticationAgeSeconds: 3600,
			}},
		},
		planning: platformOIDCDirectPlanningWire{
			Provider: pinsWire.Provider, ExternalIdentityID: entityIDWire(externalIdentityID),
			UserID: entityIDWire(userID), IdentityVersion: 12, AliasKeyVersion: secondAlias.KeyVersion,
			UserAuthenticationRevision: 13, ProviderRevision: pins.ProviderRevision,
			LoginPolicyRevision: pins.PlatformLoginRevision, ConfigurationRevision: pins.ConfigurationRevision,
			SecurityRevision: pins.SecurityRevision, PlanRevision: pins.PlanRevision,
			AssurancePolicyRevision: pins.AssurancePolicyRevision,
			PlatformFloor: assurancePolicyWire{
				ID: entityIDWire(pins.PlatformFloorPolicyID), Revision: int64(pins.PlatformFloorPolicyRevision),
				Level: "mfa", LocalRequired: true, FreshnessNanoseconds: int64(time.Hour),
			},
			AccountMode: string(platformoidcauth.AccountModeExistingIdentity), RequiresLocalTOTP: true,
			SelectedTOTP: &platformOIDCDirectSelectedTOTPWire{
				ID: entityIDWire(factorID), UserID: entityIDWire(userID), SecurityRevision: 15,
				Active: true, ConfirmedAt: confirmedAt,
			},
		},
	}
}

func TestFederatedAuthRepositoryLoadsDirectOIDCPlanningStateWithExactQuerySequence(t *testing.T) {
	fixture := newPlatformOIDCDirectRuntimePlanningFixture(t)
	var retainedPayloads, retainedResponses [][]byte
	call := 0
	repository := &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(
		_ context.Context,
		query string,
		arguments ...any,
	) pgx.Row {
		payload := platformOIDCDirectRuntimePayload(t, arguments)
		retainedPayloads = append(retainedPayloads, payload)
		switch call {
		case 0, 1:
			if query != "select app.resolve_platform_oidc_authentication_v1($1::jsonb)" {
				t.Fatalf("resolve query = %q", query)
			}
			object := assertPlatformOIDCDirectRuntimeJSONKeys(t, payload,
				"transactionId", "claimAttemptId", "provider", "subjectAlias", "observedAt",
			)
			assertPlatformOIDCDirectRuntimeJSONKeys(t, object["provider"], "scope", "providerId")
			assertPlatformOIDCDirectRuntimeJSONKeys(t, object["subjectAlias"], "keyVersion", "digest")
			var lookup platformOIDCDirectResolveLookupWire
			if err := jsonUnmarshalDirectRuntime(payload, &lookup); err != nil {
				t.Fatalf("decode resolve lookup: %v", err)
			}
			if lookup.SubjectAlias.KeyVersion != fixture.lookup.SubjectAliases[call].KeyVersion ||
				!bytes.Equal(lookup.SubjectAlias.Digest, fixture.lookup.SubjectAliases[call].Digest[:]) {
				t.Fatalf("resolve alias %d drifted", call)
			}
			response := fixture.resolve
			response.AliasKeyVersion = fixture.lookup.SubjectAliases[call].KeyVersion
			call++
			clearPlatformOIDCDirectResolveLookupWire(&lookup)
			return platformOIDCDirectRuntimeJSONRow(t, response, &retainedResponses)
		case 2:
			if query != "select app.load_platform_oidc_trust_snapshot_v1($1::jsonb)" {
				t.Fatalf("trust query = %q", query)
			}
			object := assertPlatformOIDCDirectRuntimeJSONKeys(t, payload, "provider", "pins")
			assertPlatformOIDCDirectRuntimeJSONKeys(t, object["provider"], "scope", "providerId")
			assertPlatformOIDCDirectRuntimePinsKeys(t, object["pins"])
			call++
			return platformOIDCDirectRuntimeJSONRow(t, fixture.trust, &retainedResponses)
		case 3:
			if query != "select app.load_platform_oidc_planning_state_v1($1::jsonb)" {
				t.Fatalf("planning query = %q", query)
			}
			assertPlatformOIDCDirectRuntimeJSONKeys(t, payload,
				"transactionId", "claimAttemptId", "externalIdentityId", "userId", "identityVersion",
				"aliasKeyVersion", "userAuthenticationRevision", "observedAt",
			)
			call++
			return platformOIDCDirectRuntimeJSONRow(t, fixture.planning, &retainedResponses)
		default:
			t.Fatalf("unexpected query %q", query)
			return nil
		}
	}}}
	state, err := repository.LoadDirectPlatformPlanningState(context.Background(), fixture.lookup)
	if err != nil {
		t.Fatalf("LoadDirectPlatformPlanningState() error = %v", err)
	}
	if call != 4 || state.Provider != fixture.pins.Provider || state.ProviderRevision != fixture.pins.ProviderRevision ||
		state.PlanRevision != fixture.pins.PlanRevision || len(state.Matches) != 1 ||
		state.Matches[0].Alias != fixture.lookup.SubjectAliases[1] ||
		state.Matches[0].ExternalIdentityID != fixture.externalIdentityID ||
		len(state.TrustRules) != 1 || state.TrustRules[0].ACR == nil ||
		*state.TrustRules[0].ACR != "urn:periapsis:test:mfa" ||
		len(state.PlatformFloor.PolicyRevisions) != 1 ||
		state.PlatformFloor.PolicyRevisions[0].PolicyID != fixture.pins.PlatformFloorPolicyID ||
		len(state.LiveConfirmedTOTPFactors) != 1 ||
		state.LiveConfirmedTOTPFactors[0].FactorID != fixture.factorID ||
		state.LiveConfirmedTOTPFactors[0].ConfirmedAt == nil ||
		!state.LiveConfirmedTOTPFactors[0].ConfirmedAt.Equal(fixture.now.Add(-24*time.Hour)) {
		t.Fatalf("planning state drifted: %s", state)
	}
	assertPlatformOIDCDirectRuntimeCleared(t, append(retainedPayloads, retainedResponses...)...)
	clearPlatformOIDCDirectTrustRules(state.TrustRules)
}

func TestFederatedAuthRepositoryRejectsDirectOIDCIdentityAliasCollisionBeforePlanning(t *testing.T) {
	fixture := newPlatformOIDCDirectRuntimePlanningFixture(t)
	call := 0
	repository := &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(
		_ context.Context,
		query string,
		_ ...any,
	) pgx.Row {
		if query != "select app.resolve_platform_oidc_authentication_v1($1::jsonb)" || call > 1 {
			t.Fatalf("unexpected query %d = %q", call, query)
		}
		response := fixture.resolve
		response.AliasKeyVersion = fixture.lookup.SubjectAliases[call].KeyVersion
		if call == 1 {
			response.ExternalIdentityID = entityIDWire(platformOIDCDirectRuntimeEntityID("000000000135"))
		}
		call++
		return platformOIDCDirectRuntimeJSONRow(t, response, nil)
	}}}
	state, err := repository.LoadDirectPlatformPlanningState(context.Background(), fixture.lookup)
	if !errors.Is(err, errFederatedAuthPersistence) || call != 2 ||
		len(state.Matches) != 0 || len(state.TrustRules) != 0 {
		t.Fatalf("state = %s, error = %v, calls=%d", state, err, call)
	}
}

func TestFederatedAuthRepositoryRejectsDirectOIDCPlanningPinTrustAndTOTPDrift(t *testing.T) {
	for name, mutate := range map[string]func(*platformOIDCDirectRuntimePlanningFixture){
		"full pin echo drift": func(value *platformOIDCDirectRuntimePlanningFixture) {
			value.resolve.Pins.JWKSRevision++
		},
		"trust value order": func(value *platformOIDCDirectRuntimePlanningFixture) {
			value.trust.Rules[0].RequiredValues = []string{"otp", "hwk"}
		},
		"unconfirmed selected TOTP": func(value *platformOIDCDirectRuntimePlanningFixture) {
			value.planning.SelectedTOTP.ConfirmedAt = time.Time{}
		},
		"planning CAS drift": func(value *platformOIDCDirectRuntimePlanningFixture) {
			value.planning.UserAuthenticationRevision++
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newPlatformOIDCDirectRuntimePlanningFixture(t)
			mutate(&fixture)
			call := 0
			repository := &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(
				_ context.Context,
				query string,
				_ ...any,
			) pgx.Row {
				switch query {
				case "select app.resolve_platform_oidc_authentication_v1($1::jsonb)":
					response := fixture.resolve
					response.AliasKeyVersion = fixture.lookup.SubjectAliases[call].KeyVersion
					call++
					return platformOIDCDirectRuntimeJSONRow(t, response, nil)
				case "select app.load_platform_oidc_trust_snapshot_v1($1::jsonb)":
					call++
					return platformOIDCDirectRuntimeJSONRow(t, fixture.trust, nil)
				case "select app.load_platform_oidc_planning_state_v1($1::jsonb)":
					call++
					return platformOIDCDirectRuntimeJSONRow(t, fixture.planning, nil)
				default:
					t.Fatalf("unexpected query %q", query)
					return nil
				}
			}}}
			state, err := repository.LoadDirectPlatformPlanningState(context.Background(), fixture.lookup)
			if !errors.Is(err, errFederatedAuthPersistence) || len(state.Matches) != 0 {
				t.Fatalf("state = %s, error = %v, calls=%d", state, err, call)
			}
		})
	}
}
