package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedoidc"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
	"github.com/periapsis-im/periapsis/services/api/internal/platformoidcauth"
)

type platformOIDCDirectRuntimeApplyFixture struct {
	now                time.Time
	pins               platformoidcauth.DirectOIDCConfigurationPins
	configuration      federatedoidc.AuthorizationConfiguration
	userID             identity.EntityID
	externalIdentityID identity.EntityID
	factorID           identity.EntityID
	trustRuleID        identity.EntityID
	observation        platformoidcauth.DirectSubjectObservation
	completion         federatedoidc.TransactionCompletion
	claimAttemptID     federatedoidc.TransactionID
	browserDigest      platformoidcauth.DirectBrowserCapabilityDigest
	audit              platformoidcauth.DirectAuditContext
}

func newPlatformOIDCDirectRuntimeApplyFixture(t *testing.T) platformOIDCDirectRuntimeApplyFixture {
	t.Helper()
	now := time.Date(2026, time.August, 30, 15, 20, 0, 789_000_000, time.UTC)
	repository := &FederatedAuthRepository{oidcClient: platformOIDCDirectConfigurationClient(t)}
	configuration, pins, err := repository.platformOIDCDirectConfigurationFromWire(
		platformOIDCDirectConfigurationWireFixture(t),
	)
	if err != nil {
		t.Fatalf("platformOIDCDirectConfigurationFromWire() error = %v", err)
	}
	userID := platformOIDCDirectRuntimeEntityID("000000000141")
	externalIdentityID := platformOIDCDirectRuntimeEntityID("000000000142")
	factorID := platformOIDCDirectRuntimeEntityID("000000000143")
	aliases := []identity.SubjectAlias{
		{KeyVersion: 1, Digest: platformOIDCDirectBytes(35)},
		{KeyVersion: 2, Digest: platformOIDCDirectBytes(75)},
	}
	nonceBytes := platformOIDCDirectBytes(115)
	ciphertext := platformOIDCDirectBytes(155)
	return platformOIDCDirectRuntimeApplyFixture{
		now: now, pins: pins, configuration: configuration.Authorization,
		userID: userID, externalIdentityID: externalIdentityID,
		factorID: factorID, trustRuleID: platformOIDCDirectRuntimeEntityID("000000000144"),
		observation: platformoidcauth.DirectSubjectObservation{
			ExternalIdentityID: externalIdentityID, SubjectFormat: identity.UTF8ExactSubject,
			Aliases: aliases,
			Envelope: identity.ExternalSubjectEnvelope{
				KeyVersion: 2, Format: identity.UTF8ExactSubject,
				Nonce: [12]byte(nonceBytes[:12]), Ciphertext: append([]byte(nil), ciphertext[:]...),
			},
		},
		completion: federatedoidc.TransactionCompletion{
			ID: federatedoidc.TransactionID(platformOIDCDirectBytes(5)), ExpectedVersion: 2,
			Pins: platformOIDCDirectTransactionPins(pins), CompletedAt: now.Add(-time.Second),
			ReturnPath: "/cases/17?tab=timeline", MaterialID: platformOIDCDirectRuntimeEntityID("000000000149"),
		},
		claimAttemptID: federatedoidc.TransactionID(platformOIDCDirectBytes(45)),
		browserDigest:  platformoidcauth.DirectBrowserCapabilityDigest(platformOIDCDirectBytes(85)),
		audit:          platformOIDCDirectRuntimeAuditFixture(),
	}
}

func (fixture platformOIDCDirectRuntimeApplyFixture) sessionRequest(
	t *testing.T,
) platformoidcauth.DirectOIDCApplyRequest {
	t.Helper()
	tokenDigest := platformOIDCDirectBytes(125)
	csrfDigest := platformOIDCDirectBytes(165)
	session, err := mfa.NewSessionReservation(mfa.SessionMaterial{
		SessionID:   platformOIDCDirectRuntimeEntityID("000000000145"),
		FamilyID:    platformOIDCDirectRuntimeEntityID("000000000146"),
		TokenDigest: tokenDigest, CSRFDigest: csrfDigest,
		AuthenticationMethod: mfa.SessionAuthenticationOIDC,
		IdleExpiresAt:        fixture.now.Add(time.Hour), AbsoluteExpiresAt: fixture.now.Add(8 * time.Hour),
	}, fixture.now)
	if err != nil {
		t.Fatalf("NewSessionReservation() error = %v", err)
	}
	trustRevision := uint64(14)
	selected := platformoidcauth.DirectSelectedAssurance{
		Level: identity.AssuranceMFA, AuthenticatedAt: fixture.now.Add(-time.Minute),
		TrustRuleID: &fixture.trustRuleID, TrustRuleRevision: &trustRevision,
	}
	return platformoidcauth.DirectOIDCApplyRequest{
		Plan: platformoidcauth.DirectAuthenticationPlan{
			Disposition: platformoidcauth.DirectAuthenticationImmediateSession,
			Completion:  fixture.completion, Provider: fixture.pins.Provider, UserID: fixture.userID,
			ExternalIdentityID: fixture.externalIdentityID, ProviderRevision: fixture.pins.ProviderRevision,
			PlatformLoginRevision: fixture.pins.PlatformLoginRevision,
			ConfigurationRevision: fixture.pins.ConfigurationRevision, SecurityRevision: fixture.pins.SecurityRevision,
			PlanRevision: fixture.pins.PlanRevision, AssurancePolicyRevision: fixture.pins.AssurancePolicyRevision,
			UserAuthenticationRevision: 13, IdentityRevision: 12, MatchedAliasKeyVersion: 2,
			Subject: fixture.observation, SelectedAssurance: selected,
			ValidUntil: fixture.now.Add(8 * time.Hour),
			PlatformFloor: identity.EffectiveAssuranceRequirement{
				Level: identity.AssuranceMFA, Freshness: time.Hour,
				PolicyRevisions: []identity.AssurancePolicyRevision{{
					PolicyID: fixture.pins.PlatformFloorPolicyID,
					Revision: int64(fixture.pins.PlatformFloorPolicyRevision),
				}},
			},
		},
		ClaimAttemptID: fixture.claimAttemptID, Assurance: selected,
		ContinuationAuthority: federatedauth.ContinuationAuthorityTenant, Session: session,
		BrowserCapabilityDigest: fixture.browserDigest, ReturnPath: fixture.completion.ReturnPath,
		Observation: fixture.observation, AppliedAt: fixture.now, Audit: fixture.audit,
		MaterialID: fixture.completion.MaterialID, MaterialExpiresAt: fixture.now.Add(8 * time.Hour),
		Configuration: fixture.configuration,
	}
}

func (fixture platformOIDCDirectRuntimeApplyFixture) continuationRequest(
	t *testing.T,
) platformoidcauth.DirectOIDCApplyRequest {
	t.Helper()
	receiptDigest := platformOIDCDirectBytes(205)
	continuation, err := federatedauth.NewPostPrimaryContinuationReservation(
		federatedauth.PostPrimaryContinuationMaterial{
			ContinuationID: platformOIDCDirectRuntimeEntityID("000000000147"),
			Authority:      federatedauth.ContinuationAuthorityDirectPlatformOIDC,
			ReceiptDigest:  receiptDigest, ExpiresAt: fixture.now.Add(5 * time.Minute),
		}, fixture.now,
	)
	if err != nil {
		t.Fatalf("NewPostPrimaryContinuationReservation() error = %v", err)
	}
	selected := platformoidcauth.DirectSelectedAssurance{
		Level: identity.AssurancePrimary, AuthenticatedAt: fixture.now.Add(-time.Minute),
	}
	return platformoidcauth.DirectOIDCApplyRequest{
		Plan: platformoidcauth.DirectAuthenticationPlan{
			Disposition: platformoidcauth.DirectAuthenticationTOTPContinuation,
			Completion:  fixture.completion, Provider: fixture.pins.Provider, UserID: fixture.userID,
			ExternalIdentityID: fixture.externalIdentityID, ProviderRevision: fixture.pins.ProviderRevision,
			PlatformLoginRevision: fixture.pins.PlatformLoginRevision,
			ConfigurationRevision: fixture.pins.ConfigurationRevision, SecurityRevision: fixture.pins.SecurityRevision,
			PlanRevision: fixture.pins.PlanRevision, AssurancePolicyRevision: fixture.pins.AssurancePolicyRevision,
			UserAuthenticationRevision: 13, IdentityRevision: 12, MatchedAliasKeyVersion: 2,
			Subject: fixture.observation, SelectedAssurance: selected,
			ValidUntil: fixture.now.Add(5 * time.Minute),
			PlatformFloor: identity.EffectiveAssuranceRequirement{
				Level: identity.AssuranceMFA, LocalRequired: true, Freshness: time.Hour,
				PolicyRevisions: []identity.AssurancePolicyRevision{{
					PolicyID: fixture.pins.PlatformFloorPolicyID,
					Revision: int64(fixture.pins.PlatformFloorPolicyRevision),
				}},
			},
			TOTP: &platformoidcauth.DirectTOTPContinuation{FactorID: fixture.factorID, Revision: 15},
		},
		ClaimAttemptID: fixture.claimAttemptID, Assurance: selected,
		ContinuationAuthority: federatedauth.ContinuationAuthorityDirectPlatformOIDC,
		Continuation:          continuation, BrowserCapabilityDigest: fixture.browserDigest,
		ReturnPath: fixture.completion.ReturnPath, Observation: fixture.observation,
		AppliedAt: fixture.now, Audit: fixture.audit,
		MaterialID: fixture.completion.MaterialID, MaterialExpiresAt: fixture.now.Add(5 * time.Minute),
		Configuration: fixture.configuration,
	}
}

func TestFederatedAuthRepositoryAppliesDirectOIDCWithExactStableWire(t *testing.T) {
	fixture := newPlatformOIDCDirectRuntimeApplyFixture(t)
	tests := map[string]struct {
		request      platformoidcauth.DirectOIDCApplyRequest
		topKey       string
		disposition  string
		responseWire func(platformoidcauth.DirectOIDCApplyRequest) platformOIDCDirectApplyResultWire
	}{
		"session": {
			request: fixture.sessionRequest(t), topKey: "session", disposition: "session",
			responseWire: func(request platformoidcauth.DirectOIDCApplyRequest) platformOIDCDirectApplyResultWire {
				disposition := "session"
				sessionID := entityIDWire(request.Session.SessionID())
				userID := entityIDWire(request.Plan.UserID)
				externalID := entityIDWire(request.Plan.ExternalIdentityID)
				return platformOIDCDirectApplyResultWire{
					Applied: true, Category: "success", Disposition: &disposition,
					SessionID: &sessionID, UserID: &userID, ExternalIdentityID: &externalID,
				}
			},
		},
		"continuation": {
			request: fixture.continuationRequest(t), topKey: "continuation", disposition: "continuation",
			responseWire: func(request platformoidcauth.DirectOIDCApplyRequest) platformOIDCDirectApplyResultWire {
				disposition := "continuation"
				continuationID := entityIDWire(request.Continuation.ContinuationID())
				userID := entityIDWire(request.Plan.UserID)
				externalID := entityIDWire(request.Plan.ExternalIdentityID)
				factorID := entityIDWire(request.Plan.TOTP.FactorID)
				revision := request.Plan.TOTP.Revision
				return platformOIDCDirectApplyResultWire{
					Applied: true, Category: "success", Disposition: &disposition,
					ContinuationID: &continuationID, UserID: &userID, ExternalIdentityID: &externalID,
					TOTPCredentialID: &factorID, TOTPSecurityRevision: &revision,
				}
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var payloadCopies, retainedPayloads, retainedResponses [][]byte
			var operationDigests [][]byte
			var eventIDs []string
			repository := &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(
				_ context.Context,
				query string,
				arguments ...any,
			) pgx.Row {
				if query != "select app.apply_platform_oidc_authentication_v1($1::jsonb)" {
					t.Fatalf("query = %q", query)
				}
				payload := platformOIDCDirectRuntimePayload(t, arguments)
				retainedPayloads = append(retainedPayloads, payload)
				payloadCopies = append(payloadCopies, append([]byte(nil), payload...))
				topKeys := []string{
					"transactionId", "claimAttemptId", "expectedVersion", "operationDigest",
					"browserCapabilityDigest", "returnPath", "subject", "observation", "assurance",
					"disposition", test.topKey, "observedAt", "validUntil", "audit", "materialId",
				}
				object := assertPlatformOIDCDirectRuntimeJSONKeys(t, payload, topKeys...)
				subjectKeys := []string{
					"providerId", "userId", "externalIdentityId", "providerRevision", "securityRevision",
					"loginPolicyRevision", "userAuthenticationRevision", "identityVersion", "aliasKeyVersion",
					"assurancePolicyRevision", "platformFloorPolicyId", "platformFloorPolicyRevision",
				}
				if test.topKey == "continuation" {
					subjectKeys = append(subjectKeys, "totpCredentialId", "totpSecurityRevision")
				}
				assertPlatformOIDCDirectRuntimeJSONKeys(t, object["subject"], subjectKeys...)
				observation := assertPlatformOIDCDirectRuntimeJSONKeys(
					t, object["observation"], "externalIdentityId", "format", "envelope", "aliases",
				)
				assertPlatformOIDCDirectRuntimeJSONKeys(
					t, observation["envelope"], "keyVersion", "format", "nonce", "ciphertext",
				)
				var aliases []map[string]json.RawMessage
				if err := jsonUnmarshalDirectRuntime(observation["aliases"], &aliases); err != nil || len(aliases) != 2 {
					t.Fatalf("aliases = %d, error = %v", len(aliases), err)
				}
				for _, alias := range aliases {
					encoded, marshalErr := json.Marshal(alias)
					if marshalErr != nil {
						t.Fatalf("marshal alias: %v", marshalErr)
					}
					assertPlatformOIDCDirectRuntimeJSONKeys(t, encoded, "keyVersion", "digest")
				}
				assuranceKeys := []string{"level", "authenticatedAt"}
				if test.topKey == "session" {
					assuranceKeys = append(assuranceKeys, "trustRuleId", "trustRuleRevision")
				}
				assertPlatformOIDCDirectRuntimeJSONKeys(t, object["assurance"], assuranceKeys...)
				if test.topKey == "session" {
					assertPlatformOIDCDirectRuntimeJSONKeys(t, object["session"],
						"id", "rotationFamilyId", "tokenDigest", "csrfSecretDigest", "audience",
						"idleExpiresAt", "absoluteExpiresAt", "sessionVersion",
					)
				} else {
					assertPlatformOIDCDirectRuntimeJSONKeys(t, object["continuation"],
						"id", "receiptDigest", "audience", "expiresAt",
					)
				}
				audit := assertPlatformOIDCDirectRuntimeJSONKeys(
					t, object["audit"], "eventId", "requestId", "correlationId", "ipAddress", "userAgent", "authenticationMethod",
				)
				var wire platformOIDCDirectApplyWire
				if err := jsonUnmarshalDirectRuntime(payload, &wire); err != nil {
					t.Fatalf("decode apply wire: %v", err)
				}
				assertPlatformOIDCDirectRuntimeDigest(t, wire.OperationDigest)
				operationDigests = append(operationDigests, append([]byte(nil), wire.OperationDigest...))
				clearPlatformOIDCDirectApplyWire(&wire)
				var eventID string
				if err := jsonUnmarshalDirectRuntime(audit["eventId"], &eventID); err != nil {
					t.Fatalf("decode event ID: %v", err)
				}
				eventIDs = append(eventIDs, eventID)
				return platformOIDCDirectRuntimeJSONRow(t, test.responseWire(test.request), &retainedResponses)
			}}}
			originalCiphertext := append([]byte(nil), test.request.Observation.Envelope.Ciphertext...)
			for range 2 {
				result, err := repository.ApplyDirectOIDC(context.Background(), test.request)
				if err != nil {
					t.Fatalf("ApplyDirectOIDC() error = %v", err)
				}
				if result.Disposition != test.request.Plan.Disposition || result.TransactionID != test.request.Plan.Completion.ID ||
					result.BrowserCapabilityDigest != test.request.BrowserCapabilityDigest ||
					result.UserID != test.request.Plan.UserID || result.ReturnPath != test.request.ReturnPath ||
					!result.AppliedAt.Equal(test.request.AppliedAt) {
					t.Fatalf("apply result drifted: %s", result)
				}
			}
			if len(payloadCopies) != 2 || !bytes.Equal(payloadCopies[0], payloadCopies[1]) ||
				!bytes.Equal(operationDigests[0], operationDigests[1]) || eventIDs[0] != eventIDs[1] {
				t.Fatalf("exact apply retry drifted: events=%v", eventIDs)
			}
			assertPlatformOIDCDirectRuntimeCleared(t, append(retainedPayloads, retainedResponses...)...)
			if !bytes.Equal(test.request.Observation.Envelope.Ciphertext, originalCiphertext) {
				t.Fatal("caller-owned subject ciphertext changed")
			}
		})
	}
}

func TestFederatedAuthRepositoryRejectsDirectOIDCApplyStaleCollisionAndEchoDrift(t *testing.T) {
	fixture := newPlatformOIDCDirectRuntimeApplyFixture(t)
	request := fixture.sessionRequest(t)
	disposition := "session"
	sessionID := entityIDWire(request.Session.SessionID())
	userID := entityIDWire(request.Plan.UserID)
	externalID := entityIDWire(request.Plan.ExternalIdentityID)
	valid := platformOIDCDirectApplyResultWire{
		Applied: true, Category: "success", Disposition: &disposition,
		SessionID: &sessionID, UserID: &userID, ExternalIdentityID: &externalID,
	}
	for name, response := range map[string]platformOIDCDirectApplyResultWire{
		"stale":              {Applied: false, Category: "stale"},
		"identity collision": {Applied: false, Category: "identity_collision"},
		"denied":             {Applied: false, Category: "denied"},
		"unknown category":   {Applied: false, Category: "future"},
		"user echo drift": func() platformOIDCDirectApplyResultWire {
			value := valid
			other := entityIDWire(platformOIDCDirectRuntimeEntityID("000000000148"))
			value.UserID = &other
			return value
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			repository := &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(
				_ context.Context,
				query string,
				_ ...any,
			) pgx.Row {
				if query != "select app.apply_platform_oidc_authentication_v1($1::jsonb)" {
					t.Fatalf("query = %q", query)
				}
				return platformOIDCDirectRuntimeJSONRow(t, response, nil)
			}}}
			result, err := repository.ApplyDirectOIDC(context.Background(), request)
			if !errors.Is(err, errFederatedAuthPersistence) ||
				result != (platformoidcauth.DirectOIDCApplyResult{}) {
				t.Fatalf("result = %s, error = %v", result, err)
			}
		})
	}
}

func TestFederatedAuthRepositoryRejectsDirectOIDCApplyAuthorityDriftBeforeQuery(t *testing.T) {
	fixture := newPlatformOIDCDirectRuntimeApplyFixture(t)
	for name, mutate := range map[string]func(*platformoidcauth.DirectOIDCApplyRequest){
		"floor pin drift": func(value *platformoidcauth.DirectOIDCApplyRequest) {
			value.Plan.PlatformFloor.PolicyRevisions[0].Revision++
		},
		"matched alias absent": func(value *platformoidcauth.DirectOIDCApplyRequest) {
			value.Plan.MatchedAliasKeyVersion = 3
		},
		"subject ciphertext drift": func(value *platformoidcauth.DirectOIDCApplyRequest) {
			value.Observation.Envelope.Ciphertext = append([]byte(nil), value.Observation.Envelope.Ciphertext...)
			value.Observation.Envelope.Ciphertext[0] ^= 0xff
		},
		"invalid proof expiry": func(value *platformoidcauth.DirectOIDCApplyRequest) {
			value.Plan.ValidUntil = value.AppliedAt
		},
	} {
		t.Run(name, func(t *testing.T) {
			request := fixture.sessionRequest(t)
			mutate(&request)
			called := false
			repository := &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(
				_ context.Context,
				_ string,
				_ ...any,
			) pgx.Row {
				called = true
				return nil
			}}}
			result, err := repository.ApplyDirectOIDC(context.Background(), request)
			if !errors.Is(err, errFederatedAuthPersistence) || called ||
				result != (platformoidcauth.DirectOIDCApplyResult{}) {
				t.Fatalf("result = %s, error = %v, called=%t", result, err, called)
			}
		})
	}
}
