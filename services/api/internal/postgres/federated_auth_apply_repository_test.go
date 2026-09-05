package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedoidc"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
)

type samlSessionMaterialSealerFunc func(
	context.Context,
	federatedauth.SAMLSessionMaterialSealContext,
	federatedsaml.SessionMaterial,
) (federatedsaml.ProtectedSessionMaterial, error)

func (function samlSessionMaterialSealerFunc) SealSAMLSession(
	ctx context.Context,
	sealContext federatedauth.SAMLSessionMaterialSealContext,
	material federatedsaml.SessionMaterial,
) (federatedsaml.ProtectedSessionMaterial, error) {
	return function(ctx, sealContext, material)
}

func TestFederatedAuthRepositoryAppliesDigestOnlyExactFederatedSession(t *testing.T) {
	request := postgresFederatedApplyFixture(t)
	var retainedPayload []byte
	repository := &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(
		_ context.Context,
		query string,
		arguments ...any,
	) pgx.Row {
		if query != applyFederatedAuthenticationSQL || len(arguments) != 1 {
			t.Fatalf("query = %q args=%d", query, len(arguments))
		}
		retainedPayload = arguments[0].([]byte)
		if bytes.Contains(retainedPayload, []byte("raw-subject-canary")) ||
			bytes.Contains(retainedPayload, []byte("raw-group-canary")) ||
			bytes.Contains(retainedPayload, []byte("raw-token-canary")) {
			t.Fatalf("wire leaked raw protocol/browser material: %s", retainedPayload)
		}
		var command federatedApplyCommandWire
		if err := json.Unmarshal(retainedPayload, &command); err != nil ||
			!validDigestWire(command.OperationDigest) || command.Apply.Session == nil ||
			!validDigestWire(command.Apply.Session.TokenDigest) ||
			command.Apply.Authentication.OIDC == nil || command.Apply.Plan.Mapping == nil ||
			len(command.Apply.Plan.Mapping.Profile) != 6 {
			t.Fatalf("apply command malformed: %#v, %v", command, err)
		}
		response := federatedApplyResultWire{
			OperationDigest: append([]byte(nil), command.OperationDigest...),
			Protocol:        command.Apply.Authentication.Protocol, TenantID: command.Apply.Authentication.TenantID,
			Disposition: command.Apply.Disposition, Category: string(federatedauth.ApplySuccess),
			UserID:    federatedEntityIDString(t, postgresFederatedID(111)),
			SessionID: command.Apply.Session.SessionID, ReturnPath: command.Apply.Authentication.OIDC.ReturnPath,
			Replayed: true,
		}
		encoded, err := json.Marshal(response)
		if err != nil {
			t.Fatal(err)
		}
		return federatedAuthJSONRow(encoded)
	}}}

	result, err := repository.ApplyFederatedAuthentication(context.Background(), request)
	if err != nil || result.Category != federatedauth.ApplySuccess || !result.Replayed ||
		result.SessionID != request.Session.SessionID() || result.ContinuationID != (identity.EntityID{}) ||
		result.ReturnPath != "/cases?view=mine" {
		t.Fatalf("ApplyFederatedAuthentication() = %s, %v", result, err)
	}
	if !allZeroFederatedBytes(retainedPayload) {
		t.Fatal("query payload retained mapped profile, subject envelope, or digests")
	}
}

func TestFederatedApplyWireSeparatesPlatformAdmissionAndRejectsProviderAuthority(t *testing.T) {
	request := postgresPlatformFederatedApplyFixture(t)
	command, err := federatedApplyToWire(request, nil, identity.EntityID{})
	if err != nil {
		t.Fatal(err)
	}
	defer clearFederatedApplyCommandWire(&command)
	authentication := command.Apply.Authentication
	if authentication.Admission == nil || authentication.OIDC == nil ||
		authentication.OIDC.Pins.Admission == nil ||
		*authentication.Admission != *authentication.OIDC.Pins.Admission ||
		authentication.OIDC.Pins.Provider.Scope != federatedPlatformProviderScopeWire ||
		authentication.OIDC.Pins.Provider.BindingID != "" || !validPlatformApplyPlanWire(command.Apply.Plan) {
		t.Fatalf("platform apply wire = %#v", command.Apply)
	}

	tenantCommand, err := federatedApplyToWire(postgresFederatedApplyFixture(t), nil, identity.EntityID{})
	if err != nil {
		t.Fatal(err)
	}
	tenantJSON, err := json.Marshal(tenantCommand.Apply.Authentication)
	clearFederatedApplyCommandWire(&tenantCommand)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(tenantJSON, []byte(`"admission"`)) {
		t.Fatalf("tenant apply wire gained admission: %s", tenantJSON)
	}

	repeat := postgresPlatformExistingFederatedApplyFixture(t)
	repeatCommand, err := federatedApplyToWire(repeat, nil, identity.EntityID{})
	if err != nil {
		t.Fatalf("repeat platform apply rejected: %v", err)
	}
	if repeatCommand.Apply.Plan.Mapping == nil ||
		repeatCommand.Apply.Plan.Mapping.AccessAction != "no_change" ||
		!validPlatformApplyPlanWire(repeatCommand.Apply.Plan) {
		clearFederatedApplyCommandWire(&repeatCommand)
		t.Fatalf("repeat platform apply wire = %#v", repeatCommand.Apply.Plan)
	}
	clearFederatedApplyCommandWire(&repeatCommand)

	for name, mutate := range map[string]func(*federatedauth.ApplyRequest){
		"tenant substitution": func(value *federatedauth.ApplyRequest) {
			value.Authentication.Admission.TenantID = postgresFederatedID(201)
		},
		"provider role": func(value *federatedauth.ApplyRequest) {
			value.Plan.RoleIDs = []identity.EntityID{postgresFederatedID(202)}
		},
		"provider group": func(value *federatedauth.ApplyRequest) {
			value.Plan.SecurityGroupIDs = []identity.EntityID{postgresFederatedID(203)}
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := postgresPlatformFederatedApplyFixture(t)
			mutate(&candidate)
			wire, err := federatedApplyToWire(candidate, nil, identity.EntityID{})
			clearFederatedApplyCommandWire(&wire)
			if !errors.Is(err, errFederatedAuthPersistence) {
				t.Fatalf("hostile platform apply accepted: %v", err)
			}
		})
	}
}

func TestFederatedApplyWireRejectsPinReservationAndEchoDrift(t *testing.T) {
	for name, mutate := range map[string]func(*federatedauth.ApplyRequest){
		"tenant drift":            func(value *federatedauth.ApplyRequest) { value.Plan.TenantID = postgresFederatedID(122) },
		"configuration pin drift": func(value *federatedauth.ApplyRequest) { value.Plan.ConfigurationRevision++ },
		"wrong session method": func(value *federatedauth.ApplyRequest) {
			value.Session = postgresSessionReservation(t, value.AppliedAt, mfa.SessionAuthenticationSAML, 123)
		},
		"mixed reservation": func(value *federatedauth.ApplyRequest) {
			value.Continuation = postgresContinuationReservation(t, value.AppliedAt, 124)
		},
		"role consequence drift": func(value *federatedauth.ApplyRequest) {
			value.Plan.RoleIDs = append(value.Plan.RoleIDs, postgresFederatedID(125))
		},
		"non canonical return path": func(value *federatedauth.ApplyRequest) {
			value.Authentication.OIDCCompletion.ReturnPath = "//attacker.example"
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := postgresFederatedApplyFixture(t)
			mutate(&candidate)
			if wire, err := federatedApplyToWire(candidate, nil, identity.EntityID{}); !errors.Is(err, errFederatedAuthPersistence) {
				clearFederatedApplyCommandWire(&wire)
				t.Fatalf("hostile apply accepted: %v", err)
			}
		})
	}

	request := postgresFederatedApplyFixture(t)
	command, err := federatedApplyToWire(request, nil, identity.EntityID{})
	if err != nil {
		t.Fatal(err)
	}
	defer clearFederatedApplyCommandWire(&command)
	valid := federatedApplyResultWire{
		OperationDigest: append([]byte(nil), command.OperationDigest...),
		Protocol:        command.Apply.Authentication.Protocol, TenantID: command.Apply.Authentication.TenantID,
		Disposition: command.Apply.Disposition, Category: string(federatedauth.ApplySuccess),
		UserID:    federatedEntityIDString(t, postgresFederatedID(126)),
		SessionID: command.Apply.Session.SessionID, ReturnPath: command.Apply.Authentication.OIDC.ReturnPath,
	}
	for name, mutate := range map[string]func(*federatedApplyResultWire){
		"digest drift": func(value *federatedApplyResultWire) { value.OperationDigest[0] ^= 0xff },
		"tenant echo drift": func(value *federatedApplyResultWire) {
			value.TenantID = federatedEntityIDString(t, postgresFederatedID(127))
		},
		"session substitution": func(value *federatedApplyResultWire) {
			value.SessionID = federatedEntityIDString(t, postgresFederatedID(128))
		},
		"return path drift": func(value *federatedApplyResultWire) { value.ReturnPath = "/other" },
		"failed result oracle": func(value *federatedApplyResultWire) {
			value.Category = string(federatedauth.ApplyDenied)
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := cloneFederatedApplyResultWire(t, valid)
			mutate(&candidate)
			if _, err := federatedApplyResultFromWire(candidate, command); !errors.Is(err, errFederatedAuthPersistence) {
				t.Fatalf("drifted response accepted: %v", err)
			}
		})
	}
}

func TestFederatedApplyRepositoryHonorsCancellationBeforeQuery(t *testing.T) {
	called := false
	repository := &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(
		context.Context,
		string,
		...any,
	) pgx.Row {
		called = true
		return federatedAuthJSONRow(nil)
	}}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := repository.ApplyFederatedAuthentication(ctx, postgresFederatedApplyFixture(t)); !errors.Is(err, errFederatedAuthPersistence) {
		t.Fatalf("canceled apply error = %v", err)
	}
	if called {
		t.Fatal("canceled apply reached database")
	}
}

func TestFederatedAuthRepositoryProtectsSAMLMaterialForExactAnchor(t *testing.T) {
	for _, disposition := range []federatedauth.ApplyDisposition{
		federatedauth.ApplySession,
		federatedauth.ApplyContinuation,
	} {
		t.Run(string(disposition), func(t *testing.T) {
			request := postgresSAMLApplyFixture(t, disposition)
			materialID := request.Authentication.SAMLConsumption.MaterialID
			material := federatedsaml.SessionMaterial{
				NameID: "persistent-nameid-canary", NameIDFormat: federatedsaml.PersistentNameIDFormat,
				SessionIndex: "session-index-canary",
			}
			sealCalls := 0
			repository := &FederatedAuthRepository{
				samlSessionSealer: samlSessionMaterialSealerFunc(func(
					ctx context.Context,
					sealContext federatedauth.SAMLSessionMaterialSealContext,
					observed federatedsaml.SessionMaterial,
				) (federatedsaml.ProtectedSessionMaterial, error) {
					sealCalls++
					if ctx.Err() != nil || observed != material || sealContext.Provider != request.Authentication.SAMLConsumption.Pins.Provider ||
						sealContext.BindingID != request.Authentication.SAMLConsumption.Pins.BindingID ||
						sealContext.MaterialID != materialID {
						t.Fatalf("seal context/material = %#v / %s", sealContext, observed)
					}
					return federatedsaml.ProtectedSessionMaterial{KeyVersion: 7, Ciphertext: bytes.Repeat([]byte{7}, 32)}, nil
				}),
			}
			repository.queryer = federatedAuthQueryerStub{query: func(
				_ context.Context,
				query string,
				arguments ...any,
			) pgx.Row {
				if query != applyFederatedAuthenticationSQL {
					t.Fatalf("query = %q", query)
				}
				payload := arguments[0].([]byte)
				if bytes.Contains(payload, []byte("persistent-nameid-canary")) ||
					bytes.Contains(payload, []byte("session-index-canary")) {
					t.Fatal("SAML plaintext reached SQL wire")
				}
				var command federatedApplyCommandWire
				if err := json.Unmarshal(payload, &command); err != nil || command.Apply.SAMLSession == nil ||
					command.Apply.SAMLSession.MaterialID != entityIDWire(materialID) ||
					command.Apply.Authentication.SAML.MaterialID != entityIDWire(materialID) ||
					command.Apply.SAMLSession.KeyVersion != 7 || len(command.Apply.SAMLSession.Ciphertext) != 32 {
					t.Fatalf("protected SAML wire = %#v, %v", command.Apply.SAMLSession, err)
				}
				response := federatedApplyResultWire{
					OperationDigest: append([]byte(nil), command.OperationDigest...),
					Protocol:        command.Apply.Authentication.Protocol, TenantID: command.Apply.Authentication.TenantID,
					Disposition: command.Apply.Disposition, Category: string(federatedauth.ApplySuccess),
					UserID:     federatedEntityIDString(t, postgresFederatedID(140)),
					ReturnPath: command.Apply.Authentication.SAML.ReturnPath,
				}
				if command.Apply.Session != nil {
					response.SessionID = command.Apply.Session.SessionID
				} else {
					response.ContinuationID = command.Apply.Continuation.ContinuationID
				}
				encoded, err := json.Marshal(response)
				if err != nil {
					t.Fatal(err)
				}
				return federatedAuthJSONRow(encoded)
			}}

			result, err := repository.ApplySAMLAuthentication(context.Background(), federatedauth.SAMLApplyRequest{
				Apply: request, MaterialID: materialID, SessionMaterial: material,
			})
			if err != nil || result.Category != federatedauth.ApplySuccess || sealCalls != 1 {
				t.Fatalf("ApplySAMLAuthentication() = %s, %v calls=%d", result, err, sealCalls)
			}
		})
	}
}

func TestFederatedSAMLApplyDigestExcludesOnlyNondeterministicEnvelope(t *testing.T) {
	request := postgresSAMLApplyFixture(t, federatedauth.ApplySession)
	materialID := request.Authentication.SAMLConsumption.MaterialID
	first, err := federatedApplyToWire(request, &federatedsaml.ProtectedSessionMaterial{
		KeyVersion: 7, Ciphertext: bytes.Repeat([]byte{0x31}, 32),
	}, materialID)
	if err != nil {
		t.Fatal(err)
	}
	defer clearFederatedApplyCommandWire(&first)
	second, err := federatedApplyToWire(request, &federatedsaml.ProtectedSessionMaterial{
		KeyVersion: 8, Ciphertext: bytes.Repeat([]byte{0x42}, 48),
	}, materialID)
	if err != nil {
		t.Fatal(err)
	}
	defer clearFederatedApplyCommandWire(&second)
	if !bytes.Equal(first.OperationDigest, second.OperationDigest) ||
		bytes.Equal(first.Apply.SAMLSession.Ciphertext, second.Apply.SAMLSession.Ciphertext) {
		t.Fatal("randomized SAML envelopes changed the semantic operation digest or were not retained independently")
	}

	drifted := request
	drifted.Authentication.SAMLConsumption = cloneSAMLConsumption(request.Authentication.SAMLConsumption)
	drifted.Authentication.SAMLConsumption.MaterialID = postgresFederatedID(147)
	materialDrift, err := federatedApplyToWire(drifted, &federatedsaml.ProtectedSessionMaterial{
		KeyVersion: 7, Ciphertext: bytes.Repeat([]byte{0x31}, 32),
	}, drifted.Authentication.SAMLConsumption.MaterialID)
	if err != nil {
		t.Fatal(err)
	}
	defer clearFederatedApplyCommandWire(&materialDrift)
	if bytes.Equal(first.OperationDigest, materialDrift.OperationDigest) {
		t.Fatal("material identity drift did not change the semantic operation digest")
	}

	semanticDrift := request
	semanticDrift.Authentication.SAMLConsumption = cloneSAMLConsumption(request.Authentication.SAMLConsumption)
	semanticDrift.Authentication.SAMLConsumption.ResponseID = "_different-response"
	driftCommand, err := federatedApplyToWire(semanticDrift, &federatedsaml.ProtectedSessionMaterial{
		KeyVersion: 7, Ciphertext: bytes.Repeat([]byte{0x31}, 32),
	}, materialID)
	if err != nil {
		t.Fatal(err)
	}
	defer clearFederatedApplyCommandWire(&driftCommand)
	if bytes.Equal(first.OperationDigest, driftCommand.OperationDigest) {
		t.Fatal("semantic SAML input drift did not change the operation digest")
	}
}

func cloneSAMLConsumption(value *federatedsaml.ConsumptionRequest) *federatedsaml.ConsumptionRequest {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}

func postgresFederatedApplyFixture(t *testing.T) federatedauth.ApplyRequest {
	t.Helper()
	lookup, stateWire := postgresFederatedPlanningFixture(t, false)
	state, err := federatedPlanningStateFromWire(stateWire, lookup)
	if err != nil {
		t.Fatal(err)
	}
	displayName := "mapped-profile-canary"
	subject, err := identity.CanonicalUTF8Exact([]byte("raw-subject-canary"))
	if err != nil {
		t.Fatal(err)
	}
	defer subject.Clear()
	observation, err := identity.NewFederatedMappingObservation(identity.FederatedMappingObservationInput{
		Subject: subject, Profile: identity.LDAPProfileValues{DisplayName: &displayName},
		Groups: []string{"incident-command", "raw-group-canary"}, Complete: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	mapping, err := identity.PlanFederatedMapping(observation, state.Mapping)
	if err != nil || mapping.Disposition() != identity.LDAPPlanAdmitted {
		t.Fatalf("mapping = %s, %v", mapping, err)
	}
	now := time.Date(2026, time.August, 26, 18, 0, 0, 0, time.UTC)
	trustRevision := int64(lookup.SecurityRevision)
	expiresAt := now.Add(time.Hour)
	completion := &federatedoidc.TransactionCompletion{
		ID: postgresOIDCTransactionID(44), MaterialID: postgresFederatedID(45), ExpectedVersion: 2,
		Pins: federatedoidc.TransactionPins{
			Provider: lookup.Provider, BindingID: lookup.BindingID,
			ProviderRevision: lookup.ProviderRevision, BindingRevision: lookup.BindingRevision,
			ConfigurationRevision: lookup.ConfigurationRevision, SecurityRevision: lookup.SecurityRevision,
			MappingRevision: lookup.MappingRevision, AuthorizationRevision: lookup.AuthorizationRevision,
			AssurancePolicyRevision: lookup.AssurancePolicyRevision,
			ClientSecretRevision:    17, DiscoveryRevision: 18, DiscoveryDigest: sha256.Sum256([]byte("discovery")),
			JWKSRevision: 19, JWKSDigest: sha256.Sum256([]byte("jwks")),
		},
		CompletedAt: now, ReturnPath: "/cases?view=mine",
	}
	protectedSubject := &federatedauth.ProtectedFederatedSubject{
		ExternalIdentityID: state.ExternalIdentityID, Aliases: append([]identity.SubjectAlias(nil), lookup.SubjectAliases...),
		Envelope: identity.ExternalSubjectEnvelope{
			KeyVersion: 2, Format: identity.UTF8ExactSubject,
			Ciphertext: bytes.Repeat([]byte{0x41}, 32),
		},
	}
	protectedSubject.Envelope.Nonce[0] = 1
	plan := federatedauth.AuthenticationPlan{
		PlanRevision: state.PlanRevision, TenantID: lookup.TenantID,
		ProviderRevision: lookup.ProviderRevision, BindingRevision: lookup.BindingRevision,
		ConfigurationRevision: lookup.ConfigurationRevision, SecurityRevision: lookup.SecurityRevision,
		MappingRevision: lookup.MappingRevision, AuthorizationRevision: lookup.AuthorizationRevision,
		PolicyRevision: lookup.AssurancePolicyRevision,
		RoleIDs:        mapping.ProspectiveRoleIDs(), SecurityGroupIDs: mapping.ProspectiveSecurityGroupIDs(),
		Subject: protectedSubject, Mapping: &mapping, Requirement: state.Requirement, HasEnrollableFactor: true,
	}
	return federatedauth.ApplyRequest{
		Authentication: federatedauth.ApplyAuthenticationProjection{
			Protocol: federatedauth.ProtocolOIDC, Method: federatedauth.AuthenticationMethodOIDC,
			TenantID: lookup.TenantID, AuthenticatedAt: now.Add(-time.Minute), ValidUntil: expiresAt,
			Evidence: []identity.AssuranceEvidence{{
				Level: identity.AssurancePrimary, Kind: identity.AssuranceEvidenceFactor,
				Source:          identity.AssuranceSource{ProviderID: lookup.Provider.ProviderID, BindingID: lookup.BindingID},
				AuthenticatedAt: now.Add(-time.Minute), ExpiresAt: &expiresAt, TrustRuleRevision: &trustRevision,
			}},
			OIDCCompletion: completion,
		},
		Plan: plan, Disposition: federatedauth.ApplySession, Assurance: identity.AssuranceSatisfied,
		AppliedAt: now, Session: postgresSessionReservation(t, now, mfa.SessionAuthenticationOIDC, 115),
	}
}

func postgresPlatformFederatedApplyFixture(t *testing.T) federatedauth.ApplyRequest {
	return postgresPlatformFederatedApplyFixtureForIdentity(t, false)
}

func postgresPlatformExistingFederatedApplyFixture(t *testing.T) federatedauth.ApplyRequest {
	return postgresPlatformFederatedApplyFixtureForIdentity(t, true)
}

func postgresPlatformFederatedApplyFixtureForIdentity(t *testing.T, existing bool) federatedauth.ApplyRequest {
	t.Helper()
	lookup, stateWire := postgresPlatformFederatedPlanningFixture(t, existing)
	state, err := federatedPlanningStateFromWire(stateWire, lookup)
	if err != nil {
		t.Fatal(err)
	}
	displayName := "platform-profile-canary"
	subject, err := identity.CanonicalUTF8Exact([]byte("platform-subject-canary"))
	if err != nil {
		t.Fatal(err)
	}
	defer subject.Clear()
	observation, err := identity.NewFederatedMappingObservation(identity.FederatedMappingObservationInput{
		Subject: subject, Profile: identity.LDAPProfileValues{DisplayName: &displayName},
		Groups: []string{"provider-group-must-not-authorize"}, Complete: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	mapping, err := identity.PlanFederatedMapping(observation, state.Mapping)
	if err != nil || mapping.Disposition() != identity.LDAPPlanAdmitted ||
		len(mapping.ProspectiveRoleIDs()) != 0 || len(mapping.ProspectiveSecurityGroupIDs()) != 0 ||
		len(mapping.Changes()) != 0 {
		t.Fatalf("platform mapping = %s, %v", mapping, err)
	}
	now := time.Date(2026, time.August, 29, 12, 0, 0, 0, time.UTC)
	expiresAt := now.Add(time.Hour)
	trustRevision := int64(lookup.SecurityRevision)
	completion := &federatedoidc.TransactionCompletion{
		ID: postgresOIDCTransactionID(144), MaterialID: postgresFederatedID(145), ExpectedVersion: 2,
		Pins: federatedoidc.TransactionPins{
			Provider: lookup.Provider, Admission: lookup.Admission,
			ProviderRevision: lookup.ProviderRevision, BindingRevision: lookup.BindingRevision,
			ConfigurationRevision: lookup.ConfigurationRevision, SecurityRevision: lookup.SecurityRevision,
			MappingRevision: lookup.MappingRevision, AuthorizationRevision: lookup.AuthorizationRevision,
			AssurancePolicyRevision: lookup.AssurancePolicyRevision,
			ClientSecretRevision:    17, DiscoveryRevision: 18, DiscoveryDigest: sha256.Sum256([]byte("platform-discovery")),
			JWKSRevision: 19, JWKSDigest: sha256.Sum256([]byte("platform-jwks")),
		},
		CompletedAt: now, ReturnPath: "/cases?view=platform",
	}
	protectedSubject := &federatedauth.ProtectedFederatedSubject{
		ExternalIdentityID: state.ExternalIdentityID,
		Aliases:            append([]identity.SubjectAlias(nil), lookup.SubjectAliases...),
		Envelope: identity.ExternalSubjectEnvelope{
			KeyVersion: 2, Format: identity.UTF8ExactSubject,
			Ciphertext: bytes.Repeat([]byte{0x51}, 32),
		},
	}
	protectedSubject.Envelope.Nonce[0] = 1
	plan := federatedauth.AuthenticationPlan{
		PlanRevision: state.PlanRevision, TenantID: lookup.TenantID,
		UserID: state.UserID, IdentityEpoch: state.IdentityEpoch,
		ProviderRevision: lookup.ProviderRevision, BindingRevision: lookup.BindingRevision,
		ConfigurationRevision: lookup.ConfigurationRevision, SecurityRevision: lookup.SecurityRevision,
		MappingRevision: lookup.MappingRevision, AuthorizationRevision: lookup.AuthorizationRevision,
		PolicyRevision: lookup.AssurancePolicyRevision, Subject: protectedSubject, Mapping: &mapping,
		Requirement: state.Requirement, HasEnrollableFactor: state.HasEnrollableFactor,
	}
	return federatedauth.ApplyRequest{
		Authentication: federatedauth.ApplyAuthenticationProjection{
			Protocol: federatedauth.ProtocolOIDC, Method: federatedauth.AuthenticationMethodOIDC,
			TenantID: lookup.TenantID, Admission: lookup.Admission,
			AuthenticatedAt: now.Add(-time.Minute), ValidUntil: expiresAt,
			Evidence: []identity.AssuranceEvidence{{
				Level: identity.AssurancePrimary, Kind: identity.AssuranceEvidenceFactor,
				Source: identity.AssuranceSource{
					ProviderID: lookup.Provider.ProviderID, BindingID: lookup.BindingID,
				},
				AuthenticatedAt: now.Add(-time.Minute), ExpiresAt: &expiresAt,
				TrustRuleRevision: &trustRevision,
			}},
			OIDCCompletion: completion,
		},
		Plan: plan, Disposition: federatedauth.ApplySession, Assurance: identity.AssuranceSatisfied,
		AppliedAt: now, Session: postgresSessionReservation(t, now, mfa.SessionAuthenticationOIDC, 215),
	}
}

func postgresSAMLApplyFixture(t *testing.T, disposition federatedauth.ApplyDisposition) federatedauth.ApplyRequest {
	t.Helper()
	request := postgresFederatedApplyFixture(t)
	oidc := request.Authentication.OIDCCompletion
	request.Authentication.Protocol = federatedauth.ProtocolSAML
	request.Authentication.Method = federatedauth.AuthenticationMethodSAML
	request.Authentication.OIDCCompletion = nil
	request.Authentication.SAMLConsumption = &federatedsaml.ConsumptionRequest{
		TransactionID: postgresSAMLTransactionID(45), MaterialID: postgresFederatedID(146),
		ExpectedVersion: oidc.ExpectedVersion,
		Pins: federatedsaml.TransactionPins{
			Provider: oidc.Pins.Provider, BindingID: oidc.Pins.BindingID,
			ProviderRevision: oidc.Pins.ProviderRevision, BindingRevision: oidc.Pins.BindingRevision,
			ConfigurationRevision: oidc.Pins.ConfigurationRevision, SecurityRevision: oidc.Pins.SecurityRevision,
			MappingRevision: oidc.Pins.MappingRevision, AuthorizationRevision: oidc.Pins.AuthorizationRevision,
			AssurancePolicyRevision: oidc.Pins.AssurancePolicyRevision,
			MetadataRevision:        20, MetadataDigest: sha256.Sum256([]byte("metadata")),
			SPKeyRevision: 21, ConfigurationDigest: sha256.Sum256([]byte("configuration")),
		},
		ResponseID: "_response", AssertionID: "_assertion", ConsumedAt: oidc.CompletedAt,
		ReturnPath: oidc.ReturnPath, HasSessionIndex: true,
		SessionIndexDigest: sha256.Sum256([]byte("session-index")),
	}
	request.Session = postgresSessionReservation(t, request.AppliedAt, mfa.SessionAuthenticationSAML, 135)
	if disposition == federatedauth.ApplyContinuation {
		request.Disposition = disposition
		request.Assurance = identity.AssuranceStepUpRequired
		request.Session = mfa.SessionReservation{}
		request.Continuation = postgresContinuationReservation(t, request.AppliedAt, 137)
	}
	return request
}

func postgresSessionReservation(
	t *testing.T,
	issuedAt time.Time,
	method mfa.SessionAuthenticationMethod,
	seed byte,
) mfa.SessionReservation {
	t.Helper()
	tokenDigest := sha256.Sum256([]byte{seed, 1})
	csrfDigest := sha256.Sum256([]byte{seed, 2})
	reservation, err := mfa.NewSessionReservation(mfa.SessionMaterial{
		SessionID: postgresFederatedID(seed), FamilyID: postgresFederatedID(seed + 1),
		TokenDigest: tokenDigest, CSRFDigest: csrfDigest, AuthenticationMethod: method,
		IdleExpiresAt:     issuedAt.Add(time.Hour).Truncate(time.Millisecond),
		AbsoluteExpiresAt: issuedAt.Add(8 * time.Hour).Truncate(time.Millisecond),
	}, issuedAt.Truncate(time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	return reservation
}

func postgresContinuationReservation(
	t *testing.T,
	issuedAt time.Time,
	seed byte,
) federatedauth.PostPrimaryContinuationReservation {
	t.Helper()
	receipt := sha256.Sum256([]byte{seed})
	reservation, err := federatedauth.NewPostPrimaryContinuationReservation(
		federatedauth.PostPrimaryContinuationMaterial{
			ContinuationID: postgresFederatedID(seed), ReceiptDigest: receipt,
			ExpiresAt: issuedAt.Add(5 * time.Minute),
		},
		issuedAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	return reservation
}

func cloneFederatedApplyResultWire(t *testing.T, value federatedApplyResultWire) federatedApplyResultWire {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var result federatedApplyResultWire
	if err := json.Unmarshal(encoded, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestFederatedApplyWireContainsNoRawClaimFields(t *testing.T) {
	encoded, err := json.Marshal(postgresFederatedApplyFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"raw-subject-canary", "raw-group-canary", "issuer", "claims", "groups"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("domain apply JSON exposed %q", forbidden)
		}
	}
}
