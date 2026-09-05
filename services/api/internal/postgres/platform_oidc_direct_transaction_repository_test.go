package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/periapsis-im/periapsis/modules/identity/federatedoidc"
)

func TestPlatformOIDCDirectStableAuditEventIDIsDeterministicAndDomainSeparated(t *testing.T) {
	fixture := newPlatformOIDCDirectRuntimeTransactionFixture(t)
	first, err := platformOIDCDirectStableAuditEventID(
		fixture.audit, "transaction.create", fixture.create.Begin.OperationRunID[:], fixture.create.Current.ID[:],
	)
	if err != nil {
		t.Fatalf("first stable event ID: %v", err)
	}
	second, err := platformOIDCDirectStableAuditEventID(
		fixture.audit, "transaction.create", fixture.create.Begin.OperationRunID[:], fixture.create.Current.ID[:],
	)
	if err != nil || second != first {
		t.Fatalf("retry event ID = %s, %v; want %s", second, err, first)
	}
	requestID := uuid.UUID(fixture.audit.RequestID)
	correlationID := uuid.UUID(fixture.audit.CorrelationID)
	if !platformOIDCDirectUUIDv7(first) || first == requestID || first == correlationID ||
		!bytes.Equal(first[:6], requestID[:6]) {
		t.Fatalf("stable event ID = %s", first)
	}
	actionChanged, err := platformOIDCDirectStableAuditEventID(
		fixture.audit, "transaction.claim", fixture.create.Begin.OperationRunID[:], fixture.create.Current.ID[:],
	)
	if err != nil || actionChanged == first {
		t.Fatalf("action-separated event ID = %s, %v", actionChanged, err)
	}
	authority := append([]byte(nil), fixture.create.Current.ID[:]...)
	authority[0] ^= 0xff
	authorityChanged, err := platformOIDCDirectStableAuditEventID(
		fixture.audit, "transaction.create", fixture.create.Begin.OperationRunID[:], authority,
	)
	if err != nil || authorityChanged == first {
		t.Fatalf("authority-separated event ID = %s, %v", authorityChanged, err)
	}
	if _, err := platformOIDCDirectStableAuditEventID(fixture.audit, "transaction.create"); !errors.Is(err, errFederatedAuthPersistence) {
		t.Fatalf("missing authority error = %v", err)
	}
}

func TestFederatedAuthRepositoryCreatesDirectOIDCTransactionWithExactStableWire(t *testing.T) {
	fixture := newPlatformOIDCDirectRuntimeTransactionFixture(t)
	response, err := platformOIDCDirectPendingToWire(fixture.create.Current, federatedoidc.CodeChallengeS256)
	if err != nil {
		t.Fatalf("build response: %v", err)
	}
	zone := time.FixedZone("postgres-json", 2*60*60)
	response.CreatedAt = response.CreatedAt.In(zone)
	response.ExpiresAt = response.ExpiresAt.In(zone)
	var payloadCopies, retainedPayloads, retainedResponses [][]byte
	var eventIDs []string
	repository := &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(
		_ context.Context,
		query string,
		arguments ...any,
	) pgx.Row {
		if query != "select app.create_platform_oidc_authentication_transaction_v1($1::jsonb)" {
			t.Fatalf("query = %q", query)
		}
		payload := platformOIDCDirectRuntimePayload(t, arguments)
		retainedPayloads = append(retainedPayloads, payload)
		payloadCopies = append(payloadCopies, append([]byte(nil), payload...))
		object := assertPlatformOIDCDirectRuntimeJSONKeys(
			t, payload, "begin", "current", "browserCapabilityDigest", "audit",
		)
		assertPlatformOIDCDirectRuntimeJSONKeys(
			t, object["begin"], "operationRunId", "receiptDigest", "networkDigest", "accountDigest", "providerDigest",
		)
		current := assertPlatformOIDCDirectRuntimeJSONKeys(t, object["current"],
			"id", "stateDigest", "browserDigest", "nonceDigest", "codeChallengeMethod",
			"verifierKeyVersion", "verifierCiphertext", "pins", "clientId", "redirectUri",
			"postLogoutRedirectUri", "returnPath", "scopes", "allowRefreshToken", "useUserInfo",
			"state", "version", "createdAt", "expiresAt",
		)
		assertPlatformOIDCDirectRuntimePinsKeys(t, current["pins"])
		audit := assertPlatformOIDCDirectRuntimeJSONKeys(
			t, object["audit"], "eventId", "requestId", "correlationId", "ipAddress", "userAgent", "authenticationMethod",
		)
		var eventID string
		if err := jsonUnmarshalDirectRuntime(audit["eventId"], &eventID); err != nil {
			t.Fatalf("decode event ID: %v", err)
		}
		eventIDs = append(eventIDs, eventID)
		return platformOIDCDirectRuntimeJSONRow(t, response, &retainedResponses)
	}}}
	originalCiphertext := append([]byte(nil), fixture.create.Current.Verifier.Ciphertext...)
	originalScopes := append([]string(nil), fixture.create.Current.Scopes...)
	for range 2 {
		if err := repository.CreateDirectOIDCTransaction(context.Background(), fixture.create); err != nil {
			t.Fatalf("CreateDirectOIDCTransaction() error = %v", err)
		}
	}
	if len(payloadCopies) != 2 || !bytes.Equal(payloadCopies[0], payloadCopies[1]) ||
		len(eventIDs) != 2 || eventIDs[0] != eventIDs[1] {
		t.Fatalf("exact retry payload/event drifted: events=%v", eventIDs)
	}
	eventID := uuid.MustParse(eventIDs[0])
	if eventID == uuid.UUID(fixture.audit.RequestID) || eventID == uuid.UUID(fixture.audit.CorrelationID) {
		t.Fatalf("audit event reused request/correlation ID: %s", eventID)
	}
	assertPlatformOIDCDirectRuntimeCleared(t, append(retainedPayloads, retainedResponses...)...)
	if !bytes.Equal(fixture.create.Current.Verifier.Ciphertext, originalCiphertext) ||
		!slices.Equal(fixture.create.Current.Scopes, originalScopes) {
		t.Fatal("caller-owned transaction material was changed")
	}
}

func TestPlatformOIDCDirectTransactionRoundTripsOptionalRefreshCapability(t *testing.T) {
	fixture := newPlatformOIDCDirectRuntimeTransactionFixture(t)
	pending := fixture.create.Current
	pending.AllowRefreshToken = true
	pending.Scopes = append(append([]string(nil), pending.Scopes...), "offline_access")
	wire, err := platformOIDCDirectPendingToWire(pending, federatedoidc.CodeChallengeS256)
	if err != nil || !wire.AllowRefreshToken {
		t.Fatalf("platformOIDCDirectPendingToWire() allowRefresh=%t error=%v", wire.AllowRefreshToken, err)
	}
	restored, err := platformOIDCDirectTransactionFromWire(wire)
	if err != nil || !equalPlatformOIDCDirectPending(restored, pending) || !restored.AllowRefreshToken {
		t.Fatalf("platformOIDCDirectTransactionFromWire() refresh=%t error=%v", restored.AllowRefreshToken, err)
	}
	clear(restored.Verifier.Ciphertext)

	withoutScope := pending
	withoutScope.Scopes = slices.DeleteFunc(append([]string(nil), pending.Scopes...), func(scope string) bool {
		return scope == "offline_access"
	})
	if _, err := platformOIDCDirectPendingToWire(withoutScope, federatedoidc.CodeChallengeS256); err == nil {
		t.Fatal("allowRefreshToken without offline_access was accepted")
	}
	wire.AllowRefreshToken = false
	if _, err := platformOIDCDirectTransactionFromWire(wire); err == nil {
		t.Fatal("offline_access without allowRefreshToken was accepted")
	}
}

func TestFederatedAuthRepositoryClaimsDirectOIDCTransactionWithExactStableWire(t *testing.T) {
	fixture := newPlatformOIDCDirectRuntimeTransactionFixture(t)
	response, err := platformOIDCDirectPendingToWire(fixture.create.Current, federatedoidc.CodeChallengeS256)
	if err != nil {
		t.Fatalf("build response: %v", err)
	}
	claimedAt := fixture.claim.ClaimedAt.In(time.FixedZone("postgres-json", -5*60*60))
	response.AuthorizationCode = append([]byte(nil), fixture.claim.AuthorizationCodeDigest[:]...)
	response.ClaimAttemptID = append([]byte(nil), fixture.claim.AttemptID[:]...)
	response.ClaimedAt = &claimedAt
	response.State = string(federatedoidc.TransactionClaimed)
	response.Version = 2
	var payloadCopies, retainedPayloads, retainedResponses [][]byte
	var eventIDs []string
	repository := &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(
		_ context.Context,
		query string,
		arguments ...any,
	) pgx.Row {
		if query != "select app.claim_platform_oidc_authentication_transaction_v1($1::jsonb)" {
			t.Fatalf("query = %q", query)
		}
		payload := platformOIDCDirectRuntimePayload(t, arguments)
		retainedPayloads = append(retainedPayloads, payload)
		payloadCopies = append(payloadCopies, append([]byte(nil), payload...))
		object := assertPlatformOIDCDirectRuntimeJSONKeys(t, payload,
			"stateDigest", "browserDigest", "authorizationCodeDigest", "claimAttemptId",
			"claimedAt", "expectedVersion", "audit",
		)
		audit := assertPlatformOIDCDirectRuntimeJSONKeys(
			t, object["audit"], "eventId", "requestId", "correlationId", "ipAddress", "userAgent", "authenticationMethod",
		)
		var eventID string
		if err := jsonUnmarshalDirectRuntime(audit["eventId"], &eventID); err != nil {
			t.Fatalf("decode event ID: %v", err)
		}
		eventIDs = append(eventIDs, eventID)
		return platformOIDCDirectRuntimeJSONRow(t, response, &retainedResponses)
	}}}
	for range 2 {
		claimed, err := repository.ClaimDirectOIDCTransaction(context.Background(), fixture.claim)
		if err != nil {
			t.Fatalf("ClaimDirectOIDCTransaction() error = %v", err)
		}
		if claimed.ID != fixture.create.Current.ID || claimed.ClaimAttemptID != fixture.claim.AttemptID ||
			claimed.AuthorizationCodeDigest != fixture.claim.AuthorizationCodeDigest ||
			!claimed.ClaimedAt.Equal(fixture.claim.ClaimedAt) ||
			!bytes.Equal(claimed.Verifier.Ciphertext, fixture.create.Current.Verifier.Ciphertext) {
			t.Fatalf("claimed projection drifted: %s", claimed)
		}
		clear(claimed.Verifier.Ciphertext)
	}
	if !bytes.Equal(payloadCopies[0], payloadCopies[1]) || eventIDs[0] != eventIDs[1] {
		t.Fatalf("exact retry payload/event drifted: events=%v", eventIDs)
	}
	assertPlatformOIDCDirectRuntimeCleared(t, append(retainedPayloads, retainedResponses...)...)
}

func TestFederatedAuthRepositoryFailsDirectOIDCTransactionWithExactStableWire(t *testing.T) {
	fixture := newPlatformOIDCDirectRuntimeTransactionFixture(t)
	response, err := platformOIDCDirectPendingToWire(fixture.create.Current, federatedoidc.CodeChallengeS256)
	if err != nil {
		t.Fatalf("build response: %v", err)
	}
	claimedAt := fixture.claim.ClaimedAt.In(time.FixedZone("postgres-json", 3*60*60))
	completedAt := fixture.failure.FailedAt.In(time.FixedZone("postgres-json", 3*60*60))
	reason := string(fixture.failure.Reason)
	response.AuthorizationCode = append([]byte(nil), fixture.claim.AuthorizationCodeDigest[:]...)
	response.ClaimAttemptID = append([]byte(nil), fixture.claim.AttemptID[:]...)
	response.ClaimedAt = &claimedAt
	response.CompletedAt = &completedAt
	response.FailureReason = &reason
	response.State = string(fixture.failure.State)
	response.Version = 3
	var payloadCopies, retainedPayloads, retainedResponses [][]byte
	var eventIDs []string
	repository := &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(
		_ context.Context,
		query string,
		arguments ...any,
	) pgx.Row {
		if query != "select app.fail_platform_oidc_authentication_transaction_v1($1::jsonb)" {
			t.Fatalf("query = %q", query)
		}
		payload := platformOIDCDirectRuntimePayload(t, arguments)
		retainedPayloads = append(retainedPayloads, payload)
		payloadCopies = append(payloadCopies, append([]byte(nil), payload...))
		object := assertPlatformOIDCDirectRuntimeJSONKeys(t, payload,
			"transactionId", "expectedVersion", "state", "failureReason", "completedAt", "audit",
		)
		audit := assertPlatformOIDCDirectRuntimeJSONKeys(
			t, object["audit"], "eventId", "requestId", "correlationId", "ipAddress", "userAgent", "authenticationMethod",
		)
		var eventID string
		if err := jsonUnmarshalDirectRuntime(audit["eventId"], &eventID); err != nil {
			t.Fatalf("decode event ID: %v", err)
		}
		eventIDs = append(eventIDs, eventID)
		return platformOIDCDirectRuntimeJSONRow(t, response, &retainedResponses)
	}}}
	for range 2 {
		if err := repository.FailDirectOIDCTransaction(context.Background(), fixture.failure); err != nil {
			t.Fatalf("FailDirectOIDCTransaction() error = %v", err)
		}
	}
	if !bytes.Equal(payloadCopies[0], payloadCopies[1]) || eventIDs[0] != eventIDs[1] {
		t.Fatalf("exact retry payload/event drifted: events=%v", eventIDs)
	}
	assertPlatformOIDCDirectRuntimeCleared(t, append(retainedPayloads, retainedResponses...)...)
}

func TestFederatedAuthRepositoryRejectsDirectOIDCTransactionStaleAndMalformedEchoes(t *testing.T) {
	fixture := newPlatformOIDCDirectRuntimeTransactionFixture(t)
	pending, err := platformOIDCDirectPendingToWire(fixture.create.Current, federatedoidc.CodeChallengeS256)
	if err != nil {
		t.Fatalf("build response: %v", err)
	}
	claimedAt := fixture.claim.ClaimedAt
	completedAt := fixture.failure.FailedAt
	reason := string(fixture.failure.Reason)
	malformedFailure := pending
	malformedFailure.ClaimAttemptID = append([]byte(nil), fixture.claim.AttemptID[:]...)
	malformedFailure.ClaimedAt = &claimedAt
	malformedFailure.CompletedAt = &completedAt
	malformedFailure.FailureReason = &reason
	malformedFailure.State = string(fixture.failure.State)
	malformedFailure.Version = 3

	tests := map[string]struct {
		query    string
		response any
		invoke   func(*FederatedAuthRepository) error
	}{
		"create null": {
			query:    "select app.create_platform_oidc_authentication_transaction_v1($1::jsonb)",
			response: nil,
			invoke: func(repository *FederatedAuthRepository) error {
				return repository.CreateDirectOIDCTransaction(context.Background(), fixture.create)
			},
		},
		"claim pending": {
			query:    "select app.claim_platform_oidc_authentication_transaction_v1($1::jsonb)",
			response: pending,
			invoke: func(repository *FederatedAuthRepository) error {
				claimed, invokeErr := repository.ClaimDirectOIDCTransaction(context.Background(), fixture.claim)
				clear(claimed.Verifier.Ciphertext)
				return invokeErr
			},
		},
		"failure incomplete claim lifecycle": {
			query:    "select app.fail_platform_oidc_authentication_transaction_v1($1::jsonb)",
			response: malformedFailure,
			invoke: func(repository *FederatedAuthRepository) error {
				return repository.FailDirectOIDCTransaction(context.Background(), fixture.failure)
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			called := false
			repository := &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(
				_ context.Context,
				query string,
				_ ...any,
			) pgx.Row {
				called = true
				if query != test.query {
					t.Fatalf("query = %q", query)
				}
				return platformOIDCDirectRuntimeJSONRow(t, test.response, nil)
			}}}
			if err := test.invoke(repository); !errors.Is(err, errFederatedAuthPersistence) || !called {
				t.Fatalf("invoke error = %v, called=%t", err, called)
			}
		})
	}
}

func TestPlatformOIDCDirectTransactionScopesMatchKernelVocabulary(t *testing.T) {
	if !validPlatformOIDCDirectScopes([]string{"openid", "email", "profile"}) {
		t.Fatal("valid scopes rejected")
	}
	tooMany := make([]string, maximumPlatformOIDCDirectScopes+1)
	for index := range tooMany {
		tooMany[index] = "scope" + string(rune('A'+index))
	}
	tooMany[0] = "openid"
	for name, scopes := range map[string][]string{
		"too many":        tooMany,
		"unicode":         {"openid", "profilé"},
		"quoted":          {"openid", "bad\"scope"},
		"backslash":       {"openid", "bad\\scope"},
		"space":           {"openid", "bad scope"},
		"duplicate":       {"openid", "openid"},
		"wrong mandatory": {"profile"},
	} {
		t.Run(name, func(t *testing.T) {
			if validPlatformOIDCDirectScopes(scopes) {
				t.Fatalf("accepted scopes %q", scopes)
			}
		})
	}
}

func jsonUnmarshalDirectRuntime(value []byte, destination any) error {
	return json.Unmarshal(value, destination)
}
