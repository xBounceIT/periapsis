package postgres

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
	"github.com/periapsis-im/periapsis/services/api/internal/sessionlogout"
)

var sessionLogoutRepositoryNow = time.Date(2026, time.September, 4, 8, 30, 0, 0, time.UTC)

const sessionLogoutExpectedActorContextSQL = `select
  set_config('app.tenant_id', coalesce($1::uuid::text, ''), true),
  set_config('app.user_id', $2::uuid::text, true)`

func TestSessionLogoutRepositoryUsesExactGenericResolveAndRevokeABI(t *testing.T) {
	operationID := sessionLogoutRepositoryID(t)
	sessionID := sessionLogoutRepositoryID(t)
	userID := sessionLogoutRepositoryID(t)
	continuationID := sessionLogoutRepositoryID(t)
	requestID := sessionLogoutRepositoryID(t)
	correlationID := sessionLogoutRepositoryID(t)
	tokenDigest := sha256.Sum256([]byte("session-token"))
	csrfDigest := sha256.Sum256([]byte("csrf-token"))
	requestDigest := sha256.Sum256([]byte("semantic-request"))
	continuationDigest := sha256.Sum256([]byte("continuation-proof"))
	databaseNow := sessionLogoutRepositoryNow.Add(750 * time.Millisecond)
	requestedExpiresAt := sessionLogoutRepositoryNow.Add(time.Minute)
	expiresAt := databaseNow.Add(time.Minute)
	command := sessionlogout.LocalRevokeCommand{
		OperationRunID: operationID,
		Credential: sessionlogout.Credential{
			SessionID: sessionID, UserID: userID, TokenDigest: tokenDigest, CSRFDigest: csrfDigest,
		},
		RequestUpstream: true, RequestDigest: requestDigest,
		ContinuationID: continuationID, ContinuationDigest: continuationDigest,
		ContinuationExpiresAt: requestedExpiresAt, RequestedAt: sessionLogoutRepositoryNow,
		Audit: sessionlogout.EventContext{
			RequestID: requestID, CorrelationID: correlationID,
			RemoteAddress: netip.MustParseAddr("203.0.113.44"), UserAgent: "logout-repository-test/1",
		},
	}
	queries := make([]string, 0, 3)
	queryRow := func(
		_ context.Context,
		query string,
		arguments ...any,
	) pgx.Row {
		queries = append(queries, query)
		switch query {
		case sessionLogoutExpectedActorContextSQL:
			if len(arguments) != 2 || arguments[0].(*string) != nil || arguments[1] != entityIDWire(userID) {
				t.Fatalf("actor context does not match the verified platform credential")
			}
			return samlLogoutRowFunc(func(destinations ...any) error {
				*destinations[0].(*string) = ""
				*destinations[1].(*string) = entityIDWire(userID)
				return nil
			})
		case resolveSessionForLogoutSQL:
			if len(arguments) != 1 || !bytes.Equal(arguments[0].([]byte), tokenDigest[:]) {
				t.Fatalf("resolve arguments = %#v", arguments)
			}
			return federatedAuthJSONRow(mustFederatedJSON(t, sessionLogoutCredentialWire{
				SessionID: entityIDWire(sessionID), UserID: entityIDWire(userID),
				TokenDigest: tokenDigest[:], CSRFDigest: csrfDigest[:],
			}))
		case revokeLocalSessionForLogoutSQL:
			payload := sessionLogoutRepositoryPayload(t, arguments)
			assertSessionLogoutJSONKeys(t, payload,
				"operationRunId", "sessionId", "userId", "tenantId", "tokenDigest", "requestDigest",
				"requestUpstream", "requestedAt", "continuationId", "continuationDigest",
				"continuationExpiresAt", "audit",
			)
			var decoded map[string]json.RawMessage
			if err := json.Unmarshal(payload, &decoded); err != nil {
				t.Fatal(err)
			}
			assertSessionLogoutJSONKeys(t, decoded["audit"],
				"requestId", "correlationId", "remoteAddress", "userAgent",
			)
			if bytes.Contains(payload, []byte("csrfDigest")) || bytes.Contains(payload, []byte("id_token")) {
				t.Fatalf("revoke wire contains forbidden material: %s", payload)
			}
			return federatedAuthJSONRow(mustFederatedJSON(t, sessionLogoutRevokeSnapshotWire{
				Category: string(sessionlogout.LogoutContinuation), OperationRunID: entityIDWire(operationID),
				SessionID: entityIDWire(sessionID), UserID: entityIDWire(userID), PreviousVersion: 5,
				RequestedAt: sessionLogoutRepositoryNow, ObservedAt: databaseNow,
				ContinuationID:        sessionLogoutStringPointer(entityIDWire(continuationID)),
				ContinuationExpiresAt: &expiresAt, RevokedAt: databaseNow,
			}))
		default:
			t.Fatalf("unexpected query %q", query)
			return federatedAuthJSONRow(nil)
		}
	}
	tx := &samlLogoutTransactionStub{query: queryRow}
	repository := &FederatedAuthRepository{
		queryer: federatedAuthQueryerStub{query: func(ctx context.Context, query string, arguments ...any) pgx.Row {
			if query != resolveSessionForLogoutSQL {
				t.Fatal("logout mutation escaped its transaction")
			}
			return queryRow(ctx, query, arguments...)
		}},
		begin: func(_ context.Context, options pgx.TxOptions) (databaseTransaction, error) {
			if options != (pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadWrite}) {
				t.Fatalf("transaction options = %#v", options)
			}
			return tx, nil
		},
	}
	credential, err := repository.ResolveSessionForLogout(context.Background(), tokenDigest)
	if err != nil || credential.SessionID != sessionID || credential.UserID != userID ||
		credential.TenantID != (identity.EntityID{}) || credential.CSRFDigest != csrfDigest {
		t.Fatalf("ResolveSessionForLogout() = %s, %v", credential, err)
	}
	snapshot, err := repository.RevokeLocalSession(context.Background(), command)
	if err != nil || snapshot.Category != sessionlogout.LogoutContinuation ||
		snapshot.OperationRunID != operationID || snapshot.SessionID != sessionID || snapshot.UserID != userID ||
		!snapshot.RequestedAt.Equal(command.RequestedAt) || !snapshot.ObservedAt.Equal(databaseNow) ||
		snapshot.ContinuationID != continuationID || !snapshot.ContinuationExpiresAt.Equal(expiresAt) {
		t.Fatalf("RevokeLocalSession() = %s, %v", snapshot, err)
	}
	if !reflect.DeepEqual(queries, []string{resolveSessionForLogoutSQL, sessionLogoutExpectedActorContextSQL, revokeLocalSessionForLogoutSQL}) {
		t.Fatalf("queries = %#v", queries)
	}
	if !tx.committed || !tx.rolledBack {
		t.Fatal("logout transaction did not commit and release its connection")
	}
}

func TestSessionLogoutRepositoryRevokeTransactionFailuresAreClosed(t *testing.T) {
	for _, test := range []struct {
		name             string
		stage            string
		tenant           bool
		wantBegin        bool
		wantMutation     bool
		wantCommit       bool
		wantRollback     bool
		wantSuccess      bool
		wantInvalidInput bool
	}{
		{name: "platform clears tenant context", wantBegin: true, wantMutation: true, wantCommit: true, wantRollback: true, wantSuccess: true},
		{name: "tenant installs exact context", tenant: true, wantBegin: true, wantMutation: true, wantCommit: true, wantRollback: true, wantSuccess: true},
		{name: "invalid credential before begin", stage: "invalid", wantInvalidInput: true},
		{name: "cancelled before begin", stage: "cancelled"},
		{name: "begin failure", stage: "begin", wantBegin: true},
		{name: "context failure", stage: "context", wantBegin: true, wantRollback: true},
		{name: "wrong tenant echo", stage: "tenant echo", wantBegin: true, wantRollback: true},
		{name: "wrong actor echo", stage: "actor echo", tenant: true, wantBegin: true, wantRollback: true},
		{name: "cancelled after context", stage: "context cancellation", wantBegin: true, wantRollback: true},
		{name: "mutation failure", stage: "query", wantBegin: true, wantMutation: true, wantRollback: true},
		{name: "null mutation", stage: "null", wantBegin: true, wantMutation: true, wantRollback: true},
		{name: "invalid JSON", stage: "json", wantBegin: true, wantMutation: true, wantRollback: true},
		{name: "mismatched snapshot", stage: "snapshot", wantBegin: true, wantMutation: true, wantRollback: true},
		{name: "cancelled after mutation", stage: "query cancellation", wantBegin: true, wantMutation: true, wantRollback: true},
		{name: "commit failure", stage: "commit", wantBegin: true, wantMutation: true, wantCommit: true, wantRollback: true},
		{name: "commit cancellation", stage: "commit cancellation", wantBegin: true, wantMutation: true, wantCommit: true, wantRollback: true},
		{name: "cleanup failure", stage: "rollback", wantBegin: true, wantMutation: true, wantCommit: true, wantRollback: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			command := sessionLogoutTransactionCommand(t)
			if test.tenant {
				command.Credential.TenantID = sessionLogoutRepositoryID(t)
			}
			if test.stage == "invalid" {
				command.Credential.UserID = identity.EntityID{}
			}
			if test.stage == "cancelled" {
				cancel()
			}
			expectedTenant := ""
			if test.tenant {
				expectedTenant = entityIDWire(command.Credential.TenantID)
			}
			begun, mutationCalled, contextInstalled := false, false, false
			tx := &sessionLogoutFailureTransaction{}
			tx.query = func(queryContext context.Context, query string, arguments ...any) pgx.Row {
				if queryContext != ctx || queryContext.Err() != nil {
					t.Fatal("database query lost its live request context")
				}
				if query == sessionLogoutExpectedActorContextSQL {
					if contextInstalled || len(arguments) != 2 || arguments[1] != entityIDWire(command.Credential.UserID) {
						t.Fatal("unexpected actor context arguments")
					}
					tenant, ok := arguments[0].(*string)
					if !ok || test.tenant && (tenant == nil || *tenant != expectedTenant) || !test.tenant && tenant != nil {
						t.Fatal("tenant context does not match the verified credential")
					}
					contextInstalled = true
					return samlLogoutRowFunc(func(destinations ...any) error {
						if test.stage == "context" {
							return errors.New("private context database failure")
						}
						*destinations[0].(*string) = expectedTenant
						*destinations[1].(*string) = entityIDWire(command.Credential.UserID)
						if test.stage == "tenant echo" {
							*destinations[0].(*string) = entityIDWire(sessionLogoutRepositoryID(t))
						}
						if test.stage == "actor echo" {
							*destinations[1].(*string) = entityIDWire(sessionLogoutRepositoryID(t))
						}
						if test.stage == "context cancellation" {
							cancel()
						}
						return nil
					})
				}
				if query != revokeLocalSessionForLogoutSQL || !contextInstalled || mutationCalled {
					t.Fatal("mutation did not follow the single actor-context installation")
				}
				mutationCalled = true
				return samlLogoutRowFunc(func(destinations ...any) error {
					if test.stage == "query" {
						return errors.New("private mutation database failure")
					}
					response := sessionLogoutRevokeSnapshotWire{
						Category: string(sessionlogout.LocalOnly), OperationRunID: entityIDWire(command.OperationRunID),
						SessionID: entityIDWire(command.Credential.SessionID), UserID: entityIDWire(command.Credential.UserID),
						PreviousVersion: 1, RequestedAt: command.RequestedAt, ObservedAt: command.RequestedAt, RevokedAt: command.RequestedAt,
					}
					if test.tenant {
						response.TenantID = &expectedTenant
					}
					if test.stage == "snapshot" {
						response.UserID = entityIDWire(sessionLogoutRepositoryID(t))
					}
					raw := mustFederatedJSON(t, response)
					if test.stage == "null" {
						raw = []byte("null")
					}
					if test.stage == "json" {
						raw = []byte("{")
					}
					*destinations[0].(*[]byte) = raw
					if test.stage == "query cancellation" {
						cancel()
					}
					return nil
				})
			}
			tx.commit = func(commitContext context.Context) error {
				if commitContext != ctx || commitContext.Err() != nil {
					t.Fatal("commit did not retain the live request context")
				}
				if test.stage == "commit" {
					return errors.New("private commit failure")
				}
				if test.stage == "commit cancellation" {
					cancel()
					return context.Canceled
				}
				return nil
			}
			tx.rollback = func(rollbackContext context.Context) error {
				deadline, bounded := rollbackContext.Deadline()
				if rollbackContext.Err() != nil || !bounded || time.Until(deadline) > 5*time.Second {
					t.Fatal("cleanup did not receive a bounded, uncancelled context")
				}
				if test.stage == "rollback" {
					return errors.New("private rollback failure")
				}
				if tx.committed && test.wantSuccess {
					return pgx.ErrTxClosed
				}
				return nil
			}
			repository := &FederatedAuthRepository{begin: func(beginContext context.Context, options pgx.TxOptions) (databaseTransaction, error) {
				if beginContext != ctx || options != (pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadWrite}) {
					t.Fatal("unexpected transaction context or options")
				}
				begun = true
				if test.stage == "begin" {
					return nil, errors.New("private begin failure")
				}
				return tx, nil
			}}
			snapshot, err := repository.RevokeLocalSession(ctx, command)
			if test.wantSuccess {
				if err != nil || snapshot.Category != sessionlogout.LocalOnly || snapshot.SessionID != command.Credential.SessionID {
					t.Fatalf("RevokeLocalSession() did not commit the validated snapshot: %v", err)
				}
			} else {
				wantError := sessionlogout.ErrUnavailable
				if test.wantInvalidInput {
					wantError = sessionlogout.ErrInvalidInput
				}
				if err != wantError || snapshot != (sessionlogout.LocalRevokeSnapshot{}) {
					t.Fatalf("failure leaked a snapshot or a database error: %v", err)
				}
			}
			if begun != test.wantBegin || mutationCalled != test.wantMutation || tx.committed != test.wantCommit || tx.rolledBack != test.wantRollback {
				t.Fatalf("lifecycle begin/mutate/commit/rollback = %t/%t/%t/%t", begun, mutationCalled, tx.committed, tx.rolledBack)
			}
		})
	}
}

type sessionLogoutFailureTransaction struct {
	samlLogoutTransactionStub
	commit   func(context.Context) error
	rollback func(context.Context) error
}

func (tx *sessionLogoutFailureTransaction) Commit(ctx context.Context) error {
	tx.committed = true
	return tx.commit(ctx)
}

func (tx *sessionLogoutFailureTransaction) Rollback(ctx context.Context) error {
	tx.rolledBack = true
	return tx.rollback(ctx)
}

func sessionLogoutTransactionCommand(t *testing.T) sessionlogout.LocalRevokeCommand {
	t.Helper()
	return sessionlogout.LocalRevokeCommand{
		OperationRunID: sessionLogoutRepositoryID(t),
		Credential: sessionlogout.Credential{
			SessionID: sessionLogoutRepositoryID(t), UserID: sessionLogoutRepositoryID(t),
			TokenDigest: sha256.Sum256([]byte("transaction-session-token")), CSRFDigest: sha256.Sum256([]byte("transaction-csrf-token")),
		},
		RequestUpstream: true, RequestDigest: sha256.Sum256([]byte("transaction-request")),
		ContinuationID: sessionLogoutRepositoryID(t), ContinuationDigest: sha256.Sum256([]byte("transaction-continuation")),
		ContinuationExpiresAt: sessionLogoutRepositoryNow.Add(time.Minute), RequestedAt: sessionLogoutRepositoryNow,
		Audit: sessionlogout.EventContext{
			RequestID: sessionLogoutRepositoryID(t), CorrelationID: sessionLogoutRepositoryID(t),
			RemoteAddress: netip.MustParseAddr("203.0.113.44"), UserAgent: "logout-transaction-test/1",
		},
	}
}

func TestSessionLogoutRepositoryClaimsDirectPlatformOIDCWithExactOneUseABI(t *testing.T) {
	continuationID := sessionLogoutRepositoryID(t)
	operationID := sessionLogoutRepositoryID(t)
	sessionID := sessionLogoutRepositoryID(t)
	userID := sessionLogoutRepositoryID(t)
	providerID := sessionLogoutRepositoryID(t)
	materialID := sessionLogoutRepositoryID(t)
	retryID := sessionLogoutRepositoryID(t)
	claim := sessionlogout.ContinuationClaim{
		ContinuationID:     continuationID,
		ContinuationDigest: sha256.Sum256([]byte("browser-cookie-proof")),
		ClaimedAt:          sessionLogoutRepositoryNow,
	}
	expiresAt := claim.ClaimedAt.Add(time.Minute)
	materialExpiresAt := claim.ClaimedAt.Add(time.Hour)
	idTokenDigest := sha256.Sum256([]byte("header.payload.signature"))
	protected := bytes.Repeat([]byte{0x51}, minimumOIDCProtectedTokenBytes)
	response := sessionLogoutClaimSnapshotWire{
		Category: string(sessionlogout.ClaimOIDC), RequestedClaimedAt: claim.ClaimedAt,
		ObservedAt: claim.ClaimedAt, ContinuationID: entityIDWire(continuationID),
		OperationRunID: entityIDWire(operationID), SessionID: entityIDWire(sessionID), UserID: entityIDWire(userID),
		PreviousVersion: 8,
		Provider:        &federatedProviderBindingWire{Scope: federatedPlatformProviderScopeWire, ProviderID: entityIDWire(providerID)},
		MaterialID:      entityIDWire(materialID), RevokedAt: sessionLogoutRepositoryNow, ExpiresAt: expiresAt,
		EndSessionEndpoint:    sessionLogoutStringPointer("https://idp.example.test/end-session"),
		PostLogoutRedirectURI: sessionLogoutStringPointer("https://historical-app.example.test/signed-out"),
		ProtectedIDToken:      &sessionLogoutProtectedTokenWire{KeyVersion: 2, Ciphertext: protected},
		IDTokenDigest:         idTokenDigest[:], MaterialExpiresAt: &materialExpiresAt,
		LogoutRetryJobID: sessionLogoutStringPointer(entityIDWire(retryID)),
	}
	repository := &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(
		_ context.Context,
		query string,
		arguments ...any,
	) pgx.Row {
		if query != claimLogoutContinuationSQL {
			t.Fatalf("query = %q", query)
		}
		payload := sessionLogoutRepositoryPayload(t, arguments)
		assertSessionLogoutJSONKeys(t, payload, "continuationId", "tokenDigest", "claimedAt")
		return federatedAuthJSONRow(mustFederatedJSON(t, response))
	}}}
	snapshot, err := repository.ClaimLogoutContinuation(context.Background(), claim)
	if err != nil || snapshot.Category != sessionlogout.ClaimOIDC || snapshot.ContinuationID != continuationID ||
		snapshot.OperationRunID != operationID || snapshot.SessionID != sessionID || snapshot.UserID != userID ||
		snapshot.TenantID != (identity.EntityID{}) || snapshot.Provider.Scope != identity.PlatformProviderScope ||
		snapshot.Provider.ProviderID != providerID || snapshot.Admission != (identity.TenantAdmissionContext{}) ||
		snapshot.MaterialID != materialID || !snapshot.ExpiresAt.Equal(expiresAt) ||
		snapshot.PostLogoutRedirectURI != "https://historical-app.example.test/signed-out" ||
		!bytes.Equal(snapshot.ProtectedIDToken.Ciphertext, protected) || snapshot.IDTokenDigest != idTokenDigest {
		t.Fatalf("ClaimLogoutContinuation() = %s, %v", snapshot, err)
	}
	clear(snapshot.ProtectedIDToken.Ciphertext)
	for name, redirect := range map[string]*string{
		"missing":    nil,
		"wrong path": sessionLogoutStringPointer("https://historical-app.example.test/logout"),
		"query":      sessionLogoutStringPointer("https://historical-app.example.test/signed-out?next=/"),
	} {
		t.Run("post logout redirect "+name, func(t *testing.T) {
			candidate := response
			candidate.PostLogoutRedirectURI = redirect
			if _, decodeErr := sessionLogoutClaimSnapshotFromWire(candidate, claim); !errors.Is(decodeErr, errFederatedAuthPersistence) {
				t.Fatalf("invalid historical post-logout redirect accepted: %v", decodeErr)
			}
		})
	}
}

func TestSessionLogoutRepositoryKeepsDirectOIDCMaterialContextAfterTenantSwitch(t *testing.T) {
	tenantID := sessionLogoutRepositoryID(t)
	continuationID := sessionLogoutRepositoryID(t)
	providerID := sessionLogoutRepositoryID(t)
	claim := sessionlogout.ContinuationClaim{
		ContinuationID:     continuationID,
		ContinuationDigest: sha256.Sum256([]byte("switched-browser-cookie-proof")),
		ClaimedAt:          sessionLogoutRepositoryNow,
	}
	expiresAt := claim.ClaimedAt.Add(time.Minute)
	materialExpiresAt := claim.ClaimedAt.Add(time.Hour)
	idTokenDigest := sha256.Sum256([]byte("switched.header.payload.signature"))
	response := sessionLogoutClaimSnapshotWire{
		Category: string(sessionlogout.ClaimOIDC), RequestedClaimedAt: claim.ClaimedAt,
		ObservedAt: claim.ClaimedAt, ContinuationID: entityIDWire(continuationID),
		OperationRunID: entityIDWire(sessionLogoutRepositoryID(t)),
		SessionID:      entityIDWire(sessionLogoutRepositoryID(t)),
		UserID:         entityIDWire(sessionLogoutRepositoryID(t)),
		TenantID:       sessionLogoutStringPointer(entityIDWire(tenantID)), PreviousVersion: 9,
		Provider: &federatedProviderBindingWire{
			Scope: federatedPlatformProviderScopeWire, ProviderID: entityIDWire(providerID),
		},
		MaterialID: entityIDWire(sessionLogoutRepositoryID(t)), RevokedAt: sessionLogoutRepositoryNow,
		ExpiresAt: expiresAt, EndSessionEndpoint: sessionLogoutStringPointer("https://idp.example.test/end-session"),
		PostLogoutRedirectURI: sessionLogoutStringPointer("https://historical-app.example.test/signed-out"),
		ProtectedIDToken: &sessionLogoutProtectedTokenWire{
			KeyVersion: 3, Ciphertext: bytes.Repeat([]byte{0x62}, minimumOIDCProtectedTokenBytes),
		},
		IDTokenDigest: idTokenDigest[:], MaterialExpiresAt: &materialExpiresAt,
	}
	snapshot, err := sessionLogoutClaimRepository(t, response).ClaimLogoutContinuation(context.Background(), claim)
	if err != nil || snapshot.TenantID != tenantID || snapshot.Provider.Scope != identity.PlatformProviderScope ||
		snapshot.Provider.ProviderID != providerID || snapshot.Admission != (identity.TenantAdmissionContext{}) {
		t.Fatalf("switched direct material ClaimLogoutContinuation() = %s, %v", snapshot, err)
	}
	clear(snapshot.ProtectedIDToken.Ciphertext)
}

func TestSessionLogoutRepositoryTreatsNullAndUnknownClaimResultsFailClosed(t *testing.T) {
	claim := sessionlogout.ContinuationClaim{
		ContinuationID:     sessionLogoutRepositoryID(t),
		ContinuationDigest: sha256.Sum256([]byte("browser-cookie-proof")),
		ClaimedAt:          sessionLogoutRepositoryNow,
	}
	for name, response := range map[string][]byte{
		"consumed or absent": []byte("null"),
		"unknown field":      []byte(`{"category":"oidc_end_session","unexpected":"secret"}`),
	} {
		t.Run(name, func(t *testing.T) {
			repository := &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(
				context.Context, string, ...any,
			) pgx.Row {
				return federatedAuthJSONRow(append([]byte(nil), response...))
			}}}
			_, err := repository.ClaimLogoutContinuation(context.Background(), claim)
			if name == "consumed or absent" {
				if !errors.Is(err, sessionlogout.ErrNotFound) {
					t.Fatalf("error = %v, want not found", err)
				}
			} else if !errors.Is(err, sessionlogout.ErrUnavailable) {
				t.Fatalf("error = %v, want unavailable", err)
			}
		})
	}
}

func TestSessionLogoutRepositoryClaimsTenantSAMLFromHistoricalConfiguration(t *testing.T) {
	tenantID := sessionLogoutRepositoryID(t)
	providerID := sessionLogoutRepositoryID(t)
	bindingID := sessionLogoutRepositoryID(t)
	claim, response := sessionLogoutSAMLClaimBase(t, tenantID, providerID)
	response.Provider = &federatedProviderBindingWire{
		Scope: federatedTenantProviderScopeWire, TenantID: entityIDWire(tenantID),
		ProviderID: entityIDWire(providerID), BindingID: entityIDWire(bindingID),
	}
	response.BindingID = sessionLogoutStringPointer(entityIDWire(bindingID))
	response.Configuration = mustFederatedJSON(t, sessionLogoutTenantSAMLConfigurationWire(
		t, tenantID, providerID, bindingID,
	))
	repository := sessionLogoutClaimRepository(t, response)
	snapshot, err := repository.ClaimLogoutContinuation(context.Background(), claim)
	if err != nil || snapshot.Category != sessionlogout.ClaimSAML || snapshot.TenantID != tenantID ||
		snapshot.Provider.Scope != identity.TenantProviderScope || snapshot.Provider.ProviderID != providerID ||
		snapshot.BindingID != bindingID || snapshot.SAMLConfiguration.Authority != federatedsaml.TenantCeremonyAuthority ||
		snapshot.SAMLConfiguration.Provider != snapshot.Provider ||
		snapshot.SAMLConfiguration.MaterialBindingID != bindingID ||
		snapshot.SAMLConfiguration.SLORedirectURL != "https://idp.example.test/slo" ||
		!snapshot.ExpiresAt.Equal(response.ExpiresAt) {
		t.Fatalf("ClaimLogoutContinuation() = %s, %v", snapshot, err)
	}
	clear(snapshot.ProtectedSAML.Ciphertext)
}

func TestSessionLogoutRepositoryClaimsDirectAndTenantAdmittedPlatformSAML(t *testing.T) {
	providerID := sessionLogoutRepositoryID(t)
	configuration := mustFederatedJSON(t, sessionLogoutPlatformSAMLConfigurationWire(t, providerID))
	for _, admitted := range []bool{false, true} {
		name := "direct"
		var tenantID identity.EntityID
		if admitted {
			name = "tenant admitted"
			tenantID = sessionLogoutRepositoryID(t)
		}
		t.Run(name, func(t *testing.T) {
			claim, response := sessionLogoutSAMLClaimBase(t, tenantID, providerID)
			response.Provider = &federatedProviderBindingWire{
				Scope: federatedPlatformProviderScopeWire, ProviderID: entityIDWire(providerID),
			}
			response.Configuration = append([]byte(nil), configuration...)
			if admitted {
				response.Admission = &federatedTenantAdmissionWire{
					TenantID: entityIDWire(tenantID), BindingID: entityIDWire(sessionLogoutRepositoryID(t)),
				}
			}
			repository := sessionLogoutClaimRepository(t, response)
			snapshot, err := repository.ClaimLogoutContinuation(context.Background(), claim)
			if err != nil || snapshot.Provider.Scope != identity.PlatformProviderScope ||
				snapshot.Provider.ProviderID != providerID || snapshot.BindingID != (identity.EntityID{}) ||
				snapshot.SAMLConfiguration.Authority != federatedsaml.DirectPlatformCeremonyAuthority ||
				snapshot.SAMLConfiguration.MaterialBindingID != (identity.EntityID{}) ||
				snapshot.SAMLConfiguration.PlatformLoginRevision != 3 ||
				snapshot.SAMLConfiguration.SLORedirectURL != "https://idp.example.test/slo" ||
				(admitted && snapshot.Admission.TenantID != tenantID) ||
				(!admitted && snapshot.Admission != (identity.TenantAdmissionContext{})) {
				t.Fatalf("ClaimLogoutContinuation() = %s, %v", snapshot, err)
			}
			clear(snapshot.ProtectedSAML.Ciphertext)
		})
	}
}

func sessionLogoutSAMLClaimBase(
	t *testing.T,
	tenantID identity.EntityID,
	providerID identity.EntityID,
) (sessionlogout.ContinuationClaim, sessionLogoutClaimSnapshotWire) {
	t.Helper()
	continuationID := sessionLogoutRepositoryID(t)
	claim := sessionlogout.ContinuationClaim{
		ContinuationID: continuationID, ContinuationDigest: sha256.Sum256([]byte("saml-browser-proof")),
		ClaimedAt: sessionLogoutRepositoryNow,
	}
	var tenantWire *string
	if tenantID != (identity.EntityID{}) {
		tenantWire = sessionLogoutStringPointer(entityIDWire(tenantID))
	}
	return claim, sessionLogoutClaimSnapshotWire{
		Category: string(sessionlogout.ClaimSAML), RequestedClaimedAt: claim.ClaimedAt,
		ObservedAt: claim.ClaimedAt, ContinuationID: entityIDWire(continuationID),
		OperationRunID: entityIDWire(sessionLogoutRepositoryID(t)), SessionID: entityIDWire(sessionLogoutRepositoryID(t)),
		UserID: entityIDWire(sessionLogoutRepositoryID(t)), TenantID: tenantWire, PreviousVersion: 6,
		Provider:   &federatedProviderBindingWire{Scope: federatedPlatformProviderScopeWire, ProviderID: entityIDWire(providerID)},
		MaterialID: entityIDWire(sessionLogoutRepositoryID(t)), RevokedAt: sessionLogoutRepositoryNow,
		ExpiresAt: sessionLogoutRepositoryNow.Add(time.Minute),
		ProtectedMaterial: &sessionLogoutProtectedSAMLWire{
			KeyVersion: 2, Ciphertext: bytes.Repeat([]byte{0x61}, minimumSAMLProtectedTokenBytes),
		},
	}
}

func sessionLogoutClaimRepository(
	t *testing.T,
	response sessionLogoutClaimSnapshotWire,
) *FederatedAuthRepository {
	t.Helper()
	return &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(
		_ context.Context,
		query string,
		arguments ...any,
	) pgx.Row {
		if query != claimLogoutContinuationSQL {
			t.Fatalf("query = %q", query)
		}
		payload := sessionLogoutRepositoryPayload(t, arguments)
		assertSessionLogoutJSONKeys(t, payload, "continuationId", "tokenDigest", "claimedAt")
		return federatedAuthJSONRow(mustFederatedJSON(t, response))
	}}}
}

func sessionLogoutTenantSAMLConfigurationWire(
	t *testing.T,
	tenantID identity.EntityID,
	providerID identity.EntityID,
	bindingID identity.EntityID,
) tenantSAMLConfigurationRecordWire {
	t.Helper()
	retrievedAt := time.Date(2026, time.August, 1, 0, 0, 0, 0, time.UTC)
	document := sessionLogoutSAMLMetadataDocument(t, retrievedAt, retrievedAt.Add(24*time.Hour))
	digest := sha256.Sum256(document)
	return tenantSAMLConfigurationRecordWire{
		Authentication: samlAuthenticationConfigurationWire{
			Provider: federatedProviderBindingWire{
				Scope: federatedTenantProviderScopeWire, TenantID: entityIDWire(tenantID),
				ProviderID: entityIDWire(providerID), BindingID: entityIDWire(bindingID),
			},
			ProviderRevision: 1, BindingRevision: 1, ConfigurationRevision: 1, SecurityRevision: 1,
			MappingRevision: 1, AuthorizationRevision: 1, AssurancePolicyRevision: 1,
			SPEntityID: "https://sp.example.test/saml/metadata", ACSURL: "https://sp.example.test/api/v1/auth/federated/saml/acs",
			SPKeyRevision: 7, RedirectSignatureAlgorithm: federatedsaml.RedirectRSASHA256,
		},
		ExpectedEntityID: "https://idp.example.test/entity", MetadataRevision: 4,
		MetadataDocument: document, MetadataDigest: digest[:], MetadataRetrievedAt: retrievedAt,
		MetadataMaximumValidUntil: retrievedAt.Add(48 * time.Hour),
	}
}

func sessionLogoutPlatformSAMLConfigurationWire(
	t *testing.T,
	providerID identity.EntityID,
) directPlatformSAMLConfigurationWire {
	t.Helper()
	retrievedAt := time.Date(2026, time.August, 1, 0, 0, 0, 0, time.UTC)
	observedAt := retrievedAt.Add(time.Hour)
	document := sessionLogoutSAMLMetadataDocument(t, retrievedAt, retrievedAt.Add(24*time.Hour))
	metadataDigest := sha256.Sum256(document)
	provider := platformSAMLProviderWire{Scope: federatedPlatformProviderScopeWire, ProviderID: entityIDWire(providerID)}
	return directPlatformSAMLConfigurationWire{
		ProviderKey: "historical-platform", ObservedAt: observedAt,
		Pins: platformSAMLProtocolPinsWire{
			Provider: provider, ProviderRevision: 2, PlatformLoginRevision: 3,
			ConfigurationRevision: 4, SecurityRevision: 5, PlanRevision: 6,
			AssurancePolicyRevision: 7, MetadataRevision: 8, MetadataDigest: metadataDigest[:],
			SPKeyRevision: 9,
		},
		Authentication: platformSAMLAuthenticationWire{
			Provider: provider, ProviderRevision: 2, PlatformLoginRevision: 3,
			ConfigurationRevision: 4, SecurityRevision: 5, PlanRevision: 6, AssurancePolicyRevision: 7,
			SPEntityID: "https://sp.example.test/saml/metadata",
			ACSURL:     "https://sp.example.test/api/v1/auth/platform/saml/acs", SPKeyRevision: 9,
			RedirectSignatureAlgorithm: federatedsaml.RedirectRSASHA256,
			SignaturePolicy:            federatedsaml.SignedAssertion, EncryptionPolicy: federatedsaml.EncryptionDisabled,
			RequestedAuthnContexts: []string{"urn:test:primary"},
			Subject:                platformSAMLSubjectWire{Source: string(federatedsaml.SubjectPersistentNameID)},
			ClockSkewNanoseconds:   int64(time.Minute), MaxAuthenticationAgeNanoseconds: int64(time.Hour),
		},
		Metadata: platformSAMLMetadataWire{
			ExpectedEntityID: "https://idp.example.test/entity", Revision: 8, Document: document,
			Digest: metadataDigest[:], RetrievedAt: retrievedAt, MaximumValidUntil: retrievedAt.Add(48 * time.Hour),
		},
		PlatformFloor: assurancePolicyWire{
			ID: entityIDWire(sessionLogoutRepositoryID(t)), Revision: 1, Level: "primary",
		},
	}
}

func sessionLogoutSAMLMetadataDocument(t *testing.T, certificateTime, validUntil time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "logout-test-idp"},
		NotBefore: certificateTime.Add(-time.Hour), NotAfter: certificateTime.Add(365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true,
	}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(fmt.Sprintf(
		`<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://idp.example.test/entity" validUntil="%s"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" WantAuthnRequestsSigned="true"><md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.test/slo"/><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.test/sso"/></md:IDPSSODescriptor></md:EntityDescriptor>`,
		validUntil.UTC().Format(time.RFC3339), base64.StdEncoding.EncodeToString(certificate),
	))
}

func sessionLogoutRepositoryID(t *testing.T) identity.EntityID {
	t.Helper()
	value, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	return identity.EntityID(value)
}

func sessionLogoutRepositoryPayload(t *testing.T, arguments []any) []byte {
	t.Helper()
	if len(arguments) != 1 {
		t.Fatalf("arguments = %#v", arguments)
	}
	payload, ok := arguments[0].([]byte)
	if !ok || len(payload) == 0 {
		t.Fatalf("payload = %#v", arguments[0])
	}
	return append([]byte(nil), payload...)
}

func assertSessionLogoutJSONKeys(t *testing.T, raw []byte, expected ...string) {
	t.Helper()
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatalf("decode JSON object: %v", err)
	}
	actual := make([]string, 0, len(object))
	for key := range object {
		actual = append(actual, key)
	}
	sort.Strings(actual)
	sort.Strings(expected)
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("JSON keys = %#v, want %#v; body=%s", actual, expected, raw)
	}
}

func sessionLogoutStringPointer(value string) *string { return &value }
