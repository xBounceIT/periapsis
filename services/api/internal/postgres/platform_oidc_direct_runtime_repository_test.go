package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedoidc"
	"github.com/periapsis-im/periapsis/services/api/internal/platformoidcauth"
)

type platformOIDCDirectRuntimeTransactionFixture struct {
	now     time.Time
	pins    platformoidcauth.DirectOIDCConfigurationPins
	audit   platformoidcauth.DirectAuditContext
	create  platformoidcauth.DirectOIDCCreateTransactionRequest
	claim   platformoidcauth.DirectOIDCClaimTransactionRequest
	failure platformoidcauth.DirectOIDCFailureRequest
}

func newPlatformOIDCDirectRuntimeTransactionFixture(t *testing.T) platformOIDCDirectRuntimeTransactionFixture {
	t.Helper()
	now := time.Date(2026, time.August, 30, 15, 0, 0, 123_000_000, time.UTC)
	pins := platformOIDCDirectRuntimePinsFixture()
	audit := platformOIDCDirectRuntimeAuditFixture()
	transactionID := federatedoidc.TransactionID(platformOIDCDirectBytes(1))
	stateDigest := platformOIDCDirectBytes(41)
	browserDigest := platformOIDCDirectBytes(81)
	nonceDigest := platformOIDCDirectBytes(121)
	verifier := platformOIDCDirectBytes(161)
	pending := federatedoidc.PendingTransaction{
		ID: transactionID, StateDigest: stateDigest, BrowserDigest: browserDigest,
		NonceDigest: nonceDigest,
		Verifier: federatedoidc.ProtectedVerifier{
			KeyVersion: 3, Ciphertext: append([]byte(nil), verifier[:]...),
		},
		Pins: platformOIDCDirectTransactionPins(pins), ClientID: "direct-client",
		RedirectURI:           "https://app.example.test/api/v1/auth/platform/oidc/callback",
		PostLogoutRedirectURI: "https://app.example.test/signed-out", ReturnPath: "/cases/17?tab=timeline",
		Scopes: []string{"openid", "profile"}, CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute),
		State: federatedoidc.TransactionPending, Version: 1,
	}
	receipt := platformOIDCDirectBytes(11)
	network := platformOIDCDirectBytes(21)
	account := platformOIDCDirectBytes(31)
	provider := platformOIDCDirectBytes(51)
	capability := platformOIDCDirectBytes(201)
	create := platformoidcauth.DirectOIDCCreateTransactionRequest{
		Begin: federatedoidc.AuthorizationBegin{
			OperationRunID: platformOIDCDirectRuntimeEntityID("000000000115"),
			ReceiptDigest:  federatedoidc.StartReceiptDigest(receipt),
			NetworkDigest:  federatedoidc.NetworkThrottleDigest(network),
			AccountDigest:  federatedoidc.AccountThrottleDigest(account),
			ProviderDigest: federatedoidc.ProviderThrottleDigest(provider),
		},
		Current: pending, CodeChallengeMethod: federatedoidc.CodeChallengeS256,
		BrowserCapabilityDigest: platformoidcauth.DirectBrowserCapabilityDigest(capability), Audit: audit,
	}
	attempt := federatedoidc.TransactionID(platformOIDCDirectBytes(211))
	authorizationCode := platformOIDCDirectBytes(231)
	claim := platformoidcauth.DirectOIDCClaimTransactionRequest{
		AttemptID: attempt, ExpectedVersion: 1, StateDigest: stateDigest, BrowserDigest: browserDigest,
		AuthorizationCodeDigest: authorizationCode, ClaimedAt: now.Add(time.Minute), Audit: audit,
	}
	return platformOIDCDirectRuntimeTransactionFixture{
		now: now, pins: pins, audit: audit, create: create, claim: claim,
		failure: platformoidcauth.DirectOIDCFailureRequest{
			TransactionID: transactionID, ExpectedVersion: 2, FailedAt: now.Add(time.Minute + time.Second),
			Reason: federatedoidc.FailureTokenValidation, State: federatedoidc.TransactionFailed, Audit: audit,
		},
	}
}

func platformOIDCDirectRuntimePinsFixture() platformoidcauth.DirectOIDCConfigurationPins {
	return platformoidcauth.DirectOIDCConfigurationPins{
		Provider: identity.ProviderContext{
			Scope:      identity.PlatformProviderScope,
			ProviderID: platformOIDCDirectRuntimeEntityID("000000000111"),
		},
		ProviderRevision: 2, PlatformLoginRevision: 3, ConfigurationRevision: 4,
		SecurityRevision: 5, PlanRevision: 6, AssurancePolicyRevision: 7,
		PlatformFloorPolicyID:       platformOIDCDirectRuntimeEntityID("000000000112"),
		PlatformFloorPolicyRevision: 8, ClientSecretRevision: 9, DiscoveryRevision: 10,
		DiscoveryDigest: platformOIDCDirectBytes(17), JWKSRevision: 11,
		JWKSDigest: platformOIDCDirectBytes(57),
	}
}

func platformOIDCDirectRuntimeAuditFixture() platformoidcauth.DirectAuditContext {
	return platformoidcauth.DirectAuditContext{
		RequestID:     platformOIDCDirectRuntimeEntityID("000000000113"),
		CorrelationID: platformOIDCDirectRuntimeEntityID("000000000114"),
		RemoteAddress: netip.MustParseAddr("203.0.113.71"),
		UserAgent:     "direct-oidc-runtime-repository-test/1",
	}
}

func platformOIDCDirectRuntimeEntityID(suffix string) identity.EntityID {
	return identity.EntityID(uuid.MustParse("00000000-0000-7000-8000-" + suffix))
}

func platformOIDCDirectRuntimePinsWireFixture(
	t *testing.T,
	pins platformoidcauth.DirectOIDCConfigurationPins,
) platformOIDCDirectPinsWire {
	t.Helper()
	wire, err := platformOIDCDirectPinsToWire(pins)
	if err != nil {
		t.Fatalf("platformOIDCDirectPinsToWire() error = %v", err)
	}
	return wire
}

func platformOIDCDirectRuntimePayload(t *testing.T, arguments []any) []byte {
	t.Helper()
	if len(arguments) != 1 {
		t.Fatalf("arguments = %d", len(arguments))
	}
	payload, ok := arguments[0].([]byte)
	if !ok {
		t.Fatalf("argument = %T", arguments[0])
	}
	return payload
}

func platformOIDCDirectRuntimeJSONRow(
	t *testing.T,
	value any,
	retained *[][]byte,
) pgx.Row {
	t.Helper()
	raw := mustFederatedJSON(t, value)
	if retained != nil {
		*retained = append(*retained, raw)
	}
	return federatedAuthJSONRow(raw)
}

func assertPlatformOIDCDirectRuntimeJSONKeys(
	t *testing.T,
	payload []byte,
	wanted ...string,
) map[string]json.RawMessage {
	t.Helper()
	var object map[string]json.RawMessage
	if err := json.Unmarshal(payload, &object); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	actual := make([]string, 0, len(object))
	for key := range object {
		actual = append(actual, key)
	}
	slices.Sort(actual)
	wanted = append([]string(nil), wanted...)
	slices.Sort(wanted)
	if !slices.Equal(actual, wanted) {
		t.Fatalf("JSON keys = %v, want %v; payload=%s", actual, wanted, payload)
	}
	return object
}

func assertPlatformOIDCDirectRuntimePinsKeys(t *testing.T, raw json.RawMessage) {
	t.Helper()
	object := assertPlatformOIDCDirectRuntimeJSONKeys(t, raw,
		"provider", "providerRevision", "loginPolicyRevision", "configurationRevision",
		"securityRevision", "planRevision", "assurancePolicyRevision", "platformFloorPolicyId",
		"platformFloorPolicyRevision", "clientSecretRevision", "discoveryRevision", "discoveryDigest",
		"jwksRevision", "jwksDigest",
	)
	assertPlatformOIDCDirectRuntimeJSONKeys(t, object["provider"], "scope", "providerId")
}

func assertPlatformOIDCDirectRuntimeCleared(t *testing.T, values ...[]byte) {
	t.Helper()
	for index, value := range values {
		if !bytes.Equal(value, make([]byte, len(value))) {
			t.Fatalf("retained buffer %d was not cleared", index)
		}
	}
}

func assertPlatformOIDCDirectRuntimeDigest(t *testing.T, value []byte) {
	t.Helper()
	if len(value) != sha256.Size || bytes.Equal(value, make([]byte, sha256.Size)) {
		t.Fatalf("digest = %x", value)
	}
}

func platformOIDCDirectRuntimeCancelledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func TestFederatedAuthRepositoryDirectOIDCRuntimeCancellationStopsBeforeQuery(t *testing.T) {
	transaction := newPlatformOIDCDirectRuntimeTransactionFixture(t)
	planning := newPlatformOIDCDirectRuntimePlanningFixture(t)
	apply := newPlatformOIDCDirectRuntimeApplyFixture(t).sessionRequest(t)
	secret := platformoidcauth.DirectOIDCClientSecretLookup{Pins: transaction.pins}
	tests := map[string]func(*FederatedAuthRepository, context.Context) error{
		"create transaction": func(repository *FederatedAuthRepository, ctx context.Context) error {
			return repository.CreateDirectOIDCTransaction(ctx, transaction.create)
		},
		"claim transaction": func(repository *FederatedAuthRepository, ctx context.Context) error {
			claimed, err := repository.ClaimDirectOIDCTransaction(ctx, transaction.claim)
			clear(claimed.Verifier.Ciphertext)
			return err
		},
		"fail transaction": func(repository *FederatedAuthRepository, ctx context.Context) error {
			return repository.FailDirectOIDCTransaction(ctx, transaction.failure)
		},
		"client secret": func(repository *FederatedAuthRepository, ctx context.Context) error {
			snapshot, err := repository.LoadDirectOIDCClientSecretEnvelope(ctx, secret)
			clear(snapshot.Envelope.Nonce[:])
			clear(snapshot.Envelope.Ciphertext)
			return err
		},
		"planning": func(repository *FederatedAuthRepository, ctx context.Context) error {
			state, err := repository.LoadDirectPlatformPlanningState(ctx, planning.lookup)
			clearPlatformOIDCDirectTrustRules(state.TrustRules)
			return err
		},
		"atomic apply": func(repository *FederatedAuthRepository, ctx context.Context) error {
			_, err := repository.ApplyDirectOIDC(ctx, apply)
			return err
		},
	}
	for name, invoke := range tests {
		t.Run(name, func(t *testing.T) {
			called := false
			repository := &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(
				_ context.Context,
				_ string,
				_ ...any,
			) pgx.Row {
				called = true
				return nil
			}}}
			if err := invoke(repository, platformOIDCDirectRuntimeCancelledContext()); !errors.Is(err, errFederatedAuthPersistence) || called {
				t.Fatalf("error = %v, called=%t", err, called)
			}
		})
	}
}
