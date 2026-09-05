package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedoidc"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
)

type federatedAuthQueryerStub struct {
	query func(context.Context, string, ...any) pgx.Row
}

func (stub federatedAuthQueryerStub) QueryRow(ctx context.Context, query string, arguments ...any) pgx.Row {
	return stub.query(ctx, query, arguments...)
}

type federatedAuthRowFunc func(...any) error

func (scan federatedAuthRowFunc) Scan(destinations ...any) error { return scan(destinations...) }

func TestFederatedAuthRepositoryExecutesBoundedTransactionABIs(t *testing.T) {
	postgresJSONZone := time.FixedZone("postgres-json", 2*60*60)
	oidcCreate := postgresOIDCCreateFixture()
	oidcClaim := federatedoidc.TransactionClaim{
		AttemptID: postgresOIDCTransactionID(9), StateDigest: oidcCreate.Current.StateDigest,
		BrowserDigest: oidcCreate.Current.BrowserDigest, ClaimedAt: oidcCreate.Current.CreatedAt.Add(time.Minute),
	}
	oidcFailure := federatedoidc.TransactionFailure{
		ID: oidcCreate.Current.ID, ExpectedVersion: 2, FailedAt: oidcClaim.ClaimedAt.Add(time.Second),
		Reason: federatedoidc.FailureTokenValidation, State: federatedoidc.TransactionFailed,
	}
	samlCreate := postgresSAMLCreateFixture()
	samlLookup := federatedsaml.LookupTransactionRequest{
		RelayStateDigest: samlCreate.Current.RelayStateDigest, BrowserDigest: samlCreate.Current.BrowserDigest,
		ObservedAt: samlCreate.Current.CreatedAt.Add(time.Minute),
	}

	var retainedPayloads [][]byte
	queries := make([]string, 0, 5)
	repository := &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(
		_ context.Context,
		query string,
		arguments ...any,
	) pgx.Row {
		if len(arguments) != 1 {
			t.Fatalf("%s argument count = %d", query, len(arguments))
		}
		payload, ok := arguments[0].([]byte)
		if !ok || len(payload) == 0 || len(payload) > maximumFederatedAuthenticationWireBytes {
			t.Fatalf("%s payload type/size = %T/%d", query, arguments[0], len(payload))
		}
		retainedPayloads = append(retainedPayloads, payload)
		queries = append(queries, query)

		var response any
		switch query {
		case createOIDCAuthenticationTransactionSQL:
			var request oidcCreateTransactionWire
			if err := json.Unmarshal(payload, &request); err != nil || request.Begin.OperationRunID == "" ||
				request.Current.Pins.Provider.Scope != federatedTenantProviderScopeWire ||
				request.Current.Pins.Provider.TenantID == "" || request.Current.Pins.Provider.BindingID == "" ||
				len(request.Current.VerifierCiphertext) != 16 {
				t.Fatalf("OIDC create wire malformed: %#v, %v", request, err)
			}
			response = federatedTransactionReceiptWire{
				TransactionID: append([]byte(nil), oidcCreate.Current.ID[:]...), Version: 1,
				State: string(federatedoidc.TransactionPending),
			}
		case claimOIDCAuthenticationTransactionSQL:
			var request oidcTransactionClaimWire
			if err := json.Unmarshal(payload, &request); err != nil ||
				!bytes.Equal(request.AttemptID, oidcClaim.AttemptID[:]) {
				t.Fatalf("OIDC claim wire malformed: %#v, %v", request, err)
			}
			pending := oidcCreate.Current
			pending.State, pending.Version = federatedoidc.TransactionClaimed, 2
			pendingWire, err := oidcPendingTransactionToWire(pending)
			if err != nil {
				t.Fatal(err)
			}
			pendingWire.CreatedAt = pendingWire.CreatedAt.In(postgresJSONZone)
			pendingWire.ExpiresAt = pendingWire.ExpiresAt.In(postgresJSONZone)
			response = oidcClaimedTransactionWire{
				oidcPendingTransactionWire: pendingWire,
				ClaimAttemptID:             append([]byte(nil), oidcClaim.AttemptID[:]...),
				ClaimedAt:                  oidcClaim.ClaimedAt.In(postgresJSONZone),
			}
		case failOIDCAuthenticationTransactionSQL:
			var request oidcTransactionFailureWire
			if err := json.Unmarshal(payload, &request); err != nil || request.ExpectedVersion != 2 ||
				request.Reason != string(federatedoidc.FailureTokenValidation) {
				t.Fatalf("OIDC failure wire malformed: %#v, %v", request, err)
			}
			response = federatedTransactionReceiptWire{
				TransactionID: append([]byte(nil), oidcFailure.ID[:]...), Version: 3,
				State: string(federatedoidc.TransactionFailed), Replayed: true,
			}
		case createSAMLAuthenticationTransactionSQL:
			var request samlCreateTransactionWire
			if err := json.Unmarshal(payload, &request); err != nil || request.Current.Pins.Provider.BindingID == "" ||
				request.Current.RequestID != "_request" || request.Current.MaterialID != "" {
				t.Fatalf("SAML create wire malformed: %#v, %v", request, err)
			}
			response = federatedTransactionReceiptWire{
				TransactionID: append([]byte(nil), samlCreate.Current.ID[:]...), Version: 1,
				State: string(federatedsaml.TransactionPending),
			}
		case lookupSAMLAuthenticationTransactionSQL:
			var request samlTransactionLookupWire
			if err := json.Unmarshal(payload, &request); err != nil ||
				!bytes.Equal(request.RelayStateDigest, samlLookup.RelayStateDigest[:]) {
				t.Fatalf("SAML lookup wire malformed: %#v, %v", request, err)
			}
			pending, err := samlPendingTransactionToWire(samlCreate.Current)
			if err != nil {
				t.Fatal(err)
			}
			pending.CreatedAt = pending.CreatedAt.In(postgresJSONZone)
			pending.ExpiresAt = pending.ExpiresAt.In(postgresJSONZone)
			response = pending
		default:
			t.Fatalf("unexpected query: %s", query)
		}
		encoded, err := json.Marshal(response)
		if err != nil {
			t.Fatal(err)
		}
		return federatedAuthJSONRow(encoded)
	}}}

	if receipt, err := repository.CreateOIDCTransaction(context.Background(), oidcCreate); err != nil ||
		receipt.TransactionID != oidcCreate.Current.ID || receipt.Version != 1 {
		t.Fatalf("CreateOIDCTransaction() = %s, %v", receipt, err)
	}
	claimed, err := repository.ClaimOIDCTransaction(context.Background(), oidcClaim)
	if err != nil || claimed.ID != oidcCreate.Current.ID || claimed.ClaimAttemptID != oidcClaim.AttemptID ||
		claimed.Version != 2 || claimed.State != federatedoidc.TransactionClaimed ||
		claimed.CreatedAt.Location() != time.UTC || claimed.ExpiresAt.Location() != time.UTC ||
		claimed.ClaimedAt.Location() != time.UTC {
		t.Fatalf("ClaimOIDCTransaction() = %s, %v", claimed, err)
	}
	clear(claimed.Verifier.Ciphertext)
	if receipt, err := repository.FailOIDCTransaction(context.Background(), oidcFailure); err != nil ||
		receipt.Version != 3 || receipt.State != federatedoidc.TransactionFailed || !receipt.Replayed {
		t.Fatalf("FailOIDCTransaction() = %s, %v", receipt, err)
	}
	if receipt, err := repository.CreateSAMLTransaction(context.Background(), samlCreate); err != nil ||
		receipt.TransactionID != samlCreate.Current.ID || receipt.Version != 1 {
		t.Fatalf("CreateSAMLTransaction() = %s, %v", receipt, err)
	}
	if pending, err := repository.LookupSAMLTransaction(context.Background(), samlLookup); err != nil ||
		pending != samlCreate.Current {
		t.Fatalf("LookupSAMLTransaction() = %s, %v", pending, err)
	}

	wantQueries := []string{
		createOIDCAuthenticationTransactionSQL, claimOIDCAuthenticationTransactionSQL,
		failOIDCAuthenticationTransactionSQL, createSAMLAuthenticationTransactionSQL,
		lookupSAMLAuthenticationTransactionSQL,
	}
	if fmt.Sprint(queries) != fmt.Sprint(wantQueries) {
		t.Fatalf("queries = %v, want %v", queries, wantQueries)
	}
	for index, payload := range retainedPayloads {
		if !allZeroFederatedBytes(payload) {
			t.Fatalf("payload %d retained uncleared wire material", index)
		}
	}
}

func TestOIDCTransactionPinsWirePreservesTenantShapeAndSeparatesPlatformAdmission(t *testing.T) {
	tenantPins := postgresOIDCCreateFixture().Current.Pins
	tenantWire, err := oidcPinsToWire(tenantPins)
	if err != nil {
		t.Fatal(err)
	}
	gotTenant, err := json.Marshal(tenantWire)
	if err != nil {
		t.Fatal(err)
	}
	legacy := struct {
		Provider                federatedProviderBindingWire `json:"provider"`
		ProviderRevision        uint64                       `json:"providerRevision"`
		BindingRevision         uint64                       `json:"bindingRevision"`
		ConfigurationRevision   uint64                       `json:"configurationRevision"`
		SecurityRevision        uint64                       `json:"securityRevision"`
		MappingRevision         uint64                       `json:"mappingRevision"`
		AuthorizationRevision   uint64                       `json:"authorizationRevision"`
		AssurancePolicyRevision uint64                       `json:"assurancePolicyRevision"`
		ClientSecretRevision    uint64                       `json:"clientSecretRevision"`
		DiscoveryRevision       uint64                       `json:"discoveryRevision"`
		DiscoveryDigest         []byte                       `json:"discoveryDigest"`
		JWKSRevision            uint64                       `json:"jwksRevision"`
		JWKSDigest              []byte                       `json:"jwksDigest"`
	}{
		Provider: tenantWire.Provider, ProviderRevision: tenantWire.ProviderRevision,
		BindingRevision: tenantWire.BindingRevision, ConfigurationRevision: tenantWire.ConfigurationRevision,
		SecurityRevision: tenantWire.SecurityRevision, MappingRevision: tenantWire.MappingRevision,
		AuthorizationRevision:   tenantWire.AuthorizationRevision,
		AssurancePolicyRevision: tenantWire.AssurancePolicyRevision,
		ClientSecretRevision:    tenantWire.ClientSecretRevision, DiscoveryRevision: tenantWire.DiscoveryRevision,
		DiscoveryDigest: tenantWire.DiscoveryDigest, JWKSRevision: tenantWire.JWKSRevision,
		JWKSDigest: tenantWire.JWKSDigest,
	}
	wantTenant, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotTenant, wantTenant) || bytes.Contains(gotTenant, []byte(`"admission"`)) {
		t.Fatalf("tenant pins wire changed: got %s want %s", gotTenant, wantTenant)
	}

	platformPins := postgresPlatformOIDCCreateFixture().Current.Pins
	platformWire, err := oidcPinsToWire(platformPins)
	if err != nil || platformWire.Admission == nil || platformWire.Provider.BindingID != "" ||
		platformWire.Provider.TenantID != "" {
		t.Fatalf("platform pins wire = %#v, %v", platformWire, err)
	}
	roundTrip, err := oidcPinsFromWire(platformWire)
	if err != nil || roundTrip != platformPins {
		t.Fatalf("platform pins round trip = %#v, %v", roundTrip, err)
	}

	missingAdmission := platformWire
	missingAdmission.Admission = nil
	if _, err := oidcPinsFromWire(missingAdmission); !errors.Is(err, errFederatedAuthPersistence) {
		t.Fatalf("platform pins without admission accepted: %v", err)
	}
	providerBound := platformWire
	providerBound.Provider.BindingID = platformWire.Admission.BindingID
	if _, err := oidcPinsFromWire(providerBound); !errors.Is(err, errFederatedAuthPersistence) {
		t.Fatalf("platform pins with cryptographic binding accepted: %v", err)
	}
	tenantWithAdmission := tenantWire
	tenantWithAdmission.Admission = platformWire.Admission
	if _, err := oidcPinsFromWire(tenantWithAdmission); !errors.Is(err, errFederatedAuthPersistence) {
		t.Fatalf("tenant pins with additive admission accepted: %v", err)
	}
}

func TestFederatedAuthRepositoryPersistsTenantBoundPlatformOIDCTransaction(t *testing.T) {
	request := postgresPlatformOIDCCreateFixture()
	claim := federatedoidc.TransactionClaim{
		AttemptID: postgresOIDCTransactionID(31), StateDigest: request.Current.StateDigest,
		BrowserDigest: request.Current.BrowserDigest, ClaimedAt: request.Current.CreatedAt.Add(time.Minute),
	}
	repository := &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(
		_ context.Context,
		query string,
		arguments ...any,
	) pgx.Row {
		payload := arguments[0].([]byte)
		switch query {
		case createOIDCAuthenticationTransactionSQL:
			var wire oidcCreateTransactionWire
			if err := json.Unmarshal(payload, &wire); err != nil || wire.Current.Pins.Admission == nil ||
				wire.Current.Pins.Provider.Scope != federatedPlatformProviderScopeWire ||
				wire.Current.Pins.Provider.TenantID != "" || wire.Current.Pins.Provider.BindingID != "" {
				t.Fatalf("platform transaction create wire = %#v, %v", wire, err)
			}
			return federatedAuthJSONRow(mustFederatedJSON(t, federatedTransactionReceiptWire{
				TransactionID: append([]byte(nil), request.Current.ID[:]...), Version: 1,
				State: string(federatedoidc.TransactionPending),
			}))
		case claimOIDCAuthenticationTransactionSQL:
			pending := request.Current
			pending.State, pending.Version = federatedoidc.TransactionClaimed, 2
			wire, err := oidcPendingTransactionToWire(pending)
			if err != nil {
				t.Fatal(err)
			}
			return federatedAuthJSONRow(mustFederatedJSON(t, oidcClaimedTransactionWire{
				oidcPendingTransactionWire: wire,
				ClaimAttemptID:             append([]byte(nil), claim.AttemptID[:]...),
				ClaimedAt:                  claim.ClaimedAt,
			}))
		default:
			t.Fatalf("unexpected platform transaction query = %q", query)
			return federatedAuthJSONRow(nil)
		}
	}}}
	if _, err := repository.CreateOIDCTransaction(context.Background(), request); err != nil {
		t.Fatalf("CreateOIDCTransaction() error = %v", err)
	}
	claimed, err := repository.ClaimOIDCTransaction(context.Background(), claim)
	if err != nil || claimed.Pins != request.Current.Pins || claimed.Version != 2 {
		t.Fatalf("ClaimOIDCTransaction() = %s, %v", claimed, err)
	}
	clear(claimed.Verifier.Ciphertext)
}

func TestFederatedAuthRepositoryRejectsMalformedWireAndCancellation(t *testing.T) {
	valid := postgresOIDCCreateFixture()
	for name, raw := range map[string][]byte{
		"unknown member": []byte(`{"transactionId":"bad","version":1,"state":"pending","replayed":false,"secret":"canary"}`),
		"trailing":       []byte(`{} {}`),
		"oversized":      bytes.Repeat([]byte{'x'}, maximumFederatedAuthenticationWireBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			repository := &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(
				context.Context, string, ...any,
			) pgx.Row {
				return federatedAuthJSONRow(append([]byte(nil), raw...))
			}}}
			if _, err := repository.CreateOIDCTransaction(context.Background(), valid); !errors.Is(err, errFederatedAuthPersistence) ||
				strings.Contains(err.Error(), "canary") {
				t.Fatalf("CreateOIDCTransaction() error = %v", err)
			}
		})
	}

	called := false
	repository := &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(
		context.Context, string, ...any,
	) pgx.Row {
		called = true
		return federatedAuthRowFunc(func(...any) error { return nil })
	}}}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := repository.CreateOIDCTransaction(cancelled, valid); !errors.Is(err, errFederatedAuthPersistence) {
		t.Fatalf("cancelled CreateOIDCTransaction() error = %v", err)
	}
	if called {
		t.Fatal("cancelled request reached PostgreSQL")
	}

	lateContext, lateCancel := context.WithCancel(context.Background())
	var retainedRow []byte
	repository = &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(
		context.Context,
		string,
		...any,
	) pgx.Row {
		return federatedAuthRowFunc(func(destinations ...any) error {
			retainedRow, _ = json.Marshal(federatedTransactionReceiptWire{
				TransactionID: append([]byte(nil), valid.Current.ID[:]...), Version: 1,
				State: string(federatedoidc.TransactionPending),
			})
			*destinations[0].(*[]byte) = retainedRow
			lateCancel()
			return nil
		})
	}}}
	if _, err := repository.CreateOIDCTransaction(lateContext, valid); !errors.Is(err, errFederatedAuthPersistence) ||
		!allZeroFederatedBytes(retainedRow) {
		t.Fatalf("late-cancelled CreateOIDCTransaction() error = %v retained=%x", err, retainedRow)
	}
}

func TestFederatedAuthDatabaseWireTimeNormalization(t *testing.T) {
	postgresJSONZone := time.FixedZone("postgres-json", 2*60*60)
	instant := time.Date(2026, time.August, 26, 14, 0, 0, 123456000, time.UTC).In(postgresJSONZone)
	canonical, ok := canonicalFederatedDatabaseTimeFromWire(instant)
	if !ok || canonical.Location() != time.UTC || !canonical.Equal(instant) {
		t.Fatalf("canonical wire time = %s, %t", canonical, ok)
	}
	if _, ok := canonicalFederatedDatabaseTimeFromWire(instant.Add(time.Nanosecond)); ok {
		t.Fatal("sub-microsecond database wire time accepted")
	}
}

func TestFederatedAuthRepositoryReadinessIsExactAndFailClosed(t *testing.T) {
	for name, row := range map[string]pgx.Row{
		"ready": federatedAuthRowFunc(func(destinations ...any) error {
			*destinations[0].(*bool) = true
			return nil
		}),
		"not ready": federatedAuthRowFunc(func(destinations ...any) error {
			*destinations[0].(*bool) = false
			return nil
		}),
		"database detail": federatedAuthRowFunc(func(...any) error {
			return errors.New("relation secret_canary missing")
		}),
	} {
		t.Run(name, func(t *testing.T) {
			var observed string
			repository := &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(
				_ context.Context,
				query string,
				arguments ...any,
			) pgx.Row {
				observed = query
				if len(arguments) != 0 {
					t.Fatalf("readiness arguments = %d", len(arguments))
				}
				return row
			}}}
			err := repository.CheckFederatedAuthenticationReadiness(context.Background())
			if name == "ready" && err != nil {
				t.Fatalf("readiness error = %v", err)
			}
			if name != "ready" && (!errors.Is(err, errFederatedAuthPersistence) ||
				strings.Contains(err.Error(), "canary")) {
				t.Fatalf("readiness error = %v", err)
			}
			if observed != federatedAuthenticationReadinessSQL {
				t.Fatalf("readiness query = %q", observed)
			}
		})
	}

	lateContext, lateCancel := context.WithCancel(context.Background())
	repository := &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(
		context.Context,
		string,
		...any,
	) pgx.Row {
		return federatedAuthRowFunc(func(destinations ...any) error {
			*destinations[0].(*bool) = true
			lateCancel()
			return nil
		})
	}}}
	if err := repository.CheckFederatedAuthenticationReadiness(lateContext); !errors.Is(err, errFederatedAuthPersistence) {
		t.Fatalf("late-cancelled readiness error = %v", err)
	}
}

func TestFederatedAuthRepositoryLoadsExactProtectedSecretAndKeyRows(t *testing.T) {
	oidcLookup := federatedauth.ClientSecretContext{
		Provider: identity.ProviderContext{
			Scope: identity.TenantProviderScope, TenantID: postgresFederatedID(31), ProviderID: postgresFederatedID(32),
		},
		BindingID: postgresFederatedID(33), Revision: 7,
	}
	samlLookup := federatedsaml.SPKeyRequest{
		Provider: identity.ProviderContext{
			Scope: identity.TenantProviderScope, TenantID: postgresFederatedID(41), ProviderID: postgresFederatedID(42),
		},
		BindingID: postgresFederatedID(43), KeyRevision: 9,
	}

	var retainedPayloads, retainedRows [][]byte
	repository := &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(
		_ context.Context,
		query string,
		arguments ...any,
	) pgx.Row {
		if len(arguments) != 1 {
			t.Fatalf("%s arguments = %d", query, len(arguments))
		}
		payload := arguments[0].([]byte)
		retainedPayloads = append(retainedPayloads, payload)
		var response any
		switch query {
		case loadOIDCClientSecretEnvelopeSQL:
			var request oidcClientSecretLookupWire
			if err := json.Unmarshal(payload, &request); err != nil || request.Revision != oidcLookup.Revision ||
				request.Provider.ProviderID == "" || request.Provider.BindingID == "" {
				t.Fatalf("OIDC secret lookup wire = %#v, %v", request, err)
			}
			response = oidcClientSecretEnvelopeWire{
				Lookup: request, SecretID: federatedEntityIDString(t, postgresFederatedID(34)), KeyVersion: 3,
				Nonce:      bytes.Repeat([]byte{0x31}, oidcClientSecretNonceBytes),
				Ciphertext: bytes.Repeat([]byte{0x32}, 32),
			}
		case loadSAMLSPKeyEnvelopeSQL:
			var request samlSPKeyLookupWire
			if err := json.Unmarshal(payload, &request); err != nil || request.Revision != uint64(samlLookup.KeyRevision) ||
				request.Provider.BindingID == "" {
				t.Fatalf("SAML key lookup wire = %#v, %v", request, err)
			}
			response = samlSPKeyEnvelopeWire{
				Lookup: request, KeyID: federatedEntityIDString(t, postgresFederatedID(44)),
				EnvelopeKeyVersion: 5, EnvelopeCiphertext: []byte("sealed-saml-sp-key"),
				CertificateDER: [][]byte{{0x30, 0x01}, {0x30, 0x02}},
			}
		default:
			t.Fatalf("unexpected query = %s", query)
		}
		encoded, err := json.Marshal(response)
		if err != nil {
			t.Fatal(err)
		}
		retainedRows = append(retainedRows, encoded)
		return federatedAuthJSONRow(encoded)
	}}}

	oidc, err := repository.LoadOIDCClientSecretEnvelope(context.Background(), oidcLookup)
	if err != nil || oidc.Lookup != oidcLookup || oidc.SecretID != postgresFederatedID(34) ||
		oidc.Envelope.KeyVersion != 3 || len(oidc.Envelope.Ciphertext) != 32 ||
		oidc.Envelope.Nonce != [oidcClientSecretNonceBytes]byte{
			0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
		} {
		t.Fatalf("LoadOIDCClientSecretEnvelope() = %s, %v", oidc, err)
	}
	saml, err := repository.LoadSAMLSPKeyEnvelope(context.Background(), samlLookup)
	if err != nil || saml.Context.Provider != samlLookup.Provider || saml.Context.BindingID != samlLookup.BindingID ||
		saml.Context.KeyRevision != samlLookup.KeyRevision || saml.Context.KeyID != postgresFederatedID(44) ||
		saml.Envelope.KeyVersion != 5 || len(saml.CertificateDER) != 2 {
		t.Fatalf("LoadSAMLSPKeyEnvelope() = %s, %v", saml, err)
	}
	for _, values := range [][][]byte{retainedPayloads, retainedRows} {
		for index, value := range values {
			if !allZeroFederatedBytes(value) {
				t.Fatalf("wire buffer %d retained protected material", index)
			}
		}
	}
	if allZeroFederatedBytes(oidc.Envelope.Ciphertext) || allZeroFederatedBytes(saml.Envelope.Ciphertext) ||
		allZeroFederatedBytes(saml.CertificateDER[0]) {
		t.Fatal("returned snapshots alias cleared database wire buffers")
	}
	clear(oidc.Envelope.Nonce[:])
	clear(oidc.Envelope.Ciphertext)
	clear(saml.Envelope.Ciphertext)
	for index := range saml.CertificateDER {
		clear(saml.CertificateDER[index])
	}
}

func TestFederatedAuthRepositoryRoutesSAMLLogoutKeyThroughMaterialAttestation(t *testing.T) {
	lookup := federatedsaml.SPKeyRequest{
		Provider: identity.ProviderContext{
			Scope: identity.TenantProviderScope, TenantID: postgresFederatedID(45), ProviderID: postgresFederatedID(46),
		},
		BindingID: postgresFederatedID(47), KeyRevision: 10, LogoutMaterialID: postgresFederatedID(48),
	}
	provider := mustProviderBindingWire(t, lookup.Provider, lookup.BindingID, false)
	wantedWire := samlSPKeyLookupWire{
		Provider: provider, Revision: uint64(lookup.KeyRevision),
		MaterialID: federatedEntityIDString(t, lookup.LogoutMaterialID),
	}
	repository := &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(
		_ context.Context,
		query string,
		arguments ...any,
	) pgx.Row {
		if query != loadTenantSAMLLogoutSPKeyEnvelopeSQL || len(arguments) != 1 {
			t.Fatalf("historical SAML query = %q, arguments = %d", query, len(arguments))
		}
		var request samlSPKeyLookupWire
		if err := json.Unmarshal(arguments[0].([]byte), &request); err != nil || request != wantedWire {
			t.Fatalf("historical SAML lookup = %#v, %v", request, err)
		}
		return federatedAuthJSONRow(mustFederatedJSON(t, samlSPKeyEnvelopeWire{
			Lookup: request, KeyID: federatedEntityIDString(t, postgresFederatedID(49)),
			EnvelopeKeyVersion: 6, EnvelopeCiphertext: []byte("sealed-historical-saml-sp-key"),
			CertificateDER: [][]byte{{0x30, 0x03}},
		}))
	}}}
	snapshot, err := repository.LoadSAMLSPKeyEnvelope(context.Background(), lookup)
	if err != nil || snapshot.Context.Provider != lookup.Provider || snapshot.Context.BindingID != lookup.BindingID ||
		snapshot.Context.KeyRevision != lookup.KeyRevision || snapshot.Context.KeyID != postgresFederatedID(49) {
		t.Fatalf("historical LoadSAMLSPKeyEnvelope() = %q, %v", snapshot.String(), err)
	}

	drifted := wantedWire
	drifted.MaterialID = federatedEntityIDString(t, postgresFederatedID(50))
	repository = &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(
		context.Context,
		string,
		...any,
	) pgx.Row {
		return federatedAuthJSONRow(mustFederatedJSON(t, samlSPKeyEnvelopeWire{
			Lookup: drifted, KeyID: federatedEntityIDString(t, postgresFederatedID(49)),
			EnvelopeKeyVersion: 6, EnvelopeCiphertext: []byte("sealed-historical-saml-sp-key"),
			CertificateDER: [][]byte{{0x30, 0x03}},
		}))
	}}}
	if _, err := repository.LoadSAMLSPKeyEnvelope(context.Background(), lookup); !errors.Is(err, errFederatedAuthPersistence) {
		t.Fatalf("historical material echo drift error = %v", err)
	}
}

func TestFederatedAuthRepositoryLoadsPlatformSecretThroughExactTenantAdmission(t *testing.T) {
	lookup := federatedauth.ClientSecretContext{
		Provider: identity.ProviderContext{
			Scope: identity.PlatformProviderScope, ProviderID: postgresFederatedID(32),
		},
		Admission: identity.TenantAdmissionContext{
			TenantID: postgresFederatedID(31), BindingID: postgresFederatedID(33),
		},
		Revision: 7,
	}
	repository := &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(
		_ context.Context,
		query string,
		arguments ...any,
	) pgx.Row {
		if query != loadOIDCClientSecretEnvelopeSQL || len(arguments) != 1 {
			t.Fatalf("platform secret query = %q args=%d", query, len(arguments))
		}
		var wire oidcClientSecretLookupWire
		if err := json.Unmarshal(arguments[0].([]byte), &wire); err != nil || wire.Admission == nil ||
			wire.Provider.Scope != federatedPlatformProviderScopeWire || wire.Provider.BindingID != "" {
			t.Fatalf("platform secret wire = %#v, %v", wire, err)
		}
		return federatedAuthJSONRow(mustFederatedJSON(t, oidcClientSecretEnvelopeWire{
			Lookup: wire, SecretID: federatedEntityIDString(t, postgresFederatedID(34)), KeyVersion: 3,
			Nonce:      bytes.Repeat([]byte{0x31}, oidcClientSecretNonceBytes),
			Ciphertext: bytes.Repeat([]byte{0x32}, 32),
		}))
	}}}
	snapshot, err := repository.LoadOIDCClientSecretEnvelope(context.Background(), lookup)
	if err != nil || snapshot.Lookup != lookup || snapshot.SecretID != postgresFederatedID(34) ||
		snapshot.Envelope.KeyVersion != 3 {
		t.Fatalf("LoadOIDCClientSecretEnvelope() = %s, %v", snapshot, err)
	}
	clear(snapshot.Envelope.Nonce[:])
	clear(snapshot.Envelope.Ciphertext)

	called := false
	invalid := lookup
	invalid.Admission = identity.TenantAdmissionContext{}
	invalidRepository := &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(
		context.Context, string, ...any,
	) pgx.Row {
		called = true
		return federatedAuthJSONRow(nil)
	}}}
	if _, err := invalidRepository.LoadOIDCClientSecretEnvelope(context.Background(), invalid); !errors.Is(err, errFederatedAuthPersistence) {
		t.Fatalf("platform secret without admission error = %v", err)
	}
	if called {
		t.Fatal("platform secret without admission reached persistence")
	}
}

func TestFederatedAuthRepositoryLoadsPinnedConfigurationRecords(t *testing.T) {
	postgresJSONZone := time.FixedZone("postgres-json", 2*60*60)
	oidcCreate := postgresOIDCCreateFixture()
	oidcStart := federatedauth.OIDCStartLookup{
		OperationRunID: oidcCreate.Begin.OperationRunID, ReceiptDigest: oidcCreate.Begin.ReceiptDigest,
		TenantSlug: "tenant-a", LoginKey: "oidc-main", NetworkDigest: oidcCreate.Begin.NetworkDigest,
		AccountDigest: oidcCreate.Begin.AccountDigest, ProviderDigest: oidcCreate.Begin.ProviderDigest,
	}
	oidcCallback := federatedoidc.CallbackConfigurationLookup{
		TransactionID: oidcCreate.Current.ID, ExpectedVersion: 2, Pins: oidcCreate.Current.Pins,
	}
	samlCreate := postgresSAMLCreateFixture()
	samlStart := federatedauth.SAMLStartLookup{
		OperationRunID: samlCreate.Begin.OperationRunID, ReceiptDigest: samlCreate.Begin.ReceiptDigest,
		TenantSlug: "tenant-a", LoginKey: "saml-main", NetworkDigest: samlCreate.Begin.NetworkDigest,
		AccountDigest: samlCreate.Begin.AccountDigest, ProviderDigest: samlCreate.Begin.ProviderDigest,
	}
	samlCallback := federatedsaml.CallbackConfigurationLookup{
		TransactionID: samlCreate.Current.ID, ExpectedVersion: 1, Pins: samlCreate.Current.Pins,
	}
	oidcRecord := postgresOIDCConfigurationRecordWire(t, oidcCreate.Current.Pins)
	samlRecord := postgresSAMLConfigurationRecordWire(t, samlCreate.Current.Pins)
	oidcRecord.DiscoveryCache.RetrievedAt = oidcRecord.DiscoveryCache.RetrievedAt.In(postgresJSONZone)
	oidcRecord.DiscoveryCache.FreshUntil = oidcRecord.DiscoveryCache.FreshUntil.In(postgresJSONZone)
	oidcRecord.JWKSCache.RetrievedAt = oidcRecord.JWKSCache.RetrievedAt.In(postgresJSONZone)
	oidcRecord.JWKSCache.FreshUntil = oidcRecord.JWKSCache.FreshUntil.In(postgresJSONZone)
	samlRecord.MetadataRetrievedAt = samlRecord.MetadataRetrievedAt.In(postgresJSONZone)
	samlRecord.MetadataMaximumValidUntil = samlRecord.MetadataMaximumValidUntil.In(postgresJSONZone)

	var retainedPayloads, retainedRows [][]byte
	queries := make([]string, 0, 4)
	repository := &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(
		_ context.Context,
		query string,
		arguments ...any,
	) pgx.Row {
		if len(arguments) != 1 {
			t.Fatalf("%s arguments = %d", query, len(arguments))
		}
		payload := arguments[0].([]byte)
		retainedPayloads = append(retainedPayloads, payload)
		queries = append(queries, query)
		var response any
		switch query {
		case beginTenantOIDCConfigurationSQL:
			var request federatedStartLookupWire
			if err := json.Unmarshal(payload, &request); err != nil || request.TenantSlug != oidcStart.TenantSlug ||
				request.LoginKey != oidcStart.LoginKey || request.Begin.OperationRunID == "" {
				t.Fatalf("OIDC begin wire = %#v, %v", request, err)
			}
			response = oidcRecord
		case resolveTenantOIDCConfigurationSQL:
			var request oidcCallbackConfigurationLookupWire
			if err := json.Unmarshal(payload, &request); err != nil || request.ExpectedVersion != 2 ||
				!bytes.Equal(request.TransactionID, oidcCallback.TransactionID[:]) {
				t.Fatalf("OIDC callback wire = %#v, %v", request, err)
			}
			response = oidcRecord
		case beginTenantSAMLConfigurationSQL:
			var request federatedStartLookupWire
			if err := json.Unmarshal(payload, &request); err != nil || request.LoginKey != samlStart.LoginKey {
				t.Fatalf("SAML begin wire = %#v, %v", request, err)
			}
			response = samlRecord
		case resolveTenantSAMLConfigurationSQL:
			var request samlCallbackConfigurationLookupWire
			if err := json.Unmarshal(payload, &request); err != nil || request.ExpectedVersion != 1 ||
				!bytes.Equal(request.TransactionID, samlCallback.TransactionID[:]) {
				t.Fatalf("SAML callback wire = %#v, %v", request, err)
			}
			response = samlRecord
		default:
			t.Fatalf("unexpected query = %s", query)
		}
		encoded, err := json.Marshal(response)
		if err != nil {
			t.Fatal(err)
		}
		retainedRows = append(retainedRows, encoded)
		return federatedAuthJSONRow(encoded)
	}}}

	beginOIDC, err := repository.BeginTenantOIDCConfigurationRecord(context.Background(), oidcStart)
	if err != nil || beginOIDC.Authorization.Provider != oidcCreate.Current.Pins.Provider ||
		beginOIDC.Authorization.BindingID != oidcCreate.Current.Pins.BindingID || beginOIDC.DiscoveryRevision != 9 ||
		string(beginOIDC.DiscoveryDocument) != `{"issuer":"https://idp.example.test"}` ||
		beginOIDC.DiscoveryCache.RetrievedAt.Location() != time.UTC ||
		beginOIDC.JWKSCache.FreshUntil.Location() != time.UTC {
		t.Fatalf("BeginTenantOIDCConfigurationRecord() = %s, %v", beginOIDC, err)
	}
	resolvedOIDC, err := repository.ResolveTenantOIDCConfigurationRecord(context.Background(), oidcCallback)
	if err != nil || resolvedOIDC.DiscoveryDigest != oidcCreate.Current.Pins.DiscoveryDigest ||
		resolvedOIDC.JWKSDigest != oidcCreate.Current.Pins.JWKSDigest {
		t.Fatalf("ResolveTenantOIDCConfigurationRecord() = %s, %v", resolvedOIDC, err)
	}
	beginSAML, err := repository.BeginTenantSAMLConfigurationRecord(context.Background(), samlStart)
	if err != nil || beginSAML.Authentication.Provider != samlCreate.Current.Pins.Provider ||
		beginSAML.MetadataRevision != samlCreate.Current.Pins.MetadataRevision ||
		string(beginSAML.MetadataDocument) != `<EntityDescriptor/>` ||
		beginSAML.MetadataRetrievedAt.Location() != time.UTC ||
		beginSAML.MetadataMaximumValidUntil.Location() != time.UTC {
		t.Fatalf("BeginTenantSAMLConfigurationRecord() = %s, %v", beginSAML, err)
	}
	resolvedSAML, err := repository.ResolveTenantSAMLConfigurationRecord(context.Background(), samlCallback)
	if err != nil || resolvedSAML.MetadataDigest != samlCreate.Current.Pins.MetadataDigest ||
		resolvedSAML.Authentication.SPKeyRevision != samlCreate.Current.Pins.SPKeyRevision {
		t.Fatalf("ResolveTenantSAMLConfigurationRecord() = %s, %v", resolvedSAML, err)
	}

	wantQueries := []string{
		beginTenantOIDCConfigurationSQL, resolveTenantOIDCConfigurationSQL,
		beginTenantSAMLConfigurationSQL, resolveTenantSAMLConfigurationSQL,
	}
	if fmt.Sprint(queries) != fmt.Sprint(wantQueries) {
		t.Fatalf("configuration queries = %v, want %v", queries, wantQueries)
	}
	for _, values := range [][][]byte{retainedPayloads, retainedRows} {
		for index, value := range values {
			if !allZeroFederatedBytes(value) {
				t.Fatalf("configuration wire %d retained material", index)
			}
		}
	}
	for _, value := range []*[]byte{
		&beginOIDC.DiscoveryDocument, &beginOIDC.JWKSDocument, &resolvedOIDC.DiscoveryDocument,
		&resolvedOIDC.JWKSDocument, &beginSAML.MetadataDocument, &resolvedSAML.MetadataDocument,
	} {
		if allZeroFederatedBytes(*value) {
			t.Fatal("configuration projection aliases cleared database storage")
		}
		clear(*value)
	}
}

func TestFederatedAuthRepositoryLoadsTenantBoundPlatformOIDCConfiguration(t *testing.T) {
	create := postgresPlatformOIDCCreateFixture()
	start := federatedauth.OIDCStartLookup{
		OperationRunID: create.Begin.OperationRunID, ReceiptDigest: create.Begin.ReceiptDigest,
		TenantSlug: "tenant-a", LoginKey: "platform-oidc", NetworkDigest: create.Begin.NetworkDigest,
		AccountDigest: create.Begin.AccountDigest, ProviderDigest: create.Begin.ProviderDigest,
	}
	callback := federatedoidc.CallbackConfigurationLookup{
		TransactionID: create.Current.ID, ExpectedVersion: 2, Pins: create.Current.Pins,
	}
	record := postgresOIDCConfigurationRecordWire(t, create.Current.Pins)
	record.Authorization.RedirectURI = create.Current.RedirectURI
	repository := &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(
		_ context.Context,
		query string,
		arguments ...any,
	) pgx.Row {
		if query == resolveTenantOIDCConfigurationSQL {
			var wire oidcCallbackConfigurationLookupWire
			if err := json.Unmarshal(arguments[0].([]byte), &wire); err != nil || wire.Pins.Admission == nil ||
				wire.Pins.Provider.BindingID != "" {
				t.Fatalf("platform callback lookup = %#v, %v", wire, err)
			}
		} else if query != beginTenantOIDCConfigurationSQL {
			t.Fatalf("unexpected platform configuration query = %q", query)
		}
		return federatedAuthJSONRow(mustFederatedJSON(t, record))
	}}}
	begun, err := repository.BeginTenantOIDCConfigurationRecord(context.Background(), start)
	if err != nil || begun.Authorization.Provider != create.Current.Pins.Provider ||
		begun.Authorization.Admission != create.Current.Pins.Admission ||
		begun.Authorization.BindingID != (identity.EntityID{}) {
		t.Fatalf("BeginTenantOIDCConfigurationRecord() = %s, %v", begun, err)
	}
	resolved, err := repository.ResolveTenantOIDCConfigurationRecord(context.Background(), callback)
	if err != nil || resolved.Authorization.Admission != create.Current.Pins.Admission ||
		resolved.Authorization.RedirectURI != create.Current.RedirectURI {
		t.Fatalf("ResolveTenantOIDCConfigurationRecord() = %s, %v", resolved, err)
	}
	for _, value := range []*[]byte{
		&begun.DiscoveryDocument, &begun.JWKSDocument, &resolved.DiscoveryDocument, &resolved.JWKSDocument,
	} {
		clear(*value)
	}
}

func TestFederatedAuthRepositoryUsesDedicatedConfigurationResponseBound(t *testing.T) {
	oidcCreate := postgresOIDCCreateFixture()
	lookup := federatedauth.OIDCStartLookup{
		OperationRunID: oidcCreate.Begin.OperationRunID, ReceiptDigest: oidcCreate.Begin.ReceiptDigest,
		TenantSlug: "tenant-a", LoginKey: "oidc-main", NetworkDigest: oidcCreate.Begin.NetworkDigest,
		AccountDigest: oidcCreate.Begin.AccountDigest, ProviderDigest: oidcCreate.Begin.ProviderDigest,
	}

	t.Run("accepts schema-bounded documents above generic wire limit", func(t *testing.T) {
		wire := postgresOIDCConfigurationRecordWire(t, oidcCreate.Current.Pins)
		const documentBytes = 800 * 1024
		wire.DiscoveryDocument = bytes.Repeat([]byte{' '}, documentBytes)
		wire.DiscoveryDocument[0], wire.DiscoveryDocument[documentBytes-1] = '{', '}'
		wire.JWKSDocument = bytes.Repeat([]byte{' '}, documentBytes)
		wire.JWKSDocument[0], wire.JWKSDocument[documentBytes-1] = '{', '}'
		encoded, err := json.Marshal(wire)
		if err != nil {
			t.Fatal(err)
		}
		encodedBytes := len(encoded)
		if encodedBytes <= maximumFederatedAuthenticationWireBytes ||
			encodedBytes > maximumFederatedConfigurationResponseBytes {
			t.Fatalf("configuration response bytes = %d, generic=%d configuration=%d",
				encodedBytes, maximumFederatedAuthenticationWireBytes, maximumFederatedConfigurationResponseBytes)
		}

		repository := &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(
			_ context.Context,
			query string,
			_ ...any,
		) pgx.Row {
			if query != beginTenantOIDCConfigurationSQL {
				t.Fatalf("query = %q", query)
			}
			return federatedAuthJSONRow(encoded)
		}}}
		record, err := repository.BeginTenantOIDCConfigurationRecord(context.Background(), lookup)
		if err != nil || len(record.DiscoveryDocument) != documentBytes || len(record.JWKSDocument) != documentBytes {
			t.Fatalf("BeginTenantOIDCConfigurationRecord() documents = %d/%d, error = %v",
				len(record.DiscoveryDocument), len(record.JWKSDocument), err)
		}
		clear(record.DiscoveryDocument)
		clear(record.JWKSDocument)
	})

	t.Run("rejects response above configuration wire limit", func(t *testing.T) {
		oversized := bytes.Repeat([]byte{'x'}, maximumFederatedConfigurationResponseBytes+1)
		repository := &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(
			context.Context,
			string,
			...any,
		) pgx.Row {
			return federatedAuthJSONRow(oversized)
		}}}
		if _, err := repository.BeginTenantOIDCConfigurationRecord(
			context.Background(), lookup,
		); !errors.Is(err, errFederatedAuthPersistence) {
			t.Fatalf("oversized configuration response error = %v", err)
		}
	})
}

func TestFederatedAuthConfigurationRecordsAcceptBoundPlatformRowsAndOwnClaimPolicies(t *testing.T) {
	oidc := postgresOIDCConfigurationRecordWire(t, postgresOIDCCreateFixture().Current.Pins)
	oidc.IDTokenClaims = federatedoidc.ClaimExtractionPolicy{
		Scalars: []federatedoidc.ScalarClaimRule{{Claim: "department", Required: true}},
		Groups:  &federatedoidc.StringArrayClaimRule{Claim: "groups"},
		ACR:     &federatedoidc.ScalarClaimRule{Claim: "acr"},
		AMR:     &federatedoidc.StringArrayClaimRule{Claim: "amr"},
	}
	record, err := tenantOIDCConfigurationRecordFromWire(oidc)
	if err != nil {
		t.Fatal(err)
	}
	oidc.IDTokenClaims.Scalars[0].Claim = "mutated"
	oidc.IDTokenClaims.Groups.Claim = "mutated"
	oidc.IDTokenClaims.ACR.Claim = "mutated"
	oidc.IDTokenClaims.AMR.Claim = "mutated"
	if record.IDTokenClaims.Scalars[0].Claim != "department" || record.IDTokenClaims.Groups.Claim != "groups" ||
		record.IDTokenClaims.ACR.Claim != "acr" || record.IDTokenClaims.AMR.Claim != "amr" {
		t.Fatal("OIDC configuration record aliases database claim-policy storage")
	}

	platformPins := postgresPlatformOIDCCreateFixture().Current.Pins
	platform := postgresOIDCConfigurationRecordWire(t, platformPins)
	platformRecord, err := tenantOIDCConfigurationRecordFromWire(platform)
	if err != nil || platformRecord.Authorization.Provider != platformPins.Provider ||
		platformRecord.Authorization.Admission != platformPins.Admission ||
		platformRecord.Authorization.BindingID != (identity.EntityID{}) {
		t.Fatalf("tenant-bound platform OIDC configuration = %s, %v", platformRecord, err)
	}
	platform.Authorization.Admission = nil
	if _, err := tenantOIDCConfigurationRecordFromWire(platform); !errors.Is(err, errFederatedAuthPersistence) {
		t.Fatalf("platform OIDC configuration without admission accepted: %v", err)
	}
	tenantWithAdmission := postgresOIDCConfigurationRecordWire(t, postgresOIDCCreateFixture().Current.Pins)
	admissionWire, err := tenantAdmissionToWire(identity.TenantAdmissionContext{
		TenantID: postgresFederatedID(1), BindingID: postgresFederatedID(4),
	})
	if err != nil {
		t.Fatal(err)
	}
	tenantWithAdmission.Authorization.Admission = &admissionWire
	if _, err := tenantOIDCConfigurationRecordFromWire(tenantWithAdmission); !errors.Is(err, errFederatedAuthPersistence) {
		t.Fatalf("tenant OIDC configuration with additive admission accepted: %v", err)
	}

	saml := postgresSAMLConfigurationRecordWire(t, postgresSAMLCreateFixture().Current.Pins)
	saml.Authentication.Provider.Scope = federatedPlatformProviderScopeWire
	saml.Authentication.Provider.TenantID = ""
	if _, err := tenantSAMLConfigurationRecordFromWire(saml); !errors.Is(err, errFederatedAuthPersistence) {
		t.Fatalf("tenant SAML configuration accepted platform provider: %v", err)
	}
}

func TestFederatedAuthRepositoryLoadsPinnedOIDCTrustSnapshot(t *testing.T) {
	lookup := federatedauth.OIDCTrustLookup{
		TenantID: postgresFederatedID(71),
		Provider: identity.ProviderContext{
			Scope: identity.TenantProviderScope, TenantID: postgresFederatedID(71), ProviderID: postgresFederatedID(72),
		},
		BindingID: postgresFederatedID(73), ProviderRevision: 2, BindingRevision: 3,
		SecurityRevision: 4, AssurancePolicyRevision: 5,
	}
	wireLookup, err := oidcTrustLookupToWire(lookup)
	if err != nil {
		t.Fatal(err)
	}
	acr := "urn:example:mfa"
	response := oidcTrustSnapshotWire{Lookup: wireLookup, Rules: []oidcTrustRuleWire{{
		RuleID: federatedEntityIDString(t, postgresFederatedID(74)), Revision: 6, Enabled: true,
		Level: "phishing_resistant", ACR: &acr, RequiredAMR: []string{"hwk", "mfa"},
		MaximumAuthenticationAge: int64((2 * time.Hour) / time.Second),
	}}}
	var retainedPayload, retainedRow []byte
	repository := &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(
		_ context.Context,
		query string,
		arguments ...any,
	) pgx.Row {
		if query != loadOIDCTrustSnapshotSQL || len(arguments) != 1 {
			t.Fatalf("trust query = %s args=%d", query, len(arguments))
		}
		retainedPayload = arguments[0].([]byte)
		var request oidcTrustLookupWire
		if err := json.Unmarshal(retainedPayload, &request); err != nil || request != wireLookup {
			t.Fatalf("trust lookup wire = %#v, %v", request, err)
		}
		retainedRow, err = json.Marshal(response)
		if err != nil {
			t.Fatal(err)
		}
		return federatedAuthJSONRow(retainedRow)
	}}}

	snapshot, err := repository.LoadOIDCTrustSnapshot(context.Background(), lookup)
	if err != nil || snapshot.OIDCTrustLookup != lookup || len(snapshot.Rules) != 1 ||
		snapshot.Rules[0].Level != identity.AssurancePhishingResistant || snapshot.Rules[0].ACR == nil ||
		*snapshot.Rules[0].ACR != acr || fmt.Sprint(snapshot.Rules[0].RequiredAMR) != "[hwk mfa]" {
		t.Fatalf("LoadOIDCTrustSnapshot() = %s, %v", snapshot, err)
	}
	if !allZeroFederatedBytes(retainedPayload) || !allZeroFederatedBytes(retainedRow) {
		t.Fatal("trust persistence retained wire material")
	}
	if snapshot.Rules[0].ACR == nil || *snapshot.Rules[0].ACR == "" || len(snapshot.Rules[0].RequiredAMR) == 0 {
		t.Fatal("trust snapshot aliases cleared database projection")
	}
}

func TestFederatedAuthRepositoryLoadsPlatformOIDCTrustThroughTenantAdmission(t *testing.T) {
	lookup := federatedauth.OIDCTrustLookup{
		TenantID: postgresFederatedID(71),
		Provider: identity.ProviderContext{
			Scope: identity.PlatformProviderScope, ProviderID: postgresFederatedID(72),
		},
		BindingID: postgresFederatedID(73), ProviderRevision: 2, BindingRevision: 3,
		SecurityRevision: 4, AssurancePolicyRevision: 5,
	}
	wire, err := oidcTrustLookupToWire(lookup)
	if err != nil || wire.Admission == nil || wire.Provider.BindingID != "" {
		t.Fatalf("platform trust lookup wire = %#v, %v", wire, err)
	}
	repository := &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(
		_ context.Context,
		query string,
		arguments ...any,
	) pgx.Row {
		if query != loadOIDCTrustSnapshotSQL {
			t.Fatalf("platform trust query = %q", query)
		}
		var request oidcTrustLookupWire
		if err := json.Unmarshal(arguments[0].([]byte), &request); err != nil || request.Admission == nil ||
			*request.Admission != *wire.Admission {
			t.Fatalf("platform trust request = %#v, %v", request, err)
		}
		return federatedAuthJSONRow(mustFederatedJSON(t, oidcTrustSnapshotWire{Lookup: request, Rules: []oidcTrustRuleWire{}}))
	}}}
	snapshot, err := repository.LoadOIDCTrustSnapshot(context.Background(), lookup)
	if err != nil || snapshot.OIDCTrustLookup != lookup || len(snapshot.Rules) != 0 {
		t.Fatalf("LoadOIDCTrustSnapshot() = %s, %v", snapshot, err)
	}
}

func TestFederatedAuthRepositoryRejectsMalformedOIDCTrustProjection(t *testing.T) {
	lookup := federatedauth.OIDCTrustLookup{
		TenantID: postgresFederatedID(81),
		Provider: identity.ProviderContext{
			Scope: identity.TenantProviderScope, TenantID: postgresFederatedID(81), ProviderID: postgresFederatedID(82),
		},
		BindingID: postgresFederatedID(83), ProviderRevision: 1, BindingRevision: 2,
		SecurityRevision: 3, AssurancePolicyRevision: 4,
	}
	wireLookup, err := oidcTrustLookupToWire(lookup)
	if err != nil {
		t.Fatal(err)
	}
	valid := oidcTrustSnapshotWire{Lookup: wireLookup, Rules: []oidcTrustRuleWire{{
		RuleID: federatedEntityIDString(t, postgresFederatedID(84)), Revision: 1, Enabled: true,
		Level: "mfa", RequiredAMR: []string{"mfa"}, MaximumAuthenticationAge: 60,
	}}}
	for name, mutate := range map[string]func(*oidcTrustSnapshotWire){
		"lookup drift": func(value *oidcTrustSnapshotWire) { value.Lookup.SecurityRevision++ },
		"platform row without admission": func(value *oidcTrustSnapshotWire) {
			value.Lookup.Provider.Scope = federatedPlatformProviderScopeWire
			value.Lookup.Provider.TenantID = ""
		},
		"duplicate rule": func(value *oidcTrustSnapshotWire) { value.Rules = append(value.Rules, value.Rules[0]) },
		"primary level":  func(value *oidcTrustSnapshotWire) { value.Rules[0].Level = "primary" },
		"unsorted amr":   func(value *oidcTrustSnapshotWire) { value.Rules[0].RequiredAMR = []string{"mfa", "hwk"} },
		"duplicate amr":  func(value *oidcTrustSnapshotWire) { value.Rules[0].RequiredAMR = []string{"mfa", "mfa"} },
		"directional":    func(value *oidcTrustSnapshotWire) { value.Rules[0].RequiredAMR = []string{"mfa\u202e"} },
		"unbounded age": func(value *oidcTrustSnapshotWire) {
			value.Rules[0].MaximumAuthenticationAge = int64((30*24*time.Hour)/time.Second) + 1
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			candidate.Rules = append([]oidcTrustRuleWire(nil), valid.Rules...)
			candidate.Rules[0].RequiredAMR = append([]string(nil), valid.Rules[0].RequiredAMR...)
			mutate(&candidate)
			if _, err := oidcTrustSnapshotFromWire(candidate, lookup); !errors.Is(err, errFederatedAuthPersistence) {
				t.Fatalf("malformed trust projection accepted: %v", err)
			}
		})
	}
}

func TestFederatedAuthRepositoryLoadsExactFederatedPlanningState(t *testing.T) {
	for _, existing := range []bool{false, true} {
		name := "new identity"
		if existing {
			name = "existing identity"
		}
		t.Run(name, func(t *testing.T) {
			lookup, response := postgresFederatedPlanningFixture(t, existing)
			postgresJSONZone := time.FixedZone("postgres-json", 2*60*60)
			effectiveUntil := time.Date(2026, time.August, 27, 14, 0, 0, 0, time.UTC).In(postgresJSONZone)
			enrollmentDeadline := effectiveUntil.Add(time.Hour)
			response.Mapping.EffectiveUntil = &effectiveUntil
			response.Requirement.EnrollmentDeadline = &enrollmentDeadline
			var retainedPayload, retainedRow []byte
			repository := &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(
				_ context.Context,
				query string,
				arguments ...any,
			) pgx.Row {
				if query != loadFederatedAuthenticationPlanningStateSQL || len(arguments) != 1 {
					t.Fatalf("planning query = %s args=%d", query, len(arguments))
				}
				retainedPayload = arguments[0].([]byte)
				var request federatedPlanningLookupWire
				if err := json.Unmarshal(retainedPayload, &request); err != nil {
					t.Fatalf("decode planning request: %v", err)
				}
				decoded, err := federatedPlanningLookupFromWire(request)
				if err != nil || !sameFederatedPlanningLookup(decoded, lookup) {
					t.Fatalf("planning lookup = %s, %v", decoded, err)
				}
				retainedRow, err = json.Marshal(response)
				if err != nil {
					t.Fatal(err)
				}
				return federatedAuthJSONRow(retainedRow)
			}}}

			state, err := repository.LoadFederatedPlanningState(context.Background(), lookup)
			if err != nil || state.PlanRevision != 21 || state.ExternalIdentityID != postgresFederatedID(94) ||
				state.ProviderRevision != lookup.ProviderRevision || state.Mapping.TenantID != lookup.TenantID ||
				len(state.Mapping.Rules) != 1 || len(state.Requirement.PolicyRevisions) != 1 ||
				state.Mapping.EffectiveUntil == nil || state.Mapping.EffectiveUntil.Location() != time.UTC ||
				state.Requirement.EnrollmentDeadline == nil ||
				state.Requirement.EnrollmentDeadline.Location() != time.UTC {
				t.Fatalf("LoadFederatedPlanningState() = %s, %v", state, err)
			}
			if existing != (state.UserID != (identity.EntityID{})) || existing != (state.SubjectMatch != nil) {
				t.Fatalf("identity collision projection mismatch: %s", state)
			}
			if !allZeroFederatedBytes(retainedPayload) || !allZeroFederatedBytes(retainedRow) {
				t.Fatal("planning persistence retained subject aliases or mapping material")
			}

			subject, err := identity.CanonicalUTF8Exact([]byte("opaque-subject"))
			if err != nil {
				t.Fatal(err)
			}
			defer subject.Clear()
			observation, err := identity.NewFederatedMappingObservation(identity.FederatedMappingObservationInput{
				Subject: subject, Groups: []string{"incident-command"}, Complete: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			plan, err := identity.PlanFederatedMapping(observation, state.Mapping)
			if err != nil || plan.Disposition() != identity.LDAPPlanAdmitted ||
				len(plan.ProspectiveSecurityGroupIDs()) != 1 || len(plan.ProspectiveRoleIDs()) != 1 {
				t.Fatalf("restored mapping plan = %s, %v", plan, err)
			}
		})
	}
}

func TestFederatedAuthRepositoryLoadsNonAuthorizingPlatformPlanningState(t *testing.T) {
	lookup, response := postgresPlatformFederatedPlanningFixture(t, true)
	repository := &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(
		_ context.Context,
		query string,
		arguments ...any,
	) pgx.Row {
		if query != loadFederatedAuthenticationPlanningStateSQL {
			t.Fatalf("platform planning query = %q", query)
		}
		var request federatedPlanningLookupWire
		if err := json.Unmarshal(arguments[0].([]byte), &request); err != nil || request.Admission == nil ||
			request.Provider.Scope != federatedPlatformProviderScopeWire || request.Provider.BindingID != "" {
			t.Fatalf("platform planning request = %#v, %v", request, err)
		}
		return federatedAuthJSONRow(mustFederatedJSON(t, response))
	}}}
	state, err := repository.LoadFederatedPlanningState(context.Background(), lookup)
	if err != nil || state.Mapping.Provider != lookup.Provider || state.Mapping.BindingID != lookup.BindingID ||
		len(state.Mapping.Rules) != 0 || len(state.Mapping.SecurityGroups) != 0 ||
		len(state.Mapping.RolePolicies) != 0 {
		t.Fatalf("LoadFederatedPlanningState() = %s, %v", state, err)
	}
	subject, err := identity.CanonicalUTF8Exact([]byte("platform-subject"))
	if err != nil {
		t.Fatal(err)
	}
	defer subject.Clear()
	observation, err := identity.NewFederatedMappingObservation(identity.FederatedMappingObservationInput{
		Subject: subject, Groups: []string{"provider-group-must-not-authorize"}, Complete: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := identity.PlanFederatedMapping(observation, state.Mapping)
	if err != nil || plan.Disposition() != identity.LDAPPlanAdmitted ||
		len(plan.ProspectiveSecurityGroupIDs()) != 0 || len(plan.ProspectiveRoleIDs()) != 0 ||
		len(plan.Changes()) != 0 {
		t.Fatalf("platform mapping plan = %s, %v", plan, err)
	}
}

func TestFederatedAuthRepositoryRejectsPlanningDriftCollisionAndMalformedMapping(t *testing.T) {
	lookup, valid := postgresFederatedPlanningFixture(t, true)
	samlLookup, samlValid := postgresFederatedPlanningFixture(t, false)
	samlLookup.Protocol = federatedauth.ProtocolSAML
	samlValid.Lookup.Protocol = string(federatedauth.ProtocolSAML)
	if state, err := federatedPlanningStateFromWire(samlValid, samlLookup); err != nil ||
		state.UserID != (identity.EntityID{}) || state.SubjectMatch != nil {
		t.Fatalf("valid SAML planning projection rejected: %s, %v", state, err)
	}
	for name, mutate := range map[string]func(*federatedPlanningStateWire){
		"lookup alias drift": func(value *federatedPlanningStateWire) { value.Lookup.SubjectAliases[0].Digest[0] ^= 0xff },
		"top revision drift": func(value *federatedPlanningStateWire) { value.SecurityRevision++ },
		"unknown protocol":   func(value *federatedPlanningStateWire) { value.Lookup.Protocol = "wsfed" },
		"mapping tenant drift": func(value *federatedPlanningStateWire) {
			value.Mapping.TenantID = federatedEntityIDString(t, postgresFederatedID(120))
		},
		"missing exact match": func(value *federatedPlanningStateWire) { value.SubjectMatch = nil },
		"foreign match alias": func(value *federatedPlanningStateWire) { value.SubjectMatch.Alias.Digest[0] ^= 0xff },
		"lifecycle contradiction": func(value *federatedPlanningStateWire) {
			value.Mapping.ProviderAccess.ExternalIdentityExists = false
		},
		"unknown JIT":     func(value *federatedPlanningStateWire) { value.Mapping.JITMode = "link_by_email" },
		"unknown matcher": func(value *federatedPlanningStateWire) { value.Mapping.Rules[0].Matcher.Kind = "regex" },
		"control matcher": func(value *federatedPlanningStateWire) { value.Mapping.Rules[0].Matcher.Value = "group\n" },
		"duplicate policy": func(value *federatedPlanningStateWire) {
			value.Requirement.PolicyRevisions = append(
				value.Requirement.PolicyRevisions, value.Requirement.PolicyRevisions[0],
			)
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := cloneFederatedPlanningStateWireForTest(t, valid)
			mutate(&candidate)
			if _, err := federatedPlanningStateFromWire(candidate, lookup); !errors.Is(err, errFederatedAuthPersistence) {
				t.Fatalf("malformed planning projection accepted: %v", err)
			}
		})
	}

	newLookup, newIdentity := postgresFederatedPlanningFixture(t, false)
	newIdentity.Mapping.ProviderAccess.ExternalIdentityExists = true
	if _, err := federatedPlanningStateFromWire(newIdentity, newLookup); !errors.Is(err, errFederatedAuthPersistence) {
		t.Fatalf("new identity with existing access projection accepted: %v", err)
	}

	called := false
	repository := &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(
		context.Context,
		string,
		...any,
	) pgx.Row {
		called = true
		return federatedAuthJSONRow(nil)
	}}}
	platform := lookup
	platform.Provider.Scope = identity.PlatformProviderScope
	platform.Provider.TenantID = identity.EntityID{}
	if _, err := repository.LoadFederatedPlanningState(context.Background(), platform); !errors.Is(err, errFederatedAuthPersistence) {
		t.Fatalf("platform planning lookup error = %v", err)
	}
	if called {
		t.Fatal("invalid planning lookup reached persistence")
	}
}

func TestFederatedAuthRepositoryRejectsSecretProjectionDrift(t *testing.T) {
	oidcLookup := federatedauth.ClientSecretContext{
		Provider: identity.ProviderContext{
			Scope: identity.TenantProviderScope, TenantID: postgresFederatedID(51), ProviderID: postgresFederatedID(52),
		},
		BindingID: postgresFederatedID(53), Revision: 3,
	}
	samlLookup := federatedsaml.SPKeyRequest{
		Provider: identity.ProviderContext{
			Scope: identity.TenantProviderScope, TenantID: postgresFederatedID(61), ProviderID: postgresFederatedID(62),
		},
		BindingID: postgresFederatedID(63), KeyRevision: 4,
	}
	for name, queryAndResponse := range map[string]struct {
		query    string
		response any
	}{
		"OIDC lookup drift": {
			query: loadOIDCClientSecretEnvelopeSQL,
			response: oidcClientSecretEnvelopeWire{
				Lookup: oidcClientSecretLookupWire{
					Provider: mustProviderBindingWire(t, oidcLookup.Provider, oidcLookup.BindingID, true), Revision: 99,
				},
				SecretID: federatedEntityIDString(t, postgresFederatedID(54)), KeyVersion: 1,
				Nonce: bytes.Repeat([]byte{1}, oidcClientSecretNonceBytes), Ciphertext: bytes.Repeat([]byte{2}, 32),
			},
		},
		"SAML duplicate certificate": {
			query: loadSAMLSPKeyEnvelopeSQL,
			response: samlSPKeyEnvelopeWire{
				Lookup: samlSPKeyLookupWire{
					Provider: mustProviderBindingWire(t, samlLookup.Provider, samlLookup.BindingID, false),
					Revision: uint64(samlLookup.KeyRevision),
				},
				KeyID: federatedEntityIDString(t, postgresFederatedID(64)), EnvelopeKeyVersion: 1,
				EnvelopeCiphertext: []byte("sealed"), CertificateDER: [][]byte{{1, 2}, {1, 2}},
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			repository := &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(
				_ context.Context,
				query string,
				_ ...any,
			) pgx.Row {
				if query != queryAndResponse.query {
					t.Fatalf("query = %q", query)
				}
				encoded, err := json.Marshal(queryAndResponse.response)
				if err != nil {
					t.Fatal(err)
				}
				return federatedAuthJSONRow(encoded)
			}}}
			var err error
			if strings.HasPrefix(name, "OIDC") {
				_, err = repository.LoadOIDCClientSecretEnvelope(context.Background(), oidcLookup)
			} else {
				_, err = repository.LoadSAMLSPKeyEnvelope(context.Background(), samlLookup)
			}
			if !errors.Is(err, errFederatedAuthPersistence) {
				t.Fatalf("load error = %v", err)
			}
		})
	}
}

func TestFederatedAuthRepositoryFormattingRedactsState(t *testing.T) {
	const canary = "federated-postgres-canary"
	repository := &FederatedAuthRepository{}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		output := fmt.Sprintf(format, repository)
		if strings.Contains(output, canary) || strings.Contains(output, "queryer:") {
			t.Fatalf("repository formatting leaked state with %s: %s", format, output)
		}
	}
}

func federatedAuthJSONRow(encoded []byte) pgx.Row {
	return federatedAuthRowFunc(func(destinations ...any) error {
		if len(destinations) != 1 {
			return fmt.Errorf("destination count = %d", len(destinations))
		}
		*destinations[0].(*[]byte) = encoded
		return nil
	})
}

func mustFederatedJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func federatedEntityIDString(t *testing.T, value identity.EntityID) string {
	t.Helper()
	wire, err := requiredFederatedEntityIDWire(value)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func mustProviderBindingWire(
	t *testing.T,
	provider identity.ProviderContext,
	binding identity.EntityID,
	allowPlatformWithoutBinding bool,
) federatedProviderBindingWire {
	t.Helper()
	wire, err := providerBindingToWire(provider, binding, allowPlatformWithoutBinding)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func postgresOIDCCreateFixture() federatedoidc.CreateTransactionRequest {
	now := time.Date(2026, time.August, 26, 14, 0, 0, 0, time.UTC)
	provider := identity.ProviderContext{
		Scope: identity.TenantProviderScope, TenantID: postgresFederatedID(1), ProviderID: postgresFederatedID(2),
	}
	request := federatedoidc.CreateTransactionRequest{
		Begin: federatedoidc.AuthorizationBegin{
			OperationRunID: postgresFederatedID(3), ReceiptDigest: [sha256Size]byte{1},
			NetworkDigest: [sha256Size]byte{2}, AccountDigest: [sha256Size]byte{3}, ProviderDigest: [sha256Size]byte{4},
		},
		Current: federatedoidc.PendingTransaction{
			ID: postgresOIDCTransactionID(1), StateDigest: [sha256Size]byte{5}, BrowserDigest: [sha256Size]byte{6},
			NonceDigest: [sha256Size]byte{7},
			Verifier:    federatedoidc.ProtectedVerifier{KeyVersion: 1, Ciphertext: []byte("sealed-pkce-0001")},
			Pins: federatedoidc.TransactionPins{
				Provider: provider, BindingID: postgresFederatedID(4), ProviderRevision: 1, BindingRevision: 2,
				ConfigurationRevision: 3, SecurityRevision: 4, MappingRevision: 5, AuthorizationRevision: 6,
				AssurancePolicyRevision: 7, ClientSecretRevision: 8, DiscoveryRevision: 9,
				DiscoveryDigest: [sha256Size]byte{8}, JWKSRevision: 10, JWKSDigest: [sha256Size]byte{9},
			},
			ClientID: "client", RedirectURI: "https://app.example.test/oidc/callback",
			PostLogoutRedirectURI: "https://app.example.test/logout", ReturnPath: "/cases",
			Scopes: []string{federatedoidc.RequiredScopeOpenID}, CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute),
			State: federatedoidc.TransactionPending, Version: 1,
		},
	}
	request.Current.MaterialID = request.Begin.OperationRunID
	return request
}

func postgresPlatformOIDCCreateFixture() federatedoidc.CreateTransactionRequest {
	request := postgresOIDCCreateFixture()
	request.Current.Pins.Provider = identity.ProviderContext{
		Scope: identity.PlatformProviderScope, ProviderID: postgresFederatedID(2),
	}
	request.Current.Pins.Admission = identity.TenantAdmissionContext{
		TenantID: postgresFederatedID(1), BindingID: postgresFederatedID(4),
	}
	request.Current.Pins.BindingID = identity.EntityID{}
	request.Current.RedirectURI = "https://app.example.test/api/v1/auth/federated/oidc/callback"
	return request
}

func postgresSAMLCreateFixture() federatedsaml.CreateTransactionRequest {
	now := time.Date(2026, time.August, 26, 14, 0, 0, 0, time.UTC)
	provider := identity.ProviderContext{
		Scope: identity.TenantProviderScope, TenantID: postgresFederatedID(11), ProviderID: postgresFederatedID(12),
	}
	return federatedsaml.CreateTransactionRequest{
		Begin: federatedsaml.AuthenticationBegin{
			OperationRunID: postgresFederatedID(13), ReceiptDigest: [sha256Size]byte{11},
			NetworkDigest: [sha256Size]byte{12}, AccountDigest: [sha256Size]byte{13}, ProviderDigest: [sha256Size]byte{14},
		},
		Current: federatedsaml.PendingTransaction{
			ID: postgresSAMLTransactionID(1), MaterialID: postgresFederatedID(13),
			RequestID: "_request", RelayStateDigest: [sha256Size]byte{15},
			BrowserDigest: [sha256Size]byte{16},
			Pins: federatedsaml.TransactionPins{
				Provider: provider, BindingID: postgresFederatedID(14), ProviderRevision: 1, BindingRevision: 2,
				ConfigurationRevision: 3, SecurityRevision: 4, MappingRevision: 5, AuthorizationRevision: 6,
				AssurancePolicyRevision: 7, MetadataRevision: 8, MetadataDigest: [sha256Size]byte{17},
				SPKeyRevision: 9, ConfigurationDigest: [sha256Size]byte{18},
			},
			CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute), ReturnPath: "/cases",
			State: federatedsaml.TransactionPending, Version: 1,
		},
	}
}

func postgresOIDCConfigurationRecordWire(
	t *testing.T,
	pins federatedoidc.TransactionPins,
) tenantOIDCConfigurationRecordWire {
	t.Helper()
	provider, admission, err := oidcProviderAdmissionToWire(pins.Provider, pins.BindingID, pins.Admission)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.August, 26, 13, 55, 0, 0, time.UTC)
	return tenantOIDCConfigurationRecordWire{
		Authorization: oidcAuthorizationConfigurationWire{
			Provider: provider, Admission: admission,
			ProviderRevision: pins.ProviderRevision, BindingRevision: pins.BindingRevision,
			ConfigurationRevision: pins.ConfigurationRevision, SecurityRevision: pins.SecurityRevision,
			MappingRevision: pins.MappingRevision, AuthorizationRevision: pins.AuthorizationRevision,
			AssurancePolicyRevision: pins.AssurancePolicyRevision, ClientSecretRevision: pins.ClientSecretRevision,
			ClientID: "client", RedirectURI: "https://app.example.test/oidc/callback",
			PostLogoutRedirectURI: "https://app.example.test/logout", ExtraScopes: []string{"profile"},
		},
		Issuer: "https://idp.example.test", DiscoveryRevision: pins.DiscoveryRevision,
		DiscoveryDocument: []byte(`{"issuer":"https://idp.example.test"}`),
		DiscoveryDigest:   append([]byte(nil), pins.DiscoveryDigest[:]...),
		DiscoveryCache: federatedCacheMetadataWire{
			RetrievedAt: now, FreshUntil: now.Add(time.Hour), Cacheable: true,
		},
		DiscoveryPolicy: oidcTrustPolicyWire{
			ClientAuthentication: string(federatedoidc.ClientSecretBasic), SigningAlgorithms: []string{"RS256"},
		},
		JWKSDocument: []byte(`{"keys":[]}`), JWKSDigest: append([]byte(nil), pins.JWKSDigest[:]...),
		JWKSRevision: pins.JWKSRevision,
		JWKSCache:    federatedCacheMetadataWire{RetrievedAt: now, FreshUntil: now.Add(time.Hour), Cacheable: true},
	}
}

func postgresSAMLConfigurationRecordWire(
	t *testing.T,
	pins federatedsaml.TransactionPins,
) tenantSAMLConfigurationRecordWire {
	t.Helper()
	provider := mustProviderBindingWire(t, pins.Provider, pins.BindingID, false)
	now := time.Date(2026, time.August, 26, 13, 55, 0, 0, time.UTC)
	return tenantSAMLConfigurationRecordWire{
		Authentication: samlAuthenticationConfigurationWire{
			Provider: provider, ProviderRevision: pins.ProviderRevision, BindingRevision: pins.BindingRevision,
			ConfigurationRevision: pins.ConfigurationRevision, SecurityRevision: pins.SecurityRevision,
			MappingRevision: pins.MappingRevision, AuthorizationRevision: pins.AuthorizationRevision,
			AssurancePolicyRevision: pins.AssurancePolicyRevision,
			SPEntityID:              "https://app.example.test/saml/sp", ACSURL: "https://app.example.test/saml/acs",
			SPKeyRevision: pins.SPKeyRevision, RedirectSignatureAlgorithm: federatedsaml.RedirectRSASHA256,
			SignaturePolicy: federatedsaml.SignedAssertion, EncryptionPolicy: federatedsaml.EncryptionOptional,
			DecryptionKeyVersions: []uint32{1}, Subject: federatedsaml.SubjectPolicy{
				Source: federatedsaml.SubjectPersistentNameID,
			},
			ClockSkew: time.Minute, MaxAuthenticationAge: time.Hour,
		},
		ExpectedEntityID: "https://idp.example.test/saml", MetadataRevision: pins.MetadataRevision,
		MetadataDocument: []byte(`<EntityDescriptor/>`), MetadataDigest: append([]byte(nil), pins.MetadataDigest[:]...),
		MetadataRetrievedAt: now, MetadataMaximumValidUntil: now.Add(24 * time.Hour),
	}
}

func postgresFederatedPlanningFixture(
	t *testing.T,
	existing bool,
) (federatedauth.FederatedPlanningLookup, federatedPlanningStateWire) {
	t.Helper()
	tenantID := postgresFederatedID(90)
	provider := identity.ProviderContext{
		Scope: identity.TenantProviderScope, TenantID: tenantID, ProviderID: postgresFederatedID(91),
	}
	bindingID := postgresFederatedID(92)
	lookup := federatedauth.FederatedPlanningLookup{
		Protocol: federatedauth.ProtocolOIDC, TenantID: tenantID, Provider: provider, BindingID: bindingID,
		SubjectFormat: identity.UTF8ExactSubject,
		SubjectAliases: []identity.SubjectAlias{
			{KeyVersion: 1, Digest: [sha256Size]byte{1}},
			{KeyVersion: 2, Digest: [sha256Size]byte{2}},
		},
		ProviderRevision: 10, BindingRevision: 11, ConfigurationRevision: 12,
		SecurityRevision: 13, MappingRevision: 14, AuthorizationRevision: 15,
		AssurancePolicyRevision: 16,
	}
	wireLookup, err := federatedPlanningLookupToWire(lookup)
	if err != nil {
		t.Fatal(err)
	}
	groupID := uuid.UUID(postgresFederatedID(98))
	roleID := uuid.UUID(postgresFederatedID(99))
	response := federatedPlanningStateWire{
		Lookup: wireLookup, PlanRevision: 21,
		ExternalIdentityID: federatedEntityIDString(t, postgresFederatedID(94)),
		ProviderRevision:   lookup.ProviderRevision, BindingRevision: lookup.BindingRevision,
		SecurityRevision: lookup.SecurityRevision, AssurancePolicyRevision: lookup.AssurancePolicyRevision,
		Mapping: federatedMappingPlanningSnapshotWire{
			TenantID:              federatedEntityIDString(t, tenantID),
			Provider:              mustProviderBindingWire(t, provider, bindingID, false),
			ConfigurationRevision: int64(lookup.ConfigurationRevision), RuleSetRevision: int64(lookup.MappingRevision),
			AuthorizationRevision: int64(lookup.AuthorizationRevision), JITMode: "create", NoMatchPolicy: "deny",
			ProviderAccess: federatedProviderAccessWire{
				SourceID:      federatedEntityIDString(t, postgresFederatedID(95)),
				AccessEpochID: federatedEntityIDString(t, postgresFederatedID(96)),
			},
			Rules: []federatedPlanningRuleWire{{
				RuleID: uuid.UUID(postgresFederatedID(100)), RuleEpochID: uuid.UUID(postgresFederatedID(101)),
				SourceID: uuid.UUID(postgresFederatedID(102)), Revision: 1, Priority: 10, Enabled: true,
				Matcher:            federatedMappingMatcherWire{Kind: "group_equals", Value: "incident-command"},
				ReconciliationMode: "authoritative", SecurityGroupID: groupID, RoleIDs: []uuid.UUID{roleID},
			}},
			SecurityGroups: []ldapPlanningSecurityGroupDocument{{SecurityGroupID: groupID}},
			RolePolicies:   []ldapPlanningRolePolicyDocument{{RoleID: roleID}},
		},
		Requirement: assuranceRequirementWire{
			Level: "primary", PolicyRevisions: []policyRevisionWire{{
				PolicyID: federatedEntityIDString(t, postgresFederatedID(103)), Revision: 16,
			}},
		},
		HasEnrollableFactor: true,
	}
	if existing {
		response.UserID = federatedEntityIDString(t, postgresFederatedID(104))
		response.IdentityEpoch = 7
		response.SubjectMatch = &federatedSubjectMatchWire{
			ExternalIdentityID: response.ExternalIdentityID,
			Alias: federatedSubjectAliasWire{
				KeyVersion: wireLookup.SubjectAliases[1].KeyVersion,
				Digest:     append([]byte(nil), wireLookup.SubjectAliases[1].Digest...),
			},
		}
		response.Mapping.ProviderAccess.ExternalIdentityExists = true
		response.Mapping.ProviderAccess.UserActive = true
		response.Mapping.ProviderAccess.TenantMembershipExists = true
		response.Mapping.ProviderAccess.TenantMembershipActive = true
		response.Mapping.ProviderAccess.AccessGrantLive = true
	}
	return lookup, response
}

func postgresPlatformFederatedPlanningFixture(
	t *testing.T,
	existing bool,
) (federatedauth.FederatedPlanningLookup, federatedPlanningStateWire) {
	t.Helper()
	lookup, response := postgresFederatedPlanningFixture(t, existing)
	lookup.Provider = identity.ProviderContext{
		Scope: identity.PlatformProviderScope, ProviderID: lookup.Provider.ProviderID,
	}
	lookup.Admission = identity.TenantAdmissionContext{TenantID: lookup.TenantID, BindingID: lookup.BindingID}
	wireLookup, err := federatedPlanningLookupToWire(lookup)
	if err != nil {
		t.Fatal(err)
	}
	provider, admission, err := providerTenantAdmissionToWire(
		lookup.Provider, lookup.TenantID, lookup.BindingID, lookup.Admission,
	)
	if err != nil {
		t.Fatal(err)
	}
	response.Lookup = wireLookup
	response.Mapping.Provider = provider
	response.Mapping.Admission = admission
	response.Mapping.NoMatchPolicy = "provider_access_only"
	response.Mapping.Rules = nil
	response.Mapping.SecurityGroups = nil
	response.Mapping.LiveAssignments = nil
	response.Mapping.RolePolicies = nil
	response.Mapping.ExistingEffectiveRoleIDs = nil
	response.Mapping.Delegation = nil
	response.Mapping.LiveOwnedEdges = nil
	return lookup, response
}

func cloneFederatedPlanningStateWireForTest(
	t *testing.T,
	value federatedPlanningStateWire,
) federatedPlanningStateWire {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	var clone federatedPlanningStateWire
	if err := json.Unmarshal(encoded, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}

const sha256Size = 32

func postgresFederatedID(seed byte) identity.EntityID {
	value := identity.EntityID{seed}
	value[6] = 0x70
	value[8] = 0x80
	return value
}

func postgresOIDCTransactionID(seed byte) federatedoidc.TransactionID {
	value := federatedoidc.TransactionID{seed}
	value[len(value)-1] = seed
	return value
}

func postgresSAMLTransactionID(seed byte) federatedsaml.TransactionID {
	value := federatedsaml.TransactionID{seed}
	value[len(value)-1] = seed
	return value
}
