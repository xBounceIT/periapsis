package federatedauth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedoidc"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
)

type federatedTransactionPersistenceFake struct {
	createOIDC func(context.Context, federatedoidc.CreateTransactionRequest) (OIDCTransactionWriteReceipt, error)
	claimOIDC  func(context.Context, federatedoidc.TransactionClaim) (federatedoidc.ClaimedTransaction, error)
	failOIDC   func(context.Context, federatedoidc.TransactionFailure) (OIDCTransactionWriteReceipt, error)
	createSAML func(context.Context, federatedsaml.CreateTransactionRequest) (SAMLTransactionWriteReceipt, error)
	lookupSAML func(context.Context, federatedsaml.LookupTransactionRequest) (federatedsaml.PendingTransaction, error)
}

func (fake federatedTransactionPersistenceFake) CreateOIDCTransaction(
	ctx context.Context,
	request federatedoidc.CreateTransactionRequest,
) (OIDCTransactionWriteReceipt, error) {
	return fake.createOIDC(ctx, request)
}

func (fake federatedTransactionPersistenceFake) ClaimOIDCTransaction(
	ctx context.Context,
	claim federatedoidc.TransactionClaim,
) (federatedoidc.ClaimedTransaction, error) {
	return fake.claimOIDC(ctx, claim)
}

func (fake federatedTransactionPersistenceFake) FailOIDCTransaction(
	ctx context.Context,
	failure federatedoidc.TransactionFailure,
) (OIDCTransactionWriteReceipt, error) {
	return fake.failOIDC(ctx, failure)
}

func (fake federatedTransactionPersistenceFake) CreateSAMLTransaction(
	ctx context.Context,
	request federatedsaml.CreateTransactionRequest,
) (SAMLTransactionWriteReceipt, error) {
	return fake.createSAML(ctx, request)
}

func (fake federatedTransactionPersistenceFake) LookupSAMLTransaction(
	ctx context.Context,
	request federatedsaml.LookupTransactionRequest,
) (federatedsaml.PendingTransaction, error) {
	return fake.lookupSAML(ctx, request)
}

func TestPersistentOIDCTransactionRepositoryPreservesAtomicLifecycle(t *testing.T) {
	create := oidcCreateTransactionFixture()
	claim := federatedoidc.TransactionClaim{
		AttemptID: federatedoidc.TransactionID{2}, StateDigest: create.Current.StateDigest,
		BrowserDigest: create.Current.BrowserDigest, ClaimedAt: create.Current.CreatedAt.Add(time.Minute),
	}
	claimed := federatedoidc.ClaimedTransaction{
		PendingTransaction: create.Current,
		ClaimAttemptID:     claim.AttemptID,
		ClaimedAt:          claim.ClaimedAt,
	}
	claimed.State, claimed.Version = federatedoidc.TransactionClaimed, 2
	failure := federatedoidc.TransactionFailure{
		ID: claimed.ID, ExpectedVersion: 2, FailedAt: claim.ClaimedAt.Add(time.Second),
		Reason: federatedoidc.FailureTokenExchange, State: federatedoidc.TransactionFailed,
	}

	var createCiphertext []byte
	var claimedCiphertext []byte
	backend := completeFederatedTransactionPersistenceFake()
	backend.createOIDC = func(
		_ context.Context,
		request federatedoidc.CreateTransactionRequest,
	) (OIDCTransactionWriteReceipt, error) {
		createCiphertext = request.Current.Verifier.Ciphertext
		request.Current.Verifier.Ciphertext[0] ^= 0xff
		request.Current.Scopes[0] = "mutated"
		return OIDCTransactionWriteReceipt{
			TransactionID: request.Current.ID, Version: request.Current.Version,
			State: request.Current.State,
		}, nil
	}
	backend.claimOIDC = func(
		_ context.Context,
		got federatedoidc.TransactionClaim,
	) (federatedoidc.ClaimedTransaction, error) {
		if got != claim {
			t.Fatalf("claim = %+v, want %+v", got, claim)
		}
		result := cloneOIDCClaimedTransaction(claimed)
		claimedCiphertext = result.Verifier.Ciphertext
		return result, nil
	}
	backend.failOIDC = func(
		_ context.Context,
		got federatedoidc.TransactionFailure,
	) (OIDCTransactionWriteReceipt, error) {
		if got != failure {
			t.Fatalf("failure = %+v, want %+v", got, failure)
		}
		return OIDCTransactionWriteReceipt{
			TransactionID: got.ID, Version: got.ExpectedVersion + 1, State: got.State, Replayed: true,
		}, nil
	}
	repository, err := NewPersistentOIDCTransactionRepository(backend)
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.CreateReplacing(context.Background(), create); err != nil {
		t.Fatalf("CreateReplacing() error = %v", err)
	}
	if create.Current.Verifier.Ciphertext[0] != '0' || create.Current.Scopes[0] != federatedoidc.RequiredScopeOpenID ||
		!allZero(createCiphertext) {
		t.Fatal("CreateReplacing() did not preserve caller ownership and clear the persistence copy")
	}
	result, err := repository.Claim(context.Background(), claim)
	if err != nil || result.State != federatedoidc.TransactionClaimed || result.Version != 2 {
		t.Fatalf("Claim() = %s, %v", result.String(), err)
	}
	if !allZero(claimedCiphertext) || len(result.Verifier.Ciphertext) == 0 || allZero(result.Verifier.Ciphertext) {
		t.Fatal("Claim() did not transfer the returned projection defensively")
	}
	if err := repository.Fail(context.Background(), failure); err != nil {
		t.Fatalf("Fail() error = %v", err)
	}
}

func TestPersistentSAMLTransactionRepositoryPreservesCreateAndLookup(t *testing.T) {
	create := samlCreateTransactionFixture()
	lookup := federatedsaml.LookupTransactionRequest{
		RelayStateDigest: create.Current.RelayStateDigest, BrowserDigest: create.Current.BrowserDigest,
		ObservedAt: create.Current.CreatedAt.Add(time.Minute),
	}
	backend := completeFederatedTransactionPersistenceFake()
	backend.createSAML = func(
		_ context.Context,
		request federatedsaml.CreateTransactionRequest,
	) (SAMLTransactionWriteReceipt, error) {
		if request != create {
			t.Fatalf("create request drifted: %+v", request)
		}
		return SAMLTransactionWriteReceipt{
			TransactionID: request.Current.ID, Version: 1, State: federatedsaml.TransactionPending,
		}, nil
	}
	backend.lookupSAML = func(
		_ context.Context,
		request federatedsaml.LookupTransactionRequest,
	) (federatedsaml.PendingTransaction, error) {
		if request != lookup {
			t.Fatalf("lookup = %+v, want %+v", request, lookup)
		}
		return create.Current, nil
	}
	repository, err := NewPersistentSAMLTransactionRepository(backend)
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.CreateReplacing(context.Background(), create); err != nil {
		t.Fatalf("CreateReplacing() error = %v", err)
	}
	if pending, err := repository.Lookup(context.Background(), lookup); err != nil || pending != create.Current {
		t.Fatalf("Lookup() = %+v, %v", pending, err)
	}
}

func TestPersistentTransactionRepositoriesRejectMalformedInputsBeforePersistence(t *testing.T) {
	called := false
	backend := completeFederatedTransactionPersistenceFake()
	backend.createOIDC = func(context.Context, federatedoidc.CreateTransactionRequest) (OIDCTransactionWriteReceipt, error) {
		called = true
		return OIDCTransactionWriteReceipt{}, nil
	}
	backend.createSAML = func(context.Context, federatedsaml.CreateTransactionRequest) (SAMLTransactionWriteReceipt, error) {
		called = true
		return SAMLTransactionWriteReceipt{}, nil
	}
	oidc, _ := NewPersistentOIDCTransactionRepository(backend)
	saml, _ := NewPersistentSAMLTransactionRepository(backend)

	invalidOIDC := oidcCreateTransactionFixture()
	invalidOIDC.Current.Verifier.Ciphertext = nil
	if err := oidc.CreateReplacing(context.Background(), invalidOIDC); !errors.Is(err, ErrFederatedPersistence) {
		t.Fatalf("invalid OIDC create error = %v", err)
	}
	invalidSAML := samlCreateTransactionFixture()
	invalidSAML.Current.Pins.ConfigurationDigest = [32]byte{}
	if err := saml.CreateReplacing(context.Background(), invalidSAML); !errors.Is(err, ErrFederatedPersistence) {
		t.Fatalf("invalid SAML create error = %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := saml.Lookup(cancelled, federatedsaml.LookupTransactionRequest{}); !errors.Is(err, ErrFederatedPersistence) {
		t.Fatalf("cancelled lookup error = %v", err)
	}
	if called {
		t.Fatal("malformed transaction reached persistence")
	}
}

func TestPersistentTransactionRepositoriesHonorCancellationAfterPersistence(t *testing.T) {
	oidcCreate := oidcCreateTransactionFixture()
	oidcClaim := federatedoidc.TransactionClaim{
		AttemptID: federatedoidc.TransactionID{2}, StateDigest: oidcCreate.Current.StateDigest,
		BrowserDigest: oidcCreate.Current.BrowserDigest, ClaimedAt: oidcCreate.Current.CreatedAt.Add(time.Minute),
	}
	oidcClaimed := federatedoidc.ClaimedTransaction{
		PendingTransaction: oidcCreate.Current, ClaimAttemptID: oidcClaim.AttemptID, ClaimedAt: oidcClaim.ClaimedAt,
	}
	oidcClaimed.State, oidcClaimed.Version = federatedoidc.TransactionClaimed, 2
	oidcFailure := federatedoidc.TransactionFailure{
		ID: oidcCreate.Current.ID, ExpectedVersion: 2, FailedAt: oidcClaim.ClaimedAt.Add(time.Second),
		Reason: federatedoidc.FailureTokenExchange, State: federatedoidc.TransactionFailed,
	}
	samlCreate := samlCreateTransactionFixture()
	samlLookup := federatedsaml.LookupTransactionRequest{
		RelayStateDigest: samlCreate.Current.RelayStateDigest, BrowserDigest: samlCreate.Current.BrowserDigest,
		ObservedAt: samlCreate.Current.CreatedAt.Add(time.Minute),
	}

	for name, exercise := range map[string]func(context.Context, federatedTransactionPersistenceFake) error{
		"OIDC create": func(ctx context.Context, backend federatedTransactionPersistenceFake) error {
			repository, _ := NewPersistentOIDCTransactionRepository(backend)
			return repository.CreateReplacing(ctx, oidcCreate)
		},
		"OIDC claim": func(ctx context.Context, backend federatedTransactionPersistenceFake) error {
			repository, _ := NewPersistentOIDCTransactionRepository(backend)
			_, err := repository.Claim(ctx, oidcClaim)
			return err
		},
		"OIDC fail": func(ctx context.Context, backend federatedTransactionPersistenceFake) error {
			repository, _ := NewPersistentOIDCTransactionRepository(backend)
			return repository.Fail(ctx, oidcFailure)
		},
		"SAML create": func(ctx context.Context, backend federatedTransactionPersistenceFake) error {
			repository, _ := NewPersistentSAMLTransactionRepository(backend)
			return repository.CreateReplacing(ctx, samlCreate)
		},
		"SAML lookup": func(ctx context.Context, backend federatedTransactionPersistenceFake) error {
			repository, _ := NewPersistentSAMLTransactionRepository(backend)
			_, err := repository.Lookup(ctx, samlLookup)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			backend := completeFederatedTransactionPersistenceFake()
			backend.createOIDC = func(context.Context, federatedoidc.CreateTransactionRequest) (OIDCTransactionWriteReceipt, error) {
				cancel()
				return OIDCTransactionWriteReceipt{
					TransactionID: oidcCreate.Current.ID, Version: 1, State: federatedoidc.TransactionPending,
				}, nil
			}
			backend.claimOIDC = func(context.Context, federatedoidc.TransactionClaim) (federatedoidc.ClaimedTransaction, error) {
				cancel()
				return cloneOIDCClaimedTransaction(oidcClaimed), nil
			}
			backend.failOIDC = func(context.Context, federatedoidc.TransactionFailure) (OIDCTransactionWriteReceipt, error) {
				cancel()
				return OIDCTransactionWriteReceipt{
					TransactionID: oidcFailure.ID, Version: 3, State: federatedoidc.TransactionFailed,
				}, nil
			}
			backend.createSAML = func(context.Context, federatedsaml.CreateTransactionRequest) (SAMLTransactionWriteReceipt, error) {
				cancel()
				return SAMLTransactionWriteReceipt{
					TransactionID: samlCreate.Current.ID, Version: 1, State: federatedsaml.TransactionPending,
				}, nil
			}
			backend.lookupSAML = func(context.Context, federatedsaml.LookupTransactionRequest) (federatedsaml.PendingTransaction, error) {
				cancel()
				return samlCreate.Current, nil
			}
			if err := exercise(ctx, backend); !errors.Is(err, ErrFederatedPersistence) {
				t.Fatalf("late-cancelled persistence error = %v", err)
			}
		})
	}
}

func TestPersistentTransactionValidationMatchesProtocolCanonicalShapes(t *testing.T) {
	t.Run("SAML material identity is the immutable operation identity", func(t *testing.T) {
		canonical := samlCreateTransactionFixture()
		if !validSAMLCreateTransactionRequest(canonical) {
			t.Fatal("canonical SAML material identity rejected")
		}
		for name, mutate := range map[string]func(*federatedsaml.CreateTransactionRequest){
			"missing": func(value *federatedsaml.CreateTransactionRequest) {
				value.Current.MaterialID = identity.EntityID{}
			},
			"different v7": func(value *federatedsaml.CreateTransactionRequest) {
				value.Current.MaterialID = serviceID(99)
			},
		} {
			t.Run(name, func(t *testing.T) {
				request := samlCreateTransactionFixture()
				mutate(&request)
				if validSAMLCreateTransactionRequest(request) {
					t.Fatal("divergent SAML material identity accepted")
				}
			})
		}
	})

	t.Run("OIDC verifier and digest boundaries", func(t *testing.T) {
		for name, mutate := range map[string]func(*federatedoidc.CreateTransactionRequest){
			"short protected verifier": func(request *federatedoidc.CreateTransactionRequest) {
				request.Current.Verifier.Ciphertext = bytes.Repeat([]byte{1}, minimumProtectedTransactionBytes-1)
			},
			"oversized protected verifier": func(request *federatedoidc.CreateTransactionRequest) {
				request.Current.Verifier.Ciphertext = bytes.Repeat([]byte{1}, maximumProtectedTransactionBytes+1)
			},
			"state nonce collision": func(request *federatedoidc.CreateTransactionRequest) {
				request.Current.NonceDigest = request.Current.StateDigest
			},
			"browser nonce collision": func(request *federatedoidc.CreateTransactionRequest) {
				request.Current.NonceDigest = request.Current.BrowserDigest
			},
			"unsorted scopes": func(request *federatedoidc.CreateTransactionRequest) {
				request.Current.Scopes = []string{federatedoidc.RequiredScopeOpenID, "z", "a"}
			},
			"scope with space": func(request *federatedoidc.CreateTransactionRequest) {
				request.Current.Scopes = []string{federatedoidc.RequiredScopeOpenID, "bad scope"}
			},
			"openid not first": func(request *federatedoidc.CreateTransactionRequest) {
				request.Current.Scopes = []string{"profile", federatedoidc.RequiredScopeOpenID}
			},
		} {
			t.Run(name, func(t *testing.T) {
				request := oidcCreateTransactionFixture()
				mutate(&request)
				if validOIDCCreateTransactionRequest(request) {
					t.Fatal("malformed OIDC transaction accepted")
				}
			})
		}
	})

	t.Run("protocol-specific platform binding", func(t *testing.T) {
		oidc := oidcCreateTransactionFixture()
		oidc.Current.Pins.Provider = identity.ProviderContext{
			Scope: identity.PlatformProviderScope, ProviderID: serviceID(40),
		}
		oidc.Current.Pins.BindingID = identity.EntityID{}
		oidc.Current.Pins.Admission = identity.TenantAdmissionContext{
			TenantID: serviceID(41), BindingID: serviceID(42),
		}
		if !validOIDCCreateTransactionRequest(oidc) {
			t.Fatal("platform OIDC provider with tenant admission rejected")
		}
		oidc.Current.Pins.Admission = identity.TenantAdmissionContext{}
		if validOIDCCreateTransactionRequest(oidc) {
			t.Fatal("platform OIDC provider without tenant admission accepted")
		}
		oidc.Current.Pins.Admission = identity.TenantAdmissionContext{
			TenantID: serviceID(41), BindingID: serviceID(42),
		}
		oidc.Current.Pins.BindingID = serviceID(43)
		if validOIDCCreateTransactionRequest(oidc) {
			t.Fatal("platform OIDC provider with cryptographic binding accepted")
		}

		saml := samlCreateTransactionFixture()
		saml.Current.Pins.Provider = identity.ProviderContext{
			Scope: identity.PlatformProviderScope, ProviderID: serviceID(42),
		}
		saml.Current.Pins.BindingID = serviceID(43)
		if !validSAMLCreateTransactionRequest(saml) {
			t.Fatal("canonical platform SAML provider binding rejected")
		}
		saml.Current.Pins.BindingID = identity.EntityID{}
		if validSAMLCreateTransactionRequest(saml) {
			t.Fatal("platform SAML provider without binding accepted")
		}
	})
}

func TestPersistentTransactionRepositoriesRejectDivergentDatabaseProjections(t *testing.T) {
	createOIDC := oidcCreateTransactionFixture()
	claim := federatedoidc.TransactionClaim{
		AttemptID: federatedoidc.TransactionID{2}, StateDigest: createOIDC.Current.StateDigest,
		BrowserDigest: createOIDC.Current.BrowserDigest, ClaimedAt: createOIDC.Current.CreatedAt.Add(time.Minute),
	}
	createSAML := samlCreateTransactionFixture()
	lookup := federatedsaml.LookupTransactionRequest{
		RelayStateDigest: createSAML.Current.RelayStateDigest, BrowserDigest: createSAML.Current.BrowserDigest,
		ObservedAt: createSAML.Current.CreatedAt.Add(time.Minute),
	}

	for name, configure := range map[string]func(*federatedTransactionPersistenceFake){
		"OIDC create version": func(fake *federatedTransactionPersistenceFake) {
			fake.createOIDC = func(context.Context, federatedoidc.CreateTransactionRequest) (OIDCTransactionWriteReceipt, error) {
				return OIDCTransactionWriteReceipt{TransactionID: createOIDC.Current.ID, Version: 2, State: federatedoidc.TransactionPending}, nil
			}
		},
		"OIDC claimed attempt": func(fake *federatedTransactionPersistenceFake) {
			fake.claimOIDC = func(context.Context, federatedoidc.TransactionClaim) (federatedoidc.ClaimedTransaction, error) {
				result := federatedoidc.ClaimedTransaction{PendingTransaction: createOIDC.Current, ClaimAttemptID: federatedoidc.TransactionID{9}, ClaimedAt: claim.ClaimedAt}
				result.State, result.Version = federatedoidc.TransactionClaimed, 2
				return result, nil
			}
		},
		"SAML lookup authority": func(fake *federatedTransactionPersistenceFake) {
			fake.lookupSAML = func(context.Context, federatedsaml.LookupTransactionRequest) (federatedsaml.PendingTransaction, error) {
				result := createSAML.Current
				result.Pins.Provider.Scope = identity.PlatformProviderScope
				return result, nil
			}
		},
		"database detail": func(fake *federatedTransactionPersistenceFake) {
			fake.createSAML = func(context.Context, federatedsaml.CreateTransactionRequest) (SAMLTransactionWriteReceipt, error) {
				return SAMLTransactionWriteReceipt{}, errors.New("relation tenant_federated_canary missing")
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			fake := completeFederatedTransactionPersistenceFake()
			configure(&fake)
			oidc, _ := NewPersistentOIDCTransactionRepository(fake)
			saml, _ := NewPersistentSAMLTransactionRepository(fake)
			var err error
			switch name {
			case "OIDC create version":
				err = oidc.CreateReplacing(context.Background(), createOIDC)
			case "OIDC claimed attempt":
				_, err = oidc.Claim(context.Background(), claim)
			case "SAML lookup authority":
				_, err = saml.Lookup(context.Background(), lookup)
			case "database detail":
				err = saml.CreateReplacing(context.Background(), createSAML)
			}
			if !errors.Is(err, ErrFederatedPersistence) || strings.Contains(err.Error(), "canary") {
				t.Fatalf("adapter error = %v", err)
			}
		})
	}
}

func TestPersistentTransactionFormattingRedactsIdentifiersAndCiphertext(t *testing.T) {
	const canary = "persistent-transaction-canary"
	values := []any{
		OIDCTransactionWriteReceipt{}, SAMLTransactionWriteReceipt{},
		&PersistentOIDCTransactionRepository{}, &PersistentSAMLTransactionRepository{},
		federatedoidc.ProtectedVerifier{Ciphertext: []byte(canary)},
	}
	for _, value := range values {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if output := fmt.Sprintf(format, value); strings.Contains(output, canary) {
				t.Fatalf("%T leaked with %s: %s", value, format, output)
			}
		}
	}
}

func completeFederatedTransactionPersistenceFake() federatedTransactionPersistenceFake {
	return federatedTransactionPersistenceFake{
		createOIDC: func(context.Context, federatedoidc.CreateTransactionRequest) (OIDCTransactionWriteReceipt, error) {
			return OIDCTransactionWriteReceipt{}, errors.New("unexpected OIDC create")
		},
		claimOIDC: func(context.Context, federatedoidc.TransactionClaim) (federatedoidc.ClaimedTransaction, error) {
			return federatedoidc.ClaimedTransaction{}, errors.New("unexpected OIDC claim")
		},
		failOIDC: func(context.Context, federatedoidc.TransactionFailure) (OIDCTransactionWriteReceipt, error) {
			return OIDCTransactionWriteReceipt{}, errors.New("unexpected OIDC fail")
		},
		createSAML: func(context.Context, federatedsaml.CreateTransactionRequest) (SAMLTransactionWriteReceipt, error) {
			return SAMLTransactionWriteReceipt{}, errors.New("unexpected SAML create")
		},
		lookupSAML: func(context.Context, federatedsaml.LookupTransactionRequest) (federatedsaml.PendingTransaction, error) {
			return federatedsaml.PendingTransaction{}, errors.New("unexpected SAML lookup")
		},
	}
}

func oidcCreateTransactionFixture() federatedoidc.CreateTransactionRequest {
	now := time.Date(2026, time.August, 26, 10, 0, 0, 0, time.UTC)
	begin := validOIDCStartLookupFixture()
	return federatedoidc.CreateTransactionRequest{
		Begin: federatedoidc.AuthorizationBegin{
			OperationRunID: begin.OperationRunID, ReceiptDigest: begin.ReceiptDigest,
			NetworkDigest: begin.NetworkDigest, AccountDigest: begin.AccountDigest, ProviderDigest: begin.ProviderDigest,
		},
		Current: federatedoidc.PendingTransaction{
			ID: federatedoidc.TransactionID{1}, MaterialID: begin.OperationRunID,
			StateDigest: [32]byte{1}, BrowserDigest: [32]byte{2},
			NonceDigest: [32]byte{3}, Verifier: federatedoidc.ProtectedVerifier{
				KeyVersion: 7, Ciphertext: []byte("0123456789abcdef"),
			},
			Pins:     oidcPinsFromRecord(tenantOIDCConfigurationRecordFixtureForTransactions()),
			ClientID: "client-exact", RedirectURI: "https://app.example.test/oidc/callback",
			PostLogoutRedirectURI: "https://app.example.test/logout/callback", ReturnPath: "/cases",
			Scopes: []string{federatedoidc.RequiredScopeOpenID}, CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute),
			State: federatedoidc.TransactionPending, Version: 1,
		},
	}
}

func tenantOIDCConfigurationRecordFixtureForTransactions() TenantOIDCConfigurationRecord {
	tenantID := serviceID(1)
	return TenantOIDCConfigurationRecord{
		Authorization: federatedoidc.AuthorizationConfiguration{
			Provider:  identity.ProviderContext{Scope: identity.TenantProviderScope, TenantID: tenantID, ProviderID: serviceID(2)},
			BindingID: serviceID(3), ProviderRevision: 1, BindingRevision: 2, ConfigurationRevision: 3,
			SecurityRevision: 4, MappingRevision: 5, AuthorizationRevision: 6,
			AssurancePolicyRevision: 7, ClientSecretRevision: 8,
		},
		DiscoveryRevision: 9, DiscoveryDigest: [32]byte{9}, JWKSRevision: 10, JWKSDigest: [32]byte{10},
	}
}

func samlCreateTransactionFixture() federatedsaml.CreateTransactionRequest {
	now := time.Date(2026, time.August, 26, 10, 0, 0, 0, time.UTC)
	begin := samlAuthenticationBeginFixture(20)
	tenantID := serviceID(11)
	return federatedsaml.CreateTransactionRequest{
		Begin: begin,
		Current: federatedsaml.PendingTransaction{
			ID: federatedsaml.TransactionID{1}, MaterialID: begin.OperationRunID,
			RequestID:        "_request",
			RelayStateDigest: [32]byte{1}, BrowserDigest: [32]byte{2},
			Pins: federatedsaml.TransactionPins{
				Provider:  identity.ProviderContext{Scope: identity.TenantProviderScope, TenantID: tenantID, ProviderID: serviceID(12)},
				BindingID: serviceID(13), ProviderRevision: 1, BindingRevision: 2, ConfigurationRevision: 3,
				SecurityRevision: 4, MappingRevision: 5, AuthorizationRevision: 6, AssurancePolicyRevision: 7,
				MetadataRevision: 8, MetadataDigest: [32]byte{8}, SPKeyRevision: 9, ConfigurationDigest: [32]byte{9},
			},
			CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute), ReturnPath: "/cases",
			State: federatedsaml.TransactionPending, Version: 1,
		},
	}
}
