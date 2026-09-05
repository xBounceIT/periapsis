package platformoidcauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"net/url"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/periapsis-im/periapsis/modules/identity/federatedhttp"
	"github.com/periapsis-im/periapsis/modules/identity/federatedoidc"
)

type directAdapterPersistence struct {
	mu                  sync.Mutex
	creates             []DirectOIDCCreateTransactionRequest
	claims              []DirectOIDCClaimTransactionRequest
	failures            []DirectOIDCFailureRequest
	record              federatedoidc.ClaimedTransaction
	createResponseLost  bool
	claimResponseLost   bool
	failureResponseLost bool
	committedFailure    *DirectOIDCFailureRequest
	poisonClaim         func(*federatedoidc.ClaimedTransaction)
}

func (persistence *directAdapterPersistence) CreateDirectOIDCTransaction(
	_ context.Context,
	request DirectOIDCCreateTransactionRequest,
) error {
	persistence.mu.Lock()
	defer persistence.mu.Unlock()
	request = cloneDirectOIDCCreateTransactionRequest(request)
	persistence.creates = append(persistence.creates, request)
	if persistence.record.ID == (federatedoidc.TransactionID{}) {
		persistence.record.PendingTransaction = request.Current
		persistence.record.Verifier.Ciphertext = append([]byte(nil), request.Current.Verifier.Ciphertext...)
		persistence.record.Scopes = append([]string(nil), request.Current.Scopes...)
	}
	if persistence.createResponseLost {
		persistence.createResponseLost = false
		return errors.New("create response lost")
	}
	return nil
}

func (persistence *directAdapterPersistence) ClaimDirectOIDCTransaction(
	_ context.Context,
	request DirectOIDCClaimTransactionRequest,
) (federatedoidc.ClaimedTransaction, error) {
	persistence.mu.Lock()
	defer persistence.mu.Unlock()
	persistence.claims = append(persistence.claims, request)
	if persistence.record.State == federatedoidc.TransactionPending {
		persistence.record.State = federatedoidc.TransactionClaimed
		persistence.record.Version = 2
		persistence.record.ClaimAttemptID = request.AttemptID
		persistence.record.AuthorizationCodeDigest = request.AuthorizationCodeDigest
		persistence.record.ClaimedAt = request.ClaimedAt
	}
	result := cloneDirectClaimedTransaction(persistence.record)
	if persistence.poisonClaim != nil {
		persistence.poisonClaim(&result)
	}
	if persistence.claimResponseLost {
		persistence.claimResponseLost = false
		clear(result.Verifier.Ciphertext)
		return federatedoidc.ClaimedTransaction{}, errors.New("claim response lost")
	}
	return result, nil
}

func (persistence *directAdapterPersistence) FailDirectOIDCTransaction(
	_ context.Context,
	request DirectOIDCFailureRequest,
) error {
	persistence.mu.Lock()
	defer persistence.mu.Unlock()
	persistence.failures = append(persistence.failures, request)
	if persistence.committedFailure != nil {
		if *persistence.committedFailure != request {
			return errors.New("failure replay collision")
		}
		return nil
	}
	committed := request
	persistence.committedFailure = &committed
	if persistence.failureResponseLost {
		persistence.failureResponseLost = false
		return errors.New("failure response lost")
	}
	return nil
}

type directAdapterVerifierProtector struct{}

func (directAdapterVerifierProtector) SealPKCE(
	_ context.Context,
	_ federatedoidc.TransactionProtectionContext,
	verifier []byte,
) (federatedoidc.ProtectedVerifier, error) {
	return federatedoidc.ProtectedVerifier{
		KeyVersion: 1, Ciphertext: append(bytes.Repeat([]byte{0xa5}, 16), verifier...),
	}, nil
}

func (directAdapterVerifierProtector) OpenPKCE(
	_ context.Context,
	_ federatedoidc.TransactionProtectionContext,
	protected federatedoidc.ProtectedVerifier,
) ([]byte, error) {
	if len(protected.Ciphertext) < 16 {
		return nil, errors.New("invalid verifier")
	}
	return append([]byte(nil), protected.Ciphertext[16:]...), nil
}

type directAdapterTokenEndpoint struct {
	response *federatedoidc.TokenEndpointResponse
}

func (endpoint directAdapterTokenEndpoint) Exchange(
	context.Context,
	federatedoidc.TokenExchangeRequest,
) (federatedoidc.TokenEndpointResponse, error) {
	if endpoint.response == nil {
		return federatedoidc.TokenEndpointResponse{}, errors.New("network disabled")
	}
	response := *endpoint.response
	response.Body = append([]byte(nil), endpoint.response.Body...)
	return response, nil
}

type directAdapterResolverFunc func(
	context.Context,
	federatedoidc.CallbackConfigurationLookup,
) (federatedoidc.AuthorizationConfiguration, error)

func (function directAdapterResolverFunc) ResolveOIDCCallbackConfiguration(
	ctx context.Context,
	lookup federatedoidc.CallbackConfigurationLookup,
) (federatedoidc.AuthorizationConfiguration, error) {
	return function(ctx, lookup)
}

func TestDirectOIDCTransactionAdapterCarriesDistinctBindingsPinsAuditAndExactRetries(t *testing.T) {
	adapter, persistence, configuration, pins, lookup, audit := newDirectTransactionAdapterFixture(t)
	persistence.createResponseLost = true
	start, err := adapter.StartDirectAuthorization(context.Background(), directAdapterStartRequest(
		configuration, pins, lookup, audit,
	))
	if err != nil {
		t.Fatalf("StartDirectAuthorization() error = %v", err)
	}
	redirect, err := url.Parse(start.RedirectURL())
	if err != nil {
		t.Fatal(err)
	}
	persistence.mu.Lock()
	creates := cloneDirectAdapterCreates(persistence.creates)
	persistence.mu.Unlock()
	if len(creates) != 2 || !reflect.DeepEqual(creates[0], creates[1]) ||
		creates[0].Audit != audit || creates[0].BrowserCapabilityDigest != lookup.BrowserCapabilityDigest ||
		creates[0].Current.BrowserDigest == [sha256.Size]byte(lookup.BrowserCapabilityDigest) {
		t.Fatalf("create retries/bindings = %#v", creates)
	}
	createdPins, direct := directConfigurationPinsFromTransaction(creates[0].Current.Pins)
	if !direct || createdPins != pins {
		t.Fatalf("persisted full pins = %s", createdPins)
	}

	code := "adapter-authorization-code"
	persistence.claimResponseLost = true
	var callbackLookup federatedoidc.CallbackConfigurationLookup
	claimed, err := adapter.ClaimCallbackResolved(context.Background(), DirectOIDCCallbackRequest{
		Protocol: federatedoidc.ResolvedCallbackRequest{
			RawQuery: url.Values{
				"code": {code}, "state": {redirect.Query().Get("state")},
				"iss": {configuration.Authorization.Discovery.Issuer()},
			}.Encode(),
			BrowserHandle: start.BrowserHandle(),
		},
		Audit: audit,
	}, directAdapterResolverFunc(func(
		_ context.Context,
		observed federatedoidc.CallbackConfigurationLookup,
	) (federatedoidc.AuthorizationConfiguration, error) {
		callbackLookup = observed
		bound, ok := bindDirectOIDCConfigurationPins(configuration.Authorization, pins)
		if !ok {
			t.Fatal("failed to bind direct test configuration")
		}
		return bound, nil
	}))
	if err != nil || claimed.Authorization == nil ||
		claimed.ClaimAttemptID != claimed.Authorization.ClaimAttemptID() {
		t.Fatalf("ClaimCallbackResolved() = %s, %v", claimed, err)
	}
	persistence.mu.Lock()
	claims := append([]DirectOIDCClaimTransactionRequest(nil), persistence.claims...)
	persistence.mu.Unlock()
	if len(claims) != 2 || claims[0] != claims[1] || claims[0].Audit != audit ||
		claims[0].ExpectedVersion != 1 ||
		claims[0].AuthorizationCodeDigest != sha256.Sum256([]byte(code)) ||
		callbackLookup.TransactionID != start.TransactionID() ||
		callbackLookup.ReturnPath != "/platform?from=direct" || callbackLookup.Pins != creates[0].Current.Pins {
		t.Fatalf("claim retries/lookup = claims:%#v lookup:%s", claims, callbackLookup)
	}

	wrongAudit := audit
	wrongAudit.CorrelationID = directTestEntityID(99)
	if err := adapter.AbortDirectClaimedAuthorization(context.Background(), claimed, wrongAudit); !errors.Is(err, ErrDirectAuthenticationDenied) {
		t.Fatalf("mismatched audit AbortDirectClaimedAuthorization() error = %v", err)
	}
	persistence.mu.Lock()
	failuresBefore := len(persistence.failures)
	persistence.failureResponseLost = true
	persistence.mu.Unlock()
	if failuresBefore != 0 {
		t.Fatalf("mismatched audit reached persistence: %d", failuresBefore)
	}
	if err := adapter.AbortDirectClaimedAuthorization(context.Background(), claimed, audit); !errors.Is(err, ErrDirectAuthenticationDenied) {
		t.Fatalf("first AbortDirectClaimedAuthorization() error = %v", err)
	}
	if err := adapter.AbortDirectClaimedAuthorization(context.Background(), claimed, audit); err != nil {
		t.Fatalf("retry AbortDirectClaimedAuthorization() error = %v", err)
	}
	persistence.mu.Lock()
	failures := append([]DirectOIDCFailureRequest(nil), persistence.failures...)
	persistence.mu.Unlock()
	if len(failures) != 2 || failures[0] != failures[1] || failures[0].Audit != audit ||
		failures[0].TransactionID != start.TransactionID() ||
		failures[0].Reason != federatedoidc.FailureIdentityApplication ||
		failures[0].State != federatedoidc.TransactionFailed {
		t.Fatalf("failure retries = %#v", failures)
	}
}

func TestDirectOIDCTransactionAdapterRejectsPersistenceClaimPoisoning(t *testing.T) {
	for name, poison := range map[string]func(*federatedoidc.ClaimedTransaction){
		"attempt": func(record *federatedoidc.ClaimedTransaction) {
			record.ClaimAttemptID[0] ^= 0xff
		},
		"authorization code digest": func(record *federatedoidc.ClaimedTransaction) {
			record.AuthorizationCodeDigest[0] ^= 0xff
		},
		"return path": func(record *federatedoidc.ClaimedTransaction) {
			record.ReturnPath = "//foreign.example"
		},
		"state digest": func(record *federatedoidc.ClaimedTransaction) {
			record.StateDigest[0] ^= 0xff
		},
		"browser handle digest": func(record *federatedoidc.ClaimedTransaction) {
			record.BrowserDigest[0] ^= 0xff
		},
		"claim instant": func(record *federatedoidc.ClaimedTransaction) {
			record.ClaimedAt = record.ClaimedAt.Add(time.Millisecond)
		},
		"version": func(record *federatedoidc.ClaimedTransaction) {
			record.Version++
		},
	} {
		t.Run(name, func(t *testing.T) {
			adapter, persistence, configuration, pins, lookup, audit := newDirectTransactionAdapterFixture(t)
			start, err := adapter.StartDirectAuthorization(context.Background(), directAdapterStartRequest(
				configuration, pins, lookup, audit,
			))
			if err != nil {
				t.Fatal(err)
			}
			redirect, _ := url.Parse(start.RedirectURL())
			persistence.poisonClaim = poison
			resolverCalls := 0
			claimed, err := adapter.ClaimCallbackResolved(context.Background(), DirectOIDCCallbackRequest{
				Protocol: federatedoidc.ResolvedCallbackRequest{
					RawQuery: url.Values{
						"code": {"code"}, "state": {redirect.Query().Get("state")},
					}.Encode(),
					BrowserHandle: start.BrowserHandle(),
				},
				Audit: audit,
			}, directAdapterResolverFunc(func(
				context.Context,
				federatedoidc.CallbackConfigurationLookup,
			) (federatedoidc.AuthorizationConfiguration, error) {
				resolverCalls++
				return configuration.Authorization, nil
			}))
			if !errors.Is(err, ErrDirectAuthenticationDenied) || claimed != (DirectClaimedAuthorization{}) ||
				resolverCalls != 0 {
				t.Fatalf("poisoned claim = %s, %v resolverCalls=%d", claimed, err, resolverCalls)
			}
			persistence.mu.Lock()
			claims := append([]DirectOIDCClaimTransactionRequest(nil), persistence.claims...)
			persistence.mu.Unlock()
			if len(claims) != 2 || claims[0] != claims[1] {
				t.Fatalf("poisoned exact retry = %#v", claims)
			}
		})
	}
}

func TestDirectOIDCTransactionRepositoryRejectsCollapsedOrMalformedBrowserBindings(t *testing.T) {
	adapter, persistence, configuration, pins, lookup, audit := newDirectTransactionAdapterFixture(t)
	if _, err := adapter.StartDirectAuthorization(context.Background(), directAdapterStartRequest(
		configuration, pins, lookup, audit,
	)); err != nil {
		t.Fatal(err)
	}
	persistence.mu.Lock()
	created := cloneDirectOIDCCreateTransactionRequest(persistence.creates[0])
	persistence.creates = nil
	persistence.mu.Unlock()

	baseline := federatedoidc.CreateTransactionRequest{
		Begin: created.Begin, Current: created.Current,
		PreviousBrowserDigest:     created.PreviousBrowserDigest,
		HasPreviousBrowserBinding: created.HasPreviousBrowserBinding,
		ApplicationBrowserBindingDigest: [sha256.Size]byte(
			created.BrowserCapabilityDigest,
		),
		Audit: transactionAuditContext(created.Audit),
	}
	repository := &directOIDCTransactionRepository{persistence: persistence}
	for name, mutate := range map[string]func(*federatedoidc.CreateTransactionRequest){
		"capability equals current browser handle": func(request *federatedoidc.CreateTransactionRequest) {
			request.ApplicationBrowserBindingDigest = request.Current.BrowserDigest
		},
		"previous flag without digest": func(request *federatedoidc.CreateTransactionRequest) {
			request.HasPreviousBrowserBinding = true
			request.PreviousBrowserDigest = [sha256.Size]byte{}
		},
		"previous digest without flag": func(request *federatedoidc.CreateTransactionRequest) {
			request.HasPreviousBrowserBinding = false
			request.PreviousBrowserDigest = sha256.Sum256([]byte("previous-browser"))
		},
		"previous equals current browser handle": func(request *federatedoidc.CreateTransactionRequest) {
			request.HasPreviousBrowserBinding = true
			request.PreviousBrowserDigest = request.Current.BrowserDigest
		},
		"previous equals capability": func(request *federatedoidc.CreateTransactionRequest) {
			request.HasPreviousBrowserBinding = true
			request.PreviousBrowserDigest = request.ApplicationBrowserBindingDigest
		},
	} {
		t.Run(name, func(t *testing.T) {
			request := baseline
			mutate(&request)
			if err := repository.CreateReplacing(context.Background(), request); !errors.Is(err, ErrDirectAuthenticationDenied) {
				t.Fatalf("CreateReplacing() error = %v", err)
			}
		})
	}
	persistence.mu.Lock()
	creates := len(persistence.creates)
	persistence.mu.Unlock()
	if creates != 0 {
		t.Fatalf("malformed browser binding reached persistence %d times", creates)
	}

	if err := repository.Fail(context.Background(), federatedoidc.TransactionFailure{
		ID: created.Current.ID, ExpectedVersion: 3, FailedAt: directTestNow,
		Reason: federatedoidc.FailureIdentityApplication, State: federatedoidc.TransactionFailed,
		Audit: transactionAuditContext(audit),
	}); !errors.Is(err, ErrDirectAuthenticationDenied) {
		t.Fatalf("Fail(version 3) error = %v", err)
	}
	persistence.mu.Lock()
	failures := len(persistence.failures)
	persistence.mu.Unlock()
	if failures != 0 {
		t.Fatalf("wrong-version failure reached persistence %d times", failures)
	}
}

func TestDirectAuthenticationPlannerBindsClaimAttemptObservationAndFullPins(t *testing.T) {
	response := federatedoidc.TokenEndpointResponse{}
	adapter, _, configuration, pins, lookup, audit := newDirectTransactionAdapterFixtureWithTokenEndpoint(
		t, directAdapterTokenEndpoint{response: &response},
	)
	start, err := adapter.StartDirectAuthorization(context.Background(), directAdapterStartRequest(
		configuration, pins, lookup, audit,
	))
	if err != nil {
		t.Fatal(err)
	}
	redirect, err := url.Parse(start.RedirectURL())
	if err != nil {
		t.Fatal(err)
	}
	code := "direct-planner-binding-code"
	claimed, err := adapter.ClaimCallbackResolved(context.Background(), DirectOIDCCallbackRequest{
		Protocol: federatedoidc.ResolvedCallbackRequest{
			RawQuery: url.Values{
				"code": {code}, "state": {redirect.Query().Get("state")},
			}.Encode(),
			BrowserHandle: start.BrowserHandle(),
		},
		Audit: audit,
	}, directAdapterResolverFunc(func(
		_ context.Context,
		observed federatedoidc.CallbackConfigurationLookup,
	) (federatedoidc.AuthorizationConfiguration, error) {
		bound, ok := bindDirectOIDCConfigurationPins(configuration.Authorization, pins)
		if !ok || observed.TransactionID != start.TransactionID() || observed.ReturnPath != "/platform?from=direct" {
			return federatedoidc.AuthorizationConfiguration{}, errors.New("callback authority mismatch")
		}
		return bound, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	tokenNow := time.Now().UTC().Truncate(time.Second)
	response = federatedoidc.TokenEndpointResponse{
		Category: federatedoidc.TokenEndpointSuccess, StatusCode: 200,
		MediaType: "application/json; charset=utf-8",
		Body: directBrowserJSON(t, map[string]any{
			"id_token": directAdapterSignedIDToken(
				t, configuration, redirect.Query().Get("nonce"), tokenNow,
			),
			"access_token": "direct-access-token", "token_type": "Bearer", "expires_in": 600,
		}),
	}
	bundle, err := adapter.ExchangeCode(context.Background(), claimed.Authorization, federatedoidc.ClientCredential{
		Revision: pins.ClientSecretRevision, Secret: []byte("direct-client-secret"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer bundle.Destroy()
	proof, err := adapter.VerifyIDToken(
		context.Background(), claimed.Authorization, bundle, configuration.IDTokenClaims,
	)
	if err != nil {
		t.Fatal(err)
	}

	observedAt := time.Now().UTC().Truncate(time.Millisecond)
	request := DirectOIDCTrustPlanRequest{
		TransactionID: start.TransactionID(), ClaimAttemptID: claimed.ClaimAttemptID,
		ObservedAt: observedAt, Pins: pins, Proof: proof,
	}
	var observed DirectPlatformPlanningLookup
	planner := directTestPlanner(t, directTestKeyring(t), func(
		_ context.Context,
		candidate DirectPlatformPlanningLookup,
	) (DirectPlatformPlanningState, error) {
		observed = cloneDirectPlatformPlanningLookup(candidate)
		if candidate.TransactionID != request.TransactionID ||
			candidate.ClaimAttemptID != request.ClaimAttemptID ||
			!candidate.ObservedAt.Equal(request.ObservedAt) || candidate.Pins != request.Pins {
			return DirectPlatformPlanningState{}, errors.New("swapped direct planning authority")
		}
		state := validDirectPlanningStateFixture(candidate)
		confirmedAt := candidate.ObservedAt.Add(-time.Hour)
		state.LiveConfirmedTOTPFactors[0].ConfirmedAt = &confirmedAt
		return state, nil
	})
	plan, err := planner.Plan(context.Background(), request)
	if err != nil || plan.Completion.ID != request.TransactionID ||
		observed.TransactionID != request.TransactionID || observed.ClaimAttemptID != request.ClaimAttemptID ||
		!observed.ObservedAt.Equal(request.ObservedAt) || observed.Pins != request.Pins {
		t.Fatalf("Plan() = %s, %v observed=%s", plan, err, observed)
	}

	for name, mutate := range map[string]func(*DirectOIDCTrustPlanRequest){
		"transaction":   func(value *DirectOIDCTrustPlanRequest) { value.TransactionID[0] ^= 0xff },
		"claim attempt": func(value *DirectOIDCTrustPlanRequest) { value.ClaimAttemptID[0] ^= 0xff },
		"observation":   func(value *DirectOIDCTrustPlanRequest) { value.ObservedAt = value.ObservedAt.Add(time.Millisecond) },
		"plan pin":      func(value *DirectOIDCTrustPlanRequest) { value.Pins.PlanRevision++ },
		"platform floor pin": func(value *DirectOIDCTrustPlanRequest) {
			value.Pins.PlatformFloorPolicyID = directTestEntityID(120)
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := request
			mutate(&candidate)
			denied, planErr := planner.Plan(context.Background(), candidate)
			if !errors.Is(planErr, ErrDirectAuthenticationDenied) ||
				!reflect.DeepEqual(denied, DirectAuthenticationPlan{}) {
				t.Fatalf("Plan(swapped %s) = %s, %v", name, denied, planErr)
			}
		})
	}
}

func directAdapterSignedIDToken(
	t *testing.T,
	configuration DirectOIDCConfiguration,
	nonce string,
	now time.Time,
) string {
	t.Helper()
	header, err := json.Marshal(map[string]any{
		"alg": string(federatedoidc.SigningEdDSA), "kid": "direct-browser-key-1", "typ": "JWT",
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{
		"iss": configuration.Authorization.Discovery.Issuer(), "sub": "direct-existing-subject",
		"aud": configuration.Authorization.ClientID, "nonce": nonce,
		"iat": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(),
		"auth_time": now.Add(-time.Minute).Unix(), "acr": "urn:example:mfa",
		"amr": []string{"mfa", "pwd"},
	})
	if err != nil {
		t.Fatal(err)
	}
	encodedHeader := base64.RawURLEncoding.EncodeToString(header)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	signingInput := encodedHeader + "." + encodedPayload
	seed := sha256.Sum256([]byte("direct browser deterministic Ed25519 key"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	signature := ed25519.Sign(privateKey, []byte(signingInput))
	clear(privateKey)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func TestDirectOIDCTransactionAdapterRejectsFamilyAndPinPrepopulation(t *testing.T) {
	adapter, persistence, configuration, pins, lookup, audit := newDirectTransactionAdapterFixture(t)
	request := directAdapterStartRequest(configuration, pins, lookup, audit)
	request.Protocol.Configuration.PlanRevision = pins.PlanRevision + 1
	if start, err := adapter.StartDirectAuthorization(context.Background(), request); !errors.Is(err, ErrDirectAuthenticationDenied) || start.TransactionID() != (federatedoidc.TransactionID{}) {
		t.Fatalf("prepopulated pin start = %s, %v", start, err)
	}
	persistence.mu.Lock()
	creates := len(persistence.creates)
	persistence.mu.Unlock()
	if creates != 0 {
		t.Fatalf("prepopulated pins reached persistence: %d", creates)
	}

	options := directAdapterFlowOptions(t, configuration)
	options.Transactions = &directOIDCTransactionRepository{persistence: persistence}
	if result, err := NewDirectOIDCTransactionAdapter(DirectOIDCTransactionAdapterOptions{
		Flow: options, Persistence: persistence,
	}); !errors.Is(err, ErrDirectAuthenticationDenied) || result != nil {
		t.Fatalf("constructor accepted caller repository = %v, %v", result, err)
	}
}

func newDirectTransactionAdapterFixture(
	t *testing.T,
) (*DirectOIDCTransactionAdapter, *directAdapterPersistence, DirectOIDCConfiguration,
	DirectOIDCConfigurationPins, DirectOIDCStartLookup, DirectAuditContext,
) {
	return newDirectTransactionAdapterFixtureWithTokenEndpoint(t, directAdapterTokenEndpoint{})
}

func newDirectTransactionAdapterFixtureWithTokenEndpoint(
	t *testing.T,
	tokenEndpoint federatedoidc.TokenEndpointPort,
) (*DirectOIDCTransactionAdapter, *directAdapterPersistence, DirectOIDCConfiguration,
	DirectOIDCConfigurationPins, DirectOIDCStartLookup, DirectAuditContext,
) {
	t.Helper()
	configuration := directBrowserConfigurationFixtureAt(t, time.Now().UTC().Truncate(time.Millisecond))
	configuration.Authorization.RedirectURI = "https://api.example.test/api/v1/auth/platform/oidc/callback"
	configuration.Authorization.PostLogoutRedirectURI = ""
	pins := directBrowserConfigurationPinsFixture(configuration)
	digester, err := NewDirectOIDCStartDigester(bytes.Repeat([]byte{0x77}, 32))
	if err != nil {
		t.Fatal(err)
	}
	capability := bytes.Repeat([]byte{0x51}, 32)
	lookup, err := digester.BuildLookup(
		directTestEntityID(40), bytes.Repeat([]byte{0x52}, 32), capability,
		"direct_adapter", "203.0.113.40",
	)
	if err != nil {
		t.Fatal(err)
	}
	audit := DirectAuditContext{
		RequestID: directTestEntityID(41), CorrelationID: directTestEntityID(42),
		RemoteAddress: netip.MustParseAddr("198.51.100.40"), UserAgent: "direct-adapter-test/1.0",
	}
	persistence := &directAdapterPersistence{}
	adapter, err := NewDirectOIDCTransactionAdapter(DirectOIDCTransactionAdapterOptions{
		Flow: directAdapterFlowOptions(t, configuration, tokenEndpoint), Persistence: persistence,
	})
	if err != nil {
		t.Fatalf("NewDirectOIDCTransactionAdapter() error = %v", err)
	}
	return adapter, persistence, configuration, pins, lookup, audit
}

func directAdapterFlowOptions(
	t *testing.T,
	configuration DirectOIDCConfiguration,
	tokenEndpoints ...federatedoidc.TokenEndpointPort,
) federatedoidc.FlowOptions {
	t.Helper()
	egress, err := federatedhttp.NewDeploymentEgressPolicy(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	httpClient, err := federatedhttp.New(federatedhttp.Options{
		Resolver: directBrowserResolver{}, Dialer: directBrowserDialer{}, EgressPolicy: egress,
		RootCAs: x509.NewCertPool(), Limits: federatedhttp.DefaultLimits(), MaxConcurrent: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	trust, err := federatedoidc.New(federatedoidc.Options{
		HTTP: httpClient, Limits: federatedoidc.DefaultLimits(),
	})
	if err != nil {
		t.Fatal(err)
	}
	tokenEndpoint := federatedoidc.TokenEndpointPort(directAdapterTokenEndpoint{})
	if len(tokenEndpoints) == 1 {
		tokenEndpoint = tokenEndpoints[0]
	} else if len(tokenEndpoints) > 1 {
		t.Fatal("directAdapterFlowOptions received more than one token endpoint")
	}
	return federatedoidc.FlowOptions{
		Trust: trust, VerifierProtector: directAdapterVerifierProtector{},
		TokenEndpoint: tokenEndpoint, RedirectURI: configuration.Authorization.RedirectURI,
		PostLogoutRedirectURI: configuration.Authorization.PostLogoutRedirectURI,
		Policy:                federatedoidc.DefaultFlowPolicy(),
	}
}

func directAdapterStartRequest(
	configuration DirectOIDCConfiguration,
	pins DirectOIDCConfigurationPins,
	lookup DirectOIDCStartLookup,
	audit DirectAuditContext,
) DirectOIDCStartAuthorizationRequest {
	authority := DirectOIDCStartAuthority{
		Lookup: lookup, ReturnPath: "/platform?from=direct", Audit: audit,
	}
	return DirectOIDCStartAuthorizationRequest{
		Protocol: federatedoidc.StartAuthorizationRequest{
			Begin: federatedoidc.AuthorizationBegin{
				OperationRunID: lookup.OperationRunID,
				ReceiptDigest:  federatedoidc.StartReceiptDigest(lookup.ReceiptDigest),
				NetworkDigest:  federatedoidc.NetworkThrottleDigest(lookup.NetworkDigest),
				AccountDigest:  federatedoidc.AccountThrottleDigest(lookup.AccountDigest),
				ProviderDigest: federatedoidc.ProviderThrottleDigest(lookup.ProviderDigest),
			},
			Configuration: configuration.Authorization, ReturnPath: authority.ReturnPath,
		},
		Grant: DirectOIDCStartGrant{Authority: authority, Pins: pins},
	}
}

func cloneDirectAdapterCreates(
	values []DirectOIDCCreateTransactionRequest,
) []DirectOIDCCreateTransactionRequest {
	result := make([]DirectOIDCCreateTransactionRequest, len(values))
	for index, value := range values {
		result[index] = cloneDirectOIDCCreateTransactionRequest(value)
	}
	return result
}
