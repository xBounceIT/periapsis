package federatedoidc

import (
	"context"
	"errors"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

type callbackConfigurationResolverFunc func(
	context.Context,
	CallbackConfigurationLookup,
) (AuthorizationConfiguration, error)

func (function callbackConfigurationResolverFunc) ResolveOIDCCallbackConfiguration(
	ctx context.Context,
	lookup CallbackConfigurationLookup,
) (AuthorizationConfiguration, error) {
	return function(ctx, lookup)
}

func TestClaimCallbackResolvedDerivesConfigurationOnlyAfterAtomicClaim(t *testing.T) {
	fixture := newFlowTestFixture(t, nil)
	start, callback := startResolvedCallback(t, fixture)
	var calls atomic.Int32
	claimed, err := fixture.flow.ClaimCallbackResolved(context.Background(), ResolvedCallbackRequest{
		RawQuery: callback.Encode(), BrowserHandle: start.BrowserHandle(),
	}, callbackConfigurationResolverFunc(func(
		ctx context.Context,
		lookup CallbackConfigurationLookup,
	) (AuthorizationConfiguration, error) {
		calls.Add(1)
		if ctx.Err() != nil || lookup.TransactionID != start.TransactionID() || lookup.ExpectedVersion != 2 ||
			lookup.Pins != transactionPins(fixture.configuration) {
			t.Fatalf("lookup = %s", lookup)
		}
		fixture.repository.mu.Lock()
		state := fixture.repository.records[lookup.TransactionID].State
		fixture.repository.mu.Unlock()
		if state != TransactionClaimed {
			t.Fatalf("configuration resolved before claim: state=%s", state)
		}
		return fixture.configuration, nil
	}))
	if err != nil || claimed == nil || claimed.TransactionID() != start.TransactionID() || calls.Load() != 1 {
		t.Fatalf("ClaimCallbackResolved() = %v, %v, calls=%d", claimed, err, calls.Load())
	}

	if _, replayErr := fixture.flow.ClaimCallbackResolved(context.Background(), ResolvedCallbackRequest{
		RawQuery: callback.Encode(), BrowserHandle: start.BrowserHandle(),
	}, callbackConfigurationResolverFunc(func(context.Context, CallbackConfigurationLookup) (AuthorizationConfiguration, error) {
		calls.Add(1)
		return fixture.configuration, nil
	})); !errors.Is(replayErr, ErrCallbackRejected) || calls.Load() != 1 {
		t.Fatalf("replay = %v, resolver calls=%d", replayErr, calls.Load())
	}
}

func TestPlatformProviderTenantAdmissionIsPinnedBeforeRedirectAndAtCallback(t *testing.T) {
	id := func(marker byte) identity.EntityID {
		var value identity.EntityID
		value[15] = marker
		return value
	}
	admission := identity.TenantAdmissionContext{TenantID: id(31), BindingID: id(32)}
	fixture := newFlowTestFixture(t, func(configuration *AuthorizationConfiguration, _ *FlowPolicy) {
		configuration.Provider = identity.ProviderContext{
			Scope: identity.PlatformProviderScope, ProviderID: id(30),
		}
		configuration.BindingID = identity.EntityID{}
		configuration.Admission = admission
	})
	start, callback := startResolvedCallback(t, fixture)
	redirect, err := url.Parse(start.RedirectURL())
	if err != nil || redirect.Query().Get("redirect_uri") != fixture.configuration.RedirectURI ||
		redirect.Query().Get("redirect_uri") != "https://app.example/api/v1/auth/federated/oidc/callback" {
		t.Fatalf("tenant-admission redirect = %q, %v", redirect.Query().Get("redirect_uri"), err)
	}
	fixture.repository.mu.Lock()
	pins := fixture.repository.records[start.TransactionID()].Pins
	fixture.repository.mu.Unlock()
	fixture.protector.mu.Lock()
	contexts := append([]TransactionProtectionContext(nil), fixture.protector.contexts...)
	fixture.protector.mu.Unlock()
	if pins.Authority != TenantCeremonyAuthority || pins.PlatformLoginRevision != 0 ||
		pins.Provider != fixture.configuration.Provider || pins.BindingID != (identity.EntityID{}) ||
		pins.Admission != admission || len(contexts) != 1 || contexts[0].Admission != admission ||
		contexts[0].Authority != TenantCeremonyAuthority || contexts[0].PlatformLoginRevision != 0 ||
		contexts[0].BindingID != (identity.EntityID{}) {
		t.Fatalf("platform pins=%+v protection=%+v", pins, contexts)
	}

	claimed, err := fixture.flow.ClaimCallbackResolved(context.Background(), ResolvedCallbackRequest{
		RawQuery: callback.Encode(), BrowserHandle: start.BrowserHandle(),
	}, callbackConfigurationResolverFunc(func(
		_ context.Context,
		lookup CallbackConfigurationLookup,
	) (AuthorizationConfiguration, error) {
		if lookup.Pins.Admission != admission || lookup.Pins.BindingID != (identity.EntityID{}) {
			t.Fatalf("callback lookup pins = %+v", lookup.Pins)
		}
		return fixture.configuration, nil
	}))
	if err != nil || claimed == nil {
		t.Fatalf("ClaimCallbackResolved() = %v, %v", claimed, err)
	}
}

func TestPlatformProviderCallbackRejectsTenantAdmissionSubstitution(t *testing.T) {
	id := func(marker byte) identity.EntityID {
		var value identity.EntityID
		value[15] = marker
		return value
	}
	fixture := newFlowTestFixture(t, func(configuration *AuthorizationConfiguration, _ *FlowPolicy) {
		configuration.Provider = identity.ProviderContext{
			Scope: identity.PlatformProviderScope, ProviderID: id(40),
		}
		configuration.BindingID = identity.EntityID{}
		configuration.Admission = identity.TenantAdmissionContext{TenantID: id(41), BindingID: id(42)}
	})
	start, callback := startResolvedCallback(t, fixture)
	substituted := fixture.configuration
	substituted.Admission.TenantID = id(43)
	_, err := fixture.flow.ClaimCallbackResolved(context.Background(), ResolvedCallbackRequest{
		RawQuery: callback.Encode(), BrowserHandle: start.BrowserHandle(),
	}, callbackConfigurationResolverFunc(func(context.Context, CallbackConfigurationLookup) (AuthorizationConfiguration, error) {
		return substituted, nil
	}))
	if !errors.Is(err, ErrCallbackRejected) {
		t.Fatalf("ClaimCallbackResolved() error = %v", err)
	}
}

func TestClaimCallbackResolvedRejectsEveryApplicationPinDriftTerminally(t *testing.T) {
	for name, mutate := range map[string]func(*AuthorizationConfiguration){
		"binding":       func(value *AuthorizationConfiguration) { value.BindingRevision++ },
		"mapping":       func(value *AuthorizationConfiguration) { value.MappingRevision++ },
		"authorization": func(value *AuthorizationConfiguration) { value.AuthorizationRevision++ },
		"assurance":     func(value *AuthorizationConfiguration) { value.AssurancePolicyRevision++ },
		"cross tenant": func(value *AuthorizationConfiguration) {
			value.Provider.TenantID[0] ^= 0xff
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newFlowTestFixture(t, nil)
			start, callback := startResolvedCallback(t, fixture)
			stale := fixture.configuration
			mutate(&stale)
			_, err := fixture.flow.ClaimCallbackResolved(context.Background(), ResolvedCallbackRequest{
				RawQuery: callback.Encode(), BrowserHandle: start.BrowserHandle(),
			}, callbackConfigurationResolverFunc(func(context.Context, CallbackConfigurationLookup) (AuthorizationConfiguration, error) {
				return stale, nil
			}))
			if !errors.Is(err, ErrCallbackRejected) {
				t.Fatalf("ClaimCallbackResolved() error = %v", err)
			}
			fixture.repository.mu.Lock()
			failures := append([]TransactionFailure(nil), fixture.repository.failures...)
			state := fixture.repository.records[start.TransactionID()].State
			fixture.repository.mu.Unlock()
			if len(failures) != 1 || failures[0].Reason != FailureStaleConfiguration || state != TransactionFailed {
				t.Fatalf("failure=%v state=%s", failures, state)
			}
		})
	}
}

func TestClaimCallbackResolvedIssuerDriftConsumesClaimBeforeTenantFailure(t *testing.T) {
	fixture := newFlowTestFixture(t, nil)
	start, callback := startResolvedCallback(t, fixture)
	callback.Set("iss", "https://other.example")
	_, err := fixture.flow.ClaimCallbackResolved(context.Background(), ResolvedCallbackRequest{
		RawQuery: callback.Encode(), BrowserHandle: start.BrowserHandle(),
	}, callbackConfigurationResolverFunc(func(context.Context, CallbackConfigurationLookup) (AuthorizationConfiguration, error) {
		return fixture.configuration, nil
	}))
	if !errors.Is(err, ErrCallbackRejected) {
		t.Fatalf("ClaimCallbackResolved() error = %v", err)
	}
	fixture.repository.mu.Lock()
	failures := append([]TransactionFailure(nil), fixture.repository.failures...)
	fixture.repository.mu.Unlock()
	if len(failures) != 1 || failures[0].Reason != FailureStaleConfiguration {
		t.Fatalf("failures = %v", failures)
	}
}

func TestClaimCallbackResolvedProviderFailureNeedsNoTenantLookup(t *testing.T) {
	fixture := newFlowTestFixture(t, nil)
	start, callback := startResolvedCallback(t, fixture)
	callback.Del("code")
	callback.Set("error", "access_denied")
	var calls atomic.Int32
	_, err := fixture.flow.ClaimCallbackResolved(context.Background(), ResolvedCallbackRequest{
		RawQuery: callback.Encode(), BrowserHandle: start.BrowserHandle(),
	}, callbackConfigurationResolverFunc(func(context.Context, CallbackConfigurationLookup) (AuthorizationConfiguration, error) {
		calls.Add(1)
		return AuthorizationConfiguration{}, errors.New("must not be called")
	}))
	if !errors.Is(err, ErrCallbackRejected) || calls.Load() != 0 {
		t.Fatalf("provider failure = %v, resolver calls=%d", err, calls.Load())
	}
	fixture.repository.mu.Lock()
	failures := append([]TransactionFailure(nil), fixture.repository.failures...)
	fixture.repository.mu.Unlock()
	if len(failures) != 1 || failures[0].Reason != FailureProviderResponse {
		t.Fatalf("failures = %v", failures)
	}
}

func TestClaimCallbackResolvedMalformedClaimedPinsNeverReachTenantResolver(t *testing.T) {
	fixture := newFlowTestFixture(t, nil)
	start, callback := startResolvedCallback(t, fixture)
	fixture.repository.mu.Lock()
	record := fixture.repository.records[start.TransactionID()]
	record.Pins.AuthorizationRevision = 0
	fixture.repository.records[start.TransactionID()] = record
	fixture.repository.mu.Unlock()
	var resolverCalls atomic.Int32
	_, err := fixture.flow.ClaimCallbackResolved(context.Background(), ResolvedCallbackRequest{
		RawQuery: callback.Encode(), BrowserHandle: start.BrowserHandle(),
	}, callbackConfigurationResolverFunc(func(context.Context, CallbackConfigurationLookup) (AuthorizationConfiguration, error) {
		resolverCalls.Add(1)
		return fixture.configuration, nil
	}))
	if !errors.Is(err, ErrCallbackRejected) || resolverCalls.Load() != 0 {
		t.Fatalf("ClaimCallbackResolved() error=%v resolver calls=%d", err, resolverCalls.Load())
	}
	fixture.repository.mu.Lock()
	failures := append([]TransactionFailure(nil), fixture.repository.failures...)
	fixture.repository.mu.Unlock()
	if len(failures) != 1 || failures[0].Reason != FailureStaleConfiguration {
		t.Fatalf("failures = %v", failures)
	}
}

func TestClaimCallbackResolvedOverflowedVersionNeverReachesTenantResolver(t *testing.T) {
	fixture := newFlowTestFixture(t, nil)
	start, callback := startResolvedCallback(t, fixture)
	fixture.repository.mu.Lock()
	record := fixture.repository.records[start.TransactionID()]
	record.Version = ^uint64(0)
	fixture.repository.records[start.TransactionID()] = record
	fixture.repository.mu.Unlock()
	var resolverCalls atomic.Int32
	_, err := fixture.flow.ClaimCallbackResolved(context.Background(), ResolvedCallbackRequest{
		RawQuery: callback.Encode(), BrowserHandle: start.BrowserHandle(),
	}, callbackConfigurationResolverFunc(func(context.Context, CallbackConfigurationLookup) (AuthorizationConfiguration, error) {
		resolverCalls.Add(1)
		return fixture.configuration, nil
	}))
	if !errors.Is(err, ErrCallbackRejected) || resolverCalls.Load() != 0 {
		t.Fatalf("ClaimCallbackResolved() error=%v resolver calls=%d", err, resolverCalls.Load())
	}
}

func TestClaimCallbackResolvedRejectsVersionOrTTLDriftBeforeTenantResolver(t *testing.T) {
	for name, mutate := range map[string]func(*ClaimedTransaction){
		"unexpected version": func(record *ClaimedTransaction) { record.Version = 2 },
		"extended expiry":    func(record *ClaimedTransaction) { record.ExpiresAt = record.ExpiresAt.Add(time.Second) },
		"shortened expiry":   func(record *ClaimedTransaction) { record.ExpiresAt = record.ExpiresAt.Add(-time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newFlowTestFixture(t, nil)
			start, callback := startResolvedCallback(t, fixture)
			fixture.repository.mu.Lock()
			record := fixture.repository.records[start.TransactionID()]
			mutate(&record)
			fixture.repository.records[start.TransactionID()] = record
			fixture.repository.mu.Unlock()
			var resolverCalls atomic.Int32
			_, err := fixture.flow.ClaimCallbackResolved(context.Background(), ResolvedCallbackRequest{
				RawQuery: callback.Encode(), BrowserHandle: start.BrowserHandle(),
			}, callbackConfigurationResolverFunc(func(context.Context, CallbackConfigurationLookup) (AuthorizationConfiguration, error) {
				resolverCalls.Add(1)
				return fixture.configuration, nil
			}))
			if !errors.Is(err, ErrCallbackRejected) || resolverCalls.Load() != 0 {
				t.Fatalf("ClaimCallbackResolved() error=%v resolver calls=%d", err, resolverCalls.Load())
			}
		})
	}
}

func TestClaimCallbackResolvedConcurrentCallbacksHaveOneWinner(t *testing.T) {
	fixture := newFlowTestFixture(t, nil)
	start, callback := startResolvedCallback(t, fixture)
	var resolverCalls atomic.Int32
	resolver := callbackConfigurationResolverFunc(func(context.Context, CallbackConfigurationLookup) (AuthorizationConfiguration, error) {
		resolverCalls.Add(1)
		return fixture.configuration, nil
	})
	const contenders = 16
	var winners atomic.Int32
	var wait sync.WaitGroup
	wait.Add(contenders)
	for range contenders {
		go func() {
			defer wait.Done()
			if claimed, err := fixture.flow.ClaimCallbackResolved(context.Background(), ResolvedCallbackRequest{
				RawQuery: callback.Encode(), BrowserHandle: start.BrowserHandle(),
			}, resolver); err == nil && claimed != nil {
				winners.Add(1)
			}
		}()
	}
	wait.Wait()
	if winners.Load() != 1 || resolverCalls.Load() != 1 {
		t.Fatalf("winners=%d resolver calls=%d", winners.Load(), resolverCalls.Load())
	}
}

func TestAbortClaimedAuthorizationIsTerminalAndOneUse(t *testing.T) {
	fixture := newFlowTestFixture(t, nil)
	start, callback := startResolvedCallback(t, fixture)
	claimed, err := fixture.flow.ClaimCallbackResolved(context.Background(), ResolvedCallbackRequest{
		RawQuery: callback.Encode(), BrowserHandle: start.BrowserHandle(),
	}, callbackConfigurationResolverFunc(func(context.Context, CallbackConfigurationLookup) (AuthorizationConfiguration, error) {
		return fixture.configuration, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if err = fixture.flow.AbortClaimedAuthorization(context.Background(), claimed); err != nil {
		t.Fatalf("AbortClaimedAuthorization() error = %v", err)
	}
	if err = fixture.flow.AbortClaimedAuthorization(context.Background(), claimed); !errors.Is(err, ErrCallbackRejected) {
		t.Fatalf("second abort error = %v", err)
	}
	if _, err = fixture.flow.ExchangeCode(context.Background(), claimed, ClientCredential{
		Revision: fixture.configuration.ClientSecretRevision, Secret: []byte("secret-after-abort"),
	}); !errors.Is(err, ErrTokenExchangeFailed) {
		t.Fatalf("ExchangeCode() after abort error = %v", err)
	}
	fixture.repository.mu.Lock()
	failures := append([]TransactionFailure(nil), fixture.repository.failures...)
	state := fixture.repository.records[start.TransactionID()].State
	fixture.repository.mu.Unlock()
	if len(failures) != 1 || failures[0].Reason != FailureIdentityApplication || state != TransactionFailed {
		t.Fatalf("failure=%v state=%s", failures, state)
	}
}

func TestAbortClaimedAuthorizationRetriesExactFailureAfterLostResponse(t *testing.T) {
	fixture := newFlowTestFixture(t, nil)
	start, callback := startResolvedCallback(t, fixture)
	claimed, err := fixture.flow.ClaimCallbackResolved(context.Background(), ResolvedCallbackRequest{
		RawQuery: callback.Encode(), BrowserHandle: start.BrowserHandle(),
	}, callbackConfigurationResolverFunc(func(context.Context, CallbackConfigurationLookup) (AuthorizationConfiguration, error) {
		return fixture.configuration, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	fixture.repository.failCommitThenErr = true
	if err = fixture.flow.AbortClaimedAuthorization(context.Background(), claimed); !errors.Is(err, ErrCallbackRejected) {
		t.Fatalf("lost-response abort error = %v", err)
	}
	if err = fixture.flow.AbortClaimedAuthorization(context.Background(), claimed); err != nil {
		t.Fatalf("abort replay error = %v", err)
	}
	fixture.repository.mu.Lock()
	failures := append([]TransactionFailure(nil), fixture.repository.failures...)
	state := fixture.repository.records[start.TransactionID()].State
	fixture.repository.mu.Unlock()
	if len(failures) != 1 || failures[0].Reason != FailureIdentityApplication || state != TransactionFailed {
		t.Fatalf("failures=%v state=%s", failures, state)
	}
}

func TestAbortClaimedAuthorizationConcurrentCallsHaveOneMutation(t *testing.T) {
	fixture := newFlowTestFixture(t, nil)
	authorizationStart, callback := startResolvedCallback(t, fixture)
	claimed, err := fixture.flow.ClaimCallbackResolved(context.Background(), ResolvedCallbackRequest{
		RawQuery: callback.Encode(), BrowserHandle: authorizationStart.BrowserHandle(),
	}, callbackConfigurationResolverFunc(func(context.Context, CallbackConfigurationLookup) (AuthorizationConfiguration, error) {
		return fixture.configuration, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	const contenders = 16
	var winners atomic.Int32
	var wait sync.WaitGroup
	wait.Add(contenders)
	for range contenders {
		go func() {
			defer wait.Done()
			if fixture.flow.AbortClaimedAuthorization(context.Background(), claimed) == nil {
				winners.Add(1)
			}
		}()
	}
	wait.Wait()
	fixture.repository.mu.Lock()
	failures := len(fixture.repository.failures)
	fixture.repository.mu.Unlock()
	if winners.Load() != 1 || failures != 1 {
		t.Fatalf("abort winners=%d failures=%d", winners.Load(), failures)
	}
}

func startResolvedCallback(t *testing.T, fixture flowTestFixture) (AuthorizationStart, url.Values) {
	t.Helper()
	start, err := fixture.flow.StartAuthorization(context.Background(), StartAuthorizationRequest{
		Begin: testAuthorizationBegin(), Configuration: fixture.configuration, ReturnPath: "/incidents?view=mine",
	})
	if err != nil {
		t.Fatal(err)
	}
	redirect, err := url.Parse(start.RedirectURL())
	if err != nil {
		t.Fatal(err)
	}
	return start, url.Values{
		"code":  {"authorization-code-canary"},
		"state": {redirect.Query().Get("state")},
		"iss":   {testIssuer},
	}
}
