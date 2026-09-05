package federatedoidc

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/netip"
	"net/url"
	"testing"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

func TestDirectCallbackCarriesExactAuditCodeDigestAttemptAndReturnPath(t *testing.T) {
	fixture := newFlowTestFixture(t, func(configuration *AuthorizationConfiguration, _ *FlowPolicy) {
		makeDirectPlatformConfiguration(configuration)
	})
	audit := TransactionAuditContext{
		RequestID: identity.EntityID{1}, CorrelationID: identity.EntityID{2},
		RemoteAddress: netip.MustParseAddr("198.51.100.44"), UserAgent: "direct-kernel-test/1.0",
	}
	start, err := fixture.flow.StartAuthorization(context.Background(), StartAuthorizationRequest{
		Begin: testAuthorizationBegin(), Configuration: fixture.configuration,
		ReturnPath: "/platform?from=direct", Audit: audit,
	})
	if err != nil {
		t.Fatalf("StartAuthorization() error = %v", err)
	}
	redirect, err := url.Parse(start.RedirectURL())
	if err != nil {
		t.Fatal(err)
	}
	code := "direct-authorization-code"
	callback := url.Values{
		"code": {code}, "state": {redirect.Query().Get("state")}, "iss": {testIssuer},
	}
	var lookup CallbackConfigurationLookup
	claimed, err := fixture.flow.ClaimCallbackResolved(context.Background(), ResolvedCallbackRequest{
		RawQuery: callback.Encode(), BrowserHandle: start.BrowserHandle(), Audit: audit,
	}, callbackConfigurationResolverFunc(func(
		_ context.Context,
		observed CallbackConfigurationLookup,
	) (AuthorizationConfiguration, error) {
		lookup = observed
		return fixture.configuration, nil
	}))
	if err != nil || claimed == nil {
		t.Fatalf("ClaimCallbackResolved() = %v, %v", claimed, err)
	}
	fixture.repository.mu.Lock()
	created := fixture.repository.created[0]
	claim := fixture.repository.claims[0]
	fixture.repository.mu.Unlock()
	if created.Audit != audit || claim.Audit != audit || claimed.AuditContext() != audit ||
		lookup.ReturnPath != "/platform?from=direct" || lookup.TransactionID != start.TransactionID() ||
		lookup.Pins != transactionPins(fixture.configuration) ||
		claimed.ClaimAttemptID() != claim.AttemptID || claimed.TransactionID() != start.TransactionID() ||
		claim.AuthorizationCodeDigest != sha256.Sum256([]byte(code)) {
		t.Fatalf("direct attribution drift: create=%s claim=%s lookup=%s claimed=%s", created, claim, lookup, claimed)
	}

	fixture.repository.failCommitThenErr = true
	if err := fixture.flow.AbortClaimedAuthorization(context.Background(), claimed); !errors.Is(err, ErrCallbackRejected) {
		t.Fatalf("first AbortClaimedAuthorization() error = %v", err)
	}
	if err := fixture.flow.AbortClaimedAuthorization(context.Background(), claimed); err != nil {
		t.Fatalf("retry AbortClaimedAuthorization() error = %v", err)
	}
	fixture.repository.mu.Lock()
	failCalls := append([]TransactionFailure(nil), fixture.repository.failCalls...)
	fixture.repository.mu.Unlock()
	if len(failCalls) != 2 || failCalls[0] != failCalls[1] || failCalls[0].Audit != audit ||
		failCalls[0].ID != start.TransactionID() || failCalls[0].ExpectedVersion != 2 ||
		failCalls[0].Reason != FailureIdentityApplication || failCalls[0].State != TransactionFailed {
		t.Fatalf("abort retries = %#v", failCalls)
	}
}

func TestFlowRejectsClaimedAndTokenArtifactsOwnedByAnotherFlow(t *testing.T) {
	first := newFlowTestFixture(t, nil)
	second := newFlowTestFixture(t, nil)
	_, claimed, _ := first.startAndClaim(t)
	credential := ClientCredential{Revision: claimed.record.Pins.ClientSecretRevision, Secret: []byte("secret")}
	if bundle, err := second.flow.ExchangeCode(context.Background(), claimed, credential); !errors.Is(err, ErrTokenExchangeFailed) || bundle != nil {
		t.Fatalf("foreign ExchangeCode() = %v, %v", bundle, err)
	}
	if err := second.flow.AbortClaimedAuthorization(context.Background(), claimed); !errors.Is(err, ErrCallbackRejected) {
		t.Fatalf("foreign AbortClaimedAuthorization() error = %v", err)
	}
	second.repository.mu.Lock()
	foreignFailures := len(second.repository.failCalls)
	second.repository.mu.Unlock()
	if foreignFailures != 0 {
		t.Fatalf("foreign flow failures = %d", foreignFailures)
	}
	if err := first.flow.AbortClaimedAuthorization(context.Background(), claimed); err != nil {
		t.Fatalf("owner AbortClaimedAuthorization() error = %v", err)
	}
}

func TestDirectProviderErrorUsesCanonicalAbsentCodeDigestAndExactAudit(t *testing.T) {
	fixture := newFlowTestFixture(t, func(configuration *AuthorizationConfiguration, _ *FlowPolicy) {
		makeDirectPlatformConfiguration(configuration)
	})
	audit := TransactionAuditContext{
		RequestID: identity.EntityID{3}, CorrelationID: identity.EntityID{4},
		RemoteAddress: netip.MustParseAddr("203.0.113.9"), UserAgent: "provider-error-test",
	}
	start, err := fixture.flow.StartAuthorization(context.Background(), StartAuthorizationRequest{
		Begin: testAuthorizationBegin(), Configuration: fixture.configuration, ReturnPath: "/", Audit: audit,
	})
	if err != nil {
		t.Fatal(err)
	}
	redirect, _ := url.Parse(start.RedirectURL())
	callback := url.Values{"error": {"access_denied"}, "state": {redirect.Query().Get("state")}}
	if claimed, err := fixture.flow.ClaimCallbackResolved(context.Background(), ResolvedCallbackRequest{
		RawQuery: callback.Encode(), BrowserHandle: start.BrowserHandle(), Audit: audit,
	}, callbackConfigurationResolverFunc(func(context.Context, CallbackConfigurationLookup) (AuthorizationConfiguration, error) {
		return fixture.configuration, nil
	})); !errors.Is(err, ErrCallbackRejected) || claimed != nil {
		t.Fatalf("provider error callback = %v, %v", claimed, err)
	}
	fixture.repository.mu.Lock()
	claims := append([]TransactionClaim(nil), fixture.repository.claims...)
	failures := append([]TransactionFailure(nil), fixture.repository.failures...)
	fixture.repository.mu.Unlock()
	if len(claims) != 1 || claims[0].AuthorizationCodeDigest != sha256.Sum256(nil) ||
		len(failures) != 1 || failures[0].Audit != audit || failures[0].Reason != FailureProviderResponse {
		t.Fatalf("provider error persistence = claims:%#v failures:%#v", claims, failures)
	}
}

func TestDirectCallbackEndpointFamilyIsClosed(t *testing.T) {
	fixture := newFlowTestFixture(t, nil)
	configuration := fixture.configuration
	makeDirectPlatformConfiguration(&configuration)
	configuration.RedirectURI = fixture.configuration.RedirectURI
	if _, err := fixture.flow.StartAuthorization(context.Background(), StartAuthorizationRequest{
		Begin: testAuthorizationBegin(), Configuration: configuration, ReturnPath: "/",
	}); !errors.Is(err, ErrAuthorizationRejected) {
		t.Fatalf("tenant callback flow accepted direct authority: %v", err)
	}
}
