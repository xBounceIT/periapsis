package platformsamladapter

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/periapsis-im/periapsis/services/api/internal/platformsamlauth"
)

func testOpaque(seed byte) []byte {
	return []byte(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{seed}, 32)))
}

func testBrowserTransport(t *testing.T) *BrowserTransport {
	t.Helper()
	transport, err := NewBrowserTransport(BrowserTransportPolicy{
		TransactionCookieName: DirectSAMLProductionTransactionCookie,
		ContinuationPath:      "/auth/platform/saml/totp",
	}, testInstant)
	if err != nil {
		t.Fatalf("NewBrowserTransport() error = %v", err)
	}
	return transport
}

func TestBrowserTransportStartRedirectConsumesAuthorizationStartOnEveryPath(t *testing.T) {
	fixture := newProtocolFixture(t)
	start := fixture.start(t, context.Background())
	alias := start
	originalHandle := start.BrowserHandle()
	defer clear(originalHandle)
	response, err := testBrowserTransport(t).StartRedirect(&start)
	if err != nil {
		t.Fatalf("StartRedirect() error = %v", err)
	}
	defer response.Destroy()
	if response.StatusCode != RedirectStatusSeeOther || response.Location == "" ||
		response.CacheControl != CacheControlNoStore || response.ReferrerPolicy != ReferrerPolicyNoReferrer ||
		len(response.Cookies) != 1 {
		t.Fatalf("redirect response = %q", response.String())
	}
	cookie := response.Cookies[0]
	if cookie.Name != DirectSAMLProductionTransactionCookie || cookie.Path != "/" || !cookie.Secure ||
		!cookie.HTTPOnly || !cookie.HostOnly || cookie.SameSite != SameSiteNone || cookie.MaxAge < 1 ||
		!bytes.Equal(cookie.Value, originalHandle) {
		t.Fatalf("transaction cookie = %q", cookie.String())
	}
	if handle := start.BrowserHandle(); len(handle) != 0 {
		clear(handle)
		t.Fatal("StartRedirect retained original browser handle")
	}
	if handle := alias.BrowserHandle(); len(handle) != 0 {
		clear(handle)
		t.Fatal("StartRedirect retained handle in value alias")
	}

	malformed := fixture.start(t, context.Background())
	malformedAlias := malformed
	malformed.Destroy()
	if _, err := testBrowserTransport(t).StartRedirect(&malformed); !errors.Is(err, ErrTransportRejected) {
		t.Fatalf("malformed StartRedirect() error = %v", err)
	}
	if handle := malformedAlias.BrowserHandle(); len(handle) != 0 {
		clear(handle)
		t.Fatal("malformed redirect retained aliased handle")
	}
}

func TestBrowserTransportStartRedirectIsOneUseAcrossConcurrentValueCopies(t *testing.T) {
	fixture := newProtocolFixture(t)
	start := fixture.start(t, context.Background())
	transport := testBrowserTransport(t)
	var successes atomic.Int32
	var wait sync.WaitGroup
	for range 32 {
		wait.Add(1)
		go func(copyValue platformsamlauth.AuthorizationStart) {
			defer wait.Done()
			response, err := transport.StartRedirect(&copyValue)
			defer response.Destroy()
			if err == nil {
				successes.Add(1)
			} else if !errors.Is(err, ErrTransportRejected) {
				t.Errorf("StartRedirect() error = %v", err)
			}
		}(start)
	}
	wait.Wait()
	if successes.Load() != 1 {
		t.Fatalf("concurrent redirect emissions = %d", successes.Load())
	}
	if handle := start.BrowserHandle(); len(handle) != 0 {
		clear(handle)
		t.Fatal("concurrent redirect retained owner handle")
	}
}

func TestValidSAMLRedirectRejectsNonCanonicalAuthorityAndRelayReplay(t *testing.T) {
	fixture := newProtocolFixture(t)
	start := fixture.start(t, context.Background())
	good := start.RedirectURL()
	start.Destroy()
	if !validSAMLRedirect(good) {
		t.Fatal("kernel redirect was rejected")
	}
	for name, candidate := range map[string]string{
		"http":            strings.Replace(good, "https://", "http://", 1),
		"uppercase host":  strings.Replace(good, "idp.example.test", "IDP.example.test", 1),
		"default port":    strings.Replace(good, "idp.example.test", "idp.example.test:443", 1),
		"leading port":    strings.Replace(good, "idp.example.test", "idp.example.test:0443", 1),
		"legacy ip":       strings.Replace(good, "idp.example.test", "127.1", 1),
		"backslash":       strings.Replace(good, "/sso", `/\\sso`, 1),
		"duplicate relay": good + "&RelayState=" + string(testOpaque(0x71)),
		"fragment":        good + "#fragment",
	} {
		t.Run(name, func(t *testing.T) {
			if validSAMLRedirect(candidate) {
				t.Fatalf("hostile redirect accepted: %s", candidate)
			}
		})
	}
}

func TestTransactionCapabilityIsOneUseUnderConcurrentClaimDestroy(t *testing.T) {
	transport := testBrowserTransport(t)
	handle := testOpaque(0x31)
	capability, err := transport.ClaimTransactionCookie([]RequestCookie{{
		Name: DirectSAMLProductionTransactionCookie, Value: string(handle),
	}})
	if err != nil {
		t.Fatal(err)
	}
	var successes atomic.Int32
	var wait sync.WaitGroup
	for index := range 64 {
		wait.Add(1)
		go func(destroy bool) {
			defer wait.Done()
			if destroy {
				capability.Destroy()
				return
			}
			claimed, ok := capability.Consume()
			if ok {
				successes.Add(1)
			}
			clear(claimed)
		}(index%3 == 0)
	}
	wait.Wait()
	if successes.Load() > 1 {
		t.Fatalf("transaction capability consumed %d times", successes.Load())
	}
	if claimed, ok := capability.Consume(); ok || len(claimed) != 0 {
		clear(claimed)
		t.Fatal("terminal transaction capability was reusable")
	}
	if _, err := transport.ClaimTransactionCookie([]RequestCookie{
		{Name: DirectSAMLProductionTransactionCookie, Value: string(handle)},
		{Name: DirectSAMLProductionTransactionCookie, Value: string(handle)},
	}); !errors.Is(err, ErrTransportRejected) {
		t.Fatalf("duplicate cookie error = %v", err)
	}
	clear(handle)
}

type testBrowserCredential struct {
	guard     sync.Mutex
	material  platformsamlauth.BrowserCredentialMaterial
	consumed  bool
	destroyed bool
}

func (credential *testBrowserCredential) Consume() (platformsamlauth.BrowserCredentialMaterial, bool) {
	credential.guard.Lock()
	defer credential.guard.Unlock()
	if credential.consumed || credential.destroyed {
		return platformsamlauth.BrowserCredentialMaterial{}, false
	}
	credential.consumed = true
	material := credential.material
	credential.material = platformsamlauth.BrowserCredentialMaterial{}
	return material, true
}

func (credential *testBrowserCredential) Destroy() {
	credential.guard.Lock()
	defer credential.guard.Unlock()
	credential.material.Destroy()
	credential.destroyed = true
}

type testDeliveryFinalizer struct {
	guard           sync.Mutex
	confirmCalls    int
	compensateCalls int
	confirmErr      error
	compensateErr   error
	compensateCtx   error
	onCompensate    func()
}

func (finalizer *testDeliveryFinalizer) ConfirmBrowserDelivery() error {
	finalizer.guard.Lock()
	defer finalizer.guard.Unlock()
	finalizer.confirmCalls++
	return finalizer.confirmErr
}

func (finalizer *testDeliveryFinalizer) CompensateBrowserDelivery(ctx context.Context) error {
	finalizer.guard.Lock()
	defer finalizer.guard.Unlock()
	finalizer.compensateCalls++
	finalizer.compensateCtx = ctx.Err()
	if finalizer.onCompensate != nil {
		finalizer.onCompensate()
	}
	return finalizer.compensateErr
}

type testDeliverySink struct {
	guard        sync.Mutex
	calls        int
	err          error
	disposition  platformsamlauth.Disposition
	location     string
	status       int
	cookieSecure bool
	sessionAlias []byte
	csrfAlias    []byte
	receiptAlias []byte
	mutate       func(*BrowserDelivery)
}

func (sink *testDeliverySink) DeliverDirectSAML(_ context.Context, delivery *BrowserDelivery) error {
	sink.guard.Lock()
	defer sink.guard.Unlock()
	sink.calls++
	sink.disposition = delivery.Disposition
	sink.location = delivery.Location
	sink.status = delivery.StatusCode
	sink.cookieSecure = validCredentialCookieRequirements(delivery.CookieSecurity)
	sink.sessionAlias = delivery.SessionToken
	sink.csrfAlias = delivery.CSRFToken
	sink.receiptAlias = delivery.Receipt
	if sink.mutate != nil {
		sink.mutate(delivery)
	}
	return sink.err
}

func testSessionDelivery() (*platformsamlauth.Outcome, *testBrowserCredential, []byte, []byte) {
	token, csrf := testOpaque(0x41), testOpaque(0x42)
	sessionID := testEntity(121)
	outcome := &platformsamlauth.Outcome{
		Disposition: platformsamlauth.ImmediateSession, UserID: testEntity(120), SessionID: sessionID,
		ReturnPath: "/incidents?view=mine",
	}
	credential := &testBrowserCredential{material: platformsamlauth.BrowserCredentialMaterial{
		Kind: platformsamlauth.BrowserSessionCredential, SessionID: sessionID,
		SessionToken: token, CSRFToken: csrf,
	}}
	return outcome, credential, token, csrf
}

func TestBrowserTransportConfirmsOnlyAfterSynchronousDeliveryAndClearsPlaintext(t *testing.T) {
	outcome, credential, token, csrf := testSessionDelivery()
	finalizer := &testDeliveryFinalizer{}
	sink := &testDeliverySink{}
	if err := testBrowserTransport(t).deliver(context.Background(), outcome, credential, sink, finalizer); err != nil {
		t.Fatalf("deliver() error = %v", err)
	}
	finalizer.guard.Lock()
	confirmCalls, compensateCalls := finalizer.confirmCalls, finalizer.compensateCalls
	finalizer.guard.Unlock()
	sink.guard.Lock()
	calls, status, location, secure := sink.calls, sink.status, sink.location, sink.cookieSecure
	sessionAlias, csrfAlias := sink.sessionAlias, sink.csrfAlias
	sink.guard.Unlock()
	credential.guard.Lock()
	destroyed := credential.destroyed
	credential.guard.Unlock()
	if confirmCalls != 1 || compensateCalls != 0 || calls != 1 || status != RedirectStatusSeeOther ||
		location != outcome.ReturnPath || !secure || !destroyed {
		t.Fatalf("delivery = confirm %d compensate %d sink %d status %d location %q secure %t destroyed %t",
			confirmCalls, compensateCalls, calls, status, location, secure, destroyed)
	}
	if !allZeroBytes(token) || !allZeroBytes(csrf) || !allZeroBytes(sessionAlias) || !allZeroBytes(csrfAlias) {
		t.Fatal("delivery retained plaintext after synchronous sink returned")
	}
}

func TestBrowserTransportCompensatesEveryPostCommitDeliveryFailure(t *testing.T) {
	tests := map[string]func(*platformsamlauth.Outcome, *testBrowserCredential, *testDeliverySink, *testDeliveryFinalizer) context.Context{
		"sink failure": func(_ *platformsamlauth.Outcome, _ *testBrowserCredential, sink *testDeliverySink, _ *testDeliveryFinalizer) context.Context {
			sink.err = errors.New("write failed")
			return context.Background()
		},
		"sink mutation": func(_ *platformsamlauth.Outcome, _ *testBrowserCredential, sink *testDeliverySink, _ *testDeliveryFinalizer) context.Context {
			sink.mutate = func(delivery *BrowserDelivery) { delivery.Location = "/different" }
			return context.Background()
		},
		"malformed outcome": func(outcome *platformsamlauth.Outcome, _ *testBrowserCredential, _ *testDeliverySink, _ *testDeliveryFinalizer) context.Context {
			outcome.ReturnPath = `/\\evil.example`
			return context.Background()
		},
		"decoded backslash outcome": func(outcome *platformsamlauth.Outcome, _ *testBrowserCredential, _ *testDeliverySink, _ *testDeliveryFinalizer) context.Context {
			outcome.ReturnPath = "/%5Cevil.example"
			return context.Background()
		},
		"decoded control outcome": func(outcome *platformsamlauth.Outcome, _ *testBrowserCredential, _ *testDeliverySink, _ *testDeliveryFinalizer) context.Context {
			outcome.ReturnPath = "/%0Aevil.example"
			return context.Background()
		},
		"canceled context": func(_ *platformsamlauth.Outcome, _ *testBrowserCredential, _ *testDeliverySink, _ *testDeliveryFinalizer) context.Context {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx
		},
		"confirmation failure": func(_ *platformsamlauth.Outcome, _ *testBrowserCredential, _ *testDeliverySink, finalizer *testDeliveryFinalizer) context.Context {
			finalizer.confirmErr = platformsamlauth.ErrBrowserDeliveryRejected
			return context.Background()
		},
	}
	for name, prepare := range tests {
		t.Run(name, func(t *testing.T) {
			outcome, credential, token, csrf := testSessionDelivery()
			sink := &testDeliverySink{}
			finalizer := &testDeliveryFinalizer{}
			plaintextClearedBeforeCompensation := false
			finalizer.onCompensate = func() {
				plaintextClearedBeforeCompensation = allZeroBytes(token) && allZeroBytes(csrf)
			}
			ctx := prepare(outcome, credential, sink, finalizer)
			if err := testBrowserTransport(t).deliver(ctx, outcome, credential, sink, finalizer); !errors.Is(err, ErrTransportRejected) {
				t.Fatalf("deliver() error = %v", err)
			}
			finalizer.guard.Lock()
			confirmCalls, compensateCalls := finalizer.confirmCalls, finalizer.compensateCalls
			finalizer.guard.Unlock()
			if compensateCalls != 1 || name != "confirmation failure" && confirmCalls != 0 ||
				name == "confirmation failure" && confirmCalls != 1 {
				t.Fatalf("finalizer calls = confirm %d compensate %d", confirmCalls, compensateCalls)
			}
			if !plaintextClearedBeforeCompensation || !allZeroBytes(token) || !allZeroBytes(csrf) {
				t.Fatal("failure path retained plaintext")
			}
		})
	}
}

func TestBrowserTransportSurfacesInconclusiveCompensationAsUnavailable(t *testing.T) {
	outcome, credential, token, csrf := testSessionDelivery()
	finalizer := &testDeliveryFinalizer{compensateErr: platformsamlauth.ErrBrowserDeliveryUnavailable}
	sink := &testDeliverySink{err: errors.New("write failed")}
	if err := testBrowserTransport(t).deliver(context.Background(), outcome, credential, sink, finalizer); !errors.Is(err, ErrTransportUnavailable) || errors.Is(err, ErrTransportRejected) {
		t.Fatalf("deliver() error = %v", err)
	}
	if !allZeroBytes(token) || !allZeroBytes(csrf) {
		t.Fatal("unavailable compensation path retained plaintext")
	}
}

func TestBrowserTransportForcesTOTPContinuationPath(t *testing.T) {
	receipt := testOpaque(0x61)
	continuationID := testEntity(122)
	outcome := &platformsamlauth.Outcome{
		Disposition: platformsamlauth.TOTPContinuation, UserID: testEntity(120),
		ContinuationID: continuationID, ReturnPath: "/incidents",
	}
	credential := &testBrowserCredential{material: platformsamlauth.BrowserCredentialMaterial{
		Kind: platformsamlauth.BrowserContinuationCredential, ContinuationID: continuationID,
		ExpiresAt: testInstant().Add(5 * time.Minute), Receipt: receipt,
	}}
	sink := &testDeliverySink{}
	if err := testBrowserTransport(t).deliver(context.Background(), outcome, credential, sink, &testDeliveryFinalizer{}); err != nil {
		t.Fatal(err)
	}
	sink.guard.Lock()
	location, disposition, alias := sink.location, sink.disposition, sink.receiptAlias
	sink.guard.Unlock()
	if location != "/auth/platform/saml/totp" || disposition != platformsamlauth.TOTPContinuation || !allZeroBytes(alias) ||
		!allZeroBytes(receipt) {
		t.Fatalf("continuation delivery = location %q disposition %q", location, disposition)
	}
}
