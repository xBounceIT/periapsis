package federatedsaml

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

type callbackConfigurationResolverFunc func(context.Context, CallbackConfigurationLookup) (Configuration, error)

func (function callbackConfigurationResolverFunc) ResolveSAMLCallbackConfiguration(
	ctx context.Context,
	lookup CallbackConfigurationLookup,
) (Configuration, error) {
	return function(ctx, lookup)
}

func TestValidateCallbackResolvedDerivesConfigurationFromBrowserBoundTransaction(t *testing.T) {
	fixture := newTestFixture(t)
	callback := callbackRequest(fixture, validResponseDocument(fixture))
	pending := fixture.repo.current()
	var calls atomic.Int32
	validated, err := fixture.kernel.ValidateCallbackResolved(context.Background(), ResolvedCallbackRequest{
		MediaType: callback.MediaType, RawForm: callback.RawForm, BrowserHandle: callback.BrowserHandle,
	}, callbackConfigurationResolverFunc(func(ctx context.Context, lookup CallbackConfigurationLookup) (Configuration, error) {
		calls.Add(1)
		if ctx.Err() != nil || lookup.TransactionID != pending.ID || lookup.ExpectedVersion != pending.Version ||
			!samePins(lookup.Pins, pending.Pins) {
			return Configuration{}, errors.New("unexpected lookup")
		}
		return fixture.config, nil
	}))
	if err != nil || validated == nil || calls.Load() != 1 {
		t.Fatalf("ValidateCallbackResolved() = %v, %v, calls=%d", validated, err, calls.Load())
	}
	result, err := fixture.kernel.Consume(context.Background(), validated, &atomicConsumer{})
	if err != nil || result.Category != ConsumerSuccess {
		t.Fatalf("Consume() = %v, %v", result, err)
	}
}

func TestValidateCallbackResolvedRejectsPinDriftAndMalformedBrowserBeforeProof(t *testing.T) {
	for name, mutate := range map[string]func(*Configuration){
		"binding revision":       func(value *Configuration) { value.BindingRevision++ },
		"authorization revision": func(value *Configuration) { value.AuthorizationRevision++ },
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newTestFixture(t)
			callback := callbackRequest(fixture, validResponseDocument(fixture))
			var calls atomic.Int32
			_, err := fixture.kernel.ValidateCallbackResolved(context.Background(), ResolvedCallbackRequest{
				MediaType: callback.MediaType, RawForm: callback.RawForm, BrowserHandle: callback.BrowserHandle,
			}, callbackConfigurationResolverFunc(func(context.Context, CallbackConfigurationLookup) (Configuration, error) {
				calls.Add(1)
				configuration := fixture.config
				mutate(&configuration)
				return configuration, nil
			}))
			if !errors.Is(err, ErrCallbackRejected) || calls.Load() != 1 {
				t.Fatalf("error=%v calls=%d", err, calls.Load())
			}
		})
	}

	fixture := newTestFixture(t)
	callback := callbackRequest(fixture, validResponseDocument(fixture))
	var calls atomic.Int32
	_, err := fixture.kernel.ValidateCallbackResolved(context.Background(), ResolvedCallbackRequest{
		MediaType: callback.MediaType, RawForm: callback.RawForm, BrowserHandle: []byte("not-a-browser-handle"),
	}, callbackConfigurationResolverFunc(func(context.Context, CallbackConfigurationLookup) (Configuration, error) {
		calls.Add(1)
		return fixture.config, nil
	}))
	if !errors.Is(err, ErrCallbackRejected) || calls.Load() != 0 {
		t.Fatalf("malformed browser error=%v calls=%d", err, calls.Load())
	}
}

func TestValidateCallbackResolvedRejectsRepositoryTransactionsOutsideKernelBounds(t *testing.T) {
	for name, mutate := range map[string]func(*PendingTransaction){
		"missing material identity": func(value *PendingTransaction) { value.MaterialID = identity.EntityID{} },
		"non-v7 material identity":  func(value *PendingTransaction) { value.MaterialID[6] = 0x40 },
		"overlong lifetime":         func(value *PendingTransaction) { value.ExpiresAt = value.CreatedAt.Add(16 * time.Minute) },
		"undersized lifetime": func(value *PendingTransaction) {
			value.ExpiresAt = value.CreatedAt.Add(time.Minute - time.Microsecond)
		},
		"database revision without headroom": func(value *PendingTransaction) {
			value.Version = maximumPersistentRevision
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newTestFixture(t)
			callback := callbackRequest(fixture, validResponseDocument(fixture))
			fixture.repo.mu.Lock()
			mutate(&fixture.repo.pending)
			fixture.repo.mu.Unlock()
			var calls atomic.Int32
			_, err := fixture.kernel.ValidateCallbackResolved(context.Background(), ResolvedCallbackRequest{
				MediaType: callback.MediaType, RawForm: callback.RawForm, BrowserHandle: callback.BrowserHandle,
			}, callbackConfigurationResolverFunc(func(context.Context, CallbackConfigurationLookup) (Configuration, error) {
				calls.Add(1)
				return fixture.config, nil
			}))
			if !errors.Is(err, ErrCallbackRejected) || calls.Load() != 0 {
				t.Fatalf("error=%v resolver_calls=%d", err, calls.Load())
			}
		})
	}
}

func TestResolvedCallbackFormattingRedactsArtifacts(t *testing.T) {
	fixture := newTestFixture(t)
	callback := callbackRequest(fixture, validResponseDocument(fixture))
	pending := fixture.repo.current()
	values := []string{
		ResolvedCallbackRequest{MediaType: callback.MediaType, RawForm: callback.RawForm, BrowserHandle: callback.BrowserHandle}.String(),
		CallbackConfigurationLookup{TransactionID: pending.ID, ExpectedVersion: pending.Version, Pins: pending.Pins}.String(),
	}
	for _, formatted := range values {
		for _, secret := range []string{fixture.relay, "subject-secret-value", "email-secret@example.test"} {
			if strings.Contains(formatted, secret) {
				t.Fatalf("format leaked %q: %s", secret, formatted)
			}
		}
	}
}

func FuzzValidateCallbackResolvedRejectsHostileBrowserArtifacts(f *testing.F) {
	f.Add("application/x-www-form-urlencoded", "SAMLResponse=x&RelayState=y", "browser")
	f.Add("text/xml", "<!DOCTYPE x SYSTEM 'file:///secret'>", strings.Repeat("A", 43))
	f.Fuzz(func(t *testing.T, mediaType, rawForm, browser string) {
		fixture := newTestFixture(t)
		var calls atomic.Int32
		_, _ = fixture.kernel.ValidateCallbackResolved(context.Background(), ResolvedCallbackRequest{
			MediaType: mediaType, RawForm: []byte(rawForm), BrowserHandle: []byte(browser),
		}, callbackConfigurationResolverFunc(func(context.Context, CallbackConfigurationLookup) (Configuration, error) {
			calls.Add(1)
			return fixture.config, nil
		}))
		if calls.Load() > 1 {
			t.Fatalf("resolver called %d times", calls.Load())
		}
	})
}
