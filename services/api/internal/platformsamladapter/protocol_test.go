package platformsamladapter

import (
	"context"
	"encoding/base64"
	"errors"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
	"github.com/periapsis-im/periapsis/services/api/internal/platformsamlauth"
)

func TestProtocolAdapterStartBindsFullDirectAuthority(t *testing.T) {
	fixture := newProtocolFixture(t)
	started := fixture.start(t, context.Background())
	createCalls, recoverCalls, lookupCalls, abortCalls := fixture.persistence.counts()
	if createCalls != 1 || recoverCalls != 0 || lookupCalls != 0 || abortCalls != 0 {
		t.Fatalf("persistence calls = create %d recover %d lookup %d abort %d", createCalls, recoverCalls, lookupCalls, abortCalls)
	}
	fixture.persistence.guard.Lock()
	request := fixture.persistence.createRequest
	fixture.persistence.guard.Unlock()
	if request.Grant != fixture.request.Grant || request.Protocol.Begin != fixture.request.Protocol.Begin ||
		request.Protocol.Current.Pins != fixture.pins.Protocol ||
		request.Protocol.Current.Pins.Authority != federatedsaml.DirectPlatformCeremonyAuthority ||
		request.Protocol.Current.Pins.Provider.Scope != identity.PlatformProviderScope ||
		request.Protocol.Current.Pins.Provider.TenantID != (identity.EntityID{}) ||
		request.Protocol.Current.Pins.BindingID != (identity.EntityID{}) || started.TransactionID() != request.Protocol.Current.ID {
		t.Fatalf("create did not bind exact direct authority: request=%q start=%q", request.String(), started.String())
	}

	invalid := newProtocolFixture(t)
	invalid.request.Protocol.Configuration.Provider.Scope = identity.TenantProviderScope
	if _, err := invalid.adapter.StartDirectSAML(context.Background(), invalid.request); !errors.Is(err, platformsamlauth.ErrAuthenticationDenied) {
		t.Fatalf("cross-authority StartDirectSAML() error = %v", err)
	}
	createCalls, _, _, _ = invalid.persistence.counts()
	if createCalls != 0 {
		t.Fatalf("cross-authority start reached persistence %d times", createCalls)
	}

	drifted := newProtocolFixture(t)
	drifted.request.Protocol.Configuration.ClockSkew += time.Microsecond
	if _, err := drifted.adapter.StartDirectSAML(context.Background(), drifted.request); !errors.Is(err, platformsamlauth.ErrAuthenticationDenied) {
		t.Fatalf("configuration-digest drift StartDirectSAML() error = %v", err)
	}
	createCalls, _, _, _ = drifted.persistence.counts()
	if createCalls != 0 {
		t.Fatalf("configuration-digest drift reached persistence %d times", createCalls)
	}
}

func TestProtocolAdapterRecoversAmbiguousCreateWithDetachedBoundedContext(t *testing.T) {
	fixture := newProtocolFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	fixture.persistence.guard.Lock()
	fixture.persistence.createErr = errors.New("ambiguous commit")
	fixture.persistence.cancelOnCreate = cancel
	fixture.persistence.guard.Unlock()

	started, err := fixture.adapter.StartDirectSAML(ctx, fixture.request)
	if err != nil || started.TransactionID() == (federatedsaml.TransactionID{}) {
		t.Fatalf("StartDirectSAML() = %q, %v", started.String(), err)
	}
	createCalls, recoverCalls, _, _ := fixture.persistence.counts()
	fixture.persistence.guard.Lock()
	recoveryContextErr := fixture.persistence.recoverContextErr
	fixture.persistence.guard.Unlock()
	if createCalls != 1 || recoverCalls != 1 || recoveryContextErr != nil || ctx.Err() == nil {
		t.Fatalf("recovery = create %d recover %d recovery context %v parent %v", createCalls, recoverCalls, recoveryContextErr, ctx.Err())
	}

	bounded := newProtocolFixture(t)
	bounded.persistence.guard.Lock()
	bounded.persistence.createErr = errors.New("ambiguous commit")
	bounded.persistence.recoverBlock = true
	bounded.persistence.guard.Unlock()
	startedAt := time.Now()
	if _, err := bounded.adapter.StartDirectSAML(context.Background(), bounded.request); !errors.Is(err, platformsamlauth.ErrAuthenticationUnavailable) {
		t.Fatalf("bounded StartDirectSAML() error = %v", err)
	}
	if elapsed := time.Since(startedAt); elapsed > 500*time.Millisecond {
		t.Fatalf("detached recovery was not bounded: %s", elapsed)
	}
}

func TestProtocolAdapterCallbackUsesOneResolverAndExactOuterInnerLookups(t *testing.T) {
	fixture := newProtocolFixture(t)
	started := fixture.start(t, context.Background())
	request := testCallbackRequest(t, fixture, started)
	resolver := &testConfigurationResolver{configuration: fixture.configuration}

	validated, err := fixture.adapter.ValidateDirectSAMLCallbackResolved(context.Background(), request, resolver)
	if err != nil || validated == nil {
		t.Fatalf("ValidateDirectSAMLCallbackResolved() = %v, %v", validated, err)
	}
	_, _, lookupCalls, abortCalls := fixture.persistence.counts()
	if resolver.calls.Load() != 1 || lookupCalls != 2 || abortCalls != 0 {
		t.Fatalf("callback calls = resolver %d lookup %d abort %d", resolver.calls.Load(), lookupCalls, abortCalls)
	}
	consumer := &testApplicationConsumer{}
	result, err := fixture.adapter.ConsumeDirectSAML(context.Background(), validated, consumer)
	if err != nil || result.Category != federatedsaml.ConsumerSuccess || consumer.calls.Load() != 1 {
		t.Fatalf("ConsumeDirectSAML() = %q, %v calls=%d", result.Category, err, consumer.calls.Load())
	}
	if _, err := fixture.adapter.ConsumeDirectSAML(context.Background(), validated, consumer); !errors.Is(err, platformsamlauth.ErrAuthenticationDenied) {
		t.Fatalf("callback replay error = %v", err)
	}
	if consumer.calls.Load() != 1 {
		t.Fatalf("callback replay invoked consumer %d times", consumer.calls.Load())
	}
}

func TestCallbackLookupCaptureFailsClosedOnUnexpectedSequence(t *testing.T) {
	fixture := newProtocolFixture(t)
	fixture.start(t, context.Background())
	fixture.persistence.guard.Lock()
	snapshot := fixture.persistence.snapshot
	fixture.persistence.guard.Unlock()
	lookup := federatedsaml.CallbackConfigurationLookup{
		TransactionID: snapshot.Pending.ID, ExpectedVersion: snapshot.Pending.Version, Pins: snapshot.Pins.Protocol,
	}

	t.Run("identical second observation", func(t *testing.T) {
		capture := &callbackCapture{}
		capture.observe(snapshot)
		capture.observe(snapshot)
		_, seen, violated := capture.snapshot()
		if !seen || !violated {
			t.Fatalf("capture state = seen %t violated %t", seen, violated)
		}
	})

	t.Run("outer then exact inner only", func(t *testing.T) {
		capture := &callbackCapture{}
		if !capture.recordLookup(snapshot) || !capture.expectKernelRevalidation(lookup) || !capture.recordLookup(snapshot) {
			t.Fatal("exact outer/inner sequence was rejected")
		}
		if capture.recordLookup(snapshot) {
			t.Fatal("third lookup was accepted")
		}
		_, _, violated := capture.snapshot()
		if !violated {
			t.Fatal("third lookup did not poison capture")
		}
	})

	t.Run("different inner", func(t *testing.T) {
		capture := &callbackCapture{}
		changed := snapshot
		changed.Pins.Protocol.SecurityRevision++
		if !capture.recordLookup(snapshot) || !capture.expectKernelRevalidation(lookup) || capture.recordLookup(changed) {
			t.Fatal("different inner lookup was accepted")
		}
	})

	t.Run("inner without outer", func(t *testing.T) {
		capture := &callbackCapture{}
		if capture.expectKernelRevalidation(lookup) {
			t.Fatal("inner lookup without outer was accepted")
		}
	})

	t.Run("concurrent reentrancy", func(t *testing.T) {
		capture := &callbackCapture{}
		var successes atomic.Int32
		var wait sync.WaitGroup
		for range 32 {
			wait.Add(1)
			go func() {
				defer wait.Done()
				if capture.recordLookup(snapshot) {
					successes.Add(1)
				}
			}()
		}
		wait.Wait()
		if successes.Load() != 1 {
			t.Fatalf("concurrent authority observations accepted = %d", successes.Load())
		}
	})
}

func TestProtocolAdapterRejectsDriftAndTerminalizesClaimOnce(t *testing.T) {
	fixture := newProtocolFixture(t)
	started := fixture.start(t, context.Background())
	request := testCallbackRequest(t, fixture, started)
	fixture.persistence.guard.Lock()
	fixture.persistence.lookupMutateAt = 2
	fixture.persistence.guard.Unlock()
	resolver := &testConfigurationResolver{configuration: fixture.configuration}
	if _, err := fixture.adapter.ValidateDirectSAMLCallbackResolved(context.Background(), request, resolver); err == nil {
		t.Fatal("inner pin substitution was accepted")
	}
	_, _, lookupCalls, abortCalls := fixture.persistence.counts()
	if lookupCalls != 2 || abortCalls != 1 {
		t.Fatalf("drift failure calls = lookup %d abort %d", lookupCalls, abortCalls)
	}

	malformed := newProtocolFixture(t)
	started = malformed.start(t, context.Background())
	request = testCallbackRequest(t, malformed, started)
	form, err := url.ParseQuery(string(request.Protocol.RawForm))
	if err != nil {
		t.Fatal(err)
	}
	form.Set("SAMLResponse", base64.StdEncoding.EncodeToString([]byte("<malformed")))
	request.Protocol.RawForm = []byte(form.Encode())
	malformed.persistence.guard.Lock()
	malformed.persistence.abortReceiptMutation = func(receipt *DirectSAMLAbortReceipt) { receipt.Version++ }
	malformed.persistence.guard.Unlock()
	if _, err := malformed.adapter.ValidateDirectSAMLCallbackResolved(context.Background(), request, &testConfigurationResolver{configuration: malformed.configuration}); err == nil {
		t.Fatal("malformed response was accepted")
	}
	_, _, lookupCalls, abortCalls = malformed.persistence.counts()
	if lookupCalls != 2 || abortCalls != 2 {
		t.Fatalf("failure invoked abortSnapshot more than once: lookup %d abort attempts %d", lookupCalls, abortCalls)
	}
}

func TestAbortDirectSAMLCallbackIsDetachedIdempotentAndRemovesCapability(t *testing.T) {
	fixture := newProtocolFixture(t)
	started := fixture.start(t, context.Background())
	request := testCallbackRequest(t, fixture, started)
	validated, err := fixture.adapter.ValidateDirectSAMLCallbackResolved(
		context.Background(), request, &testConfigurationResolver{configuration: fixture.configuration},
	)
	if err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := fixture.adapter.AbortDirectSAMLCallback(canceled, validated, testAudit(70)); err != nil {
		t.Fatalf("AbortDirectSAMLCallback() error = %v", err)
	}
	_, _, _, abortCalls := fixture.persistence.counts()
	if abortCalls != 1 {
		t.Fatalf("abort calls = %d", abortCalls)
	}
	if err := fixture.adapter.AbortDirectSAMLCallback(context.Background(), validated, testAudit(70)); !errors.Is(err, platformsamlauth.ErrAuthenticationDenied) {
		t.Fatalf("retained callback abort error = %v", err)
	}
	_, _, _, secondAbortCalls := fixture.persistence.counts()
	if secondAbortCalls != abortCalls {
		t.Fatalf("removed callback reached persistence: %d -> %d", abortCalls, secondAbortCalls)
	}
}

func TestAbortSnapshotUsesFreshBoundedContextPerAttempt(t *testing.T) {
	fixture := newProtocolFixture(t)
	fixture.start(t, context.Background())
	fixture.persistence.guard.Lock()
	snapshot := fixture.persistence.snapshot
	fixture.persistence.abortFirstWait = true
	fixture.persistence.guard.Unlock()
	if !fixture.adapter.abortSnapshot(context.Background(), snapshot, testAudit(80), AbortCallbackRejected) {
		t.Fatal("second abort attempt did not receive a fresh context")
	}
	_, _, _, abortCalls := fixture.persistence.counts()
	if abortCalls != 2 {
		t.Fatalf("abort calls = %d", abortCalls)
	}
}

func TestValidAbortReceiptRequiresExactSingleSuccessor(t *testing.T) {
	fixture := newProtocolFixture(t)
	fixture.start(t, context.Background())
	fixture.persistence.guard.Lock()
	snapshot := fixture.persistence.snapshot
	fixture.persistence.guard.Unlock()
	request := DirectSAMLAbortRequest{
		Transaction: federatedsaml.CallbackConfigurationLookup{
			TransactionID: snapshot.Pending.ID, ExpectedVersion: snapshot.Pending.Version, Pins: snapshot.Pins.Protocol,
		},
		OperationRunID: snapshot.Pending.MaterialID, Pins: snapshot.Pins,
		Reason: AbortCallbackRejected, FailedAt: testInstant(), Audit: testAudit(90),
	}
	for _, disposition := range []DirectSAMLAbortDisposition{AbortTerminalized, AbortAlreadyTerminal} {
		receipt := DirectSAMLAbortReceipt{
			Disposition: disposition, TransactionID: request.Transaction.TransactionID,
			OperationRunID: request.OperationRunID, Version: request.Transaction.ExpectedVersion + 1,
			State: federatedsaml.TransactionFailed, Pins: request.Pins,
		}
		if !validAbortReceipt(receipt, request) {
			t.Fatalf("valid %s receipt rejected", disposition)
		}
		receipt.Version++
		if validAbortReceipt(receipt, request) {
			t.Fatalf("%s arbitrary version jump accepted", disposition)
		}
	}
}
