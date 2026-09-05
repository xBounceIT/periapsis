package platformsamlauth

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

func completedOutcome(t *testing.T) (testHarness, Outcome) {
	t.Helper()
	harness := newTestHarness(t, identity.AssuranceMFA, false)
	outcome, err := harness.application.Complete(context.Background(), harness.request)
	if err != nil || outcome.delivery == nil {
		t.Fatalf("Complete() = %q, %v", outcome.String(), err)
	}
	return harness, outcome
}

func TestBrowserDeliveryAuthorityConfirmsExactlyOnceAndCannotThenCompensate(t *testing.T) {
	harness, outcome := completedOutcome(t)
	copyValue := outcome
	if err := outcome.ConfirmBrowserDelivery(); err != nil {
		t.Fatalf("ConfirmBrowserDelivery() error = %v", err)
	}
	if err := copyValue.ConfirmBrowserDelivery(); !errors.Is(err, ErrBrowserDeliveryRejected) {
		t.Fatalf("second confirmation error = %v", err)
	}
	if err := copyValue.CompensateBrowserDelivery(context.Background()); !errors.Is(err, ErrBrowserDeliveryRejected) {
		t.Fatalf("compensation after confirmation error = %v", err)
	}
	harness.apply.guard.Lock()
	cleanupCalls, active := harness.apply.cleanupCalls, harness.apply.active
	harness.apply.guard.Unlock()
	if cleanupCalls != 0 || !active {
		t.Fatalf("confirmed delivery cleanup = calls %d active %t", cleanupCalls, active)
	}
}

func TestNonSuccessApplyNeverCreatesBrowserDeliveryAuthority(t *testing.T) {
	harness := newTestHarness(t, identity.AssuranceMFA, false)
	harness.apply.guard.Lock()
	harness.apply.applyCategory = ApplyStale
	harness.apply.guard.Unlock()
	outcome, err := harness.application.Complete(context.Background(), harness.request)
	if err == nil || outcome.delivery != nil || outcome.Credential != nil {
		t.Fatalf("non-success Complete() = %q, %v", outcome.String(), err)
	}
}

func TestBrowserDeliveryAuthorityRetriesInconclusiveCleanupAndThenIsIdempotent(t *testing.T) {
	harness, outcome := completedOutcome(t)
	harness.apply.guard.Lock()
	harness.apply.cleanupErr = errors.New("ambiguous cleanup")
	harness.apply.guard.Unlock()
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := outcome.CompensateBrowserDelivery(canceled); !errors.Is(err, ErrBrowserDeliveryUnavailable) {
		t.Fatalf("inconclusive compensation error = %v", err)
	}
	harness.apply.guard.Lock()
	firstCalls, active := harness.apply.cleanupCalls, harness.apply.active
	harness.apply.cleanupErr = nil
	harness.apply.guard.Unlock()
	if firstCalls != 2 || !active {
		t.Fatalf("inconclusive cleanup = calls %d active %t", firstCalls, active)
	}
	if err := outcome.CompensateBrowserDelivery(canceled); err != nil {
		t.Fatalf("retry compensation error = %v", err)
	}
	harness.apply.guard.Lock()
	secondCalls, active, reason := harness.apply.cleanupCalls, harness.apply.active, harness.apply.cleanupReason
	harness.apply.guard.Unlock()
	if secondCalls != 3 || active || reason != CleanupDeliveryFailed {
		t.Fatalf("cleanup retry = calls %d active %t reason %q", secondCalls, active, reason)
	}
	if err := outcome.CompensateBrowserDelivery(context.Background()); err != nil {
		t.Fatalf("idempotent compensation error = %v", err)
	}
	harness.apply.guard.Lock()
	finalCalls := harness.apply.cleanupCalls
	harness.apply.guard.Unlock()
	if finalCalls != secondCalls {
		t.Fatalf("compensated capability repeated DB cleanup: %d -> %d", secondCalls, finalCalls)
	}
}

func TestBrowserDeliveryAuthorityRejectsMutatedCopies(t *testing.T) {
	harness, outcome := completedOutcome(t)
	mutated := outcome
	mutated.ReturnPath = "/different"
	if err := mutated.ConfirmBrowserDelivery(); !errors.Is(err, ErrBrowserDeliveryRejected) {
		t.Fatalf("mutated confirmation error = %v", err)
	}
	if err := mutated.CompensateBrowserDelivery(context.Background()); !errors.Is(err, ErrBrowserDeliveryRejected) {
		t.Fatalf("mutated compensation error = %v", err)
	}
	harness.apply.guard.Lock()
	cleanupCalls, active := harness.apply.cleanupCalls, harness.apply.active
	harness.apply.guard.Unlock()
	if cleanupCalls != 0 || !active {
		t.Fatalf("mutated copy changed state: calls %d active %t", cleanupCalls, active)
	}
	if err := outcome.CompensateBrowserDelivery(context.Background()); err != nil {
		t.Fatalf("exact compensation error = %v", err)
	}
}

func TestBrowserDeliveryAuthoritySerializesConcurrentConfirmAndCompensateCopies(t *testing.T) {
	for iteration := range 25 {
		harness, outcome := completedOutcome(t)
		left, right := outcome, outcome
		start := make(chan struct{})
		results := make(chan error, 2)
		var wait sync.WaitGroup
		wait.Add(2)
		go func() {
			defer wait.Done()
			<-start
			results <- left.ConfirmBrowserDelivery()
		}()
		go func() {
			defer wait.Done()
			<-start
			results <- right.CompensateBrowserDelivery(context.Background())
		}()
		close(start)
		wait.Wait()
		close(results)
		successes := 0
		for err := range results {
			if err == nil {
				successes++
			} else if !errors.Is(err, ErrBrowserDeliveryRejected) {
				t.Fatalf("iteration %d unexpected race error = %v", iteration, err)
			}
		}
		if successes != 1 {
			t.Fatalf("iteration %d terminal transitions = %d", iteration, successes)
		}
		harness.apply.guard.Lock()
		cleanupCalls, active := harness.apply.cleanupCalls, harness.apply.active
		harness.apply.guard.Unlock()
		if cleanupCalls == 0 && !active || cleanupCalls == 1 && active || cleanupCalls > 1 {
			t.Fatalf("iteration %d inconsistent terminal state: calls %d active %t", iteration, cleanupCalls, active)
		}
	}
}

type boundedCleanupApply struct {
	guard    sync.Mutex
	calls    int
	entryErr []error
	requests []CleanupRequest
}

func (*boundedCleanupApply) ApplyDirectSAML(context.Context, ApplyRequest) (ApplyResult, error) {
	return ApplyResult{}, errors.New("unused")
}
func (*boundedCleanupApply) RecoverDirectSAML(context.Context, RecoveryLookup) (RecoveryResult, error) {
	return RecoveryResult{}, errors.New("unused")
}
func (*boundedCleanupApply) RejectDirectSAML(context.Context, RejectRequest) error {
	return errors.New("unused")
}
func (apply *boundedCleanupApply) CleanupDirectSAML(ctx context.Context, request CleanupRequest) error {
	apply.guard.Lock()
	apply.calls++
	call := apply.calls
	apply.entryErr = append(apply.entryErr, ctx.Err())
	apply.requests = append(apply.requests, request)
	apply.guard.Unlock()
	if call == 1 {
		<-ctx.Done()
		return ctx.Err()
	}
	return nil
}

func TestBrowserDeliveryCompensationUsesFreshDetachedBoundedContextAndOriginalAudit(t *testing.T) {
	harness, outcome := completedOutcome(t)
	harness.apply.guard.Lock()
	result := applyResultForRequest(harness.apply.request, ApplySuccess)
	harness.apply.guard.Unlock()
	apply := &boundedCleanupApply{}
	outcome.delivery = newBrowserDeliveryAuthority(
		apply, func() time.Time { return harness.now.Add(time.Minute) }, 10*time.Millisecond,
		result, harness.audit, outcome,
	)
	if outcome.delivery == nil {
		t.Fatal("newBrowserDeliveryAuthority() rejected valid outcome")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := outcome.CompensateBrowserDelivery(ctx); err != nil {
		t.Fatalf("CompensateBrowserDelivery() error = %v", err)
	}
	apply.guard.Lock()
	calls := apply.calls
	entryErr := append([]error(nil), apply.entryErr...)
	requests := append([]CleanupRequest(nil), apply.requests...)
	apply.guard.Unlock()
	if calls != 2 || len(entryErr) != 2 || entryErr[0] != nil || entryErr[1] != nil {
		t.Fatalf("cleanup contexts = calls %d entry errors %v", calls, entryErr)
	}
	for _, request := range requests {
		if request.Result != result || request.Audit != harness.audit || request.Reason != CleanupDeliveryFailed ||
			request.CleanedUpAt != harness.now.Add(time.Minute) {
			t.Fatalf("cleanup request drifted: %q", request.String())
		}
	}
}

func TestAuthorizationStartDestroyClearsAllValueAliasesConcurrently(t *testing.T) {
	_, _, start, _ := directTestConfigurationAndPins(t)
	alias := start
	handle := start.BrowserHandle()
	if len(handle) == 0 {
		t.Fatal("test authorization start has no handle")
	}
	defer clear(handle)
	var wait sync.WaitGroup
	for index := range 32 {
		wait.Add(1)
		go func(copyValue AuthorizationStart, destroy bool) {
			defer wait.Done()
			if destroy {
				copyValue.Destroy()
				return
			}
			copyHandle := copyValue.BrowserHandle()
			clear(copyHandle)
		}(alias, index%2 == 0)
	}
	wait.Wait()
	if got := start.BrowserHandle(); len(got) != 0 {
		clear(got)
		t.Fatal("original retained handle after alias destroy")
	}
	if got := alias.BrowserHandle(); len(got) != 0 {
		clear(got)
		t.Fatal("value alias retained handle after destroy")
	}
	start.Destroy()
	alias.Destroy()
}
