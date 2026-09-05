package oidcmaintenance

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedoidc"
)

func TestWorkerRefreshesPreclaimedSnapshotAcrossAuthorityScopes(t *testing.T) {
	for _, authority := range []string{"tenant", "admitted_platform", "direct_platform"} {
		t.Run(authority, func(t *testing.T) {
			now := oidcMaintenanceTestNow()
			keyring := oidcMaintenanceTestKeyring(t)
			claim := oidcMaintenanceRefreshClaim(t, keyring, authority, now)
			repository := &oidcMaintenanceFakeRepository{}
			repository.claim = onceOIDCWork(KindRefresh, &Work{Kind: KindRefresh, Refresh: &claim})
			repository.load = encryptedOIDCSecretLoader(t, keyring, []byte("historical-client-secret"))
			upstream := &oidcMaintenanceFakeUpstream{refresh: func(
				_ context.Context,
				request federatedoidc.StoredRefreshExchangeRequest,
				requestNow time.Time,
			) (RefreshResult, error) {
				if request.EndpointURL != claim.Endpoint || request.ClientAuthentication != claim.ClientAuthentication ||
					request.ClientID != claim.ClientID || string(request.ClientSecret) != "historical-client-secret" ||
					string(request.RefreshToken) != "claimed-refresh-token" || !requestNow.Equal(now) {
					t.Fatalf("unexpected refresh request: %s", request.String())
				}
				return RefreshResult{
					RefreshToken: []byte("rotated-refresh-token"), AccessExpiresAt: now.Add(2 * time.Hour),
				}, nil
			}}
			worker := oidcMaintenanceTestWorker(t, repository, upstream, keyring, now, 3)

			summary, err := worker.RunOnce(context.Background())
			if err != nil {
				t.Fatalf("RunOnce() error = %v", err)
			}
			if summary != (Summary{Dispatches: 3, Claimed: 1, RefreshRotated: 1}) {
				t.Fatalf("RunOnce() summary = %+v", summary)
			}
			if got, want := repository.claimKinds(), []Kind{KindLogoutRetry, KindRefresh, KindScrub}; !reflect.DeepEqual(got, want) {
				t.Fatalf("claim kinds = %v, want %v", got, want)
			}
			if upstream.refreshCallCount() != 1 || repository.refreshCompletionCount() != 1 {
				t.Fatalf("refresh calls/completions = %d/%d, want 1/1",
					upstream.refreshCallCount(), repository.refreshCompletionCount())
			}
			lookup := repository.secretLookups()[0]
			assertOIDCMaintenanceLookup(t, authority, claim, lookup)
			completion := repository.refreshCompletions()[0]
			if completion.Outcome != RefreshRotated || completion.ExpectedGeneration != claim.Generation ||
				completion.ExpectedVersion != claim.Version || completion.SuccessorGeneration != claim.Generation+1 ||
				completion.AccessExpiresAt != claim.MaterialExpiresAt ||
				completion.AccessExpiresAt.After(claim.AbsoluteSessionExpiry) {
				t.Fatalf("unexpected refresh completion: %s", completion.String())
			}
			successor := decryptOIDCMaintenanceToken(t, keyring, claim, completion.SuccessorToken)
			defer clear(successor)
			if string(successor) != "rotated-refresh-token" ||
				completion.SuccessorDigest != sha256.Sum256(successor) {
				t.Fatal("successor refresh material did not round-trip")
			}
		})
	}
}

func TestWorkerTerminalizesSuccessorThatExpiresDuringRefresh(t *testing.T) {
	now := oidcMaintenanceTestNow()
	keyring := oidcMaintenanceTestKeyring(t)
	claim := oidcMaintenanceRefreshClaim(t, keyring, "tenant", now)
	repository := &oidcMaintenanceFakeRepository{
		claim: onceOIDCWork(KindRefresh, &Work{Kind: KindRefresh, Refresh: &claim}),
		load:  encryptedOIDCSecretLoader(t, keyring, []byte("historical-client-secret")),
	}
	upstream := &oidcMaintenanceFakeUpstream{refresh: func(
		_ context.Context,
		_ federatedoidc.StoredRefreshExchangeRequest,
		requestNow time.Time,
	) (RefreshResult, error) {
		time.Sleep(20 * time.Millisecond)
		return RefreshResult{
			RefreshToken:    []byte("rotated-refresh-token"),
			AccessExpiresAt: requestNow.Add(10 * time.Millisecond),
		}, nil
	}}
	worker := oidcMaintenanceTestWorker(t, repository, upstream, keyring, now, 3)

	summary, err := worker.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	if summary != (Summary{Dispatches: 3, Claimed: 1, DeadLettered: 1}) {
		t.Fatalf("RunOnce() summary = %+v", summary)
	}
	completions := repository.refreshCompletions()
	if len(completions) != 1 || completions[0].Outcome != RefreshAmbiguous ||
		completions[0].SuccessorGeneration != 0 || len(completions[0].SuccessorToken.Ciphertext) != 0 ||
		!completions[0].AccessExpiresAt.IsZero() {
		t.Fatalf("refresh completions = %+v", completions)
	}
}

func TestWorkerRoundRobinMakesEveryCategoryProgressWithinThreeClaims(t *testing.T) {
	now := oidcMaintenanceTestNow()
	keyring := oidcMaintenanceTestKeyring(t)
	refresh := oidcMaintenanceRefreshClaim(t, keyring, "tenant", now)
	logout := oidcMaintenanceLogoutClaim(t, keyring, "admitted_platform", now)
	scrub := ScrubReceipt{MaterialID: oidcMaintenanceTestID(40), OperationRunID: oidcMaintenanceTestID(41), CompletedAt: now}
	queued := map[Kind]*Work{
		KindLogoutRetry: {Kind: KindLogoutRetry, LogoutRetry: &logout},
		KindRefresh:     {Kind: KindRefresh, Refresh: &refresh},
		KindScrub:       {Kind: KindScrub, Scrub: &scrub},
	}
	repository := &oidcMaintenanceFakeRepository{
		claim: func(_ context.Context, kind Kind, observedAt time.Time) (*Work, error) {
			work := queued[kind]
			delete(queued, kind)
			if work != nil {
				work.ObservedAt = observedAt
			}
			return work, nil
		},
		load: encryptedOIDCSecretLoader(t, keyring, []byte("historical-client-secret")),
	}
	upstream := &oidcMaintenanceFakeUpstream{refresh: successfulOIDCMaintenanceRefresh(now), revoke: nil}
	worker := oidcMaintenanceTestWorker(t, repository, upstream, keyring, now, 3)

	summary, err := worker.runBoundedCycle(context.Background())
	if err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	if summary != (Summary{
		Dispatches: 3, Claimed: 3, RefreshRotated: 1, LogoutComplete: 1, Scrubbed: 1,
	}) {
		t.Fatalf("RunOnce() summary = %+v", summary)
	}
	if got, want := repository.claimKinds(), []Kind{KindLogoutRetry, KindRefresh, KindScrub}; !reflect.DeepEqual(got, want) {
		t.Fatalf("claim kinds = %v, want %v", got, want)
	}
	if got, want := repository.phaseNames(), []string{"access_expiry", "retention_cleanup"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("cycle phases = %v, want %v", got, want)
	}
}

func TestWorkerCleanupFailureStopsClaimsAndRecoveryRestoresReadiness(t *testing.T) {
	now := oidcMaintenanceTestNow()
	keyring := oidcMaintenanceTestKeyring(t)
	var cleanupCalls atomic.Int32
	repository := &oidcMaintenanceFakeRepository{
		cleanupRetention: func(context.Context, time.Time) error {
			if cleanupCalls.Add(1) == 1 {
				return ErrUnavailable
			}
			return nil
		},
	}
	worker := oidcMaintenanceTestWorker(
		t, repository, &oidcMaintenanceFakeUpstream{}, keyring, now, 3,
	)
	worker.pollInterval = 100 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	readiness := make(chan bool, 8)
	done := make(chan struct{})
	go func() {
		worker.Run(ctx, func(value bool) { readiness <- value })
		close(done)
	}()

	for index, want := range []bool{true, false, true} {
		select {
		case got := <-readiness:
			if got != want {
				t.Fatalf("readiness transition %d = %t, want %t", index, got, want)
			}
			if index == 1 && len(repository.claimKinds()) != 0 {
				t.Fatal("cleanup failure allowed a claim")
			}
		case <-time.After(time.Second):
			t.Fatalf("readiness transition %d was not published", index)
		}
	}
	if got, want := repository.claimKinds(), []Kind{KindLogoutRetry, KindRefresh, KindScrub}; !reflect.DeepEqual(got, want) {
		t.Fatalf("recovery claims = %v, want %v", got, want)
	}
	if got, want := repository.phaseNames(), []string{
		"access_expiry", "retention_cleanup", "access_expiry", "retention_cleanup",
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("recovery phases = %v, want %v", got, want)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("worker did not stop")
	}
}

func TestWorkerAccessExpiryFailureStopsCleanupAndClaims(t *testing.T) {
	now := oidcMaintenanceTestNow()
	keyring := oidcMaintenanceTestKeyring(t)
	repository := &oidcMaintenanceFakeRepository{
		expireAccess: func(context.Context, time.Time) error {
			return ErrUnavailable
		},
		cleanupRetention: func(context.Context, time.Time) error {
			t.Fatal("cleanup ran after access-expiry failure")
			return nil
		},
	}
	worker := oidcMaintenanceTestWorker(
		t, repository, &oidcMaintenanceFakeUpstream{}, keyring, now, 3,
	)

	summary, err := worker.RunOnce(context.Background())
	if summary != (Summary{}) || !errors.Is(err, ErrOutcomeUnknown) ||
		!errors.Is(err, ErrUnavailable) || len(repository.claimKinds()) != 0 {
		t.Fatalf("access-expiry failure = summary %+v, error %v, claims %v",
			summary, err, repository.claimKinds())
	}
	if got, want := repository.phaseNames(), []string{"access_expiry"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("failed expiry phases = %v, want %v", got, want)
	}
}

func TestWorkerClassifiesLogoutRetryOutcomes(t *testing.T) {
	tests := []struct {
		name       string
		attempt    int
		maximum    int
		upstream   error
		want       LogoutOutcome
		wantNext   bool
		wantMetric Summary
	}{
		{name: "succeeded", attempt: 1, maximum: 3, want: LogoutSucceeded, wantMetric: Summary{LogoutComplete: 1}},
		{name: "safe retry", attempt: 2, maximum: 3, upstream: errors.Join(federatedoidc.ErrRevocationFailed, federatedoidc.ErrRevocationSafeToRetry), want: LogoutSafeToRetry, wantNext: true, wantMetric: Summary{RetryScheduled: 1}},
		{name: "ambiguous", attempt: 1, maximum: 3, upstream: errors.Join(federatedoidc.ErrRevocationFailed, federatedoidc.ErrRevocationAmbiguous), want: LogoutAmbiguous, wantMetric: Summary{DeadLettered: 1}},
		{name: "rejected", attempt: 1, maximum: 3, upstream: errors.New("trace-secret-canary"), want: LogoutRejected, wantMetric: Summary{DeadLettered: 1}},
		{name: "safe retry exhausted", attempt: 3, maximum: 3, upstream: errors.Join(federatedoidc.ErrRevocationFailed, federatedoidc.ErrRevocationSafeToRetry), want: LogoutRejected, wantMetric: Summary{DeadLettered: 1}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			now := oidcMaintenanceTestNow()
			keyring := oidcMaintenanceTestKeyring(t)
			claim := oidcMaintenanceLogoutClaim(t, keyring, "tenant", now)
			claim.Attempt, claim.MaximumAttempts = test.attempt, test.maximum
			repository := &oidcMaintenanceFakeRepository{
				claim: onceOIDCWork(KindLogoutRetry, &Work{Kind: KindLogoutRetry, LogoutRetry: &claim}),
				load:  encryptedOIDCSecretLoader(t, keyring, []byte("historical-client-secret")),
			}
			upstream := &oidcMaintenanceFakeUpstream{revoke: func(
				_ context.Context, material federatedoidc.StoredRevocationMaterial,
			) error {
				if material.EndpointURL != claim.Endpoint || material.TokenKind != federatedoidc.TokenRefresh ||
					string(material.Token) != "claimed-refresh-token" ||
					string(material.ClientSecret) != "historical-client-secret" {
					t.Fatalf("unexpected revocation material: %s", material.String())
				}
				return test.upstream
			}}
			worker := oidcMaintenanceTestWorker(t, repository, upstream, keyring, now, 3)
			tracer := &oidcMaintenanceRecordingTracer{}
			worker.tracer = tracer

			summary, err := worker.RunOnce(context.Background())
			if err != nil {
				t.Fatalf("RunOnce() error = %v", err)
			}
			completions := repository.logoutCompletions()
			if len(completions) != 1 || completions[0].Outcome != test.want ||
				(completions[0].NextTryAt.IsZero()) == test.wantNext {
				t.Fatalf("logout completion = %+v, want outcome %s next=%t", completions, test.want, test.wantNext)
			}
			if test.wantNext && completions[0].NextTryAt != completions[0].CompletedAt.Add(logoutBackoff(test.attempt)) {
				t.Fatalf("next try = %s", completions[0].NextTryAt)
			}
			test.wantMetric.Dispatches = 3
			test.wantMetric.Claimed = 1
			if summary != test.wantMetric {
				t.Fatalf("summary = %+v, want %+v", summary, test.wantMetric)
			}
			traceErr, found := tracer.finished("oidc.maintenance.logout_retry")
			if !found || (test.want == LogoutSucceeded) != (traceErr == nil) ||
				(traceErr != nil && strings.Contains(traceErr.Error(), "trace-secret-canary")) {
				t.Fatalf("logout operation trace = %v, found=%t", traceErr, found)
			}
		})
	}
}

func TestLogoutCompletionAfterLeaseCannotReportDispatchSuccessOrSafeRetry(t *testing.T) {
	leaseExpiresAt := oidcMaintenanceTestNow()
	for _, outcome := range []LogoutOutcome{LogoutSucceeded, LogoutSafeToRetry} {
		if got := logoutOutcomeAtCompletion(outcome, leaseExpiresAt, leaseExpiresAt); got != LogoutAmbiguous {
			t.Fatalf("logoutOutcomeAtCompletion(%s) = %s", outcome, got)
		}
		if got := logoutOutcomeAtCompletion(outcome, leaseExpiresAt.Add(-time.Microsecond), leaseExpiresAt); got != outcome {
			t.Fatalf("pre-expiry logoutOutcomeAtCompletion(%s) = %s", outcome, got)
		}
	}
	for _, outcome := range []LogoutOutcome{LogoutLocalUnavailable, LogoutAmbiguous, LogoutRejected} {
		if got := logoutOutcomeAtCompletion(outcome, leaseExpiresAt, leaseExpiresAt); got != outcome {
			t.Fatalf("terminal/local logoutOutcomeAtCompletion(%s) = %s", outcome, got)
		}
	}
}

func TestWorkerMarksAmbiguousRefreshTraceWithoutUpstreamDetail(t *testing.T) {
	now := oidcMaintenanceTestNow()
	keyring := oidcMaintenanceTestKeyring(t)
	claim := oidcMaintenanceRefreshClaim(t, keyring, "tenant", now)
	repository := &oidcMaintenanceFakeRepository{
		claim: onceOIDCWork(KindRefresh, &Work{Kind: KindRefresh, Refresh: &claim}),
		load:  encryptedOIDCSecretLoader(t, keyring, []byte("historical-client-secret")),
	}
	upstream := &oidcMaintenanceFakeUpstream{refresh: func(
		context.Context,
		federatedoidc.StoredRefreshExchangeRequest,
		time.Time,
	) (RefreshResult, error) {
		return RefreshResult{}, errors.New("refresh-trace-secret-canary")
	}}
	worker := oidcMaintenanceTestWorker(t, repository, upstream, keyring, now, 3)
	tracer := &oidcMaintenanceRecordingTracer{}
	worker.tracer = tracer
	if _, err := worker.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	traceErr, found := tracer.finished("oidc.maintenance.refresh")
	if !found || !errors.Is(traceErr, ErrOutcomeUnknown) ||
		strings.Contains(traceErr.Error(), "refresh-trace-secret-canary") {
		t.Fatalf("refresh operation trace = %v, found=%t", traceErr, found)
	}
}

func TestWorkerDefersSecretAvailabilityFailureWithoutConsumingAnUpstreamRetry(t *testing.T) {
	for _, kind := range []Kind{KindRefresh, KindLogoutRetry} {
		t.Run(string(kind), func(t *testing.T) {
			now := oidcMaintenanceTestNow()
			keyring := oidcMaintenanceTestKeyring(t)
			repository := &oidcMaintenanceFakeRepository{
				load: func(context.Context, ClientSecretLookup) (ClientSecretSnapshot, error) {
					return ClientSecretSnapshot{}, ErrUnavailable
				},
			}
			if kind == KindRefresh {
				claim := oidcMaintenanceRefreshClaim(t, keyring, "admitted_platform", now)
				repository.claim = onceOIDCWork(kind, &Work{Kind: kind, Refresh: &claim})
			} else {
				claim := oidcMaintenanceLogoutClaim(t, keyring, "admitted_platform", now)
				repository.claim = onceOIDCWork(kind, &Work{Kind: kind, LogoutRetry: &claim})
			}
			upstream := &oidcMaintenanceFakeUpstream{}
			worker := oidcMaintenanceTestWorker(t, repository, upstream, keyring, now, 3)

			summary, err := worker.RunOnce(context.Background())
			if !errors.Is(err, ErrUnavailable) {
				t.Fatalf("RunOnce() error = %v, want unavailable", err)
			}
			if upstream.refreshCallCount() != 0 || upstream.revokeCallCount() != 0 ||
				summary.LocalDeferred != 1 || summary.RetryScheduled != 0 || summary.DeadLettered != 0 {
				t.Fatalf("availability classification = summary %+v, calls %d/%d",
					summary, upstream.refreshCallCount(), upstream.revokeCallCount())
			}
			if kind == KindRefresh {
				if got := repository.refreshCompletions(); len(got) != 1 ||
					got[0].Outcome != RefreshLocalUnavailable {
					t.Fatalf("refresh completion = %+v", got)
				}
			} else if got := repository.logoutCompletions(); len(got) != 1 ||
				got[0].Outcome != LogoutLocalUnavailable || !got[0].NextTryAt.IsZero() {
				t.Fatalf("logout completion = %+v", got)
			}
		})
	}
}

func TestWorkerDefersExpiredSafeToRetryDispatchWithoutConsumingAnUpstreamRetry(t *testing.T) {
	for _, kind := range []Kind{KindRefresh, KindLogoutRetry} {
		t.Run(string(kind), func(t *testing.T) {
			now := oidcMaintenanceTestNow()
			keyring := oidcMaintenanceTestKeyring(t)
			repository := &oidcMaintenanceFakeRepository{
				load: encryptedOIDCSecretLoader(t, keyring, []byte("historical-client-secret")),
			}
			upstream := &oidcMaintenanceFakeUpstream{}
			if kind == KindRefresh {
				claim := oidcMaintenanceRefreshClaim(t, keyring, "tenant", now)
				repository.claim = onceOIDCWork(kind, &Work{Kind: kind, Refresh: &claim})
				upstream.refresh = func(
					ctx context.Context,
					_ federatedoidc.StoredRefreshExchangeRequest,
					_ time.Time,
				) (RefreshResult, error) {
					<-ctx.Done()
					return RefreshResult{}, federatedoidc.ErrRefreshSafeToRetry
				}
			} else {
				claim := oidcMaintenanceLogoutClaim(t, keyring, "tenant", now)
				repository.claim = onceOIDCWork(kind, &Work{Kind: kind, LogoutRetry: &claim})
				upstream.revoke = func(
					ctx context.Context,
					_ federatedoidc.StoredRevocationMaterial,
				) error {
					<-ctx.Done()
					return errors.Join(
						federatedoidc.ErrRevocationFailed,
						federatedoidc.ErrRevocationSafeToRetry,
					)
				}
			}
			worker := oidcMaintenanceTestWorker(t, repository, upstream, keyring, now, 3)
			worker.operationTimeout = MinimumOperation
			if kind == KindRefresh {
				worker.nextKind = 1
			}

			summary, err := worker.RunOnce(context.Background())
			if !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrInterrupted) ||
				summary.LocalDeferred != 1 || summary.RetryScheduled != 0 || summary.DeadLettered != 0 {
				t.Fatalf("expired safe retry result = summary %+v, error %v", summary, err)
			}
			if kind == KindRefresh {
				if got := repository.refreshCompletions(); len(got) != 1 ||
					got[0].Outcome != RefreshLocalUnavailable {
					t.Fatalf("refresh completion = %+v", got)
				}
			} else if got := repository.logoutCompletions(); len(got) != 1 ||
				got[0].Outcome != LogoutLocalUnavailable || !got[0].NextTryAt.IsZero() {
				t.Fatalf("logout completion = %+v", got)
			}
		})
	}
}

func TestWorkerPreservesLiveRefreshSafeToRetryClassification(t *testing.T) {
	now := oidcMaintenanceTestNow()
	keyring := oidcMaintenanceTestKeyring(t)
	claim := oidcMaintenanceRefreshClaim(t, keyring, "tenant", now)
	repository := &oidcMaintenanceFakeRepository{
		claim: onceOIDCWork(KindRefresh, &Work{Kind: KindRefresh, Refresh: &claim}),
		load:  encryptedOIDCSecretLoader(t, keyring, []byte("historical-client-secret")),
	}
	upstream := &oidcMaintenanceFakeUpstream{refresh: func(
		ctx context.Context,
		_ federatedoidc.StoredRefreshExchangeRequest,
		_ time.Time,
	) (RefreshResult, error) {
		if ctx.Err() != nil {
			t.Fatalf("refresh context ended before the live safe-to-retry result: %v", ctx.Err())
		}
		return RefreshResult{}, federatedoidc.ErrRefreshSafeToRetry
	}}
	worker := oidcMaintenanceTestWorker(t, repository, upstream, keyring, now, 3)
	worker.nextKind = 1

	summary, err := worker.RunOnce(context.Background())
	if err != nil || summary.RetryScheduled != 1 || summary.LocalDeferred != 0 ||
		summary.DeadLettered != 0 {
		t.Fatalf("live safe retry result = summary %+v, error %v", summary, err)
	}
	if got := repository.refreshCompletions(); len(got) != 1 || got[0].Outcome != RefreshSafeToRetry {
		t.Fatalf("refresh completion = %+v", got)
	}
}

func TestWorkerLocalKeyDependencyFailureStopsBatchAndClearsReadiness(t *testing.T) {
	now := oidcMaintenanceTestNow()
	keyring := oidcMaintenanceTestKeyring(t)
	base := oidcMaintenanceRefreshClaim(t, keyring, "tenant", now)
	base.Token.KeyVersion = 2
	var claimMu sync.Mutex
	refreshClaims := 0
	repository := &oidcMaintenanceFakeRepository{
		claim: func(_ context.Context, kind Kind, observedAt time.Time) (*Work, error) {
			if kind != KindRefresh {
				return nil, nil
			}
			claimMu.Lock()
			refreshClaims++
			claimMu.Unlock()
			claim := base
			claim.Token.Ciphertext = append([]byte(nil), base.Token.Ciphertext...)
			return &Work{ObservedAt: observedAt, Kind: kind, Refresh: &claim}, nil
		},
	}
	upstream := &oidcMaintenanceFakeUpstream{}
	worker := oidcMaintenanceTestWorker(t, repository, upstream, keyring, now, 6)
	worker.pollInterval = 100 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan bool, 8)
	done := make(chan struct{})
	go func() {
		worker.Run(ctx, func(value bool) { ready <- value })
		close(done)
	}()

	select {
	case value := <-ready:
		if !value {
			t.Fatal("worker was not initially ready with a healthy database ABI")
		}
	case <-time.After(time.Second):
		t.Fatal("worker did not publish initial readiness")
	}
	select {
	case value := <-ready:
		if value {
			t.Fatal("local key dependency failure left readiness true")
		}
	case <-time.After(time.Second):
		t.Fatal("local key dependency failure did not clear readiness")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("worker did not stop")
	}
	claimMu.Lock()
	gotClaims := refreshClaims
	claimMu.Unlock()
	if gotClaims != 1 || repository.refreshCompletionCount() != 1 ||
		upstream.refreshCallCount() != 0 || len(repository.secretLookups()) != 0 {
		t.Fatalf("local dependency hot loop: claims=%d completions=%d upstream=%d lookups=%d",
			gotClaims, repository.refreshCompletionCount(), upstream.refreshCallCount(),
			len(repository.secretLookups()))
	}
	completion := repository.refreshCompletions()[0]
	if completion.Outcome != RefreshLocalUnavailable {
		t.Fatalf("completion outcome = %s", completion.Outcome)
	}
}

func TestWorkerBoundsHistoricalSecretLookupByDatabaseTimeout(t *testing.T) {
	now := oidcMaintenanceTestNow()
	keyring := oidcMaintenanceTestKeyring(t)
	claim := oidcMaintenanceRefreshClaim(t, keyring, "tenant", now)
	repository := &oidcMaintenanceFakeRepository{
		claim: onceOIDCWork(KindRefresh, &Work{Kind: KindRefresh, Refresh: &claim}),
		load: func(ctx context.Context, _ ClientSecretLookup) (ClientSecretSnapshot, error) {
			<-ctx.Done()
			return ClientSecretSnapshot{}, ctx.Err()
		},
	}
	upstream := &oidcMaintenanceFakeUpstream{refresh: successfulOIDCMaintenanceRefresh(now)}
	worker := oidcMaintenanceTestWorker(t, repository, upstream, keyring, now, 3)
	worker.nextKind = 1
	worker.databaseTimeout = 25 * time.Millisecond
	started := time.Now()

	summary, err := worker.RunOnce(context.Background())
	if !errors.Is(err, ErrUnavailable) || time.Since(started) > 500*time.Millisecond ||
		summary.LocalDeferred != 1 || upstream.refreshCallCount() != 0 ||
		repository.refreshCompletionCount() != 1 {
		t.Fatalf("bounded secret lookup = summary %+v, error %v, elapsed %s, upstream=%d, completions=%d",
			summary, err, time.Since(started), upstream.refreshCallCount(),
			repository.refreshCompletionCount())
	}
}

func TestWorkerRejectsCorruptSecretEnvelopeBeforeDispatch(t *testing.T) {
	for _, kind := range []Kind{KindRefresh, KindLogoutRetry} {
		t.Run(string(kind), func(t *testing.T) {
			now := oidcMaintenanceTestNow()
			keyring := oidcMaintenanceTestKeyring(t)
			repository := &oidcMaintenanceFakeRepository{}
			loader := encryptedOIDCSecretLoader(t, keyring, []byte("historical-client-secret"))
			repository.load = func(ctx context.Context, lookup ClientSecretLookup) (ClientSecretSnapshot, error) {
				snapshot, err := loader(ctx, lookup)
				if err == nil {
					snapshot.Envelope.Ciphertext[len(snapshot.Envelope.Ciphertext)-1] ^= 0xff
				}
				return snapshot, err
			}
			if kind == KindRefresh {
				claim := oidcMaintenanceRefreshClaim(t, keyring, "direct_platform", now)
				repository.claim = onceOIDCWork(kind, &Work{Kind: kind, Refresh: &claim})
			} else {
				claim := oidcMaintenanceLogoutClaim(t, keyring, "direct_platform", now)
				repository.claim = onceOIDCWork(kind, &Work{Kind: kind, LogoutRetry: &claim})
			}
			upstream := &oidcMaintenanceFakeUpstream{}
			worker := oidcMaintenanceTestWorker(t, repository, upstream, keyring, now, 3)

			summary, err := worker.RunOnce(context.Background())
			if err != nil {
				t.Fatalf("RunOnce() error = %v", err)
			}
			if upstream.refreshCallCount() != 0 || upstream.revokeCallCount() != 0 ||
				summary.DeadLettered != 1 || summary.RetryScheduled != 0 {
				t.Fatalf("corruption classification = summary %+v, calls %d/%d",
					summary, upstream.refreshCallCount(), upstream.revokeCallCount())
			}
			if kind == KindRefresh {
				if got := repository.refreshCompletions(); len(got) != 1 || got[0].Outcome != RefreshRejected {
					t.Fatalf("refresh completion = %+v", got)
				}
			} else if got := repository.logoutCompletions(); len(got) != 1 || got[0].Outcome != LogoutRejected {
				t.Fatalf("logout completion = %+v", got)
			}
		})
	}
}

func TestWorkerDefersCancellationBeforeDispatchAsALocalDependencyFailure(t *testing.T) {
	now := oidcMaintenanceTestNow()
	keyring := oidcMaintenanceTestKeyring(t)
	repository := &oidcMaintenanceFakeRepository{
		load: encryptedOIDCSecretLoader(t, keyring, []byte("historical-client-secret")),
	}
	upstream := &oidcMaintenanceFakeUpstream{}
	worker := oidcMaintenanceTestWorker(t, repository, upstream, keyring, now, 3)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	refresh := oidcMaintenanceRefreshClaim(t, keyring, "tenant", now)
	refreshOutcome, rotation := worker.executeRefresh(ctx, refresh, now)
	if refreshOutcome != RefreshLocalUnavailable || rotation != nil {
		t.Fatalf("cancelled refresh outcome = %s/%v", refreshOutcome, rotation)
	}
	logout := oidcMaintenanceLogoutClaim(t, keyring, "tenant", now)
	if outcome := worker.executeLogout(ctx, logout); outcome != LogoutLocalUnavailable {
		t.Fatalf("cancelled logout outcome = %s", outcome)
	}
	if upstream.refreshCallCount() != 0 || upstream.revokeCallCount() != 0 ||
		len(repository.secretLookups()) != 0 {
		t.Fatalf("cancelled work crossed a dispatch boundary: upstream=%d/%d lookups=%d",
			upstream.refreshCallCount(), upstream.revokeCallCount(), len(repository.secretLookups()))
	}
}

func TestWorkerTreatsLostCompletionFenceAsBenignAndDoesNotReclaim(t *testing.T) {
	now := oidcMaintenanceTestNow()
	keyring := oidcMaintenanceTestKeyring(t)
	claim := oidcMaintenanceRefreshClaim(t, keyring, "tenant", now)
	repository := &oidcMaintenanceFakeRepository{
		claim:            onceOIDCWork(KindRefresh, &Work{Kind: KindRefresh, Refresh: &claim}),
		load:             encryptedOIDCSecretLoader(t, keyring, []byte("historical-client-secret")),
		loseRefreshFence: true,
	}
	upstream := &oidcMaintenanceFakeUpstream{refresh: successfulOIDCMaintenanceRefresh(now)}
	worker := oidcMaintenanceTestWorker(t, repository, upstream, keyring, now, 3)

	summary, err := worker.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	if summary.FenceLost != 1 || summary.RefreshRotated != 0 || summary.DeadLettered != 0 ||
		upstream.refreshCallCount() != 1 || repository.refreshClaimCount() != 1 {
		t.Fatalf("stale completion was not CAS-inert: summary=%+v calls=%d claims=%d",
			summary, upstream.refreshCallCount(), repository.refreshClaimCount())
	}
}

func TestWorkerAllowsLeaseReclaimAfterUnknownCompletionOutcome(t *testing.T) {
	now := oidcMaintenanceTestNow()
	keyring := oidcMaintenanceTestKeyring(t)
	first := oidcMaintenanceRefreshClaim(t, keyring, "tenant", now)
	reclaimed := oidcMaintenanceRefreshClaim(t, keyring, "tenant", now)
	reclaimed.Version = first.Version + 1
	claims := []*Work{
		{Kind: KindRefresh, Refresh: &first},
		{Kind: KindRefresh, Refresh: &reclaimed},
	}
	repository := &oidcMaintenanceFakeRepository{
		claim: func(_ context.Context, kind Kind, observedAt time.Time) (*Work, error) {
			if kind != KindRefresh || len(claims) == 0 {
				return nil, nil
			}
			work := claims[0]
			claims = claims[1:]
			work.ObservedAt = observedAt
			return work, nil
		},
		load: encryptedOIDCSecretLoader(t, keyring, []byte("historical-client-secret")),
	}
	completionCalls := 0
	repository.completeRefresh = func(context.Context, RefreshCompletion) (bool, error) {
		completionCalls++
		if completionCalls == 1 {
			return false, ErrUnavailable
		}
		return true, nil
	}
	upstream := &oidcMaintenanceFakeUpstream{refresh: successfulOIDCMaintenanceRefresh(now)}
	worker := oidcMaintenanceTestWorker(t, repository, upstream, keyring, now, 3)

	firstSummary, err := worker.RunOnce(context.Background())
	if !errors.Is(err, ErrOutcomeUnknown) || firstSummary.Dispatches != 2 || firstSummary.Claimed != 1 {
		t.Fatalf("first run = summary %+v, error %v", firstSummary, err)
	}
	secondSummary, err := worker.RunOnce(context.Background())
	if err != nil || secondSummary != (Summary{Dispatches: 3, Claimed: 1, RefreshRotated: 1}) {
		t.Fatalf("reclaim run = summary %+v, error %v", secondSummary, err)
	}
	completed := repository.refreshCompletions()
	if len(completed) != 2 || completed[0].ExpectedVersion != first.Version ||
		completed[1].ExpectedVersion != reclaimed.Version || upstream.refreshCallCount() != 2 ||
		repository.refreshClaimCount() != 2 {
		t.Fatalf("reclaim evidence = completions %+v, upstream=%d claims=%d",
			completed, upstream.refreshCallCount(), repository.refreshClaimCount())
	}
}

func TestWorkerFailsClosedOnInvalidDispatcherProjection(t *testing.T) {
	now := oidcMaintenanceTestNow()
	keyring := oidcMaintenanceTestKeyring(t)
	tests := []struct {
		name  string
		claim func(context.Context, Kind, time.Time) (*Work, error)
	}{
		{name: "busy leaked by dispatcher", claim: onceOIDCWork(KindRefresh, &Work{Kind: KindRefresh})},
		{name: "adapter rejected wire", claim: func(context.Context, Kind, time.Time) (*Work, error) {
			return nil, ErrInvalidProjection
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := &oidcMaintenanceFakeRepository{claim: test.claim}
			upstream := &oidcMaintenanceFakeUpstream{}
			worker := oidcMaintenanceTestWorker(t, repository, upstream, keyring, now, 3)
			_, err := worker.RunOnce(context.Background())
			if !errors.Is(err, ErrInvalidProjection) || errors.Is(err, ErrOutcomeUnknown) ||
				upstream.refreshCallCount() != 0 || upstream.revokeCallCount() != 0 ||
				repository.refreshCompletionCount()+repository.logoutCompletionCount() != 0 {
				t.Fatalf("invalid projection did not fail closed: error=%v", err)
			}
		})
	}
}

func TestWorkerCompletesLocalDeferralWithUncancelledTerminalContextAfterCancellation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	keyring := oidcMaintenanceTestKeyring(t)
	claim := oidcMaintenanceLogoutClaim(t, keyring, "tenant", now)
	claim.LeaseExpiresAt = now.Add(27 * time.Second)
	parent, cancelParent := context.WithCancel(context.Background())
	repository := &oidcMaintenanceFakeRepository{
		claim: onceOIDCWork(KindLogoutRetry, &Work{Kind: KindLogoutRetry, LogoutRetry: &claim}),
		load:  encryptedOIDCSecretLoader(t, keyring, []byte("historical-client-secret")),
	}
	repository.completeLogout = func(ctx context.Context, _ LogoutCompletion) (bool, error) {
		if ctx.Err() != nil {
			t.Fatalf("terminal completion inherited cancellation: %v", ctx.Err())
		}
		return true, nil
	}
	upstream := &oidcMaintenanceFakeUpstream{revoke: func(
		ctx context.Context, _ federatedoidc.StoredRevocationMaterial,
	) error {
		deadline, ok := ctx.Deadline()
		remaining := time.Until(deadline)
		if !ok || remaining < 19*time.Second || remaining > 20*time.Second {
			t.Fatalf("operation deadline remaining = %s/%t, want within [19s,20s]", remaining, ok)
		}
		cancelParent()
		return errors.Join(federatedoidc.ErrRevocationFailed, federatedoidc.ErrRevocationSafeToRetry)
	}}
	worker := oidcMaintenanceTestWorker(t, repository, upstream, keyring, now, 3)

	summary, err := worker.RunOnce(parent)
	if !errors.Is(err, ErrInterrupted) || !errors.Is(err, ErrUnavailable) ||
		summary.LocalDeferred != 1 || summary.RetryScheduled != 0 ||
		repository.logoutCompletionCount() != 1 {
		t.Fatalf("graceful terminal result = summary %+v, error %v", summary, err)
	}
	if got := repository.logoutCompletions(); got[0].Outcome != LogoutLocalUnavailable ||
		!got[0].NextTryAt.IsZero() {
		t.Fatalf("cancelled logout consumed a durable retry: %+v", got)
	}
}

func TestWorkerDoesNotDispatchWithoutFullOperationAndTerminalBudget(t *testing.T) {
	now := oidcMaintenanceTestNow()
	keyring := oidcMaintenanceTestKeyring(t)
	for _, kind := range []Kind{KindRefresh, KindLogoutRetry} {
		t.Run(string(kind), func(t *testing.T) {
			repository := &oidcMaintenanceFakeRepository{
				load: encryptedOIDCSecretLoader(t, keyring, []byte("historical-client-secret")),
			}
			if kind == KindRefresh {
				claim := oidcMaintenanceRefreshClaim(t, keyring, "tenant", now)
				claim.LeaseExpiresAt = now.Add(24 * time.Second)
				repository.claim = onceOIDCWork(kind, &Work{Kind: kind, Refresh: &claim})
			} else {
				claim := oidcMaintenanceLogoutClaim(t, keyring, "tenant", now)
				claim.LeaseExpiresAt = now.Add(24 * time.Second)
				repository.claim = onceOIDCWork(kind, &Work{Kind: kind, LogoutRetry: &claim})
			}
			upstream := &oidcMaintenanceFakeUpstream{
				refresh: successfulOIDCMaintenanceRefresh(now),
				revoke: func(context.Context, federatedoidc.StoredRevocationMaterial) error {
					return nil
				},
			}
			worker := oidcMaintenanceTestWorker(t, repository, upstream, keyring, now, 3)
			if kind == KindRefresh {
				worker.nextKind = 1
			}

			summary, err := worker.RunOnce(context.Background())
			if !errors.Is(err, ErrUnavailable) || summary.LocalDeferred != 1 || summary.RetryScheduled != 0 ||
				upstream.refreshCallCount() != 0 || upstream.revokeCallCount() != 0 {
				t.Fatalf("insufficient-budget result = summary %+v, error %v, refresh=%d, revoke=%d",
					summary, err, upstream.refreshCallCount(), upstream.revokeCallCount())
			}
			if kind == KindRefresh && repository.refreshCompletionCount() != 1 {
				t.Fatal("refresh claim was not returned through its fenced retry completion")
			}
			if kind == KindLogoutRetry && repository.logoutCompletionCount() != 1 {
				t.Fatal("logout claim was not returned through its fenced retry completion")
			}
		})
	}
}

func TestWorkerDoesNotOpenSecretOrDispatchAtParentDeadlineBoundary(t *testing.T) {
	const operationTimeout = 2 * time.Second
	for _, kind := range []Kind{KindRefresh, KindLogoutRetry} {
		t.Run(string(kind), func(t *testing.T) {
			now := oidcMaintenanceTestNow()
			keyring := oidcMaintenanceTestKeyring(t)
			repository := &oidcMaintenanceFakeRepository{
				load: encryptedOIDCSecretLoader(t, keyring, []byte("historical-client-secret")),
			}
			if kind == KindRefresh {
				claim := oidcMaintenanceRefreshClaim(t, keyring, "tenant", now)
				repository.claim = onceOIDCWork(kind, &Work{Kind: kind, Refresh: &claim})
			} else {
				claim := oidcMaintenanceLogoutClaim(t, keyring, "tenant", now)
				repository.claim = onceOIDCWork(kind, &Work{Kind: kind, LogoutRetry: &claim})
			}
			upstream := &oidcMaintenanceFakeUpstream{
				refresh: successfulOIDCMaintenanceRefresh(now),
				revoke: func(context.Context, federatedoidc.StoredRevocationMaterial) error {
					return nil
				},
			}
			worker := oidcMaintenanceTestWorker(t, repository, upstream, keyring, now, 3)
			worker.operationTimeout = operationTimeout
			if kind == KindRefresh {
				worker.nextKind = 1
			}
			parent, cancel := context.WithTimeout(
				context.Background(),
				operationTimeout+MinimumLeaseSchedulingMargin/2,
			)
			defer cancel()

			summary, err := worker.RunOnce(parent)
			if !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrInterrupted) || parent.Err() != nil ||
				summary.LocalDeferred != 1 || summary.RetryScheduled != 0 || summary.DeadLettered != 0 ||
				len(repository.secretLookups()) != 0 || upstream.refreshCallCount() != 0 ||
				upstream.revokeCallCount() != 0 {
				t.Fatalf("parent-budget result = summary %+v, error %v, parent=%v, lookups=%d, refresh=%d, revoke=%d",
					summary, err, parent.Err(), len(repository.secretLookups()),
					upstream.refreshCallCount(), upstream.revokeCallCount())
			}
			if kind == KindRefresh {
				if got := repository.refreshCompletions(); len(got) != 1 ||
					got[0].Outcome != RefreshLocalUnavailable {
					t.Fatalf("refresh completion = %+v", got)
				}
			} else if got := repository.logoutCompletions(); len(got) != 1 ||
				got[0].Outcome != LogoutLocalUnavailable || !got[0].NextTryAt.IsZero() {
				t.Fatalf("logout completion = %+v", got)
			}
		})
	}
}

func TestWorkerCountsPostClaimBookkeepingAgainstLeaseBudget(t *testing.T) {
	const bookkeepingDelay = 50 * time.Millisecond
	for _, kind := range []Kind{KindRefresh, KindLogoutRetry} {
		t.Run(string(kind), func(t *testing.T) {
			now := oidcMaintenanceTestNow()
			keyring := oidcMaintenanceTestKeyring(t)
			repository := &oidcMaintenanceFakeRepository{
				load: encryptedOIDCSecretLoader(t, keyring, []byte("historical-client-secret")),
			}
			leaseBudget := MinimumOperation + MinimumLeaseSafety +
				MinimumLeaseSchedulingMargin + bookkeepingDelay/2
			if kind == KindRefresh {
				claim := oidcMaintenanceRefreshClaim(t, keyring, "tenant", now)
				claim.LeaseExpiresAt = now.Add(leaseBudget)
				repository.claim = onceOIDCWork(kind, &Work{Kind: kind, Refresh: &claim})
			} else {
				claim := oidcMaintenanceLogoutClaim(t, keyring, "tenant", now)
				claim.LeaseExpiresAt = now.Add(leaseBudget)
				repository.claim = onceOIDCWork(kind, &Work{Kind: kind, LogoutRetry: &claim})
			}
			upstream := &oidcMaintenanceFakeUpstream{
				refresh: successfulOIDCMaintenanceRefresh(now),
				revoke: func(context.Context, federatedoidc.StoredRevocationMaterial) error {
					return nil
				},
			}
			worker := oidcMaintenanceTestWorker(t, repository, upstream, keyring, now, 3)
			worker.operationTimeout = MinimumOperation
			worker.leaseSafety = MinimumLeaseSafety
			worker.tracer = &oidcMaintenanceRecordingTracer{finishHook: func(name string) {
				if name == "oidc.maintenance.claim."+string(kind) {
					time.Sleep(bookkeepingDelay)
				}
			}}
			if kind == KindRefresh {
				worker.nextKind = 1
			}

			summary, err := worker.RunOnce(context.Background())
			if !errors.Is(err, ErrUnavailable) || summary.LocalDeferred != 1 ||
				summary.RetryScheduled != 0 || summary.DeadLettered != 0 ||
				upstream.refreshCallCount() != 0 || upstream.revokeCallCount() != 0 {
				t.Fatalf("post-claim lease result = summary %+v, error %v, refresh=%d, revoke=%d",
					summary, err, upstream.refreshCallCount(), upstream.revokeCallCount())
			}
			if kind == KindRefresh {
				if got := repository.refreshCompletions(); len(got) != 1 ||
					got[0].Outcome != RefreshLocalUnavailable ||
					got[0].CompletedAt.Before(now.Add(bookkeepingDelay)) {
					t.Fatalf("refresh completion did not include post-claim elapsed time: %+v", got)
				}
			} else if got := repository.logoutCompletions(); len(got) != 1 ||
				got[0].Outcome != LogoutLocalUnavailable ||
				got[0].CompletedAt.Before(now.Add(bookkeepingDelay)) {
				t.Fatalf("logout completion did not include post-claim elapsed time: %+v", got)
			}
		})
	}
}

func TestWorkerUsesDatabaseTimeAfterClaimDespiteApplicationClockSkew(t *testing.T) {
	databaseNow := oidcMaintenanceTestNow()
	applicationNow := databaseNow.Add(-4 * time.Minute)
	keyring := oidcMaintenanceTestKeyring(t)
	for _, kind := range []Kind{KindRefresh, KindLogoutRetry} {
		t.Run(string(kind), func(t *testing.T) {
			repository := &oidcMaintenanceFakeRepository{
				load: encryptedOIDCSecretLoader(t, keyring, []byte("historical-client-secret")),
			}
			var work *Work
			if kind == KindRefresh {
				claim := oidcMaintenanceRefreshClaim(t, keyring, "tenant", databaseNow)
				work = &Work{ObservedAt: databaseNow, Kind: kind, Refresh: &claim}
			} else {
				claim := oidcMaintenanceLogoutClaim(t, keyring, "tenant", databaseNow)
				work = &Work{ObservedAt: databaseNow, Kind: kind, LogoutRetry: &claim}
			}
			repository.claim = func(_ context.Context, selected Kind, observedAt time.Time) (*Work, error) {
				if !observedAt.Equal(applicationNow) {
					t.Fatalf("claim request used time %s, want application correlation time %s", observedAt, applicationNow)
				}
				if selected != kind || work == nil {
					return nil, nil
				}
				claimed := work
				work = nil
				return claimed, nil
			}
			upstream := &oidcMaintenanceFakeUpstream{
				refresh: successfulOIDCMaintenanceRefresh(databaseNow),
			}
			worker := oidcMaintenanceTestWorker(t, repository, upstream, keyring, applicationNow, 3)
			if kind == KindRefresh {
				worker.nextKind = 1
			}

			summary, err := worker.RunOnce(context.Background())
			if err != nil || summary.Claimed != 1 || summary.LocalDeferred != 0 ||
				repository.refreshCompletionCount()+repository.logoutCompletionCount() != 1 {
				t.Fatalf("DB-clock execution failed: summary=%+v error=%v", summary, err)
			}
			if kind == KindRefresh && (summary.RefreshRotated != 1 || upstream.refreshCallCount() != 1) {
				t.Fatalf("refresh DB-clock result = %+v, calls=%d", summary, upstream.refreshCallCount())
			}
			if kind == KindLogoutRetry && (summary.LogoutComplete != 1 || upstream.revokeCallCount() != 1) {
				t.Fatalf("logout DB-clock result = %+v, calls=%d", summary, upstream.revokeCallCount())
			}
		})
	}
}

func TestWorkerPublishesStartupReadinessAndHeartbeatsDuringSlowBatch(t *testing.T) {
	now := oidcMaintenanceTestNow()
	keyring := oidcMaintenanceTestKeyring(t)
	entered := make(chan struct{})
	claimCanceled := make(chan struct{})
	var enteredOnce sync.Once
	var readyMu sync.Mutex
	readyCalls := 0
	repository := &oidcMaintenanceFakeRepository{
		ready: func(context.Context) error {
			readyMu.Lock()
			defer readyMu.Unlock()
			readyCalls++
			if readyCalls == 1 {
				return nil
			}
			return ErrUnavailable
		},
		claim: func(ctx context.Context, _ Kind, _ time.Time) (*Work, error) {
			enteredOnce.Do(func() { close(entered) })
			<-ctx.Done()
			close(claimCanceled)
			return nil, ctx.Err()
		},
	}
	worker := oidcMaintenanceTestWorker(
		t, repository, &oidcMaintenanceFakeUpstream{}, keyring, now, 3,
	)
	worker.readinessHeartbeat = 40 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	readiness := make(chan bool, 8)
	done := make(chan struct{})
	go func() {
		worker.Run(ctx, func(value bool) { readiness <- value })
		close(done)
	}()

	select {
	case value := <-readiness:
		if !value {
			t.Fatal("startup readiness was false after the trusted ABI succeeded")
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("startup readiness waited for the slow dispatch batch")
	}
	select {
	case <-entered:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("bounded dispatch cycle did not start")
	}
	select {
	case value := <-readiness:
		if value {
			t.Fatal("failed database heartbeat left readiness true")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("heartbeat did not clear readiness during the slow dispatch")
	}
	select {
	case <-claimCanceled:
		t.Fatal("readiness heartbeat canceled credential-bearing dispatch")
	case <-time.After(75 * time.Millisecond):
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("worker did not stop after cancellation")
	}
}

func TestWorkerClaimDeadlineLatchesReadinessUntilHealthyCycle(t *testing.T) {
	now := oidcMaintenanceTestNow()
	keyring := oidcMaintenanceTestKeyring(t)
	entered := make(chan struct{})
	var calls atomic.Int32
	repository := &oidcMaintenanceFakeRepository{
		claim: func(ctx context.Context, _ Kind, _ time.Time) (*Work, error) {
			if calls.Add(1) != 1 {
				return nil, nil
			}
			close(entered)
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	worker := oidcMaintenanceTestWorker(
		t, repository, &oidcMaintenanceFakeUpstream{}, keyring, now, 3,
	)
	worker.databaseTimeout = 25 * time.Millisecond
	worker.operationTimeout = MinimumOperation
	worker.dispatchTimeout = dispatchCycleTimeout(
		worker.batchSize, worker.databaseTimeout, worker.operationTimeout,
	)
	worker.pollInterval = 100 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	readiness := make(chan bool, 8)
	done := make(chan struct{})
	go func() {
		worker.Run(ctx, func(value bool) { readiness <- value })
		close(done)
	}()

	select {
	case value := <-readiness:
		if !value {
			t.Fatal("healthy startup did not publish readiness")
		}
	case <-time.After(time.Second):
		t.Fatal("worker did not publish startup readiness")
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("bounded dispatch cycle did not start")
	}
	select {
	case value := <-readiness:
		if value {
			t.Fatal("dispatch deadline overrun left readiness true")
		}
	case <-time.After(time.Second):
		t.Fatal("dispatch deadline overrun did not clear readiness")
	}
	if got := len(repository.claimKinds()); got != 1 {
		t.Fatalf("deadline overrun issued %d claims, want 1", got)
	}
	select {
	case value := <-readiness:
		if !value {
			t.Fatal("completed recovery cycle did not restore readiness")
		}
	case <-time.After(time.Second):
		t.Fatal("worker did not complete a healthy recovery cycle")
	}
	if got := len(repository.claimKinds()); got != 4 {
		t.Fatalf("recovery cycle issued %d total claims, want 4", got)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("worker did not stop")
	}
}

func TestWorkerReadinessRequiresAuthoritativeQueueSnapshot(t *testing.T) {
	now := oidcMaintenanceTestNow()
	keyring := oidcMaintenanceTestKeyring(t)
	var calls atomic.Int32
	repository := &oidcMaintenanceFakeRepository{
		queue: func(context.Context) (QueueSnapshot, error) {
			if calls.Add(1) == 1 {
				return QueueSnapshot{}, ErrUnavailable
			}
			return QueueSnapshot{ObservedAt: now}, nil
		},
	}
	worker := oidcMaintenanceTestWorker(
		t, repository, &oidcMaintenanceFakeUpstream{}, keyring, now, 3,
	)
	worker.readinessHeartbeat = 40 * time.Millisecond
	worker.pollInterval = 100 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	readiness := make(chan bool, 8)
	done := make(chan struct{})
	go func() {
		worker.Run(ctx, func(value bool) { readiness <- value })
		close(done)
	}()

	select {
	case value := <-readiness:
		if value {
			t.Fatal("missing queue snapshot published ready")
		}
	case <-time.After(time.Second):
		t.Fatal("worker did not publish failed initial readiness")
	}
	select {
	case value := <-readiness:
		if !value {
			t.Fatal("valid queue snapshot did not restore readiness")
		}
	case <-time.After(time.Second):
		t.Fatal("worker did not refresh queue-backed readiness")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("worker did not stop")
	}
}

func TestTerminalWriteBudgetFitsInsideLeaseReservation(t *testing.T) {
	if got := terminalWriteTimeout(MaximumDatabaseTimeout, MinimumLeaseSafety); got != 900*time.Millisecond {
		t.Fatalf("minimum-safety terminal timeout = %s, want 900ms", got)
	}
	if got := terminalWriteTimeout(MinimumDatabaseTimeout, MinimumLeaseSafety); got != 900*time.Millisecond {
		t.Fatalf("minimum-database terminal timeout = %s, want 900ms", got)
	}
	if got := terminalWriteTimeout(MaximumDatabaseTimeout, MaximumLeaseSafety); got != maximumTerminalWrite {
		t.Fatalf("maximum terminal timeout = %s, want %s", got, maximumTerminalWrite)
	}
	remaining := 20*time.Second + MinimumLeaseSafety + MinimumLeaseSchedulingMargin
	if !hasFullRelativeOperationBudget(remaining, 20*time.Second, MinimumLeaseSafety) {
		t.Fatal("exact full operation, claim margin, and terminal reservation did not fit")
	}
	if hasFullRelativeOperationBudget(remaining-time.Microsecond, 20*time.Second, MinimumLeaseSafety) {
		t.Fatal("microsecond-short operation budget was accepted")
	}
}

func TestDispatchCycleBudgetPreservesDefaultAndLongAcceptedOperations(t *testing.T) {
	tests := []struct {
		name      string
		batch     int
		database  time.Duration
		operation time.Duration
		want      time.Duration
	}{
		{name: "uncapped", batch: 3, database: time.Second, operation: MinimumOperation, want: 8300*time.Millisecond + time.Microsecond},
		{name: "default capped", batch: 12, database: 5 * time.Second, operation: 20 * time.Second, want: NominalLeaseDuration},
		{name: "sixty seconds capped", batch: 90, database: 25 * time.Second, operation: time.Minute, want: NominalLeaseDuration},
		{name: "nominal lease boundary capped", batch: 3, database: time.Second, operation: 117 * time.Second, want: NominalLeaseDuration},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			full := fullCycleClaimBudget(test.database, test.operation)
			if got := dispatchCycleTimeout(test.batch, test.database, test.operation); got != test.want ||
				got > NominalLeaseDuration {
				t.Fatalf("dispatch timeout = %s, want %s within nominal lease", got, test.want)
			}
			if hasFullCycleClaimBudget(full, test.database, test.operation) {
				t.Fatal("equal cycle claim budget was accepted")
			}
			if !hasFullCycleClaimBudget(full+cycleDeadlineBoundary, test.database, test.operation) {
				t.Fatal("microsecond-reserved cycle claim budget was rejected")
			}
		})
	}
	operation := 20 * time.Second
	if hasFullParentOperationBudget(operation+MinimumLeaseSchedulingMargin, operation) {
		t.Fatal("equal parent operation budget was accepted")
	}
	if !hasFullParentOperationBudget(
		operation+MinimumLeaseSchedulingMargin+time.Microsecond,
		operation,
	) {
		t.Fatal("microsecond-reserved parent operation budget was rejected")
	}
}

func TestBoundedCycleStopsNormallyAtAdditionalClaimBoundary(t *testing.T) {
	now := oidcMaintenanceTestNow()
	keyring := oidcMaintenanceTestKeyring(t)
	repository := &oidcMaintenanceFakeRepository{}
	worker := oidcMaintenanceTestWorker(
		t, repository, &oidcMaintenanceFakeUpstream{}, keyring, now, 3,
	)
	worker.databaseTimeout = MinimumDatabaseTimeout
	worker.operationTimeout = MinimumOperation
	worker.dispatchTimeout = fullCycleClaimBudget(worker.databaseTimeout, worker.operationTimeout) +
		10*time.Millisecond
	worker.tracer = &oidcMaintenanceRecordingTracer{finishHook: func(name string) {
		if strings.HasPrefix(name, "oidc.maintenance.claim.") {
			time.Sleep(20 * time.Millisecond)
		}
	}}

	summary, err := worker.runBoundedCycle(context.Background())
	if err != nil || summary != (Summary{Dispatches: 1}) {
		t.Fatalf("bounded cycle = summary %+v, error %v", summary, err)
	}
	if got, want := repository.claimKinds(), []Kind{KindLogoutRetry}; !reflect.DeepEqual(got, want) {
		t.Fatalf("claims past cycle boundary = %v, want %v", got, want)
	}
}

func TestAcceptedNominalLeaseBudgetDispatchesAfterPositiveClaimRoundTrip(t *testing.T) {
	now := oidcMaintenanceTestNow()
	keyring := oidcMaintenanceTestKeyring(t)
	claim := oidcMaintenanceRefreshClaim(t, keyring, "tenant", now)
	claim.LeaseExpiresAt = now.Add(NominalLeaseDuration)
	repository := &oidcMaintenanceFakeRepository{
		claim: func(_ context.Context, kind Kind, observedAt time.Time) (*Work, error) {
			if kind != KindRefresh {
				return nil, nil
			}
			time.Sleep(20 * time.Millisecond)
			return &Work{ObservedAt: observedAt, Kind: KindRefresh, Refresh: &claim}, nil
		},
		load: encryptedOIDCSecretLoader(t, keyring, []byte("historical-client-secret")),
	}
	upstream := &oidcMaintenanceFakeUpstream{refresh: successfulOIDCMaintenanceRefresh(now)}
	worker, err := New(Options{
		Repository: repository, Keyring: keyring, Upstream: upstream, BatchSize: 3,
		DatabaseTimeout:  MinimumDatabaseTimeout,
		OperationTimeout: 117 * time.Second, LeaseSafety: MinimumLeaseSafety,
		PollInterval: time.Second, Clock: func() time.Time { return now },
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("New() rejected a budget with a full bounded claim reserve: %v", err)
	}
	worker.nextKind = 1

	summary, err := worker.runBoundedCycle(context.Background())
	if err != nil || summary.RefreshRotated != 1 || summary.LocalDeferred != 0 ||
		upstream.refreshCallCount() != 1 {
		t.Fatalf("positive claim round trip did not dispatch: summary=%+v error=%v upstream=%d",
			summary, err, upstream.refreshCallCount())
	}
}

func TestShortUpstreamTimeoutDoesNotTruncateTerminalDatabaseWrite(t *testing.T) {
	now := oidcMaintenanceTestNow()
	keyring := oidcMaintenanceTestKeyring(t)
	claim := oidcMaintenanceRefreshClaim(t, keyring, "tenant", now)
	repository := &oidcMaintenanceFakeRepository{
		claim: onceOIDCWork(KindRefresh, &Work{Kind: KindRefresh, Refresh: &claim}),
		load:  encryptedOIDCSecretLoader(t, keyring, []byte("historical-client-secret")),
		completeRefresh: func(ctx context.Context, _ RefreshCompletion) (bool, error) {
			select {
			case <-time.After(200 * time.Millisecond):
				return true, nil
			case <-ctx.Done():
				return false, ctx.Err()
			}
		},
	}
	worker := oidcMaintenanceTestWorker(
		t, repository, &oidcMaintenanceFakeUpstream{refresh: successfulOIDCMaintenanceRefresh(now)},
		keyring, now, 3,
	)
	worker.nextKind = 1
	worker.operationTimeout = MinimumOperation
	worker.databaseTimeout = MinimumDatabaseTimeout

	summary, err := worker.RunOnce(context.Background())
	if err != nil || summary.RefreshRotated != 1 {
		t.Fatalf("short-upstream terminal result = summary %+v, error %v", summary, err)
	}
}

func TestFailureClassificationDistinguishesConfigurationFromDependencies(t *testing.T) {
	if got := classifyFailure(ErrInvalidConfiguration); got != "invalid_configuration" {
		t.Fatalf("configuration classification = %q", got)
	}
	if got := classifyFailure(ErrInvalidInput); got != "invalid_input" {
		t.Fatalf("input classification = %q", got)
	}
}

func TestWorkerRejectsUnfairOrUnboundedConfigurationAndRedactsFormatting(t *testing.T) {
	now := oidcMaintenanceTestNow()
	keyring := oidcMaintenanceTestKeyring(t)
	for _, batch := range []int{0, 2, MaximumBatchSize + 1} {
		_, err := New(Options{
			Repository: &oidcMaintenanceFakeRepository{}, Keyring: keyring,
			Upstream: &oidcMaintenanceFakeUpstream{}, BatchSize: batch,
			DatabaseTimeout:  5 * time.Second,
			OperationTimeout: 20 * time.Second, LeaseSafety: 5 * time.Second,
			PollInterval: time.Second, Clock: func() time.Time { return now },
			Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		})
		if !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("New() accepted batch %d: %v", batch, err)
		}
	}
	_, err := New(Options{
		Repository: &oidcMaintenanceFakeRepository{}, Keyring: keyring,
		Upstream: &oidcMaintenanceFakeUpstream{}, BatchSize: 3,
		DatabaseTimeout:  5 * time.Second,
		OperationTimeout: MaximumOperation, LeaseSafety: MinimumLeaseSafety,
		PollInterval: time.Second, Clock: func() time.Time { return now },
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("New() accepted operation/safety outside the nominal lease: %v", err)
	}
	_, err = New(Options{
		Repository: &oidcMaintenanceFakeRepository{}, Keyring: keyring,
		Upstream: &oidcMaintenanceFakeUpstream{}, BatchSize: 3,
		DatabaseTimeout:  5 * time.Second,
		OperationTimeout: time.Minute, LeaseSafety: 59 * time.Second,
		PollInterval: time.Second, Clock: func() time.Time { return now },
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("New() accepted a nominal lease budget without claim latency: %v", err)
	}
	worker := oidcMaintenanceTestWorker(t, &oidcMaintenanceFakeRepository{}, &oidcMaintenanceFakeUpstream{}, keyring, now, 3)
	formatted := fmt.Sprintf("%v %#v %v", worker, worker, RefreshResult{RefreshToken: []byte("secret")})
	if formatted != "oidcmaintenance.Worker{dependencies:[REDACTED],configuration:[REDACTED]} "+
		"oidcmaintenance.Worker{dependencies:[REDACTED],configuration:[REDACTED]} "+
		"oidcmaintenance.RefreshResult{material:[REDACTED]}" {
		t.Fatalf("unsafe formatting: %s", formatted)
	}
}

type oidcMaintenanceFakeRepository struct {
	mu               sync.Mutex
	ready            func(context.Context) error
	queue            func(context.Context) (QueueSnapshot, error)
	expireAccess     func(context.Context, time.Time) error
	cleanupRetention func(context.Context, time.Time) error
	claim            func(context.Context, Kind, time.Time) (*Work, error)
	load             func(context.Context, ClientSecretLookup) (ClientSecretSnapshot, error)
	completeRefresh  func(context.Context, RefreshCompletion) (bool, error)
	completeLogout   func(context.Context, LogoutCompletion) (bool, error)
	readyErr         error
	loseRefreshFence bool
	loseLogoutFence  bool
	phases           []string
	kinds            []Kind
	lookups          []ClientSecretLookup
	refreshDone      []RefreshCompletion
	logoutDone       []LogoutCompletion
}

type oidcMaintenanceTraceRecord struct {
	name string
	err  error
}

type oidcMaintenanceRecordingTracer struct {
	mu         sync.Mutex
	records    []oidcMaintenanceTraceRecord
	finishHook func(string)
}

func (tracer *oidcMaintenanceRecordingTracer) StartOperation(
	ctx context.Context,
	name string,
) (context.Context, func(error)) {
	return ctx, func(err error) {
		tracer.mu.Lock()
		tracer.records = append(tracer.records, oidcMaintenanceTraceRecord{name: name, err: err})
		tracer.mu.Unlock()
		if tracer.finishHook != nil {
			tracer.finishHook(name)
		}
	}
}

func (tracer *oidcMaintenanceRecordingTracer) finished(name string) (error, bool) {
	tracer.mu.Lock()
	defer tracer.mu.Unlock()
	for _, record := range tracer.records {
		if record.name == name {
			return record.err, true
		}
	}
	return nil, false
}

func (repository *oidcMaintenanceFakeRepository) Ready(ctx context.Context) error {
	repository.mu.Lock()
	ready, readyErr := repository.ready, repository.readyErr
	repository.mu.Unlock()
	if ready != nil {
		return ready(ctx)
	}
	return readyErr
}

func (repository *oidcMaintenanceFakeRepository) QueueSnapshot(
	ctx context.Context,
) (QueueSnapshot, error) {
	repository.mu.Lock()
	queue := repository.queue
	repository.mu.Unlock()
	if queue != nil {
		return queue(ctx)
	}
	return QueueSnapshot{ObservedAt: oidcMaintenanceTestNow()}, nil
}

func (repository *oidcMaintenanceFakeRepository) ExpireAccessLease(
	ctx context.Context,
	observedAt time.Time,
) error {
	repository.mu.Lock()
	repository.phases = append(repository.phases, "access_expiry")
	expireAccess := repository.expireAccess
	repository.mu.Unlock()
	if expireAccess != nil {
		return expireAccess(ctx, observedAt)
	}
	return nil
}

func (repository *oidcMaintenanceFakeRepository) CleanupFederatedRetention(
	ctx context.Context,
	observedAt time.Time,
) error {
	repository.mu.Lock()
	repository.phases = append(repository.phases, "retention_cleanup")
	cleanupRetention := repository.cleanupRetention
	repository.mu.Unlock()
	if cleanupRetention != nil {
		return cleanupRetention(ctx, observedAt)
	}
	return nil
}

func (repository *oidcMaintenanceFakeRepository) ClaimDue(
	ctx context.Context, kind Kind, observedAt time.Time,
) (*Work, error) {
	repository.mu.Lock()
	repository.kinds = append(repository.kinds, kind)
	claim := repository.claim
	repository.mu.Unlock()
	if claim == nil {
		return nil, nil
	}
	return claim(ctx, kind, observedAt)
}

func (repository *oidcMaintenanceFakeRepository) LoadClientSecret(
	ctx context.Context, lookup ClientSecretLookup,
) (ClientSecretSnapshot, error) {
	repository.mu.Lock()
	repository.lookups = append(repository.lookups, lookup)
	load := repository.load
	repository.mu.Unlock()
	if load == nil {
		return ClientSecretSnapshot{}, ErrUnavailable
	}
	return load(ctx, lookup)
}

func (repository *oidcMaintenanceFakeRepository) CompleteRefresh(
	ctx context.Context, completion RefreshCompletion,
) (bool, error) {
	copyCompletion := completion
	copyCompletion.SuccessorToken.Ciphertext = append([]byte(nil), completion.SuccessorToken.Ciphertext...)
	repository.mu.Lock()
	repository.refreshDone = append(repository.refreshDone, copyCompletion)
	complete := repository.completeRefresh
	applied := !repository.loseRefreshFence
	repository.mu.Unlock()
	if complete != nil {
		return complete(ctx, completion)
	}
	return applied, nil
}

func (repository *oidcMaintenanceFakeRepository) CompleteLogout(
	ctx context.Context, completion LogoutCompletion,
) (bool, error) {
	repository.mu.Lock()
	repository.logoutDone = append(repository.logoutDone, completion)
	complete := repository.completeLogout
	applied := !repository.loseLogoutFence
	repository.mu.Unlock()
	if complete != nil {
		return complete(ctx, completion)
	}
	return applied, nil
}

func (repository *oidcMaintenanceFakeRepository) claimKinds() []Kind {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	return append([]Kind(nil), repository.kinds...)
}

func (repository *oidcMaintenanceFakeRepository) phaseNames() []string {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	return append([]string(nil), repository.phases...)
}

func (repository *oidcMaintenanceFakeRepository) secretLookups() []ClientSecretLookup {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	return append([]ClientSecretLookup(nil), repository.lookups...)
}

func (repository *oidcMaintenanceFakeRepository) refreshCompletions() []RefreshCompletion {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	return append([]RefreshCompletion(nil), repository.refreshDone...)
}

func (repository *oidcMaintenanceFakeRepository) logoutCompletions() []LogoutCompletion {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	return append([]LogoutCompletion(nil), repository.logoutDone...)
}

func (repository *oidcMaintenanceFakeRepository) refreshCompletionCount() int {
	return len(repository.refreshCompletions())
}
func (repository *oidcMaintenanceFakeRepository) logoutCompletionCount() int {
	return len(repository.logoutCompletions())
}
func (repository *oidcMaintenanceFakeRepository) refreshClaimCount() int {
	count := 0
	for _, kind := range repository.claimKinds() {
		if kind == KindRefresh {
			count++
		}
	}
	return count
}

type oidcMaintenanceFakeUpstream struct {
	mu           sync.Mutex
	refresh      func(context.Context, federatedoidc.StoredRefreshExchangeRequest, time.Time) (RefreshResult, error)
	revoke       func(context.Context, federatedoidc.StoredRevocationMaterial) error
	refreshCalls int
	revokeCalls  int
}

func (upstream *oidcMaintenanceFakeUpstream) Refresh(
	ctx context.Context, request federatedoidc.StoredRefreshExchangeRequest, now time.Time,
) (RefreshResult, error) {
	upstream.mu.Lock()
	upstream.refreshCalls++
	refresh := upstream.refresh
	upstream.mu.Unlock()
	defer clear(request.ClientSecret)
	defer clear(request.RefreshToken)
	if refresh == nil {
		return RefreshResult{}, federatedoidc.ErrRefreshRejected
	}
	return refresh(ctx, request, now)
}

func (upstream *oidcMaintenanceFakeUpstream) Revoke(
	ctx context.Context, material federatedoidc.StoredRevocationMaterial,
) error {
	upstream.mu.Lock()
	upstream.revokeCalls++
	revoke := upstream.revoke
	upstream.mu.Unlock()
	defer clear(material.Token)
	defer clear(material.ClientSecret)
	if revoke == nil {
		return nil
	}
	return revoke(ctx, material)
}

func (upstream *oidcMaintenanceFakeUpstream) refreshCallCount() int {
	upstream.mu.Lock()
	defer upstream.mu.Unlock()
	return upstream.refreshCalls
}

func (upstream *oidcMaintenanceFakeUpstream) revokeCallCount() int {
	upstream.mu.Lock()
	defer upstream.mu.Unlock()
	return upstream.revokeCalls
}

func oidcMaintenanceTestWorker(
	t *testing.T,
	repository Repository,
	upstream Upstream,
	keyring identity.Keyring,
	now time.Time,
	batch int,
) *Worker {
	t.Helper()
	worker, err := New(Options{
		Repository: repository, Keyring: keyring, Upstream: upstream, BatchSize: batch,
		DatabaseTimeout:  5 * time.Second,
		OperationTimeout: 20 * time.Second, LeaseSafety: 5 * time.Second,
		PollInterval: time.Second, Clock: func() time.Time { return now },
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return worker
}

func oidcMaintenanceTestKeyring(t *testing.T) identity.Keyring {
	t.Helper()
	keyring, err := identity.NewKeyring(1, map[int16][]byte{1: make([]byte, 32)})
	if err != nil {
		t.Fatalf("NewKeyring() error = %v", err)
	}
	return keyring
}

func oidcMaintenanceRefreshClaim(
	t *testing.T, keyring identity.Keyring, authority string, now time.Time,
) RefreshClaim {
	t.Helper()
	tenantID, provider, admission, bindingID := oidcMaintenanceAuthority(authority)
	claim := RefreshClaim{
		TenantID: tenantID, EffectiveTenantID: tenantID, MaterialID: oidcMaintenanceTestID(20),
		SessionFamilyID: oidcMaintenanceTestID(21), Generation: 3, Version: 7,
		LeaseExpiresAt: now.Add(90 * time.Second), Provider: provider, Admission: admission,
		BindingID: bindingID, ClientSecretRevision: 4,
		Endpoint:             "https://idp.example.invalid/oauth/token",
		ClientAuthentication: federatedoidc.ClientSecretBasic, ClientID: "worker-client",
		MaterialExpiresAt: now.Add(30 * time.Minute), AbsoluteSessionExpiry: now.Add(time.Hour),
	}
	claim.Token = encryptOIDCMaintenanceToken(t, keyring, claim, []byte("claimed-refresh-token"))
	claim.TokenDigest = sha256.Sum256([]byte("claimed-refresh-token"))
	return claim
}

func oidcMaintenanceLogoutClaim(
	t *testing.T, keyring identity.Keyring, authority string, now time.Time,
) LogoutRetryClaim {
	t.Helper()
	tenantID, provider, admission, bindingID := oidcMaintenanceAuthority(authority)
	claim := LogoutRetryClaim{
		JobID: oidcMaintenanceTestID(30), TenantID: tenantID, MaterialID: oidcMaintenanceTestID(31),
		SessionFamilyID: oidcMaintenanceTestID(32), Attempt: 1, MaximumAttempts: 3,
		ClaimVersion: 8, LeaseExpiresAt: now.Add(90 * time.Second), NotBefore: now,
		Provider: provider, Admission: admission, BindingID: bindingID, ClientSecretRevision: 4,
		ClientAuthentication: federatedoidc.ClientSecretPost, ClientID: "worker-client",
		Endpoint: "https://idp.example.invalid/oauth/revoke", RefreshGeneration: 3,
		TokenDigest: sha256.Sum256([]byte("claimed-refresh-token")), MaterialExpiresAt: now.Add(time.Hour),
	}
	claim.OpaqueReference = encryptOIDCMaintenanceLogoutToken(t, keyring, claim, []byte("claimed-refresh-token"))
	return claim
}

func oidcMaintenanceAuthority(
	authority string,
) (identity.EntityID, identity.ProviderContext, identity.TenantAdmissionContext, identity.EntityID) {
	tenantID := oidcMaintenanceTestID(1)
	providerID := oidcMaintenanceTestID(2)
	bindingID := oidcMaintenanceTestID(3)
	switch authority {
	case "tenant":
		return tenantID, identity.ProviderContext{
			Scope: identity.TenantProviderScope, TenantID: tenantID, ProviderID: providerID,
		}, identity.TenantAdmissionContext{}, bindingID
	case "admitted_platform":
		return tenantID, identity.ProviderContext{
			Scope: identity.PlatformProviderScope, ProviderID: providerID,
		}, identity.TenantAdmissionContext{TenantID: tenantID, BindingID: bindingID}, bindingID
	case "direct_platform":
		return identity.EntityID{}, identity.ProviderContext{
			Scope: identity.PlatformProviderScope, ProviderID: providerID,
		}, identity.TenantAdmissionContext{}, identity.EntityID{}
	default:
		panic("unknown test authority")
	}
}

func encryptOIDCMaintenanceToken(
	t *testing.T, keyring identity.Keyring, claim RefreshClaim, plaintext []byte,
) ProtectedToken {
	t.Helper()
	return encryptOIDCMaintenanceTokenContext(t, keyring, identity.OIDCSessionMaterialContext{
		Provider: claim.Provider, TenantID: claim.TenantID, BindingID: claim.BindingID,
		MaterialID: claim.MaterialID,
	}, plaintext)
}

func encryptOIDCMaintenanceLogoutToken(
	t *testing.T, keyring identity.Keyring, claim LogoutRetryClaim, plaintext []byte,
) ProtectedToken {
	t.Helper()
	return encryptOIDCMaintenanceTokenContext(t, keyring, identity.OIDCSessionMaterialContext{
		Provider: claim.Provider, TenantID: claim.TenantID, BindingID: claim.BindingID,
		MaterialID: claim.MaterialID,
	}, plaintext)
}

func encryptOIDCMaintenanceTokenContext(
	t *testing.T, keyring identity.Keyring, material identity.OIDCSessionMaterialContext, plaintext []byte,
) ProtectedToken {
	t.Helper()
	envelope, err := keyring.EncryptOIDCRefreshToken(material, plaintext)
	if err != nil {
		t.Fatalf("EncryptOIDCRefreshToken() error = %v", err)
	}
	defer clear(envelope.Nonce[:])
	defer clear(envelope.Ciphertext)
	ciphertext := append([]byte(nil), envelope.Nonce[:]...)
	ciphertext = append(ciphertext, envelope.Ciphertext...)
	return ProtectedToken{KeyVersion: uint32(envelope.KeyVersion), Ciphertext: ciphertext}
}

func decryptOIDCMaintenanceToken(
	t *testing.T, keyring identity.Keyring, claim RefreshClaim, protected ProtectedToken,
) []byte {
	t.Helper()
	var nonce [12]byte
	copy(nonce[:], protected.Ciphertext[:12])
	returnValue, err := keyring.DecryptOIDCRefreshToken(identity.OIDCSessionMaterialContext{
		Provider: claim.Provider, TenantID: claim.TenantID, BindingID: claim.BindingID,
		MaterialID: claim.MaterialID,
	}, identity.OIDCSessionTokenEnvelope{
		KeyVersion: int16(protected.KeyVersion), Nonce: nonce,
		Ciphertext: append([]byte(nil), protected.Ciphertext[12:]...),
	})
	if err != nil {
		t.Fatalf("DecryptOIDCRefreshToken() error = %v", err)
	}
	return returnValue
}

func encryptedOIDCSecretLoader(
	t *testing.T, keyring identity.Keyring, plaintext []byte,
) func(context.Context, ClientSecretLookup) (ClientSecretSnapshot, error) {
	t.Helper()
	return func(_ context.Context, lookup ClientSecretLookup) (ClientSecretSnapshot, error) {
		secretID := oidcMaintenanceTestID(50)
		envelope, err := keyring.EncryptOIDCClientSecret(identity.OIDCClientSecretContext{
			Provider: lookup.Provider, BindingID: lookup.BindingID, SecretID: secretID,
		}, plaintext)
		if err != nil {
			t.Fatalf("EncryptOIDCClientSecret() error = %v", err)
		}
		return ClientSecretSnapshot{Lookup: lookup, SecretID: secretID, Envelope: envelope}, nil
	}
}

func assertOIDCMaintenanceLookup(
	t *testing.T, authority string, claim RefreshClaim, lookup ClientSecretLookup,
) {
	t.Helper()
	if lookup.Provider != claim.Provider || lookup.Revision != claim.ClientSecretRevision {
		t.Fatalf("lookup provider/revision mismatch: %+v", lookup)
	}
	switch authority {
	case "tenant":
		if lookup.BindingID != claim.BindingID || lookup.Admission != (identity.TenantAdmissionContext{}) {
			t.Fatalf("tenant lookup = %+v", lookup)
		}
	case "admitted_platform":
		if lookup.BindingID != (identity.EntityID{}) || lookup.Admission != claim.Admission {
			t.Fatalf("admitted lookup = %+v", lookup)
		}
	case "direct_platform":
		if lookup.BindingID != (identity.EntityID{}) || lookup.Admission != (identity.TenantAdmissionContext{}) {
			t.Fatalf("direct lookup = %+v", lookup)
		}
	}
}

func onceOIDCWork(expected Kind, work *Work) func(context.Context, Kind, time.Time) (*Work, error) {
	var returned bool
	return func(_ context.Context, kind Kind, observedAt time.Time) (*Work, error) {
		if kind != expected || returned {
			return nil, nil
		}
		returned = true
		if work != nil && work.ObservedAt.IsZero() {
			work.ObservedAt = observedAt
		}
		return work, nil
	}
}

func successfulOIDCMaintenanceRefresh(now time.Time) func(
	context.Context, federatedoidc.StoredRefreshExchangeRequest, time.Time,
) (RefreshResult, error) {
	return func(context.Context, federatedoidc.StoredRefreshExchangeRequest, time.Time) (RefreshResult, error) {
		return RefreshResult{RefreshToken: []byte("rotated-refresh-token"), AccessExpiresAt: now.Add(time.Minute)}, nil
	}
}

func oidcMaintenanceTestID(suffix int) identity.EntityID {
	return identity.EntityID(uuid.MustParse(fmt.Sprintf("01890f00-0000-7000-8000-%012d", suffix)))
}

func oidcMaintenanceTestNow() time.Time {
	return time.Date(2026, time.September, 4, 12, 0, 0, 123000, time.UTC)
}
