package ticketbulk

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
)

func TestRunOnceAppliesClosedCommandsAndCompletesExactProgress(t *testing.T) {
	fixture := newWorkerFixture(t, 3)
	results := []kernel.TicketBulkTargetResult{
		kernel.TicketBulkTargetSucceeded,
		kernel.TicketBulkTargetVersionConflict,
		kernel.TicketBulkTargetNotFoundOrHidden,
	}
	repository := &repositoryStub{claim: fixture.claim}
	repository.apply = func(_ context.Context, request ApplyTargetRequest) (ApplyTargetResult, error) {
		if request.Identity != fixture.identity || request.Binding != fixture.claim.Binding ||
			request.Command.Action() != kernel.ActionTransition {
			t.Fatalf("ApplyTarget() request = %#v", request)
		}
		index := int(request.Sequence - 1)
		if request.Pin != fixture.claim.Targets[index].Pin {
			t.Fatalf("ApplyTarget() pin = %#v", request.Pin)
		}
		return ApplyTargetResult{
			Disposition: ApplyTargetApplied, Sequence: request.Sequence, Result: results[index],
		}, nil
	}
	repository.release = func(_ context.Context, request ReleaseBatchRequest) (ReleaseBatchResult, error) {
		if request.Processed != 3 || request.ReceiptDigest == ([32]byte{}) ||
			request.Identity != fixture.identity || request.Binding != fixture.claim.Binding ||
			!request.ReleasedAt.Equal(fixture.now) {
			t.Fatalf("ReleaseBatch() request = %#v", request)
		}
		expected := sha256.New()
		for index, target := range fixture.claim.Targets {
			writeTicketBulkReceipt(expected, target, results[index])
		}
		var expectedDigest [sha256.Size]byte
		copy(expectedDigest[:], expected.Sum(nil))
		if got := request.ReceiptDigest; got != expectedDigest {
			t.Fatalf("receipt digest = %x", got)
		}
		progress, _ := kernel.RestoreTicketBulkProgress(fixture.claim.Progress)
		for _, result := range results {
			progress, _ = progress.WithResult(result)
		}
		snapshot := progress.Snapshot()
		return ReleaseBatchResult{Disposition: ReleaseJobCompleted, Progress: &snapshot}, nil
	}
	worker := fixture.worker(t, repository)

	result, err := worker.RunOnce(context.Background(), fixture.queue)
	if err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	if !result.Claimed || result.Outcome != OutcomeJobCompleted || result.Processed != 3 ||
		result.Progress == nil || processedTicketBulkSnapshot(*result.Progress) != 3 {
		t.Fatalf("RunOnce() = %#v", result)
	}
	if result.Progress.Succeeded != 1 || result.Progress.VersionConflict != 1 ||
		result.Progress.NotFoundOrHidden != 1 {
		t.Fatalf("progress = %#v", result.Progress)
	}
}

func TestRunOnceStopsAndFinalizesControlTransitions(t *testing.T) {
	for _, test := range []struct {
		name        string
		disposition ApplyTargetDisposition
		cancel      bool
		resultCode  kernel.TicketBulkTargetResult
		outcome     Outcome
	}{
		{
			name: "cancellation", disposition: ApplyTargetCancellationRequested,
			cancel: true, resultCode: kernel.TicketBulkTargetCancelled, outcome: OutcomeCancelled,
		},
		{
			name: "authorization revocation", disposition: ApplyTargetAuthorizationRevoked,
			resultCode: kernel.TicketBulkTargetAuthorizationRevoked, outcome: OutcomeAuthorizationRevoked,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newWorkerFixture(t, 3)
			var applyCalls, releaseCalls int
			repository := &repositoryStub{claim: fixture.claim}
			repository.apply = func(_ context.Context, _ ApplyTargetRequest) (ApplyTargetResult, error) {
				applyCalls++
				return ApplyTargetResult{
					Disposition:     test.disposition,
					ControlRevision: fixture.claim.Binding.Revision + 1,
				}, nil
			}
			repository.release = func(context.Context, ReleaseBatchRequest) (ReleaseBatchResult, error) {
				releaseCalls++
				return ReleaseBatchResult{}, nil
			}
			finalizer := func(_ context.Context, request ControlFinalizationRequest) (ControlFinalizationResult, error) {
				if request.ExpectedRevision != fixture.claim.Binding.Revision+1 ||
					request.Binding != fixture.claim.Binding || request.Identity != fixture.identity {
					t.Fatalf("finalization request = %#v", request)
				}
				progress, _ := kernel.RestoreTicketBulkProgress(fixture.claim.Progress)
				progress, _ = progress.WithRemainder(test.resultCode)
				snapshot := progress.Snapshot()
				return ControlFinalizationResult{
					Disposition: ControlFinalizationApplied, Progress: &snapshot,
					ControlRevision: request.ExpectedRevision,
				}, nil
			}
			if test.cancel {
				repository.cancel = finalizer
			} else {
				repository.revoke = finalizer
			}

			result, err := fixture.worker(t, repository).RunOnce(context.Background(), fixture.queue)
			if err != nil {
				t.Fatalf("RunOnce() error = %v", err)
			}
			if result.Outcome != test.outcome || result.Processed != 0 || result.Progress == nil ||
				result.Progress.Total != 3 || result.ProgressCount(test.resultCode) != 3 {
				t.Fatalf("RunOnce() = %#v", result)
			}
			if applyCalls != 1 || releaseCalls != 0 {
				t.Fatalf("apply calls = %d, release calls = %d", applyCalls, releaseCalls)
			}
		})
	}
}

func TestRunOnceFinalizesCancellationAfterCommittedPrefix(t *testing.T) {
	fixture := newWorkerFixture(t, 3)
	var applyCalls int
	repository := &repositoryStub{claim: fixture.claim}
	repository.apply = func(_ context.Context, request ApplyTargetRequest) (ApplyTargetResult, error) {
		applyCalls++
		if applyCalls == 1 {
			return ApplyTargetResult{
				Disposition: ApplyTargetApplied, Sequence: request.Sequence,
				Result: kernel.TicketBulkTargetSucceeded,
			}, nil
		}
		return ApplyTargetResult{
			Disposition:     ApplyTargetCancellationRequested,
			ControlRevision: fixture.claim.Binding.Revision + 1,
		}, nil
	}
	repository.cancel = func(_ context.Context, request ControlFinalizationRequest) (ControlFinalizationResult, error) {
		progress := kernel.TicketBulkProgressSnapshot{Total: 3, Succeeded: 1, Cancelled: 2}
		return ControlFinalizationResult{
			Disposition:     ControlFinalizationApplied,
			Progress:        &progress,
			ControlRevision: request.ExpectedRevision,
		}, nil
	}

	result, err := fixture.worker(t, repository).RunOnce(context.Background(), fixture.queue)
	if err != nil || result.Outcome != OutcomeCancelled || result.Processed != 1 ||
		result.Progress == nil || result.Progress.Succeeded != 1 || result.Progress.Cancelled != 2 ||
		applyCalls != 2 {
		t.Fatalf("RunOnce() = %#v, %v; apply calls = %d", result, err, applyCalls)
	}
}

func TestRunOnceReportsFenceLossAfterCommittedPrefixWithoutContradictoryTransition(t *testing.T) {
	fixture := newWorkerFixture(t, 2)
	var applyCalls, releaseCalls, failureCalls int
	repository := &repositoryStub{claim: fixture.claim}
	repository.apply = func(_ context.Context, request ApplyTargetRequest) (ApplyTargetResult, error) {
		applyCalls++
		if applyCalls == 1 {
			return ApplyTargetResult{
				Disposition: ApplyTargetApplied, Sequence: request.Sequence,
				Result: kernel.TicketBulkTargetSucceeded,
			}, nil
		}
		return ApplyTargetResult{Disposition: ApplyTargetFenceLost}, nil
	}
	repository.release = func(context.Context, ReleaseBatchRequest) (ReleaseBatchResult, error) {
		releaseCalls++
		return ReleaseBatchResult{}, nil
	}
	repository.failure = func(context.Context, BatchFailureRequest) (BatchFailureResult, error) {
		failureCalls++
		return BatchFailureResult{}, nil
	}

	result, err := fixture.worker(t, repository).RunOnce(context.Background(), fixture.queue)
	if !errors.Is(err, ErrFenceLost) || result.Outcome != OutcomeFenceLost || result.Processed != 1 ||
		applyCalls != 2 || releaseCalls != 0 || failureCalls != 0 {
		t.Fatalf(
			"RunOnce() = %#v, %v; apply=%d release=%d failure=%d",
			result, err, applyCalls, releaseCalls, failureCalls,
		)
	}
}

func TestRunOnceReportsTransientApplyFailureAndSchedulesRetry(t *testing.T) {
	fixture := newWorkerFixture(t, 2)
	repository := &repositoryStub{claim: fixture.claim}
	repository.apply = func(context.Context, ApplyTargetRequest) (ApplyTargetResult, error) {
		return ApplyTargetResult{}, errors.New("database connection detail must not escape")
	}
	repository.failure = func(_ context.Context, request BatchFailureRequest) (BatchFailureResult, error) {
		if request.Code != BatchFailureTransientDatabase || request.RetryAt == nil ||
			!request.RetryAt.After(request.FailedAt) || request.RetryAt.Nanosecond()%1_000 != 0 {
			t.Fatalf("ReportBatchFailure() request = %#v", request)
		}
		return BatchFailureResult{Disposition: FailureRetryScheduled, RetryAt: request.RetryAt}, nil
	}

	result, err := fixture.worker(t, repository).RunOnce(context.Background(), fixture.queue)
	if !errors.Is(err, ErrUnavailable) || strings.Contains(fmt.Sprint(err), "connection detail") {
		t.Fatalf("RunOnce() error = %v", err)
	}
	if result.Outcome != OutcomeRetryScheduled || result.Processed != 0 ||
		result.Failure != BatchFailureTransientDatabase {
		t.Fatalf("RunOnce() = %#v", result)
	}
}

func TestRunOnceTreatsClaimErrorAsOutcomeAmbiguousAndRedactsCause(t *testing.T) {
	fixture := newWorkerFixture(t, 1)
	repository := &repositoryStub{}
	repository.claimFn = func(context.Context, ClaimRequest) (Claim, bool, error) {
		return Claim{}, false, errors.New("tenant and database detail must not escape")
	}

	result, err := fixture.worker(t, repository).RunOnce(context.Background(), fixture.queue)
	if result != (Result{}) || !errors.Is(err, ErrTransitionOutcomeUnknown) ||
		!errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), "database detail") {
		t.Fatalf("RunOnce() = %#v, %v", result, err)
	}
}

func TestRunOncePreservesClaimAmbiguityWhenParentIsCancelled(t *testing.T) {
	fixture := newWorkerFixture(t, 1)
	ctx, cancel := context.WithCancel(context.Background())
	repository := &repositoryStub{}
	repository.claimFn = func(context.Context, ClaimRequest) (Claim, bool, error) {
		cancel()
		return Claim{}, false, context.Canceled
	}

	result, err := fixture.worker(t, repository).RunOnce(ctx, fixture.queue)
	if result.Outcome != OutcomeInterrupted || !errors.Is(err, ErrInterrupted) ||
		!errors.Is(err, ErrTransitionOutcomeUnknown) {
		t.Fatalf("RunOnce() = %#v, %v", result, err)
	}
}

func TestRunOnceDoesNotLetRepositoryMutateRetryValidationBaseline(t *testing.T) {
	fixture := newWorkerFixture(t, 1)
	repository := &repositoryStub{claim: fixture.claim}
	repository.apply = func(context.Context, ApplyTargetRequest) (ApplyTargetResult, error) {
		return ApplyTargetResult{}, errors.New("unavailable")
	}
	repository.failure = func(_ context.Context, request BatchFailureRequest) (BatchFailureResult, error) {
		*request.RetryAt = request.RetryAt.Add(time.Hour)
		return BatchFailureResult{Disposition: FailureRetryScheduled, RetryAt: request.RetryAt}, nil
	}

	result, err := fixture.worker(t, repository).RunOnce(context.Background(), fixture.queue)
	if !errors.Is(err, ErrTransitionOutcomeUnknown) || !errors.Is(err, ErrUnavailable) ||
		result.Outcome != OutcomeUnknown {
		t.Fatalf("RunOnce() = %#v, %v", result, err)
	}
}

func TestRunOnceAtAttemptCeilingAccountsInternalFailureAndFailsJob(t *testing.T) {
	fixture := newWorkerFixture(t, 2)
	fixture.claim.Binding.Attempt = fixture.claim.Definition.MaximumAttempts()
	repository := &repositoryStub{claim: fixture.claim}
	repository.apply = func(context.Context, ApplyTargetRequest) (ApplyTargetResult, error) {
		return ApplyTargetResult{}, errors.New("unavailable")
	}
	repository.failure = func(_ context.Context, request BatchFailureRequest) (BatchFailureResult, error) {
		if request.RetryAt != nil {
			t.Fatalf("retry scheduled at attempt ceiling: %#v", request)
		}
		progress, _ := kernel.RestoreTicketBulkProgress(fixture.claim.Progress)
		progress, _ = progress.WithRemainder(kernel.TicketBulkTargetInternalFailure)
		snapshot := progress.Snapshot()
		return BatchFailureResult{Disposition: FailureJobFailed, Progress: &snapshot}, nil
	}

	result, err := fixture.worker(t, repository).RunOnce(context.Background(), fixture.queue)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("RunOnce() error = %v", err)
	}
	if result.Outcome != OutcomeJobFailed || result.Progress == nil ||
		result.Progress.InternalFailure != 2 {
		t.Fatalf("RunOnce() = %#v", result)
	}
}

func TestRunOnceReportsInvalidAdapterResultWithoutTrustingIt(t *testing.T) {
	fixture := newWorkerFixture(t, 1)
	repository := &repositoryStub{claim: fixture.claim}
	repository.apply = func(_ context.Context, request ApplyTargetRequest) (ApplyTargetResult, error) {
		return ApplyTargetResult{
			Disposition: ApplyTargetApplied,
			Sequence:    request.Sequence + 1,
			Result:      kernel.TicketBulkTargetSucceeded,
		}, nil
	}
	repository.failure = func(_ context.Context, request BatchFailureRequest) (BatchFailureResult, error) {
		if request.Code != BatchFailureInvalidProjection || request.RetryAt != nil {
			t.Fatalf("ReportBatchFailure() request = %#v", request)
		}
		progress, _ := kernel.RestoreTicketBulkProgress(fixture.claim.Progress)
		progress, _ = progress.WithRemainder(kernel.TicketBulkTargetInternalFailure)
		snapshot := progress.Snapshot()
		return BatchFailureResult{Disposition: FailureJobFailed, Progress: &snapshot}, nil
	}

	result, err := fixture.worker(t, repository).RunOnce(context.Background(), fixture.queue)
	if !errors.Is(err, ErrInvalidProjection) || result.Outcome != OutcomeJobFailed ||
		result.Processed != 0 {
		t.Fatalf("RunOnce() = %#v, %v", result, err)
	}
}

func TestRunOnceDurablyReleasesInterruptedBatch(t *testing.T) {
	fixture := newWorkerFixture(t, 2)
	ctx, cancel := context.WithCancel(context.Background())
	repository := &repositoryStub{claim: fixture.claim}
	repository.apply = func(context.Context, ApplyTargetRequest) (ApplyTargetResult, error) {
		cancel()
		return ApplyTargetResult{}, context.Canceled
	}
	repository.failure = func(reportContext context.Context, request BatchFailureRequest) (BatchFailureResult, error) {
		if reportContext.Err() != nil || request.Code != BatchFailureInterrupted || request.RetryAt == nil {
			t.Fatalf("ReportBatchFailure() context/request = %v, %#v", reportContext.Err(), request)
		}
		return BatchFailureResult{Disposition: FailureRetryScheduled, RetryAt: request.RetryAt}, nil
	}

	result, err := fixture.worker(t, repository).RunOnce(ctx, fixture.queue)
	if !errors.Is(err, ErrInterrupted) || result.Outcome != OutcomeRetryScheduled ||
		result.Failure != BatchFailureInterrupted {
		t.Fatalf("RunOnce() = %#v, %v", result, err)
	}
}

func TestRunOnceRejectsMalformedClaimBeforeApplyingTargets(t *testing.T) {
	mutations := []struct {
		name   string
		mutate func(*Claim)
	}{
		{name: "wrong tenant", mutate: func(claim *Claim) { claim.Binding.TenantID = testEntityID(90) }},
		{name: "wrong worker", mutate: func(claim *Claim) { claim.Binding.WorkerID = testEntityID(91) }},
		{name: "wrong digest", mutate: func(claim *Claim) { claim.Binding.TargetSetDigest[0] ^= 0xff }},
		{name: "duplicate sequence", mutate: func(claim *Claim) { claim.Targets[1].Sequence = claim.Targets[0].Sequence }},
		{name: "duplicate target", mutate: func(claim *Claim) { claim.Targets[1].Pin = claim.Targets[0].Pin }},
		{name: "explicit pin substitution", mutate: func(claim *Claim) { claim.Targets[0].Pin = mustTargetPin(nil, 92, 1) }},
		{name: "revision without transition headroom", mutate: func(claim *Claim) { claim.Binding.Revision = math.MaxInt32 }},
		{name: "complete progress", mutate: func(claim *Claim) {
			progress, _ := kernel.RestoreTicketBulkProgress(claim.Progress)
			progress, _ = progress.WithRemainder(kernel.TicketBulkTargetInternalFailure)
			claim.Progress = progress.Snapshot()
		}},
		{name: "lease too short", mutate: func(claim *Claim) { claim.Binding.LeaseExpiresAt = claim.Binding.ClaimedAt.Add(time.Second) }},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			fixture := newWorkerFixture(t, 2)
			claim := fixture.claim
			claim.Targets = append([]ClaimedTarget(nil), claim.Targets...)
			test.mutate(&claim)
			var applyCalls int
			repository := &repositoryStub{claim: claim}
			repository.apply = func(context.Context, ApplyTargetRequest) (ApplyTargetResult, error) {
				applyCalls++
				return ApplyTargetResult{}, nil
			}
			result, err := fixture.worker(t, repository).RunOnce(context.Background(), fixture.queue)
			if !errors.Is(err, ErrInvalidProjection) || !result.Claimed || applyCalls != 0 {
				t.Fatalf("RunOnce() = %#v, %v, apply calls %d", result, err, applyCalls)
			}
		})
	}
}

func TestRunOnceIdleAndFenceLossAreClosedOutcomes(t *testing.T) {
	fixture := newWorkerFixture(t, 1)
	t.Run("idle", func(t *testing.T) {
		repository := &repositoryStub{claimFound: boolPointer(false)}
		result, err := fixture.worker(t, repository).RunOnce(context.Background(), fixture.queue)
		if err != nil || result.Claimed || result.Outcome != OutcomeIdle {
			t.Fatalf("RunOnce() = %#v, %v", result, err)
		}
	})
	t.Run("claim false with residue", func(t *testing.T) {
		repository := &repositoryStub{claim: fixture.claim, claimFound: boolPointer(false)}
		_, err := fixture.worker(t, repository).RunOnce(context.Background(), fixture.queue)
		if !errors.Is(err, ErrInvalidProjection) {
			t.Fatalf("RunOnce() error = %v", err)
		}
	})
	t.Run("apply fence lost", func(t *testing.T) {
		repository := &repositoryStub{claim: fixture.claim}
		repository.apply = func(context.Context, ApplyTargetRequest) (ApplyTargetResult, error) {
			return ApplyTargetResult{Disposition: ApplyTargetFenceLost}, nil
		}
		result, err := fixture.worker(t, repository).RunOnce(context.Background(), fixture.queue)
		if !errors.Is(err, ErrFenceLost) || result.Outcome != OutcomeFenceLost {
			t.Fatalf("RunOnce() = %#v, %v", result, err)
		}
	})
}

func TestRunOnceBoundsApplyDeadlineBeforeLeaseSafety(t *testing.T) {
	fixture := newWorkerFixture(t, 1)
	fixture.claim.Binding.LeaseExpiresAt = fixture.now.Add(MinimumLease)
	repository := &repositoryStub{claim: fixture.claim}
	repository.apply = func(ctx context.Context, _ ApplyTargetRequest) (ApplyTargetResult, error) {
		deadline, ok := ctx.Deadline()
		remaining := time.Until(deadline)
		if !ok || remaining < 19*time.Second || remaining > 20*time.Second {
			t.Fatalf("ApplyTarget() remaining deadline = %s, %t; want about 20s", remaining, ok)
		}
		return ApplyTargetResult{Disposition: ApplyTargetFenceLost}, nil
	}
	options := fixture.options(repository)
	options.OperationTimeout = 25 * time.Second
	worker, err := New(options)
	if err != nil {
		t.Fatal(err)
	}

	result, err := worker.RunOnce(context.Background(), fixture.queue)
	if !errors.Is(err, ErrFenceLost) || result.Outcome != OutcomeFenceLost {
		t.Fatalf("RunOnce() = %#v, %v", result, err)
	}
}

func TestRunOnceReconcilesSuccessReturnedAfterApplyDeadline(t *testing.T) {
	fixture := newWorkerFixture(t, 1)
	repository := &repositoryStub{claim: fixture.claim}
	repository.apply = func(ctx context.Context, request ApplyTargetRequest) (ApplyTargetResult, error) {
		<-ctx.Done()
		return ApplyTargetResult{
			Disposition: ApplyTargetApplied, Sequence: request.Sequence,
			Result: kernel.TicketBulkTargetSucceeded,
		}, nil
	}
	repository.failure = func(context.Context, BatchFailureRequest) (BatchFailureResult, error) {
		progress := kernel.TicketBulkProgressSnapshot{Total: 1, Succeeded: 1}
		return BatchFailureResult{Disposition: FailureJobCompleted, Progress: &progress}, nil
	}
	options := fixture.options(repository)
	options.OperationTimeout = minimumOperation
	worker, err := New(options)
	if err != nil {
		t.Fatal(err)
	}

	result, err := worker.RunOnce(context.Background(), fixture.queue)
	if !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrTransitionOutcomeUnknown) ||
		result.Outcome != OutcomeJobCompleted || result.Processed != 0 {
		t.Fatalf("RunOnce() = %#v, %v", result, err)
	}
}

func TestRunOnceRejectsReleaseProgressThatLosesObservedResults(t *testing.T) {
	fixture := newWorkerFixture(t, 1)
	repository := &repositoryStub{claim: fixture.claim}
	repository.apply = func(_ context.Context, request ApplyTargetRequest) (ApplyTargetResult, error) {
		return ApplyTargetResult{
			Disposition: ApplyTargetApplied, Sequence: request.Sequence,
			Result: kernel.TicketBulkTargetSucceeded,
		}, nil
	}
	repository.release = func(context.Context, ReleaseBatchRequest) (ReleaseBatchResult, error) {
		progress, _ := kernel.NewTicketBulkProgress(1)
		progress, _ = progress.WithResult(kernel.TicketBulkTargetRejected)
		snapshot := progress.Snapshot()
		return ReleaseBatchResult{Disposition: ReleaseJobCompleted, Progress: &snapshot}, nil
	}

	result, err := fixture.worker(t, repository).RunOnce(context.Background(), fixture.queue)
	if !errors.Is(err, ErrTransitionOutcomeUnknown) || result.Processed != 1 {
		t.Fatalf("RunOnce() = %#v, %v", result, err)
	}
}

func TestRunOnceTreatsReleaseErrorAsOutcomeAmbiguousWithoutCompetingFailure(t *testing.T) {
	fixture := newWorkerFixture(t, 1)
	var failureCalls int
	repository := &repositoryStub{claim: fixture.claim}
	repository.apply = func(_ context.Context, request ApplyTargetRequest) (ApplyTargetResult, error) {
		return ApplyTargetResult{
			Disposition: ApplyTargetApplied, Sequence: request.Sequence,
			Result: kernel.TicketBulkTargetSucceeded,
		}, nil
	}
	repository.release = func(context.Context, ReleaseBatchRequest) (ReleaseBatchResult, error) {
		return ReleaseBatchResult{}, errors.New("tenant database detail must not escape")
	}
	repository.failure = func(context.Context, BatchFailureRequest) (BatchFailureResult, error) {
		failureCalls++
		return BatchFailureResult{}, nil
	}

	result, err := fixture.worker(t, repository).RunOnce(context.Background(), fixture.queue)
	if !errors.Is(err, ErrTransitionOutcomeUnknown) || strings.Contains(err.Error(), "database detail") ||
		result.Processed != 1 || failureCalls != 0 {
		t.Fatalf("RunOnce() = %#v, %v; failure calls = %d", result, err, failureCalls)
	}
}

func TestRunOnceDistinguishesGlobalFailureWhenLastBatchReleases(t *testing.T) {
	for _, test := range []struct {
		name        string
		disposition ReleaseBatchDisposition
		wantOutcome Outcome
		wantErr     error
	}{
		{
			name: "failed completion", disposition: ReleaseJobFailed,
			wantOutcome: OutcomeJobFailed,
		},
		{
			name: "false success", disposition: ReleaseJobCompleted,
			wantErr: ErrTransitionOutcomeUnknown,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newWorkerFixture(t, 2)
			fixture.claim.Targets = fixture.claim.Targets[1:]
			fixture.claim.Progress = kernel.TicketBulkProgressSnapshot{Total: 2, InternalFailure: 1}
			repository := &repositoryStub{claim: fixture.claim}
			repository.apply = func(_ context.Context, request ApplyTargetRequest) (ApplyTargetResult, error) {
				return ApplyTargetResult{
					Disposition: ApplyTargetApplied, Sequence: request.Sequence,
					Result: kernel.TicketBulkTargetSucceeded,
				}, nil
			}
			repository.release = func(context.Context, ReleaseBatchRequest) (ReleaseBatchResult, error) {
				progress := kernel.TicketBulkProgressSnapshot{Total: 2, Succeeded: 1, InternalFailure: 1}
				return ReleaseBatchResult{Disposition: test.disposition, Progress: &progress}, nil
			}

			result, err := fixture.worker(t, repository).RunOnce(context.Background(), fixture.queue)
			if !errors.Is(err, test.wantErr) || result.Outcome != test.wantOutcome || result.Processed != 1 {
				t.Fatalf("RunOnce() = %#v, %v", result, err)
			}
		})
	}
}

func TestRunOnceAcceptsReplayedTargetOnlyWhenProgressIncludesIt(t *testing.T) {
	fixture := newWorkerFixture(t, 1)
	repository := &repositoryStub{claim: fixture.claim}
	repository.apply = func(_ context.Context, request ApplyTargetRequest) (ApplyTargetResult, error) {
		return ApplyTargetResult{
			Disposition: ApplyTargetReplayed, Sequence: request.Sequence,
			Result: kernel.TicketBulkTargetNoChange,
		}, nil
	}
	repository.release = func(context.Context, ReleaseBatchRequest) (ReleaseBatchResult, error) {
		progress, _ := kernel.RestoreTicketBulkProgress(fixture.claim.Progress)
		progress, _ = progress.WithResult(kernel.TicketBulkTargetNoChange)
		snapshot := progress.Snapshot()
		return ReleaseBatchResult{Disposition: ReleaseJobCompleted, Progress: &snapshot}, nil
	}

	result, err := fixture.worker(t, repository).RunOnce(context.Background(), fixture.queue)
	if err != nil || result.Outcome != OutcomeJobCompleted || result.Progress == nil ||
		result.Progress.NoChange != 1 {
		t.Fatalf("RunOnce() = %#v, %v", result, err)
	}
}

func TestRunOnceRejectsClaimWithPartiallyFinalizedControlProgress(t *testing.T) {
	fixture := newWorkerFixture(t, 3)
	fixture.claim.Targets = fixture.claim.Targets[:2]
	fixture.claim.Progress = kernel.TicketBulkProgressSnapshot{Total: 3, Cancelled: 1}
	var applyCalls int
	repository := &repositoryStub{claim: fixture.claim}
	repository.apply = func(context.Context, ApplyTargetRequest) (ApplyTargetResult, error) {
		applyCalls++
		return ApplyTargetResult{
			Disposition:     ApplyTargetCancellationRequested,
			ControlRevision: fixture.claim.Binding.Revision + 1,
		}, nil
	}

	result, err := fixture.worker(t, repository).RunOnce(context.Background(), fixture.queue)
	if !errors.Is(err, ErrInvalidProjection) || !result.Claimed || applyCalls != 0 {
		t.Fatalf("RunOnce() = %#v, %v; apply calls = %d", result, err, applyCalls)
	}
}

func TestRunOnceRejectsTerminalFailureThatDoesNotAccountWholeBatch(t *testing.T) {
	fixture := newWorkerFixture(t, 2)
	fixture.claim.Binding.Attempt = fixture.claim.Definition.MaximumAttempts()
	repository := &repositoryStub{claim: fixture.claim}
	repository.apply = func(context.Context, ApplyTargetRequest) (ApplyTargetResult, error) {
		return ApplyTargetResult{}, errors.New("response lost")
	}
	repository.failure = func(context.Context, BatchFailureRequest) (BatchFailureResult, error) {
		progress := kernel.TicketBulkProgressSnapshot{Total: 2, InternalFailure: 1}
		return BatchFailureResult{Disposition: FailureBatchTerminalized, Progress: &progress}, nil
	}

	result, err := fixture.worker(t, repository).RunOnce(context.Background(), fixture.queue)
	if !errors.Is(err, ErrTransitionOutcomeUnknown) || !errors.Is(err, ErrUnavailable) ||
		result.Outcome != OutcomeUnknown {
		t.Fatalf("RunOnce() = %#v, %v", result, err)
	}
}

func TestRunOnceReconcilesCommittedTargetAfterResponseLoss(t *testing.T) {
	fixture := newWorkerFixture(t, 1)
	repository := &repositoryStub{claim: fixture.claim}
	repository.apply = func(context.Context, ApplyTargetRequest) (ApplyTargetResult, error) {
		return ApplyTargetResult{}, errors.New("response lost after commit")
	}
	repository.failure = func(context.Context, BatchFailureRequest) (BatchFailureResult, error) {
		progress := kernel.TicketBulkProgressSnapshot{Total: 1, Succeeded: 1}
		return BatchFailureResult{Disposition: FailureJobCompleted, Progress: &progress}, nil
	}

	result, err := fixture.worker(t, repository).RunOnce(context.Background(), fixture.queue)
	if !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrTransitionOutcomeUnknown) ||
		result.Outcome != OutcomeJobCompleted || result.Failure != BatchFailureNone ||
		result.Progress == nil || result.Progress.Succeeded != 1 {
		t.Fatalf("RunOnce() = %#v, %v", result, err)
	}
}

func TestRunOnceReconcilesGlobalFailureAfterAmbiguousLastTarget(t *testing.T) {
	fixture := newWorkerFixture(t, 2)
	fixture.claim.Targets = fixture.claim.Targets[1:]
	fixture.claim.Progress = kernel.TicketBulkProgressSnapshot{Total: 2, InternalFailure: 1}
	repository := &repositoryStub{claim: fixture.claim}
	repository.apply = func(context.Context, ApplyTargetRequest) (ApplyTargetResult, error) {
		return ApplyTargetResult{}, errors.New("response lost after commit")
	}
	repository.failure = func(context.Context, BatchFailureRequest) (BatchFailureResult, error) {
		progress := kernel.TicketBulkProgressSnapshot{Total: 2, Succeeded: 1, InternalFailure: 1}
		return BatchFailureResult{Disposition: FailureJobFailed, Progress: &progress}, nil
	}

	result, err := fixture.worker(t, repository).RunOnce(context.Background(), fixture.queue)
	if !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrTransitionOutcomeUnknown) ||
		result.Outcome != OutcomeJobFailed || result.Progress == nil ||
		result.Progress.InternalFailure != 1 || result.Progress.Succeeded != 1 {
		t.Fatalf("RunOnce() = %#v, %v", result, err)
	}
}

func TestRunOnceRejectsRetryScheduleWithoutExactEcho(t *testing.T) {
	fixture := newWorkerFixture(t, 1)
	repository := &repositoryStub{claim: fixture.claim}
	repository.apply = func(context.Context, ApplyTargetRequest) (ApplyTargetResult, error) {
		return ApplyTargetResult{}, errors.New("unavailable")
	}
	repository.failure = func(context.Context, BatchFailureRequest) (BatchFailureResult, error) {
		return BatchFailureResult{Disposition: FailureRetryScheduled}, nil
	}

	result, err := fixture.worker(t, repository).RunOnce(context.Background(), fixture.queue)
	if !errors.Is(err, ErrTransitionOutcomeUnknown) || !errors.Is(err, ErrUnavailable) ||
		result.Outcome != OutcomeUnknown {
		t.Fatalf("RunOnce() = %#v, %v", result, err)
	}
}

func TestRunOnceRejectsUnboundedOrMismatchedControlRevision(t *testing.T) {
	t.Run("unbounded apply response", func(t *testing.T) {
		fixture := newWorkerFixture(t, 1)
		var finalizeCalls int
		repository := &repositoryStub{claim: fixture.claim}
		repository.apply = func(context.Context, ApplyTargetRequest) (ApplyTargetResult, error) {
			return ApplyTargetResult{
				Disposition:     ApplyTargetCancellationRequested,
				ControlRevision: math.MaxUint64,
			}, nil
		}
		repository.failure = func(context.Context, BatchFailureRequest) (BatchFailureResult, error) {
			progress := kernel.TicketBulkProgressSnapshot{Total: 1, InternalFailure: 1}
			return BatchFailureResult{Disposition: FailureJobFailed, Progress: &progress}, nil
		}
		repository.cancel = func(context.Context, ControlFinalizationRequest) (ControlFinalizationResult, error) {
			finalizeCalls++
			return ControlFinalizationResult{}, nil
		}

		result, err := fixture.worker(t, repository).RunOnce(context.Background(), fixture.queue)
		if !errors.Is(err, ErrInvalidProjection) || result.Outcome != OutcomeJobFailed || finalizeCalls != 0 {
			t.Fatalf("RunOnce() = %#v, %v; finalize calls = %d", result, err, finalizeCalls)
		}
	})

	t.Run("finalizer echo mismatch", func(t *testing.T) {
		fixture := newWorkerFixture(t, 1)
		repository := &repositoryStub{claim: fixture.claim}
		repository.apply = func(context.Context, ApplyTargetRequest) (ApplyTargetResult, error) {
			return ApplyTargetResult{
				Disposition:     ApplyTargetCancellationRequested,
				ControlRevision: fixture.claim.Binding.Revision + 1,
			}, nil
		}
		repository.cancel = func(_ context.Context, request ControlFinalizationRequest) (ControlFinalizationResult, error) {
			progress := kernel.TicketBulkProgressSnapshot{Total: 1, Cancelled: 1}
			return ControlFinalizationResult{
				Disposition: ControlFinalizationApplied, Progress: &progress,
				ControlRevision: request.ExpectedRevision + 1,
			}, nil
		}

		result, err := fixture.worker(t, repository).RunOnce(context.Background(), fixture.queue)
		if !errors.Is(err, ErrTransitionOutcomeUnknown) || result.Outcome != OutcomeUnknown {
			t.Fatalf("RunOnce() = %#v, %v", result, err)
		}
	})
}

func TestNilWorkerRejectsRunOnce(t *testing.T) {
	fixture := newWorkerFixture(t, 1)
	var worker *Worker
	result, err := worker.RunOnce(context.Background(), fixture.queue)
	if !errors.Is(err, ErrInvalidInput) || result != (Result{}) {
		t.Fatalf("RunOnce() = %#v, %v", result, err)
	}
}

func TestConcurrentRunOnceIsRaceSafeWithRepositorySerializedClaim(t *testing.T) {
	fixture := newWorkerFixture(t, 1)
	var claimed atomic.Bool
	var applyCalls atomic.Int32
	repository := &repositoryStub{}
	repository.claimFn = func(context.Context, ClaimRequest) (Claim, bool, error) {
		if claimed.CompareAndSwap(false, true) {
			return fixture.claim, true, nil
		}
		return Claim{}, false, nil
	}
	repository.apply = func(_ context.Context, request ApplyTargetRequest) (ApplyTargetResult, error) {
		applyCalls.Add(1)
		return ApplyTargetResult{
			Disposition: ApplyTargetApplied, Sequence: request.Sequence,
			Result: kernel.TicketBulkTargetSucceeded,
		}, nil
	}
	repository.release = func(context.Context, ReleaseBatchRequest) (ReleaseBatchResult, error) {
		progress, _ := kernel.RestoreTicketBulkProgress(fixture.claim.Progress)
		progress, _ = progress.WithResult(kernel.TicketBulkTargetSucceeded)
		snapshot := progress.Snapshot()
		return ReleaseBatchResult{Disposition: ReleaseJobCompleted, Progress: &snapshot}, nil
	}
	worker := fixture.worker(t, repository)

	const goroutines = 32
	results := make(chan Result, goroutines)
	errorsChannel := make(chan error, goroutines)
	var group sync.WaitGroup
	for index := 0; index < goroutines; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			result, err := worker.RunOnce(context.Background(), fixture.queue)
			results <- result
			errorsChannel <- err
		}()
	}
	group.Wait()
	close(results)
	close(errorsChannel)
	completed, idle := 0, 0
	for result := range results {
		switch result.Outcome {
		case OutcomeJobCompleted:
			completed++
		case OutcomeIdle:
			idle++
		default:
			t.Fatalf("unexpected result %#v", result)
		}
	}
	for err := range errorsChannel {
		if err != nil {
			t.Fatalf("RunOnce() error = %v", err)
		}
	}
	if completed != 1 || idle != goroutines-1 || applyCalls.Load() != 1 {
		t.Fatalf("completed=%d idle=%d apply=%d", completed, idle, applyCalls.Load())
	}
}

func TestWorkerConfigurationAndDiagnosticsAreFailClosed(t *testing.T) {
	fixture := newWorkerFixture(t, 1)
	if diagnostic := (Result{}).String(); !strings.Contains(diagnostic, "outcome:unknown") ||
		strings.Contains(diagnostic, "outcome:idle") {
		t.Fatalf("zero result diagnostic = %s", diagnostic)
	}
	typedNil := (*repositoryStub)(nil)
	for _, mutate := range []func(*Options){
		func(options *Options) { options.Repository = nil },
		func(options *Options) { options.Repository = typedNil },
		func(options *Options) { options.Identity.Purpose = "export" },
		func(options *Options) { options.BatchSize = 0 },
		func(options *Options) { options.BatchSize = MaximumBatchSize + 1 },
		func(options *Options) { options.LeaseDuration = MinimumLease - time.Microsecond },
		func(options *Options) { options.AttemptTimeout = options.LeaseDuration },
		func(options *Options) { options.LeaseSafety = maximumLeaseSafety + time.Microsecond },
		func(options *Options) { options.OperationTimeout = 0 },
		func(options *Options) { options.RetryMaximum = options.RetryBase - time.Microsecond },
		func(options *Options) { options.Clock = nil },
	} {
		options := fixture.options(&repositoryStub{})
		mutate(&options)
		if _, err := New(options); !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("New(%#v) error = %v", options, err)
		}
	}

	worker := fixture.worker(t, &repositoryStub{})
	progress := fixture.claim.Progress
	portValues := []any{
		worker,
		fixture.identity,
		fixture.queue,
		fixture.claim,
		fixture.claim.Binding,
		fixture.claim.Targets[0],
		ClaimRequest{Identity: fixture.identity, Queue: fixture.queue, Now: fixture.now, Limit: 1},
		ApplyTargetRequest{
			Identity: fixture.identity, Binding: fixture.claim.Binding,
			Sequence: fixture.claim.Targets[0].Sequence, Pin: fixture.claim.Targets[0].Pin,
		},
		ReleaseBatchRequest{
			Identity: fixture.identity, Binding: fixture.claim.Binding, Processed: 1,
			ReceiptDigest: sha256.Sum256([]byte("receipt")), ReleasedAt: fixture.now,
		},
		BatchFailureRequest{
			Identity: fixture.identity, Binding: fixture.claim.Binding,
			Code: BatchFailureInternal, FailedAt: fixture.now,
		},
		ControlFinalizationRequest{
			Identity: fixture.identity, Binding: fixture.claim.Binding,
			ExpectedRevision: fixture.claim.Binding.Revision + 1, FinalizedAt: fixture.now,
		},
		ApplyTargetResult{
			Disposition: ApplyTargetApplied, Sequence: 1,
			Result: kernel.TicketBulkTargetSucceeded,
		},
		ReleaseBatchResult{Disposition: ReleaseJobCompleted, Progress: &progress},
		BatchFailureResult{Disposition: FailureJobCompleted, Progress: &progress},
		ControlFinalizationResult{
			Disposition: ControlFinalizationApplied, Progress: &progress,
			ControlRevision: fixture.claim.Binding.Revision + 1,
		},
		Result{Claimed: true, Outcome: OutcomeJobCompleted, Progress: &progress},
	}
	sensitiveValues := []string{
		fixture.claim.Definition.ID().String(), fixture.claim.Definition.Tenant().String(),
		fixture.claim.Definition.Requester().String(), fixture.claim.Definition.OwnerMembership().String(),
		fixture.claim.Targets[0].Pin.ID().String(), fixture.identity.ServiceAccountID.String(),
		fixture.identity.WorkerID.String(), fixture.claim.Binding.BatchID.String(),
	}
	for _, value := range portValues {
		for _, diagnostic := range []string{fmt.Sprintf("%v", value), fmt.Sprintf("%#v", value)} {
			for _, sensitive := range sensitiveValues {
				if strings.Contains(diagnostic, sensitive) {
					t.Fatalf("diagnostic leaked %s: %s", sensitive, diagnostic)
				}
			}
		}
	}
}

type workerFixture struct {
	now      time.Time
	identity Identity
	queue    Queue
	claim    Claim
}

func newWorkerFixture(t *testing.T, targets int) workerFixture {
	t.Helper()
	now := time.Date(2026, 8, 26, 9, 0, 0, 123_000, time.UTC)
	tenant := testEntityID(1)
	pins := make([]kernel.TicketBulkTargetPin, 0, targets)
	for index := 0; index < targets; index++ {
		pins = append(pins, mustTargetPin(t, byte(20+index), uint64(index+5)))
	}
	selection, err := kernel.NewExplicitTicketBulkSelection(pins)
	if err != nil {
		t.Fatalf("NewExplicitTicketBulkSelection() error = %v", err)
	}
	transition, _ := kernel.NewKey("triage")
	to, _ := kernel.NewKey("investigating")
	mutation, err := kernel.NewTicketBulkTransition(transition, to)
	if err != nil {
		t.Fatalf("NewTicketBulkTransition() error = %v", err)
	}
	definition, err := kernel.NewTicketBulkDefinition(kernel.TicketBulkDefinitionInput{
		ID: testEntityID(2), Tenant: tenant, Requester: testEntityID(3),
		OwnerMembership: testEntityID(4), Kind: kernel.AggregateAlert,
		Selection: selection, Mutation: mutation,
		ProjectionVersion: kernel.TicketBulkProjectionVersion,
		MaximumAttempts:   kernel.TicketBulkMaximumAttempts,
	})
	if err != nil {
		t.Fatalf("NewTicketBulkDefinition() error = %v", err)
	}
	progress, _ := kernel.NewTicketBulkProgress(uint32(targets))
	claimedTargets := make([]ClaimedTarget, targets)
	for index, pin := range selection.ExplicitTargets() {
		claimedTargets[index] = ClaimedTarget{Sequence: uint32(index + 1), Pin: pin}
	}
	identity := Identity{
		ServiceAccountID: testEntityID(5), WorkerID: testEntityID(6), Purpose: WorkerPurpose,
	}
	binding := BatchBinding{
		TenantID: tenant, JobID: definition.ID(), BatchID: testEntityID(7),
		Kind: kernel.AggregateAlert, WorkerID: identity.WorkerID,
		Revision: 2, Attempt: 1, Fence: sha256.Sum256([]byte("bulk-fence")),
		TargetSetDigest:   selection.TargetSetDigest(),
		ProjectionVersion: kernel.TicketBulkProjectionVersion,
		ClaimedAt:         now, LeaseExpiresAt: now.Add(5 * time.Minute), JobExpiresAt: now.Add(time.Hour),
	}
	return workerFixture{
		now: now, identity: identity, queue: Queue{TenantID: tenant, Kind: kernel.AggregateAlert},
		claim: Claim{
			Definition: definition, Binding: binding, Targets: claimedTargets,
			Progress: progress.Snapshot(), ObservedAt: now,
		},
	}
}

func (fixture workerFixture) options(repository Repository) Options {
	return Options{
		Repository: repository, Identity: fixture.identity, BatchSize: MaximumBatchSize,
		LeaseDuration: 5 * time.Minute, AttemptTimeout: 4 * time.Minute,
		OperationTimeout: time.Second, LeaseSafety: 10 * time.Second,
		RetryBase: 2 * time.Second, RetryMaximum: time.Minute,
		Clock: func() time.Time { return fixture.now },
	}
}

func (fixture workerFixture) worker(t *testing.T, repository Repository) *Worker {
	t.Helper()
	worker, err := New(fixture.options(repository))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return worker
}

func (result Result) ProgressCount(code kernel.TicketBulkTargetResult) uint32 {
	if result.Progress == nil {
		return 0
	}
	progress, err := kernel.RestoreTicketBulkProgress(*result.Progress)
	if err != nil {
		return 0
	}
	return progress.Count(code)
}

type repositoryStub struct {
	claim      Claim
	claimFound *bool
	claimFn    func(context.Context, ClaimRequest) (Claim, bool, error)
	apply      func(context.Context, ApplyTargetRequest) (ApplyTargetResult, error)
	release    func(context.Context, ReleaseBatchRequest) (ReleaseBatchResult, error)
	failure    func(context.Context, BatchFailureRequest) (BatchFailureResult, error)
	cancel     func(context.Context, ControlFinalizationRequest) (ControlFinalizationResult, error)
	revoke     func(context.Context, ControlFinalizationRequest) (ControlFinalizationResult, error)
}

func (repository *repositoryStub) ClaimBatch(ctx context.Context, request ClaimRequest) (Claim, bool, error) {
	if repository.claimFn != nil {
		return repository.claimFn(ctx, request)
	}
	if repository.claimFound != nil {
		return repository.claim, *repository.claimFound, nil
	}
	return repository.claim, true, nil
}

func (repository *repositoryStub) ApplyTarget(ctx context.Context, request ApplyTargetRequest) (ApplyTargetResult, error) {
	if repository.apply == nil {
		return ApplyTargetResult{}, errors.New("unexpected ApplyTarget call")
	}
	return repository.apply(ctx, request)
}

func (repository *repositoryStub) ReleaseBatch(ctx context.Context, request ReleaseBatchRequest) (ReleaseBatchResult, error) {
	if repository.release == nil {
		return ReleaseBatchResult{}, errors.New("unexpected ReleaseBatch call")
	}
	return repository.release(ctx, request)
}

func (repository *repositoryStub) ReportBatchFailure(ctx context.Context, request BatchFailureRequest) (BatchFailureResult, error) {
	if repository.failure == nil {
		return BatchFailureResult{}, errors.New("unexpected ReportBatchFailure call")
	}
	return repository.failure(ctx, request)
}

func (repository *repositoryStub) FinalizeCancellation(ctx context.Context, request ControlFinalizationRequest) (ControlFinalizationResult, error) {
	if repository.cancel == nil {
		return ControlFinalizationResult{}, errors.New("unexpected FinalizeCancellation call")
	}
	return repository.cancel(ctx, request)
}

func (repository *repositoryStub) FinalizeAuthorizationRevocation(ctx context.Context, request ControlFinalizationRequest) (ControlFinalizationResult, error) {
	if repository.revoke == nil {
		return ControlFinalizationResult{}, errors.New("unexpected FinalizeAuthorizationRevocation call")
	}
	return repository.revoke(ctx, request)
}

func mustTargetPin(t *testing.T, suffix byte, version uint64) kernel.TicketBulkTargetPin {
	if t != nil {
		t.Helper()
	}
	pin, err := kernel.NewTicketBulkTargetPin(testEntityID(suffix), version)
	if err != nil {
		if t != nil {
			t.Fatalf("NewTicketBulkTargetPin() error = %v", err)
		}
		panic(err)
	}
	return pin
}

func testEntityID(suffix byte) kernel.EntityID {
	value := [16]byte{0x01, 0x9c, 0x7a, 0x10, 0x11, 0x22, 0x70, 0x01, 0x80, 0x00}
	value[15] = suffix
	id, err := kernel.NewEntityID(value)
	if err != nil {
		panic(err)
	}
	return id
}

func boolPointer(value bool) *bool { return &value }
