package ticketbulk

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
	"reflect"
	"slices"
	"sync"
	"time"

	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
)

type Worker struct {
	repository       Repository
	identity         Identity
	batchSize        int
	leaseDuration    time.Duration
	attemptTimeout   time.Duration
	operationTimeout time.Duration
	leaseSafety      time.Duration
	retryBase        time.Duration
	retryMaximum     time.Duration
	clock            func() time.Time
	sourceMu         sync.Mutex
}

func New(options Options) (*Worker, error) {
	if nilInterface(options.Repository) || !validIdentity(options.Identity) ||
		options.BatchSize < 1 || options.BatchSize > MaximumBatchSize ||
		options.LeaseDuration < MinimumLease || options.LeaseDuration > MaximumLease ||
		options.LeaseDuration%time.Microsecond != 0 ||
		options.AttemptTimeout < time.Second || options.AttemptTimeout > options.LeaseDuration ||
		options.AttemptTimeout%time.Microsecond != 0 ||
		options.OperationTimeout < minimumOperation || options.OperationTimeout > maximumOperation ||
		options.OperationTimeout > options.AttemptTimeout || options.OperationTimeout%time.Microsecond != 0 ||
		options.LeaseSafety < time.Second || options.LeaseSafety > maximumLeaseSafety ||
		options.LeaseSafety%time.Microsecond != 0 ||
		options.AttemptTimeout+options.LeaseSafety > options.LeaseDuration ||
		options.RetryBase < MinimumRetry || options.RetryBase > MaximumRetry ||
		options.RetryMaximum < options.RetryBase || options.RetryMaximum > MaximumRetry ||
		options.RetryBase%time.Microsecond != 0 || options.RetryMaximum%time.Microsecond != 0 ||
		options.Clock == nil {
		return nil, ErrInvalidConfiguration
	}
	return &Worker{
		repository: options.Repository, identity: options.Identity,
		batchSize: options.BatchSize, leaseDuration: options.LeaseDuration,
		attemptTimeout: options.AttemptTimeout, operationTimeout: options.OperationTimeout,
		leaseSafety: options.LeaseSafety, retryBase: options.RetryBase,
		retryMaximum: options.RetryMaximum, clock: options.Clock,
	}, nil
}

func (worker *Worker) RunOnce(ctx context.Context, queue Queue) (Result, error) {
	if worker == nil || ctx == nil || !validQueue(queue) {
		return Result{}, ErrInvalidInput
	}
	if ctx.Err() != nil {
		return Result{Outcome: OutcomeInterrupted}, ErrInterrupted
	}
	now := worker.now()
	if !validInstant(now) {
		return Result{}, ErrInvalidConfiguration
	}
	claimContext, cancelClaim := context.WithTimeout(ctx, worker.operationTimeout)
	claim, claimed, err := worker.repository.ClaimBatch(claimContext, ClaimRequest{
		Identity: worker.identity, Queue: queue, Now: now,
		LeaseDuration: worker.leaseDuration, Limit: worker.batchSize,
	})
	cancelClaim()
	if err != nil {
		if ctx.Err() != nil {
			return Result{Outcome: OutcomeInterrupted},
				errors.Join(ErrTransitionOutcomeUnknown, ErrInterrupted)
		}
		return Result{}, errors.Join(ErrTransitionOutcomeUnknown, ErrUnavailable)
	}
	if !claimed {
		if !emptyClaim(claim) {
			return Result{}, ErrInvalidProjection
		}
		return Result{Outcome: OutcomeIdle}, nil
	}
	claim, err = worker.normalizeClaim(claim, queue)
	if err != nil {
		return Result{Claimed: true}, err
	}
	progressFloor, err := kernel.RestoreTicketBulkProgress(claim.Progress)
	if err != nil {
		return Result{Claimed: true}, ErrInvalidProjection
	}

	attemptStartedAt := worker.now()
	if !validInstant(attemptStartedAt) {
		return Result{Claimed: true}, ErrTransitionOutcomeUnknown
	}
	attemptDeadline := claim.Binding.LeaseExpiresAt.Add(-worker.leaseSafety)
	maximumDeadline := attemptStartedAt.Add(worker.attemptTimeout)
	if maximumDeadline.Before(attemptDeadline) {
		attemptDeadline = maximumDeadline
	}
	if !attemptDeadline.After(attemptStartedAt) {
		return worker.reportFailure(
			ctx, claim, progressFloor, BatchFailureLeaseSafety, 0, ErrInterrupted,
		)
	}
	attemptContext, cancelAttempt := context.WithTimeout(ctx, attemptDeadline.Sub(attemptStartedAt))
	defer cancelAttempt()
	receipt := sha256.New()
	processed := uint32(0)
	mutation := claim.Definition.Mutation()
	tenant := claim.Definition.Tenant()
	for _, target := range claim.Targets {
		if ctx.Err() != nil {
			return worker.reportFailure(
				ctx, claim, progressFloor, BatchFailureInterrupted, processed, ErrInterrupted,
			)
		}
		if attemptContext.Err() != nil || !worker.leaseHasSafety(claim.Binding) {
			return worker.reportFailure(
				ctx, claim, progressFloor, BatchFailureLeaseSafety, processed, ErrInterrupted,
			)
		}
		command, commandErr := mutation.CommandFor(tenant, target.Pin)
		if commandErr != nil {
			return worker.reportFailure(
				ctx, claim, progressFloor, BatchFailureInvalidProjection, processed, ErrInvalidProjection,
			)
		}
		applyContext, cancelApply := context.WithTimeout(attemptContext, worker.operationTimeout)
		applied, applyErr := worker.repository.ApplyTarget(applyContext, ApplyTargetRequest{
			Identity: worker.identity, Binding: claim.Binding, Sequence: target.Sequence,
			Pin: target.Pin, Command: command,
		})
		applyContextErr := applyContext.Err()
		cancelApply()
		if applyErr != nil || applyContextErr != nil {
			if ctx.Err() != nil {
				return worker.reportFailure(
					ctx, claim, progressFloor, BatchFailureInterrupted, processed, ErrInterrupted,
				)
			}
			if attemptContext.Err() != nil {
				return worker.reportFailure(
					ctx, claim, progressFloor, BatchFailureLeaseSafety, processed, ErrInterrupted,
				)
			}
			return worker.reportFailure(
				ctx, claim, progressFloor, BatchFailureTransientDatabase, processed, ErrUnavailable,
			)
		}
		switch applied.Disposition {
		case ApplyTargetApplied, ApplyTargetReplayed:
			if applied.Sequence != target.Sequence ||
				!kernel.WorkerTicketBulkTargetResult(applied.Result) ||
				applied.ControlRevision != 0 {
				return worker.reportFailure(
					ctx, claim, progressFloor, BatchFailureInvalidProjection, processed, ErrInvalidProjection,
				)
			}
			nextProgressFloor, progressErr := progressFloor.WithResult(applied.Result)
			if progressErr != nil {
				return worker.reportFailure(
					ctx, claim, progressFloor, BatchFailureInvalidProjection, processed, ErrInvalidProjection,
				)
			}
			progressFloor = nextProgressFloor
			writeTicketBulkReceipt(receipt, target, applied.Result)
			processed++
		case ApplyTargetCancellationRequested:
			if !validTargetControl(applied, claim.Binding) {
				return worker.reportFailure(
					ctx, claim, progressFloor, BatchFailureInvalidProjection, processed, ErrInvalidProjection,
				)
			}
			return worker.finalizeControl(ctx, claim, progressFloor, applied.ControlRevision, processed, true)
		case ApplyTargetAuthorizationRevoked:
			if !validTargetControl(applied, claim.Binding) {
				return worker.reportFailure(
					ctx, claim, progressFloor, BatchFailureInvalidProjection, processed, ErrInvalidProjection,
				)
			}
			return worker.finalizeControl(ctx, claim, progressFloor, applied.ControlRevision, processed, false)
		case ApplyTargetFenceLost:
			if applied.Sequence != 0 || applied.Result != 0 || applied.ControlRevision != 0 {
				return Result{Claimed: true, Processed: processed}, ErrTransitionOutcomeUnknown
			}
			return Result{Claimed: true, Outcome: OutcomeFenceLost, Processed: processed}, ErrFenceLost
		default:
			return worker.reportFailure(
				ctx, claim, progressFloor, BatchFailureInvalidProjection, processed, ErrInvalidProjection,
			)
		}
	}

	if processed != uint32(len(claim.Targets)) || !worker.leaseHasSafety(claim.Binding) {
		return worker.reportFailure(
			ctx, claim, progressFloor, BatchFailureLeaseSafety, processed, ErrInterrupted,
		)
	}
	releasedAt := worker.now()
	if !validInstant(releasedAt) {
		return Result{Claimed: true, Processed: processed}, ErrTransitionOutcomeUnknown
	}
	var receiptDigest [sha256.Size]byte
	copy(receiptDigest[:], receipt.Sum(nil))
	releaseContext, cancelRelease, ok := worker.fencedTransitionContext(ctx, claim.Binding, releasedAt)
	if !ok {
		return Result{Claimed: true, Processed: processed}, ErrTransitionOutcomeUnknown
	}
	released, releaseErr := worker.repository.ReleaseBatch(releaseContext, ReleaseBatchRequest{
		Identity: worker.identity, Binding: claim.Binding, Processed: processed,
		ReceiptDigest: receiptDigest, ReleasedAt: releasedAt,
	})
	cancelRelease()
	if releaseErr != nil {
		return Result{Claimed: true, Processed: processed}, ErrTransitionOutcomeUnknown
	}
	return worker.handleRelease(ctx, claim, progressFloor, processed, released)
}

func (worker *Worker) normalizeClaim(claim Claim, queue Queue) (Claim, error) {
	selection := claim.Definition.Selection()
	if kernel.ValidateTicketBulkDefinition(claim.Definition) != nil ||
		!validBatchBinding(claim.Binding) || !validInstant(claim.ObservedAt) ||
		claim.Binding.TenantID != claim.Definition.Tenant() ||
		claim.Binding.JobID != claim.Definition.ID() || claim.Binding.Kind != claim.Definition.Kind() ||
		claim.Binding.WorkerID != worker.identity.WorkerID ||
		claim.Binding.TenantID != queue.TenantID || claim.Binding.Kind != queue.Kind ||
		claim.Binding.TargetSetDigest != selection.TargetSetDigest() ||
		claim.Binding.ProjectionVersion != claim.Definition.ProjectionVersion() ||
		claim.Binding.Attempt > claim.Definition.MaximumAttempts() ||
		!claim.ObservedAt.Equal(claim.Binding.ClaimedAt) ||
		claim.Binding.LeaseExpiresAt.Sub(claim.Binding.ClaimedAt) < MinimumLease ||
		claim.Binding.LeaseExpiresAt.Sub(claim.Binding.ClaimedAt) > worker.leaseDuration ||
		claim.Binding.JobExpiresAt.Before(claim.Binding.LeaseExpiresAt) ||
		claim.ObservedAt.After(worker.now().Add(maximumClockSkew)) ||
		!worker.leaseHasSafety(claim.Binding) ||
		len(claim.Targets) == 0 || len(claim.Targets) > worker.batchSize {
		return Claim{}, ErrInvalidProjection
	}
	progress, err := kernel.RestoreTicketBulkProgress(claim.Progress)
	if err != nil || progress.Total() != selection.TargetCount() ||
		progress.Complete() || progress.Count(kernel.TicketBulkTargetCancelled) != 0 ||
		progress.Count(kernel.TicketBulkTargetAuthorizationRevoked) != 0 ||
		uint32(len(claim.Targets)) > progress.Remaining() {
		return Claim{}, ErrInvalidProjection
	}
	explicit := selection.ExplicitTargets()
	seen := make(map[kernel.EntityID]struct{}, len(claim.Targets))
	previousSequence := uint32(0)
	for _, target := range claim.Targets {
		rebuilt, pinErr := kernel.NewTicketBulkTargetPin(target.Pin.ID(), target.Pin.Version())
		if pinErr != nil || rebuilt != target.Pin || target.Sequence == 0 ||
			target.Sequence > selection.TargetCount() || target.Sequence <= previousSequence {
			return Claim{}, ErrInvalidProjection
		}
		if _, duplicate := seen[target.Pin.ID()]; duplicate {
			return Claim{}, ErrInvalidProjection
		}
		seen[target.Pin.ID()] = struct{}{}
		if selection.Source() == kernel.TicketBulkSelectionExplicit &&
			(int(target.Sequence) > len(explicit) || explicit[target.Sequence-1] != target.Pin) {
			return Claim{}, ErrInvalidProjection
		}
		previousSequence = target.Sequence
	}
	claim.Targets = slices.Clone(claim.Targets)
	return claim, nil
}

func validBatchBinding(binding BatchBinding) bool {
	return validEntityID(binding.TenantID) && validEntityID(binding.JobID) &&
		validEntityID(binding.BatchID) && validEntityID(binding.WorkerID) &&
		(binding.Kind == kernel.AggregateAlert || binding.Kind == kernel.AggregateCase) &&
		binding.Revision > 0 && binding.Revision < math.MaxInt32 && binding.Attempt > 0 &&
		binding.Fence != ([32]byte{}) && binding.TargetSetDigest != ([32]byte{}) &&
		binding.ProjectionVersion == kernel.TicketBulkProjectionVersion &&
		validInstant(binding.ClaimedAt) && validInstant(binding.LeaseExpiresAt) &&
		validInstant(binding.JobExpiresAt) && binding.LeaseExpiresAt.After(binding.ClaimedAt) &&
		binding.JobExpiresAt.After(binding.ClaimedAt)
}

func validTargetControl(result ApplyTargetResult, binding BatchBinding) bool {
	return result.Sequence == 0 && result.Result == 0 &&
		validControlRevision(result.ControlRevision, binding)
}

func validControlRevision(revision uint64, binding BatchBinding) bool {
	return revision > binding.Revision && revision <= math.MaxInt32
}

func (worker *Worker) handleRelease(
	ctx context.Context,
	claim Claim,
	progressFloor kernel.TicketBulkProgress,
	processed uint32,
	released ReleaseBatchResult,
) (Result, error) {
	switch released.Disposition {
	case ReleaseBatchReleased, ReleaseJobCompleted, ReleaseJobFailed:
		progress, ok := validatedProgress(released.Progress, claim.Progress.Total)
		if !ok || !progressIncludes(progress, progressFloor) || released.ControlRevision != 0 ||
			released.Disposition == ReleaseBatchReleased && progress.Complete() ||
			released.Disposition == ReleaseBatchReleased && !controlRemainderFree(progress) ||
			released.Disposition != ReleaseBatchReleased && !progress.Complete() ||
			released.Disposition == ReleaseJobCompleted && !ordinaryCompletion(progress) ||
			released.Disposition == ReleaseJobFailed && !failedCompletion(progress) {
			return Result{Claimed: true, Processed: processed}, ErrTransitionOutcomeUnknown
		}
		outcome := OutcomeBatchReleased
		if released.Disposition == ReleaseJobCompleted {
			outcome = OutcomeJobCompleted
		} else if released.Disposition == ReleaseJobFailed {
			outcome = OutcomeJobFailed
		}
		snapshot := progress.Snapshot()
		return Result{
			Claimed: true, Outcome: outcome, Processed: processed, Progress: &snapshot,
		}, nil
	case ReleaseCancellationRequested:
		if released.Progress != nil || !validControlRevision(released.ControlRevision, claim.Binding) {
			return Result{Claimed: true, Processed: processed}, ErrTransitionOutcomeUnknown
		}
		return worker.finalizeControl(ctx, claim, progressFloor, released.ControlRevision, processed, true)
	case ReleaseAuthorizationRevoked:
		if released.Progress != nil || !validControlRevision(released.ControlRevision, claim.Binding) {
			return Result{Claimed: true, Processed: processed}, ErrTransitionOutcomeUnknown
		}
		return worker.finalizeControl(ctx, claim, progressFloor, released.ControlRevision, processed, false)
	case ReleaseFenceLost:
		if released.Progress != nil || released.ControlRevision != 0 {
			return Result{Claimed: true, Processed: processed}, ErrTransitionOutcomeUnknown
		}
		return Result{Claimed: true, Outcome: OutcomeFenceLost, Processed: processed}, ErrFenceLost
	default:
		return Result{Claimed: true, Processed: processed}, ErrTransitionOutcomeUnknown
	}
}

func (worker *Worker) reportFailure(
	ctx context.Context,
	claim Claim,
	progressFloor kernel.TicketBulkProgress,
	code BatchFailureCode,
	processed uint32,
	priorErr error,
) (Result, error) {
	if !validBatchFailureCode(code) || processed > uint32(len(claim.Targets)) {
		return Result{Claimed: true, Processed: processed}, errors.Join(ErrTransitionOutcomeUnknown, priorErr)
	}
	failedAt := worker.now()
	if !validInstant(failedAt) {
		return Result{Claimed: true, Processed: processed}, errors.Join(ErrTransitionOutcomeUnknown, priorErr)
	}
	var retryAt *time.Time
	if retryableBatchFailureCode(code) && claim.Binding.Attempt < claim.Definition.MaximumAttempts() {
		value := failedAt.Add(worker.retryDelay(claim.Binding.Attempt, claim.Binding.Fence))
		if value.Before(claim.Binding.JobExpiresAt) {
			retryAt = &value
		}
	}
	failureContext, cancelFailure, ok := worker.fencedTransitionContext(ctx, claim.Binding, failedAt)
	if !ok {
		return Result{Claimed: true, Processed: processed, Failure: code},
			errors.Join(ErrTransitionOutcomeUnknown, priorErr)
	}
	failure, err := worker.repository.ReportBatchFailure(failureContext, BatchFailureRequest{
		Identity: worker.identity, Binding: claim.Binding, Code: code,
		FailedAt: failedAt, RetryAt: cloneInstant(retryAt),
	})
	cancelFailure()
	if err != nil {
		return Result{Claimed: true, Processed: processed, Failure: code},
			errors.Join(ErrTransitionOutcomeUnknown, priorErr)
	}
	result, transitionErr := worker.handleFailure(
		ctx, claim, progressFloor, processed, code, retryAt, failure,
	)
	return result, errors.Join(transitionErr, priorErr)
}

func (worker *Worker) handleFailure(
	ctx context.Context,
	claim Claim,
	progressFloor kernel.TicketBulkProgress,
	processed uint32,
	code BatchFailureCode,
	retryAt *time.Time,
	failure BatchFailureResult,
) (Result, error) {
	result := Result{Claimed: true, Processed: processed, Failure: code}
	switch failure.Disposition {
	case FailureRetryScheduled, FailureReplayRetry:
		if retryAt == nil || failure.RetryAt == nil || !validInstant(*failure.RetryAt) ||
			!failure.RetryAt.Equal(*retryAt) || failure.Progress != nil || failure.ControlRevision != 0 {
			return result, ErrTransitionOutcomeUnknown
		}
		result.Outcome = OutcomeRetryScheduled
		return result, nil
	case FailureBatchReleased, FailureReplayBatchReleased,
		FailureJobCompleted, FailureReplayJobCompleted:
		progress, ok := validatedProgress(failure.Progress, claim.Progress.Total)
		completed := failure.Disposition == FailureJobCompleted ||
			failure.Disposition == FailureReplayJobCompleted
		if !ok || !progressIncludes(progress, progressFloor) ||
			!batchFullyAccounted(progress, claim) || progress.Complete() != completed ||
			!controlRemainderFree(progress) ||
			completed && !ordinaryCompletion(progress) ||
			failure.ControlRevision != 0 || failure.RetryAt != nil {
			return result, ErrTransitionOutcomeUnknown
		}
		result.Failure = BatchFailureNone
		result.Outcome = OutcomeBatchReleased
		if completed {
			result.Outcome = OutcomeJobCompleted
		}
		snapshot := progress.Snapshot()
		result.Progress = &snapshot
		return result, nil
	case FailureBatchTerminalized, FailureReplayBatchTerminalized:
		progress, ok := validatedProgress(failure.Progress, claim.Progress.Total)
		if !ok || !progressIncludes(progress, progressFloor) || !batchFullyAccounted(progress, claim) ||
			progress.Complete() || !controlRemainderFree(progress) ||
			progress.Count(kernel.TicketBulkTargetInternalFailure) <=
				progressFloor.Count(kernel.TicketBulkTargetInternalFailure) ||
			failure.ControlRevision != 0 || failure.RetryAt != nil || retryAt != nil {
			return result, ErrTransitionOutcomeUnknown
		}
		snapshot := progress.Snapshot()
		result.Outcome, result.Progress = OutcomeBatchTerminalized, &snapshot
		return result, nil
	case FailureJobFailed, FailureReplayJobFailed:
		progress, ok := validatedProgress(failure.Progress, claim.Progress.Total)
		if !ok || !progressIncludes(progress, progressFloor) || !batchFullyAccounted(progress, claim) ||
			!progress.Complete() || !failedCompletion(progress) ||
			failure.ControlRevision != 0 || failure.RetryAt != nil {
			return result, ErrTransitionOutcomeUnknown
		}
		snapshot := progress.Snapshot()
		result.Outcome, result.Progress = OutcomeJobFailed, &snapshot
		return result, nil
	case FailureCancellationRequested:
		if failure.Progress != nil || failure.RetryAt != nil ||
			!validControlRevision(failure.ControlRevision, claim.Binding) {
			return result, ErrTransitionOutcomeUnknown
		}
		return worker.finalizeControl(
			ctx, claim, progressFloor, failure.ControlRevision, processed, true,
		)
	case FailureAuthorizationRevoked:
		if failure.Progress != nil || failure.RetryAt != nil ||
			!validControlRevision(failure.ControlRevision, claim.Binding) {
			return result, ErrTransitionOutcomeUnknown
		}
		return worker.finalizeControl(
			ctx, claim, progressFloor, failure.ControlRevision, processed, false,
		)
	case FailureFenceLost:
		if failure.Progress != nil || failure.ControlRevision != 0 || failure.RetryAt != nil {
			return result, ErrTransitionOutcomeUnknown
		}
		result.Outcome = OutcomeFenceLost
		return result, ErrFenceLost
	default:
		return result, ErrTransitionOutcomeUnknown
	}
}

func (worker *Worker) finalizeControl(
	ctx context.Context,
	claim Claim,
	progressFloor kernel.TicketBulkProgress,
	revision uint64,
	processed uint32,
	cancellation bool,
) (Result, error) {
	if !validControlRevision(revision, claim.Binding) {
		return Result{Claimed: true, Processed: processed}, ErrTransitionOutcomeUnknown
	}
	now := worker.now()
	if !validInstant(now) {
		return Result{Claimed: true, Processed: processed}, ErrTransitionOutcomeUnknown
	}
	request := ControlFinalizationRequest{
		Identity: worker.identity, Binding: claim.Binding,
		ExpectedRevision: revision, FinalizedAt: now,
	}
	finalizeContext, cancelFinalize, ok := worker.fencedTransitionContext(ctx, claim.Binding, now)
	if !ok {
		return Result{Claimed: true, Processed: processed}, ErrTransitionOutcomeUnknown
	}
	var finalized ControlFinalizationResult
	var err error
	if cancellation {
		finalized, err = worker.repository.FinalizeCancellation(finalizeContext, request)
	} else {
		finalized, err = worker.repository.FinalizeAuthorizationRevocation(finalizeContext, request)
	}
	cancelFinalize()
	if err != nil {
		return Result{Claimed: true, Processed: processed}, ErrTransitionOutcomeUnknown
	}
	if finalized.Disposition == ControlFinalizationFenceLost {
		if finalized.Progress != nil || finalized.ControlRevision != 0 {
			return Result{Claimed: true, Processed: processed}, ErrTransitionOutcomeUnknown
		}
		return Result{Claimed: true, Outcome: OutcomeFenceLost, Processed: processed}, ErrFenceLost
	}
	if finalized.Disposition != ControlFinalizationApplied &&
		finalized.Disposition != ControlFinalizationReplayed {
		return Result{Claimed: true, Processed: processed}, ErrTransitionOutcomeUnknown
	}
	progress, ok := validatedProgress(
		finalized.Progress, claim.Progress.Total,
	)
	if !ok || !progress.Complete() || !progressIncludes(progress, progressFloor) ||
		finalized.ControlRevision != revision {
		return Result{Claimed: true, Processed: processed}, ErrTransitionOutcomeUnknown
	}
	outcome := OutcomeAuthorizationRevoked
	remainder := kernel.TicketBulkTargetAuthorizationRevoked
	if cancellation {
		outcome = OutcomeCancelled
		remainder = kernel.TicketBulkTargetCancelled
	}
	if progress.Count(remainder) <= progressFloor.Count(remainder) {
		return Result{Claimed: true, Processed: processed}, ErrTransitionOutcomeUnknown
	}
	oppositeRemainder := kernel.TicketBulkTargetCancelled
	if cancellation {
		oppositeRemainder = kernel.TicketBulkTargetAuthorizationRevoked
	}
	if progress.Count(oppositeRemainder) != progressFloor.Count(oppositeRemainder) {
		return Result{Claimed: true, Processed: processed}, ErrTransitionOutcomeUnknown
	}
	snapshot := progress.Snapshot()
	return Result{
		Claimed: true, Outcome: outcome, Processed: processed, Progress: &snapshot,
	}, nil
}

func validatedProgress(
	snapshot *kernel.TicketBulkProgressSnapshot,
	total uint32,
) (kernel.TicketBulkProgress, bool) {
	if snapshot == nil {
		return kernel.TicketBulkProgress{}, false
	}
	progress, err := kernel.RestoreTicketBulkProgress(*snapshot)
	return progress, err == nil && progress.Total() == total
}

func progressIncludes(actual, floor kernel.TicketBulkProgress) bool {
	if actual.Total() != floor.Total() {
		return false
	}
	actualSnapshot := actual.Snapshot()
	floorSnapshot := floor.Snapshot()
	return actualSnapshot.Succeeded >= floorSnapshot.Succeeded &&
		actualSnapshot.NoChange >= floorSnapshot.NoChange &&
		actualSnapshot.VersionConflict >= floorSnapshot.VersionConflict &&
		actualSnapshot.NotFoundOrHidden >= floorSnapshot.NotFoundOrHidden &&
		actualSnapshot.AuthorizationDenied >= floorSnapshot.AuthorizationDenied &&
		actualSnapshot.Rejected >= floorSnapshot.Rejected &&
		actualSnapshot.Cancelled >= floorSnapshot.Cancelled &&
		actualSnapshot.AuthorizationRevoked >= floorSnapshot.AuthorizationRevoked &&
		actualSnapshot.InternalFailure >= floorSnapshot.InternalFailure
}

func ordinaryCompletion(progress kernel.TicketBulkProgress) bool {
	return progress.Complete() && controlRemainderFree(progress) &&
		progress.Count(kernel.TicketBulkTargetInternalFailure) == 0
}

func failedCompletion(progress kernel.TicketBulkProgress) bool {
	return progress.Complete() && controlRemainderFree(progress) &&
		progress.Count(kernel.TicketBulkTargetInternalFailure) > 0
}

func controlRemainderFree(progress kernel.TicketBulkProgress) bool {
	return progress.Count(kernel.TicketBulkTargetCancelled) == 0 &&
		progress.Count(kernel.TicketBulkTargetAuthorizationRevoked) == 0
}

func batchFullyAccounted(progress kernel.TicketBulkProgress, claim Claim) bool {
	baseline, err := kernel.RestoreTicketBulkProgress(claim.Progress)
	if err != nil || uint32(len(claim.Targets)) > baseline.Remaining() {
		return false
	}
	return progress.Processed() >= baseline.Processed()+uint32(len(claim.Targets))
}

func cloneInstant(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func (worker *Worker) leaseHasSafety(binding BatchBinding) bool {
	now := worker.now()
	return validInstant(now) && binding.LeaseExpiresAt.After(now.Add(worker.leaseSafety))
}

func (worker *Worker) fencedTransitionContext(
	ctx context.Context,
	binding BatchBinding,
	startedAt time.Time,
) (context.Context, context.CancelFunc, bool) {
	if !validInstant(startedAt) || !startedAt.Before(binding.LeaseExpiresAt) {
		return nil, nil, false
	}
	deadline := startedAt.Add(worker.operationTimeout)
	if binding.LeaseExpiresAt.Before(deadline) {
		deadline = binding.LeaseExpiresAt
	}
	if !deadline.After(startedAt) {
		return nil, nil, false
	}
	base := context.Background()
	if ctx != nil {
		base = context.WithoutCancel(ctx)
	}
	transitionContext, cancel := context.WithTimeout(base, deadline.Sub(startedAt))
	return transitionContext, cancel, true
}

func (worker *Worker) retryDelay(attempt uint8, fence [sha256.Size]byte) time.Duration {
	ceiling := worker.retryBase
	for current := uint8(1); current < attempt && ceiling < worker.retryMaximum; current++ {
		if ceiling > worker.retryMaximum/2 {
			ceiling = worker.retryMaximum
			break
		}
		ceiling *= 2
	}
	if ceiling > worker.retryMaximum {
		ceiling = worker.retryMaximum
	}
	if ceiling <= MinimumRetry {
		return MinimumRetry
	}
	spanMicros := uint64((ceiling - MinimumRetry) / time.Microsecond)
	seed := [sha256.Size + 1]byte{}
	copy(seed[:sha256.Size], fence[:])
	seed[sha256.Size] = attempt
	digest := sha256.Sum256(seed[:])
	offsetMicros := binary.BigEndian.Uint64(digest[:8]) % (spanMicros + 1)
	return MinimumRetry + time.Duration(offsetMicros)*time.Microsecond
}

func writeTicketBulkReceipt(
	digest interface{ Write([]byte) (int, error) },
	target ClaimedTarget,
	result kernel.TicketBulkTargetResult,
) {
	var encoded [8]byte
	binary.BigEndian.PutUint32(encoded[:4], target.Sequence)
	_, _ = digest.Write(encoded[:4])
	id := target.Pin.ID().Bytes()
	_, _ = digest.Write(id[:])
	binary.BigEndian.PutUint64(encoded[:], target.Pin.Version())
	_, _ = digest.Write(encoded[:])
	_, _ = digest.Write([]byte{byte(result)})
}

func emptyClaim(claim Claim) bool {
	return reflect.DeepEqual(claim, Claim{})
}

func (worker *Worker) now() time.Time {
	worker.sourceMu.Lock()
	now := worker.clock().UTC().Truncate(time.Microsecond)
	worker.sourceMu.Unlock()
	return now
}

func (worker *Worker) String() string {
	return "ticketbulk.Worker{dependencies:[REDACTED],identity:[REDACTED],configuration:[REDACTED]}"
}

func (worker *Worker) GoString() string { return worker.String() }
