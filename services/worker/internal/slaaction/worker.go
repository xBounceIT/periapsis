package slaaction

import (
	"context"
	"errors"
	"math"
	"sync"
	"time"
)

type Worker struct {
	repository       Repository
	identity         Identity
	batchSize        int
	leaseDuration    time.Duration
	operationTimeout time.Duration
	leaseSafety      time.Duration
	clock            func() time.Time
	clockMu          sync.Mutex
}

func New(options Options) (*Worker, error) {
	if nilInterface(options.Repository) || !validIdentity(options.Identity) ||
		options.BatchSize < 1 || options.BatchSize > MaximumBatchSize ||
		options.LeaseDuration < MinimumLease || options.LeaseDuration > MaximumLease ||
		options.LeaseDuration%time.Microsecond != 0 ||
		options.OperationTimeout < MinimumOperation || options.OperationTimeout > MaximumOperation ||
		options.OperationTimeout%time.Microsecond != 0 ||
		options.LeaseSafety < MinimumLeaseSafety || options.LeaseSafety > MaximumLeaseSafety ||
		options.LeaseSafety%time.Microsecond != 0 ||
		options.OperationTimeout+options.LeaseSafety > options.LeaseDuration || options.Clock == nil {
		return nil, ErrInvalidConfiguration
	}
	return &Worker{
		repository: options.Repository, identity: options.Identity, batchSize: options.BatchSize,
		leaseDuration: options.LeaseDuration, operationTimeout: options.OperationTimeout,
		leaseSafety: options.LeaseSafety, clock: options.Clock,
	}, nil
}

func (worker *Worker) RunOnce(ctx context.Context, queue Queue) (Summary, error) {
	if worker == nil || ctx == nil || !validQueue(queue) {
		return Summary{}, ErrInvalidInput
	}
	if ctx.Err() != nil {
		return Summary{}, ErrInterrupted
	}
	now := worker.now()
	if !validInstant(now) {
		return Summary{}, ErrInvalidConfiguration
	}
	claimContext, cancelClaim := context.WithTimeout(ctx, worker.operationTimeout)
	claims, err := worker.repository.Claim(claimContext, ClaimRequest{
		Identity: worker.identity, Queue: queue, Now: now,
		LeaseDuration: worker.leaseDuration, Limit: worker.batchSize,
	})
	cancelClaim()
	if err != nil {
		if ctx.Err() != nil {
			return Summary{}, errors.Join(ErrTransitionOutcomeUnknown, ErrInterrupted)
		}
		return Summary{}, errors.Join(ErrTransitionOutcomeUnknown, ErrUnavailable)
	}
	if len(claims) == 0 {
		return Summary{}, nil
	}
	if len(claims) > worker.batchSize || !validClaims(claims, queue, now, worker.leaseDuration) {
		return Summary{Claimed: len(claims)}, ErrInvalidProjection
	}
	summary := Summary{Claimed: len(claims)}
	for _, claim := range claims {
		if ctx.Err() != nil {
			return summary, ErrInterrupted
		}
		appliedAt := worker.now()
		if !validInstant(appliedAt) || appliedAt.Before(claim.ClaimedAt) {
			return summary, ErrInvalidConfiguration
		}
		deadline := claim.LeaseExpiresAt.Add(-worker.leaseSafety)
		operationDeadline := appliedAt.Add(worker.operationTimeout)
		if operationDeadline.Before(deadline) {
			deadline = operationDeadline
		}
		if !deadline.After(appliedAt) {
			return summary, ErrInterrupted
		}
		executeContext, cancelExecute := context.WithDeadline(ctx, deadline)
		result, executeErr := worker.repository.Execute(executeContext, ExecuteRequest{
			Identity: worker.identity, Claim: claim, AppliedAt: appliedAt,
		})
		cancelExecute()
		if executeErr != nil {
			// The transaction may have committed before the response was lost.
			// Leaving the fenced claim for replay is the only non-contradictory
			// recovery path.
			if ctx.Err() != nil {
				return summary, errors.Join(ErrTransitionOutcomeUnknown, ErrInterrupted)
			}
			return summary, errors.Join(ErrTransitionOutcomeUnknown, ErrUnavailable)
		}
		if !accumulate(&summary, result.Outcome) {
			return summary, ErrInvalidProjection
		}
	}
	return summary, nil
}

func validClaims(claims []Claim, queue Queue, claimedAt time.Time, leaseDuration time.Duration) bool {
	seen := make(map[uuidKey]struct{}, len(claims))
	for _, claim := range claims {
		key := uuidKey(claim.OccurrenceID)
		if _, duplicate := seen[key]; duplicate || !validClaim(claim, queue, claimedAt, leaseDuration) {
			return false
		}
		seen[key] = struct{}{}
	}
	return true
}

type uuidKey [16]byte

func validClaim(claim Claim, queue Queue, claimedAt time.Time, leaseDuration time.Duration) bool {
	return validUUIDv7(claim.OccurrenceID) && validUUIDv7(claim.TenantID) && claim.TenantID == queue.TenantID &&
		validUUIDv7(claim.SLAInstanceID) && validUUIDv7(claim.MetricInstanceID) &&
		validUUIDv7(claim.TriggerDefinitionID) && validActionKind(claim.ActionKind) &&
		claim.DeduplicationDigest != ([32]byte{}) && claim.Fence > 0 && claim.Fence < uint64(math.MaxInt64) &&
		claim.Attempt > 0 && validInstant(claim.ScheduledAt) && !claim.ScheduledAt.After(claimedAt) &&
		validInstant(claim.ClaimedAt) && claim.ClaimedAt.Equal(claimedAt) &&
		validInstant(claim.LeaseExpiresAt) && claim.LeaseExpiresAt.Equal(claimedAt.Add(leaseDuration))
}

func accumulate(summary *Summary, outcome Outcome) bool {
	switch outcome {
	case OutcomeApplied:
		summary.Applied++
	case OutcomeReplayed:
		summary.Replayed++
	case OutcomeRetryScheduled:
		summary.RetryScheduled++
	case OutcomeDeadLettered:
		summary.DeadLettered++
	case OutcomeFenceLost:
		summary.FenceLost++
	default:
		return false
	}
	return true
}

func (worker *Worker) now() time.Time {
	worker.clockMu.Lock()
	now := worker.clock().UTC().Truncate(time.Microsecond)
	worker.clockMu.Unlock()
	return now
}

func (worker *Worker) String() string {
	return "slaaction.Worker{dependencies:[REDACTED],identity:[REDACTED],configuration:[REDACTED]}"
}

func (worker *Worker) GoString() string { return worker.String() }
