package slaengine

import (
	"context"
	"errors"
	"math"
	"slices"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/sla"
)

type Worker struct {
	repository Repository
	identity   Identity
	config     Config
	clock      func() time.Time
}

func New(repository Repository, identity Identity, config Config, clock func() time.Time) (*Worker, error) {
	if repository == nil || clock == nil || !validIdentity(identity) || !validConfig(config) {
		return nil, ErrInvalidConfig
	}
	now := clock().UTC().Truncate(time.Microsecond)
	if !validInstant(now) {
		return nil, ErrInvalidConfig
	}
	return &Worker{repository: repository, identity: identity, config: config, clock: clock}, nil
}

func (worker *Worker) RunOnce(ctx context.Context) (RunSummary, error) {
	now := worker.now()
	if !validInstant(now) || !usableDeadline(ctx, now, worker.config.RunTimeout) {
		return RunSummary{}, ErrInvalidInput
	}
	claimContext, cancelClaim := context.WithTimeout(ctx, worker.config.OperationTimeout)
	jobs, err := worker.repository.Claim(claimContext, ClaimRequest{
		Identity: worker.identity, Now: now, BatchSize: worker.config.BatchSize,
		LeaseDuration: worker.config.LeaseDuration,
	})
	cancelClaim()
	if err != nil {
		return RunSummary{}, ErrUnavailable
	}
	if len(jobs) > worker.config.BatchSize || !uniqueClaims(jobs) {
		return RunSummary{}, ErrUnavailable
	}
	summary := RunSummary{Claimed: len(jobs)}
	for _, job := range jobs {
		if ctx.Err() != nil {
			return summary, ErrUnavailable
		}
		outcome, runErr := worker.processJob(ctx, now, job)
		switch outcome {
		case outcomeCompleted:
			summary.Completed++
		case outcomeRetryable:
			summary.Retryable++
		case outcomeDeadLettered:
			summary.DeadLettered++
		}
		if runErr != nil {
			return summary, runErr
		}
	}
	return summary, nil
}

type jobOutcome uint8

const (
	outcomeNone jobOutcome = iota
	outcomeCompleted
	outcomeRetryable
	outcomeDeadLettered
)

func (worker *Worker) processJob(ctx context.Context, claimedAt time.Time, job Job) (jobOutcome, error) {
	if !validClaimIdentity(job) {
		return outcomeNone, ErrUnavailable
	}
	if !validJobProjection(job, claimedAt, worker.config.MaximumAttempts, worker.config.LeaseDuration) {
		return worker.recordFailure(ctx, job, claimedAt, "invalid_projection", true)
	}
	evaluationContext, cancelEvaluation := context.WithTimeout(ctx, worker.config.OperationTimeout)
	plan, err := kernel.PlanEngineContext(evaluationContext, kernel.EngineInput{
		ObservedAt: job.ObservedAt, Metrics: slices.Clone(job.Metrics),
	})
	evaluationErr := evaluationContext.Err()
	cancelEvaluation()
	if err != nil {
		if errors.Is(err, kernel.ErrEngineCanceled) || errors.Is(err, context.Canceled) ||
			errors.Is(err, context.DeadlineExceeded) {
			return worker.recordFailure(ctx, job, claimedAt, "evaluation_timeout", job.Attempt >= worker.config.MaximumAttempts)
		}
		return worker.recordFailure(ctx, job, claimedAt, "invalid_projection", true)
	}
	if plan.EventID() != nil || !validPlan(job, plan) {
		return worker.recordFailure(ctx, job, claimedAt, "invalid_projection", true)
	}
	if evaluationErr != nil {
		return worker.recordFailure(ctx, job, claimedAt, "evaluation_timeout", job.Attempt >= worker.config.MaximumAttempts)
	}
	completedAt := worker.now()
	if !validWorkerTimestamp(completedAt, claimedAt, worker.config.LeaseDuration) {
		return outcomeNone, ErrUnavailable
	}
	finalizeContext, cancelFinalize := context.WithTimeout(ctx, worker.config.OperationTimeout)
	defer cancelFinalize()
	if err := worker.repository.Finalize(finalizeContext, FinalizeRequest{
		Identity: worker.identity, JobID: job.ID, TenantID: job.TenantID,
		SLAInstanceID: job.SLAInstanceID, ExpectedAggregateVersion: job.AggregateVersion,
		Fence: job.Fence, Plan: plan, CompletedAt: completedAt,
	}); err != nil {
		// The commit may have succeeded and the response may have been lost. Do
		// not write a contradictory failure; the fence/idempotency ledger makes
		// a later reclaim safe.
		return outcomeNone, ErrUnavailable
	}
	return outcomeCompleted, nil
}

func (worker *Worker) recordFailure(
	ctx context.Context,
	job Job,
	claimedAt time.Time,
	code string,
	permanent bool,
) (jobOutcome, error) {
	if ctx.Err() != nil {
		return outcomeNone, ErrUnavailable
	}
	failedAt := worker.now()
	if !validWorkerTimestamp(failedAt, claimedAt, worker.config.LeaseDuration) {
		return outcomeNone, ErrUnavailable
	}
	failureContext, cancelFailure := context.WithTimeout(ctx, worker.config.OperationTimeout)
	defer cancelFailure()
	var retryAt *time.Time
	if !permanent {
		value := failedAt.Add(worker.retryDelay(job.Attempt))
		retryAt = &value
	}
	if err := worker.repository.Fail(failureContext, FailureRequest{
		Identity: worker.identity, JobID: job.ID, TenantID: job.TenantID,
		Fence: job.Fence, Attempt: job.Attempt, Code: code,
		Permanent: permanent, FailedAt: failedAt, RetryAt: retryAt,
	}); err != nil {
		return outcomeNone, ErrUnavailable
	}
	if permanent {
		return outcomeDeadLettered, nil
	}
	return outcomeRetryable, nil
}

func validConfig(config Config) bool {
	return config.BatchSize >= 1 && config.BatchSize <= 250 &&
		config.OperationTimeout >= time.Second && config.OperationTimeout <= 5*time.Minute &&
		config.OperationTimeout%time.Microsecond == 0 &&
		config.LeaseDuration >= config.OperationTimeout+5*time.Second && config.LeaseDuration <= 15*time.Minute &&
		config.LeaseDuration%time.Microsecond == 0 &&
		config.RunTimeout >= config.OperationTimeout && config.RunTimeout <= 30*time.Minute &&
		config.RunTimeout%time.Microsecond == 0 &&
		config.MaximumAttempts >= 1 && config.MaximumAttempts <= 100 &&
		config.RetryBaseDelay >= time.Second && config.RetryBaseDelay <= time.Hour &&
		config.RetryBaseDelay%time.Microsecond == 0 &&
		config.RetryMaximumDelay >= config.RetryBaseDelay && config.RetryMaximumDelay <= 24*time.Hour &&
		config.RetryMaximumDelay%time.Microsecond == 0
}

func (worker *Worker) retryDelay(attempt uint16) time.Duration {
	delay := worker.config.RetryBaseDelay
	for index := uint16(1); index < attempt && delay < worker.config.RetryMaximumDelay; index++ {
		if delay > worker.config.RetryMaximumDelay/2 {
			return worker.config.RetryMaximumDelay
		}
		delay *= 2
	}
	if delay > worker.config.RetryMaximumDelay {
		return worker.config.RetryMaximumDelay
	}
	return delay
}

func validIdentity(identity Identity) bool {
	return validUUIDv7(identity.WorkerID) && identity.Purpose == "sla-engine"
}

func uniqueClaims(jobs []Job) bool {
	seenJobs := make(map[kernel.EntityID]struct{}, len(jobs))
	type aggregateIdentity struct {
		tenantID      uuid.UUID
		slaInstanceID kernel.EntityID
	}
	seenAggregates := make(map[aggregateIdentity]struct{}, len(jobs))
	for _, job := range jobs {
		if _, duplicate := seenJobs[job.ID]; duplicate {
			return false
		}
		seenJobs[job.ID] = struct{}{}
		aggregate := aggregateIdentity{tenantID: job.TenantID, slaInstanceID: job.SLAInstanceID}
		if _, duplicate := seenAggregates[aggregate]; duplicate {
			return false
		}
		seenAggregates[aggregate] = struct{}{}
	}
	return true
}

func validClaimIdentity(job Job) bool {
	return validKernelID(job.ID) && validUUIDv7(job.TenantID) && job.Fence > 0 &&
		job.Fence < uint64(math.MaxInt64) && job.Attempt > 0
}

func validJobProjection(job Job, claimedAt time.Time, maximumAttempts uint16, leaseDuration time.Duration) bool {
	if (job.ObjectType != kernel.ObjectAlert && job.ObjectType != kernel.ObjectCase && job.ObjectType != kernel.ObjectTask) ||
		!validKernelID(job.ObjectID) || !validKernelID(job.SLAInstanceID) || job.AggregateVersion == 0 ||
		job.AggregateVersion >= uint64(math.MaxInt64-1) || job.Attempt > maximumAttempts || !validInstant(job.ObservedAt) ||
		!job.ObservedAt.Equal(claimedAt) ||
		!validInstant(job.LeaseExpiresAt) || !job.LeaseExpiresAt.Equal(claimedAt.Add(leaseDuration)) ||
		len(job.Metrics) == 0 || len(job.Metrics) > 32 {
		return false
	}
	for _, work := range job.Metrics {
		instance := work.Instance
		if instance.TenantID().String() != job.TenantID.String() || instance.ObjectType() != job.ObjectType ||
			instance.ObjectID() != job.ObjectID || instance.SLAInstanceID() != job.SLAInstanceID {
			return false
		}
	}
	return true
}

func validPlan(job Job, plan kernel.EnginePlan) bool {
	if !plan.ObservedAt().Equal(job.ObservedAt) {
		return false
	}
	metrics := plan.Metrics()
	if len(metrics) != len(job.Metrics) {
		return false
	}
	seen := make(map[kernel.EntityID]struct{}, len(metrics))
	for _, metric := range metrics {
		instance := metric.Instance()
		if instance.TenantID().String() != job.TenantID.String() || instance.ObjectType() != job.ObjectType ||
			instance.ObjectID() != job.ObjectID || instance.SLAInstanceID() != job.SLAInstanceID ||
			metric.Changed() && instance.Version() != metric.PreviousVersion()+1 ||
			!metric.Changed() && instance.Version() != metric.PreviousVersion() {
			return false
		}
		if _, duplicate := seen[instance.ID()]; duplicate {
			return false
		}
		seen[instance.ID()] = struct{}{}
	}
	return true
}

func usableDeadline(ctx context.Context, now time.Time, maximum time.Duration) bool {
	if ctx == nil {
		return false
	}
	deadline, ok := ctx.Deadline()
	remaining := deadline.Sub(now)
	// Domain instants are normalized to microseconds while Go context
	// deadlines retain nanoseconds. Accept only that sub-microsecond rounding
	// difference; a full extra precision unit remains out of bounds.
	return ctx.Err() == nil && ok && remaining > 0 && remaining < maximum+time.Microsecond
}

func (worker *Worker) now() time.Time {
	return worker.clock().UTC().Truncate(time.Microsecond)
}

func validInstant(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Year() >= 1970 && value.Year() <= 9999 &&
		value.Nanosecond()%1_000 == 0
}

func validWorkerTimestamp(value, claimedAt time.Time, leaseDuration time.Duration) bool {
	return validInstant(value) && !value.Before(claimedAt) && !value.After(claimedAt.Add(leaseDuration))
}

func validUUIDv7(value uuid.UUID) bool {
	return value != uuid.Nil && value.Version() == 7 && value.Variant() == uuid.RFC4122
}

func validKernelID(value kernel.EntityID) bool {
	_, err := kernel.ParseEntityID(value.String())
	return err == nil
}

func (worker Worker) String() string {
	return "slaengine.Worker{repository:[REDACTED],identity:[REDACTED]}"
}
func (worker Worker) GoString() string { return worker.String() }
