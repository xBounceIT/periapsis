package slaevent

import (
	"context"
	"errors"
	"math"
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
		return nil, ErrInvalidConfiguration
	}
	now := normalizeInstant(clock())
	if !validInstant(now) {
		return nil, ErrInvalidConfiguration
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
	if err != nil || len(jobs) > worker.config.BatchSize || !uniqueClaims(jobs) {
		return RunSummary{}, ErrUnavailable
	}
	summary := RunSummary{Claimed: len(jobs)}
	for _, job := range jobs {
		if ctx.Err() != nil {
			return summary, ErrUnavailable
		}
		outcome, runErr := worker.process(ctx, now, job)
		switch outcome {
		case runApplied:
			summary.Applied++
		case runReplayed:
			summary.Replayed++
		case runRetryScheduled:
			summary.RetryScheduled++
		case runDeadLettered:
			summary.DeadLettered++
		case runFenceLost:
			summary.FenceLost++
		}
		if runErr != nil {
			return summary, runErr
		}
	}
	return summary, nil
}

type runOutcome uint8

const (
	runNone runOutcome = iota
	runApplied
	runReplayed
	runRetryScheduled
	runDeadLettered
	runFenceLost
)

func (worker *Worker) process(ctx context.Context, claimedAt time.Time, job Job) (runOutcome, error) {
	if !validClaimIdentity(job) {
		return runNone, ErrUnavailable
	}
	if job.InvalidProjection || !validJobProjection(job, claimedAt, worker.config.MaximumAttempts, worker.config.LeaseDuration) {
		return worker.recordFailure(ctx, job, claimedAt, "invalid_projection", true)
	}
	planningContext, cancelPlanning := context.WithTimeout(ctx, worker.config.OperationTimeout)
	plan, err := kernel.PlanObjectEventContext(planningContext, job.Event, job.State)
	planningErr := planningContext.Err()
	cancelPlanning()
	if err != nil || planningErr != nil {
		permanent := !errors.Is(err, kernel.ErrEngineCanceled) &&
			!errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) &&
			planningErr == nil
		if !permanent && job.Attempt >= worker.config.MaximumAttempts {
			permanent = true
		}
		code := "planning_timeout"
		if permanent {
			code = "invalid_projection"
		}
		return worker.recordFailure(ctx, job, claimedAt, code, permanent)
	}
	if !validPlan(job, plan) {
		return worker.recordFailure(ctx, job, claimedAt, "invalid_projection", true)
	}
	completedAt := worker.now()
	if !validWorkerTimestamp(completedAt, claimedAt, worker.config.LeaseDuration) {
		return runNone, ErrUnavailable
	}
	commitContext, cancelCommit := context.WithTimeout(ctx, worker.config.OperationTimeout)
	result, err := worker.repository.Commit(commitContext, CommitRequest{
		Identity: worker.identity, Job: job, Plan: plan, CompletedAt: completedAt,
	})
	cancelCommit()
	if err != nil {
		// A commit can have succeeded even if its response was lost. A failure
		// transition here could contradict that receipt, so only the lease/fence
		// protocol may decide whether this job is reclaimable.
		if errors.Is(err, ErrFenceLost) {
			return runFenceLost, nil
		}
		return runNone, ErrUnavailable
	}
	if !validCommitResult(job, plan, result) {
		return runNone, ErrUnavailable
	}
	if result.Replayed {
		return runReplayed, nil
	}
	return runApplied, nil
}

func (worker *Worker) recordFailure(
	ctx context.Context,
	job Job,
	claimedAt time.Time,
	code string,
	permanent bool,
) (runOutcome, error) {
	if ctx == nil || ctx.Err() != nil {
		return runNone, ErrUnavailable
	}
	failedAt := worker.now()
	if !validWorkerTimestamp(failedAt, claimedAt, worker.config.LeaseDuration) {
		return runNone, ErrUnavailable
	}
	if !permanent && job.Attempt >= worker.config.MaximumAttempts {
		permanent = true
		code = "attempts_exhausted"
	}
	var retryAt *time.Time
	if !permanent {
		value := failedAt.Add(worker.retryDelay(job.Attempt))
		retryAt = &value
	}
	failureContext, cancelFailure := context.WithTimeout(ctx, worker.config.OperationTimeout)
	err := worker.repository.Fail(failureContext, FailureRequest{
		Identity: worker.identity, JobID: job.ID, TenantID: job.TenantID,
		Fence: job.Fence, Attempt: job.Attempt, Code: code, Permanent: permanent,
		FailedAt: failedAt, RetryAt: retryAt,
	})
	cancelFailure()
	if errors.Is(err, ErrFenceLost) {
		return runFenceLost, nil
	}
	if err != nil {
		return runNone, ErrUnavailable
	}
	if permanent {
		return runDeadLettered, nil
	}
	return runRetryScheduled, nil
}

func validConfig(config Config) bool {
	return config.BatchSize >= 1 && config.BatchSize <= 100 &&
		config.OperationTimeout >= time.Second && config.OperationTimeout <= 2*time.Minute &&
		config.OperationTimeout%time.Microsecond == 0 &&
		config.LeaseDuration >= config.OperationTimeout+5*time.Second && config.LeaseDuration <= 15*time.Minute &&
		config.LeaseDuration%time.Microsecond == 0 &&
		config.RunTimeout >= config.OperationTimeout && config.RunTimeout <= 30*time.Minute &&
		config.RunTimeout <= config.LeaseDuration && config.RunTimeout%time.Microsecond == 0 &&
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
	return validUUIDv7(identity.WorkerID) && identity.Purpose == WorkerPurpose
}

func uniqueClaims(jobs []Job) bool {
	seenJobs := make(map[kernel.EntityID]struct{}, len(jobs))
	type objectIdentity struct {
		tenantID   uuid.UUID
		objectType kernel.ObjectType
		objectID   kernel.EntityID
	}
	seenObjects := make(map[objectIdentity]struct{}, len(jobs))
	for _, job := range jobs {
		if _, duplicate := seenJobs[job.ID]; duplicate {
			return false
		}
		seenJobs[job.ID] = struct{}{}
		object := objectIdentity{tenantID: job.TenantID, objectType: job.ObjectType, objectID: job.ObjectID}
		if _, duplicate := seenObjects[object]; duplicate {
			return false
		}
		seenObjects[object] = struct{}{}
	}
	return true
}

func validClaimIdentity(job Job) bool {
	return validEntity(job.ID) && validUUIDv7(job.TenantID) && validEntity(job.SourceEventID) &&
		job.Sequence > 0 && job.Sequence < uint64(math.MaxInt64) &&
		job.Fence > 0 && job.Fence < uint64(math.MaxInt64) && job.Attempt > 0 &&
		job.SourceDigest != ([32]byte{})
}

func validJobProjection(job Job, claimedAt time.Time, maximumAttempts uint16, leaseDuration time.Duration) bool {
	if job.ObjectType != kernel.ObjectAlert && job.ObjectType != kernel.ObjectCase ||
		!validEntity(job.ObjectID) || job.Attempt > maximumAttempts ||
		!validInstant(job.ClaimedAt) || !job.ClaimedAt.Equal(claimedAt) ||
		!validInstant(job.LeaseExpiresAt) || !job.LeaseExpiresAt.Equal(claimedAt.Add(leaseDuration)) ||
		job.Event.ID != job.SourceEventID || job.Event.TenantID.String() != job.TenantID.String() ||
		job.Event.ObjectID != job.ObjectID || job.Event.Key.String() == "" || !validInstant(job.Event.OccurredAt) {
		return false
	}
	switch job.State.Mode {
	case kernel.ObjectEventStateNoPolicy:
		return job.State.AggregateVersion == 0 && len(job.State.Metrics) == 0 && job.State.Snapshot == nil &&
			len(job.State.Policies) == 0 && len(job.State.Calendars) == 0 && len(job.State.Columns) == 0 &&
			job.SLAInstanceID == nil && job.PolicyID == nil && job.PolicyVersion == 0
	case kernel.ObjectEventStateExisting:
		return job.State.AggregateVersion > 0 && job.State.AggregateVersion < uint64(math.MaxInt64-1) &&
			len(job.State.Metrics) > 0 && len(job.State.Metrics) <= 32 && job.State.Snapshot == nil &&
			len(job.State.Policies) == 0 && len(job.State.Calendars) == 0 && len(job.State.Columns) == 0 &&
			job.SLAInstanceID != nil && validEntity(*job.SLAInstanceID) &&
			job.PolicyID != nil && validEntity(*job.PolicyID) && job.PolicyVersion > 0
	case kernel.ObjectEventStateUnassigned:
		return job.State.AggregateVersion == 0 && len(job.State.Metrics) == 0 && job.State.Snapshot != nil &&
			job.State.Snapshot.TenantID().String() == job.TenantID.String() &&
			job.State.Snapshot.ObjectType() == job.ObjectType && job.State.Snapshot.EvaluatedAt().Equal(job.Event.OccurredAt) &&
			job.SLAInstanceID == nil && job.PolicyID == nil && job.PolicyVersion == 0
	default:
		return false
	}
}

func validPlan(job Job, plan kernel.ObjectEventPlan) bool {
	assignment, engine := plan.Assignment(), plan.Engine()
	if job.State.Mode == kernel.ObjectEventStateNoPolicy {
		return plan.PinnedNoPolicy() && assignment == nil && engine == nil &&
			plan.ExpectedAggregateVersion() == 0 && plan.NextAggregateVersion() == 0
	}
	if plan.PinnedNoPolicy() {
		return false
	}
	if job.State.Mode == kernel.ObjectEventStateExisting {
		return assignment == nil && engine != nil && plan.ExpectedAggregateVersion() == job.State.AggregateVersion &&
			plan.NextAggregateVersion() == job.State.AggregateVersion+1 && validEventEngine(job, *engine)
	}
	if assignment == nil || assignment.AssignmentEventID() != job.Event.ID ||
		assignment.ObjectID() != job.ObjectID || !assignment.CreatedAt().Equal(job.Event.OccurredAt) ||
		plan.ExpectedAggregateVersion() != 0 {
		return false
	}
	if !assignment.Matched() {
		return engine == nil && plan.NextAggregateVersion() == 0
	}
	policy := assignment.Policy()
	return policy != nil && assignment.SLAInstanceID() != (kernel.EntityID{}) && engine != nil &&
		plan.NextAggregateVersion() == 1 && validEventEngine(job, *engine)
}

func validEventEngine(job Job, plan kernel.EnginePlan) bool {
	eventID := plan.EventID()
	if eventID == nil || *eventID != job.Event.ID || !plan.ObservedAt().Equal(job.Event.OccurredAt) {
		return false
	}
	metrics := plan.Metrics()
	if len(metrics) == 0 || len(metrics) > 32 {
		return false
	}
	for _, metric := range metrics {
		instance := metric.Instance()
		if instance.TenantID().String() != job.TenantID.String() || instance.ObjectType() != job.ObjectType ||
			instance.ObjectID() != job.ObjectID || !validEntity(instance.SLAInstanceID()) ||
			metric.PreviousVersion() == 0 || metric.Changed() && instance.Version() != metric.PreviousVersion()+1 ||
			!metric.Changed() && instance.Version() != metric.PreviousVersion() {
			return false
		}
	}
	return true
}

func validCommitResult(job Job, plan kernel.ObjectEventPlan, result CommitResult) bool {
	if plan.PinnedNoPolicy() {
		return job.State.Mode == kernel.ObjectEventStateNoPolicy && result.Outcome == OutcomeNoPolicy &&
			result.SLAInstanceID == nil && result.AggregateVersion == 0
	}
	assignment := plan.Assignment()
	switch {
	case assignment == nil:
		return result.Outcome == OutcomeUpdated && result.SLAInstanceID != nil && job.SLAInstanceID != nil &&
			*result.SLAInstanceID == *job.SLAInstanceID && result.AggregateVersion == plan.NextAggregateVersion()
	case !assignment.Matched():
		return result.Outcome == OutcomeNoPolicy && result.SLAInstanceID == nil && result.AggregateVersion == 0
	default:
		return result.Outcome == OutcomeAssigned && result.SLAInstanceID != nil &&
			*result.SLAInstanceID == assignment.SLAInstanceID() && result.AggregateVersion == 1
	}
}

func usableDeadline(ctx context.Context, now time.Time, maximum time.Duration) bool {
	if ctx == nil || ctx.Err() != nil {
		return false
	}
	deadline, ok := ctx.Deadline()
	remaining := deadline.Sub(now)
	return ok && remaining > 0 && remaining < maximum+time.Microsecond
}

func (worker *Worker) now() time.Time { return normalizeInstant(worker.clock()) }

func normalizeInstant(value time.Time) time.Time { return value.UTC().Truncate(time.Microsecond) }

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

func validEntity(value kernel.EntityID) bool {
	_, err := kernel.ParseEntityID(value.String())
	return err == nil
}

func (worker Worker) String() string {
	return "slaevent.Worker{repository:[REDACTED],identity:[REDACTED]}"
}

func (worker Worker) GoString() string { return worker.String() }
