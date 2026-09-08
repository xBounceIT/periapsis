package postgres

import (
	"context"
	"math"
	"regexp"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	kernel "github.com/periapsis-im/periapsis/modules/sla"
	"github.com/periapsis-im/periapsis/services/worker/internal/slaevent"
)

const readySLAObjectEventIngressQuery = `SELECT app.sla_object_event_ingress_schema_readiness_v59()`

const claimSLAObjectEventsQuery = `
WITH trace_context AS MATERIALIZED (
  SELECT set_config('app.traceparent', $1, true) AS traceparent,
         set_config('app.tracestate', $2, true) AS tracestate
)
SELECT job.job_id, job.tenant_id, job.object_type, job.object_id,
       job.object_sequence, job.source_event_id, job.source_digest,
       job.event_key, job.occurred_at, job.state_mode,
       job.sla_instance_id, job.aggregate_version,
       job.policy_id, job.policy_version, job.fence, job.attempt,
       job.claimed_at, job.lease_expires_at, job.state_document
FROM trace_context AS trace
CROSS JOIN LATERAL app.claim_sla_object_events_v1(
  CASE WHEN trace.traceparent = $1 AND trace.tracestate = $2
    THEN $3 ELSE NULL::uuid END,
  $4, $5, $6
) AS job
`

const commitSLAObjectEventQuery = `
WITH trace_context AS MATERIALIZED (
  SELECT set_config('app.traceparent', $1, true) AS traceparent,
         set_config('app.tracestate', $2, true) AS tracestate
)
SELECT result.transition, result.outcome, result.sla_instance_id,
       result.aggregate_version
FROM trace_context AS trace
CROSS JOIN LATERAL app.commit_sla_object_event_ingress_v1(
  CASE WHEN trace.traceparent = $1 AND trace.tracestate = $2
    THEN $3 ELSE NULL::uuid END,
  $4, $5, $6, decode($7, 'hex'), $8::public.sla_event_outcome,
  $9, $10, $11, $12, $13, $14, $15::jsonb
) AS result
`

const failSLAObjectEventQuery = `
WITH trace_context AS MATERIALIZED (
  SELECT set_config('app.traceparent', $1, true) AS traceparent,
         set_config('app.tracestate', $2, true) AS tracestate
)
SELECT app.fail_sla_object_event_ingress_v1(
  CASE WHEN trace.traceparent = $1 AND trace.tracestate = $2
    THEN $3 ELSE NULL::uuid END,
  $4, $5, $6, $7, $8, $9, $10, $11
)::text
FROM trace_context AS trace
`

const readSLAObjectEventQueueMetricsQuery = `
SELECT metrics.observed_at, metrics.pending_events,
       metrics.reclaimable_events, metrics.dead_lettered_events,
       metrics.oldest_pending_micros
FROM app.read_sla_object_event_ingress_queue_metrics_v1() AS metrics
`

var slaEventFailureCodePattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)

type SLAEventRepository struct{ pool slaWorkerQuerier }

func NewSLAEventRepository(pool slaWorkerQuerier) *SLAEventRepository {
	return &SLAEventRepository{pool: pool}
}

var _ slaevent.Repository = (*SLAEventRepository)(nil)

func (repository *SLAEventRepository) Ready(ctx context.Context) error {
	if repository == nil || repository.pool == nil || ctx == nil || ctx.Err() != nil {
		return slaevent.ErrInvalidInput
	}
	var ready bool
	if err := repository.pool.QueryRow(ctx, readySLAObjectEventIngressQuery).Scan(&ready); err != nil || !ready {
		return slaevent.ErrUnavailable
	}
	return nil
}

func (repository *SLAEventRepository) Claim(
	ctx context.Context,
	request slaevent.ClaimRequest,
) ([]slaevent.Job, error) {
	if repository == nil || repository.pool == nil || ctx == nil || ctx.Err() != nil ||
		!validSLAEventIdentity(request.Identity) || !validSLAWorkerInstant(request.Now) ||
		request.BatchSize < 1 || request.BatchSize > 100 ||
		request.LeaseDuration < time.Second || request.LeaseDuration > 15*time.Minute ||
		request.LeaseDuration%time.Microsecond != 0 {
		return nil, slaevent.ErrInvalidInput
	}
	traceparent, tracestate := slaTraceContextArguments(ctx)
	rows, err := repository.pool.Query(
		ctx, claimSLAObjectEventsQuery, traceparent, tracestate,
		request.Identity.WorkerID, request.Now, request.BatchSize,
		request.LeaseDuration.Microseconds(),
	)
	if err != nil {
		return nil, slaevent.ErrUnavailable
	}
	defer rows.Close()
	jobs := make([]slaevent.Job, 0, request.BatchSize)
	for rows.Next() {
		job, decodeErr := scanSLAEventJob(rows, request)
		if decodeErr != nil {
			return nil, decodeErr
		}
		jobs = append(jobs, job)
	}
	if err := rows.Err(); err != nil {
		return nil, slaevent.ErrUnavailable
	}
	return jobs, nil
}

func scanSLAEventJob(row pgx.Row, request slaevent.ClaimRequest) (slaevent.Job, error) {
	var jobID, tenantID, objectID, sourceEventID uuid.UUID
	var objectType, eventKey, stateMode string
	var objectSequence, aggregateVersion, policyVersion, fence int64
	var attempt int32
	var sourceDigest, stateDocument []byte
	var occurredAt, claimedAt, leaseExpiresAt time.Time
	var slaInstanceID, policyID *uuid.UUID
	if err := row.Scan(
		&jobID, &tenantID, &objectType, &objectID, &objectSequence,
		&sourceEventID, &sourceDigest, &eventKey, &occurredAt, &stateMode,
		&slaInstanceID, &aggregateVersion, &policyID, &policyVersion,
		&fence, &attempt, &claimedAt, &leaseExpiresAt, &stateDocument,
	); err != nil {
		clear(sourceDigest)
		clear(stateDocument)
		return slaevent.Job{}, slaevent.ErrUnavailable
	}
	job, envelopeValid := baseSLAEventJob(
		jobID, tenantID, objectType, objectID, objectSequence, sourceEventID,
		sourceDigest, eventKey, occurredAt, stateMode, slaInstanceID,
		aggregateVersion, policyID, policyVersion, fence, attempt,
		claimedAt, leaseExpiresAt, request,
	)
	clear(sourceDigest)
	if !envelopeValid {
		clear(stateDocument)
		return slaevent.Job{}, slaevent.ErrUnavailable
	}
	var state kernel.ObjectEventState
	var decodeErr error
	if stateMode == string(kernel.ObjectEventStateExisting) {
		if slaInstanceID == nil {
			decodeErr = slaevent.ErrInvalidProjection
		} else {
			decodedType, decodedObjectID, metrics, err := decodeSLAWorkerState(
				tenantID, *slaInstanceID, uint64(aggregateVersion), stateDocument,
			)
			if err != nil || decodedType != job.ObjectType || decodedObjectID != job.ObjectID {
				decodeErr = slaevent.ErrInvalidProjection
			} else {
				state = kernel.ObjectEventState{
					Mode:             kernel.ObjectEventStateExisting,
					AggregateVersion: uint64(aggregateVersion), Metrics: metrics,
				}
			}
		}
	} else if stateMode == string(kernel.ObjectEventStateUnassigned) {
		state, decodeErr = decodeSLAEventAssignmentSnapshot(
			tenantID, job.ObjectType, job.ObjectID, job.Event.OccurredAt, stateDocument,
		)
	} else if stateMode == string(kernel.ObjectEventStateNoPolicy) {
		if len(stateDocument) != 0 {
			decodeErr = slaevent.ErrInvalidProjection
		} else {
			state = kernel.ObjectEventState{Mode: kernel.ObjectEventStateNoPolicy}
		}
	} else {
		decodeErr = slaevent.ErrInvalidProjection
	}
	clear(stateDocument)
	if decodeErr != nil {
		job.InvalidProjection = true
		return job, nil
	}
	job.State = state
	return job, nil
}

func baseSLAEventJob(
	jobID uuid.UUID,
	tenantID uuid.UUID,
	objectTypeValue string,
	objectID uuid.UUID,
	objectSequence int64,
	sourceEventID uuid.UUID,
	sourceDigest []byte,
	eventKeyValue string,
	occurredAt time.Time,
	stateMode string,
	slaInstanceID *uuid.UUID,
	aggregateVersion int64,
	policyID *uuid.UUID,
	policyVersion int64,
	fence int64,
	attempt int32,
	claimedAt time.Time,
	leaseExpiresAt time.Time,
	request slaevent.ClaimRequest,
) (slaevent.Job, bool) {
	digest, digestErr := decodeSLAEventDigest(sourceDigest)
	objectType := kernel.ObjectType(objectTypeValue)
	eventKey, keyErr := kernel.NewKey(eventKeyValue)
	if !slaWorkerUUIDv7(jobID) || !slaWorkerUUIDv7(tenantID) || !slaWorkerUUIDv7(objectID) ||
		!slaWorkerUUIDv7(sourceEventID) || digestErr != nil || keyErr != nil ||
		(objectType != kernel.ObjectAlert && objectType != kernel.ObjectCase) ||
		objectSequence < 1 || aggregateVersion < 0 || aggregateVersion >= math.MaxInt64 ||
		policyVersion < 0 || policyVersion >= math.MaxInt64 || fence < 1 ||
		attempt < 1 || attempt > math.MaxUint16 || !normalizeSLAWorkerInstant(&occurredAt) ||
		!normalizeSLAWorkerInstant(&claimedAt) || !normalizeSLAWorkerInstant(&leaseExpiresAt) ||
		!claimedAt.Equal(request.Now) || !leaseExpiresAt.Equal(request.Now.Add(request.LeaseDuration)) ||
		(stateMode != string(kernel.ObjectEventStateExisting) &&
			stateMode != string(kernel.ObjectEventStateUnassigned) &&
			stateMode != string(kernel.ObjectEventStateNoPolicy)) ||
		stateMode == string(kernel.ObjectEventStateExisting) &&
			(slaInstanceID == nil || policyID == nil || aggregateVersion < 1 || policyVersion < 1) ||
		stateMode == string(kernel.ObjectEventStateUnassigned) &&
			(slaInstanceID != nil || policyID != nil || aggregateVersion != 0 || policyVersion != 0) ||
		stateMode == string(kernel.ObjectEventStateNoPolicy) &&
			(slaInstanceID != nil || policyID != nil || aggregateVersion != 0 || policyVersion != 0) {
		return slaevent.Job{}, false
	}
	jobEntity, _ := kernel.ParseEntityID(jobID.String())
	tenantEntity, _ := kernel.ParseEntityID(tenantID.String())
	objectEntity, _ := kernel.ParseEntityID(objectID.String())
	sourceEntity, _ := kernel.ParseEntityID(sourceEventID.String())
	job := slaevent.Job{
		ID: jobEntity, TenantID: tenantID, ObjectType: objectType,
		ObjectID: objectEntity, Sequence: uint64(objectSequence),
		SourceEventID: sourceEntity, SourceDigest: digest,
		Event: kernel.MetricEvent{
			ID: sourceEntity, TenantID: tenantEntity, ObjectID: objectEntity,
			Key: eventKey, OccurredAt: occurredAt,
		},
		Fence: uint64(fence), Attempt: uint16(attempt), ClaimedAt: claimedAt,
		LeaseExpiresAt: leaseExpiresAt,
	}
	if slaInstanceID != nil {
		parsed, err := kernel.ParseEntityID(slaInstanceID.String())
		if err != nil {
			return slaevent.Job{}, false
		}
		job.SLAInstanceID = &parsed
	}
	if policyID != nil {
		parsed, err := kernel.ParseEntityID(policyID.String())
		if err != nil {
			return slaevent.Job{}, false
		}
		job.PolicyID = &parsed
		job.PolicyVersion = uint64(policyVersion)
	}
	return job, true
}

func (repository *SLAEventRepository) Commit(
	ctx context.Context,
	request slaevent.CommitRequest,
) (slaevent.CommitResult, error) {
	if repository == nil || repository.pool == nil || ctx == nil || ctx.Err() != nil ||
		!validSLAEventIdentity(request.Identity) || request.Job.InvalidProjection ||
		!validSLAEventCommitEnvelope(request) {
		return slaevent.CommitResult{}, slaevent.ErrInvalidInput
	}
	outcome, slaInstanceID, policyID, policyVersion, ok := slaEventCommitIdentity(request.Job, request.Plan)
	if !ok {
		return slaevent.CommitResult{}, slaevent.ErrInvalidInput
	}
	planDocument, err := encodeSLAEventPlan(request.Plan)
	if err != nil {
		return slaevent.CommitResult{}, slaevent.ErrInvalidInput
	}
	defer clear(planDocument)
	traceparent, tracestate := slaTraceContextArguments(ctx)
	var transition, returnedOutcome string
	var returnedSLAInstanceID *uuid.UUID
	var aggregateVersion int64
	err = repository.pool.QueryRow(
		ctx, commitSLAObjectEventQuery, traceparent, tracestate,
		request.Identity.WorkerID, uuid.UUID(request.Job.ID.Bytes()), request.Job.TenantID,
		request.Job.Fence, encodeSLAEventDigest(request.Job.SourceDigest), string(outcome),
		slaInstanceID, request.Plan.ExpectedAggregateVersion(), request.Plan.NextAggregateVersion(),
		policyID, policyVersion, request.CompletedAt, planDocument,
	).Scan(&transition, &returnedOutcome, &returnedSLAInstanceID, &aggregateVersion)
	if err != nil {
		return slaevent.CommitResult{}, slaevent.ErrUnavailable
	}
	if transition == "fence_lost" {
		return slaevent.CommitResult{}, slaevent.ErrFenceLost
	}
	if transition != "applied" && transition != "replayed" || returnedOutcome != string(outcome) ||
		aggregateVersion != int64(request.Plan.NextAggregateVersion()) {
		return slaevent.CommitResult{}, slaevent.ErrUnavailable
	}
	result := slaevent.CommitResult{
		Outcome:          slaevent.EventOutcome(returnedOutcome),
		AggregateVersion: uint64(aggregateVersion), Replayed: transition == "replayed",
	}
	if returnedSLAInstanceID != nil {
		parsed, parseErr := kernel.ParseEntityID(returnedSLAInstanceID.String())
		if parseErr != nil {
			return slaevent.CommitResult{}, slaevent.ErrUnavailable
		}
		result.SLAInstanceID = &parsed
	}
	return result, nil
}

func slaEventCommitIdentity(
	job slaevent.Job,
	plan kernel.ObjectEventPlan,
) (slaevent.EventOutcome, any, any, uint64, bool) {
	if plan.PinnedNoPolicy() {
		if job.State.Mode != kernel.ObjectEventStateNoPolicy || plan.Assignment() != nil || plan.Engine() != nil {
			return "", nil, nil, 0, false
		}
		return slaevent.OutcomeNoPolicy, nil, nil, 0, true
	}
	assignment := plan.Assignment()
	if assignment == nil {
		if job.SLAInstanceID == nil || job.PolicyID == nil {
			return "", nil, nil, 0, false
		}
		return slaevent.OutcomeUpdated, uuid.UUID(job.SLAInstanceID.Bytes()),
			uuid.UUID(job.PolicyID.Bytes()), job.PolicyVersion, true
	}
	if !assignment.Matched() {
		return slaevent.OutcomeNoPolicy, nil, nil, 0, true
	}
	policy := assignment.Policy()
	if policy == nil {
		return "", nil, nil, 0, false
	}
	return slaevent.OutcomeAssigned, uuid.UUID(assignment.SLAInstanceID().Bytes()),
		uuid.UUID(policy.ID().Bytes()), policy.Version(), true
}

func validSLAEventCommitEnvelope(request slaevent.CommitRequest) bool {
	job := request.Job
	return validSLAWorkerEntity(job.ID) && slaWorkerUUIDv7(job.TenantID) &&
		job.Fence > 0 && job.Fence < uint64(math.MaxInt64) &&
		job.SourceDigest != ([32]byte{}) && validSLAWorkerInstant(request.CompletedAt) &&
		!request.CompletedAt.Before(job.ClaimedAt) && !request.CompletedAt.After(job.LeaseExpiresAt)
}

func (repository *SLAEventRepository) Fail(
	ctx context.Context,
	request slaevent.FailureRequest,
) error {
	if repository == nil || repository.pool == nil || ctx == nil || ctx.Err() != nil ||
		!validSLAEventIdentity(request.Identity) || !validSLAWorkerEntity(request.JobID) ||
		!slaWorkerUUIDv7(request.TenantID) || request.Fence < 1 || request.Fence >= uint64(math.MaxInt64) ||
		request.Attempt < 1 || !slaEventFailureCodePattern.MatchString(request.Code) ||
		!validSLAWorkerInstant(request.FailedAt) || request.Permanent && request.RetryAt != nil ||
		!request.Permanent && (request.RetryAt == nil || !validSLAWorkerInstant(*request.RetryAt) ||
			!request.RetryAt.After(request.FailedAt)) {
		return slaevent.ErrInvalidInput
	}
	var retryAt any
	if request.RetryAt != nil {
		retryAt = *request.RetryAt
	}
	traceparent, tracestate := slaTraceContextArguments(ctx)
	var status string
	err := repository.pool.QueryRow(
		ctx, failSLAObjectEventQuery, traceparent, tracestate,
		request.Identity.WorkerID, uuid.UUID(request.JobID.Bytes()), request.TenantID,
		request.Fence, request.Attempt, request.Code, request.Permanent,
		request.FailedAt, retryAt,
	).Scan(&status)
	if err != nil {
		return slaevent.ErrUnavailable
	}
	if status == "fence_lost" {
		return slaevent.ErrFenceLost
	}
	if status != "retry_scheduled" && status != "dead_lettered" ||
		request.Permanent && status != "dead_lettered" {
		return slaevent.ErrUnavailable
	}
	return nil
}

func (repository *SLAEventRepository) ReadQueueMetrics(ctx context.Context) (slaevent.QueueMetrics, error) {
	if repository == nil || repository.pool == nil || ctx == nil || ctx.Err() != nil {
		return slaevent.QueueMetrics{}, slaevent.ErrInvalidInput
	}
	var metrics slaevent.QueueMetrics
	err := repository.pool.QueryRow(ctx, readSLAObjectEventQueueMetricsQuery).Scan(
		&metrics.ObservedAt, &metrics.PendingEvents, &metrics.ReclaimableEvents,
		&metrics.DeadLetteredEvents, &metrics.OldestPendingMicros,
	)
	if err != nil || !normalizeSLAWorkerInstant(&metrics.ObservedAt) ||
		metrics.PendingEvents < 0 || metrics.ReclaimableEvents < 0 ||
		metrics.DeadLetteredEvents < 0 || metrics.OldestPendingMicros < 0 ||
		metrics.PendingEvents == 0 && metrics.OldestPendingMicros != 0 {
		return slaevent.QueueMetrics{}, slaevent.ErrUnavailable
	}
	return metrics, nil
}

func validSLAEventIdentity(identity slaevent.Identity) bool {
	return slaWorkerUUIDv7(identity.WorkerID) && identity.Purpose == slaevent.WorkerPurpose
}
