package postgres

import (
	"context"
	"math"
	"regexp"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	kernel "github.com/periapsis-im/periapsis/modules/sla"
	"github.com/periapsis-im/periapsis/services/worker/internal/slaengine"
)

const claimSLAEvaluationJobsQuery = `
WITH trace_context AS MATERIALIZED (
  SELECT set_config('app.traceparent', $1, true) AS traceparent,
         set_config('app.tracestate', $2, true) AS tracestate
)
SELECT job.job_id, job.tenant_id, job.sla_instance_id,
       job.expected_aggregate_version, job.fence, job.attempt,
       job.observed_at, job.lease_expires_at, job.state_document
FROM trace_context AS trace
CROSS JOIN LATERAL app.claim_sla_evaluation_jobs_v3(
  CASE WHEN trace.traceparent = $1 AND trace.tracestate = $2 THEN $3 ELSE NULL::uuid END,
  $4, $5, $6
) AS job
`

const finalizeSLAEvaluationJobQuery = `
WITH trace_context AS MATERIALIZED (
  SELECT set_config('app.traceparent', $1, true) AS traceparent,
         set_config('app.tracestate', $2, true) AS tracestate
)
SELECT app.finalize_sla_evaluation_job_v1(
  CASE WHEN traceparent = $1 AND tracestate = $2 THEN $3 ELSE NULL::uuid END,
  $4, $5, $6, $7, $8, $9, $10::jsonb
)
FROM trace_context
`

const failSLAEvaluationJobQuery = `
WITH trace_context AS MATERIALIZED (
  SELECT set_config('app.traceparent', $1, true) AS traceparent,
         set_config('app.tracestate', $2, true) AS tracestate
)
SELECT app.fail_sla_evaluation_job_v1(
  CASE WHEN traceparent = $1 AND tracestate = $2 THEN $3 ELSE NULL::uuid END,
  $4, $5, $6, $7, $8, $9, $10, $11
)::text
FROM trace_context
`

const readSLAEvaluationQueueMetricsQuery = `
SELECT metrics.observed_at, metrics.pending_jobs,
       metrics.oldest_pending_micros
FROM app.read_sla_evaluation_queue_metrics_v1() AS metrics
`

var slaFailureCodePattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)

type slaWorkerQuerier interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

// SLARepository is the worker-role adapter for fenced SLA timer evaluation.
// Claim, finalize, and failure transitions are each one database transaction
// because their public entry points are PostgreSQL functions.
type SLARepository struct {
	pool slaWorkerQuerier
}

func NewSLARepository(pool slaWorkerQuerier) *SLARepository {
	return &SLARepository{pool: pool}
}

var _ slaengine.Repository = (*SLARepository)(nil)

// SLAQueueMetrics is one database-clock snapshot of work that can be claimed
// now. It intentionally excludes future retries and live leases.
type SLAQueueMetrics struct {
	ObservedAt          time.Time
	PendingJobs         int64
	OldestPendingMicros int64
}

func (repository *SLARepository) ReadQueueMetrics(ctx context.Context) (SLAQueueMetrics, error) {
	if repository == nil || repository.pool == nil || ctx == nil || ctx.Err() != nil {
		return SLAQueueMetrics{}, slaengine.ErrInvalidInput
	}
	var metrics SLAQueueMetrics
	err := repository.pool.QueryRow(ctx, readSLAEvaluationQueueMetricsQuery).Scan(
		&metrics.ObservedAt,
		&metrics.PendingJobs,
		&metrics.OldestPendingMicros,
	)
	if err != nil || !normalizeSLAWorkerInstant(&metrics.ObservedAt) ||
		metrics.PendingJobs < 0 || metrics.OldestPendingMicros < 0 ||
		metrics.PendingJobs == 0 && metrics.OldestPendingMicros != 0 {
		return SLAQueueMetrics{}, slaengine.ErrUnavailable
	}
	return metrics, nil
}

func (repository *SLARepository) Claim(
	ctx context.Context,
	request slaengine.ClaimRequest,
) ([]slaengine.Job, error) {
	if repository == nil || repository.pool == nil || ctx == nil || ctx.Err() != nil ||
		!validSLAWorkerIdentity(request.Identity) || !validSLAWorkerInstant(request.Now) ||
		request.BatchSize < 1 || request.BatchSize > 100 ||
		request.LeaseDuration < time.Second || request.LeaseDuration > 5*time.Minute ||
		request.LeaseDuration%time.Microsecond != 0 {
		return nil, slaengine.ErrInvalidInput
	}
	traceparent, tracestate := slaTraceContextArguments(ctx)
	rows, err := repository.pool.Query(
		ctx, claimSLAEvaluationJobsQuery, traceparent, tracestate, request.Identity.WorkerID, request.Now,
		request.BatchSize, request.LeaseDuration.Microseconds(),
	)
	if err != nil {
		return nil, slaengine.ErrUnavailable
	}
	defer rows.Close()
	jobs := make([]slaengine.Job, 0, request.BatchSize)
	for rows.Next() {
		var jobID, tenantID, slaInstanceID uuid.UUID
		var expectedAggregateVersion, fence int64
		var attempt int32
		var observedAt, leaseExpiresAt time.Time
		var stateDocument []byte
		if err := rows.Scan(
			&jobID, &tenantID, &slaInstanceID, &expectedAggregateVersion,
			&fence, &attempt, &observedAt, &leaseExpiresAt, &stateDocument,
		); err != nil {
			return nil, slaengine.ErrUnavailable
		}
		if len(jobs) >= request.BatchSize || !slaWorkerUUIDv7(jobID) ||
			!slaWorkerUUIDv7(tenantID) || !slaWorkerUUIDv7(slaInstanceID) ||
			expectedAggregateVersion < 1 || expectedAggregateVersion >= math.MaxInt64 ||
			fence < 1 || attempt < 1 || attempt > math.MaxUint16 ||
			!normalizeSLAWorkerInstant(&observedAt) || !normalizeSLAWorkerInstant(&leaseExpiresAt) ||
			!observedAt.Equal(request.Now) || !leaseExpiresAt.Equal(request.Now.Add(request.LeaseDuration)) {
			clear(stateDocument)
			return nil, slaengine.ErrUnavailable
		}
		objectType, objectID, metrics, decodeErr := decodeSLAWorkerState(
			tenantID, slaInstanceID, uint64(expectedAggregateVersion), stateDocument,
		)
		clear(stateDocument)
		if decodeErr != nil {
			return nil, slaengine.ErrUnavailable
		}
		parsedJobID, _ := kernel.ParseEntityID(jobID.String())
		parsedSLAInstanceID, _ := kernel.ParseEntityID(slaInstanceID.String())
		jobs = append(jobs, slaengine.Job{
			ID: parsedJobID, TenantID: tenantID, ObjectType: objectType,
			ObjectID: objectID, SLAInstanceID: parsedSLAInstanceID,
			AggregateVersion: uint64(expectedAggregateVersion), Fence: uint64(fence),
			Attempt: uint16(attempt), ObservedAt: observedAt,
			LeaseExpiresAt: leaseExpiresAt, Metrics: metrics,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, slaengine.ErrUnavailable
	}
	return jobs, nil
}

func (repository *SLARepository) Finalize(
	ctx context.Context,
	request slaengine.FinalizeRequest,
) error {
	if repository == nil || repository.pool == nil || ctx == nil || ctx.Err() != nil ||
		!validSLAWorkerIdentity(request.Identity) || !validSLAWorkerEntity(request.JobID) ||
		!slaWorkerUUIDv7(request.TenantID) || !validSLAWorkerEntity(request.SLAInstanceID) ||
		request.ExpectedAggregateVersion < 1 || request.ExpectedAggregateVersion >= uint64(math.MaxInt64-1) ||
		request.Fence < 1 || request.Fence >= uint64(math.MaxInt64) ||
		!validSLAWorkerInstant(request.CompletedAt) || !validSLAWorkerFinalizePlan(request) {
		return slaengine.ErrInvalidInput
	}
	planDocument, err := encodeSLAWorkerPlan(request.Plan)
	if err != nil {
		return slaengine.ErrInvalidInput
	}
	defer clear(planDocument)
	var nextAggregateVersion int64
	traceparent, tracestate := slaTraceContextArguments(ctx)
	err = repository.pool.QueryRow(
		ctx, finalizeSLAEvaluationJobQuery,
		traceparent, tracestate, request.Identity.WorkerID,
		uuid.UUID(request.JobID.Bytes()), request.TenantID,
		uuid.UUID(request.SLAInstanceID.Bytes()), request.ExpectedAggregateVersion,
		request.Fence, request.CompletedAt, planDocument,
	).Scan(&nextAggregateVersion)
	if err != nil || nextAggregateVersion != int64(request.ExpectedAggregateVersion+1) {
		return slaengine.ErrUnavailable
	}
	return nil
}

func (repository *SLARepository) Fail(
	ctx context.Context,
	request slaengine.FailureRequest,
) error {
	if repository == nil || repository.pool == nil || ctx == nil || ctx.Err() != nil ||
		!validSLAWorkerIdentity(request.Identity) || !validSLAWorkerEntity(request.JobID) ||
		!slaWorkerUUIDv7(request.TenantID) || request.Fence < 1 || request.Fence >= uint64(math.MaxInt64) ||
		request.Attempt < 1 || !slaFailureCodePattern.MatchString(request.Code) ||
		!validSLAWorkerInstant(request.FailedAt) ||
		(request.Permanent && request.RetryAt != nil) ||
		(!request.Permanent && (request.RetryAt == nil || !validSLAWorkerInstant(*request.RetryAt) ||
			!request.RetryAt.After(request.FailedAt))) {
		return slaengine.ErrInvalidInput
	}
	var retryAt any
	if request.RetryAt != nil {
		retryAt = *request.RetryAt
	}
	var status string
	traceparent, tracestate := slaTraceContextArguments(ctx)
	err := repository.pool.QueryRow(
		ctx, failSLAEvaluationJobQuery,
		traceparent, tracestate, request.Identity.WorkerID,
		uuid.UUID(request.JobID.Bytes()), request.TenantID,
		request.Fence, request.Attempt, request.Code, request.Permanent,
		request.FailedAt, retryAt,
	).Scan(&status)
	if err != nil || status != "retry_scheduled" && status != "dead_lettered" ||
		request.Permanent && status != "dead_lettered" {
		return slaengine.ErrUnavailable
	}
	return nil
}

func validSLAWorkerIdentity(identity slaengine.Identity) bool {
	return slaWorkerUUIDv7(identity.WorkerID) && identity.Purpose == "sla-engine"
}

func validSLAWorkerEntity(value kernel.EntityID) bool {
	_, err := kernel.ParseEntityID(value.String())
	return err == nil
}

func validSLAWorkerFinalizePlan(request slaengine.FinalizeRequest) bool {
	if !validSLAWorkerInstant(request.Plan.ObservedAt()) ||
		request.Plan.ObservedAt().After(request.CompletedAt) || request.Plan.EventID() != nil {
		return false
	}
	metrics := request.Plan.Metrics()
	if len(metrics) == 0 || len(metrics) > 32 {
		return false
	}
	for _, metric := range metrics {
		instance := metric.Instance()
		if instance.TenantID().String() != request.TenantID.String() ||
			instance.SLAInstanceID() != request.SLAInstanceID ||
			(metric.Changed() && instance.Version() != metric.PreviousVersion()+1) ||
			(!metric.Changed() && instance.Version() != metric.PreviousVersion()) {
			return false
		}
	}
	return true
}
