package postgres

import (
	"context"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	kernel "github.com/periapsis-im/periapsis/modules/sla"
	"github.com/periapsis-im/periapsis/services/worker/internal/slaaction"
)

const listSLAActionQueuesQuery = `
WITH trace_context AS MATERIALIZED (
  SELECT set_config('app.traceparent', $1, true) AS traceparent,
         set_config('app.tracestate', $2, true) AS tracestate
)
SELECT queue.tenant_id
FROM trace_context AS trace
CROSS JOIN LATERAL app.list_sla_trigger_action_queues_v1(
  CASE WHEN trace.traceparent = $1 AND trace.tracestate = $2 THEN $3 ELSE NULL::timestamptz END,
  $4
) AS queue
`

const claimSLATriggerActionsQuery = `
WITH trace_context AS MATERIALIZED (
  SELECT set_config('app.traceparent', $1, true) AS traceparent,
         set_config('app.tracestate', $2, true) AS tracestate
)
SELECT claimed.occurrence_id, claimed.tenant_id, claimed.sla_instance_id,
       claimed.metric_instance_id, claimed.trigger_definition_id,
       claimed.action_kind, claimed.deduplication_digest, claimed.fence,
       claimed.attempt, claimed.scheduled_at, claimed.claimed_at,
       claimed.lease_expires_at
FROM trace_context AS trace
CROSS JOIN LATERAL app.claim_sla_trigger_actions_v1(
  CASE WHEN trace.traceparent = $1 AND trace.tracestate = $2 THEN $3 ELSE NULL::uuid END,
  $4, $5, $6, $7
) AS claimed
`

const executeSLATriggerActionQuery = `
WITH trace_context AS MATERIALIZED (
  SELECT set_config('app.traceparent', $1, true) AS traceparent,
         set_config('app.tracestate', $2, true) AS tracestate
)
SELECT app.execute_sla_trigger_action_v1(
  CASE WHEN traceparent = $1 AND tracestate = $2 THEN $3 ELSE NULL::uuid END,
  $4, $5, $6, $7, $8::public.sla_trigger_action_kind, $9
)::text
FROM trace_context
`

const readSLAActionQueueMetricsQuery = `
SELECT metrics.observed_at, metrics.pending_actions,
       metrics.oldest_pending_micros
FROM app.read_sla_trigger_action_queue_metrics_v1() AS metrics
`

const slaActionReadinessQuery = `SELECT app.sla_trigger_action_runtime_schema_readiness_v53()`

type slaActionQuerier interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

// SLAActionRepository calls only the closed worker-role SLA-action ABI. Table
// access is intentionally neither required nor accepted by this adapter.
type SLAActionRepository struct {
	pool slaActionQuerier
}

func NewSLAActionRepository(pool slaActionQuerier) *SLAActionRepository {
	return &SLAActionRepository{pool: pool}
}

var _ slaaction.Repository = (*SLAActionRepository)(nil)

type SLAActionQueueMetrics struct {
	ObservedAt          time.Time
	PendingActions      int64
	OldestPendingMicros int64
}

func (repository *SLAActionRepository) Ready(ctx context.Context) error {
	if repository == nil || repository.pool == nil || ctx == nil || ctx.Err() != nil {
		return slaaction.ErrInvalidInput
	}
	var ready bool
	if err := repository.pool.QueryRow(ctx, slaActionReadinessQuery).Scan(&ready); err != nil || !ready || ctx.Err() != nil {
		return slaaction.ErrUnavailable
	}
	return nil
}

func (repository *SLAActionRepository) ListQueues(
	ctx context.Context,
	observedAt time.Time,
	limit int,
) ([]slaaction.Queue, error) {
	if repository == nil || repository.pool == nil || ctx == nil || ctx.Err() != nil ||
		!validSLAWorkerInstant(observedAt) || limit < 1 || limit > 500 {
		return nil, slaaction.ErrInvalidInput
	}
	traceparent, tracestate := slaTraceContextArguments(ctx)
	rows, err := repository.pool.Query(
		ctx, listSLAActionQueuesQuery, traceparent, tracestate, observedAt, limit,
	)
	if err != nil {
		return nil, slaaction.ErrUnavailable
	}
	defer rows.Close()
	queues := make([]slaaction.Queue, 0, limit)
	seen := make(map[uuid.UUID]struct{}, limit)
	for rows.Next() {
		var tenantID uuid.UUID
		if err := rows.Scan(&tenantID); err != nil || !slaWorkerUUIDv7(tenantID) || len(queues) >= limit {
			return nil, slaaction.ErrUnavailable
		}
		if _, duplicate := seen[tenantID]; duplicate {
			return nil, slaaction.ErrUnavailable
		}
		seen[tenantID] = struct{}{}
		queues = append(queues, slaaction.Queue{TenantID: tenantID})
	}
	if err := rows.Err(); err != nil {
		return nil, slaaction.ErrUnavailable
	}
	return queues, nil
}

func (repository *SLAActionRepository) ReadQueueMetrics(ctx context.Context) (SLAActionQueueMetrics, error) {
	if repository == nil || repository.pool == nil || ctx == nil || ctx.Err() != nil {
		return SLAActionQueueMetrics{}, slaaction.ErrInvalidInput
	}
	var metrics SLAActionQueueMetrics
	err := repository.pool.QueryRow(ctx, readSLAActionQueueMetricsQuery).Scan(
		&metrics.ObservedAt, &metrics.PendingActions, &metrics.OldestPendingMicros,
	)
	if err != nil || !normalizeSLAWorkerInstant(&metrics.ObservedAt) ||
		metrics.PendingActions < 0 || metrics.OldestPendingMicros < 0 ||
		metrics.PendingActions == 0 && metrics.OldestPendingMicros != 0 {
		return SLAActionQueueMetrics{}, slaaction.ErrUnavailable
	}
	return metrics, nil
}

func (repository *SLAActionRepository) Claim(
	ctx context.Context,
	request slaaction.ClaimRequest,
) ([]slaaction.Claim, error) {
	if repository == nil || repository.pool == nil || ctx == nil || ctx.Err() != nil ||
		!validSLAActionIdentity(request.Identity) || !slaWorkerUUIDv7(request.Queue.TenantID) ||
		!validSLAWorkerInstant(request.Now) || request.Limit < 1 || request.Limit > slaaction.MaximumBatchSize ||
		request.LeaseDuration < slaaction.MinimumLease || request.LeaseDuration > slaaction.MaximumLease ||
		request.LeaseDuration%time.Microsecond != 0 {
		return nil, slaaction.ErrInvalidInput
	}
	traceparent, tracestate := slaTraceContextArguments(ctx)
	rows, err := repository.pool.Query(
		ctx, claimSLATriggerActionsQuery, traceparent, tracestate, request.Identity.WorkerID,
		request.Queue.TenantID, request.Now, request.Limit, request.LeaseDuration.Microseconds(),
	)
	if err != nil {
		return nil, slaaction.ErrUnavailable
	}
	defer rows.Close()
	claims := make([]slaaction.Claim, 0, request.Limit)
	for rows.Next() {
		var claim slaaction.Claim
		var actionKind string
		var digest []byte
		var fence int64
		var attempt int32
		if err := rows.Scan(
			&claim.OccurrenceID, &claim.TenantID, &claim.SLAInstanceID,
			&claim.MetricInstanceID, &claim.TriggerDefinitionID, &actionKind,
			&digest, &fence, &attempt, &claim.ScheduledAt, &claim.ClaimedAt,
			&claim.LeaseExpiresAt,
		); err != nil || len(claims) >= request.Limit || len(digest) != len(claim.DeduplicationDigest) ||
			fence < 1 || fence >= math.MaxInt64 || attempt < 1 || attempt > math.MaxUint16 {
			return nil, slaaction.ErrUnavailable
		}
		copy(claim.DeduplicationDigest[:], digest)
		claim.ActionKind = kernel.ActionKind(actionKind)
		claim.Fence = uint64(fence)
		claim.Attempt = uint16(attempt)
		if !normalizeSLAWorkerInstant(&claim.ScheduledAt) || !normalizeSLAWorkerInstant(&claim.ClaimedAt) ||
			!normalizeSLAWorkerInstant(&claim.LeaseExpiresAt) {
			return nil, slaaction.ErrUnavailable
		}
		claims = append(claims, claim)
	}
	if err := rows.Err(); err != nil {
		return nil, slaaction.ErrUnavailable
	}
	return claims, nil
}

func (repository *SLAActionRepository) Execute(
	ctx context.Context,
	request slaaction.ExecuteRequest,
) (slaaction.ExecuteResult, error) {
	claim := request.Claim
	if repository == nil || repository.pool == nil || ctx == nil || ctx.Err() != nil ||
		!validSLAActionIdentity(request.Identity) || !slaWorkerUUIDv7(claim.TenantID) ||
		!slaWorkerUUIDv7(claim.OccurrenceID) || claim.Fence == 0 || claim.Fence >= math.MaxInt64 ||
		claim.DeduplicationDigest == ([32]byte{}) || !validSLAWorkerInstant(request.AppliedAt) {
		return slaaction.ExecuteResult{}, slaaction.ErrInvalidInput
	}
	traceparent, tracestate := slaTraceContextArguments(ctx)
	var disposition string
	err := repository.pool.QueryRow(
		ctx, executeSLATriggerActionQuery, traceparent, tracestate, request.Identity.WorkerID,
		claim.TenantID, claim.OccurrenceID, claim.Fence, claim.DeduplicationDigest[:],
		string(claim.ActionKind), request.AppliedAt,
	).Scan(&disposition)
	if err != nil {
		return slaaction.ExecuteResult{}, slaaction.ErrUnavailable
	}
	result := slaaction.ExecuteResult{}
	switch disposition {
	case "applied":
		result.Outcome = slaaction.OutcomeApplied
	case "replayed":
		result.Outcome = slaaction.OutcomeReplayed
	case "retry_scheduled":
		result.Outcome = slaaction.OutcomeRetryScheduled
	case "dead_lettered":
		result.Outcome = slaaction.OutcomeDeadLettered
	case "fence_lost":
		result.Outcome = slaaction.OutcomeFenceLost
	default:
		return slaaction.ExecuteResult{}, slaaction.ErrUnavailable
	}
	return result, nil
}

func validSLAActionIdentity(identity slaaction.Identity) bool {
	return slaWorkerUUIDv7(identity.WorkerID) && identity.Purpose == slaaction.WorkerPurpose
}
