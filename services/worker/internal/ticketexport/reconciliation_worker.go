package ticketexport

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
)

const (
	ReconcileWorkerPurpose     = "ticket_export_reconcile"
	MaximumReconcileBatchSize  = 100
	MinimumReconcileLease      = 30 * time.Second
	MaximumReconcileLease      = 15 * time.Minute
	MaximumReconcileAttempts   = 100
	MinimumReconcileRetryDelay = time.Second
	MaximumReconcileRetryDelay = 24 * time.Hour
)

type ReconcileReason uint8

const (
	ReconcileExpired ReconcileReason = iota + 1
	ReconcileOrphaned
)

func (reason ReconcileReason) String() string {
	switch reason {
	case ReconcileExpired:
		return "expired"
	case ReconcileOrphaned:
		return "orphaned"
	default:
		return "unknown"
	}
}

type ReconcileIdentity struct {
	ServiceAccountID kernel.EntityID
	WorkerID         kernel.EntityID
	Purpose          string
}

func (identity ReconcileIdentity) String() string {
	return "ticketexport.ReconcileIdentity{identity:[REDACTED],purpose:[REDACTED]}"
}

func (identity ReconcileIdentity) GoString() string { return identity.String() }

type ReconcileClaimRequest struct {
	Identity      ReconcileIdentity
	Queue         Queue
	Now           time.Time
	LeaseDuration time.Duration
	Limit         int
}

func (request ReconcileClaimRequest) String() string {
	return fmt.Sprintf(
		"ticketexport.ReconcileClaimRequest{queue:%s,limit:%d,lease:%s,identity:[REDACTED],time:[REDACTED]}",
		request.Queue, request.Limit, request.LeaseDuration,
	)
}

func (request ReconcileClaimRequest) GoString() string { return request.String() }

// ReconcileClaim is a database-fenced deletion lease. ObjectRevision and
// ObjectAttempt authenticate the immutable S3 metadata; JobRevision and
// CleanupRevision independently bind the current durable cleanup state.
type ReconcileClaim struct {
	Artifact        ReconcileArtifact
	Reason          ReconcileReason
	JobRevision     uint64
	CleanupRevision uint64
	CleanupAttempt  uint8
	CleanupFence    [sha256.Size]byte
	EligibleAt      time.Time
	ClaimedAt       time.Time
	LeaseExpiresAt  time.Time
}

func (claim ReconcileClaim) String() string {
	return fmt.Sprintf(
		"ticketexport.ReconcileClaim{reason:%s,job_revision:%d,cleanup_revision:%d,attempt:%d,artifact:%s,fence:[REDACTED],times:[REDACTED]}",
		claim.Reason, claim.JobRevision, claim.CleanupRevision, claim.CleanupAttempt,
		claim.Artifact,
	)
}

func (claim ReconcileClaim) GoString() string { return claim.String() }

type ReconcileFinalizeRequest struct {
	Identity ReconcileIdentity
	Claim    ReconcileClaim
	PurgedAt time.Time
}

type ReconcileFinalizeDisposition uint8

const (
	ReconcileFinalizeApplied ReconcileFinalizeDisposition = iota + 1
	ReconcileFinalizeReplayed
	ReconcileFinalizeFenceLost
)

type ReconcileFinalizeResult struct {
	Disposition            ReconcileFinalizeDisposition
	CurrentCleanupRevision uint64
	ArtifactID             kernel.EntityID
	Reason                 ReconcileReason
	CleanupFence           [sha256.Size]byte
}

type ReconcileFailureCode uint8

const (
	ReconcileFailureStorageUnavailable ReconcileFailureCode = iota + 1
	ReconcileFailureObjectConflict
)

func (code ReconcileFailureCode) String() string {
	switch code {
	case ReconcileFailureStorageUnavailable:
		return "storage_unavailable"
	case ReconcileFailureObjectConflict:
		return "object_conflict"
	default:
		return "unknown"
	}
}

type ReconcileFailureRequest struct {
	Identity ReconcileIdentity
	Claim    ReconcileClaim
	Code     ReconcileFailureCode
	FailedAt time.Time
	RetryAt  time.Time
}

type ReconcileFailureDisposition uint8

const (
	ReconcileFailureRetryScheduled ReconcileFailureDisposition = iota + 1
	ReconcileFailureDeadLettered
	ReconcileFailureReplayRetry
	ReconcileFailureReplayDeadLetter
	ReconcileFailureFenceLost
)

type ReconcileFailureResult struct {
	Disposition            ReconcileFailureDisposition
	CurrentCleanupRevision uint64
	Code                   ReconcileFailureCode
	RetryAt                time.Time
	ArtifactID             kernel.EntityID
	Reason                 ReconcileReason
	CleanupFence           [sha256.Size]byte
}

// ReconcileRepository may operate only through closed, worker-role functions.
// Claim is scoped to one explicit tenant/kind/audience queue. Finalize must
// atomically close the ledger, expire the user-visible job when applicable,
// and append redacted audit. Failure transitions CAS the same cleanup fence.
type ReconcileRepository interface {
	ClaimArtifactReconciliation(context.Context, ReconcileClaimRequest) ([]ReconcileClaim, error)
	FinalizeArtifactReconciliation(context.Context, ReconcileFinalizeRequest) (ReconcileFinalizeResult, error)
	ReportArtifactReconciliationFailure(context.Context, ReconcileFailureRequest) (ReconcileFailureResult, error)
}

type ReconcileOptions struct {
	Repository       ReconcileRepository
	Artifacts        ArtifactReconciler
	Identity         ReconcileIdentity
	BatchSize        int
	MaximumAttempts  int
	LeaseDuration    time.Duration
	OperationTimeout time.Duration
	LeaseSafety      time.Duration
	RetryBase        time.Duration
	RetryMaximum     time.Duration
	Clock            func() time.Time
}

func (options ReconcileOptions) String() string {
	return "ticketexport.ReconcileOptions{dependencies:[REDACTED],identity:[REDACTED],configuration:[REDACTED]}"
}

func (options ReconcileOptions) GoString() string { return options.String() }

type Reconciler struct {
	repository       ReconcileRepository
	artifacts        ArtifactReconciler
	identity         ReconcileIdentity
	batchSize        int
	maximumAttempts  int
	leaseDuration    time.Duration
	operationTimeout time.Duration
	leaseSafety      time.Duration
	retryBase        time.Duration
	retryMaximum     time.Duration
	clock            func() time.Time
	sourceMu         sync.Mutex
}

type ReconcileSummary struct {
	Claimed        int
	Purged         int
	Replayed       int
	RetryScheduled int
	DeadLettered   int
	FenceLost      int
}

func (summary ReconcileSummary) String() string {
	return fmt.Sprintf(
		"ticketexport.ReconcileSummary{claimed:%d,purged:%d,replayed:%d,retry_scheduled:%d,dead_lettered:%d,fence_lost:%d}",
		summary.Claimed, summary.Purged, summary.Replayed, summary.RetryScheduled,
		summary.DeadLettered, summary.FenceLost,
	)
}

func (summary ReconcileSummary) GoString() string { return summary.String() }

func NewReconciler(options ReconcileOptions) (*Reconciler, error) {
	if nilInterface(options.Repository) || nilInterface(options.Artifacts) ||
		!validReconcileIdentity(options.Identity) || options.Clock == nil ||
		options.BatchSize < 1 || options.BatchSize > MaximumReconcileBatchSize ||
		options.MaximumAttempts < 1 || options.MaximumAttempts > MaximumReconcileAttempts ||
		options.LeaseDuration < MinimumReconcileLease || options.LeaseDuration > MaximumReconcileLease ||
		options.OperationTimeout < time.Second || options.OperationTimeout > 5*time.Minute ||
		options.LeaseSafety < time.Second || options.LeaseSafety > time.Minute ||
		options.OperationTimeout+options.LeaseSafety > options.LeaseDuration ||
		options.RetryBase < MinimumReconcileRetryDelay || options.RetryBase > MaximumReconcileRetryDelay ||
		options.RetryMaximum < options.RetryBase || options.RetryMaximum > MaximumReconcileRetryDelay ||
		options.LeaseDuration%time.Microsecond != 0 || options.OperationTimeout%time.Microsecond != 0 ||
		options.LeaseSafety%time.Microsecond != 0 || options.RetryBase%time.Microsecond != 0 ||
		options.RetryMaximum%time.Microsecond != 0 {
		return nil, ErrInvalidConfiguration
	}
	return &Reconciler{
		repository: options.Repository, artifacts: options.Artifacts, identity: options.Identity,
		batchSize: options.BatchSize, maximumAttempts: options.MaximumAttempts,
		leaseDuration: options.LeaseDuration, operationTimeout: options.OperationTimeout,
		leaseSafety: options.LeaseSafety, retryBase: options.RetryBase,
		retryMaximum: options.RetryMaximum, clock: options.Clock,
	}, nil
}

func (worker *Reconciler) RunOnce(ctx context.Context, queue Queue) (ReconcileSummary, error) {
	if worker == nil || ctx == nil || ctx.Err() != nil || !validQueue(queue) {
		return ReconcileSummary{}, ErrInvalidInput
	}
	now := worker.now()
	if !validInstant(now) {
		return ReconcileSummary{}, ErrInvalidConfiguration
	}
	claimContext, cancelClaim := context.WithTimeout(ctx, worker.operationTimeout)
	claims, err := worker.repository.ClaimArtifactReconciliation(claimContext, ReconcileClaimRequest{
		Identity: worker.identity, Queue: queue, Now: now,
		LeaseDuration: worker.leaseDuration, Limit: worker.batchSize,
	})
	claimContextErr := claimContext.Err()
	cancelClaim()
	if err != nil || claimContextErr != nil {
		if ctx.Err() != nil {
			return ReconcileSummary{}, ErrInterrupted
		}
		return ReconcileSummary{}, ErrUnavailable
	}
	if !validReconcileClaims(claims, queue, now, worker.leaseDuration, worker.batchSize, worker.maximumAttempts) {
		return ReconcileSummary{Claimed: len(claims)}, ErrInvalidProjection
	}
	summary := ReconcileSummary{Claimed: len(claims)}
	for _, claim := range claims {
		if ctx.Err() != nil {
			return summary, ErrInterrupted
		}
		startedAt := worker.now()
		purgeContext, cancelPurge, ok := worker.operationContext(ctx, claim, startedAt, false)
		if !ok {
			return summary, ErrInvalidProjection
		}
		purgeErr := worker.artifacts.PurgeArtifact(purgeContext, claim.Artifact)
		purgeContextErr := purgeContext.Err()
		cancelPurge()
		if purgeErr != nil || purgeContextErr != nil {
			if ctx.Err() != nil {
				return summary, ErrInterrupted
			}
			if err := worker.recordFailure(ctx, claim, purgeErr, &summary); err != nil {
				return summary, err
			}
			continue
		}
		if err := worker.finalize(ctx, claim, &summary); err != nil {
			return summary, err
		}
	}
	return summary, nil
}

func (worker *Reconciler) finalize(
	ctx context.Context,
	claim ReconcileClaim,
	summary *ReconcileSummary,
) error {
	purgedAt := worker.now()
	operationContext, cancelOperation, ok := worker.operationContext(ctx, claim, purgedAt, true)
	if !ok {
		return ErrTransitionOutcomeUnknown
	}
	result, err := worker.repository.FinalizeArtifactReconciliation(
		operationContext,
		ReconcileFinalizeRequest{Identity: worker.identity, Claim: claim, PurgedAt: purgedAt},
	)
	operationContextErr := operationContext.Err()
	cancelOperation()
	if err != nil || operationContextErr != nil {
		return ErrTransitionOutcomeUnknown
	}
	nextRevision, validRevision := reconcileRevisionSuccessor(claim.CleanupRevision)
	switch result.Disposition {
	case ReconcileFinalizeApplied:
		if !validRevision || result.CurrentCleanupRevision != nextRevision ||
			!reconcileFinalizeEchoMatches(result, claim) {
			return ErrTransitionOutcomeUnknown
		}
		summary.Purged++
	case ReconcileFinalizeReplayed:
		if !validRevision || result.CurrentCleanupRevision != nextRevision ||
			!reconcileFinalizeEchoMatches(result, claim) {
			return ErrTransitionOutcomeUnknown
		}
		summary.Replayed++
	case ReconcileFinalizeFenceLost:
		if result.CurrentCleanupRevision != 0 || result.ArtifactID != (kernel.EntityID{}) ||
			result.Reason != 0 || result.CleanupFence != ([sha256.Size]byte{}) {
			return ErrTransitionOutcomeUnknown
		}
		summary.FenceLost++
	default:
		return ErrTransitionOutcomeUnknown
	}
	return nil
}

func (worker *Reconciler) recordFailure(
	ctx context.Context,
	claim ReconcileClaim,
	purgeErr error,
	summary *ReconcileSummary,
) error {
	failedAt := worker.now()
	code := ReconcileFailureStorageUnavailable
	if errors.Is(purgeErr, ErrArtifactConflict) {
		code = ReconcileFailureObjectConflict
	}
	var retryAt time.Time
	if code == ReconcileFailureStorageUnavailable && int(claim.CleanupAttempt) < worker.maximumAttempts {
		retryAt = failedAt.Add(worker.retryDelay(claim.CleanupAttempt, claim.CleanupFence))
	}
	operationContext, cancelOperation, ok := worker.operationContext(ctx, claim, failedAt, true)
	if !ok {
		return ErrTransitionOutcomeUnknown
	}
	result, err := worker.repository.ReportArtifactReconciliationFailure(
		operationContext,
		ReconcileFailureRequest{
			Identity: worker.identity, Claim: claim, Code: code,
			FailedAt: failedAt, RetryAt: retryAt,
		},
	)
	operationContextErr := operationContext.Err()
	cancelOperation()
	if err != nil || operationContextErr != nil {
		return ErrTransitionOutcomeUnknown
	}
	nextRevision, validRevision := reconcileRevisionSuccessor(claim.CleanupRevision)
	switch result.Disposition {
	case ReconcileFailureRetryScheduled, ReconcileFailureReplayRetry:
		if !validRevision || retryAt.IsZero() || result.CurrentCleanupRevision != nextRevision ||
			result.Code != code || !result.RetryAt.Equal(retryAt) ||
			!reconcileFailureEchoMatches(result, claim) {
			return ErrTransitionOutcomeUnknown
		}
		summary.RetryScheduled++
	case ReconcileFailureDeadLettered, ReconcileFailureReplayDeadLetter:
		if !validRevision || !retryAt.IsZero() || result.CurrentCleanupRevision != nextRevision ||
			result.Code != code || !result.RetryAt.IsZero() ||
			!reconcileFailureEchoMatches(result, claim) {
			return ErrTransitionOutcomeUnknown
		}
		summary.DeadLettered++
	case ReconcileFailureFenceLost:
		if result.CurrentCleanupRevision != 0 || result.Code != 0 || !result.RetryAt.IsZero() ||
			result.ArtifactID != (kernel.EntityID{}) || result.Reason != 0 ||
			result.CleanupFence != ([sha256.Size]byte{}) {
			return ErrTransitionOutcomeUnknown
		}
		summary.FenceLost++
	default:
		return ErrTransitionOutcomeUnknown
	}
	return nil
}

func (worker *Reconciler) operationContext(
	ctx context.Context,
	claim ReconcileClaim,
	startedAt time.Time,
	detached bool,
) (context.Context, context.CancelFunc, bool) {
	if !validInstant(startedAt) || startedAt.Before(claim.ClaimedAt) {
		return nil, nil, false
	}
	deadline := startedAt.Add(worker.operationTimeout)
	leaseDeadline := claim.LeaseExpiresAt.Add(-worker.leaseSafety)
	if leaseDeadline.Before(deadline) {
		deadline = leaseDeadline
	}
	if !deadline.After(startedAt) {
		return nil, nil, false
	}
	base := ctx
	if detached {
		base = context.WithoutCancel(ctx)
	}
	operationContext, cancel := context.WithTimeout(base, deadline.Sub(startedAt))
	return operationContext, cancel, true
}

func (worker *Reconciler) retryDelay(attempt uint8, fence [sha256.Size]byte) time.Duration {
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
	if ceiling <= MinimumReconcileRetryDelay {
		return MinimumReconcileRetryDelay
	}
	span := ceiling - MinimumReconcileRetryDelay
	seed := [sha256.Size + 1]byte{}
	copy(seed[:sha256.Size], fence[:])
	seed[sha256.Size] = attempt
	digest := sha256.Sum256(seed[:])
	spanMicros := uint64(span / time.Microsecond)
	offsetMicros := binary.BigEndian.Uint64(digest[:8]) % (spanMicros + 1)
	return MinimumReconcileRetryDelay + time.Duration(offsetMicros)*time.Microsecond
}

func (worker *Reconciler) now() time.Time {
	worker.sourceMu.Lock()
	now := worker.clock().UTC().Truncate(time.Microsecond)
	worker.sourceMu.Unlock()
	return now
}

func reconcileFinalizeEchoMatches(result ReconcileFinalizeResult, claim ReconcileClaim) bool {
	return result.ArtifactID == claim.Artifact.ArtifactID && result.Reason == claim.Reason &&
		result.CleanupFence == claim.CleanupFence
}

func reconcileFailureEchoMatches(result ReconcileFailureResult, claim ReconcileClaim) bool {
	return result.ArtifactID == claim.Artifact.ArtifactID && result.Reason == claim.Reason &&
		result.CleanupFence == claim.CleanupFence
}

func validReconcileIdentity(identity ReconcileIdentity) bool {
	return validEntityID(identity.ServiceAccountID) && validEntityID(identity.WorkerID) &&
		identity.Purpose == ReconcileWorkerPurpose
}

func validReconcileClaims(
	claims []ReconcileClaim,
	queue Queue,
	now time.Time,
	lease time.Duration,
	limit int,
	maximumAttempts int,
) bool {
	if len(claims) > limit {
		return false
	}
	seen := make(map[kernel.EntityID]struct{}, len(claims))
	for _, claim := range claims {
		if !validReconcileArtifact(claim.Artifact) || claim.Artifact.TenantID != queue.TenantID ||
			claim.Artifact.Kind != queue.Kind || claim.Artifact.Audience != queue.Audience ||
			(claim.Reason != ReconcileExpired && claim.Reason != ReconcileOrphaned) ||
			claim.JobRevision == 0 || claim.JobRevision >= math.MaxInt64 ||
			claim.CleanupRevision == 0 || claim.CleanupRevision >= math.MaxInt64 ||
			claim.CleanupAttempt == 0 || int(claim.CleanupAttempt) > maximumAttempts ||
			claim.CleanupFence == ([sha256.Size]byte{}) || !validInstant(claim.EligibleAt) ||
			claim.EligibleAt.After(now) || !claim.ClaimedAt.Equal(now) ||
			!validInstant(claim.LeaseExpiresAt) || !claim.LeaseExpiresAt.Equal(now.Add(lease)) {
			return false
		}
		if _, duplicate := seen[claim.Artifact.ArtifactID]; duplicate {
			return false
		}
		seen[claim.Artifact.ArtifactID] = struct{}{}
	}
	return true
}

func reconcileRevisionSuccessor(revision uint64) (uint64, bool) {
	if revision == 0 || revision >= math.MaxInt64 {
		return 0, false
	}
	return revision + 1, true
}

func (*Reconciler) String() string {
	return "ticketexport.Reconciler{dependencies:[REDACTED],identity:[REDACTED],configuration:[REDACTED]}"
}

func (worker *Reconciler) GoString() string { return worker.String() }
