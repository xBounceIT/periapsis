package ticketexport

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"slices"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
)

type Worker struct {
	repository       Repository
	artifacts        ArtifactStore
	identity         Identity
	pageSize         int
	leaseDuration    time.Duration
	attemptTimeout   time.Duration
	operationTimeout time.Duration
	leaseSafety      time.Duration
	cleanupTimeout   time.Duration
	cleanupAttempts  int
	retryBase        time.Duration
	retryMaximum     time.Duration
	clock            func() time.Time
	newArtifactID    func() (kernel.EntityID, error)
	sourceMu         sync.Mutex
}

func New(options Options) (*Worker, error) {
	if nilInterface(options.Repository) || nilInterface(options.Artifacts) ||
		!validIdentity(options.Identity) || options.PageSize < 1 || options.PageSize > MaximumPageSize ||
		options.LeaseDuration < kernel.TicketExportMinimumLease ||
		options.LeaseDuration > kernel.TicketExportMaximumLease ||
		options.LeaseDuration%time.Microsecond != 0 ||
		options.AttemptTimeout < time.Second || options.AttemptTimeout > options.LeaseDuration ||
		options.AttemptTimeout%time.Microsecond != 0 ||
		options.OperationTimeout < time.Second || options.OperationTimeout > 5*time.Minute ||
		options.OperationTimeout > options.AttemptTimeout || options.OperationTimeout%time.Microsecond != 0 ||
		options.LeaseSafety < time.Second || options.LeaseSafety > time.Minute ||
		options.LeaseSafety%time.Microsecond != 0 ||
		options.AttemptTimeout+options.LeaseSafety > options.LeaseDuration ||
		options.CleanupTimeout < time.Second || options.CleanupTimeout > time.Minute ||
		options.CleanupTimeout%time.Microsecond != 0 ||
		options.CleanupAttempts < 1 || options.CleanupAttempts > maximumCleanupAttempts ||
		options.RetryBase < kernel.TicketExportMinimumRetry ||
		options.RetryBase > kernel.TicketExportMaximumRetry ||
		options.RetryMaximum < options.RetryBase ||
		options.RetryMaximum > kernel.TicketExportMaximumRetry ||
		options.RetryBase%time.Microsecond != 0 || options.RetryMaximum%time.Microsecond != 0 ||
		options.Clock == nil || options.NewArtifactID == nil {
		return nil, ErrInvalidConfiguration
	}
	now := options.Clock().UTC().Truncate(time.Microsecond)
	if !validInstant(now) {
		return nil, ErrInvalidConfiguration
	}
	return &Worker{
		repository: options.Repository, artifacts: options.Artifacts, identity: options.Identity,
		pageSize: options.PageSize, leaseDuration: options.LeaseDuration,
		attemptTimeout: options.AttemptTimeout, operationTimeout: options.OperationTimeout,
		leaseSafety: options.LeaseSafety, cleanupTimeout: options.CleanupTimeout,
		cleanupAttempts: options.CleanupAttempts, retryBase: options.RetryBase,
		retryMaximum: options.RetryMaximum, clock: options.Clock,
		newArtifactID: options.NewArtifactID,
	}, nil
}

func (worker *Worker) RunOnce(ctx context.Context, queue Queue) (Result, error) {
	if worker == nil || ctx == nil || !validQueue(queue) {
		return Result{}, ErrInvalidInput
	}
	if ctx.Err() != nil {
		return Result{Outcome: OutcomeInterrupted}, ErrInterrupted
	}
	claimedAt := worker.now()
	if !validInstant(claimedAt) {
		return Result{}, ErrUnavailable
	}
	artifactID, err := worker.artifactID()
	if err != nil {
		return Result{}, ErrUnavailable
	}
	claimContext, cancelClaim := context.WithTimeout(ctx, worker.operationTimeout)
	claim, found, err := worker.repository.Claim(claimContext, ClaimRequest{
		Identity: worker.identity, Queue: queue, ArtifactID: artifactID,
		Now: claimedAt, LeaseDuration: worker.leaseDuration,
	})
	claimContextErr := claimContext.Err()
	cancelClaim()
	if err != nil || claimContextErr != nil {
		if ctx.Err() != nil {
			return Result{Outcome: OutcomeInterrupted},
				errors.Join(ErrTransitionOutcomeUnknown, ErrInterrupted)
		}
		return Result{}, errors.Join(ErrTransitionOutcomeUnknown, ErrUnavailable)
	}
	if ctx.Err() != nil {
		return Result{Claimed: found, Outcome: OutcomeInterrupted}, ErrInterrupted
	}
	if !found {
		if !emptyClaim(claim) {
			return Result{}, ErrInvalidProjection
		}
		return Result{Outcome: OutcomeIdle}, nil
	}
	attemptStartedAt := worker.now()
	if !validInstant(attemptStartedAt) {
		return Result{Claimed: true}, ErrTransitionOutcomeUnknown
	}
	claim, binding, err := worker.normalizeClaim(claim, queue, artifactID, attemptStartedAt)
	if err != nil {
		return Result{Claimed: true}, err
	}
	result := Result{Claimed: true}
	attemptDeadline := binding.LeaseExpiresAt.Add(-worker.leaseSafety)
	maximumDeadline := attemptStartedAt.Add(worker.attemptTimeout)
	if maximumDeadline.Before(attemptDeadline) {
		attemptDeadline = maximumDeadline
	}
	if !attemptDeadline.After(attemptStartedAt) {
		return result, ErrInvalidProjection
	}
	attemptContext, cancelAttempt := context.WithDeadline(ctx, attemptDeadline)
	defer cancelAttempt()

	openContext, cancelOpen := context.WithTimeout(attemptContext, worker.operationTimeout)
	object, err := worker.artifacts.OpenTemporary(openContext, attemptContext, TemporaryRequest{
		Identity: worker.identity, Binding: binding, ArtifactID: artifactID,
		MaximumBytes: claim.Job.Definition().MaximumBytes(),
	})
	openContextErr := openContext.Err()
	cancelOpen()
	if err != nil || openContextErr != nil || nilInterface(object) {
		if nilInterface(object) {
			object = nil
		}
		if ctx.Err() != nil {
			return worker.interrupt(ctx, object)
		}
		return worker.reportFailure(ctx, claim, binding, object, kernel.TicketExportFailureTransientStorage, nil)
	}

	encoder, err := kernel.NewTicketExportCSVEncoder(object, claim.Job.Definition(), claim.Header)
	if err != nil {
		code := kernel.TicketExportFailureSnapshotStale
		if errors.Is(err, kernel.ErrTicketExportOutputLimit) {
			code = kernel.TicketExportFailureOutputLimit
		} else if errors.Is(err, kernel.ErrTicketExportWriteFailed) {
			code = kernel.TicketExportFailureTransientStorage
		}
		return worker.reportFailure(ctx, claim, binding, object, code, nil)
	}

	stats, result, err := worker.streamPages(attemptContext, ctx, claim, binding, encoder, object)
	if err != nil || result.Outcome != OutcomeUnknown {
		return result, err
	}
	manifest := StreamManifest{
		ArtifactID: artifactID, Digest: stats.Digest, Rows: stats.Rows, Bytes: stats.Bytes,
	}
	continueAttempt, manifestResult, manifestErr := worker.recordManifest(
		attemptContext, ctx, claim, binding, object, manifest,
	)
	if !continueAttempt {
		return manifestResult, manifestErr
	}
	sealContext, cancelSeal := context.WithTimeout(attemptContext, worker.operationTimeout)
	sealErr := object.Seal(sealContext, manifest)
	sealContextErr := sealContext.Err()
	cancelSeal()
	if sealErr != nil || sealContextErr != nil {
		if ctx.Err() != nil {
			return worker.interrupt(ctx, object)
		}
		return worker.reportFailure(ctx, claim, binding, object, kernel.TicketExportFailureTransientStorage, nil)
	}
	promoteContext, cancelPromote := context.WithTimeout(attemptContext, worker.operationTimeout)
	promotion, promoteErr := object.Promote(promoteContext, artifactID)
	promoteContextErr := promoteContext.Err()
	cancelPromote()
	if promoteErr != nil || promoteContextErr != nil {
		// Promotion errors are outcome-ambiguous. The object may already be at
		// its final tenant-prefixed key, so deleting it here is unsafe. It is
		// unreferenced and inaccessible until the fenced DB commit succeeds;
		// the storage adapter's orphan collector owns reconciliation.
		if ctx.Err() != nil {
			return Result{Claimed: true, Outcome: OutcomeInterrupted},
				errors.Join(ErrInterrupted, ErrPublicationOutcomeUnknown)
		}
		return worker.reportFailure(
			ctx, claim, binding, nil, kernel.TicketExportFailureTransientStorage,
			ErrPublicationOutcomeUnknown,
		)
	}
	if promotion == PromotionRejected {
		return worker.reportFailure(ctx, claim, binding, object, kernel.TicketExportFailureTransientStorage, nil)
	}
	if promotion != PromotionApplied && promotion != PromotionReplayed {
		return worker.reportFailure(
			ctx, claim, binding, nil, kernel.TicketExportFailureTransientStorage,
			ErrPublicationOutcomeUnknown,
		)
	}
	if ctx.Err() != nil {
		return Result{Claimed: true, Outcome: OutcomeInterrupted}, ErrInterrupted
	}
	if attemptContext.Err() != nil {
		return worker.reportPublishedFailure(
			ctx, claim, binding, object, artifactID,
			kernel.TicketExportFailureTransientStorage, nil,
		)
	}

	completedAt := worker.now()
	if !validAttemptInstant(binding, completedAt) {
		return worker.reportPublishedFailure(
			ctx, claim, binding, object, artifactID,
			kernel.TicketExportFailureInternal, nil,
		)
	}
	finishContext, cancelFinish := context.WithTimeout(attemptContext, worker.operationTimeout)
	commit, commitErr := worker.repository.CommitSuccess(finishContext, SuccessRequest{
		Identity: worker.identity, Binding: binding, ArtifactID: artifactID,
		Digest: stats.Digest, Rows: stats.Rows, Bytes: stats.Bytes,
		ExpiresAt: binding.JobExpiresAt, CompletedAt: completedAt,
	})
	finishContextErr := finishContext.Err()
	cancelFinish()
	if commitErr != nil || finishContextErr != nil {
		// A response can be lost after the transaction commits. Retaining the
		// promoted object is mandatory; deleting it could corrupt a succeeded
		// export. A later claim/reconciliation observes the durable state.
		if ctx.Err() != nil {
			return Result{Claimed: true, Outcome: OutcomeInterrupted},
				errors.Join(ErrCommitOutcomeUnknown, ErrInterrupted)
		}
		return Result{Claimed: true}, ErrCommitOutcomeUnknown
	}
	return worker.handleCommit(ctx, claim, binding, object, manifest, commit)
}

func (worker *Worker) streamPages(
	attemptContext context.Context,
	parentContext context.Context,
	claim Claim,
	binding LeaseBinding,
	encoder *kernel.TicketExportCSVEncoder,
	object TemporaryArtifact,
) (kernel.TicketExportCSVStats, Result, error) {
	after := ""
	written := uint32(0)
	seenCursors := make(map[[sha256.Size]byte]struct{})
	seenRows := make(map[[sha256.Size]byte]struct{})
	for {
		if parentContext.Err() != nil {
			result, err := worker.interrupt(parentContext, object)
			return kernel.TicketExportCSVStats{}, result, err
		}
		if attemptContext.Err() != nil {
			result, err := worker.reportFailure(
				parentContext, claim, binding, object, kernel.TicketExportFailureInternal, nil,
			)
			return kernel.TicketExportCSVStats{}, result, err
		}
		remaining := claim.Job.Definition().MaximumRows() - written
		if remaining == 0 && after != "" {
			result, err := worker.reportFailure(
				parentContext, claim, binding, object, kernel.TicketExportFailureOutputLimit, nil,
			)
			return kernel.TicketExportCSVStats{}, result, err
		}
		limit := worker.pageSize
		if uint32(limit) > remaining {
			limit = int(remaining)
		}
		if limit == 0 {
			limit = 1
		}
		pageContext, cancelPage := context.WithTimeout(attemptContext, worker.operationTimeout)
		page, err := worker.repository.ReadPage(pageContext, PageRequest{
			Identity: worker.identity, Binding: binding, After: after, Limit: limit,
		})
		pageContextErr := pageContext.Err()
		cancelPage()
		if err != nil || pageContextErr != nil {
			if parentContext.Err() != nil {
				result, interruptErr := worker.interrupt(parentContext, object)
				return kernel.TicketExportCSVStats{}, result, interruptErr
			}
			result, failureErr := worker.reportFailure(
				parentContext, claim, binding, object,
				kernel.TicketExportFailureTransientDatabase, nil,
			)
			return kernel.TicketExportCSVStats{}, result, failureErr
		}
		switch page.Control {
		case PageReady:
			if page.ControlRevision != 0 || !validPage(page.Page, after, limit, claim.Job.Definition(), len(claim.Header)) {
				result, failureErr := worker.reportFailure(
					parentContext, claim, binding, object,
					kernel.TicketExportFailureSnapshotStale, nil,
				)
				return kernel.TicketExportCSVStats{}, result, failureErr
			}
			if !rememberRows(page.Page.Rows, seenRows) {
				result, failureErr := worker.reportFailure(
					parentContext, claim, binding, object,
					kernel.TicketExportFailureSnapshotStale, nil,
				)
				return kernel.TicketExportCSVStats{}, result, failureErr
			}
			if page.Page.NextCursor != "" {
				cursorDigest := sha256.Sum256([]byte(page.Page.NextCursor))
				if _, repeated := seenCursors[cursorDigest]; repeated {
					result, failureErr := worker.reportFailure(
						parentContext, claim, binding, object,
						kernel.TicketExportFailureSnapshotStale, nil,
					)
					return kernel.TicketExportCSVStats{}, result, failureErr
				}
				seenCursors[cursorDigest] = struct{}{}
			}
		case PageCancellationRequested:
			if !validControlPage(page, binding, true) {
				result, failureErr := worker.reportFailure(
					parentContext, claim, binding, object,
					kernel.TicketExportFailureSnapshotStale, nil,
				)
				return kernel.TicketExportCSVStats{}, result, failureErr
			}
			result, transitionErr := worker.acknowledgeCancellation(
				parentContext, binding, page.ControlRevision,
			)
			cleanupErr := worker.abort(parentContext, object)
			return kernel.TicketExportCSVStats{}, result, errors.Join(transitionErr, cleanupErr)
		case PageAuthorizationRevoked:
			if !validControlPage(page, binding, false) {
				result, failureErr := worker.reportFailure(
					parentContext, claim, binding, object,
					kernel.TicketExportFailureSnapshotStale, nil,
				)
				return kernel.TicketExportCSVStats{}, result, failureErr
			}
			result, transitionErr := worker.rejectRevoked(
				parentContext, binding, page.ControlRevision,
			)
			cleanupErr := worker.abort(parentContext, object)
			return kernel.TicketExportCSVStats{}, result, errors.Join(transitionErr, cleanupErr)
		case PageFenceLost:
			if !emptyControlPage(page) || page.ControlRevision != 0 {
				result, failureErr := worker.reportFailure(
					parentContext, claim, binding, object,
					kernel.TicketExportFailureSnapshotStale, nil,
				)
				return kernel.TicketExportCSVStats{}, result, failureErr
			}
			cleanupErr := worker.abort(parentContext, object)
			return kernel.TicketExportCSVStats{},
				Result{Claimed: true, Outcome: OutcomeFenceLost}, errors.Join(ErrFenceLost, cleanupErr)
		case PageSnapshotStale:
			if !emptyControlPage(page) || page.ControlRevision != 0 {
				result, failureErr := worker.reportFailure(
					parentContext, claim, binding, object,
					kernel.TicketExportFailureSnapshotStale, nil,
				)
				return kernel.TicketExportCSVStats{}, result, failureErr
			}
			result, failureErr := worker.reportFailure(
				parentContext, claim, binding, object, kernel.TicketExportFailureSnapshotStale, nil,
			)
			return kernel.TicketExportCSVStats{}, result, failureErr
		default:
			result, failureErr := worker.reportFailure(
				parentContext, claim, binding, object, kernel.TicketExportFailureSnapshotStale, nil,
			)
			return kernel.TicketExportCSVStats{}, result, failureErr
		}

		for _, row := range page.Page.Rows {
			if parentContext.Err() != nil {
				result, interruptErr := worker.interrupt(parentContext, object)
				return kernel.TicketExportCSVStats{}, result, interruptErr
			}
			if attemptContext.Err() != nil {
				result, failureErr := worker.reportFailure(
					parentContext, claim, binding, object, kernel.TicketExportFailureInternal, nil,
				)
				return kernel.TicketExportCSVStats{}, result, failureErr
			}
			if err := encoder.WriteRow(row.Cells); err != nil {
				code := kernel.TicketExportFailureSnapshotStale
				if errors.Is(err, kernel.ErrTicketExportOutputLimit) {
					code = kernel.TicketExportFailureOutputLimit
				} else if errors.Is(err, kernel.ErrTicketExportWriteFailed) {
					code = kernel.TicketExportFailureTransientStorage
				}
				result, failureErr := worker.reportFailure(parentContext, claim, binding, object, code, nil)
				return kernel.TicketExportCSVStats{}, result, failureErr
			}
			written++
			if parentContext.Err() != nil {
				result, interruptErr := worker.interrupt(parentContext, object)
				return kernel.TicketExportCSVStats{}, result, interruptErr
			}
		}
		if page.Page.NextCursor == "" {
			stats, err := encoder.Close()
			if err != nil {
				code := kernel.TicketExportFailureTransientStorage
				if errors.Is(err, kernel.ErrTicketExportOutputLimit) {
					code = kernel.TicketExportFailureOutputLimit
				}
				result, failureErr := worker.reportFailure(parentContext, claim, binding, object, code, nil)
				return kernel.TicketExportCSVStats{}, result, failureErr
			}
			if stats.Rows != written || stats.Bytes == 0 || stats.Digest == ([32]byte{}) {
				result, failureErr := worker.reportFailure(
					parentContext, claim, binding, object, kernel.TicketExportFailureInternal, nil,
				)
				return kernel.TicketExportCSVStats{}, result, failureErr
			}
			return stats, Result{Claimed: true}, nil
		}
		after = page.Page.NextCursor
	}
}

func (worker *Worker) handleCommit(
	ctx context.Context,
	claim Claim,
	binding LeaseBinding,
	object TemporaryArtifact,
	manifest StreamManifest,
	commit CommitResult,
) (Result, error) {
	nextRevision, validRevision := revisionSuccessor(binding.Revision)
	switch commit.Disposition {
	case CommitApplied, CommitReplayed:
		if !validRevision || commit.CurrentRevision != nextRevision || commit.Manifest != manifest {
			return Result{Claimed: true}, ErrCommitOutcomeUnknown
		}
		return Result{
			Claimed: true, Outcome: OutcomeSucceeded, Rows: manifest.Rows, Bytes: manifest.Bytes,
		}, nil
	case CommitCancellationRequested:
		if !validRevision || commit.CurrentRevision != nextRevision || commit.Manifest != (StreamManifest{}) {
			return Result{Claimed: true}, ErrCommitOutcomeUnknown
		}
		result, transitionErr := worker.acknowledgeCancellation(ctx, binding, commit.CurrentRevision)
		cleanupErr := worker.purge(ctx, object, manifest.ArtifactID)
		return result, errors.Join(transitionErr, cleanupErr)
	case CommitAuthorizationRevoked:
		if commit.CurrentRevision != binding.Revision || commit.Manifest != (StreamManifest{}) {
			return Result{Claimed: true}, ErrCommitOutcomeUnknown
		}
		result, transitionErr := worker.rejectRevoked(ctx, binding, commit.CurrentRevision)
		cleanupErr := worker.purge(ctx, object, manifest.ArtifactID)
		return result, errors.Join(transitionErr, cleanupErr)
	case CommitFenceLost:
		if commit.CurrentRevision != 0 || commit.Manifest != (StreamManifest{}) {
			return Result{Claimed: true}, ErrCommitOutcomeUnknown
		}
		cleanupErr := worker.purge(ctx, object, manifest.ArtifactID)
		return Result{Claimed: true, Outcome: OutcomeFenceLost}, errors.Join(ErrFenceLost, cleanupErr)
	case CommitSnapshotStale:
		if commit.CurrentRevision != 0 || commit.Manifest != (StreamManifest{}) {
			return Result{Claimed: true}, ErrCommitOutcomeUnknown
		}
		return worker.reportPublishedFailure(
			ctx, claim, binding, object, manifest.ArtifactID,
			kernel.TicketExportFailureSnapshotStale, nil,
		)
	default:
		// An invalid success response is also outcome-ambiguous. Preserve the
		// promoted object until durable reconciliation proves it is orphaned.
		return Result{Claimed: true}, ErrCommitOutcomeUnknown
	}
}

func (worker *Worker) recordManifest(
	attemptContext context.Context,
	parentContext context.Context,
	claim Claim,
	binding LeaseBinding,
	object TemporaryArtifact,
	manifest StreamManifest,
) (bool, Result, error) {
	recordedAt := worker.now()
	if !validAttemptInstant(binding, recordedAt) {
		result, err := worker.reportFailure(
			parentContext, claim, binding, object, kernel.TicketExportFailureInternal, nil,
		)
		return false, result, err
	}
	recordContext, cancelRecord := context.WithTimeout(attemptContext, worker.operationTimeout)
	recorded, err := worker.repository.RecordManifest(recordContext, ManifestRequest{
		Identity: worker.identity, Binding: binding, ArtifactID: manifest.ArtifactID,
		Digest: manifest.Digest, Rows: manifest.Rows, Bytes: manifest.Bytes, RecordedAt: recordedAt,
	})
	recordContextErr := recordContext.Err()
	cancelRecord()
	if err != nil || recordContextErr != nil {
		if parentContext.Err() != nil {
			result, interruptErr := worker.interrupt(parentContext, object)
			return false, result, interruptErr
		}
		result, failureErr := worker.reportFailure(
			parentContext, claim, binding, object,
			kernel.TicketExportFailureTransientDatabase, nil,
		)
		return false, result, failureErr
	}
	nextRevision, validRevision := revisionSuccessor(binding.Revision)
	switch recorded.Disposition {
	case ManifestRecorded:
		if recorded.CurrentRevision == binding.Revision && recorded.Manifest == manifest {
			return true, Result{}, nil
		}
	case ManifestCancellationRequested:
		if validRevision && recorded.CurrentRevision == nextRevision &&
			recorded.Manifest == (StreamManifest{}) {
			result, transitionErr := worker.acknowledgeCancellation(
				parentContext, binding, recorded.CurrentRevision,
			)
			cleanupErr := worker.abort(parentContext, object)
			return false, result, errors.Join(transitionErr, cleanupErr)
		}
	case ManifestAuthorizationRevoked:
		if recorded.CurrentRevision == binding.Revision && recorded.Manifest == (StreamManifest{}) {
			result, transitionErr := worker.rejectRevoked(
				parentContext, binding, recorded.CurrentRevision,
			)
			cleanupErr := worker.abort(parentContext, object)
			return false, result, errors.Join(transitionErr, cleanupErr)
		}
	case ManifestFenceLost:
		if recorded.CurrentRevision == 0 && recorded.Manifest == (StreamManifest{}) {
			cleanupErr := worker.abort(parentContext, object)
			return false, Result{Claimed: true, Outcome: OutcomeFenceLost},
				errors.Join(ErrFenceLost, cleanupErr)
		}
	case ManifestSnapshotStale:
		if recorded.CurrentRevision == 0 && recorded.Manifest == (StreamManifest{}) {
			result, failureErr := worker.reportFailure(
				parentContext, claim, binding, object,
				kernel.TicketExportFailureSnapshotStale, nil,
			)
			return false, result, failureErr
		}
	}
	result, failureErr := worker.reportFailure(
		parentContext, claim, binding, object, kernel.TicketExportFailureSnapshotStale, nil,
	)
	return false, result, failureErr
}

func (worker *Worker) reportFailure(
	ctx context.Context,
	claim Claim,
	binding LeaseBinding,
	object TemporaryArtifact,
	code kernel.TicketExportFailureCode,
	priorErr error,
) (Result, error) {
	finish := func(result Result, resultErr error) (Result, error) {
		if object != nil {
			resultErr = errors.Join(resultErr, worker.abort(ctx, object))
		}
		return result, errors.Join(resultErr, priorErr)
	}
	if ctx == nil || ctx.Err() != nil {
		return finish(Result{Claimed: true, Outcome: OutcomeInterrupted}, ErrInterrupted)
	}
	failedAt := worker.now()
	if !validAttemptInstant(binding, failedAt) {
		return finish(Result{Claimed: true}, ErrTransitionOutcomeUnknown)
	}
	var retryAt time.Time
	if retryableFailure(code) && binding.Attempt < claim.Job.Definition().MaximumAttempts() {
		value := failedAt.Add(worker.retryDelay(binding.Attempt, binding.Fence))
		if value.Before(binding.JobExpiresAt) {
			retryAt = value
		}
	}
	failureContext, cancelFailure, ok := worker.fencedTransitionContext(ctx, binding, failedAt, false)
	if !ok {
		return finish(Result{Claimed: true}, ErrTransitionOutcomeUnknown)
	}
	failure, err := worker.repository.ReportFailure(failureContext, FailureRequest{
		Identity: worker.identity, Binding: binding, Code: code, FailedAt: failedAt, RetryAt: retryAt,
	})
	failureContextErr := failureContext.Err()
	cancelFailure()
	if err != nil || failureContextErr != nil {
		transitionErr := errors.Join(ErrTransitionOutcomeUnknown, ErrUnavailable)
		if ctx.Err() != nil {
			transitionErr = errors.Join(transitionErr, ErrInterrupted)
		}
		return finish(Result{Claimed: true, FailureCode: code}, transitionErr)
	}
	nextRevision, validRevision := revisionSuccessor(binding.Revision)
	switch failure.Disposition {
	case FailureRetryScheduled, FailureReplayRetry:
		if retryAt.IsZero() || !validRevision || failure.CurrentRevision != nextRevision ||
			failure.Code != code || failure.RetryAt != retryAt {
			return finish(Result{Claimed: true, FailureCode: code}, ErrTransitionOutcomeUnknown)
		}
		return finish(Result{Claimed: true, Outcome: OutcomeRetryScheduled, FailureCode: code}, nil)
	case FailureTerminal, FailureReplayTerminal:
		if !retryAt.IsZero() || !validRevision || failure.CurrentRevision != nextRevision ||
			failure.Code != code || !failure.RetryAt.IsZero() {
			return finish(Result{Claimed: true, FailureCode: code}, ErrTransitionOutcomeUnknown)
		}
		return finish(Result{Claimed: true, Outcome: OutcomeFailed, FailureCode: code}, nil)
	case FailureCancellationRequested:
		if !validRevision || failure.CurrentRevision != nextRevision ||
			failure.Code != kernel.TicketExportFailureNone || !failure.RetryAt.IsZero() {
			return finish(Result{Claimed: true, FailureCode: code}, ErrTransitionOutcomeUnknown)
		}
		result, transitionErr := worker.acknowledgeCancellation(ctx, binding, failure.CurrentRevision)
		return finish(result, transitionErr)
	case FailureAuthorizationRevoked:
		if failure.CurrentRevision != binding.Revision ||
			failure.Code != kernel.TicketExportFailureNone || !failure.RetryAt.IsZero() {
			return finish(Result{Claimed: true, FailureCode: code}, ErrTransitionOutcomeUnknown)
		}
		result, transitionErr := worker.rejectRevoked(ctx, binding, failure.CurrentRevision)
		return finish(result, transitionErr)
	case FailureFenceLost:
		if failure.CurrentRevision != 0 || failure.Code != kernel.TicketExportFailureNone ||
			!failure.RetryAt.IsZero() {
			return finish(Result{Claimed: true, FailureCode: code}, ErrTransitionOutcomeUnknown)
		}
		return finish(Result{Claimed: true, Outcome: OutcomeFenceLost}, ErrFenceLost)
	default:
		return finish(Result{Claimed: true, FailureCode: code}, ErrTransitionOutcomeUnknown)
	}
}

func (worker *Worker) reportPublishedFailure(
	ctx context.Context,
	claim Claim,
	binding LeaseBinding,
	object TemporaryArtifact,
	artifactID kernel.EntityID,
	code kernel.TicketExportFailureCode,
	priorErr error,
) (Result, error) {
	result, transitionErr := worker.reportFailure(ctx, claim, binding, nil, code, priorErr)
	return result, errors.Join(transitionErr, worker.purge(ctx, object, artifactID))
}

func (worker *Worker) acknowledgeCancellation(
	ctx context.Context,
	binding LeaseBinding,
	revision uint64,
) (Result, error) {
	nextRevision, validRevision := revisionSuccessor(revision)
	if revision == 0 || !validRevision {
		return Result{Claimed: true}, ErrTransitionOutcomeUnknown
	}
	now := worker.now()
	if !validAttemptInstant(binding, now) {
		return Result{Claimed: true}, ErrTransitionOutcomeUnknown
	}
	transitionContext, cancelTransition, ok := worker.fencedTransitionContext(ctx, binding, now, true)
	if !ok {
		return Result{Claimed: true}, ErrTransitionOutcomeUnknown
	}
	transition, err := worker.repository.AcknowledgeCancellation(transitionContext, CancellationRequest{
		Identity: worker.identity, Binding: binding, ExpectedRevision: revision, AcknowledgedAt: now,
	})
	transitionContextErr := transitionContext.Err()
	cancelTransition()
	if err != nil || transitionContextErr != nil {
		return Result{Claimed: true}, ErrTransitionOutcomeUnknown
	}
	if transition.Disposition == TransitionFenceLost {
		if transition.CurrentRevision != 0 {
			return Result{Claimed: true}, ErrTransitionOutcomeUnknown
		}
		return Result{Claimed: true, Outcome: OutcomeFenceLost}, ErrFenceLost
	}
	if transition.Disposition != TransitionApplied && transition.Disposition != TransitionReplayed ||
		transition.CurrentRevision != nextRevision {
		return Result{Claimed: true}, ErrTransitionOutcomeUnknown
	}
	return Result{Claimed: true, Outcome: OutcomeCancelled}, nil
}

func (worker *Worker) rejectRevoked(
	ctx context.Context,
	binding LeaseBinding,
	revision uint64,
) (Result, error) {
	nextRevision, validRevision := revisionSuccessor(revision)
	if revision == 0 || !validRevision {
		return Result{Claimed: true}, ErrTransitionOutcomeUnknown
	}
	now := worker.now()
	if !validAttemptInstant(binding, now) {
		return Result{Claimed: true}, ErrTransitionOutcomeUnknown
	}
	transitionContext, cancelTransition, ok := worker.fencedTransitionContext(ctx, binding, now, true)
	if !ok {
		return Result{Claimed: true}, ErrTransitionOutcomeUnknown
	}
	transition, err := worker.repository.RejectRevoked(transitionContext, RevocationRequest{
		Identity: worker.identity, Binding: binding, ExpectedRevision: revision, RejectedAt: now,
	})
	transitionContextErr := transitionContext.Err()
	cancelTransition()
	if err != nil || transitionContextErr != nil {
		return Result{Claimed: true}, ErrTransitionOutcomeUnknown
	}
	if transition.Disposition == TransitionFenceLost {
		if transition.CurrentRevision != 0 {
			return Result{Claimed: true}, ErrTransitionOutcomeUnknown
		}
		return Result{Claimed: true, Outcome: OutcomeFenceLost}, ErrFenceLost
	}
	if transition.Disposition != TransitionApplied && transition.Disposition != TransitionReplayed ||
		transition.CurrentRevision != nextRevision {
		return Result{Claimed: true}, ErrTransitionOutcomeUnknown
	}
	return Result{Claimed: true, Outcome: OutcomeAuthorizationRevoked}, nil
}

func (worker *Worker) interrupt(ctx context.Context, object TemporaryArtifact) (Result, error) {
	cleanupErr := worker.abort(ctx, object)
	return Result{Claimed: true, Outcome: OutcomeInterrupted}, errors.Join(ErrInterrupted, cleanupErr)
}

func (worker *Worker) abort(ctx context.Context, object TemporaryArtifact) error {
	if object == nil {
		return nil
	}
	return worker.cleanup(ctx, object.Abort)
}

func (worker *Worker) purge(
	ctx context.Context,
	object TemporaryArtifact,
	artifactID kernel.EntityID,
) error {
	if object == nil {
		return nil
	}
	return worker.cleanup(ctx, func(cleanupContext context.Context) error {
		return object.Purge(cleanupContext, artifactID)
	})
}

func (worker *Worker) cleanup(ctx context.Context, action func(context.Context) error) error {
	base := context.Background()
	if ctx != nil {
		base = context.WithoutCancel(ctx)
	}
	cleanupContext, cancelCleanup := context.WithTimeout(base, worker.cleanupTimeout)
	defer cancelCleanup()
	for attempt := 0; attempt < worker.cleanupAttempts; attempt++ {
		err := action(cleanupContext)
		if err == nil {
			return nil
		}
		if cleanupContext.Err() != nil {
			break
		}
	}
	return ErrCleanupPending
}

func (worker *Worker) fencedTransitionContext(
	ctx context.Context,
	binding LeaseBinding,
	startedAt time.Time,
	detached bool,
) (context.Context, context.CancelFunc, bool) {
	if !validAttemptInstant(binding, startedAt) {
		return nil, nil, false
	}
	deadline := startedAt.Add(worker.operationTimeout)
	if binding.LeaseExpiresAt.Before(deadline) {
		deadline = binding.LeaseExpiresAt
	}
	if !deadline.After(startedAt) {
		return nil, nil, false
	}
	base := ctx
	if base == nil {
		base = context.Background()
	} else if detached {
		base = context.WithoutCancel(base)
	}
	transitionContext, cancel := context.WithTimeout(base, deadline.Sub(startedAt))
	return transitionContext, cancel, true
}

func (worker *Worker) normalizeClaim(
	claim Claim,
	queue Queue,
	expectedArtifactID kernel.EntityID,
	attemptStartedAt time.Time,
) (Claim, LeaseBinding, error) {
	if kernel.ValidateTicketExportJob(claim.Job) != nil || claim.Job.State() != kernel.TicketExportRunning ||
		!validEntityID(claim.ArtifactID) || claim.ArtifactID != expectedArtifactID ||
		!validInstant(claim.ObservedAt) || !validInstant(attemptStartedAt) ||
		attemptStartedAt.Before(claim.ObservedAt) || claim.Job.Revision() == ^uint64(0) {
		return Claim{}, LeaseBinding{}, ErrInvalidProjection
	}
	definition := claim.Job.Definition()
	lease := claim.Job.Lease()
	if lease == nil || definition.Tenant() != queue.TenantID || definition.Kind() != queue.Kind ||
		definition.Audience() != queue.Audience || lease.Worker() != worker.identity.WorkerID ||
		!lease.ClaimedAt().Equal(claim.ObservedAt) ||
		lease.ExpiresAt().Sub(lease.ClaimedAt()) < kernel.TicketExportMinimumLease ||
		lease.ExpiresAt().Sub(lease.ClaimedAt()) > worker.leaseDuration ||
		!lease.ExpiresAt().After(attemptStartedAt.Add(worker.leaseSafety)) ||
		len(claim.Header) == 0 || len(claim.Header) > kernel.TicketExportMaximumColumns {
		return Claim{}, LeaseBinding{}, ErrInvalidProjection
	}
	header := slices.Clone(claim.Header)
	claim.Header = header
	return claim, LeaseBinding{
		TenantID: definition.Tenant(), JobID: definition.ID(), Kind: definition.Kind(),
		Audience: definition.Audience(), WorkerID: lease.Worker(), Revision: claim.Job.Revision(),
		Attempt: claim.Job.Attempts(), Fence: lease.Fence(), QueryDigest: definition.QueryDigest(),
		CatalogDigest: definition.CatalogDigest(), ProjectionVersion: definition.ProjectionVersion(),
		LeaseClaimedAt: lease.ClaimedAt(), LeaseExpiresAt: lease.ExpiresAt(),
		JobExpiresAt: claim.Job.ExpiresAt(),
	}, nil
}

func emptyClaim(claim Claim) bool {
	return claim.Job == (kernel.TicketExportJob{}) && claim.ArtifactID == (kernel.EntityID{}) &&
		claim.Header == nil && claim.ObservedAt.IsZero()
}

func validPage(
	page Page,
	after string,
	limit int,
	definition kernel.TicketExportDefinition,
	columns int,
) bool {
	if len(page.Rows) > limit || !validCursor(page.NextCursor) ||
		page.NextCursor != "" && page.NextCursor == after ||
		len(page.Rows) == 0 && page.NextCursor != "" {
		return false
	}
	totalBytes := 0
	for _, row := range page.Rows {
		if row.SnapshotKey == ([sha256.Size]byte{}) || len(row.Cells) != columns ||
			!validRowKind(row.Kind, definition) {
			return false
		}
		for _, cell := range row.Cells {
			if !validCell(cell) {
				return false
			}
			worstCaseBytes := len(cell)*2 + 3
			if worstCaseBytes > MaximumPageBytes-totalBytes {
				return false
			}
			totalBytes += worstCaseBytes
		}
		if 2 > MaximumPageBytes-totalBytes {
			return false
		}
		totalBytes += 2
	}
	return true
}

func validControlPage(result PageResult, binding LeaseBinding, cancellation bool) bool {
	if !emptyControlPage(result) {
		return false
	}
	if !cancellation {
		return result.ControlRevision == binding.Revision
	}
	nextRevision, ok := revisionSuccessor(binding.Revision)
	return ok && result.ControlRevision == nextRevision
}

func emptyControlPage(result PageResult) bool {
	return len(result.Page.Rows) == 0 && result.Page.NextCursor == ""
}

func validRowKind(kind RowKind, definition kernel.TicketExportDefinition) bool {
	switch kind {
	case RowTicket:
		return true
	case RowPublicComment:
		return definition.Comments() != kernel.TicketExportCommentsNone
	case RowPrivateComment:
		return definition.Audience() == kernel.TicketExportAudienceOperator &&
			definition.Comments() == kernel.TicketExportCommentsPublicAndPrivate
	default:
		return false
	}
}

func validCursor(value string) bool {
	if value == "" {
		return true
	}
	if len(value) > MaximumCursorBytes {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil
}

func validCell(value string) bool {
	if len(value) > kernel.TicketExportMaximumCellBytes || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character == '\n' || character == '\r' || character == '\t' {
			continue
		}
		if unicode.IsControl(character) || directionalControl(character) {
			return false
		}
	}
	return true
}

func directionalControl(character rune) bool {
	return character == '\u200e' || character == '\u200f' ||
		character >= '\u202a' && character <= '\u202e' ||
		character >= '\u2066' && character <= '\u2069'
}

func rememberRows(rows []Row, seen map[[sha256.Size]byte]struct{}) bool {
	for _, row := range rows {
		if _, repeated := seen[row.SnapshotKey]; repeated {
			return false
		}
		seen[row.SnapshotKey] = struct{}{}
	}
	return true
}

func revisionSuccessor(revision uint64) (uint64, bool) {
	if revision == ^uint64(0) {
		return 0, false
	}
	return revision + 1, true
}

func validAttemptInstant(binding LeaseBinding, value time.Time) bool {
	return validInstant(value) && !value.Before(binding.LeaseClaimedAt) &&
		value.Before(binding.LeaseExpiresAt)
}

func retryableFailure(code kernel.TicketExportFailureCode) bool {
	return code == kernel.TicketExportFailureTransientStorage ||
		code == kernel.TicketExportFailureTransientDatabase ||
		code == kernel.TicketExportFailureInternal
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
	minimum := kernel.TicketExportMinimumRetry
	if ceiling <= minimum {
		return minimum
	}
	span := ceiling - minimum
	seed := [sha256.Size + 1]byte{}
	copy(seed[:sha256.Size], fence[:])
	seed[sha256.Size] = attempt
	digest := sha256.Sum256(seed[:])
	spanMicros := uint64(span / time.Microsecond)
	offsetMicros := binary.BigEndian.Uint64(digest[:8]) % (spanMicros + 1)
	return minimum + time.Duration(offsetMicros)*time.Microsecond
}

func (worker *Worker) now() time.Time {
	worker.sourceMu.Lock()
	now := worker.clock().UTC().Truncate(time.Microsecond)
	worker.sourceMu.Unlock()
	return now
}

func (worker *Worker) artifactID() (kernel.EntityID, error) {
	worker.sourceMu.Lock()
	id, err := worker.newArtifactID()
	worker.sourceMu.Unlock()
	if err != nil || !validEntityID(id) {
		return kernel.EntityID{}, ErrUnavailable
	}
	return id, nil
}

func (worker *Worker) String() string {
	return "ticketexport.Worker{dependencies:[REDACTED],identity:[REDACTED],configuration:[REDACTED]}"
}

func (worker *Worker) GoString() string { return worker.String() }
