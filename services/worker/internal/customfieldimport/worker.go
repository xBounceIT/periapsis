// Package customfieldimport owns the worker-side application boundary for
// bounded Alert and Case custom-field imports. It intentionally depends only
// on the shared custom-field kernel; the API's internal packages are not part
// of the worker ABI.
package customfieldimport

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/customfields"
)

const WorkerPurpose = "custom_field_import"

var (
	ErrInvalidInput         = errors.New("invalid custom-field import worker input")
	ErrConflict             = errors.New("custom-field import worker conflict")
	ErrAuthorizationRevoked = errors.New("custom-field import authorization revoked")
	ErrUnavailable          = errors.New("custom-field import worker dependency unavailable")
)

type Identity struct {
	ServiceAccountID uuid.UUID
	WorkerID         uuid.UUID
}

type Queue struct {
	TenantID uuid.UUID
	JobID    uuid.UUID
}

type Record struct {
	Job kernel.ImportJob
}

type RowSnapshot struct {
	FoundAndVisible   bool
	Allowed           bool
	DefinitionChanged bool
	CurrentVersion    uint64
	Existing          []kernel.FieldValue
}

type RowDecision struct {
	Result  kernel.ImportRowResult
	Patches []kernel.FieldValue
	Next    kernel.ImportJob
}

type RowDecider func(RowSnapshot) (RowDecision, error)

// Repository implementations establish one explicit tenant RLS context for
// every call. ProcessRow must load, reauthorize, decide, mutate the ticket,
// append activity/audit/outbox evidence, record the immutable row receipt and
// advance job progress in one transaction. The callback runs while its locks
// are held so the kernel decision and durable commit share one snapshot.
type Repository interface {
	Ready(context.Context, Identity) error
	ListQueues(context.Context, Identity, time.Time, int) ([]Queue, error)
	Load(context.Context, Identity, Queue) (Record, error)
	CommitTransition(
		context.Context, Identity, Queue, kernel.ImportJob, kernel.ImportJob,
	) (Record, error)
	ProcessRow(
		context.Context, Identity, Queue, kernel.ImportJob, kernel.ImportRow,
		kernel.EntityID, time.Time, RowDecider,
	) (Record, error)
}

type Options struct {
	Repository    Repository
	Identity      Identity
	BatchSize     int
	LeaseDuration time.Duration
	LeaseSafety   time.Duration
	Clock         func() time.Time
}

type Worker struct {
	repository    Repository
	identity      Identity
	batchSize     int
	leaseDuration time.Duration
	leaseSafety   time.Duration
	clock         func() time.Time
}

type Result struct {
	DidWork bool
	State   kernel.ImportJobState
	Rows    uint32
}

func New(options Options) (*Worker, error) {
	if dependencyNil(options.Repository) || !validIdentity(options.Identity) ||
		options.BatchSize <= 0 || options.BatchSize > kernel.ImportMaximumBatchRows ||
		options.LeaseDuration <= 0 || options.LeaseDuration > kernel.ImportMaximumLease ||
		options.LeaseSafety < 0 || options.LeaseSafety >= options.LeaseDuration {
		return nil, ErrInvalidInput
	}
	if options.Clock == nil {
		options.Clock = time.Now
	}
	return &Worker{
		repository: options.Repository, identity: options.Identity,
		batchSize: options.BatchSize, leaseDuration: options.LeaseDuration,
		leaseSafety: options.LeaseSafety, clock: options.Clock,
	}, nil
}

func (worker *Worker) Ready(ctx context.Context) error {
	if worker == nil || ctx == nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	return worker.repository.Ready(ctx, worker.identity)
}

func (worker *Worker) ListQueues(ctx context.Context, limit int) ([]Queue, error) {
	if worker == nil || ctx == nil || ctx.Err() != nil || limit <= 0 || limit > 100 {
		return nil, ErrInvalidInput
	}
	now, err := worker.now()
	if err != nil {
		return nil, err
	}
	queues, err := worker.repository.ListQueues(ctx, worker.identity, now, limit)
	if err != nil {
		return nil, ErrUnavailable
	}
	for _, queue := range queues {
		if !validQueue(queue) {
			return nil, ErrUnavailable
		}
	}
	return queues, nil
}

func (worker *Worker) RunOnce(ctx context.Context, queue Queue) (Result, error) {
	if worker == nil || ctx == nil || ctx.Err() != nil || !validQueue(queue) {
		return Result{}, ErrInvalidInput
	}
	record, err := worker.repository.Load(ctx, worker.identity, queue)
	if err != nil {
		return Result{}, mapRepositoryError(err)
	}
	if !recordMatches(record, queue) {
		return Result{}, ErrUnavailable
	}
	before := record.Job.Progress().Processed()
	now, err := worker.now()
	if err != nil {
		return Result{}, err
	}
	record, didWork, err := worker.ensureRunnable(ctx, queue, record, now)
	if err != nil || !didWork && record.Job.State() != kernel.ImportJobRunning {
		return Result{DidWork: didWork, State: record.Job.State()}, err
	}
	if record.Job.State() != kernel.ImportJobRunning {
		return Result{DidWork: didWork, State: record.Job.State()}, nil
	}

	fence := record.Job.Fence()
	if fence == nil || uuid.UUID(fence.Bytes()) != worker.identity.WorkerID {
		return Result{DidWork: didWork, State: record.Job.State()}, nil
	}
	rows := record.Job.NextRows(worker.batchSize)
	for _, row := range rows {
		if ctx.Err() != nil {
			return Result{}, ErrUnavailable
		}
		now, err = worker.now()
		if err != nil {
			return Result{}, err
		}
		current := record.Job
		record, err = worker.repository.ProcessRow(
			ctx, worker.identity, queue, current, row, *fence, now,
			func(snapshot RowSnapshot) (RowDecision, error) {
				return decideRow(current, row, *fence, now, snapshot)
			},
		)
		if err != nil {
			if errors.Is(err, ErrAuthorizationRevoked) {
				next, planErr := kernel.RevokeImportAuthorization(
					current, current.Revision(), *fence, now,
				)
				if planErr != nil {
					return Result{}, ErrConflict
				}
				record, err = worker.repository.CommitTransition(
					ctx, worker.identity, queue, current, next,
				)
			}
			if err != nil {
				return Result{}, mapRepositoryError(err)
			}
		}
		if !recordMatches(record, queue) {
			return Result{}, ErrUnavailable
		}
		if record.Job.State() != kernel.ImportJobRunning {
			break
		}
	}
	processed := record.Job.Progress().Processed() - before
	return Result{DidWork: didWork || processed > 0, State: record.Job.State(), Rows: processed}, nil
}

func (worker *Worker) ensureRunnable(
	ctx context.Context,
	queue Queue,
	record Record,
	now time.Time,
) (Record, bool, error) {
	job := record.Job
	if terminal(job.State()) {
		return record, false, nil
	}
	if job.State() == kernel.ImportJobCancellationRequested {
		fence := job.Fence()
		lease := job.LeaseUntil()
		if fence != nil && lease != nil && now.Before(*lease) &&
			uuid.UUID(fence.Bytes()) == worker.identity.WorkerID {
			next, err := kernel.CompleteImportCancellation(job, job.Revision(), *fence, now)
			if err != nil {
				return Record{}, false, ErrConflict
			}
			stored, err := worker.repository.CommitTransition(ctx, worker.identity, queue, job, next)
			return stored, true, mapRepositoryError(err)
		}
		if lease == nil || !now.Before(*lease) {
			next, err := kernel.ExpireImportJob(job, job.Revision(), now)
			if err != nil {
				return Record{}, false, ErrConflict
			}
			stored, err := worker.repository.CommitTransition(ctx, worker.identity, queue, job, next)
			return stored, true, mapRepositoryError(err)
		}
		return record, false, nil
	}
	if job.State() == kernel.ImportJobRunning {
		lease, fence := job.LeaseUntil(), job.Fence()
		if lease != nil && now.Before(*lease) {
			if fence == nil || uuid.UUID(fence.Bytes()) != worker.identity.WorkerID {
				return record, false, nil
			}
			if lease.Sub(now) > worker.leaseSafety {
				return record, true, nil
			}
			leaseUntil := boundedLease(now, worker.leaseDuration, job.ExpiresAt())
			next, err := kernel.HeartbeatImportJob(job, job.Revision(), *fence, now, leaseUntil)
			if err != nil {
				return Record{}, false, ErrConflict
			}
			stored, err := worker.repository.CommitTransition(ctx, worker.identity, queue, job, next)
			return stored, true, mapRepositoryError(err)
		}
		if !now.Before(job.ExpiresAt()) || job.Attempts() >= job.Manifest().MaximumAttempts() {
			next, err := kernel.ExpireImportJob(job, job.Revision(), now)
			if err != nil {
				return Record{}, false, ErrConflict
			}
			stored, err := worker.repository.CommitTransition(ctx, worker.identity, queue, job, next)
			return stored, true, mapRepositoryError(err)
		}
	}
	if job.State() == kernel.ImportJobPending && !now.Before(job.ExpiresAt()) {
		next, err := kernel.ExpireImportJob(job, job.Revision(), now)
		if err != nil {
			return Record{}, false, ErrConflict
		}
		stored, err := worker.repository.CommitTransition(ctx, worker.identity, queue, job, next)
		return stored, true, mapRepositoryError(err)
	}
	fence, err := kernel.ParseEntityID(worker.identity.WorkerID.String())
	if err != nil {
		return Record{}, false, ErrUnavailable
	}
	leaseUntil := boundedLease(now, worker.leaseDuration, job.ExpiresAt())
	next, err := kernel.ClaimImportJob(job, job.Revision(), fence, now, leaseUntil)
	if err != nil {
		return Record{}, false, ErrConflict
	}
	stored, err := worker.repository.CommitTransition(ctx, worker.identity, queue, job, next)
	return stored, true, mapRepositoryError(err)
}

func decideRow(
	current kernel.ImportJob,
	row kernel.ImportRow,
	fence kernel.EntityID,
	now time.Time,
	snapshot RowSnapshot,
) (RowDecision, error) {
	manifest := current.Manifest()
	var result kernel.ImportRowResult
	var patches []kernel.FieldValue
	var err error
	switch {
	case !snapshot.FoundAndVisible:
		result, err = kernel.NewImportRowResult(row.Sequence(), kernel.ImportRowNotFoundOrHidden, 0, nil)
	case !snapshot.Allowed:
		result, err = kernel.NewImportRowResult(row.Sequence(), kernel.ImportRowAuthorizationDenied, 0, nil)
	case snapshot.CurrentVersion != row.ExpectedVersion():
		result, err = kernel.NewImportRowResult(row.Sequence(), kernel.ImportRowVersionConflict, 0, nil)
	case snapshot.DefinitionChanged:
		result, err = kernel.NewImportRowResult(row.Sequence(), kernel.ImportRowDefinitionChanged, 0, nil)
	default:
		var fieldErrors []kernel.FieldError
		patches, fieldErrors, err = kernel.ValidateImportPatch(manifest, row, snapshot.Existing)
		if err == nil && len(fieldErrors) != 0 {
			result, err = kernel.NewImportRowResult(
				row.Sequence(), kernel.ImportRowValidationFailed, 0, fieldErrors,
			)
		} else if err == nil && len(patches) == 0 {
			result, err = kernel.NewImportRowResult(
				row.Sequence(), kernel.ImportRowNoChange, row.ExpectedVersion(), nil,
			)
		} else if err == nil && manifest.Mode() == kernel.ImportDryRun {
			result, err = kernel.NewImportRowResult(
				row.Sequence(), kernel.ImportRowDryRunValid, row.ExpectedVersion(), nil,
			)
		} else if err == nil {
			result, err = kernel.NewImportRowResult(
				row.Sequence(), kernel.ImportRowCommitted, row.ExpectedVersion()+1, nil,
			)
		}
	}
	if err != nil {
		return RowDecision{}, ErrUnavailable
	}
	next, err := kernel.RecordImportBatch(
		current, current.Revision(), fence, []kernel.ImportRowResult{result}, now,
	)
	if err != nil {
		return RowDecision{}, ErrConflict
	}
	return RowDecision{Result: result, Patches: patches, Next: next}, nil
}

func boundedLease(now time.Time, duration time.Duration, expiresAt time.Time) time.Time {
	lease := now.Add(duration)
	if lease.After(expiresAt) {
		return expiresAt
	}
	return lease
}

func (worker *Worker) now() (time.Time, error) {
	now := worker.clock().UTC().Truncate(time.Microsecond)
	if now.IsZero() || now.Year() < 1 || now.Year() > 9999 {
		return time.Time{}, ErrUnavailable
	}
	return now, nil
}

func validIdentity(identity Identity) bool {
	return identity.ServiceAccountID != uuid.Nil && identity.WorkerID != uuid.Nil &&
		identity.ServiceAccountID.Version() == 7 && identity.WorkerID.Version() == 7
}

func validQueue(queue Queue) bool {
	return queue.TenantID != uuid.Nil && queue.JobID != uuid.Nil &&
		queue.TenantID.Version() == 7 && queue.JobID.Version() == 7
}

func recordMatches(record Record, queue Queue) bool {
	if kernel.ValidateImportJob(record.Job) != nil {
		return false
	}
	manifest := record.Job.Manifest()
	return uuid.UUID(manifest.Tenant().Bytes()) == queue.TenantID &&
		uuid.UUID(manifest.ID().Bytes()) == queue.JobID
}

func terminal(state kernel.ImportJobState) bool {
	return state == kernel.ImportJobCompleted || state == kernel.ImportJobFailed ||
		state == kernel.ImportJobCancelled || state == kernel.ImportJobAuthorizationRevoked ||
		state == kernel.ImportJobExpired
}

func mapRepositoryError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrAuthorizationRevoked) {
		return ErrAuthorizationRevoked
	}
	if errors.Is(err, ErrConflict) {
		return ErrConflict
	}
	return ErrUnavailable
}

func dependencyNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	return reflected.Kind() == reflect.Pointer && reflected.IsNil()
}

func (result Result) String() string {
	return fmt.Sprintf("CustomFieldImportResult{worked:%t,state:%s,rows:%d}", result.DidWork, result.State, result.Rows)
}
