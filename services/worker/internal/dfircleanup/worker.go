// Package dfircleanup removes expired, uncommitted evidence uploads through a
// two-phase database fence. Object locations are never formatted or logged.
package dfircleanup

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	SinglePutMaximumBytes int64 = 5_000_000_000
	MaximumBatchSize            = 16
	leaseSafetyMargin           = 5 * time.Second
)

var (
	ErrInvalidConfiguration = errors.New("DFIR cleanup configuration is invalid")
	ErrInvalidClaim         = errors.New("DFIR cleanup claim is invalid")
	ErrUnavailable          = errors.New("DFIR cleanup dependency is unavailable")
	bucketPattern           = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
)

type Claim struct {
	TenantID       uuid.UUID
	StorageID      uuid.UUID
	Fence          int64
	Bucket         string
	ObjectKey      string
	ExpectedSize   int64
	UploadExpires  time.Time
	LeaseExpiresAt time.Time
}

func (claim Claim) String() string {
	return fmt.Sprintf(
		"dfircleanup.Claim{fence:%d,expectedSize:%d,location:[REDACTED]}",
		claim.Fence, claim.ExpectedSize,
	)
}

func (claim Claim) GoString() string { return claim.String() }

type ObjectLocation struct {
	Bucket string
	Key    string
}

func (ObjectLocation) String() string            { return "dfircleanup.ObjectLocation{[REDACTED]}" }
func (location ObjectLocation) GoString() string { return location.String() }

type FinalizeInput struct {
	StorageID     uuid.UUID
	Fence         int64
	DeletedAt     time.Time
	OperationID   uuid.UUID
	AuditID       uuid.UUID
	OutboxID      uuid.UUID
	RequestID     uuid.UUID
	CorrelationID uuid.UUID
}

type Repository interface {
	Check(context.Context) error
	Claim(context.Context, int, time.Duration, time.Time) ([]Claim, error)
	Retry(context.Context, uuid.UUID, int64, string, time.Time, time.Time) error
	Finalize(context.Context, FinalizeInput) error
}

type ObjectDeleter interface {
	Check(context.Context) error
	Delete(context.Context, ObjectLocation) error
}

type Options struct {
	Repository    Repository
	Deleter       ObjectDeleter
	BatchSize     int
	LeaseDuration time.Duration
	DeleteTimeout time.Duration
	RetryBase     time.Duration
	Clock         func() time.Time
	NewID         func() (uuid.UUID, error)
}

type Worker struct {
	repository    Repository
	deleter       ObjectDeleter
	batchSize     int
	leaseDuration time.Duration
	deleteTimeout time.Duration
	retryBase     time.Duration
	clock         func() time.Time
	newID         func() (uuid.UUID, error)
	clockMu       sync.Mutex
	idMu          sync.Mutex
}

type Result struct {
	Claimed   int
	Deleted   int
	Retryable int
}

func New(options Options) (*Worker, error) {
	if options.Repository == nil || options.Deleter == nil || options.Clock == nil || options.NewID == nil ||
		options.BatchSize < 1 || options.BatchSize > MaximumBatchSize ||
		options.LeaseDuration < 30*time.Second || options.LeaseDuration > 15*time.Minute ||
		options.DeleteTimeout < time.Second || options.DeleteTimeout > 5*time.Minute ||
		options.DeleteTimeout+leaseSafetyMargin >= options.LeaseDuration ||
		options.RetryBase < time.Second || options.RetryBase > time.Minute {
		return nil, ErrInvalidConfiguration
	}
	return &Worker{
		repository: options.Repository, deleter: options.Deleter,
		batchSize: options.BatchSize, leaseDuration: options.LeaseDuration,
		deleteTimeout: options.DeleteTimeout, retryBase: options.RetryBase,
		clock: options.Clock, newID: options.NewID,
	}, nil
}

func (worker *Worker) Check(ctx context.Context) error {
	if worker == nil || ctx == nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	for _, check := range []func(context.Context) error{
		worker.repository.Check, worker.deleter.Check,
	} {
		checkContext, cancel := context.WithTimeout(ctx, worker.deleteTimeout)
		err := check(checkContext)
		cancel()
		if err != nil {
			return ErrUnavailable
		}
	}
	return nil
}

func (worker *Worker) RunOnce(ctx context.Context) (Result, error) {
	if worker == nil || ctx == nil || ctx.Err() != nil {
		return Result{}, ErrUnavailable
	}
	now := worker.now()
	claims, err := worker.repository.Claim(ctx, worker.batchSize, worker.leaseDuration, now)
	if err != nil {
		return Result{}, ErrUnavailable
	}
	if len(claims) > worker.batchSize {
		return Result{}, ErrInvalidClaim
	}
	outcomes := make(chan outcome, len(claims))
	for _, claim := range claims {
		claim := claim
		go func() { outcomes <- worker.processClaim(ctx, claim) }()
	}
	result := Result{Claimed: len(claims)}
	var firstError error
	for range claims {
		item := <-outcomes
		if item.deleted {
			result.Deleted++
		}
		if item.retryable {
			result.Retryable++
		}
		if firstError == nil && item.err != nil {
			firstError = item.err
		}
	}
	if firstError != nil {
		return result, firstError
	}
	return result, nil
}

func (worker *Worker) processClaim(ctx context.Context, claim Claim) outcome {
	now := worker.now()
	if err := validateClaim(claim, now, worker.leaseDuration, worker.deleteTimeout); err != nil {
		return outcome{err: err}
	}
	deleteContext, cancel := context.WithTimeout(ctx, worker.deleteTimeout)
	deleteErr := worker.deleter.Delete(deleteContext, ObjectLocation{
		Bucket: claim.Bucket,
		Key:    claim.ObjectKey,
	})
	cancel()
	if deleteErr != nil {
		if err := worker.retry(ctx, claim, "object_delete_failed"); err != nil {
			return outcome{err: ErrUnavailable}
		}
		return outcome{retryable: true}
	}
	ids, err := worker.ids(5)
	if err != nil {
		return outcome{err: ErrUnavailable}
	}
	deletedAt := worker.now()
	err = worker.repository.Finalize(ctx, FinalizeInput{
		StorageID: claim.StorageID, Fence: claim.Fence, DeletedAt: deletedAt,
		OperationID: ids[0], AuditID: ids[1], OutboxID: ids[2], RequestID: ids[3], CorrelationID: ids[4],
	})
	if err != nil {
		if retryErr := worker.retry(ctx, claim, "database_finalize_failed"); retryErr != nil {
			return outcome{err: ErrUnavailable}
		}
		return outcome{retryable: true}
	}
	return outcome{deleted: true}
}

type outcome struct {
	deleted   bool
	retryable bool
	err       error
}

func (worker *Worker) retry(ctx context.Context, claim Claim, code string) error {
	failedAt := worker.now()
	delay := worker.retryBase
	for attempt := int64(1); attempt < claim.Fence && delay < 15*time.Minute; attempt++ {
		if delay > 15*time.Minute/2 {
			delay = 15 * time.Minute
			break
		}
		delay *= 2
	}
	if delay > 15*time.Minute {
		delay = 15 * time.Minute
	}
	return worker.repository.Retry(ctx, claim.StorageID, claim.Fence, code, failedAt, failedAt.Add(delay))
}

func (worker *Worker) ids(count int) ([]uuid.UUID, error) {
	worker.idMu.Lock()
	defer worker.idMu.Unlock()
	result := make([]uuid.UUID, count)
	seen := make(map[uuid.UUID]struct{}, count)
	for index := range result {
		value, err := worker.newID()
		_, duplicate := seen[value]
		if err != nil || value.Version() != 7 || duplicate {
			return nil, ErrUnavailable
		}
		seen[value] = struct{}{}
		result[index] = value
	}
	return result, nil
}

func (worker *Worker) now() time.Time {
	worker.clockMu.Lock()
	defer worker.clockMu.Unlock()
	return worker.clock().UTC().Truncate(time.Microsecond)
}

func validateClaim(claim Claim, now time.Time, lease, operationTimeout time.Duration) error {
	if claim.TenantID.Version() != 7 || claim.StorageID.Version() != 7 || claim.Fence < 1 ||
		!validBucket(claim.Bucket) || claim.ObjectKey != claim.TenantID.String()+"/"+claim.StorageID.String() ||
		claim.ExpectedSize <= 0 || claim.ExpectedSize > SinglePutMaximumBytes ||
		claim.UploadExpires.IsZero() || claim.UploadExpires.Add(5*time.Minute).After(now) ||
		!claim.LeaseExpiresAt.After(now.Add(operationTimeout+leaseSafetyMargin)) ||
		claim.LeaseExpiresAt.After(now.Add(lease+time.Minute)) {
		return ErrInvalidClaim
	}
	return nil
}

func validBucket(value string) bool {
	return bucketPattern.MatchString(value) && !strings.Contains(value, "..") &&
		!strings.Contains(value, ".-") && !strings.Contains(value, "-.") &&
		!looksLikeAmbiguousAddress(value)
}
