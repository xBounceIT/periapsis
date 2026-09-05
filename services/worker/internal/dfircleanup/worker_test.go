package dfircleanup

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestWorkerDeletesThenFinalizesExactFencedClaim(t *testing.T) {
	now := cleanupTestTime()
	claim := validClaim(now)
	repository := &fakeRepository{claims: []Claim{claim}}
	deleter := &fakeDeleter{}
	worker := mustWorker(t, repository, deleter, now)

	result, err := worker.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	if result != (Result{Claimed: 1, Deleted: 1}) || deleter.calls != 1 || len(repository.finalized) != 1 || len(repository.retried) != 0 {
		t.Fatalf("RunOnce() result=%+v delete=%d finalized=%d retried=%d", result, deleter.calls, len(repository.finalized), len(repository.retried))
	}
	finalized := repository.finalized[0]
	if finalized.StorageID != claim.StorageID || finalized.Fence != claim.Fence ||
		finalized.OperationID.Version() != 7 || finalized.AuditID.Version() != 7 || finalized.OutboxID.Version() != 7 ||
		finalized.RequestID.Version() != 7 || finalized.CorrelationID.Version() != 7 {
		t.Fatalf("Finalize() input = %#v", finalized)
	}
	identifiers := []uuid.UUID{
		finalized.OperationID, finalized.AuditID, finalized.OutboxID,
		finalized.RequestID, finalized.CorrelationID,
	}
	seen := make(map[uuid.UUID]struct{}, len(identifiers))
	for _, identifier := range identifiers {
		if _, duplicate := seen[identifier]; duplicate {
			t.Fatalf("Finalize() reused identifier %s", identifier)
		}
		seen[identifier] = struct{}{}
	}
	if strings.Contains(claim.String(), claim.ObjectKey) || strings.Contains(claim.GoString(), claim.Bucket) {
		t.Fatal("claim formatter exposed object location")
	}
}

func TestWorkerRetriesBoundedlyAfterIdempotentDeleteFailure(t *testing.T) {
	now := cleanupTestTime()
	claim := validClaim(now)
	claim.Fence = 20
	repository := &fakeRepository{claims: []Claim{claim}}
	deleter := &fakeDeleter{err: errors.New("endpoint contained customer key")}
	worker := mustWorker(t, repository, deleter, now)

	result, err := worker.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	if result != (Result{Claimed: 1, Retryable: 1}) || len(repository.retried) != 1 || len(repository.finalized) != 0 {
		t.Fatalf("RunOnce() result=%+v finalized=%d retried=%d", result, len(repository.finalized), len(repository.retried))
	}
	retry := repository.retried[0]
	if retry.code != "object_delete_failed" || retry.retryAt.Sub(retry.failedAt) != 15*time.Minute {
		t.Fatalf("Retry() = %#v", retry)
	}
}

func TestWorkerRejectsForgedLocationBeforeObjectStoreCall(t *testing.T) {
	now := cleanupTestTime()
	claim := validClaim(now)
	claim.ObjectKey = claim.TenantID.String() + "/../secret"
	repository := &fakeRepository{claims: []Claim{claim}}
	deleter := &fakeDeleter{}
	worker := mustWorker(t, repository, deleter, now)

	result, err := worker.RunOnce(context.Background())
	if !errors.Is(err, ErrInvalidClaim) || result.Claimed != 1 || deleter.calls != 0 ||
		len(repository.finalized) != 0 || len(repository.retried) != 0 {
		t.Fatalf("RunOnce() result=%+v error=%v delete=%d", result, err, deleter.calls)
	}
}

func TestWorkerRetriesWhenFinalizeFailsAfterSuccessfulDelete(t *testing.T) {
	now := cleanupTestTime()
	repository := &fakeRepository{claims: []Claim{validClaim(now)}, finalizeErr: errors.New("database unavailable")}
	worker := mustWorker(t, repository, &fakeDeleter{}, now)

	result, err := worker.RunOnce(context.Background())
	if err != nil || result.Retryable != 1 || len(repository.retried) != 1 ||
		repository.retried[0].code != "database_finalize_failed" {
		t.Fatalf("RunOnce() result=%+v error=%v retries=%#v", result, err, repository.retried)
	}
}

func TestWorkerProcessesClaimedBatchConcurrentlyWithinLease(t *testing.T) {
	now := cleanupTestTime()
	first := validClaim(now)
	second := validClaim(now)
	second.StorageID = cleanupUUID(3)
	second.ObjectKey = second.TenantID.String() + "/" + second.StorageID.String()
	repository := &fakeRepository{claims: []Claim{first, second}}
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	deleter := &fakeDeleter{started: started, release: release}
	worker := mustWorker(t, repository, deleter, now)
	done := make(chan error, 1)
	go func() {
		_, err := worker.RunOnce(context.Background())
		done <- err
	}()
	for index := 0; index < 2; index++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("claimed cleanup operations were processed sequentially")
		}
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	if len(repository.finalized) != 2 {
		t.Fatalf("Finalize() calls = %d", len(repository.finalized))
	}
}

func TestWorkerRejectsUnsafeClaimAndDuplicateTransitionIDs(t *testing.T) {
	now := cleanupTestTime()
	for name, mutate := range map[string]func(*Claim){
		"zero size": func(claim *Claim) { claim.ExpectedSize = 0 },
		"insufficient remaining lease": func(claim *Claim) {
			claim.LeaseExpiresAt = now.Add(10 * time.Second)
		},
	} {
		t.Run(name, func(t *testing.T) {
			claim := validClaim(now)
			mutate(&claim)
			worker := mustWorker(t, &fakeRepository{claims: []Claim{claim}}, &fakeDeleter{}, now)
			if _, err := worker.RunOnce(context.Background()); !errors.Is(err, ErrInvalidClaim) {
				t.Fatalf("RunOnce() error = %v", err)
			}
		})
	}
	repository := &fakeRepository{claims: []Claim{validClaim(now)}}
	worker, err := New(Options{
		Repository: repository, Deleter: &fakeDeleter{}, BatchSize: 1,
		LeaseDuration: time.Minute, DeleteTimeout: 5 * time.Second, RetryBase: 5 * time.Second,
		Clock: func() time.Time { return now },
		NewID: func() (uuid.UUID, error) { return cleanupUUID(99), nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := worker.RunOnce(context.Background()); !errors.Is(err, ErrUnavailable) || len(repository.finalized) != 0 {
		t.Fatalf("RunOnce() duplicate IDs error=%v finalized=%d", err, len(repository.finalized))
	}
}

func mustWorker(t *testing.T, repository Repository, deleter ObjectDeleter, now time.Time) *Worker {
	t.Helper()
	seed := byte(40)
	worker, err := New(Options{
		Repository: repository, Deleter: deleter, BatchSize: 10,
		LeaseDuration: time.Minute, DeleteTimeout: 5 * time.Second, RetryBase: 5 * time.Second,
		Clock: func() time.Time { return now },
		NewID: func() (uuid.UUID, error) {
			seed++
			return cleanupUUID(seed), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return worker
}

func validClaim(now time.Time) Claim {
	tenantID, storageID := cleanupUUID(1), cleanupUUID(2)
	return Claim{
		TenantID: tenantID, StorageID: storageID, Fence: 1,
		Bucket: "periapsis-evidence", ObjectKey: tenantID.String() + "/" + storageID.String(),
		ExpectedSize: 1024, UploadExpires: now.Add(-10 * time.Minute),
		LeaseExpiresAt: now.Add(time.Minute),
	}
}

func cleanupTestTime() time.Time {
	return time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
}

func cleanupUUID(seed byte) uuid.UUID {
	return uuid.UUID{0x01, 0x9d, 0x02, 0x00, 0, seed, 0x70, seed, 0x80, seed, 0, 0, 0, 0, 0, seed}
}

type fakeDeleter struct {
	mu      sync.Mutex
	calls   int
	err     error
	started chan<- struct{}
	release <-chan struct{}
}

func (deleter *fakeDeleter) Check(context.Context) error { return deleter.err }

func (deleter *fakeDeleter) Delete(context.Context, ObjectLocation) error {
	deleter.mu.Lock()
	deleter.calls++
	err := deleter.err
	started, release := deleter.started, deleter.release
	deleter.mu.Unlock()
	if started != nil {
		started <- struct{}{}
	}
	if release != nil {
		<-release
	}
	return err
}

type retryRecord struct {
	storageID uuid.UUID
	fence     int64
	code      string
	failedAt  time.Time
	retryAt   time.Time
}

type fakeRepository struct {
	mu          sync.Mutex
	claims      []Claim
	claimErr    error
	finalizeErr error
	retryErr    error
	finalized   []FinalizeInput
	retried     []retryRecord
}

func (repository *fakeRepository) Check(context.Context) error {
	return repository.claimErr
}

func (repository *fakeRepository) Claim(context.Context, int, time.Duration, time.Time) ([]Claim, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	return append([]Claim(nil), repository.claims...), repository.claimErr
}

func (repository *fakeRepository) Retry(_ context.Context, storageID uuid.UUID, fence int64, code string, failedAt, retryAt time.Time) error {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.retried = append(repository.retried, retryRecord{
		storageID: storageID, fence: fence, code: code, failedAt: failedAt, retryAt: retryAt,
	})
	return repository.retryErr
}

func (repository *fakeRepository) Finalize(_ context.Context, input FinalizeInput) error {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.finalized = append(repository.finalized, input)
	return repository.finalizeErr
}
