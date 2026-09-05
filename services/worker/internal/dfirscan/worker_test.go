package dfirscan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/dfir"
)

func TestWorkerCleanUploadUsesOneExactStreamPerPhase(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)
	content := []byte("plain forensic evidence\n")
	claim := testClaim(t, testPendingStorage(t, now, int64(len(content))), now)
	repository := &scanRepositoryFake{claims: []Claim{claim}}
	store := &scanStoreFake{bodies: [][]byte{content, content}, declaredMIME: "text/plain"}
	scanner := &scanScannerFake{verdict: ScanClean}
	worker := testWorker(t, repository, store, scanner, now)

	result, err := worker.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	if result.Available != 1 || result.Claimed != 1 || !repository.completedByTransition {
		t.Fatalf("RunOnce() result = %+v, completeByTransition=%t", result, repository.completedByTransition)
	}
	states := make([]kernel.ScanState, 0, len(repository.transitions))
	identifiers := make(map[uuid.UUID]struct{})
	for _, transition := range repository.transitions {
		states = append(states, transition.Updated.State())
		for _, identifier := range []uuid.UUID{
			transition.IDs.OperationID, transition.IDs.RequestID,
			transition.IDs.AuditID, transition.IDs.OutboxID,
		} {
			if identifier.Version() != 7 {
				t.Fatalf("transition identifier is not UUIDv7: %s", identifier)
			}
			if _, duplicate := identifiers[identifier]; duplicate {
				t.Fatalf("transition identifier was reused: %s", identifier)
			}
			identifiers[identifier] = struct{}{}
		}
	}
	wantStates := []kernel.ScanState{
		kernel.ScanUploaded, kernel.ScanVerifying, kernel.ScanQuarantined,
		kernel.ScanScanning, kernel.ScanAvailable,
	}
	if !slices.Equal(states, wantStates) {
		t.Fatalf("transition states = %v, want %v", states, wantStates)
	}
	if !bytes.Equal(scanner.content, content) || store.opens != 2 {
		t.Fatalf("scanner content/open count = %q/%d", scanner.content, store.opens)
	}
	digest := sha256.Sum256(content)
	if got := repository.transitions[len(repository.transitions)-1].Updated.ContentSHA256(); got != hex.EncodeToString(digest[:]) {
		t.Fatalf("stored digest = %q", got)
	}
}

func TestWorkerRejectsContentChangedBetweenVerificationAndScan(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)
	verified := []byte("known forensic evidence\n")
	drifted := []byte("other forensic evidence\n")
	claim := testClaim(t, testPendingStorage(t, now, int64(len(verified))), now)
	repository := &scanRepositoryFake{claims: []Claim{claim}}
	store := &scanStoreFake{bodies: [][]byte{verified, drifted}, declaredMIME: "text/plain"}
	scanner := &scanScannerFake{verdict: ScanClean}
	worker := testWorker(t, repository, store, scanner, now)

	result, err := worker.RunOnce(context.Background())
	if err != nil || result.Rejected != 1 {
		t.Fatalf("RunOnce() = %+v, %v", result, err)
	}
	last := repository.transitions[len(repository.transitions)-1]
	if last.Updated.State() != kernel.ScanRejected || last.FailureCategory != "object_content_drift" || !last.CompleteJob {
		t.Fatalf("last transition = %+v", last)
	}
}

func TestWorkerRetriesScannerFailureFromScanFailedState(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)
	content := []byte("known forensic evidence\n")
	storage := testVerifiedStorage(t, now, content, kernel.ScanScanning)
	claim := testClaim(t, storage, now)
	claim.Attempt = 2
	repository := &scanRepositoryFake{claims: []Claim{claim}}
	store := &scanStoreFake{bodies: [][]byte{content}, declaredMIME: "text/plain"}
	scanner := &scanScannerFake{err: ErrUnavailable}
	worker := testWorker(t, repository, store, scanner, now)

	result, err := worker.RunOnce(context.Background())
	if err != nil || result.RetryScheduled != 1 || len(repository.retries) != 1 {
		t.Fatalf("RunOnce() = %+v, %v retries=%d", result, err, len(repository.retries))
	}
	if repository.transitions[len(repository.transitions)-1].Updated.State() != kernel.ScanFailed ||
		repository.retries[0].FailureCategory != "scanner_unavailable" {
		t.Fatalf("scanner failure was not persisted safely")
	}
}

func TestWorkerCustodyLimitDeadLettersWithoutAnotherTransition(t *testing.T) {
	t.Parallel()
	for _, executeAttempt := range []bool{true, false} {
		for _, completionError := range []error{nil, ErrFenceLost, ErrUnavailable} {
			now := time.Date(2026, 9, 5, 10, 0, 0, 0, time.UTC)
			content := []byte("known forensic evidence\n")
			claim := testClaim(t, testVerifiedStorage(t, now, content, kernel.ScanScanning), now)
			claim.ExecuteAttempt = executeAttempt
			if !executeAttempt {
				claim.Attempt = claim.MaximumAttempts
			}
			repository := &scanRepositoryFake{
				claims: []Claim{claim}, transitionError: ErrEvidenceCustodyLimit,
				completionError: completionError,
			}
			store := &scanStoreFake{bodies: [][]byte{content}, declaredMIME: "text/plain"}
			worker := testWorker(t, repository, store, &scanScannerFake{verdict: ScanClean}, now)
			result, err := worker.RunOnce(context.Background())
			if len(repository.transitions) != 1 || len(repository.completions) != 1 ||
				len(repository.retries) != 0 || repository.completedByTransition {
				t.Fatalf("custody limit retried or changed projections: %+v", result)
			}
			completion := repository.completions[0]
			if completion.Fence != fenceFor(claim) || !completion.DeadLetter ||
				completion.FailureCategory != "evidence_custody_limit" {
				t.Fatalf("custody limit completion lost its exact fence: %+v", completion)
			}
			switch completionError {
			case nil:
				if err != nil || result.ScanFailed != 1 {
					t.Fatalf("custody-limited job did not terminate: %+v, %v", result, err)
				}
			case ErrFenceLost:
				if err != nil || result.FenceLost != 1 || result.ScanFailed != 0 {
					t.Fatalf("lost completion fence was reported as success: %+v, %v", result, err)
				}
			default:
				if !errors.Is(err, completionError) || result.ScanFailed != 0 {
					t.Fatalf("failed completion was reported as success: %+v, %v", result, err)
				}
			}
		}
	}
}

func TestWorkerCustodyLimitStopsEarlierPhasesAndClosesOpenedStream(t *testing.T) {
	t.Parallel()
	for _, state := range []kernel.ScanState{
		kernel.ScanPendingUpload, kernel.ScanUploaded, kernel.ScanVerifying,
		kernel.ScanQuarantined, kernel.ScanFailed,
	} {
		t.Run(string(state), func(t *testing.T) {
			now := time.Date(2026, 9, 5, 10, 0, 0, 0, time.UTC)
			content := []byte("known forensic evidence\n")
			storage := testPendingStorage(t, now, int64(len(content)))
			var err error
			switch state {
			case kernel.ScanUploaded:
				storage, err = storage.MarkUploaded(storage.Version(), storage.UpdatedAt())
			case kernel.ScanVerifying:
				storage = testVerifyingStorage(t, now, content)
			case kernel.ScanQuarantined:
				storage = testVerifiedStorage(t, now, content, state)
			case kernel.ScanFailed:
				storage = testVerifiedStorage(t, now, content, kernel.ScanScanning)
				storage, err = storage.CompleteScan(storage.Version(), state, storage.UpdatedAt())
			}
			if err != nil || storage.State() != state {
				t.Fatalf("prepare %s storage: %v", state, err)
			}
			claim := testClaim(t, storage, now)
			repository := &scanRepositoryFake{claims: []Claim{claim}, transitionError: ErrEvidenceCustodyLimit}
			body := &closeTrackingReader{Reader: bytes.NewReader(content)}
			store := &scanStoreFake{readers: []ObjectReader{{
				Body: body, SizeBytes: int64(len(content)), DeclaredMIME: "text/plain",
			}}}
			scanner := &scanScannerFake{verdict: ScanClean}
			result, err := testWorker(t, repository, store, scanner, now).RunOnce(context.Background())
			if err != nil || result != (Result{Claimed: 1, ScanFailed: 1}) ||
				len(repository.transitions) != 1 || len(repository.completions) != 1 ||
				len(repository.retries) != 0 || len(repository.waits) != 0 ||
				repository.completedByTransition || len(scanner.content) != 0 {
				t.Fatalf("custody limit did not stop before scanning: %+v, %v", result, err)
			}
			completion := repository.completions[0]
			if completion.Fence != fenceFor(claim) || !completion.DeadLetter ||
				completion.FailureCategory != "evidence_custody_limit" {
				t.Fatalf("custody limit completion lost its exact fence: %+v", completion)
			}
			wantOpens := 0
			if state == kernel.ScanPendingUpload || state == kernel.ScanVerifying {
				wantOpens = 1
			}
			if store.opens != wantOpens || body.closed != (wantOpens == 1) {
				t.Fatalf("opened stream lifecycle = %d/closed=%t, want opens=%d", store.opens, body.closed, wantOpens)
			}
		})
	}
}

func TestWorkerMissingPendingUploadWaitsWithoutBurningAttempt(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)
	claim := testClaim(t, testPendingStorage(t, now, 24), now)
	repository := &scanRepositoryFake{claims: []Claim{claim}}
	store := &scanStoreFake{err: ErrObjectNotFound}
	worker := testWorker(t, repository, store, &scanScannerFake{}, now)

	result, err := worker.RunOnce(context.Background())
	if err != nil || result.WaitingUpload != 1 || len(repository.waits) != 1 || len(repository.retries) != 0 {
		t.Fatalf("RunOnce() = %+v, %v waits=%d retries=%d", result, err, len(repository.waits), len(repository.retries))
	}
	if !repository.waits[0].AvailableAt.After(now) || !repository.waits[0].AvailableAt.Before(claim.Storage.UploadExpiresAt()) {
		t.Fatalf("wait availability = %s", repository.waits[0].AvailableAt)
	}
}

func TestWorkerMissingExpiredUploadCompletesForCleanup(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)
	storage := testPendingStorage(t, now.Add(-10*time.Minute), 24)
	claim := testClaim(t, storage, now)
	repository := &scanRepositoryFake{claims: []Claim{claim}}
	store := &scanStoreFake{err: ErrObjectNotFound}
	worker := testWorker(t, repository, store, &scanScannerFake{}, now)

	result, err := worker.RunOnce(context.Background())
	if err != nil || result.UploadExpired != 1 || len(repository.completions) != 1 {
		t.Fatalf("RunOnce() = %+v, %v completions=%d", result, err, len(repository.completions))
	}
	if repository.completions[0].FailureCategory != "upload_expired" || repository.completions[0].DeadLetter {
		t.Fatalf("completion = %+v", repository.completions[0])
	}
}

func TestWorkerExhaustedExpiredUploadCompletesWithoutInventingContent(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)
	storage := testPendingStorage(t, now.Add(-10*time.Minute), 24)
	claim := testClaim(t, storage, now)
	claim.Attempt = claim.MaximumAttempts
	claim.ExecuteAttempt = false
	repository := &scanRepositoryFake{claims: []Claim{claim}}
	store := &scanStoreFake{err: ErrObjectNotFound}
	worker := testWorker(t, repository, store, &scanScannerFake{}, now)

	result, err := worker.RunOnce(context.Background())
	if err != nil || result.UploadExpired != 1 || len(repository.completions) != 1 {
		t.Fatalf("RunOnce() = %+v, %v completions=%d", result, err, len(repository.completions))
	}
	if store.opens != 0 || len(repository.transitions) != 0 ||
		repository.completions[0].FailureCategory != "upload_expired" ||
		repository.completions[0].DeadLetter {
		t.Fatalf(
			"exhausted pending upload was not left for cleanup: opens=%d transitions=%d completion=%+v",
			store.opens, len(repository.transitions), repository.completions[0],
		)
	}
}

func TestWorkerRejectsPolicyBeforeAvailability(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)
	content := []byte("<html><script>alert(1)</script></html>")
	storage := testVerifiedStorage(t, now, content, kernel.ScanScanning)
	claim := testClaim(t, storage, now)
	claim.DeclaredMIME = "text/html"
	repository := &scanRepositoryFake{claims: []Claim{claim}}
	store := &scanStoreFake{bodies: [][]byte{content}, declaredMIME: "text/html"}
	scanner := &scanScannerFake{verdict: ScanClean}
	worker := testWorker(t, repository, store, scanner, now)

	result, err := worker.RunOnce(context.Background())
	if err != nil || result.Rejected != 1 {
		t.Fatalf("RunOnce() = %+v, %v", result, err)
	}
	last := repository.transitions[len(repository.transitions)-1]
	if last.Updated.State() != kernel.ScanRejected || last.FailureCategory != "file_policy_active_content" || len(scanner.content) != 0 {
		t.Fatalf("policy transition=%+v scanner=%q", last, scanner.content)
	}
}

func TestWorkerFailsClosedWhenStoreReturnsNilBody(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)
	content := []byte("known forensic evidence\n")
	tests := []struct {
		name            string
		storage         kernel.StorageObject
		wantTransitions int
	}{
		{name: "pending", storage: testPendingStorage(t, now, int64(len(content)))},
		{name: "verifying", storage: testVerifyingStorage(t, now, content)},
		{name: "scanning", storage: testVerifiedStorage(t, now, content, kernel.ScanScanning), wantTransitions: 1},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			claim := testClaim(t, test.storage, now)
			repository := &scanRepositoryFake{claims: []Claim{claim}}
			store := &scanStoreFake{readers: []ObjectReader{{
				SizeBytes: int64(len(content)), DeclaredMIME: claim.DeclaredMIME,
			}}}
			worker := testWorker(t, repository, store, &scanScannerFake{}, now)

			result, err := worker.RunOnce(context.Background())
			if err != nil || result.RetryScheduled != 1 || len(repository.retries) != 1 {
				t.Fatalf("RunOnce() = %+v, %v retries=%d", result, err, len(repository.retries))
			}
			if repository.retries[0].FailureCategory != "storage_unavailable" ||
				len(repository.transitions) != test.wantTransitions {
				t.Fatalf("retry/transitions = %+v/%d", repository.retries[0], len(repository.transitions))
			}
		})
	}
}

func TestWorkerRejectsObjectReaderDeclaredMIMEDriftBeforeStateWork(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)
	content := []byte("known forensic evidence\n")
	tests := []struct {
		name    string
		storage kernel.StorageObject
	}{
		{name: "pending", storage: testPendingStorage(t, now, int64(len(content)))},
		{name: "verifying", storage: testVerifyingStorage(t, now, content)},
		{name: "scanning", storage: testVerifiedStorage(t, now, content, kernel.ScanScanning)},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			claim := testClaim(t, test.storage, now)
			repository := &scanRepositoryFake{claims: []Claim{claim}}
			body := &closeTrackingReader{Reader: bytes.NewReader(content)}
			store := &scanStoreFake{readers: []ObjectReader{{
				Body: body, SizeBytes: int64(len(content)), DeclaredMIME: "application/octet-stream",
			}}}
			worker := testWorker(t, repository, store, &scanScannerFake{}, now)

			result, err := worker.RunOnce(context.Background())
			if err != nil || result.Rejected != 1 || !body.closed {
				t.Fatalf("RunOnce() = %+v, %v bodyClosed=%t", result, err, body.closed)
			}
			last := repository.transitions[len(repository.transitions)-1]
			if last.Updated.State() != kernel.ScanRejected || !last.CompleteJob {
				t.Fatalf("last transition = %+v", last)
			}
		})
	}
}

func TestWorkerProcessesClaimedBatchConcurrentlyWithinLease(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)
	content := []byte("parallel forensic evidence\n")
	claims := []Claim{
		testClaim(t, testVerifiedStorage(t, now, content, kernel.ScanScanning), now),
		testClaim(t, testVerifiedStorage(t, now, content, kernel.ScanScanning), now),
	}
	started := make(chan struct{}, len(claims))
	release := make(chan struct{})
	worker := testWorker(
		t, &parallelScanRepository{claims: claims}, &parallelScanStore{content: content},
		&parallelScanner{started: started, release: release}, now,
	)
	done := make(chan struct {
		result Result
		err    error
	}, 1)
	go func() {
		result, err := worker.RunOnce(context.Background())
		done <- struct {
			result Result
			err    error
		}{result: result, err: err}
	}()
	for range claims {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("claimed scans were processed sequentially")
		}
	}
	close(release)
	completed := <-done
	if completed.err != nil || completed.result.Available != len(claims) {
		t.Fatalf("RunOnce() = %+v, %v", completed.result, completed.err)
	}
}

func TestWorkerRejectsClaimWithoutFullOperationLease(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)
	content := []byte("forensic evidence\n")
	claim := testClaim(t, testVerifiedStorage(t, now, content, kernel.ScanScanning), now)
	claim.LeaseUntil = now.Add(time.Minute + minimumLeaseSafety)
	worker := testWorker(
		t, &parallelScanRepository{claims: []Claim{claim}}, &parallelScanStore{content: content},
		&parallelScanner{}, now,
	)
	if _, err := worker.RunOnce(context.Background()); !errors.Is(err, ErrInvalidClaim) {
		t.Fatalf("RunOnce() short-lease error = %v", err)
	}
}

type parallelScanRepository struct{ claims []Claim }

func (*parallelScanRepository) Check(context.Context) error { return nil }
func (repository *parallelScanRepository) Claim(context.Context, uuid.UUID, int, time.Duration, time.Time) ([]Claim, error) {
	return slices.Clone(repository.claims), nil
}
func (*parallelScanRepository) Transition(_ context.Context, input TransitionInput) (kernel.StorageObject, error) {
	return input.Updated, nil
}
func (*parallelScanRepository) Complete(context.Context, CompleteInput) error { return nil }
func (*parallelScanRepository) Retry(context.Context, RetryInput) error       { return nil }
func (*parallelScanRepository) WaitForUpload(context.Context, WaitInput) error {
	return nil
}

type parallelScanStore struct{ content []byte }

func (*parallelScanStore) Check(context.Context) error { return nil }
func (store *parallelScanStore) Open(context.Context, ObjectLocation, int64, string) (ObjectReader, error) {
	content := slices.Clone(store.content)
	return ObjectReader{
		Body: io.NopCloser(bytes.NewReader(content)), SizeBytes: int64(len(content)),
		DeclaredMIME: "text/plain",
	}, nil
}

type parallelScanner struct {
	started chan<- struct{}
	release <-chan struct{}
}

func (*parallelScanner) Check(context.Context) error { return nil }
func (scanner *parallelScanner) Scan(_ context.Context, reader io.Reader, _ int64) (ScanVerdict, error) {
	if scanner.started != nil {
		scanner.started <- struct{}{}
	}
	if scanner.release != nil {
		<-scanner.release
	}
	if _, err := io.Copy(io.Discard, reader); err != nil {
		return "", err
	}
	return ScanClean, nil
}

type scanRepositoryFake struct {
	claims                []Claim
	transitions           []TransitionInput
	completions           []CompleteInput
	retries               []RetryInput
	waits                 []WaitInput
	completedByTransition bool
	transitionError       error
	completionError       error
}

func (*scanRepositoryFake) Check(context.Context) error { return nil }
func (repository *scanRepositoryFake) Claim(context.Context, uuid.UUID, int, time.Duration, time.Time) ([]Claim, error) {
	return slices.Clone(repository.claims), nil
}
func (repository *scanRepositoryFake) Transition(_ context.Context, input TransitionInput) (kernel.StorageObject, error) {
	repository.transitions = append(repository.transitions, input)
	if repository.transitionError != nil {
		return kernel.StorageObject{}, repository.transitionError
	}
	if input.CompleteJob {
		repository.completedByTransition = true
	}
	return input.Updated, nil
}
func (repository *scanRepositoryFake) Complete(_ context.Context, input CompleteInput) error {
	repository.completions = append(repository.completions, input)
	return repository.completionError
}
func (repository *scanRepositoryFake) Retry(_ context.Context, input RetryInput) error {
	repository.retries = append(repository.retries, input)
	return nil
}
func (repository *scanRepositoryFake) WaitForUpload(_ context.Context, input WaitInput) error {
	repository.waits = append(repository.waits, input)
	return nil
}

type scanStoreFake struct {
	bodies       [][]byte
	readers      []ObjectReader
	declaredMIME string
	err          error
	opens        int
}

func (*scanStoreFake) Check(context.Context) error { return nil }
func (store *scanStoreFake) Open(context.Context, ObjectLocation, int64, string) (ObjectReader, error) {
	if store.err != nil {
		return ObjectReader{}, store.err
	}
	if store.opens < len(store.readers) {
		reader := store.readers[store.opens]
		store.opens++
		return reader, nil
	}
	if store.opens >= len(store.bodies) {
		return ObjectReader{}, ErrUnavailable
	}
	content := slices.Clone(store.bodies[store.opens])
	store.opens++
	return ObjectReader{
		Body: io.NopCloser(bytes.NewReader(content)), SizeBytes: int64(len(content)), DeclaredMIME: store.declaredMIME,
	}, nil
}

type scanScannerFake struct {
	verdict ScanVerdict
	err     error
	content []byte
}

func (*scanScannerFake) Check(context.Context) error { return nil }
func (scanner *scanScannerFake) Scan(_ context.Context, reader io.Reader, _ int64) (ScanVerdict, error) {
	content, err := io.ReadAll(reader)
	if err != nil {
		return "", err
	}
	scanner.content = content
	if scanner.err != nil {
		return "", scanner.err
	}
	return scanner.verdict, nil
}

func testWorker(
	t *testing.T,
	repository Repository,
	store ObjectStore,
	scanner MalwareScanner,
	now time.Time,
) *Worker {
	t.Helper()
	workerID := mustUUIDv7(t)
	worker, err := New(Options{
		Repository: repository, Store: store, Scanner: scanner, WorkerID: workerID,
		BatchSize: 4, LeaseDuration: 2 * time.Minute, OperationTimeout: time.Minute,
		UploadPollDelay: 10 * time.Second, RetryBaseDelay: time.Second,
		RetryMaximumDelay: time.Minute, MaximumObjectSize: 10 * 1024 * 1024,
		Clock: func() time.Time { return now }, NewID: uuid.NewV7,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return worker
}

func testClaim(t *testing.T, storage kernel.StorageObject, now time.Time) Claim {
	t.Helper()
	return Claim{
		EventID: mustUUIDv7(t), TenantID: uuid.UUID(storage.TenantID().Bytes()),
		StorageID: uuid.UUID(storage.ID().Bytes()), CorrelationID: mustUUIDv7(t),
		LeaseToken: mustUUIDv7(t), Attempt: 1, MaximumAttempts: MaximumPersistentTries,
		ExecuteAttempt: true, LeaseUntil: now.Add(2 * time.Minute), DeclaredMIME: "text/plain",
		Storage: storage,
	}
}

func testPendingStorage(t *testing.T, now time.Time, size int64) kernel.StorageObject {
	t.Helper()
	storageID, tenantID, creatorID := mustEntityID(t), mustEntityID(t), mustEntityID(t)
	createdAt := now.Add(-time.Minute)
	storage, err := kernel.NewStorageObject(kernel.StorageObjectInput{
		ID: storageID, TenantID: tenantID, Bucket: "periapsis-evidence",
		ObjectKey: tenantID.String() + "/" + storageID.String(), OriginalFilename: "evidence.txt",
		Classification: kernel.EvidenceInternal, ExpectedSizeBytes: size,
		UploadExpiresAt: createdAt.Add(6 * time.Minute), CreatedBy: creatorID, CreatedAt: createdAt,
	})
	if err != nil {
		t.Fatalf("NewStorageObject() error = %v", err)
	}
	return storage
}

func testVerifiedStorage(t *testing.T, now time.Time, content []byte, target kernel.ScanState) kernel.StorageObject {
	t.Helper()
	storage := testPendingStorage(t, now, int64(len(content)))
	var err error
	storage, err = storage.MarkUploaded(storage.Version(), storage.UpdatedAt())
	if err == nil {
		storage, err = storage.BeginVerification(storage.Version(), storage.UpdatedAt())
	}
	digest := sha256.Sum256(content)
	if err == nil {
		storage, err = storage.CompleteVerification(
			storage.Version(), hex.EncodeToString(digest[:]), int64(len(content)),
			detectForTest(content), storage.UpdatedAt(),
		)
	}
	if err == nil && target != kernel.ScanQuarantined {
		storage, err = storage.BeginScan(storage.Version(), storage.UpdatedAt())
	}
	if err != nil {
		t.Fatalf("prepare verified storage: %v", err)
	}
	return storage
}

func testVerifyingStorage(t *testing.T, now time.Time, content []byte) kernel.StorageObject {
	t.Helper()
	storage := testPendingStorage(t, now, int64(len(content)))
	var err error
	storage, err = storage.MarkUploaded(storage.Version(), storage.UpdatedAt())
	if err == nil {
		storage, err = storage.BeginVerification(storage.Version(), storage.UpdatedAt())
	}
	if err != nil {
		t.Fatalf("prepare verifying storage: %v", err)
	}
	return storage
}

func detectForTest(content []byte) string {
	_, _, detected, _, err := readObject(context.Background(), bytes.NewReader(content), 10*1024*1024)
	if err != nil {
		panic(err)
	}
	return detected
}

func mustEntityID(t *testing.T) kernel.EntityID {
	t.Helper()
	value := mustUUIDv7(t)
	id, err := kernel.NewEntityID([16]byte(value))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func mustUUIDv7(t *testing.T) uuid.UUID {
	t.Helper()
	value, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestRepositoryFenceErrorsRemainDistinguishable(t *testing.T) {
	t.Parallel()
	if !errors.Is(classifyRepositoryError(ErrFenceLost), ErrFenceLost) ||
		!errors.Is(classifyRepositoryError(errors.New("database")), ErrUnavailable) {
		t.Fatal("repository error classification widened")
	}
}
