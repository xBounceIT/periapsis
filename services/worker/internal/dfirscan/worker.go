// Package dfirscan consumes the dedicated DFIR storage scan outbox and drives
// every storage transition through a database-fenced repository.
package dfirscan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/dfir"
)

const (
	EventType              = "dfir.storage.scan.requested"
	MaximumBatchSize       = 16
	MaximumPersistentTries = 12
	minimumLeaseSafety     = 5 * time.Second
	mimeSniffPrefixSize    = 512
	filePolicyPrefixSize   = 8 * 1024
)

var (
	ErrInvalidConfiguration = errors.New("DFIR scan worker configuration is invalid")
	ErrInvalidClaim         = errors.New("DFIR scan worker claim is invalid")
	ErrUnavailable          = errors.New("DFIR scan worker dependency is unavailable")
	ErrFenceLost            = errors.New("DFIR scan worker lease was fenced")
	ErrEvidenceCustodyLimit = errors.New("DFIR evidence custody limit is reached")
	ErrObjectNotFound       = errors.New("DFIR object was not found")
	ErrObjectDrift          = errors.New("DFIR object metadata or content drifted")
)

type ObjectLocation struct {
	TenantID uuid.UUID
	ObjectID uuid.UUID
	Bucket   string
	Key      string
}

func (ObjectLocation) String() string            { return "dfirscan.ObjectLocation{[REDACTED]}" }
func (location ObjectLocation) GoString() string { return location.String() }

type ObjectReader struct {
	Body         io.ReadCloser
	SizeBytes    int64
	DeclaredMIME string
}

func (ObjectReader) String() string          { return "dfirscan.ObjectReader{[REDACTED]}" }
func (reader ObjectReader) GoString() string { return reader.String() }

type ScanVerdict string

const (
	ScanClean     ScanVerdict = "clean"
	ScanMalicious ScanVerdict = "malicious"
)

type Claim struct {
	EventID         uuid.UUID
	TenantID        uuid.UUID
	StorageID       uuid.UUID
	CorrelationID   uuid.UUID
	LeaseToken      uuid.UUID
	Attempt         int
	MaximumAttempts int
	ExecuteAttempt  bool
	LeaseUntil      time.Time
	DeclaredMIME    string
	Storage         kernel.StorageObject
}

func (claim Claim) String() string {
	return fmt.Sprintf(
		"dfirscan.Claim{state:%s,attempt:%d,maximumAttempts:%d,execute:%t,location:[REDACTED]}",
		claim.Storage.State(), claim.Attempt, claim.MaximumAttempts, claim.ExecuteAttempt,
	)
}

func (claim Claim) GoString() string { return claim.String() }

type Fence struct {
	EventID    uuid.UUID
	LeaseToken uuid.UUID
}

type TransitionIDs struct {
	OperationID uuid.UUID
	RequestID   uuid.UUID
	AuditID     uuid.UUID
	OutboxID    uuid.UUID
}

type TransitionInput struct {
	Fence           Fence
	Current         kernel.StorageObject
	Updated         kernel.StorageObject
	TransitionedAt  time.Time
	IDs             TransitionIDs
	CompleteJob     bool
	FailureCategory string
	FileTypeClass   string
	FileTypeReason  string
}

type CompleteInput struct {
	Fence           Fence
	CompletedAt     time.Time
	FailureCategory string
	DeadLetter      bool
}

type RetryInput struct {
	Fence           Fence
	FailedAt        time.Time
	RetryAt         time.Time
	FailureCategory string
}

type WaitInput struct {
	Fence       Fence
	ObservedAt  time.Time
	AvailableAt time.Time
}

type Repository interface {
	Check(context.Context) error
	Claim(context.Context, uuid.UUID, int, time.Duration, time.Time) ([]Claim, error)
	Transition(context.Context, TransitionInput) (kernel.StorageObject, error)
	Complete(context.Context, CompleteInput) error
	Retry(context.Context, RetryInput) error
	WaitForUpload(context.Context, WaitInput) error
}

type ObjectStore interface {
	Check(context.Context) error
	Open(context.Context, ObjectLocation, int64, string) (ObjectReader, error)
}

type MalwareScanner interface {
	Check(context.Context) error
	Scan(context.Context, io.Reader, int64) (ScanVerdict, error)
}

type Options struct {
	Repository        Repository
	Store             ObjectStore
	Scanner           MalwareScanner
	WorkerID          uuid.UUID
	BatchSize         int
	LeaseDuration     time.Duration
	OperationTimeout  time.Duration
	UploadPollDelay   time.Duration
	RetryBaseDelay    time.Duration
	RetryMaximumDelay time.Duration
	MaximumObjectSize int64
	Clock             func() time.Time
	NewID             func() (uuid.UUID, error)
}

type Worker struct {
	repository        Repository
	store             ObjectStore
	scanner           MalwareScanner
	workerID          uuid.UUID
	batchSize         int
	leaseDuration     time.Duration
	operationTimeout  time.Duration
	uploadPollDelay   time.Duration
	retryBaseDelay    time.Duration
	retryMaximumDelay time.Duration
	maximumObjectSize int64
	clock             func() time.Time
	newID             func() (uuid.UUID, error)
	clockMu           sync.Mutex
	idMu              sync.Mutex
}

type Result struct {
	Claimed        int
	Available      int
	Rejected       int
	ScanFailed     int
	WaitingUpload  int
	UploadExpired  int
	RetryScheduled int
	FenceLost      int
}

type outcome uint8

const (
	outcomeAvailable outcome = iota + 1
	outcomeRejected
	outcomeScanFailed
	outcomeWaiting
	outcomeExpired
	outcomeRetry
	outcomeFenceLost
)

func New(options Options) (*Worker, error) {
	if options.Repository == nil || options.Store == nil || options.Scanner == nil ||
		options.WorkerID.Version() != 7 || options.Clock == nil || options.NewID == nil ||
		options.BatchSize < 1 || options.BatchSize > MaximumBatchSize ||
		options.LeaseDuration < 30*time.Second || options.LeaseDuration > 30*time.Minute ||
		options.OperationTimeout < 10*time.Second || options.OperationTimeout > 15*time.Minute ||
		options.OperationTimeout+minimumLeaseSafety >= options.LeaseDuration ||
		options.UploadPollDelay < time.Second || options.UploadPollDelay > time.Minute ||
		options.RetryBaseDelay < time.Second || options.RetryBaseDelay > time.Hour ||
		options.RetryMaximumDelay < options.RetryBaseDelay || options.RetryMaximumDelay > 24*time.Hour ||
		options.MaximumObjectSize < 1024*1024 || options.MaximumObjectSize > 5_000_000_000 {
		return nil, ErrInvalidConfiguration
	}
	return &Worker{
		repository: options.Repository, store: options.Store, scanner: options.Scanner,
		workerID: options.WorkerID, batchSize: options.BatchSize,
		leaseDuration: options.LeaseDuration, operationTimeout: options.OperationTimeout,
		uploadPollDelay: options.UploadPollDelay, retryBaseDelay: options.RetryBaseDelay,
		retryMaximumDelay: options.RetryMaximumDelay, maximumObjectSize: options.MaximumObjectSize,
		clock: options.Clock, newID: options.NewID,
	}, nil
}

func (worker *Worker) Check(ctx context.Context) error {
	if worker == nil || ctx == nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	for _, check := range []func(context.Context) error{
		worker.repository.Check, worker.store.Check, worker.scanner.Check,
	} {
		checkContext, cancel := context.WithTimeout(ctx, min(worker.operationTimeout, 10*time.Second))
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
	claims, err := worker.repository.Claim(ctx, worker.workerID, worker.batchSize, worker.leaseDuration, now)
	if err != nil || len(claims) > worker.batchSize {
		return Result{}, ErrUnavailable
	}
	result := Result{Claimed: len(claims)}
	type processedClaim struct {
		outcome outcome
		err     error
	}
	processed := make(chan processedClaim, len(claims))
	for _, claim := range claims {
		claim := claim
		go func() {
			claimNow := worker.now()
			if err := validateClaim(
				claim, claimNow, worker.leaseDuration, worker.operationTimeout, worker.maximumObjectSize,
			); err != nil {
				processed <- processedClaim{err: err}
				return
			}
			attemptContext, cancel := context.WithTimeout(ctx, worker.operationTimeout)
			classified, runErr := worker.process(attemptContext, claim)
			if errors.Is(runErr, ErrEvidenceCustodyLimit) {
				runErr = worker.complete(attemptContext, claim, true, "evidence_custody_limit")
				classified = outcomeScanFailed
			}
			cancel()
			processed <- processedClaim{outcome: classified, err: runErr}
		}()
	}
	var firstError error
	for range claims {
		completed := <-processed
		classified, runErr := completed.outcome, completed.err
		if runErr != nil {
			if errors.Is(runErr, ErrFenceLost) {
				result.FenceLost++
				continue
			}
			if firstError == nil {
				firstError = runErr
			}
			continue
		}
		switch classified {
		case outcomeAvailable:
			result.Available++
		case outcomeRejected:
			result.Rejected++
		case outcomeScanFailed:
			result.ScanFailed++
		case outcomeWaiting:
			result.WaitingUpload++
		case outcomeExpired:
			result.UploadExpired++
		case outcomeRetry:
			result.RetryScheduled++
		case outcomeFenceLost:
			result.FenceLost++
		default:
			if firstError == nil {
				firstError = ErrUnavailable
			}
		}
	}
	return result, firstError
}

func (worker *Worker) process(ctx context.Context, claim Claim) (outcome, error) {
	if !claim.ExecuteAttempt {
		return worker.exhaust(ctx, claim, "attempts_exhausted")
	}
	switch claim.Storage.State() {
	case kernel.ScanAvailable, kernel.ScanRejected, kernel.ScanDeleted:
		if err := worker.complete(ctx, claim, false, ""); err != nil {
			return 0, err
		}
		if claim.Storage.State() == kernel.ScanAvailable {
			return outcomeAvailable, nil
		}
		return outcomeRejected, nil
	case kernel.ScanFailed:
		updated, err := claim.Storage.RetryScan(claim.Storage.Version(), worker.transitionTime(claim.Storage))
		if err != nil {
			return 0, ErrInvalidClaim
		}
		claim.Storage, err = worker.transition(ctx, claim, updated, false, "")
		if err != nil {
			return 0, err
		}
		return worker.scan(ctx, claim)
	case kernel.ScanQuarantined:
		updated, err := claim.Storage.BeginScan(claim.Storage.Version(), worker.transitionTime(claim.Storage))
		if err != nil {
			return 0, ErrInvalidClaim
		}
		claim.Storage, err = worker.transition(ctx, claim, updated, false, "")
		if err != nil {
			return 0, err
		}
		return worker.scan(ctx, claim)
	case kernel.ScanScanning:
		return worker.scan(ctx, claim)
	case kernel.ScanPendingUpload:
		return worker.pending(ctx, claim)
	case kernel.ScanUploaded, kernel.ScanVerifying:
		return worker.verify(ctx, claim, ObjectReader{})
	default:
		return 0, ErrInvalidClaim
	}
}

func (worker *Worker) pending(ctx context.Context, claim Claim) (outcome, error) {
	reader, err := worker.store.Open(ctx, locationFor(claim), claim.Storage.ExpectedSizeBytes(), claim.DeclaredMIME)
	if err != nil {
		now := worker.now()
		switch {
		case errors.Is(err, ErrObjectNotFound) && claim.Storage.UploadExpiresAt().After(now):
			availableAt := now.Add(worker.uploadPollDelay)
			if availableAt.After(claim.Storage.UploadExpiresAt()) {
				availableAt = claim.Storage.UploadExpiresAt()
			}
			if waitErr := worker.repository.WaitForUpload(ctx, WaitInput{
				Fence: fenceFor(claim), ObservedAt: now, AvailableAt: availableAt,
			}); waitErr != nil {
				return 0, classifyRepositoryError(waitErr)
			}
			return outcomeWaiting, nil
		case errors.Is(err, ErrObjectNotFound):
			if completeErr := worker.complete(ctx, claim, false, "upload_expired"); completeErr != nil {
				return 0, completeErr
			}
			return outcomeExpired, nil
		case errors.Is(err, ErrObjectDrift):
			return worker.rejectUnverified(ctx, claim, "object_metadata_drift")
		default:
			return worker.retryOrExhaust(ctx, claim, "storage_unavailable", false)
		}
	}
	if readerErr := validateObjectReader(reader, claim.Storage.ExpectedSizeBytes(), claim.DeclaredMIME); readerErr != nil {
		closeObjectReader(reader)
		if errors.Is(readerErr, ErrObjectDrift) {
			return worker.rejectUnverified(ctx, claim, "object_metadata_drift")
		}
		return worker.retryOrExhaust(ctx, claim, "storage_unavailable", false)
	}
	defer reader.Body.Close()
	updated, transitionErr := claim.Storage.MarkUploaded(
		claim.Storage.Version(), worker.transitionTime(claim.Storage),
	)
	if transitionErr != nil {
		return 0, ErrInvalidClaim
	}
	claim.Storage, transitionErr = worker.transition(ctx, claim, updated, false, "")
	if transitionErr != nil {
		return 0, transitionErr
	}
	return worker.verify(ctx, claim, reader)
}

func (worker *Worker) verify(ctx context.Context, claim Claim, reader ObjectReader) (outcome, error) {
	if claim.Storage.State() == kernel.ScanUploaded {
		updated, err := claim.Storage.BeginVerification(
			claim.Storage.Version(), worker.transitionTime(claim.Storage),
		)
		if err != nil {
			return 0, ErrInvalidClaim
		}
		claim.Storage, err = worker.transition(ctx, claim, updated, false, "")
		if err != nil {
			return 0, err
		}
	}
	if claim.Storage.State() != kernel.ScanVerifying {
		return 0, ErrInvalidClaim
	}
	openedHere := false
	if reader.Body == nil {
		opened, err := worker.store.Open(ctx, locationFor(claim), claim.Storage.ExpectedSizeBytes(), claim.DeclaredMIME)
		if err != nil {
			if errors.Is(err, ErrObjectNotFound) || errors.Is(err, ErrObjectDrift) {
				return worker.rejectUnverified(ctx, claim, "object_verification_drift")
			}
			return worker.retryOrExhaust(ctx, claim, "storage_unavailable", false)
		}
		reader = opened
		openedHere = true
	}
	if readerErr := validateObjectReader(reader, claim.Storage.ExpectedSizeBytes(), claim.DeclaredMIME); readerErr != nil {
		if openedHere {
			closeObjectReader(reader)
		}
		if errors.Is(readerErr, ErrObjectDrift) {
			return worker.rejectUnverified(ctx, claim, "object_verification_drift")
		}
		return worker.retryOrExhaust(ctx, claim, "storage_unavailable", false)
	}
	if openedHere {
		defer reader.Body.Close()
	}
	digest, size, detected, _, err := readObject(ctx, reader.Body, worker.maximumObjectSize)
	if err != nil || size != claim.Storage.ExpectedSizeBytes() {
		return worker.rejectUnverified(ctx, claim, "object_content_drift")
	}
	updated, err := claim.Storage.CompleteVerification(
		claim.Storage.Version(), digest, size, detected, worker.transitionTime(claim.Storage),
	)
	if err != nil {
		return worker.rejectUnverified(ctx, claim, "object_content_invalid")
	}
	claim.Storage, err = worker.transition(ctx, claim, updated, false, "")
	if err != nil {
		return 0, err
	}
	updated, err = claim.Storage.BeginScan(claim.Storage.Version(), worker.transitionTime(claim.Storage))
	if err != nil {
		return 0, ErrInvalidClaim
	}
	claim.Storage, err = worker.transition(ctx, claim, updated, false, "")
	if err != nil {
		return 0, err
	}
	return worker.scan(ctx, claim)
}

func (worker *Worker) scan(ctx context.Context, claim Claim) (outcome, error) {
	if claim.Storage.State() != kernel.ScanScanning || claim.Storage.SizeBytes() <= 0 {
		return 0, ErrInvalidClaim
	}
	reader, err := worker.store.Open(ctx, locationFor(claim), claim.Storage.SizeBytes(), claim.DeclaredMIME)
	if err != nil {
		if errors.Is(err, ErrObjectNotFound) || errors.Is(err, ErrObjectDrift) {
			return worker.rejectScanning(ctx, claim, "object_metadata_drift", "", "")
		}
		return worker.retryOrExhaust(ctx, claim, "storage_unavailable", true)
	}
	if readerErr := validateObjectReader(reader, claim.Storage.SizeBytes(), claim.DeclaredMIME); readerErr != nil {
		closeObjectReader(reader)
		if errors.Is(readerErr, ErrObjectDrift) {
			return worker.rejectScanning(ctx, claim, "object_metadata_drift", "", "")
		}
		return worker.retryOrExhaust(ctx, claim, "storage_unavailable", true)
	}
	defer reader.Body.Close()

	prefix := make([]byte, filePolicyPrefixSize)
	read, readErr := io.ReadFull(contextReader{ctx: ctx, reader: reader.Body}, prefix)
	if readErr != nil && !errors.Is(readErr, io.EOF) && !errors.Is(readErr, io.ErrUnexpectedEOF) {
		return worker.retryOrExhaust(ctx, claim, "object_stream_unavailable", true)
	}
	prefix = prefix[:read]
	detected := http.DetectContentType(prefix[:min(len(prefix), mimeSniffPrefixSize)])
	decision := kernel.DecideFileType(kernel.FileTypeInput{
		DeclaredMIME:  reader.DeclaredMIME,
		DetectedMIME:  detected,
		ContentPrefix: prefix,
	})

	hash := sha256.New()
	counting := &countingWriter{writer: hash, maximum: worker.maximumObjectSize}
	stream := io.TeeReader(
		io.MultiReader(bytes.NewReader(prefix), contextReader{ctx: ctx, reader: reader.Body}),
		counting,
	)
	verdict := ScanClean
	var scanErr error
	if decision.Allowed() {
		verdict, scanErr = worker.scanner.Scan(ctx, stream, worker.maximumObjectSize)
	} else {
		_, scanErr = io.Copy(io.Discard, stream)
	}
	if _, drainErr := io.Copy(io.Discard, stream); drainErr != nil && scanErr == nil {
		scanErr = drainErr
	}
	digest := hex.EncodeToString(hash.Sum(nil))
	contentMatches := counting.err == nil && counting.total == claim.Storage.SizeBytes() &&
		constantTimeTextEqual(digest, claim.Storage.ContentSHA256()) &&
		decision.CanonicalDetectedMIME() == claim.Storage.DetectedMIME()
	if !contentMatches {
		return worker.rejectScanning(ctx, claim, "object_content_drift", "", "")
	}
	if !decision.Allowed() {
		return worker.rejectScanning(
			ctx, claim, fileTypeFailureCategory(decision),
			string(decision.Class()), string(decision.Reason()),
		)
	}
	if scanErr != nil {
		return worker.retryOrExhaust(ctx, claim, "scanner_unavailable", true)
	}
	switch verdict {
	case ScanClean:
		updated, transitionErr := claim.Storage.CompleteScan(
			claim.Storage.Version(), kernel.ScanAvailable, worker.transitionTime(claim.Storage),
		)
		if transitionErr != nil {
			return 0, ErrInvalidClaim
		}
		if _, transitionErr = worker.transition(ctx, claim, updated, true, ""); transitionErr != nil {
			return 0, transitionErr
		}
		return outcomeAvailable, nil
	case ScanMalicious:
		return worker.rejectScanning(ctx, claim, "malware_detected", "", "")
	default:
		return worker.retryOrExhaust(ctx, claim, "scanner_invalid_verdict", true)
	}
}

func (worker *Worker) rejectUnverified(ctx context.Context, claim Claim, category string) (outcome, error) {
	var err error
	if claim.Storage.State() == kernel.ScanPendingUpload {
		updated, updateErr := claim.Storage.MarkUploaded(claim.Storage.Version(), worker.transitionTime(claim.Storage))
		if updateErr != nil {
			return 0, ErrInvalidClaim
		}
		claim.Storage, err = worker.transition(ctx, claim, updated, false, "")
		if err != nil {
			return 0, err
		}
	}
	if claim.Storage.State() == kernel.ScanUploaded {
		updated, updateErr := claim.Storage.BeginVerification(claim.Storage.Version(), worker.transitionTime(claim.Storage))
		if updateErr != nil {
			return 0, ErrInvalidClaim
		}
		claim.Storage, err = worker.transition(ctx, claim, updated, false, "")
		if err != nil {
			return 0, err
		}
	}
	if claim.Storage.State() != kernel.ScanVerifying {
		return 0, ErrInvalidClaim
	}
	updated, err := claim.Storage.RejectVerification(claim.Storage.Version(), worker.transitionTime(claim.Storage))
	if err != nil {
		return 0, ErrInvalidClaim
	}
	if _, err = worker.transition(ctx, claim, updated, true, category); err != nil {
		return 0, err
	}
	return outcomeRejected, nil
}

func (worker *Worker) rejectScanning(
	ctx context.Context,
	claim Claim,
	category string,
	fileTypeClass string,
	fileTypeReason string,
) (outcome, error) {
	updated, err := claim.Storage.CompleteScan(
		claim.Storage.Version(), kernel.ScanRejected, worker.transitionTime(claim.Storage),
	)
	if err != nil {
		return 0, ErrInvalidClaim
	}
	if _, err = worker.transitionWithPolicy(
		ctx, claim, updated, true, category, fileTypeClass, fileTypeReason,
	); err != nil {
		return 0, err
	}
	return outcomeRejected, nil
}

func (worker *Worker) retryOrExhaust(
	ctx context.Context,
	claim Claim,
	category string,
	verified bool,
) (outcome, error) {
	if claim.Attempt >= claim.MaximumAttempts {
		return worker.exhaust(ctx, claim, category)
	}
	if verified && claim.Storage.State() == kernel.ScanScanning {
		updated, err := claim.Storage.CompleteScan(
			claim.Storage.Version(), kernel.ScanFailed, worker.transitionTime(claim.Storage),
		)
		if err != nil {
			return 0, ErrInvalidClaim
		}
		var transitionErr error
		claim.Storage, transitionErr = worker.transition(ctx, claim, updated, false, category)
		if transitionErr != nil {
			return 0, transitionErr
		}
	}
	failedAt := worker.now()
	delay := exponentialDelay(worker.retryBaseDelay, worker.retryMaximumDelay, claim.Attempt)
	if err := worker.repository.Retry(ctx, RetryInput{
		Fence: fenceFor(claim), FailedAt: failedAt, RetryAt: failedAt.Add(delay), FailureCategory: category,
	}); err != nil {
		return 0, classifyRepositoryError(err)
	}
	return outcomeRetry, nil
}

func (worker *Worker) exhaust(ctx context.Context, claim Claim, category string) (outcome, error) {
	if claim.Storage.State() == kernel.ScanAvailable || claim.Storage.State() == kernel.ScanRejected ||
		claim.Storage.State() == kernel.ScanDeleted {
		if err := worker.complete(ctx, claim, false, category); err != nil {
			return 0, err
		}
		if claim.Storage.State() == kernel.ScanAvailable {
			return outcomeAvailable, nil
		}
		return outcomeRejected, nil
	}
	if claim.Storage.State() == kernel.ScanFailed {
		if err := worker.complete(ctx, claim, true, category); err != nil {
			return 0, err
		}
		return outcomeScanFailed, nil
	}
	if claim.Storage.State() == kernel.ScanPendingUpload {
		if claim.Storage.UploadExpiresAt().After(worker.now()) {
			return 0, ErrInvalidClaim
		}
		if err := worker.complete(ctx, claim, false, "upload_expired"); err != nil {
			return 0, err
		}
		return outcomeExpired, nil
	}
	if claim.Storage.State() == kernel.ScanUploaded ||
		claim.Storage.State() == kernel.ScanVerifying {
		return worker.rejectUnverified(ctx, claim, category)
	}
	if claim.Storage.State() == kernel.ScanQuarantined {
		updated, err := claim.Storage.BeginScan(claim.Storage.Version(), worker.transitionTime(claim.Storage))
		if err != nil {
			return 0, ErrInvalidClaim
		}
		claim.Storage, err = worker.transition(ctx, claim, updated, false, "")
		if err != nil {
			return 0, err
		}
	}
	if claim.Storage.State() != kernel.ScanScanning {
		return 0, ErrInvalidClaim
	}
	updated, err := claim.Storage.CompleteScan(
		claim.Storage.Version(), kernel.ScanFailed, worker.transitionTime(claim.Storage),
	)
	if err != nil {
		return 0, ErrInvalidClaim
	}
	if _, err = worker.transition(ctx, claim, updated, true, category); err != nil {
		return 0, err
	}
	return outcomeScanFailed, nil
}

func (worker *Worker) transition(
	ctx context.Context,
	claim Claim,
	updated kernel.StorageObject,
	complete bool,
	category string,
) (kernel.StorageObject, error) {
	return worker.transitionWithPolicy(ctx, claim, updated, complete, category, "", "")
}

func (worker *Worker) transitionWithPolicy(
	ctx context.Context,
	claim Claim,
	updated kernel.StorageObject,
	complete bool,
	category string,
	fileTypeClass string,
	fileTypeReason string,
) (kernel.StorageObject, error) {
	ids, err := worker.ids()
	if err != nil {
		return kernel.StorageObject{}, err
	}
	transitionedAt := updated.UpdatedAt()
	stored, err := worker.repository.Transition(ctx, TransitionInput{
		Fence: fenceFor(claim), Current: claim.Storage, Updated: updated,
		TransitionedAt: transitionedAt, IDs: ids, CompleteJob: complete,
		FailureCategory: category, FileTypeClass: fileTypeClass, FileTypeReason: fileTypeReason,
	})
	if err != nil {
		return kernel.StorageObject{}, classifyRepositoryError(err)
	}
	if !sameStorageTransition(stored, updated) {
		return kernel.StorageObject{}, ErrUnavailable
	}
	return stored, nil
}

func (worker *Worker) complete(ctx context.Context, claim Claim, deadLetter bool, category string) error {
	err := worker.repository.Complete(ctx, CompleteInput{
		Fence: fenceFor(claim), CompletedAt: worker.now(),
		FailureCategory: category, DeadLetter: deadLetter,
	})
	return classifyRepositoryError(err)
}

func (worker *Worker) ids() (TransitionIDs, error) {
	worker.idMu.Lock()
	defer worker.idMu.Unlock()
	values := make([]uuid.UUID, 4)
	seen := make(map[uuid.UUID]struct{}, len(values))
	for index := range values {
		value, err := worker.newID()
		if err != nil || value.Version() != 7 {
			return TransitionIDs{}, ErrUnavailable
		}
		if _, duplicate := seen[value]; duplicate {
			return TransitionIDs{}, ErrUnavailable
		}
		seen[value] = struct{}{}
		values[index] = value
	}
	return TransitionIDs{
		OperationID: values[0], RequestID: values[1], AuditID: values[2], OutboxID: values[3],
	}, nil
}

func (worker *Worker) transitionTime(current kernel.StorageObject) time.Time {
	now := worker.now()
	if now.Before(current.UpdatedAt()) {
		return current.UpdatedAt()
	}
	return now
}

func (worker *Worker) now() time.Time {
	worker.clockMu.Lock()
	defer worker.clockMu.Unlock()
	return canonicalTime(worker.clock())
}

func validateClaim(
	claim Claim,
	now time.Time,
	lease time.Duration,
	operationTimeout time.Duration,
	maximum int64,
) error {
	snapshot := claim.Storage.Snapshot()
	if claim.EventID.Version() != 7 || claim.TenantID.Version() != 7 || claim.StorageID.Version() != 7 ||
		claim.CorrelationID.Version() != 7 || claim.LeaseToken.Version() != 7 ||
		claim.Attempt < 1 || claim.Attempt > claim.MaximumAttempts ||
		claim.MaximumAttempts < 1 || claim.MaximumAttempts > MaximumPersistentTries ||
		!claim.ExecuteAttempt && claim.Attempt != claim.MaximumAttempts ||
		!claim.LeaseUntil.After(now.Add(operationTimeout+minimumLeaseSafety)) ||
		claim.LeaseUntil.After(now.Add(lease+time.Minute)) ||
		snapshot.ID.String() != claim.StorageID.String() || snapshot.TenantID.String() != claim.TenantID.String() ||
		claim.Storage.ExpectedSizeBytes() <= 0 || claim.Storage.ExpectedSizeBytes() > maximum ||
		claim.Storage.Bucket() == "" || claim.Storage.ObjectKey() != claim.TenantID.String()+"/"+claim.StorageID.String() ||
		claim.DeclaredMIME == "" || len(claim.DeclaredMIME) > kernel.MaximumFileTypeMIMEBytes {
		return ErrInvalidClaim
	}
	return nil
}

func locationFor(claim Claim) ObjectLocation {
	return ObjectLocation{
		TenantID: claim.TenantID, ObjectID: claim.StorageID,
		Bucket: claim.Storage.Bucket(), Key: claim.Storage.ObjectKey(),
	}
}

func fenceFor(claim Claim) Fence {
	return Fence{EventID: claim.EventID, LeaseToken: claim.LeaseToken}
}

func validateObjectReader(reader ObjectReader, expectedSize int64, expectedDeclaredMIME string) error {
	if reader.Body == nil {
		return ErrUnavailable
	}
	if reader.SizeBytes != expectedSize || reader.DeclaredMIME != expectedDeclaredMIME {
		return ErrObjectDrift
	}
	return nil
}

func closeObjectReader(reader ObjectReader) {
	if reader.Body != nil {
		_ = reader.Body.Close()
	}
}

func readObject(ctx context.Context, body io.Reader, maximum int64) (string, int64, string, []byte, error) {
	if ctx == nil || ctx.Err() != nil || body == nil || maximum <= 0 || maximum > 5_000_000_000 {
		return "", 0, "", nil, ErrObjectDrift
	}
	hash := sha256.New()
	prefix := make([]byte, mimeSniffPrefixSize)
	read, err := io.ReadFull(contextReader{ctx: ctx, reader: body}, prefix)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return "", 0, "", nil, ErrObjectDrift
	}
	prefix = prefix[:read]
	if _, err = hash.Write(prefix); err != nil {
		return "", 0, "", nil, ErrObjectDrift
	}
	copied, err := io.Copy(hash, io.LimitReader(contextReader{ctx: ctx, reader: body}, maximum-int64(read)+1))
	if err != nil || int64(read)+copied > maximum {
		return "", 0, "", nil, ErrObjectDrift
	}
	return hex.EncodeToString(hash.Sum(nil)), int64(read) + copied, http.DetectContentType(prefix), slices.Clone(prefix), nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader contextReader) Read(target []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(target)
}

type countingWriter struct {
	writer  io.Writer
	maximum int64
	total   int64
	err     error
}

func (writer *countingWriter) Write(value []byte) (int, error) {
	if writer == nil || writer.writer == nil || writer.err != nil || int64(len(value)) > writer.maximum-writer.total {
		if writer != nil {
			writer.err = ErrObjectDrift
		}
		return 0, ErrObjectDrift
	}
	written, err := writer.writer.Write(value)
	if written < 0 || written > len(value) || written != len(value) || err != nil {
		writer.err = ErrObjectDrift
		return written, ErrObjectDrift
	}
	writer.total += int64(written)
	return written, nil
}

func sameStorageTransition(left, right kernel.StorageObject) bool {
	leftState, rightState := left.Snapshot(), right.Snapshot()
	return leftState.ID == rightState.ID && leftState.TenantID == rightState.TenantID &&
		leftState.Bucket == rightState.Bucket && leftState.ObjectKey == rightState.ObjectKey &&
		leftState.OriginalFilename == rightState.OriginalFilename &&
		leftState.Classification == rightState.Classification &&
		leftState.ExpectedSizeBytes == rightState.ExpectedSizeBytes &&
		leftState.UploadExpiresAt.Equal(rightState.UploadExpiresAt) &&
		leftState.CreatedBy == rightState.CreatedBy && leftState.CreatedAt.Equal(rightState.CreatedAt) &&
		leftState.State == rightState.State && leftState.Version == rightState.Version &&
		leftState.UpdatedAt.Equal(rightState.UpdatedAt) &&
		leftState.ContentSHA256 == rightState.ContentSHA256 && leftState.SizeBytes == rightState.SizeBytes &&
		leftState.DetectedMIME == rightState.DetectedMIME &&
		sameOptionalTime(leftState.VerifiedAt, rightState.VerifiedAt) &&
		sameOptionalTime(leftState.RetentionUntil, rightState.RetentionUntil) &&
		leftState.LegalHold == rightState.LegalHold
}

func sameOptionalTime(left, right *time.Time) bool {
	return left == nil && right == nil || left != nil && right != nil && left.Equal(*right)
}

func exponentialDelay(base, maximum time.Duration, attempt int) time.Duration {
	delay := base
	for current := 1; current < attempt && delay < maximum; current++ {
		if delay > maximum/2 {
			return maximum
		}
		delay *= 2
	}
	return min(delay, maximum)
}

func fileTypeFailureCategory(decision kernel.FileTypeDecision) string {
	if decision.Allowed() {
		return ""
	}
	return "file_policy_" + string(decision.Reason())
}

func constantTimeTextEqual(left, right string) bool {
	return len(left) == len(right) && subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func canonicalTime(value time.Time) time.Time { return value.UTC().Truncate(time.Microsecond) }

func classifyRepositoryError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrFenceLost) {
		return ErrFenceLost
	}
	if errors.Is(err, ErrEvidenceCustodyLimit) {
		return ErrEvidenceCustodyLimit
	}
	return ErrUnavailable
}
