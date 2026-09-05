package auditoperations

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/google/uuid"
)

type Worker struct {
	repository       Repository
	artifacts        ArtifactStore
	signer           SegmentSigner
	workerID         uuid.UUID
	pageSize         int
	tenantBatch      int
	retentionRows    int
	receiptBatch     int
	leaseDuration    time.Duration
	operationTimeout time.Duration
	spoolDirectory   string
	newID            func() (uuid.UUID, error)
}

func New(options Options) (*Worker, error) {
	if nilDependency(options.Repository) || nilDependency(options.Artifacts) || nilDependency(options.Signer) ||
		!validUUIDv7(options.WorkerID) || options.PageSize < 1 || options.PageSize > MaximumPageSize ||
		options.TenantBatch < 1 || options.TenantBatch > MaximumTenantBatch ||
		options.RetentionRows < 1 || options.RetentionRows > MaximumRetentionRows ||
		options.ReceiptBatch < 1 || options.ReceiptBatch > MaximumPageSize ||
		options.LeaseDuration < 30*time.Second || options.LeaseDuration > 15*time.Minute ||
		options.LeaseDuration%time.Microsecond != 0 || options.OperationTimeout < time.Second ||
		options.OperationTimeout > 5*time.Minute || options.OperationTimeout >= options.LeaseDuration ||
		options.OperationTimeout%time.Microsecond != 0 || options.NewID == nil ||
		options.SpoolDirectory == "" || !filepath.IsAbs(options.SpoolDirectory) ||
		filepath.Clean(options.SpoolDirectory) != options.SpoolDirectory {
		return nil, ErrInvalidConfiguration
	}
	return &Worker{
		repository: options.Repository, artifacts: options.Artifacts, signer: options.Signer,
		workerID: options.WorkerID, pageSize: options.PageSize, tenantBatch: options.TenantBatch,
		retentionRows: options.RetentionRows, receiptBatch: options.ReceiptBatch,
		leaseDuration: options.LeaseDuration, operationTimeout: options.OperationTimeout,
		spoolDirectory: options.SpoolDirectory, newID: options.NewID,
	}, nil
}

func (worker *Worker) Check(ctx context.Context) error {
	if worker == nil || ctx == nil || ctx.Err() != nil {
		return ErrInvalidInput
	}
	checkContext, cancel := context.WithTimeout(ctx, worker.operationTimeout)
	defer cancel()
	return worker.artifacts.Check(checkContext)
}

func (worker *Worker) RunOnce(ctx context.Context) (Summary, error) {
	if worker == nil || ctx == nil || ctx.Err() != nil {
		return Summary{}, ErrInvalidInput
	}
	var summary Summary
	var failures []error
	for _, stream := range []Stream{TenantStream, PlatformStream} {
		result, err := worker.runExport(ctx, stream)
		summary.ExportsClaimed += result.ExportsClaimed
		summary.ExportsSucceeded += result.ExportsSucceeded
		summary.ExportsDiscarded += result.ExportsDiscarded
		if err != nil {
			failures = append(failures, err)
		}
	}
	platformSummary, err := worker.runRetention(ctx, PlatformStream, uuid.Nil)
	mergeSummary(&summary, platformSummary)
	if err != nil {
		failures = append(failures, err)
	}
	candidates, err := worker.listTenantCandidates(ctx)
	if err != nil {
		failures = append(failures, err)
	} else {
		for _, tenantID := range candidates {
			if ctx.Err() != nil {
				failures = append(failures, ctx.Err())
				break
			}
			result, retentionErr := worker.runRetention(ctx, TenantStream, tenantID)
			mergeSummary(&summary, result)
			if retentionErr != nil {
				failures = append(failures, retentionErr)
			}
			receipts, receiptErr := worker.pruneTenantReceipts(ctx, tenantID)
			summary.ReceiptsPruned += receipts
			if receiptErr != nil {
				failures = append(failures, receiptErr)
			}
		}
	}
	receipts, err := worker.prunePlatformReceipts(ctx)
	summary.ReceiptsPruned += receipts
	if err != nil {
		failures = append(failures, err)
	}
	return summary, errors.Join(failures...)
}

func (worker *Worker) runExport(ctx context.Context, stream Stream) (Summary, error) {
	fence, err := newFence()
	if err != nil {
		return Summary{}, ErrUnavailable
	}
	auditID, err := worker.id()
	if err != nil {
		return Summary{}, err
	}
	claimContext, cancelClaim := context.WithTimeout(ctx, worker.operationTimeout)
	claim, found, err := worker.repository.ClaimExport(
		claimContext, stream, worker.workerID, fence, worker.leaseDuration, auditID,
	)
	cancelClaim()
	if err != nil || !found {
		return Summary{}, err
	}
	if err := validExportClaim(claim, stream, worker.workerID, fence); err != nil {
		return Summary{ExportsClaimed: 1}, err
	}
	deadline := claim.LeaseExpiresAt.Add(-time.Second)
	if !deadline.After(time.Now()) {
		return Summary{ExportsClaimed: 1}, ErrFenceLost
	}
	attemptContext, cancelAttempt := context.WithDeadline(ctx, deadline)
	defer cancelAttempt()
	spool, stats, err := worker.spoolExport(attemptContext, claim)
	if err != nil {
		return Summary{ExportsClaimed: 1}, err
	}
	defer os.Remove(spool)
	artifactID, err := worker.id()
	if err != nil {
		return Summary{ExportsClaimed: 1}, err
	}
	artifact := Artifact{
		Kind: ExportArtifactKind, Stream: stream, TenantID: claim.TenantID,
		JobID: claim.JobID, ArtifactID: artifactID, ProjectionVersion: 1, Format: "jsonl",
		ObjectKey: claim.ObjectKey, Digest: stats.digest, Rows: stats.rows,
		Bytes: stats.bytes, Path: spool,
	}
	if err := worker.artifacts.Put(attemptContext, artifact); err != nil {
		return Summary{ExportsClaimed: 1}, err
	}
	finalAuditID, err := worker.id()
	if err != nil {
		return Summary{ExportsClaimed: 1}, err
	}
	finalContext, cancelFinal := context.WithTimeout(attemptContext, worker.operationTimeout)
	finalization, err := worker.repository.FinalizeExport(
		finalContext, claim, artifactID, stats.digest, stats.rows, stats.bytes, finalAuditID,
	)
	cancelFinal()
	if err != nil {
		// Outcome is ambiguous; the create-only artifact remains inaccessible
		// unless an exact database manifest committed.
		return Summary{ExportsClaimed: 1}, err
	}
	switch finalization.State {
	case "succeeded":
		return Summary{ExportsClaimed: 1, ExportsSucceeded: 1}, nil
	case "cancelled", "expired", "authorization_revoked":
		deleteContext, cancelDelete := context.WithTimeout(ctx, worker.operationTimeout)
		deleteErr := worker.artifacts.DeleteExact(deleteContext, artifact)
		cancelDelete()
		return Summary{ExportsClaimed: 1, ExportsDiscarded: 1}, deleteErr
	default:
		return Summary{ExportsClaimed: 1}, ErrInvalidProjection
	}
}

func (worker *Worker) runRetention(ctx context.Context, stream Stream, tenantID uuid.UUID) (Summary, error) {
	segment, found, err := worker.getRetentionWork(ctx, stream, tenantID)
	if err != nil {
		return Summary{}, err
	}
	if !found {
		segment, found, err = worker.closeRetentionSegment(ctx, stream, tenantID)
		if err != nil || !found {
			return Summary{}, err
		}
	}
	if err := validSegment(segment, stream, tenantID); err != nil {
		return Summary{}, err
	}
	var summary Summary
	if segment.State == "closed" {
		spool, stats, spoolErr := worker.spoolSegment(ctx, segment)
		if spoolErr != nil {
			return summary, spoolErr
		}
		defer os.Remove(spool)
		signature, signErr := worker.signer.Sign(segment, stats.digest, stats.bytes)
		if signErr != nil {
			return summary, signErr
		}
		artifact := segmentArtifact(segment, stats.digest, stats.bytes, worker.signer.KeyID(), signature, spool)
		if err := worker.artifacts.Put(ctx, artifact); err != nil {
			return summary, err
		}
		preserveAuditID, idErr := worker.id()
		if idErr != nil {
			return summary, idErr
		}
		preserveContext, cancelPreserve := context.WithTimeout(ctx, worker.operationTimeout)
		err = worker.repository.PreserveRetentionSegment(
			preserveContext, segment, worker.workerID, stats.digest, stats.bytes,
			worker.signer.KeyID(), signature, DefaultOperationReason, preserveAuditID,
		)
		cancelPreserve()
		if err != nil {
			return summary, err
		}
		segment.State = "preserved"
		segment.Revision = 2
		segment.Digest = stats.digest
		segment.Bytes = stats.bytes
		segment.SigningKeyID = worker.signer.KeyID()
		segment.Signature = signature
		summary.SegmentsPreserved++
	}
	artifact := segmentArtifact(
		segment, segment.Digest, segment.Bytes, segment.SigningKeyID, segment.Signature, "",
	)
	if !worker.signer.Verify(segment, segment.Digest, segment.Bytes, segment.Signature) {
		return summary, ErrArtifactConflict
	}
	verifyContext, cancelVerify := context.WithTimeout(ctx, worker.operationTimeout)
	err = worker.artifacts.Verify(verifyContext, artifact)
	cancelVerify()
	if err != nil {
		return summary, err
	}
	pruneAuditID, err := worker.id()
	if err != nil {
		return summary, err
	}
	pruneContext, cancelPrune := context.WithTimeout(ctx, worker.operationTimeout)
	err = worker.repository.PruneRetentionSegment(
		pruneContext, segment, worker.workerID, artifact, DefaultOperationReason, pruneAuditID,
	)
	cancelPrune()
	if err != nil {
		return summary, err
	}
	summary.SegmentsPruned++
	return summary, nil
}

type spoolStats struct {
	digest [32]byte
	rows   int64
	bytes  int64
}

func (worker *Worker) spoolExport(ctx context.Context, claim ExportClaim) (string, spoolStats, error) {
	return worker.spool(ctx, claim.Stream, claim.TenantID, 0, 0, func(after int64, limit int) ([]PageRow, error) {
		pageContext, cancel := context.WithTimeout(ctx, worker.operationTimeout)
		defer cancel()
		return worker.repository.ReadExportPage(pageContext, claim, after, limit)
	})
}

func (worker *Worker) spoolSegment(ctx context.Context, segment Segment) (string, spoolStats, error) {
	return worker.spool(ctx, segment.Stream, segment.TenantID, segment.Start-1, segment.End,
		func(after int64, limit int) ([]PageRow, error) {
			pageContext, cancel := context.WithTimeout(ctx, worker.operationTimeout)
			defer cancel()
			return worker.repository.ReadRetentionPage(pageContext, segment, worker.workerID, after, limit)
		})
}

func (worker *Worker) spool(ctx context.Context, stream Stream, tenantID uuid.UUID, firstAfter, terminal int64,
	read func(int64, int) ([]PageRow, error)) (string, spoolStats, error) {
	file, err := os.CreateTemp(worker.spoolDirectory, ".audit-operations-*.partial")
	if err != nil {
		return "", spoolStats{}, ErrUnavailable
	}
	path := file.Name()
	cleanup := func() {
		_ = file.Close()
		_ = os.Remove(path)
	}
	digest := sha256.New()
	written := int64(0)
	rows := int64(0)
	after := firstAfter
	for {
		if ctx.Err() != nil {
			cleanup()
			return "", spoolStats{}, ctx.Err()
		}
		page, err := read(after, worker.pageSize)
		if err != nil {
			cleanup()
			return "", spoolStats{}, err
		}
		if len(page) > worker.pageSize {
			cleanup()
			return "", spoolStats{}, ErrInvalidProjection
		}
		for _, row := range page {
			if row.Sequence <= after || terminal > 0 && row.Sequence > terminal {
				cleanup()
				return "", spoolStats{}, ErrInvalidProjection
			}
			canonical, err := canonicalProjection(row.Document, stream, tenantID, row.Sequence)
			if err != nil {
				cleanup()
				return "", spoolStats{}, err
			}
			lineBytes := int64(len(canonical) + 1)
			if rows >= MaximumArtifactRows || written > MaximumArtifactBytes-lineBytes {
				cleanup()
				return "", spoolStats{}, ErrInvalidProjection
			}
			if _, err := io.MultiWriter(file, digest).Write(append(canonical, '\n')); err != nil {
				cleanup()
				return "", spoolStats{}, ErrUnavailable
			}
			written += lineBytes
			rows++
			after = row.Sequence
		}
		if terminal > 0 && after == terminal || len(page) < worker.pageSize {
			break
		}
		if len(page) == 0 {
			cleanup()
			return "", spoolStats{}, ErrInvalidProjection
		}
	}
	if terminal > 0 && (after != terminal || rows != terminal-firstAfter) {
		cleanup()
		return "", spoolStats{}, ErrInvalidProjection
	}
	syncErr := file.Sync()
	closeErr := file.Close()
	if syncErr != nil || closeErr != nil {
		_ = os.Remove(path)
		return "", spoolStats{}, ErrUnavailable
	}
	var sum [32]byte
	copy(sum[:], digest.Sum(nil))
	return path, spoolStats{digest: sum, rows: rows, bytes: written}, nil
}

func (worker *Worker) listTenantCandidates(ctx context.Context) ([]uuid.UUID, error) {
	operationContext, cancel := context.WithTimeout(ctx, worker.operationTimeout)
	defer cancel()
	return worker.repository.ListTenantRetentionCandidates(operationContext, worker.workerID, worker.tenantBatch)
}

func (worker *Worker) getRetentionWork(ctx context.Context, stream Stream, tenantID uuid.UUID) (Segment, bool, error) {
	operationContext, cancel := context.WithTimeout(ctx, worker.operationTimeout)
	defer cancel()
	return worker.repository.GetRetentionWork(operationContext, stream, tenantID, worker.workerID)
}

func (worker *Worker) closeRetentionSegment(ctx context.Context, stream Stream, tenantID uuid.UUID) (Segment, bool, error) {
	auditID, err := worker.id()
	if err != nil {
		return Segment{}, false, err
	}
	operationContext, cancel := context.WithTimeout(ctx, worker.operationTimeout)
	defer cancel()
	return worker.repository.CloseRetentionSegment(
		operationContext, stream, tenantID, worker.workerID, worker.retentionRows,
		DefaultOperationReason, auditID,
	)
}

func (worker *Worker) pruneTenantReceipts(ctx context.Context, tenantID uuid.UUID) (int, error) {
	auditID, err := worker.id()
	if err != nil {
		return 0, err
	}
	operationContext, cancel := context.WithTimeout(ctx, worker.operationTimeout)
	defer cancel()
	return worker.repository.PruneTenantReceipts(
		operationContext, tenantID, worker.workerID, worker.receiptBatch,
		DefaultOperationReason, auditID,
	)
}

func (worker *Worker) prunePlatformReceipts(ctx context.Context) (int, error) {
	auditID, err := worker.id()
	if err != nil {
		return 0, err
	}
	operationContext, cancel := context.WithTimeout(ctx, worker.operationTimeout)
	defer cancel()
	return worker.repository.PrunePlatformReceipts(
		operationContext, worker.workerID, worker.receiptBatch, DefaultOperationReason, auditID,
	)
}

func (worker *Worker) id() (uuid.UUID, error) {
	value, err := worker.newID()
	if err != nil || !validUUIDv7(value) {
		return uuid.Nil, ErrUnavailable
	}
	return value, nil
}

func newFence() ([32]byte, error) {
	var fence [32]byte
	_, err := rand.Read(fence[:])
	return fence, err
}

func validExportClaim(claim ExportClaim, stream Stream, workerID uuid.UUID, fence [32]byte) error {
	if claim.Stream != stream || !validUUIDv7(claim.JobID) || claim.WorkerID != workerID || claim.Fence != fence ||
		claim.ProjectionVersion != 1 || claim.Format != "jsonl" ||
		!validObjectKey(stream, claim.TenantID, claim.ObjectKey) || claim.ExpiresAt.IsZero() ||
		claim.LeaseExpiresAt.IsZero() || !claim.LeaseExpiresAt.Before(claim.ExpiresAt) || !validUUIDv7(workerID) {
		return ErrInvalidProjection
	}
	expected := "platform/audit/exports/" + claim.JobID.String() + "/v1.jsonl"
	if stream == TenantStream {
		expected = "tenants/" + claim.TenantID.String() + "/audit/exports/" + claim.JobID.String() + "/v1.jsonl"
	} else if claim.TenantID != uuid.Nil {
		return ErrInvalidProjection
	}
	if claim.ObjectKey != expected {
		return ErrInvalidProjection
	}
	return nil
}

func validSegment(segment Segment, stream Stream, tenantID uuid.UUID) error {
	if segment.Stream != stream || segment.TenantID != tenantID || !validUUIDv7(segment.ID) ||
		(segment.State != "closed" || segment.Revision != 1) &&
			(segment.State != "preserved" || segment.Revision != 2) ||
		segment.Start < 1 || segment.End < segment.Start || segment.EventCount != segment.End-segment.Start+1 ||
		len(segment.PreviousHash) != 64 || len(segment.EndHash) != 64 ||
		!validObjectKey(stream, tenantID, segment.ObjectKey) {
		return ErrInvalidProjection
	}
	if segment.State == "preserved" && (segment.Digest == ([32]byte{}) || segment.Bytes < 1 ||
		!signingKeyIDPattern.MatchString(segment.SigningKeyID) || segment.Signature == ([64]byte{})) {
		return ErrInvalidProjection
	}
	return nil
}

func segmentArtifact(segment Segment, digest [32]byte, bytes int64, keyID string, signature [64]byte, path string) Artifact {
	return Artifact{
		Kind: SegmentArtifactKind, Stream: segment.Stream, TenantID: segment.TenantID,
		SegmentID: segment.ID, StartSequence: segment.Start, EndSequence: segment.End,
		ProjectionVersion: 1, Format: "jsonl", ObjectKey: segment.ObjectKey,
		Digest: digest, Rows: segment.EventCount, Bytes: bytes, SigningKeyID: keyID,
		Signature: signature, Path: path,
	}
}

func mergeSummary(target *Summary, source Summary) {
	target.ExportsClaimed += source.ExportsClaimed
	target.ExportsSucceeded += source.ExportsSucceeded
	target.ExportsDiscarded += source.ExportsDiscarded
	target.SegmentsPreserved += source.SegmentsPreserved
	target.SegmentsPruned += source.SegmentsPruned
	target.ReceiptsPruned += source.ReceiptsPruned
}

func nilDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
