package ticketexport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
)

func TestRunOnceStreamsPagesAndCommitsExactArtifact(t *testing.T) {
	fixture := newWorkerFixture(t, kernel.TicketExportAudienceOperator, 10, 1<<20)
	repository := newFakeRepository(fixture, []string{"ticket", "state"}, map[string]Page{
		"": {
			Rows:       []Row{testRow(1, RowTicket, "A-1", "open")},
			NextCursor: "MQ",
		},
		"MQ": {Rows: []Row{testRow(2, RowTicket, "A-2", "closed")}},
	})
	store := &fakeArtifactStore{promotion: PromotionApplied}
	worker := newTestWorker(t, fixture, repository, store, nil)

	result, err := worker.RunOnce(context.Background(), fixture.queue)
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != OutcomeSucceeded || !result.Claimed || result.Rows != 2 {
		t.Fatalf("result=%#v", result)
	}
	object := store.onlyObject(t)
	expected := "ticket,state\r\nA-1,open\r\nA-2,closed\r\n"
	if got := object.contents(); got != expected {
		t.Fatalf("CSV mismatch\ngot:  %q\nwant: %q", got, expected)
	}
	digest := sha256.Sum256([]byte(expected))
	if !object.sealed || !object.promoted || object.manifest.Digest != digest ||
		object.manifest.Rows != 2 || object.manifest.Bytes != uint64(len(expected)) {
		t.Fatalf("object=%#v", object.snapshot())
	}
	snapshot := repository.snapshot()
	if snapshot.job.State() != kernel.TicketExportSucceeded || snapshot.manifestCalls != 1 ||
		snapshot.successCalls != 1 || snapshot.artifactID != object.request.ArtifactID ||
		snapshot.manifest == nil || *snapshot.manifest != object.manifest {
		t.Fatalf("repository=%#v", snapshot)
	}
}

func TestRunOnceTreatsLostClaimResponseAsOutcomeUnknown(t *testing.T) {
	fixture := newWorkerFixture(t, kernel.TicketExportAudienceOperator, 10, 1<<20)
	repository := newFakeRepository(fixture, []string{"ticket"}, map[string]Page{"": {}})
	repository.claimErrorAfterApply = errors.New("raw database endpoint and secret")
	store := &fakeArtifactStore{promotion: PromotionApplied}
	worker := newTestWorker(t, fixture, repository, store, nil)

	result, err := worker.RunOnce(context.Background(), fixture.queue)
	if !errors.Is(err, ErrTransitionOutcomeUnknown) || !errors.Is(err, ErrUnavailable) ||
		result.Outcome != OutcomeUnknown || strings.Contains(err.Error(), "secret") {
		t.Fatalf("result=%#v error=%v", result, err)
	}
	snapshot := repository.snapshot()
	if snapshot.job.State() != kernel.TicketExportRunning ||
		!validEntityID(snapshot.artifactID) || len(store.snapshot()) != 0 {
		t.Fatalf("repository=%#v objects=%d", snapshot, len(store.snapshot()))
	}
}

func TestRunOnceRejectsPayloadOnIdleClaim(t *testing.T) {
	fixture := newWorkerFixture(t, kernel.TicketExportAudienceOperator, 10, 1<<20)
	repository := newFakeRepository(fixture, []string{"ticket"}, nil)
	repository.forceNotFound = true
	repository.idleClaim = Claim{ArtifactID: testArtifactID(244)}
	store := &fakeArtifactStore{promotion: PromotionApplied}
	worker := newTestWorker(t, fixture, repository, store, nil)

	result, err := worker.RunOnce(context.Background(), fixture.queue)
	if !errors.Is(err, ErrInvalidProjection) || result.Outcome != OutcomeUnknown ||
		len(store.snapshot()) != 0 {
		t.Fatalf("result=%#v error=%v objects=%d", result, err, len(store.snapshot()))
	}
}

func TestRunOnceRejectsLateNilClaimResponseAfterCancellation(t *testing.T) {
	fixture := newWorkerFixture(t, kernel.TicketExportAudienceOperator, 10, 1<<20)
	repository := newFakeRepository(fixture, []string{"ticket"}, nil)
	repository.blockClaim = true
	repository.claimLateNil = true
	repository.claimStarted = make(chan struct{})
	store := &fakeArtifactStore{promotion: PromotionApplied}
	worker := newTestWorker(t, fixture, repository, store, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		<-repository.claimStarted
		cancel()
		close(done)
	}()

	result, err := worker.RunOnce(ctx, fixture.queue)
	<-done
	if !errors.Is(err, ErrTransitionOutcomeUnknown) || !errors.Is(err, ErrInterrupted) ||
		result.Outcome != OutcomeInterrupted || len(store.snapshot()) != 0 {
		t.Fatalf("result=%#v error=%v objects=%d", result, err, len(store.snapshot()))
	}
}

func TestRunOnceDurablyRecordsManifestBeforeStorageMutation(t *testing.T) {
	fixture := newWorkerFixture(t, kernel.TicketExportAudienceOperator, 10, 1<<20)
	repository := newFakeRepository(fixture, []string{"ticket"}, map[string]Page{"": {}})
	repository.manifestErrorAfterApply = errors.New("raw database location and secret")
	store := &fakeArtifactStore{promotion: PromotionApplied}
	worker := newTestWorker(t, fixture, repository, store, nil)

	result, err := worker.RunOnce(context.Background(), fixture.queue)
	if err != nil || result.Outcome != OutcomeRetryScheduled ||
		result.FailureCode != kernel.TicketExportFailureTransientDatabase {
		t.Fatalf("result=%#v error=%v", result, err)
	}
	object := store.onlyObject(t)
	snapshot := repository.snapshot()
	if snapshot.manifestCalls != 1 || snapshot.manifest == nil ||
		snapshot.manifest.ArtifactID != snapshot.artifactID ||
		snapshot.manifest.ArtifactID != object.request.ArtifactID ||
		object.sealed || object.promoted || object.abortCalls != 1 || snapshot.failureCalls != 1 {
		t.Fatalf("repository=%#v object=%#v", snapshot, object.snapshot())
	}
}

func TestRunOnceHandlesManifestLedgerControlsBeforeUpload(t *testing.T) {
	tests := []struct {
		name        string
		disposition ManifestDisposition
		wantOutcome Outcome
		wantError   error
		wantFailure kernel.TicketExportFailureCode
	}{
		{name: "cancellation", disposition: ManifestCancellationRequested, wantOutcome: OutcomeCancelled},
		{name: "authorization revoked", disposition: ManifestAuthorizationRevoked, wantOutcome: OutcomeAuthorizationRevoked},
		{name: "fence lost", disposition: ManifestFenceLost, wantOutcome: OutcomeFenceLost, wantError: ErrFenceLost},
		{name: "snapshot stale", disposition: ManifestSnapshotStale, wantOutcome: OutcomeFailed, wantFailure: kernel.TicketExportFailureSnapshotStale},
		{name: "unknown", disposition: 255, wantOutcome: OutcomeFailed, wantFailure: kernel.TicketExportFailureSnapshotStale},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newWorkerFixture(t, kernel.TicketExportAudienceOperator, 10, 1<<20)
			repository := newFakeRepository(fixture, []string{"ticket"}, map[string]Page{"": {}})
			repository.manifestDisposition = test.disposition
			store := &fakeArtifactStore{promotion: PromotionApplied}
			worker := newTestWorker(t, fixture, repository, store, nil)

			result, err := worker.RunOnce(context.Background(), fixture.queue)
			if test.wantError == nil && err != nil ||
				test.wantError != nil && !errors.Is(err, test.wantError) ||
				result.Outcome != test.wantOutcome || result.FailureCode != test.wantFailure {
				t.Fatalf("result=%#v error=%v", result, err)
			}
			object := store.onlyObject(t)
			if object.sealed || object.promoted || object.abortCalls != 1 ||
				repository.snapshot().successCalls != 0 {
				t.Fatalf("repository=%#v object=%#v", repository.snapshot(), object.snapshot())
			}
		})
	}
}

func TestRunOnceRejectsManifestRecordedWithoutExactEchoBeforeSeal(t *testing.T) {
	fixture := newWorkerFixture(t, kernel.TicketExportAudienceOperator, 10, 1<<20)
	repository := newFakeRepository(fixture, []string{"ticket"}, map[string]Page{"": {}})
	repository.manifestResultOverride = &ManifestResult{
		Disposition: ManifestRecorded, CurrentRevision: fixture.pendingJob.Revision() + 1,
		Manifest: StreamManifest{
			ArtifactID: testArtifactID(199), Digest: [32]byte{0xff}, Rows: 1, Bytes: 1,
		},
	}
	store := &fakeArtifactStore{promotion: PromotionApplied}
	worker := newTestWorker(t, fixture, repository, store, nil)

	result, err := worker.RunOnce(context.Background(), fixture.queue)
	if err != nil || result.Outcome != OutcomeFailed ||
		result.FailureCode != kernel.TicketExportFailureSnapshotStale {
		t.Fatalf("result=%#v error=%v", result, err)
	}
	object := store.onlyObject(t)
	if object.sealed || object.promoted || object.abortCalls != 1 ||
		repository.snapshot().successCalls != 0 {
		t.Fatalf("repository=%#v object=%#v", repository.snapshot(), object.snapshot())
	}
}

func TestRunOncePublishesEmptyExportWithHeader(t *testing.T) {
	fixture := newWorkerFixture(t, kernel.TicketExportAudienceOperator, 10, 1<<20)
	repository := newFakeRepository(fixture, []string{"ticket"}, map[string]Page{"": {}})
	store := &fakeArtifactStore{promotion: PromotionApplied}
	worker := newTestWorker(t, fixture, repository, store, nil)

	result, err := worker.RunOnce(context.Background(), fixture.queue)
	if err != nil || result.Outcome != OutcomeSucceeded || result.Rows != 0 {
		t.Fatalf("result=%#v error=%v", result, err)
	}
	if got := store.onlyObject(t).contents(); got != "ticket\r\n" {
		t.Fatalf("empty CSV=%q", got)
	}
}

func TestRunOnceFormulaNeutralizationComposesWithoutDoublePrefix(t *testing.T) {
	fixture := newWorkerFixture(t, kernel.TicketExportAudienceOperator, 10, 1<<20)
	repository := newFakeRepository(fixture, []string{"raw", "already_safe"}, map[string]Page{
		"": {Rows: []Row{testRow(1, RowTicket, "=1+1", "'=1+1")}},
	})
	store := &fakeArtifactStore{promotion: PromotionApplied}
	worker := newTestWorker(t, fixture, repository, store, nil)

	result, err := worker.RunOnce(context.Background(), fixture.queue)
	if err != nil || result.Outcome != OutcomeSucceeded {
		t.Fatalf("result=%#v error=%v", result, err)
	}
	records, err := csv.NewReader(strings.NewReader(store.onlyObject(t).contents())).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || len(records[1]) != 2 || records[1][0] != "'=1+1" || records[1][1] != "'=1+1" {
		t.Fatalf("records=%#v", records)
	}
}

func TestRunOnceCursorCycleFailsBoundedWithoutPublication(t *testing.T) {
	fixture := newWorkerFixture(t, kernel.TicketExportAudienceOperator, 10, 1<<20)
	repository := newFakeRepository(fixture, []string{"ticket"}, map[string]Page{
		"":   {Rows: []Row{testRow(1, RowTicket, "A-1")}, NextCursor: "QQ"},
		"QQ": {Rows: []Row{testRow(2, RowTicket, "A-2")}, NextCursor: "Qg"},
		"Qg": {Rows: []Row{testRow(3, RowTicket, "A-3")}, NextCursor: "QQ"},
	})
	store := &fakeArtifactStore{promotion: PromotionApplied}
	worker := newTestWorker(t, fixture, repository, store, nil)

	result, err := worker.RunOnce(context.Background(), fixture.queue)
	if err != nil || result.Outcome != OutcomeFailed ||
		result.FailureCode != kernel.TicketExportFailureSnapshotStale {
		t.Fatalf("result=%#v error=%v", result, err)
	}
	object := store.onlyObject(t)
	if object.promoted || object.abortCalls != 1 || repository.snapshot().pageCalls != 3 {
		t.Fatalf("object=%#v repository=%#v", object.snapshot(), repository.snapshot())
	}
}

func TestRunOnceDuplicateSnapshotRowFailsWithoutPublication(t *testing.T) {
	fixture := newWorkerFixture(t, kernel.TicketExportAudienceOperator, 10, 1<<20)
	first := testRow(1, RowTicket, "A-1")
	duplicate := testRow(1, RowTicket, "A-1-replayed")
	repository := newFakeRepository(fixture, []string{"ticket"}, map[string]Page{
		"":   {Rows: []Row{first}, NextCursor: "QQ"},
		"QQ": {Rows: []Row{duplicate}},
	})
	store := &fakeArtifactStore{promotion: PromotionApplied}
	worker := newTestWorker(t, fixture, repository, store, nil)

	result, err := worker.RunOnce(context.Background(), fixture.queue)
	if err != nil || result.Outcome != OutcomeFailed ||
		result.FailureCode != kernel.TicketExportFailureSnapshotStale {
		t.Fatalf("result=%#v error=%v", result, err)
	}
	object := store.onlyObject(t)
	if object.sealed || object.promoted || object.abortCalls != 1 ||
		repository.snapshot().pageCalls != 2 {
		t.Fatalf("object=%#v repository=%#v", object.snapshot(), repository.snapshot())
	}
}

func TestRunOncePartialWriteAbortsAndSchedulesStorageRetry(t *testing.T) {
	fixture := newWorkerFixture(t, kernel.TicketExportAudienceOperator, 10, 1<<20)
	repository := newFakeRepository(fixture, []string{"ticket"}, map[string]Page{
		"": {Rows: []Row{testRow(1, RowTicket, "A-1")}},
	})
	store := &fakeArtifactStore{promotion: PromotionApplied, writeLimit: len("ticket\r\n") + 1}
	worker := newTestWorker(t, fixture, repository, store, nil)

	result, err := worker.RunOnce(context.Background(), fixture.queue)
	if err != nil || result.Outcome != OutcomeRetryScheduled ||
		result.FailureCode != kernel.TicketExportFailureTransientStorage {
		t.Fatalf("result=%#v error=%v", result, err)
	}
	object := store.onlyObject(t)
	if object.abortCalls != 1 || object.promoted || repository.snapshot().failureCalls != 1 {
		t.Fatalf("object=%#v repository=%#v", object.snapshot(), repository.snapshot())
	}
}

func TestRunOnceOutputLimitIsTerminalAndNeverPromoted(t *testing.T) {
	fixture := newWorkerFixture(t, kernel.TicketExportAudienceOperator, 10, uint64(len("ticket\r\n")))
	repository := newFakeRepository(fixture, []string{"ticket"}, map[string]Page{
		"": {Rows: []Row{testRow(1, RowTicket, "A-1")}},
	})
	store := &fakeArtifactStore{promotion: PromotionApplied}
	worker := newTestWorker(t, fixture, repository, store, nil)

	result, err := worker.RunOnce(context.Background(), fixture.queue)
	if err != nil || result.Outcome != OutcomeFailed ||
		result.FailureCode != kernel.TicketExportFailureOutputLimit {
		t.Fatalf("result=%#v error=%v", result, err)
	}
	object := store.onlyObject(t)
	if object.promoted || object.abortCalls != 1 || repository.snapshot().job.State() != kernel.TicketExportFailed {
		t.Fatalf("object=%#v repository=%#v", object.snapshot(), repository.snapshot())
	}
}

func TestRunOnceRejectsPrivateCustomerProjection(t *testing.T) {
	fixture := newWorkerFixture(t, kernel.TicketExportAudienceCustomer, 10, 1<<20)
	repository := newFakeRepository(fixture, []string{"ticket"}, map[string]Page{
		"": {Rows: []Row{testRow(1, RowPrivateComment, "secret")}},
	})
	store := &fakeArtifactStore{promotion: PromotionApplied}
	worker := newTestWorker(t, fixture, repository, store, nil)

	result, err := worker.RunOnce(context.Background(), fixture.queue)
	if err != nil || result.Outcome != OutcomeFailed ||
		result.FailureCode != kernel.TicketExportFailureSnapshotStale {
		t.Fatalf("result=%#v error=%v", result, err)
	}
	if store.onlyObject(t).promoted {
		t.Fatal("private customer projection was promoted")
	}
}

func TestRunOnceAcknowledgesCancellationAndCleansTemporaryObject(t *testing.T) {
	fixture := newWorkerFixture(t, kernel.TicketExportAudienceOperator, 10, 1<<20)
	repository := newFakeRepository(fixture, []string{"ticket"}, nil)
	repository.pageControl = PageCancellationRequested
	store := &fakeArtifactStore{promotion: PromotionApplied}
	worker := newTestWorker(t, fixture, repository, store, nil)

	result, err := worker.RunOnce(context.Background(), fixture.queue)
	if err != nil || result.Outcome != OutcomeCancelled {
		t.Fatalf("result=%#v error=%v", result, err)
	}
	snapshot := repository.snapshot()
	if snapshot.job.State() != kernel.TicketExportCancelledState || snapshot.cancelCalls != 1 ||
		store.onlyObject(t).abortCalls != 1 {
		t.Fatalf("repository=%#v object=%#v", snapshot, store.onlyObject(t).snapshot())
	}
}

func TestRunOnceFenceLossNeverReportsContradictoryFailure(t *testing.T) {
	fixture := newWorkerFixture(t, kernel.TicketExportAudienceOperator, 10, 1<<20)
	repository := newFakeRepository(fixture, []string{"ticket"}, nil)
	repository.pageControl = PageFenceLost
	store := &fakeArtifactStore{promotion: PromotionApplied}
	worker := newTestWorker(t, fixture, repository, store, nil)

	result, err := worker.RunOnce(context.Background(), fixture.queue)
	if !errors.Is(err, ErrFenceLost) || result.Outcome != OutcomeFenceLost {
		t.Fatalf("result=%#v error=%v", result, err)
	}
	if repository.snapshot().failureCalls != 0 || store.onlyObject(t).abortCalls != 1 {
		t.Fatalf("repository=%#v object=%#v", repository.snapshot(), store.onlyObject(t).snapshot())
	}
}

func TestRunOnceUsesDedicatedAuthorizationRevocationTransition(t *testing.T) {
	fixture := newWorkerFixture(t, kernel.TicketExportAudienceOperator, 10, 1<<20)
	repository := newFakeRepository(fixture, []string{"ticket"}, nil)
	repository.pageControl = PageAuthorizationRevoked
	store := &fakeArtifactStore{promotion: PromotionApplied}
	worker := newTestWorker(t, fixture, repository, store, nil)

	result, err := worker.RunOnce(context.Background(), fixture.queue)
	if err != nil || result.Outcome != OutcomeAuthorizationRevoked {
		t.Fatalf("result=%#v error=%v", result, err)
	}
	snapshot := repository.snapshot()
	if snapshot.revocationCalls != 1 || snapshot.failureCalls != 0 ||
		snapshot.job.FailureCode() != kernel.TicketExportFailureAuthorizationRevoked {
		t.Fatalf("repository=%#v", snapshot)
	}
}

func TestRunOnceRejectsPayloadAttachedToControlOnlySignal(t *testing.T) {
	fixture := newWorkerFixture(t, kernel.TicketExportAudienceOperator, 10, 1<<20)
	repository := newFakeRepository(fixture, []string{"ticket"}, nil)
	repository.pageControl = PageAuthorizationRevoked
	repository.controlPage = Page{Rows: []Row{testRow(1, RowTicket, "must-not-cross")}}
	store := &fakeArtifactStore{promotion: PromotionApplied}
	worker := newTestWorker(t, fixture, repository, store, nil)

	result, err := worker.RunOnce(context.Background(), fixture.queue)
	if err != nil || result.Outcome != OutcomeFailed ||
		result.FailureCode != kernel.TicketExportFailureSnapshotStale {
		t.Fatalf("result=%#v error=%v", result, err)
	}
	if repository.snapshot().revocationCalls != 0 || store.onlyObject(t).promoted {
		t.Fatalf("repository=%#v object=%#v", repository.snapshot(), store.onlyObject(t).snapshot())
	}
}

func TestRunOnceCrashWindowRetainsPromotedObjectAfterLostCommitResponse(t *testing.T) {
	fixture := newWorkerFixture(t, kernel.TicketExportAudienceOperator, 10, 1<<20)
	repository := newFakeRepository(fixture, []string{"ticket"}, map[string]Page{"": {}})
	repository.finishErrorAfterApply = errors.New("raw database address and secret")
	store := &fakeArtifactStore{promotion: PromotionApplied}
	worker := newTestWorker(t, fixture, repository, store, nil)

	result, err := worker.RunOnce(context.Background(), fixture.queue)
	if !errors.Is(err, ErrCommitOutcomeUnknown) || strings.Contains(err.Error(), "secret") || !result.Claimed {
		t.Fatalf("result=%#v error=%v", result, err)
	}
	object := store.onlyObject(t)
	if !object.promoted || object.purgeCalls != 0 || object.abortCalls != 0 {
		t.Fatalf("promoted object was destructively cleaned: %#v", object.snapshot())
	}
	if repository.snapshot().job.State() != kernel.TicketExportSucceeded {
		t.Fatalf("durable commit did not apply: %#v", repository.snapshot())
	}
	second, secondErr := worker.RunOnce(context.Background(), fixture.queue)
	if secondErr != nil || second.Outcome != OutcomeIdle || second.Claimed {
		t.Fatalf("reconciliation replay result=%#v error=%v", second, secondErr)
	}
}

func TestRunOnceRejectsLateNilCommitResponseAfterCancellation(t *testing.T) {
	fixture := newWorkerFixture(t, kernel.TicketExportAudienceOperator, 10, 1<<20)
	repository := newFakeRepository(fixture, []string{"ticket"}, map[string]Page{"": {}})
	repository.blockFinish = true
	repository.finishStarted = make(chan struct{})
	store := &fakeArtifactStore{promotion: PromotionApplied}
	worker := newTestWorker(t, fixture, repository, store, nil)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	type response struct {
		result Result
		err    error
	}
	responses := make(chan response, 1)
	go func() {
		result, err := worker.RunOnce(ctx, fixture.queue)
		responses <- response{result: result, err: err}
	}()
	<-repository.finishStarted
	cancel()
	got := <-responses

	if !errors.Is(got.err, ErrCommitOutcomeUnknown) || !errors.Is(got.err, ErrInterrupted) ||
		got.result.Outcome != OutcomeInterrupted {
		t.Fatalf("result=%#v error=%v", got.result, got.err)
	}
	object := store.onlyObject(t)
	snapshot := repository.snapshot()
	if !object.promoted || object.purgeCalls != 0 || object.abortCalls != 0 ||
		snapshot.job.State() != kernel.TicketExportRunning || snapshot.successCalls != 1 {
		t.Fatalf("repository=%#v object=%#v", snapshot, object.snapshot())
	}
}

func TestRunOncePreservesPromotedObjectOnMalformedAppliedCommitEcho(t *testing.T) {
	fixture := newWorkerFixture(t, kernel.TicketExportAudienceOperator, 10, 1<<20)
	repository := newFakeRepository(fixture, []string{"ticket"}, map[string]Page{"": {}})
	repository.finishResultOverride = &CommitResult{
		Disposition: CommitApplied, CurrentRevision: fixture.pendingJob.Revision() + 2,
		Manifest: StreamManifest{
			ArtifactID: testArtifactID(198), Digest: [32]byte{0xee}, Bytes: 1,
		},
	}
	store := &fakeArtifactStore{promotion: PromotionApplied}
	worker := newTestWorker(t, fixture, repository, store, nil)

	result, err := worker.RunOnce(context.Background(), fixture.queue)
	if !errors.Is(err, ErrCommitOutcomeUnknown) || result.Outcome != OutcomeUnknown {
		t.Fatalf("result=%#v error=%v", result, err)
	}
	object := store.onlyObject(t)
	if !object.promoted || object.purgeCalls != 0 || object.abortCalls != 0 ||
		repository.snapshot().job.State() != kernel.TicketExportSucceeded {
		t.Fatalf("repository=%#v object=%#v", repository.snapshot(), object.snapshot())
	}
}

func TestRunOnceTreatsIdempotentCommitReplayAsSuccess(t *testing.T) {
	fixture := newWorkerFixture(t, kernel.TicketExportAudienceOperator, 10, 1<<20)
	repository := newFakeRepository(fixture, []string{"ticket"}, map[string]Page{"": {}})
	repository.finishDisposition = CommitReplayed
	store := &fakeArtifactStore{promotion: PromotionReplayed}
	worker := newTestWorker(t, fixture, repository, store, nil)

	result, err := worker.RunOnce(context.Background(), fixture.queue)
	if err != nil || result.Outcome != OutcomeSucceeded {
		t.Fatalf("result=%#v error=%v", result, err)
	}
}

func TestRunOncePurgesPublishedObjectWhenCancellationWinsCommitRace(t *testing.T) {
	fixture := newWorkerFixture(t, kernel.TicketExportAudienceOperator, 10, 1<<20)
	repository := newFakeRepository(fixture, []string{"ticket"}, map[string]Page{"": {}})
	repository.finishDisposition = CommitCancellationRequested
	store := &fakeArtifactStore{promotion: PromotionApplied}
	worker := newTestWorker(t, fixture, repository, store, nil)

	result, err := worker.RunOnce(context.Background(), fixture.queue)
	if err != nil || result.Outcome != OutcomeCancelled {
		t.Fatalf("result=%#v error=%v", result, err)
	}
	object := store.onlyObject(t)
	if object.purgeCalls != 1 || repository.snapshot().job.State() != kernel.TicketExportCancelledState {
		t.Fatalf("object=%#v repository=%#v", object.snapshot(), repository.snapshot())
	}
}

func TestRunOnceCancellationStopsBlockingPageWithoutFalseFailure(t *testing.T) {
	fixture := newWorkerFixture(t, kernel.TicketExportAudienceOperator, 10, 1<<20)
	repository := newFakeRepository(fixture, []string{"ticket"}, nil)
	repository.blockPage = true
	repository.pageStarted = make(chan struct{})
	store := &fakeArtifactStore{promotion: PromotionApplied}
	worker := newTestWorker(t, fixture, repository, store, nil)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	type response struct {
		result Result
		err    error
	}
	responseChannel := make(chan response, 1)
	go func() {
		result, err := worker.RunOnce(ctx, fixture.queue)
		responseChannel <- response{result: result, err: err}
	}()
	<-repository.pageStarted
	cancel()
	got := <-responseChannel
	if !errors.Is(got.err, ErrInterrupted) || got.result.Outcome != OutcomeInterrupted {
		t.Fatalf("result=%#v error=%v", got.result, got.err)
	}
	if repository.snapshot().failureCalls != 0 || store.onlyObject(t).abortCalls != 1 {
		t.Fatalf("repository=%#v object=%#v", repository.snapshot(), store.onlyObject(t).snapshot())
	}
}

func TestRunOnceCancellationDuringClaimIsInterruptedWithoutFalseFailure(t *testing.T) {
	fixture := newWorkerFixture(t, kernel.TicketExportAudienceOperator, 10, 1<<20)
	repository := newFakeRepository(fixture, []string{"ticket"}, nil)
	repository.blockClaim = true
	repository.claimStarted = make(chan struct{})
	store := &fakeArtifactStore{promotion: PromotionApplied}
	worker := newTestWorker(t, fixture, repository, store, nil)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	type response struct {
		result Result
		err    error
	}
	responseChannel := make(chan response, 1)
	go func() {
		result, err := worker.RunOnce(ctx, fixture.queue)
		responseChannel <- response{result: result, err: err}
	}()
	<-repository.claimStarted
	cancel()
	got := <-responseChannel
	if !errors.Is(got.err, ErrInterrupted) || !errors.Is(got.err, ErrTransitionOutcomeUnknown) ||
		got.result.Outcome != OutcomeInterrupted || got.result.Claimed {
		t.Fatalf("result=%#v error=%v", got.result, got.err)
	}
	if repository.snapshot().failureCalls != 0 || len(store.snapshot()) != 0 {
		t.Fatalf("repository=%#v objects=%d", repository.snapshot(), len(store.snapshot()))
	}
}

func TestRunOnceCancellationDuringStreamingAbortsBeforeSeal(t *testing.T) {
	fixture := newWorkerFixture(t, kernel.TicketExportAudienceOperator, 10, 1<<20)
	repository := newFakeRepository(fixture, []string{"ticket"}, map[string]Page{
		"": {Rows: []Row{testRow(1, RowTicket, "A-1")}},
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	store := &fakeArtifactStore{
		promotion: PromotionApplied,
		writeHook: func(call int) {
			if call == 2 {
				cancel()
			}
		},
	}
	worker := newTestWorker(t, fixture, repository, store, nil)

	result, err := worker.RunOnce(ctx, fixture.queue)
	if !errors.Is(err, ErrInterrupted) || result.Outcome != OutcomeInterrupted {
		t.Fatalf("result=%#v error=%v", result, err)
	}
	object := store.onlyObject(t)
	if object.abortCalls != 1 || object.sealed || object.promoted || repository.snapshot().failureCalls != 0 {
		t.Fatalf("object=%#v repository=%#v", object.snapshot(), repository.snapshot())
	}
}

func TestRunOnceCancellationAfterPromotionPreservesLedgerObjectWithoutCommit(t *testing.T) {
	fixture := newWorkerFixture(t, kernel.TicketExportAudienceOperator, 10, 1<<20)
	repository := newFakeRepository(fixture, []string{"ticket"}, map[string]Page{"": {}})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	store := &fakeArtifactStore{promotion: PromotionApplied, promoteHook: cancel}
	worker := newTestWorker(t, fixture, repository, store, nil)

	result, err := worker.RunOnce(ctx, fixture.queue)
	if !errors.Is(err, ErrInterrupted) || result.Outcome != OutcomeInterrupted {
		t.Fatalf("result=%#v error=%v", result, err)
	}
	object := store.onlyObject(t)
	snapshot := repository.snapshot()
	if !object.promoted || object.purgeCalls != 0 || object.abortCalls != 0 ||
		snapshot.manifest == nil || snapshot.successCalls != 0 || snapshot.failureCalls != 0 {
		t.Fatalf("repository=%#v object=%#v", snapshot, object.snapshot())
	}
}

func TestRunOnceRetriesIdempotentCleanupAfterFailureTransition(t *testing.T) {
	fixture := newWorkerFixture(t, kernel.TicketExportAudienceOperator, 10, 1<<20)
	repository := newFakeRepository(fixture, []string{"ticket"}, map[string]Page{
		"": {Rows: []Row{testRow(1, RowTicket, "A-1")}},
	})
	var observedTransition atomic.Bool
	store := &fakeArtifactStore{
		promotion: PromotionApplied, writeLimit: len("ticket\r\n") + 1, abortFailures: 2,
		abortHook: func() {
			observedTransition.Store(repository.snapshot().failureCalls == 1)
		},
	}
	worker := newTestWorker(t, fixture, repository, store, nil)

	result, err := worker.RunOnce(context.Background(), fixture.queue)
	if err != nil || result.Outcome != OutcomeRetryScheduled {
		t.Fatalf("result=%#v error=%v", result, err)
	}
	if store.onlyObject(t).abortCalls != 3 || repository.snapshot().failureCalls != 1 ||
		!observedTransition.Load() {
		t.Fatalf("object=%#v repository=%#v", store.onlyObject(t).snapshot(), repository.snapshot())
	}
}

func TestRunOnceReportsBoundedCleanupDebtAfterRetryCeiling(t *testing.T) {
	fixture := newWorkerFixture(t, kernel.TicketExportAudienceOperator, 10, 1<<20)
	repository := newFakeRepository(fixture, []string{"ticket"}, map[string]Page{
		"": {Rows: []Row{testRow(1, RowTicket, "A-1")}},
	})
	store := &fakeArtifactStore{
		promotion: PromotionApplied, writeLimit: len("ticket\r\n") + 1, abortFailures: 3,
	}
	worker := newTestWorker(t, fixture, repository, store, nil)

	result, err := worker.RunOnce(context.Background(), fixture.queue)
	if !errors.Is(err, ErrCleanupPending) || result.Outcome != OutcomeRetryScheduled ||
		strings.Contains(err.Error(), "abort") {
		t.Fatalf("result=%#v error=%v", result, err)
	}
	if store.onlyObject(t).abortCalls != 3 || repository.snapshot().failureCalls != 1 {
		t.Fatalf("object=%#v repository=%#v", store.onlyObject(t).snapshot(), repository.snapshot())
	}
}

func TestRunOnceSealFailureAbortsAndSchedulesStorageRetry(t *testing.T) {
	fixture := newWorkerFixture(t, kernel.TicketExportAudienceOperator, 10, 1<<20)
	repository := newFakeRepository(fixture, []string{"ticket"}, map[string]Page{"": {}})
	store := &fakeArtifactStore{promotion: PromotionApplied, sealErr: errors.New("raw multipart secret")}
	worker := newTestWorker(t, fixture, repository, store, nil)

	result, err := worker.RunOnce(context.Background(), fixture.queue)
	if err != nil || result.Outcome != OutcomeRetryScheduled ||
		result.FailureCode != kernel.TicketExportFailureTransientStorage {
		t.Fatalf("result=%#v error=%v", result, err)
	}
	object := store.onlyObject(t)
	if object.abortCalls != 1 || object.promoted {
		t.Fatalf("object=%#v", object.snapshot())
	}
}

func TestRunOnceAcceptsIdempotentFailureReplay(t *testing.T) {
	fixture := newWorkerFixture(t, kernel.TicketExportAudienceOperator, 10, 1<<20)
	repository := newFakeRepository(fixture, []string{"ticket"}, map[string]Page{
		"": {Rows: []Row{testRow(1, RowTicket, "A-1")}},
	})
	repository.failureReplay = true
	store := &fakeArtifactStore{promotion: PromotionApplied, writeLimit: len("ticket\r\n") + 1}
	worker := newTestWorker(t, fixture, repository, store, nil)

	result, err := worker.RunOnce(context.Background(), fixture.queue)
	if err != nil || result.Outcome != OutcomeRetryScheduled {
		t.Fatalf("result=%#v error=%v", result, err)
	}
}

func TestRetryJitterIsDeterministicBoundedAndDomainPrecisionSafe(t *testing.T) {
	fixture := newWorkerFixture(t, kernel.TicketExportAudienceOperator, 10, 1<<20)
	worker := newTestWorker(
		t, fixture, newFakeRepository(fixture, []string{"ticket"}, nil),
		&fakeArtifactStore{promotion: PromotionApplied},
		func(options *Options) {
			options.RetryBase = 2 * time.Second
			options.RetryMaximum = 8 * time.Second
		},
	)
	fence := [32]byte{0x21, 0x7f}
	for _, attempt := range []uint8{1, 2, 3, 4, 5} {
		first := worker.retryDelay(attempt, fence)
		second := worker.retryDelay(attempt, fence)
		ceiling := 2 * time.Second
		for index := uint8(1); index < attempt && ceiling < 8*time.Second; index++ {
			ceiling *= 2
		}
		if ceiling > 8*time.Second {
			ceiling = 8 * time.Second
		}
		if first != second || first < kernel.TicketExportMinimumRetry || first > ceiling ||
			first%time.Microsecond != 0 {
			t.Fatalf("attempt=%d first=%s second=%s ceiling=%s", attempt, first, second, ceiling)
		}
	}
}

func TestRunOnceRejectsFailureDispositionIncompatibleWithRetryRequest(t *testing.T) {
	fixture := newWorkerFixture(t, kernel.TicketExportAudienceOperator, 10, 1<<20)
	repository := newFakeRepository(fixture, []string{"ticket"}, map[string]Page{
		"": {Rows: []Row{testRow(1, RowTicket, "A-1")}},
	})
	repository.failureDisposition = FailureTerminal
	store := &fakeArtifactStore{promotion: PromotionApplied, writeLimit: len("ticket\r\n") + 1}
	worker := newTestWorker(t, fixture, repository, store, nil)

	result, err := worker.RunOnce(context.Background(), fixture.queue)
	if !errors.Is(err, ErrTransitionOutcomeUnknown) || result.Outcome != OutcomeUnknown {
		t.Fatalf("result=%#v error=%v", result, err)
	}
}

func TestRunOnceRejectsFailureRetryWithoutByteExactTimeEcho(t *testing.T) {
	fixture := newWorkerFixture(t, kernel.TicketExportAudienceOperator, 10, 1<<20)
	repository := newFakeRepository(fixture, []string{"ticket"}, map[string]Page{
		"": {Rows: []Row{testRow(1, RowTicket, "A-1")}},
	})
	repository.failureResultOverride = &FailureResult{
		Disposition: FailureRetryScheduled, CurrentRevision: fixture.pendingJob.Revision() + 2,
		Code:    kernel.TicketExportFailureTransientStorage,
		RetryAt: fixture.now.Add(time.Second).In(time.FixedZone("drift", 3_600)),
	}
	store := &fakeArtifactStore{promotion: PromotionApplied, writeLimit: len("ticket\r\n") + 1}
	worker := newTestWorker(t, fixture, repository, store, nil)

	result, err := worker.RunOnce(context.Background(), fixture.queue)
	if !errors.Is(err, ErrTransitionOutcomeUnknown) || result.Outcome != OutcomeUnknown {
		t.Fatalf("result=%#v error=%v", result, err)
	}
}

func TestRunOncePromotionErrorLeavesUnreferencedObjectForGCAndRetriesJob(t *testing.T) {
	fixture := newWorkerFixture(t, kernel.TicketExportAudienceOperator, 10, 1<<20)
	repository := newFakeRepository(fixture, []string{"ticket"}, map[string]Page{"": {}})
	store := &fakeArtifactStore{promotion: PromotionApplied, promoteErr: errors.New("raw storage secret")}
	worker := newTestWorker(t, fixture, repository, store, nil)

	result, err := worker.RunOnce(context.Background(), fixture.queue)
	if !errors.Is(err, ErrPublicationOutcomeUnknown) || result.Outcome != OutcomeRetryScheduled ||
		result.FailureCode != kernel.TicketExportFailureTransientStorage {
		t.Fatalf("result=%#v error=%v", result, err)
	}
	object := store.onlyObject(t)
	if object.abortCalls != 0 || object.purgeCalls != 0 || repository.snapshot().successCalls != 0 {
		t.Fatalf("object=%#v repository=%#v", object.snapshot(), repository.snapshot())
	}
}

func TestRunOnceOnlyOneConcurrentWorkerClaimsAndPublishes(t *testing.T) {
	fixture := newWorkerFixture(t, kernel.TicketExportAudienceOperator, 10, 1<<20)
	repository := newFakeRepository(fixture, []string{"ticket"}, map[string]Page{"": {}})
	store := &fakeArtifactStore{promotion: PromotionApplied}
	worker := newTestWorker(t, fixture, repository, store, nil)

	const contenders = 32
	var successes atomic.Int64
	var idle atomic.Int64
	errorsChannel := make(chan error, contenders)
	var wait sync.WaitGroup
	wait.Add(contenders)
	for range contenders {
		go func() {
			defer wait.Done()
			result, err := worker.RunOnce(context.Background(), fixture.queue)
			if err != nil {
				errorsChannel <- err
				return
			}
			switch result.Outcome {
			case OutcomeSucceeded:
				successes.Add(1)
			case OutcomeIdle:
				idle.Add(1)
			default:
				errorsChannel <- fmt.Errorf("unexpected outcome %s", result.Outcome)
			}
		}()
	}
	wait.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		t.Error(err)
	}
	if successes.Load() != 1 || idle.Load() != contenders-1 || repository.snapshot().claimCalls != 1 {
		t.Fatalf(
			"successes=%d idle=%d repository=%#v", successes.Load(), idle.Load(), repository.snapshot(),
		)
	}
}

func TestWorkerRejectsInvalidConfigurationProjectionAndRedactsDiagnostics(t *testing.T) {
	if _, err := New(Options{}); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("invalid options error=%v", err)
	}
	var nilWorker *Worker
	if _, err := nilWorker.RunOnce(context.Background(), Queue{}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("nil worker error=%v", err)
	}
	fixture := newWorkerFixture(t, kernel.TicketExportAudienceOperator, 10, 1<<20)
	repository := newFakeRepository(fixture, []string{"ticket"}, map[string]Page{"": {}})
	repository.claimWorkerOverride = testEntityID(t, 99)
	store := &fakeArtifactStore{promotion: PromotionApplied}
	worker := newTestWorker(t, fixture, repository, store, nil)
	result, err := worker.RunOnce(context.Background(), fixture.queue)
	if !errors.Is(err, ErrInvalidProjection) || !result.Claimed || len(store.snapshot()) != 0 {
		t.Fatalf("result=%#v error=%v objects=%d", result, err, len(store.snapshot()))
	}
	repository = newFakeRepository(fixture, []string{"ticket"}, map[string]Page{"": {}})
	repository.claimArtifactOverride = testArtifactID(250)
	store = &fakeArtifactStore{promotion: PromotionApplied}
	worker = newTestWorker(t, fixture, repository, store, nil)
	result, err = worker.RunOnce(context.Background(), fixture.queue)
	if !errors.Is(err, ErrInvalidProjection) || !result.Claimed || len(store.snapshot()) != 0 {
		t.Fatalf("artifact mismatch result=%#v error=%v objects=%d", result, err, len(store.snapshot()))
	}

	binding := LeaseBinding{
		TenantID: fixture.tenant, JobID: fixture.jobID, WorkerID: fixture.identity.WorkerID,
		Fence: [32]byte{0xde, 0xad, 0xbe, 0xef}, QueryDigest: [32]byte{0xaa},
	}
	diagnostics := fmt.Sprintf(
		"%#v %#v %#v %#v %#v %#v",
		fixture.identity, fixture.queue, binding, worker,
		PageResult{Control: PageReady, Page: Page{Rows: []Row{testRow(1, RowTicket, "customer-secret")}}},
		ManifestRequest{
			Identity: fixture.identity, Binding: binding, ArtifactID: testArtifactID(251),
			Digest: [32]byte{0xbb}, Rows: 1, Bytes: 2, RecordedAt: fixture.now,
		},
	)
	for _, secret := range []string{fixture.tenant.String(), fixture.jobID.String(), "deadbeef", "aa0000"} {
		if strings.Contains(strings.ToLower(diagnostics), strings.ToLower(secret)) {
			t.Fatalf("diagnostics leaked %q: %s", secret, diagnostics)
		}
	}
	if strings.Contains(diagnostics, "customer-secret") {
		t.Fatalf("page diagnostics leaked row data: %s", diagnostics)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	interrupted, interruptErr := newTestWorker(
		t, fixture, newFakeRepository(fixture, []string{"ticket"}, nil),
		&fakeArtifactStore{promotion: PromotionApplied}, nil,
	).RunOnce(ctx, fixture.queue)
	if !errors.Is(interruptErr, ErrInterrupted) || interrupted.Outcome != OutcomeInterrupted {
		t.Fatalf("canceled result=%#v error=%v", interrupted, interruptErr)
	}

}

func TestExportPortDiagnosticsRedactEveryOpaquePayload(t *testing.T) {
	fixture := newWorkerFixture(t, kernel.TicketExportAudienceOperator, 10, 1<<20)
	repository := newFakeRepository(fixture, []string{"customer-secret"}, nil)
	store := &fakeArtifactStore{promotion: PromotionApplied}
	worker := newTestWorker(t, fixture, repository, store, nil)
	fence := sha256.Sum256([]byte("deadbeef-fence"))
	binding := LeaseBinding{
		TenantID: fixture.tenant, JobID: fixture.jobID, Kind: fixture.queue.Kind,
		Audience: fixture.queue.Audience, WorkerID: fixture.identity.WorkerID,
		Revision: 7, Attempt: 2, Fence: fence, QueryDigest: [32]byte{0xde, 0xad},
		CatalogDigest: [32]byte{0xbe, 0xef}, ProjectionVersion: kernel.TicketExportProjectionVersion,
		LeaseClaimedAt: fixture.now, LeaseExpiresAt: fixture.now.Add(time.Minute),
		JobExpiresAt: fixture.now.Add(time.Hour),
	}
	artifactID := testArtifactID(245)
	manifest := StreamManifest{
		ArtifactID: artifactID, Digest: [32]byte{0xca, 0xfe}, Rows: 1, Bytes: 2,
	}
	retryAt := fixture.now.Add(time.Second)
	values := []any{
		fixture.identity,
		fixture.queue,
		Options{Repository: repository, Artifacts: store, Identity: fixture.identity},
		Result{Claimed: true, Outcome: OutcomeFailed, Rows: 1, Bytes: 2},
		ClaimRequest{Identity: fixture.identity, Queue: fixture.queue, ArtifactID: artifactID},
		Claim{Job: fixture.pendingJob, ArtifactID: artifactID, Header: []string{"customer-secret"}},
		binding,
		PageRequest{Identity: fixture.identity, Binding: binding, After: "customer-secret", Limit: 1},
		testRow(1, RowTicket, "customer-secret"),
		Page{Rows: []Row{testRow(2, RowTicket, "customer-secret")}, NextCursor: "customer-secret"},
		PageResult{Control: PageReady, Page: Page{Rows: []Row{testRow(3, RowTicket, "customer-secret")}}},
		SuccessRequest{Identity: fixture.identity, Binding: binding, ArtifactID: artifactID, Digest: manifest.Digest},
		ManifestRequest{Identity: fixture.identity, Binding: binding, ArtifactID: artifactID, Digest: manifest.Digest},
		ManifestResult{Disposition: ManifestRecorded, CurrentRevision: binding.Revision, Manifest: manifest},
		CommitResult{Disposition: CommitApplied, CurrentRevision: binding.Revision + 1, Manifest: manifest},
		FailureRequest{Identity: fixture.identity, Binding: binding, Code: kernel.TicketExportFailureInternal, RetryAt: retryAt},
		FailureResult{Disposition: FailureRetryScheduled, CurrentRevision: binding.Revision + 1, Code: kernel.TicketExportFailureInternal, RetryAt: retryAt},
		CancellationRequest{Identity: fixture.identity, Binding: binding, ExpectedRevision: binding.Revision + 1},
		RevocationRequest{Identity: fixture.identity, Binding: binding, ExpectedRevision: binding.Revision},
		TransitionResult{Disposition: TransitionApplied, CurrentRevision: binding.Revision + 1},
		TemporaryRequest{Identity: fixture.identity, Binding: binding, ArtifactID: artifactID},
		manifest,
		S3ArtifactOptions{Bucket: "customer-secret", ExpectedBucketOwner: "123456789012", TemporaryDirectory: "customer-secret"},
		SpoolSweepResult{Examined: 1, Removed: 1, Remaining: true},
		worker,
	}
	var diagnostics strings.Builder
	for _, value := range values {
		_, _ = fmt.Fprintf(&diagnostics, "%v %#v ", value, value)
	}
	text := strings.ToLower(diagnostics.String())
	for _, sensitive := range []string{
		fixture.tenant.String(), fixture.jobID.String(), fixture.identity.WorkerID.String(),
		artifactID.String(), "customer-secret", "deadbeef", "cafe",
	} {
		if strings.Contains(text, strings.ToLower(sensitive)) {
			t.Fatalf("diagnostics leaked %q: %s", sensitive, diagnostics.String())
		}
	}
}

type workerFixture struct {
	now        time.Time
	tenant     kernel.EntityID
	jobID      kernel.EntityID
	identity   Identity
	queue      Queue
	pendingJob kernel.TicketExportJob
}

func newWorkerFixture(
	t *testing.T,
	audience kernel.TicketExportAudience,
	maximumRows uint32,
	maximumBytes uint64,
) workerFixture {
	t.Helper()
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	tenant := testEntityID(t, 1)
	jobID := testEntityID(t, 2)
	requester := testEntityID(t, 3)
	membership := testEntityID(t, 4)
	serviceAccount := testEntityID(t, 5)
	workerID := testEntityID(t, 6)
	queryDigest := [32]byte{1}
	catalogDigest := [32]byte{2}
	var contact *kernel.EntityID
	if audience == kernel.TicketExportAudienceCustomer {
		value := testEntityID(t, 7)
		contact = &value
	}
	definition, err := kernel.NewTicketExportDefinition(kernel.TicketExportDefinitionInput{
		ID: jobID, Tenant: tenant, Requester: requester, OwnerMembership: membership,
		CustomerContact: contact, Kind: kernel.AggregateAlert, Audience: audience,
		Comments: kernel.TicketExportCommentsPublic, QuerySource: kernel.TicketExportQueryInline,
		QueryDigest: queryDigest, CatalogDigest: catalogDigest,
		ProjectionVersion: kernel.TicketExportProjectionVersion, Format: kernel.TicketExportCSV,
		MaximumRows: maximumRows, MaximumBytes: maximumBytes,
		MaximumAttempts: kernel.TicketExportMaximumAttempts,
	})
	if err != nil {
		t.Fatal(err)
	}
	creation, err := kernel.PlanTicketExportCreation(definition, now, now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return workerFixture{
		now: now, tenant: tenant, jobID: jobID,
		identity:   Identity{ServiceAccountID: serviceAccount, WorkerID: workerID, Purpose: WorkerPurpose},
		queue:      Queue{TenantID: tenant, Kind: kernel.AggregateAlert, Audience: audience},
		pendingJob: creation.Next(),
	}
}

func testEntityID(t *testing.T, seed byte) kernel.EntityID {
	t.Helper()
	var value [16]byte
	value[0], value[1], value[2], value[3] = 0x01, 0x9d, 0x12, seed
	value[6] = 0x70
	value[8] = 0x80
	value[15] = seed
	id, err := kernel.NewEntityID(value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func newTestWorker(
	t *testing.T,
	fixture workerFixture,
	repository Repository,
	store ArtifactStore,
	mutate func(*Options),
) *Worker {
	t.Helper()
	var sequence atomic.Uint32
	options := Options{
		Repository: repository, Artifacts: store, Identity: fixture.identity,
		PageSize: 2, LeaseDuration: time.Minute, AttemptTimeout: 30 * time.Second,
		OperationTimeout: 5 * time.Second, LeaseSafety: 5 * time.Second,
		CleanupTimeout: time.Second, CleanupAttempts: 3,
		RetryBase: time.Second, RetryMaximum: time.Second,
		Clock: func() time.Time { return fixture.now },
		NewArtifactID: func() (kernel.EntityID, error) {
			return testArtifactID(100 + byte(sequence.Add(1))), nil
		},
	}
	if mutate != nil {
		mutate(&options)
	}
	worker, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	return worker
}

func testArtifactID(seed byte) kernel.EntityID {
	var value [16]byte
	value[0], value[1], value[2], value[3] = 0x01, 0x9d, 0x13, seed
	value[6] = 0x70
	value[8] = 0x80
	value[15] = seed
	id, _ := kernel.NewEntityID(value)
	return id
}

func testRow(seed byte, kind RowKind, cells ...string) Row {
	key := sha256.Sum256([]byte{seed})
	return Row{Kind: kind, SnapshotKey: key, Cells: append([]string(nil), cells...)}
}

type fakeRepository struct {
	mu                      sync.Mutex
	job                     kernel.TicketExportJob
	artifactID              kernel.EntityID
	manifest                *StreamManifest
	header                  []string
	pages                   map[string]Page
	pageControl             PageControl
	controlPage             Page
	blockPage               bool
	pageStarted             chan struct{}
	pageStartedOnce         sync.Once
	blockClaim              bool
	claimLateNil            bool
	claimStarted            chan struct{}
	claimStartedOnce        sync.Once
	claimWorkerOverride     kernel.EntityID
	claimArtifactOverride   kernel.EntityID
	forceNotFound           bool
	idleClaim               Claim
	claimErrorAfterApply    error
	finishDisposition       CommitDisposition
	finishErrorAfterApply   error
	finishResultOverride    *CommitResult
	blockFinish             bool
	finishStarted           chan struct{}
	finishStartedOnce       sync.Once
	manifestDisposition     ManifestDisposition
	manifestErrorAfterApply error
	manifestResultOverride  *ManifestResult
	failureReplay           bool
	failureDisposition      FailureDisposition
	failureResultOverride   *FailureResult
	claimCalls              int
	pageCalls               int
	manifestCalls           int
	successCalls            int
	failureCalls            int
	cancelCalls             int
	revocationCalls         int
	lastFailure             FailureRequest
}

func newFakeRepository(
	fixture workerFixture,
	header []string,
	pages map[string]Page,
) *fakeRepository {
	return &fakeRepository{
		job: fixture.pendingJob, header: append([]string(nil), header...), pages: pages,
		finishDisposition: CommitApplied, manifestDisposition: ManifestRecorded,
	}
}

func (repository *fakeRepository) Claim(
	ctx context.Context,
	request ClaimRequest,
) (Claim, bool, error) {
	repository.mu.Lock()
	if repository.blockClaim {
		started := repository.claimStarted
		repository.claimStartedOnce.Do(func() { close(started) })
		repository.mu.Unlock()
		<-ctx.Done()
		if repository.claimLateNil {
			return Claim{}, false, nil
		}
		return Claim{}, false, ctx.Err()
	}
	defer repository.mu.Unlock()
	if repository.forceNotFound {
		return repository.idleClaim, false, nil
	}
	if repository.job.State() != kernel.TicketExportPending || repository.job.AvailableAt().After(request.Now) {
		return Claim{}, false, nil
	}
	if !validEntityID(request.ArtifactID) {
		return Claim{}, false, errors.New("invalid artifact reservation")
	}
	workerID := request.Identity.WorkerID
	if validEntityID(repository.claimWorkerOverride) {
		workerID = repository.claimWorkerOverride
	}
	fence := [32]byte{byte(repository.job.Attempts() + 1), 0x7f}
	plan, err := kernel.PlanTicketExportClaim(
		repository.job, workerID, fence, request.Now, request.Now.Add(request.LeaseDuration),
	)
	if err != nil {
		return Claim{}, false, err
	}
	repository.job = plan.Next()
	repository.artifactID = request.ArtifactID
	repository.manifest = nil
	repository.claimCalls++
	if repository.claimErrorAfterApply != nil {
		return Claim{}, false, repository.claimErrorAfterApply
	}
	returnedArtifactID := request.ArtifactID
	if validEntityID(repository.claimArtifactOverride) {
		returnedArtifactID = repository.claimArtifactOverride
	}
	return Claim{
		Job: repository.job, ArtifactID: returnedArtifactID,
		Header: append([]string(nil), repository.header...), ObservedAt: request.Now,
	}, true, nil
}

func (repository *fakeRepository) ReadPage(
	ctx context.Context,
	request PageRequest,
) (PageResult, error) {
	repository.mu.Lock()
	repository.pageCalls++
	if repository.blockPage {
		started := repository.pageStarted
		repository.pageStartedOnce.Do(func() { close(started) })
		repository.mu.Unlock()
		<-ctx.Done()
		return PageResult{}, ctx.Err()
	}
	if !repository.bindingMatches(request.Binding) {
		repository.mu.Unlock()
		return PageResult{Control: PageFenceLost}, nil
	}
	control := repository.pageControl
	if control == PageCancellationRequested && repository.job.State() == kernel.TicketExportRunning {
		plan, err := kernel.PlanTicketExportCancellation(
			repository.job, repository.job.Revision(), repository.job.UpdatedAt(),
		)
		if err != nil {
			repository.mu.Unlock()
			return PageResult{}, err
		}
		repository.job = plan.Next()
	}
	if control != 0 && control != PageReady {
		revision := uint64(0)
		if control == PageCancellationRequested || control == PageAuthorizationRevoked {
			revision = repository.job.Revision()
		}
		repository.mu.Unlock()
		return PageResult{
			Control: control, ControlRevision: revision, Page: clonePage(repository.controlPage),
		}, nil
	}
	page, ok := repository.pages[request.After]
	repository.mu.Unlock()
	if !ok {
		return PageResult{Control: PageReady, Page: Page{}}, nil
	}
	return PageResult{Control: PageReady, Page: clonePage(page)}, nil
}

func (repository *fakeRepository) RecordManifest(
	_ context.Context,
	request ManifestRequest,
) (ManifestResult, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.manifestCalls++
	if !repository.bindingMatches(request.Binding) || request.ArtifactID != repository.artifactID {
		return ManifestResult{Disposition: ManifestFenceLost}, nil
	}
	disposition := repository.manifestDisposition
	if disposition == ManifestCancellationRequested {
		plan, err := kernel.PlanTicketExportCancellation(
			repository.job, repository.job.Revision(), request.RecordedAt,
		)
		if err != nil {
			return ManifestResult{}, err
		}
		repository.job = plan.Next()
		return ManifestResult{Disposition: disposition, CurrentRevision: repository.job.Revision()}, nil
	}
	if disposition == ManifestAuthorizationRevoked {
		return ManifestResult{Disposition: disposition, CurrentRevision: repository.job.Revision()}, nil
	}
	if disposition == ManifestFenceLost || disposition == ManifestSnapshotStale {
		return ManifestResult{Disposition: disposition}, nil
	}
	if disposition != ManifestRecorded || request.Digest == ([32]byte{}) || request.Bytes == 0 {
		return ManifestResult{Disposition: disposition}, nil
	}
	manifest := StreamManifest{
		ArtifactID: request.ArtifactID, Digest: request.Digest,
		Rows: request.Rows, Bytes: request.Bytes,
	}
	if repository.manifest != nil && *repository.manifest != manifest {
		return ManifestResult{Disposition: ManifestSnapshotStale}, nil
	}
	repository.manifest = &manifest
	if repository.manifestErrorAfterApply != nil {
		return ManifestResult{}, repository.manifestErrorAfterApply
	}
	if repository.manifestResultOverride != nil {
		return *repository.manifestResultOverride, nil
	}
	return ManifestResult{
		Disposition: ManifestRecorded, CurrentRevision: repository.job.Revision(), Manifest: manifest,
	}, nil
}

func (repository *fakeRepository) CommitSuccess(
	ctx context.Context,
	request SuccessRequest,
) (CommitResult, error) {
	repository.mu.Lock()
	repository.successCalls++
	if repository.blockFinish {
		started := repository.finishStarted
		repository.finishStartedOnce.Do(func() { close(started) })
		repository.mu.Unlock()
		<-ctx.Done()
		return CommitResult{}, nil
	}
	defer repository.mu.Unlock()
	if !repository.bindingMatches(request.Binding) || request.ArtifactID != repository.artifactID ||
		repository.manifest == nil || repository.manifest.ArtifactID != request.ArtifactID ||
		repository.manifest.Digest != request.Digest || repository.manifest.Rows != request.Rows ||
		repository.manifest.Bytes != request.Bytes {
		return CommitResult{Disposition: CommitFenceLost}, nil
	}
	disposition := repository.finishDisposition
	if disposition == CommitCancellationRequested {
		plan, err := kernel.PlanTicketExportCancellation(
			repository.job, repository.job.Revision(), request.CompletedAt,
		)
		if err != nil {
			return CommitResult{}, err
		}
		repository.job = plan.Next()
		return CommitResult{Disposition: disposition, CurrentRevision: repository.job.Revision()}, nil
	}
	if disposition == CommitAuthorizationRevoked {
		return CommitResult{Disposition: disposition, CurrentRevision: repository.job.Revision()}, nil
	}
	if disposition == CommitFenceLost || disposition == CommitSnapshotStale {
		return CommitResult{Disposition: disposition}, nil
	}
	artifact, err := kernel.NewTicketExportArtifact(
		request.ArtifactID, request.Digest, request.Rows, request.Bytes, request.ExpiresAt,
	)
	if err != nil {
		return CommitResult{}, err
	}
	plan, err := kernel.PlanTicketExportSuccess(
		repository.job, request.Binding.WorkerID, request.Binding.Fence, artifact, request.CompletedAt,
	)
	if err != nil {
		return CommitResult{}, err
	}
	repository.job = plan.Next()
	if repository.finishErrorAfterApply != nil {
		return CommitResult{}, repository.finishErrorAfterApply
	}
	if repository.finishResultOverride != nil {
		return *repository.finishResultOverride, nil
	}
	return CommitResult{
		Disposition: disposition, CurrentRevision: repository.job.Revision(),
		Manifest: *repository.manifest,
	}, nil
}

func (repository *fakeRepository) ReportFailure(
	_ context.Context,
	request FailureRequest,
) (FailureResult, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.failureCalls++
	repository.lastFailure = request
	if !repository.bindingMatches(request.Binding) {
		return FailureResult{Disposition: FailureFenceLost}, nil
	}
	if repository.failureDisposition != 0 {
		return FailureResult{Disposition: repository.failureDisposition}, nil
	}
	var retryAt *time.Time
	if !request.RetryAt.IsZero() {
		value := request.RetryAt
		retryAt = &value
	}
	plan, err := kernel.PlanTicketExportFailure(
		repository.job, request.Binding.WorkerID, request.Binding.Fence,
		request.Code, retryAt, request.FailedAt,
	)
	if err != nil {
		return FailureResult{}, err
	}
	repository.job = plan.Next()
	if repository.failureResultOverride != nil {
		return *repository.failureResultOverride, nil
	}
	retry := repository.job.State() == kernel.TicketExportPending
	if repository.failureReplay {
		if retry {
			return FailureResult{
				Disposition: FailureReplayRetry, CurrentRevision: repository.job.Revision(),
				Code: request.Code, RetryAt: request.RetryAt,
			}, nil
		}
		return FailureResult{
			Disposition: FailureReplayTerminal, CurrentRevision: repository.job.Revision(),
			Code: request.Code,
		}, nil
	}
	if retry {
		return FailureResult{
			Disposition: FailureRetryScheduled, CurrentRevision: repository.job.Revision(),
			Code: request.Code, RetryAt: request.RetryAt,
		}, nil
	}
	return FailureResult{
		Disposition: FailureTerminal, CurrentRevision: repository.job.Revision(), Code: request.Code,
	}, nil
}

func (repository *fakeRepository) AcknowledgeCancellation(
	_ context.Context,
	request CancellationRequest,
) (TransitionResult, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.cancelCalls++
	if repository.job.Revision() != request.ExpectedRevision {
		return TransitionResult{Disposition: TransitionFenceLost}, nil
	}
	plan, err := kernel.PlanTicketExportCancellationAcknowledgement(
		repository.job, request.Binding.WorkerID, request.Binding.Fence, request.AcknowledgedAt,
	)
	if err != nil {
		return TransitionResult{}, err
	}
	repository.job = plan.Next()
	return TransitionResult{
		Disposition: TransitionApplied, CurrentRevision: repository.job.Revision(),
	}, nil
}

func (repository *fakeRepository) RejectRevoked(
	_ context.Context,
	request RevocationRequest,
) (TransitionResult, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.revocationCalls++
	if repository.job.Revision() != request.ExpectedRevision {
		return TransitionResult{Disposition: TransitionFenceLost}, nil
	}
	plan, err := kernel.PlanTicketExportAuthorizationRevocation(repository.job, request.RejectedAt)
	if err != nil {
		return TransitionResult{}, err
	}
	repository.job = plan.Next()
	return TransitionResult{
		Disposition: TransitionApplied, CurrentRevision: repository.job.Revision(),
	}, nil
}

func (repository *fakeRepository) bindingMatches(binding LeaseBinding) bool {
	definition := repository.job.Definition()
	lease := repository.job.Lease()
	return lease != nil && definition.ID() == binding.JobID && definition.Tenant() == binding.TenantID &&
		repository.job.Revision() == binding.Revision && lease.Worker() == binding.WorkerID &&
		lease.Fence() == binding.Fence
}

type fakeRepositorySnapshot struct {
	job             kernel.TicketExportJob
	artifactID      kernel.EntityID
	manifest        *StreamManifest
	claimCalls      int
	pageCalls       int
	manifestCalls   int
	successCalls    int
	failureCalls    int
	cancelCalls     int
	revocationCalls int
	lastFailure     FailureRequest
}

func (repository *fakeRepository) snapshot() fakeRepositorySnapshot {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	var manifest *StreamManifest
	if repository.manifest != nil {
		value := *repository.manifest
		manifest = &value
	}
	return fakeRepositorySnapshot{
		job: repository.job, artifactID: repository.artifactID,
		manifest: manifest, claimCalls: repository.claimCalls, pageCalls: repository.pageCalls,
		manifestCalls: repository.manifestCalls,
		successCalls:  repository.successCalls, failureCalls: repository.failureCalls,
		cancelCalls: repository.cancelCalls, revocationCalls: repository.revocationCalls,
		lastFailure: repository.lastFailure,
	}
}

func clonePage(page Page) Page {
	result := Page{Rows: make([]Row, len(page.Rows)), NextCursor: page.NextCursor}
	for index, row := range page.Rows {
		result.Rows[index] = Row{
			Kind: row.Kind, SnapshotKey: row.SnapshotKey,
			Cells: append([]string(nil), row.Cells...),
		}
	}
	return result
}

type fakeArtifactStore struct {
	mu            sync.Mutex
	objects       []*fakeTemporaryArtifact
	openErr       error
	writeLimit    int
	sealErr       error
	promoteErr    error
	promotion     PromotionDisposition
	abortFailures int
	purgeFailures int
	writeHook     func(int)
	promoteHook   func()
	abortHook     func()
}

func (store *fakeArtifactStore) OpenTemporary(
	_ context.Context,
	_ context.Context,
	request TemporaryRequest,
) (TemporaryArtifact, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.openErr != nil {
		return nil, store.openErr
	}
	object := &fakeTemporaryArtifact{
		request:    request,
		writeLimit: store.writeLimit, sealErr: store.sealErr, promoteErr: store.promoteErr,
		promotion: store.promotion, abortFailures: store.abortFailures, purgeFailures: store.purgeFailures,
		writeHook: store.writeHook, promoteHook: store.promoteHook, abortHook: store.abortHook,
	}
	store.objects = append(store.objects, object)
	return object, nil
}

func (store *fakeArtifactStore) snapshot() []*fakeTemporaryArtifact {
	store.mu.Lock()
	defer store.mu.Unlock()
	return append([]*fakeTemporaryArtifact(nil), store.objects...)
}

func (store *fakeArtifactStore) onlyObject(t *testing.T) *fakeTemporaryArtifact {
	t.Helper()
	objects := store.snapshot()
	if len(objects) != 1 {
		t.Fatalf("objects=%d, want 1", len(objects))
	}
	return objects[0]
}

type fakeTemporaryArtifact struct {
	mu            sync.Mutex
	request       TemporaryRequest
	buffer        bytes.Buffer
	writeLimit    int
	sealErr       error
	promoteErr    error
	promotion     PromotionDisposition
	abortFailures int
	purgeFailures int
	manifest      StreamManifest
	sealed        bool
	promoted      bool
	abortCalls    int
	purgeCalls    int
	writeCalls    int
	writeHook     func(int)
	promoteHook   func()
	abortHook     func()
}

func (object *fakeTemporaryArtifact) Write(value []byte) (int, error) {
	object.mu.Lock()
	defer object.mu.Unlock()
	object.writeCalls++
	if object.writeHook != nil {
		object.writeHook(object.writeCalls)
	}
	if object.writeLimit > 0 && object.buffer.Len()+len(value) > object.writeLimit {
		remaining := object.writeLimit - object.buffer.Len()
		if remaining < 0 {
			remaining = 0
		}
		if remaining > 0 {
			_, _ = object.buffer.Write(value[:remaining])
		}
		return remaining, nil
	}
	return object.buffer.Write(value)
}

func (object *fakeTemporaryArtifact) Seal(_ context.Context, manifest StreamManifest) error {
	object.mu.Lock()
	defer object.mu.Unlock()
	if object.sealErr != nil {
		return object.sealErr
	}
	contents := object.buffer.Bytes()
	digest := sha256.Sum256(contents)
	if manifest.Bytes != uint64(len(contents)) || manifest.Digest != digest || !validEntityID(manifest.ArtifactID) {
		return errors.New("manifest mismatch")
	}
	object.manifest = manifest
	object.sealed = true
	return nil
}

func (object *fakeTemporaryArtifact) Promote(
	_ context.Context,
	artifactID kernel.EntityID,
) (PromotionDisposition, error) {
	object.mu.Lock()
	defer object.mu.Unlock()
	if object.promoteErr != nil {
		return 0, object.promoteErr
	}
	if !object.sealed || artifactID != object.manifest.ArtifactID {
		return PromotionRejected, nil
	}
	object.promoted = true
	if object.promoteHook != nil {
		object.promoteHook()
	}
	return object.promotion, nil
}

func (object *fakeTemporaryArtifact) Abort(context.Context) error {
	object.mu.Lock()
	defer object.mu.Unlock()
	object.abortCalls++
	if object.abortHook != nil {
		object.abortHook()
	}
	if object.abortCalls <= object.abortFailures {
		return errors.New("transient abort error")
	}
	return nil
}

func (object *fakeTemporaryArtifact) Purge(_ context.Context, artifactID kernel.EntityID) error {
	object.mu.Lock()
	defer object.mu.Unlock()
	object.purgeCalls++
	if object.purgeCalls <= object.purgeFailures {
		return errors.New("transient purge error")
	}
	if artifactID != object.manifest.ArtifactID {
		return errors.New("artifact mismatch")
	}
	object.promoted = false
	return nil
}

type fakeObjectSnapshot struct {
	contents   string
	manifest   StreamManifest
	sealed     bool
	promoted   bool
	abortCalls int
	purgeCalls int
}

func (object *fakeTemporaryArtifact) snapshot() fakeObjectSnapshot {
	object.mu.Lock()
	defer object.mu.Unlock()
	return fakeObjectSnapshot{
		contents: object.buffer.String(), manifest: object.manifest,
		sealed: object.sealed, promoted: object.promoted,
		abortCalls: object.abortCalls, purgeCalls: object.purgeCalls,
	}
}

func (object *fakeTemporaryArtifact) contents() string {
	object.mu.Lock()
	defer object.mu.Unlock()
	return object.buffer.String()
}

var _ io.Writer = (*fakeTemporaryArtifact)(nil)
