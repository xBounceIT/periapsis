package customfieldimport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/customfields"
	customapp "github.com/periapsis-im/periapsis/services/api/internal/customfields"
)

func TestRequestUsesExactReplayBeforeMutableDefinitionResolution(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 123_456_000, time.UTC)
	actor, audit := importActorAndAudit()
	repository := newRequestRepository(t, importDefinition(t, "summary", "Summary"))
	service, err := NewService(repository, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	input := RequestInput{
		ObjectType: kernel.ObjectAlert, Mode: kernel.ImportCommit,
		Rows: []RowInput{{
			Target: importUUID(10), ExpectedVersion: 4,
			Fields: []CellInput{{Key: "summary", Present: true, RawJSON: json.RawMessage(`"alpha"`)}},
		}},
		Retention: time.Hour, IdempotencyKey: "import-replay-key-0001", Audit: audit,
	}
	created, err := service.Request(context.Background(), actor, actor.TenantID, input)
	if err != nil || created.Replayed || created.Record.Job.State() != kernel.ImportJobPending {
		t.Fatalf("created=%#v err=%v", created, err)
	}
	if pins := created.Record.Job.Manifest().DefinitionPins(); len(pins) != 1 ||
		pins[0].Key().String() != "summary" {
		t.Fatalf("pins = %#v", pins)
	}

	// The current definition changes, but exact replay returns the original
	// immutable job before re-resolving that mutable inventory.
	repository.definitions = []kernel.Definition{importDefinition(t, "summary", "Renamed")}
	replayed, err := service.Request(context.Background(), actor, actor.TenantID, input)
	if err != nil || !replayed.Replayed ||
		!kernel.SameImportJob(replayed.Record.Job, created.Record.Job) {
		t.Fatalf("replayed=%#v err=%v", replayed, err)
	}
	if repository.definitionLoads.Load() != 1 || repository.reservations.Load() != 1 {
		t.Fatalf("definition loads=%d reservations=%d", repository.definitionLoads.Load(), repository.reservations.Load())
	}

	divergent := input
	divergent.Rows = []RowInput{input.Rows[0]}
	divergent.Rows[0].Fields = []CellInput{input.Rows[0].Fields[0]}
	divergent.Rows[0].Fields[0].RawJSON = json.RawMessage(`""`)
	if _, err := service.Request(context.Background(), actor, actor.TenantID, divergent); !errors.Is(err, ErrConflict) {
		t.Fatalf("divergent replay error = %v", err)
	}
}

func TestConcurrentRequestCommitReturnsOneExactWinner(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 15, 0, 0, time.UTC)
	actor, audit := importActorAndAudit()
	base := newRequestRepository(t, importDefinition(t, "summary", "Summary"))
	repository := &concurrentRequestRepository{
		requestRepository: base,
		lookupRelease:     make(chan struct{}),
	}
	service, _ := NewService(repository, func() time.Time { return now })
	input := RequestInput{
		ObjectType: kernel.ObjectAlert, Mode: kernel.ImportCommit,
		Rows: []RowInput{{
			Target: importUUID(10), ExpectedVersion: 4,
			Fields: []CellInput{{Key: "summary", Present: true, RawJSON: json.RawMessage(`"alpha"`)}},
		}},
		Retention: time.Hour, IdempotencyKey: "concurrent-request-key-1", Audit: audit,
	}
	type response struct {
		result Result
		err    error
	}
	responses := make(chan response, 2)
	for range 2 {
		go func() {
			result, err := service.Request(context.Background(), actor, actor.TenantID, input)
			responses <- response{result: result, err: err}
		}()
	}
	first, second := <-responses, <-responses
	if first.err != nil || second.err != nil {
		t.Fatalf("concurrent errors: first=%v second=%v", first.err, second.err)
	}
	if first.result.Replayed == second.result.Replayed ||
		!kernel.SameImportJob(first.result.Record.Job, second.result.Record.Job) {
		t.Fatalf("first=%#v second=%#v", first.result, second.result)
	}
	if repository.reserved.Load() != 2 || repository.effects.Load() != 1 {
		t.Fatalf("reservations=%d effects=%d", repository.reserved.Load(), repository.effects.Load())
	}
}

func TestRequestRejectsForeignRequesterReplayProjection(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 30, 0, 0, time.UTC)
	actor, audit := importActorAndAudit()
	definition := importDefinition(t, "summary", "Summary")
	repository := newRequestRepository(t, definition)
	foreignManifest, err := kernel.NewImportManifest(kernel.ImportManifestInput{
		ID: mustImportEntity(t, importUUID(21)), Tenant: mustImportEntity(t, importUUID(1)),
		Requester: mustImportEntity(t, importUUID(7)), OwnerMembership: mustImportEntity(t, importUUID(8)),
		ObjectType: kernel.ObjectAlert, Mode: kernel.ImportCommit, Definitions: []kernel.Definition{definition},
		Rows: []kernel.ImportRowInput{{
			Sequence: 1, Target: mustImportEntity(t, importUUID(10)), ExpectedVersion: 4,
			Fields: []kernel.FieldInput{{Key: definition.Key(), Value: kernel.JSONInputValue(json.RawMessage(`"alpha"`))}},
		}},
		ProjectionVersion: kernel.ImportProjectionVersion, MaximumAttempts: kernel.ImportMaximumAttempts,
	})
	if err != nil {
		t.Fatal(err)
	}
	foreignJob, err := kernel.NewImportJob(foreignManifest, now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	foreign := Record{Job: foreignJob, RequestedAudit: audit}
	repository.replayOverride = &foreign
	service, _ := NewService(repository, func() time.Time { return now })
	_, err = service.Request(context.Background(), actor, actor.TenantID, RequestInput{
		ObjectType: kernel.ObjectAlert, Mode: kernel.ImportCommit,
		Rows: []RowInput{{
			Target: importUUID(10), ExpectedVersion: 4,
			Fields: []CellInput{{Key: "summary", Present: true, RawJSON: json.RawMessage(`"alpha"`)}},
		}},
		Retention: time.Hour, IdempotencyKey: "foreign-replay-key-01", Audit: audit,
	})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("foreign replay error = %v", err)
	}
	if repository.definitionLoads.Load() != 0 || repository.reservations.Load() != 0 {
		t.Fatal("foreign replay reached mutable resolution")
	}
}

func TestRequestDeniesCustomerAndForgedAuthority(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	actor, audit := importActorAndAudit()
	repository := newRequestRepository(t, importDefinition(t, "summary", "Summary"))
	service, _ := NewService(repository, func() time.Time { return now })
	input := RequestInput{
		ObjectType: kernel.ObjectCase, Mode: kernel.ImportDryRun,
		Rows: []RowInput{{
			Target: importUUID(11), ExpectedVersion: 2,
			Fields: []CellInput{{Key: "summary", Present: false}},
		}},
		Retention: time.Hour, IdempotencyKey: "import-authority-key-1", Audit: audit,
	}
	customer := actor
	customer.Kind = customapp.PrincipalCustomer
	if _, err := service.Request(context.Background(), customer, actor.TenantID, input); !errors.Is(err, ErrForbidden) {
		t.Fatalf("customer error = %v", err)
	}

	repository.allowed = false
	if _, err := service.Request(context.Background(), actor, actor.TenantID, input); !errors.Is(err, ErrForbidden) {
		t.Fatalf("denied access error = %v", err)
	}
	if repository.definitionLoads.Load() != 0 || repository.reservations.Load() != 0 {
		t.Fatal("denied request reached definition or ID resolution")
	}
}

func TestRequestDoesNotPinOperatorHiddenDefinition(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 45, 0, 0, time.UTC)
	actor, audit := importActorAndAudit()
	hiddenInput := kernel.DefinitionInput{
		ID: mustImportEntity(t, importUUID(91)), TenantID: mustImportEntity(t, importUUID(1)),
		ObjectType: kernel.ObjectAlert, Key: mustImportKey(t, "private_note"), Label: "Private note",
		DataType: kernel.TypeShortText, Nullable: true, Visibility: kernel.Visibility{Customer: true},
		Placement: kernel.Placement{ShowInDetail: true}, SchemaVersion: 1,
	}
	hidden, err := kernel.NewDefinition(hiddenInput)
	if err != nil {
		t.Fatal(err)
	}
	repository := newRequestRepository(t, hidden)
	service, _ := NewService(repository, func() time.Time { return now })
	result, err := service.Request(context.Background(), actor, actor.TenantID, RequestInput{
		ObjectType: kernel.ObjectAlert, Mode: kernel.ImportDryRun,
		Rows: []RowInput{{
			Target: importUUID(10), ExpectedVersion: 4,
			Fields: []CellInput{{Key: "private_note", Present: true, RawJSON: json.RawMessage(`"guess"`)}},
		}},
		Retention: time.Hour, IdempotencyKey: "hidden-definition-key-01", Audit: audit,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Record.Job.Manifest().Definitions()) != 0 ||
		len(result.Record.Job.Manifest().DefinitionPins()) != 0 {
		t.Fatal("operator-hidden definition escaped into the import projection")
	}
}

func TestCancellationCASAndExactReplay(t *testing.T) {
	requestedAt := time.Date(2026, 9, 3, 12, 50, 0, 0, time.UTC)
	actor, audit := importActorAndAudit()
	current := importWorkerRecord(t, kernel.ImportCommit, requestedAt)
	leaseBoundary := requestedAt.Add(2 * time.Second)
	claimed, err := kernel.ClaimImportJob(
		current.Job, current.Job.Revision(), mustImportEntity(t, importUUID(35)),
		requestedAt.Add(time.Second), leaseBoundary,
	)
	if err != nil {
		t.Fatal(err)
	}
	current.Job = claimed
	base := newRequestRepository(t, importDefinition(t, "summary", "Summary"))
	repository := &cancellationRepository{requestRepository: base, current: current}
	service, _ := NewService(repository, func() time.Time { return leaseBoundary })
	input := CancelInput{
		ExpectedRevision: claimed.Revision(), IdempotencyKey: "cancel-import-key-0001", Audit: audit,
	}
	created, err := service.Cancel(
		context.Background(), actor, actor.TenantID, kernel.ObjectAlert, importUUID(20), input,
	)
	if err != nil || created.Replayed || created.Record.Job.State() != kernel.ImportJobCancelled {
		t.Fatalf("created=%#v err=%v", created, err)
	}
	replayed, err := service.Cancel(
		context.Background(), actor, actor.TenantID, kernel.ObjectAlert, importUUID(20), input,
	)
	if err != nil || !replayed.Replayed ||
		!kernel.SameImportJob(replayed.Record.Job, created.Record.Job) || repository.effects != 1 {
		t.Fatalf("replayed=%#v effects=%d err=%v", replayed, repository.effects, err)
	}
	divergent := input
	divergent.ExpectedRevision++
	if _, err := service.Cancel(
		context.Background(), actor, actor.TenantID, kernel.ObjectAlert, importUUID(20), divergent,
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("divergent replay error = %v", err)
	}
	stale := input
	stale.IdempotencyKey = "cancel-import-key-0002"
	if _, err := service.Cancel(
		context.Background(), actor, actor.TenantID, kernel.ObjectAlert, importUUID(20), stale,
	); !errors.Is(err, ErrPreconditionFailed) {
		t.Fatalf("stale cancellation error = %v", err)
	}
}

func TestConcurrentCancellationCommitReturnsOneExactWinner(t *testing.T) {
	requestedAt := time.Date(2026, 9, 3, 12, 55, 0, 0, time.UTC)
	actor, audit := importActorAndAudit()
	base := newRequestRepository(t, importDefinition(t, "summary", "Summary"))
	cancellations := &cancellationRepository{
		requestRepository: base,
		current:           importWorkerRecord(t, kernel.ImportCommit, requestedAt),
	}
	repository := &concurrentCancellationRepository{
		cancellationRepository: cancellations,
		lookupRelease:          make(chan struct{}),
		getRelease:             make(chan struct{}),
	}
	var clockCalls atomic.Int64
	service, _ := NewService(repository, func() time.Time {
		return requestedAt.Add(time.Duration(clockCalls.Add(1)) * time.Microsecond)
	})
	input := CancelInput{
		ExpectedRevision: 1, IdempotencyKey: "concurrent-cancel-key-1", Audit: audit,
	}
	type response struct {
		result Result
		err    error
	}
	responses := make(chan response, 2)
	for range 2 {
		go func() {
			result, err := service.Cancel(
				context.Background(), actor, actor.TenantID, kernel.ObjectAlert, importUUID(20), input,
			)
			responses <- response{result: result, err: err}
		}()
	}
	first, second := <-responses, <-responses
	if first.err != nil || second.err != nil {
		t.Fatalf("concurrent cancellation errors: first=%v second=%v", first.err, second.err)
	}
	if first.result.Replayed == second.result.Replayed ||
		!kernel.SameImportJob(first.result.Record.Job, second.result.Record.Job) || cancellations.effects != 1 {
		t.Fatalf("first=%#v second=%#v effects=%d", first.result, second.result, cancellations.effects)
	}
}

func TestCancellationRechecksReplayWhenWinnerCommitsBeforeCurrentRead(t *testing.T) {
	requestedAt := time.Date(2026, 9, 3, 12, 57, 0, 0, time.UTC)
	actor, audit := importActorAndAudit()
	current := importWorkerRecord(t, kernel.ImportCommit, requestedAt)
	command, err := bindCancellation(
		"late-cancel-replay-key-1", actor, actor.TenantID, kernel.ObjectAlert,
		importUUID(20), 1,
	)
	if err != nil {
		t.Fatal(err)
	}
	next, err := kernel.RequestImportCancellation(
		current.Job, 1, requestedAt.Add(time.Microsecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	current.Job = next
	receipt := Result{Record: current}
	base := &cancellationRepository{
		requestRepository: newRequestRepository(t, importDefinition(t, "summary", "Summary")),
		current:           current,
		cancelCommand:     command,
		cancelReceipt:     &receipt,
		effects:           1,
	}
	repository := &lateCancellationReplayRepository{cancellationRepository: base}
	service, err := NewService(repository, func() time.Time { return requestedAt.Add(2 * time.Microsecond) })
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Cancel(
		context.Background(), actor, actor.TenantID, kernel.ObjectAlert, importUUID(20),
		CancelInput{
			ExpectedRevision: 1,
			IdempotencyKey:   "late-cancel-replay-key-1",
			Audit:            audit,
		},
	)
	if err != nil || !result.Replayed ||
		!kernel.SameImportJob(result.Record.Job, receipt.Record.Job) ||
		repository.lookupCalls.Load() != 2 || base.effects != 1 {
		t.Fatalf(
			"result=%#v lookupCalls=%d effects=%d err=%v",
			result, repository.lookupCalls.Load(), base.effects, err,
		)
	}
}

func TestRequestPreservesMissingNullEmptyInCommandFingerprint(t *testing.T) {
	actor, audit := importActorAndAudit()
	repository := newRequestRepository(t, importDefinition(t, "summary", "Summary"))
	service, _ := NewService(repository, func() time.Time {
		return time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	})
	base := RequestInput{
		ObjectType: kernel.ObjectAlert, Mode: kernel.ImportDryRun,
		Rows:      []RowInput{{Target: importUUID(12), ExpectedVersion: 3}},
		Retention: time.Hour, Audit: audit,
	}
	variants := []CellInput{
		{Key: "summary", Present: false},
		{Key: "summary", Present: true, RawJSON: json.RawMessage("null")},
		{Key: "summary", Present: true, RawJSON: json.RawMessage(`""`)},
	}
	fingerprints := make(map[[32]byte]struct{})
	for index, cell := range variants {
		input := base
		input.IdempotencyKey = fmt.Sprintf("presence-key-%016d", index)
		input.Rows = []RowInput{{
			Target: importUUID(12), ExpectedVersion: 3, Fields: []CellInput{cell},
		}}
		if _, err := service.Request(context.Background(), actor, actor.TenantID, input); err != nil {
			t.Fatal(err)
		}
		fingerprints[repository.lastCommand.Fingerprint] = struct{}{}
		repository.resetStored()
	}
	if len(fingerprints) != 3 {
		t.Fatalf("distinct fingerprints = %d, want 3", len(fingerprints))
	}
}

func TestWorkerRowCommitAtomicallyAdvancesProgressAndReceiptReplay(t *testing.T) {
	now := time.Date(2026, 9, 3, 13, 0, 0, 0, time.UTC)
	record := importWorkerRecord(t, kernel.ImportCommit, now)
	repository := newWorkerRepository(t, record)
	repository.failRowResponseOnce = true
	worker, err := NewWorker(repository)
	if err != nil {
		t.Fatal(err)
	}
	fence := mustImportEntity(t, importUUID(30))
	claimed, err := worker.Claim(
		context.Background(), importUUID(1), importUUID(20), 1, fence,
		now.Add(time.Second), now.Add(time.Minute),
	)
	if err != nil || claimed.Job.State() != kernel.ImportJobRunning {
		t.Fatalf("claim=%#v err=%v", claimed, err)
	}
	if _, err := worker.ProcessBatch(
		context.Background(), importUUID(1), importUUID(20), fence, 10, now.Add(2*time.Second),
	); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("first process error = %v", err)
	}
	if repository.mutations != 1 || repository.currentVersion != 11 || len(repository.receipts) != 1 ||
		repository.record.Job.State() != kernel.ImportJobCompleted || repository.record.Job.Progress().Committed != 1 {
		t.Fatalf("after uncertain response mutations=%d version=%d receipts=%d job=%s", repository.mutations, repository.currentVersion, len(repository.receipts), repository.record.Job)
	}
	replayed, err := repository.CommitRow(context.Background(), repository.lastRowWrite)
	if err != nil || !replayed.Replayed || replayed.Result.Outcome() != kernel.ImportRowCommitted ||
		!kernel.SameImportJob(replayed.Record.Job, repository.record.Job) {
		t.Fatalf("replayed=%#v err=%v", replayed, err)
	}
	if repository.mutations != 1 || repository.currentVersion != 11 {
		t.Fatalf("receipt replay repeated mutation: mutations=%d version=%d", repository.mutations, repository.currentVersion)
	}
	divergent := repository.lastRowWrite
	divergent.Command.Fingerprint[0] ^= 0xff
	if _, err := repository.CommitRow(context.Background(), divergent); !errors.Is(err, ErrRepositoryConflict) {
		t.Fatalf("divergent receipt replay error = %v", err)
	}
}

func TestWorkerValidatesReceiptReplayAtStoredTransitionTime(t *testing.T) {
	now := time.Date(2026, 9, 3, 13, 5, 0, 0, time.UTC)
	record := importWorkerRecord(t, kernel.ImportDryRun, now)
	fence := mustImportEntity(t, importUUID(34))
	claimed, err := kernel.ClaimImportJob(
		record.Job, record.Job.Revision(), fence, now.Add(time.Second), now.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	record.Job = claimed
	row := claimed.Manifest().Rows()[0]
	snapshot := newWorkerRepository(t, record).snapshot
	intended, patches, err := prepareRow(claimed.Manifest(), row, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	command, err := bindRow(claimed.Manifest(), row, patches, intended)
	if err != nil {
		t.Fatal(err)
	}
	storedAt := now.Add(2 * time.Second)
	next, err := kernel.RecordImportBatch(
		claimed, claimed.Revision(), fence, []kernel.ImportRowResult{intended}, storedAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	receipt := RowReceipt{
		Result: intended, Command: command,
		Record: Record{Job: next, RequestedAudit: record.RequestedAudit}, Replayed: true,
	}
	validated, err := validateReceipt(
		record, row, intended, command, receipt, importUUID(1), importUUID(20), fence,
		now.Add(3*time.Second),
	)
	if err != nil || !kernel.SameImportJob(validated.Job, next) {
		t.Fatalf("validated=%#v err=%v", validated, err)
	}
	receipt.Replayed = false
	if _, err := validateReceipt(
		record, row, intended, command, receipt, importUUID(1), importUUID(20), fence,
		now.Add(3*time.Second),
	); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("non-replay timestamp mismatch error = %v", err)
	}
}

func TestWorkerAcceptsFailClosedDryRunPersistenceRaces(t *testing.T) {
	for _, outcome := range []kernel.ImportRowOutcome{
		kernel.ImportRowDefinitionChanged,
		kernel.ImportRowVersionConflict,
		kernel.ImportRowNotFoundOrHidden,
		kernel.ImportRowAuthorizationDenied,
	} {
		t.Run(outcome.String(), func(t *testing.T) {
			now := time.Date(2026, 9, 3, 13, 15, 0, 0, time.UTC)
			repository := newWorkerRepository(t, importWorkerRecord(t, kernel.ImportDryRun, now))
			repository.rowRaceOutcome = outcome
			worker, _ := NewWorker(repository)
			fence := mustImportEntity(t, importUUID(32))
			claimed, err := worker.Claim(
				context.Background(), importUUID(1), importUUID(20), 1, fence,
				now.Add(time.Second), now.Add(time.Minute),
			)
			if err != nil {
				t.Fatal(err)
			}
			completed, err := worker.ProcessBatch(
				context.Background(), importUUID(1), importUUID(20), fence, 1,
				now.Add(2*time.Second),
			)
			if err != nil || completed.Job.State() != kernel.ImportJobCompleted ||
				completed.Job.Progress().Count(outcome) != 1 || repository.mutations != 0 {
				t.Fatalf("outcome=%s record=%#v mutations=%d err=%v", outcome, completed, repository.mutations, err)
			}
			if claimed.Job.Revision()+1 != completed.Job.Revision() {
				t.Fatalf("revision=%d want=%d", completed.Job.Revision(), claimed.Job.Revision()+1)
			}
		})
	}
}

func TestPersistenceRaceOutcomeMatrixIsFailClosed(t *testing.T) {
	sources := []struct {
		mode    kernel.ImportMode
		outcome kernel.ImportRowOutcome
	}{
		{kernel.ImportCommit, kernel.ImportRowCommitted},
		{kernel.ImportDryRun, kernel.ImportRowDryRunValid},
		{kernel.ImportCommit, kernel.ImportRowNoChange},
		{kernel.ImportCommit, kernel.ImportRowValidationFailed},
	}
	targets := []kernel.ImportRowOutcome{
		kernel.ImportRowDefinitionChanged,
		kernel.ImportRowVersionConflict,
		kernel.ImportRowNotFoundOrHidden,
		kernel.ImportRowAuthorizationDenied,
	}
	for _, source := range sources {
		for _, target := range targets {
			if !allowedPersistenceRaceOutcome(source.mode, source.outcome, target) {
				t.Fatalf("rejected fail-closed transition %s -> %s", source.outcome, target)
			}
		}
	}
	for _, transition := range []struct {
		mode     kernel.ImportMode
		intended kernel.ImportRowOutcome
		actual   kernel.ImportRowOutcome
	}{
		{kernel.ImportDryRun, kernel.ImportRowDryRunValid, kernel.ImportRowNoChange},
		{kernel.ImportCommit, kernel.ImportRowValidationFailed, kernel.ImportRowCommitted},
		{kernel.ImportCommit, kernel.ImportRowAuthorizationDenied, kernel.ImportRowVersionConflict},
		{kernel.ImportDryRun, kernel.ImportRowCommitted, kernel.ImportRowVersionConflict},
	} {
		if allowedPersistenceRaceOutcome(transition.mode, transition.intended, transition.actual) {
			t.Fatalf("accepted unsafe transition %s -> %s", transition.intended, transition.actual)
		}
	}
	if !allowedPersistenceRaceOutcome(
		kernel.ImportCommit, kernel.ImportRowCommitted, kernel.ImportRowNoChange,
	) {
		t.Fatal("commit convergence to no_change was rejected")
	}
}

func TestWorkerTerminalizesLiveAuthorizationRevocationRace(t *testing.T) {
	now := time.Date(2026, 9, 3, 13, 20, 0, 0, time.UTC)
	repository := newWorkerRepository(t, importWorkerRecord(t, kernel.ImportDryRun, now))
	repository.authorizationRevokedOnCommit = true
	worker, _ := NewWorker(repository)
	fence := mustImportEntity(t, importUUID(33))
	_, err := worker.Claim(
		context.Background(), importUUID(1), importUUID(20), 1, fence,
		now.Add(time.Second), now.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	terminal, err := worker.ProcessBatch(
		context.Background(), importUUID(1), importUUID(20), fence, 1,
		now.Add(2*time.Second),
	)
	if err != nil || terminal.Job.State() != kernel.ImportJobAuthorizationRevoked ||
		terminal.Job.Progress().AuthorizationRevoked != 1 || repository.mutations != 0 ||
		len(repository.receipts) != 0 {
		t.Fatalf("terminal=%#v mutations=%d receipts=%d err=%v", terminal, repository.mutations, len(repository.receipts), err)
	}
}

func TestWorkerAtomicRowProgressPreventsCancellationFromHidingMutation(t *testing.T) {
	now := time.Date(2026, 9, 3, 13, 30, 0, 0, time.UTC)
	repository := newWorkerRepository(t, importWorkerRecord(t, kernel.ImportCommit, now))
	worker, _ := NewWorker(repository)
	fence := mustImportEntity(t, importUUID(31))
	claimed, err := worker.Claim(
		context.Background(), importUUID(1), importUUID(20), 1, fence,
		now.Add(time.Second), now.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	staleCancellation, err := kernel.RequestImportCancellation(
		claimed.Job, claimed.Job.Revision(), now.Add(1500*time.Millisecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	completed, err := worker.ProcessBatch(
		context.Background(), importUUID(1), importUUID(20), fence, 1, now.Add(2*time.Second),
	)
	if err != nil || completed.Job.State() != kernel.ImportJobCompleted || repository.mutations != 1 {
		t.Fatalf("completed=%#v mutations=%d err=%v", completed, repository.mutations, err)
	}
	if _, err := repository.CommitJob(context.Background(), JobWrite{
		Tenant: importUUID(1), JobID: importUUID(20), Kind: JobWriteControl,
		Current: claimed.Job, Next: staleCancellation, Fence: fence,
	}); !errors.Is(err, ErrRepositoryPrecondition) {
		t.Fatalf("stale cancellation CAS error = %v", err)
	}
	if repository.record.Job.State() != kernel.ImportJobCompleted ||
		repository.record.Job.Progress().Committed != 1 {
		t.Fatalf("stale cancellation replaced committed progress: %s", repository.record.Job)
	}
}

func TestWorkerClaimCASAllowsOneConcurrentFence(t *testing.T) {
	now := time.Date(2026, 9, 3, 14, 0, 0, 0, time.UTC)
	repository := newWorkerRepository(t, importWorkerRecord(t, kernel.ImportDryRun, now))
	worker, _ := NewWorker(repository)
	var succeeded atomic.Int32
	var wait sync.WaitGroup
	for index := 0; index < 32; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			fence := mustImportEntity(t, importUUID(byte(40+index)))
			if _, err := worker.Claim(
				context.Background(), importUUID(1), importUUID(20), 1, fence,
				now.Add(time.Second), now.Add(time.Minute),
			); err == nil {
				succeeded.Add(1)
			}
		}(index)
	}
	wait.Wait()
	if succeeded.Load() != 1 {
		t.Fatalf("successful claims = %d, want 1", succeeded.Load())
	}
}

func TestWorkerHeartbeatLeaseBoundaryFailureAndLateRecovery(t *testing.T) {
	now := time.Date(2026, 9, 3, 14, 30, 0, 0, time.UTC)
	repository := newWorkerRepository(t, importWorkerRecord(t, kernel.ImportCommit, now))
	worker, _ := NewWorker(repository)
	fence := mustImportEntity(t, importUUID(75))
	lease := now.Add(time.Minute)
	claimed, err := worker.Claim(
		context.Background(), importUUID(1), importUUID(20), 1, fence,
		now.Add(time.Second), lease,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := worker.Heartbeat(
		context.Background(), importUUID(1), importUUID(20), claimed.Job.Revision(),
		mustImportEntity(t, importUUID(76)), now.Add(2*time.Second), now.Add(2*time.Minute),
	); !errors.Is(err, ErrPreconditionFailed) {
		t.Fatalf("stale heartbeat fence error = %v", err)
	}
	if _, err := worker.ProcessBatch(
		context.Background(), importUUID(1), importUUID(20), fence, 1, lease,
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("lease boundary process error = %v", err)
	}
	extended, err := worker.Heartbeat(
		context.Background(), importUUID(1), importUUID(20), claimed.Job.Revision(), fence,
		now.Add(2*time.Second), now.Add(2*time.Minute),
	)
	if err != nil || !extended.Job.LeaseUntil().Equal(now.Add(2*time.Minute)) {
		t.Fatalf("extended=%#v err=%v", extended, err)
	}
	failed, err := worker.Fail(
		context.Background(), importUUID(1), importUUID(20), extended.Job.Revision(), fence,
		now.Add(3*time.Second),
	)
	if err != nil || failed.Job.State() != kernel.ImportJobFailed || failed.Job.Progress().InternalFailure != 1 {
		t.Fatalf("failed=%#v err=%v", failed, err)
	}

	pendingRepository := newWorkerRepository(t, importWorkerRecord(t, kernel.ImportDryRun, now))
	pendingWorker, _ := NewWorker(pendingRepository)
	expired, err := pendingWorker.RecoverExpired(
		context.Background(), importUUID(1), importUUID(20), 1,
		now.Add(time.Hour+time.Second),
	)
	if err != nil || expired.Job.State() != kernel.ImportJobExpired || expired.Job.Progress().Expired != 1 {
		t.Fatalf("late recovery=%#v err=%v", expired, err)
	}
}

func TestWorkerCompletesCancellationAndRedactsDiagnostics(t *testing.T) {
	now := time.Date(2026, 9, 3, 15, 0, 0, 0, time.UTC)
	repository := newWorkerRepository(t, importWorkerRecord(t, kernel.ImportCommit, now))
	worker, _ := NewWorker(repository)
	fence := mustImportEntity(t, importUUID(70))
	claimed, _ := worker.Claim(
		context.Background(), importUUID(1), importUUID(20), 1, fence,
		now.Add(time.Second), now.Add(time.Minute),
	)
	cancelling, err := kernel.RequestImportCancellation(
		claimed.Job, claimed.Job.Revision(), now.Add(2*time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	repository.record.Job = cancelling
	completed, err := worker.ProcessBatch(
		context.Background(), importUUID(1), importUUID(20), fence, 10, now.Add(3*time.Second),
	)
	if err != nil || completed.Job.State() != kernel.ImportJobCancelled ||
		completed.Job.Progress().Cancelled != 1 {
		t.Fatalf("cancelled=%#v err=%v", completed, err)
	}
	for _, diagnostic := range []string{
		repository.lastRowWrite.String(), repository.lastRowWrite.Command.String(),
		repository.snapshot.String(), repository.record.String(),
	} {
		if containsAny(diagnostic, "very-secret", "summary", importUUID(10).String()) {
			t.Fatalf("diagnostic leak: %s", diagnostic)
		}
	}
}

type requestRepository struct {
	mu              sync.Mutex
	allowed         bool
	definitions     []kernel.Definition
	record          *Record
	replayOverride  *Record
	storedCommand   CommandBinding
	lastCommand     CommandBinding
	definitionLoads atomic.Int32
	reservations    atomic.Int32
}

type concurrentRequestRepository struct {
	*requestRepository
	lookupEntered atomic.Int32
	lookupRelease chan struct{}
	closeLookup   sync.Once
	reserved      atomic.Int32
	effects       atomic.Int32
}

type cancellationRepository struct {
	*requestRepository
	current       Record
	cancelCommand CommandBinding
	cancelReceipt *Result
	effects       int
}

type concurrentCancellationRepository struct {
	*cancellationRepository
	lookupEntered atomic.Int32
	lookupRelease chan struct{}
	lookupOnce    sync.Once
	getEntered    atomic.Int32
	getRelease    chan struct{}
	getOnce       sync.Once
}

type lateCancellationReplayRepository struct {
	*cancellationRepository
	lookupCalls atomic.Int32
}

func (repository *lateCancellationReplayRepository) LookupReplay(
	ctx context.Context,
	query ReplayQuery,
) (Result, bool, error) {
	if repository.lookupCalls.Add(1) == 1 {
		return Result{}, false, nil
	}
	return repository.cancellationRepository.LookupReplay(ctx, query)
}

func (repository *concurrentCancellationRepository) LookupReplay(_ context.Context, _ ReplayQuery) (Result, bool, error) {
	if repository.lookupEntered.Add(1) == 2 {
		repository.lookupOnce.Do(func() { close(repository.lookupRelease) })
	}
	<-repository.lookupRelease
	return Result{}, false, nil
}

func (repository *concurrentCancellationRepository) Get(context.Context, Actor, uuid.UUID, uuid.UUID, Access) (Record, error) {
	repository.mu.Lock()
	current := repository.current
	repository.mu.Unlock()
	if repository.getEntered.Add(1) == 2 {
		repository.getOnce.Do(func() { close(repository.getRelease) })
	}
	<-repository.getRelease
	return current, nil
}

func (repository *cancellationRepository) LookupReplay(ctx context.Context, query ReplayQuery) (Result, bool, error) {
	if query.Command.Action != CommandCancel {
		return repository.requestRepository.LookupReplay(ctx, query)
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if repository.cancelReceipt == nil || repository.cancelCommand.KeyHash != query.Command.KeyHash {
		return Result{}, false, nil
	}
	if repository.cancelCommand.Fingerprint != query.Command.Fingerprint {
		return Result{}, false, ErrRepositoryConflict
	}
	result := *repository.cancelReceipt
	result.Replayed = true
	return result, true, nil
}

func (repository *cancellationRepository) Get(context.Context, Actor, uuid.UUID, uuid.UUID, Access) (Record, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	return repository.current, nil
}

func (repository *cancellationRepository) CommitCancellation(_ context.Context, write CancellationWrite) (Result, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if repository.cancelReceipt != nil {
		if repository.cancelCommand != write.Command {
			return Result{}, ErrRepositoryConflict
		}
		result := *repository.cancelReceipt
		result.Replayed = true
		return result, nil
	}
	if !kernel.SameImportJob(repository.current.Job, write.Current) {
		return Result{}, ErrRepositoryPrecondition
	}
	repository.current.Job = write.Next
	result := Result{Record: repository.current}
	repository.cancelCommand, repository.cancelReceipt = write.Command, &result
	repository.effects++
	return result, nil
}

func (repository *concurrentRequestRepository) LookupReplay(_ context.Context, _ ReplayQuery) (Result, bool, error) {
	if repository.lookupEntered.Add(1) == 2 {
		repository.closeLookup.Do(func() { close(repository.lookupRelease) })
	}
	<-repository.lookupRelease
	return Result{}, false, nil
}

func (repository *concurrentRequestRepository) ReserveImportID(context.Context, uuid.UUID) (kernel.EntityID, error) {
	sequence := repository.reserved.Add(1)
	return mustImportEntity(nil, importUUID(byte(20+sequence))), nil
}

func (repository *concurrentRequestRepository) CommitRequest(ctx context.Context, write RequestWrite) (Result, error) {
	result, err := repository.requestRepository.CommitRequest(ctx, write)
	if err == nil && !result.Replayed {
		repository.effects.Add(1)
	}
	return result, err
}

func newRequestRepository(t *testing.T, definitions ...kernel.Definition) *requestRepository {
	t.Helper()
	return &requestRepository{allowed: true, definitions: definitions}
}

func (repository *requestRepository) ResolveAccess(_ context.Context, actor Actor, tenant uuid.UUID, objectType kernel.ObjectType, capability Capability) (Access, error) {
	return NewAccess(tenant, actor.UserID, actor.MembershipID, objectType, capability, customapp.ScopeTenant, repository.allowed)
}

func (repository *requestRepository) LoadDefinitions(_ context.Context, _ Actor, _ uuid.UUID, _ kernel.ObjectType, _ Access) ([]kernel.Definition, error) {
	repository.definitionLoads.Add(1)
	return append([]kernel.Definition(nil), repository.definitions...), nil
}

func (repository *requestRepository) ReserveImportID(context.Context, uuid.UUID) (kernel.EntityID, error) {
	repository.reservations.Add(1)
	return mustImportEntity(nil, importUUID(20)), nil
}

func (repository *requestRepository) LookupReplay(_ context.Context, query ReplayQuery) (Result, bool, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.lastCommand = query.Command
	if repository.replayOverride != nil {
		return Result{Record: *repository.replayOverride, Replayed: true}, true, nil
	}
	if repository.record == nil || repository.storedCommand.Action != query.Command.Action ||
		repository.storedCommand.KeyHash != query.Command.KeyHash {
		return Result{}, false, nil
	}
	if repository.storedCommand.Fingerprint != query.Command.Fingerprint {
		return Result{}, false, ErrRepositoryConflict
	}
	return Result{Record: *repository.record, Replayed: true}, true, nil
}

func (repository *requestRepository) CommitRequest(_ context.Context, write RequestWrite) (Result, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.lastCommand = write.Command
	if repository.record != nil {
		if repository.storedCommand.KeyHash == write.Command.KeyHash && repository.storedCommand.Fingerprint == write.Command.Fingerprint {
			return Result{Record: *repository.record, Replayed: true}, nil
		}
		return Result{}, ErrRepositoryConflict
	}
	record := Record{Job: write.Job, RequestedAudit: write.Audit}
	repository.record, repository.storedCommand = &record, write.Command
	return Result{Record: record}, nil
}

func (repository *requestRepository) Get(_ context.Context, _ Actor, _ uuid.UUID, _ uuid.UUID, _ Access) (Record, error) {
	if repository.record == nil {
		return Record{}, ErrRepositoryNotFound
	}
	return *repository.record, nil
}

func (repository *requestRepository) ListResults(
	context.Context, Actor, uuid.UUID, uuid.UUID, Access, uint32, int,
) (ResultPage, error) {
	return ResultPage{Items: []RowResult{}}, nil
}

func (repository *requestRepository) CommitCancellation(_ context.Context, write CancellationWrite) (Result, error) {
	record := Record{Job: write.Next, RequestedAudit: repository.record.RequestedAudit}
	repository.record = &record
	return Result{Record: record}, nil
}

func (repository *requestRepository) resetStored() {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.record = nil
	repository.storedCommand = CommandBinding{}
}

type workerRepository struct {
	mu                           sync.Mutex
	record                       Record
	snapshot                     RowSnapshot
	receipts                     map[uint32]RowReceipt
	commands                     map[uint32]RowCommandBinding
	currentVersion               uint64
	mutations                    int
	failRowResponseOnce          bool
	rowRaceOutcome               kernel.ImportRowOutcome
	authorizationRevokedOnCommit bool
	lastRowWrite                 RowWrite
}

func newWorkerRepository(t *testing.T, record Record) *workerRepository {
	t.Helper()
	manifest := record.Job.Manifest()
	row := manifest.Rows()[0]
	access, err := NewRowAccess(
		importUUID(1), importUUID(2), importUUID(3), manifest.ObjectType(),
		uuidFromEntity(row.Target()), customapp.ScopeTenant, true,
	)
	if err != nil {
		t.Fatal(err)
	}
	return &workerRepository{
		record: record, currentVersion: row.ExpectedVersion(),
		snapshot: RowSnapshot{
			Access: access, FoundAndVisible: true, CurrentVersion: row.ExpectedVersion(),
			Definitions: manifest.Definitions(),
		},
		receipts: make(map[uint32]RowReceipt), commands: make(map[uint32]RowCommandBinding),
	}
}

func (repository *workerRepository) LoadForClaim(context.Context, uuid.UUID, uuid.UUID) (Record, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	return repository.record, nil
}

func (repository *workerRepository) LoadClaimed(_ context.Context, _ uuid.UUID, _ uuid.UUID, fence kernel.EntityID) (Record, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if repository.record.Job.Fence() == nil || *repository.record.Job.Fence() != fence {
		return Record{}, ErrRepositoryPrecondition
	}
	return repository.record, nil
}

func (repository *workerRepository) CommitJob(_ context.Context, write JobWrite) (Record, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if !kernel.SameImportJob(repository.record.Job, write.Current) {
		return Record{}, ErrRepositoryPrecondition
	}
	repository.record.Job = write.Next
	return repository.record, nil
}

func (repository *workerRepository) LoadRow(_ context.Context, _ Record, row kernel.ImportRow, _ kernel.EntityID) (RowSnapshot, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	result := repository.snapshot
	result.CurrentVersion = repository.currentVersion
	return result, nil
}

func (repository *workerRepository) CommitRow(_ context.Context, write RowWrite) (RowReceipt, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.lastRowWrite = write
	if repository.authorizationRevokedOnCommit {
		return RowReceipt{}, ErrRepositoryAuthorizationRevoked
	}
	sequence := write.Row.Sequence()
	if receipt, exists := repository.receipts[sequence]; exists {
		if repository.commands[sequence] != write.Command {
			return RowReceipt{}, ErrRepositoryConflict
		}
		receipt.Replayed = true
		return receipt, nil
	}
	if !kernel.SameImportJob(repository.record.Job, write.Current) ||
		repository.record.Job.Revision() != write.JobRevision {
		return RowReceipt{}, ErrRepositoryPrecondition
	}
	result := write.Intended
	if repository.rowRaceOutcome != 0 {
		result, _ = kernel.NewImportRowResult(sequence, repository.rowRaceOutcome, 0, nil)
	} else if write.Intended.Outcome() == kernel.ImportRowCommitted {
		if repository.currentVersion != write.Row.ExpectedVersion() {
			result, _ = kernel.NewImportRowResult(sequence, kernel.ImportRowVersionConflict, 0, nil)
		} else {
			repository.currentVersion++
			repository.mutations++
		}
	}
	next, err := kernel.RecordImportBatch(
		repository.record.Job, write.JobRevision, write.Fence,
		[]kernel.ImportRowResult{result}, write.RecordedAt,
	)
	if err != nil {
		return RowReceipt{}, ErrRepositoryPrecondition
	}
	repository.record.Job = next
	receipt := RowReceipt{Result: result, Command: write.Command, Record: repository.record}
	repository.receipts[sequence], repository.commands[sequence] = receipt, write.Command
	if repository.failRowResponseOnce {
		repository.failRowResponseOnce = false
		return RowReceipt{}, errors.New("injected storage failure with very-secret details")
	}
	return receipt, nil
}

func importWorkerRecord(t *testing.T, mode kernel.ImportMode, now time.Time) Record {
	t.Helper()
	definition := importDefinition(t, "summary", "Summary")
	manifest, err := kernel.NewImportManifest(kernel.ImportManifestInput{
		ID: mustImportEntity(t, importUUID(20)), Tenant: mustImportEntity(t, importUUID(1)),
		Requester: mustImportEntity(t, importUUID(2)), OwnerMembership: mustImportEntity(t, importUUID(3)),
		ObjectType: kernel.ObjectAlert, Mode: mode, Definitions: []kernel.Definition{definition},
		Rows: []kernel.ImportRowInput{{
			Sequence: 1, Target: mustImportEntity(t, importUUID(10)), ExpectedVersion: 10,
			Fields: []kernel.FieldInput{{
				Key: definition.Key(), Value: kernel.JSONInputValue(json.RawMessage(`"very-secret"`)),
			}},
		}},
		ProjectionVersion: kernel.ImportProjectionVersion, MaximumAttempts: kernel.ImportMaximumAttempts,
	})
	if err != nil {
		t.Fatal(err)
	}
	job, err := kernel.NewImportJob(manifest, now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	_, audit := importActorAndAudit()
	return Record{Job: job, RequestedAudit: audit}
}

func importDefinition(t *testing.T, keyValue, label string) kernel.Definition {
	t.Helper()
	key, err := kernel.NewKey(keyValue)
	if err != nil {
		t.Fatal(err)
	}
	definition, err := kernel.NewDefinition(kernel.DefinitionInput{
		ID: mustImportEntity(t, importUUID(90)), TenantID: mustImportEntity(t, importUUID(1)),
		ObjectType: kernel.ObjectAlert, Key: key, Label: label, DataType: kernel.TypeShortText,
		Nullable: true, Visibility: kernel.Visibility{Operator: true},
		EditPolicy: kernel.EditPolicy{OperatorCreate: true, OperatorUpdate: true},
		Placement:  kernel.Placement{ShowInDetail: true}, SchemaVersion: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	return definition
}

func mustImportKey(t *testing.T, value string) kernel.Key {
	t.Helper()
	key, err := kernel.NewKey(value)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func importActorAndAudit() (Actor, AuditContext) {
	audit := AuditContext{
		RequestID: importUUID(4), CorrelationID: importUUID(5),
		IPAddress: netip.MustParseAddr("192.0.2.10"), UserAgent: "test-agent",
		AuthenticationMethod: "oidc",
	}
	return Actor{
		TenantID: importUUID(1), ActiveTenantID: importUUID(1), UserID: importUUID(2),
		SessionID: importUUID(6), MembershipID: importUUID(3), AuthenticationMethod: "oidc",
		Kind: customapp.PrincipalHuman, Audit: audit,
	}, audit
}

func importUUID(sequence byte) uuid.UUID {
	value := [16]byte{0x01, 0x9d, 0x00, 0x00, 0x00, sequence, 0x70, sequence, 0x80}
	return uuid.UUID(value)
}

func mustImportEntity(t *testing.T, id uuid.UUID) kernel.EntityID {
	if t != nil {
		t.Helper()
	}
	entity, err := kernel.ParseEntityID(id.String())
	if err != nil {
		if t == nil {
			panic(err)
		}
		t.Fatal(err)
	}
	return entity
}

func containsAny(value string, needles ...string) bool {
	for _, needle := range needles {
		if needle != "" && strings.Contains(value, needle) {
			return true
		}
	}
	return false
}
