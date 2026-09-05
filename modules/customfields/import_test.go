package customfields

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestImportManifestCanonicalPinsAndPresence(t *testing.T) {
	textDefinition := validDefinitionInput(TypeShortText)
	textDefinition.ID = fixtureID(30)
	textDefinition.Key = mustKey("summary")
	textDefinition.Nullable = true
	text := mustDefinition(t, textDefinition)

	unreferencedInput := validDefinitionInput(TypeBoolean)
	unreferencedInput.ID = fixtureID(31)
	unreferencedInput.Key = mustKey("unreferenced")
	unreferenced := mustDefinition(t, unreferencedInput)

	raw := json.RawMessage(` "alpha" `)
	manifest := mustImportManifest(t, ImportCommit, []Definition{unreferenced, text}, []ImportRowInput{{
		Sequence: 1, Target: fixtureID(40), ExpectedVersion: 7,
		Fields: []FieldInput{
			{Key: mustKey("summary"), Value: JSONInputValue(raw)},
			{Key: mustKey("unknown_key"), Value: MissingInputValue()},
		},
	}})
	raw[2] = 'X'

	if pins := manifest.DefinitionPins(); len(pins) != 1 || pins[0].Key() != mustKey("summary") ||
		pins[0].SchemaVersion() != 1 {
		t.Fatalf("pins = %#v", pins)
	}
	cells := manifest.Rows()[0].Cells()
	if cells[0].Key() != mustKey("summary") || cells[0].Presence() != PresencePresent ||
		string(cells[0].InputValue().RawJSON()) != `"alpha"` ||
		cells[1].Presence() != PresenceMissing || cells[1].InputValue().Provided() {
		t.Fatalf("canonical cells = %#v", cells)
	}

	reordered := mustImportManifestWithID(t, fixtureID(91), ImportCommit, []Definition{text, unreferenced}, []ImportRowInput{{
		Sequence: 1, Target: fixtureID(40), ExpectedVersion: 7,
		Fields: []FieldInput{
			{Key: mustKey("unknown_key"), Value: MissingInputValue()},
			{Key: mustKey("summary"), Value: JSONInputValue(json.RawMessage(`"alpha"`))},
		},
	}})
	if !SameImportRequest(manifest, reordered) {
		t.Fatal("canonical reorder did not preserve request digest")
	}

	nullManifest := mustImportManifestWithID(t, fixtureID(92), ImportCommit, []Definition{text}, []ImportRowInput{{
		Sequence: 1, Target: fixtureID(40), ExpectedVersion: 7,
		Fields: []FieldInput{{Key: mustKey("summary"), Value: NullInputValue()}},
	}})
	emptyManifest := mustImportManifestWithID(t, fixtureID(93), ImportCommit, []Definition{text}, []ImportRowInput{{
		Sequence: 1, Target: fixtureID(40), ExpectedVersion: 7,
		Fields: []FieldInput{{Key: mustKey("summary"), Value: JSONInputValue(json.RawMessage(`""`))}},
	}})
	missingManifest := mustImportManifestWithID(t, fixtureID(94), ImportCommit, []Definition{text}, []ImportRowInput{{
		Sequence: 1, Target: fixtureID(40), ExpectedVersion: 7,
		Fields: []FieldInput{{Key: mustKey("summary"), Value: MissingInputValue()}},
	}})
	if SameImportRequest(nullManifest, emptyManifest) || SameImportRequest(nullManifest, missingManifest) ||
		SameImportRequest(emptyManifest, missingManifest) {
		t.Fatal("missing, null, and empty must have distinct replay fingerprints")
	}

	changedInput := textDefinition
	changedInput.Label = "Changed label"
	changed := mustDefinition(t, changedInput)
	if !errors.Is(MatchImportDefinitionPins(manifest, []Definition{changed}), ErrImportDefinitionConflict) {
		t.Fatal("same-version definition drift was accepted")
	}
	if err := MatchImportDefinitionPins(manifest, []Definition{text}); err != nil {
		t.Fatalf("matching pins error = %v", err)
	}
}

func TestImportManifestSupportsCaseTargets(t *testing.T) {
	definitionInput := validDefinitionInput(TypeShortText)
	definitionInput.ID = fixtureID(34)
	definitionInput.ObjectType = ObjectCase
	definitionInput.Key = mustKey("case_summary")
	definition := mustDefinition(t, definitionInput)
	manifest, err := NewImportManifest(ImportManifestInput{
		ID: fixtureID(90), Tenant: fixtureID(1), Requester: fixtureID(2),
		OwnerMembership: fixtureID(3), ObjectType: ObjectCase, Mode: ImportDryRun,
		Definitions: []Definition{definition}, Rows: []ImportRowInput{{
			Sequence: 1, Target: fixtureID(43), ExpectedVersion: 1,
			Fields: []FieldInput{{
				Key: definition.Key(), Value: JSONInputValue(json.RawMessage(`"case"`)),
			}},
		}},
		ProjectionVersion: ImportProjectionVersion, MaximumAttempts: ImportMaximumAttempts,
	})
	if err != nil || manifest.ObjectType() != ObjectCase || len(manifest.DefinitionPins()) != 1 {
		t.Fatalf("case manifest=%#v err=%v", manifest, err)
	}
}

func TestImportManifestPreservesZeroCellNoChangeRows(t *testing.T) {
	manifest := mustImportManifest(t, ImportCommit, nil, []ImportRowInput{{
		Sequence: 1, Target: fixtureID(40), ExpectedVersion: 7,
	}})
	rows := manifest.Rows()
	if len(rows) != 1 || len(rows[0].Cells()) != 0 {
		t.Fatalf("rows = %#v", rows)
	}
	_, fieldErrors, err := ValidateImportPatch(manifest, rows[0], nil)
	if err != nil || len(fieldErrors) != 0 {
		t.Fatalf("no-change validation errors=%#v err=%v", fieldErrors, err)
	}
}

func TestImportDefinitionPinMatchesPostgreSQLProjectionContract(t *testing.T) {
	tenant, err := ParseEntityID("01993ea0-0000-7000-8000-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	id, err := ParseEntityID("01993ea0-0000-7000-8000-000000000801")
	if err != nil {
		t.Fatal(err)
	}
	minimum, maximum := uint32(1), uint32(120)
	definition, err := NewDefinition(DefinitionInput{
		ID: id, TenantID: tenant, ObjectType: ObjectCase,
		Key: mustKey("demo_affected_service"), Label: "Affected service",
		Description: "Synthetic service label used by the complete demo Case.",
		DataType:    TypeShortText, Constraints: ConstraintsInput{
			MinimumLength: &minimum, MaximumLength: &maximum,
		},
		Visibility: Visibility{Operator: true},
		EditPolicy: EditPolicy{OperatorCreate: true, OperatorUpdate: true},
		Placement: Placement{
			ShowInCreate: true, ShowInDetail: true, ShowInList: true, ShowInExport: true,
		},
		Searchable: true, Filterable: true, Sortable: true, SchemaVersion: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	pin := importDefinitionPin(definition).Fingerprint()
	if got, want := hex.EncodeToString(pin[:]), "8fe843f7ab8da275a2019672975ceb363ca3a177e99c4c3e425ebceb14a74f06"; got != want {
		t.Fatalf("pin = %s, want %s", got, want)
	}
}

func TestImportManifestBoundsAggregateCellsAndDefersTypedJSONErrors(t *testing.T) {
	integerInput := validDefinitionInput(TypeInteger)
	integerInput.ID = fixtureID(32)
	integerInput.Key = mustKey("count")
	integerDefinition := mustDefinition(t, integerInput)
	manifest := mustImportManifest(t, ImportDryRun, []Definition{integerDefinition}, []ImportRowInput{{
		Sequence: 1, Target: fixtureID(41), ExpectedVersion: 1,
		Fields: []FieldInput{{Key: integerDefinition.Key(), Value: JSONInputValue(json.RawMessage(`1e3`))}},
	}})
	_, fieldErrors, err := ValidateImportPatch(manifest, manifest.Rows()[0], nil)
	if err != nil || len(fieldErrors) != 1 || fieldErrors[0].Code != "invalid_integer" {
		t.Fatalf("typed exponent validation errors=%#v err=%v", fieldErrors, err)
	}

	fields := make([]FieldInput, ImportMaximumFieldsPerRow)
	for index := range fields {
		fields[index] = FieldInput{Key: mustKey(fmt.Sprintf("field_%03d", index)), Value: MissingInputValue()}
	}
	rowCount := ImportMaximumCells/ImportMaximumFieldsPerRow + 1
	rows := make([]ImportRowInput, rowCount)
	for index := range rows {
		rows[index] = ImportRowInput{
			Sequence: uint32(index + 1), Target: fixtureLargeID(index + 1),
			ExpectedVersion: 1, Fields: fields,
		}
	}
	_, err = NewImportManifest(ImportManifestInput{
		ID: fixtureID(90), Tenant: fixtureID(1), Requester: fixtureID(2), OwnerMembership: fixtureID(3),
		ObjectType: ObjectAlert, Mode: ImportDryRun, Rows: rows,
		ProjectionVersion: ImportProjectionVersion, MaximumAttempts: ImportMaximumAttempts,
	})
	if !errors.Is(err, ErrInvalidImportManifest) {
		t.Fatalf("aggregate cell overflow error = %v", err)
	}

	patternInput := validDefinitionInput(TypeShortText)
	patternInput.ID = fixtureID(33)
	patternInput.Key = mustKey("patterned")
	patternInput.Constraints.Pattern = `^ok$`
	corrupt := mustDefinition(t, patternInput)
	corrupt.constraints.compiled = nil
	_, err = NewImportManifest(ImportManifestInput{
		ID: fixtureID(90), Tenant: fixtureID(1), Requester: fixtureID(2), OwnerMembership: fixtureID(3),
		ObjectType: ObjectAlert, Mode: ImportDryRun, Definitions: []Definition{corrupt},
		Rows: []ImportRowInput{{
			Sequence: 1, Target: fixtureID(42), ExpectedVersion: 1,
			Fields: []FieldInput{{Key: corrupt.Key(), Value: JSONInputValue(json.RawMessage(`"ok"`))}},
		}},
		ProjectionVersion: ImportProjectionVersion, MaximumAttempts: ImportMaximumAttempts,
	})
	if !errors.Is(err, ErrInvalidImportManifest) {
		t.Fatalf("corrupt definition snapshot error = %v", err)
	}

	whitespacePadded := json.RawMessage(" \t\r\n1 \t\r\n")
	_, measuredBytes, err := canonicalImportCell(FieldInput{
		Key: mustKey("count"), Value: JSONInputValue(whitespacePadded),
	})
	if err != nil || measuredBytes != len(whitespacePadded) {
		t.Fatalf("payload measurement=%d want=%d err=%v", measuredBytes, len(whitespacePadded), err)
	}
}

func TestValidateImportPatchDistinguishesMissingNullEmptyAndPolicies(t *testing.T) {
	editableInput := validDefinitionInput(TypeShortText)
	editableInput.ID = fixtureID(50)
	editableInput.Key = mustKey("editable")
	editableInput.Nullable = true
	editable := mustDefinition(t, editableInput)

	readOnlyInput := validDefinitionInput(TypeShortText)
	readOnlyInput.ID = fixtureID(51)
	readOnlyInput.Key = mustKey("read_only")
	readOnlyInput.EditPolicy.OperatorUpdate = false
	readOnly := mustDefinition(t, readOnlyInput)

	hiddenInput := validDefinitionInput(TypeShortText)
	hiddenInput.ID = fixtureID(52)
	hiddenInput.Key = mustKey("hidden")
	hiddenInput.Visibility.Operator = false
	hiddenInput.EditPolicy.OperatorCreate = false
	hiddenInput.EditPolicy.OperatorUpdate = false
	hidden := mustDefinition(t, hiddenInput)

	existing, err := RestoreFieldValue(editable, json.RawMessage(`"before"`))
	if err != nil {
		t.Fatal(err)
	}
	manifest := mustImportManifest(t, ImportCommit, []Definition{editable, readOnly, hidden}, []ImportRowInput{{
		Sequence: 1, Target: fixtureID(60), ExpectedVersion: 8,
		Fields: []FieldInput{
			{Key: editable.Key(), Value: MissingInputValue()},
			{Key: readOnly.Key(), Value: JSONInputValue(json.RawMessage(`"blocked"`))},
			{Key: hidden.Key(), Value: JSONInputValue(json.RawMessage(`"secret"`))},
			{Key: mustKey("unknown"), Value: JSONInputValue(json.RawMessage(`"value"`))},
		},
	}})
	patches, fieldErrors, err := ValidateImportPatch(manifest, manifest.Rows()[0], []FieldValue{existing})
	if err != nil || patches != nil || len(fieldErrors) != 3 {
		t.Fatalf("patches=%#v fieldErrors=%#v err=%v", patches, fieldErrors, err)
	}
	codes := map[string]string{}
	for _, fieldError := range fieldErrors {
		codes[fieldError.Field.String()] = fieldError.Code
	}
	if codes["read_only"] != "edit_denied" || codes["hidden"] != "visibility_denied" ||
		codes["unknown"] != "unknown" {
		t.Fatalf("codes = %#v", codes)
	}

	nullManifest := mustImportManifest(t, ImportCommit, []Definition{editable}, []ImportRowInput{{
		Sequence: 1, Target: fixtureID(61), ExpectedVersion: 9,
		Fields: []FieldInput{{Key: editable.Key(), Value: NullInputValue()}},
	}})
	patches, fieldErrors, err = ValidateImportPatch(nullManifest, nullManifest.Rows()[0], []FieldValue{existing})
	if err != nil || len(fieldErrors) != 0 || len(patches) != 1 ||
		patches[0].Value().Presence() != PresenceNull {
		t.Fatalf("null patch = %#v, errors=%#v, err=%v", patches, fieldErrors, err)
	}

	emptyManifest := mustImportManifest(t, ImportCommit, []Definition{editable}, []ImportRowInput{{
		Sequence: 1, Target: fixtureID(62), ExpectedVersion: 9,
		Fields: []FieldInput{{Key: editable.Key(), Value: JSONInputValue(json.RawMessage(`""`))}},
	}})
	patches, fieldErrors, err = ValidateImportPatch(emptyManifest, emptyManifest.Rows()[0], []FieldValue{existing})
	if err != nil || len(fieldErrors) != 0 || len(patches) != 1 ||
		patches[0].Value().Presence() != PresencePresent || string(patches[0].Value().CanonicalJSON()) != `""` {
		t.Fatalf("empty patch = %#v, errors=%#v, err=%v", patches, fieldErrors, err)
	}

	missingManifest := mustImportManifest(t, ImportCommit, []Definition{editable}, []ImportRowInput{{
		Sequence: 1, Target: fixtureID(63), ExpectedVersion: 9,
		Fields: []FieldInput{{Key: editable.Key(), Value: MissingInputValue()}},
	}})
	patches, fieldErrors, err = ValidateImportPatch(missingManifest, missingManifest.Rows()[0], []FieldValue{existing})
	if err != nil || len(fieldErrors) != 0 || len(patches) != 0 {
		t.Fatalf("missing patch = %#v, errors=%#v, err=%v", patches, fieldErrors, err)
	}
	if len(missingManifest.DefinitionPins()) != 0 || len(missingManifest.Definitions()) != 0 {
		t.Fatal("missing no-op unexpectedly pinned a definition")
	}

	unknownMissing := mustImportManifest(t, ImportCommit, nil, []ImportRowInput{{
		Sequence: 1, Target: fixtureID(64), ExpectedVersion: 9,
		Fields: []FieldInput{{Key: mustKey("not_defined"), Value: MissingInputValue()}},
	}})
	patches, fieldErrors, err = ValidateImportPatch(unknownMissing, unknownMissing.Rows()[0], nil)
	if err != nil || len(fieldErrors) != 0 || len(patches) != 0 {
		t.Fatalf("unknown missing patch = %#v, errors=%#v, err=%v", patches, fieldErrors, err)
	}
}

func TestImportRowResultRejectsUnregisteredErrorCodes(t *testing.T) {
	_, err := NewImportRowResult(1, ImportRowValidationFailed, 0, []FieldError{{
		Field: mustKey("editable"), Code: "secret_value",
	}})
	if !errors.Is(err, ErrInvalidImportRowResult) {
		t.Fatalf("unregistered code error = %v", err)
	}
	if _, err := NewImportRowResult(1, ImportRowCommitted, 0, nil); !errors.Is(err, ErrInvalidImportRowResult) {
		t.Fatalf("zero committed version error = %v", err)
	}
}

func TestImportJobFencingCASProgressAndCancellation(t *testing.T) {
	manifest := importJobManifest(t, ImportDryRun, 3)
	now := time.Date(2026, 9, 3, 10, 0, 0, 0, time.UTC)
	job, err := NewImportJob(manifest, now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	fence := fixtureID(70)
	job, err = ClaimImportJob(job, 1, fence, now.Add(time.Second), now.Add(time.Minute))
	if err != nil || job.State() != ImportJobRunning || job.Attempts() != 1 || len(job.NextRows(2)) != 2 {
		t.Fatalf("claimed job = %#v, err=%v", job, err)
	}
	valid, _ := NewImportRowResult(1, ImportRowDryRunValid, 10, nil)
	fieldFailure, _ := NewImportRowResult(2, ImportRowValidationFailed, 0, []FieldError{{
		Field: mustKey("editable"), Code: "invalid_text",
	}})
	if _, err := RecordImportBatch(job, job.Revision(), fixtureID(71), []ImportRowResult{valid}, now.Add(2*time.Second)); !errors.Is(err, ErrImportJobConflict) {
		t.Fatalf("stale fence error = %v", err)
	}
	job, err = RecordImportBatch(job, job.Revision(), fence, []ImportRowResult{valid, fieldFailure}, now.Add(2*time.Second))
	if err != nil || job.Progress().Processed() != 2 || job.Progress().ValidationFailed != 1 {
		t.Fatalf("partial job = %#v, err=%v", job, err)
	}
	noChange, _ := NewImportRowResult(3, ImportRowNoChange, 12, nil)
	job, err = RecordImportBatch(job, job.Revision(), fence, []ImportRowResult{noChange}, now.Add(3*time.Second))
	if err != nil || job.State() != ImportJobCompleted || !job.Progress().Complete() {
		t.Fatalf("completed job = %#v, err=%v", job, err)
	}

	cancelManifest := importJobManifest(t, ImportCommit, 3)
	cancelJob, _ := NewImportJob(cancelManifest, now, now.Add(time.Hour))
	cancelJob, _ = ClaimImportJob(cancelJob, 1, fence, now.Add(time.Second), now.Add(time.Minute))
	cancelJob, err = RequestImportCancellation(cancelJob, cancelJob.Revision(), now.Add(2*time.Second))
	if err != nil || cancelJob.State() != ImportJobCancellationRequested {
		t.Fatalf("cancel request = %#v, err=%v", cancelJob, err)
	}
	if _, err := HeartbeatImportJob(
		cancelJob, cancelJob.Revision(), fence, now.Add(2500*time.Millisecond), now.Add(2*time.Minute),
	); !errors.Is(err, ErrImportJobConflict) {
		t.Fatalf("cancellation heartbeat error = %v", err)
	}
	cancelJob, err = CompleteImportCancellation(
		cancelJob, cancelJob.Revision(), fence, now.Add(3*time.Second),
	)
	if err != nil || cancelJob.State() != ImportJobCancelled || cancelJob.Progress().Cancelled != 3 {
		t.Fatalf("cancelled job = %#v, err=%v", cancelJob, err)
	}
}

func TestImportJobHeartbeatCannotShortenLease(t *testing.T) {
	now := time.Date(2026, 9, 3, 10, 0, 0, 0, time.UTC)
	job, _ := NewImportJob(importJobManifest(t, ImportDryRun, 1), now, now.Add(time.Hour))
	fence := fixtureID(73)
	job, _ = ClaimImportJob(job, job.Revision(), fence, now.Add(time.Second), now.Add(2*time.Minute))
	for _, lease := range []time.Time{now.Add(90 * time.Second), now.Add(2 * time.Minute)} {
		if _, err := HeartbeatImportJob(
			job, job.Revision(), fence, now.Add(2*time.Second), lease,
		); !errors.Is(err, ErrImportJobConflict) {
			t.Fatalf("non-extending lease %s error = %v", lease, err)
		}
	}
}

func TestImportJobCancellationAtLeaseBoundaryCompetesWithReclaimCAS(t *testing.T) {
	now := time.Date(2026, 9, 3, 10, 0, 0, 0, time.UTC)
	job, _ := NewImportJob(importJobManifest(t, ImportCommit, 2), now, now.Add(time.Hour))
	leaseBoundary := now.Add(time.Minute)
	job, _ = ClaimImportJob(job, job.Revision(), fixtureID(74), now.Add(time.Second), leaseBoundary)

	direct, err := RequestImportCancellation(job, job.Revision(), leaseBoundary)
	if err != nil || direct.State() != ImportJobCancelled || direct.Progress().Cancelled != 2 ||
		direct.Fence() != nil || direct.LeaseUntil() != nil {
		t.Fatalf("boundary cancellation=%#v err=%v", direct, err)
	}

	store := &importCASStore{job: job}
	var successes atomic.Int32
	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		if store.claim(
			job.Revision(), fixtureID(75), leaseBoundary, leaseBoundary.Add(time.Minute),
		) {
			successes.Add(1)
		}
	}()
	go func() {
		defer wait.Done()
		if store.cancel(job.Revision(), leaseBoundary) {
			successes.Add(1)
		}
	}()
	wait.Wait()
	if successes.Load() != 1 {
		t.Fatalf("successful reclaim/cancel transitions = %d, want 1", successes.Load())
	}
	state := store.snapshot().State()
	if state != ImportJobRunning && state != ImportJobCancelled {
		t.Fatalf("winner state = %s", state)
	}
}

func TestImportJobRejectsControlResultsOutsideTransitionsAndRecoversLateExpiry(t *testing.T) {
	now := time.Date(2026, 9, 3, 10, 0, 0, 0, time.UTC)
	manifest := importJobManifest(t, ImportCommit, 2)
	job, _ := NewImportJob(manifest, now, now.Add(time.Hour))
	fence := fixtureID(72)
	job, _ = ClaimImportJob(job, 1, fence, now.Add(time.Second), now.Add(time.Minute))
	cancelled, _ := NewImportRowResult(1, ImportRowCancelled, 0, nil)
	if _, err := RecordImportBatch(job, job.Revision(), fence, []ImportRowResult{cancelled}, now.Add(2*time.Second)); !errors.Is(err, ErrInvalidImportRowResult) {
		t.Fatalf("control batch error = %v", err)
	}
	expired, err := ExpireImportJob(job, job.Revision(), job.ExpiresAt().Add(time.Second))
	if err != nil || expired.State() != ImportJobExpired || expired.Progress().Expired != 2 ||
		expired.TerminalAt() == nil || !expired.TerminalAt().After(expired.ExpiresAt()) {
		t.Fatalf("late expired job=%#v err=%v", expired, err)
	}

	pending, _ := NewImportJob(manifest, now, now.Add(time.Hour))
	pending, err = ExpireImportJob(pending, pending.Revision(), pending.ExpiresAt().Add(time.Second))
	if err != nil || pending.State() != ImportJobExpired || pending.Progress().Expired != 2 {
		t.Fatalf("pending expiry=%#v err=%v", pending, err)
	}
}

func TestRestoreImportJobValidatesEveryControlSuffixResult(t *testing.T) {
	now := time.Date(2026, 9, 3, 10, 0, 0, 0, time.UTC)
	manifest := importJobManifest(t, ImportCommit, 2)
	job, _ := NewImportJob(manifest, now, now.Add(time.Hour))
	first, _ := NewImportRowResult(1, ImportRowCancelled, 0, nil)
	second, _ := NewImportRowResult(2, ImportRowCancelled, 0, nil)
	second.resultingVersion = 99
	terminalAt := now.Add(time.Second)
	snapshot := job.Snapshot()
	snapshot.State = ImportJobCancelled
	snapshot.Revision++
	snapshot.Results = []ImportRowResult{first, second}
	snapshot.UpdatedAt = terminalAt
	snapshot.TerminalAt = &terminalAt
	if _, err := RestoreImportJob(snapshot); !errors.Is(err, ErrInvalidImportJob) {
		t.Fatalf("corrupt control suffix error = %v", err)
	}
	pending := job.Snapshot()
	pending.Revision = 2
	if _, err := RestoreImportJob(pending); !errors.Is(err, ErrInvalidImportJob) {
		t.Fatalf("unreachable pending revision error = %v", err)
	}
}

func TestImportJobConcurrentClaimAndBatchCAS(t *testing.T) {
	manifest := importJobManifest(t, ImportCommit, 1)
	now := time.Date(2026, 9, 3, 10, 0, 0, 0, time.UTC)
	initial, err := NewImportJob(manifest, now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	store := &importCASStore{job: initial}
	var claims atomic.Int32
	var wait sync.WaitGroup
	for worker := 0; worker < 32; worker++ {
		wait.Add(1)
		go func(worker int) {
			defer wait.Done()
			if store.claim(1, fixtureID(uint16(100+worker)), now.Add(time.Second), now.Add(time.Minute)) {
				claims.Add(1)
			}
		}(worker)
	}
	wait.Wait()
	if claims.Load() != 1 {
		t.Fatalf("successful claims = %d, want 1", claims.Load())
	}

	claimed := store.snapshot()
	fence := *claimed.Fence()
	committed, _ := NewImportRowResult(1, ImportRowCommitted, 11, nil)
	var commits atomic.Int32
	for worker := 0; worker < 32; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if store.record(claimed.Revision(), fence, committed, now.Add(2*time.Second)) {
				commits.Add(1)
			}
		}()
	}
	wait.Wait()
	if commits.Load() != 1 || store.snapshot().State() != ImportJobCompleted {
		t.Fatalf("successful batch commits = %d, job=%s", commits.Load(), store.snapshot())
	}
}

func TestImportDiagnosticsRedactTenantValuesAndTargets(t *testing.T) {
	secret := "raw-secret@example.invalid"
	definitionInput := validDefinitionInput(TypeShortText)
	definitionInput.ID = fixtureID(80)
	definitionInput.Key = mustKey("sensitive_field")
	definition := mustDefinition(t, definitionInput)
	manifest := mustImportManifest(t, ImportCommit, []Definition{definition}, []ImportRowInput{{
		Sequence: 1, Target: fixtureID(81), ExpectedVersion: 4,
		Fields: []FieldInput{{Key: definition.Key(), Value: JSONInputValue(json.RawMessage(`"` + secret + `"`))}},
	}})
	result, _ := NewImportRowResult(1, ImportRowValidationFailed, 0, []FieldError{{
		Field: definition.Key(), Code: "invalid_text",
	}})
	job, _ := NewImportJob(
		manifest, time.Date(2026, 9, 3, 10, 0, 0, 0, time.UTC),
		time.Date(2026, 9, 3, 11, 0, 0, 0, time.UTC),
	)
	for _, diagnostic := range []string{
		manifest.String(), manifest.Rows()[0].String(), manifest.Rows()[0].Cells()[0].String(),
		result.String(), job.String(),
	} {
		if strings.Contains(diagnostic, secret) || strings.Contains(diagnostic, "sensitive_field") ||
			strings.Contains(diagnostic, fixtureID(81).String()) {
			t.Fatalf("diagnostic leaked tenant data: %s", diagnostic)
		}
	}
}

type importCASStore struct {
	mu  sync.Mutex
	job ImportJob
}

func (store *importCASStore) claim(revision uint64, fence EntityID, now, lease time.Time) bool {
	store.mu.Lock()
	defer store.mu.Unlock()
	next, err := ClaimImportJob(store.job, revision, fence, now, lease)
	if err != nil {
		return false
	}
	store.job = next
	return true
}

func (store *importCASStore) record(revision uint64, fence EntityID, result ImportRowResult, now time.Time) bool {
	store.mu.Lock()
	defer store.mu.Unlock()
	next, err := RecordImportBatch(store.job, revision, fence, []ImportRowResult{result}, now)
	if err != nil {
		return false
	}
	store.job = next
	return true
}

func (store *importCASStore) cancel(revision uint64, now time.Time) bool {
	store.mu.Lock()
	defer store.mu.Unlock()
	next, err := RequestImportCancellation(store.job, revision, now)
	if err != nil {
		return false
	}
	store.job = next
	return true
}

func (store *importCASStore) snapshot() ImportJob {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.job
}

func importJobManifest(t *testing.T, mode ImportMode, rows int) ImportManifest {
	t.Helper()
	definitionInput := validDefinitionInput(TypeShortText)
	definitionInput.ID = fixtureID(95)
	definitionInput.Key = mustKey("editable")
	definition := mustDefinition(t, definitionInput)
	inputs := make([]ImportRowInput, rows)
	for index := range inputs {
		inputs[index] = ImportRowInput{
			Sequence: uint32(index + 1), Target: fixtureID(uint16(200 + index)),
			ExpectedVersion: uint64(10 + index),
			Fields: []FieldInput{{
				Key: definition.Key(), Value: JSONInputValue(json.RawMessage(`"value"`)),
			}},
		}
	}
	return mustImportManifest(t, mode, []Definition{definition}, inputs)
}

func mustImportManifest(
	t *testing.T,
	mode ImportMode,
	definitions []Definition,
	rows []ImportRowInput,
) ImportManifest {
	t.Helper()
	return mustImportManifestWithID(t, fixtureID(90), mode, definitions, rows)
}

func mustImportManifestWithID(
	t *testing.T,
	id EntityID,
	mode ImportMode,
	definitions []Definition,
	rows []ImportRowInput,
) ImportManifest {
	t.Helper()
	manifest, err := NewImportManifest(ImportManifestInput{
		ID: id, Tenant: fixtureID(1), Requester: fixtureID(2), OwnerMembership: fixtureID(3),
		ObjectType: ObjectAlert, Mode: mode, Definitions: definitions, Rows: rows,
		ProjectionVersion: ImportProjectionVersion, MaximumAttempts: ImportMaximumAttempts,
	})
	if err != nil {
		t.Fatalf("NewImportManifest() error = %v", err)
	}
	return manifest
}

func fixtureLargeID(sequence int) EntityID {
	value := [16]byte{0x01, 0x9d, 0, 0, 0, 0, 0x70, 0, 0x80}
	value[14], value[15] = byte(sequence>>8), byte(sequence)
	id, err := NewEntityID(value)
	if err != nil {
		panic(err)
	}
	return id
}
