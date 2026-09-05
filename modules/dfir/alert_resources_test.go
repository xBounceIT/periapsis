package dfir

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAlertEvidenceBindsRootAndPreservesImmutableCustodyHistory(t *testing.T) {
	t.Parallel()
	input := validAlertEvidenceInput()
	evidence, err := NewAlertEvidence(input)
	if err != nil {
		t.Fatal(err)
	}
	if evidence.AlertID() != input.AlertID || !evidence.VerifyCustodyChain() || evidence.Version() != 1 {
		t.Fatal("new Alert evidence lost its root or custody invariant")
	}
	updated, err := evidence.AppendCustodyEvent(1, CustodyEventInput{
		ID: fixtureID(604), ActorID: fixtureID(9), Action: CustodyAccessed,
		Reason: "forensic review", OccurredAt: input.CollectedAt.Add(time.Microsecond),
	})
	if err != nil || updated.Version() != 2 || len(updated.CustodyEvents()) != 2 || len(evidence.CustodyEvents()) != 1 {
		t.Fatalf("append custody = (%d, %d, %v)", updated.Version(), len(updated.CustodyEvents()), err)
	}
	state := updated.Snapshot()
	restored, err := RestoreAlertEvidence(state)
	if err != nil || !restored.VerifyCustodyChain() {
		t.Fatalf("restore Alert evidence = (%v, %v)", restored, err)
	}
	state.AlertID = fixtureID(605)
	if _, err := RestoreAlertEvidence(state); !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("root substitution error = %v, want invalid evidence", err)
	}
	if rendered := fmt.Sprintf("%#v %#v", updated, updated.Snapshot()); strings.Contains(rendered, input.Title) || strings.Contains(rendered, input.ContentSHA256) {
		t.Fatalf("Alert evidence formatting leaked protected data: %q", rendered)
	}
}

func TestEvidenceCustodyAnchorRejectsCrossKindTransplant(t *testing.T) {
	t.Parallel()
	alertInput := validAlertEvidenceInput()
	alertInput.ScanState = ScanAvailable
	alertEvidence, err := NewAlertEvidence(alertInput)
	if err != nil {
		t.Fatal(err)
	}
	if !alertEvidence.CanIssueDownload() {
		t.Fatal("valid available Alert evidence was not downloadable through its root-specific verifier")
	}
	alertAsCase := alertEvidence.evidence.Snapshot()
	if _, err := RestoreEvidence(alertAsCase); !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("Alert custody restored as Case evidence: %v", err)
	}
	if alertEvidence.evidence.VerifyCustodyChain() || alertEvidence.evidence.CanIssueDownload() {
		t.Fatal("Alert custody validated or downloaded through the Case evidence verifier")
	}

	caseEvidence := mustEvidence(t)
	caseAsAlertValue := AlertEvidence{alertID: caseEvidence.CaseID(), evidence: caseEvidence}
	if caseAsAlertValue.VerifyCustodyChain() {
		t.Fatal("Case custody validated through the Alert evidence verifier")
	}
	caseAsAlert := caseAsAlertValue.Snapshot()
	if _, err := RestoreAlertEvidence(caseAsAlert); !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("Case custody restored as Alert evidence: %v", err)
	}
	caseRoundTrip, err := RestoreEvidence(caseEvidence.Snapshot())
	if err != nil || !caseRoundTrip.VerifyCustodyChain() {
		t.Fatalf("legacy Case v1 custody no longer round-trips: %v", err)
	}
}

func TestAlertEvidenceRejectsUnsafeMetadataAndVersionOverflow(t *testing.T) {
	t.Parallel()
	for _, mutate := range []func(*AlertEvidenceInput){
		func(input *AlertEvidenceInput) { input.AlertID = EntityID{} },
		func(input *AlertEvidenceInput) { input.Title = "spoof\u202eexe" },
		func(input *AlertEvidenceInput) { input.Title = "split\u2028title" },
		func(input *AlertEvidenceInput) { input.Description = strings.Repeat("x", 16*1024+1) },
		func(input *AlertEvidenceInput) { input.ContentSHA256 = strings.Repeat("00", 31) },
		func(input *AlertEvidenceInput) { input.SizeBytes = maximumStorageObjectBytes + 1 },
	} {
		input := validAlertEvidenceInput()
		mutate(&input)
		if _, err := NewAlertEvidence(input); !errors.Is(err, ErrInvalidEvidence) {
			t.Fatalf("unsafe Alert evidence error = %v", err)
		}
	}
	evidence, err := NewAlertEvidence(validAlertEvidenceInput())
	if err != nil {
		t.Fatal(err)
	}
	state := evidence.Snapshot()
	state.Version = maximumAggregateVersion
	state.CustodyEvents = make([]CustodyEventState, 1)
	if _, err := RestoreAlertEvidence(state); !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("incoherent overflow state error = %v", err)
	}
}

func TestAlertTaskLifecycleAssignmentDueDateAndCAS(t *testing.T) {
	t.Parallel()
	state := validAlertTaskState()
	task, err := NewAlertTask(state)
	if err != nil {
		t.Fatal(err)
	}
	team, assignee := fixtureID(612), fixtureID(613)
	assigned, err := task.Assign(1, &team, &assignee, state.UpdatedAt.Add(time.Microsecond))
	if err != nil || assigned.Version() != 2 || assigned.AssigneeID() == nil || *assigned.AssigneeID() != assignee {
		t.Fatalf("assign = (%v, %v)", assigned, err)
	}
	due := state.UpdatedAt.Add(24 * time.Hour)
	scheduled, err := assigned.Reschedule(2, &due, state.UpdatedAt.Add(2*time.Microsecond))
	if err != nil || scheduled.Version() != 3 || scheduled.DueAt() == nil || !scheduled.DueAt().Equal(due) {
		t.Fatalf("reschedule = (%v, %v)", scheduled, err)
	}
	started, err := scheduled.Transition(TaskTransitionInput{
		ExpectedVersion: 3, Target: TaskInProgress, ActorID: assignee,
		OccurredAt: state.UpdatedAt.Add(3 * time.Microsecond), Reason: "investigation started",
	})
	if err != nil || started.Status() != TaskInProgress || started.Version() != 4 {
		t.Fatalf("transition = (%v, %v)", started, err)
	}
	if _, err := started.Reschedule(3, nil, state.UpdatedAt.Add(4*time.Microsecond)); !errors.Is(err, ErrTaskConflict) {
		t.Fatalf("stale reschedule error = %v", err)
	}
	if task.AssigneeID() != nil || task.DueAt() != nil || task.Version() != 1 {
		t.Fatal("Alert task mutation modified the original value")
	}

	overflowState := validAlertTaskState()
	overflowState.Version = MaximumAlertResourceVersion
	overflow, err := NewAlertTask(overflowState)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := overflow.Reschedule(MaximumAlertResourceVersion, &due, due); !errors.Is(err, ErrInvalidTask) {
		t.Fatalf("overflow reschedule error = %v", err)
	}
	overflowState.Version++
	if _, err := NewAlertTask(overflowState); !errors.Is(err, ErrInvalidTask) {
		t.Fatalf("non-JSON-safe task revision error = %v", err)
	}
}

func TestAlertTaskConcurrentValueMutationsAreRaceFreeAndIndependent(t *testing.T) {
	t.Parallel()
	task, err := NewAlertTask(validAlertTaskState())
	if err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	for index := 0; index < 64; index++ {
		wait.Add(1)
		go func(offset int) {
			defer wait.Done()
			due := task.UpdatedAt().Add(time.Duration(offset+1) * time.Hour)
			updated, updateErr := task.Reschedule(1, &due, task.UpdatedAt().Add(time.Duration(offset+1)*time.Microsecond))
			if updateErr != nil || updated.Version() != 2 || task.Version() != 1 {
				t.Errorf("concurrent reschedule = (%v, %v)", updated, updateErr)
			}
		}(index)
	}
	wait.Wait()
}

func TestAlertTaskTransitionIntentRejectsInvalidReplayPayloads(t *testing.T) {
	t.Parallel()
	for name, testCase := range map[string]struct {
		target         TaskStatus
		reason         string
		completionData json.RawMessage
	}{
		"unknown target": {
			target: "unknown", reason: "investigate",
		},
		"invalid UTF-8 reason": {
			target: TaskInProgress, reason: string([]byte{0xff}),
		},
		"Unicode line separator reason": {
			target: TaskInProgress, reason: "split\u2028reason",
		},
		"duplicate JSON key": {
			target: TaskDone, reason: "complete", completionData: json.RawMessage(`{"proof":1,"proof":2}`),
		},
		"invalid UTF-8 JSON": {
			target: TaskDone, reason: "complete",
			completionData: json.RawMessage{'{', '"', 'p', 'r', 'o', 'o', 'f', '"', ':', '"', 0xff, '"', '}'},
		},
		"oversized JSON": {
			target: TaskDone, reason: "complete",
			completionData: json.RawMessage(`{"proof":"` + strings.Repeat("x", maximumEnrichmentBytes) + `"}`),
		},
		"completion on non-terminal transition": {
			target: TaskInProgress, reason: "investigate", completionData: json.RawMessage(`{"ignored":true}`),
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := ValidateAlertTaskTransitionIntent(
				testCase.target, testCase.reason, testCase.completionData,
			); !errors.Is(err, ErrInvalidTask) {
				t.Fatalf("transition intent error = %v", err)
			}
		})
	}
	if err := ValidateAlertTaskTransitionIntent(
		TaskDone, "complete", json.RawMessage(`{"proof":{"digest":"sha256"}}`),
	); err != nil {
		t.Fatalf("valid transition intent error = %v", err)
	}

	taskState := validAlertTaskState()
	completedAt, completedBy := taskState.UpdatedAt, fixtureID(619)
	taskState.Status, taskState.CompletedAt, taskState.CompletedBy = TaskCancelled, &completedAt, &completedBy
	taskState.CompletionData = json.RawMessage{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'}
	if _, err := NewAlertTask(taskState); !errors.Is(err, ErrInvalidTask) {
		t.Fatalf("invalid UTF-8 restored completion data error = %v", err)
	}
	checklistItem, err := NewChecklistItem(ChecklistItemInput{
		ID: fixtureID(620), Title: "split\u2028checklist item",
	})
	if err != nil {
		t.Fatal(err)
	}
	taskState = validAlertTaskState()
	taskState.Checklist = []ChecklistItem{checklistItem}
	if _, err := NewAlertTask(taskState); !errors.Is(err, ErrInvalidTask) {
		t.Fatalf("line-breaking checklist title error = %v", err)
	}
}

func TestAlertTaskAndRelationshipStatesRedactProtectedContent(t *testing.T) {
	t.Parallel()
	taskState := validAlertTaskState()
	taskState.Title = "private task title"
	taskState.Description = "private task details"
	taskState.CompletionData = json.RawMessage(`{"secret":"task-secret"}`)
	taskRendered := fmt.Sprintf("%v %#v", taskState, taskState)
	for _, protected := range []string{
		taskState.Title, taskState.Description, "task-secret", taskState.ID.String(), taskState.AlertID.String(),
	} {
		if strings.Contains(taskRendered, protected) {
			t.Fatalf("Alert task state formatting leaked %q: %q", protected, taskRendered)
		}
	}

	tenant, alertID := fixtureID(1), fixtureID(640)
	alert, _ := NewEntityReference(tenant, EntityAlert, alertID)
	asset, _ := NewEntityReference(tenant, EntityAsset, fixtureID(641))
	relationshipState := AlertRelationshipState{
		ID: fixtureID(642), TenantID: tenant, AlertID: alertID, Source: alert, Target: asset,
		RelationshipType: "contains", Metadata: json.RawMessage(`{"secret":"relationship-secret"}`),
		CreatedBy: fixtureID(9), CreatedAt: testAlertResourceTime(), Version: 2,
		Retractions: []AlertRelationshipRetractionState{{
			ID: fixtureID(643), TenantID: tenant, RelationshipID: fixtureID(642), Sequence: 1,
			ActorID: fixtureID(9), Reason: "private retraction reason",
			OccurredAt: testAlertResourceTime().Add(time.Microsecond),
		}},
	}
	relationshipRendered := fmt.Sprintf(
		"%v %#v %v %#v", relationshipState, relationshipState,
		relationshipState.Retractions[0], relationshipState.Retractions[0],
	)
	for _, protected := range []string{
		"relationship-secret", relationshipState.Retractions[0].Reason,
		relationshipState.ID.String(), relationshipState.AlertID.String(),
	} {
		if strings.Contains(relationshipRendered, protected) {
			t.Fatalf("Alert relationship state formatting leaked %q: %q", protected, relationshipRendered)
		}
	}
}

func TestAlertRelationshipIsDirectionalAppendOnlyAndRetractable(t *testing.T) {
	t.Parallel()
	tenant, alertID := fixtureID(1), fixtureID(620)
	alert, _ := NewEntityReference(tenant, EntityAlert, alertID)
	asset, _ := NewEntityReference(tenant, EntityAsset, fixtureID(621))
	state := AlertRelationshipState{
		ID: fixtureID(622), TenantID: tenant, AlertID: alertID, Source: alert, Target: asset,
		RelationshipType: "contains", Metadata: json.RawMessage(`{"confidence":90}`),
		CreatedBy: fixtureID(9), CreatedAt: testAlertResourceTime(), Version: 1,
	}
	relationship, err := NewAlertRelationship(state)
	if err != nil || !relationship.Active() {
		t.Fatalf("new relationship = (%v, %v)", relationship, err)
	}
	reversed := state
	reversed.ID, reversed.Source, reversed.Target = fixtureID(623), asset, alert
	reverseRelationship, err := NewAlertRelationship(reversed)
	if err != nil || reverseRelationship.Source() != asset || reverseRelationship.Target() != alert {
		t.Fatalf("directional relationship = (%v, %v)", reverseRelationship, err)
	}

	retracted, err := relationship.Retract(1, AlertRelationshipRetractionInput{
		ID: fixtureID(624), ActorID: fixtureID(9), Reason: "superseded evidence",
		OccurredAt: state.CreatedAt.Add(time.Microsecond),
	})
	if err != nil || retracted.Active() || retracted.Version() != 2 || relationship.Version() != 1 {
		t.Fatalf("retract = (%v, %v)", retracted, err)
	}
	if _, err := relationship.Retract(2, AlertRelationshipRetractionInput{
		ID: fixtureID(625), ActorID: fixtureID(9), Reason: "stale",
		OccurredAt: state.CreatedAt.Add(time.Microsecond),
	}); !errors.Is(err, ErrRelationshipConflict) {
		t.Fatalf("stale retraction error = %v", err)
	}
	if _, err := retracted.Retract(2, AlertRelationshipRetractionInput{
		ID: fixtureID(625), ActorID: fixtureID(9), Reason: "second retraction",
		OccurredAt: state.CreatedAt.Add(2 * time.Microsecond),
	}); !errors.Is(err, ErrInvalidRelationship) {
		t.Fatalf("second retraction error = %v", err)
	}

	restoredState := retracted.Snapshot()
	restored, err := NewAlertRelationship(restoredState)
	if err != nil || restored.Active() || restored.Version() != 2 {
		t.Fatalf("restore relationship = (%v, %v)", restored, err)
	}
	restoredState.Retractions[0].Reason = "spoof\u2066text"
	if _, err := NewAlertRelationship(restoredState); !errors.Is(err, ErrInvalidRelationship) {
		t.Fatalf("unsafe retraction error = %v", err)
	}
	restoredState.Retractions[0].Reason = "split\u2029reason"
	if _, err := NewAlertRelationship(restoredState); !errors.Is(err, ErrInvalidRelationship) {
		t.Fatalf("line-breaking retraction error = %v", err)
	}
	if rendered := fmt.Sprintf("%#v", relationship); strings.Contains(rendered, "confidence") {
		t.Fatalf("relationship formatting leaked metadata: %q", rendered)
	}
}

func TestAlertRelationshipRequiresRootContextAndDoesNotCanonicalizeEndpoints(t *testing.T) {
	t.Parallel()
	tenant, alertID := fixtureID(1), fixtureID(630)
	caseReference, _ := NewEntityReference(tenant, EntityCase, fixtureID(631))
	asset, _ := NewEntityReference(tenant, EntityAsset, fixtureID(632))
	state := AlertRelationshipState{
		ID: fixtureID(633), TenantID: tenant, AlertID: alertID, Source: caseReference, Target: asset,
		RelationshipType: "contains", CreatedBy: fixtureID(9), CreatedAt: testAlertResourceTime(), Version: 1,
	}
	if relation, err := NewAlertRelationship(state); err != nil || relation.AlertID() != alertID ||
		relation.Source() != caseReference || relation.Target() != asset {
		t.Fatalf("workspace-rooted relationship error = %v", err)
	}
	alert, _ := NewEntityReference(tenant, EntityAlert, alertID)
	state.Source = alert
	state.AlertID = EntityID{}
	if _, err := NewAlertRelationship(state); !errors.Is(err, ErrInvalidRelationship) {
		t.Fatalf("wrong-root relationship error = %v", err)
	}
	state.AlertID = alertID
	state.Metadata = json.RawMessage{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'}
	if _, err := NewAlertRelationship(state); !errors.Is(err, ErrInvalidRelationship) {
		t.Fatalf("invalid UTF-8 relationship metadata error = %v", err)
	}
	external, err := NewExternalEntityReference(tenant, "ticket", "split\u2028identifier")
	if err != nil {
		t.Fatal(err)
	}
	state.Metadata = nil
	state.Target = external
	if _, err := NewAlertRelationship(state); !errors.Is(err, ErrInvalidRelationship) {
		t.Fatalf("line-breaking external identifier error = %v", err)
	}
}

func TestAlertRelationshipSupportsChildEndpointsAcrossRetractionAndRestore(t *testing.T) {
	t.Parallel()
	tenant, alertID := fixtureID(1), fixtureID(670)
	source, _ := NewEntityReference(tenant, EntityIOC, fixtureID(671))
	target, _ := NewEntityReference(tenant, EntityAsset, fixtureID(672))
	relationship, err := NewAlertRelationship(AlertRelationshipState{
		ID: fixtureID(673), TenantID: tenant, AlertID: alertID, Source: source, Target: target,
		RelationshipType: "observed_on", CreatedBy: fixtureID(9), CreatedAt: testAlertResourceTime(), Version: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	retracted, err := relationship.Retract(1, AlertRelationshipRetractionInput{
		ID: fixtureID(674), ActorID: fixtureID(9), Reason: "association disproved",
		OccurredAt: testAlertResourceTime().Add(time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	restored, err := NewAlertRelationship(retracted.Snapshot())
	if err != nil || restored.AlertID() != alertID || restored.Source() != source ||
		restored.Target() != target || restored.Active() || restored.Version() != 2 {
		t.Fatalf("restored child relationship = (%v, %v)", restored, err)
	}
	wrongTenant := relationship.Snapshot()
	wrongTenant.Target, _ = NewEntityReference(fixtureID(2), EntityAsset, fixtureID(672))
	if _, err := NewAlertRelationship(wrongTenant); !errors.Is(err, ErrInvalidRelationship) {
		t.Fatalf("cross-tenant child relationship error = %v", err)
	}
}

func TestAlertRelationshipReservesDualAlertDuplicateAndCorrelationSemantics(t *testing.T) {
	t.Parallel()
	tenant, alertID := fixtureID(1), fixtureID(650)
	source, _ := NewEntityReference(tenant, EntityAlert, alertID)
	target, _ := NewEntityReference(tenant, EntityAlert, fixtureID(651))
	state := AlertRelationshipState{
		ID: fixtureID(652), TenantID: tenant, AlertID: alertID, Source: source, Target: target,
		CreatedBy: fixtureID(9), CreatedAt: testAlertResourceTime(), Version: 1,
	}
	for _, reserved := range []string{"duplicate_of", "correlation"} {
		state.RelationshipType = reserved
		if _, err := NewAlertRelationship(state); !errors.Is(err, ErrInvalidRelationship) {
			t.Fatalf("dedicated Alert relation type %q error = %v", reserved, err)
		}
	}
	state.RelationshipType = "depends_on"
	if _, err := NewAlertRelationship(state); err != nil {
		t.Fatalf("general dual-Alert relationship error = %v", err)
	}
}

func TestAlertResourcesRejectUnixMicroAliasesOutsideSerializableRange(t *testing.T) {
	t.Parallel()
	input := validAlertEvidenceInput()
	evidence, err := NewAlertEvidence(input)
	if err != nil {
		t.Fatal(err)
	}
	alias := unixMicroAlias(input.CollectedAt)
	if alias.UnixMicro() != input.CollectedAt.UnixMicro() {
		t.Fatal("test timestamp is not a UnixMicro wraparound alias")
	}
	if _, err := alias.MarshalJSON(); err == nil {
		t.Fatal("test timestamp unexpectedly has an RFC 3339 JSON representation")
	}
	state := evidence.Snapshot()
	state.CollectedAt = alias
	state.CustodyEvents[0].OccurredAt = alias
	if _, err := RestoreAlertEvidence(state); !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("custody timestamp alias error = %v", err)
	}
	if _, err := evidence.AppendCustodyEvent(1, CustodyEventInput{
		ID: fixtureID(660), ActorID: fixtureID(9), Action: CustodyAccessed,
		Reason: "future alias", OccurredAt: alias,
	}); !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("new custody timestamp alias error = %v", err)
	}

	taskState := validAlertTaskState()
	taskState.CreatedAt, taskState.UpdatedAt = alias, alias
	if _, err := NewAlertTask(taskState); !errors.Is(err, ErrInvalidTask) {
		t.Fatalf("task timestamp alias error = %v", err)
	}

	tenant, alertID := fixtureID(1), fixtureID(661)
	alert, _ := NewEntityReference(tenant, EntityAlert, alertID)
	asset, _ := NewEntityReference(tenant, EntityAsset, fixtureID(662))
	if _, err := NewAlertRelationship(AlertRelationshipState{
		ID: fixtureID(663), TenantID: tenant, AlertID: alertID, Source: alert, Target: asset,
		RelationshipType: "contains", CreatedBy: fixtureID(9), CreatedAt: alias, Version: 1,
	}); !errors.Is(err, ErrInvalidRelationship) {
		t.Fatalf("relationship timestamp alias error = %v", err)
	}
}

func validAlertEvidenceInput() AlertEvidenceInput {
	base := validEvidenceInput()
	return AlertEvidenceInput{
		ID: base.ID, TenantID: base.TenantID, AlertID: fixtureID(600),
		StorageObjectID: base.StorageObjectID, InitialCustodyEventID: base.InitialCustodyEventID,
		Title: base.Title, Description: base.Description, EvidenceType: base.EvidenceType,
		Classification: base.Classification, ContentSHA256: base.ContentSHA256,
		SizeBytes: base.SizeBytes, DetectedMIME: base.DetectedMIME,
		CollectedAt: base.CollectedAt, CollectedBy: base.CollectedBy,
		InitialCustodyActorID: fixtureID(9), Source: base.Source,
		RetentionUntil: base.RetentionUntil, LegalHold: base.LegalHold, ScanState: base.ScanState,
	}
}

func validAlertTaskState() AlertTaskState {
	base := validTaskInput(nil)
	return AlertTaskState{
		ID: base.ID, TenantID: base.TenantID, AlertID: fixtureID(610),
		Title: base.Title, Description: base.Description, Status: base.Status, Priority: base.Priority,
		AssigneeID: base.AssigneeID, OperatorTeamID: base.OperatorTeamID, DueAt: base.DueAt,
		Checklist: base.Checklist, CompletedAt: base.CompletedAt, CompletedBy: base.CompletedBy,
		CompletionData: base.CompletionData, CommentIDs: base.CommentIDs, SLAInstanceID: base.SLAInstanceID,
		CreatedAt: base.CreatedAt, UpdatedAt: base.UpdatedAt, Version: base.Version,
	}
}

func testAlertResourceTime() time.Time {
	return time.Date(2026, 8, 25, 15, 0, 0, 0, time.UTC)
}

func unixMicroAlias(value time.Time) time.Time {
	const wrapSeconds int64 = 18_446_744_073_709
	const wrapMicroseconds int64 = 551_616
	return time.Unix(
		value.Unix()+wrapSeconds,
		int64(value.Nanosecond())+wrapMicroseconds*int64(time.Microsecond),
	).UTC()
}
