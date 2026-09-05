package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	dfirkernel "github.com/periapsis-im/periapsis/modules/dfir"
	applicationdfir "github.com/periapsis-im/periapsis/services/api/internal/dfir"
)

type alertInvestigationTransportStub struct {
	unavailableAlertInvestigationService
	workspace           func(context.Context, applicationdfir.Actor, uuid.UUID, dfirkernel.EntityID) (applicationdfir.AlertInvestigationWorkspace, error)
	collectEvidence     func(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.AlertEvidenceCollectCommand) (applicationdfir.MutationResult[dfirkernel.AlertEvidence], error)
	appendCustody       func(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.AlertCustodyCommand) (applicationdfir.MutationResult[dfirkernel.AlertEvidence], error)
	createTask          func(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.AlertTaskCreateCommand) (applicationdfir.MutationResult[dfirkernel.AlertTask], error)
	transitionTask      func(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.AlertTaskTransitionCommand) (applicationdfir.MutationResult[dfirkernel.AlertTask], error)
	replaceTaskDetails  func(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.AlertTaskDetailsCommand) (applicationdfir.MutationResult[dfirkernel.AlertTask], error)
	assignTask          func(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.AlertTaskAssignmentCommand) (applicationdfir.MutationResult[dfirkernel.AlertTask], error)
	rescheduleTask      func(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.AlertTaskDueDateCommand) (applicationdfir.MutationResult[dfirkernel.AlertTask], error)
	replaceChecklist    func(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.AlertTaskChecklistCommand) (applicationdfir.MutationResult[dfirkernel.AlertTask], error)
	replaceComments     func(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.AlertTaskCommentsCommand) (applicationdfir.MutationResult[dfirkernel.AlertTask], error)
	createRelationship  func(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.AlertRelationshipCreateCommand) (applicationdfir.MutationResult[dfirkernel.AlertRelationship], error)
	retractRelationship func(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.AlertRelationshipRetractCommand) (applicationdfir.MutationResult[dfirkernel.AlertRelationship], error)
}

func (stub *alertInvestigationTransportStub) Workspace(ctx context.Context, actor applicationdfir.Actor, tenantID uuid.UUID, alertID dfirkernel.EntityID) (applicationdfir.AlertInvestigationWorkspace, error) {
	return stub.workspace(ctx, actor, tenantID, alertID)
}

func (stub *alertInvestigationTransportStub) CollectEvidence(ctx context.Context, actor applicationdfir.Actor, tenantID uuid.UUID, command applicationdfir.AlertEvidenceCollectCommand) (applicationdfir.MutationResult[dfirkernel.AlertEvidence], error) {
	return stub.collectEvidence(ctx, actor, tenantID, command)
}

func (stub *alertInvestigationTransportStub) AppendCustody(ctx context.Context, actor applicationdfir.Actor, tenantID uuid.UUID, command applicationdfir.AlertCustodyCommand) (applicationdfir.MutationResult[dfirkernel.AlertEvidence], error) {
	return stub.appendCustody(ctx, actor, tenantID, command)
}

func (stub *alertInvestigationTransportStub) CreateTask(ctx context.Context, actor applicationdfir.Actor, tenantID uuid.UUID, command applicationdfir.AlertTaskCreateCommand) (applicationdfir.MutationResult[dfirkernel.AlertTask], error) {
	return stub.createTask(ctx, actor, tenantID, command)
}

func (stub *alertInvestigationTransportStub) TransitionTask(ctx context.Context, actor applicationdfir.Actor, tenantID uuid.UUID, command applicationdfir.AlertTaskTransitionCommand) (applicationdfir.MutationResult[dfirkernel.AlertTask], error) {
	return stub.transitionTask(ctx, actor, tenantID, command)
}

func (stub *alertInvestigationTransportStub) ReplaceTaskDetails(ctx context.Context, actor applicationdfir.Actor, tenantID uuid.UUID, command applicationdfir.AlertTaskDetailsCommand) (applicationdfir.MutationResult[dfirkernel.AlertTask], error) {
	return stub.replaceTaskDetails(ctx, actor, tenantID, command)
}

func (stub *alertInvestigationTransportStub) AssignTask(ctx context.Context, actor applicationdfir.Actor, tenantID uuid.UUID, command applicationdfir.AlertTaskAssignmentCommand) (applicationdfir.MutationResult[dfirkernel.AlertTask], error) {
	return stub.assignTask(ctx, actor, tenantID, command)
}

func (stub *alertInvestigationTransportStub) RescheduleTask(ctx context.Context, actor applicationdfir.Actor, tenantID uuid.UUID, command applicationdfir.AlertTaskDueDateCommand) (applicationdfir.MutationResult[dfirkernel.AlertTask], error) {
	return stub.rescheduleTask(ctx, actor, tenantID, command)
}

func (stub *alertInvestigationTransportStub) ReplaceTaskChecklist(ctx context.Context, actor applicationdfir.Actor, tenantID uuid.UUID, command applicationdfir.AlertTaskChecklistCommand) (applicationdfir.MutationResult[dfirkernel.AlertTask], error) {
	return stub.replaceChecklist(ctx, actor, tenantID, command)
}

func (stub *alertInvestigationTransportStub) ReplaceTaskComments(ctx context.Context, actor applicationdfir.Actor, tenantID uuid.UUID, command applicationdfir.AlertTaskCommentsCommand) (applicationdfir.MutationResult[dfirkernel.AlertTask], error) {
	return stub.replaceComments(ctx, actor, tenantID, command)
}

func (stub *alertInvestigationTransportStub) CreateRelationship(ctx context.Context, actor applicationdfir.Actor, tenantID uuid.UUID, command applicationdfir.AlertRelationshipCreateCommand) (applicationdfir.MutationResult[dfirkernel.AlertRelationship], error) {
	return stub.createRelationship(ctx, actor, tenantID, command)
}

func (stub *alertInvestigationTransportStub) RetractRelationship(ctx context.Context, actor applicationdfir.Actor, tenantID uuid.UUID, command applicationdfir.AlertRelationshipRetractCommand) (applicationdfir.MutationResult[dfirkernel.AlertRelationship], error) {
	return stub.retractRelationship(ctx, actor, tenantID, command)
}

func TestAlertInvestigationTaskTransportPreservesUserIdentityCASAndReplay(t *testing.T) {
	fixture := newPhase4HTTPFixture(t)
	alertID, taskID, itemID := mustTransportUUIDv7(t), mustTransportUUIDv7(t), mustTransportUUIDv7(t)
	teamID, assigneeID := mustTransportUUIDv7(t), mustTransportUUIDv7(t)
	alertEntity, _ := dfirEntityID(alertID)
	taskEntity, _ := dfirEntityID(taskID)
	teamEntity, _ := dfirEntityID(teamID)
	assigneeEntity, _ := dfirEntityID(assigneeID)
	userEntity, _ := dfirEntityID(fixture.userID)
	createdAt := time.Date(2026, time.September, 3, 12, 0, 0, 0, time.UTC)

	oldWorkspace := &alertTransportDFIRService{transportDFIRStub: &transportDFIRStub{}}
	oldWorkspace.workspace = func(context.Context, applicationdfir.Actor, uuid.UUID, dfirkernel.EntityID) (applicationdfir.AlertWorkspace, error) {
		return applicationdfir.AlertWorkspace{}, nil
	}
	service := &alertInvestigationTransportStub{}
	var created dfirkernel.AlertTask
	service.workspace = func(_ context.Context, actor applicationdfir.Actor, tenantID uuid.UUID, gotAlert dfirkernel.EntityID) (applicationdfir.AlertInvestigationWorkspace, error) {
		if actor.UserID != fixture.userID || actor.MembershipID != fixture.membershipID || tenantID != fixture.tenantID || gotAlert != alertEntity {
			t.Fatalf("workspace lost exact authority: actor=%#v tenant=%s alert=%s", actor, tenantID, gotAlert)
		}
		return applicationdfir.AlertInvestigationWorkspace{Tasks: []dfirkernel.AlertTask{created}}, nil
	}
	service.createTask = func(_ context.Context, actor applicationdfir.Actor, tenantID uuid.UUID, command applicationdfir.AlertTaskCreateCommand) (applicationdfir.MutationResult[dfirkernel.AlertTask], error) {
		if actor.UserID == actor.MembershipID || actor.UserID != fixture.userID || tenantID != fixture.tenantID ||
			command.AlertID != alertEntity || command.Input.ID != taskEntity || command.Input.OperatorTeamID == nil ||
			*command.Input.OperatorTeamID != teamEntity || command.Input.AssigneeID == nil || *command.Input.AssigneeID != assigneeEntity ||
			len(command.Input.Checklist) != 1 || !command.Input.Checklist[0].Completed ||
			command.Envelope.IdempotencyKey != "alert-task-create-0001" {
			t.Fatalf("unexpected create command: actor=%#v command=%#v", actor, command)
		}
		item, err := dfirkernel.NewChecklistItem(dfirkernel.ChecklistItemInput{
			ID: command.Input.Checklist[0].ID, Title: command.Input.Checklist[0].Title, Completed: true,
			CompletedAt: &createdAt, CompletedBy: &userEntity,
		})
		if err != nil {
			return applicationdfir.MutationResult[dfirkernel.AlertTask]{}, err
		}
		created, err = dfirkernel.NewAlertTask(dfirkernel.AlertTaskState{
			ID: taskEntity, TenantID: mustDFIRHTTPKernelID(t, fixture.tenantID), AlertID: alertEntity,
			Title: command.Input.Title, Description: command.Input.Description, Status: dfirkernel.TaskTodo,
			Priority: command.Input.Priority, OperatorTeamID: &teamEntity, AssigneeID: &assigneeEntity,
			Checklist: []dfirkernel.ChecklistItem{item}, CreatedAt: createdAt, UpdatedAt: createdAt, Version: 1,
		})
		return applicationdfir.MutationResult[dfirkernel.AlertTask]{Resource: created, Replayed: true}, err
	}
	service.replaceTaskDetails = func(_ context.Context, actor applicationdfir.Actor, tenantID uuid.UUID, command applicationdfir.AlertTaskDetailsCommand) (applicationdfir.MutationResult[dfirkernel.AlertTask], error) {
		if actor.UserID != fixture.userID || tenantID != fixture.tenantID || command.AlertID != alertEntity ||
			command.TaskID != taskEntity || command.ExpectedVersion != 1 || command.Title != "Contain endpoint" ||
			command.Description != "Updated instructions" || command.Priority != dfirkernel.TaskPriorityUrgent ||
			command.SLAInstanceID != nil || command.Envelope.IdempotencyKey != "alert-task-details-0001" {
			t.Fatalf("unexpected details command: actor=%#v command=%#v", actor, command)
		}
		updated, err := created.ReplaceDetails(
			1, command.Title, command.Description, command.Priority, nil, createdAt.Add(time.Second),
		)
		if err == nil {
			created = updated
		}
		return applicationdfir.MutationResult[dfirkernel.AlertTask]{Resource: updated, Replayed: false}, err
	}
	service.assignTask = func(_ context.Context, actor applicationdfir.Actor, tenantID uuid.UUID, command applicationdfir.AlertTaskAssignmentCommand) (applicationdfir.MutationResult[dfirkernel.AlertTask], error) {
		if actor.UserID != fixture.userID || tenantID != fixture.tenantID || command.AlertID != alertEntity ||
			command.TaskID != taskEntity || command.ExpectedVersion != 2 || command.OperatorTeamID != nil ||
			command.AssigneeID != nil || command.Envelope.IdempotencyKey != "alert-task-assign-0001" {
			t.Fatalf("unexpected assignment command: actor=%#v command=%#v", actor, command)
		}
		updated, err := created.Assign(2, nil, nil, createdAt.Add(2*time.Second))
		return applicationdfir.MutationResult[dfirkernel.AlertTask]{Resource: updated, Replayed: false}, err
	}

	router := newPhase4TestRouterWithAlertInvestigation(
		t, fixture, &transportCustomFieldStub{}, oldWorkspace, service,
	)
	base := "/api/v1/tenants/" + fixture.tenantID.String() + "/alerts/" + alertID.String() + "/dfir"
	createBody := `{"taskId":"` + taskID.String() + `","task":{"title":"Acquire memory","description":"private","priority":"high","operatorTeamId":"` + teamID.String() + `","assigneeId":"` + assigneeID.String() + `","checklist":[{"id":"` + itemID.String() + `","title":"Verify hash","completed":true}]}}`
	request := phase4MutationRequest(http.MethodPost, base+"/tasks", createBody, "alert-task-create-0001")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusCreated || response.Header().Get("ETag") != `"v1"` ||
		response.Header().Get(idempotentReplayHeader) != "true" || response.Header().Get("Location") != base+"/tasks/"+taskID.String() {
		t.Fatalf("create response = %d %v: %s", response.Code, response.Header(), response.Body.String())
	}
	var mapped struct {
		CompletedBy *uuid.UUID `json:"completedBy"`
		Checklist   []struct {
			CompletedBy *uuid.UUID `json:"completedBy"`
		} `json:"checklist"`
		Version int64 `json:"version"`
	}
	if json.Unmarshal(response.Body.Bytes(), &mapped) != nil || mapped.CompletedBy != nil || mapped.Version != 1 ||
		len(mapped.Checklist) != 1 || mapped.Checklist[0].CompletedBy == nil ||
		*mapped.Checklist[0].CompletedBy != fixture.userID {
		t.Fatalf("unexpected task projection: %s", response.Body.String())
	}

	request = phase4MutationRequest(http.MethodPut, base+"/tasks/"+taskID.String()+"/details", `{"expectedVersion":1,"title":"Contain endpoint","description":"Updated instructions","priority":"urgent"}`, "alert-task-details-0001")
	request.Header.Set("If-Match", `"v1"`)
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"v2"` || response.Header().Get(idempotentReplayHeader) != "false" {
		t.Fatalf("details response = %d %v: %s", response.Code, response.Header(), response.Body.String())
	}

	request = phase4MutationRequest(http.MethodPut, base+"/tasks/"+taskID.String()+"/assignment", `{"expectedVersion":2}`, "alert-task-assign-0001")
	request.Header.Set("If-Match", `"v2"`)
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"v3"` || response.Header().Get(idempotentReplayHeader) != "false" {
		t.Fatalf("assignment response = %d %v: %s", response.Code, response.Header(), response.Body.String())
	}

	read := httptest.NewRequest(http.MethodGet, base, nil)
	prepareTenantLDAPTransportRequest(read, false)
	response = httptest.NewRecorder()
	router.ServeHTTP(response, read)
	if response.Code != http.StatusOK || !json.Valid(response.Body.Bytes()) {
		t.Fatalf("workspace response = %d: %s", response.Code, response.Body.String())
	}
}

func TestAlertTaskCommentsTransportBindsFullReplacementAndCAS(t *testing.T) {
	fixture := newPhase4HTTPFixture(t)
	alertID, taskID, firstCommentID, secondCommentID := mustTransportUUIDv7(t), mustTransportUUIDv7(t), mustTransportUUIDv7(t), mustTransportUUIDv7(t)
	alertEntity, _ := dfirEntityID(alertID)
	taskEntity, _ := dfirEntityID(taskID)
	tenantEntity, _ := dfirEntityID(fixture.tenantID)

	oldWorkspace := &alertTransportDFIRService{transportDFIRStub: &transportDFIRStub{}}
	oldWorkspace.workspace = func(context.Context, applicationdfir.Actor, uuid.UUID, dfirkernel.EntityID) (applicationdfir.AlertWorkspace, error) {
		return applicationdfir.AlertWorkspace{}, nil
	}
	service := &alertInvestigationTransportStub{}
	service.replaceComments = func(_ context.Context, actor applicationdfir.Actor, tenantID uuid.UUID, command applicationdfir.AlertTaskCommentsCommand) (applicationdfir.MutationResult[dfirkernel.AlertTask], error) {
		if actor.MembershipID != fixture.membershipID || tenantID != fixture.tenantID || command.AlertID != alertEntity ||
			command.TaskID != taskEntity || command.ExpectedVersion != 11 || command.Envelope.IdempotencyKey != "alert-task-comments-key-1" ||
			len(command.CommentIDs) != 2 || command.CommentIDs[0].String() != secondCommentID.String() ||
			command.CommentIDs[1].String() != firstCommentID.String() {
			t.Fatalf("unexpected Alert task comments command: actor=%#v tenant=%s command=%#v", actor, tenantID, command)
		}
		value, err := dfirkernel.NewAlertTask(dfirkernel.AlertTaskState{
			ID: taskEntity, TenantID: tenantEntity, AlertID: alertEntity,
			Title: "Triage alert", Status: dfirkernel.TaskTodo, Priority: dfirkernel.TaskPriorityHigh,
			Checklist: []dfirkernel.ChecklistItem{}, CommentIDs: []dfirkernel.EntityID{command.CommentIDs[1], command.CommentIDs[0]},
			CreatedAt: time.Date(2026, time.September, 4, 8, 0, 0, 0, time.UTC),
			UpdatedAt: time.Date(2026, time.September, 4, 9, 0, 0, 0, time.UTC), Version: 12,
		})
		return applicationdfir.MutationResult[dfirkernel.AlertTask]{Resource: value, Replayed: true}, err
	}
	router := newPhase4TestRouterWithAlertInvestigation(t, fixture, &transportCustomFieldStub{}, oldWorkspace, service)
	path := "/api/v1/tenants/" + fixture.tenantID.String() + "/alerts/" + alertID.String() +
		"/dfir/tasks/" + taskID.String() + "/comments"
	body := `{"expectedVersion":11,"commentIds":["` + secondCommentID.String() + `","` + firstCommentID.String() + `"]}`
	request := phase4MutationRequest(http.MethodPut, path, body, "alert-task-comments-key-1")
	request.Header.Set("If-Match", `"v11"`)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"v12"` ||
		response.Header().Get(idempotentReplayHeader) != "true" {
		t.Fatalf("status/headers = %d %#v: %s", response.Code, response.Header(), response.Body.String())
	}
}

func TestCanonicalAlertTransportInstantPreservesWireTimeWithoutSilentTruncation(t *testing.T) {
	offset := time.FixedZone("UTC+05:30", 5*60*60+30*60)
	input := time.Date(2026, time.September, 3, 17, 30, 0, 123456000, offset)
	want := time.Date(2026, time.September, 3, 12, 0, 0, 123456000, time.UTC)

	got, err := canonicalAlertTransportInstant(input)
	if err != nil || !got.Equal(want) || got.Location() != time.UTC {
		t.Fatalf("canonical instant = %v (%v), want %v UTC", got, err, want)
	}

	if _, err := canonicalAlertTransportInstant(input.Add(time.Nanosecond)); err != applicationdfir.ErrInvalidInput {
		t.Fatalf("sub-microsecond instant error = %v, want invalid input", err)
	}
	if _, err := canonicalAlertTransportInstant(time.Time{}); err != applicationdfir.ErrInvalidInput {
		t.Fatalf("zero instant error = %v, want invalid input", err)
	}
}

func mustDFIRHTTPKernelID(t *testing.T, value uuid.UUID) dfirkernel.EntityID {
	t.Helper()
	id, err := dfirEntityID(value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
