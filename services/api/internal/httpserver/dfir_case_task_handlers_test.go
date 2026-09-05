package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	dfirkernel "github.com/periapsis-im/periapsis/modules/dfir"
	applicationdfir "github.com/periapsis-im/periapsis/services/api/internal/dfir"
)

type caseTaskTransportDFIRService struct {
	*transportDFIRStub
	createTask      func(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.TaskCreateCommand) (applicationdfir.MutationResult[dfirkernel.Task], error)
	replaceDetails  func(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.TaskDetailsCommand) (applicationdfir.MutationResult[dfirkernel.Task], error)
	replaceComments func(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.TaskCommentsCommand) (applicationdfir.MutationResult[dfirkernel.Task], error)
}

func (service *caseTaskTransportDFIRService) CreateTask(ctx context.Context, actor applicationdfir.Actor, tenantID uuid.UUID, command applicationdfir.TaskCreateCommand) (applicationdfir.MutationResult[dfirkernel.Task], error) {
	return service.createTask(ctx, actor, tenantID, command)
}

func (service *caseTaskTransportDFIRService) ReplaceTaskDetails(ctx context.Context, actor applicationdfir.Actor, tenantID uuid.UUID, command applicationdfir.TaskDetailsCommand) (applicationdfir.MutationResult[dfirkernel.Task], error) {
	return service.replaceDetails(ctx, actor, tenantID, command)
}

func (service *caseTaskTransportDFIRService) ReplaceTaskComments(ctx context.Context, actor applicationdfir.Actor, tenantID uuid.UUID, command applicationdfir.TaskCommentsCommand) (applicationdfir.MutationResult[dfirkernel.Task], error) {
	return service.replaceComments(ctx, actor, tenantID, command)
}

func TestCaseTaskCreateRejectsClientOwnedLifecycleFields(t *testing.T) {
	fixture := newPhase4HTTPFixture(t)
	taskID := mustTransportUUIDv7(t)
	calls := 0
	service := &caseTaskTransportDFIRService{
		transportDFIRStub: &transportDFIRStub{},
		createTask: func(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.TaskCreateCommand) (applicationdfir.MutationResult[dfirkernel.Task], error) {
			calls++
			return applicationdfir.MutationResult[dfirkernel.Task]{}, applicationdfir.ErrUnavailable
		},
	}
	router := newPhase4TestRouter(t, fixture, &transportCustomFieldStub{}, service)
	base := "/api/v1/tenants/" + fixture.tenantID.String() + "/cases/" + fixture.caseID.String() + "/dfir/tasks"
	for _, forged := range []string{
		`"status":"done"`,
		`"completedAt":"2026-09-04T10:00:00Z"`,
		`"completedBy":"` + fixture.userID.String() + `"`,
		`"commentIds":[]`,
	} {
		body := `{"taskId":"` + taskID.String() + `","task":{"title":"Contain host","description":"","priority":"high","checklist":[],` + forged + `}}`
		request := phase4MutationRequest(http.MethodPost, base, body, "case-task-create-key-0001")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		assertProblem(t, response, http.StatusBadRequest, "invalid_request")
	}
	if calls != 0 {
		t.Fatalf("forged Case task create reached service %d times", calls)
	}
}

func TestCaseTaskDetailsPreservesBigintCASAndClearIntent(t *testing.T) {
	for _, expectedVersion := range []int64{3_000_000_000, maximumExactJSONResourceVersion - 1} {
		t.Run(strconv.FormatInt(expectedVersion, 10), func(t *testing.T) {
			fixture := newPhase4HTTPFixture(t)
			taskID := mustTransportUUIDv7(t)
			calls := 0
			service := &caseTaskTransportDFIRService{
				transportDFIRStub: &transportDFIRStub{},
				replaceDetails: func(_ context.Context, actor applicationdfir.Actor, tenantID uuid.UUID, command applicationdfir.TaskDetailsCommand) (applicationdfir.MutationResult[dfirkernel.Task], error) {
					calls++
					if tenantID != fixture.tenantID || actor.MembershipID != fixture.membershipID ||
						command.CaseID.String() != fixture.caseID.String() || command.TaskID.String() != taskID.String() ||
						command.ExpectedVersion != uint64(expectedVersion) || command.SLAInstanceID != nil ||
						command.Envelope.IdempotencyKey != "case-task-details-key-01" {
						t.Fatalf("unexpected Case task details command: actor=%#v tenant=%s command=%#v", actor, tenantID, command)
					}
					tenantEntity, tenantErr := dfirEntityID(tenantID)
					if tenantErr != nil {
						t.Fatal(tenantErr)
					}
					now := time.Date(2026, time.September, 4, 10, 0, 0, 0, time.UTC)
					value, err := dfirkernel.NewTask(dfirkernel.TaskInput{
						ID: command.TaskID, TenantID: tenantEntity, CaseID: command.CaseID,
						Title: command.Title, Description: command.Description, Status: dfirkernel.TaskTodo,
						Priority: command.Priority, Checklist: []dfirkernel.ChecklistItem{},
						CreatedAt: now.Add(-time.Hour), UpdatedAt: now, Version: command.ExpectedVersion + 1,
					})
					return applicationdfir.MutationResult[dfirkernel.Task]{Resource: value, Replayed: true}, err
				},
			}
			router := newPhase4TestRouter(t, fixture, &transportCustomFieldStub{}, service)
			path := "/api/v1/tenants/" + fixture.tenantID.String() + "/cases/" + fixture.caseID.String() +
				"/dfir/tasks/" + taskID.String() + "/details"
			body := fmt.Sprintf(`{"expectedVersion":%d,"title":"Contain host","description":"Updated","priority":"urgent"}`, expectedVersion)
			request := phase4MutationRequest(http.MethodPut, path, body, "case-task-details-key-01")
			request.Header.Set("If-Match", fmt.Sprintf(`"v%d"`, expectedVersion))
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != http.StatusOK || response.Header().Get("ETag") != fmt.Sprintf(`"v%d"`, expectedVersion+1) ||
				response.Header().Get(idempotentReplayHeader) != "true" || calls != 1 {
				t.Fatalf("status/headers/calls = %d %#v %d: %s", response.Code, response.Header(), calls, response.Body.String())
			}
			decoder := json.NewDecoder(response.Body)
			decoder.UseNumber()
			var resource map[string]any
			if err := decoder.Decode(&resource); err != nil {
				t.Fatal(err)
			}
			version, ok := resource["version"].(json.Number)
			if !ok || version.String() != strconv.FormatInt(expectedVersion+1, 10) {
				t.Fatalf("response version is not the exact JSON integer: %#v", resource["version"])
			}
		})
	}
}

func TestCaseTaskDetailsRejectsTerminalAndUnsafeVersions(t *testing.T) {
	for _, test := range []struct {
		name            string
		expectedVersion int64
		etagVersion     int64
	}{
		{"terminal", maximumExactJSONResourceVersion, maximumExactJSONResourceVersion},
		{"unsafe", maximumExactJSONResourceVersion + 1, maximumExactJSONResourceVersion + 1},
		{"unsafe_body", maximumExactJSONResourceVersion + 1, maximumExactJSONResourceVersion - 1},
		{"unsafe_etag", maximumExactJSONResourceVersion - 1, maximumExactJSONResourceVersion + 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPhase4HTTPFixture(t)
			taskID := mustTransportUUIDv7(t)
			calls := 0
			service := &caseTaskTransportDFIRService{
				transportDFIRStub: &transportDFIRStub{},
				replaceDetails: func(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.TaskDetailsCommand) (applicationdfir.MutationResult[dfirkernel.Task], error) {
					calls++
					return applicationdfir.MutationResult[dfirkernel.Task]{}, applicationdfir.ErrUnavailable
				},
			}
			router := newPhase4TestRouter(t, fixture, &transportCustomFieldStub{}, service)
			path := "/api/v1/tenants/" + fixture.tenantID.String() + "/cases/" + fixture.caseID.String() +
				"/dfir/tasks/" + taskID.String() + "/details"
			body := fmt.Sprintf(`{"expectedVersion":%d,"title":"Contain host","description":"Updated","priority":"urgent"}`, test.expectedVersion)
			request := phase4MutationRequest(http.MethodPut, path, body, "case-task-details-key-01")
			request.Header.Set("If-Match", fmt.Sprintf(`"v%d"`, test.etagVersion))
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			assertProblem(t, response, http.StatusBadRequest, "invalid_request")
			if calls != 0 {
				t.Fatalf("invalid Case task revision reached service %d times", calls)
			}
		})
	}
}

func TestDFIRResourcePreconditionUsesExactJSONBigintBoundary(t *testing.T) {
	t.Parallel()
	request := httptest.NewRequest(http.MethodPut, "/unused", nil)
	request.Header.Set("If-Match", `"v3000000000"`)
	response := httptest.NewRecorder()
	if !dfirResourcePrecondition(response, request, 3_000_000_000) {
		t.Fatalf("valid bigint DFIR resource precondition rejected: %s", response.Body.String())
	}

	request = httptest.NewRequest(http.MethodPut, "/unused", nil)
	request.Header.Set("If-Match", `"v9007199254740991"`)
	response = httptest.NewRecorder()
	if dfirResourcePrecondition(response, request, maximumExactJSONResourceVersion) {
		t.Fatal("terminal DFIR resource revision was accepted for mutation")
	}
	assertProblem(t, response, http.StatusBadRequest, "invalid_request")
}

func TestCaseTaskCommentsTransportBindsFullReplacementAndCAS(t *testing.T) {
	fixture := newPhase4HTTPFixture(t)
	taskID, firstCommentID, secondCommentID := mustTransportUUIDv7(t), mustTransportUUIDv7(t), mustTransportUUIDv7(t)
	service := &caseTaskTransportDFIRService{transportDFIRStub: &transportDFIRStub{}}
	service.replaceComments = func(_ context.Context, actor applicationdfir.Actor, tenantID uuid.UUID, command applicationdfir.TaskCommentsCommand) (applicationdfir.MutationResult[dfirkernel.Task], error) {
		if actor.MembershipID != fixture.membershipID || tenantID != fixture.tenantID ||
			command.CaseID.String() != fixture.caseID.String() || command.TaskID.String() != taskID.String() ||
			command.ExpectedVersion != 7 || command.Envelope.IdempotencyKey != "case-task-comments-key-1" ||
			len(command.CommentIDs) != 2 || command.CommentIDs[0].String() != secondCommentID.String() ||
			command.CommentIDs[1].String() != firstCommentID.String() {
			t.Fatalf("unexpected Case task comments command: actor=%#v tenant=%s command=%#v", actor, tenantID, command)
		}
		tenantEntity, _ := dfirEntityID(tenantID)
		value, err := dfirkernel.NewTask(dfirkernel.TaskInput{
			ID: command.TaskID, TenantID: tenantEntity, CaseID: command.CaseID,
			Title: "Preserve evidence", Status: dfirkernel.TaskTodo, Priority: dfirkernel.TaskPriorityHigh,
			Checklist: []dfirkernel.ChecklistItem{}, CommentIDs: []dfirkernel.EntityID{command.CommentIDs[1], command.CommentIDs[0]},
			CreatedAt: time.Date(2026, time.September, 4, 8, 0, 0, 0, time.UTC),
			UpdatedAt: time.Date(2026, time.September, 4, 9, 0, 0, 0, time.UTC), Version: 8,
		})
		return applicationdfir.MutationResult[dfirkernel.Task]{Resource: value, Replayed: true}, err
	}
	router := newPhase4TestRouter(t, fixture, &transportCustomFieldStub{}, service)
	path := "/api/v1/tenants/" + fixture.tenantID.String() + "/cases/" + fixture.caseID.String() +
		"/dfir/tasks/" + taskID.String() + "/comments"
	body := `{"expectedVersion":7,"commentIds":["` + secondCommentID.String() + `","` + firstCommentID.String() + `"]}`
	request := phase4MutationRequest(http.MethodPut, path, body, "case-task-comments-key-1")
	request.Header.Set("If-Match", `"v7"`)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"v8"` ||
		response.Header().Get(idempotentReplayHeader) != "true" {
		t.Fatalf("status/headers = %d %#v: %s", response.Code, response.Header(), response.Body.String())
	}
}

var _ DFIRService = (*caseTaskTransportDFIRService)(nil)
