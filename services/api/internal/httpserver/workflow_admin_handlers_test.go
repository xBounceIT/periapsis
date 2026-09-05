package httpserver

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	applicationticketing "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

type workflowAdminHTTPStub struct {
	*transportWorkflowAdministrationStub
	listFn     func(context.Context, applicationticketing.Actor, uuid.UUID, applicationticketing.WorkflowAdminListInput) (applicationticketing.WorkflowAdminPage, error)
	getFn      func(context.Context, applicationticketing.Actor, uuid.UUID, uuid.UUID) (applicationticketing.WorkflowAdminRecord, error)
	createFn   func(context.Context, applicationticketing.Actor, uuid.UUID, applicationticketing.WorkflowCreateInput) (applicationticketing.WorkflowAdminMutationResult, error)
	metadataFn func(context.Context, applicationticketing.Actor, uuid.UUID, uuid.UUID, applicationticketing.WorkflowMetadataInput) (applicationticketing.WorkflowAdminMutationResult, error)
	simulateFn func(context.Context, applicationticketing.Actor, uuid.UUID, uuid.UUID, applicationticketing.WorkflowSimulationInput) (applicationticketing.WorkflowSimulationResult, error)
}

func (stub *workflowAdminHTTPStub) ListWorkflows(ctx context.Context, actor applicationticketing.Actor, tenantID uuid.UUID, input applicationticketing.WorkflowAdminListInput) (applicationticketing.WorkflowAdminPage, error) {
	if stub.listFn == nil {
		return stub.transportWorkflowAdministrationStub.ListWorkflows(ctx, actor, tenantID, input)
	}
	return stub.listFn(ctx, actor, tenantID, input)
}

func (stub *workflowAdminHTTPStub) GetWorkflow(ctx context.Context, actor applicationticketing.Actor, tenantID, workflowID uuid.UUID) (applicationticketing.WorkflowAdminRecord, error) {
	if stub.getFn == nil {
		return stub.transportWorkflowAdministrationStub.GetWorkflow(ctx, actor, tenantID, workflowID)
	}
	return stub.getFn(ctx, actor, tenantID, workflowID)
}

func (stub *workflowAdminHTTPStub) CreateWorkflow(ctx context.Context, actor applicationticketing.Actor, tenantID uuid.UUID, input applicationticketing.WorkflowCreateInput) (applicationticketing.WorkflowAdminMutationResult, error) {
	if stub.createFn == nil {
		return stub.transportWorkflowAdministrationStub.CreateWorkflow(ctx, actor, tenantID, input)
	}
	return stub.createFn(ctx, actor, tenantID, input)
}

func (stub *workflowAdminHTTPStub) UpdateWorkflowMetadata(ctx context.Context, actor applicationticketing.Actor, tenantID, workflowID uuid.UUID, input applicationticketing.WorkflowMetadataInput) (applicationticketing.WorkflowAdminMutationResult, error) {
	if stub.metadataFn == nil {
		return stub.transportWorkflowAdministrationStub.UpdateWorkflowMetadata(ctx, actor, tenantID, workflowID, input)
	}
	return stub.metadataFn(ctx, actor, tenantID, workflowID, input)
}

func (stub *workflowAdminHTTPStub) SimulateWorkflow(ctx context.Context, actor applicationticketing.Actor, tenantID, workflowID uuid.UUID, input applicationticketing.WorkflowSimulationInput) (applicationticketing.WorkflowSimulationResult, error) {
	if stub.simulateFn == nil {
		return stub.transportWorkflowAdministrationStub.SimulateWorkflow(ctx, actor, tenantID, workflowID, input)
	}
	return stub.simulateFn(ctx, actor, tenantID, workflowID, input)
}

func TestApplicationHandlerRequiresWorkflowAdministrationBoundary(t *testing.T) {
	t.Parallel()
	tenantID := mustTransportUUIDv7(t)
	auth := workflowAdminTransportAuthentication(tenantID, mustTransportUUIDv7(t), mustTransportUUIDv7(t))
	options := workflowAdminApplicationOptions(auth, &transportWorkflowAdministrationStub{})
	options.WorkflowAdministration = nil
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	_, err := NewApplicationHandler(fixedChecker{ready: true}, logger, "test", time.Second, options)
	if err == nil || !strings.Contains(err.Error(), "workflow-administration") {
		t.Fatalf("NewApplicationHandler() error = %v, want missing workflow-administration boundary", err)
	}
}

func TestWorkflowAdministrationReadsMapCanonicalProjectionAndETag(t *testing.T) {
	t.Parallel()
	tenantID := mustTransportUUIDv7(t)
	workflowID := mustTransportUUIDv7(t)
	userID := mustTransportUUIDv7(t)
	sessionID := mustTransportUUIDv7(t)
	record := workflowAdminHTTPRecord(t, tenantID, workflowID, 3)
	var capturedActor applicationticketing.Actor
	service := &workflowAdminHTTPStub{
		transportWorkflowAdministrationStub: &transportWorkflowAdministrationStub{},
		getFn: func(_ context.Context, actor applicationticketing.Actor, requestedTenant, requestedWorkflow uuid.UUID) (applicationticketing.WorkflowAdminRecord, error) {
			capturedActor = actor
			if requestedTenant != tenantID || requestedWorkflow != workflowID {
				t.Fatalf("requested identity = %s/%s, want %s/%s", requestedTenant, requestedWorkflow, tenantID, workflowID)
			}
			return record, nil
		},
	}
	router := newWorkflowAdminTestRouter(t, workflowAdminTransportAuthentication(tenantID, userID, sessionID), service)
	request := workflowAdminReadRequest(http.MethodGet, workflowAdminPath(tenantID, workflowID), "")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if got, want := response.Header().Get("ETag"), applicationticketing.WorkflowAdminStrongETag(record); got != want {
		t.Fatalf("ETag = %q, want %q", got, want)
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q", response.Header().Get("Cache-Control"))
	}
	var body contract.ManagedWorkflow
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Id != workflowID || body.TenantId != tenantID || body.Revision != 3 || body.Current.Id != workflowID {
		t.Fatalf("mapped workflow identity/version drifted: %#v", body)
	}
	if capturedActor.UserID != userID || capturedActor.SessionID != sessionID || capturedActor.ActiveTenantID != tenantID || capturedActor.AuthenticationMethod != "totp" {
		t.Fatalf("captured actor = %#v", capturedActor)
	}
	if capturedActor.Audit != (applicationticketing.AuditContext{}) {
		t.Fatalf("read actor unexpectedly received mutation audit context: %#v", capturedActor.Audit)
	}
}

func TestWorkflowAdministrationCreateCarriesExactBodyAuditAndReplay(t *testing.T) {
	t.Parallel()
	tenantID := mustTransportUUIDv7(t)
	workflowID := mustTransportUUIDv7(t)
	record := workflowAdminHTTPRecord(t, tenantID, workflowID, 1)
	var calls int
	service := &workflowAdminHTTPStub{
		transportWorkflowAdministrationStub: &transportWorkflowAdministrationStub{},
		createFn: func(_ context.Context, actor applicationticketing.Actor, requestedTenant uuid.UUID, input applicationticketing.WorkflowCreateInput) (applicationticketing.WorkflowAdminMutationResult, error) {
			calls++
			if requestedTenant != tenantID || actor.ActiveTenantID != tenantID || actor.UserID == uuid.Nil || actor.SessionID == uuid.Nil || actor.AuthenticationMethod != "totp" {
				t.Fatalf("actor/tenant drifted: %#v/%s", actor, requestedTenant)
			}
			if actor.Audit.RequestID == uuid.Nil || actor.Audit.CorrelationID == uuid.Nil || !actor.Audit.RemoteAddress.IsValid() || actor.Audit.UserAgent != "workflow-http-test" {
				t.Fatalf("mutation audit context = %#v", actor.Audit)
			}
			if input.Kind != kernel.AggregateAlert || input.Key != "alert_response" || input.DisplayName != "Alert response" || input.Description != "Governed workflow" || input.IdempotencyKey != "workflow-create-0001" {
				t.Fatalf("create input = %#v", input)
			}
			if len(input.Design.States) != 2 || len(input.Design.Transitions) != 1 || input.Design.Transitions[0].From().String() != "new" || input.Design.Transitions[0].To().String() != "closed" {
				t.Fatalf("design was not constructed canonically: %#v", input.Design)
			}
			return applicationticketing.WorkflowAdminMutationResult{Record: record, Replayed: true}, nil
		},
	}
	router := newWorkflowAdminTestRouter(t, workflowAdminTransportAuthentication(tenantID, mustTransportUUIDv7(t), mustTransportUUIDv7(t)), service)
	request := workflowAdminMutationRequest(http.MethodPost, "/api/v1/tenants/"+tenantID.String()+"/workflows", workflowAdminCreateBody())
	request.Header.Set(idempotencyKeyHeader, "workflow-create-0001")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if calls != 1 {
		t.Fatalf("create calls = %d, want 1", calls)
	}
	if got, want := response.Header().Get("Location"), workflowAdminPath(tenantID, workflowID); got != want {
		t.Fatalf("Location = %q, want %q", got, want)
	}
	if got, want := response.Header().Get("ETag"), applicationticketing.WorkflowAdminStrongETag(record); got != want {
		t.Fatalf("ETag = %q, want %q", got, want)
	}
	var body contract.WorkflowAdminMutationResult
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !body.Replayed || body.Workflow.Id != workflowID || body.Workflow.Revision != 1 {
		t.Fatalf("mutation response = %#v", body)
	}
}

func TestWorkflowAdministrationMutationRequiresIdentityBoundPrecondition(t *testing.T) {
	t.Parallel()
	tenantID := mustTransportUUIDv7(t)
	workflowID := mustTransportUUIDv7(t)
	otherWorkflowID := mustTransportUUIDv7(t)
	record := workflowAdminHTTPRecord(t, tenantID, workflowID, 4)
	var calls int
	service := &workflowAdminHTTPStub{
		transportWorkflowAdministrationStub: &transportWorkflowAdministrationStub{},
		metadataFn: func(_ context.Context, _ applicationticketing.Actor, requestedTenant, requestedWorkflow uuid.UUID, input applicationticketing.WorkflowMetadataInput) (applicationticketing.WorkflowAdminMutationResult, error) {
			calls++
			if requestedTenant != tenantID || requestedWorkflow != workflowID || input.ExpectedRevision != 3 || input.IdempotencyKey != "workflow-update-0001" {
				t.Fatalf("metadata mutation drifted: %s/%s %#v", requestedTenant, requestedWorkflow, input)
			}
			return applicationticketing.WorkflowAdminMutationResult{Record: record}, nil
		},
	}
	router := newWorkflowAdminTestRouter(t, workflowAdminTransportAuthentication(tenantID, mustTransportUUIDv7(t), mustTransportUUIDv7(t)), service)
	path := workflowAdminPath(tenantID, workflowID)
	body := `{"expectedRevision":3,"displayName":"Updated workflow","description":"Reviewed"}`

	tests := []struct {
		name       string
		ifMatch    []string
		wantStatus int
		wantCalls  int
	}{
		{name: "missing", wantStatus: http.StatusPreconditionRequired, wantCalls: 0},
		{name: "weak", ifMatch: []string{`W/"v3"`}, wantStatus: http.StatusBadRequest, wantCalls: 0},
		{name: "duplicate", ifMatch: []string{applicationticketing.WorkflowAdminStrongETagFor(workflowID, 3), applicationticketing.WorkflowAdminStrongETagFor(workflowID, 3)}, wantStatus: http.StatusBadRequest, wantCalls: 0},
		{name: "different lineage", ifMatch: []string{applicationticketing.WorkflowAdminStrongETagFor(otherWorkflowID, 3)}, wantStatus: http.StatusPreconditionFailed, wantCalls: 0},
		{name: "different revision", ifMatch: []string{applicationticketing.WorkflowAdminStrongETagFor(workflowID, 2)}, wantStatus: http.StatusPreconditionFailed, wantCalls: 0},
		{name: "exact", ifMatch: []string{applicationticketing.WorkflowAdminStrongETagFor(workflowID, 3)}, wantStatus: http.StatusOK, wantCalls: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			calls = 0
			request := workflowAdminMutationRequest(http.MethodPatch, path, body)
			request.Header.Set(idempotencyKeyHeader, "workflow-update-0001")
			for _, value := range test.ifMatch {
				request.Header.Add(ifMatchHeader, value)
			}
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; body = %s", response.Code, test.wantStatus, response.Body.String())
			}
			if calls != test.wantCalls {
				t.Fatalf("service calls = %d, want %d", calls, test.wantCalls)
			}
			if response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("Cache-Control = %q", response.Header().Get("Cache-Control"))
			}
		})
	}
}

func TestWorkflowAdministrationRejectsCrossTenantBeforeBodyOrUseCase(t *testing.T) {
	t.Parallel()
	activeTenantID := mustTransportUUIDv7(t)
	pathTenantID := mustTransportUUIDv7(t)
	workflowID := mustTransportUUIDv7(t)
	var calls int
	service := &workflowAdminHTTPStub{
		transportWorkflowAdministrationStub: &transportWorkflowAdministrationStub{},
		metadataFn: func(context.Context, applicationticketing.Actor, uuid.UUID, uuid.UUID, applicationticketing.WorkflowMetadataInput) (applicationticketing.WorkflowAdminMutationResult, error) {
			calls++
			return applicationticketing.WorkflowAdminMutationResult{}, applicationticketing.ErrUnavailable
		},
	}
	router := newWorkflowAdminTestRouter(t, workflowAdminTransportAuthentication(activeTenantID, mustTransportUUIDv7(t), mustTransportUUIDv7(t)), service)
	request := workflowAdminMutationRequest(http.MethodPatch, workflowAdminPath(pathTenantID, workflowID), `{"expectedRevision":`)
	request.Header.Set(ifMatchHeader, applicationticketing.WorkflowAdminStrongETagFor(workflowID, 1))
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	assertProblem(t, response, http.StatusForbidden, "forbidden")
	if calls != 0 {
		t.Fatalf("service calls after cross-tenant denial = %d", calls)
	}
}

func TestWorkflowAdministrationSimulationCarriesTypedFactsAndExplainsResults(t *testing.T) {
	t.Parallel()
	tenantID := mustTransportUUIDv7(t)
	workflowID := mustTransportUUIDv7(t)
	definition := workflowAdminHTTPDefinition(t, workflowID)
	var calls int
	service := &workflowAdminHTTPStub{
		transportWorkflowAdministrationStub: &transportWorkflowAdministrationStub{},
		simulateFn: func(_ context.Context, actor applicationticketing.Actor, requestedTenant, requestedWorkflow uuid.UUID, input applicationticketing.WorkflowSimulationInput) (applicationticketing.WorkflowSimulationResult, error) {
			calls++
			if requestedTenant != tenantID || requestedWorkflow != workflowID || actor.Audit != (applicationticketing.AuditContext{}) {
				t.Fatalf("simulation identity/audit drifted: %#v/%s/%s", actor, requestedTenant, requestedWorkflow)
			}
			if input.Version != 1 || input.State.String() != "new" || !input.CommentPresent || len(input.Roles) != 1 || len(input.Permissions) != 1 || len(input.ProvidedCustomFields) != 1 {
				t.Fatalf("simulation input = %#v", input)
			}
			facts := input.Facts.Items()
			if len(facts) != 5 {
				t.Fatalf("typed facts = %d, want 5", len(facts))
			}
			seenKinds := make(map[string]string, len(facts))
			for _, fact := range facts {
				value, hasValue := fact.Value()
				if !hasValue {
					seenKinds[fact.Field().String()] = "presence"
					continue
				}
				seenKinds[fact.Field().String()] = value.Kind().String()
			}
			for field, want := range map[string]string{"custom.fact_boolean": "boolean", "custom.fact_instant": "instant", "custom.fact_number": "number", "custom.fact_present": "presence", "custom.fact_text": "text"} {
				if seenKinds[field] != want {
					t.Fatalf("fact %s kind = %q, want %q (all: %#v)", field, seenKinds[field], want, seenKinds)
				}
			}
			scenario, err := kernel.NewWorkflowSimulationScenario(input.State, input.CommentPresent, input.Roles, input.Permissions, input.ProvidedCustomFields, input.Facts)
			if err != nil {
				t.Fatalf("construct scenario: %v", err)
			}
			results, err := kernel.SimulateWorkflow(definition, scenario)
			if err != nil {
				t.Fatalf("simulate workflow: %v", err)
			}
			return applicationticketing.WorkflowSimulationResult{WorkflowID: workflowID, Kind: kernel.AggregateAlert, Version: 1, Results: results}, nil
		},
	}
	router := newWorkflowAdminTestRouter(t, workflowAdminTransportAuthentication(tenantID, mustTransportUUIDv7(t), mustTransportUUIDv7(t)), service)
	body := `{"version":1,"state":"new","commentPresent":true,"roles":["senior_analyst"],"permissions":["alert.update"],"providedCustomFields":["classification"],"facts":[{"field":"custom.fact_text","value":{"type":"text","value":"critical"}},{"field":"custom.fact_number","value":{"type":"number","value":42.5}},{"field":"custom.fact_boolean","value":{"type":"boolean","value":true}},{"field":"custom.fact_instant","value":{"type":"instant","value":"2026-08-26T10:00:00.123456Z"}},{"field":"custom.fact_present"}]}`
	request := workflowAdminMutationRequest(http.MethodPost, workflowAdminPath(tenantID, workflowID)+"/simulate", body)
	request.Header.Del(idempotencyKeyHeader)
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if calls != 1 {
		t.Fatalf("simulation calls = %d, want 1", calls)
	}
	var result contract.WorkflowSimulationResult
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !bool(result.Explanatory) || result.WorkflowId != workflowID || result.Version != 1 || len(result.Transitions) != 1 || !result.Transitions[0].Eligible {
		t.Fatalf("simulation response = %#v", result)
	}
}

func TestDecodeWorkflowBodyRejectsAmbiguousOrUnboundedJSON(t *testing.T) {
	t.Parallel()
	deep := strings.Repeat(`{"kind":"all","children":[`, maximumWorkflowJSONDepth+1) + `{"kind":"predicate","field":"severity","operator":"equal","values":[{"type":"text","value":"critical"}]}` + strings.Repeat(`]}`, maximumWorkflowJSONDepth+1)
	tests := []struct {
		name        string
		contentType string
		body        string
	}{
		{name: "wrong media type", contentType: "text/plain", body: `{"expectedRevision":1}`},
		{name: "duplicate member", contentType: "application/json", body: `{"expectedRevision":1,"expectedRevision":2}`},
		{name: "unknown member", contentType: "application/json", body: `{"expectedRevision":1,"opaque":"secret"}`},
		{name: "trailing value", contentType: "application/json", body: `{"expectedRevision":1}{}`},
		{name: "deep graph", contentType: "application/json", body: `{"version":1,"state":"new","commentPresent":false,"roles":[],"permissions":[],"providedCustomFields":[],"facts":[],"extra":` + deep + `}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(test.body))
			request.Header.Set("Content-Type", test.contentType)
			var destination workflowLifecycleBody
			if err := decodeWorkflowBody(request, &destination); err == nil {
				t.Fatal("decodeWorkflowBody() accepted hostile JSON")
			}
		})
	}
}

func TestWorkflowETagRevisionAcceptsOnlyCanonicalStrongTags(t *testing.T) {
	t.Parallel()
	workflowID := mustTransportUUIDv7(t)
	canonical := applicationticketing.WorkflowAdminStrongETagFor(workflowID, 17)
	if revision, err := workflowETagRevision(canonical); err != nil || revision != 17 {
		t.Fatalf("workflowETagRevision(%q) = %d, %v", canonical, revision, err)
	}
	for _, value := range []string{
		`W/` + canonical,
		`"v017-` + canonical[strings.IndexByte(canonical, '-')+1:],
		strings.TrimSuffix(canonical, `"`) + `=\"`,
		`"v17-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!"`,
		canonical + "," + canonical,
	} {
		if _, err := workflowETagRevision(value); err == nil {
			t.Fatalf("workflowETagRevision(%q) accepted non-canonical tag", value)
		}
	}
}

func newWorkflowAdminTestRouter(t testing.TB, auth AuthenticationService, service WorkflowAdministrationService) http.Handler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler, err := NewApplicationHandler(
		fixedChecker{ready: true}, logger, "test", time.Second,
		workflowAdminApplicationOptions(auth, service),
	)
	if err != nil {
		t.Fatalf("NewApplicationHandler() error = %v", err)
	}
	return Router(handler, logger, false)
}

func workflowAdminApplicationOptions(auth AuthenticationService, service WorkflowAdministrationService) ApplicationOptions {
	return ApplicationOptions{
		Alerts: &transportAlertStub{}, Audit: &transportSecurityAuditStub{}, Authentication: auth, Authorization: &transportAuthorizationStub{},
		Contacts: &transportContactStub{}, CustomFields: &transportCustomFieldStub{}, DFIR: &transportDFIRStub{}, Environment: "test",
		IdentityProviders: &transportIdentityProviderStub{}, LDAPAdministration: &transportLDAPAdministrationStub{}, MFA: &transportMFAStub{}, Notifications: &transportNotificationStub{},
		OperatorTeams: &transportOperatorTeamStub{}, Platform: &transportPlatformStub{}, PublicOrigin: "http://localhost:8081",
		ServiceAccounts: &transportServiceAccountStub{}, SLA: &transportSLAStub{}, Ticketing: &transportTicketingStub{}, WorkflowAdministration: service,
	}
}

func workflowAdminTransportAuthentication(tenantID, userID, sessionID uuid.UUID) *transportAuthStub {
	return &transportAuthStub{authenticateResult: authentication.Session{
		ID: sessionID, User: authentication.User{ID: userID}, ActiveTenantID: &tenantID, AuthenticationMethod: "totp",
	}}
}

func workflowAdminReadRequest(method, path, body string) *http.Request {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.AddCookie(&http.Cookie{Name: developmentCookie, Value: "opaque-session"})
	request.RemoteAddr = "198.51.100.42:4123"
	request.Header.Set("User-Agent", "workflow-http-test")
	return request
}

func workflowAdminMutationRequest(method, path, body string) *http.Request {
	request := workflowAdminReadRequest(method, path, body)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://localhost:8081")
	request.Header.Set(csrfTokenHeader, "csrf-value")
	request.Header.Set(idempotencyKeyHeader, "workflow-mutation-0001")
	return request
}

func workflowAdminPath(tenantID, workflowID uuid.UUID) string {
	return "/api/v1/tenants/" + tenantID.String() + "/workflows/" + workflowID.String()
}

func workflowAdminCreateBody() string {
	return `{"kind":"alert","key":"alert_response","displayName":"Alert response","description":"Governed workflow","design":{"states":[{"key":"new","initial":true,"terminal":false,"visibility":"customer","actions":[{"action":"create","effects":["activity","audit"]}]},{"key":"closed","initial":false,"terminal":true,"visibility":"customer","actions":[]}],"transitions":[{"key":"close_alert","from":"new","to":"closed","requiredComment":false,"reopen":false,"requiredRoles":[],"requiredPermissions":[],"requiredCustomFields":[],"effects":["activity","audit"]}]}}`
}

func workflowAdminHTTPRecord(t testing.TB, tenantID, workflowID uuid.UUID, revision uint64) applicationticketing.WorkflowAdminRecord {
	t.Helper()
	tenant, err := kernel.NewEntityID([16]byte(tenantID))
	if err != nil {
		t.Fatalf("tenant entity ID: %v", err)
	}
	definition := workflowAdminHTTPDefinition(t, workflowID)
	key, err := kernel.NewKey("alert_response")
	if err != nil {
		t.Fatalf("workflow key: %v", err)
	}
	managed, err := kernel.NewManagedWorkflow(tenant, key, "Alert response", "Governed workflow", false, kernel.WorkflowActive, revision, definition)
	if err != nil {
		t.Fatalf("managed workflow: %v", err)
	}
	now := time.Date(2026, time.August, 26, 10, 0, 0, 0, time.UTC)
	return applicationticketing.WorkflowAdminRecord{Workflow: managed, CreatedAt: now, UpdatedAt: now}
}

func workflowAdminHTTPDefinition(t testing.TB, workflowID uuid.UUID) kernel.WorkflowDefinition {
	t.Helper()
	effects, err := kernel.NewEffectPlan(kernel.EffectActivity, kernel.EffectAudit)
	if err != nil {
		t.Fatalf("effect plan: %v", err)
	}
	createAction, err := kernel.NewStateAction(kernel.ActionCreate, effects)
	if err != nil {
		t.Fatalf("create action: %v", err)
	}
	newKey, _ := kernel.NewKey("new")
	closedKey, _ := kernel.NewKey("closed")
	newState, err := kernel.NewStateDefinition(newKey, true, false, kernel.VisibilityCustomer, []kernel.StateAction{createAction})
	if err != nil {
		t.Fatalf("initial state: %v", err)
	}
	closedState, err := kernel.NewStateDefinition(closedKey, false, true, kernel.VisibilityCustomer, nil)
	if err != nil {
		t.Fatalf("terminal state: %v", err)
	}
	transitionKey, _ := kernel.NewKey("close_alert")
	transition, err := kernel.NewTransitionDefinition(transitionKey, newKey, closedKey, false, false, nil, nil, nil, effects)
	if err != nil {
		t.Fatalf("transition: %v", err)
	}
	workflowEntity, err := kernel.NewEntityID([16]byte(workflowID))
	if err != nil {
		t.Fatalf("workflow entity ID: %v", err)
	}
	definition, err := kernel.NewWorkflowDefinition(workflowEntity, kernel.AggregateAlert, 1, []kernel.StateDefinition{newState, closedState}, []kernel.TransitionDefinition{transition})
	if err != nil {
		t.Fatalf("workflow definition: %v", err)
	}
	return definition
}
