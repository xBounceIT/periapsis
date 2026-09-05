package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	applicationticketing "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

var _ contract.ServerInterface = (*Handler)(nil)

type transportTicketingStub struct {
	*applicationticketing.Service
	commentsFn        func(context.Context, applicationticketing.Actor, uuid.UUID, kernel.AggregateKind, uuid.UUID, applicationticketing.CursorPageInput, bool) (applicationticketing.CommentPage, error)
	addCommentFn      func(context.Context, applicationticketing.Actor, uuid.UUID, kernel.AggregateKind, uuid.UUID, applicationticketing.CommentInput, bool) (applicationticketing.Comment, applicationticketing.Projection, bool, error)
	previewCommentFn  func(context.Context, applicationticketing.Actor, uuid.UUID, kernel.AggregateKind, uuid.UUID, applicationticketing.CommentPreviewInput, bool) (applicationticketing.CommentPreview, error)
	candidatesFn      func(context.Context, applicationticketing.Actor, uuid.UUID, kernel.AggregateKind, uuid.UUID, applicationticketing.CommentMentionCandidateInput) (applicationticketing.CommentMentionCandidateList, error)
	editCommentFn     func(context.Context, applicationticketing.Actor, uuid.UUID, kernel.AggregateKind, uuid.UUID, uuid.UUID, applicationticketing.CommentEditInput, bool) (applicationticketing.Comment, applicationticketing.Projection, bool, error)
	revisionsFn       func(context.Context, applicationticketing.Actor, uuid.UUID, kernel.AggregateKind, uuid.UUID, uuid.UUID, applicationticketing.CommentRevisionPageInput, bool) (applicationticketing.CommentRevisionPage, error)
	getFn             func(context.Context, applicationticketing.Actor, uuid.UUID, kernel.AggregateKind, uuid.UUID) (applicationticketing.View, error)
	deleteFn          func(context.Context, applicationticketing.Actor, uuid.UUID, uuid.UUID, applicationticketing.DeleteAlertInput) (applicationticketing.DeleteAlertReceipt, error)
	exportFn          func(context.Context, applicationticketing.Actor, uuid.UUID, kernel.AggregateKind, uuid.UUID) (applicationticketing.CustomerPortalExport, error)
	mutateFn          func(context.Context, applicationticketing.Actor, uuid.UUID, kernel.AggregateKind, uuid.UUID, kernel.Action, applicationticketing.MutationInput) (applicationticketing.MutationResult, error)
	replaceMetadataFn func(context.Context, applicationticketing.Actor, uuid.UUID, kernel.AggregateKind, uuid.UUID, applicationticketing.MetadataReplaceInput) (applicationticketing.MetadataMutationResult, error)
	activityFeedFn    func(context.Context, applicationticketing.Actor, uuid.UUID, kernel.AggregateKind, applicationticketing.CursorPageInput) (applicationticketing.ActivityPage, error)
	getCalls          int
	deleteCalls       int
	exportCalls       int
	mutations         int
	metadataCalls     int
	commentCalls      int
	activityFeedCalls int
}

func (stub *transportTicketingStub) ActivityFeed(ctx context.Context, actor applicationticketing.Actor, tenantID uuid.UUID, kind kernel.AggregateKind, page applicationticketing.CursorPageInput) (applicationticketing.ActivityPage, error) {
	stub.activityFeedCalls++
	if stub.activityFeedFn == nil {
		return applicationticketing.ActivityPage{}, applicationticketing.ErrUnavailable
	}
	return stub.activityFeedFn(ctx, actor, tenantID, kind, page)
}

func TestTenantActivityFeedTransportBindsKindCursorAndOperatorProjection(t *testing.T) {
	tenantID := mustTransportUUIDv7(t)
	userID := mustTransportUUIDv7(t)
	resourceID := mustTransportUUIDv7(t)
	after := mustTransportUUIDv7(t)
	activityID := mustTransportUUIDv7(t)
	occurredAt := time.Date(2026, time.September, 2, 15, 3, 4, 123000000, time.UTC)
	tests := []struct {
		kind kernel.AggregateKind
		path string
	}{
		{kind: kernel.AggregateAlert, path: "alerts"},
		{kind: kernel.AggregateCase, path: "cases"},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			stub := &transportTicketingStub{activityFeedFn: func(
				_ context.Context,
				actor applicationticketing.Actor,
				requestedTenant uuid.UUID,
				kind kernel.AggregateKind,
				page applicationticketing.CursorPageInput,
			) (applicationticketing.ActivityPage, error) {
				if actor.UserID != userID || requestedTenant != tenantID || kind != test.kind ||
					page.After == nil || *page.After != after || page.Limit != 23 {
					t.Fatalf("activity feed input actor=%s tenant=%s kind=%v page=%+v", actor.UserID, requestedTenant, kind, page)
				}
				return applicationticketing.ActivityPage{
					Projection: applicationticketing.ProjectionOperator,
					Items: []applicationticketing.Activity{{
						ID: activityID, TenantID: tenantID, ResourceID: resourceID,
						ResourceKind: test.kind, Kind: "assigned", Summary: "Queue ownership changed",
						ActorKind: applicationticketing.ActivityActorHuman, ActorID: mustTransportUUIDv7(t),
						DisplayName: "Incident operator", Origin: "operator",
						Details: map[string]any{"team": "primary"}, OccurredAt: occurredAt,
					}},
				}, nil
			}}
			router := newTicketingTestRouter(t, tenantLDAPTransportAuthentication(tenantID, userID), stub)
			request := httptest.NewRequest(
				http.MethodGet,
				"/api/v1/tenants/"+tenantID.String()+"/activities/"+test.path+
					"?after="+after.String()+"&limit=23",
				nil,
			)
			prepareTenantLDAPTransportRequest(request, false)
			response := httptest.NewRecorder()

			router.ServeHTTP(response, request)

			if response.Code != http.StatusOK {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
			if stub.activityFeedCalls != 1 || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("calls=%d headers=%v", stub.activityFeedCalls, response.Header())
			}
			var body struct {
				Items []map[string]any `json:"items"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || len(body.Items) != 1 {
				t.Fatalf("decode activity feed: items=%v err=%v", body.Items, err)
			}
			item := body.Items[0]
			if item["projection"] != "operator" || item["resourceKind"] != test.kind.String() ||
				item["resourceId"] != resourceID.String() || item["kind"] != "assigned" {
				t.Fatalf("activity projection = %#v", item)
			}
		})
	}
}

func (stub *transportTicketingStub) ReplaceAlertMetadata(ctx context.Context, actor applicationticketing.Actor, tenantID, alertID uuid.UUID, input applicationticketing.MetadataReplaceInput) (applicationticketing.MetadataMutationResult, error) {
	return stub.replaceMetadata(ctx, actor, tenantID, kernel.AggregateAlert, alertID, input)
}

func (stub *transportTicketingStub) ReplaceCaseMetadata(ctx context.Context, actor applicationticketing.Actor, tenantID, caseID uuid.UUID, input applicationticketing.MetadataReplaceInput) (applicationticketing.MetadataMutationResult, error) {
	return stub.replaceMetadata(ctx, actor, tenantID, kernel.AggregateCase, caseID, input)
}

func (stub *transportTicketingStub) replaceMetadata(ctx context.Context, actor applicationticketing.Actor, tenantID uuid.UUID, kind kernel.AggregateKind, ticketID uuid.UUID, input applicationticketing.MetadataReplaceInput) (applicationticketing.MetadataMutationResult, error) {
	stub.metadataCalls++
	if stub.replaceMetadataFn == nil {
		return applicationticketing.MetadataMutationResult{}, applicationticketing.ErrUnavailable
	}
	return stub.replaceMetadataFn(ctx, actor, tenantID, kind, ticketID, input)
}

func (stub *transportTicketingStub) DeleteAlert(ctx context.Context, actor applicationticketing.Actor, tenantID, alertID uuid.UUID, input applicationticketing.DeleteAlertInput) (applicationticketing.DeleteAlertReceipt, error) {
	stub.deleteCalls++
	if stub.deleteFn == nil {
		return applicationticketing.DeleteAlertReceipt{}, applicationticketing.ErrUnavailable
	}
	return stub.deleteFn(ctx, actor, tenantID, alertID, input)
}

func TestAlertDeleteTransportBindsStrongVersionReasonAndReplayReceipt(t *testing.T) {
	tenantID := mustTransportUUIDv7(t)
	alertID := mustTransportUUIDv7(t)
	userID := mustTransportUUIDv7(t)
	deletedAt := time.Date(2026, time.August, 30, 18, 20, 0, 123000000, time.UTC)
	var captured applicationticketing.DeleteAlertInput
	stub := &transportTicketingStub{deleteFn: func(
		_ context.Context,
		actor applicationticketing.Actor,
		requestedTenant, requestedAlert uuid.UUID,
		input applicationticketing.DeleteAlertInput,
	) (applicationticketing.DeleteAlertReceipt, error) {
		if requestedTenant != tenantID || requestedAlert != alertID || actor.UserID != userID {
			t.Fatalf("unexpected delete target or actor")
		}
		captured = input
		return applicationticketing.DeleteAlertReceipt{
			TenantID: tenantID, AlertID: alertID, PreviousVersion: 7,
			TombstoneVersion: 8, DeletedAt: deletedAt, Replayed: true,
		}, nil
	}}
	router := newTicketingTestRouter(t, tenantLDAPTransportAuthentication(tenantID, userID), stub)
	request := ticketingMutationRequest(
		http.MethodDelete,
		"/api/v1/tenants/"+tenantID.String()+"/alerts/"+alertID.String(),
		`{"expectedVersion":7,"reason":"False positive confirmed."}`,
	)
	request.Header.Set(ifMatchHeader, `"v7"`)
	request.Header.Set(idempotencyKeyHeader, "delete-alert-key-0001")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if response.Header().Get("ETag") != `"v8"` || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("headers = %#v", response.Header())
	}
	if captured.ExpectedVersion != 7 || captured.Reason != "False positive confirmed." || captured.IdempotencyKey != "delete-alert-key-0001" {
		t.Fatalf("delete input = %+v", captured)
	}
	var receipt contract.AlertDeleteReceipt
	if err := json.Unmarshal(response.Body.Bytes(), &receipt); err != nil {
		t.Fatalf("decode receipt: %v", err)
	}
	if receipt.TenantId != tenantID || receipt.AlertId != alertID || receipt.PreviousVersion != 7 ||
		receipt.TombstoneVersion != 8 || !receipt.DeletedAt.Equal(deletedAt) || !receipt.Replayed {
		t.Fatalf("receipt = %+v", receipt)
	}
}

func TestAlertDeleteTransportRejectsAmbiguousOrStaleRequestsBeforeUseCase(t *testing.T) {
	tenantID := mustTransportUUIDv7(t)
	alertID := mustTransportUUIDv7(t)
	userID := mustTransportUUIDv7(t)
	tests := []struct {
		name           string
		body           string
		ifMatch        string
		idempotencyKey string
	}{
		{name: "version mismatch", body: `{"expectedVersion":2,"reason":"Duplicate."}`, ifMatch: `"v1"`, idempotencyKey: "delete-alert-key-0002"},
		{name: "unknown field", body: `{"expectedVersion":1,"reason":"Duplicate.","hard":true}`, ifMatch: `"v1"`, idempotencyKey: "delete-alert-key-0003"},
		{name: "weak validator", body: `{"expectedVersion":1,"reason":"Duplicate."}`, ifMatch: `W/"v1"`, idempotencyKey: "delete-alert-key-0004"},
		{name: "folded key", body: `{"expectedVersion":1,"reason":"Duplicate."}`, ifMatch: `"v1"`, idempotencyKey: "delete-alert-key-0005,delete-alert-key-0006"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stub := &transportTicketingStub{}
			router := newTicketingTestRouter(t, tenantLDAPTransportAuthentication(tenantID, userID), stub)
			request := ticketingMutationRequest(http.MethodDelete, "/api/v1/tenants/"+tenantID.String()+"/alerts/"+alertID.String(), test.body)
			request.Header.Set(ifMatchHeader, test.ifMatch)
			request.Header.Set(idempotencyKeyHeader, test.idempotencyKey)
			response := httptest.NewRecorder()

			router.ServeHTTP(response, request)

			assertProblem(t, response, http.StatusBadRequest, "invalid_request")
			if stub.deleteCalls != 0 {
				t.Fatalf("delete calls = %d, want 0", stub.deleteCalls)
			}
		})
	}
}

func TestAlertDeleteTransportRequiresIfMatchBeforeUseCase(t *testing.T) {
	tenantID := mustTransportUUIDv7(t)
	alertID := mustTransportUUIDv7(t)
	userID := mustTransportUUIDv7(t)
	stub := &transportTicketingStub{}
	router := newTicketingTestRouter(t, tenantLDAPTransportAuthentication(tenantID, userID), stub)
	request := ticketingMutationRequest(
		http.MethodDelete,
		"/api/v1/tenants/"+tenantID.String()+"/alerts/"+alertID.String(),
		`{"expectedVersion":1,"reason":"Duplicate alert."}`,
	)
	request.Header.Del(ifMatchHeader)
	request.Header.Set(idempotencyKeyHeader, "delete-alert-key-0007")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	assertProblem(t, response, http.StatusPreconditionRequired, "precondition_required")
	if stub.deleteCalls != 0 {
		t.Fatalf("delete calls = %d, want 0", stub.deleteCalls)
	}
}

func (stub *transportTicketingStub) Get(ctx context.Context, actor applicationticketing.Actor, tenantID uuid.UUID, kind kernel.AggregateKind, id uuid.UUID) (applicationticketing.View, error) {
	stub.getCalls++
	if stub.getFn == nil {
		return applicationticketing.View{}, applicationticketing.ErrUnavailable
	}
	return stub.getFn(ctx, actor, tenantID, kind, id)
}

func (stub *transportTicketingStub) Mutate(ctx context.Context, actor applicationticketing.Actor, tenantID uuid.UUID, kind kernel.AggregateKind, id uuid.UUID, action kernel.Action, input applicationticketing.MutationInput) (applicationticketing.MutationResult, error) {
	stub.mutations++
	if stub.mutateFn == nil {
		return applicationticketing.MutationResult{}, applicationticketing.ErrUnavailable
	}
	return stub.mutateFn(ctx, actor, tenantID, kind, id, action, input)
}

func (stub *transportTicketingStub) ExportPortal(ctx context.Context, actor applicationticketing.Actor, tenantID uuid.UUID, kind kernel.AggregateKind, id uuid.UUID) (applicationticketing.CustomerPortalExport, error) {
	stub.exportCalls++
	if stub.exportFn == nil {
		return applicationticketing.CustomerPortalExport{}, applicationticketing.ErrUnavailable
	}
	return stub.exportFn(ctx, actor, tenantID, kind, id)
}

func TestTicketTransitionTransportRejectsHostileBodiesBeforeUseCase(t *testing.T) {
	tenantID := mustTransportUUIDv7(t)
	alertID := mustTransportUUIDv7(t)
	userID := mustTransportUUIDv7(t)
	tests := []struct {
		name    string
		body    string
		ifMatch string
		want    int
	}{
		{name: "unknown field", body: `{"expectedVersion":1,"transitionKey":"close_alert","targetStateKey":"closed","unexpected":true}`, ifMatch: `"v1"`, want: http.StatusBadRequest},
		{name: "duplicate field", body: `{"expectedVersion":1,"transitionKey":"close_alert","transitionKey":"other","targetStateKey":"closed"}`, ifMatch: `"v1"`, want: http.StatusBadRequest},
		{name: "missing transition key", body: `{"expectedVersion":1,"targetStateKey":"closed"}`, ifMatch: `"v1"`, want: http.StatusBadRequest},
		{name: "nested custom field", body: `{"expectedVersion":1,"transitionKey":"close_alert","targetStateKey":"closed","customFields":{"nested":{"value":"hidden"}}}`, ifMatch: `"v1"`, want: http.StatusBadRequest},
		{name: "incoherent expected version", body: `{"expectedVersion":2,"transitionKey":"close_alert","targetStateKey":"closed"}`, ifMatch: `"v1"`, want: http.StatusBadRequest},
		{name: "version above contract maximum", body: `{"expectedVersion":2147483648,"transitionKey":"close_alert","targetStateKey":"closed"}`, ifMatch: `"v2147483648"`, want: http.StatusBadRequest},
		{name: "weak validator", body: `{"expectedVersion":1,"transitionKey":"close_alert","targetStateKey":"closed"}`, ifMatch: `W/"v1"`, want: http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stub := &transportTicketingStub{}
			router := newTicketingTestRouter(t, tenantLDAPTransportAuthentication(tenantID, userID), stub)
			request := ticketingMutationRequest(
				http.MethodPost,
				"/api/v1/tenants/"+tenantID.String()+"/alerts/"+alertID.String()+"/transition",
				test.body,
			)
			request.Header.Set(ifMatchHeader, test.ifMatch)
			request.Header.Set(idempotencyKeyHeader, "transition-key-0001")
			response := httptest.NewRecorder()

			router.ServeHTTP(response, request)

			assertProblem(t, response, test.want, "invalid_request")
			if stub.mutations != 0 {
				t.Fatalf("use case calls = %d, want 0", stub.mutations)
			}
		})
	}
}

func TestExplicitCloseAndReopenTransportRoutesBindServerIntent(t *testing.T) {
	tests := []struct {
		name       string
		kind       kernel.AggregateKind
		resource   string
		action     string
		transition string
		target     string
		intent     kernel.TransitionIntent
	}{
		{name: "close Alert", kind: kernel.AggregateAlert, resource: "alerts", action: "close", transition: "close_alert", target: "closed", intent: kernel.TransitionIntentClose},
		{name: "reopen Alert", kind: kernel.AggregateAlert, resource: "alerts", action: "reopen", transition: "reopen_alert", target: "new", intent: kernel.TransitionIntentReopen},
		{name: "close Case", kind: kernel.AggregateCase, resource: "cases", action: "close", transition: "close_case", target: "closed", intent: kernel.TransitionIntentClose},
		{name: "reopen Case", kind: kernel.AggregateCase, resource: "cases", action: "reopen", transition: "reopen_case", target: "open", intent: kernel.TransitionIntentReopen},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tenantID := mustTransportUUIDv7(t)
			ticketID := mustTransportUUIDv7(t)
			userID := mustTransportUUIDv7(t)
			view := transportTicketViewForKind(
				t, tenantID, ticketID, userID, 8, applicationticketing.ProjectionOperator, test.kind,
			)
			stub := &transportTicketingStub{mutateFn: func(
				_ context.Context,
				actor applicationticketing.Actor,
				requestedTenant uuid.UUID,
				kind kernel.AggregateKind,
				requestedID uuid.UUID,
				action kernel.Action,
				input applicationticketing.MutationInput,
			) (applicationticketing.MutationResult, error) {
				if actor.UserID != userID || requestedTenant != tenantID || requestedID != ticketID ||
					kind != test.kind || action != kernel.ActionTransition || input.ExpectedVersion != 7 ||
					input.TransitionIntent != test.intent || input.TransitionKey != test.transition ||
					input.TargetStateKey != test.target || input.Comment != "Workflow intent verified." ||
					input.IdempotencyKey != "explicit-transition-key-0001" || input.CustomFields["classification"] != "malware" {
					t.Fatalf("unexpected mutation actor/target/input: %+v %s/%s/%s/%s %+v", actor, requestedTenant, requestedID, kind, action, input)
				}
				return applicationticketing.MutationResult{View: view, Effects: []string{"activity", "audit"}}, nil
			}}
			router := newTicketingTestRouter(t, tenantLDAPTransportAuthentication(tenantID, userID), stub)
			body := `{"expectedVersion":7,"transitionKey":"` + test.transition +
				`","targetStateKey":"` + test.target +
				`","comment":"Workflow intent verified.","customFields":{"classification":"malware"}}`
			request := ticketingMutationRequest(
				http.MethodPost,
				"/api/v1/tenants/"+tenantID.String()+"/"+test.resource+"/"+ticketID.String()+"/"+test.action,
				body,
			)
			request.Header.Set(ifMatchHeader, `"v7"`)
			request.Header.Set(idempotencyKeyHeader, "explicit-transition-key-0001")
			response := httptest.NewRecorder()

			router.ServeHTTP(response, request)

			if response.Code != http.StatusOK || response.Header().Get("ETag") != `"v8"` || stub.mutations != 1 {
				t.Fatalf("response status=%d ETag=%q calls=%d body=%s", response.Code, response.Header().Get("ETag"), stub.mutations, response.Body.String())
			}
		})
	}
}

func TestExplicitTransitionRoutesRejectMissingSecurityAndConcurrencyInputs(t *testing.T) {
	tenantID := mustTransportUUIDv7(t)
	ticketID := mustTransportUUIDv7(t)
	userID := mustTransportUUIDv7(t)
	basePath := "/api/v1/tenants/" + tenantID.String()
	validBody := `{"expectedVersion":7,"transitionKey":"close_alert","targetStateKey":"closed"}`
	tests := []struct {
		name       string
		path       string
		mutate     func(*http.Request)
		wantStatus int
		wantCode   string
	}{
		{name: "close Alert requires CSRF", path: basePath + "/alerts/" + ticketID.String() + "/close", mutate: func(request *http.Request) { request.Header.Del(csrfTokenHeader) }, wantStatus: http.StatusForbidden, wantCode: "forbidden"},
		{name: "reopen Alert requires If-Match", path: basePath + "/alerts/" + ticketID.String() + "/reopen", mutate: func(request *http.Request) { request.Header.Del(ifMatchHeader) }, wantStatus: http.StatusPreconditionRequired, wantCode: "precondition_required"},
		{name: "close Case requires idempotency", path: basePath + "/cases/" + ticketID.String() + "/close", mutate: func(request *http.Request) { request.Header.Del(idempotencyKeyHeader) }, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "reopen Case binds body to If-Match", path: basePath + "/cases/" + ticketID.String() + "/reopen", mutate: func(request *http.Request) { request.Header.Set(ifMatchHeader, `"v8"`) }, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stub := &transportTicketingStub{}
			router := newTicketingTestRouter(t, tenantLDAPTransportAuthentication(tenantID, userID), stub)
			request := ticketingMutationRequest(http.MethodPost, test.path, validBody)
			request.Header.Set(ifMatchHeader, `"v7"`)
			request.Header.Set(idempotencyKeyHeader, "explicit-transition-key-0002")
			test.mutate(request)
			response := httptest.NewRecorder()

			router.ServeHTTP(response, request)

			assertProblem(t, response, test.wantStatus, test.wantCode)
			if stub.mutations != 0 {
				t.Fatalf("use case calls = %d, want 0", stub.mutations)
			}
		})
	}
}

func TestEscalationTargetDiscriminatorsMatchCanonicalContract(t *testing.T) {
	alertID := mustTransportUUIDv7(t)
	caseID := mustTransportUUIDv7(t)
	body := escalationRequestBody{
		ExpectedVersion: 1, Reason: "Correlated investigation", RelationType: contract.AlertCaseRelationTypeEscalation,
		Sources: []escalationSourceBody{{
			AlertID: alertID, ExpectedVersion: 1, CopySelection: escalationCopySelectionBody{},
		}},
		Target: escalationTargetBody{
			Mode: "create_case",
			Case: &contract.CaseCreateRequest{
				Title: "Investigation", Severity: contract.AlertSeverityHigh, Priority: contract.TicketPriorityHigh,
			},
		},
	}
	input, createsCase, err := escalationInput(body, alertID, 1, "escalation-key-0001")
	if err != nil || !createsCase || input.Target.NewCase == nil {
		t.Fatalf("create_case input = (%+v, %t, %v)", input, createsCase, err)
	}

	existingVersion := int64(3)
	body.Target = escalationTargetBody{Mode: "existing_case", CaseID: &caseID, ExpectedVersion: &existingVersion}
	input, createsCase, err = escalationInput(body, alertID, 1, "escalation-key-0001")
	if err != nil || createsCase || input.Target.ExistingCaseID == nil || *input.Target.ExistingCaseID != caseID {
		t.Fatalf("existing_case input = (%+v, %t, %v)", input, createsCase, err)
	}

	body.Target.Mode = "new"
	if _, _, err := escalationInput(body, alertID, 1, "escalation-key-0001"); !errors.Is(err, applicationticketing.ErrInvalidInput) {
		t.Fatalf("legacy discriminator error = %v, want invalid input", err)
	}
}

func TestTicketingSurfaceRequiresRepositoryAtStartup(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	_, err := NewApplicationHandler(
		fixedChecker{ready: true}, logger, "test", time.Second,
		ApplicationOptions{
			Alerts: &transportAlertStub{}, Audit: &transportSecurityAuditStub{}, Authentication: &transportAuthStub{}, Authorization: &transportAuthorizationStub{},
			Contacts: &transportContactStub{}, CustomFields: &transportCustomFieldStub{}, DFIR: &transportDFIRStub{},
			Environment: "test", IdentityProviders: &transportIdentityProviderStub{}, LDAPAdministration: &transportLDAPAdministrationStub{},
			Notifications: &transportNotificationStub{}, OperatorTeams: &transportOperatorTeamStub{}, Platform: &transportPlatformStub{},
			PublicOrigin: "http://localhost:8081", ServiceAccounts: &transportServiceAccountStub{},
		},
	)
	if err == nil || !strings.Contains(err.Error(), "ticketing") {
		t.Fatalf("NewApplicationHandler() error = %v, want missing ticketing boundary", err)
	}
}

func TestTicketAssignmentTransportCarriesAuditAndStrongVersion(t *testing.T) {
	tenantID := mustTransportUUIDv7(t)
	alertID := mustTransportUUIDv7(t)
	teamID := mustTransportUUIDv7(t)
	userID := mustTransportUUIDv7(t)
	requestID := mustTransportUUIDv7(t)
	view := transportTicketView(t, tenantID, alertID, userID, 2, applicationticketing.ProjectionOperator)
	var capturedActor applicationticketing.Actor
	var capturedInput applicationticketing.MutationInput
	stub := &transportTicketingStub{mutateFn: func(
		_ context.Context,
		actor applicationticketing.Actor,
		requestedTenant uuid.UUID,
		kind kernel.AggregateKind,
		requestedID uuid.UUID,
		action kernel.Action,
		input applicationticketing.MutationInput,
	) (applicationticketing.MutationResult, error) {
		if requestedTenant != tenantID || requestedID != alertID || kind != kernel.AggregateAlert || action != kernel.ActionAssign {
			t.Fatalf("unexpected target %s/%s/%s/%s", requestedTenant, requestedID, kind, action)
		}
		capturedActor = actor
		capturedInput = input
		return applicationticketing.MutationResult{View: view, Effects: []string{"activity", "audit"}}, nil
	}}
	router := newTicketingTestRouter(t, tenantLDAPTransportAuthentication(tenantID, userID), stub)
	body := `{"assignedTeamId":"` + teamID.String() + `","expectedVersion":1}`
	request := ticketingMutationRequest(http.MethodPost, "/api/v1/tenants/"+tenantID.String()+"/alerts/"+alertID.String()+"/assign", body)
	request.Header.Set(ifMatchHeader, `"v1"`)
	request.Header.Set(requestIDHeader, requestID.String())
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", response.Code, response.Body.String())
	}
	if response.Header().Get("ETag") != `"v2"` {
		t.Fatalf("ETag = %q, want v2", response.Header().Get("ETag"))
	}
	if capturedActor.Audit.RequestID != requestID || capturedActor.Audit.RemoteAddress.String() != "198.51.100.42" ||
		capturedInput.ExpectedVersion != 1 || capturedInput.TeamID == nil || *capturedInput.TeamID != teamID {
		t.Fatalf("captured actor/input = %#v / %#v", capturedActor, capturedInput)
	}
}

func TestCustomerTicketProjectionStructurallyOmitsOperatorFields(t *testing.T) {
	tenantID := mustTransportUUIDv7(t)
	alertID := mustTransportUUIDv7(t)
	creatorID := mustTransportUUIDv7(t)
	view := transportTicketView(t, tenantID, alertID, creatorID, 1, applicationticketing.ProjectionCustomer)
	classification := "restricted"
	view.Record.Classification = &classification
	view.Record.RawPayload = map[string]any{"credential": "must-not-leak"}
	view.Record.CustomFields = map[string]any{"internal_key": "must-not-leak"}
	view.Record.CustomerCustomFields = map[string]any{"public_key": "safe"}

	mapped, err := mapTicketView(view)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(mapped)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	for _, forbidden := range []string{"rawPayload", "classification", "assignment", "creator", "internal_key", "credential", creatorID.String()} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("customer projection leaked %q: %s", forbidden, text)
		}
	}
	if !strings.Contains(text, `"projection":"customer"`) || !strings.Contains(text, `"public_key":"safe"`) {
		t.Fatalf("customer projection missing safe fields: %s", text)
	}
}

func TestOperatorActivityActorsPreserveClosedTenantScopedIdentities(t *testing.T) {
	tenantID := mustTransportUUIDv7(t)
	now := time.Date(2026, 8, 25, 11, 0, 0, 0, time.UTC)
	tests := []struct {
		name      string
		activity  applicationticketing.Activity
		required  map[string]any
		forbidden []string
	}{
		{
			name: "service-account Alert activity",
			activity: applicationticketing.Activity{
				ID: mustTransportUUIDv7(t), TenantID: tenantID, ResourceID: mustTransportUUIDv7(t),
				ResourceKind: kernel.AggregateAlert, Kind: "created", Summary: "Alert created",
				ActorKind: applicationticketing.ActivityActorServiceAccount, ActorID: mustTransportUUIDv7(t),
				DisplayName: "EDR ingest", Origin: "operator", OccurredAt: now,
			},
			required:  map[string]any{"principalType": "service_account"},
			forbidden: []string{"membershipId"},
		},
		{
			name: "human Case activity",
			activity: applicationticketing.Activity{
				ID: mustTransportUUIDv7(t), TenantID: tenantID, ResourceID: mustTransportUUIDv7(t),
				ResourceKind: kernel.AggregateCase, Kind: "transitioned", Summary: "Case transitioned",
				ActorKind: applicationticketing.ActivityActorHuman, ActorID: mustTransportUUIDv7(t),
				DisplayName: "Analyst", Origin: "operator", OccurredAt: now,
			},
			required:  map[string]any{},
			forbidden: []string{"principalType", "serviceAccountId"},
		},
		{
			name: "system activity",
			activity: applicationticketing.Activity{
				ID: mustTransportUUIDv7(t), TenantID: tenantID, ResourceID: mustTransportUUIDv7(t),
				ResourceKind: kernel.AggregateCase, Kind: "sla_breached", Summary: "SLA breached",
				ActorKind: applicationticketing.ActivityActorSystem, DisplayName: "System",
				Origin: "operator", OccurredAt: now,
			},
			required:  map[string]any{"principalType": "system"},
			forbidden: []string{"membershipId", "serviceAccountId"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mapped := mapActivityPage(applicationticketing.ActivityPage{
				Items: []applicationticketing.Activity{test.activity}, Projection: applicationticketing.ProjectionOperator,
			})
			items := mapped["items"].([]any)
			actor := items[0].(map[string]any)["actor"].(map[string]any)
			for key, value := range test.required {
				if actor[key] != value {
					t.Fatalf("actor[%q] = %#v, want %#v", key, actor[key], value)
				}
			}
			for _, key := range test.forbidden {
				if _, exists := actor[key]; exists {
					t.Fatalf("actor unexpectedly contains %q: %#v", key, actor)
				}
			}
			if test.activity.ActorKind == applicationticketing.ActivityActorHuman && actor["membershipId"] != test.activity.ActorID {
				t.Fatalf("human actor membershipId = %#v, want %s", actor["membershipId"], test.activity.ActorID)
			}
			if test.activity.ActorKind == applicationticketing.ActivityActorServiceAccount && actor["serviceAccountId"] != test.activity.ActorID {
				t.Fatalf("service actor serviceAccountId = %#v, want %s", actor["serviceAccountId"], test.activity.ActorID)
			}
		})
	}
}

func newTicketingTestRouter(t *testing.T, auth AuthenticationService, ticketing TicketingService) http.Handler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler, err := NewApplicationHandler(
		fixedChecker{ready: true}, logger, "test", time.Second,
		ApplicationOptions{
			Alerts: &transportAlertStub{}, Audit: &transportSecurityAuditStub{}, Authentication: auth, Authorization: &transportAuthorizationStub{},
			Contacts: &transportContactStub{}, CustomFields: &transportCustomFieldStub{}, DFIR: &transportDFIRStub{},
			Environment: "test", IdentityProviders: &transportIdentityProviderStub{}, LDAPAdministration: &transportLDAPAdministrationStub{}, MFA: &transportMFAStub{}, Notifications: &transportNotificationStub{}, OperatorTeams: &transportOperatorTeamStub{}, Platform: &transportPlatformStub{},
			PublicOrigin: "http://localhost:8081", ServiceAccounts: &transportServiceAccountStub{}, SLA: &transportSLAStub{}, Ticketing: ticketing, WorkflowAdministration: &transportWorkflowAdministrationStub{},
		},
	)
	if err != nil {
		t.Fatalf("NewApplicationHandler() error = %v", err)
	}
	return Router(handler, logger, false)
}

func ticketingMutationRequest(method, path, body string) *http.Request {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	prepareTenantLDAPTransportRequest(request, true)
	request.Header.Set("Content-Type", "application/json")
	return request
}

func transportTicketView(t testing.TB, tenantUUID, ticketUUID, creatorUUID uuid.UUID, version uint64, projection applicationticketing.Projection) applicationticketing.View {
	return transportTicketViewForKind(
		t, tenantUUID, ticketUUID, creatorUUID, version, projection, kernel.AggregateAlert,
	)
}

func transportTicketViewForKind(
	t testing.TB,
	tenantUUID, ticketUUID, creatorUUID uuid.UUID,
	version uint64,
	projection applicationticketing.Projection,
	kind kernel.AggregateKind,
) applicationticketing.View {
	t.Helper()
	tenant, _ := kernel.NewEntityID([16]byte(tenantUUID))
	ticket, _ := kernel.NewEntityID([16]byte(ticketUUID))
	workflowID, _ := kernel.NewEntityID([16]byte(mustTransportUUIDv7(t)))
	initialState := "new"
	closeTransition := "close_alert"
	if kind == kernel.AggregateCase {
		initialState = "open"
		closeTransition = "close_case"
	}
	newKey, _ := kernel.NewKey(initialState)
	closedKey, _ := kernel.NewKey("closed")
	effects, _ := kernel.NewEffectPlan(kernel.EffectActivity, kernel.EffectAudit)
	create, _ := kernel.NewStateAction(kernel.ActionCreate, effects)
	assign, _ := kernel.NewStateAction(kernel.ActionAssign, effects)
	newState, _ := kernel.NewStateDefinition(newKey, true, false, kernel.VisibilityCustomer, []kernel.StateAction{create, assign})
	closedState, _ := kernel.NewStateDefinition(closedKey, false, true, kernel.VisibilityCustomer, nil)
	transitionKey, _ := kernel.NewKey(closeTransition)
	transition, _ := kernel.NewTransitionDefinition(transitionKey, newKey, closedKey, false, false, nil, nil, nil, effects)
	workflow, err := kernel.NewWorkflowDefinition(workflowID, kind, 1, []kernel.StateDefinition{newState, closedState}, []kernel.TransitionDefinition{transition})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := kernel.NewTicketSnapshot(workflow, tenant, ticket, newKey, version, true, kernel.Assignment{})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC)
	return applicationticketing.View{Projection: projection, Record: applicationticketing.Record{
		Workflow: workflow, Snapshot: snapshot, Number: "ALT-000001", Title: "Alert",
		Description: "Description", Severity: "high", Priority: "urgent", Category: "security",
		Source: "sensor", SourceType: "edr", Tags: []string{}, CustomFields: map[string]any{},
		CustomerCustomFields: map[string]any{}, Creator: applicationticketing.Creator{
			Kind: kernel.PrincipalOperator, ID: creatorUUID, UserID: &creatorUUID, DisplayName: "Operator",
		},
		DetectedAt: now, ReceivedAt: now, CreatedAt: now, UpdatedAt: now,
	}}
}

func mustTransportUUIDv7(t testing.TB) uuid.UUID {
	t.Helper()
	value, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	return value
}
