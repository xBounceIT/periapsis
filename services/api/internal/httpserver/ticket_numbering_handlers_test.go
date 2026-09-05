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
	"github.com/periapsis-im/periapsis/services/api/internal/ticketnumbering"
)

type ticketNumberingHTTPStub struct {
	getCalls       int
	getSession     authentication.Session
	getTenant      uuid.UUID
	getKind        kernel.AggregateKind
	getResult      kernel.NumberingPolicy
	getError       error
	previewCalls   int
	previewSession authentication.Session
	previewTenant  uuid.UUID
	previewKind    kernel.AggregateKind
	previewDraft   ticketnumbering.PolicyDraft
	previewResult  ticketnumbering.Preview
	previewError   error
	replaceCalls   int
	replaceSession authentication.Session
	replaceTenant  uuid.UUID
	replaceKind    kernel.AggregateKind
	replaceInput   ticketnumbering.ReplaceInput
	replaceResult  ticketnumbering.ReplaceResult
	replaceError   error
}

func (stub *ticketNumberingHTTPStub) Get(
	_ context.Context,
	session authentication.Session,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
) (kernel.NumberingPolicy, error) {
	stub.getCalls++
	stub.getSession, stub.getTenant, stub.getKind = session, tenantID, kind
	return stub.getResult, stub.getError
}

func (stub *ticketNumberingHTTPStub) Preview(
	_ context.Context,
	session authentication.Session,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	draft ticketnumbering.PolicyDraft,
) (ticketnumbering.Preview, error) {
	stub.previewCalls++
	stub.previewSession, stub.previewTenant, stub.previewKind = session, tenantID, kind
	stub.previewDraft = draft
	return stub.previewResult, stub.previewError
}

func (stub *ticketNumberingHTTPStub) Replace(
	_ context.Context,
	session authentication.Session,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	input ticketnumbering.ReplaceInput,
) (ticketnumbering.ReplaceResult, error) {
	stub.replaceCalls++
	stub.replaceSession, stub.replaceTenant, stub.replaceKind = session, tenantID, kind
	stub.replaceInput = input
	return stub.replaceResult, stub.replaceError
}

func TestTicketNumberingReadMapsSystemPolicyWithStrongETag(t *testing.T) {
	t.Parallel()
	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	policy := ticketNumberingHTTPPolicy(t, tenantID, kernel.AggregateAlert, 1, true)
	service := &ticketNumberingHTTPStub{getResult: policy}
	request := ticketNumberingHTTPRequest(http.MethodGet, tenantID, "alert", "", false)
	response := httptest.NewRecorder()

	newTicketNumberingTestRouter(
		t, groupTransportAuthentication(tenantID, userID), service,
	).ServeHTTP(response, request)

	if response.Code != http.StatusOK || service.getCalls != 1 ||
		service.getTenant != tenantID || service.getKind != kernel.AggregateAlert ||
		service.getSession.User.ID != userID {
		t.Fatalf("status/service = %d/%#v: %s", response.Code, service, response.Body.String())
	}
	if response.Header().Get("ETag") != `"v1"` ||
		response.Header().Get("Cache-Control") != "private, no-store" {
		t.Fatalf("headers = %#v", response.Header())
	}
	var body contract.TicketNumberingPolicy
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.TenantId != tenantID || body.Kind != contract.TicketNumberingKindAlert ||
		body.Version != 1 || body.Prefix != "ALT" || body.Separator != "-" ||
		body.Period != contract.Annual || body.Width != 6 || body.Start != 1 ||
		body.Publisher.Type != contract.TicketNumberingPublisherTypeSystem ||
		body.Publisher.MembershipId != nil {
		t.Fatalf("body = %#v", body)
	}
}

func TestTicketNumberingPreviewRouteIsCSRFProtectedAndSideEffectFree(t *testing.T) {
	t.Parallel()
	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	at := time.Date(2026, time.September, 3, 12, 0, 0, 123_456_000, time.UTC)
	service := &ticketNumberingHTTPStub{previewResult: ticketnumbering.Preview{
		TenantID: tenantID, Kind: kernel.AggregateCase, Prefix: "CASE", Separator: "/",
		Period: kernel.NumberingPeriodNone, Width: 8, Start: 100,
		MaximumSequence: 99_999_999, At: at, PeriodKey: 0, Example: "CASE/00000100",
	}}
	auth := groupTransportAuthentication(tenantID, userID)
	request := ticketNumberingHTTPRequest(
		http.MethodPost, tenantID, "case/preview",
		`{"prefix":" case ","separator":" / ","period":"lifetime","width":8,"start":100}`,
		true,
	)
	response := httptest.NewRecorder()

	newTicketNumberingTestRouter(t, auth, service).ServeHTTP(response, request)

	if response.Code != http.StatusOK || service.previewCalls != 1 || service.getCalls != 0 ||
		service.replaceCalls != 0 || auth.csrfCalls != 1 || service.previewTenant != tenantID ||
		service.previewKind != kernel.AggregateCase || service.previewSession.User.ID != userID {
		t.Fatalf("status/service/csrf = %d/%#v/%d: %s", response.Code, service, auth.csrfCalls, response.Body.String())
	}
	if service.previewDraft.Prefix != " case " || service.previewDraft.Separator != " / " ||
		service.previewDraft.Period != kernel.NumberingPeriodNone ||
		service.previewDraft.Width != 8 || service.previewDraft.Start != 100 {
		t.Fatalf("draft = %#v", service.previewDraft)
	}
	var body contract.TicketNumberingPreview
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil ||
		body.Example != "CASE/00000100" || body.Period != contract.Lifetime ||
		body.PeriodKey != 0 || body.MaximumSequence != 99_999_999 {
		t.Fatalf("body = %#v, err = %v", body, err)
	}
}

func TestTicketNumberingUpdateBindsCASIdempotencyAuditAndReplay(t *testing.T) {
	t.Parallel()
	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	requestID := uuid.Must(uuid.NewV7())
	policy := ticketNumberingHTTPPolicy(t, tenantID, kernel.AggregateCase, 8, false)
	service := &ticketNumberingHTTPStub{replaceResult: ticketnumbering.ReplaceResult{
		Policy: policy, Replayed: true,
	}}
	auth := groupTransportAuthentication(tenantID, userID)
	request := ticketNumberingHTTPRequest(
		http.MethodPut, tenantID, "case",
		`{"expectedVersion":7,"prefix":"CASE","separator":"/","period":"lifetime","width":8,"start":100}`,
		true,
	)
	request.Header.Set(ifMatchHeader, `"v7"`)
	request.Header.Set(idempotencyKeyHeader, "ticket-numbering-policy-0001")
	request.Header.Set("X-Audit-Reason", "Approve reviewed Case numbering")
	request.Header.Set(requestIDHeader, requestID.String())
	response := httptest.NewRecorder()

	newTicketNumberingTestRouter(t, auth, service).ServeHTTP(response, request)

	if response.Code != http.StatusOK || service.replaceCalls != 1 ||
		service.replaceTenant != tenantID || service.replaceKind != kernel.AggregateCase ||
		service.replaceSession.User.ID != userID || auth.csrfCalls != 1 {
		t.Fatalf("status/service/csrf = %d/%#v/%d: %s", response.Code, service, auth.csrfCalls, response.Body.String())
	}
	input := service.replaceInput
	if input.ExpectedVersion != 7 || input.Policy.Prefix != "CASE" ||
		input.Policy.Separator != "/" || input.Policy.Period != kernel.NumberingPeriodNone ||
		input.Policy.Width != 8 || input.Policy.Start != 100 ||
		input.IdempotencyKey != "ticket-numbering-policy-0001" ||
		input.Reason != "Approve reviewed Case numbering" || input.Event.RequestID != requestID ||
		!input.Event.RemoteAddress.IsValid() || input.Event.UserAgent != "periapsis-ticket-numbering-test" {
		t.Fatalf("input = %#v", input)
	}
	if response.Header().Get("ETag") != `"v8"` ||
		response.Header().Get(idempotentReplayHeader) != "true" ||
		response.Header().Get("Cache-Control") != "private, no-store" ||
		strings.Contains(response.Body.String(), "Approve reviewed") {
		t.Fatalf("headers/body = %#v/%s", response.Header(), response.Body.String())
	}
}

func TestTicketNumberingRejectsUntrustedTransportBeforeService(t *testing.T) {
	t.Parallel()
	tenantID := uuid.Must(uuid.NewV7())
	valid := `{"expectedVersion":7,"prefix":"CASE","separator":"-","period":"annual","width":6,"start":1}`
	tests := []struct {
		name       string
		method     string
		pathKind   string
		body       string
		configure  func(*http.Request)
		wantStatus int
		wantCode   string
	}{
		{name: "missing session", method: http.MethodGet, pathKind: "alert", configure: func(r *http.Request) { r.Header.Del("Cookie") }, wantStatus: http.StatusUnauthorized, wantCode: "authentication_failed"},
		{name: "mixed bearer and session", method: http.MethodGet, pathKind: "alert", configure: func(r *http.Request) { r.Header.Set("Authorization", "Bearer forged") }, wantStatus: http.StatusUnauthorized, wantCode: "authentication_failed"},
		{name: "unknown kind", method: http.MethodGet, pathKind: "incident", wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "preview missing csrf", method: http.MethodPost, pathKind: "case/preview", body: `{"prefix":"CASE","separator":"-","period":"annual","width":6,"start":1}`, configure: func(r *http.Request) { r.Header.Del(csrfTokenHeader) }, wantStatus: http.StatusForbidden, wantCode: "forbidden"},
		{name: "missing if match", method: http.MethodPut, pathKind: "case", body: valid, wantStatus: http.StatusPreconditionRequired, wantCode: "precondition_required"},
		{name: "weak if match", method: http.MethodPut, pathKind: "case", body: valid, configure: func(r *http.Request) { r.Header.Set(ifMatchHeader, `W/"v7"`) }, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "duplicate if match", method: http.MethodPut, pathKind: "case", body: valid, configure: func(r *http.Request) { r.Header.Set(ifMatchHeader, `"v7"`); r.Header.Add(ifMatchHeader, `"v7"`) }, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "body header mismatch", method: http.MethodPut, pathKind: "case", body: strings.Replace(valid, `"expectedVersion":7`, `"expectedVersion":6`, 1), configure: func(r *http.Request) { r.Header.Set(ifMatchHeader, `"v7"`) }, wantStatus: http.StatusPreconditionFailed, wantCode: "precondition_failed"},
		{name: "missing idempotency", method: http.MethodPut, pathKind: "case", body: valid, configure: func(r *http.Request) { r.Header.Set(ifMatchHeader, `"v7"`); r.Header.Del(idempotencyKeyHeader) }, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "duplicate idempotency", method: http.MethodPut, pathKind: "case", body: valid, configure: func(r *http.Request) {
			r.Header.Set(ifMatchHeader, `"v7"`)
			r.Header.Add(idempotencyKeyHeader, "ticket-numbering-policy-0002")
		}, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "missing audit reason", method: http.MethodPut, pathKind: "case", body: valid, configure: func(r *http.Request) { r.Header.Set(ifMatchHeader, `"v7"`); r.Header.Del("X-Audit-Reason") }, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "comma audit reason", method: http.MethodPut, pathKind: "case", body: valid, configure: func(r *http.Request) {
			r.Header.Set(ifMatchHeader, `"v7"`)
			r.Header.Set("X-Audit-Reason", "first,second")
		}, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "unknown body field", method: http.MethodPut, pathKind: "case", body: strings.TrimSuffix(valid, "}") + `,"secret":"no"}`, configure: func(r *http.Request) { r.Header.Set(ifMatchHeader, `"v7"`) }, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "cross origin", method: http.MethodPut, pathKind: "case", body: valid, configure: func(r *http.Request) {
			r.Header.Set(ifMatchHeader, `"v7"`)
			r.Header.Set("Origin", "https://attacker.invalid")
		}, wantStatus: http.StatusForbidden, wantCode: "forbidden"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			service := &ticketNumberingHTTPStub{}
			request := ticketNumberingHTTPRequest(test.method, tenantID, test.pathKind, test.body, test.method != http.MethodGet)
			if test.method == http.MethodPut {
				request.Header.Set(idempotencyKeyHeader, "ticket-numbering-policy-0001")
				request.Header.Set("X-Audit-Reason", "Approved")
			}
			if test.configure != nil {
				test.configure(request)
			}
			response := httptest.NewRecorder()
			newTicketNumberingTestRouter(
				t, groupTransportAuthentication(tenantID, uuid.Must(uuid.NewV7())), service,
			).ServeHTTP(response, request)
			if response.Code != test.wantStatus || service.getCalls != 0 ||
				service.previewCalls != 0 || service.replaceCalls != 0 {
				t.Fatalf("status/service = %d/%#v, want %d: %s", response.Code, service, test.wantStatus, response.Body.String())
			}
			assertTicketNumberingProblem(t, response, test.wantCode)
		})
	}
}

func TestTicketNumberingMapsClosedServiceOutcomes(t *testing.T) {
	t.Parallel()
	tenantID := uuid.Must(uuid.NewV7())
	for _, test := range []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{name: "forbidden", err: ticketnumbering.ErrForbidden, wantStatus: http.StatusForbidden, wantCode: "forbidden"},
		{name: "not found", err: ticketnumbering.ErrNotFound, wantStatus: http.StatusNotFound, wantCode: "not_found"},
		{name: "stale CAS", err: ticketnumbering.ErrPrecondition, wantStatus: http.StatusPreconditionFailed, wantCode: "precondition_failed"},
		{name: "idempotency conflict", err: ticketnumbering.ErrConflict, wantStatus: http.StatusConflict, wantCode: "conflict"},
		{name: "no change", err: ticketnumbering.ErrNoChange, wantStatus: http.StatusConflict, wantCode: "conflict"},
		{name: "unavailable", err: ticketnumbering.ErrUnavailable, wantStatus: http.StatusServiceUnavailable, wantCode: "service_unavailable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			service := &ticketNumberingHTTPStub{replaceError: test.err}
			request := ticketNumberingHTTPRequest(
				http.MethodPut, tenantID, "case",
				`{"expectedVersion":7,"prefix":"CASE","separator":"-","period":"annual","width":6,"start":1}`,
				true,
			)
			request.Header.Set(ifMatchHeader, `"v7"`)
			request.Header.Set(idempotencyKeyHeader, "ticket-numbering-policy-0001")
			request.Header.Set("X-Audit-Reason", "Approved")
			response := httptest.NewRecorder()
			newTicketNumberingTestRouter(
				t, groupTransportAuthentication(tenantID, uuid.Must(uuid.NewV7())), service,
			).ServeHTTP(response, request)
			if response.Code != test.wantStatus || service.replaceCalls != 1 {
				t.Fatalf("status/calls = %d/%d: %s", response.Code, service.replaceCalls, response.Body.String())
			}
			assertTicketNumberingProblem(t, response, test.wantCode)
		})
	}
}

func newTicketNumberingTestRouter(
	t testing.TB,
	auth AuthenticationService,
	service TicketNumberingService,
) http.Handler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler, err := NewApplicationHandler(
		fixedChecker{ready: true}, logger, "test", time.Second,
		ApplicationOptions{
			Alerts: &transportAlertStub{}, Audit: &transportSecurityAuditStub{}, Authentication: auth, Authorization: &transportAuthorizationStub{},
			Contacts: &transportContactStub{}, CustomFields: &transportCustomFieldStub{}, DFIR: &transportDFIRStub{},
			Environment: "test", IdentityProviders: &transportIdentityProviderStub{}, LDAPAdministration: &transportLDAPAdministrationStub{}, MFA: &transportMFAStub{}, Notifications: &transportNotificationStub{}, OperatorTeams: &transportOperatorTeamStub{}, Platform: &transportPlatformStub{},
			PublicOrigin: "http://localhost:8081", ServiceAccounts: &transportServiceAccountStub{}, SLA: &transportSLAStub{}, TicketNumbering: service, Ticketing: &transportTicketingStub{}, WorkflowAdministration: &transportWorkflowAdministrationStub{},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return Router(handler, logger, false)
}

func ticketNumberingHTTPRequest(
	method string,
	tenantID uuid.UUID,
	kindPath string,
	body string,
	mutation bool,
) *http.Request {
	request := httptest.NewRequest(
		method, "/api/v1/tenants/"+tenantID.String()+"/ticket-numbering/"+kindPath,
		strings.NewReader(body),
	)
	request.AddCookie(&http.Cookie{Name: developmentCookie, Value: "opaque-session"})
	request.Header.Set("User-Agent", "periapsis-ticket-numbering-test")
	if mutation {
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", "http://localhost:8081")
		request.Header.Set(csrfTokenHeader, "csrf-value")
	}
	return request
}

func ticketNumberingHTTPPolicy(
	t testing.TB,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	version uint64,
	system bool,
) kernel.NumberingPolicy {
	t.Helper()
	versionID := uuid.Must(uuid.NewV7())
	versionEntity, err := kernel.NewEntityID([16]byte(versionID))
	if err != nil {
		t.Fatal(err)
	}
	tenantEntity, err := kernel.NewEntityID([16]byte(tenantID))
	if err != nil {
		t.Fatal(err)
	}
	prefix, period := "CASE", kernel.NumberingPeriodNone
	separator, width, start := "/", uint8(8), uint64(100)
	if kind == kernel.AggregateAlert {
		prefix, period, separator, width, start = "ALT", kernel.NumberingPeriodAnnual, "-", 6, 1
	}
	spec, err := kernel.NewNumberingPolicySpec(prefix, separator, period, width, start)
	if err != nil {
		t.Fatal(err)
	}
	publishedAt := time.Date(2026, time.September, 3, 12, 0, 0, 123_456_000, time.UTC)
	if system {
		policy, restoreErr := kernel.RestoreSystemNumberingPolicy(
			versionEntity, tenantEntity, kind, spec, publishedAt,
		)
		if restoreErr != nil {
			t.Fatal(restoreErr)
		}
		return policy
	}
	publisherUUID := uuid.Must(uuid.NewV7())
	publisher, err := kernel.NewEntityID([16]byte(publisherUUID))
	if err != nil {
		t.Fatal(err)
	}
	policy, err := kernel.NewNumberingPolicy(
		versionEntity, tenantEntity, kind, version, spec, publisher, publishedAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func assertTicketNumberingProblem(t testing.TB, response *httptest.ResponseRecorder, code string) {
	t.Helper()
	if !strings.HasPrefix(response.Header().Get("Content-Type"), "application/problem+json") ||
		!strings.Contains(response.Header().Get("Cache-Control"), "no-store") {
		t.Fatalf("problem headers = %#v", response.Header())
	}
	var problem contract.Problem
	if err := json.NewDecoder(response.Body).Decode(&problem); err != nil || problem.Code != code {
		t.Fatalf("problem = %#v, err=%v, want=%q", problem, err, code)
	}
}

var _ TicketNumberingService = (*ticketNumberingHTTPStub)(nil)
