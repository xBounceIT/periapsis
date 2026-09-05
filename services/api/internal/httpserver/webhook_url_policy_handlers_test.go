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

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	"github.com/periapsis-im/periapsis/services/api/internal/webhookurlpolicy"
)

type webhookURLPolicyHTTPStub struct {
	getCalls       int
	getSession     authentication.Session
	getTenant      uuid.UUID
	getResult      webhookurlpolicy.Policy
	getError       error
	publishCalls   int
	publishSession authentication.Session
	publishTenant  uuid.UUID
	publishInput   webhookurlpolicy.PublishInput
	publishResult  webhookurlpolicy.PublishResult
	publishError   error
}

func (stub *webhookURLPolicyHTTPStub) Get(
	_ context.Context,
	session authentication.Session,
	tenantID uuid.UUID,
) (webhookurlpolicy.Policy, error) {
	stub.getCalls++
	stub.getSession, stub.getTenant = session, tenantID
	return stub.getResult, stub.getError
}

func (stub *webhookURLPolicyHTTPStub) Publish(
	_ context.Context,
	session authentication.Session,
	tenantID uuid.UUID,
	input webhookurlpolicy.PublishInput,
) (webhookurlpolicy.PublishResult, error) {
	stub.publishCalls++
	stub.publishSession, stub.publishTenant, stub.publishInput = session, tenantID, input
	return stub.publishResult, stub.publishError
}

func TestWebhookURLPolicyReadMapsBoundedProjectionAndStrongETag(t *testing.T) {
	t.Parallel()
	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	policy := webhookURLPolicyHTTPPolicy(t, tenantID, 7)
	service := &webhookURLPolicyHTTPStub{getResult: policy}
	request := webhookURLPolicyHTTPRequest(http.MethodGet, tenantID, "", false)
	response := httptest.NewRecorder()

	newWebhookURLPolicyTestRouter(
		t, groupTransportAuthentication(tenantID, userID), service,
	).ServeHTTP(response, request)

	if response.Code != http.StatusOK || service.getCalls != 1 ||
		service.getTenant != tenantID || service.getSession.User.ID != userID {
		t.Fatalf("status/service = %d/%#v: %s", response.Code, service, response.Body.String())
	}
	if response.Header().Get("ETag") != `"v7"` ||
		response.Header().Get("Cache-Control") != webhookURLPolicyCacheControl {
		t.Fatalf("headers = %#v", response.Header())
	}
	var body contract.WebhookUrlPolicy
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Id != policy.ID() || body.VersionId != policy.VersionID() ||
		body.TenantId != tenantID || body.Version != 7 || body.Scheme != contract.Https ||
		body.DefaultAction != contract.WebhookUrlPolicyDefaultActionDeny ||
		body.PublishedByMembershipId != policy.PublishedByMembershipID() || len(body.Rules) != 2 ||
		body.Rules[0].Hostname == "" || body.Rules[1].Hostname == "" {
		t.Fatalf("body = %#v", body)
	}
}

func TestWebhookURLPolicyPublishBindsBootstrapCASIdempotencyAuditAndReplay(t *testing.T) {
	t.Parallel()
	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	requestID := uuid.Must(uuid.NewV7())
	policy := webhookURLPolicyHTTPPolicy(t, tenantID, 1)
	service := &webhookURLPolicyHTTPStub{publishResult: webhookurlpolicy.PublishResult{
		Policy: policy, Replayed: true,
	}}
	auth := groupTransportAuthentication(tenantID, userID)
	request := webhookURLPolicyHTTPRequest(
		http.MethodPut, tenantID,
		`{"expectedVersion":0,"rules":[{"effect":"allow","match":"exact","hostname":"Hooks.Example.COM"},{"effect":"deny","match":"subdomains","hostname":"private.example.com","port":8443}]}`,
		true,
	)
	request.Header.Set(ifMatchHeader, `"v0"`)
	request.Header.Set(idempotencyKeyHeader, "webhook-url-policy-0001")
	request.Header.Set("X-Audit-Reason", "Approve reviewed egress policy")
	request.Header.Set(requestIDHeader, requestID.String())
	response := httptest.NewRecorder()

	newWebhookURLPolicyTestRouter(t, auth, service).ServeHTTP(response, request)

	if response.Code != http.StatusOK || service.publishCalls != 1 ||
		service.publishTenant != tenantID || service.publishSession.User.ID != userID ||
		auth.csrfCalls != 1 {
		t.Fatalf("status/service/csrf = %d/%#v/%d: %s", response.Code, service, auth.csrfCalls, response.Body.String())
	}
	input := service.publishInput
	if input.ExpectedVersion != 0 || len(input.Policy.Rules) != 2 ||
		input.Policy.Rules[0].Effect != webhookurlpolicy.RuleAllow ||
		input.Policy.Rules[0].Match != webhookurlpolicy.RuleExact ||
		input.Policy.Rules[0].Hostname != "Hooks.Example.COM" || input.Policy.Rules[0].Port != 0 ||
		input.Policy.Rules[1].Port != 8443 || input.IdempotencyKey != "webhook-url-policy-0001" ||
		input.Reason != "Approve reviewed egress policy" || input.Event.RequestID != requestID ||
		!input.Event.RemoteAddress.IsValid() || input.Event.UserAgent != "periapsis-webhook-policy-test" {
		t.Fatalf("input = %#v", input)
	}
	if response.Header().Get("ETag") != `"v1"` ||
		response.Header().Get(idempotentReplayHeader) != "true" ||
		response.Header().Get("Cache-Control") != webhookURLPolicyCacheControl ||
		strings.Contains(response.Body.String(), "Approve reviewed") {
		t.Fatalf("headers/body = %#v/%s", response.Header(), response.Body.String())
	}
}

func TestWebhookURLPolicyRejectsUntrustedTransportBeforeService(t *testing.T) {
	t.Parallel()
	tenantID := uuid.Must(uuid.NewV7())
	valid := `{"expectedVersion":7,"rules":[{"effect":"allow","match":"exact","hostname":"hooks.example.com"}]}`
	tests := []struct {
		name       string
		method     string
		body       string
		configure  func(*http.Request)
		wantStatus int
		wantCode   string
	}{
		{name: "missing session", method: http.MethodGet, configure: func(r *http.Request) { r.Header.Del("Cookie") }, wantStatus: http.StatusUnauthorized, wantCode: "authentication_failed"},
		{name: "mixed bearer and session", method: http.MethodGet, configure: func(r *http.Request) { r.Header.Set("Authorization", "Bearer forged") }, wantStatus: http.StatusUnauthorized, wantCode: "authentication_failed"},
		{name: "missing csrf", method: http.MethodPut, body: valid, configure: func(r *http.Request) { r.Header.Del(csrfTokenHeader) }, wantStatus: http.StatusForbidden, wantCode: "forbidden"},
		{name: "missing if match", method: http.MethodPut, body: valid, configure: func(r *http.Request) { r.Header.Del(ifMatchHeader) }, wantStatus: http.StatusPreconditionRequired, wantCode: "precondition_required"},
		{name: "weak if match", method: http.MethodPut, body: valid, configure: func(r *http.Request) { r.Header.Set(ifMatchHeader, `W/"v7"`) }, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "wildcard if match", method: http.MethodPut, body: valid, configure: func(r *http.Request) { r.Header.Set(ifMatchHeader, "*") }, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "folded if match", method: http.MethodPut, body: valid, configure: func(r *http.Request) { r.Header.Add(ifMatchHeader, `"v7"`) }, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "noncanonical if match", method: http.MethodPut, body: valid, configure: func(r *http.Request) { r.Header.Set(ifMatchHeader, `"v07"`) }, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "body header mismatch", method: http.MethodPut, body: strings.Replace(valid, `"expectedVersion":7`, `"expectedVersion":6`, 1), wantStatus: http.StatusPreconditionFailed, wantCode: "precondition_failed"},
		{name: "missing idempotency", method: http.MethodPut, body: valid, configure: func(r *http.Request) { r.Header.Del(idempotencyKeyHeader) }, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "duplicate idempotency", method: http.MethodPut, body: valid, configure: func(r *http.Request) { r.Header.Add(idempotencyKeyHeader, "webhook-url-policy-0002") }, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "missing audit reason", method: http.MethodPut, body: valid, configure: func(r *http.Request) { r.Header.Del("X-Audit-Reason") }, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "comma audit reason", method: http.MethodPut, body: valid, configure: func(r *http.Request) { r.Header.Set("X-Audit-Reason", "first,second") }, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "unicode audit reason", method: http.MethodPut, body: valid, configure: func(r *http.Request) { r.Header.Set("X-Audit-Reason", "approv\u00e9") }, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "unknown body field", method: http.MethodPut, body: strings.TrimSuffix(valid, "}") + `,"secret":"no"}`, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "cross origin", method: http.MethodPut, body: valid, configure: func(r *http.Request) { r.Header.Set("Origin", "https://attacker.invalid") }, wantStatus: http.StatusForbidden, wantCode: "forbidden"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			service := &webhookURLPolicyHTTPStub{}
			request := webhookURLPolicyHTTPRequest(test.method, tenantID, test.body, test.method == http.MethodPut)
			if test.method == http.MethodPut {
				request.Header.Set(ifMatchHeader, `"v7"`)
				request.Header.Set(idempotencyKeyHeader, "webhook-url-policy-0001")
				request.Header.Set("X-Audit-Reason", "Approved")
			}
			if test.configure != nil {
				test.configure(request)
			}
			response := httptest.NewRecorder()
			newWebhookURLPolicyTestRouter(
				t, groupTransportAuthentication(tenantID, uuid.Must(uuid.NewV7())), service,
			).ServeHTTP(response, request)
			if response.Code != test.wantStatus || service.getCalls != 0 || service.publishCalls != 0 {
				t.Fatalf("status/service = %d/%#v, want %d: %s", response.Code, service, test.wantStatus, response.Body.String())
			}
			assertWebhookURLPolicyProblem(t, response, test.wantCode)
		})
	}
}

func TestWebhookURLPolicyMapsClosedServiceOutcomes(t *testing.T) {
	t.Parallel()
	tenantID := uuid.Must(uuid.NewV7())
	for _, test := range []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{name: "forbidden", err: webhookurlpolicy.ErrForbidden, wantStatus: http.StatusForbidden, wantCode: "forbidden"},
		{name: "not found", err: webhookurlpolicy.ErrNotFound, wantStatus: http.StatusNotFound, wantCode: "not_found"},
		{name: "idempotency conflict", err: webhookurlpolicy.ErrConflict, wantStatus: http.StatusConflict, wantCode: "conflict"},
		{name: "no change", err: webhookurlpolicy.ErrNoChange, wantStatus: http.StatusConflict, wantCode: "conflict"},
		{name: "unavailable", err: webhookurlpolicy.ErrUnavailable, wantStatus: http.StatusServiceUnavailable, wantCode: "service_unavailable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			service := &webhookURLPolicyHTTPStub{publishError: test.err}
			request := webhookURLPolicyHTTPRequest(
				http.MethodPut, tenantID,
				`{"expectedVersion":7,"rules":[{"effect":"allow","match":"exact","hostname":"hooks.example.com"}]}`,
				true,
			)
			request.Header.Set(ifMatchHeader, `"v7"`)
			request.Header.Set(idempotencyKeyHeader, "webhook-url-policy-0001")
			request.Header.Set("X-Audit-Reason", "Approved")
			response := httptest.NewRecorder()
			newWebhookURLPolicyTestRouter(
				t, groupTransportAuthentication(tenantID, uuid.Must(uuid.NewV7())), service,
			).ServeHTTP(response, request)
			if response.Code != test.wantStatus || service.publishCalls != 1 {
				t.Fatalf("status/calls = %d/%d: %s", response.Code, service.publishCalls, response.Body.String())
			}
			assertWebhookURLPolicyProblem(t, response, test.wantCode)
		})
	}
}

func newWebhookURLPolicyTestRouter(
	t testing.TB,
	auth AuthenticationService,
	service WebhookURLPolicyService,
) http.Handler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler, err := NewApplicationHandler(
		fixedChecker{ready: true}, logger, "test", time.Second,
		ApplicationOptions{
			Alerts: &transportAlertStub{}, Audit: &transportSecurityAuditStub{}, Authentication: auth, Authorization: &transportAuthorizationStub{},
			Contacts: &transportContactStub{}, CustomFields: &transportCustomFieldStub{}, DFIR: &transportDFIRStub{},
			Environment: "test", IdentityProviders: &transportIdentityProviderStub{}, LDAPAdministration: &transportLDAPAdministrationStub{}, MFA: &transportMFAStub{}, Notifications: &transportNotificationStub{}, OperatorTeams: &transportOperatorTeamStub{}, Platform: &transportPlatformStub{},
			PublicOrigin: "http://localhost:8081", ServiceAccounts: &transportServiceAccountStub{}, SLA: &transportSLAStub{}, Ticketing: &transportTicketingStub{}, WebhookURLPolicy: service, WorkflowAdministration: &transportWorkflowAdministrationStub{},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return Router(handler, logger, false)
}

func webhookURLPolicyHTTPRequest(
	method string,
	tenantID uuid.UUID,
	body string,
	mutation bool,
) *http.Request {
	request := httptest.NewRequest(
		method, "/api/v1/tenants/"+tenantID.String()+"/notification-webhook-url-policy",
		strings.NewReader(body),
	)
	request.AddCookie(&http.Cookie{Name: developmentCookie, Value: "opaque-session"})
	request.Header.Set("User-Agent", "periapsis-webhook-policy-test")
	if mutation {
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", "http://localhost:8081")
		request.Header.Set(csrfTokenHeader, "csrf-value")
	}
	return request
}

func webhookURLPolicyHTTPPolicy(
	t testing.TB,
	tenantID uuid.UUID,
	version int64,
) webhookurlpolicy.Policy {
	t.Helper()
	policy, err := webhookurlpolicy.NewPolicy(webhookurlpolicy.PolicyInput{
		ID: uuid.Must(uuid.NewV7()), VersionID: uuid.Must(uuid.NewV7()), TenantID: tenantID,
		Version: version,
		Rules: []webhookurlpolicy.RuleInput{
			{Effect: webhookurlpolicy.RuleAllow, Match: webhookurlpolicy.RuleExact, Hostname: "hooks.example.com", Port: 443},
			{Effect: webhookurlpolicy.RuleDeny, Match: webhookurlpolicy.RuleSubdomains, Hostname: "private.example.com", Port: 8443},
		},
		PublishedByMembershipID: uuid.Must(uuid.NewV7()),
		PublishedAt:             time.Date(2026, time.September, 3, 12, 0, 0, 123_000_000, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func assertWebhookURLPolicyProblem(t testing.TB, response *httptest.ResponseRecorder, code string) {
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

var _ WebhookURLPolicyService = (*webhookURLPolicyHTTPStub)(nil)
