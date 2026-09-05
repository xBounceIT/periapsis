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
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	"github.com/periapsis-im/periapsis/services/api/internal/platform"
)

type tenantLifecycleHTTPStub struct {
	calls   int
	session authentication.Session
	command platform.TenantLifecycleCommand
	event   authentication.EventContext
	receipt platform.TenantLifecycleReceipt
	err     error
}

func (stub *tenantLifecycleHTTPStub) Change(
	_ context.Context,
	session authentication.Session,
	command platform.TenantLifecycleCommand,
	event authentication.EventContext,
) (platform.TenantLifecycleReceipt, error) {
	stub.calls++
	stub.session = session
	stub.command = command
	stub.event = event
	return stub.receipt, stub.err
}

func TestPlatformTenantProjectionCarriesLifecycleVersionWithRollingCompatibility(t *testing.T) {
	t.Parallel()

	tenant := authentication.Tenant{
		ID: uuid.Must(uuid.NewV7()), Slug: "acme-soc", Name: "Acme SOC", Status: "active",
		Timezone: "Europe/Rome", Locale: "it-IT", Version: 7,
		CreatedAt: time.Date(2026, time.August, 26, 10, 0, 0, 0, time.UTC),
		UpdatedAt: time.Date(2026, time.August, 26, 11, 0, 0, 0, time.UTC),
	}
	mapped, err := mapTenant(tenant)
	if err != nil || mapped.Version == nil || *mapped.Version != 7 {
		t.Fatalf("mapTenant() = %#v, %v", mapped, err)
	}
	tenant.Version = 0
	mapped, err = mapTenant(tenant)
	if err != nil || mapped.Version != nil {
		t.Fatalf("rolling mapTenant() = %#v, %v", mapped, err)
	}
	tenant.Version = -1
	if _, err := mapTenant(tenant); err == nil {
		t.Fatal("mapTenant() accepted a negative lifecycle version")
	}
}

func TestPlatformTenantLifecycleRoutesBindExactTransitionAndVersion(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name     string
		path     string
		previous platform.TenantLifecycleStatus
		target   platform.TenantLifecycleStatus
	}{
		{
			name: "suspend", path: "/suspend",
			previous: platform.TenantLifecycleActive, target: platform.TenantLifecycleSuspended,
		},
		{
			name: "reactivate", path: "/reactivate",
			previous: platform.TenantLifecycleSuspended, target: platform.TenantLifecycleActive,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			tenantID := uuid.Must(uuid.NewV7())
			userID := uuid.Must(uuid.NewV7())
			requestID := uuid.Must(uuid.NewV7())
			updatedAt := time.Date(2026, time.August, 26, 14, 15, 16, 789_123_000, time.UTC)
			receipt, err := platform.RestoreTenantLifecycleReceipt(platform.TenantLifecycleReceiptInput{
				TenantID: tenantID, Previous: test.previous, Current: test.target,
				Version: 5, UpdatedAt: updatedAt,
			})
			if err != nil {
				t.Fatalf("RestoreTenantLifecycleReceipt() error = %v", err)
			}
			service := &tenantLifecycleHTTPStub{receipt: receipt}
			auth := groupTransportAuthentication(tenantID, userID)
			auth.authenticateResult.Permissions = []authorization.Permission{
				authorization.PermissionPlatformTenantManage,
			}
			request := tenantLifecycleMutationRequest(
				"/api/v1/platform/tenants/"+tenantID.String()+test.path,
				`{"expectedVersion":4,"reason":"Approved change SEC-2048"}`,
			)
			request.Header.Set(ifMatchHeader, `"v4"`)
			request.Header.Set(requestIDHeader, requestID.String())
			response := httptest.NewRecorder()

			newTenantLifecycleTestRouter(t, auth, service).ServeHTTP(response, request)

			if response.Code != http.StatusOK {
				t.Fatalf("status = %d: %s", response.Code, response.Body.String())
			}
			if response.Header().Get("ETag") != `"v5"` ||
				!strings.Contains(response.Header().Get("Cache-Control"), "no-store") {
				t.Fatalf("ETag/cache = %q/%q", response.Header().Get("ETag"), response.Header().Get("Cache-Control"))
			}
			if service.calls != 1 || service.session.User.ID != userID ||
				service.command.TenantID() != tenantID || service.command.Target() != test.target ||
				service.command.ExpectedVersion() != 4 || service.command.Reason() != "Approved change SEC-2048" ||
				service.event.RequestID != requestID || auth.csrfCalls != 1 {
				t.Fatalf("captured service boundary = %#v/%#v", service.command, service.event)
			}
			rawBody := response.Body.Bytes()
			var body contract.TenantLifecycleReceipt
			if err := json.Unmarshal(rawBody, &body); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(rawBody, &fields); err != nil {
				t.Fatalf("decode response shape: %v", err)
			}
			if body.TenantId != tenantID || int64(body.Version) != 5 || body.UpdatedAt != updatedAt ||
				string(body.PreviousStatus) != string(test.previous) || string(body.Status) != string(test.target) ||
				body.Replayed || len(fields) != 6 || fields["reason"] != nil || strings.Contains(string(rawBody), "SEC-2048") {
				t.Fatalf("response = %#v", body)
			}
		})
	}
}

func TestPlatformTenantLifecycleRejectsMalformedOrUntrustedRequests(t *testing.T) {
	t.Parallel()

	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	validPath := "/api/v1/platform/tenants/" + tenantID.String() + "/suspend"
	tests := []struct {
		name       string
		path       string
		body       string
		ifMatch    []string
		mutate     func(*http.Request, *transportAuthStub)
		wantStatus int
		wantCode   string
		wantCalls  int
	}{
		{name: "missing If-Match", path: validPath, body: `{"expectedVersion":4,"reason":"Approved"}`, wantStatus: http.StatusPreconditionRequired, wantCode: "precondition_required"},
		{name: "weak If-Match", path: validPath, body: `{"expectedVersion":4,"reason":"Approved"}`, ifMatch: []string{`W/"v4"`}, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "duplicate If-Match", path: validPath, body: `{"expectedVersion":4,"reason":"Approved"}`, ifMatch: []string{`"v4"`, `"v4"`}, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "header body mismatch", path: validPath, body: `{"expectedVersion":3,"reason":"Approved"}`, ifMatch: []string{`"v4"`}, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "version overflow", path: validPath, body: `{"expectedVersion":2147483647,"reason":"Approved"}`, ifMatch: []string{`"v2147483647"`}, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "zero version", path: validPath, body: `{"expectedVersion":0,"reason":"Approved"}`, ifMatch: []string{`"v0"`}, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "blank reason", path: validPath, body: `{"expectedVersion":4,"reason":""}`, ifMatch: []string{`"v4"`}, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "surrounding reason whitespace", path: validPath, body: `{"expectedVersion":4,"reason":" Approved "}`, ifMatch: []string{`"v4"`}, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "control in reason", path: validPath, body: `{"expectedVersion":4,"reason":"line\nbreak"}`, ifMatch: []string{`"v4"`}, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "format code point in reason", path: validPath, body: `{"expectedVersion":4,"reason":"Approved\u200e"}`, ifMatch: []string{`"v4"`}, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "reason exceeds UTF-8 byte bound", path: validPath, body: `{"expectedVersion":4,"reason":"` + strings.Repeat("é", 1025) + `"}`, ifMatch: []string{`"v4"`}, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "unknown field", path: validPath, body: `{"expectedVersion":4,"reason":"Approved","target":"active"}`, ifMatch: []string{`"v4"`}, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "duplicate field", path: validPath, body: `{"expectedVersion":4,"expectedVersion":4,"reason":"Approved"}`, ifMatch: []string{`"v4"`}, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "trailing JSON value", path: validPath, body: `{"expectedVersion":4,"reason":"Approved"}{}`, ifMatch: []string{`"v4"`}, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "wrong media type", path: validPath, body: `{"expectedVersion":4,"reason":"Approved"}`, ifMatch: []string{`"v4"`}, mutate: func(request *http.Request, _ *transportAuthStub) { request.Header.Set("Content-Type", "text/plain") }, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "non v7 tenant", path: "/api/v1/platform/tenants/" + uuid.NewString() + "/suspend", body: `{"expectedVersion":4,"reason":"Approved"}`, ifMatch: []string{`"v4"`}, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "cross origin", path: validPath, body: `{"expectedVersion":4,"reason":"Approved"}`, ifMatch: []string{`"v4"`}, mutate: func(request *http.Request, _ *transportAuthStub) {
			request.Header.Set("Origin", "https://attacker.invalid")
		}, wantStatus: http.StatusForbidden, wantCode: "forbidden"},
		{name: "missing CSRF", path: validPath, body: `{"expectedVersion":4,"reason":"Approved"}`, ifMatch: []string{`"v4"`}, mutate: func(request *http.Request, _ *transportAuthStub) { request.Header.Del(csrfTokenHeader) }, wantStatus: http.StatusForbidden, wantCode: "forbidden"},
		{name: "missing session cookie", path: validPath, body: `{"expectedVersion":4,"reason":"Approved"}`, ifMatch: []string{`"v4"`}, mutate: func(request *http.Request, _ *transportAuthStub) { request.Header.Del("Cookie") }, wantStatus: http.StatusUnauthorized, wantCode: "authentication_failed"},
		{name: "invalid session", path: validPath, body: `{"expectedVersion":4,"reason":"Approved"}`, ifMatch: []string{`"v4"`}, mutate: func(_ *http.Request, auth *transportAuthStub) {
			auth.authenticateError = authentication.ErrInvalidAuthentication
		}, wantStatus: http.StatusUnauthorized, wantCode: "authentication_failed"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			service := &tenantLifecycleHTTPStub{}
			auth := groupTransportAuthentication(tenantID, userID)
			request := tenantLifecycleMutationRequest(test.path, test.body)
			for _, value := range test.ifMatch {
				request.Header.Add(ifMatchHeader, value)
			}
			if test.mutate != nil {
				test.mutate(request, auth)
			}
			response := httptest.NewRecorder()

			newTenantLifecycleTestRouter(t, auth, service).ServeHTTP(response, request)

			if response.Code != test.wantStatus || service.calls != test.wantCalls {
				t.Fatalf("status/calls = %d/%d, want %d/%d: %s", response.Code, service.calls, test.wantStatus, test.wantCalls, response.Body.String())
			}
			assertLifecycleProblem(t, response, test.wantCode)
		})
	}
}

func TestPlatformTenantLifecycleMapsClosedServiceOutcomes(t *testing.T) {
	t.Parallel()

	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{name: "live permission denied", err: authentication.ErrForbidden, wantStatus: http.StatusForbidden, wantCode: "forbidden"},
		{name: "tenant absent", err: authentication.ErrNotFound, wantStatus: http.StatusNotFound, wantCode: "not_found"},
		{name: "stale version", err: authentication.ErrConflict, wantStatus: http.StatusPreconditionFailed, wantCode: "precondition_failed"},
		{name: "no change", err: platform.ErrTenantLifecycleNoChange, wantStatus: http.StatusPreconditionFailed, wantCode: "precondition_failed"},
		{name: "dependency unavailable", err: authentication.ErrUnavailable, wantStatus: http.StatusServiceUnavailable, wantCode: "service_unavailable"},
		{name: "invalid success receipt", wantStatus: http.StatusServiceUnavailable, wantCode: "service_unavailable"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			service := &tenantLifecycleHTTPStub{err: test.err}
			request := tenantLifecycleMutationRequest(
				"/api/v1/platform/tenants/"+tenantID.String()+"/suspend",
				`{"expectedVersion":4,"reason":"Approved"}`,
			)
			request.Header.Set(ifMatchHeader, `"v4"`)
			response := httptest.NewRecorder()

			newTenantLifecycleTestRouter(t, groupTransportAuthentication(tenantID, userID), service).ServeHTTP(response, request)

			if response.Code != test.wantStatus || service.calls != 1 {
				t.Fatalf("status/calls = %d/%d: %s", response.Code, service.calls, response.Body.String())
			}
			assertLifecycleProblem(t, response, test.wantCode)
		})
	}
}

func TestPlatformTenantLifecycleFailsClosedUntilCompositionIsWired(t *testing.T) {
	t.Parallel()

	tenantID := uuid.Must(uuid.NewV7())
	var typedNil *tenantLifecycleHTTPStub
	for _, test := range []struct {
		name    string
		service TenantLifecycleService
	}{
		{name: "nil interface"},
		{name: "typed nil service", service: typedNil},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := tenantLifecycleMutationRequest(
				"/api/v1/platform/tenants/"+tenantID.String()+"/suspend",
				`{"expectedVersion":1,"reason":"Approved"}`,
			)
			request.Header.Set(ifMatchHeader, `"v1"`)
			response := httptest.NewRecorder()

			newTenantLifecycleTestRouter(
				t, groupTransportAuthentication(tenantID, uuid.Must(uuid.NewV7())), test.service,
			).ServeHTTP(response, request)

			if response.Code != http.StatusServiceUnavailable || response.Header().Get("Retry-After") != "5" {
				t.Fatalf("status/retry = %d/%q: %s", response.Code, response.Header().Get("Retry-After"), response.Body.String())
			}
			assertLifecycleProblem(t, response, "service_unavailable")
		})
	}
}

func newTenantLifecycleTestRouter(
	t *testing.T,
	auth AuthenticationService,
	lifecycle TenantLifecycleService,
	access ...PlatformTenantAccessService,
) http.Handler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	var tenantAccess PlatformTenantAccessService
	if len(access) > 0 {
		tenantAccess = access[0]
	}
	handler, err := NewApplicationHandler(
		fixedChecker{ready: true}, logger, "test", time.Second,
		ApplicationOptions{
			Alerts: &transportAlertStub{}, Audit: &transportSecurityAuditStub{}, Authentication: auth, Authorization: &transportAuthorizationStub{},
			Contacts: &transportContactStub{}, CustomFields: &transportCustomFieldStub{}, DFIR: &transportDFIRStub{},
			Environment: "test", IdentityProviders: &transportIdentityProviderStub{}, LDAPAdministration: &transportLDAPAdministrationStub{}, MFA: &transportMFAStub{}, Notifications: &transportNotificationStub{}, OperatorTeams: &transportOperatorTeamStub{}, Platform: &transportPlatformStub{},
			PublicOrigin: "http://localhost:8081", ServiceAccounts: &transportServiceAccountStub{}, SLA: &transportSLAStub{}, TenantLifecycle: lifecycle, PlatformTenantAccess: tenantAccess, Ticketing: &transportTicketingStub{}, WorkflowAdministration: &transportWorkflowAdministrationStub{},
		},
	)
	if err != nil {
		t.Fatalf("NewApplicationHandler() error = %v", err)
	}
	return Router(handler, logger, false)
}

func tenantLifecycleMutationRequest(path, body string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	request.AddCookie(&http.Cookie{Name: developmentCookie, Value: "opaque-session"})
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://localhost:8081")
	request.Header.Set(csrfTokenHeader, "csrf-value")
	return request
}

func assertLifecycleProblem(t *testing.T, response *httptest.ResponseRecorder, code string) {
	t.Helper()
	if !strings.HasPrefix(response.Header().Get("Content-Type"), "application/problem+json") ||
		!strings.Contains(response.Header().Get("Cache-Control"), "no-store") {
		t.Fatalf("problem headers = %#v", response.Header())
	}
	var body contract.Problem
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if body.Code != code {
		t.Fatalf("problem code = %q, want %q", body.Code, code)
	}
}

var _ TenantLifecycleService = (*tenantLifecycleHTTPStub)(nil)
