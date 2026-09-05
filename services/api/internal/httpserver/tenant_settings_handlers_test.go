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
	"github.com/periapsis-im/periapsis/services/api/internal/tenantsettings"
)

type tenantSettingsHTTPStub struct {
	getCalls      int
	getSession    authentication.Session
	getTenantID   uuid.UUID
	getResult     tenantsettings.Settings
	getError      error
	updateCalls   int
	updateSession authentication.Session
	updateTenant  uuid.UUID
	updateInput   tenantsettings.UpdateInput
	updateResult  tenantsettings.Settings
	updateError   error
}

func (stub *tenantSettingsHTTPStub) Get(
	_ context.Context,
	session authentication.Session,
	tenantID uuid.UUID,
) (tenantsettings.Settings, error) {
	stub.getCalls++
	stub.getSession = session
	stub.getTenantID = tenantID
	return stub.getResult, stub.getError
}

func (stub *tenantSettingsHTTPStub) Update(
	_ context.Context,
	session authentication.Session,
	tenantID uuid.UUID,
	input tenantsettings.UpdateInput,
) (tenantsettings.Settings, error) {
	stub.updateCalls++
	stub.updateSession = session
	stub.updateTenant = tenantID
	stub.updateInput = input
	return stub.updateResult, stub.updateError
}

func TestTenantSettingsReadReturnsExactActiveTenantProjection(t *testing.T) {
	t.Parallel()

	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	updatedAt := time.Date(2026, time.September, 1, 18, 30, 0, 123_456_000, time.UTC)
	service := &tenantSettingsHTTPStub{getResult: tenantSettingsHTTPFixture(tenantID, 7, updatedAt)}
	request := tenantSettingsRequest(http.MethodGet, tenantID, "")
	response := httptest.NewRecorder()

	newTenantSettingsTestRouter(
		t,
		groupTransportAuthentication(tenantID, userID),
		service,
	).ServeHTTP(response, request)

	if response.Code != http.StatusOK || service.getCalls != 1 ||
		service.getTenantID != tenantID || service.getSession.User.ID != userID {
		t.Fatalf("status/service = %d/%#v: %s", response.Code, service, response.Body.String())
	}
	if response.Header().Get("ETag") != `"v7"` ||
		response.Header().Get("Cache-Control") != "private, no-store" {
		t.Fatalf("ETag/cache = %q/%q", response.Header().Get("ETag"), response.Header().Get("Cache-Control"))
	}
	var body contract.TenantSettings
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.TenantId != tenantID || body.Version != 7 || body.BrandName != "Periapsis Response" ||
		body.BrandMark != "PR" || body.PrimaryColor != "#103b53" || body.AccentColor != "#dc6843" ||
		body.Timezone != "Europe/Rome" || body.Locale != "it-IT" || body.UpdatedAt != updatedAt {
		t.Fatalf("response = %#v", body)
	}
}

func TestTenantCompatibilityAliasUsesCanonicalReadBoundary(t *testing.T) {
	t.Parallel()

	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	updatedAt := time.Date(2026, time.September, 1, 18, 35, 0, 0, time.UTC)
	service := &tenantSettingsHTTPStub{getResult: tenantSettingsHTTPFixture(tenantID, 9, updatedAt)}
	router := newTenantSettingsTestRouter(
		t,
		groupTransportAuthentication(tenantID, userID),
		service,
	)
	for _, path := range []string{
		"/api/v1/tenants/" + tenantID.String() + "/settings",
		"/api/v1/tenants/" + tenantID.String(),
	} {
		request := tenantSettingsRequest(http.MethodGet, tenantID, "")
		request.URL.Path = path
		response := httptest.NewRecorder()

		router.ServeHTTP(response, request)

		if response.Code != http.StatusOK || service.getTenantID != tenantID ||
			service.getSession.User.ID != userID || response.Header().Get("ETag") != `"v9"` ||
			response.Header().Get("Cache-Control") != "private, no-store" {
			t.Fatalf("%s status/service/headers = %d/%#v/%#v: %s", path, response.Code, service, response.Header(), response.Body.String())
		}
	}
	if service.getCalls != 2 {
		t.Fatalf("canonical and compatibility service calls = %d, want 2", service.getCalls)
	}
}

func TestTenantCompatibilityAliasPreservesCanonicalAuthenticationFailures(t *testing.T) {
	t.Parallel()

	tenantID := uuid.Must(uuid.NewV7())
	paths := []string{
		"/api/v1/tenants/" + tenantID.String() + "/settings",
		"/api/v1/tenants/" + tenantID.String(),
	}
	for _, test := range []struct {
		name        string
		mutate      func(*http.Request)
		serviceErr  error
		wantStatus  int
		wantCode    string
		wantGetCall int
	}{
		{name: "missing session", mutate: func(request *http.Request) { request.Header.Del("Cookie") }, wantStatus: http.StatusUnauthorized, wantCode: "authentication_failed"},
		{name: "duplicate session", mutate: func(request *http.Request) {
			request.AddCookie(&http.Cookie{Name: developmentCookie, Value: "second-session"})
		}, wantStatus: http.StatusUnauthorized, wantCode: "authentication_failed"},
		{name: "mixed cookie and bearer", mutate: func(request *http.Request) { request.Header.Set("Authorization", "Bearer attacker") }, wantStatus: http.StatusUnauthorized, wantCode: "authentication_failed"},
		{name: "revoked live membership", serviceErr: tenantsettings.ErrForbidden, wantStatus: http.StatusForbidden, wantCode: "forbidden", wantGetCall: 1},
		{name: "hidden tenant", serviceErr: tenantsettings.ErrNotFound, wantStatus: http.StatusNotFound, wantCode: "not_found", wantGetCall: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			for _, path := range paths {
				service := &tenantSettingsHTTPStub{getError: test.serviceErr}
				request := tenantSettingsRequest(http.MethodGet, tenantID, "")
				request.URL.Path = path
				if test.mutate != nil {
					test.mutate(request)
				}
				response := httptest.NewRecorder()

				newTenantSettingsTestRouter(
					t,
					groupTransportAuthentication(tenantID, uuid.Must(uuid.NewV7())),
					service,
				).ServeHTTP(response, request)

				if response.Code != test.wantStatus || service.getCalls != test.wantGetCall {
					t.Fatalf("%s status/calls = %d/%d, want %d/%d: %s", path, response.Code, service.getCalls, test.wantStatus, test.wantGetCall, response.Body.String())
				}
				assertTenantSettingsProblem(t, response, test.wantCode)
			}
		})
	}
}

func TestTenantSettingsUpdateBindsTransportCASReasonAndEvent(t *testing.T) {
	t.Parallel()

	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	requestID := uuid.Must(uuid.NewV7())
	updatedAt := time.Date(2026, time.September, 1, 18, 45, 0, 0, time.UTC)
	service := &tenantSettingsHTTPStub{updateResult: tenantSettingsHTTPFixture(tenantID, 8, updatedAt)}
	request := tenantSettingsRequest(
		http.MethodPut,
		tenantID,
		`{"expectedVersion":7,"brandName":"Periapsis Response","brandMark":"PR","primaryColor":"#103b53","accentColor":"#dc6843","timezone":"Europe/Rome","locale":"it-IT"}`,
	)
	request.Header.Set(ifMatchHeader, `"v7"`)
	request.Header.Set("X-Audit-Reason", "Approved brand refresh SEC-2048")
	request.Header.Set(requestIDHeader, requestID.String())
	response := httptest.NewRecorder()
	auth := groupTransportAuthentication(tenantID, userID)

	newTenantSettingsTestRouter(t, auth, service).ServeHTTP(response, request)

	if response.Code != http.StatusOK || service.updateCalls != 1 ||
		service.updateTenant != tenantID || service.updateSession.User.ID != userID || auth.csrfCalls != 1 {
		t.Fatalf("status/service/csrf = %d/%#v/%d: %s", response.Code, service, auth.csrfCalls, response.Body.String())
	}
	input := service.updateInput
	if input.ExpectedVersion != 7 || input.BrandName != "Periapsis Response" || input.BrandMark != "PR" ||
		input.PrimaryColor != "#103b53" || input.AccentColor != "#dc6843" ||
		input.Timezone != "Europe/Rome" || input.Locale != "it-IT" ||
		input.Reason != "Approved brand refresh SEC-2048" || input.Event.RequestID != requestID ||
		!input.Event.RemoteAddress.IsValid() || input.Event.UserAgent != "periapsis-tenant-settings-test" {
		t.Fatalf("captured input = %#v", input)
	}
	if response.Header().Get("ETag") != `"v8"` ||
		response.Header().Get("Cache-Control") != "private, no-store" {
		t.Fatalf("ETag/cache = %q/%q", response.Header().Get("ETag"), response.Header().Get("Cache-Control"))
	}
	if strings.Contains(response.Body.String(), "SEC-2048") {
		t.Fatalf("audit reason reflected in response: %s", response.Body.String())
	}
}

func TestTenantSettingsUpdateRejectsUntrustedTransportBeforeService(t *testing.T) {
	t.Parallel()

	tenantID := uuid.Must(uuid.NewV7())
	validBody := `{"expectedVersion":7,"brandName":"Periapsis Response","brandMark":"PR","primaryColor":"#103b53","accentColor":"#dc6843","timezone":"Europe/Rome","locale":"it-IT"}`
	tests := []struct {
		name       string
		body       string
		ifMatch    []string
		reasons    []string
		mutate     func(*http.Request)
		wantStatus int
		wantCode   string
	}{
		{name: "missing If-Match", body: validBody, reasons: []string{"Approved"}, wantStatus: http.StatusPreconditionRequired, wantCode: "precondition_required"},
		{name: "weak If-Match", body: validBody, ifMatch: []string{`W/"v7"`}, reasons: []string{"Approved"}, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "duplicate If-Match", body: validBody, ifMatch: []string{`"v7"`, `"v7"`}, reasons: []string{"Approved"}, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "body header mismatch", body: strings.Replace(validBody, `"expectedVersion":7`, `"expectedVersion":6`, 1), ifMatch: []string{`"v7"`}, reasons: []string{"Approved"}, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "terminal version", body: strings.Replace(validBody, `"expectedVersion":7`, `"expectedVersion":2147483647`, 1), ifMatch: []string{`"v2147483647"`}, reasons: []string{"Approved"}, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "missing reason", body: validBody, ifMatch: []string{`"v7"`}, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "duplicate reason", body: validBody, ifMatch: []string{`"v7"`}, reasons: []string{"Approved", "Approved"}, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "comma folded reason", body: validBody, ifMatch: []string{`"v7"`}, reasons: []string{"Approved, later"}, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "reason too long", body: validBody, ifMatch: []string{`"v7"`}, reasons: []string{strings.Repeat("A", 501)}, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "unknown body field", body: strings.TrimSuffix(validBody, "}") + `,"remoteLogo":"https://tracker.invalid/pixel"}`, ifMatch: []string{`"v7"`}, reasons: []string{"Approved"}, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "wrong media type", body: validBody, ifMatch: []string{`"v7"`}, reasons: []string{"Approved"}, mutate: func(request *http.Request) { request.Header.Set("Content-Type", "text/plain") }, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "cross origin", body: validBody, ifMatch: []string{`"v7"`}, reasons: []string{"Approved"}, mutate: func(request *http.Request) { request.Header.Set("Origin", "https://attacker.invalid") }, wantStatus: http.StatusForbidden, wantCode: "forbidden"},
		{name: "missing CSRF", body: validBody, ifMatch: []string{`"v7"`}, reasons: []string{"Approved"}, mutate: func(request *http.Request) { request.Header.Del(csrfTokenHeader) }, wantStatus: http.StatusForbidden, wantCode: "forbidden"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			service := &tenantSettingsHTTPStub{}
			request := tenantSettingsRequest(http.MethodPut, tenantID, test.body)
			for _, value := range test.ifMatch {
				request.Header.Add(ifMatchHeader, value)
			}
			for _, value := range test.reasons {
				request.Header.Add("X-Audit-Reason", value)
			}
			if test.mutate != nil {
				test.mutate(request)
			}
			response := httptest.NewRecorder()

			newTenantSettingsTestRouter(
				t,
				groupTransportAuthentication(tenantID, uuid.Must(uuid.NewV7())),
				service,
			).ServeHTTP(response, request)

			if response.Code != test.wantStatus || service.updateCalls != 0 {
				t.Fatalf("status/calls = %d/%d, want %d/0: %s", response.Code, service.updateCalls, test.wantStatus, response.Body.String())
			}
			assertTenantSettingsProblem(t, response, test.wantCode)
		})
	}
}

func TestTenantSettingsMapsClosedServiceOutcomes(t *testing.T) {
	t.Parallel()

	tenantID := uuid.Must(uuid.NewV7())
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{name: "permission denied", err: tenantsettings.ErrForbidden, wantStatus: http.StatusForbidden, wantCode: "forbidden"},
		{name: "tenant absent", err: tenantsettings.ErrNotFound, wantStatus: http.StatusNotFound, wantCode: "not_found"},
		{name: "stale version", err: tenantsettings.ErrConflict, wantStatus: http.StatusPreconditionFailed, wantCode: "precondition_failed"},
		{name: "invalid input", err: tenantsettings.ErrInvalidInput, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "dependency unavailable", err: tenantsettings.ErrUnavailable, wantStatus: http.StatusServiceUnavailable, wantCode: "service_unavailable"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			service := &tenantSettingsHTTPStub{updateError: test.err}
			request := tenantSettingsRequest(
				http.MethodPut,
				tenantID,
				`{"expectedVersion":7,"brandName":"Periapsis Response","brandMark":"PR","primaryColor":"#103b53","accentColor":"#dc6843","timezone":"Europe/Rome","locale":"it-IT"}`,
			)
			request.Header.Set(ifMatchHeader, `"v7"`)
			request.Header.Set("X-Audit-Reason", "Approved")
			response := httptest.NewRecorder()

			newTenantSettingsTestRouter(
				t,
				groupTransportAuthentication(tenantID, uuid.Must(uuid.NewV7())),
				service,
			).ServeHTTP(response, request)

			if response.Code != test.wantStatus || service.updateCalls != 1 {
				t.Fatalf("status/calls = %d/%d: %s", response.Code, service.updateCalls, response.Body.String())
			}
			assertTenantSettingsProblem(t, response, test.wantCode)
		})
	}
}

func TestTenantSettingsFailsClosedForUnwiredOrInvalidSuccess(t *testing.T) {
	t.Parallel()

	tenantID := uuid.Must(uuid.NewV7())
	var typedNil *tenantSettingsHTTPStub
	for _, test := range []struct {
		name    string
		service TenantSettingsService
	}{
		{name: "nil interface"},
		{name: "typed nil", service: typedNil},
		{name: "invalid projection", service: &tenantSettingsHTTPStub{getResult: tenantSettingsHTTPFixture(uuid.Must(uuid.NewV7()), 7, time.Now().UTC())}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			response := httptest.NewRecorder()
			newTenantSettingsTestRouter(
				t,
				groupTransportAuthentication(tenantID, uuid.Must(uuid.NewV7())),
				test.service,
			).ServeHTTP(response, tenantSettingsRequest(http.MethodGet, tenantID, ""))

			if response.Code != http.StatusServiceUnavailable || response.Header().Get("Retry-After") != "5" {
				t.Fatalf("status/retry = %d/%q: %s", response.Code, response.Header().Get("Retry-After"), response.Body.String())
			}
			assertTenantSettingsProblem(t, response, "service_unavailable")
		})
	}
}

func newTenantSettingsTestRouter(
	t testing.TB,
	auth AuthenticationService,
	service TenantSettingsService,
) http.Handler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler, err := NewApplicationHandler(
		fixedChecker{ready: true},
		logger,
		"test",
		time.Second,
		ApplicationOptions{
			Alerts: &transportAlertStub{}, Audit: &transportSecurityAuditStub{}, Authentication: auth, Authorization: &transportAuthorizationStub{},
			Contacts: &transportContactStub{}, CustomFields: &transportCustomFieldStub{}, DFIR: &transportDFIRStub{},
			Environment: "test", IdentityProviders: &transportIdentityProviderStub{}, LDAPAdministration: &transportLDAPAdministrationStub{}, MFA: &transportMFAStub{}, Notifications: &transportNotificationStub{}, OperatorTeams: &transportOperatorTeamStub{}, Platform: &transportPlatformStub{},
			PublicOrigin: "http://localhost:8081", ServiceAccounts: &transportServiceAccountStub{}, SLA: &transportSLAStub{}, TenantSettings: service, Ticketing: &transportTicketingStub{}, WorkflowAdministration: &transportWorkflowAdministrationStub{},
		},
	)
	if err != nil {
		t.Fatalf("NewApplicationHandler() error = %v", err)
	}
	return Router(handler, logger, false)
}

func tenantSettingsRequest(method string, tenantID uuid.UUID, body string) *http.Request {
	request := httptest.NewRequest(method, "/api/v1/tenants/"+tenantID.String()+"/settings", strings.NewReader(body))
	request.AddCookie(&http.Cookie{Name: developmentCookie, Value: "opaque-session"})
	request.Header.Set("User-Agent", "periapsis-tenant-settings-test")
	if method == http.MethodPut {
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", "http://localhost:8081")
		request.Header.Set(csrfTokenHeader, "csrf-value")
	}
	return request
}

func tenantSettingsHTTPFixture(tenantID uuid.UUID, version int32, updatedAt time.Time) tenantsettings.Settings {
	return tenantsettings.Settings{
		TenantID: tenantID, BrandName: "Periapsis Response", BrandMark: "PR",
		PrimaryColor: "#103b53", AccentColor: "#dc6843", Timezone: "Europe/Rome",
		Locale: "it-IT", Version: version, UpdatedAt: updatedAt,
	}
}

func assertTenantSettingsProblem(t testing.TB, response *httptest.ResponseRecorder, code string) {
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

var _ TenantSettingsService = (*tenantSettingsHTTPStub)(nil)
