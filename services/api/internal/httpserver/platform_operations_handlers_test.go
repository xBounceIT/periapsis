package httpserver

import (
	"context"
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
	"github.com/periapsis-im/periapsis/services/api/internal/platformoperations"
)

func TestPlatformOperationsUsersResponseIsNoStoreAndPreservesLiveMethodSummary(t *testing.T) {
	t.Parallel()

	userID := uuid.Must(uuid.NewV7())
	next := userID
	service := &platformOperationsHTTPStub{listUsersResult: platformoperations.UserPage{
		ProjectionVersion: 1,
		Items: []platformoperations.User{{
			ID: userID, DisplayName: "Recovery-capable operator", Active: true,
			LiveSessionsByAuthenticationMethod: []platformoperations.LiveSessionSummary{{
				Method: "recovery_code", LiveSessionCount: 1,
			}},
		}},
		NextCursor: &next,
	}}
	response := httptest.NewRecorder()
	request := platformOperationsRequest(http.MethodGet, "/api/v1/platform/users?limit=25", "")

	newPlatformOperationsTestRouter(t, platformOperationsAuthentication(), service).
		ServeHTTP(response, request)

	if response.Code != http.StatusOK || service.listUsersCalls != 1 ||
		service.listUsersInput.Limit != 25 {
		t.Fatalf("status/calls/limit = %d/%d/%d: %s", response.Code, service.listUsersCalls, service.listUsersInput.Limit, response.Body.String())
	}
	if !strings.Contains(response.Header().Get("Cache-Control"), "no-store") {
		t.Fatalf("cache-control = %q", response.Header().Get("Cache-Control"))
	}
	if !strings.Contains(response.Body.String(), `"method":"recovery_code"`) ||
		strings.Contains(response.Body.String(), "credential") {
		t.Fatalf("unexpected projection: %s", response.Body.String())
	}
}

func TestPlatformOperationsSettingsMutationBindsCSRFVersionAndReason(t *testing.T) {
	t.Parallel()

	auth := platformOperationsAuthentication()
	service := &platformOperationsHTTPStub{updateSettingsResult: platformoperations.GlobalSettings{
		PlatformName: "Periapsis SOC", DefaultLocale: "it-IT",
		DefaultTimezone: "Europe/Rome", Version: 2, UpdatedAt: time.Now().UTC(),
	}}
	request := platformOperationsRequest(
		http.MethodPut,
		"/api/v1/platform/settings",
		`{"expectedVersion":1,"platformName":"Periapsis SOC","defaultLocale":"it-IT","defaultTimezone":"Europe/Rome","supportUrl":null}`,
	)
	request.Header.Set(ifMatchHeader, `"v1"`)
	request.Header.Set("X-Audit-Reason", "Align platform defaults")
	response := httptest.NewRecorder()

	newPlatformOperationsTestRouter(t, auth, service).ServeHTTP(response, request)

	if response.Code != http.StatusOK || auth.csrfCalls != 1 || service.updateSettingsCalls != 1 {
		t.Fatalf("status/csrf/calls = %d/%d/%d: %s", response.Code, auth.csrfCalls, service.updateSettingsCalls, response.Body.String())
	}
	if response.Header().Get("ETag") != `"v2"` ||
		!strings.Contains(response.Header().Get("Cache-Control"), "no-store") {
		t.Fatalf("response headers = %#v", response.Header())
	}
	if service.updateSettingsInput.ExpectedVersion != 1 ||
		service.updateSettingsInput.Reason != "Align platform defaults" ||
		service.updateSettingsInput.SupportURL != nil {
		t.Fatalf("input = %#v", service.updateSettingsInput)
	}
}

func TestPlatformGlobalSettingsUpdateDecoderAcceptsOnlyCanonicalNullableShape(t *testing.T) {
	t.Parallel()

	valid := map[string]struct {
		body       string
		supportURL *string
	}{
		"cleared": {
			body: `{"expectedVersion":1,"platformName":"Periapsis SOC","defaultLocale":"it-IT","defaultTimezone":"Europe/Rome","supportUrl":null}`,
		},
		"configured": {
			body:       `{"supportUrl":"https://support.example.invalid/help","platformName":"Periapsis SOC","expectedVersion":1,"defaultTimezone":"Europe/Rome","defaultLocale":"it-IT"}`,
			supportURL: stringPointer("https://support.example.invalid/help"),
		},
	}
	for name, test := range valid {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPut, "/", strings.NewReader(test.body))
			request.Header.Set("Content-Type", "application/json")
			var body contract.PlatformGlobalSettingsUpdateRequest
			if err := decodePlatformGlobalSettingsUpdateBody(request, &body); err != nil {
				t.Fatal(err)
			}
			if body.ExpectedVersion != 1 || body.PlatformName != "Periapsis SOC" ||
				body.DefaultLocale != "it-IT" || body.DefaultTimezone != "Europe/Rome" ||
				!equalOptionalString(body.SupportUrl, test.supportURL) {
				t.Fatalf("body = %#v", body)
			}
		})
	}

	invalid := map[string]string{
		"duplicate":              `{"expectedVersion":1,"platformName":"Periapsis SOC","defaultLocale":"it-IT","defaultTimezone":"Europe/Rome","supportUrl":null,"supportUrl":null}`,
		"missing nullable field": `{"expectedVersion":1,"platformName":"Periapsis SOC","defaultLocale":"it-IT","defaultTimezone":"Europe/Rome"}`,
		"null nonnullable field": `{"expectedVersion":1,"platformName":null,"defaultLocale":"it-IT","defaultTimezone":"Europe/Rome","supportUrl":null}`,
		"nested value":           `{"expectedVersion":1,"platformName":"Periapsis SOC","defaultLocale":"it-IT","defaultTimezone":"Europe/Rome","supportUrl":{}}`,
		"unknown field":          `{"expectedVersion":1,"platformName":"Periapsis SOC","defaultLocale":"it-IT","defaultTimezone":"Europe/Rome","supportUrl":null,"secret":"no"}`,
		"trailing value":         `{"expectedVersion":1,"platformName":"Periapsis SOC","defaultLocale":"it-IT","defaultTimezone":"Europe/Rome","supportUrl":null} {}`,
	}
	for name, document := range invalid {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPut, "/", strings.NewReader(document))
			request.Header.Set("Content-Type", "application/json")
			var body contract.PlatformGlobalSettingsUpdateRequest
			if err := decodePlatformGlobalSettingsUpdateBody(request, &body); err == nil {
				t.Fatalf("document accepted: %s", document)
			}
		})
	}
}

func TestPlatformOperationsTransportHonorsCancellationAndMapsDeadline(t *testing.T) {
	t.Parallel()

	request := httptest.NewRequest(http.MethodGet, "/api/v1/platform/operations/health", nil)
	ctx, cancel := context.WithCancel(request.Context())
	cancel()
	canceledResponse := httptest.NewRecorder()
	writePlatformOperationsDomainError(canceledResponse, request.WithContext(ctx), context.Canceled)
	if canceledResponse.Body.Len() != 0 || canceledResponse.Header().Get("Content-Type") != "" {
		t.Fatalf("canceled response = headers %#v body %q", canceledResponse.Header(), canceledResponse.Body.String())
	}

	deadlineResponse := httptest.NewRecorder()
	writePlatformOperationsDomainError(deadlineResponse, request, context.DeadlineExceeded)
	if deadlineResponse.Code != http.StatusServiceUnavailable ||
		deadlineResponse.Header().Get("Retry-After") != "5" {
		t.Fatalf("deadline response = %d %#v", deadlineResponse.Code, deadlineResponse.Header())
	}
}

func stringPointer(value string) *string { return &value }

func equalOptionalString(left, right *string) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func TestPlatformFailedNotificationCursorIsCanonicalAndExact(t *testing.T) {
	t.Parallel()

	cursor := platformoperations.FailedNotificationCursor{
		FailureAt: time.Date(2026, 9, 1, 10, 11, 12, 123, time.UTC),
		ID:        uuid.Must(uuid.NewV7()),
	}
	encoded, err := encodePlatformFailedNotificationCursor(cursor)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodePlatformFailedNotificationCursor(encoded)
	if err != nil || decoded.ID != cursor.ID || !decoded.FailureAt.Equal(cursor.FailureAt) {
		t.Fatalf("decoded = %#v, error = %v", decoded, err)
	}
	if _, err := decodePlatformFailedNotificationCursor(encoded + "="); err == nil {
		t.Fatal("padded alias cursor accepted")
	}
}

func newPlatformOperationsTestRouter(
	t testing.TB,
	auth AuthenticationService,
	service PlatformOperationsService,
) http.Handler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler, err := NewApplicationHandler(
		fixedChecker{ready: true}, logger, "test", time.Second,
		ApplicationOptions{
			Alerts: &transportAlertStub{}, Audit: &transportSecurityAuditStub{}, Authentication: auth,
			Authorization: &transportAuthorizationStub{}, Contacts: &transportContactStub{},
			CustomFields: &transportCustomFieldStub{}, DFIR: &transportDFIRStub{}, Environment: "test",
			IdentityProviders: &transportIdentityProviderStub{}, LDAPAdministration: &transportLDAPAdministrationStub{},
			MFA: &transportMFAStub{}, Notifications: &transportNotificationStub{}, OperatorTeams: &transportOperatorTeamStub{},
			Platform: &transportPlatformStub{}, PlatformOperations: service, PublicOrigin: "http://localhost:8081",
			ServiceAccounts: &transportServiceAccountStub{}, SLA: &transportSLAStub{},
			Ticketing: &transportTicketingStub{}, WorkflowAdministration: &transportWorkflowAdministrationStub{},
		},
	)
	if err != nil {
		t.Fatalf("NewApplicationHandler() error = %v", err)
	}
	return Router(handler, logger, false)
}

func platformOperationsAuthentication() *transportAuthStub {
	return &transportAuthStub{authenticateResult: authentication.Session{
		ID: uuid.Must(uuid.NewV7()), User: authentication.User{ID: uuid.Must(uuid.NewV7())},
		AuthenticationMethod: "totp",
	}}
}

func platformOperationsRequest(method, path, body string) *http.Request {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.AddCookie(&http.Cookie{Name: developmentCookie, Value: "opaque-session"})
	request.Header.Set("User-Agent", "periapsis-platform-operations-test")
	if method == http.MethodPut {
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", "http://localhost:8081")
		request.Header.Set(csrfTokenHeader, "csrf-memory-only")
	}
	return request
}

type platformOperationsHTTPStub struct {
	listUsersCalls       int
	listUsersInput       platformoperations.ListUsersInput
	listUsersResult      platformoperations.UserPage
	updateSettingsCalls  int
	updateSettingsInput  platformoperations.UpdateSettingsInput
	updateSettingsResult platformoperations.GlobalSettings
}

func (stub *platformOperationsHTTPStub) ListUsers(_ context.Context, _ authentication.Session, input platformoperations.ListUsersInput) (platformoperations.UserPage, error) {
	stub.listUsersCalls++
	stub.listUsersInput = input
	return stub.listUsersResult, nil
}

func (stub *platformOperationsHTTPStub) GetSettings(context.Context, authentication.Session, platformoperations.ReadInput) (platformoperations.GlobalSettings, error) {
	return platformoperations.GlobalSettings{}, platformoperations.ErrUnavailable
}

func (stub *platformOperationsHTTPStub) UpdateSettings(_ context.Context, _ authentication.Session, input platformoperations.UpdateSettingsInput) (platformoperations.GlobalSettings, error) {
	stub.updateSettingsCalls++
	stub.updateSettingsInput = input
	return stub.updateSettingsResult, nil
}

func (stub *platformOperationsHTTPStub) GetHealth(context.Context, authentication.Session, platformoperations.ReadInput) (platformoperations.Health, error) {
	return platformoperations.Health{}, platformoperations.ErrUnavailable
}

func (stub *platformOperationsHTTPStub) ListQueues(context.Context, authentication.Session, platformoperations.ReadInput) (platformoperations.QueueSnapshot, error) {
	return platformoperations.QueueSnapshot{}, platformoperations.ErrUnavailable
}

func (stub *platformOperationsHTTPStub) ListFailedNotifications(context.Context, authentication.Session, platformoperations.ListFailedNotificationsInput) (platformoperations.FailedNotificationPage, error) {
	return platformoperations.FailedNotificationPage{}, platformoperations.ErrUnavailable
}

func (stub *platformOperationsHTTPStub) ListFeatureFlags(context.Context, authentication.Session, platformoperations.ReadInput) (platformoperations.FeatureFlagList, error) {
	return platformoperations.FeatureFlagList{}, platformoperations.ErrUnavailable
}

func (stub *platformOperationsHTTPStub) UpdateFeatureFlag(context.Context, authentication.Session, platformoperations.UpdateFeatureFlagInput) (platformoperations.FeatureFlag, error) {
	return platformoperations.FeatureFlag{}, platformoperations.ErrUnavailable
}

var _ PlatformOperationsService = (*platformOperationsHTTPStub)(nil)
