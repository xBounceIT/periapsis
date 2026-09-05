package httpserver

import (
	"context"
	"encoding/json"
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

type platformTenantAccessHTTPStub struct {
	calls   int
	session authentication.Session
	command platform.PlatformTenantAccessCommand
	event   authentication.EventContext
	receipt platform.PlatformTenantAccessReceipt
	err     error
}

func (stub *platformTenantAccessHTTPStub) Authorize(
	_ context.Context,
	session authentication.Session,
	command platform.PlatformTenantAccessCommand,
	event authentication.EventContext,
) (platform.PlatformTenantAccessReceipt, error) {
	stub.calls++
	stub.session, stub.command, stub.event = session, command, event
	return stub.receipt, stub.err
}

func TestPlatformTenantAccessRouteBindsExplicitCommandAndSanitizedReceipt(t *testing.T) {
	t.Parallel()
	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	membershipID := uuid.Must(uuid.NewV7())
	authorizedAt := time.Date(2026, time.September, 1, 20, 30, 0, 123_456_000, time.UTC)
	receipt, err := platform.RestorePlatformTenantAccessReceipt(platform.PlatformTenantAccessReceiptInput{
		TenantID: tenantID, MembershipID: membershipID, UserID: userID,
		TenantVersion: 4, MembershipRevision: 1, AuthorizationRevision: 27,
		AuthorizedAt: authorizedAt,
	})
	if err != nil {
		t.Fatalf("RestorePlatformTenantAccessReceipt() error = %v", err)
	}
	service := &platformTenantAccessHTTPStub{receipt: receipt}
	auth := groupTransportAuthentication(tenantID, userID)
	auth.authenticateResult.Permissions = []authorization.Permission{
		authorization.PermissionPlatformTenantAccess,
	}
	request := platformTenantAccessRequest(tenantID, `{"expectedVersion":4,"reason":"Approved investigation SEC-2048"}`)
	request.Header.Set(requestIDHeader, uuid.Must(uuid.NewV7()).String())
	response := httptest.NewRecorder()

	newTenantLifecycleTestRouter(t, auth, nil, service).ServeHTTP(response, request)

	if response.Code != http.StatusCreated || response.Header().Get("ETag") != `"v4"` ||
		!strings.Contains(response.Header().Get("Cache-Control"), "no-store") {
		t.Fatalf("status/headers = %d/%#v: %s", response.Code, response.Header(), response.Body.String())
	}
	if service.calls != 1 || service.session.User.ID != userID ||
		service.command.TenantID() != tenantID || service.command.ExpectedVersion() != 4 ||
		service.command.Reason() != "Approved investigation SEC-2048" ||
		service.command.IdempotencyKey() != "tenant-access-key-0001" ||
		service.event.UserAgent != "tenant-access-http-test/1" || auth.csrfCalls != 1 {
		t.Fatalf("service boundary = %#v/%#v", service.command, service.event)
	}
	raw := response.Body.Bytes()
	var body contract.PlatformTenantAccessReceipt
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("decode response shape: %v", err)
	}
	if body.TenantId != tenantID || body.MembershipId != membershipID || body.UserId != userID ||
		body.TenantVersion != 4 || body.MembershipRevision != 1 || body.AuthorizationRevision != "27" ||
		body.AuthorizedAt != authorizedAt || body.Replayed || len(fields) != 8 ||
		fields["reason"] != nil || fields["idempotencyKey"] != nil || strings.Contains(string(raw), "SEC-2048") {
		t.Fatalf("response = %#v / %s", body, raw)
	}
}

func TestPlatformTenantAccessReplayUsesHTTP200(t *testing.T) {
	t.Parallel()
	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	receipt, _ := platform.RestorePlatformTenantAccessReceipt(platform.PlatformTenantAccessReceiptInput{
		TenantID: tenantID, MembershipID: uuid.Must(uuid.NewV7()), UserID: userID,
		TenantVersion: 4, MembershipRevision: 1, AuthorizationRevision: 27,
		AuthorizedAt: time.Date(2026, time.September, 1, 20, 30, 0, 0, time.UTC), Replayed: true,
	})
	response := httptest.NewRecorder()
	newTenantLifecycleTestRouter(
		t, groupTransportAuthentication(tenantID, userID), nil,
		&platformTenantAccessHTTPStub{receipt: receipt},
	).ServeHTTP(response, platformTenantAccessRequest(tenantID, `{"expectedVersion":4,"reason":"Approved"}`))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", response.Code, response.Body.String())
	}
}

func TestPlatformTenantAccessRejectsMalformedBoundaryBeforeService(t *testing.T) {
	t.Parallel()
	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	validBody := `{"expectedVersion":4,"reason":"Approved"}`
	for _, test := range []struct {
		name       string
		body       string
		mutate     func(*http.Request)
		wantStatus int
		wantCode   string
	}{
		{name: "missing idempotency", body: validBody, mutate: func(request *http.Request) { request.Header.Del(idempotencyKeyHeader) }, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "duplicate idempotency", body: validBody, mutate: func(request *http.Request) { request.Header.Add(idempotencyKeyHeader, "tenant-access-key-0002") }, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "short idempotency", body: validBody, mutate: func(request *http.Request) { request.Header.Set(idempotencyKeyHeader, "short") }, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "missing If-Match", body: validBody, mutate: func(request *http.Request) { request.Header.Del(ifMatchHeader) }, wantStatus: http.StatusPreconditionRequired, wantCode: "precondition_required"},
		{name: "version mismatch", body: `{"expectedVersion":3,"reason":"Approved"}`, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "format code", body: `{"expectedVersion":4,"reason":"Approved\u200e"}`, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "unknown field", body: `{"expectedVersion":4,"reason":"Approved","role":"owner"}`, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			service := &platformTenantAccessHTTPStub{}
			request := platformTenantAccessRequest(tenantID, test.body)
			if test.mutate != nil {
				test.mutate(request)
			}
			response := httptest.NewRecorder()
			newTenantLifecycleTestRouter(
				t, groupTransportAuthentication(tenantID, userID), nil, service,
			).ServeHTTP(response, request)
			if response.Code != test.wantStatus || service.calls != 0 {
				t.Fatalf("status/calls = %d/%d: %s", response.Code, service.calls, response.Body.String())
			}
			if !strings.Contains(response.Header().Get("Cache-Control"), "no-store") {
				t.Fatalf("validation response was cacheable: %#v", response.Header())
			}
			assertLifecycleProblem(t, response, test.wantCode)
		})
	}
}

func TestPlatformTenantAccessMapsClosedServiceOutcomes(t *testing.T) {
	t.Parallel()
	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	for _, test := range []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{name: "permission", err: authentication.ErrForbidden, wantStatus: http.StatusForbidden, wantCode: "forbidden"},
		{name: "not found", err: authentication.ErrNotFound, wantStatus: http.StatusNotFound, wantCode: "not_found"},
		{name: "membership conflict", err: authentication.ErrConflict, wantStatus: http.StatusConflict, wantCode: "conflict"},
		{name: "stale tenant", err: platform.ErrPlatformTenantAccessPreconditionFailed, wantStatus: http.StatusPreconditionFailed, wantCode: "precondition_failed"},
		{name: "unavailable", err: authentication.ErrUnavailable, wantStatus: http.StatusServiceUnavailable, wantCode: "service_unavailable"},
		{name: "invalid receipt", wantStatus: http.StatusServiceUnavailable, wantCode: "service_unavailable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			service := &platformTenantAccessHTTPStub{err: test.err}
			response := httptest.NewRecorder()
			newTenantLifecycleTestRouter(
				t, groupTransportAuthentication(tenantID, userID), nil, service,
			).ServeHTTP(response, platformTenantAccessRequest(tenantID, `{"expectedVersion":4,"reason":"Approved"}`))
			if response.Code != test.wantStatus || service.calls != 1 {
				t.Fatalf("status/calls = %d/%d: %s", response.Code, service.calls, response.Body.String())
			}
			assertLifecycleProblem(t, response, test.wantCode)
		})
	}
}

func platformTenantAccessRequest(tenantID uuid.UUID, body string) *http.Request {
	request := tenantLifecycleMutationRequest(
		"/api/v1/platform/tenants/"+tenantID.String()+"/access", body,
	)
	request.Header.Set(ifMatchHeader, `"v4"`)
	request.Header.Set(idempotencyKeyHeader, "tenant-access-key-0001")
	request.Header.Set("User-Agent", "tenant-access-http-test/1")
	return request
}

var _ PlatformTenantAccessService = (*platformTenantAccessHTTPStub)(nil)
