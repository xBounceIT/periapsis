package httpserver

import (
	"bytes"
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
	"github.com/periapsis-im/periapsis/services/api/internal/platformidentityaccount"
)

type platformIdentityAccountHTTPStub struct {
	listCalls     int
	listProvider  uuid.UUID
	listInput     platformidentityaccount.ListInput
	listResult    platformidentityaccount.AccountPage
	listError     error
	getCalls      int
	getProvider   uuid.UUID
	getAccount    uuid.UUID
	getResult     platformidentityaccount.Account
	getError      error
	prelinkCalls  int
	prelinkInput  platformidentityaccount.PrelinkInput
	prelinkResult platformidentityaccount.PrelinkResult
	prelinkError  error
	retireCalls   int
	retireInput   platformidentityaccount.RetireInput
	retireResult  platformidentityaccount.RetireResult
	retireError   error
}

func (stub *platformIdentityAccountHTTPStub) List(
	_ context.Context,
	_ authentication.Session,
	providerID uuid.UUID,
	input platformidentityaccount.ListInput,
) (platformidentityaccount.AccountPage, error) {
	stub.listCalls++
	stub.listProvider = providerID
	stub.listInput = input
	return stub.listResult, stub.listError
}

func (stub *platformIdentityAccountHTTPStub) Get(
	_ context.Context,
	_ authentication.Session,
	providerID, accountID uuid.UUID,
) (platformidentityaccount.Account, error) {
	stub.getCalls++
	stub.getProvider = providerID
	stub.getAccount = accountID
	return stub.getResult, stub.getError
}

func (stub *platformIdentityAccountHTTPStub) Prelink(
	_ context.Context,
	_ authentication.Session,
	_ uuid.UUID,
	input platformidentityaccount.PrelinkInput,
) (platformidentityaccount.PrelinkResult, error) {
	stub.prelinkCalls++
	stub.prelinkInput = input
	return stub.prelinkResult, stub.prelinkError
}

func (stub *platformIdentityAccountHTTPStub) Retire(
	_ context.Context,
	_ authentication.Session,
	_, _ uuid.UUID,
	input platformidentityaccount.RetireInput,
) (platformidentityaccount.RetireResult, error) {
	stub.retireCalls++
	stub.retireInput = input
	return stub.retireResult, stub.retireError
}

func TestPlatformIdentityAccountListAndGetReturnOnlySafeNoStoreProjections(t *testing.T) {
	providerID, firstID, secondID, userID :=
		mustTransportUUIDv7(t), mustTransportUUIDv7(t), mustTransportUUIDv7(t), mustTransportUUIDv7(t)
	if bytes.Compare(firstID[:], secondID[:]) > 0 {
		firstID, secondID = secondID, firstID
	}
	first := platformIdentityAccountHTTPFixture(providerID, firstID, userID, 1, false)
	second := platformIdentityAccountHTTPFixture(providerID, secondID, userID, 2, true)
	service := &platformIdentityAccountHTTPStub{
		listResult: platformidentityaccount.AccountPage{
			Items: []platformidentityaccount.Account{first, second}, NextCursor: &secondID,
		},
		getResult: second,
	}
	router := newPlatformIdentityAccountTestRouter(t, service)

	listRequest := platformIdentityAccountReadRequest(
		"/api/v1/platform/auth-providers/" + providerID.String() +
			"/accounts?limit=2&includeRetired=true",
	)
	listResponse := httptest.NewRecorder()
	router.ServeHTTP(listResponse, listRequest)
	if listResponse.Code != http.StatusOK ||
		!strings.Contains(listResponse.Header().Get("Cache-Control"), "no-store") {
		t.Fatalf("list response = %d headers=%#v body=%s", listResponse.Code, listResponse.Header(), listResponse.Body.String())
	}
	if service.listCalls != 1 || service.listProvider != providerID || service.listInput.Limit != 2 ||
		!service.listInput.IncludeRetired || service.listInput.After != nil {
		t.Fatalf("list invocation = calls:%d provider:%s input:%#v", service.listCalls, service.listProvider, service.listInput)
	}
	assertPlatformIdentityAccountResponseSafe(t, listResponse.Body.Bytes())

	getRequest := platformIdentityAccountReadRequest(platformIdentityAccountLocation(providerID, secondID))
	getResponse := httptest.NewRecorder()
	router.ServeHTTP(getResponse, getRequest)
	if getResponse.Code != http.StatusOK || getResponse.Header().Get("ETag") != `"v2-u1"` ||
		!strings.Contains(getResponse.Header().Get("Cache-Control"), "no-store") {
		t.Fatalf("get response = %d headers=%#v body=%s", getResponse.Code, getResponse.Header(), getResponse.Body.String())
	}
	if service.getCalls != 1 || service.getProvider != providerID || service.getAccount != secondID {
		t.Fatalf("get invocation = %d %s %s", service.getCalls, service.getProvider, service.getAccount)
	}
	assertPlatformIdentityAccountResponseSafe(t, getResponse.Body.Bytes())
	var mapped contract.PlatformAuthProviderAccount
	if err := json.Unmarshal(getResponse.Body.Bytes(), &mapped); err != nil ||
		mapped.Id != secondID || mapped.ProviderId != providerID ||
		mapped.State != contract.PlatformAuthProviderAccountStateRetired || mapped.RetiredAt == nil ||
		mapped.LastObservationState != contract.Known || mapped.LastObservedAt == nil ||
		mapped.User.Version != 1 {
		t.Fatalf("mapped account = %#v, error=%v", mapped, err)
	}
}

func TestPlatformIdentityAccountGetProjectsLegacyUnknownObservationWithoutTimestamp(t *testing.T) {
	providerID, accountID, userID := mustTransportUUIDV7Set(t)
	account := platformIdentityAccountHTTPFixture(providerID, accountID, userID, 1, true)
	account.LastObservationState = platformidentityaccount.LastObservationStateLegacyUnknown
	account.LastObservedAt = nil
	service := &platformIdentityAccountHTTPStub{getResult: account}
	response := httptest.NewRecorder()
	newPlatformIdentityAccountTestRouter(t, service).ServeHTTP(
		response,
		platformIdentityAccountReadRequest(platformIdentityAccountLocation(providerID, accountID)),
	)
	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"v1-u1"` {
		t.Fatalf("legacy response = %d headers=%#v body=%s", response.Code, response.Header(), response.Body.String())
	}
	var mapped contract.PlatformAuthProviderAccount
	if err := json.Unmarshal(response.Body.Bytes(), &mapped); err != nil ||
		mapped.LastObservationState != contract.LegacyUnknown || mapped.LastObservedAt != nil ||
		mapped.State != contract.PlatformAuthProviderAccountStateRetired {
		t.Fatalf("legacy account = %#v, error=%v", mapped, err)
	}
}

func TestPlatformIdentityAccountPrelinkBindsHeadersAndNeverReturnsIdentityTuple(t *testing.T) {
	providerID, accountID, userID := mustTransportUUIDV7Set(t)
	account := platformIdentityAccountHTTPFixture(providerID, accountID, userID, 1, false)
	result, err := platformidentityaccount.RestorePrelinkResult(platformidentityaccount.PrelinkResultInput{
		AccountID: accountID, Version: 1, Account: account,
	})
	if err != nil {
		t.Fatal(err)
	}
	service := &platformIdentityAccountHTTPStub{prelinkResult: result}
	router := newPlatformIdentityAccountTestRouter(t, service)
	request := platformIdentityProviderMutationRequest(
		http.MethodPost,
		"/api/v1/platform/auth-providers/"+providerID.String()+"/accounts",
		`{"userId":"`+userID.String()+`","issuer":"https://id.example.test/oidc","subject":"opaque-subject-123"}`,
	)
	request.Header.Set(idempotencyKeyHeader, "prelink-account-0001")
	request.Header.Set("X-Audit-Reason", "Pre-link corporate operator")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusCreated || response.Header().Get("ETag") != `"v1-u1"` ||
		response.Header().Get("Location") != platformIdentityAccountLocation(providerID, accountID) ||
		!strings.Contains(response.Header().Get("Cache-Control"), "no-store") {
		t.Fatalf("prelink response = %d headers=%#v body=%s", response.Code, response.Header(), response.Body.String())
	}
	if service.prelinkCalls != 1 || service.prelinkInput.UserID != userID ||
		service.prelinkInput.Issuer != "https://id.example.test/oidc" ||
		service.prelinkInput.Subject != "opaque-subject-123" ||
		service.prelinkInput.Reason != "Pre-link corporate operator" ||
		service.prelinkInput.IdempotencyKey != "prelink-account-0001" ||
		service.prelinkInput.Event.RequestID == uuid.Nil {
		t.Fatalf("prelink input = %#v", service.prelinkInput)
	}
	assertPlatformIdentityAccountResponseSafe(t, response.Body.Bytes())
}

func TestPlatformIdentityAccountPrelinkReplayReturnsCurrentRetiredVersion(t *testing.T) {
	providerID, accountID, userID := mustTransportUUIDV7Set(t)
	account := platformIdentityAccountHTTPFixture(providerID, accountID, userID, 3, true)
	result, err := platformidentityaccount.RestorePrelinkResult(platformidentityaccount.PrelinkResultInput{
		AccountID: accountID, Version: 1, Replayed: true, Account: account,
	})
	if err != nil {
		t.Fatal(err)
	}
	service := &platformIdentityAccountHTTPStub{prelinkResult: result}
	request := platformIdentityProviderMutationRequest(
		http.MethodPost,
		"/api/v1/platform/auth-providers/"+providerID.String()+"/accounts",
		`{"userId":"`+userID.String()+`","issuer":"https://id.example.test/oidc","subject":"opaque-subject-123"}`,
	)
	request.Header.Set(idempotencyKeyHeader, "prelink-account-0001")
	request.Header.Set("X-Audit-Reason", "Pre-link corporate operator")
	response := httptest.NewRecorder()
	newPlatformIdentityAccountTestRouter(t, service).ServeHTTP(response, request)
	if response.Code != http.StatusCreated || response.Header().Get("ETag") != `"v3-u1"` {
		t.Fatalf("replay response = %d headers=%#v body=%s", response.Code, response.Header(), response.Body.String())
	}
	var mapped contract.PlatformAuthProviderAccount
	if err := json.Unmarshal(response.Body.Bytes(), &mapped); err != nil ||
		mapped.State != contract.PlatformAuthProviderAccountStateRetired || mapped.Version != 3 {
		t.Fatalf("replay account = %#v, error=%v", mapped, err)
	}
	assertPlatformIdentityAccountResponseSafe(t, response.Body.Bytes())
}

func TestPlatformIdentityAccountRetireBindsStrongCASAndReturnsRetiredProjection(t *testing.T) {
	providerID, accountID, userID := mustTransportUUIDV7Set(t)
	account := platformIdentityAccountHTTPFixture(providerID, accountID, userID, 2, true)
	result, err := platformidentityaccount.RestoreRetireResult(platformidentityaccount.RetireResultInput{
		AccountID: accountID, Version: 2, Account: account,
	})
	if err != nil {
		t.Fatal(err)
	}
	service := &platformIdentityAccountHTTPStub{retireResult: result}
	router := newPlatformIdentityAccountTestRouter(t, service)
	request := platformIdentityProviderMutationRequest(
		http.MethodDelete, platformIdentityAccountLocation(providerID, accountID),
		`{"expectedVersion":1}`,
	)
	request.Header.Set(ifMatchHeader, `"v1-u1"`)
	request.Header.Set("X-Audit-Reason", "Retire departed operator")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"v2-u1"` ||
		!strings.Contains(response.Header().Get("Cache-Control"), "no-store") {
		t.Fatalf("retire response = %d headers=%#v body=%s", response.Code, response.Header(), response.Body.String())
	}
	if service.retireCalls != 1 || service.retireInput.ExpectedEntityTag == nil ||
		*service.retireInput.ExpectedEntityTag != `"v1-u1"` ||
		service.retireInput.Reason != "Retire departed operator" {
		t.Fatalf("retire input = %#v", service.retireInput)
	}
	assertPlatformIdentityAccountResponseSafe(t, response.Body.Bytes())
}

func TestPlatformIdentityAccountTransportRejectsMalformedBodiesAndHeadersBeforeService(t *testing.T) {
	providerID, accountID, userID := mustTransportUUIDV7Set(t)
	prelinkPath := "/api/v1/platform/auth-providers/" + providerID.String() + "/accounts"
	itemPath := platformIdentityAccountLocation(providerID, accountID)
	tests := []struct {
		name       string
		method     string
		path       string
		body       string
		configure  func(*http.Request)
		wantStatus int
	}{
		{name: "missing subject", method: http.MethodPost, path: prelinkPath, body: `{"userId":"` + userID.String() + `","issuer":"https://id.example.test"}`, wantStatus: http.StatusBadRequest},
		{name: "unknown member", method: http.MethodPost, path: prelinkPath, body: `{"userId":"` + userID.String() + `","issuer":"https://id.example.test","subject":"subject","roleId":"` + userID.String() + `"}`, wantStatus: http.StatusBadRequest},
		{name: "duplicate subject", method: http.MethodPost, path: prelinkPath, body: `{"userId":"` + userID.String() + `","issuer":"https://id.example.test","subject":"a","subject":"b"}`, wantStatus: http.StatusBadRequest},
		{name: "folded idempotency", method: http.MethodPost, path: prelinkPath, body: `{"userId":"` + userID.String() + `","issuer":"https://id.example.test","subject":"subject"}`, configure: func(request *http.Request) { request.Header.Add(idempotencyKeyHeader, "second-account-key") }, wantStatus: http.StatusBadRequest},
		{name: "padded audit reason", method: http.MethodPost, path: prelinkPath, body: `{"userId":"` + userID.String() + `","issuer":"https://id.example.test","subject":"subject"}`, configure: func(request *http.Request) { request.Header.Set("X-Audit-Reason", " padded reason ") }, wantStatus: http.StatusBadRequest},
		{name: "missing if match", method: http.MethodDelete, path: itemPath, body: `{"expectedVersion":1}`, configure: func(request *http.Request) { request.Header.Del(ifMatchHeader) }, wantStatus: http.StatusPreconditionRequired},
		{name: "mismatched version", method: http.MethodDelete, path: itemPath, body: `{"expectedVersion":2}`, configure: func(request *http.Request) { request.Header.Set(ifMatchHeader, `"v1-u1"`) }, wantStatus: http.StatusBadRequest},
		{name: "version only if match", method: http.MethodDelete, path: itemPath, body: `{"expectedVersion":1}`, configure: func(request *http.Request) { request.Header.Set(ifMatchHeader, `"v1"`) }, wantStatus: http.StatusBadRequest},
		{name: "duplicate if match", method: http.MethodDelete, path: itemPath, body: `{"expectedVersion":1}`, configure: func(request *http.Request) { request.Header.Add(ifMatchHeader, `"v2-u1"`) }, wantStatus: http.StatusBadRequest},
		{name: "reason in body", method: http.MethodDelete, path: itemPath, body: `{"expectedVersion":1,"reason":"not allowed"}`, wantStatus: http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &platformIdentityAccountHTTPStub{}
			router := newPlatformIdentityAccountTestRouter(t, service)
			request := platformIdentityProviderMutationRequest(test.method, test.path, test.body)
			request.Header.Set(idempotencyKeyHeader, "prelink-account-0001")
			request.Header.Set(ifMatchHeader, `"v1-u1"`)
			request.Header.Set("X-Audit-Reason", "Bounded administrative reason")
			if test.configure != nil {
				test.configure(request)
			}
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != test.wantStatus || service.prelinkCalls != 0 || service.retireCalls != 0 {
				t.Fatalf("response=%d calls=%d/%d body=%s", response.Code, service.prelinkCalls, service.retireCalls, response.Body.String())
			}
			code := "invalid_request"
			if test.wantStatus == http.StatusPreconditionRequired {
				code = "precondition_required"
			}
			assertPlatformIdentityProviderProblem(t, response, code)
		})
	}
}

func TestPlatformIdentityAccountErrorsAndMalformedProjectionFailClosed(t *testing.T) {
	providerID, accountID, userID := mustTransportUUIDV7Set(t)
	path := platformIdentityAccountLocation(providerID, accountID)
	for _, test := range []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{name: "not found", err: authentication.ErrNotFound, wantStatus: http.StatusNotFound, wantCode: "not_found"},
		{name: "forbidden", err: authentication.ErrForbidden, wantStatus: http.StatusForbidden, wantCode: "forbidden"},
		{name: "conflict", err: authentication.ErrConflict, wantStatus: http.StatusConflict, wantCode: "conflict"},
		{name: "precondition", err: platformidentityaccount.ErrPreconditionFailed, wantStatus: http.StatusPreconditionFailed, wantCode: "precondition_failed"},
		{name: "unavailable", err: authentication.ErrUnavailable, wantStatus: http.StatusServiceUnavailable, wantCode: "service_unavailable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := &platformIdentityAccountHTTPStub{getError: test.err}
			response := httptest.NewRecorder()
			newPlatformIdentityAccountTestRouter(t, service).ServeHTTP(
				response, platformIdentityAccountReadRequest(path),
			)
			if response.Code != test.wantStatus {
				t.Fatalf("response=%d body=%s", response.Code, response.Body.String())
			}
			assertPlatformIdentityProviderProblem(t, response, test.wantCode)
		})
	}

	malformed := platformIdentityAccountHTTPFixture(providerID, accountID, userID, 1, false)
	malformed.State = platformidentityaccount.AccountStateRetired
	service := &platformIdentityAccountHTTPStub{getResult: malformed}
	response := httptest.NewRecorder()
	newPlatformIdentityAccountTestRouter(t, service).ServeHTTP(
		response, platformIdentityAccountReadRequest(path),
	)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("malformed projection response=%d body=%s", response.Code, response.Body.String())
	}
	assertPlatformIdentityProviderProblem(t, response, "service_unavailable")
}

func TestPlatformIdentityAccountServiceDefaultsFailClosed(t *testing.T) {
	providerID := mustTransportUUIDv7(t)
	response := httptest.NewRecorder()
	newPlatformIdentityAccountTestRouter(t, nil).ServeHTTP(
		response,
		platformIdentityAccountReadRequest(
			"/api/v1/platform/auth-providers/"+providerID.String()+"/accounts",
		),
	)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("unconfigured response=%d body=%s", response.Code, response.Body.String())
	}
	assertPlatformIdentityProviderProblem(t, response, "service_unavailable")
}

func newPlatformIdentityAccountTestRouter(
	t *testing.T,
	service PlatformIdentityAccountService,
) http.Handler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	userID := mustTransportUUIDv7(t)
	auth := groupTransportAuthentication(mustTransportUUIDv7(t), userID)
	auth.authenticateResult.ActiveTenantID = nil
	auth.authenticateResult.Permissions = []authorization.Permission{
		authorization.PermissionPlatformIdentityAccountRead,
		authorization.PermissionPlatformIdentityAccountManage,
	}
	handler, err := NewApplicationHandler(
		fixedChecker{ready: true}, logger, "test", time.Second,
		ApplicationOptions{
			Alerts: &transportAlertStub{}, Audit: &transportSecurityAuditStub{}, Authentication: auth, Authorization: &transportAuthorizationStub{},
			Contacts: &transportContactStub{}, CustomFields: &transportCustomFieldStub{}, DFIR: &transportDFIRStub{},
			Environment: "test", IdentityProviders: &transportIdentityProviderStub{}, LDAPAdministration: &transportLDAPAdministrationStub{}, MFA: &transportMFAStub{}, Notifications: &transportNotificationStub{}, OperatorTeams: &transportOperatorTeamStub{}, Platform: &transportPlatformStub{},
			PlatformIdentityAccounts: service, PlatformIdentityProviders: &platformIdentityProviderHTTPStub{}, PublicOrigin: "http://localhost:8081", ServiceAccounts: &transportServiceAccountStub{}, SLA: &transportSLAStub{}, Ticketing: &transportTicketingStub{}, WorkflowAdministration: &transportWorkflowAdministrationStub{},
		},
	)
	if err != nil {
		t.Fatalf("NewApplicationHandler() error = %v", err)
	}
	return Router(handler, logger, false)
}

func platformIdentityAccountReadRequest(path string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, path, nil)
	request.AddCookie(&http.Cookie{Name: developmentCookie, Value: "opaque-session"})
	return request
}

func platformIdentityAccountHTTPFixture(
	providerID, accountID, userID uuid.UUID,
	version int64,
	retired bool,
) platformidentityaccount.Account {
	createdAt := time.Date(2026, time.August, 30, 10, 0, 0, 123_000, time.UTC)
	updatedAt := createdAt
	state := platformidentityaccount.AccountStateActive
	var retiredAt *time.Time
	if retired {
		state = platformidentityaccount.AccountStateRetired
		value := createdAt.Add(time.Minute)
		retiredAt = &value
		updatedAt = value
	}
	email := "operator@example.test"
	return platformidentityaccount.Account{
		ID: accountID, ProviderID: providerID,
		User: platformidentityaccount.UserSummary{
			ID: userID, DisplayName: "Platform Operator", Email: &email, Active: true, Version: 1,
		},
		State: state, AdmittedConfigurationRevision: 7, AdmittedSecurityRevision: 11,
		LastObservationState: platformidentityaccount.LastObservationStateKnown,
		LastObservedAt:       &createdAt, RetiredAt: retiredAt, Version: version,
		CreatedAt: createdAt, UpdatedAt: updatedAt,
	}
}

func mustTransportUUIDV7Set(t *testing.T) (uuid.UUID, uuid.UUID, uuid.UUID) {
	t.Helper()
	return mustTransportUUIDv7(t), mustTransportUUIDv7(t), mustTransportUUIDv7(t)
}

func assertPlatformIdentityAccountResponseSafe(t *testing.T, body []byte) {
	t.Helper()
	lower := strings.ToLower(string(body))
	for _, forbidden := range []string{
		`"issuer"`, `"subject"`, `"aliases"`, `"ciphertext"`, `"nonce"`,
		`"claims"`, `"roles"`, `"permissions"`, `"memberships"`,
	} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("account response exposed %s: %s", forbidden, body)
		}
	}
}

var _ PlatformIdentityAccountService = (*platformIdentityAccountHTTPStub)(nil)
