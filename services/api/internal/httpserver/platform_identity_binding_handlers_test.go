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
	"github.com/periapsis-im/periapsis/services/api/internal/platformidentitybinding"
)

type platformIdentityBindingHTTPStub struct {
	listCalls          int
	listProviderID     uuid.UUID
	listInput          platformidentitybinding.ListInput
	listResult         platformidentitybinding.BindingPage
	listError          error
	getCalls           int
	getProviderID      uuid.UUID
	getBindingID       uuid.UUID
	getResult          platformidentitybinding.Binding
	getError           error
	createCalls        int
	createProvider     uuid.UUID
	createInput        platformidentitybinding.CreateInput
	createResult       platformidentitybinding.CreateResult
	createError        error
	updateCalls        int
	updateProvider     uuid.UUID
	updateBinding      uuid.UUID
	updateInput        platformidentitybinding.UpdateInput
	updateResult       platformidentitybinding.UpdateResult
	updateError        error
	archiveCalls       int
	archiveProvider    uuid.UUID
	archiveBinding     uuid.UUID
	archiveInput       platformidentitybinding.ArchiveInput
	archiveResult      platformidentitybinding.MutationReceipt
	archiveError       error
	activateCalls      int
	activateProvider   uuid.UUID
	activateBinding    uuid.UUID
	activateInput      platformidentitybinding.ActivateInput
	activateResult     platformidentitybinding.UpdateResult
	activateError      error
	deactivateCalls    int
	deactivateProvider uuid.UUID
	deactivateBinding  uuid.UUID
	deactivateInput    platformidentitybinding.DeactivateInput
	deactivateResult   platformidentitybinding.UpdateResult
	deactivateError    error
}

func (stub *platformIdentityBindingHTTPStub) List(
	_ context.Context,
	_ authentication.Session,
	providerID uuid.UUID,
	input platformidentitybinding.ListInput,
) (platformidentitybinding.BindingPage, error) {
	stub.listCalls++
	stub.listProviderID = providerID
	stub.listInput = input
	return stub.listResult, stub.listError
}

func (stub *platformIdentityBindingHTTPStub) Get(
	_ context.Context,
	_ authentication.Session,
	providerID, bindingID uuid.UUID,
) (platformidentitybinding.Binding, error) {
	stub.getCalls++
	stub.getProviderID = providerID
	stub.getBindingID = bindingID
	return stub.getResult, stub.getError
}

func (stub *platformIdentityBindingHTTPStub) Create(
	_ context.Context,
	_ authentication.Session,
	providerID uuid.UUID,
	input platformidentitybinding.CreateInput,
) (platformidentitybinding.CreateResult, error) {
	stub.createCalls++
	stub.createProvider = providerID
	stub.createInput = input
	return stub.createResult, stub.createError
}

func (stub *platformIdentityBindingHTTPStub) Update(
	_ context.Context,
	_ authentication.Session,
	providerID, bindingID uuid.UUID,
	input platformidentitybinding.UpdateInput,
) (platformidentitybinding.UpdateResult, error) {
	stub.updateCalls++
	stub.updateProvider = providerID
	stub.updateBinding = bindingID
	stub.updateInput = input
	return stub.updateResult, stub.updateError
}

func (stub *platformIdentityBindingHTTPStub) Archive(
	_ context.Context,
	_ authentication.Session,
	providerID, bindingID uuid.UUID,
	input platformidentitybinding.ArchiveInput,
) (platformidentitybinding.MutationReceipt, error) {
	stub.archiveCalls++
	stub.archiveProvider = providerID
	stub.archiveBinding = bindingID
	stub.archiveInput = input
	return stub.archiveResult, stub.archiveError
}

func (stub *platformIdentityBindingHTTPStub) Activate(
	_ context.Context,
	_ authentication.Session,
	providerID, bindingID uuid.UUID,
	input platformidentitybinding.ActivateInput,
) (platformidentitybinding.UpdateResult, error) {
	stub.activateCalls++
	stub.activateProvider = providerID
	stub.activateBinding = bindingID
	stub.activateInput = input
	return stub.activateResult, stub.activateError
}

func (stub *platformIdentityBindingHTTPStub) Deactivate(
	_ context.Context,
	_ authentication.Session,
	providerID, bindingID uuid.UUID,
	input platformidentitybinding.DeactivateInput,
) (platformidentitybinding.UpdateResult, error) {
	stub.deactivateCalls++
	stub.deactivateProvider = providerID
	stub.deactivateBinding = bindingID
	stub.deactivateInput = input
	return stub.deactivateResult, stub.deactivateError
}

func TestPlatformIdentityBindingCreateReturnsCurrentDisabledProjection(t *testing.T) {
	binding := platformIdentityBindingHTTPValue(t, 1)
	result, err := platformidentitybinding.RestoreCreateResult(platformidentitybinding.CreateResultInput{
		BindingID: binding.ID, Version: 1, Binding: binding,
	})
	if err != nil {
		t.Fatalf("RestoreCreateResult() error = %v", err)
	}
	service := &platformIdentityBindingHTTPStub{createResult: result}
	router := newPlatformIdentityBindingTestRouter(t, service)
	request := platformIdentityProviderMutationRequest(
		http.MethodPost,
		platformAuthProviderLocation(binding.ProviderID)+"/tenant-bindings",
		`{"tenantId":"`+binding.Tenant.ID.String()+`","loginKey":"corp_sso","profilePriority":40}`,
	)
	request.Header.Set(idempotencyKeyHeader, "create-binding-0001")
	request.Header.Set("X-Audit-Reason", "Bind tenant without activation")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusCreated || response.Header().Get("ETag") != `"v1-t11"` ||
		response.Header().Get("Location") != platformIdentityBindingLocation(binding.ProviderID, binding.ID) ||
		!strings.Contains(response.Header().Get("Cache-Control"), "no-store") {
		t.Fatalf("response=%d headers=%#v body=%s", response.Code, response.Header(), response.Body.String())
	}
	if service.createCalls != 1 || service.createProvider != binding.ProviderID ||
		service.createInput.TenantID != binding.Tenant.ID || service.createInput.LoginKey != "corp_sso" ||
		service.createInput.ProfilePriority != 40 ||
		service.createInput.IdempotencyKey != "create-binding-0001" ||
		service.createInput.Reason != "Bind tenant without activation" {
		t.Fatalf("create provider/input = %s / %#v", service.createProvider, service.createInput)
	}
	var document map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &document); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if document["enabled"] != false || document["activationAvailable"] != false ||
		document["origin"] != "platform" || document["currentAccessEpochId"] != nil {
		t.Fatalf("unsafe binding projection = %#v", document)
	}
	tenant, ok := document["tenant"].(map[string]any)
	if !ok || tenant["version"] != float64(11) {
		t.Fatalf("binding tenant version is not projected: %#v", document["tenant"])
	}
	for _, forbidden := range []string{"subject", "claims", "roles", "platformAuthority", "accessSource"} {
		if _, present := document[forbidden]; present {
			t.Fatalf("safe projection contains %q: %#v", forbidden, document)
		}
	}
}

func TestPlatformIdentityBindingCreateReplayUsesCurrentProjection(t *testing.T) {
	binding := platformIdentityBindingHTTPValue(t, 5)
	result, err := platformidentitybinding.RestoreCreateResult(platformidentitybinding.CreateResultInput{
		BindingID: binding.ID, Version: 1, Replayed: true, Binding: binding,
	})
	if err != nil {
		t.Fatalf("RestoreCreateResult() error = %v", err)
	}
	service := &platformIdentityBindingHTTPStub{createResult: result}
	router := newPlatformIdentityBindingTestRouter(t, service)
	request := platformIdentityProviderMutationRequest(
		http.MethodPost,
		platformAuthProviderLocation(binding.ProviderID)+"/tenant-bindings",
		`{"tenantId":"`+binding.Tenant.ID.String()+`","loginKey":"corp_sso","profilePriority":40}`,
	)
	request.Header.Set(idempotencyKeyHeader, "create-binding-0001")
	request.Header.Set("X-Audit-Reason", "Bind tenant without activation")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusCreated || response.Header().Get("ETag") != `"v5-t11"` ||
		service.createCalls != 1 || service.getCalls != 0 || service.listCalls != 0 {
		t.Fatalf(
			"response=%d ETag=%q calls create/get/list=%d/%d/%d body=%s",
			response.Code, response.Header().Get("ETag"), service.createCalls,
			service.getCalls, service.listCalls, response.Body.String(),
		)
	}
}

func TestPlatformIdentityBindingListAndGetRemainProviderScoped(t *testing.T) {
	binding := platformIdentityBindingHTTPValue(t, 3)
	after := uuid.Must(uuid.NewV7())
	service := &platformIdentityBindingHTTPStub{
		listResult: platformidentitybinding.BindingPage{Items: []platformidentitybinding.Binding{binding}},
		getResult:  binding,
	}
	router := newPlatformIdentityBindingTestRouter(t, service)

	listRequest := httptest.NewRequest(
		http.MethodGet,
		platformAuthProviderLocation(binding.ProviderID)+"/tenant-bindings?includeArchived=true&limit=17&after="+after.String(),
		nil,
	)
	listRequest.AddCookie(&http.Cookie{Name: developmentCookie, Value: "opaque-session"})
	listResponse := httptest.NewRecorder()
	router.ServeHTTP(listResponse, listRequest)
	if listResponse.Code != http.StatusOK || service.listCalls != 1 ||
		service.listProviderID != binding.ProviderID || !service.listInput.IncludeArchived ||
		service.listInput.Limit != 17 || service.listInput.After == nil || *service.listInput.After != after {
		t.Fatalf("list response=%d input=%#v body=%s", listResponse.Code, service.listInput, listResponse.Body.String())
	}

	getRequest := httptest.NewRequest(
		http.MethodGet, platformIdentityBindingLocation(binding.ProviderID, binding.ID), nil,
	)
	getRequest.AddCookie(&http.Cookie{Name: developmentCookie, Value: "opaque-session"})
	getResponse := httptest.NewRecorder()
	router.ServeHTTP(getResponse, getRequest)
	if getResponse.Code != http.StatusOK || getResponse.Header().Get("ETag") != `"v3-t11"` ||
		service.getCalls != 1 || service.getProviderID != binding.ProviderID ||
		service.getBindingID != binding.ID {
		t.Fatalf("get response=%d headers=%#v body=%s", getResponse.Code, getResponse.Header(), getResponse.Body.String())
	}
}

func TestPlatformIdentityBindingUpdateRejectsVersionMismatchBeforeMutation(t *testing.T) {
	binding := platformIdentityBindingHTTPValue(t, 5)
	service := &platformIdentityBindingHTTPStub{}
	router := newPlatformIdentityBindingTestRouter(t, service)
	request := platformIdentityProviderMutationRequest(
		http.MethodPatch,
		platformIdentityBindingLocation(binding.ProviderID, binding.ID),
		`{"expectedTenantVersion":11,"expectedVersion":6,"loginKey":"corp_sso","profilePriority":50}`,
	)
	request.Header.Set(ifMatchHeader, `"v5-t11"`)
	request.Header.Set("X-Audit-Reason", "Change profile ordering")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest || service.updateCalls != 0 {
		t.Fatalf("response=%d update calls=%d body=%s", response.Code, service.updateCalls, response.Body.String())
	}
	assertPlatformIdentityProviderProblem(t, response, "invalid_request")
}

func TestPlatformIdentityBindingCompositePreconditionRejectsUnsafeValidators(t *testing.T) {
	binding := platformIdentityBindingHTTPValue(t, 5)
	validBody := `{"expectedTenantVersion":11,"expectedVersion":5,"loginKey":"corp_sso","profilePriority":50}`
	tests := []struct {
		name       string
		body       string
		validators []string
		wantStatus int
	}{
		{name: "missing", wantStatus: http.StatusPreconditionRequired},
		{name: "weak", validators: []string{`W/"v5-t11"`}, wantStatus: http.StatusBadRequest},
		{name: "wildcard", validators: []string{"*"}, wantStatus: http.StatusBadRequest},
		{name: "version only", validators: []string{`"v5"`}, wantStatus: http.StatusBadRequest},
		{name: "padded binding", validators: []string{`"v05-t11"`}, wantStatus: http.StatusBadRequest},
		{name: "padded tenant", validators: []string{`"v5-t011"`}, wantStatus: http.StatusBadRequest},
		{name: "folded", validators: []string{`"v5-t11","v5-t11"`}, wantStatus: http.StatusBadRequest},
		{name: "duplicate", validators: []string{`"v5-t11"`, `"v5-t11"`}, wantStatus: http.StatusBadRequest},
		{name: "trailing whitespace", validators: []string{"\"v5-t11\"\t"}, wantStatus: http.StatusBadRequest},
		{name: "binding overflow", validators: []string{`"v2147483648-t11"`}, wantStatus: http.StatusBadRequest},
		{name: "tenant overflow", validators: []string{`"v5-t2147483648"`}, wantStatus: http.StatusBadRequest},
		{
			name: "body tenant mismatch", body: `{"expectedTenantVersion":12,"expectedVersion":5,"loginKey":"corp_sso","profilePriority":50}`,
			validators: []string{`"v5-t11"`}, wantStatus: http.StatusBadRequest,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &platformIdentityBindingHTTPStub{}
			router := newPlatformIdentityBindingTestRouter(t, service)
			body := test.body
			if body == "" {
				body = validBody
			}
			request := platformIdentityProviderMutationRequest(
				http.MethodPatch, platformIdentityBindingLocation(binding.ProviderID, binding.ID), body,
			)
			request.Header.Set("X-Audit-Reason", "Reject stale tenant projection")
			for _, validator := range test.validators {
				request.Header.Add(ifMatchHeader, validator)
			}
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != test.wantStatus || service.updateCalls != 0 {
				t.Fatalf(
					"response=%d, want=%d update calls=%d body=%s",
					response.Code, test.wantStatus, service.updateCalls, response.Body.String(),
				)
			}
		})
	}
}

func TestPlatformIdentityBindingBodiesRejectInvalidShapeBeforeServiceCall(t *testing.T) {
	binding := platformIdentityBindingHTTPValue(t, 1)
	tests := []struct {
		name   string
		method string
		path   string
		body   string
		create bool
	}{
		{
			name: "create explicit null", method: http.MethodPost,
			path:   platformAuthProviderLocation(binding.ProviderID) + "/tenant-bindings",
			body:   `{"tenantId":"` + binding.Tenant.ID.String() + `","loginKey":null,"profilePriority":40}`,
			create: true,
		},
		{
			name: "create unknown member", method: http.MethodPost,
			path:   platformAuthProviderLocation(binding.ProviderID) + "/tenant-bindings",
			body:   `{"tenantId":"` + binding.Tenant.ID.String() + `","loginKey":"corp_sso","profilePriority":40,"enabled":true}`,
			create: true,
		},
		{
			name: "update explicit null", method: http.MethodPatch,
			path: platformIdentityBindingLocation(binding.ProviderID, binding.ID),
			body: `{"expectedTenantVersion":11,"expectedVersion":1,"loginKey":null,"profilePriority":50}`,
		},
		{
			name: "archive unknown member", method: http.MethodDelete,
			path: platformIdentityBindingLocation(binding.ProviderID, binding.ID),
			body: `{"expectedTenantVersion":11,"expectedVersion":1,"enabled":true}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &platformIdentityBindingHTTPStub{}
			router := newPlatformIdentityBindingTestRouter(t, service)
			request := platformIdentityProviderMutationRequest(test.method, test.path, test.body)
			request.Header.Set("X-Audit-Reason", "Reject invalid binding document")
			if test.create {
				request.Header.Set(idempotencyKeyHeader, "reject-binding-0001")
			} else {
				request.Header.Set(ifMatchHeader, `"v1-t11"`)
			}
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)

			if response.Code != http.StatusBadRequest || service.createCalls != 0 ||
				service.updateCalls != 0 || service.archiveCalls != 0 {
				t.Fatalf(
					"response=%d calls create/update/archive=%d/%d/%d body=%s",
					response.Code, service.createCalls, service.updateCalls,
					service.archiveCalls, response.Body.String(),
				)
			}
			assertPlatformIdentityProviderProblem(t, response, "invalid_request")
		})
	}
}

func TestPlatformIdentityBindingUpdateAndArchiveUseTransactionalResults(t *testing.T) {
	binding := platformIdentityBindingHTTPValue(t, 6)
	binding.ProfilePriority = 50
	updateResult, err := platformidentitybinding.RestoreUpdateResult(platformidentitybinding.UpdateResultInput{
		BindingID: binding.ID, Version: binding.Version, Binding: binding,
	})
	if err != nil {
		t.Fatalf("RestoreUpdateResult() error = %v", err)
	}
	service := &platformIdentityBindingHTTPStub{updateResult: updateResult}
	router := newPlatformIdentityBindingTestRouter(t, service)
	request := platformIdentityProviderMutationRequest(
		http.MethodPatch,
		platformIdentityBindingLocation(binding.ProviderID, binding.ID),
		`{"expectedTenantVersion":11,"expectedVersion":5,"loginKey":"corp_sso","profilePriority":50}`,
	)
	request.Header.Set(ifMatchHeader, `"v5-t11"`)
	request.Header.Set("X-Audit-Reason", "Change profile ordering")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"v6-t11"` ||
		service.updateCalls != 1 || service.getCalls != 0 ||
		service.updateProvider != binding.ProviderID || service.updateBinding != binding.ID ||
		service.updateInput.ExpectedEntityTag == nil || *service.updateInput.ExpectedEntityTag != `"v5-t11"` {
		t.Fatalf("update response=%d input=%#v body=%s", response.Code, service.updateInput, response.Body.String())
	}

	receipt, err := platformidentitybinding.RestoreMutationReceipt(platformidentitybinding.MutationReceiptInput{
		BindingID: binding.ID, Version: 7, TenantVersion: 11,
	})
	if err != nil {
		t.Fatalf("RestoreMutationReceipt() error = %v", err)
	}
	service = &platformIdentityBindingHTTPStub{archiveResult: receipt}
	router = newPlatformIdentityBindingTestRouter(t, service)
	request = platformIdentityProviderMutationRequest(
		http.MethodDelete,
		platformIdentityBindingLocation(binding.ProviderID, binding.ID),
		`{"expectedTenantVersion":11,"expectedVersion":6}`,
	)
	request.Header.Set(ifMatchHeader, `"v6-t11"`)
	request.Header.Set("X-Audit-Reason", "Retire unused binding")
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || response.Header().Get("ETag") != `"v7-t11"` ||
		response.Header().Get("Cache-Control") != "no-store" || response.Body.Len() != 0 ||
		service.archiveCalls != 1 || service.archiveProvider != binding.ProviderID ||
		service.archiveBinding != binding.ID {
		t.Fatalf("archive response=%d headers=%#v body=%s", response.Code, response.Header(), response.Body.String())
	}
}

func TestPlatformIdentityBindingLifecycleUsesCompositeCASAndExactAccessEpochProjection(t *testing.T) {
	active := platformIdentityBindingHTTPValue(t, 2)
	epochID := uuid.Must(uuid.NewV7())
	active.Enabled = true
	active.ActivationAvailable = false
	active.JITMode = platformidentitybinding.JITModeCreate
	active.NoMatchPolicy = platformidentitybinding.NoMatchPolicyProviderAccessOnly
	active.CurrentAccessEpochID = &epochID
	active.UpdatedAt = active.UpdatedAt.Add(time.Microsecond)
	activation, err := platformidentitybinding.RestoreUpdateResult(
		platformidentitybinding.UpdateResultInput{
			BindingID: active.ID, Version: active.Version, Binding: active,
		},
	)
	if err != nil {
		t.Fatalf("RestoreUpdateResult(activation) error = %v", err)
	}
	service := &platformIdentityBindingHTTPStub{activateResult: activation}
	router := newPlatformIdentityBindingTestRouter(t, service)
	request := platformIdentityProviderMutationRequest(
		http.MethodPost, platformIdentityBindingLocation(active.ProviderID, active.ID)+"/activate",
		`{"expectedTenantVersion":11,"expectedVersion":1,"jitMode":"create","noMatchPolicy":"provider_access_only"}`,
	)
	request.Header.Set(ifMatchHeader, `"v1-t11"`)
	request.Header.Set("X-Audit-Reason", "Admit tenant through corporate identity")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"v2-t11"` ||
		!strings.Contains(response.Header().Get("Cache-Control"), "no-store") ||
		service.activateCalls != 1 || service.activateProvider != active.ProviderID ||
		service.activateBinding != active.ID || service.activateInput.JITMode != platformidentitybinding.JITModeCreate ||
		service.activateInput.NoMatchPolicy != platformidentitybinding.NoMatchPolicyProviderAccessOnly ||
		service.activateInput.ExpectedEntityTag == nil || *service.activateInput.ExpectedEntityTag != `"v1-t11"` {
		t.Fatalf("activate response=%d headers=%#v input=%#v body=%s", response.Code, response.Header(), service.activateInput, response.Body.String())
	}

	disabled := active
	disabled.Version = 3
	disabled.Enabled = false
	disabled.ActivationAvailable = true
	disabled.CurrentAccessEpochID = nil
	disabled.UpdatedAt = disabled.UpdatedAt.Add(time.Microsecond)
	deactivation, err := platformidentitybinding.RestoreUpdateResult(
		platformidentitybinding.UpdateResultInput{
			BindingID: disabled.ID, Version: disabled.Version, Binding: disabled,
		},
	)
	if err != nil {
		t.Fatalf("RestoreUpdateResult(deactivation) error = %v", err)
	}
	service = &platformIdentityBindingHTTPStub{deactivateResult: deactivation}
	router = newPlatformIdentityBindingTestRouter(t, service)
	request = platformIdentityProviderMutationRequest(
		http.MethodPost, platformIdentityBindingLocation(disabled.ProviderID, disabled.ID)+"/deactivate",
		`{"expectedTenantVersion":11,"expectedVersion":2}`,
	)
	request.Header.Set(ifMatchHeader, `"v2-t11"`)
	request.Header.Set("X-Audit-Reason", "Withdraw tenant admission")
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"v3-t11"` ||
		service.deactivateCalls != 1 || service.deactivateProvider != disabled.ProviderID ||
		service.deactivateBinding != disabled.ID || service.deactivateInput.ExpectedEntityTag == nil ||
		*service.deactivateInput.ExpectedEntityTag != `"v2-t11"` {
		t.Fatalf("deactivate response=%d headers=%#v input=%#v body=%s", response.Code, response.Header(), service.deactivateInput, response.Body.String())
	}
}

func TestPlatformIdentityBindingActivationRejectsUnsafeDocumentsBeforeService(t *testing.T) {
	binding := platformIdentityBindingHTTPValue(t, 1)
	for _, body := range []string{
		`{"expectedTenantVersion":11,"expectedVersion":1,"jitMode":"unknown","noMatchPolicy":"deny"}`,
		`{"expectedTenantVersion":11,"expectedVersion":1,"jitMode":"create","noMatchPolicy":"unknown"}`,
		`{"expectedTenantVersion":11,"expectedVersion":1,"jitMode":"create","noMatchPolicy":"deny","enabled":true}`,
		`{"expectedTenantVersion":12,"expectedVersion":1,"jitMode":"create","noMatchPolicy":"deny"}`,
	} {
		service := &platformIdentityBindingHTTPStub{}
		router := newPlatformIdentityBindingTestRouter(t, service)
		request := platformIdentityProviderMutationRequest(
			http.MethodPost, platformIdentityBindingLocation(binding.ProviderID, binding.ID)+"/activate", body,
		)
		request.Header.Set(ifMatchHeader, `"v1-t11"`)
		request.Header.Set("X-Audit-Reason", "Reject unsafe admission")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest || service.activateCalls != 0 {
			t.Fatalf("body=%s response=%d calls=%d payload=%s", body, response.Code, service.activateCalls, response.Body.String())
		}
		assertPlatformIdentityProviderProblem(t, response, "invalid_request")
	}
}

func TestPlatformIdentityBindingErrorsAreNonOracularAndFailClosed(t *testing.T) {
	handler := &Handler{}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/platform/auth-providers/missing/tenant-bindings/missing", nil)
	response := httptest.NewRecorder()
	handler.writePlatformIdentityBindingError(response, request, authentication.ErrNotFound)
	var notFoundDocument struct {
		Detail string `json:"detail"`
	}
	decodeError := json.Unmarshal(response.Body.Bytes(), &notFoundDocument)
	if response.Code != http.StatusNotFound || response.Header().Get("Cache-Control") != "no-store" ||
		decodeError != nil || strings.Contains(notFoundDocument.Detail, "provider") ||
		strings.Contains(notFoundDocument.Detail, "tenant") {
		t.Fatalf("not-found response=%d headers=%#v body=%s", response.Code, response.Header(), response.Body.String())
	}
	assertPlatformIdentityProviderProblem(t, response, "not_found")

	response = httptest.NewRecorder()
	handler.writePlatformIdentityBindingError(response, request, platformidentitybinding.ErrPreconditionFailed)
	if response.Code != http.StatusPreconditionFailed {
		t.Fatalf("precondition response=%d body=%s", response.Code, response.Body.String())
	}
	assertPlatformIdentityProviderProblem(t, response, "precondition_failed")

	canceledContext, cancel := context.WithCancel(context.Background())
	cancel()
	request = request.WithContext(canceledContext)
	response = httptest.NewRecorder()
	handler.writePlatformIdentityBindingError(response, request, context.Canceled)
	if response.Body.Len() != 0 || len(response.Header()) != 0 {
		t.Fatalf("canceled request wrote response: headers=%#v body=%q", response.Header(), response.Body.String())
	}

	binding := platformIdentityBindingHTTPValue(t, 1)
	router := newPlatformIdentityBindingTestRouter(t, nil)
	request = httptest.NewRequest(
		http.MethodGet, platformAuthProviderLocation(binding.ProviderID)+"/tenant-bindings", nil,
	)
	request.AddCookie(&http.Cookie{Name: developmentCookie, Value: "opaque-session"})
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("unavailable response=%d body=%s", response.Code, response.Body.String())
	}
	assertPlatformIdentityProviderProblem(t, response, "service_unavailable")
}

func newPlatformIdentityBindingTestRouter(
	t *testing.T,
	service PlatformIdentityBindingService,
) http.Handler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	userID := uuid.Must(uuid.NewV7())
	auth := groupTransportAuthentication(uuid.Must(uuid.NewV7()), userID)
	auth.authenticateResult.ActiveTenantID = nil
	auth.authenticateResult.Permissions = []authorization.Permission{
		authorization.PermissionPlatformIdentityBindingRead,
		authorization.PermissionPlatformIdentityBindingManage,
	}
	handler, err := NewApplicationHandler(
		fixedChecker{ready: true}, logger, "test", time.Second,
		ApplicationOptions{
			Alerts: &transportAlertStub{}, Audit: &transportSecurityAuditStub{}, Authentication: auth,
			Authorization: &transportAuthorizationStub{}, Contacts: &transportContactStub{},
			CustomFields: &transportCustomFieldStub{}, DFIR: &transportDFIRStub{}, Environment: "test",
			IdentityProviders:  &transportIdentityProviderStub{},
			LDAPAdministration: &transportLDAPAdministrationStub{}, MFA: &transportMFAStub{},
			Notifications: &transportNotificationStub{}, OperatorTeams: &transportOperatorTeamStub{},
			Platform: &transportPlatformStub{}, PlatformIdentityBindings: service,
			PublicOrigin: "http://localhost:8081", ServiceAccounts: &transportServiceAccountStub{},
			SLA: &transportSLAStub{}, Ticketing: &transportTicketingStub{},
			WorkflowAdministration: &transportWorkflowAdministrationStub{},
		},
	)
	if err != nil {
		t.Fatalf("NewApplicationHandler() error = %v", err)
	}
	return Router(handler, logger, false)
}

func platformIdentityBindingHTTPValue(t *testing.T, version int64) platformidentitybinding.Binding {
	t.Helper()
	createdAt := time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)
	return platformidentitybinding.Binding{
		ID: uuid.Must(uuid.NewV7()), ProviderID: uuid.Must(uuid.NewV7()),
		Tenant: platformidentitybinding.TenantSummary{
			ID: uuid.Must(uuid.NewV7()), Slug: "acme", Name: "Acme S.p.A.",
			Status: platformidentitybinding.TenantStatusActive, Version: 11,
		},
		LoginKey: "corp_sso", ProfilePriority: 40,
		JITMode:       platformidentitybinding.JITModeDisabled,
		NoMatchPolicy: platformidentitybinding.NoMatchPolicyDeny, Enabled: false,
		AuthRevision: 1, MappingRevision: 1, CurrentAccessEpochID: nil,
		Version: version, CreatedAt: createdAt, UpdatedAt: createdAt,
	}
}

var _ PlatformIdentityBindingService = (*platformIdentityBindingHTTPStub)(nil)
