package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	customkernel "github.com/periapsis-im/periapsis/modules/customfields"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	application "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

func TestMapSavedViewColumnWidthPreservesDefaultAndExplicitValues(t *testing.T) {
	t.Parallel()
	for _, value := range []uint16{0, 320} {
		mapped, err := mapSavedViewColumnWidth(value)
		if err != nil {
			t.Fatalf("mapSavedViewColumnWidth(%d) error = %v", value, err)
		}
		encoded, err := json.Marshal(mapped)
		if err != nil {
			t.Fatalf("json.Marshal(width %d) error = %v", value, err)
		}
		if got, want := string(encoded), fmt.Sprint(value); got != want {
			t.Fatalf("encoded width = %s, want %s", got, want)
		}
	}
}

func TestSavedViewAndDynamicNumericProjectionIsLosslessForBrowserClients(t *testing.T) {
	t.Parallel()
	wide := strings.Repeat("9", 200)
	scalar, err := mapSavedViewScalar([]byte(wide))
	if err != nil {
		t.Fatalf("mapSavedViewScalar() error = %v", err)
	}
	encoded, err := json.Marshal(scalar)
	if err != nil {
		t.Fatalf("json.Marshal(saved-view scalar) error = %v", err)
	}
	if got, want := string(encoded), `"`+wide+`"`; got != want {
		t.Fatalf("saved-view scalar = %s, want %s", got, want)
	}

	definitionID := uuid.MustParse("019c2f0e-7a5b-7cf1-b594-6f8826f6b913")
	columns, err := mapTicketDynamicColumns(map[string]application.DynamicColumnValue{
		"custom_field:" + definitionID.String(): {
			Source: application.SavedViewDefinitionCustomField, DefinitionID: definitionID,
			DefinitionVersion: 3, Value: json.RawMessage(wide),
		},
	})
	if err != nil {
		t.Fatalf("mapTicketDynamicColumns() error = %v", err)
	}
	encoded, err = json.Marshal(columns)
	if err != nil {
		t.Fatalf("json.Marshal(dynamic columns) error = %v", err)
	}
	if !strings.Contains(string(encoded), `"value":"`+wide+`"`) {
		t.Fatalf("dynamic column lost numeric precision: %s", encoded)
	}
}

type transportSavedViewStub struct {
	createCalls  int
	replaceCalls int
	createInput  application.SavedViewCreateInput
	replaceInput application.SavedViewReplaceInput
}

func (stub *transportSavedViewStub) ListSavedViews(context.Context, application.Actor, uuid.UUID, kernel.AggregateKind, application.SavedViewListInput) (application.SavedViewPage, error) {
	return application.SavedViewPage{}, application.ErrUnavailable
}

func (stub *transportSavedViewStub) GetSavedView(context.Context, application.Actor, uuid.UUID, kernel.AggregateKind, uuid.UUID) (application.SavedViewRecord, error) {
	return application.SavedViewRecord{}, application.ErrUnavailable
}

func (stub *transportSavedViewStub) CreateSavedView(_ context.Context, _ application.Actor, _ uuid.UUID, _ kernel.AggregateKind, input application.SavedViewCreateInput) (application.SavedViewMutationResult, error) {
	stub.createCalls++
	stub.createInput = input
	return application.SavedViewMutationResult{}, application.ErrUnavailable
}

func (stub *transportSavedViewStub) ReplaceSavedView(_ context.Context, _ application.Actor, _ uuid.UUID, _ kernel.AggregateKind, _ uuid.UUID, input application.SavedViewReplaceInput) (application.SavedViewMutationResult, error) {
	stub.replaceCalls++
	stub.replaceInput = input
	return application.SavedViewMutationResult{}, application.ErrUnavailable
}

func (*transportSavedViewStub) ArchiveSavedView(context.Context, application.Actor, uuid.UUID, kernel.AggregateKind, uuid.UUID, application.SavedViewLifecycleInput) (application.SavedViewMutationResult, error) {
	return application.SavedViewMutationResult{}, application.ErrUnavailable
}

func (*transportSavedViewStub) RestoreSavedView(context.Context, application.Actor, uuid.UUID, kernel.AggregateKind, uuid.UUID, application.SavedViewLifecycleInput) (application.SavedViewMutationResult, error) {
	return application.SavedViewMutationResult{}, application.ErrUnavailable
}

func TestSavedViewCreateTransportAcceptsCanonicalEqualityOperator(t *testing.T) {
	tenantID := mustTransportUUIDv7(t)
	userID := mustTransportUUIDv7(t)
	definitionID := mustTransportUUIDv7(t)
	stub := &transportSavedViewStub{}
	router := newSavedViewTestRouter(t, tenantLDAPTransportAuthentication(tenantID, userID), stub)
	body := `{"kind":"alert","name":"Finance queue","spec":{"filters":{"states":["new"],"severities":["high"],"priorities":["urgent"],"queue":"all","custom":[{"definitionId":"` + definitionID.String() + `","expectedDefinitionVersion":4,"operator":"equal","value":"finance"}]},"sort":{"source":"core","coreKey":"updated_at","direction":"desc","nulls":"last"},"columns":[{"source":"core","coreKey":"ticket","width":320,"visible":true,"pin":"start"}]}}`
	var decoded savedViewCreateBody
	decodeRequest := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	decodeRequest.Header.Set("Content-Type", "application/json")
	if err := decodeSLABody(decodeRequest, &decoded); err != nil {
		t.Fatalf("decodeSLABody() error = %v", err)
	}
	if _, err := savedViewSpecInput(decoded.Spec); err != nil {
		t.Fatalf("savedViewSpecInput() error = %v", err)
	}
	request := ticketingMutationRequest(http.MethodPost, "/api/v1/tenants/"+tenantID.String()+"/ticket-views", body)
	request.Header.Set(idempotencyKeyHeader, "saved-view-create-0001")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	assertProblem(t, response, http.StatusServiceUnavailable, "service_unavailable")
	if stub.createCalls != 1 {
		t.Fatalf("CreateSavedView calls = %d, want 1", stub.createCalls)
	}
	if len(stub.createInput.Spec.Filters.Custom) != 1 || stub.createInput.Spec.Filters.Custom[0].Operator != customkernel.FilterEqual {
		t.Fatalf("custom filter = %#v, want canonical equality", stub.createInput.Spec.Filters.Custom)
	}
	if stub.createInput.IdempotencyKey != "saved-view-create-0001" {
		t.Fatalf("idempotency key = %q", stub.createInput.IdempotencyKey)
	}
}

func TestSavedViewCreateTransportRejectsLegacyEqualitySpelling(t *testing.T) {
	tenantID := mustTransportUUIDv7(t)
	userID := mustTransportUUIDv7(t)
	definitionID := mustTransportUUIDv7(t)
	stub := &transportSavedViewStub{}
	router := newSavedViewTestRouter(t, tenantLDAPTransportAuthentication(tenantID, userID), stub)
	body := `{"kind":"alert","name":"Finance queue","spec":{"filters":{"states":[],"severities":[],"priorities":[],"queue":"all","custom":[{"definitionId":"` + definitionID.String() + `","expectedDefinitionVersion":4,"operator":"eq","value":"finance"}]},"sort":{"source":"core","coreKey":"updated_at","direction":"desc","nulls":"last"},"columns":[{"source":"core","coreKey":"ticket","visible":true,"pin":"start"}]}}`
	request := ticketingMutationRequest(http.MethodPost, "/api/v1/tenants/"+tenantID.String()+"/ticket-views", body)
	request.Header.Set(idempotencyKeyHeader, "saved-view-create-0001")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	assertProblem(t, response, http.StatusBadRequest, "invalid_request")
	if stub.createCalls != 0 {
		t.Fatalf("CreateSavedView calls = %d, want 0", stub.createCalls)
	}
}

func TestSavedViewCreateTransportRejectsNoncanonicalOptionalValues(t *testing.T) {
	tenantID := mustTransportUUIDv7(t)
	userID := mustTransportUUIDv7(t)
	for _, fragment := range []string{`"search":""`, `"search":"x"`} {
		stub := &transportSavedViewStub{}
		router := newSavedViewTestRouter(t, tenantLDAPTransportAuthentication(tenantID, userID), stub)
		width := "0"
		if fragment == `"search":""` {
			width = "320"
		}
		body := `{"kind":"alert","name":"Finance queue","spec":{"filters":{"states":[],"severities":[],"priorities":[],"queue":"all",` + fragment + `,"custom":[]},"sort":{"source":"core","coreKey":"updated_at","direction":"desc","nulls":"last"},"columns":[{"source":"core","coreKey":"ticket","width":` + width + `,"visible":true,"pin":"start"}]}}`
		request := ticketingMutationRequest(http.MethodPost, "/api/v1/tenants/"+tenantID.String()+"/ticket-views", body)
		request.Header.Set(idempotencyKeyHeader, "saved-view-create-0001")
		response := httptest.NewRecorder()

		router.ServeHTTP(response, request)

		assertProblem(t, response, http.StatusBadRequest, "invalid_request")
		if stub.createCalls != 0 {
			t.Fatalf("CreateSavedView calls = %d, want 0", stub.createCalls)
		}
	}
}

func TestSavedViewReplaceTransportCarriesExactValidatorAndRevision(t *testing.T) {
	tenantID := mustTransportUUIDv7(t)
	userID := mustTransportUUIDv7(t)
	viewID := mustTransportUUIDv7(t)
	stub := &transportSavedViewStub{}
	router := newSavedViewTestRouter(t, tenantLDAPTransportAuthentication(tenantID, userID), stub)
	body := `{"kind":"case","expectedRevision":7,"name":"My cases","spec":{"filters":{"states":[],"severities":[],"priorities":[],"queue":"all","custom":[]},"sort":{"source":"core","coreKey":"created_at","direction":"asc","nulls":"last"},"columns":[{"source":"core","coreKey":"ticket","visible":true,"pin":"none"}]}}`
	etag := `"sha256-` + strings.Repeat("a", 64) + `"`
	request := ticketingMutationRequest(http.MethodPut, "/api/v1/tenants/"+tenantID.String()+"/ticket-views/"+viewID.String(), body)
	request.Header.Set(idempotencyKeyHeader, "saved-view-replace-0001")
	request.Header.Set(ifMatchHeader, etag)
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	assertProblem(t, response, http.StatusServiceUnavailable, "service_unavailable")
	if stub.replaceCalls != 1 || stub.replaceInput.ExpectedRevision != 7 || stub.replaceInput.ExpectedETag != etag {
		t.Fatalf("replace capture = calls:%d input:%#v", stub.replaceCalls, stub.replaceInput)
	}
}

func TestSavedViewRoutesFailUnavailableWithoutPersistenceBoundary(t *testing.T) {
	tenantID := mustTransportUUIDv7(t)
	userID := mustTransportUUIDv7(t)
	viewID := mustTransportUUIDv7(t)
	router := newSavedViewTestRouter(t, tenantLDAPTransportAuthentication(tenantID, userID), nil)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/"+tenantID.String()+"/ticket-views/"+viewID.String()+"?kind=alert", nil)
	prepareTenantLDAPTransportRequest(request, false)
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	assertProblem(t, response, http.StatusServiceUnavailable, "service_unavailable")
}

func newSavedViewTestRouter(t *testing.T, auth AuthenticationService, savedViews SavedViewService) http.Handler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler, err := NewApplicationHandler(
		fixedChecker{ready: true}, logger, "test", time.Second,
		ApplicationOptions{
			Alerts: &transportAlertStub{}, Audit: &transportSecurityAuditStub{}, Authentication: auth, Authorization: &transportAuthorizationStub{},
			Contacts: &transportContactStub{}, CustomFields: &transportCustomFieldStub{}, DFIR: &transportDFIRStub{}, Environment: "test",
			IdentityProviders: &transportIdentityProviderStub{}, LDAPAdministration: &transportLDAPAdministrationStub{}, MFA: &transportMFAStub{},
			Notifications: &transportNotificationStub{}, OperatorTeams: &transportOperatorTeamStub{}, Platform: &transportPlatformStub{},
			PublicOrigin: "http://localhost:8081", SavedViews: savedViews, ServiceAccounts: &transportServiceAccountStub{},
			SLA: &transportSLAStub{}, Ticketing: &transportTicketingStub{}, WorkflowAdministration: &transportWorkflowAdministrationStub{},
		},
	)
	if err != nil {
		t.Fatalf("NewApplicationHandler() error = %v", err)
	}
	return Router(handler, logger, false)
}
