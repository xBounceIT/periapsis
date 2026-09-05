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
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	application "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

type transportAsyncExportStub struct {
	requestCalls    int
	getCalls        int
	cancelCalls     int
	prepareCalls    int
	requestTenant   uuid.UUID
	requestKind     kernel.AggregateKind
	requestInput    application.AsyncExportRequestInput
	getTenant       uuid.UUID
	getKind         kernel.AggregateKind
	getAudience     kernel.TicketExportAudience
	getID           uuid.UUID
	cancelTenant    uuid.UUID
	cancelKind      kernel.AggregateKind
	cancelAudience  kernel.TicketExportAudience
	cancelID        uuid.UUID
	cancelInput     application.AsyncExportCancelInput
	prepareActor    application.Actor
	prepareTenant   uuid.UUID
	prepareKind     kernel.AggregateKind
	prepareAudience kernel.TicketExportAudience
	prepareID       uuid.UUID
	requestResult   application.AsyncExportResult
	requestError    error
	getRecord       application.AsyncExportRecord
	getError        error
	cancelResult    application.AsyncExportResult
	cancelError     error
	prepareResult   application.AsyncExportPreparedDownload
	prepareError    error
}

func (stub *transportAsyncExportStub) Request(
	_ context.Context,
	_ application.Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	input application.AsyncExportRequestInput,
) (application.AsyncExportResult, error) {
	stub.requestCalls++
	stub.requestTenant, stub.requestKind, stub.requestInput = tenantID, kind, input
	return stub.requestResult, stub.requestError
}

func (stub *transportAsyncExportStub) Get(
	_ context.Context,
	_ application.Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	audience kernel.TicketExportAudience,
	jobID uuid.UUID,
) (application.AsyncExportRecord, error) {
	stub.getCalls++
	stub.getTenant, stub.getKind, stub.getAudience, stub.getID = tenantID, kind, audience, jobID
	return stub.getRecord, stub.getError
}

func (stub *transportAsyncExportStub) Cancel(
	_ context.Context,
	_ application.Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	audience kernel.TicketExportAudience,
	jobID uuid.UUID,
	input application.AsyncExportCancelInput,
) (application.AsyncExportResult, error) {
	stub.cancelCalls++
	stub.cancelTenant, stub.cancelKind, stub.cancelAudience, stub.cancelID, stub.cancelInput =
		tenantID, kind, audience, jobID, input
	return stub.cancelResult, stub.cancelError
}

func (stub *transportAsyncExportStub) PrepareDownload(
	_ context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	audience kernel.TicketExportAudience,
	jobID uuid.UUID,
) (application.AsyncExportPreparedDownload, error) {
	stub.prepareCalls++
	stub.prepareActor, stub.prepareTenant, stub.prepareKind = actor, tenantID, kind
	stub.prepareAudience, stub.prepareID = audience, jobID
	return stub.prepareResult, stub.prepareError
}

func TestTicketExportSavedViewRequestPreservesExactVersionDigestAndBounds(t *testing.T) {
	tenantID, userID, viewID := mustTransportUUIDv7(t), mustTransportUUIDv7(t), mustTransportUUIDv7(t)
	digest := strings.Repeat("ab", 32)
	stub := &transportAsyncExportStub{requestError: application.ErrUnavailable}
	router := newTicketExportTestRouter(t, tenantLDAPTransportAuthentication(tenantID, userID), stub)
	body := `{"kind":"case","comments":"public_and_private","source":{"source":"saved_view","savedView":{"id":"` + viewID.String() + `","expectedRevision":11,"expectedSpecSha256":"` + digest + `"}},"maximumRows":90000,"maximumBytes":500000000,"retentionSeconds":7200}`
	request := ticketingMutationRequest(http.MethodPost, "/api/v1/tenants/"+tenantID.String()+"/ticket-exports", body)
	request.Header.Set(idempotencyKeyHeader, "ticket-export-request-0001")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	assertProblem(t, response, http.StatusServiceUnavailable, "service_unavailable")
	input := stub.requestInput
	if stub.requestCalls != 1 || stub.requestTenant != tenantID || stub.requestKind != kernel.AggregateCase ||
		input.Audience != kernel.TicketExportAudienceOperator ||
		input.Comments != kernel.TicketExportCommentsPublicAndPrivate || input.Source.Inline != nil ||
		input.Source.SavedView == nil || input.Source.SavedView.ID != viewID ||
		input.Source.SavedView.ExpectedRevision != 11 || ticketExportHexDigest(input.Source.SavedView.ExpectedSpecDigest) != digest ||
		input.MaximumRows != 90_000 || input.MaximumBytes != 500_000_000 || input.Retention != 2*time.Hour ||
		input.IdempotencyKey != "ticket-export-request-0001" {
		t.Fatalf("request capture = %#v", stub)
	}
}

func TestTicketExportInlineRequestPreservesCanonicalSpecAndServiceDefaults(t *testing.T) {
	tenantID, userID := mustTransportUUIDv7(t), mustTransportUUIDv7(t)
	stub := &transportAsyncExportStub{requestError: application.ErrUnavailable}
	router := newTicketExportTestRouter(t, tenantLDAPTransportAuthentication(tenantID, userID), stub)
	body := `{"kind":"alert","comments":"none","source":{"source":"inline","spec":{"filters":{"states":[],"severities":[],"priorities":[],"queue":"all","custom":[]},"sort":{"source":"core","coreKey":"updated_at","direction":"desc","nulls":"last"},"columns":[{"source":"core","coreKey":"ticket","visible":true,"pin":"start"}]}}}`
	request := ticketingMutationRequest(http.MethodPost, "/api/v1/tenants/"+tenantID.String()+"/ticket-exports", body)
	request.Header.Set(idempotencyKeyHeader, "ticket-export-request-0002")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	assertProblem(t, response, http.StatusServiceUnavailable, "service_unavailable")
	input := stub.requestInput
	if stub.requestCalls != 1 || stub.requestKind != kernel.AggregateAlert || input.Source.Inline == nil ||
		input.Source.SavedView != nil || len(input.Source.Inline.Columns) != 1 ||
		input.Source.Inline.Columns[0].CoreKey != "ticket" || input.MaximumRows != 0 ||
		input.MaximumBytes != 0 || input.Retention != 0 {
		t.Fatalf("request input = %#v", input)
	}
}

func TestTicketExportRequestRejectsAmbiguousNullUnknownAndUnboundedInputBeforeUseCase(t *testing.T) {
	tenantID, userID, viewID := mustTransportUUIDv7(t), mustTransportUUIDv7(t), mustTransportUUIDv7(t)
	digest := strings.Repeat("ab", 32)
	validSaved := `{"id":"` + viewID.String() + `","expectedRevision":1,"expectedSpecSha256":"` + digest + `"}`
	for _, body := range []string{
		`{"kind":"alert","comments":"none","source":{"source":"inline","spec":null}}`,
		`{"kind":"alert","comments":"none","source":{"source":"saved_view"}}`,
		`{"kind":"alert","comments":"none","source":{"source":"saved_view","savedView":` + validSaved + `,"spec":{"filters":{},"sort":{},"columns":[]}}}`,
		`{"kind":"alert","comments":"none","source":{"source":"saved_view","savedView":` + validSaved + `},"maximumRows":100001}`,
		`{"kind":"alert","comments":"none","source":{"source":"saved_view","savedView":` + validSaved + `},"maximumBytes":null}`,
		`{"kind":"alert","comments":"none","source":{"source":"inline","spec":{"filters":{"states":[],"severities":[],"priorities":[],"queue":"all","search":null,"custom":[]},"sort":{"source":"core","coreKey":"updated_at","direction":"desc","nulls":"last"},"columns":[{"source":"core","coreKey":"ticket","visible":true,"pin":"start"}]}}}`,
		`{"kind":"alert","comments":"none","audience":"customer","source":{"source":"saved_view","savedView":` + validSaved + `}}`,
		`{"kind":"alert","kind":"case","comments":"none","source":{"source":"saved_view","savedView":` + validSaved + `}}`,
		`{"kind":"alert","comments":"none","source":{"source":"inline","spec":{"filters":{"queue":"all","custom":[]},"sort":{"source":"core","coreKey":"updated_at","direction":"desc","nulls":"last"},"columns":[{"source":"core","coreKey":"ticket","visible":true,"pin":"start"}]}}}`,
		`{"kind":"alert","comments":"none","source":{"source":"inline","spec":{"filters":{"states":[],"severities":[],"priorities":[],"queue":"all","custom":[]},"sort":{"source":"core","coreKey":"updated_at","direction":"desc","nulls":"last"},"columns":[{"source":"core","coreKey":"ticket","pin":"start"}]}}}`,
		`{"kind":"alert","comments":"none","source":{"source":"saved_view","savedView":{"id":"` + viewID.String() + `","expectedSpecSha256":"` + digest + `"}}}`,
		`{"kind":"alert","comments":"none","source":{"source":"saved_view","savedView":{"id":"` + viewID.String() + `","expectedRevision":1,"expectedSpecSha256":"` + strings.Repeat("AB", 32) + `"}}}`,
	} {
		stub := &transportAsyncExportStub{requestError: application.ErrUnavailable}
		router := newTicketExportTestRouter(t, tenantLDAPTransportAuthentication(tenantID, userID), stub)
		request := ticketingMutationRequest(http.MethodPost, "/api/v1/tenants/"+tenantID.String()+"/ticket-exports", body)
		request.Header.Set(idempotencyKeyHeader, "ticket-export-request-0003")
		response := httptest.NewRecorder()

		router.ServeHTTP(response, request)

		assertProblem(t, response, http.StatusBadRequest, "invalid_request")
		if stub.requestCalls != 0 {
			t.Fatalf("Request calls = %d for %s", stub.requestCalls, body)
		}
	}
}

func TestTicketExportGetAndCancelBindOperatorOwnerCoordinates(t *testing.T) {
	tenantID, userID, jobID := mustTransportUUIDv7(t), mustTransportUUIDv7(t), mustTransportUUIDv7(t)
	stub := &transportAsyncExportStub{getError: application.ErrUnavailable, cancelError: application.ErrUnavailable}
	router := newTicketExportTestRouter(t, tenantLDAPTransportAuthentication(tenantID, userID), stub)
	get := httptest.NewRequest(
		http.MethodGet, "/api/v1/tenants/"+tenantID.String()+"/ticket-exports/"+jobID.String()+"?kind=alert", nil,
	)
	prepareTenantLDAPTransportRequest(get, false)
	getResponse := httptest.NewRecorder()
	router.ServeHTTP(getResponse, get)

	assertProblem(t, getResponse, http.StatusServiceUnavailable, "service_unavailable")
	if stub.getCalls != 1 || stub.getTenant != tenantID || stub.getKind != kernel.AggregateAlert ||
		stub.getAudience != kernel.TicketExportAudienceOperator || stub.getID != jobID {
		t.Fatalf("get capture = %#v", stub)
	}

	cancel := ticketingMutationRequest(
		http.MethodPost, "/api/v1/tenants/"+tenantID.String()+"/ticket-exports/"+jobID.String()+"/cancel",
		`{"kind":"case","expectedRevision":17}`,
	)
	cancel.Header.Set(idempotencyKeyHeader, "ticket-export-cancel-0001")
	cancelResponse := httptest.NewRecorder()
	router.ServeHTTP(cancelResponse, cancel)

	assertProblem(t, cancelResponse, http.StatusServiceUnavailable, "service_unavailable")
	if stub.cancelCalls != 1 || stub.cancelTenant != tenantID || stub.cancelKind != kernel.AggregateCase ||
		stub.cancelAudience != kernel.TicketExportAudienceOperator || stub.cancelID != jobID ||
		stub.cancelInput.ExpectedRevision != 17 || stub.cancelInput.IdempotencyKey != "ticket-export-cancel-0001" {
		t.Fatalf("cancel capture = %#v", stub)
	}
}

func TestTicketExportCancelRejectsMissingRequiredMembersBeforeUseCase(t *testing.T) {
	tenantID, userID, jobID := mustTransportUUIDv7(t), mustTransportUUIDv7(t), mustTransportUUIDv7(t)
	for _, body := range []string{
		`{"kind":"alert"}`,
		`{"expectedRevision":1}`,
		`{"kind":"alert","expectedRevision":null}`,
	} {
		stub := &transportAsyncExportStub{cancelError: application.ErrUnavailable}
		router := newTicketExportTestRouter(t, tenantLDAPTransportAuthentication(tenantID, userID), stub)
		request := ticketingMutationRequest(
			http.MethodPost,
			"/api/v1/tenants/"+tenantID.String()+"/ticket-exports/"+jobID.String()+"/cancel",
			body,
		)
		request.Header.Set(idempotencyKeyHeader, "ticket-export-cancel-required-0001")
		response := httptest.NewRecorder()

		router.ServeHTTP(response, request)

		assertProblem(t, response, http.StatusBadRequest, "invalid_request")
		if stub.cancelCalls != 0 {
			t.Fatalf("Cancel calls = %d for %s", stub.cancelCalls, body)
		}
	}
}

func TestTicketExportSuccessfulGetReturnsPrivateBoundedProjection(t *testing.T) {
	record, IDs, _, _ := savedViewTicketExportRecord(t, true)
	stub := &transportAsyncExportStub{getRecord: record}
	router := newTicketExportTestRouter(t, tenantLDAPTransportAuthentication(IDs.tenant, IDs.requester), stub)
	request := httptest.NewRequest(
		http.MethodGet, "/api/v1/tenants/"+IDs.tenant.String()+"/ticket-exports/"+IDs.job.String()+"?kind=case", nil,
	)
	prepareTenantLDAPTransportRequest(request, false)
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", response.Code, response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "private, no-store" ||
		!strings.Contains(response.Body.String(), `"state":"succeeded"`) ||
		strings.Contains(strings.ToLower(response.Body.String()), "fence") ||
		strings.Contains(strings.ToLower(response.Body.String()), "worker") {
		t.Fatalf("response headers/body = %#v %s", response.Header(), response.Body.String())
	}
}

func TestTicketExportPrepareDownloadUsesLiveMutationAuthorityWithoutIdempotency(t *testing.T) {
	record, IDs, _, _ := savedViewTicketExportRecord(t, true)
	artifact := *record.Job.Artifact()
	grantExpiry := artifact.ExpiresAt().Add(-time.Minute)
	stub := &transportAsyncExportStub{prepareResult: application.AsyncExportPreparedDownload{
		Record: record, Artifact: artifact, Grant: application.AsyncExportDownloadGrant{
			TargetURL: "https://storage.invalid/private.csv?X-Amz-Signature=secret",
			ExpiresAt: grantExpiry,
		},
	}}
	auth := tenantLDAPTransportAuthentication(IDs.tenant, IDs.requester)
	router := newTicketExportTestRouter(t, auth, stub)
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/tenants/"+IDs.tenant.String()+"/ticket-exports/"+IDs.job.String()+"/prepare-download?kind=case",
		nil,
	)
	prepareTenantLDAPTransportRequest(request, true)
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", response.Code, response.Body.String())
	}
	var result contract.TicketExportPreparedDownload
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if response.Header().Get("Cache-Control") != "private, no-store" ||
		stub.prepareCalls != 1 || stub.prepareTenant != IDs.tenant || stub.prepareKind != kernel.AggregateCase ||
		stub.prepareAudience != kernel.TicketExportAudienceOperator || stub.prepareID != IDs.job ||
		stub.prepareActor.UserID != IDs.requester || result.Artifact.Id != IDs.artifact ||
		result.DownloadUrl != stub.prepareResult.Grant.TargetURL || !result.ExpiresAt.Equal(grantExpiry) ||
		auth.csrfCalls != 1 {
		t.Fatalf("prepare capture/result = %#v / %#v / %#v", stub, result, response.Header())
	}
}

func TestTicketExportPrepareDownloadRejectsMissingCSRFForeignOrMalformedResponses(t *testing.T) {
	record, IDs, _, _ := savedViewTicketExportRecord(t, true)
	artifact := *record.Job.Artifact()
	valid := application.AsyncExportPreparedDownload{
		Record: record, Artifact: artifact, Grant: application.AsyncExportDownloadGrant{
			TargetURL: "https://storage.invalid/private.csv?signature=secret",
			ExpiresAt: artifact.ExpiresAt().Add(-time.Minute),
		},
	}
	t.Run("missing csrf", func(t *testing.T) {
		stub := &transportAsyncExportStub{prepareResult: valid}
		router := newTicketExportTestRouter(t, tenantLDAPTransportAuthentication(IDs.tenant, IDs.requester), stub)
		request := httptest.NewRequest(
			http.MethodPost,
			"/api/v1/tenants/"+IDs.tenant.String()+"/ticket-exports/"+IDs.job.String()+"/prepare-download?kind=case",
			nil,
		)
		prepareTenantLDAPTransportRequest(request, false)
		response := httptest.NewRecorder()

		router.ServeHTTP(response, request)

		assertProblem(t, response, http.StatusForbidden, "forbidden")
		if stub.prepareCalls != 0 {
			t.Fatal("download preparation reached service without CSRF")
		}
	})

	for name, mutate := range map[string]func(*application.AsyncExportPreparedDownload){
		"foreign tenant": func(prepared *application.AsyncExportPreparedDownload) {
			foreign, _, _, _ := savedViewTicketExportRecord(t, true)
			prepared.Record = foreign
		},
		"artifact drift": func(prepared *application.AsyncExportPreparedDownload) {
			prepared.Artifact = kernel.TicketExportArtifact{}
		},
		"credentialed url": func(prepared *application.AsyncExportPreparedDownload) {
			prepared.Grant.TargetURL = "https://user:secret@storage.invalid/private.csv"
		},
	} {
		t.Run(name, func(t *testing.T) {
			prepared := valid
			mutate(&prepared)
			stub := &transportAsyncExportStub{prepareResult: prepared}
			router := newTicketExportTestRouter(t, tenantLDAPTransportAuthentication(IDs.tenant, IDs.requester), stub)
			request := httptest.NewRequest(
				http.MethodPost,
				"/api/v1/tenants/"+IDs.tenant.String()+"/ticket-exports/"+IDs.job.String()+"/prepare-download?kind=case",
				nil,
			)
			prepareTenantLDAPTransportRequest(request, true)
			response := httptest.NewRecorder()

			router.ServeHTTP(response, request)

			assertProblem(t, response, http.StatusServiceUnavailable, "service_unavailable")
			if stub.prepareCalls != 1 || strings.Contains(response.Body.String(), "storage.invalid") {
				t.Fatalf("calls/body = %d/%s", stub.prepareCalls, response.Body.String())
			}
		})
	}
}

func TestTicketExportTransportRejectsValidCrossCoordinateServiceResponse(t *testing.T) {
	record, IDs, _, _ := savedViewTicketExportRecord(t, false)
	otherTenant := mustTransportUUIDv7(t)
	stub := &transportAsyncExportStub{getRecord: record}
	router := newTicketExportTestRouter(t, tenantLDAPTransportAuthentication(otherTenant, IDs.requester), stub)
	request := httptest.NewRequest(
		http.MethodGet, "/api/v1/tenants/"+otherTenant.String()+"/ticket-exports/"+IDs.job.String()+"?kind=case", nil,
	)
	prepareTenantLDAPTransportRequest(request, false)
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	assertProblem(t, response, http.StatusServiceUnavailable, "service_unavailable")
}

func TestTicketExportRoutesFailUnavailableWithoutDurableBoundary(t *testing.T) {
	tenantID, userID, jobID := mustTransportUUIDv7(t), mustTransportUUIDv7(t), mustTransportUUIDv7(t)
	router := newTicketExportTestRouter(t, tenantLDAPTransportAuthentication(tenantID, userID), nil)
	request := httptest.NewRequest(
		http.MethodGet, "/api/v1/tenants/"+tenantID.String()+"/ticket-exports/"+jobID.String()+"?kind=alert", nil,
	)
	prepareTenantLDAPTransportRequest(request, false)
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	assertProblem(t, response, http.StatusServiceUnavailable, "service_unavailable")
	if got := response.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
}

func newTicketExportTestRouter(
	t *testing.T,
	auth AuthenticationService,
	asyncExports AsyncExportService,
) http.Handler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler, err := NewApplicationHandler(
		fixedChecker{ready: true}, logger, "test", time.Second,
		ApplicationOptions{
			Alerts: &transportAlertStub{}, AsyncExports: asyncExports, Audit: &transportSecurityAuditStub{},
			Authentication: auth, Authorization: &transportAuthorizationStub{}, Contacts: &transportContactStub{},
			CustomFields: &transportCustomFieldStub{}, DFIR: &transportDFIRStub{}, Environment: "test",
			IdentityProviders: &transportIdentityProviderStub{}, LDAPAdministration: &transportLDAPAdministrationStub{},
			MFA: &transportMFAStub{}, Notifications: &transportNotificationStub{}, OperatorTeams: &transportOperatorTeamStub{},
			Platform: &transportPlatformStub{}, PublicOrigin: "http://localhost:8081",
			ServiceAccounts: &transportServiceAccountStub{}, SLA: &transportSLAStub{}, Ticketing: &transportTicketingStub{},
			WorkflowAdministration: &transportWorkflowAdministrationStub{},
		},
	)
	if err != nil {
		t.Fatalf("NewApplicationHandler() error = %v", err)
	}
	return Router(handler, logger, false)
}
