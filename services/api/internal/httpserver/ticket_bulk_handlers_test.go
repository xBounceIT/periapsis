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
	application "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

type transportTicketBulkStub struct {
	requestCalls int
	cancelCalls  int
	resultCalls  int
	requestKind  kernel.AggregateKind
	requestInput application.TicketBulkRequestInput
	cancelKind   kernel.AggregateKind
	cancelID     uuid.UUID
	cancelInput  application.TicketBulkCancelInput
	resultKind   kernel.AggregateKind
	resultID     uuid.UUID
	resultInput  application.TicketBulkResultListInput
}

func (stub *transportTicketBulkStub) Request(_ context.Context, _ application.Actor, _ uuid.UUID, kind kernel.AggregateKind, input application.TicketBulkRequestInput) (application.TicketBulkResult, error) {
	stub.requestCalls++
	stub.requestKind, stub.requestInput = kind, input
	return application.TicketBulkResult{}, application.ErrUnavailable
}

func (*transportTicketBulkStub) Get(context.Context, application.Actor, uuid.UUID, kernel.AggregateKind, uuid.UUID) (application.TicketBulkRecord, error) {
	return application.TicketBulkRecord{}, application.ErrUnavailable
}

func (stub *transportTicketBulkStub) Cancel(_ context.Context, _ application.Actor, _ uuid.UUID, kind kernel.AggregateKind, jobID uuid.UUID, input application.TicketBulkCancelInput) (application.TicketBulkResult, error) {
	stub.cancelCalls++
	stub.cancelKind, stub.cancelID, stub.cancelInput = kind, jobID, input
	return application.TicketBulkResult{}, application.ErrUnavailable
}

func (stub *transportTicketBulkStub) ListResults(_ context.Context, _ application.Actor, _ uuid.UUID, kind kernel.AggregateKind, jobID uuid.UUID, input application.TicketBulkResultListInput) (application.TicketBulkResultPage, error) {
	stub.resultCalls++
	stub.resultKind, stub.resultID, stub.resultInput = kind, jobID, input
	return application.TicketBulkResultPage{}, application.ErrUnavailable
}

func TestTicketBulkExplicitRequestTransportPreservesExactPinsAndDefaultRetention(t *testing.T) {
	tenantID, userID := mustTransportUUIDv7(t), mustTransportUUIDv7(t)
	first, second := mustTransportUUIDv7(t), mustTransportUUIDv7(t)
	stub := &transportTicketBulkStub{}
	router := newTicketBulkTestRouter(t, tenantLDAPTransportAuthentication(tenantID, userID), stub)
	body := `{"kind":"alert","selection":{"source":"explicit","targets":[{"id":"` + first.String() + `","expectedVersion":7},{"id":"` + second.String() + `","expectedVersion":9}]},"mutation":{"action":"release"}}`
	request := ticketingMutationRequest(http.MethodPost, "/api/v1/tenants/"+tenantID.String()+"/ticket-bulk-jobs", body)
	request.Header.Set(idempotencyKeyHeader, "ticket-bulk-request-0001")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	assertProblem(t, response, http.StatusServiceUnavailable, "service_unavailable")
	if stub.requestCalls != 1 || stub.requestKind != kernel.AggregateAlert {
		t.Fatalf("request capture = calls:%d kind:%s", stub.requestCalls, stub.requestKind)
	}
	input := stub.requestInput
	if input.IdempotencyKey != "ticket-bulk-request-0001" || input.Retention != 0 ||
		input.Mutation.Action != "release" || len(input.Selection.Explicit) != 2 || input.Selection.Query != nil ||
		input.Selection.Explicit[0].ID != first || input.Selection.Explicit[0].ExpectedVersion != 7 ||
		input.Selection.Explicit[1].ID != second || input.Selection.Explicit[1].ExpectedVersion != 9 {
		t.Fatalf("request input = %#v", input)
	}
}

func TestTicketBulkSavedViewRequestTransportPreservesDigestRevisionAndRetention(t *testing.T) {
	tenantID, userID := mustTransportUUIDv7(t), mustTransportUUIDv7(t)
	viewID, teamID, assigneeID := mustTransportUUIDv7(t), mustTransportUUIDv7(t), mustTransportUUIDv7(t)
	digest := strings.Repeat("ab", 32)
	stub := &transportTicketBulkStub{}
	router := newTicketBulkTestRouter(t, tenantLDAPTransportAuthentication(tenantID, userID), stub)
	body := `{"kind":"case","selection":{"source":"query","query":{"source":"saved_view","savedView":{"id":"` + viewID.String() + `","expectedRevision":11,"expectedSpecSha256":"` + digest + `"}}},"mutation":{"action":"transfer","teamId":"` + teamID.String() + `","assigneeId":"` + assigneeID.String() + `"},"retentionSeconds":3600}`
	request := ticketingMutationRequest(http.MethodPost, "/api/v1/tenants/"+tenantID.String()+"/ticket-bulk-jobs", body)
	request.Header.Set(idempotencyKeyHeader, "ticket-bulk-request-0002")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	assertProblem(t, response, http.StatusServiceUnavailable, "service_unavailable")
	input := stub.requestInput
	if stub.requestCalls != 1 || stub.requestKind != kernel.AggregateCase || input.Retention != time.Hour ||
		input.Selection.Query == nil || input.Selection.Query.SavedView == nil || input.Selection.Query.Inline != nil ||
		input.Selection.Query.SavedView.ID != viewID || input.Selection.Query.SavedView.ExpectedRevision != 11 ||
		input.Mutation.Action != "transfer" || input.Mutation.TeamID != teamID || input.Mutation.AssigneeID == nil ||
		*input.Mutation.AssigneeID != assigneeID {
		t.Fatalf("request input = %#v", input)
	}
	if got := hexDigest(input.Selection.Query.SavedView.ExpectedSpecDigest); got != digest {
		t.Fatalf("digest = %q, want %q", got, digest)
	}
}

func TestTicketBulkTransportRejectsNullUnknownAndNonCanonicalShapesBeforeUseCase(t *testing.T) {
	tenantID, userID := mustTransportUUIDv7(t), mustTransportUUIDv7(t)
	targetID := mustTransportUUIDv7(t)
	for _, body := range []string{
		`{"kind":"alert","selection":{"source":"explicit","targets":null},"mutation":{"action":"release"}}`,
		`{"kind":"alert","selection":{"source":"explicit","targets":[{"id":"` + targetID.String() + `","expectedVersion":1}]},"mutation":{"action":"release","teamId":null}}`,
		`{"kind":"alert","selection":{"source":"explicit","targets":[{"id":"` + targetID.String() + `","expectedVersion":1}]},"mutation":{"action":"release"},"retentionSeconds":null}`,
		`{"kind":"alert","selection":{"source":"explicit","targets":[{"id":"` + targetID.String() + `","expectedVersion":1,"secret":"x"}]},"mutation":{"action":"release"}}`,
		`{"kind":"alert","selection":{"source":"explicit","targets":[{"id":"` + targetID.String() + `","expectedVersion":1}]},"mutation":{"action":"release","teamId":"` + targetID.String() + `"}}`,
	} {
		stub := &transportTicketBulkStub{}
		router := newTicketBulkTestRouter(t, tenantLDAPTransportAuthentication(tenantID, userID), stub)
		request := ticketingMutationRequest(http.MethodPost, "/api/v1/tenants/"+tenantID.String()+"/ticket-bulk-jobs", body)
		request.Header.Set(idempotencyKeyHeader, "ticket-bulk-request-0003")
		response := httptest.NewRecorder()

		router.ServeHTTP(response, request)

		assertProblem(t, response, http.StatusBadRequest, "invalid_request")
		if stub.requestCalls != 0 {
			t.Fatalf("Request calls = %d for %s", stub.requestCalls, body)
		}
	}
}

func TestTicketBulkTransportRejectsUppercaseOrZeroSavedViewDigest(t *testing.T) {
	tenantID, userID, viewID := mustTransportUUIDv7(t), mustTransportUUIDv7(t), mustTransportUUIDv7(t)
	for _, digest := range []string{strings.Repeat("AB", 32), strings.Repeat("0", 64)} {
		stub := &transportTicketBulkStub{}
		router := newTicketBulkTestRouter(t, tenantLDAPTransportAuthentication(tenantID, userID), stub)
		body := `{"kind":"alert","selection":{"source":"query","query":{"source":"saved_view","savedView":{"id":"` + viewID.String() + `","expectedRevision":1,"expectedSpecSha256":"` + digest + `"}}},"mutation":{"action":"release"}}`
		request := ticketingMutationRequest(http.MethodPost, "/api/v1/tenants/"+tenantID.String()+"/ticket-bulk-jobs", body)
		request.Header.Set(idempotencyKeyHeader, "ticket-bulk-request-0004")
		response := httptest.NewRecorder()

		router.ServeHTTP(response, request)

		assertProblem(t, response, http.StatusBadRequest, "invalid_request")
		if stub.requestCalls != 0 {
			t.Fatalf("Request calls = %d for digest %q", stub.requestCalls, digest)
		}
	}
}

func TestTicketBulkCancelAndResultTransportPreserveOwnerScopedCoordinates(t *testing.T) {
	tenantID, userID, jobID := mustTransportUUIDv7(t), mustTransportUUIDv7(t), mustTransportUUIDv7(t)
	stub := &transportTicketBulkStub{}
	router := newTicketBulkTestRouter(t, tenantLDAPTransportAuthentication(tenantID, userID), stub)
	cancel := ticketingMutationRequest(http.MethodPost, "/api/v1/tenants/"+tenantID.String()+"/ticket-bulk-jobs/"+jobID.String()+"/cancel", `{"kind":"case","expectedRevision":17}`)
	cancel.Header.Set(idempotencyKeyHeader, "ticket-bulk-cancel-0001")
	cancelResponse := httptest.NewRecorder()

	router.ServeHTTP(cancelResponse, cancel)

	assertProblem(t, cancelResponse, http.StatusServiceUnavailable, "service_unavailable")
	if stub.cancelCalls != 1 || stub.cancelKind != kernel.AggregateCase || stub.cancelID != jobID ||
		stub.cancelInput.ExpectedRevision != 17 || stub.cancelInput.IdempotencyKey != "ticket-bulk-cancel-0001" {
		t.Fatalf("cancel capture = %#v", stub)
	}

	list := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/"+tenantID.String()+"/ticket-bulk-jobs/"+jobID.String()+"/results?kind=alert&after=opaque-cursor", nil)
	prepareTenantLDAPTransportRequest(list, false)
	listResponse := httptest.NewRecorder()
	router.ServeHTTP(listResponse, list)

	assertProblem(t, listResponse, http.StatusServiceUnavailable, "service_unavailable")
	if stub.resultCalls != 1 || stub.resultKind != kernel.AggregateAlert || stub.resultID != jobID ||
		stub.resultInput.Limit != 50 || stub.resultInput.After != "opaque-cursor" {
		t.Fatalf("result capture = %#v", stub)
	}
}

func TestTicketBulkRoutesFailUnavailableWithoutDurableBoundary(t *testing.T) {
	tenantID, userID, jobID := mustTransportUUIDv7(t), mustTransportUUIDv7(t), mustTransportUUIDv7(t)
	router := newTicketBulkTestRouter(t, tenantLDAPTransportAuthentication(tenantID, userID), nil)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/"+tenantID.String()+"/ticket-bulk-jobs/"+jobID.String()+"?kind=alert", nil)
	prepareTenantLDAPTransportRequest(request, false)
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	assertProblem(t, response, http.StatusServiceUnavailable, "service_unavailable")
	if got := response.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
}

func TestTicketBulkOptionalRejectsNullAndDuplicateJSONValues(t *testing.T) {
	for _, raw := range []string{"null", "1 2"} {
		var value ticketBulkOptional[int64]
		if err := json.Unmarshal([]byte(raw), &value); err == nil {
			t.Fatalf("json.Unmarshal(%q) unexpectedly succeeded", raw)
		}
	}
}

func newTicketBulkTestRouter(t *testing.T, auth AuthenticationService, ticketBulk TicketBulkService) http.Handler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler, err := NewApplicationHandler(
		fixedChecker{ready: true}, logger, "test", time.Second,
		ApplicationOptions{
			Alerts: &transportAlertStub{}, Audit: &transportSecurityAuditStub{}, Authentication: auth, Authorization: &transportAuthorizationStub{},
			Contacts: &transportContactStub{}, CustomFields: &transportCustomFieldStub{}, DFIR: &transportDFIRStub{}, Environment: "test",
			IdentityProviders: &transportIdentityProviderStub{}, LDAPAdministration: &transportLDAPAdministrationStub{}, MFA: &transportMFAStub{},
			Notifications: &transportNotificationStub{}, OperatorTeams: &transportOperatorTeamStub{}, Platform: &transportPlatformStub{},
			PublicOrigin: "http://localhost:8081", ServiceAccounts: &transportServiceAccountStub{}, SLA: &transportSLAStub{},
			TicketBulk: ticketBulk, Ticketing: &transportTicketingStub{}, WorkflowAdministration: &transportWorkflowAdministrationStub{},
		},
	)
	if err != nil {
		t.Fatalf("NewApplicationHandler() error = %v", err)
	}
	return Router(handler, logger, false)
}

func hexDigest(value [32]byte) string {
	const alphabet = "0123456789abcdef"
	encoded := make([]byte, len(value)*2)
	for index, item := range value {
		encoded[index*2], encoded[index*2+1] = alphabet[item>>4], alphabet[item&15]
	}
	return string(encoded)
}
