package httpserver

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/customfields"
	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	application "github.com/periapsis-im/periapsis/services/api/internal/customfieldimport"
)

type customFieldImportHTTPStub struct {
	unavailableCustomFieldImportService
	request func(context.Context, application.Actor, uuid.UUID, application.RequestInput) (application.Result, error)
	get     func(context.Context, application.Actor, uuid.UUID, kernel.ObjectType, uuid.UUID) (application.Record, error)
	cancel  func(context.Context, application.Actor, uuid.UUID, kernel.ObjectType, uuid.UUID, application.CancelInput) (application.Result, error)
	list    func(context.Context, application.Actor, uuid.UUID, kernel.ObjectType, uuid.UUID, uint32, int) (application.ResultPage, error)
}

func (stub *customFieldImportHTTPStub) Request(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	input application.RequestInput,
) (application.Result, error) {
	return stub.request(ctx, actor, tenantID, input)
}

func (stub *customFieldImportHTTPStub) Get(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	objectType kernel.ObjectType,
	jobID uuid.UUID,
) (application.Record, error) {
	return stub.get(ctx, actor, tenantID, objectType, jobID)
}

func (stub *customFieldImportHTTPStub) Cancel(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	objectType kernel.ObjectType,
	jobID uuid.UUID,
	input application.CancelInput,
) (application.Result, error) {
	return stub.cancel(ctx, actor, tenantID, objectType, jobID, input)
}

func (stub *customFieldImportHTTPStub) ListResults(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	objectType kernel.ObjectType,
	jobID uuid.UUID,
	after uint32,
	pageSize int,
) (application.ResultPage, error) {
	return stub.list(ctx, actor, tenantID, objectType, jobID, after, pageSize)
}

func TestCustomFieldImportRequestPreservesPresenceAndWritesPrivateReplayHeaders(t *testing.T) {
	fixture := newPhase4HTTPFixture(t)
	targetID := mustTransportUUIDv7(t)
	jobID := mustTransportUUIDv7(t)
	now := time.Date(2026, 9, 3, 10, 0, 0, 123_456_000, time.UTC)
	job := newCustomFieldImportTransportJob(
		t, fixture, jobID, targetID, kernel.ObjectAlert, kernel.ImportCommit, now,
	)
	calls := 0
	service := &customFieldImportHTTPStub{}
	service.request = func(
		_ context.Context,
		actor application.Actor,
		tenantID uuid.UUID,
		input application.RequestInput,
	) (application.Result, error) {
		calls++
		if tenantID != fixture.tenantID || actor.UserID != fixture.userID ||
			actor.MembershipID != fixture.membershipID || actor.Audit.RequestID == uuid.Nil ||
			input.ObjectType != kernel.ObjectAlert || input.Mode != kernel.ImportCommit ||
			input.Retention != customFieldImportDefaultRetention ||
			input.IdempotencyKey != "custom-import-key-0001" || len(input.Rows) != 1 ||
			input.Rows[0].Target != targetID || input.Rows[0].ExpectedVersion != 7 ||
			len(input.Rows[0].Fields) != 3 {
			t.Fatalf("unexpected request actor/input: %#v %#v", actor, input)
		}
		fields := input.Rows[0].Fields
		if fields[0].Key != "missing" || fields[0].Present || len(fields[0].RawJSON) != 0 ||
			fields[1].Key != "nullable" || !fields[1].Present || string(fields[1].RawJSON) != "null" ||
			fields[2].Key != "empty" || !fields[2].Present || string(fields[2].RawJSON) != `""` {
			t.Fatalf("presence projection = %#v", fields)
		}
		return application.Result{Record: application.Record{Job: job}, Replayed: true}, nil
	}
	request := phase4MutationRequest(
		http.MethodPost,
		"/api/v1/tenants/"+fixture.tenantID.String()+"/custom-field-imports",
		`{"objectType":"alert","mode":"commit","rows":[{"targetId":"`+targetID.String()+`","expectedVersion":7,"fields":[{"key":"missing"},{"key":"nullable","value":null},{"key":"empty","value":""}]}]}`,
		"custom-import-key-0001",
	)
	response := httptest.NewRecorder()

	newCustomFieldImportTestRouter(t, fixture, service).ServeHTTP(response, request)

	if response.Code != http.StatusAccepted || calls != 1 ||
		response.Header().Get("Cache-Control") != "private, no-store" ||
		response.Header().Get("ETag") != `"v1"` ||
		response.Header().Get(idempotentReplayHeader) != "true" ||
		response.Header().Get("Location") != "/api/v1/tenants/"+fixture.tenantID.String()+
			"/custom-field-imports/"+jobID.String() {
		t.Fatalf("response = %d headers=%#v calls=%d body=%s", response.Code, response.Header(), calls, response.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || body["replayed"] != true {
		t.Fatalf("mutation body = %#v, error=%v", body, err)
	}
}

func TestCustomFieldImportReadResultsAndCancellationContract(t *testing.T) {
	fixture := newPhase4HTTPFixture(t)
	targetID := mustTransportUUIDv7(t)
	jobID := mustTransportUUIDv7(t)
	now := time.Date(2026, 9, 3, 11, 0, 0, 654_321_000, time.UTC)
	pending := newCustomFieldImportTransportJob(
		t, fixture, jobID, targetID, kernel.ObjectCase, kernel.ImportDryRun, now,
	)
	cancelled, err := kernel.RequestImportCancellation(pending, 1, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	rowResult, err := kernel.NewImportRowResult(1, kernel.ImportRowNoChange, 7, nil)
	if err != nil {
		t.Fatal(err)
	}
	service := &customFieldImportHTTPStub{}
	service.get = func(
		_ context.Context,
		actor application.Actor,
		tenantID uuid.UUID,
		objectType kernel.ObjectType,
		requestedJobID uuid.UUID,
	) (application.Record, error) {
		if actor.UserID != fixture.userID || tenantID != fixture.tenantID ||
			objectType != kernel.ObjectCase || requestedJobID != jobID {
			t.Fatal("read coordinates diverged")
		}
		return application.Record{Job: pending}, nil
	}
	service.list = func(
		_ context.Context,
		_ application.Actor,
		_ uuid.UUID,
		_ kernel.ObjectType,
		_ uuid.UUID,
		after uint32,
		pageSize int,
	) (application.ResultPage, error) {
		if after != 0 || pageSize != 100 {
			t.Fatalf("pagination = %d/%d", after, pageSize)
		}
		return application.ResultPage{Items: []application.RowResult{{
			Sequence: 1, Target: targetID, ExpectedVersion: 7,
			Result: rowResult, RecordedAt: now.Add(time.Second),
		}}}, nil
	}
	cancelCalls := 0
	service.cancel = func(
		_ context.Context,
		_ application.Actor,
		_ uuid.UUID,
		objectType kernel.ObjectType,
		requestedJobID uuid.UUID,
		input application.CancelInput,
	) (application.Result, error) {
		cancelCalls++
		if objectType != kernel.ObjectCase || requestedJobID != jobID ||
			input.ExpectedRevision != 1 || input.IdempotencyKey != "custom-cancel-key-001" ||
			input.Audit.RequestID == uuid.Nil {
			t.Fatalf("cancel input = %#v", input)
		}
		return application.Result{Record: application.Record{Job: cancelled}}, nil
	}
	router := newCustomFieldImportTestRouter(t, fixture, service)

	for path, wantBody := range map[string]string{
		"/api/v1/tenants/" + fixture.tenantID.String() + "/custom-field-imports/" + jobID.String() + "?objectType=case":                      `"state":"pending"`,
		"/api/v1/tenants/" + fixture.tenantID.String() + "/custom-field-imports/" + jobID.String() + "/results?objectType=case&pageSize=100": `"outcome":"no_change"`,
	} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		prepareTenantLDAPTransportRequest(request, false)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "private, no-store" ||
			!strings.Contains(response.Body.String(), wantBody) {
			t.Fatalf("GET %s = %d %#v %s", path, response.Code, response.Header(), response.Body.String())
		}
	}

	cancelRequest := phase4MutationRequest(
		http.MethodPost,
		"/api/v1/tenants/"+fixture.tenantID.String()+"/custom-field-imports/"+jobID.String()+"/cancel",
		`{"objectType":"case","expectedRevision":1}`,
		"custom-cancel-key-001",
	)
	cancelRequest.Header.Set(ifMatchHeader, `"v1"`)
	cancelResponse := httptest.NewRecorder()
	router.ServeHTTP(cancelResponse, cancelRequest)
	if cancelResponse.Code != http.StatusOK || cancelCalls != 1 ||
		cancelResponse.Header().Get("Cache-Control") != "private, no-store" ||
		cancelResponse.Header().Get("ETag") != `"v2"` ||
		cancelResponse.Header().Get(idempotentReplayHeader) != "false" ||
		!strings.Contains(cancelResponse.Body.String(), `"state":"cancelled"`) {
		t.Fatalf("cancel = %d %#v calls=%d body=%s", cancelResponse.Code, cancelResponse.Header(), cancelCalls, cancelResponse.Body.String())
	}
}

func TestCustomFieldImportCancellationRequiresMatchingStrongPrecondition(t *testing.T) {
	fixture := newPhase4HTTPFixture(t)
	jobID := mustTransportUUIDv7(t)
	service := &customFieldImportHTTPStub{}
	service.cancel = func(context.Context, application.Actor, uuid.UUID, kernel.ObjectType, uuid.UUID, application.CancelInput) (application.Result, error) {
		t.Fatal("invalid precondition reached the service")
		return application.Result{}, nil
	}
	router := newCustomFieldImportTestRouter(t, fixture, service)
	for name, test := range map[string]struct {
		etag         string
		bodyRevision int
		wantStatus   int
		wantCode     string
	}{
		"missing":  {bodyRevision: 1, wantStatus: http.StatusPreconditionRequired, wantCode: "precondition_required"},
		"mismatch": {etag: `"v2"`, bodyRevision: 1, wantStatus: http.StatusPreconditionFailed, wantCode: "precondition_failed"},
	} {
		t.Run(name, func(t *testing.T) {
			request := phase4MutationRequest(
				http.MethodPost,
				"/api/v1/tenants/"+fixture.tenantID.String()+"/custom-field-imports/"+jobID.String()+"/cancel",
				`{"objectType":"alert","expectedRevision":`+strconv.Itoa(test.bodyRevision)+`}`,
				"custom-cancel-key-002",
			)
			if test.etag != "" {
				request.Header.Set(ifMatchHeader, test.etag)
			}
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			assertProblem(t, response, test.wantStatus, test.wantCode)
		})
	}
}

func newCustomFieldImportTransportJob(
	t testing.TB,
	fixture phase4HTTPFixture,
	jobID uuid.UUID,
	targetID uuid.UUID,
	objectType kernel.ObjectType,
	mode kernel.ImportMode,
	requestedAt time.Time,
) kernel.ImportJob {
	t.Helper()
	entity := func(value uuid.UUID) kernel.EntityID {
		parsed, err := kernel.ParseEntityID(value.String())
		if err != nil {
			t.Fatal(err)
		}
		return parsed
	}
	manifest, err := kernel.NewImportManifest(kernel.ImportManifestInput{
		ID: entity(jobID), Tenant: entity(fixture.tenantID), Requester: entity(fixture.userID),
		OwnerMembership: entity(fixture.membershipID), ObjectType: objectType, Mode: mode,
		Rows: []kernel.ImportRowInput{{
			Sequence: 1, Target: entity(targetID), ExpectedVersion: 7,
		}},
		ProjectionVersion: kernel.ImportProjectionVersion,
		MaximumAttempts:   kernel.ImportMaximumAttempts,
	})
	if err != nil {
		t.Fatal(err)
	}
	job, err := kernel.NewImportJob(manifest, requestedAt, requestedAt.Add(customFieldImportDefaultRetention))
	if err != nil {
		t.Fatal(err)
	}
	return job
}

func newCustomFieldImportTestRouter(
	t testing.TB,
	fixture phase4HTTPFixture,
	imports CustomFieldImportService,
) http.Handler {
	t.Helper()
	auth := &transportAuthStub{authenticateResult: authentication.Session{
		ID: mustTransportUUIDv7(t), User: authentication.User{ID: fixture.userID},
		ActiveTenantID: &fixture.tenantID, AuthenticationMethod: "totp",
	}}
	authorizationService := &tenantAuthorizationTransportStub{getAuthorityFunc: func(
		_ context.Context,
		actor authorization.Actor,
		tenantID uuid.UUID,
	) (authorization.TenantAuthority, error) {
		if tenantID != fixture.tenantID || actor.UserID != fixture.userID ||
			actor.ActiveTenantID != fixture.tenantID {
			return authorization.TenantAuthority{}, authorization.ErrForbidden
		}
		return authorization.TenantAuthority{
			TenantID: tenantID,
			Principal: authorization.TenantPrincipal{
				ID: fixture.userID, Kind: authorization.PrincipalKindHuman,
			},
			MembershipID: fixture.membershipID, MembershipStatus: authorization.MembershipStatusActive,
			LegacyRole: authorization.LegacyMembershipRoleTenantAdmin, EvaluatedAt: time.Now().UTC(),
		}, nil
	}}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler, err := NewApplicationHandler(
		fixedChecker{ready: true}, logger, "test", time.Second,
		ApplicationOptions{
			Alerts: &transportAlertStub{}, Audit: &transportSecurityAuditStub{},
			Authentication: auth, Authorization: authorizationService,
			Contacts: &transportContactStub{}, CustomFields: &transportCustomFieldStub{},
			CustomFieldImports: imports, DFIR: &transportDFIRStub{}, Environment: "test",
			IdentityProviders:  &transportIdentityProviderStub{},
			LDAPAdministration: &transportLDAPAdministrationStub{}, MFA: &transportMFAStub{},
			Notifications: &transportNotificationStub{}, OperatorTeams: &transportOperatorTeamStub{},
			Platform: &transportPlatformStub{}, PublicOrigin: "http://localhost:8081",
			ServiceAccounts: &transportServiceAccountStub{}, SLA: &transportSLAStub{},
			Ticketing: &transportTicketingStub{}, WorkflowAdministration: &transportWorkflowAdministrationStub{},
		},
	)
	if err != nil {
		t.Fatalf("NewApplicationHandler() error = %v", err)
	}
	return Router(handler, logger, false)
}
