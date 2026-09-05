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
	contactkernel "github.com/periapsis-im/periapsis/modules/contacts"
	customfieldkernel "github.com/periapsis-im/periapsis/modules/customfields"
	dfirkernel "github.com/periapsis-im/periapsis/modules/dfir"
	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	applicationcontacts "github.com/periapsis-im/periapsis/services/api/internal/contacts"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	applicationcustomfields "github.com/periapsis-im/periapsis/services/api/internal/customfields"
	applicationdfir "github.com/periapsis-im/periapsis/services/api/internal/dfir"
)

type phase4HTTPFixture struct {
	tenantID     uuid.UUID
	userID       uuid.UUID
	membershipID uuid.UUID
	caseID       uuid.UUID
}

type listingContactLinkService struct {
	*transportContactStub
	list func(context.Context, applicationcontacts.Actor, uuid.UUID, applicationcontacts.LinkListInput) (applicationcontacts.LinkPage, error)
}

func (service *listingContactLinkService) ListLinks(
	ctx context.Context,
	actor applicationcontacts.Actor,
	tenantID uuid.UUID,
	input applicationcontacts.LinkListInput,
) (applicationcontacts.LinkPage, error) {
	return service.list(ctx, actor, tenantID, input)
}

func TestTicketContactLinkListsForwardCursorPagination(t *testing.T) {
	fixture := newPhase4HTTPFixture(t)
	alertID := mustTransportUUIDv7(t)
	calls := 0
	service := &listingContactLinkService{
		transportContactStub: &transportContactStub{},
		list: func(
			_ context.Context,
			actor applicationcontacts.Actor,
			tenantID uuid.UUID,
			input applicationcontacts.LinkListInput,
		) (applicationcontacts.LinkPage, error) {
			calls++
			wantKind := contactkernel.TicketAlert
			wantID := alertID
			if calls == 2 {
				wantKind = contactkernel.TicketCase
				wantID = fixture.caseID
			}
			if tenantID != fixture.tenantID || actor.TenantID != fixture.tenantID ||
				actor.UserID != fixture.userID || actor.MembershipID != fixture.membershipID ||
				input.TicketKind != wantKind || input.TicketID != wantID ||
				input.After != "opaque-cursor" || input.Limit != 7 {
				t.Fatalf("unexpected actor/input: %#v %#v", actor, input)
			}
			return applicationcontacts.LinkPage{Items: []contactkernel.TicketContactLink{}}, nil
		},
	}
	router := newPhase4TestRouter(t, fixture, &transportCustomFieldStub{}, &transportDFIRStub{}, service)
	for _, route := range []string{
		"alerts/" + alertID.String(),
		"cases/" + fixture.caseID.String(),
	} {
		request := httptest.NewRequest(
			http.MethodGet,
			"/api/v1/tenants/"+fixture.tenantID.String()+"/"+route+"/contacts?after=opaque-cursor&limit=7",
			nil,
		)
		prepareTenantLDAPTransportRequest(request, false)
		response := httptest.NewRecorder()

		router.ServeHTTP(response, request)

		if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s status/headers = %d/%#v: %s", route, response.Code, response.Header(), response.Body.String())
		}
	}
	if calls != 2 {
		t.Fatalf("contact-link service calls = %d, want 2", calls)
	}
}

func TestRawCustomFieldInputsPreservesExplicitNull(t *testing.T) {
	t.Parallel()
	inputs, err := rawCustomFieldInputs(contract.CustomFieldValues{"nullable_note": nil})
	if err != nil {
		t.Fatal(err)
	}
	if len(inputs) != 1 || inputs[0].Key != "nullable_note" || !inputs[0].Present ||
		string(inputs[0].RawJSON) != "null" {
		t.Fatalf("explicit null input = %#v", inputs)
	}
}

type creatingCustomFieldService struct {
	*transportCustomFieldStub
	create func(context.Context, applicationcustomfields.Actor, uuid.UUID, applicationcustomfields.CreateDefinitionInput) (applicationcustomfields.DefinitionResult, error)
}

type listingCustomFieldService struct {
	*transportCustomFieldStub
	list func(context.Context, applicationcustomfields.Actor, uuid.UUID, applicationcustomfields.DefinitionListInput) (applicationcustomfields.DefinitionPage, error)
}

func (service *listingCustomFieldService) ListDefinitions(
	ctx context.Context,
	actor applicationcustomfields.Actor,
	tenantID uuid.UUID,
	input applicationcustomfields.DefinitionListInput,
) (applicationcustomfields.DefinitionPage, error) {
	return service.list(ctx, actor, tenantID, input)
}

func (service *creatingCustomFieldService) CreateDefinition(
	ctx context.Context,
	actor applicationcustomfields.Actor,
	tenantID uuid.UUID,
	input applicationcustomfields.CreateDefinitionInput,
) (applicationcustomfields.DefinitionResult, error) {
	return service.create(ctx, actor, tenantID, input)
}

func TestPhase4CustomFieldListCompatibilityAliasMatchesCanonicalBoundary(t *testing.T) {
	fixture := newPhase4HTTPFixture(t)
	called := 0
	service := &listingCustomFieldService{
		transportCustomFieldStub: &transportCustomFieldStub{},
		list: func(
			_ context.Context,
			actor applicationcustomfields.Actor,
			tenantID uuid.UUID,
			input applicationcustomfields.DefinitionListInput,
		) (applicationcustomfields.DefinitionPage, error) {
			called++
			if tenantID != fixture.tenantID || actor.TenantID != fixture.tenantID ||
				actor.UserID != fixture.userID || actor.MembershipID != fixture.membershipID ||
				input.ObjectType != customfieldkernel.ObjectAlert || !input.IncludeArchived ||
				input.Limit != 7 || input.After != "opaque-cursor" {
				t.Fatalf("unexpected actor/input: %#v %#v", actor, input)
			}
			return applicationcustomfields.DefinitionPage{Items: []customfieldkernel.Definition{}}, nil
		},
	}
	router := newPhase4TestRouter(t, fixture, service, &transportDFIRStub{})
	for _, collection := range []string{"custom-field-definitions", "custom-fields"} {
		request := httptest.NewRequest(
			http.MethodGet,
			"/api/v1/tenants/"+fixture.tenantID.String()+"/"+collection+"?objectType=alert&includeArchived=true&limit=7&after=opaque-cursor",
			nil,
		)
		prepareTenantLDAPTransportRequest(request, false)
		response := httptest.NewRecorder()

		router.ServeHTTP(response, request)

		if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s status/headers = %d/%#v: %s", collection, response.Code, response.Header(), response.Body.String())
		}
	}
	if called != 2 {
		t.Fatalf("canonical and compatibility service calls = %d, want 2", called)
	}
}

type creatingDFIRService struct {
	*transportDFIRStub
	createIndicator func(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.IndicatorCommand) (applicationdfir.MutationResult[dfirkernel.Indicator], error)
}

type preparingDFIRService struct {
	*transportDFIRStub
	prepare func(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.PrepareUploadCommand) (applicationdfir.PreparedUpload, error)
}

type downloadingDFIRService struct {
	*transportDFIRStub
	prepare func(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.DownloadCommand) (applicationdfir.PreparedDownload, error)
}

func (service *preparingDFIRService) PrepareUpload(
	ctx context.Context,
	actor applicationdfir.Actor,
	tenantID uuid.UUID,
	command applicationdfir.PrepareUploadCommand,
) (applicationdfir.PreparedUpload, error) {
	return service.prepare(ctx, actor, tenantID, command)
}

func (service *downloadingDFIRService) PrepareDownload(
	ctx context.Context,
	actor applicationdfir.Actor,
	tenantID uuid.UUID,
	command applicationdfir.DownloadCommand,
) (applicationdfir.PreparedDownload, error) {
	return service.prepare(ctx, actor, tenantID, command)
}

func (service *creatingDFIRService) CreateIndicator(
	ctx context.Context,
	actor applicationdfir.Actor,
	tenantID uuid.UUID,
	command applicationdfir.IndicatorCommand,
) (applicationdfir.MutationResult[dfirkernel.Indicator], error) {
	return service.createIndicator(ctx, actor, tenantID, command)
}

func TestPhase4CustomFieldCreateUsesLiveActorAndWritesVersionHeaders(t *testing.T) {
	fixture := newPhase4HTTPFixture(t)
	definitionID := mustTransportUUIDv7(t)
	called := 0
	service := &creatingCustomFieldService{
		transportCustomFieldStub: &transportCustomFieldStub{},
		create: func(
			_ context.Context,
			actor applicationcustomfields.Actor,
			tenantID uuid.UUID,
			input applicationcustomfields.CreateDefinitionInput,
		) (applicationcustomfields.DefinitionResult, error) {
			called++
			if tenantID != fixture.tenantID || actor.TenantID != fixture.tenantID ||
				actor.UserID != fixture.userID || actor.MembershipID != fixture.membershipID ||
				actor.Kind != applicationcustomfields.PrincipalHuman || input.IdempotencyKey != "phase4-create-key-0001" ||
				input.Audit.RequestID == uuid.Nil || input.Audit.CorrelationID == uuid.Nil || !input.Audit.IPAddress.IsValid() {
				t.Fatalf("unexpected actor/input: %#v %#v", actor, input)
			}
			definition, err := customfieldkernel.NewDefinition(input.Definition)
			if err != nil {
				t.Fatalf("NewDefinition() error = %v", err)
			}
			return applicationcustomfields.DefinitionResult{Definition: definition}, nil
		},
	}
	router := newPhase4TestRouter(t, fixture, service, &transportDFIRStub{})
	body := phase4CustomFieldDefinitionBody(definitionID)
	probe := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	probe.Header.Set("Content-Type", "application/json")
	var decoded contract.CustomFieldDefinitionCreateRequest
	if err := decodePhase4Body(probe, &decoded); err != nil {
		t.Fatalf("decodePhase4Body() error = %v", err)
	}
	if _, err := customFieldDefinitionInput(fixture.tenantID, definitionID, 1, false, decoded.Definition); err != nil {
		t.Fatalf("customFieldDefinitionInput() error = %v", err)
	}
	request := phase4MutationRequest(http.MethodPost, "/api/v1/tenants/"+fixture.tenantID.String()+"/custom-field-definitions", body, "phase4-create-key-0001")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d, service calls = %d: %s", response.Code, called, response.Body.String())
	}
	if called != 1 || response.Header().Get("ETag") != `"v1"` ||
		response.Header().Get("Cache-Control") != "no-store" ||
		response.Header().Get("Location") != "/api/v1/tenants/"+fixture.tenantID.String()+"/custom-field-definitions/"+definitionID.String() {
		t.Fatalf("called/headers = %d %#v", called, response.Header())
	}
	var representation map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &representation); err != nil || representation["tenantId"] != fixture.tenantID.String() {
		t.Fatalf("representation = %#v, error = %v", representation, err)
	}
}

func TestPhase4CustomFieldCreateCompatibilityAliasReturnsCanonicalLocation(t *testing.T) {
	fixture := newPhase4HTTPFixture(t)
	definitionID := mustTransportUUIDv7(t)
	called := 0
	service := &creatingCustomFieldService{
		transportCustomFieldStub: &transportCustomFieldStub{},
		create: func(
			_ context.Context,
			actor applicationcustomfields.Actor,
			tenantID uuid.UUID,
			input applicationcustomfields.CreateDefinitionInput,
		) (applicationcustomfields.DefinitionResult, error) {
			called++
			if tenantID != fixture.tenantID || actor.TenantID != fixture.tenantID ||
				actor.UserID != fixture.userID || actor.MembershipID != fixture.membershipID ||
				input.IdempotencyKey != "phase4-alias-key-0001" {
				t.Fatalf("unexpected actor/tenant/input: %#v %s %#v", actor, tenantID, input)
			}
			definition, err := customfieldkernel.NewDefinition(input.Definition)
			if err != nil {
				t.Fatalf("NewDefinition() error = %v", err)
			}
			return applicationcustomfields.DefinitionResult{Definition: definition}, nil
		},
	}
	router := newPhase4TestRouter(t, fixture, service, &transportDFIRStub{})
	wantLocation := "/api/v1/tenants/" + fixture.tenantID.String() + "/custom-field-definitions/" + definitionID.String()
	for _, collection := range []string{"custom-field-definitions", "custom-fields"} {
		request := phase4MutationRequest(
			http.MethodPost,
			"/api/v1/tenants/"+fixture.tenantID.String()+"/"+collection,
			phase4CustomFieldDefinitionBody(definitionID),
			"phase4-alias-key-0001",
		)
		response := httptest.NewRecorder()

		router.ServeHTTP(response, request)

		if response.Code != http.StatusCreated || response.Header().Get("Location") != wantLocation ||
			response.Header().Get("ETag") != `"v1"` || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s status/headers = %d/%#v: %s", collection, response.Code, response.Header(), response.Body.String())
		}
	}
	if called != 2 {
		t.Fatalf("canonical and compatibility service calls = %d, want 2", called)
	}
}

func TestPhase4CustomFieldCompatibilityAliasesRejectCanonicalBoundaryViolations(t *testing.T) {
	fixture := newPhase4HTTPFixture(t)
	collections := []string{"custom-field-definitions", "custom-fields"}

	for _, test := range []struct {
		name          string
		query         string
		foreignTenant bool
		mutate        func(*http.Request)
		wantStatus    int
		wantCode      string
	}{
		{name: "missing object type", wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "invalid object type", query: "?objectType=secret", wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "invalid include archived", query: "?objectType=alert&includeArchived=maybe", wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "duplicate object type", query: "?objectType=alert&objectType=case", wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "missing session", query: "?objectType=alert", mutate: func(request *http.Request) { request.Header.Del("Cookie") }, wantStatus: http.StatusUnauthorized, wantCode: "authentication_failed"},
		{name: "mixed cookie and bearer", query: "?objectType=alert", mutate: func(request *http.Request) { request.Header.Set("Authorization", "Bearer attacker") }, wantStatus: http.StatusUnauthorized, wantCode: "authentication_failed"},
		{name: "cross tenant", query: "?objectType=alert", foreignTenant: true, wantStatus: http.StatusForbidden, wantCode: "forbidden"},
	} {
		t.Run("list/"+test.name, func(t *testing.T) {
			for _, collection := range collections {
				calls := 0
				service := &listingCustomFieldService{
					transportCustomFieldStub: &transportCustomFieldStub{},
					list: func(context.Context, applicationcustomfields.Actor, uuid.UUID, applicationcustomfields.DefinitionListInput) (applicationcustomfields.DefinitionPage, error) {
						calls++
						return applicationcustomfields.DefinitionPage{}, applicationcustomfields.ErrUnavailable
					},
				}
				tenantID := fixture.tenantID
				if test.foreignTenant {
					tenantID = mustTransportUUIDv7(t)
				}
				request := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/"+tenantID.String()+"/"+collection+test.query, nil)
				prepareTenantLDAPTransportRequest(request, false)
				if test.mutate != nil {
					test.mutate(request)
				}
				response := httptest.NewRecorder()

				newPhase4TestRouter(t, fixture, service, &transportDFIRStub{}).ServeHTTP(response, request)

				assertProblem(t, response, test.wantStatus, test.wantCode)
				if calls != 0 {
					t.Fatalf("%s reached list service %d times", collection, calls)
				}
			}
		})
	}

	definitionID := mustTransportUUIDv7(t)
	validBody := phase4CustomFieldDefinitionBody(definitionID)
	duplicateBody := strings.Replace(
		validBody,
		`{"definitionId":"`+definitionID.String()+`"`,
		`{"definitionId":"`+definitionID.String()+`","definitionId":"`+definitionID.String()+`"`,
		1,
	)
	for _, test := range []struct {
		name          string
		body          string
		foreignTenant bool
		mutate        func(*http.Request)
		wantStatus    int
		wantCode      string
	}{
		{name: "missing session", body: validBody, mutate: func(request *http.Request) { request.Header.Del("Cookie") }, wantStatus: http.StatusUnauthorized, wantCode: "authentication_failed"},
		{name: "mixed cookie and bearer", body: validBody, mutate: func(request *http.Request) { request.Header.Set("Authorization", "Bearer attacker") }, wantStatus: http.StatusUnauthorized, wantCode: "authentication_failed"},
		{name: "missing CSRF", body: validBody, mutate: func(request *http.Request) { request.Header.Del(csrfTokenHeader) }, wantStatus: http.StatusForbidden, wantCode: "forbidden"},
		{name: "cross tenant", body: validBody, foreignTenant: true, wantStatus: http.StatusForbidden, wantCode: "forbidden"},
		{name: "missing idempotency key", body: validBody, mutate: func(request *http.Request) { request.Header.Del(idempotencyKeyHeader) }, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "duplicate idempotency key", body: validBody, mutate: func(request *http.Request) { request.Header.Add(idempotencyKeyHeader, "phase4-alias-key-0002") }, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "comma folded idempotency key", body: validBody, mutate: func(request *http.Request) {
			request.Header.Set(idempotencyKeyHeader, "phase4-alias-key-0001,phase4-alias-key-0002")
		}, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "duplicate body member", body: duplicateBody, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "unknown body member", body: strings.TrimSuffix(validBody, "}") + `,"unexpected":true}`, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "trailing body", body: validBody + `{}`, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "wrong media type", body: validBody, mutate: func(request *http.Request) { request.Header.Set("Content-Type", "text/plain") }, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
	} {
		t.Run("create/"+test.name, func(t *testing.T) {
			for _, collection := range collections {
				calls := 0
				service := &creatingCustomFieldService{
					transportCustomFieldStub: &transportCustomFieldStub{},
					create: func(context.Context, applicationcustomfields.Actor, uuid.UUID, applicationcustomfields.CreateDefinitionInput) (applicationcustomfields.DefinitionResult, error) {
						calls++
						return applicationcustomfields.DefinitionResult{}, applicationcustomfields.ErrUnavailable
					},
				}
				tenantID := fixture.tenantID
				if test.foreignTenant {
					tenantID = mustTransportUUIDv7(t)
				}
				request := phase4MutationRequest(
					http.MethodPost,
					"/api/v1/tenants/"+tenantID.String()+"/"+collection,
					test.body,
					"phase4-alias-key-0001",
				)
				if test.mutate != nil {
					test.mutate(request)
				}
				response := httptest.NewRecorder()

				newPhase4TestRouter(t, fixture, service, &transportDFIRStub{}).ServeHTTP(response, request)

				assertProblem(t, response, test.wantStatus, test.wantCode)
				if calls != 0 {
					t.Fatalf("%s reached create service %d times", collection, calls)
				}
			}
		})
	}
}

func TestPhase4TransportRejectsDuplicateMembersAndMissingPrecondition(t *testing.T) {
	fixture := newPhase4HTTPFixture(t)
	called := 0
	service := &creatingCustomFieldService{
		transportCustomFieldStub: &transportCustomFieldStub{},
		create: func(context.Context, applicationcustomfields.Actor, uuid.UUID, applicationcustomfields.CreateDefinitionInput) (applicationcustomfields.DefinitionResult, error) {
			called++
			return applicationcustomfields.DefinitionResult{}, applicationcustomfields.ErrUnavailable
		},
	}
	router := newPhase4TestRouter(t, fixture, service, &transportDFIRStub{})
	definitionID := mustTransportUUIDv7(t)
	duplicate := `{"definitionId":"` + definitionID.String() + `","definitionId":"` + definitionID.String() + `","definition":{}}`
	request := phase4MutationRequest(http.MethodPost, "/api/v1/tenants/"+fixture.tenantID.String()+"/custom-field-definitions", duplicate, "phase4-create-key-0002")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	assertProblem(t, response, http.StatusBadRequest, "invalid_request")
	if called != 0 {
		t.Fatalf("service called %d times for duplicate member", called)
	}

	replaceBody := `{"expectedVersion":1,"definition":{"objectType":"alert","key":"triage_note","label":"Triage note","description":"","dataType":"short_text","required":false,"nullable":false,"visibility":{"customer":false,"operator":true},"editPolicy":{"customerCreate":false,"customerUpdate":false,"operatorCreate":true,"operatorUpdate":true},"placement":{"showInCreate":true,"showInDetail":true,"showInList":false,"showInExport":false},"requiredOnTransitions":[],"searchable":true,"filterable":false,"sortable":false,"allowStructuredJson":false}}`
	request = phase4MutationRequest(http.MethodPut, "/api/v1/tenants/"+fixture.tenantID.String()+"/custom-field-definitions/"+definitionID.String(), replaceBody, "phase4-replace-key-01")
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	assertProblem(t, response, http.StatusPreconditionRequired, "precondition_required")
}

func TestPhase4DFIRCreateRedactsObservableOnErrorsAndReturnsNoStoreOnSuccess(t *testing.T) {
	fixture := newPhase4HTTPFixture(t)
	indicatorID := mustTransportUUIDv7(t)
	service := &creatingDFIRService{
		transportDFIRStub: &transportDFIRStub{},
		createIndicator: func(
			_ context.Context,
			actor applicationdfir.Actor,
			tenantID uuid.UUID,
			command applicationdfir.IndicatorCommand,
		) (applicationdfir.MutationResult[dfirkernel.Indicator], error) {
			if actor.MembershipID != fixture.membershipID || tenantID != fixture.tenantID || command.Envelope.IdempotencyKey != "phase4-ioc-key-00001" {
				t.Fatalf("unexpected actor/command: %#v %#v", actor, command)
			}
			indicator, err := dfirkernel.NewIndicator(command.Input)
			if err != nil {
				t.Fatalf("NewIndicator() error = %v", err)
			}
			return applicationdfir.MutationResult[dfirkernel.Indicator]{Resource: indicator}, nil
		},
	}
	router := newPhase4TestRouter(t, fixture, &transportCustomFieldStub{}, service)
	body := phase4IndicatorBody(indicatorID, "secret-observable.example")
	request := phase4MutationRequest(http.MethodPost, "/api/v1/tenants/"+fixture.tenantID.String()+"/cases/"+fixture.caseID.String()+"/dfir/iocs", body, "phase4-ioc-key-00001")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusCreated || response.Header().Get("ETag") != `"v1"` || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status/headers = %d %#v: %s", response.Code, response.Header(), response.Body.String())
	}

	service.createIndicator = func(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.IndicatorCommand) (applicationdfir.MutationResult[dfirkernel.Indicator], error) {
		return applicationdfir.MutationResult[dfirkernel.Indicator]{}, applicationdfir.ErrConflict
	}
	request = phase4MutationRequest(http.MethodPost, "/api/v1/tenants/"+fixture.tenantID.String()+"/cases/"+fixture.caseID.String()+"/dfir/iocs", body, "phase4-ioc-key-00002")
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	assertProblem(t, response, http.StatusConflict, "conflict")
	if strings.Contains(response.Body.String(), "secret-observable.example") {
		t.Fatal("problem response leaked the observable")
	}
}

func TestPhase4UploadBindsExactSizeAndRejectsLegacyMaximum(t *testing.T) {
	fixture := newPhase4HTTPFixture(t)
	attachmentID, storageID := mustTransportUUIDv7(t), mustTransportUUIDv7(t)
	calls := 0
	service := &preparingDFIRService{
		transportDFIRStub: &transportDFIRStub{},
		prepare: func(
			_ context.Context,
			_ applicationdfir.Actor,
			tenantID uuid.UUID,
			command applicationdfir.PrepareUploadCommand,
		) (applicationdfir.PreparedUpload, error) {
			calls++
			if tenantID != fixture.tenantID || command.SizeBytes != 4_096 || command.ContentType != "application/octet-stream" {
				t.Fatalf("upload command was not bound to the exact file size: %#v", command)
			}
			return applicationdfir.PreparedUpload{}, applicationdfir.ErrUnavailable
		},
	}
	router := newPhase4TestRouter(t, fixture, &transportCustomFieldStub{}, service)
	path := "/api/v1/tenants/" + fixture.tenantID.String() + "/cases/" + fixture.caseID.String() + "/dfir/attachments/prepare-upload"
	body := `{"attachmentId":"` + attachmentID.String() + `","storageObjectId":"` + storageID.String() + `","subject":{"kind":"case","id":"` + fixture.caseID.String() + `"},"originalFilename":"capture.bin","classification":"internal","requestedVisibility":"private","sizeBytes":4096,"contentType":"application/octet-stream"}`
	request := phase4MutationRequest(http.MethodPost, path, body, "phase4-upload-size-0001")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	assertProblem(t, response, http.StatusServiceUnavailable, "service_unavailable")
	if calls != 1 {
		t.Fatalf("exact-size request service calls = %d, want 1", calls)
	}

	legacyBody := strings.Replace(body, `"sizeBytes":4096`, `"maximumBytes":4096`, 1)
	request = phase4MutationRequest(http.MethodPost, path, legacyBody, "phase4-upload-size-0002")
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	assertProblem(t, response, http.StatusBadRequest, "invalid_request")
	if calls != 1 {
		t.Fatalf("legacy maximum reached service; calls = %d", calls)
	}
}

func TestPhase4CaseDownloadPassesCompleteAuditContext(t *testing.T) {
	fixture := newPhase4HTTPFixture(t)
	attachmentID := mustTransportUUIDv7(t)
	caseEntity, err := dfirEntityID(fixture.caseID)
	if err != nil {
		t.Fatal(err)
	}
	attachmentEntity, err := dfirEntityID(attachmentID)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	service := &downloadingDFIRService{
		transportDFIRStub: &transportDFIRStub{},
		prepare: func(_ context.Context, actor applicationdfir.Actor, tenantID uuid.UUID, command applicationdfir.DownloadCommand) (applicationdfir.PreparedDownload, error) {
			calls++
			if actor.Kind != applicationdfir.PrincipalHuman || tenantID != fixture.tenantID ||
				command.CaseID != caseEntity || command.AttachmentID != attachmentEntity ||
				command.Subject.Kind() != dfirkernel.EntityCase || command.Subject.ID() != caseEntity ||
				command.Audit.RequestID == uuid.Nil || command.Audit.CorrelationID == uuid.Nil ||
				!command.Audit.IPAddress.IsValid() || command.Audit.UserAgent != "case-download-test" ||
				command.Audit.AuthenticationMethod != actor.AuthenticationMethod {
				t.Fatalf("Case download lost exact actor/root/attachment/audit context: actor=%#v command=%#v", actor, command)
			}
			return applicationdfir.PreparedDownload{}, applicationdfir.ErrUnavailable
		},
	}
	router := newPhase4TestRouter(t, fixture, &transportCustomFieldStub{}, service)
	path := "/api/v1/tenants/" + fixture.tenantID.String() + "/cases/" + fixture.caseID.String() +
		"/dfir/attachments/" + attachmentID.String() + "/prepare-download"
	body := `{"subject":{"kind":"case","id":"` + fixture.caseID.String() + `"}}`
	request := phase4MutationRequest(http.MethodPost, path, body, "unused-download-key")
	request.Header.Set("User-Agent", "case-download-test")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	assertProblem(t, response, http.StatusServiceUnavailable, "service_unavailable")
	if calls != 1 {
		t.Fatalf("Case download service calls = %d, want 1", calls)
	}
}

func TestPhase4DomainErrorsUseRFC9457StatusAndNeverCache(t *testing.T) {
	tests := []struct {
		err  error
		code int
		key  string
	}{
		{applicationcustomfields.ErrInvalidInput, http.StatusBadRequest, "invalid_request"},
		{applicationdfir.ErrForbidden, http.StatusForbidden, "forbidden"},
		{applicationcustomfields.ErrNotFound, http.StatusNotFound, "not_found"},
		{applicationdfir.ErrConflict, http.StatusConflict, "conflict"},
		{applicationcustomfields.ErrPreconditionFailed, http.StatusPreconditionFailed, "precondition_failed"},
		{applicationdfir.ErrUnavailable, http.StatusServiceUnavailable, "service_unavailable"},
	}
	for _, test := range tests {
		t.Run(test.key, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/api/v1/phase4-test", nil)
			response := httptest.NewRecorder()
			writeDomainError(response, request, test.err)
			assertProblem(t, response, test.code, test.key)
			if response.Header().Get("Cache-Control") != "no-store" || !strings.HasPrefix(response.Header().Get("Content-Type"), "application/problem+json") {
				t.Fatalf("problem headers = %#v", response.Header())
			}
		})
	}
}

func newPhase4HTTPFixture(t testing.TB) phase4HTTPFixture {
	t.Helper()
	return phase4HTTPFixture{
		tenantID: mustTransportUUIDv7(t), userID: mustTransportUUIDv7(t),
		membershipID: mustTransportUUIDv7(t), caseID: mustTransportUUIDv7(t),
	}
}

func TestPhase4ActorUsesOperatorRouteIntentNotLegacyRole(t *testing.T) {
	t.Parallel()
	for _, role := range []authorization.LegacyMembershipRole{
		authorization.LegacyMembershipRoleTenantAdmin,
		authorization.LegacyMembershipRoleReadOnly,
		authorization.LegacyMembershipRoleCustomerManager,
		authorization.LegacyMembershipRoleCustomerUser,
	} {
		role := role
		t.Run(string(role), func(t *testing.T) {
			t.Parallel()
			tenantID := mustTransportUUIDv7(t)
			userID := mustTransportUUIDv7(t)
			membershipID := mustTransportUUIDv7(t)
			handler := &Handler{authorization: &transportSLAAuthorizationStub{
				authority: authorization.TenantAuthority{
					TenantID: tenantID,
					Principal: authorization.TenantPrincipal{
						ID: userID, Kind: authorization.PrincipalKindHuman,
					},
					MembershipID: membershipID, MembershipStatus: authorization.MembershipStatusActive,
					LegacyRole: role,
				},
			}}
			request := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/"+tenantID.String()+"/custom-field-definitions", nil)
			response := httptest.NewRecorder()
			resolved, ok := handler.resolvePhase4Actor(response, request, authorization.Actor{
				UserID: userID, SessionID: mustTransportUUIDv7(t), ActiveTenantID: tenantID,
				AuthenticationMethod: "totp",
			}, authorization.AuditContext{}, tenantID)
			if !ok || resolved.custom.Kind != applicationcustomfields.PrincipalHuman ||
				resolved.dfir.Kind != applicationdfir.PrincipalHuman {
				t.Fatalf("role %q resolved actor = %#v, ok=%t", role, resolved, ok)
			}
		})
	}
}

func newPhase4TestRouter(t testing.TB, fixture phase4HTTPFixture, customFields CustomFieldService, dfir DFIRService, contactServices ...ContactService) http.Handler {
	return newPhase4TestRouterWithAlertInvestigation(
		t, fixture, customFields, dfir, testEmptyAlertInvestigationService{}, contactServices...,
	)
}

func newPhase4TestRouterWithAlertInvestigation(
	t testing.TB,
	fixture phase4HTTPFixture,
	customFields CustomFieldService,
	dfir DFIRService,
	alertInvestigation AlertInvestigationService,
	contactServices ...ContactService,
) http.Handler {
	t.Helper()
	contacts := ContactService(&transportContactStub{})
	if len(contactServices) > 1 {
		t.Fatal("at most one contact service is supported")
	}
	if len(contactServices) == 1 {
		contacts = contactServices[0]
	}
	auth := &transportAuthStub{authenticateResult: authentication.Session{
		ID: mustTransportUUIDv7(t), User: authentication.User{ID: fixture.userID}, ActiveTenantID: &fixture.tenantID,
		AuthenticationMethod: "totp",
	}}
	authorizationService := &tenantAuthorizationTransportStub{getAuthorityFunc: func(
		_ context.Context,
		actor authorization.Actor,
		tenantID uuid.UUID,
	) (authorization.TenantAuthority, error) {
		if tenantID != fixture.tenantID || actor.UserID != fixture.userID || actor.ActiveTenantID != fixture.tenantID {
			return authorization.TenantAuthority{}, authorization.ErrForbidden
		}
		return authorization.TenantAuthority{
			TenantID: tenantID, Principal: authorization.TenantPrincipal{ID: fixture.userID, Kind: authorization.PrincipalKindHuman},
			MembershipID: fixture.membershipID, MembershipStatus: authorization.MembershipStatusActive,
			LegacyRole: authorization.LegacyMembershipRoleTenantAdmin, EvaluatedAt: time.Now().UTC(),
		}, nil
	}}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler, err := NewApplicationHandler(fixedChecker{ready: true}, logger, "test", time.Second, ApplicationOptions{
		Alerts: &transportAlertStub{}, Audit: &transportSecurityAuditStub{}, Authentication: auth, Authorization: authorizationService,
		AlertInvestigation: alertInvestigation, Contacts: contacts, CustomFields: customFields, DFIR: dfir, Environment: "test",
		IdentityProviders: &transportIdentityProviderStub{}, LDAPAdministration: &transportLDAPAdministrationStub{}, MFA: &transportMFAStub{},
		Notifications: &transportNotificationStub{}, OperatorTeams: &transportOperatorTeamStub{}, Platform: &transportPlatformStub{},
		PublicOrigin: "http://localhost:8081", ServiceAccounts: &transportServiceAccountStub{}, SLA: &transportSLAStub{}, Ticketing: &transportTicketingStub{}, WorkflowAdministration: &transportWorkflowAdministrationStub{},
	})
	if err != nil {
		t.Fatalf("NewApplicationHandler() error = %v", err)
	}
	return Router(handler, logger, false)
}

type testEmptyAlertInvestigationService struct {
	unavailableAlertInvestigationService
}

func (testEmptyAlertInvestigationService) Workspace(
	context.Context,
	applicationdfir.Actor,
	uuid.UUID,
	dfirkernel.EntityID,
) (applicationdfir.AlertInvestigationWorkspace, error) {
	return applicationdfir.AlertInvestigationWorkspace{
		Evidence: []dfirkernel.AlertEvidence{}, Tasks: []dfirkernel.AlertTask{},
		Relationships: []dfirkernel.AlertRelationship{},
	}, nil
}

func phase4MutationRequest(method, path, body, key string) *http.Request {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	prepareTenantLDAPTransportRequest(request, true)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(idempotencyKeyHeader, key)
	return request
}

func phase4IndicatorBody(indicatorID uuid.UUID, observable string) string {
	return `{"indicatorId":"` + indicatorID.String() + `","indicator":{"type":"domain","value":"` + observable + `","description":"sensitive context","source":"analyst","confidence":80,"tlp":"amber","firstSeen":"2026-08-25T10:00:00Z","lastSeen":"2026-08-25T10:00:00Z","malicious":"suspicious","tags":[]}}`
}

func phase4CustomFieldDefinitionBody(definitionID uuid.UUID) string {
	return `{"definitionId":"` + definitionID.String() + `","definition":{"objectType":"alert","key":"triage_note","label":"Triage note","description":"","dataType":"short_text","required":false,"nullable":false,"visibility":{"customer":false,"operator":true},"editPolicy":{"customerCreate":false,"customerUpdate":false,"operatorCreate":true,"operatorUpdate":true},"placement":{"showInCreate":true,"showInDetail":true,"showInList":false,"showInExport":false},"requiredOnTransitions":[],"searchable":true,"filterable":false,"sortable":false,"allowStructuredJson":false}}`
}
