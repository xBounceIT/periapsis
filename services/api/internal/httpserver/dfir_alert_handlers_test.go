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
	dfirkernel "github.com/periapsis-im/periapsis/modules/dfir"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	applicationdfir "github.com/periapsis-im/periapsis/services/api/internal/dfir"
)

type alertTransportDFIRService struct {
	*transportDFIRStub
	workspace        func(context.Context, applicationdfir.Actor, uuid.UUID, dfirkernel.EntityID) (applicationdfir.AlertWorkspace, error)
	createIndicator  func(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.AlertIndicatorCommand) (applicationdfir.MutationResult[dfirkernel.Indicator], error)
	replaceIndicator func(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.AlertIndicatorCommand) (applicationdfir.MutationResult[dfirkernel.Indicator], error)
	createAsset      func(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.AlertAssetCommand) (applicationdfir.MutationResult[dfirkernel.Asset], error)
	replaceAsset     func(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.AlertAssetCommand) (applicationdfir.MutationResult[dfirkernel.Asset], error)
	createTimeline   func(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.AlertTimelineCommand) (applicationdfir.MutationResult[dfirkernel.TimelineEvent], error)
	prepareUpload    func(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.AlertPrepareUploadCommand) (applicationdfir.PreparedUpload, error)
	prepareDownload  func(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.AlertDownloadCommand) (applicationdfir.PreparedDownload, error)
}

func (service *alertTransportDFIRService) AlertWorkspace(ctx context.Context, actor applicationdfir.Actor, tenantID uuid.UUID, alertID dfirkernel.EntityID) (applicationdfir.AlertWorkspace, error) {
	return service.workspace(ctx, actor, tenantID, alertID)
}

func (service *alertTransportDFIRService) CreateAlertIndicator(ctx context.Context, actor applicationdfir.Actor, tenantID uuid.UUID, command applicationdfir.AlertIndicatorCommand) (applicationdfir.MutationResult[dfirkernel.Indicator], error) {
	return service.createIndicator(ctx, actor, tenantID, command)
}

func (service *alertTransportDFIRService) ReplaceAlertIndicator(ctx context.Context, actor applicationdfir.Actor, tenantID uuid.UUID, command applicationdfir.AlertIndicatorCommand) (applicationdfir.MutationResult[dfirkernel.Indicator], error) {
	return service.replaceIndicator(ctx, actor, tenantID, command)
}

func (service *alertTransportDFIRService) CreateAlertAsset(ctx context.Context, actor applicationdfir.Actor, tenantID uuid.UUID, command applicationdfir.AlertAssetCommand) (applicationdfir.MutationResult[dfirkernel.Asset], error) {
	return service.createAsset(ctx, actor, tenantID, command)
}

func (service *alertTransportDFIRService) ReplaceAlertAsset(ctx context.Context, actor applicationdfir.Actor, tenantID uuid.UUID, command applicationdfir.AlertAssetCommand) (applicationdfir.MutationResult[dfirkernel.Asset], error) {
	return service.replaceAsset(ctx, actor, tenantID, command)
}

func (service *alertTransportDFIRService) CreateAlertTimelineEvent(ctx context.Context, actor applicationdfir.Actor, tenantID uuid.UUID, command applicationdfir.AlertTimelineCommand) (applicationdfir.MutationResult[dfirkernel.TimelineEvent], error) {
	return service.createTimeline(ctx, actor, tenantID, command)
}

func (service *alertTransportDFIRService) PrepareAlertUpload(ctx context.Context, actor applicationdfir.Actor, tenantID uuid.UUID, command applicationdfir.AlertPrepareUploadCommand) (applicationdfir.PreparedUpload, error) {
	return service.prepareUpload(ctx, actor, tenantID, command)
}

func (service *alertTransportDFIRService) PrepareAlertDownload(ctx context.Context, actor applicationdfir.Actor, tenantID uuid.UUID, command applicationdfir.AlertDownloadCommand) (applicationdfir.PreparedDownload, error) {
	return service.prepareDownload(ctx, actor, tenantID, command)
}

func TestAlertDFIRRoutesBindExactRootAndReturnAlertProjections(t *testing.T) {
	fixture := newPhase4HTTPFixture(t)
	alertID := mustTransportUUIDv7(t)
	indicatorID := mustTransportUUIDv7(t)
	assetID := mustTransportUUIDv7(t)
	timelineID := mustTransportUUIDv7(t)
	wantAlert, err := dfirEntityID(alertID)
	if err != nil {
		t.Fatal(err)
	}
	service := &alertTransportDFIRService{transportDFIRStub: &transportDFIRStub{}}
	assertRoot := func(actor applicationdfir.Actor, tenantID uuid.UUID, gotAlert dfirkernel.EntityID) {
		t.Helper()
		if tenantID != fixture.tenantID || actor.MembershipID != fixture.membershipID || gotAlert != wantAlert || actor.Kind != applicationdfir.PrincipalHuman {
			t.Fatalf("Alert transport lost actor/tenant/root: actor=%#v tenant=%s alert=%s", actor, tenantID, gotAlert)
		}
	}
	service.workspace = func(_ context.Context, actor applicationdfir.Actor, tenantID uuid.UUID, gotAlert dfirkernel.EntityID) (applicationdfir.AlertWorkspace, error) {
		assertRoot(actor, tenantID, gotAlert)
		return applicationdfir.AlertWorkspace{}, nil
	}
	service.createIndicator = func(_ context.Context, actor applicationdfir.Actor, tenantID uuid.UUID, command applicationdfir.AlertIndicatorCommand) (applicationdfir.MutationResult[dfirkernel.Indicator], error) {
		assertRoot(actor, tenantID, command.AlertID)
		if command.Envelope.IdempotencyKey != "alert-ioc-create-key-0001" || command.ExpectedVersion != 0 {
			t.Fatalf("unexpected Alert IOC create command: %#v", command)
		}
		value, createErr := dfirkernel.NewIndicator(command.Input)
		return applicationdfir.MutationResult[dfirkernel.Indicator]{Resource: value}, createErr
	}
	service.replaceIndicator = func(_ context.Context, actor applicationdfir.Actor, tenantID uuid.UUID, command applicationdfir.AlertIndicatorCommand) (applicationdfir.MutationResult[dfirkernel.Indicator], error) {
		assertRoot(actor, tenantID, command.AlertID)
		if command.Envelope.IdempotencyKey != "alert-ioc-replace-key-001" || command.ExpectedVersion != 3 {
			t.Fatalf("unexpected Alert IOC replace command: %#v", command)
		}
		value, createErr := dfirkernel.NewIndicator(command.Input)
		return applicationdfir.MutationResult[dfirkernel.Indicator]{Resource: value}, createErr
	}
	service.createAsset = func(_ context.Context, actor applicationdfir.Actor, tenantID uuid.UUID, command applicationdfir.AlertAssetCommand) (applicationdfir.MutationResult[dfirkernel.Asset], error) {
		assertRoot(actor, tenantID, command.AlertID)
		if command.ExpectedVersion != 0 {
			t.Fatalf("unexpected Alert asset create version: %d", command.ExpectedVersion)
		}
		value, createErr := dfirkernel.NewAsset(command.Input)
		return applicationdfir.MutationResult[dfirkernel.Asset]{Resource: value}, createErr
	}
	service.replaceAsset = func(_ context.Context, actor applicationdfir.Actor, tenantID uuid.UUID, command applicationdfir.AlertAssetCommand) (applicationdfir.MutationResult[dfirkernel.Asset], error) {
		assertRoot(actor, tenantID, command.AlertID)
		if command.ExpectedVersion != 5 {
			t.Fatalf("unexpected Alert asset replace version: %d", command.ExpectedVersion)
		}
		value, createErr := dfirkernel.NewAsset(command.Input)
		return applicationdfir.MutationResult[dfirkernel.Asset]{Resource: value}, createErr
	}
	service.createTimeline = func(_ context.Context, actor applicationdfir.Actor, tenantID uuid.UUID, command applicationdfir.AlertTimelineCommand) (applicationdfir.MutationResult[dfirkernel.TimelineEvent], error) {
		assertRoot(actor, tenantID, command.Input.AlertID)
		if command.Input.CaseID != (dfirkernel.EntityID{}) || len(command.Input.EvidenceIDs) != 0 ||
			command.Input.EventTime != time.Date(2026, time.August, 25, 10, 0, 0, 0, time.UTC) {
			t.Fatalf("Alert timeline was not an exact autonomous-Alert shape: %#v", command.Input)
		}
		command.Input.IngestedAt = time.Now().UTC().Truncate(time.Microsecond)
		value, createErr := dfirkernel.NewTimelineEvent(command.Input)
		return applicationdfir.MutationResult[dfirkernel.TimelineEvent]{Resource: value}, createErr
	}
	service.prepareUpload = func(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.AlertPrepareUploadCommand) (applicationdfir.PreparedUpload, error) {
		return applicationdfir.PreparedUpload{}, applicationdfir.ErrUnavailable
	}
	service.prepareDownload = func(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.AlertDownloadCommand) (applicationdfir.PreparedDownload, error) {
		return applicationdfir.PreparedDownload{}, applicationdfir.ErrUnavailable
	}
	router := newPhase4TestRouter(t, fixture, &transportCustomFieldStub{}, service)
	base := "/api/v1/tenants/" + fixture.tenantID.String() + "/alerts/" + alertID.String() + "/dfir"

	readRequest := httptest.NewRequest(http.MethodGet, base, nil)
	prepareTenantLDAPTransportRequest(readRequest, false)
	readResponse := httptest.NewRecorder()
	router.ServeHTTP(readResponse, readRequest)
	assertAlertDFIRResponse(t, readResponse, http.StatusOK, alertID, "")

	indicatorSpec := `{"type":"domain","value":"secret-observable.example","description":"sensitive context","source":"analyst","confidence":80,"tlp":"amber","firstSeen":"2026-08-25T10:00:00Z","lastSeen":"2026-08-25T10:00:00Z","malicious":"suspicious","tags":[]}`
	request := phase4MutationRequest(http.MethodPost, base+"/iocs", `{"indicatorId":"`+indicatorID.String()+`","indicator":`+indicatorSpec+`}`, "alert-ioc-create-key-0001")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	assertAlertDFIRResponse(t, response, http.StatusCreated, alertID, `"v1"`)
	assertRequiredNestedEmptyJSONArray(t, response, "indicator", "tags")

	request = phase4MutationRequest(http.MethodPut, base+"/iocs/"+indicatorID.String(), `{"expectedVersion":3,"indicator":`+indicatorSpec+`}`, "alert-ioc-replace-key-001")
	request.Header.Set("If-Match", `"v3"`)
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	assertAlertDFIRResponse(t, response, http.StatusOK, alertID, `"v4"`)

	assetSpec := `{"hostname":"workstation-01","fqdn":"","ipAddresses":[],"macAddresses":[],"assetType":"endpoint","operatingSystem":"","owner":"","businessUnit":"","criticality":"high","environment":"production","externalId":"","tags":[],"firstSeen":"2026-08-25T10:00:00Z","lastSeen":"2026-08-25T10:00:00Z"}`
	request = phase4MutationRequest(http.MethodPost, base+"/assets", `{"assetId":"`+assetID.String()+`","asset":`+assetSpec+`}`, "alert-asset-create-0001")
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	assertAlertDFIRResponse(t, response, http.StatusCreated, alertID, `"v1"`)
	assertRequiredNestedEmptyJSONArray(t, response, "asset", "tags")

	request = phase4MutationRequest(http.MethodPut, base+"/assets/"+assetID.String(), `{"expectedVersion":5,"asset":`+assetSpec+`}`, "alert-asset-replace-001")
	request.Header.Set("If-Match", `"v5"`)
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	assertAlertDFIRResponse(t, response, http.StatusOK, alertID, `"v6"`)

	timelineSpec := `{"eventTime":"2026-08-25T15:30:00+05:30","originalTimezone":"Asia/Kolkata","precision":"second","source":"sensor","category":"process_start","title":"Observed event","description":"private detail","iocIds":[],"assetIds":[],"evidenceIds":[],"tags":[]}`
	request = phase4MutationRequest(http.MethodPost, base+"/timeline-events", `{"timelineEventId":"`+timelineID.String()+`","event":`+timelineSpec+`}`, "alert-timeline-key-0001")
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	assertAlertDFIRResponse(t, response, http.StatusCreated, alertID, `"v1"`)
	assertRequiredNestedEmptyJSONArray(t, response, "event", "tags")
}

func TestAlertDFIRAttachmentRoutesFenceSubjectAndRejectTimelineEvidence(t *testing.T) {
	fixture := newPhase4HTTPFixture(t)
	alertID := mustTransportUUIDv7(t)
	attachmentID, storageID, evidenceID := mustTransportUUIDv7(t), mustTransportUUIDv7(t), mustTransportUUIDv7(t)
	alertEntity, err := dfirEntityID(alertID)
	if err != nil {
		t.Fatal(err)
	}
	uploadCalls, downloadCalls, timelineCalls := 0, 0, 0
	service := &alertTransportDFIRService{transportDFIRStub: &transportDFIRStub{}}
	service.workspace = func(context.Context, applicationdfir.Actor, uuid.UUID, dfirkernel.EntityID) (applicationdfir.AlertWorkspace, error) {
		return applicationdfir.AlertWorkspace{}, applicationdfir.ErrUnavailable
	}
	service.createIndicator = func(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.AlertIndicatorCommand) (applicationdfir.MutationResult[dfirkernel.Indicator], error) {
		return applicationdfir.MutationResult[dfirkernel.Indicator]{}, applicationdfir.ErrUnavailable
	}
	service.replaceIndicator = service.createIndicator
	service.createAsset = func(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.AlertAssetCommand) (applicationdfir.MutationResult[dfirkernel.Asset], error) {
		return applicationdfir.MutationResult[dfirkernel.Asset]{}, applicationdfir.ErrUnavailable
	}
	service.replaceAsset = service.createAsset
	service.createTimeline = func(_ context.Context, _ applicationdfir.Actor, _ uuid.UUID, command applicationdfir.AlertTimelineCommand) (applicationdfir.MutationResult[dfirkernel.TimelineEvent], error) {
		timelineCalls++
		if len(command.Input.EvidenceIDs) != 1 || command.Input.EvidenceIDs[0].String() != evidenceID.String() ||
			command.Input.CaseID != (dfirkernel.EntityID{}) || command.Input.AlertID != alertEntity {
			t.Fatalf("unexpected Alert timeline evidence link: %#v", command.Input)
		}
		return applicationdfir.MutationResult[dfirkernel.TimelineEvent]{}, applicationdfir.ErrUnavailable
	}
	service.prepareUpload = func(_ context.Context, actor applicationdfir.Actor, tenantID uuid.UUID, command applicationdfir.AlertPrepareUploadCommand) (applicationdfir.PreparedUpload, error) {
		uploadCalls++
		if actor.MembershipID != fixture.membershipID || tenantID != fixture.tenantID || command.AlertID != alertEntity ||
			command.Subject.Kind() != dfirkernel.EntityAlert || command.Subject.ID() != alertEntity || command.SizeBytes != 4096 {
			t.Fatalf("unexpected Alert upload command: actor=%#v tenant=%s command=%#v", actor, tenantID, command)
		}
		return applicationdfir.PreparedUpload{}, applicationdfir.ErrUnavailable
	}
	service.prepareDownload = func(_ context.Context, actor applicationdfir.Actor, tenantID uuid.UUID, command applicationdfir.AlertDownloadCommand) (applicationdfir.PreparedDownload, error) {
		downloadCalls++
		if actor.MembershipID != fixture.membershipID || tenantID != fixture.tenantID || command.AlertID != alertEntity ||
			command.AttachmentID.String() != attachmentID.String() || command.Subject.Kind() != dfirkernel.EntityAlert || command.Subject.ID() != alertEntity ||
			command.Audit.RequestID == uuid.Nil || command.Audit.CorrelationID == uuid.Nil || !command.Audit.IPAddress.IsValid() ||
			command.Audit.AuthenticationMethod != actor.AuthenticationMethod {
			t.Fatalf("unexpected Alert download command: actor=%#v tenant=%s command=%#v", actor, tenantID, command)
		}
		return applicationdfir.PreparedDownload{}, applicationdfir.ErrUnavailable
	}
	router := newPhase4TestRouter(t, fixture, &transportCustomFieldStub{}, service)
	base := "/api/v1/tenants/" + fixture.tenantID.String() + "/alerts/" + alertID.String() + "/dfir"
	subject := `{"kind":"alert","id":"` + alertID.String() + `"}`
	uploadBody := `{"attachmentId":"` + attachmentID.String() + `","storageObjectId":"` + storageID.String() + `","subject":` + subject + `,"originalFilename":"capture.bin","classification":"internal","requestedVisibility":"private","sizeBytes":4096,"contentType":"application/octet-stream"}`
	request := phase4MutationRequest(http.MethodPost, base+"/attachments/prepare-upload", uploadBody, "alert-upload-size-0001")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	assertProblem(t, response, http.StatusServiceUnavailable, "service_unavailable")

	request = phase4MutationRequest(http.MethodPost, base+"/attachments/"+attachmentID.String()+"/prepare-download", `{"subject":`+subject+`}`, "unused-download-key")
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	assertProblem(t, response, http.StatusServiceUnavailable, "service_unavailable")
	if uploadCalls != 1 || downloadCalls != 1 {
		t.Fatalf("attachment calls = upload %d, download %d", uploadCalls, downloadCalls)
	}

	timelineID := mustTransportUUIDv7(t)
	timelineBody := `{"timelineEventId":"` + timelineID.String() + `","event":{"eventTime":"2026-08-25T10:00:00Z","originalTimezone":"UTC","precision":"second","source":"sensor","category":"process_start","title":"Observed event","description":"","iocIds":[],"assetIds":[],"evidenceIds":["` + evidenceID.String() + `"],"tags":[]}}`
	request = phase4MutationRequest(http.MethodPost, base+"/timeline-events", timelineBody, "alert-timeline-key-0002")
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	assertProblem(t, response, http.StatusServiceUnavailable, "service_unavailable")
	if timelineCalls != 1 {
		t.Fatalf("Alert timeline with same-root evidence reached service %d times", timelineCalls)
	}
}

func TestAlertDFIRReplaceRejectsTerminalResourceVersion(t *testing.T) {
	t.Parallel()
	request := httptest.NewRequest(http.MethodPut, "/api/v1/tenants/unused/alerts/unused/dfir/iocs/unused", nil)
	request.Header.Set("If-Match", `"v9007199254740991"`)
	response := httptest.NewRecorder()
	if dfirResourcePrecondition(response, request, maximumExactJSONResourceVersion) {
		t.Fatal("terminal resource version was accepted for an incrementing replacement")
	}
	assertProblem(t, response, http.StatusBadRequest, "invalid_request")
}

func TestDFIRProjectionVersionBoundsMatchContract(t *testing.T) {
	t.Parallel()
	if validDfirResourceVersion(0) || !validDfirResourceVersion(3_000_000_000) ||
		!validDfirResourceVersion(uint64(maximumExactJSONResourceVersion)) ||
		validDfirResourceVersion(uint64(maximumExactJSONResourceVersion)+1) {
		t.Fatal("DFIR projection version bounds diverged from DfirResourceVersion")
	}
}

func assertAlertDFIRResponse(t testing.TB, response *httptest.ResponseRecorder, status int, alertID uuid.UUID, etag string) {
	t.Helper()
	if response.Code != status || response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("ETag") != etag {
		t.Fatalf("status/headers = %d %#v: %s", response.Code, response.Header(), response.Body.String())
	}
	var decoded map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got, present := decoded["alertId"]; !present || got != alertID.String() {
		t.Fatalf("response Alert root = %#v, want %s: %s", got, alertID, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "caseId") {
		t.Fatalf("Alert projection leaked a Case root: %s", response.Body.String())
	}
}

func assertRequiredNestedEmptyJSONArray(t testing.TB, response *httptest.ResponseRecorder, objectField, arrayField string) {
	t.Helper()
	var outer map[string]json.RawMessage
	if err := json.Unmarshal(response.Body.Bytes(), &outer); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	var nested map[string]json.RawMessage
	if err := json.Unmarshal(outer[objectField], &nested); err != nil {
		t.Fatalf("decode response field %q: %v", objectField, err)
	}
	if raw, present := nested[arrayField]; !present || string(raw) != "[]" {
		t.Fatalf("required array %q.%q was not serialized as []: %s", objectField, arrayField, response.Body.String())
	}
}

var _ DFIRService = (*alertTransportDFIRService)(nil)
var _ contract.ServerInterface = (*Handler)(nil)
