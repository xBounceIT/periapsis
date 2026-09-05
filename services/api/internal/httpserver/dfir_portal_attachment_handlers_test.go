package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	dfirkernel "github.com/periapsis-im/periapsis/modules/dfir"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	application "github.com/periapsis-im/periapsis/services/api/internal/dfir"
)

func TestCustomerPortalAttachmentListRoutesReturnOnlyNoStoreAllowlist(t *testing.T) {
	t.Parallel()
	for name, kind := range map[string]application.PortalTicketKind{
		"alerts": application.PortalTicketAlert,
		"cases":  application.PortalTicketCase,
	} {
		name, kind := name, kind
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fixture := newPhase4HTTPFixture(t)
			rootID, attachmentID := mustTransportUUIDv7(t), mustTransportUUIDv7(t)
			rootEntity, _ := dfirEntityID(rootID)
			attachmentEntity, _ := dfirEntityID(attachmentID)
			uploadedAt := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Minute)
			calls := 0
			service := &portalTransportDFIRService{transportDFIRStub: &transportDFIRStub{}}
			service.list = func(_ context.Context, actor application.Actor, tenantID uuid.UUID, root application.PortalAttachmentRoot, input application.CustomerPortalAttachmentListInput) (application.CustomerPortalAttachmentPage, error) {
				calls++
				if actor.Kind != application.PrincipalCustomer || actor.TenantID != fixture.tenantID || actor.MembershipID != fixture.membershipID ||
					tenantID != fixture.tenantID || root.Kind != kind || root.ID != rootEntity || input.After != "cursor_token_0001" || input.Limit != 7 {
					t.Fatalf("portal list transport lost exact customer/root/page input: actor=%#v root=%#v input=%#v", actor, root, input)
				}
				return application.CustomerPortalAttachmentPage{
					Items: []application.CustomerPortalAttachment{{
						ID: attachmentEntity, ResourceKind: kind, ResourceID: rootEntity,
						OriginalFilename: "customer-visible.txt", UploadedAt: uploadedAt,
					}},
					NextCursor: "next_cursor_0002",
				}, nil
			}
			router := newPhase4TestRouter(t, fixture, &transportCustomFieldStub{}, service)
			path := "/api/v1/tenants/" + fixture.tenantID.String() + "/portal/" + name + "/" + rootID.String() +
				"/dfir/attachments?after=cursor_token_0001&limit=7"
			request := httptest.NewRequest(http.MethodGet, path, nil)
			prepareTenantLDAPTransportRequest(request, false)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != http.StatusOK || calls != 1 || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("portal list status=%d calls=%d headers=%#v body=%s", response.Code, calls, response.Header(), response.Body.String())
			}
			var body contract.CustomerPortalAttachmentList
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if len(body.Items) != 1 || body.Items[0].Id != attachmentID || body.Items[0].ResourceId != rootID ||
				body.Items[0].ResourceKind != contract.TicketResourceKind(kind) || body.Items[0].OriginalFilename != "customer-visible.txt" ||
				body.Items[0].Projection != contract.CustomerPortalAttachmentProjectionCustomer ||
				body.Items[0].Downloadable != contract.CustomerPortalAttachmentDownloadableTrue || body.NextCursor == nil ||
				*body.NextCursor != "next_cursor_0002" {
				t.Fatalf("portal attachment projection = %#v", body)
			}
			for _, forbidden := range []string{"tenantId", "subject", "storageObjectId", "uploadedBy", "classification", "visibility", "scanState"} {
				if strings.Contains(response.Body.String(), `"`+forbidden+`"`) {
					t.Fatalf("customer projection leaked %q: %s", forbidden, response.Body.String())
				}
			}
		})
	}
}

func TestCustomerPortalAttachmentPrepareDownloadIsCSRFProtectedBodylessAndNoReferrer(t *testing.T) {
	t.Parallel()
	fixture := newPhase4HTTPFixture(t)
	rootID, attachmentID := mustTransportUUIDv7(t), mustTransportUUIDv7(t)
	rootEntity, _ := dfirEntityID(rootID)
	attachmentEntity, _ := dfirEntityID(attachmentID)
	uploadedAt := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Minute)
	calls := 0
	service := &portalTransportDFIRService{transportDFIRStub: &transportDFIRStub{}}
	service.prepare = func(_ context.Context, actor application.Actor, tenantID uuid.UUID, root application.PortalAttachmentRoot, gotAttachment dfirkernel.EntityID, audit application.AuditContext) (application.CustomerPortalPreparedDownload, error) {
		calls++
		if actor.Kind != application.PrincipalCustomer || tenantID != fixture.tenantID || root.Kind != application.PortalTicketAlert ||
			root.ID != rootEntity || gotAttachment != attachmentEntity || audit.RequestID == uuid.Nil ||
			audit.CorrelationID == uuid.Nil || !audit.IPAddress.IsValid() || audit.UserAgent != "portal-download-test" ||
			audit.AuthenticationMethod != actor.AuthenticationMethod {
			t.Fatalf("portal prepare lost customer/root/attachment/audit binding: actor=%#v root=%#v attachment=%s audit=%#v", actor, root, gotAttachment, audit)
		}
		return application.CustomerPortalPreparedDownload{
			Attachment: application.CustomerPortalAttachment{
				ID: attachmentEntity, ResourceKind: root.Kind, ResourceID: root.ID,
				OriginalFilename: "report.pdf", UploadedAt: uploadedAt,
			},
			Grant: application.DownloadGrant{
				TargetURL: "https://storage.invalid/customer-report?signature=redacted",
				ExpiresAt: uploadedAt.Add(10 * time.Minute),
			},
		}, nil
	}
	router := newPhase4TestRouter(t, fixture, &transportCustomFieldStub{}, service)
	path := "/api/v1/tenants/" + fixture.tenantID.String() + "/portal/alerts/" + rootID.String() +
		"/dfir/attachments/" + attachmentID.String() + "/prepare-download"

	request := httptest.NewRequest(http.MethodPost, path, nil)
	prepareTenantLDAPTransportRequest(request, true)
	request.Header.Set("User-Agent", "portal-download-test")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK || calls != 1 || response.Header().Get("Cache-Control") != "no-store" ||
		response.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("portal prepare status=%d calls=%d headers=%#v body=%s", response.Code, calls, response.Header(), response.Body.String())
	}
	var body contract.CustomerPortalPreparedAttachmentDownload
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Attachment.Id != attachmentID || body.Attachment.ResourceId != rootID || body.DownloadUrl == "" || body.ExpiresAt.IsZero() {
		t.Fatalf("portal prepared download = %#v", body)
	}

	unexpectedBody := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
	prepareTenantLDAPTransportRequest(unexpectedBody, true)
	response = httptest.NewRecorder()
	router.ServeHTTP(response, unexpectedBody)
	if response.Code != http.StatusBadRequest || calls != 1 || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("unexpected body status=%d calls=%d headers=%#v body=%s", response.Code, calls, response.Header(), response.Body.String())
	}

	missingCSRF := httptest.NewRequest(http.MethodPost, path, nil)
	prepareTenantLDAPTransportRequest(missingCSRF, false)
	response = httptest.NewRecorder()
	router.ServeHTTP(response, missingCSRF)
	if response.Code != http.StatusForbidden || calls != 1 || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("missing CSRF status=%d calls=%d headers=%#v body=%s", response.Code, calls, response.Header(), response.Body.String())
	}
}

func TestCustomerPortalAttachmentRouteRejectsCrossTenantBeforeService(t *testing.T) {
	t.Parallel()
	fixture := newPhase4HTTPFixture(t)
	rootID, foreignTenant := mustTransportUUIDv7(t), mustTransportUUIDv7(t)
	calls := 0
	service := &portalTransportDFIRService{transportDFIRStub: &transportDFIRStub{}, list: func(
		context.Context, application.Actor, uuid.UUID, application.PortalAttachmentRoot, application.CustomerPortalAttachmentListInput,
	) (application.CustomerPortalAttachmentPage, error) {
		calls++
		return application.CustomerPortalAttachmentPage{}, errors.New("must not be called")
	}}
	router := newPhase4TestRouter(t, fixture, &transportCustomFieldStub{}, service)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/"+foreignTenant.String()+"/portal/cases/"+rootID.String()+"/dfir/attachments", nil)
	prepareTenantLDAPTransportRequest(request, false)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || calls != 0 || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("cross-tenant status=%d calls=%d headers=%#v body=%s", response.Code, calls, response.Header(), response.Body.String())
	}
}

type portalTransportDFIRService struct {
	*transportDFIRStub
	list    func(context.Context, application.Actor, uuid.UUID, application.PortalAttachmentRoot, application.CustomerPortalAttachmentListInput) (application.CustomerPortalAttachmentPage, error)
	prepare func(context.Context, application.Actor, uuid.UUID, application.PortalAttachmentRoot, dfirkernel.EntityID, application.AuditContext) (application.CustomerPortalPreparedDownload, error)
}

func (service *portalTransportDFIRService) ListCustomerPortalAttachments(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	root application.PortalAttachmentRoot,
	input application.CustomerPortalAttachmentListInput,
) (application.CustomerPortalAttachmentPage, error) {
	if service.list == nil {
		return application.CustomerPortalAttachmentPage{}, application.ErrUnavailable
	}
	return service.list(ctx, actor, tenantID, root, input)
}

func (service *portalTransportDFIRService) PrepareCustomerPortalAttachmentDownload(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	root application.PortalAttachmentRoot,
	attachmentID dfirkernel.EntityID,
	audit application.AuditContext,
) (application.CustomerPortalPreparedDownload, error) {
	if service.prepare == nil {
		return application.CustomerPortalPreparedDownload{}, application.ErrUnavailable
	}
	return service.prepare(ctx, actor, tenantID, root, attachmentID, audit)
}
