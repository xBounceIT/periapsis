package httpserver

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/dfir"
	application "github.com/periapsis-im/periapsis/services/api/internal/dfir"
)

type sharedLinkHTTPService struct {
	*transportDFIRStub
	change func(application.Actor, uuid.UUID, application.SharedResourceLinkCommand)
}

func (s *sharedLinkHTTPService) ChangeIndicatorLink(_ context.Context, actor application.Actor, tenantID uuid.UUID, command application.SharedResourceLinkCommand) (application.MutationResult[kernel.Indicator], error) {
	s.change(actor, tenantID, command)
	tenant, _ := dfirEntityID(tenantID)
	instant := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	resource, err := kernel.NewIndicator(kernel.IndicatorInput{ID: command.ResourceID, TenantID: tenant,
		Type: kernel.IndicatorDomain, Value: "shared.example", Source: "analyst", Confidence: 80,
		TLP: kernel.TLPAmber, FirstSeen: instant, LastSeen: instant, Malicious: kernel.MaliciousSuspicious})
	return application.MutationResult[kernel.Indicator]{Resource: resource, Replayed: true}, err
}

func (s *sharedLinkHTTPService) ChangeAssetLink(_ context.Context, actor application.Actor, tenantID uuid.UUID, command application.SharedResourceLinkCommand) (application.MutationResult[kernel.Asset], error) {
	s.change(actor, tenantID, command)
	tenant, _ := dfirEntityID(tenantID)
	instant := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	resource, err := kernel.NewAsset(kernel.AssetInput{ID: command.ResourceID, TenantID: tenant,
		Hostname: "shared-host", AssetType: "host", Criticality: kernel.AssetCriticalityHigh,
		Environment: "production", FirstSeen: instant, LastSeen: instant})
	return application.MutationResult[kernel.Asset]{Resource: resource, Replayed: true}, err
}

func TestSharedDFIRLinkRoutesPreserveCallerIdentityRootAndCAS(t *testing.T) {
	for _, rootKind := range []string{"case", "alert"} {
		for _, segment := range []string{"iocs", "assets"} {
			for _, action := range []string{"link", "unlink"} {
				t.Run(rootKind+"/"+segment+"/"+action, func(t *testing.T) {
					fixture := newPhase4HTTPFixture(t)
					rootID, resourceID, eventID := fixture.caseID, mustTransportUUIDv7(t), mustTransportUUIDv7(t)
					calls := 0
					service := &sharedLinkHTTPService{transportDFIRStub: &transportDFIRStub{}, change: func(actor application.Actor, tenantID uuid.UUID, command application.SharedResourceLinkCommand) {
						calls++
						if actor.MembershipID != fixture.membershipID || tenantID != fixture.tenantID || string(command.RootKind) != rootKind ||
							command.RootID.String() != rootID.String() || command.ResourceID.String() != resourceID.String() ||
							command.EventID.String() != eventID.String() || command.ExpectedVersion != 3_000_000_000 || command.Linked != (action == "link") ||
							command.Envelope.IdempotencyKey != "shared-lifecycle-key-001" {
							t.Fatalf("shared link command lost coordinates: %#v", command)
						}
					}}
					path := fmt.Sprintf("/api/v1/tenants/%s/%ss/%s/dfir/%s/%s/%s", fixture.tenantID, rootKind, rootID, segment, resourceID, action)
					body := fmt.Sprintf(`{"%sId":"%s","expectedVersion":3000000000}`, action, eventID)
					request := phase4MutationRequest(http.MethodPost, path, body, "shared-lifecycle-key-001")
					request.Header.Set("If-Match", `"v3000000000"`)
					response := httptest.NewRecorder()
					newPhase4TestRouter(t, fixture, &transportCustomFieldStub{}, service).ServeHTTP(response, request)
					if response.Code != http.StatusOK || calls != 1 || response.Header().Get("ETag") != `"v3000000001"` ||
						response.Header().Get("Cache-Control") != "no-store" || response.Header().Get(idempotentReplayHeader) != "true" {
						t.Fatalf("shared lifecycle response %d calls=%d headers=%v body=%s", response.Code, calls, response.Header(), response.Body.String())
					}
				})
			}
		}
	}
}

func TestSharedDFIRLinkRejectsInvalidCallerIDAndMissingCASBeforeService(t *testing.T) {
	fixture := newPhase4HTTPFixture(t)
	calls := 0
	service := &sharedLinkHTTPService{transportDFIRStub: &transportDFIRStub{}, change: func(application.Actor, uuid.UUID, application.SharedResourceLinkCommand) { calls++ }}
	path := fmt.Sprintf("/api/v1/tenants/%s/cases/%s/dfir/iocs/%s/link", fixture.tenantID, fixture.caseID, mustTransportUUIDv7(t))
	for _, candidate := range []struct {
		body, tag string
		status    int
	}{
		{fmt.Sprintf(`{"linkId":"%s","expectedVersion":1}`, uuid.New()), `"v1"`, http.StatusBadRequest},
		{fmt.Sprintf(`{"linkId":"%s","expectedVersion":1}`, mustTransportUUIDv7(t)), "", http.StatusPreconditionRequired},
		{fmt.Sprintf(`{"linkId":"%s","expectedVersion":1}`, mustTransportUUIDv7(t)), `"v2"`, http.StatusBadRequest},
	} {
		request := phase4MutationRequest(http.MethodPost, path, candidate.body, "shared-lifecycle-key-002")
		if candidate.tag != "" {
			request.Header.Set("If-Match", candidate.tag)
		}
		response := httptest.NewRecorder()
		newPhase4TestRouter(t, fixture, &transportCustomFieldStub{}, service).ServeHTTP(response, request)
		if response.Code != candidate.status || calls != 0 {
			t.Fatalf("invalid link command tag=%q expected=%d returned %d and %d calls: %s", candidate.tag, candidate.status, response.Code, calls, response.Body.String())
		}
	}
}
