package httpserver

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	"github.com/periapsis-im/periapsis/services/api/internal/securityaudit"
)

type transportSecurityAuditStub struct {
	listTenantFunc     func(context.Context, authorization.Actor, uuid.UUID, securityaudit.Query, authorization.AuditContext) (securityaudit.Page, error)
	verifyTenantFunc   func(context.Context, authorization.Actor, uuid.UUID, authorization.AuditContext) (securityaudit.Verification, error)
	listPlatformFunc   func(context.Context, authentication.Session, securityaudit.Query, authentication.EventContext) (securityaudit.Page, error)
	verifyPlatformFunc func(context.Context, authentication.Session, authentication.EventContext) (securityaudit.Verification, error)
}

func (stub *transportSecurityAuditStub) ListTenant(
	ctx context.Context,
	actor authorization.Actor,
	tenantID uuid.UUID,
	query securityaudit.Query,
	audit authorization.AuditContext,
) (securityaudit.Page, error) {
	if stub.listTenantFunc == nil {
		return securityaudit.Page{}, securityaudit.ErrUnavailable
	}
	return stub.listTenantFunc(ctx, actor, tenantID, query, audit)
}

func (stub *transportSecurityAuditStub) VerifyTenant(
	ctx context.Context,
	actor authorization.Actor,
	tenantID uuid.UUID,
	audit authorization.AuditContext,
) (securityaudit.Verification, error) {
	if stub.verifyTenantFunc == nil {
		return securityaudit.Verification{}, securityaudit.ErrUnavailable
	}
	return stub.verifyTenantFunc(ctx, actor, tenantID, audit)
}

func (stub *transportSecurityAuditStub) ListPlatform(
	ctx context.Context,
	session authentication.Session,
	query securityaudit.Query,
	event authentication.EventContext,
) (securityaudit.Page, error) {
	if stub.listPlatformFunc == nil {
		return securityaudit.Page{}, securityaudit.ErrUnavailable
	}
	return stub.listPlatformFunc(ctx, session, query, event)
}

func (stub *transportSecurityAuditStub) VerifyPlatform(
	ctx context.Context,
	session authentication.Session,
	event authentication.EventContext,
) (securityaudit.Verification, error) {
	if stub.verifyPlatformFunc == nil {
		return securityaudit.Verification{}, securityaudit.ErrUnavailable
	}
	return stub.verifyPlatformFunc(ctx, session, event)
}

func TestTenantAuditListCarriesExactIdentityFiltersAndAuditContext(t *testing.T) {
	t.Parallel()
	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	sessionID := uuid.Must(uuid.NewV7())
	actorServiceID := uuid.Must(uuid.NewV7())
	resourceID := uuid.Must(uuid.NewV7())
	filterRequestID := uuid.Must(uuid.NewV7())
	filterCorrelationID := uuid.Must(uuid.NewV7())
	requestID := uuid.Must(uuid.NewV7())
	correlationID := uuid.Must(uuid.NewV7())
	nextSequence := uint64(42)
	occurredAt := time.Date(2026, 8, 25, 18, 30, 0, 0, time.UTC)

	var capturedActor authorization.Actor
	var capturedTenantID uuid.UUID
	var capturedQuery securityaudit.Query
	var capturedAudit authorization.AuditContext
	stub := &transportSecurityAuditStub{listTenantFunc: func(
		_ context.Context,
		actor authorization.Actor,
		gotTenantID uuid.UUID,
		query securityaudit.Query,
		audit authorization.AuditContext,
	) (securityaudit.Page, error) {
		capturedActor, capturedTenantID, capturedQuery, capturedAudit = actor, gotTenantID, query, audit
		return securityaudit.Page{
			Items: []securityaudit.Event{{
				ID: uuid.Must(uuid.NewV7()), TenantID: &tenantID, Sequence: 41,
				OccurredAt: occurredAt, ActorType: securityaudit.ActorUser, ActorUserID: &userID,
				Action: "ticket.assigned", ResourceType: "case", ResourceID: &resourceID,
				Outcome: securityaudit.OutcomeSuccess, Before: json.RawMessage(`{"status":"open"}`),
				After: json.RawMessage(`{"status":"assigned"}`), Metadata: json.RawMessage(`{"authorizationrevision":7}`),
				PreviousHash: strings.Repeat("0", 64), EventHash: strings.Repeat("a", 64),
			}},
			NextSequence: &nextSequence,
		}, nil
	}}
	auth := tenantLDAPTransportAuthentication(tenantID, userID)
	auth.authenticateResult.ID = sessionID
	router := newSecurityAuditTestRouter(t, auth, stub)
	path := "/api/v1/tenants/" + tenantID.String() + "/audit-events" +
		"?afterSequence=7&limit=25&actorType=user&actorUserId=" + userID.String() +
		"&actorServiceAccountId=" + actorServiceID.String() + "&actionPrefix=ticket." +
		"&resourceType=case&resourceId=" + resourceID.String() + "&requestId=" + filterRequestID.String() +
		"&correlationId=" + filterCorrelationID.String() + "&outcome=success&search=responder" +
		"&occurredFrom=2026-08-24T00%3A00%3A00Z&occurredBefore=2026-08-26T00%3A00%3A00Z"
	request := httptest.NewRequest(http.MethodGet, path, nil)
	prepareAuditRequest(request, requestID, correlationID, false)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", response.Code, response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", response.Header().Get("Cache-Control"))
	}
	if capturedTenantID != tenantID || capturedActor.UserID != userID || capturedActor.SessionID != sessionID || capturedActor.ActiveTenantID != tenantID {
		t.Fatalf("captured tenant actor = %+v, tenant = %s", capturedActor, capturedTenantID)
	}
	if capturedActor.AuthenticationMethod != "totp" || capturedQuery.AfterSequence != 7 || capturedQuery.Limit != 25 {
		t.Fatalf("captured actor/query = %+v / %+v", capturedActor, capturedQuery)
	}
	if capturedQuery.ActorType == nil || *capturedQuery.ActorType != securityaudit.ActorUser ||
		capturedQuery.ActorUserID == nil || *capturedQuery.ActorUserID != userID ||
		capturedQuery.ActorServiceAccountID == nil || *capturedQuery.ActorServiceAccountID != actorServiceID ||
		capturedQuery.ResourceID == nil || *capturedQuery.ResourceID != resourceID ||
		capturedQuery.RequestID == nil || *capturedQuery.RequestID != filterRequestID ||
		capturedQuery.CorrelationID == nil || *capturedQuery.CorrelationID != filterCorrelationID ||
		capturedQuery.Outcome == nil || *capturedQuery.Outcome != securityaudit.OutcomeSuccess {
		t.Fatalf("captured typed filters = %+v", capturedQuery)
	}
	if capturedQuery.ActionPrefix != "ticket." || capturedQuery.ResourceType != "case" || capturedQuery.Search != "responder" ||
		capturedQuery.OccurredFrom == nil || capturedQuery.OccurredBefore == nil {
		t.Fatalf("captured textual/time filters = %+v", capturedQuery)
	}
	if capturedAudit.RequestID != requestID || capturedAudit.CorrelationID != correlationID ||
		capturedAudit.RemoteAddress != netip.MustParseAddr("198.51.100.42") || capturedAudit.UserAgent != "audit-test-agent" {
		t.Fatalf("captured audit context = %+v", capturedAudit)
	}
	var page contract.AuditEventPage
	if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(page.Items) != 1 || page.Items[0].Sequence != 41 || page.NextSequence == nil || *page.NextSequence != 42 {
		t.Fatalf("mapped page = %+v", page)
	}
	if page.Items[0].After["status"] != "assigned" || page.Items[0].Metadata["authorizationrevision"] != float64(7) {
		t.Fatalf("mapped redacted documents = %+v / %+v", page.Items[0].After, page.Items[0].Metadata)
	}
}

func TestAuditEventMapsCanonicalEmptyDocuments(t *testing.T) {
	t.Parallel()

	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	eventID := uuid.Must(uuid.NewV7())
	mapped, err := mapAuditEvent(securityaudit.Event{
		ID: eventID, TenantID: &tenantID, Sequence: 1,
		OccurredAt: time.Date(2026, 8, 26, 0, 0, 0, 0, time.UTC),
		ActorType:  securityaudit.ActorUser, ActorUserID: &userID,
		Action: "audit.fixture", ResourceType: "audit_log",
		Outcome: securityaudit.OutcomeSuccess,
		Before:  json.RawMessage(`{}`), After: json.RawMessage(`{}`),
		Metadata: json.RawMessage(`{}`), PreviousHash: strings.Repeat("0", 64),
		EventHash: strings.Repeat("a", 64),
	})
	if err != nil {
		t.Fatalf("mapAuditEvent() error = %v", err)
	}
	if mapped.Id != eventID || mapped.Before == nil || mapped.After == nil ||
		len(mapped.Before) != 0 || len(mapped.After) != 0 {
		t.Fatalf("mapped canonical empty documents = %#v / %#v", mapped.Before, mapped.After)
	}
}

func TestTenantAuditListRejectsNegativeSequenceBeforeUseCase(t *testing.T) {
	t.Parallel()
	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	called := false
	stub := &transportSecurityAuditStub{listTenantFunc: func(
		context.Context, authorization.Actor, uuid.UUID, securityaudit.Query, authorization.AuditContext,
	) (securityaudit.Page, error) {
		called = true
		return securityaudit.Page{}, nil
	}}
	router := newSecurityAuditTestRouter(t, tenantLDAPTransportAuthentication(tenantID, userID), stub)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/"+tenantID.String()+"/audit-events?afterSequence=-1", nil)
	prepareAuditRequest(request, uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), false)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	assertProblem(t, response, http.StatusBadRequest, "invalid_request")
	if called {
		t.Fatal("audit use case was called for a negative sequence")
	}
}

func TestTenantAuditVerificationRequiresCSRFAndMapsAggregate(t *testing.T) {
	t.Parallel()
	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	requestID := uuid.Must(uuid.NewV7())
	correlationID := uuid.Must(uuid.NewV7())
	verifiedAt := time.Date(2026, 8, 25, 19, 0, 0, 0, time.UTC)
	firstInvalid := uint64(11)
	calls := 0
	stub := &transportSecurityAuditStub{verifyTenantFunc: func(
		_ context.Context, actor authorization.Actor, gotTenantID uuid.UUID, audit authorization.AuditContext,
	) (securityaudit.Verification, error) {
		calls++
		if actor.UserID != userID || gotTenantID != tenantID || audit.RequestID != requestID || audit.CorrelationID != correlationID {
			t.Fatalf("verification inputs = %+v, %s, %+v", actor, gotTenantID, audit)
		}
		return securityaudit.Verification{
			EventCount: 12, LastSequence: 12, FirstInvalidSequence: &firstInvalid,
			HeadValid: false, Valid: false, VerifiedAt: verifiedAt,
		}, nil
	}}
	auth := tenantLDAPTransportAuthentication(tenantID, userID)
	router := newSecurityAuditTestRouter(t, auth, stub)
	path := "/api/v1/tenants/" + tenantID.String() + "/audit-events/verify"

	missingCSRF := httptest.NewRequest(http.MethodPost, path, nil)
	prepareAuditRequest(missingCSRF, requestID, correlationID, false)
	missingCSRF.Header.Set("Origin", "http://localhost:8081")
	missingResponse := httptest.NewRecorder()
	router.ServeHTTP(missingResponse, missingCSRF)
	assertProblem(t, missingResponse, http.StatusForbidden, "forbidden")
	if calls != 0 {
		t.Fatal("verification use case was called without CSRF")
	}

	request := httptest.NewRequest(http.MethodPost, path, nil)
	prepareAuditRequest(request, requestID, correlationID, true)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", response.Code, response.Body.String())
	}
	var result contract.AuditChainVerification
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if calls != 1 || result.EventCount != 12 || result.LastSequence != 12 || result.Valid || result.HeadValid ||
		result.FirstInvalidSequence == nil || *result.FirstInvalidSequence != 11 || !result.VerifiedAt.Equal(verifiedAt) {
		t.Fatalf("mapped verification = %+v, calls = %d", result, calls)
	}
}

func TestPlatformAuditListAndVerificationUseIndependentSession(t *testing.T) {
	t.Parallel()
	userID := uuid.Must(uuid.NewV7())
	sessionID := uuid.Must(uuid.NewV7())
	requestID := uuid.Must(uuid.NewV7())
	correlationID := uuid.Must(uuid.NewV7())
	verifiedAt := time.Date(2026, 8, 25, 20, 0, 0, 0, time.UTC)
	listCalls, verifyCalls := 0, 0
	stub := &transportSecurityAuditStub{
		listPlatformFunc: func(
			_ context.Context, session authentication.Session, query securityaudit.Query, event authentication.EventContext,
		) (securityaudit.Page, error) {
			listCalls++
			if session.ID != sessionID || session.User.ID != userID || session.ActiveTenantID != nil || query.AfterSequence != 5 ||
				query.ActorServiceAccountID != nil || event.RequestID != requestID || event.CorrelationID != correlationID {
				t.Fatalf("platform list inputs = %+v, %+v, %+v", session, query, event)
			}
			return securityaudit.Page{Items: []securityaudit.Event{}}, nil
		},
		verifyPlatformFunc: func(
			_ context.Context, session authentication.Session, event authentication.EventContext,
		) (securityaudit.Verification, error) {
			verifyCalls++
			if session.ID != sessionID || event.RequestID != requestID || event.CorrelationID != correlationID {
				t.Fatalf("platform verify inputs = %+v, %+v", session, event)
			}
			return securityaudit.Verification{EventCount: 3, LastSequence: 3, HeadValid: true, Valid: true, VerifiedAt: verifiedAt}, nil
		},
	}
	auth := &transportAuthStub{authenticateResult: authentication.Session{
		ID: sessionID, User: authentication.User{ID: userID}, AuthenticationMethod: "totp",
	}}
	router := newSecurityAuditTestRouter(t, auth, stub)
	listRequest := httptest.NewRequest(http.MethodGet, "/api/v1/platform/audit?afterSequence=5&limit=10", nil)
	prepareAuditRequest(listRequest, requestID, correlationID, false)
	listResponse := httptest.NewRecorder()
	router.ServeHTTP(listResponse, listRequest)
	if listResponse.Code != http.StatusOK || listCalls != 1 {
		t.Fatalf("platform list status = %d, calls = %d: %s", listResponse.Code, listCalls, listResponse.Body.String())
	}

	verifyRequest := httptest.NewRequest(http.MethodPost, "/api/v1/platform/audit/verify", nil)
	prepareAuditRequest(verifyRequest, requestID, correlationID, true)
	verifyResponse := httptest.NewRecorder()
	router.ServeHTTP(verifyResponse, verifyRequest)
	if verifyResponse.Code != http.StatusOK || verifyCalls != 1 || auth.csrfCalls != 1 {
		t.Fatalf("platform verify status = %d, calls = %d, csrf = %d: %s", verifyResponse.Code, verifyCalls, auth.csrfCalls, verifyResponse.Body.String())
	}
	var result contract.AuditChainVerification
	if err := json.Unmarshal(verifyResponse.Body.Bytes(), &result); err != nil || !result.Valid || !result.HeadValid || !result.VerifiedAt.Equal(verifiedAt) {
		t.Fatalf("platform verification = %+v, decode error = %v", result, err)
	}
}

func TestApplicationHandlerRequiresSecurityAuditBoundary(t *testing.T) {
	t.Parallel()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	_, err := NewApplicationHandler(fixedChecker{ready: true}, logger, "test", time.Second, ApplicationOptions{
		Alerts: &transportAlertStub{}, Authentication: &transportAuthStub{}, Authorization: &transportAuthorizationStub{},
		Contacts: &transportContactStub{}, CustomFields: &transportCustomFieldStub{}, DFIR: &transportDFIRStub{},
		Environment: "test", IdentityProviders: &transportIdentityProviderStub{}, LDAPAdministration: &transportLDAPAdministrationStub{},
		Notifications: &transportNotificationStub{}, OperatorTeams: &transportOperatorTeamStub{}, Platform: &transportPlatformStub{},
		PublicOrigin: "http://localhost:8081", ServiceAccounts: &transportServiceAccountStub{}, Ticketing: &transportTicketingStub{}, WorkflowAdministration: &transportWorkflowAdministrationStub{},
	})
	if err == nil || !strings.Contains(err.Error(), "audit") {
		t.Fatalf("NewApplicationHandler() error = %v, want missing audit boundary failure", err)
	}
}

func newSecurityAuditTestRouter(
	t *testing.T,
	auth AuthenticationService,
	audit SecurityAuditService,
) http.Handler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler, err := NewApplicationHandler(
		fixedChecker{ready: true}, logger, "test", time.Second,
		ApplicationOptions{
			Alerts: &transportAlertStub{}, Audit: audit, Authentication: auth, Authorization: &transportAuthorizationStub{},
			Contacts: &transportContactStub{}, CustomFields: &transportCustomFieldStub{}, DFIR: &transportDFIRStub{},
			Environment: "test", IdentityProviders: &transportIdentityProviderStub{}, LDAPAdministration: &transportLDAPAdministrationStub{}, MFA: &transportMFAStub{},
			Notifications: &transportNotificationStub{}, OperatorTeams: &transportOperatorTeamStub{}, Platform: &transportPlatformStub{},
			PublicOrigin: "http://localhost:8081", ServiceAccounts: &transportServiceAccountStub{}, SLA: &transportSLAStub{}, Ticketing: &transportTicketingStub{}, WorkflowAdministration: &transportWorkflowAdministrationStub{},
		},
	)
	if err != nil {
		t.Fatalf("NewApplicationHandler() error = %v", err)
	}
	return Router(handler, logger, false)
}

func prepareAuditRequest(request *http.Request, requestID, correlationID uuid.UUID, mutation bool) {
	request.AddCookie(&http.Cookie{Name: developmentCookie, Value: "opaque-session"})
	request.RemoteAddr = "198.51.100.42:4123"
	request.Header.Set("User-Agent", "audit-test-agent")
	request.Header.Set(requestIDHeader, requestID.String())
	request.Header.Set(correlationIDHeader, correlationID.String())
	if mutation {
		request.Header.Set("Origin", "http://localhost:8081")
		request.Header.Set(csrfTokenHeader, "csrf-value")
	}
}
