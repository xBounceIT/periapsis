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
	"github.com/periapsis-im/periapsis/services/api/internal/notificationinbox"
)

type notificationInboxTransportStub struct {
	listCalls    int
	countCalls   int
	setCalls     int
	markAllCalls int

	actor   notificationinbox.Actor
	tenant  uuid.UUID
	list    notificationinbox.ListInput
	set     notificationinbox.SetReadStateInput
	markAll notificationinbox.MarkAllReadInput

	page       notificationinbox.Page
	unread     notificationinbox.UnreadState
	readResult notificationinbox.ReadStateResult
	markResult notificationinbox.MarkAllReadResult
	err        error
}

func (stub *notificationInboxTransportStub) List(
	_ context.Context,
	actor notificationinbox.Actor,
	tenantID uuid.UUID,
	input notificationinbox.ListInput,
) (notificationinbox.Page, error) {
	stub.listCalls++
	stub.actor, stub.tenant, stub.list = actor, tenantID, input
	return stub.page, stub.err
}

func (stub *notificationInboxTransportStub) CountUnread(
	_ context.Context,
	actor notificationinbox.Actor,
	tenantID uuid.UUID,
) (notificationinbox.UnreadState, error) {
	stub.countCalls++
	stub.actor, stub.tenant = actor, tenantID
	return stub.unread, stub.err
}

func (stub *notificationInboxTransportStub) SetReadState(
	_ context.Context,
	actor notificationinbox.Actor,
	tenantID uuid.UUID,
	input notificationinbox.SetReadStateInput,
) (notificationinbox.ReadStateResult, error) {
	stub.setCalls++
	stub.actor, stub.tenant, stub.set = actor, tenantID, input
	return stub.readResult, stub.err
}

func (stub *notificationInboxTransportStub) MarkAllRead(
	_ context.Context,
	actor notificationinbox.Actor,
	tenantID uuid.UUID,
	input notificationinbox.MarkAllReadInput,
) (notificationinbox.MarkAllReadResult, error) {
	stub.markAllCalls++
	stub.actor, stub.tenant, stub.markAll = actor, tenantID, input
	return stub.markResult, stub.err
}

func TestNotificationInboxRoutesUsePersonalSessionBoundaryAndPreservePrecedence(t *testing.T) {
	tenantID, userID, sessionID := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	itemID, resourceID := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	now := time.Date(2026, time.September, 3, 10, 0, 0, 0, time.UTC)
	readAt := now.Add(time.Minute)
	item := notificationinbox.Item{
		ID: itemID, TenantID: tenantID, UserID: userID, Audience: notificationinbox.AudienceOperator,
		EventType: notificationinbox.EventAlertCreated, ResourceKind: notificationinbox.ResourceAlert,
		ResourceID: resourceID, ResourceVersion: 4, Title: "Alert created", Summary: "",
		OccurredAt: now, ReadAt: &readAt, Revision: 2,
	}
	service := &notificationInboxTransportStub{
		page: notificationinbox.Page{
			TenantID: tenantID, UserID: userID, Items: []notificationinbox.Item{item}, InboxRevision: 9,
		},
		unread: notificationinbox.UnreadState{
			TenantID: tenantID, UserID: userID, Count: 3, InboxRevision: 9,
		},
		readResult: notificationinbox.ReadStateResult{
			Item: item, InboxRevision: 9, Changed: true,
		},
		markResult: notificationinbox.MarkAllReadResult{
			TenantID: tenantID, UserID: userID, Affected: 3, InboxRevision: 1, Changed: true,
		},
	}
	auth := notificationInboxTransportAuthentication(tenantID, userID, sessionID)
	router := newNotificationInboxTestRouter(t, auth, service)
	base := "/api/v1/tenants/" + tenantID.String() + "/notification-inbox"

	listResponse := httptest.NewRecorder()
	router.ServeHTTP(listResponse, notificationInboxRequest(http.MethodGet, base+"?limit=1&unreadOnly=true", "", false))
	if listResponse.Code != http.StatusOK || listResponse.Header().Get("Cache-Control") != notificationInboxPrivateCacheControl ||
		service.listCalls != 1 || service.list.Limit != 1 || !service.list.UnreadOnly {
		t.Fatalf("list response = %d %#v, calls/input = %d %#v", listResponse.Code, listResponse.Header(), service.listCalls, service.list)
	}
	var page map[string]any
	if err := json.Unmarshal(listResponse.Body.Bytes(), &page); err != nil || page["inboxRevision"] != float64(9) {
		t.Fatalf("list body = %s, error = %v", listResponse.Body.String(), err)
	}

	countResponse := httptest.NewRecorder()
	router.ServeHTTP(countResponse, notificationInboxRequest(http.MethodGet, base+"/unread-count", "", false))
	if countResponse.Code != http.StatusOK || countResponse.Header().Get("Cache-Control") != notificationInboxPrivateCacheControl ||
		service.countCalls != 1 || service.setCalls != 0 {
		t.Fatalf("unread route response = %d, count calls = %d, set calls = %d", countResponse.Code, service.countCalls, service.setCalls)
	}

	setRequest := notificationInboxRequest(http.MethodPut, base+"/"+itemID.String()+"/read-state", `{"read":true}`, true)
	setRequest.Header.Set(ifMatchHeader, `"v1"`)
	setRequest.Header.Set(idempotencyKeyHeader, "notification-item-read-0001")
	setResponse := httptest.NewRecorder()
	router.ServeHTTP(setResponse, setRequest)
	if setResponse.Code != http.StatusOK || setResponse.Header().Get("ETag") != `"v2"` ||
		setResponse.Header().Get("Cache-Control") != notificationInboxPrivateCacheControl || service.setCalls != 1 ||
		service.set.ItemID != itemID || !service.set.Read || service.set.ExpectedRevision != 1 ||
		service.set.IdempotencyKey != "notification-item-read-0001" || auth.csrfCalls != 1 {
		t.Fatalf("set response = %d %#v, input = %#v, csrf calls = %d", setResponse.Code, setResponse.Header(), service.set, auth.csrfCalls)
	}
	if service.actor.UserID != userID || service.actor.SessionID != sessionID || service.actor.ActiveTenantID != tenantID ||
		service.actor.Audit.RequestID == uuid.Nil || service.actor.Audit.CorrelationID == uuid.Nil ||
		service.actor.Audit.UserAgent != "notification-inbox-http-test" {
		t.Fatalf("set actor = %#v", service.actor)
	}

	markRequest := notificationInboxRequest(http.MethodPost, base+"/mark-all-read", "", true)
	markRequest.Header.Set(ifMatchHeader, `"v0"`)
	markRequest.Header.Set(idempotencyKeyHeader, "notification-mark-all-0001")
	markResponse := httptest.NewRecorder()
	router.ServeHTTP(markResponse, markRequest)
	if markResponse.Code != http.StatusOK || markResponse.Header().Get("ETag") != `"v1"` ||
		markResponse.Header().Get("Cache-Control") != notificationInboxPrivateCacheControl ||
		service.markAllCalls != 1 || service.setCalls != 1 || service.markAll.ExpectedRevision != 0 ||
		service.markAll.IdempotencyKey != "notification-mark-all-0001" || auth.csrfCalls != 2 {
		t.Fatalf("mark-all response = %d %#v, calls/input = %d %#v", markResponse.Code, markResponse.Header(), service.markAllCalls, service.markAll)
	}
}

func TestNotificationInboxMutationTransportFailsClosed(t *testing.T) {
	tenantID, userID, sessionID := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	itemID := uuid.Must(uuid.NewV7())
	base := "/api/v1/tenants/" + tenantID.String() + "/notification-inbox"

	tests := map[string]struct {
		request func() *http.Request
		status  int
		code    string
	}{
		"service credential cannot enter personal inbox": {
			request: func() *http.Request {
				request := httptest.NewRequest(http.MethodGet, base, nil)
				request.Header.Set("Authorization", "Bearer service-account-token")
				request.RemoteAddr = "198.51.100.42:4123"
				return request
			},
			status: http.StatusUnauthorized, code: "authentication_failed",
		},
		"missing csrf": {
			request: func() *http.Request {
				request := notificationInboxRequest(http.MethodPost, base+"/mark-all-read", "", true)
				request.Header.Del(csrfTokenHeader)
				request.Header.Set(ifMatchHeader, `"v0"`)
				request.Header.Set(idempotencyKeyHeader, "notification-mark-all-0001")
				return request
			},
			status: http.StatusForbidden, code: "forbidden",
		},
		"missing if match": {
			request: func() *http.Request {
				request := notificationInboxRequest(http.MethodPut, base+"/"+itemID.String()+"/read-state", `{"read":true}`, true)
				request.Header.Set(idempotencyKeyHeader, "notification-item-read-0001")
				return request
			},
			status: http.StatusPreconditionRequired, code: "precondition_required",
		},
		"non canonical if match": {
			request: func() *http.Request {
				request := notificationInboxRequest(http.MethodPut, base+"/"+itemID.String()+"/read-state", `{"read":true}`, true)
				request.Header.Set(ifMatchHeader, `"v01"`)
				request.Header.Set(idempotencyKeyHeader, "notification-item-read-0001")
				return request
			},
			status: http.StatusBadRequest, code: "invalid_request",
		},
		"duplicate idempotency header": {
			request: func() *http.Request {
				request := notificationInboxRequest(http.MethodPut, base+"/"+itemID.String()+"/read-state", `{"read":true}`, true)
				request.Header.Set(ifMatchHeader, `"v1"`)
				request.Header[idempotencyKeyHeader] = []string{"notification-item-read-0001", "notification-item-read-0002"}
				return request
			},
			status: http.StatusBadRequest, code: "invalid_request",
		},
		"missing required body field": {
			request: func() *http.Request {
				request := notificationInboxRequest(http.MethodPut, base+"/"+itemID.String()+"/read-state", `{}`, true)
				request.Header.Set(ifMatchHeader, `"v1"`)
				request.Header.Set(idempotencyKeyHeader, "notification-item-read-0001")
				return request
			},
			status: http.StatusBadRequest, code: "invalid_request",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			service := &notificationInboxTransportStub{}
			auth := notificationInboxTransportAuthentication(tenantID, userID, sessionID)
			router := newNotificationInboxTestRouter(t, auth, service)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, test.request())
			assertProblem(t, response, test.status, test.code)
			if service.listCalls+service.countCalls+service.setCalls+service.markAllCalls != 0 {
				t.Fatalf("failed request reached inbox service: %#v", service)
			}
		})
	}
}

func TestNotificationInboxExpectedRevisionRequiresCanonicalIncrementableTag(t *testing.T) {
	for _, value := range []string{`W/"v1"`, `"v01"`, `"v2147483647"`, `*`, `"v1","v2"`, ` "v1" `} {
		request := httptest.NewRequest(http.MethodPut, "/", nil)
		request.Header.Set(ifMatchHeader, value)
		if _, err := notificationInboxExpectedRevision(request, value, false); err == nil {
			t.Fatalf("notificationInboxExpectedRevision(%q) accepted a non-canonical tag", value)
		}
	}
	request := httptest.NewRequest(http.MethodPost, "/", nil)
	request.Header.Set(ifMatchHeader, `"v0"`)
	if got, err := notificationInboxExpectedRevision(request, `"v0"`, true); err != nil || got != 0 {
		t.Fatalf("mark-all v0 = %d, %v", got, err)
	}
}

func newNotificationInboxTestRouter(
	t testing.TB,
	auth AuthenticationService,
	service NotificationInboxService,
) http.Handler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	options := workflowAdminApplicationOptions(auth, &transportWorkflowAdministrationStub{})
	options.NotificationInbox = service
	handler, err := NewApplicationHandler(fixedChecker{ready: true}, logger, "test", time.Second, options)
	if err != nil {
		t.Fatalf("NewApplicationHandler() error = %v", err)
	}
	return Router(handler, logger, false)
}

func notificationInboxTransportAuthentication(tenantID, userID, sessionID uuid.UUID) *transportAuthStub {
	return &transportAuthStub{authenticateResult: authentication.Session{
		ID: sessionID, User: authentication.User{ID: userID}, ActiveTenantID: &tenantID,
		AuthenticationMethod: "totp",
	}}
}

func notificationInboxRequest(method, path, body string, mutation bool) *http.Request {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.AddCookie(&http.Cookie{Name: developmentCookie, Value: "opaque-session"})
	request.RemoteAddr = "198.51.100.42:4123"
	request.Header.Set("User-Agent", "notification-inbox-http-test")
	if mutation {
		request.Header.Set("Origin", "http://localhost:8081")
		request.Header.Set(csrfTokenHeader, "csrf-value")
		if body != "" {
			request.Header.Set("Content-Type", "application/json")
		}
	}
	return request
}
