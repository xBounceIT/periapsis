package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	applicationticketing "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

type watcherTransportStub struct {
	*transportTicketingStub
	listFn func(
		context.Context, applicationticketing.Actor, uuid.UUID, kernel.AggregateKind, uuid.UUID,
	) (applicationticketing.TicketWatcherProjection, error)
	mutateFn func(
		context.Context, applicationticketing.Actor, uuid.UUID, kernel.AggregateKind, uuid.UUID,
		uuid.UUID, applicationticketing.WatcherMutationAction, applicationticketing.WatcherMutationInput,
	) (applicationticketing.WatcherMutationResult, error)
	listCalls   int
	mutateCalls int
}

func (stub *watcherTransportStub) ListAlertWatchers(
	ctx context.Context,
	actor applicationticketing.Actor,
	tenantID uuid.UUID,
	alertID uuid.UUID,
) (applicationticketing.TicketWatcherProjection, error) {
	return stub.listWatchers(ctx, actor, tenantID, kernel.AggregateAlert, alertID)
}

func (stub *watcherTransportStub) ListCaseWatchers(
	ctx context.Context,
	actor applicationticketing.Actor,
	tenantID uuid.UUID,
	caseID uuid.UUID,
) (applicationticketing.TicketWatcherProjection, error) {
	return stub.listWatchers(ctx, actor, tenantID, kernel.AggregateCase, caseID)
}

func (stub *watcherTransportStub) listWatchers(
	ctx context.Context,
	actor applicationticketing.Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	ticketID uuid.UUID,
) (applicationticketing.TicketWatcherProjection, error) {
	stub.listCalls++
	if stub.listFn == nil {
		return applicationticketing.TicketWatcherProjection{}, applicationticketing.ErrUnavailable
	}
	return stub.listFn(ctx, actor, tenantID, kind, ticketID)
}

func (stub *watcherTransportStub) AddAlertWatcher(
	ctx context.Context,
	actor applicationticketing.Actor,
	tenantID, alertID, userID uuid.UUID,
	input applicationticketing.WatcherMutationInput,
) (applicationticketing.WatcherMutationResult, error) {
	return stub.mutateWatcher(
		ctx, actor, tenantID, kernel.AggregateAlert, alertID, userID,
		applicationticketing.WatcherAdd, input,
	)
}

func (stub *watcherTransportStub) AddCaseWatcher(
	ctx context.Context,
	actor applicationticketing.Actor,
	tenantID, caseID, userID uuid.UUID,
	input applicationticketing.WatcherMutationInput,
) (applicationticketing.WatcherMutationResult, error) {
	return stub.mutateWatcher(
		ctx, actor, tenantID, kernel.AggregateCase, caseID, userID,
		applicationticketing.WatcherAdd, input,
	)
}

func (stub *watcherTransportStub) RemoveAlertWatcher(
	ctx context.Context,
	actor applicationticketing.Actor,
	tenantID, alertID, userID uuid.UUID,
	input applicationticketing.WatcherMutationInput,
) (applicationticketing.WatcherMutationResult, error) {
	return stub.mutateWatcher(
		ctx, actor, tenantID, kernel.AggregateAlert, alertID, userID,
		applicationticketing.WatcherRemove, input,
	)
}

func (stub *watcherTransportStub) RemoveCaseWatcher(
	ctx context.Context,
	actor applicationticketing.Actor,
	tenantID, caseID, userID uuid.UUID,
	input applicationticketing.WatcherMutationInput,
) (applicationticketing.WatcherMutationResult, error) {
	return stub.mutateWatcher(
		ctx, actor, tenantID, kernel.AggregateCase, caseID, userID,
		applicationticketing.WatcherRemove, input,
	)
}

func (stub *watcherTransportStub) mutateWatcher(
	ctx context.Context,
	actor applicationticketing.Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	ticketID uuid.UUID,
	targetUserID uuid.UUID,
	action applicationticketing.WatcherMutationAction,
	input applicationticketing.WatcherMutationInput,
) (applicationticketing.WatcherMutationResult, error) {
	stub.mutateCalls++
	if stub.mutateFn == nil {
		return applicationticketing.WatcherMutationResult{}, applicationticketing.ErrUnavailable
	}
	return stub.mutateFn(ctx, actor, tenantID, kind, ticketID, targetUserID, action, input)
}

func TestAlertWatcherListTransportReturnsCanonicalPageAndStrongETag(t *testing.T) {
	t.Parallel()
	tenantID, alertID := mustTransportUUIDv7(t), mustTransportUUIDv7(t)
	actorID, targetID := mustTransportUUIDv7(t), mustTransportUUIDv7(t)
	now := time.Date(2026, 9, 1, 10, 0, 0, 123_456_000, time.UTC)
	stub := &watcherTransportStub{
		transportTicketingStub: &transportTicketingStub{},
		listFn: func(
			ctx context.Context,
			actor applicationticketing.Actor,
			requestedTenant uuid.UUID,
			kind kernel.AggregateKind,
			requestedTicket uuid.UUID,
		) (applicationticketing.TicketWatcherProjection, error) {
			if ctx.Err() != nil || actor.UserID != actorID || actor.Audit.RequestID != uuid.Nil ||
				requestedTenant != tenantID || requestedTicket != alertID || kind != kernel.AggregateAlert {
				t.Fatalf("unexpected watcher list target or actor")
			}
			return watcherTransportProjection(
				tenantID, alertID, kind, now, 5,
				applicationticketing.TicketWatcher{
					UserID: targetID, DisplayName: "Incident Responder", AddedAt: now.Add(-time.Minute),
				},
			), nil
		},
	}
	router := newTicketingTestRouter(t, tenantLDAPTransportAuthentication(tenantID, actorID), stub)
	request := httptest.NewRequest(
		http.MethodGet,
		"/api/v1/tenants/"+tenantID.String()+"/alerts/"+alertID.String()+"/watchers",
		nil,
	)
	prepareTenantLDAPTransportRequest(request, false)
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if response.Header().Get("ETag") != `"v5"` || response.Header().Get("Cache-Control") != "no-store" ||
		response.Header().Get(idempotentReplayHeader) != "" {
		t.Fatalf("headers=%#v", response.Header())
	}
	var page contract.TicketWatcherPage
	if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if page.Version != 5 || !page.UpdatedAt.Equal(now) || len(page.Items) != 1 ||
		uuid.UUID(page.Items[0].UserId) != targetID || page.Items[0].DisplayName != "Incident Responder" {
		t.Fatalf("page=%#v", page)
	}
	if stub.listCalls != 1 || stub.mutateCalls != 0 {
		t.Fatalf("list=%d mutate=%d", stub.listCalls, stub.mutateCalls)
	}
}

func TestWatcherMutationTransportBindsHeadersAndReturnsReplayReceipt(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		kind   kernel.AggregateKind
		action applicationticketing.WatcherMutationAction
		method string
		path   func(uuid.UUID, uuid.UUID, uuid.UUID) string
		items  func(uuid.UUID, time.Time) []applicationticketing.TicketWatcher
		result uint64
		replay bool
	}{
		{
			name: "add Alert replay", kind: kernel.AggregateAlert, action: applicationticketing.WatcherAdd,
			method: http.MethodPut, result: 8, replay: true,
			path: func(tenantID, ticketID, userID uuid.UUID) string {
				return "/api/v1/tenants/" + tenantID.String() + "/alerts/" + ticketID.String() + "/watchers/" + userID.String()
			},
			items: func(userID uuid.UUID, now time.Time) []applicationticketing.TicketWatcher {
				return []applicationticketing.TicketWatcher{{UserID: userID, DisplayName: "Responder", AddedAt: now}}
			},
		},
		{
			name: "remove Case absent no-op", kind: kernel.AggregateCase, action: applicationticketing.WatcherRemove,
			method: http.MethodDelete, result: 7, replay: false,
			path: func(tenantID, ticketID, userID uuid.UUID) string {
				return "/api/v1/tenants/" + tenantID.String() + "/cases/" + ticketID.String() + "/watchers/" + userID.String()
			},
			items: func(uuid.UUID, time.Time) []applicationticketing.TicketWatcher {
				return []applicationticketing.TicketWatcher{}
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			tenantID, ticketID := mustTransportUUIDv7(t), mustTransportUUIDv7(t)
			actorID, targetID := mustTransportUUIDv7(t), mustTransportUUIDv7(t)
			requestID := mustTransportUUIDv7(t)
			now := time.Date(2026, 9, 1, 10, 5, 0, 0, time.UTC)
			stub := &watcherTransportStub{
				transportTicketingStub: &transportTicketingStub{},
				mutateFn: func(
					ctx context.Context,
					actor applicationticketing.Actor,
					requestedTenant uuid.UUID,
					kind kernel.AggregateKind,
					requestedTicket uuid.UUID,
					requestedTarget uuid.UUID,
					action applicationticketing.WatcherMutationAction,
					input applicationticketing.WatcherMutationInput,
				) (applicationticketing.WatcherMutationResult, error) {
					if ctx.Err() != nil || actor.UserID != actorID || actor.Audit.RequestID != requestID ||
						requestedTenant != tenantID || requestedTicket != ticketID || requestedTarget != targetID ||
						kind != test.kind || action != test.action || input.ExpectedVersion != 7 ||
						input.IdempotencyKey != "watcher-transport-key-0001" {
						t.Fatalf("unexpected watcher mutation binding")
					}
					return applicationticketing.WatcherMutationResult{
						Projection: watcherTransportProjection(
							tenantID, ticketID, kind, now, test.result, test.items(targetID, now)...,
						),
						Replayed: test.replay,
					}, nil
				},
			}
			router := newTicketingTestRouter(t, tenantLDAPTransportAuthentication(tenantID, actorID), stub)
			request := httptest.NewRequest(test.method, test.path(tenantID, ticketID, targetID), nil)
			prepareTenantLDAPTransportRequest(request, true)
			request.Header.Set(ifMatchHeader, `"v7"`)
			request.Header.Set(idempotencyKeyHeader, "watcher-transport-key-0001")
			request.Header.Set(requestIDHeader, requestID.String())
			response := httptest.NewRecorder()

			router.ServeHTTP(response, request)

			if response.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if response.Header().Get("ETag") != `"v`+strconv.FormatUint(test.result, 10)+`"` {
				t.Fatalf("ETag=%q", response.Header().Get("ETag"))
			}
			if response.Header().Get(idempotentReplayHeader) != map[bool]string{true: "true", false: "false"}[test.replay] ||
				response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("headers=%#v", response.Header())
			}
			var page contract.TicketWatcherPage
			if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil || uint64(page.Version) != test.result {
				t.Fatalf("page=%#v err=%v", page, err)
			}
			if stub.mutateCalls != 1 || stub.listCalls != 0 {
				t.Fatalf("mutate=%d list=%d", stub.mutateCalls, stub.listCalls)
			}
		})
	}
}

func TestWatcherTransportRejectsPreconditionErrorsAndMalformedProjection(t *testing.T) {
	t.Parallel()
	tenantID, alertID := mustTransportUUIDv7(t), mustTransportUUIDv7(t)
	actorID, targetID := mustTransportUUIDv7(t), mustTransportUUIDv7(t)
	path := "/api/v1/tenants/" + tenantID.String() + "/alerts/" + alertID.String() + "/watchers/" + targetID.String()
	tests := []struct {
		name      string
		configure func(*http.Request)
		service   error
		body      string
		want      int
	}{
		{name: "missing If-Match", configure: func(request *http.Request) { request.Header.Del(ifMatchHeader) }, want: http.StatusPreconditionRequired},
		{name: "duplicate idempotency key", configure: func(request *http.Request) { request.Header.Add(idempotencyKeyHeader, "watcher-other-key-0002") }, want: http.StatusBadRequest},
		{name: "maximum non-incrementable version", configure: func(request *http.Request) { request.Header.Set(ifMatchHeader, `"v2147483647"`) }, want: http.StatusBadRequest},
		{name: "unexpected request body", body: `{}`, want: http.StatusBadRequest},
		{name: "stale version", service: applicationticketing.ErrPreconditionFailed, want: http.StatusPreconditionFailed},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			stub := &watcherTransportStub{
				transportTicketingStub: &transportTicketingStub{},
				mutateFn: func(
					context.Context, applicationticketing.Actor, uuid.UUID, kernel.AggregateKind, uuid.UUID,
					uuid.UUID, applicationticketing.WatcherMutationAction, applicationticketing.WatcherMutationInput,
				) (applicationticketing.WatcherMutationResult, error) {
					return applicationticketing.WatcherMutationResult{}, test.service
				},
			}
			router := newTicketingTestRouter(t, tenantLDAPTransportAuthentication(tenantID, actorID), stub)
			var body *strings.Reader
			if test.body != "" {
				body = strings.NewReader(test.body)
			} else {
				body = strings.NewReader("")
			}
			request := httptest.NewRequest(http.MethodPut, path, body)
			prepareTenantLDAPTransportRequest(request, true)
			request.Header.Set(ifMatchHeader, `"v7"`)
			request.Header.Set(idempotencyKeyHeader, "watcher-transport-key-0001")
			if test.configure != nil {
				test.configure(request)
			}
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("status=%d want=%d body=%s", response.Code, test.want, response.Body.String())
			}
			if test.service == nil && stub.mutateCalls != 0 {
				t.Fatalf("use case calls=%d", stub.mutateCalls)
			}
		})
	}

	now := time.Date(2026, 9, 1, 10, 10, 0, 0, time.UTC)
	stub := &watcherTransportStub{
		transportTicketingStub: &transportTicketingStub{},
		listFn: func(
			context.Context, applicationticketing.Actor, uuid.UUID, kernel.AggregateKind, uuid.UUID,
		) (applicationticketing.TicketWatcherProjection, error) {
			return watcherTransportProjection(
				tenantID, alertID, kernel.AggregateAlert, now, 2,
				applicationticketing.TicketWatcher{UserID: mustTransportUUIDv7(t), DisplayName: "Zulu", AddedAt: now},
				applicationticketing.TicketWatcher{UserID: mustTransportUUIDv7(t), DisplayName: "Alpha", AddedAt: now},
			), nil
		},
	}
	router := newTicketingTestRouter(t, tenantLDAPTransportAuthentication(tenantID, actorID), stub)
	request := httptest.NewRequest(
		http.MethodGet,
		"/api/v1/tenants/"+tenantID.String()+"/alerts/"+alertID.String()+"/watchers",
		nil,
	)
	prepareTenantLDAPTransportRequest(request, false)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("malformed projection status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestMapTicketWatcherPageRejectsHistoricalShapeDrift(t *testing.T) {
	t.Parallel()
	tenantID, ticketID := mustTransportUUIDv7(t), mustTransportUUIDv7(t)
	now := time.Date(2026, 9, 1, 10, 15, 0, 0, time.UTC)
	valid := watcherTransportProjection(tenantID, ticketID, kernel.AggregateAlert, now, 2)
	tests := []struct {
		name   string
		mutate func(*applicationticketing.TicketWatcherProjection)
	}{
		{name: "tenant mismatch", mutate: func(value *applicationticketing.TicketWatcherProjection) { value.TenantID = mustTransportUUIDv7(t) }},
		{name: "nil items", mutate: func(value *applicationticketing.TicketWatcherProjection) { value.Items = nil }},
		{name: "version leap", mutate: func(value *applicationticketing.TicketWatcherProjection) { value.Version = 4 }},
	}
	expected := uint64(1)
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			value := valid
			test.mutate(&value)
			if _, err := mapTicketWatcherPage(value, tenantID, kernel.AggregateAlert, ticketID, &expected); err == nil {
				t.Fatal("malformed watcher page was accepted")
			}
		})
	}
	if _, err := mapTicketWatcherPage(valid, tenantID, kernel.AggregateAlert, ticketID, &expected); err != nil {
		t.Fatalf("valid page error=%v", err)
	}
	if _, err := mapTicketWatcherPage(valid, tenantID, kernel.AggregateAlert, ticketID, nil); err != nil {
		t.Fatalf("valid list page error=%v", err)
	}
}

func watcherTransportProjection(
	tenantID uuid.UUID,
	ticketID uuid.UUID,
	kind kernel.AggregateKind,
	updatedAt time.Time,
	version uint64,
	items ...applicationticketing.TicketWatcher,
) applicationticketing.TicketWatcherProjection {
	return applicationticketing.TicketWatcherProjection{
		TenantID: tenantID, TicketID: ticketID, Kind: kind,
		Items:   append([]applicationticketing.TicketWatcher{}, items...),
		Version: version, UpdatedAt: updatedAt,
	}
}
