package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	applicationticketing "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

type alertRelationTransportStub struct {
	*transportTicketingStub
	listFn    func(context.Context, applicationticketing.Actor, uuid.UUID, uuid.UUID, applicationticketing.CursorPageInput) (applicationticketing.AlertRelationPage, error)
	createFn  func(context.Context, applicationticketing.Actor, uuid.UUID, uuid.UUID, applicationticketing.AlertRelationCreateInput) (applicationticketing.AlertRelationMutationReceipt, error)
	retractFn func(context.Context, applicationticketing.Actor, uuid.UUID, uuid.UUID, uuid.UUID, applicationticketing.AlertRelationRetractionInput) (applicationticketing.AlertRelationMutationReceipt, error)
}

func (stub *alertRelationTransportStub) AlertRelations(ctx context.Context, actor applicationticketing.Actor, tenantID, alertID uuid.UUID, page applicationticketing.CursorPageInput) (applicationticketing.AlertRelationPage, error) {
	return stub.listFn(ctx, actor, tenantID, alertID, page)
}

func (stub *alertRelationTransportStub) CreateAlertRelation(ctx context.Context, actor applicationticketing.Actor, tenantID, alertID uuid.UUID, input applicationticketing.AlertRelationCreateInput) (applicationticketing.AlertRelationMutationReceipt, error) {
	return stub.createFn(ctx, actor, tenantID, alertID, input)
}

func (stub *alertRelationTransportStub) RetractAlertRelation(ctx context.Context, actor applicationticketing.Actor, tenantID, alertID, relationID uuid.UUID, input applicationticketing.AlertRelationRetractionInput) (applicationticketing.AlertRelationMutationReceipt, error) {
	return stub.retractFn(ctx, actor, tenantID, alertID, relationID, input)
}

func TestAlertRelationListTransportIsOperatorMinimalAndBindsCursor(t *testing.T) {
	tenantID, alertID, relatedID := mustTransportUUIDv7(t), mustTransportUUIDv7(t), mustTransportUUIDv7(t)
	userID, relationID, cursor := mustTransportUUIDv7(t), mustTransportUUIDv7(t), mustTransportUUIDv7(t)
	related := transportTicketView(t, tenantID, relatedID, userID, 8, applicationticketing.ProjectionOperator).Record
	linkedAt := time.Date(2026, time.September, 2, 12, 0, 0, 123000000, time.UTC)
	stub := &alertRelationTransportStub{transportTicketingStub: &transportTicketingStub{}}
	stub.listFn = func(_ context.Context, actor applicationticketing.Actor, requestedTenant, requestedAlert uuid.UUID, page applicationticketing.CursorPageInput) (applicationticketing.AlertRelationPage, error) {
		if actor.UserID != userID || requestedTenant != tenantID || requestedAlert != alertID ||
			page.After == nil || *page.After != cursor || page.Limit != 17 {
			t.Fatalf("unexpected list binding: actor=%+v tenant=%s alert=%s page=%+v", actor, requestedTenant, requestedAlert, page)
		}
		return applicationticketing.AlertRelationPage{Items: []applicationticketing.AlertRelationRecord{{
			Direction: applicationticketing.AlertRelationIncoming, Related: related,
			Relation: applicationticketing.AlertRelation{
				ID: relationID, TenantID: tenantID, SourceAlertID: relatedID, TargetAlertID: alertID,
				Type: applicationticketing.AlertRelationDuplicateOf, Reason: "Same endpoint",
				PreviousSourceVersion: 6, SourceVersion: 7,
				PreviousTargetVersion: 3, TargetVersion: 4, LinkedAt: linkedAt,
			},
		}}}, nil
	}
	router := newTicketingTestRouter(t, tenantLDAPTransportAuthentication(tenantID, userID), stub)
	request := httptest.NewRequest(http.MethodGet,
		"/api/v1/tenants/"+tenantID.String()+"/alerts/"+alertID.String()+
			"/related-alerts?after="+cursor.String()+"&limit=17", nil)
	prepareTenantLDAPTransportRequest(request, false)
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	items, ok := body["items"].([]any)
	if !ok || len(items) != 1 {
		t.Fatalf("items=%#v", body["items"])
	}
	item := items[0].(map[string]any)
	summary := item["relatedAlert"].(map[string]any)
	if item["direction"] != "incoming" || item["status"] != "active" || summary["id"] != relatedID.String() {
		t.Fatalf("relation projection=%#v", item)
	}
	for _, forbidden := range []string{"rawPayload", "customFields", "assignment", "creator", "description"} {
		if _, exists := summary[forbidden]; exists {
			t.Fatalf("related summary leaked %q: %#v", forbidden, summary)
		}
	}
}

func TestAlertRelationCreateTransportBindsBothCASPinsAndReplayReceipt(t *testing.T) {
	tenantID, alertID, targetID := mustTransportUUIDv7(t), mustTransportUUIDv7(t), mustTransportUUIDv7(t)
	userID, relationID := mustTransportUUIDv7(t), mustTransportUUIDv7(t)
	var captured applicationticketing.AlertRelationCreateInput
	stub := &alertRelationTransportStub{transportTicketingStub: &transportTicketingStub{}}
	stub.createFn = func(_ context.Context, actor applicationticketing.Actor, requestedTenant, requestedAlert uuid.UUID, input applicationticketing.AlertRelationCreateInput) (applicationticketing.AlertRelationMutationReceipt, error) {
		if actor.UserID != userID || requestedTenant != tenantID || requestedAlert != alertID {
			t.Fatalf("unexpected create actor or target")
		}
		captured = input
		return applicationticketing.AlertRelationMutationReceipt{
			TenantID: tenantID, AlertID: alertID, RelatedAlertID: targetID,
			RelationID: relationID, RelationType: applicationticketing.AlertRelationCorrelation,
			PreviousAlertVersion: 4, AlertVersion: 5,
			PreviousRelatedAlertVersion: 9, RelatedAlertVersion: 10,
			OccurredAt: time.Date(2026, time.September, 2, 13, 0, 0, 0, time.UTC), Replayed: true,
		}, nil
	}
	router := newTicketingTestRouter(t, tenantLDAPTransportAuthentication(tenantID, userID), stub)
	request := ticketingMutationRequest(http.MethodPost,
		"/api/v1/tenants/"+tenantID.String()+"/alerts/"+alertID.String()+"/related-alerts",
		`{"targetAlertId":"`+targetID.String()+`","relationType":"correlation","expectedVersion":4,"expectedTargetVersion":9,"reason":"Shared indicators"}`)
	request.Header.Set(ifMatchHeader, `"v4"`)
	request.Header.Set(idempotencyKeyHeader, "alert-relation-create-transport-0001")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"v5"` ||
		response.Header().Get(idempotentReplayHeader) != "true" || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
	if captured.TargetAlertID != targetID || captured.ExpectedVersion != 4 || captured.ExpectedTargetVersion != 9 ||
		captured.RelationType != applicationticketing.AlertRelationCorrelation || captured.Reason != "Shared indicators" ||
		captured.IdempotencyKey != "alert-relation-create-transport-0001" {
		t.Fatalf("captured input=%+v", captured)
	}
	var receipt struct {
		AlertVersion        int       `json:"alertVersion"`
		RelatedAlertVersion int       `json:"relatedAlertVersion"`
		RelationID          uuid.UUID `json:"relationId"`
		Replayed            bool      `json:"replayed"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &receipt); err != nil || receipt.RelationID != relationID ||
		receipt.AlertVersion != 5 || receipt.RelatedAlertVersion != 10 || !receipt.Replayed {
		t.Fatalf("receipt=%+v err=%v", receipt, err)
	}
}

func TestAlertRelationMutationTransportRejectsHeaderBodyVersionMismatch(t *testing.T) {
	tenantID, alertID, targetID := mustTransportUUIDv7(t), mustTransportUUIDv7(t), mustTransportUUIDv7(t)
	userID := mustTransportUUIDv7(t)
	called := false
	stub := &alertRelationTransportStub{transportTicketingStub: &transportTicketingStub{}}
	stub.createFn = func(context.Context, applicationticketing.Actor, uuid.UUID, uuid.UUID, applicationticketing.AlertRelationCreateInput) (applicationticketing.AlertRelationMutationReceipt, error) {
		called = true
		return applicationticketing.AlertRelationMutationReceipt{}, nil
	}
	router := newTicketingTestRouter(t, tenantLDAPTransportAuthentication(tenantID, userID), stub)
	request := ticketingMutationRequest(http.MethodPost,
		"/api/v1/tenants/"+tenantID.String()+"/alerts/"+alertID.String()+"/related-alerts",
		`{"targetAlertId":"`+targetID.String()+`","relationType":"duplicate_of","expectedVersion":4,"expectedTargetVersion":9,"reason":"Duplicate evidence"}`)
	request.Header.Set(ifMatchHeader, `"v5"`)
	request.Header.Set(idempotencyKeyHeader, "alert-relation-create-transport-0002")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	assertProblem(t, response, http.StatusBadRequest, "invalid_request")
	if called {
		t.Fatal("use case called after header/body version mismatch")
	}
}
