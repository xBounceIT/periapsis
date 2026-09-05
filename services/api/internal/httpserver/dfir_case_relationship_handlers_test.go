package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	dfirkernel "github.com/periapsis-im/periapsis/modules/dfir"
	applicationdfir "github.com/periapsis-im/periapsis/services/api/internal/dfir"
)

type caseRelationshipTransportDFIRService struct {
	*transportDFIRStub
	retract func(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.RelationshipRetractCommand) (applicationdfir.MutationResult[dfirkernel.Relationship], error)
}

func (service *caseRelationshipTransportDFIRService) RetractRelationship(ctx context.Context, actor applicationdfir.Actor, tenantID uuid.UUID, command applicationdfir.RelationshipRetractCommand) (applicationdfir.MutationResult[dfirkernel.Relationship], error) {
	return service.retract(ctx, actor, tenantID, command)
}

func TestCaseRelationshipRetractionTransportPreservesCASIdentityAndHistory(t *testing.T) {
	fixture := newPhase4HTTPFixture(t)
	relationshipID, retractionID := mustTransportUUIDv7(t), mustTransportUUIDv7(t)
	caseEntity, _ := dfirEntityID(fixture.caseID)
	relationshipEntity, _ := dfirEntityID(relationshipID)
	retractionEntity, _ := dfirEntityID(retractionID)
	tenantEntity, _ := dfirEntityID(fixture.tenantID)
	actorEntity, _ := dfirEntityID(fixture.membershipID)
	createdAt := time.Date(2026, time.September, 4, 8, 0, 0, 0, time.UTC)
	retractedAt := createdAt.Add(time.Hour)

	service := &caseRelationshipTransportDFIRService{transportDFIRStub: &transportDFIRStub{}}
	service.retract = func(_ context.Context, actor applicationdfir.Actor, tenantID uuid.UUID, command applicationdfir.RelationshipRetractCommand) (applicationdfir.MutationResult[dfirkernel.Relationship], error) {
		if actor.MembershipID != fixture.membershipID || tenantID != fixture.tenantID || command.CaseID != caseEntity ||
			command.RelationshipID != relationshipEntity || command.RetractionID != retractionEntity ||
			command.ExpectedVersion != 1 || command.Reason != "Merged duplicate relationship" ||
			command.Envelope.IdempotencyKey != "case-relationship-retract-1" {
			t.Fatalf("unexpected Case relationship retraction command: actor=%#v tenant=%s command=%#v", actor, tenantID, command)
		}
		source, sourceErr := dfirkernel.NewEntityReference(tenantEntity, dfirkernel.EntityCase, caseEntity)
		target, targetErr := dfirkernel.NewExternalEntityReference(tenantEntity, "mitre-technique", "T1059")
		if sourceErr != nil || targetErr != nil {
			t.Fatalf("construct references: %v / %v", sourceErr, targetErr)
		}
		value, err := dfirkernel.NewRelationship(dfirkernel.RelationshipInput{
			ID: relationshipEntity, TenantID: tenantEntity, Source: source, Target: target,
			RelationshipType: "indicates", Metadata: []byte(`{"confidence":95}`),
			CreatedBy: actorEntity, CreatedAt: createdAt, Version: 2,
			Retractions: []dfirkernel.RelationshipRetractionState{{
				ID: retractionEntity, TenantID: tenantEntity, RelationshipID: relationshipEntity,
				Sequence: 1, ActorID: actorEntity, Reason: command.Reason, OccurredAt: retractedAt,
			}},
		})
		return applicationdfir.MutationResult[dfirkernel.Relationship]{Resource: value, Replayed: true}, err
	}
	router := newPhase4TestRouter(t, fixture, &transportCustomFieldStub{}, service)
	path := "/api/v1/tenants/" + fixture.tenantID.String() + "/cases/" + fixture.caseID.String() +
		"/dfir/relationships/" + relationshipID.String() + "/retract"
	body := `{"expectedVersion":1,"retractionId":"` + retractionID.String() + `","reason":"Merged duplicate relationship"}`
	request := phase4MutationRequest(http.MethodPost, path, body, "case-relationship-retract-1")
	request.Header.Set("If-Match", `"v1"`)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"v2"` ||
		response.Header().Get(idempotentReplayHeader) != "true" {
		t.Fatalf("status/headers = %d %#v: %s", response.Code, response.Header(), response.Body.String())
	}
	var mapped struct {
		Active      bool  `json:"active"`
		Version     int64 `json:"version"`
		Retractions []struct {
			ID       uuid.UUID `json:"id"`
			ActorID  uuid.UUID `json:"actorId"`
			Sequence int64     `json:"sequence"`
			Reason   string    `json:"reason"`
		} `json:"retractions"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &mapped); err != nil || mapped.Active || mapped.Version != 2 ||
		len(mapped.Retractions) != 1 || mapped.Retractions[0].ID != retractionID ||
		mapped.Retractions[0].ActorID != fixture.membershipID || mapped.Retractions[0].Sequence != 1 ||
		mapped.Retractions[0].Reason != "Merged duplicate relationship" {
		t.Fatalf("unexpected Case relationship projection (%v): %s", err, response.Body.String())
	}
}

func TestCaseRelationshipRetractionRejectsMalformedBodyBeforeService(t *testing.T) {
	fixture := newPhase4HTTPFixture(t)
	service := &caseRelationshipTransportDFIRService{transportDFIRStub: &transportDFIRStub{}}
	calls := 0
	service.retract = func(context.Context, applicationdfir.Actor, uuid.UUID, applicationdfir.RelationshipRetractCommand) (applicationdfir.MutationResult[dfirkernel.Relationship], error) {
		calls++
		return applicationdfir.MutationResult[dfirkernel.Relationship]{}, applicationdfir.ErrUnavailable
	}
	path := "/api/v1/tenants/" + fixture.tenantID.String() + "/cases/" + fixture.caseID.String() +
		"/dfir/relationships/" + mustTransportUUIDv7(t).String() + "/retract"
	request := phase4MutationRequest(http.MethodPost, path, `{"expectedVersion":1`, "case-relationship-retract-2")
	request.Header.Set("If-Match", `"v1"`)
	response := httptest.NewRecorder()
	newPhase4TestRouter(t, fixture, &transportCustomFieldStub{}, service).ServeHTTP(response, request)
	assertProblem(t, response, http.StatusBadRequest, "invalid_request")
	if calls != 0 {
		t.Fatalf("malformed body reached service %d times", calls)
	}
}

var _ DFIRService = (*caseRelationshipTransportDFIRService)(nil)
