package ticketing

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
)

func TestCreateAlertRelationUsesOneCompoundAuthorityAndPinsBothVersions(t *testing.T) {
	fixture := newServiceFixture(t)
	targetID := mustUUIDv7(t)
	source := alertRelationRecordFixture(t, fixture, fixture.ticketUUID, 3)
	target := alertRelationRecordFixture(t, fixture, targetID, 7)
	relationID := mustUUIDv7(t)
	repository := &fakeRepository{
		fixture: fixture,
		records: map[uuid.UUID]Record{fixture.ticketUUID: source, targetID: target},
		alertRelationReceipt: AlertRelationMutationReceipt{
			TenantID: fixture.tenantUUID, AlertID: fixture.ticketUUID,
			RelatedAlertID: targetID, RelationID: relationID,
			RelationType:         AlertRelationDuplicateOf,
			PreviousAlertVersion: 3, AlertVersion: 4,
			PreviousRelatedAlertVersion: 7, RelatedAlertVersion: 8,
			OccurredAt: source.UpdatedAt.Add(time.Second),
		},
	}
	service := mustService(t, repository)

	receipt, err := service.CreateAlertRelation(
		context.Background(), fixture.actor, fixture.tenantUUID, fixture.ticketUUID,
		AlertRelationCreateInput{
			TargetAlertID: targetID, RelationType: AlertRelationDuplicateOf,
			ExpectedVersion: 3, ExpectedTargetVersion: 7,
			Reason: "Literal <endpoint> evidence", IdempotencyKey: "alert-relation-create-0001",
		},
	)
	if err != nil || receipt.RelationID != relationID || repository.alertRelationCreates.Load() != 1 {
		t.Fatalf("CreateAlertRelation() = (%+v, %v), writes=%d", receipt, err, repository.alertRelationCreates.Load())
	}
	if len(repository.accessCalls) != 1 || repository.accessCalls[0] != CapabilityAlertRelationManage {
		t.Fatalf("resolved authorities = %v, want one compound capability", repository.accessCalls)
	}
	write := repository.alertRelationCreateWrite
	if write.Plan.PreviousSourceVersion() != 3 || write.Plan.SourceVersion() != 4 ||
		write.Plan.PreviousTargetVersion() != 7 || write.Plan.TargetVersion() != 8 ||
		write.Source.Title != source.Title || write.Target.Title != target.Title {
		t.Fatalf("create write did not preserve both CAS pins: %+v", write)
	}
}

func TestAlertRelationApplicationReasonRejectsEveryControlCharacter(t *testing.T) {
	fixture := newServiceFixture(t)
	targetID := mustUUIDv7(t)
	for name, reason := range map[string]string{
		"tab":     "same\tendpoint",
		"newline": "same\nendpoint",
		"bidi":    "same\u202eendpoint",
	} {
		t.Run(name, func(t *testing.T) {
			_, _, _, _, err := prepareAlertRelationCreate(
				fixture.actor,
				fixture.tenantUUID,
				fixture.ticketUUID,
				AlertRelationCreateInput{
					TargetAlertID: targetID, RelationType: AlertRelationCorrelation,
					ExpectedVersion: 1, ExpectedTargetVersion: 1,
					Reason: reason, IdempotencyKey: "alert-relation-control-0001",
				},
			)
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("prepareAlertRelationCreate(%q) error=%v, want invalid", reason, err)
			}
		})
	}
}

func TestCreateAlertRelationExactReplayDoesNotReadOrRewriteAlerts(t *testing.T) {
	fixture := newServiceFixture(t)
	targetID := mustUUIDv7(t)
	relationID := mustUUIDv7(t)
	repository := &fakeRepository{
		fixture: fixture, alertRelationFound: true,
		alertRelationReplay: AlertRelationMutationReceipt{
			TenantID: fixture.tenantUUID, AlertID: fixture.ticketUUID,
			RelatedAlertID: targetID, RelationID: relationID,
			RelationType:         AlertRelationCorrelation,
			PreviousAlertVersion: 2, AlertVersion: 3,
			PreviousRelatedAlertVersion: 5, RelatedAlertVersion: 6,
			OccurredAt: fixture.record.UpdatedAt,
		},
	}
	service := mustService(t, repository)

	receipt, err := service.CreateAlertRelation(
		context.Background(), fixture.actor, fixture.tenantUUID, fixture.ticketUUID,
		AlertRelationCreateInput{
			TargetAlertID: targetID, RelationType: AlertRelationCorrelation,
			ExpectedVersion: 2, ExpectedTargetVersion: 5,
			Reason: "Exact shared indicators", IdempotencyKey: "alert-relation-create-replay-0001",
		},
	)
	if err != nil || !receipt.Replayed || repository.getCalls.Load() != 0 || repository.alertRelationCreates.Load() != 0 {
		t.Fatalf("exact replay = (%+v, %v), gets=%d writes=%d", receipt, err, repository.getCalls.Load(), repository.alertRelationCreates.Load())
	}
}

func TestCreateAlertRelationRejectsDisjointResourceScopes(t *testing.T) {
	fixture := newServiceFixture(t)
	targetID := mustUUIDv7(t)
	source := alertRelationRecordFixture(t, fixture, fixture.ticketUUID, 1)
	target := alertRelationRecordFixture(t, fixture, targetID, 1)
	other := mustUUIDv7(t)
	target.Creator.UserID = &other
	actorEntity, _ := entityID(fixture.actor.UserID)
	target.Snapshot = mustSnapshot(
		t, fixture.workflow, fixture.tenant, target.Snapshot.ID(), true,
		mustAssignment(t, fixture.team, &actorEntity, nil), 1,
	)
	repository := &fakeRepository{
		fixture: fixture, scopes: []Scope{ScopeOwn, ScopeAssigned},
		records: map[uuid.UUID]Record{fixture.ticketUUID: source, targetID: target},
	}
	service := mustService(t, repository)

	_, err := service.CreateAlertRelation(
		context.Background(), fixture.actor, fixture.tenantUUID, fixture.ticketUUID,
		AlertRelationCreateInput{
			TargetAlertID: targetID, RelationType: AlertRelationCorrelation,
			ExpectedVersion: 1, ExpectedTargetVersion: 1,
			Reason: "Disjoint authorization must fail", IdempotencyKey: "alert-relation-disjoint-0001",
		},
	)
	if !errors.Is(err, ErrForbidden) || repository.alertRelationCreates.Load() != 0 {
		t.Fatalf("CreateAlertRelation(disjoint) error=%v writes=%d", err, repository.alertRelationCreates.Load())
	}
}

func TestAlertRelationsRejectsPartialPageCursorAndImpossibleRetraction(t *testing.T) {
	fixture := newServiceFixture(t)
	targetID := mustUUIDv7(t)
	path := alertRelationRecordFixture(t, fixture, fixture.ticketUUID, 8)
	related := alertRelationRecordFixture(t, fixture, targetID, 9)
	relationID := mustUUIDv7(t)
	item := AlertRelationRecord{
		Direction: AlertRelationOutgoing, Related: related,
		Relation: AlertRelation{
			ID: relationID, TenantID: fixture.tenantUUID,
			SourceAlertID: fixture.ticketUUID, TargetAlertID: targetID,
			Type: AlertRelationDuplicateOf, Reason: "Same telemetry",
			PreviousSourceVersion: 2, SourceVersion: 3,
			PreviousTargetVersion: 4, TargetVersion: 5,
			LinkedAt: fixture.record.CreatedAt,
		},
	}
	repository := &fakeRepository{
		fixture: fixture, record: path,
		alertRelationPage: StoredAlertRelationPage{Items: []AlertRelationRecord{item}, NextCursor: &relationID},
	}
	service := mustService(t, repository)

	_, err := service.AlertRelations(
		context.Background(), fixture.actor, fixture.tenantUUID, fixture.ticketUUID,
		CursorPageInput{Limit: 2},
	)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("AlertRelations(partial cursor) error=%v, want unavailable", err)
	}

	item.Relation.Retraction = &AlertRelationRetraction{
		Reason:                "Evidence was incorrect",
		PreviousSourceVersion: 2, SourceVersion: 3,
		PreviousTargetVersion: 5, TargetVersion: 6,
		RetractedAt: fixture.record.CreatedAt.Add(time.Second),
	}
	repository.alertRelationPage = StoredAlertRelationPage{Items: []AlertRelationRecord{item}}
	_, err = service.AlertRelations(
		context.Background(), fixture.actor, fixture.tenantUUID, fixture.ticketUUID,
		CursorPageInput{Limit: 2},
	)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("AlertRelations(impossible retraction) error=%v, want unavailable", err)
	}
}

func TestAlertRelationsRejectsSnapshotsOlderThanImmutableEvidence(t *testing.T) {
	fixture := newServiceFixture(t)
	targetID := mustUUIDv7(t)
	relationID := mustUUIDv7(t)
	path := alertRelationRecordFixture(t, fixture, fixture.ticketUUID, 2)
	related := alertRelationRecordFixture(t, fixture, targetID, 5)
	item := AlertRelationRecord{
		Direction: AlertRelationOutgoing, Related: related,
		Relation: AlertRelation{
			ID: relationID, TenantID: fixture.tenantUUID,
			SourceAlertID: fixture.ticketUUID, TargetAlertID: targetID,
			Type: AlertRelationDuplicateOf, Reason: "Same telemetry",
			PreviousSourceVersion: 2, SourceVersion: 3,
			PreviousTargetVersion: 5, TargetVersion: 6,
			LinkedAt: fixture.record.CreatedAt,
		},
	}
	repository := &fakeRepository{
		fixture: fixture, record: path,
		alertRelationPage: StoredAlertRelationPage{Items: []AlertRelationRecord{item}},
	}
	service := mustService(t, repository)

	_, err := service.AlertRelations(
		context.Background(), fixture.actor, fixture.tenantUUID, fixture.ticketUUID,
		CursorPageInput{Limit: 2},
	)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("AlertRelations(stale snapshots) error=%v, want unavailable", err)
	}
}

func TestAlertRelationsRejectsOverflowedEvidenceVersions(t *testing.T) {
	fixture := newServiceFixture(t)
	targetID := mustUUIDv7(t)
	relationID := mustUUIDv7(t)
	path := alertRelationRecordFixture(t, fixture, fixture.ticketUUID, 2)
	related := alertRelationRecordFixture(t, fixture, targetID, 2)
	item := AlertRelationRecord{
		Direction: AlertRelationOutgoing, Related: related,
		Relation: AlertRelation{
			ID: relationID, TenantID: fixture.tenantUUID,
			SourceAlertID: fixture.ticketUUID, TargetAlertID: targetID,
			Type: AlertRelationDuplicateOf, Reason: "Same telemetry",
			PreviousSourceVersion: ^uint64(0), SourceVersion: 0,
			PreviousTargetVersion: 1, TargetVersion: 2,
			LinkedAt: fixture.record.CreatedAt,
		},
	}
	repository := &fakeRepository{
		fixture: fixture, record: path,
		alertRelationPage: StoredAlertRelationPage{Items: []AlertRelationRecord{item}},
	}
	service := mustService(t, repository)

	_, err := service.AlertRelations(
		context.Background(), fixture.actor, fixture.tenantUUID, fixture.ticketUUID,
		CursorPageInput{Limit: 2},
	)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("AlertRelations(overflowed evidence) error=%v, want unavailable", err)
	}
}

func alertRelationRecordFixture(t testing.TB, fixture serviceFixture, id uuid.UUID, version uint64) Record {
	t.Helper()
	value := fixture.record
	entity, _ := entityID(id)
	value.Snapshot = mustSnapshot(t, fixture.workflow, fixture.tenant, entity, true, kernel.Assignment{}, version)
	value.Number = "ALT-RELATED"
	value.Title = "Related alert"
	return value
}
