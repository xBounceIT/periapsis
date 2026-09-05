package httpserver

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	application "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

func TestMapTicketBulkJobPreservesImmutableReceiptAndProgress(t *testing.T) {
	record, IDs := explicitTicketBulkRecord(t)
	mapped, err := mapTicketBulkJob(record)
	if err != nil {
		t.Fatalf("mapTicketBulkJob() error = %v", err)
	}
	if mapped.Id != IDs.job || mapped.TenantId != IDs.tenant || mapped.RequesterUserId != IDs.requester ||
		mapped.OwnerMembershipId != IDs.owner || mapped.Kind != "alert" || mapped.State != "pending" ||
		mapped.Revision != 1 || mapped.Progress.Total != 2 || mapped.Progress.Succeeded != 0 ||
		mapped.Selection.Source != "explicit" || mapped.Selection.TargetCount != 2 || mapped.Selection.Targets == nil ||
		len(*mapped.Selection.Targets) != 2 || mapped.Selection.QuerySha256 != nil || mapped.Selection.EffectiveSpec != nil ||
		mapped.Mutation.Action != "assign" || mapped.Mutation.TeamId == nil || *mapped.Mutation.TeamId != IDs.team ||
		mapped.Mutation.AssigneeId == nil || *mapped.Mutation.AssigneeId != IDs.assignee {
		t.Fatalf("mapped job = %#v", mapped)
	}
	if mapped.Selection.TargetSetSha256 == ticketBulkZeroDigest || len(mapped.Selection.TargetSetSha256) != 64 {
		t.Fatalf("target-set digest = %q", mapped.Selection.TargetSetSha256)
	}
	encoded, err := json.Marshal(mapped)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	for _, required := range []string{`"activeBatch":false`, `"availableAt":`, `"targetSetSha256":`, `"authorizationRevoked":0`} {
		if !strings.Contains(string(encoded), required) {
			t.Fatalf("projection omitted %s: %s", required, encoded)
		}
	}
}

func TestMapTicketBulkQueryJobPreservesEffectiveSpecAndSavedViewPins(t *testing.T) {
	record, IDs, queryDigest, catalogDigest := queryTicketBulkRecord(t)
	mapped, err := mapTicketBulkJob(record)
	if err != nil {
		t.Fatalf("mapTicketBulkJob() error = %v", err)
	}
	selection := mapped.Selection
	if selection.Source != "query" || selection.Targets != nil || selection.QuerySource == nil ||
		*selection.QuerySource != "saved_view" || selection.QuerySha256 == nil || *selection.QuerySha256 != queryDigest ||
		selection.CatalogSha256 == nil || *selection.CatalogSha256 != catalogDigest || selection.EffectiveSpec == nil ||
		selection.SavedView == nil || selection.SavedView.Id != IDs.view || selection.SavedView.OwnerMembershipId != IDs.owner ||
		selection.SavedView.Revision != 4 || selection.SavedView.SpecSha256 != queryDigest {
		t.Fatalf("mapped query selection = %#v", selection)
	}
	if selection.EffectiveSpec.Filters.Queue != "all" || len(selection.EffectiveSpec.Columns) != 1 {
		t.Fatalf("effective spec = %#v", selection.EffectiveSpec)
	}
}

func TestMapTicketBulkProjectionFailsClosedForInvalidRecords(t *testing.T) {
	if _, err := mapTicketBulkJob(application.TicketBulkRecord{}); err == nil {
		t.Fatal("mapTicketBulkJob(zero) unexpectedly succeeded")
	}
	record, _ := explicitTicketBulkRecord(t)
	query := application.TicketBulkQuerySnapshot{}
	record.Query = &query
	if _, err := mapTicketBulkJob(record); err == nil {
		t.Fatal("explicit record with query proof unexpectedly succeeded")
	}
}

func TestMapTicketBulkResultPageUsesBoundedStableCodes(t *testing.T) {
	target := mustTransportUUIDv7(t)
	recordedAt := time.Date(2026, 8, 26, 19, 0, 0, 123_456_000, time.UTC)
	mapped, err := mapTicketBulkResultPage(application.TicketBulkResultPage{
		Items: []application.TicketBulkTargetResultRecord{{
			Sequence: 2, TargetID: target, TargetVersion: 9,
			Result: kernel.TicketBulkTargetVersionConflict, RecordedAt: recordedAt,
		}},
		Next: "opaque-next",
	})
	if err != nil {
		t.Fatalf("mapTicketBulkResultPage() error = %v", err)
	}
	if len(mapped.Items) != 1 || mapped.Items[0].Sequence != 2 || mapped.Items[0].TargetId != target ||
		mapped.Items[0].TargetVersion != 9 || mapped.Items[0].Result != "version_conflict" ||
		!mapped.Items[0].RecordedAt.Equal(recordedAt) || mapped.NextCursor == nil || *mapped.NextCursor != "opaque-next" {
		t.Fatalf("mapped page = %#v", mapped)
	}
	if _, err := mapTicketBulkResultPage(application.TicketBulkResultPage{Items: []application.TicketBulkTargetResultRecord{{
		Sequence: 1, TargetID: target, TargetVersion: 1, Result: 255, RecordedAt: recordedAt,
	}}}); err == nil {
		t.Fatal("unknown result code unexpectedly mapped")
	}
}

type ticketBulkMappingIDs struct {
	job, tenant, requester, owner, team, assignee, targetA, targetB, view uuid.UUID
}

func explicitTicketBulkRecord(t *testing.T) (application.TicketBulkRecord, ticketBulkMappingIDs) {
	t.Helper()
	IDs := ticketBulkMappingIDs{
		job: mustTransportUUIDv7(t), tenant: mustTransportUUIDv7(t), requester: mustTransportUUIDv7(t),
		owner: mustTransportUUIDv7(t), team: mustTransportUUIDv7(t), assignee: mustTransportUUIDv7(t),
		targetA: mustTransportUUIDv7(t), targetB: mustTransportUUIDv7(t),
	}
	selection, err := kernel.NewExplicitTicketBulkSelection([]kernel.TicketBulkTargetPin{
		mustTicketBulkTargetPin(t, IDs.targetA, 3), mustTicketBulkTargetPin(t, IDs.targetB, 5),
	})
	if err != nil {
		t.Fatal(err)
	}
	team, assignee := mustTicketBulkEntity(t, IDs.team), mustTicketBulkEntity(t, IDs.assignee)
	mutation, err := kernel.NewTicketBulkAssignment(team, &assignee)
	if err != nil {
		t.Fatal(err)
	}
	definition := mustTicketBulkDefinition(t, IDs, selection, mutation)
	now := time.Date(2026, 8, 26, 18, 0, 0, 123_456_000, time.UTC)
	plan, err := kernel.PlanTicketBulkCreation(definition, now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return application.TicketBulkRecord{Job: plan.Next()}, IDs
}

func queryTicketBulkRecord(t *testing.T) (application.TicketBulkRecord, ticketBulkMappingIDs, string, string) {
	t.Helper()
	IDs := ticketBulkMappingIDs{
		job: mustTransportUUIDv7(t), tenant: mustTransportUUIDv7(t), requester: mustTransportUUIDv7(t),
		owner: mustTransportUUIDv7(t), targetA: mustTransportUUIDv7(t), view: mustTransportUUIDv7(t),
	}
	tenant := mustTicketBulkEntity(t, IDs.tenant)
	filters, err := kernel.NewSavedViewFilters(kernel.SavedViewFiltersInput{Queue: kernel.SavedViewQueueAll})
	if err != nil {
		t.Fatal(err)
	}
	sortKey, _ := kernel.NewKey("updated_at")
	sortPlan, err := kernel.NewSavedViewCoreSort(sortKey, kernel.SavedViewSortDescending)
	if err != nil {
		t.Fatal(err)
	}
	columnKey, _ := kernel.NewKey("ticket")
	column, err := kernel.NewSavedViewCoreColumn(columnKey, 320, true, kernel.SavedViewColumnPinnedStart)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := kernel.NewSavedViewSpec(tenant, kernel.AggregateCase, filters, sortPlan, []kernel.SavedViewColumn{column})
	if err != nil {
		t.Fatal(err)
	}
	inline, err := application.NewTicketBulkQuerySnapshot(IDs.tenant, kernel.AggregateCase, application.TicketBulkQueryInline, spec, nil)
	if err != nil {
		t.Fatal(err)
	}
	pin, err := kernel.NewTicketBulkSavedViewPin(
		mustTicketBulkEntity(t, IDs.view), mustTicketBulkEntity(t, IDs.owner), 4, inline.QueryDigest(),
	)
	if err != nil {
		t.Fatal(err)
	}
	query, err := application.NewTicketBulkQuerySnapshot(IDs.tenant, kernel.AggregateCase, application.TicketBulkQuerySavedView, spec, &pin)
	if err != nil {
		t.Fatal(err)
	}
	targetDigest := [32]byte{1, 2, 3}
	selection, err := kernel.NewQueryTicketBulkSelection(query.QueryDigest(), targetDigest, 25, &pin)
	if err != nil {
		t.Fatal(err)
	}
	definition := mustTicketBulkDefinition(t, IDs, selection, kernel.NewTicketBulkRelease())
	now := time.Date(2026, 8, 26, 18, 0, 0, 654_321_000, time.UTC)
	plan, err := kernel.PlanTicketBulkCreation(definition, now, now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return application.TicketBulkRecord{Job: plan.Next(), Query: &query}, IDs,
		hexDigest(query.QueryDigest()), hexDigest(query.CatalogDigest())
}

func mustTicketBulkDefinition(t *testing.T, IDs ticketBulkMappingIDs, selection kernel.TicketBulkSelection, mutation kernel.TicketBulkMutation) kernel.TicketBulkDefinition {
	t.Helper()
	definition, err := kernel.NewTicketBulkDefinition(kernel.TicketBulkDefinitionInput{
		ID: mustTicketBulkEntity(t, IDs.job), Tenant: mustTicketBulkEntity(t, IDs.tenant),
		Requester: mustTicketBulkEntity(t, IDs.requester), OwnerMembership: mustTicketBulkEntity(t, IDs.owner),
		Kind: func() kernel.AggregateKind {
			if selection.Source() == kernel.TicketBulkSelectionQuery {
				return kernel.AggregateCase
			}
			return kernel.AggregateAlert
		}(),
		Selection: selection, Mutation: mutation, ProjectionVersion: kernel.TicketBulkProjectionVersion,
		MaximumAttempts: kernel.TicketBulkMaximumAttempts,
	})
	if err != nil {
		t.Fatal(err)
	}
	return definition
}

func mustTicketBulkTargetPin(t *testing.T, value uuid.UUID, version uint64) kernel.TicketBulkTargetPin {
	t.Helper()
	pin, err := kernel.NewTicketBulkTargetPin(mustTicketBulkEntity(t, value), version)
	if err != nil {
		t.Fatal(err)
	}
	return pin
}

func mustTicketBulkEntity(t *testing.T, value uuid.UUID) kernel.EntityID {
	t.Helper()
	entity, err := kernel.NewEntityID([16]byte(value))
	if err != nil {
		t.Fatal(err)
	}
	return entity
}
