package ticketing

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
)

func TestRuntimeActivityKindsRemainOperatorOnly(t *testing.T) {
	fixture := newServiceFixture(t)
	for _, kind := range []string{"custom_field.imported", "sla.action.executed", "dfir.ioc.created", "dfir.ioc.replaced", "dfir.ioc.linked", "dfir.ioc.unlinked", "dfir.asset.created", "dfir.asset.replaced", "dfir.asset.linked", "dfir.asset.unlinked", "dfir.attachment.prepared", "dfir.timeline.created", "evidence.added", "evidence.custody_appended", "task.created", "task.transitioned", "task.assigned", "task.rescheduled", "task.checklist_replaced", "relationship.created", "relationship.retracted"} {
		activity := Activity{ID: mustUUIDv7(t), TenantID: fixture.tenantUUID, ResourceID: fixture.ticketUUID, ResourceKind: kernel.AggregateAlert, Kind: kind, Summary: "Runtime action", ActorKind: ActivityActorSystem, DisplayName: "System", Origin: "operator", OccurredAt: fixture.record.CreatedAt, Details: map[string]any{"contentRedacted": true}}
		if !validActivity(activity, View{Record: fixture.record, Projection: ProjectionOperator}, fixture.tenantUUID, kernel.AggregateAlert) {
			t.Fatalf("operator runtime activity rejected: %s", kind)
		}
		activity.ActorKind = ActivityActorRedacted
		activity.ActorID = uuid.Nil
		activity.Details = nil
		if validActivity(activity, View{Record: fixture.record, Projection: ProjectionCustomer}, fixture.tenantUUID, kernel.AggregateAlert) {
			t.Fatalf("runtime activity exposed to customer: %s", kind)
		}
	}
}

func TestActivityDetailsKeepValueAndSizeBounds(t *testing.T) {
	metadata := map[string]any{"occurrenceId": "synthetic", "contentRedacted": true}
	if !validActivityDetails(metadata) || validCustomFields(metadata) {
		t.Fatal("runtime metadata and custom-field key grammars were conflated")
	}
	for _, invalid := range []map[string]any{
		{"nested": map[string]any{"private": "value"}},
		{"bad key": true},
		{"value": strings.Repeat("x", 10_001)},
	} {
		if validActivityDetails(invalid) {
			t.Fatal("unbounded activity detail accepted")
		}
	}
	tooMany := make(map[string]any)
	for index := range 26 {
		tooMany[string(rune('a'+index))] = true
	}
	if validActivityDetails(tooMany) {
		t.Fatal("oversized activity inventory accepted")
	}
}
