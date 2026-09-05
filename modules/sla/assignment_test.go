package sla

import (
	"errors"
	"slices"
	"testing"
	"time"
)

func TestAssignmentSelectsPolicyAndDerivesReplayStableAggregate(t *testing.T) {
	createdAt := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	snapshot := mustFactSnapshot(t, FactSnapshotInput{
		TenantID: fixtureID(1), ObjectType: ObjectCase, EvaluatedAt: createdAt, Timezone: "UTC",
		Facts: []FactInput{{Path: FactPath{Kind: FactSeverity}, Values: []string{"critical"}}},
	})
	low := mustPolicy(t, policyInput(270, "default_assignment", 10, mustRule(t, &RuleInput{Kind: RuleAll})))
	highInput := policyInput(271, "critical_assignment", 20, mustRule(t,
		predicateRule(FactPath{Kind: FactSeverity}, PredicateEquals, "critical"),
	))
	metric := highInput.Metrics[0]
	trigger := mustTrigger(t, metric, TriggerDefinitionInput{
		ID: fixtureID(272), Key: mustKey("assignment_due"), MetricID: metric.ID(), Kind: TriggerDue,
		Action: TriggerActionInput{Kind: ActionDomainEvent, Value: mustKey("sla.assignment_due")},
	})
	highInput.Triggers = []TriggerDefinition{trigger}
	high := mustPolicy(t, highInput)
	column, err := NewColumnDefinition(metric, ColumnDefinitionInput{
		ID: fixtureID(273), TenantID: snapshot.TenantID(), Key: mustKey("assignment_remaining"),
		Label: "Assignment remaining", MetricID: metric.ID(), Calculation: ColumnRemaining,
		Format: FormatDuration, Sortable: true, Filterable: true, Version: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	input := AssignmentInput{
		Snapshot: snapshot, Policies: []Policy{low, high}, ObjectID: fixtureID(274),
		AssignmentEventID: fixtureID(275), CreatedAt: createdAt, Columns: []ColumnDefinition{column},
	}
	plan, err := PlanAssignment(input)
	if err != nil || !plan.Matched() || plan.Policy().ID() != high.ID() || !validEntityID(plan.SLAInstanceID()) {
		t.Fatalf("assignment=%#v error=%v", plan, err)
	}
	work := plan.Metrics()
	if len(work) != 1 || work[0].Instance.SLAInstanceID() != plan.SLAInstanceID() ||
		work[0].Instance.PolicyID() != high.ID() || len(work[0].Triggers) != 1 || len(work[0].Columns) != 1 {
		t.Fatalf("assignment work=%#v", work)
	}

	reversed := input
	reversed.Policies = slices.Clone(input.Policies)
	slices.Reverse(reversed.Policies)
	replay, err := PlanAssignment(reversed)
	if err != nil || replay.SLAInstanceID() != plan.SLAInstanceID() ||
		replay.Metrics()[0].Instance.ID() != work[0].Instance.ID() {
		t.Fatalf("replayed assignment=%#v error=%v", replay, err)
	}

	event := MetricEvent{
		ID: input.AssignmentEventID, TenantID: snapshot.TenantID(), ObjectID: input.ObjectID,
		Key: metric.StartEvent(), OccurredAt: createdAt,
	}
	engine, err := PlanEngine(EngineInput{ObservedAt: createdAt, Event: &event, Metrics: work})
	if err != nil || !engine.Metrics()[0].Changed() || engine.Metrics()[0].Instance().Version() != 2 {
		t.Fatalf("creation event plan=%#v error=%v", engine, err)
	}
}

func TestAssignmentPersistsExplicitNoMatchAndRejectsAmbiguousOrMalformedInventory(t *testing.T) {
	createdAt := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	snapshot := mustFactSnapshot(t, FactSnapshotInput{
		TenantID: fixtureID(1), ObjectType: ObjectCase, EvaluatedAt: createdAt, Timezone: "UTC",
	})
	disabledInput := policyInput(280, "disabled_assignment", 10, mustRule(t, &RuleInput{Kind: RuleAll}))
	disabledInput.Enabled = false
	disabled := mustPolicy(t, disabledInput)
	base := AssignmentInput{
		Snapshot: snapshot, Policies: []Policy{disabled}, ObjectID: fixtureID(281),
		AssignmentEventID: fixtureID(282), CreatedAt: createdAt,
	}
	plan, err := PlanAssignment(base)
	if err != nil || plan.Matched() || len(plan.Metrics()) != 0 || plan.SLAInstanceID() != (EntityID{}) {
		t.Fatalf("no-match assignment=%#v error=%v", plan, err)
	}

	left := mustPolicy(t, policyInput(283, "ambiguous_left", 20, mustRule(t, &RuleInput{Kind: RuleAll})))
	right := mustPolicy(t, policyInput(284, "ambiguous_right", 20, mustRule(t, &RuleInput{Kind: RuleAll})))
	ambiguous := base
	ambiguous.Policies = []Policy{left, right}
	if _, err := PlanAssignment(ambiguous); !errors.Is(err, ErrAmbiguousPolicy) {
		t.Fatalf("ambiguous assignment error=%v", err)
	}

	matched := base
	matched.Policies = []Policy{left}
	metric := left.Metrics()[0]
	foreignColumn, err := NewColumnDefinition(metric, ColumnDefinitionInput{
		ID: fixtureID(285), TenantID: fixtureID(2), Key: mustKey("foreign_remaining"),
		Label: "Foreign remaining", MetricID: metric.ID(), Calculation: ColumnRemaining,
		Format: FormatDuration, Version: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	matched.Columns = []ColumnDefinition{foreignColumn}
	if _, err := PlanAssignment(matched); !errors.Is(err, ErrInvalidMetric) {
		t.Fatalf("cross-tenant column error=%v", err)
	}
}

func TestEngineRejectsMetricsFromDifferentSLAAggregates(t *testing.T) {
	definition := mustMetricDefinition(t, elapsedMetricInput())
	left := mustMetricInstance(t, definition)
	input := left.Snapshot()
	input.ID = fixtureID(290)
	input.SLAInstanceID = fixtureID(291)
	right, err := RestoreMetricInstance(input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PlanEngine(EngineInput{
		ObservedAt: left.CreatedAt(), Metrics: []MetricWork{{Instance: left}, {Instance: right}},
	}); !errors.Is(err, ErrInvalidMetric) {
		t.Fatalf("mixed aggregate error=%v", err)
	}
}
