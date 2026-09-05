package sla

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"
)

func TestObjectEventPlannerProjectsImmutableConfigurationToSelectedPolicy(t *testing.T) {
	event, state, required, extra, selectedColumn, extraColumn := objectEventInventoryFixture(t)
	for _, test := range []struct {
		name        string
		policies    []Policy
		calendars   []BusinessCalendar
		columns     []ColumnDefinition
		matched     bool
		business    bool
		columnCount int
	}{
		{name: "no policy with unused calendar", calendars: []BusinessCalendar{extra}},
		{name: "no policy with unrelated column", columns: []ColumnDefinition{extraColumn}},
		{name: "elapsed policy with unused calendar", policies: []Policy{state.Policies[1]}, calendars: []BusinessCalendar{extra}, matched: true},
		{name: "elapsed policy with unrelated column", policies: []Policy{state.Policies[1]}, columns: []ColumnDefinition{extraColumn}, matched: true},
		{name: "business policy with required and unused calendar", policies: state.Policies, calendars: []BusinessCalendar{extra, required}, matched: true, business: true},
		{name: "business policy with selected and unrelated column", policies: state.Policies, calendars: []BusinessCalendar{required}, columns: []ColumnDefinition{extraColumn, selectedColumn}, matched: true, business: true, columnCount: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := state
			input.Policies, input.Calendars, input.Columns = test.policies, test.calendars, test.columns
			plan, err := PlanObjectEvent(event, input)
			if err != nil || plan.Assignment() == nil || plan.Assignment().Matched() != test.matched {
				t.Fatalf("configuration projection matched=%t plan=%#v error=%v", test.matched, plan, err)
			}
			if !test.matched {
				if plan.Engine() != nil || plan.NextAggregateVersion() != 0 {
					t.Fatal("no-policy configuration produced an engine mutation")
				}
				return
			}
			work := plan.Assignment().Metrics()
			if len(work) != 1 || len(work[0].Columns) != test.columnCount ||
				(work[0].Calendar != nil) != test.business {
				t.Fatalf("wrong selected inventory: %#v", work)
			}
			if test.business && (work[0].Calendar.ID() != required.ID() || work[0].Calendar.Digest() != required.Digest()) {
				t.Fatal("assignment did not retain the exact required calendar")
			}
			if test.columnCount == 1 && work[0].Columns[0].Digest() != selectedColumn.Digest() {
				t.Fatal("assignment did not retain the exact selected column")
			}
			slices.Reverse(input.Calendars)
			slices.Reverse(input.Columns)
			replay, replayErr := PlanObjectEvent(event, input)
			if replayErr != nil || replay.Assignment().SLAInstanceID() != plan.Assignment().SLAInstanceID() {
				t.Fatalf("inventory order changed assignment identity: %v", replayErr)
			}
		})
	}
}

func TestObjectEventPlannerRejectsMalformedOrCrossTenantConfigurationBeforeProjection(t *testing.T) {
	event, state, required, extra, selectedColumn, extraColumn := objectEventInventoryFixture(t)
	foreignInput := extra.Input()
	foreignInput.TenantID = fixtureID(2)
	foreignCalendar := mustCalendar(t, foreignInput)
	wrongVersionInput := required.Input()
	wrongVersionInput.Version++
	wrongVersion := mustCalendar(t, wrongVersionInput)
	foreignColumn := extraColumn
	foreignColumn.tenantID = fixtureID(2)
	duplicateKeyColumn := extraColumn
	duplicateKeyColumn.key = selectedColumn.key
	for _, test := range []struct {
		name      string
		calendars []BusinessCalendar
		columns   []ColumnDefinition
		want      error
	}{
		{name: "missing required calendar", calendars: []BusinessCalendar{extra}, want: ErrInvalidCalendar},
		{name: "wrong required version", calendars: []BusinessCalendar{wrongVersion, extra}, want: ErrInvalidCalendar},
		{name: "duplicate required calendar", calendars: []BusinessCalendar{required, required}, want: ErrInvalidCalendar},
		{name: "duplicate unused calendar", calendars: []BusinessCalendar{required, extra, extra}, want: ErrInvalidCalendar},
		{name: "foreign unused calendar", calendars: []BusinessCalendar{required, foreignCalendar}, want: ErrInvalidCalendar},
		{name: "invalid unused calendar", calendars: []BusinessCalendar{required, {}}, want: ErrInvalidCalendar},
		{name: "foreign unused column", calendars: []BusinessCalendar{required}, columns: []ColumnDefinition{foreignColumn}, want: ErrInvalidMetric},
		{name: "duplicate selected column", calendars: []BusinessCalendar{required}, columns: []ColumnDefinition{selectedColumn, selectedColumn}, want: ErrInvalidMetric},
		{name: "duplicate unused column", calendars: []BusinessCalendar{required}, columns: []ColumnDefinition{extraColumn, extraColumn}, want: ErrInvalidMetric},
		{name: "duplicate column key across policies", calendars: []BusinessCalendar{required}, columns: []ColumnDefinition{selectedColumn, duplicateKeyColumn}, want: ErrInvalidMetric},
		{name: "invalid unused column", calendars: []BusinessCalendar{required}, columns: []ColumnDefinition{{}}, want: ErrInvalidMetric},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := state
			input.Calendars, input.Columns = test.calendars, test.columns
			if _, err := PlanObjectEvent(event, input); !errors.Is(err, test.want) {
				t.Fatalf("configuration error=%v, want %v", err, test.want)
			}
		})
	}
	state.Calendars = []BusinessCalendar{required, extra}
	state.Policies = append(state.Policies, state.Policies[0])
	if _, err := PlanObjectEvent(event, state); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("duplicate policy error=%v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := PlanObjectEventContext(ctx, event, state); !errors.Is(err, ErrEngineCanceled) {
		t.Fatalf("canceled configuration error=%v", err)
	}
}

func objectEventInventoryFixture(t *testing.T) (MetricEvent, ObjectEventState, BusinessCalendar, BusinessCalendar, ColumnDefinition, ColumnDefinition) {
	t.Helper()
	createdAt := time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)
	snapshot := mustFactSnapshot(t, FactSnapshotInput{TenantID: fixtureID(1), ObjectType: ObjectCase, EvaluatedAt: createdAt, Timezone: "UTC"})
	required := mustCalendar(t, allDayCalendarInput("UTC"))
	extraInput := allDayCalendarInput("UTC")
	extraInput.ID, extraInput.Key = fixtureID(520), mustKey("unused_calendar")
	extra := mustCalendar(t, extraInput)
	metricInput := elapsedMetricInput()
	metricInput.Clock, metricInput.CalendarID, metricInput.CalendarVersion = ClockBusiness, &required.id, required.Version()
	business := mustMetricDefinition(t, metricInput)
	selectedInput := policyInput(521, "selected_event_policy", 20, mustRule(t, &RuleInput{Kind: RuleAll}))
	selectedInput.Metrics = []MetricDefinition{business}
	selected := mustPolicy(t, selectedInput)
	elapsedInput := policyInput(522, "elapsed_event_policy", 10, mustRule(t, &RuleInput{Kind: RuleAll}))
	elapsed := mustPolicy(t, elapsedInput)
	extraMetricInput := elapsedMetricInput()
	extraMetricInput.ID = fixtureID(523)
	extraMetric := mustMetricDefinition(t, extraMetricInput)
	column := func(metric MetricDefinition, id uint16, key string) ColumnDefinition {
		value, err := NewColumnDefinition(metric, ColumnDefinitionInput{
			ID: fixtureID(id), TenantID: snapshot.TenantID(), Key: mustKey(key), Label: "Event inventory column",
			MetricID: metric.ID(), Calculation: ColumnDueAt, Format: FormatDateTime, Version: 1,
		})
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	event := MetricEvent{ID: fixtureID(524), TenantID: snapshot.TenantID(), ObjectID: fixtureID(525), Key: business.StartEvent(), OccurredAt: createdAt}
	state := ObjectEventState{Mode: ObjectEventStateUnassigned, Snapshot: &snapshot, Policies: []Policy{selected, elapsed}}
	return event, state, required, extra, column(business, 526, "selected_column"), column(extraMetric, 527, "unrelated_column")
}

func TestObjectEventPlannerSharesAssignmentAndExistingAggregateSemantics(t *testing.T) {
	createdAt := time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)
	snapshot := mustFactSnapshot(t, FactSnapshotInput{
		TenantID: fixtureID(1), ObjectType: ObjectCase, EvaluatedAt: createdAt, Timezone: "UTC",
	})
	policy := mustPolicy(t, policyInput(500, "object_event", 10, mustRule(t, &RuleInput{Kind: RuleAll})))
	event := MetricEvent{
		ID: fixtureID(501), TenantID: snapshot.TenantID(), ObjectID: fixtureID(502),
		Key: policy.Metrics()[0].StartEvent(), OccurredAt: createdAt,
	}
	assigned, err := PlanObjectEvent(event, ObjectEventState{
		Mode: ObjectEventStateUnassigned, Snapshot: &snapshot, Policies: []Policy{policy},
	})
	if err != nil || assigned.Assignment() == nil || !assigned.Assignment().Matched() ||
		assigned.Engine() == nil || assigned.ExpectedAggregateVersion() != 0 ||
		assigned.NextAggregateVersion() != 1 {
		t.Fatalf("assignment plan = %#v, error = %v", assigned, err)
	}

	nextAt := createdAt.Add(time.Minute)
	nextEvent := MetricEvent{
		ID: fixtureID(503), TenantID: event.TenantID, ObjectID: event.ObjectID,
		Key: mustKey("ticket.unrelated"), OccurredAt: nextAt,
	}
	work := assigned.Assignment().Metrics()
	for index := range work {
		work[index].Instance = assigned.Engine().Metrics()[index].Instance()
	}
	updated, err := PlanObjectEvent(nextEvent, ObjectEventState{
		Mode: ObjectEventStateExisting, AggregateVersion: 1, Metrics: work,
	})
	if err != nil || updated.Assignment() != nil || updated.Engine() == nil ||
		updated.ExpectedAggregateVersion() != 1 || updated.NextAggregateVersion() != 2 {
		t.Fatalf("existing plan = %#v, error = %v", updated, err)
	}
}

func TestObjectEventPlannerPersistsNoPolicyAndFailsClosedOnMixedState(t *testing.T) {
	createdAt := time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)
	snapshot := mustFactSnapshot(t, FactSnapshotInput{
		TenantID: fixtureID(1), ObjectType: ObjectAlert, EvaluatedAt: createdAt, Timezone: "UTC",
	})
	disabledInput := policyInput(510, "disabled_object_event", 10, mustRule(t, &RuleInput{Kind: RuleAll}))
	disabledInput.Enabled = false
	event := MetricEvent{
		ID: fixtureID(511), TenantID: snapshot.TenantID(), ObjectID: fixtureID(512),
		Key: mustKey("ticket.created"), OccurredAt: createdAt,
	}
	plan, err := PlanObjectEvent(event, ObjectEventState{
		Mode: ObjectEventStateUnassigned, Snapshot: &snapshot,
		Policies: []Policy{mustPolicy(t, disabledInput)},
	})
	if err != nil || plan.Assignment() == nil || plan.Assignment().Matched() ||
		plan.Engine() != nil || plan.NextAggregateVersion() != 0 {
		t.Fatalf("no-policy plan = %#v, error = %v", plan, err)
	}
	if _, err := PlanObjectEvent(event, ObjectEventState{
		Mode: ObjectEventStateExisting, AggregateVersion: 1, Snapshot: &snapshot,
	}); !errors.Is(err, ErrInvalidMetric) {
		t.Fatalf("mixed existing state error = %v", err)
	}

	subsequent := event
	subsequent.ID = fixtureID(513)
	subsequent.Key = mustKey("ticket.triaged")
	subsequent.OccurredAt = createdAt.Add(time.Minute)
	pinned, err := PlanObjectEvent(subsequent, ObjectEventState{Mode: ObjectEventStateNoPolicy})
	if err != nil || !pinned.PinnedNoPolicy() || pinned.Assignment() != nil ||
		pinned.Engine() != nil || pinned.ExpectedAggregateVersion() != 0 ||
		pinned.NextAggregateVersion() != 0 {
		t.Fatalf("pinned no-policy plan = %#v, error = %v", pinned, err)
	}
	if _, err := PlanObjectEvent(MetricEvent{}, ObjectEventState{Mode: ObjectEventStateNoPolicy}); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("invalid pinned no-policy event error = %v", err)
	}
}
