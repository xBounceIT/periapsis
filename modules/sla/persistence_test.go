package sla

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"
)

func TestMetricAndTriggerPersistenceRoundTripRejectMalformedProjection(t *testing.T) {
	definition := mustMetricDefinition(t, elapsedMetricInput())
	instance := startedMetricInstance(t, definition)
	pausedAt := instance.CreatedAt().Add(time.Hour)
	paused, changed, err := instance.ApplyEvent(
		instance.Version(), metricEventForInstance(instance, 200, definition.PauseEvent().String(), pausedAt), nil,
	)
	if err != nil || !changed {
		t.Fatalf("pause changed=%t error=%v", changed, err)
	}

	snapshot := paused.Snapshot()
	restored, err := RestoreMetricInstance(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Snapshot().Lifecycle != LifecyclePaused || restored.Version() != paused.Version() ||
		restored.PausedAt() == nil || !restored.PausedAt().Equal(pausedAt) {
		t.Fatalf("restored metric = %#v", restored)
	}
	snapshot.PausedAt = timePointer(pausedAt.Add(time.Hour))
	if restored.PausedAt().Equal(*snapshot.PausedAt) {
		t.Fatal("restored metric retained caller snapshot pointer")
	}

	malformed := paused.Snapshot()
	malformed.Lifecycle = LifecycleRunning
	if _, err := RestoreMetricInstance(malformed); !errors.Is(err, ErrInvalidMetric) {
		t.Fatalf("malformed lifecycle error=%v", err)
	}
	malformed = paused.Snapshot()
	malformed.LastOverrideDigest[0] = 1
	if _, err := RestoreMetricInstance(malformed); !errors.Is(err, ErrInvalidMetric) {
		t.Fatalf("orphan override digest error=%v", err)
	}

	trigger := mustTrigger(t, definition, TriggerDefinitionInput{
		ID: fixtureID(201), Key: mustKey("half_consumed"), MetricID: definition.ID(),
		Kind: TriggerConsumedPercent, ConsumedPercent: 50,
		Action: TriggerActionInput{Kind: ActionDomainEvent, Value: mustKey("sla.half_consumed")},
	})
	cursor, err := NewTriggerCursor(trigger.ID())
	if err != nil {
		t.Fatal(err)
	}
	cursor, occurrence, err := ObserveTrigger(
		instance, trigger, cursor, instance.CreatedAt().Add(2*time.Hour), nil, false,
	)
	if err != nil || occurrence == nil {
		t.Fatalf("observe occurrence=%#v error=%v", occurrence, err)
	}
	restoredCursor, err := RestoreTriggerCursor(cursor.Snapshot())
	if err != nil || restoredCursor.FireCount() != 1 || restoredCursor.LastFiredAt() == nil {
		t.Fatalf("restored cursor=%#v error=%v", restoredCursor, err)
	}
	badCursor := cursor.Snapshot()
	badCursor.LastPercentage = math.NaN()
	if _, err := RestoreTriggerCursor(badCursor); !errors.Is(err, ErrInvalidMetric) {
		t.Fatalf("NaN cursor error=%v", err)
	}
	badCursor = cursor.Snapshot()
	badCursor.LastRepeatWindow = 1
	badCursor.FireCount = 0
	badCursor.LastFiredAt = nil
	if _, err := RestoreTriggerCursor(badCursor); !errors.Is(err, ErrInvalidMetric) {
		t.Fatalf("repeat window without firing error=%v", err)
	}

	for _, rendered := range []string{fmt.Sprint(snapshot), fmt.Sprintf("%#v", cursor.Snapshot())} {
		if strings.Contains(rendered, instance.ID().String()) || strings.Contains(rendered, trigger.ID().String()) {
			t.Fatalf("persistence formatter leaked identity: %q", rendered)
		}
	}
}

func TestPersistenceInputProjectionsOwnCanonicalConfiguration(t *testing.T) {
	calendar := mustCalendar(t, allDayCalendarInput("Europe/Rome"))
	calendarInput := calendar.Input()
	calendarRoundTrip, err := NewBusinessCalendar(calendarInput)
	if err != nil || calendarRoundTrip.ID() != calendar.ID() || calendarRoundTrip.Version() != calendar.Version() {
		t.Fatalf("calendar round trip=%#v error=%v", calendarRoundTrip, err)
	}
	calendarInput.WeeklySchedules[0].Intervals[0].EndMinute = 1
	if !calendar.IsBusinessTime(time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)) {
		t.Fatal("calendar retained caller persistence input")
	}

	rule := mustRule(t, &RuleInput{Kind: RuleAll, Children: []*RuleInput{
		predicateRule(FactPath{Kind: FactSeverity}, PredicateEquals, "critical"),
	}})
	ruleInput := rule.Input()
	ruleRoundTrip, err := NewRule(ruleInput)
	if err != nil || ruleRoundTrip.nodeCount() != rule.nodeCount() {
		t.Fatalf("rule round trip=%#v error=%v", ruleRoundTrip, err)
	}
	ruleInput.Children[0].Predicate.Values[0] = "low"
	if rule.Input().Children[0].Predicate.Values[0] != "critical" {
		t.Fatal("rule retained caller persistence input")
	}

	policy := mustPolicy(t, policyInput(202, "persisted_policy", 40, rule))
	policyRoundTrip, err := NewPolicy(policy.Input())
	if err != nil || policyRoundTrip.ID() != policy.ID() || policyRoundTrip.Version() != policy.Version() {
		t.Fatalf("policy round trip=%#v error=%v", policyRoundTrip, err)
	}
	metric := policy.Metrics()[0]
	column, err := NewColumnDefinition(metric, ColumnDefinitionInput{
		ID: fixtureID(203), TenantID: policy.TenantID(), Key: mustKey("resolution_state"),
		Label: "Resolution state", MetricID: metric.ID(), Calculation: ColumnState,
		Format: FormatStateBadge, Sortable: true, Filterable: true, Version: 1,
		StyleRules: []ColumnStyleRuleInput{{StyleKey: mustKey("danger"), State: StateBreached}},
	})
	if err != nil {
		t.Fatal(err)
	}
	columnRoundTrip, err := NewColumnDefinition(metric, column.Input())
	if err != nil || columnRoundTrip.ID() != column.ID() || columnRoundTrip.Version() != column.Version() {
		t.Fatalf("column round trip=%#v error=%v", columnRoundTrip, err)
	}
}

func TestCreateTaskTriggerActionRoundTripsExactTextAndRejectsOtherShapes(t *testing.T) {
	definition := mustMetricDefinition(t, elapsedMetricInput())
	trigger := mustTrigger(t, definition, TriggerDefinitionInput{
		ID: fixtureID(204), Key: mustKey("create_follow_up"), MetricID: definition.ID(), Kind: TriggerDue,
		Action: TriggerActionInput{Kind: ActionCreateTask, Text: "Investigate the breached response target"},
	})

	roundTrip, err := NewTriggerDefinition(definition, trigger.Input())
	if err != nil || roundTrip.Action().Kind() != ActionCreateTask ||
		roundTrip.Action().Text() != "Investigate the breached response target" ||
		roundTrip.Action().ConfigurationID() != nil || roundTrip.Action().Value().String() != "" {
		t.Fatalf("create-task round trip=%#v error=%v", roundTrip, err)
	}

	invalid := []TriggerActionInput{
		{Kind: ActionCreateTask},
		{Kind: ActionCreateTask, Text: " leading whitespace"},
		{Kind: ActionCreateTask, Text: "line one\nline two"},
		{Kind: ActionCreateTask, Text: "task", ConfigurationID: idPointer(fixtureID(205))},
		{Kind: ActionCreateTask, Text: "task", Value: mustKey("unexpected")},
	}
	for index, action := range invalid {
		input := trigger.Input()
		input.Action = action
		if _, err := NewTriggerDefinition(definition, input); !errors.Is(err, ErrInvalidMetric) {
			t.Fatalf("invalid create-task action %d error=%v", index, err)
		}
	}
}

func timePointer(value time.Time) *time.Time { return &value }
