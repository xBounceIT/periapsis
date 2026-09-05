package sla

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestTriggerObservationFiresThresholdOnceWithStableDeduplication(t *testing.T) {
	definition := mustMetricDefinition(t, elapsedMetricInput())
	instance := startedMetricInstance(t, definition)
	trigger := mustTrigger(t, definition, TriggerDefinitionInput{
		ID: fixtureID(80), Key: mustKey("half_consumed"), MetricID: definition.ID(),
		Kind: TriggerConsumedPercent, ConsumedPercent: 50,
		Action: TriggerActionInput{Kind: ActionDomainEvent, Value: mustKey("sla.half_consumed")},
	})
	cursor, err := NewTriggerCursor(trigger.ID())
	if err != nil {
		t.Fatal(err)
	}
	start := *instance.StartedAt()
	cursor, occurrence, err := ObserveTrigger(instance, trigger, cursor, start.Add(time.Hour), nil, false)
	if err != nil || occurrence != nil || !cursor.Initialized() {
		t.Fatalf("first observation occurrence=%#v cursor=%#v error=%v", occurrence, cursor, err)
	}
	cursor, occurrence, err = ObserveTrigger(instance, trigger, cursor, start.Add(2*time.Hour), nil, false)
	if err != nil || occurrence == nil || cursor.FireCount() != 1 {
		t.Fatalf("crossing occurrence=%#v cursor=%#v error=%v", occurrence, cursor, err)
	}
	wantDedup := occurrence.DeduplicationKey()
	cursor, repeated, err := ObserveTrigger(instance, trigger, cursor, start.Add(3*time.Hour), nil, false)
	if err != nil || repeated != nil || cursor.FireCount() != 1 {
		t.Fatalf("post-crossing repeat=%#v cursor=%#v error=%v", repeated, cursor, err)
	}

	fresh, _ := NewTriggerCursor(trigger.ID())
	_, duplicate, err := ObserveTrigger(instance, trigger, fresh, start.Add(2*time.Hour), nil, false)
	if err != nil || duplicate == nil || duplicate.DeduplicationKey() != wantDedup {
		t.Fatalf("stable dedup occurrence=%#v error=%v", duplicate, err)
	}
	newAggregateSnapshot := instance.Snapshot()
	newAggregateSnapshot.ID = fixtureID(78)
	newAggregateSnapshot.SLAInstanceID = fixtureID(79)
	newAggregate, err := RestoreMetricInstance(newAggregateSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	fresh, _ = NewTriggerCursor(trigger.ID())
	_, newAggregateOccurrence, err := ObserveTrigger(newAggregate, trigger, fresh, start.Add(2*time.Hour), nil, false)
	if err != nil || newAggregateOccurrence == nil || newAggregateOccurrence.DeduplicationKey() == wantDedup {
		t.Fatalf("new aggregate dedup occurrence=%#v error=%v", newAggregateOccurrence, err)
	}
	revisionSnapshot := instance.Snapshot()
	revisionSnapshot.PolicyVersion++
	revision, err := RestoreMetricInstance(revisionSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	fresh, _ = NewTriggerCursor(trigger.ID())
	_, revisionOccurrence, err := ObserveTrigger(revision, trigger, fresh, start.Add(2*time.Hour), nil, false)
	if err != nil || revisionOccurrence == nil || revisionOccurrence.DeduplicationKey() == wantDedup {
		t.Fatalf("new policy revision dedup occurrence=%#v error=%v", revisionOccurrence, err)
	}
}

func TestDueAndRepeatedBreachTriggersRecoverWithoutStorm(t *testing.T) {
	definition := mustMetricDefinition(t, elapsedMetricInput())
	instance := startedMetricInstance(t, definition)
	dueTrigger := mustTrigger(t, definition, TriggerDefinitionInput{
		ID: fixtureID(81), Key: mustKey("due"), MetricID: definition.ID(), Kind: TriggerDue,
		Action: TriggerActionInput{Kind: ActionWebhook, ConfigurationID: idPointer(fixtureID(90))},
	})
	dueCursor, _ := NewTriggerCursor(dueTrigger.ID())
	due := *instance.DueAt()
	dueCursor, occurrence, err := ObserveTrigger(instance, dueTrigger, dueCursor, due.Add(-time.Microsecond), nil, false)
	if err != nil || occurrence != nil {
		t.Fatalf("pre-due occurrence=%#v error=%v", occurrence, err)
	}
	dueCursor, occurrence, err = ObserveTrigger(instance, dueTrigger, dueCursor, due, nil, false)
	if err != nil || occurrence == nil || !occurrence.ScheduledAt().Equal(due) {
		t.Fatalf("due occurrence=%#v error=%v", occurrence, err)
	}
	_, occurrence, err = ObserveTrigger(instance, dueTrigger, dueCursor, due.Add(time.Hour), nil, false)
	if err != nil || occurrence != nil {
		t.Fatalf("due fired twice: %#v error=%v", occurrence, err)
	}

	repeatedTrigger := mustTrigger(t, definition, TriggerDefinitionInput{
		ID: fixtureID(82), Key: mustKey("repeat_breach"), MetricID: definition.ID(),
		Kind: TriggerRepeatedBreach, RepeatInterval: 30 * time.Minute,
		Action: TriggerActionInput{Kind: ActionCreateSystemAlert, Value: mustKey("resolution_breach")},
	})
	repeatCursor, _ := NewTriggerCursor(repeatedTrigger.ID())
	breach := due.Add(definition.BreachGrace())
	recoveredAt := breach.Add(2*time.Hour + 5*time.Minute)
	repeatCursor, occurrence, err = ObserveTrigger(instance, repeatedTrigger, repeatCursor, recoveredAt, nil, false)
	if err != nil || occurrence == nil || !occurrence.ScheduledAt().Equal(breach.Add(2*time.Hour)) {
		t.Fatalf("recovery occurrence=%#v error=%v", occurrence, err)
	}
	if occurrence.Action().SystemAlertSource() != "sla-engine" || occurrence.Action().AllowRecursiveSLA() {
		t.Fatal("system Alert action did not force loop-safe source/default")
	}
	_, duplicate, err := ObserveTrigger(instance, repeatedTrigger, repeatCursor, recoveredAt.Add(20*time.Minute), nil, false)
	if err != nil || duplicate != nil {
		t.Fatalf("same repeat window fired twice: %#v error=%v", duplicate, err)
	}
	repeatCursor, next, err := ObserveTrigger(instance, repeatedTrigger, repeatCursor, recoveredAt.Add(30*time.Minute), nil, false)
	if err != nil || next == nil || repeatCursor.FireCount() != 2 {
		t.Fatalf("next repeat window occurrence=%#v cursor=%#v error=%v", next, repeatCursor, err)
	}
}

func TestResumeAndStateChangeTriggersUseExplicitObservation(t *testing.T) {
	definition := mustMetricDefinition(t, elapsedMetricInput())
	instance := startedMetricInstance(t, definition)
	resumeTrigger := mustTrigger(t, definition, TriggerDefinitionInput{
		ID: fixtureID(83), Key: mustKey("resumed"), MetricID: definition.ID(), Kind: TriggerResumed,
		Action: TriggerActionInput{Kind: ActionEmail, ConfigurationID: idPointer(fixtureID(91))},
	})
	cursor, _ := NewTriggerCursor(resumeTrigger.ID())
	at := instance.CreatedAt().Add(time.Hour)
	cursor, occurrence, err := ObserveTrigger(instance, resumeTrigger, cursor, at, nil, false)
	if err != nil || occurrence != nil {
		t.Fatalf("non-resume occurrence=%#v error=%v", occurrence, err)
	}
	_, occurrence, err = ObserveTrigger(instance, resumeTrigger, cursor, at.Add(time.Microsecond), nil, true)
	if err != nil || occurrence == nil {
		t.Fatalf("resume occurrence=%#v error=%v", occurrence, err)
	}

	stateTrigger := mustTrigger(t, definition, TriggerDefinitionInput{
		ID: fixtureID(84), Key: mustKey("at_risk"), MetricID: definition.ID(),
		Kind: TriggerStateChanged, TargetState: StateAtRisk,
		Action: TriggerActionInput{Kind: ActionAddTag, Value: mustKey("sla_at_risk")},
	})
	stateCursor, _ := NewTriggerCursor(stateTrigger.ID())
	start := *instance.StartedAt()
	stateCursor, occurrence, _ = ObserveTrigger(instance, stateTrigger, stateCursor, start.Add(2*time.Hour), nil, false)
	if occurrence != nil {
		t.Fatal("state trigger fired before transition")
	}
	_, occurrence, err = ObserveTrigger(instance, stateTrigger, stateCursor, start.Add(3*time.Hour), nil, false)
	if err != nil || occurrence == nil {
		t.Fatalf("state transition occurrence=%#v error=%v", occurrence, err)
	}
}

func TestTriggerDefinitionAndCursorFailClosed(t *testing.T) {
	definition := mustMetricDefinition(t, elapsedMetricInput())
	tests := []TriggerDefinitionInput{
		{ID: fixtureID(85), Key: mustKey("bad_percent"), MetricID: definition.ID(), Kind: TriggerConsumedPercent, ConsumedPercent: 0, Action: TriggerActionInput{Kind: ActionDomainEvent, Value: mustKey("event")}},
		{ID: fixtureID(86), Key: mustKey("bad_remaining"), MetricID: definition.ID(), Kind: TriggerRemaining, Remaining: definition.Duration(), Action: TriggerActionInput{Kind: ActionDomainEvent, Value: mustKey("event")}},
		{ID: fixtureID(87), Key: mustKey("bad_repeat"), MetricID: definition.ID(), Kind: TriggerRepeatedBreach, Action: TriggerActionInput{Kind: ActionDomainEvent, Value: mustKey("event")}},
		{ID: fixtureID(88), Key: mustKey("bad_action"), MetricID: definition.ID(), Kind: TriggerDue, Action: TriggerActionInput{Kind: ActionEmail, Value: mustKey("wrong_shape")}},
		{ID: fixtureID(89), Key: mustKey("bad_recursion"), MetricID: definition.ID(), Kind: TriggerDue, Action: TriggerActionInput{Kind: ActionWebhook, ConfigurationID: idPointer(fixtureID(90)), AllowRecursiveSLA: true}},
	}
	for index, input := range tests {
		if _, err := NewTriggerDefinition(definition, input); !errors.Is(err, ErrInvalidMetric) {
			t.Fatalf("invalid trigger %d error = %v", index, err)
		}
	}

	trigger := mustTrigger(t, definition, TriggerDefinitionInput{
		ID: fixtureID(90), Key: mustKey("due_valid"), MetricID: definition.ID(), Kind: TriggerDue,
		Action: TriggerActionInput{Kind: ActionDomainEvent, Value: mustKey("sla.due")},
	})
	instance := startedMetricInstance(t, definition)
	cursor, _ := NewTriggerCursor(trigger.ID())
	cursor, _, err := ObserveTrigger(instance, trigger, cursor, instance.CreatedAt().Add(time.Hour), nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ObserveTrigger(instance, trigger, cursor, instance.CreatedAt(), nil, false); !errors.Is(err, ErrInvalidMetric) {
		t.Fatalf("regressing cursor observation error = %v", err)
	}

	for _, rendered := range []string{fmt.Sprint(trigger), fmt.Sprintf("%#v", trigger)} {
		if strings.Contains(rendered, trigger.Key().String()) || strings.Contains(rendered, trigger.Action().Value().String()) {
			t.Fatalf("trigger formatting leaked configuration: %q", rendered)
		}
	}
}

func TestTriggerFireCountNeverProducesAnUnrestorableCursor(t *testing.T) {
	definition := mustMetricDefinition(t, elapsedMetricInput())
	instance := startedMetricInstance(t, definition)
	trigger := mustTrigger(t, definition, TriggerDefinitionInput{
		ID: fixtureID(91), Key: mustKey("bounded_repeat"), MetricID: definition.ID(),
		Kind: TriggerRepeatedBreach, RepeatInterval: 30 * time.Minute,
		Action: TriggerActionInput{Kind: ActionDomainEvent, Value: mustKey("sla.bounded_repeat")},
	})
	cursor, err := NewTriggerCursor(trigger.ID())
	if err != nil {
		t.Fatal(err)
	}
	breach := instance.DueAt().Add(definition.BreachGrace())
	cursor, occurrence, err := ObserveTrigger(instance, trigger, cursor, breach, nil, false)
	if err != nil || occurrence == nil {
		t.Fatalf("initial observation occurrence=%#v error=%v", occurrence, err)
	}
	snapshot := cursor.Snapshot()
	snapshot.FireCount = maximumVersion - 2
	cursor, err = RestoreTriggerCursor(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	cursor, occurrence, err = ObserveTrigger(instance, trigger, cursor, breach.Add(30*time.Minute), nil, false)
	if err != nil || occurrence == nil || cursor.FireCount() != maximumVersion-1 {
		t.Fatalf("last representable firing cursor=%#v occurrence=%#v error=%v", cursor, occurrence, err)
	}
	if _, err := RestoreTriggerCursor(cursor.Snapshot()); err != nil {
		t.Fatalf("last representable cursor did not round trip: %v", err)
	}
	if _, _, err := ObserveTrigger(
		instance, trigger, cursor, breach.Add(time.Hour), nil, false,
	); !errors.Is(err, ErrInvalidMetric) {
		t.Fatalf("unrepresentable firing error=%v", err)
	}
}

func startedMetricInstance(t *testing.T, definition MetricDefinition) MetricInstance {
	t.Helper()
	instance := mustMetricInstance(t, definition)
	event := metricEventForInstance(instance, 99, definition.StartEvent().String(), instance.CreatedAt())
	started, changed, err := instance.ApplyEvent(1, event, nil)
	if err != nil || !changed {
		t.Fatalf("start metric changed=%t error=%v", changed, err)
	}
	return started
}

func mustTrigger(t *testing.T, metric MetricDefinition, input TriggerDefinitionInput) TriggerDefinition {
	t.Helper()
	trigger, err := NewTriggerDefinition(metric, input)
	if err != nil {
		t.Fatal(err)
	}
	return trigger
}

func idPointer(value EntityID) *EntityID { return &value }
