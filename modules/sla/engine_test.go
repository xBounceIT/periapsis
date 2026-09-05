package sla

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestEnginePlansTimerTriggerCursorAndNextEvaluationDeterministically(t *testing.T) {
	definition := mustMetricDefinition(t, elapsedMetricInput())
	instance := startedMetricInstance(t, definition)
	trigger := mustTrigger(t, definition, TriggerDefinitionInput{
		ID: fixtureID(210), Key: mustKey("half_consumed"), MetricID: definition.ID(),
		Kind: TriggerConsumedPercent, ConsumedPercent: 50,
		Action: TriggerActionInput{Kind: ActionDomainEvent, Value: mustKey("sla.half_consumed")},
	})
	cursor, err := NewTriggerCursor(trigger.ID())
	if err != nil {
		t.Fatal(err)
	}
	at := instance.CreatedAt().Add(2 * time.Hour)
	plan, err := PlanEngine(EngineInput{
		ObservedAt: at,
		Metrics: []MetricWork{{
			Instance: instance,
			Triggers: []TriggerBinding{{Definition: trigger, Cursor: cursor}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	metrics := plan.Metrics()
	if len(metrics) != 1 || !metrics[0].Changed() || len(metrics[0].Occurrences()) != 1 ||
		metrics[0].TriggerCursors()[0].FireCount() != 1 {
		t.Fatalf("timer plan=%#v", plan)
	}
	occurrence := metrics[0].Occurrences()[0]
	if occurrence.ScheduledAt() != at || occurrence.Action().Kind() != ActionDomainEvent {
		t.Fatalf("occurrence=%#v", occurrence)
	}
	wantNext := instance.CreatedAt().Add(3 * time.Hour)
	if metrics[0].NextEvaluationAt() == nil || !metrics[0].NextEvaluationAt().Equal(wantNext) {
		t.Fatalf("next evaluation=%v want=%v", metrics[0].NextEvaluationAt(), wantNext)
	}

	replay, err := PlanEngine(EngineInput{
		ObservedAt: at,
		Metrics: []MetricWork{{
			Instance: metrics[0].Instance(),
			Triggers: []TriggerBinding{{Definition: trigger, Cursor: metrics[0].TriggerCursors()[0]}},
		}},
	})
	if err != nil || len(replay.Metrics()[0].Occurrences()) != 0 ||
		replay.Metrics()[0].TriggerCursors()[0].FireCount() != 1 {
		t.Fatalf("replayed timer plan=%#v error=%v", replay, err)
	}
	if occurrence.DeduplicationKey() != metrics[0].Occurrences()[0].DeduplicationKey() {
		t.Fatal("occurrence projection changed through getter")
	}
}

func TestEngineAppliesOrderedEventAndMaterializesDynamicColumns(t *testing.T) {
	definition := mustMetricDefinition(t, elapsedMetricInput())
	instance := mustMetricInstance(t, definition)
	column, err := NewColumnDefinition(definition, ColumnDefinitionInput{
		ID: fixtureID(220), TenantID: instance.TenantID(), Key: mustKey("first_response_remaining"),
		Label: "First response remaining", MetricID: definition.ID(), Calculation: ColumnRemaining,
		Format: FormatDuration, Sortable: true, Filterable: true, Position: 2, Version: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	event := metricEventForInstance(instance, 221, definition.StartEvent().String(), instance.CreatedAt())
	plan, err := PlanEngine(EngineInput{
		ObservedAt: event.OccurredAt, Event: &event,
		Metrics: []MetricWork{{Instance: instance, Columns: []ColumnDefinition{column}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	metric := plan.Metrics()[0]
	if !metric.Changed() || metric.PreviousVersion() != 1 || metric.Instance().Version() != 2 ||
		metric.Evaluation().State != StateOnTrack || len(metric.Columns()) != 1 {
		t.Fatalf("event plan=%#v", plan)
	}
	nextMinute := event.OccurredAt.Add(time.Minute)
	if metric.NextEvaluationAt() == nil || !metric.NextEvaluationAt().Equal(nextMinute) {
		t.Fatalf("dynamic column next evaluation=%v want=%v", metric.NextEvaluationAt(), nextMinute)
	}
	value := metric.Columns()[0]
	if value.Duration() == nil || *value.Duration() != definition.Duration() || value.NextRefreshAt() == nil {
		t.Fatalf("materialized column=%#v", value)
	}

	badEvent := event
	badEvent.OccurredAt = badEvent.OccurredAt.Add(time.Minute)
	if _, err := PlanEngine(EngineInput{ObservedAt: event.OccurredAt, Event: &badEvent, Metrics: []MetricWork{{Instance: instance}}}); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("mismatched observation error=%v", err)
	}
}

func TestEngineRejectsDuplicateAndCrossTenantRuntimeProjection(t *testing.T) {
	definition := mustMetricDefinition(t, elapsedMetricInput())
	instance := startedMetricInstance(t, definition)
	trigger := mustTrigger(t, definition, TriggerDefinitionInput{
		ID: fixtureID(230), Key: mustKey("due"), MetricID: definition.ID(), Kind: TriggerDue,
		Action: TriggerActionInput{Kind: ActionDomainEvent, Value: mustKey("sla.due")},
	})
	cursor, _ := NewTriggerCursor(trigger.ID())
	work := MetricWork{Instance: instance, Triggers: []TriggerBinding{{Definition: trigger, Cursor: cursor}}}
	if _, err := PlanEngine(EngineInput{ObservedAt: instance.UpdatedAt(), Metrics: []MetricWork{work, work}}); !errors.Is(err, ErrInvalidMetric) {
		t.Fatalf("duplicate metric error=%v", err)
	}

	foreignInput := MetricInstanceInput{
		ID: fixtureID(231), SLAInstanceID: fixtureID(232), TenantID: fixtureID(2),
		ObjectType: instance.ObjectType(), ObjectID: instance.ObjectID(),
		PolicyID: instance.PolicyID(), PolicyVersion: instance.PolicyVersion(), Definition: definition,
		CreatedAt: instance.CreatedAt(),
	}
	foreign, err := NewMetricInstance(foreignInput)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PlanEngine(EngineInput{ObservedAt: instance.UpdatedAt(), Metrics: []MetricWork{work, {Instance: foreign}}}); !errors.Is(err, ErrInvalidMetric) {
		t.Fatalf("cross-tenant metric error=%v", err)
	}

	event := metricEventForInstance(instance, 233, definition.StartEvent().String(), instance.UpdatedAt())
	input := EngineInput{ObservedAt: instance.UpdatedAt(), Event: &event, Metrics: []MetricWork{work}}
	for _, rendered := range []string{
		fmt.Sprint(work), fmt.Sprintf("%#v", mustEnginePlan(t, instance)), fmt.Sprintf("%+v", input),
		fmt.Sprintf("%#v", cursor), fmt.Sprintf("%+v", event),
	} {
		if strings.Contains(rendered, instance.ID().String()) || strings.Contains(rendered, instance.ObjectID().String()) ||
			strings.Contains(rendered, trigger.ID().String()) || strings.Contains(rendered, event.ID.String()) ||
			strings.Contains(rendered, event.Key.String()) {
			t.Fatalf("engine formatting leaked identity: %q", rendered)
		}
	}
}

func TestEngineResetStartsANewRepeatedBreachWindow(t *testing.T) {
	definition := mustMetricDefinition(t, elapsedMetricInput())
	instance := startedMetricInstance(t, definition)
	trigger := mustTrigger(t, definition, TriggerDefinitionInput{
		ID: fixtureID(235), Key: mustKey("repeat_after_reset"), MetricID: definition.ID(),
		Kind: TriggerRepeatedBreach, RepeatInterval: 30 * time.Minute,
		Action: TriggerActionInput{Kind: ActionDomainEvent, Value: mustKey("sla.repeat_after_reset")},
	})
	cursor, err := NewTriggerCursor(trigger.ID())
	if err != nil {
		t.Fatal(err)
	}
	firstObservation := instance.DueAt().Add(definition.BreachGrace() + 65*time.Minute)
	first, err := PlanEngine(EngineInput{
		ObservedAt: firstObservation,
		Metrics: []MetricWork{{
			Instance: instance, Triggers: []TriggerBinding{{Definition: trigger, Cursor: cursor}},
		}},
	})
	if err != nil || len(first.Metrics()[0].Occurrences()) != 1 {
		t.Fatalf("first repeated window plan=%#v error=%v", first, err)
	}

	firstMetric := first.Metrics()[0]
	resetAt := firstObservation.Add(time.Minute)
	reset := metricEventForInstance(firstMetric.Instance(), 236, definition.ResetEvent().String(), resetAt)
	resetPlan, err := PlanEngine(EngineInput{
		ObservedAt: resetAt, Event: &reset,
		Metrics: []MetricWork{{
			Instance: firstMetric.Instance(),
			Triggers: []TriggerBinding{{Definition: trigger, Cursor: firstMetric.TriggerCursors()[0]}},
		}},
	})
	if err != nil || len(resetPlan.Metrics()[0].Occurrences()) != 0 {
		t.Fatalf("reset plan=%#v error=%v", resetPlan, err)
	}

	resetMetric := resetPlan.Metrics()[0]
	secondBreach := resetAt.Add(definition.Duration() + definition.BreachGrace())
	second, err := PlanEngine(EngineInput{
		ObservedAt: secondBreach,
		Metrics: []MetricWork{{
			Instance: resetMetric.Instance(),
			Triggers: []TriggerBinding{{Definition: trigger, Cursor: resetMetric.TriggerCursors()[0]}},
		}},
	})
	if err != nil || len(second.Metrics()[0].Occurrences()) != 1 ||
		!second.Metrics()[0].Occurrences()[0].ScheduledAt().Equal(secondBreach) {
		t.Fatalf("second repeated window plan=%#v error=%v", second, err)
	}
}

func mustEnginePlan(t *testing.T, instance MetricInstance) EnginePlan {
	t.Helper()
	plan, err := PlanEngine(EngineInput{ObservedAt: instance.UpdatedAt(), Metrics: []MetricWork{{Instance: instance}}})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}
