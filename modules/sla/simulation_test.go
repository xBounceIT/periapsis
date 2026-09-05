package sla

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestSimulationUsesLiveEngineAndProjectsDeadlinesAndTriggers(t *testing.T) {
	rule := mustRule(t, &RuleInput{Kind: RuleAll})
	input := policyInput(150, "simulation_policy", 10, rule)
	metric := input.Metrics[0]
	percent := mustTrigger(t, metric, TriggerDefinitionInput{
		ID: fixtureID(151), Key: mustKey("half"), MetricID: metric.ID(),
		Kind: TriggerConsumedPercent, ConsumedPercent: 50,
		Action: TriggerActionInput{Kind: ActionDomainEvent, Value: mustKey("sla.half")},
	})
	due := mustTrigger(t, metric, TriggerDefinitionInput{
		ID: fixtureID(152), Key: mustKey("due"), MetricID: metric.ID(), Kind: TriggerDue,
		Action: TriggerActionInput{Kind: ActionWebhook, ConfigurationID: idPointer(fixtureID(153))},
	})
	state := mustTrigger(t, metric, TriggerDefinitionInput{
		ID: fixtureID(154), Key: mustKey("completed"), MetricID: metric.ID(),
		Kind: TriggerStateChanged, TargetState: StateCompleted,
		Action: TriggerActionInput{Kind: ActionDomainEvent, Value: mustKey("sla.completed")},
	})
	input.Triggers = []TriggerDefinition{due, state, percent}
	policy := mustPolicy(t, input)
	created := input.EffectiveFrom.Add(time.Hour)
	objectID := fixtureID(155)
	snapshot := mustFactSnapshot(t, FactSnapshotInput{
		TenantID: fixtureID(1), ObjectType: ObjectAlert, EvaluatedAt: created,
		Timezone: "UTC", Facts: []FactInput{{Path: FactPath{Kind: FactSource}, Values: []string{"edr"}}},
	})
	result, err := Simulate(SimulationInput{
		Snapshot: snapshot, Policy: policy, SLAInstanceID: fixtureID(157), ObjectID: objectID,
		CreatedAt: created, EvaluateAt: created.Add(time.Hour),
		MetricBindings: []SimulationMetricBinding{{MetricID: metric.ID(), InstanceID: fixtureID(156)}},
		Events: []MetricEvent{{
			ID: fixtureID(157), TenantID: fixtureID(1), ObjectID: objectID,
			Key: metric.StartEvent(), OccurredAt: created,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	metrics := result.Metrics()
	if result.PolicyID() != policy.ID() || result.PolicyVersion() != policy.Version() || len(metrics) != 1 {
		t.Fatalf("simulation result=%#v", result)
	}
	if metrics[0].Evaluation().Remaining != 3*time.Hour || metrics[0].Evaluation().State != StateOnTrack {
		t.Fatalf("simulation evaluation=%#v", metrics[0].Evaluation())
	}
	projected := metrics[0].Triggers()
	if len(projected) != 3 {
		t.Fatalf("projected triggers=%#v", projected)
	}
	byID := make(map[EntityID]ProjectedTrigger, len(projected))
	for _, trigger := range projected {
		byID[trigger.TriggerID()] = trigger
	}
	if got := byID[percent.ID()].ScheduledAt(); got == nil || !got.Equal(created.Add(2*time.Hour)) {
		t.Fatalf("percent schedule=%v", got)
	}
	if got := byID[due.ID()].ScheduledAt(); got == nil || !got.Equal(created.Add(4*time.Hour)) {
		t.Fatalf("due schedule=%v", got)
	}
	if !byID[state.ID()].EventDriven() || byID[state.ID()].ScheduledAt() != nil {
		t.Fatal("state trigger was not represented as event-driven")
	}
	completed, err := Simulate(SimulationInput{
		Snapshot: snapshot, Policy: policy, SLAInstanceID: fixtureID(158), ObjectID: objectID,
		CreatedAt: created, EvaluateAt: created.Add(2 * time.Hour),
		MetricBindings: []SimulationMetricBinding{{MetricID: metric.ID(), InstanceID: fixtureID(159)}},
		Events: []MetricEvent{
			{ID: fixtureID(160), TenantID: fixtureID(1), ObjectID: objectID, Key: metric.StartEvent(), OccurredAt: created},
			{ID: fixtureID(161), TenantID: fixtureID(1), ObjectID: objectID, Key: metric.CompletionEvent(), OccurredAt: created.Add(time.Hour)},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, trigger := range completed.Metrics()[0].Triggers() {
		if trigger.TriggerID() != state.ID() && trigger.ScheduledAt() != nil {
			t.Fatalf("completed simulation retained time trigger schedule: %#v", trigger)
		}
	}

	projected[0].scheduledAt = nil
	if metrics[0].Triggers()[0].ScheduledAt() == nil && !metrics[0].Triggers()[0].EventDriven() {
		t.Fatal("simulation trigger getter leaked mutable storage")
	}
	for _, rendered := range []string{fmt.Sprint(result), fmt.Sprintf("%#v", result)} {
		if strings.Contains(rendered, policy.Key().String()) || strings.Contains(rendered, objectID.String()) {
			t.Fatalf("simulation formatting leaked identity/configuration: %q", rendered)
		}
	}
}

func TestSimulationFailsClosedForPolicyMismatchDuplicateEventsAndMissingCalendar(t *testing.T) {
	policy := mustPolicy(t, policyInput(160, "simulation_fail_closed", 10, mustRule(t, &RuleInput{Kind: RuleAll})))
	metric := policy.Metrics()[0]
	created := policy.EffectiveFrom().Add(time.Hour)
	objectID := fixtureID(161)
	snapshot := mustFactSnapshot(t, FactSnapshotInput{
		TenantID: fixtureID(1), ObjectType: ObjectAlert, EvaluatedAt: created, Timezone: "UTC",
	})
	base := SimulationInput{
		Snapshot: snapshot, Policy: policy, SLAInstanceID: fixtureID(163), ObjectID: objectID,
		CreatedAt: created, EvaluateAt: created.Add(time.Hour),
		MetricBindings: []SimulationMetricBinding{{MetricID: metric.ID(), InstanceID: fixtureID(162)}},
	}
	event := MetricEvent{
		ID: fixtureID(163), TenantID: fixtureID(1), ObjectID: objectID,
		Key: metric.StartEvent(), OccurredAt: created,
	}
	base.Events = []MetricEvent{event, event}
	if _, err := Simulate(base); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("duplicate simulation event error=%v", err)
	}

	base.Events = []MetricEvent{event}
	base.MetricBindings[0].MetricID = fixtureID(199)
	if _, err := Simulate(base); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("unknown metric binding error=%v", err)
	}

	calendar := mustCalendar(t, weekdayCalendarInput())
	businessInput := elapsedMetricInput()
	businessInput.Clock = ClockBusiness
	calendarID := calendar.ID()
	businessInput.CalendarID, businessInput.CalendarVersion = &calendarID, calendar.Version()
	business := mustMetricDefinition(t, businessInput)
	policyInput := policyInput(164, "business_simulation", 10, mustRule(t, &RuleInput{Kind: RuleAll}))
	policyInput.Metrics = []MetricDefinition{business}
	businessPolicy := mustPolicy(t, policyInput)
	base.Policy = businessPolicy
	base.MetricBindings = []SimulationMetricBinding{{MetricID: business.ID(), InstanceID: fixtureID(165)}}
	base.Events = nil
	if _, err := Simulate(base); !errors.Is(err, ErrInvalidCalendar) {
		t.Fatalf("missing pinned calendar error=%v", err)
	}

	base.Policy = policy
	base.MetricBindings = []SimulationMetricBinding{{MetricID: metric.ID(), InstanceID: fixtureID(166)}}
	base.Calendars = []BusinessCalendar{calendar}
	if _, err := Simulate(base); !errors.Is(err, ErrInvalidCalendar) {
		t.Fatalf("unreferenced calendar projection error=%v", err)
	}
}
