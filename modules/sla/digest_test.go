package sla

import (
	"testing"
	"time"
)

func TestRevisionDigestsAreCanonicalOwnedAndPayloadSensitive(t *testing.T) {
	calendar := mustCalendar(t, allDayCalendarInput("UTC"))
	calendarAgain := mustCalendar(t, calendar.Input())
	if calendar.Digest() == ([32]byte{}) || calendar.Digest() != calendarAgain.Digest() {
		t.Fatal("calendar digest is empty or nondeterministic")
	}
	calendarInput := calendar.Input()
	calendarInput.Version++
	changedCalendar := mustCalendar(t, calendarInput)
	if changedCalendar.Digest() == calendar.Digest() {
		t.Fatal("calendar version was not digest-bound")
	}

	rule := mustRule(t, &RuleInput{Kind: RuleAll, Children: []*RuleInput{
		predicateRule(FactPath{Kind: FactSeverity}, PredicateEquals, "critical"),
	}})
	policy := mustPolicy(t, policyInput(240, "digest_policy", 10, rule))
	policyAgain := mustPolicy(t, policy.Input())
	if policy.Digest() == ([32]byte{}) || policy.Digest() != policyAgain.Digest() {
		t.Fatal("policy digest is empty or nondeterministic")
	}
	changedInput := policy.Input()
	changedInput.Priority++
	changedPolicy := mustPolicy(t, changedInput)
	if changedPolicy.Digest() == policy.Digest() {
		t.Fatal("policy priority was not digest-bound")
	}

	metric := policy.Metrics()[0]
	column, err := NewColumnDefinition(metric, ColumnDefinitionInput{
		ID: fixtureID(241), TenantID: policy.TenantID(), Key: mustKey("digest_column"), Label: "Digest column",
		MetricID: metric.ID(), Calculation: ColumnConsumedPercentage, Format: FormatPercentage,
		Version: 1, StyleRules: []ColumnStyleRuleInput{{
			StyleKey: mustKey("warning"), MinimumPercentage: floatPointer(75),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	columnInput := column.Input()
	columnInput.Position++
	changedColumn, err := NewColumnDefinition(metric, columnInput)
	if err != nil {
		t.Fatal(err)
	}
	if column.Digest() == ([32]byte{}) || column.Digest() == changedColumn.Digest() {
		t.Fatal("column digest did not bind position")
	}
}

func TestSimulationDigestBindsProjectedEventHistory(t *testing.T) {
	policy := mustPolicy(t, policyInput(250, "simulation_digest", 10, mustRule(t, &RuleInput{Kind: RuleAll})))
	createdAt := time.Date(2026, 8, 25, 8, 0, 0, 0, time.UTC)
	snapshot := mustFactSnapshot(t, FactSnapshotInput{
		TenantID: policy.TenantID(), ObjectType: ObjectCase, EvaluatedAt: createdAt, Timezone: "UTC",
	})
	metric := policy.Metrics()[0]
	base := SimulationInput{
		Snapshot: snapshot, Policy: policy, SLAInstanceID: fixtureID(253),
		ObjectID: fixtureID(251), CreatedAt: createdAt,
		EvaluateAt:     createdAt.Add(time.Hour),
		MetricBindings: []SimulationMetricBinding{{MetricID: metric.ID(), InstanceID: fixtureID(252)}},
	}
	withoutEvent, err := Simulate(base)
	if err != nil {
		t.Fatal(err)
	}
	base.Events = []MetricEvent{{
		ID: fixtureID(253), TenantID: policy.TenantID(), ObjectID: base.ObjectID,
		Key: metric.StartEvent(), OccurredAt: createdAt,
	}}
	withEvent, err := Simulate(base)
	if err != nil {
		t.Fatal(err)
	}
	digest := withEvent.Digest()
	if withoutEvent.Digest() == ([32]byte{}) || digest == withoutEvent.Digest() ||
		digest != withEvent.Digest() {
		t.Fatal("simulation digest was empty, unstable, or ignored event history")
	}
}

func floatPointer(value float64) *float64 { return &value }
