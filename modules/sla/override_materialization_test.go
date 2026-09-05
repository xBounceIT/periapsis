package sla

import (
	"testing"
	"time"
)

func TestOverrideMaterializationAtomicallyRefreshesTriggersColumnsAndSchedule(t *testing.T) {
	definition := mustMetricDefinition(t, elapsedMetricInput())
	instance := startedMetricInstance(t, definition)
	start := *instance.StartedAt()
	pauseAt := start.Add(time.Hour)
	pause := metricEventForInstance(instance, 240, definition.PauseEvent().String(), pauseAt)
	paused, changed, err := instance.ApplyEvent(instance.Version(), pause, nil)
	if err != nil || !changed {
		t.Fatalf("pause changed=%t error=%v", changed, err)
	}
	resumeTrigger := mustTrigger(t, definition, TriggerDefinitionInput{
		ID: fixtureID(241), Key: mustKey("override_resumed"), MetricID: definition.ID(), Kind: TriggerResumed,
		Action: TriggerActionInput{Kind: ActionDomainEvent, Value: mustKey("sla.override_resumed")},
	})
	stateTrigger := mustTrigger(t, definition, TriggerDefinitionInput{
		ID: fixtureID(242), Key: mustKey("override_on_track"), MetricID: definition.ID(), Kind: TriggerStateChanged,
		TargetState: StateOnTrack,
		Action:      TriggerActionInput{Kind: ActionDomainEvent, Value: mustKey("sla.override_on_track")},
	})
	resumeCursor, _ := NewTriggerCursor(resumeTrigger.ID())
	stateCursor, _ := NewTriggerCursor(stateTrigger.ID())
	resumeCursor, occurrence, err := ObserveTrigger(paused, resumeTrigger, resumeCursor, pauseAt, nil, false)
	if err != nil || occurrence != nil {
		t.Fatalf("resume cursor initialization occurrence=%#v error=%v", occurrence, err)
	}
	stateCursor, occurrence, err = ObserveTrigger(paused, stateTrigger, stateCursor, pauseAt, nil, false)
	if err != nil || occurrence != nil {
		t.Fatalf("state cursor initialization occurrence=%#v error=%v", occurrence, err)
	}
	column, err := NewColumnDefinition(definition, ColumnDefinitionInput{
		ID: fixtureID(243), TenantID: fixtureID(1), Key: mustKey("override_due"), Label: "Override due",
		MetricID: definition.ID(), Calculation: ColumnDueAt, Format: FormatDateTime, Version: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	resumeAt := start.Add(2 * time.Hour)
	command := validOverrideCommand(paused, 244, OverrideResume, resumeAt)
	resumed, record, changed, err := paused.ApplyOverride(
		paused.Version(), command, overrideAuthorityFixture(command), nil, nil,
	)
	if err != nil || !changed || record == nil {
		t.Fatalf("resume changed=%t record=%#v error=%v", changed, record, err)
	}
	plan, err := PlanOverrideMaterialization(OverrideMaterializationInput{
		Work: MetricWork{
			Instance: resumed,
			Triggers: []TriggerBinding{
				{Definition: resumeTrigger, Cursor: resumeCursor},
				{Definition: stateTrigger, Cursor: stateCursor},
			},
			Columns: []ColumnDefinition{column},
		},
		Record: *record,
	})
	metrics := plan.Metrics()
	if err != nil || len(metrics) != 1 || metrics[0].Changed() ||
		metrics[0].PreviousVersion() != resumed.Version() || len(metrics[0].Occurrences()) != 2 ||
		len(metrics[0].Columns()) != 1 || metrics[0].NextEvaluationAt() == nil {
		t.Fatalf("override materialization=%#v error=%v", plan, err)
	}
	if instant := metrics[0].Columns()[0].Instant(); instant == nil || resumed.DueAt() == nil || !instant.Equal(*resumed.DueAt()) {
		t.Fatalf("materialized due=%v, metric due=%v", instant, resumed.DueAt())
	}
	kinds := map[EntityID]bool{}
	for _, item := range metrics[0].Occurrences() {
		kinds[item.TriggerID()] = true
	}
	if !kinds[resumeTrigger.ID()] || !kinds[stateTrigger.ID()] {
		t.Fatalf("override occurrences=%#v", metrics[0].Occurrences())
	}
}
