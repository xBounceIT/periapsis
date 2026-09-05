package sla

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestElapsedMetricPauseResumeWarningCompletionAndReplay(t *testing.T) {
	definition := mustMetricDefinition(t, elapsedMetricInput())
	instance := mustMetricInstance(t, definition)
	base := instance.CreatedAt()

	start := metricEvent(20, "ticket.created", base.Add(time.Hour))
	instance, changed, err := instance.ApplyEvent(1, start, nil)
	if err != nil || !changed || instance.Version() != 2 {
		t.Fatalf("start result changed=%t version=%d error=%v", changed, instance.Version(), err)
	}
	if got, want := *instance.DueAt(), start.OccurredAt.Add(4*time.Hour); !got.Equal(want) {
		t.Fatalf("initial due = %s, want %s", got, want)
	}

	evaluation, err := instance.Evaluate(start.OccurredAt.Add(2*time.Hour), nil)
	if err != nil || evaluation.State != StateOnTrack || evaluation.Remaining != 2*time.Hour ||
		evaluation.ConsumedPercentage != 50 {
		t.Fatalf("on-track evaluation = %#v, error=%v", evaluation, err)
	}
	evaluation, err = instance.Evaluate(start.OccurredAt.Add(3*time.Hour), nil)
	if err != nil || evaluation.State != StateAtRisk || evaluation.ConsumedPercentage != 75 {
		t.Fatalf("warning evaluation = %#v, error=%v", evaluation, err)
	}

	pause := metricEvent(21, "ticket.waiting_customer", start.OccurredAt.Add(3*time.Hour))
	instance, changed, err = instance.ApplyEvent(2, pause, nil)
	if err != nil || !changed || instance.Consumed() != 3*time.Hour {
		t.Fatalf("pause result changed=%t consumed=%s error=%v", changed, instance.Consumed(), err)
	}
	evaluation, err = instance.Evaluate(pause.OccurredAt.Add(48*time.Hour), nil)
	if err != nil || evaluation.State != StatePaused || evaluation.Remaining != time.Hour {
		t.Fatalf("paused evaluation = %#v, error=%v", evaluation, err)
	}

	resume := metricEvent(22, "ticket.customer_replied", pause.OccurredAt.Add(48*time.Hour))
	instance, changed, err = instance.ApplyEvent(3, resume, nil)
	if err != nil || !changed {
		t.Fatalf("resume result changed=%t error=%v", changed, err)
	}
	if got, want := *instance.DueAt(), resume.OccurredAt.Add(time.Hour); !got.Equal(want) {
		t.Fatalf("resumed due = %s, want %s", got, want)
	}

	complete := metricEvent(23, "ticket.resolved", *instance.DueAt())
	instance, changed, err = instance.ApplyEvent(4, complete, nil)
	if err != nil || !changed || instance.BreachedAt() != nil {
		t.Fatalf("on-deadline completion changed=%t breached=%v error=%v", changed, instance.BreachedAt(), err)
	}
	evaluation, err = instance.Evaluate(complete.OccurredAt.Add(24*time.Hour), nil)
	if err != nil || evaluation.State != StateCompleted || evaluation.Remaining != 0 {
		t.Fatalf("completed evaluation = %#v, error=%v", evaluation, err)
	}

	replayed, changed, err := instance.ApplyEvent(instance.Version(), complete, nil)
	if err != nil || changed || replayed.Version() != instance.Version() {
		t.Fatalf("terminal replay changed=%t version=%d error=%v", changed, replayed.Version(), err)
	}
}

func TestElapsedMetricBreachGraceAndCompletionPreserveBreach(t *testing.T) {
	instance := mustMetricInstance(t, mustMetricDefinition(t, elapsedMetricInput()))
	base := instance.CreatedAt()
	start := metricEvent(30, "ticket.created", base)
	var err error
	instance, _, err = instance.ApplyEvent(1, start, nil)
	if err != nil {
		t.Fatal(err)
	}
	due := *instance.DueAt()
	evaluation, err := instance.Evaluate(due.Add(15*time.Minute), nil)
	if err != nil || evaluation.State != StateAtRisk || evaluation.Remaining != 0 || evaluation.BreachedAt != nil {
		t.Fatalf("grace evaluation = %#v, error=%v", evaluation, err)
	}
	evaluation, err = instance.Evaluate(due.Add(30*time.Minute), nil)
	if err != nil || evaluation.State != StateBreached || evaluation.BreachedAt == nil {
		t.Fatalf("breach evaluation = %#v, error=%v", evaluation, err)
	}
	complete := metricEvent(31, "ticket.resolved", due.Add(31*time.Minute))
	instance, _, err = instance.ApplyEvent(2, complete, nil)
	if err != nil || instance.BreachedAt() == nil || !instance.BreachedAt().Equal(due.Add(30*time.Minute)) {
		t.Fatalf("late completion breachedAt=%v error=%v", instance.BreachedAt(), err)
	}
}

func TestBusinessMetricPinsCalendarAndExcludesClosedTime(t *testing.T) {
	calendar := mustCalendar(t, weekdayCalendarInput())
	input := elapsedMetricInput()
	input.Clock = ClockBusiness
	calendarID := calendar.ID()
	input.CalendarID = &calendarID
	input.CalendarVersion = calendar.Version()
	input.Duration = 2 * time.Hour
	definition := mustMetricDefinition(t, input)
	created := time.Date(2026, 8, 28, 14, 0, 0, 0, time.UTC) // Friday 16:00 CEST.
	instance, err := NewMetricInstance(MetricInstanceInput{
		ID: fixtureID(41), SLAInstanceID: fixtureID(40), TenantID: fixtureID(1), ObjectType: ObjectCase,
		ObjectID: fixtureID(42), PolicyID: fixtureID(43), PolicyVersion: 7,
		Definition: definition, CreatedAt: created,
	})
	if err != nil {
		t.Fatal(err)
	}
	event := MetricEvent{
		ID: fixtureID(44), TenantID: fixtureID(1), ObjectID: fixtureID(42),
		Key: mustKey("ticket.created"), OccurredAt: created,
	}
	instance, _, err = instance.ApplyEvent(1, event, &calendar)
	wantDue := time.Date(2026, 8, 31, 8, 0, 0, 0, time.UTC) // Monday 10:00 CEST.
	if err != nil || instance.DueAt() == nil || !instance.DueAt().Equal(wantDue) {
		t.Fatalf("business due=%v error=%v, want %s", instance.DueAt(), err, wantDue)
	}

	wrongCalendar := calendar
	wrongCalendar.version++
	if _, _, err := instance.ApplyEvent(instance.Version(), metricEventForInstance(instance, 45, "ticket.waiting_customer", created.Add(time.Hour)), &wrongCalendar); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("calendar-version drift error = %v", err)
	}
}

func TestMetricFailsClosedForStaleMalformedCrossTenantAndAliasedEvents(t *testing.T) {
	instance := mustMetricInstance(t, mustMetricDefinition(t, elapsedMetricInput()))
	bad := MetricEvent{}
	if _, _, err := instance.ApplyEvent(0, bad, nil); !errors.Is(err, ErrMetricConflict) {
		t.Fatalf("stale malformed error = %v, want conflict", err)
	}
	bad = metricEventForInstance(instance, 50, "ticket.created", instance.CreatedAt())
	bad.TenantID = fixtureID(2)
	if _, _, err := instance.ApplyEvent(1, bad, nil); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("cross-tenant event error = %v", err)
	}

	start := metricEventForInstance(instance, 51, "ticket.created", instance.CreatedAt())
	instance, _, _ = instance.ApplyEvent(1, start, nil)
	unknown := metricEventForInstance(instance, 52, "ticket.unrelated", instance.CreatedAt().Add(time.Hour))
	unchanged, changed, err := instance.ApplyEvent(2, unknown, nil)
	if err != nil || changed || unchanged.Version() != 2 || unchanged.Consumed() != 0 {
		t.Fatalf("unrelated event changed=%t instance=%#v error=%v", changed, unchanged, err)
	}
	aliased := start
	aliased.Key = mustKey("ticket.resolved")
	if _, _, err := instance.ApplyEvent(2, aliased, nil); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("event-id alias error = %v", err)
	}
}

func TestMetricDefinitionRejectsAmbiguousConfigurationAndOwnsPins(t *testing.T) {
	tests := []func(*MetricDefinitionInput){
		func(input *MetricDefinitionInput) { input.Duration = 0 },
		func(input *MetricDefinitionInput) { input.StartEvent = input.CompletionEvent },
		func(input *MetricDefinitionInput) { input.ResumeEvent = Key{} },
		func(input *MetricDefinitionInput) { input.ResetEvent = Key{} },
		func(input *MetricDefinitionInput) {
			input.Warning = WarningThreshold{Kind: WarningConsumedPercent, ConsumedPercent: 100}
		},
		func(input *MetricDefinitionInput) { input.Clock = ClockBusiness },
		func(input *MetricDefinitionInput) { input.DisplayFormat = "private\u202E" },
	}
	for index, mutate := range tests {
		input := elapsedMetricInput()
		mutate(&input)
		if _, err := NewMetricDefinition(input); !errors.Is(err, ErrInvalidMetric) {
			t.Fatalf("invalid configuration %d error = %v", index, err)
		}
	}

	calendarID := fixtureID(70)
	input := elapsedMetricInput()
	input.Clock, input.CalendarID, input.CalendarVersion = ClockBusiness, &calendarID, 3
	definition := mustMetricDefinition(t, input)
	calendarID = fixtureID(71)
	if definition.CalendarID() == nil || *definition.CalendarID() != fixtureID(70) {
		t.Fatal("metric retained caller-owned calendar pin")
	}
	for _, rendered := range []string{fmt.Sprint(definition), fmt.Sprintf("%#v", definition)} {
		if strings.Contains(rendered, definition.Key().String()) || strings.Contains(rendered, definition.Label()) {
			t.Fatalf("metric definition formatting leaked configuration: %q", rendered)
		}
	}
}

func TestTimerObservationCheckpointsConsumptionAndBreachWithoutDomainEvent(t *testing.T) {
	definition := mustMetricDefinition(t, elapsedMetricInput())
	instance := startedMetricInstance(t, definition)
	at := instance.CreatedAt().Add(5 * time.Hour)
	observed, changed, err := instance.Observe(instance.Version(), at, nil)
	if err != nil || !changed {
		t.Fatalf("observe changed=%t error=%v", changed, err)
	}
	if observed.Version() != instance.Version()+1 || observed.Consumed() != 5*time.Hour ||
		observed.BreachedAt() == nil || !observed.BreachedAt().Equal(instance.CreatedAt().Add(4*time.Hour+30*time.Minute)) {
		t.Fatalf("observed metric=%#v", observed)
	}
	replayed, changed, err := observed.Observe(observed.Version(), at, nil)
	if err != nil || changed || replayed.Version() != observed.Version() {
		t.Fatalf("same-boundary observe changed=%t metric=%#v error=%v", changed, replayed, err)
	}
	if _, _, err := instance.Observe(instance.Version()+1, at, nil); !errors.Is(err, ErrMetricConflict) {
		t.Fatalf("stale observe error=%v", err)
	}
}

func elapsedMetricInput() MetricDefinitionInput {
	return MetricDefinitionInput{
		ID: fixtureID(30), Key: mustKey("first_response"), Label: "First response",
		Description: "Time to first operator response", Duration: 4 * time.Hour, Clock: ClockElapsed,
		StartEvent: mustKey("ticket.created"), PauseEvent: mustKey("ticket.waiting_customer"),
		ResumeEvent: mustKey("ticket.customer_replied"), CompletionEvent: mustKey("ticket.resolved"),
		ResetEvent: mustKey("ticket.reopened"), ResetPolicy: ResetRestart,
		Warning:     WarningThreshold{Kind: WarningConsumedPercent, ConsumedPercent: 75},
		BreachGrace: 30 * time.Minute, DisplayFormat: "duration", CustomerVisible: true, APIVisible: true,
	}
}

func mustMetricDefinition(t *testing.T, input MetricDefinitionInput) MetricDefinition {
	t.Helper()
	definition, err := NewMetricDefinition(input)
	if err != nil {
		t.Fatal(err)
	}
	return definition
}

func mustMetricInstance(t *testing.T, definition MetricDefinition) MetricInstance {
	t.Helper()
	instance, err := NewMetricInstance(MetricInstanceInput{
		ID: fixtureID(31), SLAInstanceID: fixtureID(34), TenantID: fixtureID(1), ObjectType: ObjectCase,
		ObjectID: fixtureID(32), PolicyID: fixtureID(33), PolicyVersion: 7,
		Definition: definition, CreatedAt: time.Date(2026, 8, 25, 8, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	return instance
}

func metricEvent(sequence uint16, key string, at time.Time) MetricEvent {
	return MetricEvent{ID: fixtureID(sequence), TenantID: fixtureID(1), ObjectID: fixtureID(32), Key: mustKey(key), OccurredAt: at}
}

func metricEventForInstance(instance MetricInstance, sequence uint16, key string, at time.Time) MetricEvent {
	return MetricEvent{ID: fixtureID(sequence), TenantID: instance.TenantID(), ObjectID: instance.ObjectID(), Key: mustKey(key), OccurredAt: at}
}
