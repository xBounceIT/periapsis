package sla

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"
)

func TestContextAwarePlannersRejectCanceledWorkBeforeValidation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := PlanEngineContext(ctx, EngineInput{}); !errors.Is(err, ErrEngineCanceled) {
		t.Fatalf("engine cancellation error=%v", err)
	}
	if _, err := PlanAssignmentContext(ctx, AssignmentInput{}); !errors.Is(err, ErrEngineCanceled) {
		t.Fatalf("assignment cancellation error=%v", err)
	}
	if _, err := PlanPolicyOverrideContext(ctx, PolicyOverrideInput{}); !errors.Is(err, ErrEngineCanceled) {
		t.Fatalf("policy override cancellation error=%v", err)
	}
	if _, err := SimulateContext(ctx, SimulationInput{}); !errors.Is(err, ErrEngineCanceled) {
		t.Fatalf("simulation cancellation error=%v", err)
	}
}

func TestPercentageThresholdsRoundUpToCanonicalMicrosecondsForEveryClock(t *testing.T) {
	if got := percentageDuration(time.Microsecond, 33); got != time.Microsecond {
		t.Fatalf("percentage duration=%s, want 1us", got)
	}
	for _, clock := range []ClockType{ClockElapsed, ClockBusiness} {
		t.Run(string(clock), func(t *testing.T) {
			input := elapsedMetricInput()
			input.ID = fixtureID(245)
			input.Duration = time.Microsecond
			input.BreachGrace = 0
			input.Warning = WarningThreshold{Kind: WarningConsumedPercent, ConsumedPercent: 33}
			input.Clock = clock
			var calendar *BusinessCalendar
			if clock == ClockBusiness {
				value := mustCalendar(t, allDayCalendarInput("UTC"))
				calendar = &value
				calendarID := value.ID()
				input.CalendarID, input.CalendarVersion = &calendarID, value.Version()
			}
			definition := mustMetricDefinition(t, input)
			createdAt := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
			instance, err := NewMetricInstance(MetricInstanceInput{
				ID: fixtureID(246), SLAInstanceID: fixtureID(247), TenantID: fixtureID(1), ObjectType: ObjectCase,
				ObjectID: fixtureID(248), PolicyID: fixtureID(249), PolicyVersion: 1,
				Definition: definition, CreatedAt: createdAt,
			})
			if err != nil {
				t.Fatal(err)
			}
			start := metricEventForInstance(instance, 250, definition.StartEvent().String(), createdAt)
			instance, changed, err := instance.ApplyEvent(instance.Version(), start, calendar)
			if err != nil || !changed {
				t.Fatalf("start changed=%t error=%v", changed, err)
			}
			trigger := mustTrigger(t, definition, TriggerDefinitionInput{
				ID: fixtureID(251), Key: mustKey("one_microsecond_threshold"), MetricID: definition.ID(),
				Kind: TriggerConsumedPercent, ConsumedPercent: 33,
				Action: TriggerActionInput{Kind: ActionDomainEvent, Value: mustKey("sla.one_microsecond_threshold")},
			})
			cursor, _ := NewTriggerCursor(trigger.ID())
			plan, err := PlanEngine(EngineInput{
				ObservedAt: createdAt,
				Metrics: []MetricWork{{
					Instance: instance, Calendar: calendar,
					Triggers: []TriggerBinding{{Definition: trigger, Cursor: cursor}},
				}},
			})
			want := createdAt.Add(time.Microsecond)
			if err != nil || len(plan.Metrics()) != 1 || plan.Metrics()[0].NextEvaluationAt() == nil ||
				!plan.Metrics()[0].NextEvaluationAt().Equal(want) {
				t.Fatalf("next evaluation=%v error=%v, want %s", plan.Metrics(), err, want)
			}
		})
	}
}

func TestRepeatedTriggerRejectsUnsupportedFirstEvaluationInstant(t *testing.T) {
	definition := mustMetricDefinition(t, elapsedMetricInput())
	instance := startedMetricInstance(t, definition)
	boundary := time.Date(9999, 12, 31, 23, 59, 59, 999999000, time.UTC)
	instance.breachThresholdAt = &boundary
	trigger := mustTrigger(t, definition, TriggerDefinitionInput{
		ID: fixtureID(252), Key: mustKey("range_repeat"), MetricID: definition.ID(),
		Kind: TriggerRepeatedBreach, Offset: time.Microsecond, RepeatInterval: time.Microsecond,
		Action: TriggerActionInput{Kind: ActionDomainEvent, Value: mustKey("sla.range_repeat")},
	})
	cursor, _ := NewTriggerCursor(trigger.ID())
	if _, err := nextTriggerEvaluation(
		context.Background(), instance, trigger, cursor, MetricEvaluation{}, instance.UpdatedAt(), nil,
	); !errors.Is(err, ErrCalendarRange) {
		t.Fatalf("unsupported repeated-trigger instant error=%v", err)
	}
}

func TestEngineCancellationInterruptsLongBusinessCalendarTraversal(t *testing.T) {
	calendar := mustCalendar(t, weekdayCalendarInput())
	input := elapsedMetricInput()
	input.Clock = ClockBusiness
	calendarID := calendar.ID()
	input.CalendarID, input.CalendarVersion = &calendarID, calendar.Version()
	input.Duration = 2 * time.Hour
	definition := mustMetricDefinition(t, input)
	createdAt := time.Date(2026, 1, 2, 8, 0, 0, 0, time.UTC)
	instance, err := NewMetricInstance(MetricInstanceInput{
		ID: fixtureID(192), SLAInstanceID: fixtureID(193), TenantID: fixtureID(1), ObjectType: ObjectCase,
		ObjectID: fixtureID(194), PolicyID: fixtureID(195), PolicyVersion: 1,
		Definition: definition, CreatedAt: createdAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	start := metricEventForInstance(instance, 196, definition.StartEvent().String(), createdAt)
	instance, changed, err := instance.ApplyEvent(instance.Version(), start, &calendar)
	if err != nil || !changed {
		t.Fatalf("start changed=%t error=%v", changed, err)
	}
	ctx := &cancelAfterChecks{remaining: 20}
	_, err = PlanEngineContext(ctx, EngineInput{
		ObservedAt: createdAt.Add(365 * 24 * time.Hour),
		Metrics:    []MetricWork{{Instance: instance, Calendar: &calendar}},
	})
	if !errors.Is(err, ErrEngineCanceled) {
		t.Fatalf("long business traversal cancellation error=%v", err)
	}
}

type cancelAfterChecks struct {
	remaining int
}

func (ctx *cancelAfterChecks) Deadline() (time.Time, bool) { return time.Time{}, false }
func (ctx *cancelAfterChecks) Done() <-chan struct{}       { return nil }
func (ctx *cancelAfterChecks) Value(any) any               { return nil }
func (ctx *cancelAfterChecks) Err() error {
	ctx.remaining--
	if ctx.remaining <= 0 {
		return context.Canceled
	}
	return nil
}

func TestBusinessCalendarRejectsConfigurationWithoutOpenTime(t *testing.T) {
	input := weekdayCalendarInput()
	input.WeeklySchedules = nil
	if _, err := NewBusinessCalendar(input); !errors.Is(err, ErrInvalidCalendar) {
		t.Fatalf("empty weekly schedule error = %v", err)
	}

	input = weekdayCalendarInput()
	for index := range input.WeeklySchedules {
		input.WeeklySchedules[index].Intervals = nil
	}
	if _, err := NewBusinessCalendar(input); !errors.Is(err, ErrInvalidCalendar) {
		t.Fatalf("all-closed weekly schedule error = %v", err)
	}
}

func TestRuleRejectsNonCanonicalSourceLiteralsForEveryValueOperator(t *testing.T) {
	tests := []*RuleInput{
		predicateRule(FactPath{Kind: FactSource}, PredicateEquals, "SLA-ENGINE"),
		predicateRule(FactPath{Kind: FactSource}, PredicateOneOf, "edr", "SLA-ENGINE"),
		predicateRule(FactPath{Kind: FactSource}, PredicateNoneOf, "edr", "SLA-ENGINE"),
	}
	for index, input := range tests {
		if _, err := NewRule(input); !errors.Is(err, ErrInvalidPolicy) {
			t.Fatalf("non-canonical source rule %d error = %v", index, err)
		}
	}
}

func TestPolicySelectionRejectsDuplicateIdentityInventory(t *testing.T) {
	snapshot := mustFactSnapshot(t, FactSnapshotInput{
		TenantID: fixtureID(1), ObjectType: ObjectAlert,
		EvaluatedAt: time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC), Timezone: "UTC",
	})
	first := mustPolicy(t, policyInput(180, "identity_one", 10, mustRule(t, &RuleInput{Kind: RuleAll})))

	duplicateIDInput := policyInput(180, "identity_two", 9, mustRule(t, &RuleInput{Kind: RuleAll}))
	duplicateID := mustPolicy(t, duplicateIDInput)
	if _, err := SelectPolicy([]Policy{first, duplicateID}, snapshot); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("duplicate policy id error = %v", err)
	}

	duplicateKeyInput := policyInput(181, "identity_one", 9, mustRule(t, &RuleInput{Kind: RuleAll}))
	duplicateKey := mustPolicy(t, duplicateKeyInput)
	if _, err := SelectPolicy([]Policy{first, duplicateKey}, snapshot); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("duplicate policy key error = %v", err)
	}
}

func TestPausedMetricPreservesRecordedBreachState(t *testing.T) {
	definition := mustMetricDefinition(t, elapsedMetricInput())
	instance := startedMetricInstance(t, definition)
	pauseAt := instance.DueAt().Add(definition.BreachGrace())
	pause := metricEventForInstance(instance, 182, definition.PauseEvent().String(), pauseAt)
	paused, changed, err := instance.ApplyEvent(instance.Version(), pause, nil)
	if err != nil || !changed || paused.BreachedAt() == nil {
		t.Fatalf("late pause changed=%t breachedAt=%v error=%v", changed, paused.BreachedAt(), err)
	}
	evaluation, err := paused.Evaluate(pauseAt.Add(24*time.Hour), nil)
	if err != nil || evaluation.State != StateBreached {
		t.Fatalf("paused breached evaluation = %#v, error=%v", evaluation, err)
	}
}

func TestCompletedMetricSuppressesFutureTimeAndThresholdTriggers(t *testing.T) {
	definition := mustMetricDefinition(t, elapsedMetricInput())
	instance := startedMetricInstance(t, definition)
	completeAt := instance.CreatedAt().Add(2 * time.Hour)
	complete := metricEventForInstance(instance, 183, definition.CompletionEvent().String(), completeAt)
	completed, changed, err := instance.ApplyEvent(instance.Version(), complete, nil)
	if err != nil || !changed {
		t.Fatalf("complete changed=%t error=%v", changed, err)
	}

	inputs := []TriggerDefinitionInput{
		{ID: fixtureID(184), Key: mustKey("completed_percent"), MetricID: definition.ID(), Kind: TriggerConsumedPercent, ConsumedPercent: 25, Action: TriggerActionInput{Kind: ActionDomainEvent, Value: mustKey("sla.percent")}},
		{ID: fixtureID(185), Key: mustKey("completed_remaining"), MetricID: definition.ID(), Kind: TriggerRemaining, Remaining: 3 * time.Hour, Action: TriggerActionInput{Kind: ActionDomainEvent, Value: mustKey("sla.remaining")}},
		{ID: fixtureID(186), Key: mustKey("completed_due"), MetricID: definition.ID(), Kind: TriggerDue, Action: TriggerActionInput{Kind: ActionDomainEvent, Value: mustKey("sla.due")}},
		{ID: fixtureID(187), Key: mustKey("completed_breach"), MetricID: definition.ID(), Kind: TriggerAfterBreach, Offset: time.Hour, Action: TriggerActionInput{Kind: ActionDomainEvent, Value: mustKey("sla.breach")}},
	}
	observedAt := instance.DueAt().Add(definition.BreachGrace() + 2*time.Hour)
	for index, input := range inputs {
		trigger := mustTrigger(t, definition, input)
		cursor, cursorErr := NewTriggerCursor(trigger.ID())
		if cursorErr != nil {
			t.Fatal(cursorErr)
		}
		_, occurrence, observeErr := ObserveTrigger(completed, trigger, cursor, observedAt, nil, false)
		if observeErr != nil || occurrence != nil {
			t.Fatalf("completed trigger %d occurrence=%#v error=%v", index, occurrence, observeErr)
		}
	}
}

func TestCompletionWinsOverBreachTriggerAtExactBoundary(t *testing.T) {
	definition := mustMetricDefinition(t, elapsedMetricInput())
	instance := startedMetricInstance(t, definition)
	breachAt := instance.DueAt().Add(definition.BreachGrace())
	completionAt := breachAt.Add(time.Hour)
	completion := metricEventForInstance(instance, 189, definition.CompletionEvent().String(), completionAt)
	completed, changed, err := instance.ApplyEvent(instance.Version(), completion, nil)
	if err != nil || !changed || completed.BreachedAt() == nil {
		t.Fatalf("completion changed=%t breached=%v error=%v", changed, completed.BreachedAt(), err)
	}

	for _, input := range []TriggerDefinitionInput{
		{
			ID: fixtureID(190), Key: mustKey("exact_after_breach"), MetricID: definition.ID(),
			Kind: TriggerAfterBreach, Offset: time.Hour,
			Action: TriggerActionInput{Kind: ActionDomainEvent, Value: mustKey("sla.exact_after_breach")},
		},
		{
			ID: fixtureID(191), Key: mustKey("exact_repeat_breach"), MetricID: definition.ID(),
			Kind: TriggerRepeatedBreach, Offset: time.Hour, RepeatInterval: 30 * time.Minute,
			Action: TriggerActionInput{Kind: ActionDomainEvent, Value: mustKey("sla.exact_repeat_breach")},
		},
	} {
		trigger := mustTrigger(t, definition, input)
		cursor, cursorErr := NewTriggerCursor(trigger.ID())
		if cursorErr != nil {
			t.Fatal(cursorErr)
		}
		_, occurrence, observeErr := ObserveTrigger(completed, trigger, cursor, completionAt, nil, false)
		if observeErr != nil || occurrence != nil {
			t.Fatalf("exact completion trigger=%s occurrence=%#v error=%v", input.Kind, occurrence, observeErr)
		}
	}
}

func TestColumnDefinitionRejectsNonFiniteStyleThresholds(t *testing.T) {
	definition := mustMetricDefinition(t, elapsedMetricInput())
	for name, threshold := range map[string]float64{"nan": math.NaN(), "positive infinity": math.Inf(1), "negative infinity": math.Inf(-1)} {
		t.Run(name, func(t *testing.T) {
			input := ColumnDefinitionInput{
				ID: fixtureID(188), TenantID: fixtureID(1), Key: mustKey("finite_threshold"), Label: "Finite threshold",
				MetricID: definition.ID(), Calculation: ColumnConsumedPercentage, Format: FormatPercentage, Version: 1,
				StyleRules: []ColumnStyleRuleInput{{StyleKey: mustKey("danger"), MinimumPercentage: &threshold}},
			}
			if _, err := NewColumnDefinition(definition, input); !errors.Is(err, ErrInvalidMetric) {
				t.Fatalf("non-finite threshold error = %v", err)
			}
		})
	}
}

func TestMetricVersionExhaustionFailsBeforeMutation(t *testing.T) {
	definition := mustMetricDefinition(t, elapsedMetricInput())
	pending := mustMetricInstance(t, definition)
	pendingSnapshot := pending.Snapshot()
	pendingSnapshot.Version = maximumVersion - 1
	pending, err := RestoreMetricInstance(pendingSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	start := metricEventForInstance(pending, 197, definition.StartEvent().String(), pending.CreatedAt().Add(time.Hour))
	if _, changed, applyErr := pending.ApplyEvent(pending.Version(), start, nil); !errors.Is(applyErr, ErrMetricConflict) || changed {
		t.Fatalf("version-exhausted event changed=%t error=%v", changed, applyErr)
	}

	running := startedMetricInstance(t, definition)
	runningSnapshot := running.Snapshot()
	runningSnapshot.Version = maximumVersion - 1
	running, err = RestoreMetricInstance(runningSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	observedAt := running.UpdatedAt().Add(time.Hour)
	if _, changed, observeErr := running.Observe(running.Version(), observedAt, nil); !errors.Is(observeErr, ErrMetricConflict) || changed {
		t.Fatalf("version-exhausted observation changed=%t error=%v", changed, observeErr)
	}
	command := validOverrideCommand(running, 198, OverrideExtend, observedAt)
	command.Extension = time.Hour
	if _, record, changed, overrideErr := running.ApplyOverride(
		running.Version(), command, overrideAuthorityFixture(command), nil, nil,
	); !errors.Is(overrideErr, ErrMetricConflict) || changed || record != nil {
		t.Fatalf("version-exhausted override changed=%t record=%#v error=%v", changed, record, overrideErr)
	}
}
