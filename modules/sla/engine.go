package sla

import (
	"context"
	"fmt"
	"math"
	"slices"
	"time"
)

const (
	maximumEngineMetrics  = 32
	maximumEngineBindings = 256
)

// TriggerBinding couples an immutable trigger definition to its durable
// observation cursor. Repositories must persist the returned cursor in the
// same transaction as occurrences and materialized metric state.
type TriggerBinding struct {
	Definition TriggerDefinition
	Cursor     TriggerCursor
}

func (binding TriggerBinding) String() string {
	return fmt.Sprintf("sla.TriggerBinding{definition:%s,cursor:%s}", binding.Definition.Kind(), binding.Cursor)
}
func (binding TriggerBinding) GoString() string { return binding.String() }

// MetricWork is the complete version-pinned input for one metric evaluation.
// Calendar is nil only for elapsed-time metrics.
type MetricWork struct {
	Instance MetricInstance
	Calendar *BusinessCalendar
	Triggers []TriggerBinding
	Columns  []ColumnDefinition
}

func (work MetricWork) String() string {
	return fmt.Sprintf(
		"sla.MetricWork{clock:%s,triggers:%d,columns:%d,identity:[REDACTED],values:[REDACTED]}",
		work.Instance.Definition().Clock(), len(work.Triggers), len(work.Columns),
	)
}
func (work MetricWork) GoString() string { return work.String() }

// EngineInput drives either an object-domain event or a timer observation.
// Event must be nil for a timer observation and, when present, must occur at
// ObservedAt. This keeps event order and materialization time unambiguous.
type EngineInput struct {
	ObservedAt time.Time
	Event      *MetricEvent
	Metrics    []MetricWork
}

func (input EngineInput) String() string {
	return fmt.Sprintf(
		"sla.EngineInput{observedAt:%s,event:%t,metrics:%d,identity:[REDACTED],values:[REDACTED]}",
		input.ObservedAt.Format(time.RFC3339), input.Event != nil, len(input.Metrics),
	)
}
func (input EngineInput) GoString() string { return input.String() }

type MetricPlan struct {
	previousVersion uint64
	instance        MetricInstance
	changed         bool
	evaluation      MetricEvaluation
	cursors         []TriggerCursor
	occurrences     []TriggerOccurrence
	columns         []MaterializedColumnValue
	nextEvaluation  *time.Time
}

func (plan MetricPlan) PreviousVersion() uint64          { return plan.previousVersion }
func (plan MetricPlan) Instance() MetricInstance         { return plan.instance.clone() }
func (plan MetricPlan) Changed() bool                    { return plan.changed }
func (plan MetricPlan) Evaluation() MetricEvaluation     { return cloneEvaluation(plan.evaluation) }
func (plan MetricPlan) NextEvaluationAt() *time.Time     { return cloneTime(plan.nextEvaluation) }
func (plan MetricPlan) TriggerCursors() []TriggerCursor  { return cloneTriggerCursors(plan.cursors) }
func (plan MetricPlan) Occurrences() []TriggerOccurrence { return cloneOccurrences(plan.occurrences) }
func (plan MetricPlan) Columns() []MaterializedColumnValue {
	result := make([]MaterializedColumnValue, len(plan.columns))
	for index, value := range plan.columns {
		result[index] = value.clone()
	}
	return result
}
func (plan MetricPlan) String() string {
	return fmt.Sprintf(
		"sla.MetricPlan{previousVersion:%d,nextVersion:%d,changed:%t,occurrences:%d,identity:[REDACTED],values:[REDACTED]}",
		plan.previousVersion, plan.instance.version, plan.changed, len(plan.occurrences),
	)
}
func (plan MetricPlan) GoString() string { return plan.String() }

type EnginePlan struct {
	observedAt time.Time
	eventID    *EntityID
	metrics    []MetricPlan
}

func (plan EnginePlan) ObservedAt() time.Time { return plan.observedAt }
func (plan EnginePlan) EventID() *EntityID    { return cloneEntityID(plan.eventID) }
func (plan EnginePlan) Metrics() []MetricPlan {
	result := make([]MetricPlan, len(plan.metrics))
	for index, metric := range plan.metrics {
		result[index] = metric.clone()
	}
	return result
}
func (plan EnginePlan) String() string {
	return fmt.Sprintf(
		"sla.EnginePlan{observedAt:%s,metrics:%d,event:[REDACTED],values:[REDACTED]}",
		plan.observedAt.Format(time.RFC3339), len(plan.metrics),
	)
}
func (plan EnginePlan) GoString() string { return plan.String() }

// PlanEngine evaluates every metric against one ordered event or timer tick.
// It is pure: persistence, occurrence emission, and acknowledgement remain a
// single transaction owned by the caller. All returned collections are
// canonicalized so database query order cannot affect the result.
func PlanEngine(input EngineInput) (EnginePlan, error) {
	return PlanEngineContext(context.Background(), input)
}

// PlanEngineContext is PlanEngine with cooperative cancellation between
// bounded metric evaluations. It is intended for transaction and worker
// orchestration; callers that only need the pure kernel may use PlanEngine.
func PlanEngineContext(ctx context.Context, input EngineInput) (EnginePlan, error) {
	if ctx == nil || ctx.Err() != nil {
		return EnginePlan{}, ErrEngineCanceled
	}
	if !validInstant(input.ObservedAt) || len(input.Metrics) == 0 || len(input.Metrics) > maximumEngineMetrics {
		return EnginePlan{}, ErrInvalidMetric
	}
	if input.Event != nil && (!validEntityID(input.Event.ID) || !input.Event.OccurredAt.Equal(input.ObservedAt)) {
		return EnginePlan{}, ErrInvalidEvent
	}

	plan := EnginePlan{observedAt: input.ObservedAt}
	if input.Event != nil {
		plan.eventID = cloneEntityID(&input.Event.ID)
	}
	seenInstances := make(map[EntityID]struct{}, len(input.Metrics))
	seenMetrics := make(map[EntityID]struct{}, len(input.Metrics))
	seenTriggers := make(map[EntityID]struct{})
	seenColumns := make(map[EntityID]struct{})
	var tenantID, objectID, slaInstanceID, policyID EntityID
	var objectType ObjectType
	var policyVersion uint64

	for index, work := range input.Metrics {
		if ctx.Err() != nil {
			return EnginePlan{}, ErrEngineCanceled
		}
		instance := work.Instance
		if !instance.valid() || len(work.Triggers) > maximumEngineBindings || len(work.Columns) > maximumEngineBindings {
			return EnginePlan{}, ErrInvalidMetric
		}
		if index == 0 {
			tenantID, objectID, objectType = instance.tenantID, instance.objectID, instance.objectType
			slaInstanceID, policyID, policyVersion = instance.slaInstanceID, instance.policyID, instance.policyVersion
		} else if instance.tenantID != tenantID || instance.objectID != objectID || instance.objectType != objectType ||
			instance.slaInstanceID != slaInstanceID || instance.policyID != policyID || instance.policyVersion != policyVersion {
			return EnginePlan{}, ErrInvalidMetric
		}
		if _, duplicate := seenInstances[instance.id]; duplicate {
			return EnginePlan{}, ErrInvalidMetric
		}
		if _, duplicate := seenMetrics[instance.definition.id]; duplicate {
			return EnginePlan{}, ErrInvalidMetric
		}
		seenInstances[instance.id] = struct{}{}
		seenMetrics[instance.definition.id] = struct{}{}
		if input.Event != nil && (input.Event.TenantID != tenantID || input.Event.ObjectID != objectID) {
			return EnginePlan{}, ErrInvalidEvent
		}

		metricPlan, err := planMetric(ctx, work, input.ObservedAt, input.Event, metricPlanMode{}, seenTriggers, seenColumns)
		if err != nil {
			return EnginePlan{}, err
		}
		plan.metrics = append(plan.metrics, metricPlan)
	}
	slices.SortFunc(plan.metrics, func(left, right MetricPlan) int {
		return compareEntityID(left.instance.definition.id, right.instance.definition.id)
	})
	return plan, nil
}

func planMetric(
	ctx context.Context,
	work MetricWork,
	observedAt time.Time,
	event *MetricEvent,
	mode metricPlanMode,
	seenTriggers map[EntityID]struct{},
	seenColumns map[EntityID]struct{},
) (MetricPlan, error) {
	instance := work.Instance
	calendar := cloneCalendarPointer(work.Calendar)
	if work.Calendar != nil && calendar == nil {
		return MetricPlan{}, ErrInvalidCalendar
	}
	updated, changed := instance.clone(), false
	var err error
	if mode.materializeOnly {
		if event != nil || !instance.matchesCalendar(calendar) || !instance.updatedAt.Equal(observedAt) ||
			mode.resumed && instance.lifecycle != lifecycleRunning {
			return MetricPlan{}, ErrInvalidOverride
		}
	} else if event != nil {
		updated, changed, err = instance.ApplyEventContext(ctx, instance.version, *event, calendar)
	} else {
		updated, changed, err = instance.observeContext(ctx, instance.version, observedAt, calendar)
	}
	if err != nil {
		return MetricPlan{}, err
	}
	evaluation, err := updated.EvaluateContext(ctx, observedAt, calendar)
	if err != nil {
		return MetricPlan{}, err
	}
	resumed := mode.resumed || event != nil && changed && validKey(updated.definition.resumeEvent.value) &&
		event.Key == updated.definition.resumeEvent
	reset := event != nil && changed && validKey(updated.definition.resetEvent.value) &&
		event.Key == updated.definition.resetEvent
	plan := MetricPlan{
		previousVersion: instance.version, instance: updated.clone(), changed: changed,
		evaluation: cloneEvaluation(evaluation),
	}

	bindings := slices.Clone(work.Triggers)
	slices.SortFunc(bindings, func(left, right TriggerBinding) int {
		return compareEntityID(left.Definition.id, right.Definition.id)
	})
	for _, binding := range bindings {
		if _, duplicate := seenTriggers[binding.Definition.id]; duplicate ||
			binding.Definition.metricID != updated.definition.id ||
			!binding.Definition.validFor(updated.definition) || binding.Cursor.triggerID != binding.Definition.id {
			return MetricPlan{}, ErrInvalidMetric
		}
		if _, cursorErr := RestoreTriggerCursor(binding.Cursor.Snapshot()); cursorErr != nil {
			return MetricPlan{}, cursorErr
		}
		cursorInput := binding.Cursor
		if reset {
			// A reset starts a new metric run. Keep the append-only firing
			// counters, but restart the repeated-breach window so a previous
			// run cannot suppress window zero of the new run.
			cursorInput.lastRepeatWindow = -1
		}
		seenTriggers[binding.Definition.id] = struct{}{}
		cursor, occurrence, observeErr := ObserveTriggerContext(
			ctx, updated, binding.Definition, cursorInput, observedAt, calendar, resumed,
		)
		if observeErr != nil {
			return MetricPlan{}, observeErr
		}
		plan.cursors = append(plan.cursors, cursor.clone())
		if occurrence != nil {
			plan.occurrences = append(plan.occurrences, occurrence.clone())
		}
		nextTrigger, nextErr := nextTriggerEvaluation(
			ctx, updated, binding.Definition, cursor, evaluation, observedAt, calendar,
		)
		if nextErr != nil {
			return MetricPlan{}, nextErr
		}
		plan.nextEvaluation = earlierFuture(plan.nextEvaluation, nextTrigger, observedAt)
	}

	columns := slices.Clone(work.Columns)
	slices.SortFunc(columns, func(left, right ColumnDefinition) int {
		if left.position < right.position {
			return -1
		}
		if left.position > right.position {
			return 1
		}
		return compareEntityID(left.id, right.id)
	})
	for _, column := range columns {
		if _, duplicate := seenColumns[column.id]; duplicate || column.tenantID != updated.tenantID ||
			column.metricID != updated.definition.id {
			return MetricPlan{}, ErrInvalidMetric
		}
		seenColumns[column.id] = struct{}{}
		value, materializeErr := MaterializeColumnContext(ctx, column, updated, observedAt, calendar)
		if materializeErr != nil {
			return MetricPlan{}, materializeErr
		}
		plan.columns = append(plan.columns, value.clone())
		plan.nextEvaluation = earlierFuture(plan.nextEvaluation, value.nextRefreshAt, observedAt)
	}
	nextState, nextErr := nextMetricStateEvaluation(ctx, updated, evaluation, observedAt, calendar)
	if nextErr != nil {
		return MetricPlan{}, nextErr
	}
	plan.nextEvaluation = earlierFuture(plan.nextEvaluation, nextState, observedAt)
	return plan, nil
}

type metricPlanMode struct {
	materializeOnly bool
	resumed         bool
}

func nextMetricStateEvaluation(
	ctx context.Context,
	instance MetricInstance,
	evaluation MetricEvaluation,
	at time.Time,
	calendar *BusinessCalendar,
) (*time.Time, error) {
	if instance.lifecycle != lifecycleRunning {
		return nil, nil
	}
	var next *time.Time
	next = earlierFuture(next, instance.dueAt, at)
	next = earlierFuture(next, instance.breachThresholdAt, at)
	consumed := instance.effectiveDuration() - evaluation.Remaining
	switch instance.definition.warning.Kind {
	case WarningConsumedPercent:
		target := percentageDuration(instance.effectiveDuration(), instance.definition.warning.ConsumedPercent)
		candidate, err := futureClockInstant(ctx, instance, at, target-consumed, calendar)
		if err != nil {
			return nil, err
		}
		next = earlierFuture(next, candidate, at)
	case WarningRemainingDuration:
		target := instance.effectiveDuration() - instance.definition.warning.RemainingDuration
		candidate, err := futureClockInstant(ctx, instance, at, target-consumed, calendar)
		if err != nil {
			return nil, err
		}
		next = earlierFuture(next, candidate, at)
	}
	return next, nil
}

func nextTriggerEvaluation(
	ctx context.Context,
	instance MetricInstance,
	definition TriggerDefinition,
	cursor TriggerCursor,
	evaluation MetricEvaluation,
	at time.Time,
	calendar *BusinessCalendar,
) (*time.Time, error) {
	if instance.lifecycle == lifecyclePending || instance.lifecycle == lifecyclePaused || instance.lifecycle == lifecycleCompleted {
		return nil, nil
	}
	consumed := instance.effectiveDuration() - evaluation.Remaining
	switch definition.kind {
	case TriggerConsumedPercent:
		target := percentageDuration(instance.effectiveDuration(), definition.consumedPercent)
		return futureClockInstant(ctx, instance, at, target-consumed, calendar)
	case TriggerRemaining:
		target := instance.effectiveDuration() - definition.remaining
		return futureClockInstant(ctx, instance, at, target-consumed, calendar)
	case TriggerDue:
		return cloneTime(instance.dueAt), nil
	case TriggerAfterBreach:
		if instance.breachThresholdAt == nil {
			return nil, nil
		}
		candidate := instance.breachThresholdAt.Add(definition.offset)
		if !validInstant(candidate) {
			return nil, ErrCalendarRange
		}
		return &candidate, nil
	case TriggerRepeatedBreach:
		if instance.breachThresholdAt == nil {
			return nil, nil
		}
		first := instance.breachThresholdAt.Add(definition.offset)
		if !validInstant(first) {
			return nil, ErrCalendarRange
		}
		if first.After(at) {
			return &first, nil
		}
		nextWindow := cursor.lastRepeatWindow + 1
		if nextWindow < 0 {
			nextWindow = 0
		}
		if nextWindow > math.MaxInt64/int64(definition.repeatInterval) {
			return nil, ErrInvalidMetric
		}
		candidate := first.Add(time.Duration(nextWindow) * definition.repeatInterval)
		if !validInstant(candidate) {
			return nil, ErrCalendarRange
		}
		return &candidate, nil
	default:
		return nil, nil
	}
}

func futureClockInstant(
	ctx context.Context,
	instance MetricInstance,
	at time.Time,
	remaining time.Duration,
	calendar *BusinessCalendar,
) (*time.Time, error) {
	if remaining <= 0 {
		return nil, nil
	}
	value, err := instance.addClockTimeContext(ctx, at, remaining, calendar)
	if err != nil {
		return nil, err
	}
	return &value, nil
}

func earlierFuture(current, candidate *time.Time, after time.Time) *time.Time {
	if candidate == nil || !validInstant(*candidate) || !candidate.After(after) {
		return cloneTime(current)
	}
	if current == nil || candidate.Before(*current) {
		return cloneTime(candidate)
	}
	return cloneTime(current)
}

func cloneCalendarPointer(value *BusinessCalendar) *BusinessCalendar {
	if value == nil {
		return nil
	}
	input := value.Input()
	copy, err := NewBusinessCalendar(input)
	if err != nil {
		return nil
	}
	return &copy
}

func (cursor TriggerCursor) clone() TriggerCursor {
	result := cursor
	result.lastObservedAt = cloneTime(cursor.lastObservedAt)
	result.lastFiredAt = cloneTime(cursor.lastFiredAt)
	return result
}

func cloneTriggerCursors(values []TriggerCursor) []TriggerCursor {
	result := make([]TriggerCursor, len(values))
	for index, cursor := range values {
		result[index] = cursor.clone()
	}
	return result
}

func (occurrence TriggerOccurrence) clone() TriggerOccurrence {
	result := occurrence
	result.action = occurrence.action.clone()
	return result
}

func cloneOccurrences(values []TriggerOccurrence) []TriggerOccurrence {
	result := make([]TriggerOccurrence, len(values))
	for index, occurrence := range values {
		result[index] = occurrence.clone()
	}
	return result
}

func (value MaterializedColumnValue) clone() MaterializedColumnValue {
	result := value
	result.instant = cloneTime(value.instant)
	result.duration = cloneDuration(value.duration)
	result.percentage = cloneFloat64(value.percentage)
	result.nextRefreshAt = cloneTime(value.nextRefreshAt)
	return result
}

func (plan MetricPlan) clone() MetricPlan {
	result := plan
	result.instance = plan.instance.clone()
	result.evaluation = cloneEvaluation(plan.evaluation)
	result.cursors = cloneTriggerCursors(plan.cursors)
	result.occurrences = cloneOccurrences(plan.occurrences)
	result.columns = plan.Columns()
	result.nextEvaluation = cloneTime(plan.nextEvaluation)
	return result
}
