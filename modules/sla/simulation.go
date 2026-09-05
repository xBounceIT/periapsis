package sla

import (
	"context"
	"fmt"
	"slices"
	"time"
)

type SimulationMetricBinding struct {
	MetricID   EntityID
	InstanceID EntityID
}

type SimulationInput struct {
	Snapshot       FactSnapshot
	Policy         Policy
	SLAInstanceID  EntityID
	ObjectID       EntityID
	CreatedAt      time.Time
	EvaluateAt     time.Time
	MetricBindings []SimulationMetricBinding
	Calendars      []BusinessCalendar
	Events         []MetricEvent
}

type ProjectedTrigger struct {
	triggerID   EntityID
	metricID    EntityID
	scheduledAt *time.Time
	eventDriven bool
	action      TriggerAction
}

func (projected ProjectedTrigger) TriggerID() EntityID     { return projected.triggerID }
func (projected ProjectedTrigger) MetricID() EntityID      { return projected.metricID }
func (projected ProjectedTrigger) ScheduledAt() *time.Time { return cloneTime(projected.scheduledAt) }
func (projected ProjectedTrigger) EventDriven() bool       { return projected.eventDriven }
func (projected ProjectedTrigger) Action() TriggerAction   { return projected.action.clone() }

type SimulationMetricResult struct {
	metricID   EntityID
	metricKey  Key
	instance   MetricInstance
	evaluation MetricEvaluation
	triggers   []ProjectedTrigger
}

func (result SimulationMetricResult) MetricID() EntityID       { return result.metricID }
func (result SimulationMetricResult) MetricKey() Key           { return result.metricKey }
func (result SimulationMetricResult) Instance() MetricInstance { return result.instance.clone() }
func (result SimulationMetricResult) Evaluation() MetricEvaluation {
	return cloneEvaluation(result.evaluation)
}
func (result SimulationMetricResult) Triggers() []ProjectedTrigger {
	resultCopy := make([]ProjectedTrigger, len(result.triggers))
	for index, trigger := range result.triggers {
		resultCopy[index] = trigger.clone()
	}
	return resultCopy
}

type SimulationResult struct {
	policyID      EntityID
	policyVersion uint64
	metrics       []SimulationMetricResult
}

func (result SimulationResult) PolicyID() EntityID    { return result.policyID }
func (result SimulationResult) PolicyVersion() uint64 { return result.policyVersion }
func (result SimulationResult) Metrics() []SimulationMetricResult {
	copy := make([]SimulationMetricResult, len(result.metrics))
	for index, metric := range result.metrics {
		copy[index] = metric.clone()
	}
	return copy
}
func (result SimulationResult) String() string {
	return fmt.Sprintf(
		"sla.SimulationResult{policyVersion:%d,metrics:%d,identity:[REDACTED],values:[REDACTED]}",
		result.policyVersion, len(result.metrics),
	)
}
func (result SimulationResult) GoString() string { return result.String() }

// Simulate executes the same immutable metric engine used by live processing.
// It never calls repositories or emits actions, making it safe for policy
// validation and administrator previews.
func Simulate(input SimulationInput) (SimulationResult, error) {
	return SimulateContext(context.Background(), input)
}

func SimulateContext(ctx context.Context, input SimulationInput) (SimulationResult, error) {
	if ctx == nil || ctx.Err() != nil {
		return SimulationResult{}, ErrEngineCanceled
	}
	if !input.Snapshot.valid() || !input.Policy.valid() || !validEntityID(input.SLAInstanceID) ||
		!validEntityID(input.ObjectID) || input.SLAInstanceID == input.ObjectID ||
		input.Policy.tenantID != input.Snapshot.tenantID || !input.Policy.Matches(input.Snapshot) ||
		!validInstant(input.CreatedAt) || !validInstant(input.EvaluateAt) ||
		input.EvaluateAt.Before(input.CreatedAt) || len(input.Events) > 10_000 ||
		len(input.MetricBindings) != len(input.Policy.metrics) {
		return SimulationResult{}, ErrInvalidPolicy
	}
	bindings := make(map[EntityID]EntityID, len(input.MetricBindings))
	instanceIDs := make(map[EntityID]struct{}, len(input.MetricBindings))
	for _, binding := range input.MetricBindings {
		if !validEntityID(binding.MetricID) || !validEntityID(binding.InstanceID) {
			return SimulationResult{}, ErrInvalidPolicy
		}
		if _, duplicate := bindings[binding.MetricID]; duplicate {
			return SimulationResult{}, ErrInvalidPolicy
		}
		if _, duplicate := instanceIDs[binding.InstanceID]; duplicate {
			return SimulationResult{}, ErrInvalidPolicy
		}
		bindings[binding.MetricID] = binding.InstanceID
		instanceIDs[binding.InstanceID] = struct{}{}
	}
	calendars, err := assignmentCalendars(input.Policy, input.Calendars)
	if err != nil {
		return SimulationResult{}, err
	}
	if !validSimulationEvents(input.Events, input.Policy.tenantID, input.ObjectID, input.CreatedAt, input.EvaluateAt) {
		return SimulationResult{}, ErrInvalidEvent
	}

	result := SimulationResult{policyID: input.Policy.id, policyVersion: input.Policy.version}
	for _, metric := range input.Policy.metrics {
		if ctx.Err() != nil {
			return SimulationResult{}, ErrEngineCanceled
		}
		instanceID, exists := bindings[metric.id]
		if !exists {
			return SimulationResult{}, ErrInvalidPolicy
		}
		calendar := cloneCalendarPointer(calendars[metric.id])
		instance, err := NewMetricInstance(MetricInstanceInput{
			ID: instanceID, SLAInstanceID: input.SLAInstanceID,
			TenantID: input.Policy.tenantID, ObjectType: input.Snapshot.objectType,
			ObjectID: input.ObjectID, PolicyID: input.Policy.id, PolicyVersion: input.Policy.version,
			Definition: metric, CreatedAt: input.CreatedAt,
		})
		if err != nil {
			return SimulationResult{}, err
		}
		for _, event := range input.Events {
			if ctx.Err() != nil {
				return SimulationResult{}, ErrEngineCanceled
			}
			updated, _, applyErr := instance.ApplyEventContext(ctx, instance.version, event, calendar)
			if applyErr != nil {
				return SimulationResult{}, applyErr
			}
			instance = updated
		}
		evaluation, err := instance.EvaluateContext(ctx, input.EvaluateAt, calendar)
		if err != nil {
			return SimulationResult{}, err
		}
		triggers, err := projectMetricTriggers(ctx, input.Policy.triggers, instance, input.EvaluateAt, calendar)
		if err != nil {
			return SimulationResult{}, err
		}
		result.metrics = append(result.metrics, SimulationMetricResult{
			metricID: metric.id, metricKey: metric.key, instance: instance.clone(),
			evaluation: cloneEvaluation(evaluation), triggers: triggers,
		})
	}
	return result, nil
}

func projectMetricTriggers(
	ctx context.Context,
	definitions []TriggerDefinition,
	instance MetricInstance,
	at time.Time,
	calendar *BusinessCalendar,
) ([]ProjectedTrigger, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrEngineCanceled
	}
	evaluation, evaluationErr := instance.EvaluateContext(ctx, at, calendar)
	if evaluationErr != nil {
		return nil, evaluationErr
	}
	consumedAtObservation := instance.effectiveDuration() - evaluation.Remaining
	result := make([]ProjectedTrigger, 0)
	for _, definition := range definitions {
		if ctx.Err() != nil {
			return nil, ErrEngineCanceled
		}
		if definition.metricID != instance.definition.id {
			continue
		}
		projected := ProjectedTrigger{
			triggerID: definition.id, metricID: definition.metricID, action: definition.action.clone(),
		}
		switch definition.kind {
		case TriggerDue:
			if instance.lifecycle == lifecycleRunning {
				projected.scheduledAt = cloneTime(instance.dueAt)
			}
		case TriggerAfterBreach, TriggerRepeatedBreach:
			if instance.lifecycle == lifecycleRunning && instance.breachThresholdAt != nil {
				scheduled := instance.breachThresholdAt.Add(definition.offset)
				if !validInstant(scheduled) {
					return nil, ErrCalendarRange
				}
				projected.scheduledAt = &scheduled
			}
		case TriggerConsumedPercent:
			if instance.lifecycle == lifecycleRunning {
				target := percentageDuration(instance.effectiveDuration(), definition.consumedPercent)
				remaining := target - consumedAtObservation
				if remaining < 0 {
					remaining = 0
				}
				scheduled, err := instance.addClockTimeContext(ctx, at, remaining, calendar)
				if err != nil {
					return nil, err
				}
				projected.scheduledAt = &scheduled
			}
		case TriggerRemaining:
			if instance.lifecycle == lifecycleRunning {
				targetConsumed := instance.effectiveDuration() - definition.remaining
				remaining := targetConsumed - consumedAtObservation
				if remaining < 0 {
					remaining = 0
				}
				scheduled, err := instance.addClockTimeContext(ctx, at, remaining, calendar)
				if err != nil {
					return nil, err
				}
				projected.scheduledAt = &scheduled
			}
		case TriggerStateChanged, TriggerResumed:
			projected.eventDriven = true
		}
		result = append(result, projected)
	}
	slices.SortFunc(result, func(left, right ProjectedTrigger) int {
		return compareEntityID(left.triggerID, right.triggerID)
	})
	return result, nil
}

func validSimulationEvents(events []MetricEvent, tenantID, objectID EntityID, start, end time.Time) bool {
	seen := make(map[EntityID]struct{}, len(events))
	previous := start
	for _, event := range events {
		if !validEntityID(event.ID) || event.TenantID != tenantID || event.ObjectID != objectID ||
			!validKey(event.Key.value) || !validInstant(event.OccurredAt) || event.OccurredAt.Before(previous) ||
			event.OccurredAt.After(end) {
			return false
		}
		if _, duplicate := seen[event.ID]; duplicate {
			return false
		}
		seen[event.ID] = struct{}{}
		previous = event.OccurredAt
	}
	return true
}

func percentageDuration(duration time.Duration, percentage uint8) time.Duration {
	quotient, remainder := duration/100, duration%100
	result := quotient*time.Duration(percentage) + remainder*time.Duration(percentage)/100
	if result <= 0 {
		return 0
	}
	return (result + time.Microsecond - 1) / time.Microsecond * time.Microsecond
}

func (projected ProjectedTrigger) clone() ProjectedTrigger {
	result := projected
	result.scheduledAt = cloneTime(projected.scheduledAt)
	result.action = projected.action.clone()
	return result
}

func (result SimulationMetricResult) clone() SimulationMetricResult {
	copy := result
	copy.instance = result.instance.clone()
	copy.evaluation = cloneEvaluation(result.evaluation)
	copy.triggers = result.Triggers()
	return copy
}
