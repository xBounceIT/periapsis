package sla

import "context"

// OverrideMaterializationInput carries the exact metric work locked by the
// repository after ApplyOverride has produced Record. The planner does not
// mutate the metric a second time; it atomically derives trigger cursors,
// occurrences, dynamic columns, and the next evaluation job from that result.
type OverrideMaterializationInput struct {
	Work   MetricWork
	Record OverrideRecord
}

func (input OverrideMaterializationInput) String() string {
	return "sla.OverrideMaterializationInput{payload:[REDACTED],identity:[REDACTED]}"
}
func (input OverrideMaterializationInput) GoString() string { return input.String() }

func PlanOverrideMaterialization(input OverrideMaterializationInput) (EnginePlan, error) {
	return PlanOverrideMaterializationContext(context.Background(), input)
}

func PlanOverrideMaterializationContext(
	ctx context.Context,
	input OverrideMaterializationInput,
) (EnginePlan, error) {
	if ctx == nil || ctx.Err() != nil {
		return EnginePlan{}, ErrEngineCanceled
	}
	instance, record := input.Work.Instance, input.Record
	if !validOverrideMaterialization(instance, record) {
		return EnginePlan{}, ErrInvalidOverride
	}
	metric, err := planMetric(
		ctx, input.Work, record.occurredAt, nil,
		metricPlanMode{materializeOnly: true, resumed: record.kind == OverrideResume},
		make(map[EntityID]struct{}), make(map[EntityID]struct{}),
	)
	if err != nil {
		return EnginePlan{}, err
	}
	return EnginePlan{observedAt: record.occurredAt, metrics: []MetricPlan{metric}}, nil
}

func validOverrideMaterialization(instance MetricInstance, record OverrideRecord) bool {
	if !instance.valid() || record.kind == OverrideChangePolicy || !validEntityID(record.id) ||
		instance.lastOverrideID == nil || *instance.lastOverrideID != record.id ||
		instance.lastOverrideDigest == ([32]byte{}) || instance.lastOverrideDigest != record.commandDigest ||
		!record.occurredAt.Equal(instance.updatedAt) || !validInstant(record.occurredAt) ||
		record.tenantID != instance.tenantID || record.objectID != instance.objectID {
		return false
	}
	next := record.next
	calendarID := instance.definition.calendarID
	if next.policyID != instance.policyID || next.policyVersion != instance.policyVersion ||
		next.metricID != instance.definition.id || next.metricKey != instance.definition.key ||
		next.calendarVersion != instance.definition.calendarVersion ||
		!sameOptionalID(next.calendarID, calendarID) || next.extension != instance.extension ||
		next.effectiveDuration != instance.effectiveDuration() {
		return false
	}
	previousState, nextState := record.previous.evaluation.State, record.next.evaluation.State
	switch record.kind {
	case OverrideResume:
		return previousState == StatePaused && instance.lifecycle == lifecycleRunning && nextState != StatePaused && nextState != StateCompleted
	case OverrideSuspend:
		return previousState != StatePaused && previousState != StateCompleted && nextState == StatePaused && instance.lifecycle == lifecyclePaused
	case OverrideComplete:
		return previousState != StateCompleted && nextState == StateCompleted && instance.lifecycle == lifecycleCompleted
	case OverrideExtend, OverrideChangeCalendar, OverrideRecalculate:
		return true
	default:
		return false
	}
}

func sameOptionalID(left, right *EntityID) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}
