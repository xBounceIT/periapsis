package sla

import (
	"context"
	"fmt"
	"slices"
)

// PolicyOverrideInput changes one whole SLA aggregate to an immutable policy
// revision. Metric instance identities and lifecycle state are retained by
// stable metric key. Adding, removing, or renaming metrics is rejected because
// it would require an explicit migration strategy beyond a policy override.
type PolicyOverrideInput struct {
	Metrics              []MetricWork
	ReplacementPolicy    Policy
	ReplacementCalendars []BusinessCalendar
	ReplacementColumns   []ColumnDefinition
	Command              OverrideCommand
	Authority            OverrideAuthority
}

type PolicyOverridePlan struct {
	slaInstanceID       EntityID
	previousPolicyID    EntityID
	previousPolicy      uint64
	replacementPolicy   Policy
	metricWork          []MetricWork
	records             []OverrideRecord
	materializationPlan EnginePlan
}

func (plan PolicyOverridePlan) SLAInstanceID() EntityID    { return plan.slaInstanceID }
func (plan PolicyOverridePlan) PreviousPolicyID() EntityID { return plan.previousPolicyID }
func (plan PolicyOverridePlan) PreviousPolicyVersion() uint64 {
	return plan.previousPolicy
}
func (plan PolicyOverridePlan) ReplacementPolicy() Policy { return plan.replacementPolicy.clone() }
func (plan PolicyOverridePlan) Metrics() []MetricWork     { return cloneMetricWork(plan.metricWork) }
func (plan PolicyOverridePlan) Records() []OverrideRecord { return slices.Clone(plan.records) }
func (plan PolicyOverridePlan) MaterializationPlan() EnginePlan {
	result := plan.materializationPlan
	result.metrics = plan.materializationPlan.Metrics()
	return result
}
func (plan PolicyOverridePlan) String() string {
	return fmt.Sprintf(
		"sla.PolicyOverridePlan{metrics:%d,records:%d,identity:[REDACTED],snapshots:[REDACTED]}",
		len(plan.metricWork), len(plan.records),
	)
}
func (plan PolicyOverridePlan) GoString() string { return plan.String() }

// PlanPolicyOverride applies a policy change to every metric in an aggregate,
// then runs the normal timer planner at the override instant to materialize the
// new cursors, columns, trigger effects, and next evaluation in the same write.
func PlanPolicyOverride(input PolicyOverrideInput) (PolicyOverridePlan, error) {
	return PlanPolicyOverrideContext(context.Background(), input)
}

func PlanPolicyOverrideContext(ctx context.Context, input PolicyOverrideInput) (PolicyOverridePlan, error) {
	if ctx == nil || ctx.Err() != nil {
		return PolicyOverridePlan{}, ErrEngineCanceled
	}
	if len(input.Metrics) == 0 || len(input.Metrics) > maximumEngineMetrics ||
		!input.ReplacementPolicy.valid() || input.Command.Kind != OverrideChangePolicy ||
		input.Command.NewMetric != nil || input.Command.Extension != 0 ||
		input.Command.NewPolicyID != input.ReplacementPolicy.id ||
		input.Command.NewPolicyVersion != input.ReplacementPolicy.version ||
		!input.ReplacementPolicy.enabled || input.Command.OccurredAt.Before(input.ReplacementPolicy.effectiveFrom) ||
		input.ReplacementPolicy.effectiveUntil != nil &&
			!input.Command.OccurredAt.Before(*input.ReplacementPolicy.effectiveUntil) {
		return PolicyOverridePlan{}, ErrInvalidOverride
	}

	currentByKey := make(map[Key]MetricWork, len(input.Metrics))
	seenInstanceIDs := make(map[EntityID]struct{}, len(input.Metrics))
	seenMetricIDs := make(map[EntityID]struct{}, len(input.Metrics))
	var tenantID, objectID, slaInstanceID, previousPolicyID EntityID
	var objectType ObjectType
	var previousPolicyVersion uint64
	for index, work := range input.Metrics {
		if ctx.Err() != nil {
			return PolicyOverridePlan{}, ErrEngineCanceled
		}
		instance := work.Instance
		if !instance.valid() || !instance.matchesCalendar(work.Calendar) || len(work.Triggers) != 0 || len(work.Columns) != 0 {
			return PolicyOverridePlan{}, ErrInvalidMetric
		}
		if index == 0 {
			tenantID, objectID, objectType = instance.tenantID, instance.objectID, instance.objectType
			slaInstanceID = instance.slaInstanceID
			previousPolicyID, previousPolicyVersion = instance.policyID, instance.policyVersion
		} else if instance.tenantID != tenantID || instance.objectID != objectID || instance.objectType != objectType ||
			instance.slaInstanceID != slaInstanceID || instance.policyID != previousPolicyID ||
			instance.policyVersion != previousPolicyVersion {
			return PolicyOverridePlan{}, ErrInvalidMetric
		}
		if _, duplicate := currentByKey[instance.definition.key]; duplicate {
			return PolicyOverridePlan{}, ErrInvalidMetric
		}
		if _, duplicate := seenInstanceIDs[instance.id]; duplicate {
			return PolicyOverridePlan{}, ErrInvalidMetric
		}
		if _, duplicate := seenMetricIDs[instance.definition.id]; duplicate {
			return PolicyOverridePlan{}, ErrInvalidMetric
		}
		currentByKey[instance.definition.key] = work
		seenInstanceIDs[instance.id] = struct{}{}
		seenMetricIDs[instance.definition.id] = struct{}{}
	}
	if input.ReplacementPolicy.tenantID != tenantID ||
		!slices.Contains(input.ReplacementPolicy.objectTypes, objectType) ||
		input.Command.TenantID != tenantID || input.Command.ObjectID != objectID ||
		input.ReplacementPolicy.id == previousPolicyID && input.ReplacementPolicy.version == previousPolicyVersion ||
		len(input.ReplacementPolicy.metrics) != len(currentByKey) {
		return PolicyOverridePlan{}, ErrInvalidOverride
	}
	calendars, err := assignmentCalendars(input.ReplacementPolicy, input.ReplacementCalendars)
	if err != nil {
		return PolicyOverridePlan{}, err
	}
	columns, err := assignmentColumns(input.ReplacementPolicy, input.ReplacementColumns)
	if err != nil {
		return PolicyOverridePlan{}, err
	}

	plan := PolicyOverridePlan{
		slaInstanceID: slaInstanceID, previousPolicyID: previousPolicyID,
		previousPolicy: previousPolicyVersion, replacementPolicy: input.ReplacementPolicy.clone(),
	}
	for _, replacement := range input.ReplacementPolicy.metrics {
		if ctx.Err() != nil {
			return PolicyOverridePlan{}, ErrEngineCanceled
		}
		current, exists := currentByKey[replacement.key]
		if !exists {
			return PolicyOverridePlan{}, ErrInvalidOverride
		}
		command := input.Command
		metricCopy := replacement.clone()
		command.NewMetric = &metricCopy
		updated, record, changed, applyErr := current.Instance.applyOverrideCommandContext(
			ctx, current.Instance.version, command, input.Authority, current.Calendar, calendars[replacement.id],
		)
		if applyErr != nil || !changed || record == nil {
			if applyErr != nil {
				return PolicyOverridePlan{}, applyErr
			}
			return PolicyOverridePlan{}, ErrInvalidOverride
		}
		work := MetricWork{Instance: updated, Calendar: cloneCalendarPointer(calendars[replacement.id])}
		for _, trigger := range input.ReplacementPolicy.triggers {
			if trigger.metricID != replacement.id {
				continue
			}
			cursor, cursorErr := NewTriggerCursor(trigger.id)
			if cursorErr != nil {
				return PolicyOverridePlan{}, cursorErr
			}
			work.Triggers = append(work.Triggers, TriggerBinding{Definition: trigger.clone(), Cursor: cursor})
		}
		work.Columns = slices.Clone(columns[replacement.id])
		plan.metricWork = append(plan.metricWork, work)
		plan.records = append(plan.records, *record)
	}
	plan.materializationPlan, err = PlanEngineContext(ctx, EngineInput{
		ObservedAt: input.Command.OccurredAt, Metrics: plan.metricWork,
	})
	if err != nil {
		return PolicyOverridePlan{}, err
	}
	return plan, nil
}
