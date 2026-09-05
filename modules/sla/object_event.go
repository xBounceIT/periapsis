package sla

import (
	"context"
	"slices"
)

// ObjectEventStateMode distinguishes the two transaction-local projections an
// event planner can consume. Existing aggregates carry only pinned metric
// work; unassigned objects carry only one immutable fact/configuration view.
type ObjectEventStateMode string

const (
	ObjectEventStateExisting   ObjectEventStateMode = "existing"
	ObjectEventStateUnassigned ObjectEventStateMode = "unassigned"
	ObjectEventStateNoPolicy   ObjectEventStateMode = "no_policy"
)

type ObjectEventState struct {
	Mode             ObjectEventStateMode
	AggregateVersion uint64
	Metrics          []MetricWork
	Snapshot         *FactSnapshot
	Policies         []Policy
	Calendars        []BusinessCalendar
	Columns          []ColumnDefinition
}

// ObjectEventPlan is the complete pure result for one ordered domain event.
// An unmatched first event deliberately returns an assignment decision with no
// engine plan so callers can persist an idempotent no-policy receipt.
type ObjectEventPlan struct {
	assignment               *AssignmentPlan
	engine                   *EnginePlan
	expectedAggregateVersion uint64
	nextAggregateVersion     uint64
	pinnedNoPolicy           bool
}

func (plan ObjectEventPlan) Assignment() *AssignmentPlan {
	if plan.assignment == nil {
		return nil
	}
	result := *plan.assignment
	return &result
}

func (plan ObjectEventPlan) Engine() *EnginePlan {
	if plan.engine == nil {
		return nil
	}
	result := *plan.engine
	return &result
}

func (plan ObjectEventPlan) ExpectedAggregateVersion() uint64 {
	return plan.expectedAggregateVersion
}

func (plan ObjectEventPlan) NextAggregateVersion() uint64 { return plan.nextAggregateVersion }

// PinnedNoPolicy reports a durable no-op decision inherited from the object's
// creation event. It prevents later events from consulting configuration that
// did not apply when the object was created.
func (plan ObjectEventPlan) PinnedNoPolicy() bool { return plan.pinnedNoPolicy }

func (plan ObjectEventPlan) String() string {
	return "sla.ObjectEventPlan{payload:[REDACTED]}"
}

func (plan ObjectEventPlan) GoString() string { return plan.String() }

func PlanObjectEvent(event MetricEvent, state ObjectEventState) (ObjectEventPlan, error) {
	return PlanObjectEventContext(context.Background(), event, state)
}

// PlanObjectEventContext is the shared application/worker planner for an
// ordered immutable object event. It performs no persistence or authorization.
func PlanObjectEventContext(
	ctx context.Context,
	event MetricEvent,
	state ObjectEventState,
) (ObjectEventPlan, error) {
	if ctx == nil || ctx.Err() != nil {
		return ObjectEventPlan{}, ErrEngineCanceled
	}
	switch state.Mode {
	case ObjectEventStateNoPolicy:
		if state.AggregateVersion != 0 || state.Snapshot != nil || len(state.Metrics) != 0 ||
			len(state.Policies) != 0 || len(state.Calendars) != 0 || len(state.Columns) != 0 ||
			!validEntityID(event.ID) || !validEntityID(event.TenantID) ||
			!validEntityID(event.ObjectID) || !validKey(event.Key.value) ||
			!validInstant(event.OccurredAt) {
			return ObjectEventPlan{}, ErrInvalidEvent
		}
		return ObjectEventPlan{pinnedNoPolicy: true}, nil
	case ObjectEventStateExisting:
		if state.AggregateVersion == 0 || state.AggregateVersion >= maximumVersion-1 ||
			state.Snapshot != nil || len(state.Metrics) == 0 || len(state.Policies) != 0 ||
			len(state.Calendars) != 0 || len(state.Columns) != 0 {
			return ObjectEventPlan{}, ErrInvalidMetric
		}
		engine, err := PlanEngineContext(ctx, EngineInput{
			ObservedAt: event.OccurredAt,
			Event:      &event,
			Metrics:    slices.Clone(state.Metrics),
		})
		if err != nil {
			return ObjectEventPlan{}, err
		}
		return ObjectEventPlan{
			engine:                   &engine,
			expectedAggregateVersion: state.AggregateVersion,
			nextAggregateVersion:     state.AggregateVersion + 1,
		}, nil
	case ObjectEventStateUnassigned:
		if state.AggregateVersion != 0 || state.Snapshot == nil || len(state.Metrics) != 0 {
			return ObjectEventPlan{}, ErrInvalidPolicy
		}
		selected, err := selectPolicyContext(ctx, state.Policies, *state.Snapshot)
		if err != nil {
			return ObjectEventPlan{}, err
		}
		calendars, columns, err := objectEventAssignmentInventory(ctx, state, selected)
		if err != nil {
			return ObjectEventPlan{}, err
		}
		var policies []Policy
		if selected != nil {
			policies = []Policy{*selected}
		}
		assignment, err := PlanAssignmentContext(ctx, AssignmentInput{
			Snapshot:          *state.Snapshot,
			Policies:          policies,
			ObjectID:          event.ObjectID,
			AssignmentEventID: event.ID,
			CreatedAt:         event.OccurredAt,
			Calendars:         calendars,
			Columns:           columns,
		})
		if err != nil {
			return ObjectEventPlan{}, err
		}
		result := ObjectEventPlan{assignment: &assignment}
		if !assignment.Matched() {
			return result, nil
		}
		engine, err := PlanEngineContext(ctx, EngineInput{
			ObservedAt: event.OccurredAt,
			Event:      &event,
			Metrics:    assignment.Metrics(),
		})
		if err != nil {
			return ObjectEventPlan{}, err
		}
		result.engine = &engine
		result.nextAggregateVersion = 1
		return result, nil
	default:
		return ObjectEventPlan{}, ErrInvalidMetric
	}
}

// An immutable event snapshot contains the tenant's complete calendar/column
// inventory, including definitions for other policies and object types. Keep
// snapshot ownership and uniqueness checks ahead of projection, then let the
// strict assignment planner validate the selected policy's exact dependencies.
func objectEventAssignmentInventory(
	ctx context.Context,
	state ObjectEventState,
	selected *Policy,
) ([]BusinessCalendar, []ColumnDefinition, error) {
	if len(state.Calendars) > 512 {
		return nil, nil, ErrInvalidCalendar
	}
	if len(state.Columns) > maximumAssignmentColumns {
		return nil, nil, ErrInvalidMetric
	}
	requiredCalendars := make(map[EntityID]struct{})
	selectedMetrics := make(map[EntityID]struct{})
	if selected != nil {
		for _, metric := range selected.metrics {
			selectedMetrics[metric.id] = struct{}{}
			if metric.calendarID != nil {
				requiredCalendars[*metric.calendarID] = struct{}{}
			}
		}
	}
	var calendars []BusinessCalendar
	calendarIDs := make(map[EntityID]struct{}, len(state.Calendars))
	for _, calendar := range state.Calendars {
		if ctx.Err() != nil {
			return nil, nil, ErrEngineCanceled
		}
		if !calendar.valid() || calendar.tenantID != state.Snapshot.tenantID {
			return nil, nil, ErrInvalidCalendar
		}
		if _, duplicate := calendarIDs[calendar.id]; duplicate {
			return nil, nil, ErrInvalidCalendar
		}
		calendarIDs[calendar.id] = struct{}{}
		if _, required := requiredCalendars[calendar.id]; required {
			calendars = append(calendars, calendar)
		}
	}
	var columns []ColumnDefinition
	columnIDs := make(map[EntityID]struct{}, len(state.Columns))
	columnKeys := make(map[Key]struct{}, len(state.Columns))
	for _, column := range state.Columns {
		if ctx.Err() != nil {
			return nil, nil, ErrEngineCanceled
		}
		// ColumnDefinition is opaque and constructed against its own metric before
		// entering the snapshot; that metric may belong to another object type.
		if !validEntityID(column.id) || !validEntityID(column.metricID) ||
			column.tenantID != state.Snapshot.tenantID || !validKey(column.key.value) ||
			column.version == 0 || column.version >= maximumVersion {
			return nil, nil, ErrInvalidMetric
		}
		if _, duplicate := columnIDs[column.id]; duplicate {
			return nil, nil, ErrInvalidMetric
		}
		if _, duplicate := columnKeys[column.key]; duplicate {
			return nil, nil, ErrInvalidMetric
		}
		columnIDs[column.id], columnKeys[column.key] = struct{}{}, struct{}{}
		if _, required := selectedMetrics[column.metricID]; required {
			columns = append(columns, column)
		}
	}
	return calendars, columns, nil
}
