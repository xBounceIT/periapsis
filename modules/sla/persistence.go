package sla

import (
	"fmt"
	"math"
	"slices"
	"time"
)

// MetricLifecycle is the persisted lifecycle of a metric. It is deliberately
// separate from MetricState: a running metric can evaluate as on-track,
// at-risk, or breached without changing lifecycle.
type MetricLifecycle string

const (
	LifecyclePending   MetricLifecycle = "pending"
	LifecycleRunning   MetricLifecycle = "running"
	LifecyclePaused    MetricLifecycle = "paused"
	LifecycleCompleted MetricLifecycle = "completed"
)

// MetricInstanceSnapshot is the complete immutable persistence projection of
// a metric instance. RestoreMetricInstance validates every field and rejects
// malformed or cross-version database projections before they reach the
// engine.
type MetricInstanceSnapshot struct {
	ID                 EntityID
	SLAInstanceID      EntityID
	TenantID           EntityID
	ObjectType         ObjectType
	ObjectID           EntityID
	PolicyID           EntityID
	PolicyVersion      uint64
	Definition         MetricDefinition
	CreatedAt          time.Time
	UpdatedAt          time.Time
	Extension          time.Duration
	Lifecycle          MetricLifecycle
	StartedAt          *time.Time
	LastResumedAt      *time.Time
	PausedAt           *time.Time
	CompletedAt        *time.Time
	DueAt              *time.Time
	BreachThresholdAt  *time.Time
	BreachedAt         *time.Time
	Consumed           time.Duration
	LastEventID        *EntityID
	LastEventKey       Key
	LastEventAt        *time.Time
	LastOverrideID     *EntityID
	LastOverrideDigest [32]byte
	Version            uint64
}

func (snapshot MetricInstanceSnapshot) String() string {
	return fmt.Sprintf(
		"sla.MetricInstanceSnapshot{lifecycle:%s,version:%d,identity:[REDACTED],state:[REDACTED]}",
		snapshot.Lifecycle, snapshot.Version,
	)
}

func (snapshot MetricInstanceSnapshot) GoString() string { return snapshot.String() }

func (instance MetricInstance) Snapshot() MetricInstanceSnapshot {
	return MetricInstanceSnapshot{
		ID: instance.id, SLAInstanceID: instance.slaInstanceID,
		TenantID: instance.tenantID, ObjectType: instance.objectType,
		ObjectID: instance.objectID, PolicyID: instance.policyID, PolicyVersion: instance.policyVersion,
		Definition: instance.definition.clone(), CreatedAt: instance.createdAt, UpdatedAt: instance.updatedAt,
		Extension: instance.extension, Lifecycle: exportedLifecycle(instance.lifecycle),
		StartedAt: cloneTime(instance.startedAt), LastResumedAt: cloneTime(instance.lastResumedAt),
		PausedAt: cloneTime(instance.pausedAt), CompletedAt: cloneTime(instance.completedAt),
		DueAt: cloneTime(instance.dueAt), BreachThresholdAt: cloneTime(instance.breachThresholdAt),
		BreachedAt: cloneTime(instance.breachedAt), Consumed: instance.consumed,
		LastEventID: cloneEntityID(instance.lastEventID), LastEventKey: instance.lastEventKey,
		LastEventAt: cloneTime(instance.lastEventAt), LastOverrideID: cloneEntityID(instance.lastOverrideID),
		LastOverrideDigest: instance.lastOverrideDigest, Version: instance.version,
	}
}

func RestoreMetricInstance(snapshot MetricInstanceSnapshot) (MetricInstance, error) {
	lifecycle, ok := internalLifecycle(snapshot.Lifecycle)
	if !ok {
		return MetricInstance{}, ErrInvalidMetric
	}
	instance := MetricInstance{
		id: snapshot.ID, slaInstanceID: snapshot.SLAInstanceID,
		tenantID: snapshot.TenantID, objectType: snapshot.ObjectType,
		objectID: snapshot.ObjectID, policyID: snapshot.PolicyID, policyVersion: snapshot.PolicyVersion,
		definition: snapshot.Definition.clone(), createdAt: snapshot.CreatedAt, updatedAt: snapshot.UpdatedAt,
		extension: snapshot.Extension, lifecycle: lifecycle,
		startedAt: cloneTime(snapshot.StartedAt), lastResumedAt: cloneTime(snapshot.LastResumedAt),
		pausedAt: cloneTime(snapshot.PausedAt), completedAt: cloneTime(snapshot.CompletedAt),
		dueAt: cloneTime(snapshot.DueAt), breachThresholdAt: cloneTime(snapshot.BreachThresholdAt),
		breachedAt: cloneTime(snapshot.BreachedAt), consumed: snapshot.Consumed,
		lastEventID: cloneEntityID(snapshot.LastEventID), lastEventKey: snapshot.LastEventKey,
		lastEventAt: cloneTime(snapshot.LastEventAt), lastOverrideID: cloneEntityID(snapshot.LastOverrideID),
		lastOverrideDigest: snapshot.LastOverrideDigest, version: snapshot.Version,
	}
	if !instance.valid() {
		return MetricInstance{}, ErrInvalidMetric
	}
	return instance, nil
}

func exportedLifecycle(value metricLifecycle) MetricLifecycle {
	switch value {
	case lifecyclePending:
		return LifecyclePending
	case lifecycleRunning:
		return LifecycleRunning
	case lifecyclePaused:
		return LifecyclePaused
	case lifecycleCompleted:
		return LifecycleCompleted
	default:
		return ""
	}
}

func internalLifecycle(value MetricLifecycle) (metricLifecycle, bool) {
	switch value {
	case LifecyclePending:
		return lifecyclePending, true
	case LifecycleRunning:
		return lifecycleRunning, true
	case LifecyclePaused:
		return lifecyclePaused, true
	case LifecycleCompleted:
		return lifecycleCompleted, true
	default:
		return 0, false
	}
}

// TriggerCursorSnapshot is the complete persistence projection for one
// trigger cursor. LastRepeatWindow is -1 before the first repeated firing.
type TriggerCursorSnapshot struct {
	TriggerID        EntityID
	Initialized      bool
	LastObservedAt   *time.Time
	LastState        MetricState
	LastPercentage   float64
	LastRemaining    time.Duration
	LastRepeatWindow int64
	LastFiredAt      *time.Time
	FireCount        uint64
}

func (snapshot TriggerCursorSnapshot) String() string {
	return fmt.Sprintf(
		"sla.TriggerCursorSnapshot{initialized:%t,fireCount:%d,identity:[REDACTED],history:[REDACTED]}",
		snapshot.Initialized, snapshot.FireCount,
	)
}

func (snapshot TriggerCursorSnapshot) GoString() string { return snapshot.String() }

func (cursor TriggerCursor) Snapshot() TriggerCursorSnapshot {
	return TriggerCursorSnapshot{
		TriggerID: cursor.triggerID, Initialized: cursor.initialized,
		LastObservedAt: cloneTime(cursor.lastObservedAt), LastState: cursor.lastState,
		LastPercentage: cursor.lastPercentage, LastRemaining: cursor.lastRemaining,
		LastRepeatWindow: cursor.lastRepeatWindow, LastFiredAt: cloneTime(cursor.lastFiredAt),
		FireCount: cursor.fireCount,
	}
}

func RestoreTriggerCursor(snapshot TriggerCursorSnapshot) (TriggerCursor, error) {
	if !validEntityID(snapshot.TriggerID) || snapshot.LastRepeatWindow < -1 ||
		snapshot.LastRepeatWindow > int64((100*365*24*time.Hour)/time.Microsecond) ||
		math.IsNaN(snapshot.LastPercentage) || math.IsInf(snapshot.LastPercentage, 0) ||
		snapshot.LastPercentage < 0 || snapshot.LastPercentage > 100 || snapshot.LastRemaining < 0 ||
		snapshot.LastRemaining%time.Microsecond != 0 || snapshot.FireCount >= maximumVersion {
		return TriggerCursor{}, ErrInvalidMetric
	}
	if !snapshot.Initialized {
		if snapshot.LastObservedAt != nil || snapshot.LastState != "" || snapshot.LastPercentage != 0 ||
			snapshot.LastRemaining != 0 || snapshot.LastRepeatWindow != -1 || snapshot.LastFiredAt != nil ||
			snapshot.FireCount != 0 {
			return TriggerCursor{}, ErrInvalidMetric
		}
	} else if snapshot.LastObservedAt == nil || !validInstant(*snapshot.LastObservedAt) ||
		!validMetricState(snapshot.LastState) || (snapshot.LastFiredAt == nil) != (snapshot.FireCount == 0) ||
		snapshot.LastRepeatWindow >= 0 && snapshot.FireCount == 0 ||
		snapshot.LastFiredAt != nil && (!validInstant(*snapshot.LastFiredAt) || snapshot.LastFiredAt.After(*snapshot.LastObservedAt)) {
		return TriggerCursor{}, ErrInvalidMetric
	}
	return TriggerCursor{
		triggerID: snapshot.TriggerID, initialized: snapshot.Initialized,
		lastObservedAt: cloneTime(snapshot.LastObservedAt), lastState: snapshot.LastState,
		lastPercentage: snapshot.LastPercentage, lastRemaining: snapshot.LastRemaining,
		lastRepeatWindow: snapshot.LastRepeatWindow, lastFiredAt: cloneTime(snapshot.LastFiredAt),
		fireCount: snapshot.FireCount,
	}, nil
}

// Input projections return owned copies suitable for deterministic persistence
// encoders. They never expose the kernel's internal backing slices.
func (calendar BusinessCalendar) Input() BusinessCalendarInput {
	weekly := make([]WeeklyScheduleInput, 0, 7)
	for weekday, intervals := range calendar.weekly {
		if len(intervals) == 0 {
			continue
		}
		weekly = append(weekly, WeeklyScheduleInput{
			Weekday: time.Weekday(weekday), Intervals: minuteIntervalInputs(intervals),
		})
	}
	exceptions := make([]DateExceptionInput, len(calendar.exceptions))
	for index, exception := range calendar.exceptions {
		exceptions[index] = DateExceptionInput{
			Date:   fmt.Sprintf("%04d-%02d-%02d", exception.date.year, exception.date.month, exception.date.day),
			Closed: exception.closed, Intervals: minuteIntervalInputs(exception.intervals),
		}
	}
	return BusinessCalendarInput{
		ID: calendar.id, TenantID: calendar.tenantID, Key: calendar.key, Label: calendar.label,
		Timezone: calendar.timezone, Version: calendar.version,
		WeeklySchedules: weekly, Exceptions: exceptions,
	}
}

func minuteIntervalInputs(values []minuteInterval) []MinuteIntervalInput {
	result := make([]MinuteIntervalInput, len(values))
	for index, interval := range values {
		result[index] = MinuteIntervalInput{StartMinute: interval.start, EndMinute: interval.end}
	}
	return result
}

func (rule Rule) Input() *RuleInput {
	result := &RuleInput{Kind: rule.kind}
	if rule.kind == RulePredicate {
		result.Predicate = PredicateInput{
			Path: rule.predicate.path, Operator: rule.predicate.operator,
			Values: slices.Clone(rule.predicate.values),
		}
		return result
	}
	result.Children = make([]*RuleInput, len(rule.children))
	for index, child := range rule.children {
		result.Children[index] = child.Input()
	}
	return result
}

func (definition MetricDefinition) Input() MetricDefinitionInput {
	return MetricDefinitionInput{
		ID: definition.id, Key: definition.key, Label: definition.label, Description: definition.description,
		Duration: definition.duration, Clock: definition.clock, CalendarID: cloneEntityID(definition.calendarID),
		CalendarVersion: definition.calendarVersion, StartEvent: definition.startEvent,
		PauseEvent: definition.pauseEvent, ResumeEvent: definition.resumeEvent,
		CompletionEvent: definition.completionEvent, ResetEvent: definition.resetEvent,
		ResetPolicy: definition.resetPolicy, Warning: definition.warning, BreachGrace: definition.breachGrace,
		DisplayFormat: definition.displayFormat, CustomerVisible: definition.customerVisible,
		APIVisible: definition.apiVisible,
	}
}

func (definition TriggerDefinition) Input() TriggerDefinitionInput {
	return TriggerDefinitionInput{
		ID: definition.id, Key: definition.key, MetricID: definition.metricID, Kind: definition.kind,
		ConsumedPercent: definition.consumedPercent, Remaining: definition.remaining,
		Offset: definition.offset, RepeatInterval: definition.repeatInterval, TargetState: definition.targetState,
		Action: TriggerActionInput{
			Kind: definition.action.kind, ConfigurationID: cloneEntityID(definition.action.configurationID),
			Value: definition.action.value, Text: definition.action.text,
			AllowRecursiveSLA: definition.action.allowRecursiveSLA,
		},
	}
}

func (policy Policy) Input() PolicyInput {
	return PolicyInput{
		ID: policy.id, TenantID: policy.tenantID, Key: policy.key, Name: policy.name,
		Description: policy.description, Version: policy.version, Priority: policy.priority,
		ObjectTypes: slices.Clone(policy.objectTypes), MatchRule: policy.matchRule.clone(),
		Metrics: policy.Metrics(), Triggers: policy.Triggers(), EffectiveFrom: policy.effectiveFrom,
		EffectiveUntil: cloneTime(policy.effectiveUntil), Enabled: policy.enabled,
		ApplyToSLAEngineSource: policy.applyToSLAEngineSource,
	}
}

func (column ColumnDefinition) Input() ColumnDefinitionInput {
	styles := make([]ColumnStyleRuleInput, len(column.styleRules))
	for index, style := range column.styleRules {
		styles[index] = ColumnStyleRuleInput{
			StyleKey: style.styleKey, State: style.state,
			MinimumPercentage: cloneFloat64(style.minimumPercentage),
			MaximumRemaining:  cloneDuration(style.maximumRemaining),
		}
	}
	return ColumnDefinitionInput{
		ID: column.id, TenantID: column.tenantID, Key: column.key, Label: column.label,
		MetricID: column.metricID, Calculation: column.calculation, Format: column.format,
		Sortable: column.sortable, Filterable: column.filterable, CustomerVisible: column.customerVisible,
		VisibleRoleKeys: slices.Clone(column.visibleRoleKeys), Position: column.position,
		Version: column.version, StyleRules: styles,
	}
}
