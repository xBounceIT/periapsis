package sla

import (
	"context"
	"fmt"
	"math"
	"slices"
	"time"
)

type ObjectType string

const (
	ObjectAlert ObjectType = "alert"
	ObjectCase  ObjectType = "case"
	ObjectTask  ObjectType = "task"
)

func validObjectType(value ObjectType) bool {
	return value == ObjectAlert || value == ObjectCase || value == ObjectTask
}

type ClockType string

const (
	ClockElapsed  ClockType = "elapsed"
	ClockBusiness ClockType = "business"
)

type ResetPolicy string

const (
	ResetIgnore  ResetPolicy = "ignore"
	ResetClear   ResetPolicy = "clear"
	ResetRestart ResetPolicy = "restart"
)

type WarningKind string

const (
	WarningNone              WarningKind = "none"
	WarningConsumedPercent   WarningKind = "consumed_percent"
	WarningRemainingDuration WarningKind = "remaining_duration"
)

type WarningThreshold struct {
	Kind              WarningKind
	ConsumedPercent   uint8
	RemainingDuration time.Duration
}

type MetricDefinitionInput struct {
	ID              EntityID
	Key             Key
	Label           string
	Description     string
	Duration        time.Duration
	Clock           ClockType
	CalendarID      *EntityID
	CalendarVersion uint64
	StartEvent      Key
	PauseEvent      Key
	ResumeEvent     Key
	CompletionEvent Key
	ResetEvent      Key
	ResetPolicy     ResetPolicy
	Warning         WarningThreshold
	BreachGrace     time.Duration
	DisplayFormat   string
	CustomerVisible bool
	APIVisible      bool
}

type MetricDefinition struct {
	id              EntityID
	key             Key
	label           string
	description     string
	duration        time.Duration
	clock           ClockType
	calendarID      *EntityID
	calendarVersion uint64
	startEvent      Key
	pauseEvent      Key
	resumeEvent     Key
	completionEvent Key
	resetEvent      Key
	resetPolicy     ResetPolicy
	warning         WarningThreshold
	breachGrace     time.Duration
	displayFormat   string
	customerVisible bool
	apiVisible      bool
}

func NewMetricDefinition(input MetricDefinitionInput) (MetricDefinition, error) {
	calendarID := cloneEntityID(input.CalendarID)
	events := []Key{input.StartEvent, input.CompletionEvent}
	if validKey(input.PauseEvent.value) {
		events = append(events, input.PauseEvent, input.ResumeEvent)
	}
	if validKey(input.ResetEvent.value) {
		events = append(events, input.ResetEvent)
	}
	if !validEntityID(input.ID) || !validKey(input.Key.value) ||
		!validText(input.Label, maximumLabelBytes, false, false) ||
		!validText(input.Description, maximumDescription, true, true) ||
		input.Duration <= 0 || input.Duration%time.Microsecond != 0 ||
		input.Duration > 100*365*24*time.Hour ||
		(input.Clock != ClockElapsed && input.Clock != ClockBusiness) ||
		!validKey(input.StartEvent.value) || !validKey(input.CompletionEvent.value) ||
		validKey(input.PauseEvent.value) != validKey(input.ResumeEvent.value) ||
		(input.ResetPolicy == ResetIgnore) != !validKey(input.ResetEvent.value) ||
		input.ResetPolicy != ResetIgnore && input.ResetPolicy != ResetClear && input.ResetPolicy != ResetRestart ||
		!uniqueKeys(events) || !validWarning(input.Warning, input.Duration) ||
		input.BreachGrace < 0 || input.BreachGrace%time.Microsecond != 0 ||
		input.BreachGrace > input.Duration ||
		!validText(input.DisplayFormat, 128, false, false) {
		return MetricDefinition{}, ErrInvalidMetric
	}
	if input.Clock == ClockBusiness {
		if calendarID == nil || !validEntityID(*calendarID) || input.CalendarVersion == 0 || input.CalendarVersion >= maximumVersion {
			return MetricDefinition{}, ErrInvalidMetric
		}
	} else if calendarID != nil || input.CalendarVersion != 0 {
		return MetricDefinition{}, ErrInvalidMetric
	}
	return MetricDefinition{
		id: input.ID, key: input.Key, label: input.Label, description: input.Description,
		duration: input.Duration, clock: input.Clock, calendarID: calendarID,
		calendarVersion: input.CalendarVersion, startEvent: input.StartEvent,
		pauseEvent: input.PauseEvent, resumeEvent: input.ResumeEvent,
		completionEvent: input.CompletionEvent, resetEvent: input.ResetEvent,
		resetPolicy: input.ResetPolicy, warning: input.Warning, breachGrace: input.BreachGrace,
		displayFormat: input.DisplayFormat, customerVisible: input.CustomerVisible, apiVisible: input.APIVisible,
	}, nil
}

func (definition MetricDefinition) ID() EntityID            { return definition.id }
func (definition MetricDefinition) Key() Key                { return definition.key }
func (definition MetricDefinition) Label() string           { return definition.label }
func (definition MetricDefinition) Description() string     { return definition.description }
func (definition MetricDefinition) Duration() time.Duration { return definition.duration }
func (definition MetricDefinition) Clock() ClockType        { return definition.clock }
func (definition MetricDefinition) CalendarID() *EntityID {
	return cloneEntityID(definition.calendarID)
}
func (definition MetricDefinition) CalendarVersion() uint64    { return definition.calendarVersion }
func (definition MetricDefinition) StartEvent() Key            { return definition.startEvent }
func (definition MetricDefinition) PauseEvent() Key            { return definition.pauseEvent }
func (definition MetricDefinition) ResumeEvent() Key           { return definition.resumeEvent }
func (definition MetricDefinition) CompletionEvent() Key       { return definition.completionEvent }
func (definition MetricDefinition) ResetEvent() Key            { return definition.resetEvent }
func (definition MetricDefinition) ResetPolicy() ResetPolicy   { return definition.resetPolicy }
func (definition MetricDefinition) Warning() WarningThreshold  { return definition.warning }
func (definition MetricDefinition) BreachGrace() time.Duration { return definition.breachGrace }
func (definition MetricDefinition) DisplayFormat() string      { return definition.displayFormat }
func (definition MetricDefinition) CustomerVisible() bool      { return definition.customerVisible }
func (definition MetricDefinition) APIVisible() bool           { return definition.apiVisible }
func (definition MetricDefinition) String() string {
	return fmt.Sprintf(
		"sla.MetricDefinition{clock:%s,duration:%s,customerVisible:%t,apiVisible:%t,key:[REDACTED],label:[REDACTED]}",
		definition.clock, definition.duration, definition.customerVisible, definition.apiVisible,
	)
}
func (definition MetricDefinition) GoString() string { return definition.String() }

type metricLifecycle uint8

const (
	lifecyclePending metricLifecycle = iota
	lifecycleRunning
	lifecyclePaused
	lifecycleCompleted
)

type MetricState string

const (
	StatePending   MetricState = "pending"
	StateOnTrack   MetricState = "on_track"
	StateAtRisk    MetricState = "at_risk"
	StatePaused    MetricState = "paused"
	StateBreached  MetricState = "breached"
	StateCompleted MetricState = "completed"
)

type MetricInstanceInput struct {
	ID            EntityID
	SLAInstanceID EntityID
	TenantID      EntityID
	ObjectType    ObjectType
	ObjectID      EntityID
	PolicyID      EntityID
	PolicyVersion uint64
	Definition    MetricDefinition
	CreatedAt     time.Time
}

type MetricInstance struct {
	id                 EntityID
	slaInstanceID      EntityID
	tenantID           EntityID
	objectType         ObjectType
	objectID           EntityID
	policyID           EntityID
	policyVersion      uint64
	definition         MetricDefinition
	createdAt          time.Time
	updatedAt          time.Time
	extension          time.Duration
	lifecycle          metricLifecycle
	startedAt          *time.Time
	lastResumedAt      *time.Time
	pausedAt           *time.Time
	completedAt        *time.Time
	dueAt              *time.Time
	breachThresholdAt  *time.Time
	breachedAt         *time.Time
	consumed           time.Duration
	lastEventID        *EntityID
	lastEventKey       Key
	lastEventAt        *time.Time
	lastOverrideID     *EntityID
	lastOverrideDigest [32]byte
	version            uint64
}

func NewMetricInstance(input MetricInstanceInput) (MetricInstance, error) {
	if !validEntityID(input.ID) || !validEntityID(input.SLAInstanceID) || !validEntityID(input.TenantID) ||
		input.ID == input.SLAInstanceID || !validObjectType(input.ObjectType) ||
		!validEntityID(input.ObjectID) || !validEntityID(input.PolicyID) ||
		input.PolicyVersion == 0 || input.PolicyVersion >= maximumVersion ||
		!input.Definition.valid() || !validInstant(input.CreatedAt) {
		return MetricInstance{}, ErrInvalidMetric
	}
	return MetricInstance{
		id: input.ID, slaInstanceID: input.SLAInstanceID, tenantID: input.TenantID, objectType: input.ObjectType,
		objectID: input.ObjectID, policyID: input.PolicyID, policyVersion: input.PolicyVersion,
		definition: input.Definition.clone(), createdAt: input.CreatedAt, updatedAt: input.CreatedAt,
		lifecycle: lifecyclePending, version: 1,
	}, nil
}

func (instance MetricInstance) ID() EntityID                 { return instance.id }
func (instance MetricInstance) SLAInstanceID() EntityID      { return instance.slaInstanceID }
func (instance MetricInstance) TenantID() EntityID           { return instance.tenantID }
func (instance MetricInstance) ObjectType() ObjectType       { return instance.objectType }
func (instance MetricInstance) ObjectID() EntityID           { return instance.objectID }
func (instance MetricInstance) PolicyID() EntityID           { return instance.policyID }
func (instance MetricInstance) PolicyVersion() uint64        { return instance.policyVersion }
func (instance MetricInstance) Definition() MetricDefinition { return instance.definition.clone() }
func (instance MetricInstance) CreatedAt() time.Time         { return instance.createdAt }
func (instance MetricInstance) UpdatedAt() time.Time         { return instance.updatedAt }
func (instance MetricInstance) StartedAt() *time.Time        { return cloneTime(instance.startedAt) }
func (instance MetricInstance) PausedAt() *time.Time         { return cloneTime(instance.pausedAt) }
func (instance MetricInstance) CompletedAt() *time.Time      { return cloneTime(instance.completedAt) }
func (instance MetricInstance) DueAt() *time.Time            { return cloneTime(instance.dueAt) }
func (instance MetricInstance) BreachedAt() *time.Time       { return cloneTime(instance.breachedAt) }
func (instance MetricInstance) Consumed() time.Duration      { return instance.consumed }
func (instance MetricInstance) Extension() time.Duration     { return instance.extension }
func (instance MetricInstance) EffectiveDuration() time.Duration {
	return instance.effectiveDuration()
}
func (instance MetricInstance) Version() uint64 { return instance.version }
func (instance MetricInstance) String() string {
	return fmt.Sprintf(
		"sla.MetricInstance{lifecycle:%d,clock:%s,version:%d,consumed:%s,identity:[REDACTED]}",
		instance.lifecycle, instance.definition.clock, instance.version, instance.consumed,
	)
}
func (instance MetricInstance) GoString() string { return instance.String() }

type MetricEvent struct {
	ID         EntityID
	TenantID   EntityID
	ObjectID   EntityID
	Key        Key
	OccurredAt time.Time
}

func (event MetricEvent) String() string {
	return fmt.Sprintf("sla.MetricEvent{occurredAt:%s,identity:[REDACTED],key:[REDACTED]}", event.OccurredAt.Format(time.RFC3339))
}
func (event MetricEvent) GoString() string { return event.String() }

// Observe checkpoints a running metric at a timer boundary. It advances only
// version-pinned clock state; it does not synthesize a domain event. Paused,
// pending, and completed observations remain no-ops. Closed-business-time
// observations remain no-ops unless the persisted breach threshold is crossed.
func (instance MetricInstance) Observe(
	expectedVersion uint64,
	at time.Time,
	calendar *BusinessCalendar,
) (MetricInstance, bool, error) {
	return instance.observeContext(context.Background(), expectedVersion, at, calendar)
}

func (instance MetricInstance) observeContext(
	ctx context.Context,
	expectedVersion uint64,
	at time.Time,
	calendar *BusinessCalendar,
) (MetricInstance, bool, error) {
	if ctx == nil || ctx.Err() != nil {
		return MetricInstance{}, false, ErrEngineCanceled
	}
	if expectedVersion != instance.version {
		return MetricInstance{}, false, ErrMetricConflict
	}
	if !instance.valid() || !validInstant(at) || at.Before(instance.updatedAt) ||
		at.Sub(instance.createdAt) > 100*365*24*time.Hour || !instance.matchesCalendar(calendar) {
		return MetricInstance{}, false, ErrInvalidMetric
	}
	if instance.lifecycle != lifecycleRunning || at.Equal(instance.updatedAt) {
		return instance.clone(), false, nil
	}
	elapsed, err := instance.elapsedBetweenContext(ctx, *instance.lastResumedAt, at, calendar)
	if err != nil {
		return MetricInstance{}, false, err
	}
	updated := instance.clone()
	wasBreached := updated.breachedAt != nil
	updated.consumed += elapsed
	updated.recordBreach(at)
	if elapsed == 0 && wasBreached == (updated.breachedAt != nil) {
		return instance.clone(), false, nil
	}
	if updated.version >= maximumVersion-1 {
		return MetricInstance{}, false, ErrMetricConflict
	}
	updated.lastResumedAt = cloneTime(&at)
	updated.updatedAt = at
	updated.version++
	return updated, true, nil
}

func (instance MetricInstance) ApplyEvent(
	expectedVersion uint64,
	event MetricEvent,
	calendar *BusinessCalendar,
) (MetricInstance, bool, error) {
	return instance.ApplyEventContext(context.Background(), expectedVersion, event, calendar)
}

// ApplyEventContext applies one ordered domain event with cooperative
// cancellation through business-calendar calculations.
func (instance MetricInstance) ApplyEventContext(
	ctx context.Context,
	expectedVersion uint64,
	event MetricEvent,
	calendar *BusinessCalendar,
) (MetricInstance, bool, error) {
	if ctx == nil || ctx.Err() != nil {
		return MetricInstance{}, false, ErrEngineCanceled
	}
	if expectedVersion != instance.version {
		return MetricInstance{}, false, ErrMetricConflict
	}
	if !instance.valid() || !instance.validEvent(event) || !instance.matchesCalendar(calendar) {
		return MetricInstance{}, false, ErrInvalidEvent
	}
	if instance.lastEventID != nil && *instance.lastEventID == event.ID {
		if instance.lastEventKey == event.Key && instance.lastEventAt != nil && instance.lastEventAt.Equal(event.OccurredAt) {
			return instance.clone(), false, nil
		}
		return MetricInstance{}, false, ErrInvalidEvent
	}
	action := instance.definition.actionFor(event.Key)
	if action == metricActionNone {
		return instance.clone(), false, nil
	}
	updated := instance.clone()
	if updated.lifecycle == lifecycleRunning {
		elapsed, err := updated.elapsedBetweenContext(ctx, *updated.lastResumedAt, event.OccurredAt, calendar)
		if err != nil {
			return MetricInstance{}, false, err
		}
		updated.consumed += elapsed
		updated.recordBreach(event.OccurredAt)
	}

	changed, err := updated.applyActionContext(ctx, action, event.OccurredAt, calendar)
	if err != nil {
		return MetricInstance{}, false, err
	}
	if !changed {
		return instance.clone(), false, nil
	}
	if updated.version >= maximumVersion-1 {
		return MetricInstance{}, false, ErrMetricConflict
	}
	updated.lastEventID = cloneEntityID(&event.ID)
	updated.lastEventKey = event.Key
	updated.lastEventAt = cloneTime(&event.OccurredAt)
	updated.updatedAt = event.OccurredAt
	updated.version++
	return updated, true, nil
}

type metricAction uint8

const (
	metricActionNone metricAction = iota
	metricActionStart
	metricActionPause
	metricActionResume
	metricActionComplete
	metricActionReset
)

func (definition MetricDefinition) actionFor(key Key) metricAction {
	switch key {
	case definition.startEvent:
		return metricActionStart
	case definition.pauseEvent:
		if validKey(definition.pauseEvent.value) {
			return metricActionPause
		}
	case definition.resumeEvent:
		if validKey(definition.resumeEvent.value) {
			return metricActionResume
		}
	case definition.completionEvent:
		return metricActionComplete
	case definition.resetEvent:
		if validKey(definition.resetEvent.value) {
			return metricActionReset
		}
	}
	return metricActionNone
}

func (instance *MetricInstance) applyActionContext(
	ctx context.Context,
	action metricAction,
	at time.Time,
	calendar *BusinessCalendar,
) (bool, error) {
	switch action {
	case metricActionStart:
		if instance.lifecycle != lifecyclePending {
			return false, nil
		}
		return true, instance.startContext(ctx, at, calendar)
	case metricActionPause:
		if instance.lifecycle != lifecycleRunning {
			return false, nil
		}
		instance.lifecycle = lifecyclePaused
		instance.pausedAt = cloneTime(&at)
		instance.lastResumedAt = nil
		return true, nil
	case metricActionResume:
		if instance.lifecycle != lifecyclePaused {
			return false, nil
		}
		instance.lifecycle = lifecycleRunning
		instance.pausedAt = nil
		instance.lastResumedAt = cloneTime(&at)
		return true, instance.recalculateDeadlinesContext(ctx, at, calendar)
	case metricActionComplete:
		if instance.lifecycle != lifecycleRunning && instance.lifecycle != lifecyclePaused {
			return false, nil
		}
		instance.lifecycle = lifecycleCompleted
		instance.completedAt = cloneTime(&at)
		instance.lastResumedAt = nil
		instance.pausedAt = nil
		return true, nil
	case metricActionReset:
		switch instance.definition.resetPolicy {
		case ResetClear:
			instance.clearRuntime()
			return true, nil
		case ResetRestart:
			instance.clearRuntime()
			return true, instance.startContext(ctx, at, calendar)
		default:
			return false, nil
		}
	default:
		return false, nil
	}
}

func (instance *MetricInstance) startContext(ctx context.Context, at time.Time, calendar *BusinessCalendar) error {
	instance.lifecycle = lifecycleRunning
	instance.startedAt = cloneTime(&at)
	instance.lastResumedAt = cloneTime(&at)
	return instance.recalculateDeadlinesContext(ctx, at, calendar)
}

func (instance *MetricInstance) clearRuntime() {
	instance.lifecycle = lifecyclePending
	instance.startedAt = nil
	instance.lastResumedAt = nil
	instance.pausedAt = nil
	instance.completedAt = nil
	instance.dueAt = nil
	instance.breachThresholdAt = nil
	instance.breachedAt = nil
	instance.consumed = 0
}

func (instance *MetricInstance) recalculateDeadlinesContext(
	ctx context.Context,
	at time.Time,
	calendar *BusinessCalendar,
) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrEngineCanceled
	}
	dueRemaining := instance.effectiveDuration() - instance.consumed
	if dueRemaining < 0 {
		dueRemaining = 0
	}
	breachRemaining := instance.effectiveDuration() + instance.definition.breachGrace - instance.consumed
	if breachRemaining < 0 {
		breachRemaining = 0
	}
	dueAt, err := instance.addClockTimeContext(ctx, at, dueRemaining, calendar)
	if err != nil {
		return err
	}
	breachAt, err := instance.addClockTimeContext(ctx, at, breachRemaining, calendar)
	if err != nil {
		return err
	}
	instance.dueAt = cloneTime(&dueAt)
	instance.breachThresholdAt = cloneTime(&breachAt)
	return nil
}

func (instance *MetricInstance) recordBreach(observedAt time.Time) {
	if instance.breachedAt == nil && instance.breachThresholdAt != nil && !observedAt.Before(*instance.breachThresholdAt) {
		instance.breachedAt = cloneTime(instance.breachThresholdAt)
	}
}

type MetricEvaluation struct {
	State              MetricState
	StartedAt          *time.Time
	DueAt              *time.Time
	Remaining          time.Duration
	ConsumedPercentage float64
	BreachedAt         *time.Time
	CompletedAt        *time.Time
}

func (instance MetricInstance) Evaluate(at time.Time, calendar *BusinessCalendar) (MetricEvaluation, error) {
	return instance.EvaluateContext(context.Background(), at, calendar)
}

// EvaluateContext evaluates a projection while honoring cancellation inside
// business-time traversal.
func (instance MetricInstance) EvaluateContext(
	ctx context.Context,
	at time.Time,
	calendar *BusinessCalendar,
) (MetricEvaluation, error) {
	if ctx == nil || ctx.Err() != nil {
		return MetricEvaluation{}, ErrEngineCanceled
	}
	if !instance.valid() || !validInstant(at) || at.Before(instance.createdAt) ||
		at.Before(instance.updatedAt) || !instance.matchesCalendar(calendar) {
		return MetricEvaluation{}, ErrInvalidMetric
	}
	consumed := instance.consumed
	if instance.lifecycle == lifecycleRunning {
		elapsed, err := instance.elapsedBetweenContext(ctx, *instance.lastResumedAt, at, calendar)
		if err != nil {
			return MetricEvaluation{}, err
		}
		consumed += elapsed
	}
	remaining := instance.effectiveDuration() - consumed
	if remaining < 0 {
		remaining = 0
	}
	percentage := math.Min(100, float64(consumed)*100/float64(instance.effectiveDuration()))
	breachedAt := cloneTime(instance.breachedAt)
	if breachedAt == nil && instance.lifecycle != lifecycleCompleted && instance.lifecycle != lifecyclePaused &&
		instance.breachThresholdAt != nil && !at.Before(*instance.breachThresholdAt) {
		breachedAt = cloneTime(instance.breachThresholdAt)
	}
	state := StateOnTrack
	switch instance.lifecycle {
	case lifecyclePending:
		state = StatePending
	case lifecyclePaused:
		if breachedAt != nil {
			state = StateBreached
		} else {
			state = StatePaused
		}
	case lifecycleCompleted:
		state = StateCompleted
	default:
		if breachedAt != nil {
			state = StateBreached
		} else if warningReached(instance.definition.warning, consumed, remaining) {
			state = StateAtRisk
		}
	}
	return MetricEvaluation{
		State: state, StartedAt: cloneTime(instance.startedAt), DueAt: cloneTime(instance.dueAt),
		Remaining: remaining, ConsumedPercentage: percentage, BreachedAt: breachedAt,
		CompletedAt: cloneTime(instance.completedAt),
	}, nil
}

func (instance MetricInstance) elapsedBetweenContext(
	ctx context.Context,
	start time.Time,
	end time.Time,
	calendar *BusinessCalendar,
) (time.Duration, error) {
	if ctx == nil || ctx.Err() != nil {
		return 0, ErrEngineCanceled
	}
	if end.Before(start) || end.Sub(start) > 100*365*24*time.Hour {
		return 0, ErrInvalidEvent
	}
	if instance.definition.clock == ClockElapsed {
		return end.Sub(start), nil
	}
	return calendar.BusinessElapsedContext(ctx, start, end)
}

func (instance MetricInstance) addClockTimeContext(
	ctx context.Context,
	start time.Time,
	duration time.Duration,
	calendar *BusinessCalendar,
) (time.Time, error) {
	if ctx == nil || ctx.Err() != nil {
		return time.Time{}, ErrEngineCanceled
	}
	var result time.Time
	var err error
	if instance.definition.clock == ClockElapsed {
		result = start.Add(duration)
	} else {
		result, err = calendar.AddBusinessTimeContext(ctx, start, duration)
	}
	if err != nil || !validInstant(result) {
		return time.Time{}, ErrCalendarRange
	}
	return result, nil
}

func (instance MetricInstance) matchesCalendar(calendar *BusinessCalendar) bool {
	if instance.definition.clock == ClockElapsed {
		return calendar == nil
	}
	return calendar != nil && calendar.tenantID == instance.tenantID &&
		instance.definition.calendarID != nil && calendar.id == *instance.definition.calendarID &&
		calendar.version == instance.definition.calendarVersion && calendar.valid()
}

func (instance MetricInstance) validEvent(event MetricEvent) bool {
	return validEntityID(event.ID) && event.TenantID == instance.tenantID && event.ObjectID == instance.objectID &&
		validKey(event.Key.value) && validInstant(event.OccurredAt) && !event.OccurredAt.Before(instance.createdAt) &&
		event.OccurredAt.Sub(instance.createdAt) <= 100*365*24*time.Hour &&
		!event.OccurredAt.Before(instance.updatedAt)
}

func (instance MetricInstance) valid() bool {
	if !validEntityID(instance.id) || !validEntityID(instance.slaInstanceID) || instance.id == instance.slaInstanceID ||
		!validEntityID(instance.tenantID) || !validObjectType(instance.objectType) ||
		!validEntityID(instance.objectID) || !validEntityID(instance.policyID) || instance.policyVersion == 0 ||
		instance.policyVersion >= maximumVersion || !instance.definition.valid() || !validInstant(instance.createdAt) ||
		instance.version == 0 || instance.version >= maximumVersion || instance.consumed < 0 ||
		!validInstant(instance.updatedAt) || instance.updatedAt.Before(instance.createdAt) ||
		instance.extension < 0 || instance.extension > 100*365*24*time.Hour-instance.definition.duration {
		return false
	}
	if (instance.lastEventID == nil) != (instance.lastEventAt == nil) ||
		(instance.lastEventID == nil) != !validKey(instance.lastEventKey.value) {
		return false
	}
	if instance.lastEventID != nil && (!validEntityID(*instance.lastEventID) || !validInstant(*instance.lastEventAt) ||
		instance.lastEventAt.Before(instance.createdAt)) {
		return false
	}
	if instance.breachedAt != nil && (!validInstant(*instance.breachedAt) ||
		instance.breachedAt.Before(instance.createdAt) || instance.breachedAt.After(instance.updatedAt)) {
		return false
	}
	if (instance.lastOverrideID == nil) != zeroDigest(instance.lastOverrideDigest) ||
		instance.lastOverrideID != nil && !validEntityID(*instance.lastOverrideID) ||
		instance.lastEventAt != nil && instance.lastEventAt.After(instance.updatedAt) {
		return false
	}
	validDeadline := func(value *time.Time) bool {
		return value != nil && validInstant(*value) && !value.Before(instance.createdAt)
	}
	switch instance.lifecycle {
	case lifecyclePending:
		return instance.startedAt == nil && instance.lastResumedAt == nil && instance.pausedAt == nil &&
			instance.completedAt == nil && instance.dueAt == nil && instance.breachThresholdAt == nil &&
			instance.breachedAt == nil && instance.consumed == 0
	case lifecycleRunning:
		return validDeadline(instance.startedAt) && validDeadline(instance.lastResumedAt) &&
			!instance.lastResumedAt.Before(*instance.startedAt) &&
			instance.pausedAt == nil && instance.completedAt == nil && validDeadline(instance.dueAt) &&
			validDeadline(instance.breachThresholdAt) && !instance.breachThresholdAt.Before(*instance.dueAt)
	case lifecyclePaused:
		return validDeadline(instance.startedAt) && instance.lastResumedAt == nil && validDeadline(instance.pausedAt) &&
			!instance.pausedAt.Before(*instance.startedAt) &&
			instance.completedAt == nil && validDeadline(instance.dueAt) && validDeadline(instance.breachThresholdAt) &&
			!instance.breachThresholdAt.Before(*instance.dueAt)
	case lifecycleCompleted:
		return validDeadline(instance.startedAt) && instance.lastResumedAt == nil && instance.pausedAt == nil &&
			validDeadline(instance.completedAt) && !instance.completedAt.Before(*instance.startedAt) && validDeadline(instance.dueAt) &&
			validDeadline(instance.breachThresholdAt) && !instance.breachThresholdAt.Before(*instance.dueAt)
	default:
		return false
	}
}

func (instance MetricInstance) effectiveDuration() time.Duration {
	return instance.definition.duration + instance.extension
}

func (instance MetricInstance) clone() MetricInstance {
	result := instance
	result.definition = instance.definition.clone()
	result.startedAt = cloneTime(instance.startedAt)
	result.lastResumedAt = cloneTime(instance.lastResumedAt)
	result.pausedAt = cloneTime(instance.pausedAt)
	result.completedAt = cloneTime(instance.completedAt)
	result.dueAt = cloneTime(instance.dueAt)
	result.breachThresholdAt = cloneTime(instance.breachThresholdAt)
	result.breachedAt = cloneTime(instance.breachedAt)
	result.lastEventID = cloneEntityID(instance.lastEventID)
	result.lastEventAt = cloneTime(instance.lastEventAt)
	result.lastOverrideID = cloneEntityID(instance.lastOverrideID)
	return result
}

func (definition MetricDefinition) valid() bool {
	calendarID := cloneEntityID(definition.calendarID)
	canonical, err := NewMetricDefinition(MetricDefinitionInput{
		ID: definition.id, Key: definition.key, Label: definition.label, Description: definition.description,
		Duration: definition.duration, Clock: definition.clock, CalendarID: calendarID,
		CalendarVersion: definition.calendarVersion, StartEvent: definition.startEvent,
		PauseEvent: definition.pauseEvent, ResumeEvent: definition.resumeEvent,
		CompletionEvent: definition.completionEvent, ResetEvent: definition.resetEvent,
		ResetPolicy: definition.resetPolicy, Warning: definition.warning, BreachGrace: definition.breachGrace,
		DisplayFormat: definition.displayFormat, CustomerVisible: definition.customerVisible, APIVisible: definition.apiVisible,
	})
	return err == nil && canonical.id == definition.id && canonical.key == definition.key &&
		canonical.duration == definition.duration && canonical.clock == definition.clock
}

func (definition MetricDefinition) clone() MetricDefinition {
	result := definition
	result.calendarID = cloneEntityID(definition.calendarID)
	return result
}

func cloneEntityID(value *EntityID) *EntityID {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func uniqueKeys(values []Key) bool {
	copy := slices.Clone(values)
	for _, value := range copy {
		if !validKey(value.value) {
			return false
		}
	}
	slices.SortFunc(copy, func(left, right Key) int {
		if left.value < right.value {
			return -1
		}
		if left.value > right.value {
			return 1
		}
		return 0
	})
	for index := 1; index < len(copy); index++ {
		if copy[index-1] == copy[index] {
			return false
		}
	}
	return true
}

func validWarning(warning WarningThreshold, duration time.Duration) bool {
	switch warning.Kind {
	case WarningNone:
		return warning.ConsumedPercent == 0 && warning.RemainingDuration == 0
	case WarningConsumedPercent:
		return warning.ConsumedPercent > 0 && warning.ConsumedPercent < 100 && warning.RemainingDuration == 0
	case WarningRemainingDuration:
		return warning.ConsumedPercent == 0 && warning.RemainingDuration > 0 &&
			warning.RemainingDuration < duration && warning.RemainingDuration%time.Microsecond == 0
	default:
		return false
	}
}

func warningReached(warning WarningThreshold, consumed, remaining time.Duration) bool {
	switch warning.Kind {
	case WarningConsumedPercent:
		total := consumed + remaining
		return total > 0 && float64(consumed)*100/float64(total) >= float64(warning.ConsumedPercent)
	case WarningRemainingDuration:
		return remaining <= warning.RemainingDuration
	default:
		return false
	}
}
