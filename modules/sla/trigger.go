package sla

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"
)

type TriggerKind string

const (
	TriggerConsumedPercent TriggerKind = "consumed_percent"
	TriggerRemaining       TriggerKind = "remaining_duration"
	TriggerDue             TriggerKind = "due"
	TriggerAfterBreach     TriggerKind = "after_breach"
	TriggerRepeatedBreach  TriggerKind = "repeated_after_breach"
	TriggerStateChanged    TriggerKind = "state_changed"
	TriggerResumed         TriggerKind = "resumed"
)

type ActionKind string

const (
	ActionEmail             ActionKind = "email"
	ActionWebhook           ActionKind = "webhook"
	ActionAddTag            ActionKind = "add_tag"
	ActionChangePriority    ActionKind = "change_priority"
	ActionAssignTeam        ActionKind = "assign_operator_team"
	ActionCreateTask        ActionKind = "create_task"
	ActionCreateSystemAlert ActionKind = "create_system_alert"
	ActionDomainEvent       ActionKind = "domain_event"
)

type TriggerActionInput struct {
	Kind              ActionKind
	ConfigurationID   *EntityID
	Value             Key
	Text              string
	AllowRecursiveSLA bool
}

type TriggerAction struct {
	kind              ActionKind
	configurationID   *EntityID
	value             Key
	text              string
	allowRecursiveSLA bool
}

func (action TriggerAction) Kind() ActionKind           { return action.kind }
func (action TriggerAction) ConfigurationID() *EntityID { return cloneEntityID(action.configurationID) }
func (action TriggerAction) Value() Key                 { return action.value }
func (action TriggerAction) Text() string               { return action.text }
func (action TriggerAction) AllowRecursiveSLA() bool    { return action.allowRecursiveSLA }
func (action TriggerAction) SystemAlertSource() string {
	if action.kind == ActionCreateSystemAlert {
		return "sla-engine"
	}
	return ""
}

type TriggerDefinitionInput struct {
	ID              EntityID
	Key             Key
	MetricID        EntityID
	Kind            TriggerKind
	ConsumedPercent uint8
	Remaining       time.Duration
	Offset          time.Duration
	RepeatInterval  time.Duration
	TargetState     MetricState
	Action          TriggerActionInput
}

type TriggerDefinition struct {
	id              EntityID
	key             Key
	metricID        EntityID
	kind            TriggerKind
	consumedPercent uint8
	remaining       time.Duration
	offset          time.Duration
	repeatInterval  time.Duration
	targetState     MetricState
	action          TriggerAction
}

func NewTriggerDefinition(metric MetricDefinition, input TriggerDefinitionInput) (TriggerDefinition, error) {
	action, ok := canonicalTriggerAction(input.Action)
	if !metric.valid() || !validEntityID(input.ID) || !validKey(input.Key.value) ||
		input.MetricID != metric.id || !validTriggerShape(metric, input) || !ok {
		return TriggerDefinition{}, ErrInvalidMetric
	}
	return TriggerDefinition{
		id: input.ID, key: input.Key, metricID: input.MetricID, kind: input.Kind,
		consumedPercent: input.ConsumedPercent, remaining: input.Remaining,
		offset: input.Offset, repeatInterval: input.RepeatInterval,
		targetState: input.TargetState, action: action,
	}, nil
}

func (definition TriggerDefinition) ID() EntityID                  { return definition.id }
func (definition TriggerDefinition) Key() Key                      { return definition.key }
func (definition TriggerDefinition) MetricID() EntityID            { return definition.metricID }
func (definition TriggerDefinition) Kind() TriggerKind             { return definition.kind }
func (definition TriggerDefinition) ConsumedPercent() uint8        { return definition.consumedPercent }
func (definition TriggerDefinition) Remaining() time.Duration      { return definition.remaining }
func (definition TriggerDefinition) Offset() time.Duration         { return definition.offset }
func (definition TriggerDefinition) RepeatInterval() time.Duration { return definition.repeatInterval }
func (definition TriggerDefinition) TargetState() MetricState      { return definition.targetState }
func (definition TriggerDefinition) Action() TriggerAction         { return definition.action.clone() }
func (definition TriggerDefinition) String() string {
	return fmt.Sprintf(
		"sla.TriggerDefinition{kind:%s,action:%s,key:[REDACTED],target:[REDACTED]}",
		definition.kind, definition.action.kind,
	)
}
func (definition TriggerDefinition) GoString() string { return definition.String() }

type TriggerCursor struct {
	triggerID        EntityID
	initialized      bool
	lastObservedAt   *time.Time
	lastState        MetricState
	lastPercentage   float64
	lastRemaining    time.Duration
	lastRepeatWindow int64
	lastFiredAt      *time.Time
	fireCount        uint64
}

func NewTriggerCursor(triggerID EntityID) (TriggerCursor, error) {
	if !validEntityID(triggerID) {
		return TriggerCursor{}, ErrInvalidMetric
	}
	return TriggerCursor{triggerID: triggerID, lastRepeatWindow: -1}, nil
}

func (cursor TriggerCursor) TriggerID() EntityID          { return cursor.triggerID }
func (cursor TriggerCursor) Initialized() bool            { return cursor.initialized }
func (cursor TriggerCursor) LastObservedAt() *time.Time   { return cloneTime(cursor.lastObservedAt) }
func (cursor TriggerCursor) LastState() MetricState       { return cursor.lastState }
func (cursor TriggerCursor) LastPercentage() float64      { return cursor.lastPercentage }
func (cursor TriggerCursor) LastRemaining() time.Duration { return cursor.lastRemaining }
func (cursor TriggerCursor) LastFiredAt() *time.Time      { return cloneTime(cursor.lastFiredAt) }
func (cursor TriggerCursor) FireCount() uint64            { return cursor.fireCount }
func (cursor TriggerCursor) String() string {
	return fmt.Sprintf("sla.TriggerCursor{initialized:%t,identity:[REDACTED],history:[REDACTED]}", cursor.initialized)
}
func (cursor TriggerCursor) GoString() string { return cursor.String() }

type TriggerOccurrence struct {
	id          EntityID
	triggerID   EntityID
	metricID    EntityID
	scheduledAt time.Time
	dedupKey    [32]byte
	action      TriggerAction
}

func (occurrence TriggerOccurrence) ID() EntityID               { return occurrence.id }
func (occurrence TriggerOccurrence) TriggerID() EntityID        { return occurrence.triggerID }
func (occurrence TriggerOccurrence) MetricID() EntityID         { return occurrence.metricID }
func (occurrence TriggerOccurrence) ScheduledAt() time.Time     { return occurrence.scheduledAt }
func (occurrence TriggerOccurrence) DeduplicationKey() [32]byte { return occurrence.dedupKey }
func (occurrence TriggerOccurrence) Action() TriggerAction      { return occurrence.action.clone() }
func (occurrence TriggerOccurrence) String() string {
	return fmt.Sprintf(
		"sla.TriggerOccurrence{scheduledAt:%s,action:%s,identity:[REDACTED],dedup:[REDACTED]}",
		occurrence.scheduledAt.Format(time.RFC3339), occurrence.action.kind,
	)
}
func (occurrence TriggerOccurrence) GoString() string { return occurrence.String() }

// ObserveTrigger materializes exactly one firing for the newest threshold
// window. Missed repeated windows collapse into the current window so recovery
// cannot create an unbounded notification storm.
func ObserveTrigger(
	instance MetricInstance,
	definition TriggerDefinition,
	cursor TriggerCursor,
	observedAt time.Time,
	calendar *BusinessCalendar,
	resumed bool,
) (TriggerCursor, *TriggerOccurrence, error) {
	return ObserveTriggerContext(
		context.Background(), instance, definition, cursor, observedAt, calendar, resumed,
	)
}

// ObserveTriggerContext is ObserveTrigger with cancellation propagated into
// business-time metric evaluation.
func ObserveTriggerContext(
	ctx context.Context,
	instance MetricInstance,
	definition TriggerDefinition,
	cursor TriggerCursor,
	observedAt time.Time,
	calendar *BusinessCalendar,
	resumed bool,
) (TriggerCursor, *TriggerOccurrence, error) {
	if ctx == nil || ctx.Err() != nil {
		return TriggerCursor{}, nil, ErrEngineCanceled
	}
	if !instance.valid() || !definition.validFor(instance.definition) || cursor.triggerID != definition.id ||
		!validInstant(observedAt) || cursor.initialized && (cursor.lastObservedAt == nil || observedAt.Before(*cursor.lastObservedAt)) {
		return TriggerCursor{}, nil, ErrInvalidMetric
	}
	evaluation, err := instance.EvaluateContext(ctx, observedAt, calendar)
	if err != nil {
		return TriggerCursor{}, nil, err
	}
	fire, scheduledAt, repeatWindow := definition.shouldFire(cursor, evaluation, observedAt, resumed)
	if fire && (!validInstant(scheduledAt) || cursor.fireCount >= maximumVersion-1) {
		return TriggerCursor{}, nil, ErrInvalidMetric
	}
	updated := cursor
	updated.initialized = true
	updated.lastObservedAt = cloneTime(&observedAt)
	updated.lastState = evaluation.State
	updated.lastPercentage = evaluation.ConsumedPercentage
	updated.lastRemaining = evaluation.Remaining
	if repeatWindow >= 0 {
		updated.lastRepeatWindow = repeatWindow
	}
	if !fire {
		return updated, nil, nil
	}
	updated.lastFiredAt = cloneTime(&observedAt)
	updated.fireCount++
	deduplicationKey := triggerDeduplicationKey(instance, definition, scheduledAt, repeatWindow)
	occurrenceID, err := triggerOccurrenceID(scheduledAt, deduplicationKey)
	if err != nil {
		return TriggerCursor{}, nil, err
	}
	occurrence := TriggerOccurrence{
		id:        occurrenceID,
		triggerID: definition.id, metricID: definition.metricID, scheduledAt: scheduledAt,
		dedupKey: deduplicationKey,
		action:   definition.action.clone(),
	}
	return updated, &occurrence, nil
}

func (definition TriggerDefinition) shouldFire(
	cursor TriggerCursor,
	evaluation MetricEvaluation,
	observedAt time.Time,
	resumed bool,
) (bool, time.Time, int64) {
	switch definition.kind {
	case TriggerConsumedPercent:
		fire := evaluation.State != StateCompleted && evaluation.ConsumedPercentage >= float64(definition.consumedPercent) &&
			(!cursor.initialized || cursor.lastPercentage < float64(definition.consumedPercent))
		return fire, observedAt, -1
	case TriggerRemaining:
		fire := evaluation.State != StatePending && evaluation.State != StateCompleted && evaluation.Remaining <= definition.remaining &&
			(!cursor.initialized || cursor.lastRemaining > definition.remaining)
		return fire, observedAt, -1
	case TriggerDue:
		if evaluation.DueAt == nil {
			return false, time.Time{}, -1
		}
		if evaluation.CompletedAt != nil && !evaluation.CompletedAt.After(*evaluation.DueAt) {
			return false, time.Time{}, -1
		}
		fire := !observedAt.Before(*evaluation.DueAt) &&
			(!cursor.initialized || cursor.lastObservedAt.Before(*evaluation.DueAt))
		return fire, *evaluation.DueAt, -1
	case TriggerAfterBreach:
		if evaluation.BreachedAt == nil {
			return false, time.Time{}, -1
		}
		scheduled := evaluation.BreachedAt.Add(definition.offset)
		if evaluation.CompletedAt != nil && !evaluation.CompletedAt.After(scheduled) {
			return false, time.Time{}, -1
		}
		fire := !observedAt.Before(scheduled) && (!cursor.initialized || cursor.lastObservedAt.Before(scheduled))
		return fire, scheduled, -1
	case TriggerRepeatedBreach:
		if evaluation.BreachedAt == nil {
			return false, time.Time{}, -1
		}
		first := evaluation.BreachedAt.Add(definition.offset)
		effectiveObservedAt := observedAt
		if evaluation.CompletedAt != nil {
			if !evaluation.CompletedAt.After(first) {
				return false, time.Time{}, -1
			}
			// A completion at the exact scheduled instant wins over the
			// trigger. Instants are canonicalized to microseconds, so this
			// produces the latest window strictly before completion.
			completionBoundary := evaluation.CompletedAt.Add(-time.Microsecond)
			if completionBoundary.Before(effectiveObservedAt) {
				effectiveObservedAt = completionBoundary
			}
		}
		if effectiveObservedAt.Before(first) {
			return false, time.Time{}, -1
		}
		window := int64(effectiveObservedAt.Sub(first) / definition.repeatInterval)
		scheduled := first.Add(time.Duration(window) * definition.repeatInterval)
		return window > cursor.lastRepeatWindow, scheduled, window
	case TriggerStateChanged:
		return evaluation.State == definition.targetState && (!cursor.initialized || cursor.lastState != definition.targetState), observedAt, -1
	case TriggerResumed:
		return resumed, observedAt, -1
	default:
		return false, time.Time{}, -1
	}
}

func validTriggerShape(metric MetricDefinition, input TriggerDefinitionInput) bool {
	zeroDurationFields := func() bool {
		return input.ConsumedPercent == 0 && input.Remaining == 0 && input.Offset == 0 &&
			input.RepeatInterval == 0 && input.TargetState == ""
	}
	switch input.Kind {
	case TriggerConsumedPercent:
		return input.ConsumedPercent > 0 && input.ConsumedPercent <= 100 && input.Remaining == 0 &&
			input.Offset == 0 && input.RepeatInterval == 0 && input.TargetState == ""
	case TriggerRemaining:
		return input.ConsumedPercent == 0 && input.Remaining > 0 && input.Remaining < metric.duration &&
			input.Remaining%time.Microsecond == 0 && input.Offset == 0 && input.RepeatInterval == 0 && input.TargetState == ""
	case TriggerDue, TriggerResumed:
		return zeroDurationFields()
	case TriggerAfterBreach:
		return input.ConsumedPercent == 0 && input.Remaining == 0 && input.Offset >= 0 &&
			input.Offset <= 100*365*24*time.Hour && input.Offset%time.Microsecond == 0 &&
			input.RepeatInterval == 0 && input.TargetState == ""
	case TriggerRepeatedBreach:
		return input.ConsumedPercent == 0 && input.Remaining == 0 && input.Offset >= 0 &&
			input.Offset <= 100*365*24*time.Hour && input.Offset%time.Microsecond == 0 && input.RepeatInterval > 0 &&
			input.RepeatInterval <= 100*365*24*time.Hour &&
			input.RepeatInterval%time.Microsecond == 0 && input.TargetState == ""
	case TriggerStateChanged:
		return input.ConsumedPercent == 0 && input.Remaining == 0 && input.Offset == 0 &&
			input.RepeatInterval == 0 && validMetricState(input.TargetState)
	default:
		return false
	}
}

func canonicalTriggerAction(input TriggerActionInput) (TriggerAction, bool) {
	configuration := cloneEntityID(input.ConfigurationID)
	wantsConfiguration := input.Kind == ActionEmail || input.Kind == ActionWebhook || input.Kind == ActionAssignTeam
	wantsValue := input.Kind == ActionAddTag || input.Kind == ActionChangePriority ||
		input.Kind == ActionCreateSystemAlert || input.Kind == ActionDomainEvent
	wantsText := input.Kind == ActionCreateTask
	if !wantsConfiguration && !wantsValue && !wantsText || wantsConfiguration != (configuration != nil) ||
		wantsValue != validKey(input.Value.value) || wantsText != validText(input.Text, 2048, false, false) ||
		!wantsText && input.Text != "" || configuration != nil && !validEntityID(*configuration) ||
		input.AllowRecursiveSLA && input.Kind != ActionCreateSystemAlert {
		return TriggerAction{}, false
	}
	return TriggerAction{
		kind: input.Kind, configurationID: configuration,
		value: input.Value, text: input.Text, allowRecursiveSLA: input.AllowRecursiveSLA,
	}, true
}

func (definition TriggerDefinition) validFor(metric MetricDefinition) bool {
	_, err := NewTriggerDefinition(metric, TriggerDefinitionInput{
		ID: definition.id, Key: definition.key, MetricID: definition.metricID,
		Kind: definition.kind, ConsumedPercent: definition.consumedPercent,
		Remaining: definition.remaining, Offset: definition.offset,
		RepeatInterval: definition.repeatInterval, TargetState: definition.targetState,
		Action: TriggerActionInput{
			Kind: definition.action.kind, ConfigurationID: definition.action.configurationID,
			Value: definition.action.value, Text: definition.action.text,
			AllowRecursiveSLA: definition.action.allowRecursiveSLA,
		},
	})
	return err == nil
}

func (definition TriggerDefinition) clone() TriggerDefinition {
	result := definition
	result.action = definition.action.clone()
	return result
}

func (action TriggerAction) clone() TriggerAction {
	result := action
	result.configurationID = cloneEntityID(action.configurationID)
	return result
}

func validMetricState(value MetricState) bool {
	return value == StatePending || value == StateOnTrack || value == StateAtRisk ||
		value == StatePaused || value == StateBreached || value == StateCompleted
}

func triggerDeduplicationKey(
	instance MetricInstance,
	definition TriggerDefinition,
	scheduledAt time.Time,
	repeatWindow int64,
) [32]byte {
	hash := sha256.New()
	hash.Write([]byte("periapsis:sla-trigger:v2\x00"))
	tenant := instance.tenantID.Bytes()
	object := instance.objectID.Bytes()
	slaInstance := instance.slaInstanceID.Bytes()
	policy := instance.policyID.Bytes()
	metric := definition.metricID.Bytes()
	trigger := definition.id.Bytes()
	hash.Write(tenant[:])
	hash.Write(object[:])
	hash.Write(slaInstance[:])
	hash.Write(policy[:])
	hash.Write(metric[:])
	hash.Write(trigger[:])
	buffer := make([]byte, 24)
	binary.BigEndian.PutUint64(buffer[:8], uint64(scheduledAt.UnixMicro()))
	binary.BigEndian.PutUint64(buffer[8:], uint64(repeatWindow))
	binary.BigEndian.PutUint64(buffer[16:], instance.policyVersion)
	hash.Write(buffer)
	var result [32]byte
	copy(result[:], hash.Sum(nil))
	return result
}

func triggerOccurrenceID(scheduledAt time.Time, digest [32]byte) (EntityID, error) {
	milliseconds := scheduledAt.UnixMilli()
	if !validInstant(scheduledAt) || milliseconds < 0 || milliseconds > 0x0000ffffffffffff {
		return EntityID{}, ErrInvalidMetric
	}
	var value [16]byte
	for index := 5; index >= 0; index-- {
		value[index] = byte(milliseconds)
		milliseconds >>= 8
	}
	value[6] = 0x70 | digest[0]&0x0f
	value[7] = digest[1]
	value[8] = 0x80 | digest[2]&0x3f
	copy(value[9:], digest[3:10])
	return NewEntityID(value)
}
