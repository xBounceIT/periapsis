package postgres

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/sla"
)

const maximumSLAWorkerDocumentBytes = 16 * 1024 * 1024

type slaWorkerStateDocument struct {
	Aggregate slaWorkerAggregateDocument `json:"aggregate"`
	Metrics   []slaWorkerMetricDocument  `json:"metrics"`
}

type slaWorkerAggregateDocument struct {
	ID               uuid.UUID         `json:"id"`
	TenantID         uuid.UUID         `json:"tenant_id"`
	ObjectType       kernel.ObjectType `json:"object_type"`
	ObjectID         uuid.UUID         `json:"object_id"`
	PolicyID         uuid.UUID         `json:"policy_id"`
	PolicyVersion    uint64            `json:"policy_version"`
	AggregateVersion uint64            `json:"aggregate_version"`
	CreatedAt        time.Time         `json:"created_at"`
	UpdatedAt        time.Time         `json:"updated_at"`
	CompletedAt      *time.Time        `json:"completed_at"`
}

type slaWorkerMetricDocument struct {
	ID                    uuid.UUID              `json:"id"`
	TenantID              uuid.UUID              `json:"tenant_id"`
	SLAInstanceID         uuid.UUID              `json:"sla_instance_id"`
	DefinitionID          uuid.UUID              `json:"definition_id"`
	PolicyID              uuid.UUID              `json:"policy_id"`
	PolicyVersion         uint64                 `json:"policy_version"`
	Version               uint64                 `json:"version"`
	Lifecycle             kernel.MetricLifecycle `json:"lifecycle"`
	CreatedAt             time.Time              `json:"created_at"`
	UpdatedAt             time.Time              `json:"updated_at"`
	ExtensionMicros       int64                  `json:"extension_micros"`
	ConsumedMicros        int64                  `json:"consumed_micros"`
	StartedAt             *time.Time             `json:"started_at"`
	LastResumedAt         *time.Time             `json:"last_resumed_at"`
	PausedAt              *time.Time             `json:"paused_at"`
	CompletedAt           *time.Time             `json:"completed_at"`
	DueAt                 *time.Time             `json:"due_at"`
	BreachThresholdAt     *time.Time             `json:"breach_threshold_at"`
	BreachedAt            *time.Time             `json:"breached_at"`
	LastEventID           *uuid.UUID             `json:"last_event_id"`
	LastEventKey          *string                `json:"last_event_key"`
	LastEventAt           *time.Time             `json:"last_event_at"`
	LastOverrideID        *uuid.UUID             `json:"last_override_id"`
	LastOverrideDigestHex *string                `json:"last_override_digest"`
	Definition            slaWorkerDefinition    `json:"definition"`
	Calendar              *slaWorkerCalendar     `json:"calendar"`
	Triggers              []slaWorkerTrigger     `json:"triggers"`
	Cursors               []slaWorkerCursor      `json:"cursors"`
	Columns               []slaWorkerColumn      `json:"columns"`
}

type slaWorkerDefinition struct {
	ID                     uuid.UUID          `json:"id"`
	Key                    string             `json:"key"`
	Label                  string             `json:"label"`
	Description            string             `json:"description"`
	DurationMicros         int64              `json:"duration_micros"`
	Clock                  kernel.ClockType   `json:"clock"`
	CalendarID             *uuid.UUID         `json:"calendar_id"`
	CalendarVersion        *uint64            `json:"calendar_version"`
	StartEvent             string             `json:"start_event"`
	PauseEvent             *string            `json:"pause_event"`
	ResumeEvent            *string            `json:"resume_event"`
	CompletionEvent        string             `json:"completion_event"`
	ResetEvent             *string            `json:"reset_event"`
	ResetPolicy            kernel.ResetPolicy `json:"reset_policy"`
	WarningKind            kernel.WarningKind `json:"warning_kind"`
	WarningConsumedPercent *uint8             `json:"warning_consumed_percent"`
	WarningRemainingMicros *int64             `json:"warning_remaining_micros"`
	BreachGraceMicros      int64              `json:"breach_grace_micros"`
	DisplayFormat          string             `json:"display_format"`
	CustomerVisible        bool               `json:"customer_visible"`
	APIVisible             bool               `json:"api_visible"`
	Position               uint16             `json:"position"`
	DefinitionDigest       string             `json:"definition_digest"`
}

type slaWorkerCalendar struct {
	ID             uuid.UUID                 `json:"id"`
	TenantID       uuid.UUID                 `json:"tenant_id"`
	Key            string                    `json:"key"`
	Label          string                    `json:"label"`
	Timezone       string                    `json:"timezone"`
	Version        uint64                    `json:"version"`
	WeeklySchedule []slaWorkerWeeklySchedule `json:"weekly_schedule"`
	Exceptions     []slaWorkerDateException  `json:"exceptions"`
	RevisionDigest string                    `json:"revision_digest"`
}

type slaWorkerMinuteInterval struct {
	StartMinute uint16 `json:"start_minute"`
	EndMinute   uint16 `json:"end_minute"`
}

type slaWorkerWeeklySchedule struct {
	Weekday   int                       `json:"weekday"`
	Intervals []slaWorkerMinuteInterval `json:"intervals"`
}

type slaWorkerDateException struct {
	Date      string                    `json:"date"`
	Closed    bool                      `json:"closed"`
	Intervals []slaWorkerMinuteInterval `json:"intervals"`
}

type slaWorkerTrigger struct {
	ID                    uuid.UUID           `json:"id"`
	MetricDefinitionID    uuid.UUID           `json:"metric_definition_id"`
	Key                   string              `json:"key"`
	Kind                  kernel.TriggerKind  `json:"kind"`
	ConsumedPercent       *uint8              `json:"consumed_percent"`
	RemainingMicros       *int64              `json:"remaining_micros"`
	OffsetMicros          *int64              `json:"offset_micros"`
	RepeatIntervalMicros  *int64              `json:"repeat_interval_micros"`
	TargetState           *kernel.MetricState `json:"target_state"`
	ActionKind            kernel.ActionKind   `json:"action_kind"`
	ActionConfigurationID *uuid.UUID          `json:"action_configuration_id"`
	ActionValue           *string             `json:"action_value"`
	AllowRecursiveSLA     bool                `json:"allow_recursive_sla"`
	Position              uint16              `json:"position"`
	DefinitionDigest      string              `json:"definition_digest"`
}

type slaWorkerCursor struct {
	TriggerDefinitionID uuid.UUID           `json:"trigger_definition_id"`
	Initialized         bool                `json:"initialized"`
	LastObservedAt      *time.Time          `json:"last_observed_at"`
	LastState           *kernel.MetricState `json:"last_state"`
	LastPercentage      float64             `json:"last_percentage"`
	LastRemainingMicros int64               `json:"last_remaining_micros"`
	LastRepeatWindow    int64               `json:"last_repeat_window"`
	LastFiredAt         *time.Time          `json:"last_fired_at"`
	FireCount           uint64              `json:"fire_count"`
}

type slaWorkerColumn struct {
	ID                 uuid.UUID                `json:"id"`
	TenantID           uuid.UUID                `json:"tenant_id"`
	Key                string                   `json:"key"`
	Label              string                   `json:"label"`
	MetricDefinitionID uuid.UUID                `json:"metric_definition_id"`
	Calculation        kernel.ColumnCalculation `json:"calculation"`
	Format             kernel.ColumnFormat      `json:"format"`
	Sortable           bool                     `json:"sortable"`
	Filterable         bool                     `json:"filterable"`
	CustomerVisible    bool                     `json:"customer_visible"`
	VisibleRoleKeys    []string                 `json:"visible_role_keys"`
	Position           uint16                   `json:"position"`
	StyleRules         []slaWorkerColumnStyle   `json:"style_rules"`
	Version            uint64                   `json:"version"`
	RevisionDigest     string                   `json:"revision_digest"`
}

type slaWorkerColumnStyle struct {
	StyleKey               string             `json:"style_key"`
	State                  kernel.MetricState `json:"state"`
	MinimumPercentage      *float64           `json:"minimum_percentage"`
	MaximumRemainingMicros *int64             `json:"maximum_remaining_micros"`
}

func decodeSLAWorkerState(
	tenantID uuid.UUID,
	slaInstanceID uuid.UUID,
	expectedAggregateVersion uint64,
	raw []byte,
) (kernel.ObjectType, kernel.EntityID, []kernel.MetricWork, error) {
	var document slaWorkerStateDocument
	if err := decodeStrictSLAWorkerJSON(raw, &document); err != nil {
		return "", kernel.EntityID{}, nil, err
	}
	aggregate := &document.Aggregate
	if aggregate.ID != slaInstanceID || aggregate.TenantID != tenantID ||
		aggregate.AggregateVersion != expectedAggregateVersion || aggregate.PolicyVersion == 0 ||
		!slaWorkerUUIDv7(aggregate.ID) || !slaWorkerUUIDv7(aggregate.ObjectID) ||
		!slaWorkerUUIDv7(aggregate.PolicyID) || aggregate.CompletedAt != nil ||
		!normalizeSLAWorkerInstant(&aggregate.CreatedAt) ||
		!normalizeSLAWorkerInstant(&aggregate.UpdatedAt) ||
		aggregate.UpdatedAt.Before(aggregate.CreatedAt) ||
		(aggregate.ObjectType != kernel.ObjectAlert && aggregate.ObjectType != kernel.ObjectCase &&
			aggregate.ObjectType != kernel.ObjectTask) {
		return "", kernel.EntityID{}, nil, errors.New("database returned an invalid SLA worker aggregate")
	}
	objectID, err := kernel.ParseEntityID(aggregate.ObjectID.String())
	if err != nil {
		return "", kernel.EntityID{}, nil, errors.New("database returned an invalid SLA worker object")
	}
	tenantEntity, _ := kernel.ParseEntityID(tenantID.String())
	slaEntity, _ := kernel.ParseEntityID(slaInstanceID.String())
	policyEntity, _ := kernel.ParseEntityID(aggregate.PolicyID.String())
	if len(document.Metrics) == 0 || len(document.Metrics) > 32 {
		return "", kernel.EntityID{}, nil, errors.New("database returned an invalid SLA worker metric inventory")
	}
	metrics := make([]kernel.MetricWork, len(document.Metrics))
	seen := make(map[uuid.UUID]struct{}, len(document.Metrics))
	for index := range document.Metrics {
		if document.Metrics[index].Definition.Position != uint16(index) {
			return "", kernel.EntityID{}, nil, errors.New("database returned unordered SLA worker metrics")
		}
		metric, decodeErr := decodeSLAWorkerMetric(
			document.Metrics[index], tenantID, tenantEntity, slaInstanceID,
			slaEntity, aggregate.ObjectType, objectID, aggregate.PolicyID,
			policyEntity, aggregate.PolicyVersion,
		)
		if decodeErr != nil {
			return "", kernel.EntityID{}, nil, decodeErr
		}
		if _, duplicate := seen[document.Metrics[index].ID]; duplicate {
			return "", kernel.EntityID{}, nil, errors.New("database returned duplicate SLA worker metric identity")
		}
		seen[document.Metrics[index].ID] = struct{}{}
		metrics[index] = metric
	}
	return aggregate.ObjectType, objectID, metrics, nil
}

func decodeSLAWorkerMetric(
	document slaWorkerMetricDocument,
	tenantID uuid.UUID,
	tenantEntity kernel.EntityID,
	slaInstanceID uuid.UUID,
	slaEntity kernel.EntityID,
	objectType kernel.ObjectType,
	objectID kernel.EntityID,
	policyID uuid.UUID,
	policyEntity kernel.EntityID,
	policyVersion uint64,
) (kernel.MetricWork, error) {
	definition, err := decodeSLAWorkerDefinition(document.Definition)
	if err != nil || document.ID == uuid.Nil || document.TenantID != tenantID ||
		document.SLAInstanceID != slaInstanceID || document.DefinitionID != document.Definition.ID ||
		document.PolicyID != policyID || document.PolicyVersion != policyVersion ||
		document.Version == 0 || !slaWorkerUUIDv7(document.ID) ||
		!normalizeSLAWorkerMetricTimes(&document) {
		return kernel.MetricWork{}, errors.New("database returned an invalid SLA worker metric")
	}
	id, _ := kernel.ParseEntityID(document.ID.String())
	extension, err := slaWorkerDuration(document.ExtensionMicros)
	if err != nil {
		return kernel.MetricWork{}, err
	}
	consumed, err := slaWorkerDuration(document.ConsumedMicros)
	if err != nil {
		return kernel.MetricWork{}, err
	}
	lastEventID, err := optionalSLAWorkerEntity(document.LastEventID)
	if err != nil {
		return kernel.MetricWork{}, err
	}
	lastOverrideID, err := optionalSLAWorkerEntity(document.LastOverrideID)
	if err != nil {
		return kernel.MetricWork{}, err
	}
	lastEventKey, err := optionalSLAWorkerKey(document.LastEventKey)
	if err != nil {
		return kernel.MetricWork{}, err
	}
	lastOverrideDigest, err := optionalSLAWorkerDigest(document.LastOverrideDigestHex)
	if err != nil {
		return kernel.MetricWork{}, err
	}
	instance, err := kernel.RestoreMetricInstance(kernel.MetricInstanceSnapshot{
		ID: id, SLAInstanceID: slaEntity, TenantID: tenantEntity,
		ObjectType: objectType, ObjectID: objectID, PolicyID: policyEntity,
		PolicyVersion: policyVersion, Definition: definition,
		CreatedAt: document.CreatedAt, UpdatedAt: document.UpdatedAt,
		Extension: extension, Lifecycle: document.Lifecycle,
		StartedAt: document.StartedAt, LastResumedAt: document.LastResumedAt,
		PausedAt: document.PausedAt, CompletedAt: document.CompletedAt,
		DueAt: document.DueAt, BreachThresholdAt: document.BreachThresholdAt,
		BreachedAt: document.BreachedAt, Consumed: consumed,
		LastEventID: lastEventID, LastEventKey: lastEventKey,
		LastEventAt: document.LastEventAt, LastOverrideID: lastOverrideID,
		LastOverrideDigest: lastOverrideDigest, Version: document.Version,
	})
	if err != nil {
		return kernel.MetricWork{}, errors.New("database returned a non-restorable SLA worker metric")
	}
	work := kernel.MetricWork{Instance: instance}
	if document.Calendar != nil {
		calendar, calendarErr := decodeSLAWorkerCalendar(*document.Calendar, tenantID, tenantEntity)
		if calendarErr != nil {
			return kernel.MetricWork{}, calendarErr
		}
		work.Calendar = &calendar
	}
	if (definition.Clock() == kernel.ClockBusiness) != (work.Calendar != nil) {
		return kernel.MetricWork{}, errors.New("database returned an invalid SLA worker calendar binding")
	}
	if work.Calendar != nil {
		calendarID := definition.CalendarID()
		if calendarID == nil || work.Calendar.ID() != *calendarID ||
			work.Calendar.Version() != definition.CalendarVersion() {
			return kernel.MetricWork{}, errors.New("database returned a mismatched SLA worker calendar")
		}
	}
	work.Triggers, err = decodeSLAWorkerTriggers(definition, document.Triggers, document.Cursors)
	if err != nil {
		return kernel.MetricWork{}, err
	}
	work.Columns, err = decodeSLAWorkerColumns(definition, tenantID, tenantEntity, document.Columns)
	if err != nil {
		return kernel.MetricWork{}, err
	}
	return work, nil
}

func decodeSLAWorkerDefinition(document slaWorkerDefinition) (kernel.MetricDefinition, error) {
	id, err := kernel.ParseEntityID(document.ID.String())
	if err != nil {
		return kernel.MetricDefinition{}, errors.New("database returned an invalid SLA worker definition identity")
	}
	key, err := kernel.NewKey(document.Key)
	if err != nil {
		return kernel.MetricDefinition{}, err
	}
	start, err := kernel.NewKey(document.StartEvent)
	if err != nil {
		return kernel.MetricDefinition{}, err
	}
	completion, err := kernel.NewKey(document.CompletionEvent)
	if err != nil {
		return kernel.MetricDefinition{}, err
	}
	pause, err := optionalSLAWorkerKey(document.PauseEvent)
	if err != nil {
		return kernel.MetricDefinition{}, err
	}
	resume, err := optionalSLAWorkerKey(document.ResumeEvent)
	if err != nil {
		return kernel.MetricDefinition{}, err
	}
	reset, err := optionalSLAWorkerKey(document.ResetEvent)
	if err != nil {
		return kernel.MetricDefinition{}, err
	}
	duration, err := slaWorkerDuration(document.DurationMicros)
	if err != nil {
		return kernel.MetricDefinition{}, err
	}
	grace, err := slaWorkerDuration(document.BreachGraceMicros)
	if err != nil {
		return kernel.MetricDefinition{}, err
	}
	var calendarID *kernel.EntityID
	if document.CalendarID != nil {
		parsed, parseErr := kernel.ParseEntityID(document.CalendarID.String())
		if parseErr != nil {
			return kernel.MetricDefinition{}, parseErr
		}
		calendarID = &parsed
	}
	calendarVersion := uint64(0)
	if document.CalendarVersion != nil {
		calendarVersion = *document.CalendarVersion
	}
	warning := kernel.WarningThreshold{Kind: document.WarningKind}
	if document.WarningConsumedPercent != nil {
		warning.ConsumedPercent = *document.WarningConsumedPercent
	}
	if document.WarningRemainingMicros != nil {
		warning.RemainingDuration, err = slaWorkerDuration(*document.WarningRemainingMicros)
		if err != nil {
			return kernel.MetricDefinition{}, err
		}
	}
	definition, err := kernel.NewMetricDefinition(kernel.MetricDefinitionInput{
		ID: id, Key: key, Label: document.Label, Description: document.Description,
		Duration: duration, Clock: document.Clock, CalendarID: calendarID,
		CalendarVersion: calendarVersion, StartEvent: start, PauseEvent: pause,
		ResumeEvent: resume, CompletionEvent: completion, ResetEvent: reset,
		ResetPolicy: document.ResetPolicy, Warning: warning, BreachGrace: grace,
		DisplayFormat: document.DisplayFormat, CustomerVisible: document.CustomerVisible,
		APIVisible: document.APIVisible,
	})
	if err != nil || !matchesSLAWorkerDigest(document.DefinitionDigest, definition.Digest()) {
		return kernel.MetricDefinition{}, errors.New("database returned an invalid SLA worker definition")
	}
	return definition, nil
}

func decodeSLAWorkerCalendar(
	document slaWorkerCalendar,
	tenantID uuid.UUID,
	tenantEntity kernel.EntityID,
) (kernel.BusinessCalendar, error) {
	if document.TenantID != tenantID {
		return kernel.BusinessCalendar{}, errors.New("database returned a cross-tenant SLA worker calendar")
	}
	id, err := kernel.ParseEntityID(document.ID.String())
	if err != nil {
		return kernel.BusinessCalendar{}, err
	}
	key, err := kernel.NewKey(document.Key)
	if err != nil {
		return kernel.BusinessCalendar{}, err
	}
	weekly := make([]kernel.WeeklyScheduleInput, len(document.WeeklySchedule))
	for index, schedule := range document.WeeklySchedule {
		weekly[index] = kernel.WeeklyScheduleInput{
			Weekday:   time.Weekday(schedule.Weekday),
			Intervals: decodeSLAWorkerIntervals(schedule.Intervals),
		}
	}
	exceptions := make([]kernel.DateExceptionInput, len(document.Exceptions))
	for index, exception := range document.Exceptions {
		exceptions[index] = kernel.DateExceptionInput{
			Date: exception.Date, Closed: exception.Closed,
			Intervals: decodeSLAWorkerIntervals(exception.Intervals),
		}
	}
	calendar, err := kernel.NewBusinessCalendar(kernel.BusinessCalendarInput{
		ID: id, TenantID: tenantEntity, Key: key, Label: document.Label,
		Timezone: document.Timezone, Version: document.Version,
		WeeklySchedules: weekly, Exceptions: exceptions,
	})
	if err != nil || !matchesSLAWorkerDigest(document.RevisionDigest, calendar.Digest()) {
		return kernel.BusinessCalendar{}, errors.New("database returned an invalid SLA worker calendar")
	}
	return calendar, nil
}

func decodeSLAWorkerTriggers(
	metric kernel.MetricDefinition,
	documents []slaWorkerTrigger,
	cursors []slaWorkerCursor,
) ([]kernel.TriggerBinding, error) {
	if len(documents) > 256 || len(cursors) > len(documents) {
		return nil, errors.New("database returned an invalid SLA worker trigger inventory")
	}
	cursorByID := make(map[uuid.UUID]slaWorkerCursor, len(cursors))
	for _, cursor := range cursors {
		if _, duplicate := cursorByID[cursor.TriggerDefinitionID]; duplicate {
			return nil, errors.New("database returned duplicate SLA worker cursors")
		}
		cursorByID[cursor.TriggerDefinitionID] = cursor
	}
	bindings := make([]kernel.TriggerBinding, len(documents))
	for index, document := range documents {
		if document.Position != uint16(index) || document.MetricDefinitionID != uuid.UUID(metric.ID().Bytes()) {
			return nil, errors.New("database returned an unordered SLA worker trigger")
		}
		definition, err := decodeSLAWorkerTrigger(document, metric)
		if err != nil {
			return nil, err
		}
		cursor, err := kernel.NewTriggerCursor(definition.ID())
		if err != nil {
			return nil, err
		}
		if stored, exists := cursorByID[document.ID]; exists {
			if !normalizeSLAWorkerInstantPointer(stored.LastObservedAt) ||
				!normalizeSLAWorkerInstantPointer(stored.LastFiredAt) {
				return nil, errors.New("database returned an invalid SLA worker cursor instant")
			}
			lastState := kernel.MetricState("")
			if stored.LastState != nil {
				lastState = *stored.LastState
			}
			remaining, durationErr := slaWorkerDuration(stored.LastRemainingMicros)
			if durationErr != nil {
				return nil, durationErr
			}
			cursor, err = kernel.RestoreTriggerCursor(kernel.TriggerCursorSnapshot{
				TriggerID: definition.ID(), Initialized: stored.Initialized,
				LastObservedAt: stored.LastObservedAt, LastState: lastState,
				LastPercentage: stored.LastPercentage, LastRemaining: remaining,
				LastRepeatWindow: stored.LastRepeatWindow, LastFiredAt: stored.LastFiredAt,
				FireCount: stored.FireCount,
			})
			if err != nil {
				return nil, errors.New("database returned a non-restorable SLA worker cursor")
			}
			delete(cursorByID, document.ID)
		}
		bindings[index] = kernel.TriggerBinding{Definition: definition, Cursor: cursor}
	}
	if len(cursorByID) != 0 {
		return nil, errors.New("database returned an orphan SLA worker cursor")
	}
	return bindings, nil
}

func decodeSLAWorkerTrigger(document slaWorkerTrigger, metric kernel.MetricDefinition) (kernel.TriggerDefinition, error) {
	id, err := kernel.ParseEntityID(document.ID.String())
	if err != nil {
		return kernel.TriggerDefinition{}, err
	}
	key, err := kernel.NewKey(document.Key)
	if err != nil {
		return kernel.TriggerDefinition{}, err
	}
	var configurationID *kernel.EntityID
	if document.ActionConfigurationID != nil {
		value, parseErr := kernel.ParseEntityID(document.ActionConfigurationID.String())
		if parseErr != nil {
			return kernel.TriggerDefinition{}, parseErr
		}
		configurationID = &value
	}
	var actionValue kernel.Key
	var actionText string
	if document.ActionKind == kernel.ActionCreateTask {
		if document.ActionValue != nil {
			actionText = *document.ActionValue
		}
	} else {
		actionValue, err = optionalSLAWorkerKey(document.ActionValue)
		if err != nil {
			return kernel.TriggerDefinition{}, err
		}
	}
	remaining, err := optionalSLAWorkerDuration(document.RemainingMicros)
	if err != nil {
		return kernel.TriggerDefinition{}, err
	}
	offset, err := optionalSLAWorkerDuration(document.OffsetMicros)
	if err != nil {
		return kernel.TriggerDefinition{}, err
	}
	repeat, err := optionalSLAWorkerDuration(document.RepeatIntervalMicros)
	if err != nil {
		return kernel.TriggerDefinition{}, err
	}
	consumed := uint8(0)
	if document.ConsumedPercent != nil {
		consumed = *document.ConsumedPercent
	}
	state := kernel.MetricState("")
	if document.TargetState != nil {
		state = *document.TargetState
	}
	definition, err := kernel.NewTriggerDefinition(metric, kernel.TriggerDefinitionInput{
		ID: id, Key: key, MetricID: metric.ID(), Kind: document.Kind,
		ConsumedPercent: consumed, Remaining: remaining, Offset: offset,
		RepeatInterval: repeat, TargetState: state,
		Action: kernel.TriggerActionInput{
			Kind: document.ActionKind, ConfigurationID: configurationID,
			Value: actionValue, Text: actionText,
			AllowRecursiveSLA: document.AllowRecursiveSLA,
		},
	})
	if err != nil || !matchesSLAWorkerDigest(document.DefinitionDigest, definition.Digest()) {
		return kernel.TriggerDefinition{}, errors.New("database returned an invalid SLA worker trigger")
	}
	return definition, nil
}

func decodeSLAWorkerColumns(
	metric kernel.MetricDefinition,
	tenantID uuid.UUID,
	tenantEntity kernel.EntityID,
	documents []slaWorkerColumn,
) ([]kernel.ColumnDefinition, error) {
	if len(documents) > 256 {
		return nil, errors.New("database returned an invalid SLA worker column inventory")
	}
	result := make([]kernel.ColumnDefinition, len(documents))
	seen := make(map[uuid.UUID]struct{}, len(documents))
	for index, document := range documents {
		if document.TenantID != tenantID || document.MetricDefinitionID != uuid.UUID(metric.ID().Bytes()) {
			return nil, errors.New("database returned a cross-boundary SLA worker column")
		}
		if _, duplicate := seen[document.ID]; duplicate {
			return nil, errors.New("database returned duplicate SLA worker columns")
		}
		seen[document.ID] = struct{}{}
		id, err := kernel.ParseEntityID(document.ID.String())
		if err != nil {
			return nil, err
		}
		key, err := kernel.NewKey(document.Key)
		if err != nil {
			return nil, err
		}
		roles := make([]kernel.Key, len(document.VisibleRoleKeys))
		for roleIndex, value := range document.VisibleRoleKeys {
			roles[roleIndex], err = kernel.NewKey(value)
			if err != nil {
				return nil, err
			}
		}
		styles := make([]kernel.ColumnStyleRuleInput, len(document.StyleRules))
		for styleIndex, style := range document.StyleRules {
			styleKey, styleErr := kernel.NewKey(style.StyleKey)
			if styleErr != nil {
				return nil, styleErr
			}
			var maximumRemaining *time.Duration
			if style.MaximumRemainingMicros != nil {
				value, durationErr := slaWorkerDuration(*style.MaximumRemainingMicros)
				if durationErr != nil {
					return nil, durationErr
				}
				maximumRemaining = &value
			}
			styles[styleIndex] = kernel.ColumnStyleRuleInput{
				StyleKey: styleKey, State: style.State,
				MinimumPercentage: style.MinimumPercentage,
				MaximumRemaining:  maximumRemaining,
			}
		}
		column, err := kernel.NewColumnDefinition(metric, kernel.ColumnDefinitionInput{
			ID: id, TenantID: tenantEntity, Key: key, Label: document.Label,
			MetricID: metric.ID(), Calculation: document.Calculation, Format: document.Format,
			Sortable: document.Sortable, Filterable: document.Filterable,
			CustomerVisible: document.CustomerVisible, VisibleRoleKeys: roles,
			Position: document.Position, Version: document.Version, StyleRules: styles,
		})
		if err != nil || !matchesSLAWorkerDigest(document.RevisionDigest, column.Digest()) {
			return nil, errors.New("database returned an invalid SLA worker column")
		}
		result[index] = column
	}
	return result, nil
}

func decodeSLAWorkerIntervals(values []slaWorkerMinuteInterval) []kernel.MinuteIntervalInput {
	result := make([]kernel.MinuteIntervalInput, len(values))
	for index, value := range values {
		result[index] = kernel.MinuteIntervalInput{StartMinute: value.StartMinute, EndMinute: value.EndMinute}
	}
	return result
}

func decodeStrictSLAWorkerJSON(raw []byte, target any) error {
	if len(raw) == 0 || len(raw) > maximumSLAWorkerDocumentBytes || target == nil {
		return errors.New("database returned an invalid SLA worker document")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errors.New("database returned a malformed SLA worker document")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("database returned trailing SLA worker document data")
	}
	return nil
}

func normalizeSLAWorkerMetricTimes(document *slaWorkerMetricDocument) bool {
	return document != nil && normalizeSLAWorkerInstant(&document.CreatedAt) &&
		normalizeSLAWorkerInstant(&document.UpdatedAt) &&
		normalizeSLAWorkerInstantPointer(document.StartedAt) &&
		normalizeSLAWorkerInstantPointer(document.LastResumedAt) &&
		normalizeSLAWorkerInstantPointer(document.PausedAt) &&
		normalizeSLAWorkerInstantPointer(document.CompletedAt) &&
		normalizeSLAWorkerInstantPointer(document.DueAt) &&
		normalizeSLAWorkerInstantPointer(document.BreachThresholdAt) &&
		normalizeSLAWorkerInstantPointer(document.BreachedAt) &&
		normalizeSLAWorkerInstantPointer(document.LastEventAt) &&
		!document.UpdatedAt.Before(document.CreatedAt)
}

func normalizeSLAWorkerInstantPointer(value *time.Time) bool {
	return value == nil || normalizeSLAWorkerInstant(value)
}

func normalizeSLAWorkerInstant(value *time.Time) bool {
	if value == nil || value.IsZero() || value.Year() < 1970 || value.Year() > 9999 ||
		value.Nanosecond()%1_000 != 0 {
		return false
	}
	*value = value.UTC()
	return true
}

func slaWorkerDuration(value int64) (time.Duration, error) {
	if value < 0 || value > math.MaxInt64/int64(time.Microsecond) {
		return 0, errors.New("database returned an invalid SLA worker duration")
	}
	return time.Duration(value) * time.Microsecond, nil
}

func optionalSLAWorkerDuration(value *int64) (time.Duration, error) {
	if value == nil {
		return 0, nil
	}
	return slaWorkerDuration(*value)
}

func optionalSLAWorkerKey(value *string) (kernel.Key, error) {
	if value == nil {
		return kernel.Key{}, nil
	}
	key, err := kernel.NewKey(*value)
	if err != nil {
		return kernel.Key{}, errors.New("database returned an invalid optional SLA worker key")
	}
	return key, nil
}

func optionalSLAWorkerEntity(value *uuid.UUID) (*kernel.EntityID, error) {
	if value == nil {
		return nil, nil
	}
	parsed, err := kernel.ParseEntityID(value.String())
	if err != nil {
		return nil, errors.New("database returned an invalid optional SLA worker identity")
	}
	return &parsed, nil
}

func optionalSLAWorkerDigest(value *string) ([sha256.Size]byte, error) {
	if value == nil {
		return [sha256.Size]byte{}, nil
	}
	decoded, err := hex.DecodeString(*value)
	if err != nil || len(decoded) != sha256.Size {
		return [sha256.Size]byte{}, errors.New("database returned an invalid optional SLA worker digest")
	}
	var result [sha256.Size]byte
	copy(result[:], decoded)
	return result, nil
}

func matchesSLAWorkerDigest(value string, expected [sha256.Size]byte) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && bytes.Equal(decoded, expected[:])
}

func slaWorkerUUIDv7(value uuid.UUID) bool {
	return value != uuid.Nil && value.Version() == 7 && value.Variant() == uuid.RFC4122
}
