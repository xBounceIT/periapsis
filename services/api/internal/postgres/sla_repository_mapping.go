package postgres

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"time"

	"github.com/google/uuid"

	kernel "github.com/periapsis-im/periapsis/modules/sla"
	application "github.com/periapsis-im/periapsis/services/api/internal/sla"
)

const maximumSLADocumentBytes = 16 * 1024 * 1024

type slaMinuteIntervalDocument struct {
	StartMinute uint16 `json:"start_minute"`
	EndMinute   uint16 `json:"end_minute"`
}

type slaWeeklyScheduleDocument struct {
	Weekday   int                         `json:"weekday"`
	Intervals []slaMinuteIntervalDocument `json:"intervals"`
}

type slaDateExceptionDocument struct {
	Date      string                      `json:"date"`
	Closed    bool                        `json:"closed"`
	Intervals []slaMinuteIntervalDocument `json:"intervals"`
}

type slaCalendarDocument struct {
	ID              uuid.UUID                   `json:"id"`
	Key             string                      `json:"key"`
	ResourceVersion uint64                      `json:"resource_version"`
	ActiveVersion   uint64                      `json:"active_version"`
	ArchivedAt      *time.Time                  `json:"archived_at"`
	Label           string                      `json:"label"`
	Timezone        string                      `json:"timezone"`
	WeeklySchedule  []slaWeeklyScheduleDocument `json:"weekly_schedule"`
	Exceptions      []slaDateExceptionDocument  `json:"exceptions"`
	RevisionDigest  string                      `json:"revision_digest"`
	CreatedAt       time.Time                   `json:"created_at"`
	UpdatedAt       time.Time                   `json:"updated_at"`
}

type slaRuleDocument struct {
	Kind      kernel.RuleKind       `json:"kind"`
	Children  []slaRuleDocument     `json:"children,omitempty"`
	Predicate *slaPredicateDocument `json:"predicate,omitempty"`
}

type slaPredicateDocument struct {
	Kind     kernel.FactKind          `json:"kind"`
	Key      string                   `json:"key,omitempty"`
	Operator kernel.PredicateOperator `json:"operator"`
	Values   []string                 `json:"values"`
}

type slaMetricDocument struct {
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

type slaTriggerDocument struct {
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

type slaPolicyDocument struct {
	ID                     uuid.UUID            `json:"id"`
	Key                    string               `json:"key"`
	ResourceVersion        uint64               `json:"resource_version"`
	ActiveVersion          uint64               `json:"active_version"`
	ArchivedAt             *time.Time           `json:"archived_at"`
	Name                   string               `json:"name"`
	Description            string               `json:"description"`
	Priority               int32                `json:"priority"`
	ObjectTypes            []kernel.ObjectType  `json:"object_types"`
	MatchRule              slaRuleDocument      `json:"match_rule"`
	EffectiveFrom          time.Time            `json:"effective_from"`
	EffectiveUntil         *time.Time           `json:"effective_until"`
	Enabled                bool                 `json:"enabled"`
	ApplyToSLAEngineSource bool                 `json:"apply_to_sla_engine_source"`
	Metrics                []slaMetricDocument  `json:"metrics"`
	Triggers               []slaTriggerDocument `json:"triggers"`
	RevisionDigest         string               `json:"revision_digest"`
	CreatedAt              time.Time            `json:"created_at"`
	UpdatedAt              time.Time            `json:"updated_at"`
}

type slaColumnStyleDocument struct {
	StyleKey               string             `json:"style_key"`
	State                  kernel.MetricState `json:"state"`
	MinimumPercentage      *float64           `json:"minimum_percentage"`
	MaximumRemainingMicros *int64             `json:"maximum_remaining_micros"`
}

type slaColumnDocument struct {
	ID                 uuid.UUID                `json:"id"`
	Key                string                   `json:"key"`
	ResourceVersion    uint64                   `json:"resource_version"`
	ActiveVersion      uint64                   `json:"active_version"`
	ArchivedAt         *time.Time               `json:"archived_at"`
	Label              string                   `json:"label"`
	MetricDefinitionID uuid.UUID                `json:"metric_definition_id"`
	Metric             *slaMetricDocument       `json:"metric,omitempty"`
	Calculation        kernel.ColumnCalculation `json:"calculation"`
	Format             kernel.ColumnFormat      `json:"format"`
	Sortable           bool                     `json:"sortable"`
	Filterable         bool                     `json:"filterable"`
	CustomerVisible    bool                     `json:"customer_visible"`
	VisibleRoleKeys    []string                 `json:"visible_role_keys"`
	Position           uint16                   `json:"position"`
	StyleRules         []slaColumnStyleDocument `json:"style_rules"`
	RevisionDigest     string                   `json:"revision_digest"`
	CreatedAt          time.Time                `json:"created_at"`
	UpdatedAt          time.Time                `json:"updated_at"`
}

type slaMetricRuntimeWrite struct {
	ID                    uuid.UUID              `json:"id"`
	DefinitionID          uuid.UUID              `json:"definition_id"`
	PolicyID              uuid.UUID              `json:"policy_id"`
	PolicyVersion         uint64                 `json:"policy_version"`
	Version               uint64                 `json:"version"`
	Lifecycle             kernel.MetricLifecycle `json:"lifecycle"`
	State                 kernel.MetricState     `json:"state"`
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
}

type slaTriggerCursorWrite struct {
	MetricInstanceID    uuid.UUID           `json:"metric_instance_id"`
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

type slaTriggerOccurrenceWrite struct {
	ID                    uuid.UUID         `json:"id"`
	MetricInstanceID      uuid.UUID         `json:"metric_instance_id"`
	TriggerDefinitionID   uuid.UUID         `json:"trigger_definition_id"`
	ScheduledAt           time.Time         `json:"scheduled_at"`
	DeduplicationDigest   string            `json:"deduplication_digest"`
	ActionKind            kernel.ActionKind `json:"action_kind"`
	ActionConfigurationID *uuid.UUID        `json:"action_configuration_id"`
	ActionValue           *string           `json:"action_value"`
	AllowRecursiveSLA     bool              `json:"allow_recursive_sla"`
}

type slaMaterializedColumnWrite struct {
	MetricInstanceID uuid.UUID           `json:"metric_instance_id"`
	ColumnID         uuid.UUID           `json:"column_id"`
	ColumnVersion    uint64              `json:"column_version"`
	StateValue       *kernel.MetricState `json:"state_value"`
	InstantValue     *time.Time          `json:"instant_value"`
	DurationMicros   *int64              `json:"duration_micros_value"`
	PercentageValue  *float64            `json:"percentage_value"`
	StyleKey         *string             `json:"style_key"`
	NextRefreshAt    *time.Time          `json:"next_refresh_at"`
}

type slaRuntimePlanWrite struct {
	Metrics              []slaMetricRuntimeWrite      `json:"metrics"`
	Cursors              []slaTriggerCursorWrite      `json:"cursors"`
	Occurrences          []slaTriggerOccurrenceWrite  `json:"occurrences"`
	Columns              []slaMaterializedColumnWrite `json:"columns"`
	NextEvaluationAt     *time.Time                   `json:"next_evaluation_at"`
	AggregateCompletedAt *time.Time                   `json:"aggregate_completed_at"`
	PreviousSnapshot     any                          `json:"previous_snapshot,omitempty"`
	CurrentSnapshot      any                          `json:"current_snapshot,omitempty"`
}

type slaFactValueDocument struct {
	Kind   kernel.FactKind `json:"kind"`
	Key    *string         `json:"key"`
	Values []string        `json:"values"`
}

type slaFactSnapshotDocument struct {
	TenantID    uuid.UUID              `json:"tenant_id"`
	ObjectType  kernel.ObjectType      `json:"object_type"`
	ObjectID    uuid.UUID              `json:"object_id"`
	EvaluatedAt time.Time              `json:"evaluated_at"`
	Timezone    string                 `json:"timezone"`
	Facts       []slaFactValueDocument `json:"facts"`
}

type slaAggregateDocument struct {
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

type slaTriggerCursorDocument struct {
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

type slaRuntimeMetricDocument struct {
	ID                    uuid.UUID                  `json:"id"`
	SLAInstanceID         uuid.UUID                  `json:"sla_instance_id"`
	TenantID              uuid.UUID                  `json:"tenant_id"`
	DefinitionID          uuid.UUID                  `json:"definition_id"`
	PolicyID              uuid.UUID                  `json:"policy_id"`
	PolicyVersion         uint64                     `json:"policy_version"`
	Version               uint64                     `json:"version"`
	Lifecycle             kernel.MetricLifecycle     `json:"lifecycle"`
	CreatedAt             time.Time                  `json:"created_at"`
	UpdatedAt             time.Time                  `json:"updated_at"`
	ExtensionMicros       int64                      `json:"extension_micros"`
	ConsumedMicros        int64                      `json:"consumed_micros"`
	StartedAt             *time.Time                 `json:"started_at"`
	LastResumedAt         *time.Time                 `json:"last_resumed_at"`
	PausedAt              *time.Time                 `json:"paused_at"`
	CompletedAt           *time.Time                 `json:"completed_at"`
	DueAt                 *time.Time                 `json:"due_at"`
	BreachThresholdAt     *time.Time                 `json:"breach_threshold_at"`
	BreachedAt            *time.Time                 `json:"breached_at"`
	LastEventID           *uuid.UUID                 `json:"last_event_id"`
	LastEventKey          *string                    `json:"last_event_key"`
	LastEventAt           *time.Time                 `json:"last_event_at"`
	LastOverrideID        *uuid.UUID                 `json:"last_override_id"`
	LastOverrideDigestHex *string                    `json:"last_override_digest"`
	Definition            slaMetricDocument          `json:"definition"`
	Calendar              *slaCalendarDocument       `json:"calendar"`
	Triggers              []slaTriggerDocument       `json:"triggers"`
	Cursors               []slaTriggerCursorDocument `json:"cursors"`
	Columns               []slaColumnDocument        `json:"columns"`
}

type slaRuntimeStateDocument struct {
	Facts                slaFactSnapshotDocument    `json:"facts"`
	PermissionEpoch      uint64                     `json:"permission_epoch"`
	SubjectEpoch         uint64                     `json:"subject_epoch"`
	Aggregate            *slaAggregateDocument      `json:"aggregate"`
	Metrics              []slaRuntimeMetricDocument `json:"metrics"`
	ActivePolicies       []slaPolicyDocument        `json:"active_policies"`
	ActiveCalendars      []slaCalendarDocument      `json:"active_calendars"`
	ActiveColumns        []slaColumnDocument        `json:"active_columns"`
	ReplacementCalendar  *slaCalendarDocument       `json:"replacement_calendar"`
	ReplacementPolicy    *slaPolicyDocument         `json:"replacement_policy"`
	ReplacementCalendars []slaCalendarDocument      `json:"replacement_calendars"`
	ReplacementColumns   []slaColumnDocument        `json:"replacement_columns"`
	SimulationDigest     *string                    `json:"simulation_digest"`
	OccurredAt           time.Time                  `json:"occurred_at"`
}

type decodedSLARuntimeState struct {
	Facts                kernel.FactSnapshot
	PermissionEpoch      uint64
	SubjectEpoch         uint64
	Aggregate            *slaAggregateDocument
	Metrics              []kernel.MetricWork
	ActivePolicies       []kernel.Policy
	ActiveCalendars      []kernel.BusinessCalendar
	ActiveColumns        []kernel.ColumnDefinition
	ReplacementCalendar  *kernel.BusinessCalendar
	ReplacementPolicy    *kernel.Policy
	ReplacementCalendars []kernel.BusinessCalendar
	ReplacementColumns   []kernel.ColumnDefinition
	SimulationDigest     [32]byte
	OccurredAt           time.Time
}

func encodeSLACalendar(calendar kernel.BusinessCalendar) ([]byte, error) {
	input := calendar.Input()
	document := slaCalendarDocument{
		ID: slaUUID(input.ID), Key: input.Key.String(), Label: input.Label,
		Timezone: input.Timezone, ActiveVersion: input.Version,
		RevisionDigest: encodeSLADigest(calendar.Digest()),
		WeeklySchedule: make([]slaWeeklyScheduleDocument, len(input.WeeklySchedules)),
		Exceptions:     make([]slaDateExceptionDocument, len(input.Exceptions)),
	}
	for index, schedule := range input.WeeklySchedules {
		document.WeeklySchedule[index] = slaWeeklyScheduleDocument{
			Weekday: int(schedule.Weekday), Intervals: encodeSLAIntervals(schedule.Intervals),
		}
	}
	for index, exception := range input.Exceptions {
		document.Exceptions[index] = slaDateExceptionDocument{
			Date: exception.Date, Closed: exception.Closed, Intervals: encodeSLAIntervals(exception.Intervals),
		}
	}
	return marshalSLADocument(document)
}

func encodeSLAPolicy(policy kernel.Policy) ([]byte, error) {
	input := policy.Input()
	document := slaPolicyDocument{
		ID: slaUUID(input.ID), Key: input.Key.String(), ActiveVersion: input.Version,
		Name: input.Name, Description: input.Description, Priority: input.Priority,
		ObjectTypes: input.ObjectTypes, MatchRule: encodeSLARule(input.MatchRule.Input()),
		EffectiveFrom: input.EffectiveFrom, EffectiveUntil: input.EffectiveUntil,
		Enabled: input.Enabled, ApplyToSLAEngineSource: input.ApplyToSLAEngineSource,
		Metrics:        make([]slaMetricDocument, len(input.Metrics)),
		Triggers:       make([]slaTriggerDocument, len(input.Triggers)),
		RevisionDigest: encodeSLADigest(policy.Digest()),
	}
	for index, metric := range input.Metrics {
		document.Metrics[index] = encodeSLAMetric(metric, uint16(index))
	}
	for index, trigger := range input.Triggers {
		document.Triggers[index] = encodeSLATrigger(trigger, uint16(index))
	}
	return marshalSLADocument(document)
}

func encodeSLAColumn(column kernel.ColumnDefinition) ([]byte, error) {
	input := column.Input()
	document := slaColumnDocument{
		ID: slaUUID(input.ID), Key: input.Key.String(), ActiveVersion: input.Version,
		Label: input.Label, MetricDefinitionID: slaUUID(input.MetricID),
		Calculation: input.Calculation, Format: input.Format, Sortable: input.Sortable,
		Filterable: input.Filterable, CustomerVisible: input.CustomerVisible,
		VisibleRoleKeys: make([]string, len(input.VisibleRoleKeys)), Position: input.Position,
		StyleRules:     make([]slaColumnStyleDocument, len(input.StyleRules)),
		RevisionDigest: encodeSLADigest(column.Digest()),
	}
	for index, key := range input.VisibleRoleKeys {
		document.VisibleRoleKeys[index] = key.String()
	}
	for index, style := range input.StyleRules {
		var remaining *int64
		if style.MaximumRemaining != nil {
			value := style.MaximumRemaining.Microseconds()
			remaining = &value
		}
		document.StyleRules[index] = slaColumnStyleDocument{
			StyleKey: style.StyleKey.String(), State: style.State,
			MinimumPercentage: style.MinimumPercentage, MaximumRemainingMicros: remaining,
		}
	}
	return marshalSLADocument(document)
}

func encodeSLAEnginePlan(
	plan kernel.EnginePlan,
	aggregateMayComplete bool,
	persistUnchangedMetrics bool,
) ([]byte, error) {
	document := slaRuntimePlanWrite{
		Metrics: []slaMetricRuntimeWrite{}, Cursors: []slaTriggerCursorWrite{},
		Occurrences: []slaTriggerOccurrenceWrite{}, Columns: []slaMaterializedColumnWrite{},
	}
	metrics := plan.Metrics()
	if len(metrics) == 0 || len(metrics) > 32 {
		return nil, errors.New("SLA engine plan has an invalid metric inventory")
	}
	allCompleted := aggregateMayComplete
	for _, metricPlan := range metrics {
		instance := metricPlan.Instance()
		snapshot := instance.Snapshot()
		evaluation := metricPlan.Evaluation()
		metric, err := encodeSLAMetricRuntime(snapshot, evaluation.State)
		if err != nil {
			return nil, err
		}
		if metricPlan.Changed() || persistUnchangedMetrics {
			document.Metrics = append(document.Metrics, metric)
		}
		allCompleted = allCompleted && snapshot.Lifecycle == kernel.LifecycleCompleted
		for _, cursor := range metricPlan.TriggerCursors() {
			snapshot := cursor.Snapshot()
			encoded := slaTriggerCursorWrite{
				MetricInstanceID: slaUUID(instance.ID()), TriggerDefinitionID: slaUUID(snapshot.TriggerID),
				Initialized: snapshot.Initialized, LastObservedAt: snapshot.LastObservedAt,
				LastPercentage: snapshot.LastPercentage, LastRemainingMicros: snapshot.LastRemaining.Microseconds(),
				LastRepeatWindow: snapshot.LastRepeatWindow, LastFiredAt: snapshot.LastFiredAt,
				FireCount: snapshot.FireCount,
			}
			if snapshot.Initialized {
				state := snapshot.LastState
				encoded.LastState = &state
			}
			document.Cursors = append(document.Cursors, encoded)
		}
		for _, occurrence := range metricPlan.Occurrences() {
			action := occurrence.Action()
			encoded := slaTriggerOccurrenceWrite{
				ID: slaUUID(occurrence.ID()), MetricInstanceID: slaUUID(instance.ID()),
				TriggerDefinitionID: slaUUID(occurrence.TriggerID()), ScheduledAt: occurrence.ScheduledAt(),
				DeduplicationDigest: encodeSLADigest(occurrence.DeduplicationKey()), ActionKind: action.Kind(),
				AllowRecursiveSLA: action.AllowRecursiveSLA(),
			}
			if configurationID := action.ConfigurationID(); configurationID != nil {
				value := slaUUID(*configurationID)
				encoded.ActionConfigurationID = &value
			}
			value := action.Value().String()
			if action.Kind() == kernel.ActionCreateTask {
				value = action.Text()
			}
			encoded.ActionValue = slaStringPointer(value)
			document.Occurrences = append(document.Occurrences, encoded)
		}
		for _, value := range metricPlan.Columns() {
			var durationMicros *int64
			if duration := value.Duration(); duration != nil {
				micros := duration.Microseconds()
				durationMicros = &micros
			}
			var stateValue *kernel.MetricState
			if value.Calculation() == kernel.ColumnState {
				state := value.State()
				stateValue = &state
			}
			document.Columns = append(document.Columns, slaMaterializedColumnWrite{
				MetricInstanceID: slaUUID(instance.ID()), ColumnID: slaUUID(value.ColumnID()),
				ColumnVersion: value.ColumnVersion(), StateValue: stateValue, InstantValue: value.Instant(),
				DurationMicros: durationMicros, PercentageValue: value.Percentage(),
				StyleKey: slaStringPointer(value.StyleKey().String()), NextRefreshAt: value.NextRefreshAt(),
			})
		}
		if next := metricPlan.NextEvaluationAt(); next != nil &&
			(document.NextEvaluationAt == nil || next.Before(*document.NextEvaluationAt)) {
			document.NextEvaluationAt = next
		}
	}
	if allCompleted {
		completedAt := plan.ObservedAt()
		document.AggregateCompletedAt = &completedAt
	}
	return marshalSLADocument(document)
}

func encodeSLAMetricRuntime(
	snapshot kernel.MetricInstanceSnapshot,
	state kernel.MetricState,
) (slaMetricRuntimeWrite, error) {
	if snapshot.Extension < 0 || snapshot.Consumed < 0 ||
		snapshot.Extension%time.Microsecond != 0 || snapshot.Consumed%time.Microsecond != 0 {
		return slaMetricRuntimeWrite{}, errors.New("SLA metric runtime duration is invalid")
	}
	lastEventID := optionalSLAUUID(snapshot.LastEventID)
	lastOverrideID := optionalSLAUUID(snapshot.LastOverrideID)
	var overrideDigest *string
	if snapshot.LastOverrideDigest != ([32]byte{}) {
		value := encodeSLADigest(snapshot.LastOverrideDigest)
		overrideDigest = &value
	}
	return slaMetricRuntimeWrite{
		ID: slaUUID(snapshot.ID), DefinitionID: slaUUID(snapshot.Definition.ID()),
		PolicyID: slaUUID(snapshot.PolicyID), PolicyVersion: snapshot.PolicyVersion,
		Version: snapshot.Version, Lifecycle: snapshot.Lifecycle, State: state,
		CreatedAt: snapshot.CreatedAt, UpdatedAt: snapshot.UpdatedAt,
		ExtensionMicros: snapshot.Extension.Microseconds(), ConsumedMicros: snapshot.Consumed.Microseconds(),
		StartedAt: snapshot.StartedAt, LastResumedAt: snapshot.LastResumedAt,
		PausedAt: snapshot.PausedAt, CompletedAt: snapshot.CompletedAt, DueAt: snapshot.DueAt,
		BreachThresholdAt: snapshot.BreachThresholdAt, BreachedAt: snapshot.BreachedAt,
		LastEventID: lastEventID, LastEventKey: slaStringPointer(snapshot.LastEventKey.String()),
		LastEventAt: snapshot.LastEventAt, LastOverrideID: lastOverrideID,
		LastOverrideDigestHex: overrideDigest,
	}, nil
}

func optionalSLAUUID(value *kernel.EntityID) *uuid.UUID {
	if value == nil {
		return nil
	}
	result := slaUUID(*value)
	return &result
}

func decodeSLACalendar(tenantID uuid.UUID, raw []byte) (application.CalendarRecord, error) {
	var document slaCalendarDocument
	if err := unmarshalSLADocument(raw, &document); err != nil {
		return application.CalendarRecord{}, err
	}
	if !normalizeSLADocumentTimes(&document.CreatedAt, &document.UpdatedAt, &document.ArchivedAt) {
		return application.CalendarRecord{}, errors.New("database returned invalid SLA calendar timestamps")
	}
	weekly := make([]kernel.WeeklyScheduleInput, len(document.WeeklySchedule))
	for index, schedule := range document.WeeklySchedule {
		if schedule.Weekday < int(time.Sunday) || schedule.Weekday > int(time.Saturday) {
			return application.CalendarRecord{}, errors.New("database returned an invalid SLA weekday")
		}
		weekly[index] = kernel.WeeklyScheduleInput{
			Weekday: time.Weekday(schedule.Weekday), Intervals: decodeSLAIntervals(schedule.Intervals),
		}
	}
	exceptions := make([]kernel.DateExceptionInput, len(document.Exceptions))
	for index, exception := range document.Exceptions {
		exceptions[index] = kernel.DateExceptionInput{
			Date: exception.Date, Closed: exception.Closed, Intervals: decodeSLAIntervals(exception.Intervals),
		}
	}
	id, tenant, key, err := slaIdentity(document.ID, tenantID, document.Key)
	if err != nil || document.ActiveVersion == 0 || document.ResourceVersion == 0 {
		return application.CalendarRecord{}, errors.New("database returned an invalid SLA calendar identity")
	}
	calendar, err := kernel.NewBusinessCalendar(kernel.BusinessCalendarInput{
		ID: id, TenantID: tenant, Key: key, Label: document.Label, Timezone: document.Timezone,
		Version: document.ActiveVersion, WeeklySchedules: weekly, Exceptions: exceptions,
	})
	if err != nil || !matchesSLADigest(document.RevisionDigest, calendar.Digest()) ||
		!validSLATimestamps(document.CreatedAt, document.UpdatedAt, document.ArchivedAt) {
		return application.CalendarRecord{}, errors.New("database returned an invalid SLA calendar")
	}
	return application.CalendarRecord{
		Value: calendar, ResourceVersion: document.ResourceVersion, CreatedAt: document.CreatedAt,
		UpdatedAt: document.UpdatedAt, ArchivedAt: document.ArchivedAt,
	}, nil
}

func decodeSLARuntimeState(
	tenantID uuid.UUID,
	resource application.Resource,
	raw []byte,
) (decodedSLARuntimeState, error) {
	return decodeSLARuntimeStateForAudience(tenantID, resource, raw, false)
}

func decodeSLACustomerRuntimeState(
	tenantID uuid.UUID,
	resource application.Resource,
	raw []byte,
) (decodedSLARuntimeState, error) {
	return decodeSLARuntimeStateForAudience(tenantID, resource, raw, true)
}

func decodeSLARuntimeStateForAudience(
	tenantID uuid.UUID,
	resource application.Resource,
	raw []byte,
	customer bool,
) (decodedSLARuntimeState, error) {
	var document slaRuntimeStateDocument
	if err := unmarshalSLADocument(raw, &document); err != nil {
		return decodedSLARuntimeState{}, err
	}
	if customer {
		if err := validateSLACustomerRuntimeDocument(document); err != nil {
			return decodedSLARuntimeState{}, err
		}
	}
	if document.PermissionEpoch == 0 || document.SubjectEpoch == 0 ||
		document.Facts.TenantID != tenantID || document.Facts.ObjectType != resource.ObjectType ||
		document.Facts.ObjectID != slaUUID(resource.ObjectID) || !normalizeSLAInstant(&document.Facts.EvaluatedAt) {
		return decodedSLARuntimeState{}, errors.New("database returned invalid SLA runtime authority or facts")
	}
	tenant, err := kernel.ParseEntityID(tenantID.String())
	if err != nil {
		return decodedSLARuntimeState{}, err
	}
	facts := make([]kernel.FactInput, len(document.Facts.Facts))
	for index, fact := range document.Facts.Facts {
		key := kernel.Key{}
		if fact.Key != nil {
			key, err = kernel.NewKey(*fact.Key)
			if err != nil {
				return decodedSLARuntimeState{}, errors.New("database returned an invalid SLA fact key")
			}
		}
		facts[index] = kernel.FactInput{
			Path: kernel.FactPath{Kind: fact.Kind, Key: key}, Values: append([]string(nil), fact.Values...),
		}
	}
	snapshot, err := kernel.NewFactSnapshot(kernel.FactSnapshotInput{
		TenantID: tenant, ObjectType: resource.ObjectType, EvaluatedAt: document.Facts.EvaluatedAt,
		Timezone: document.Facts.Timezone, Facts: facts,
	})
	if err != nil {
		return decodedSLARuntimeState{}, errors.New("database returned invalid SLA runtime facts")
	}
	result := decodedSLARuntimeState{
		Facts: snapshot, PermissionEpoch: document.PermissionEpoch, SubjectEpoch: document.SubjectEpoch,
		OccurredAt: document.OccurredAt,
	}
	if document.Aggregate != nil {
		aggregate := document.Aggregate
		if aggregate.TenantID != tenantID || aggregate.ObjectType != resource.ObjectType ||
			aggregate.ObjectID != slaUUID(resource.ObjectID) || aggregate.AggregateVersion == 0 ||
			aggregate.PolicyVersion == 0 || !authorizationUUIDv7(aggregate.ID) || !authorizationUUIDv7(aggregate.PolicyID) ||
			!normalizeSLAInstant(&aggregate.CreatedAt) || !normalizeSLAInstant(&aggregate.UpdatedAt) ||
			!normalizeSLAInstantPointer(aggregate.CompletedAt) || aggregate.UpdatedAt.Before(aggregate.CreatedAt) {
			return decodedSLARuntimeState{}, errors.New("database returned an invalid SLA aggregate")
		}
		result.Aggregate = aggregate
		result.Metrics, err = decodeSLARuntimeMetrics(tenantID, resource, *aggregate, document.Metrics, customer)
		if err != nil {
			return decodedSLARuntimeState{}, err
		}
	} else if len(document.Metrics) != 0 {
		return decodedSLARuntimeState{}, errors.New("database returned orphan SLA runtime metrics")
	}
	result.ActivePolicies, err = decodeSLAPolicyDocuments(tenantID, document.ActivePolicies)
	if err != nil {
		return decodedSLARuntimeState{}, err
	}
	result.ActiveCalendars, err = decodeSLACalendarDocuments(tenantID, document.ActiveCalendars)
	if err != nil {
		return decodedSLARuntimeState{}, err
	}
	result.ActiveColumns, err = decodeSLAColumnDocuments(tenantID, document.ActiveColumns)
	if err != nil {
		return decodedSLARuntimeState{}, err
	}
	if document.ReplacementCalendar != nil {
		values, decodeErr := decodeSLACalendarDocuments(tenantID, []slaCalendarDocument{*document.ReplacementCalendar})
		if decodeErr != nil {
			return decodedSLARuntimeState{}, decodeErr
		}
		result.ReplacementCalendar = &values[0]
	}
	if document.ReplacementPolicy != nil {
		values, decodeErr := decodeSLAPolicyDocuments(tenantID, []slaPolicyDocument{*document.ReplacementPolicy})
		if decodeErr != nil {
			return decodedSLARuntimeState{}, decodeErr
		}
		result.ReplacementPolicy = &values[0]
	}
	result.ReplacementCalendars, err = decodeSLACalendarDocuments(tenantID, document.ReplacementCalendars)
	if err != nil {
		return decodedSLARuntimeState{}, err
	}
	result.ReplacementColumns, err = decodeSLAColumnDocuments(tenantID, document.ReplacementColumns)
	if err != nil {
		return decodedSLARuntimeState{}, err
	}
	if document.SimulationDigest != nil {
		decoded, decodeErr := hex.DecodeString(*document.SimulationDigest)
		if decodeErr != nil || len(decoded) != sha256.Size {
			return decodedSLARuntimeState{}, errors.New("database returned an invalid SLA simulation digest")
		}
		copy(result.SimulationDigest[:], decoded)
	}
	if !document.OccurredAt.IsZero() && !normalizeSLAInstant(&result.OccurredAt) {
		return decodedSLARuntimeState{}, errors.New("database returned an invalid SLA occurrence instant")
	}
	return result, nil
}

func validateSLACustomerRuntimeDocument(document slaRuntimeStateDocument) error {
	if len(document.Facts.Facts) != 0 || len(document.ActivePolicies) != 0 || len(document.ActiveCalendars) != 0 ||
		len(document.ActiveColumns) != 0 || document.ReplacementCalendar != nil || document.ReplacementPolicy != nil ||
		len(document.ReplacementCalendars) != 0 || len(document.ReplacementColumns) != 0 || document.SimulationDigest != nil {
		return errors.New("database returned an operator-shaped customer SLA runtime document")
	}
	for _, metric := range document.Metrics {
		if !metric.Definition.APIVisible || !metric.Definition.CustomerVisible ||
			len(metric.Triggers) != 0 || len(metric.Cursors) != 0 {
			return errors.New("database returned a private customer SLA metric")
		}
		for _, column := range metric.Columns {
			if !column.CustomerVisible {
				return errors.New("database returned a private customer SLA column")
			}
		}
	}
	return nil
}

func decodeSLARuntimeMetrics(
	tenantID uuid.UUID,
	resource application.Resource,
	aggregate slaAggregateDocument,
	documents []slaRuntimeMetricDocument,
	customer bool,
) ([]kernel.MetricWork, error) {
	if (!customer && len(documents) == 0) || len(documents) > 32 {
		return nil, errors.New("database returned an invalid SLA metric inventory")
	}
	tenant, _ := kernel.ParseEntityID(tenantID.String())
	objectID := resource.ObjectID
	slaInstanceID, err := kernel.ParseEntityID(aggregate.ID.String())
	if err != nil {
		return nil, err
	}
	seen := make(map[kernel.EntityID]struct{}, len(documents))
	result := make([]kernel.MetricWork, len(documents))
	for index, document := range documents {
		operatorOrderInvalid := !customer && document.Definition.Position != uint16(index)
		customerOrderInvalid := customer && index > 0 &&
			documents[index-1].Definition.Position >= document.Definition.Position
		if operatorOrderInvalid || customerOrderInvalid {
			return nil, errors.New("database returned unordered SLA runtime metrics")
		}
		metric, decodeErr := decodeSLAMetric(document.Definition)
		if decodeErr != nil || document.DefinitionID != slaUUID(metric.ID()) || document.TenantID != tenantID ||
			document.SLAInstanceID != aggregate.ID || document.PolicyID != aggregate.PolicyID ||
			document.PolicyVersion != aggregate.PolicyVersion || !authorizationUUIDv7(document.ID) ||
			document.Version == 0 || !normalizeSLARuntimeMetricTimes(&document) {
			return nil, errors.New("database returned an invalid SLA metric runtime projection")
		}
		id, _ := kernel.ParseEntityID(document.ID.String())
		policyID, _ := kernel.ParseEntityID(document.PolicyID.String())
		if _, duplicate := seen[id]; duplicate {
			return nil, errors.New("database returned duplicate SLA metric runtime identity")
		}
		seen[id] = struct{}{}
		extension, durationErr := durationFromMicros(document.ExtensionMicros)
		if durationErr != nil {
			return nil, durationErr
		}
		consumed, durationErr := durationFromMicros(document.ConsumedMicros)
		if durationErr != nil {
			return nil, durationErr
		}
		lastEventID, parseErr := parseOptionalSLAEntity(document.LastEventID)
		if parseErr != nil {
			return nil, parseErr
		}
		lastOverrideID, parseErr := parseOptionalSLAEntity(document.LastOverrideID)
		if parseErr != nil {
			return nil, parseErr
		}
		lastEventKey, parseErr := optionalSLAKey(document.LastEventKey)
		if parseErr != nil {
			return nil, parseErr
		}
		lastOverrideDigest, parseErr := decodeOptionalSLADigest(document.LastOverrideDigestHex)
		if parseErr != nil {
			return nil, parseErr
		}
		instance, restoreErr := kernel.RestoreMetricInstance(kernel.MetricInstanceSnapshot{
			ID: id, SLAInstanceID: slaInstanceID, TenantID: tenant, ObjectType: resource.ObjectType,
			ObjectID: objectID, PolicyID: policyID, PolicyVersion: document.PolicyVersion,
			Definition: metric, CreatedAt: document.CreatedAt, UpdatedAt: document.UpdatedAt,
			Extension: extension, Lifecycle: document.Lifecycle, StartedAt: document.StartedAt,
			LastResumedAt: document.LastResumedAt, PausedAt: document.PausedAt,
			CompletedAt: document.CompletedAt, DueAt: document.DueAt,
			BreachThresholdAt: document.BreachThresholdAt, BreachedAt: document.BreachedAt,
			Consumed: consumed, LastEventID: lastEventID, LastEventKey: lastEventKey,
			LastEventAt: document.LastEventAt, LastOverrideID: lastOverrideID,
			LastOverrideDigest: lastOverrideDigest, Version: document.Version,
		})
		if restoreErr != nil {
			return nil, errors.New("database returned a non-restorable SLA metric")
		}
		work := kernel.MetricWork{Instance: instance}
		if document.Calendar != nil {
			calendars, calendarErr := decodeSLACalendarDocuments(tenantID, []slaCalendarDocument{*document.Calendar})
			if calendarErr != nil {
				return nil, calendarErr
			}
			work.Calendar = &calendars[0]
		}
		if (metric.Clock() == kernel.ClockBusiness) != (work.Calendar != nil) {
			return nil, errors.New("database returned an invalid SLA calendar binding")
		}
		if work.Calendar != nil {
			calendarID := metric.CalendarID()
			if calendarID == nil || work.Calendar.ID() != *calendarID ||
				work.Calendar.Version() != metric.CalendarVersion() {
				return nil, errors.New("database returned a mismatched SLA calendar binding")
			}
		}
		work.Triggers, decodeErr = decodeSLATriggerBindings(metric, document.Triggers, document.Cursors)
		if decodeErr != nil {
			return nil, decodeErr
		}
		work.Columns, decodeErr = decodeSLAColumnDocumentsForMetric(tenantID, document.Columns, metric)
		if decodeErr != nil {
			return nil, decodeErr
		}
		result[index] = work
	}
	return result, nil
}

func decodeSLAPolicy(tenantID uuid.UUID, raw []byte) (application.PolicyRecord, error) {
	var document slaPolicyDocument
	if err := unmarshalSLADocument(raw, &document); err != nil {
		return application.PolicyRecord{}, err
	}
	if !normalizeSLADocumentTimes(&document.CreatedAt, &document.UpdatedAt, &document.ArchivedAt) ||
		!normalizeSLAInstant(&document.EffectiveFrom) || !normalizeSLAInstantPointer(document.EffectiveUntil) {
		return application.PolicyRecord{}, errors.New("database returned invalid SLA policy timestamps")
	}
	id, tenant, key, err := slaIdentity(document.ID, tenantID, document.Key)
	if err != nil || document.ActiveVersion == 0 || document.ResourceVersion == 0 {
		return application.PolicyRecord{}, errors.New("database returned an invalid SLA policy identity")
	}
	rule, err := kernel.NewRule(decodeSLARule(document.MatchRule))
	if err != nil {
		return application.PolicyRecord{}, errors.New("database returned an invalid SLA policy rule")
	}
	metrics := make([]kernel.MetricDefinition, len(document.Metrics))
	metricByID := make(map[kernel.EntityID]kernel.MetricDefinition, len(document.Metrics))
	for index, metricDocument := range document.Metrics {
		if metricDocument.Position != uint16(index) {
			return application.PolicyRecord{}, errors.New("database returned an unordered SLA metric")
		}
		metric, metricErr := decodeSLAMetric(metricDocument)
		if metricErr != nil {
			return application.PolicyRecord{}, metricErr
		}
		metrics[index] = metric
		metricByID[metric.ID()] = metric
	}
	triggers := make([]kernel.TriggerDefinition, len(document.Triggers))
	for index, triggerDocument := range document.Triggers {
		if triggerDocument.Position != uint16(index) {
			return application.PolicyRecord{}, errors.New("database returned an unordered SLA trigger")
		}
		metricID, parseErr := kernel.ParseEntityID(triggerDocument.MetricDefinitionID.String())
		metric, found := metricByID[metricID]
		if parseErr != nil || !found {
			return application.PolicyRecord{}, errors.New("database returned an orphan SLA trigger")
		}
		trigger, triggerErr := decodeSLATrigger(triggerDocument, metric)
		if triggerErr != nil {
			return application.PolicyRecord{}, triggerErr
		}
		triggers[index] = trigger
	}
	policy, err := kernel.NewPolicy(kernel.PolicyInput{
		ID: id, TenantID: tenant, Key: key, Name: document.Name, Description: document.Description,
		Version: document.ActiveVersion, Priority: document.Priority, ObjectTypes: document.ObjectTypes,
		MatchRule: rule, Metrics: metrics, Triggers: triggers, EffectiveFrom: document.EffectiveFrom,
		EffectiveUntil: document.EffectiveUntil, Enabled: document.Enabled,
		ApplyToSLAEngineSource: document.ApplyToSLAEngineSource,
	})
	if err != nil || !matchesSLADigest(document.RevisionDigest, policy.Digest()) ||
		!validSLATimestamps(document.CreatedAt, document.UpdatedAt, document.ArchivedAt) {
		return application.PolicyRecord{}, errors.New("database returned an invalid SLA policy")
	}
	return application.PolicyRecord{
		Value: policy, ResourceVersion: document.ResourceVersion, CreatedAt: document.CreatedAt,
		UpdatedAt: document.UpdatedAt, ArchivedAt: document.ArchivedAt,
	}, nil
}

func decodeSLACalendarDocuments(tenantID uuid.UUID, documents []slaCalendarDocument) ([]kernel.BusinessCalendar, error) {
	result := make([]kernel.BusinessCalendar, len(documents))
	for index, document := range documents {
		raw, err := marshalSLADocument(document)
		if err != nil {
			return nil, err
		}
		record, err := decodeSLACalendar(tenantID, raw)
		if err != nil {
			return nil, err
		}
		result[index] = record.Value
	}
	return result, nil
}

func decodeSLAPolicyDocuments(tenantID uuid.UUID, documents []slaPolicyDocument) ([]kernel.Policy, error) {
	result := make([]kernel.Policy, len(documents))
	for index, document := range documents {
		raw, err := marshalSLADocument(document)
		if err != nil {
			return nil, err
		}
		record, err := decodeSLAPolicy(tenantID, raw)
		if err != nil {
			return nil, err
		}
		result[index] = record.Value
	}
	return result, nil
}

func decodeSLAColumnDocuments(tenantID uuid.UUID, documents []slaColumnDocument) ([]kernel.ColumnDefinition, error) {
	result := make([]kernel.ColumnDefinition, len(documents))
	for index, document := range documents {
		if document.Metric == nil {
			return nil, errors.New("database omitted an SLA column metric")
		}
		metric, err := decodeSLAMetric(*document.Metric)
		if err != nil {
			return nil, err
		}
		values, err := decodeSLAColumnDocumentsForMetric(tenantID, []slaColumnDocument{document}, metric)
		if err != nil {
			return nil, err
		}
		result[index] = values[0]
	}
	return result, nil
}

func decodeSLAColumnDocumentsForMetric(
	tenantID uuid.UUID,
	documents []slaColumnDocument,
	metric kernel.MetricDefinition,
) ([]kernel.ColumnDefinition, error) {
	result := make([]kernel.ColumnDefinition, len(documents))
	seen := make(map[kernel.EntityID]struct{}, len(documents))
	for index, document := range documents {
		raw, err := marshalSLADocument(document)
		if err != nil {
			return nil, err
		}
		record, err := decodeSLAColumn(tenantID, raw, &metric)
		if err != nil {
			return nil, err
		}
		if _, duplicate := seen[record.Value.ID()]; duplicate {
			return nil, errors.New("database returned duplicate SLA columns")
		}
		seen[record.Value.ID()] = struct{}{}
		result[index] = record.Value
	}
	return result, nil
}

func decodeSLATriggerBindings(
	metric kernel.MetricDefinition,
	triggers []slaTriggerDocument,
	cursors []slaTriggerCursorDocument,
) ([]kernel.TriggerBinding, error) {
	if len(triggers) > 256 || len(cursors) > len(triggers) {
		return nil, errors.New("database returned an invalid SLA trigger inventory")
	}
	cursorByID := make(map[uuid.UUID]slaTriggerCursorDocument, len(cursors))
	for _, cursor := range cursors {
		if _, duplicate := cursorByID[cursor.TriggerDefinitionID]; duplicate {
			return nil, errors.New("database returned duplicate SLA trigger cursors")
		}
		cursorByID[cursor.TriggerDefinitionID] = cursor
	}
	result := make([]kernel.TriggerBinding, len(triggers))
	seen := make(map[uuid.UUID]struct{}, len(triggers))
	for index, document := range triggers {
		// Each metric contains an ordered subset of policy-global positions.
		if index > 0 && document.Position <= triggers[index-1].Position {
			return nil, errors.New("database returned unordered SLA triggers")
		}
		if _, duplicate := seen[document.ID]; duplicate {
			return nil, errors.New("database returned duplicate SLA triggers")
		}
		seen[document.ID] = struct{}{}
		definition, err := decodeSLATrigger(document, metric)
		if err != nil {
			return nil, err
		}
		cursor, err := kernel.NewTriggerCursor(definition.ID())
		if err != nil {
			return nil, err
		}
		if stored, exists := cursorByID[document.ID]; exists {
			if !normalizeSLAInstantPointer(stored.LastObservedAt) || !normalizeSLAInstantPointer(stored.LastFiredAt) {
				return nil, errors.New("database returned an invalid SLA trigger cursor instant")
			}
			var lastState kernel.MetricState
			if stored.LastState != nil {
				lastState = *stored.LastState
			}
			remaining, durationErr := durationFromMicros(stored.LastRemainingMicros)
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
				return nil, errors.New("database returned a non-restorable SLA trigger cursor")
			}
			delete(cursorByID, document.ID)
		}
		result[index] = kernel.TriggerBinding{Definition: definition, Cursor: cursor}
	}
	if len(cursorByID) != 0 {
		return nil, errors.New("database returned orphan SLA trigger cursors")
	}
	return result, nil
}

func normalizeSLARuntimeMetricTimes(document *slaRuntimeMetricDocument) bool {
	if document == nil || !normalizeSLAInstant(&document.CreatedAt) || !normalizeSLAInstant(&document.UpdatedAt) ||
		!normalizeSLAInstantPointer(document.StartedAt) || !normalizeSLAInstantPointer(document.LastResumedAt) ||
		!normalizeSLAInstantPointer(document.PausedAt) || !normalizeSLAInstantPointer(document.CompletedAt) ||
		!normalizeSLAInstantPointer(document.DueAt) || !normalizeSLAInstantPointer(document.BreachThresholdAt) ||
		!normalizeSLAInstantPointer(document.BreachedAt) || !normalizeSLAInstantPointer(document.LastEventAt) {
		return false
	}
	return !document.UpdatedAt.Before(document.CreatedAt)
}

func parseOptionalSLAEntity(value *uuid.UUID) (*kernel.EntityID, error) {
	if value == nil {
		return nil, nil
	}
	parsed, err := kernel.ParseEntityID(value.String())
	if err != nil {
		return nil, errors.New("database returned an invalid optional SLA identity")
	}
	return &parsed, nil
}

func decodeOptionalSLADigest(value *string) ([32]byte, error) {
	if value == nil {
		return [32]byte{}, nil
	}
	decoded, err := hex.DecodeString(*value)
	if err != nil || len(decoded) != sha256.Size {
		return [32]byte{}, errors.New("database returned an invalid optional SLA digest")
	}
	var result [32]byte
	copy(result[:], decoded)
	return result, nil
}

func decodeSLAColumn(
	tenantID uuid.UUID,
	raw []byte,
	metric *kernel.MetricDefinition,
) (application.ColumnRecord, error) {
	var document slaColumnDocument
	if err := unmarshalSLADocument(raw, &document); err != nil {
		return application.ColumnRecord{}, err
	}
	if !normalizeSLADocumentTimes(&document.CreatedAt, &document.UpdatedAt, &document.ArchivedAt) {
		return application.ColumnRecord{}, errors.New("database returned invalid SLA column timestamps")
	}
	if metric == nil && document.Metric != nil {
		value, metricErr := decodeSLAMetric(*document.Metric)
		if metricErr != nil {
			return application.ColumnRecord{}, metricErr
		}
		metric = &value
	}
	if metric == nil {
		return application.ColumnRecord{}, errors.New("database omitted the SLA column metric definition")
	}
	id, tenant, key, err := slaIdentity(document.ID, tenantID, document.Key)
	if err != nil || document.ActiveVersion == 0 || document.ResourceVersion == 0 ||
		document.MetricDefinitionID != slaUUID(metric.ID()) {
		return application.ColumnRecord{}, errors.New("database returned an invalid SLA column identity")
	}
	roleKeys := make([]kernel.Key, len(document.VisibleRoleKeys))
	for index, value := range document.VisibleRoleKeys {
		roleKeys[index], err = kernel.NewKey(value)
		if err != nil {
			return application.ColumnRecord{}, errors.New("database returned an invalid SLA column role")
		}
	}
	styles := make([]kernel.ColumnStyleRuleInput, len(document.StyleRules))
	for index, style := range document.StyleRules {
		styleKey, styleErr := kernel.NewKey(style.StyleKey)
		if styleErr != nil {
			return application.ColumnRecord{}, errors.New("database returned an invalid SLA column style")
		}
		var maximumRemaining *time.Duration
		if style.MaximumRemainingMicros != nil {
			value, durationErr := durationFromMicros(*style.MaximumRemainingMicros)
			if durationErr != nil {
				return application.ColumnRecord{}, durationErr
			}
			maximumRemaining = &value
		}
		styles[index] = kernel.ColumnStyleRuleInput{
			StyleKey: styleKey, State: style.State, MinimumPercentage: style.MinimumPercentage,
			MaximumRemaining: maximumRemaining,
		}
	}
	column, err := kernel.NewColumnDefinition(*metric, kernel.ColumnDefinitionInput{
		ID: id, TenantID: tenant, Key: key, Label: document.Label,
		MetricID: metric.ID(), Calculation: document.Calculation, Format: document.Format,
		Sortable: document.Sortable, Filterable: document.Filterable,
		CustomerVisible: document.CustomerVisible, VisibleRoleKeys: roleKeys,
		Position: document.Position, Version: document.ActiveVersion, StyleRules: styles,
	})
	if err != nil || !matchesSLADigest(document.RevisionDigest, column.Digest()) ||
		!validSLATimestamps(document.CreatedAt, document.UpdatedAt, document.ArchivedAt) {
		return application.ColumnRecord{}, errors.New("database returned an invalid SLA column")
	}
	return application.ColumnRecord{
		Value: column, ResourceVersion: document.ResourceVersion, CreatedAt: document.CreatedAt,
		UpdatedAt: document.UpdatedAt, ArchivedAt: document.ArchivedAt,
	}, nil
}

func decodeSLAMetric(document slaMetricDocument) (kernel.MetricDefinition, error) {
	id, err := kernel.ParseEntityID(document.ID.String())
	if err != nil {
		return kernel.MetricDefinition{}, errors.New("database returned an invalid SLA metric identity")
	}
	key, err := kernel.NewKey(document.Key)
	if err != nil {
		return kernel.MetricDefinition{}, errors.New("database returned an invalid SLA metric key")
	}
	start, err := kernel.NewKey(document.StartEvent)
	if err != nil {
		return kernel.MetricDefinition{}, errors.New("database returned an invalid SLA start event")
	}
	completion, err := kernel.NewKey(document.CompletionEvent)
	if err != nil {
		return kernel.MetricDefinition{}, errors.New("database returned an invalid SLA completion event")
	}
	pause, err := optionalSLAKey(document.PauseEvent)
	if err != nil {
		return kernel.MetricDefinition{}, err
	}
	resume, err := optionalSLAKey(document.ResumeEvent)
	if err != nil {
		return kernel.MetricDefinition{}, err
	}
	reset, err := optionalSLAKey(document.ResetEvent)
	if err != nil {
		return kernel.MetricDefinition{}, err
	}
	duration, err := durationFromMicros(document.DurationMicros)
	if err != nil {
		return kernel.MetricDefinition{}, err
	}
	grace, err := durationFromMicros(document.BreachGraceMicros)
	if err != nil {
		return kernel.MetricDefinition{}, err
	}
	var calendarID *kernel.EntityID
	if document.CalendarID != nil {
		value, parseErr := kernel.ParseEntityID(document.CalendarID.String())
		if parseErr != nil {
			return kernel.MetricDefinition{}, errors.New("database returned an invalid SLA calendar reference")
		}
		calendarID = &value
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
		warning.RemainingDuration, err = durationFromMicros(*document.WarningRemainingMicros)
		if err != nil {
			return kernel.MetricDefinition{}, err
		}
	}
	metric, err := kernel.NewMetricDefinition(kernel.MetricDefinitionInput{
		ID: id, Key: key, Label: document.Label, Description: document.Description,
		Duration: duration, Clock: document.Clock, CalendarID: calendarID,
		CalendarVersion: calendarVersion, StartEvent: start, PauseEvent: pause,
		ResumeEvent: resume, CompletionEvent: completion, ResetEvent: reset,
		ResetPolicy: document.ResetPolicy, Warning: warning, BreachGrace: grace,
		DisplayFormat: document.DisplayFormat, CustomerVisible: document.CustomerVisible,
		APIVisible: document.APIVisible,
	})
	if err != nil || !matchesSLADigest(document.DefinitionDigest, metric.Digest()) {
		return kernel.MetricDefinition{}, errors.New("database returned an invalid SLA metric")
	}
	return metric, nil
}

func decodeSLATrigger(document slaTriggerDocument, metric kernel.MetricDefinition) (kernel.TriggerDefinition, error) {
	id, err := kernel.ParseEntityID(document.ID.String())
	if err != nil || document.MetricDefinitionID != slaUUID(metric.ID()) {
		return kernel.TriggerDefinition{}, errors.New("database returned an invalid SLA trigger identity")
	}
	key, err := kernel.NewKey(document.Key)
	if err != nil {
		return kernel.TriggerDefinition{}, errors.New("database returned an invalid SLA trigger key")
	}
	configurationID := (*kernel.EntityID)(nil)
	if document.ActionConfigurationID != nil {
		parsed, parseErr := kernel.ParseEntityID(document.ActionConfigurationID.String())
		if parseErr != nil {
			return kernel.TriggerDefinition{}, errors.New("database returned an invalid SLA trigger configuration")
		}
		configurationID = &parsed
	}
	var actionValue kernel.Key
	var actionText string
	if document.ActionKind == kernel.ActionCreateTask {
		if document.ActionValue != nil {
			actionText = *document.ActionValue
		}
	} else {
		actionValue, err = optionalSLAKey(document.ActionValue)
		if err != nil {
			return kernel.TriggerDefinition{}, err
		}
	}
	remaining, err := optionalSLADuration(document.RemainingMicros)
	if err != nil {
		return kernel.TriggerDefinition{}, err
	}
	offset, err := optionalSLADuration(document.OffsetMicros)
	if err != nil {
		return kernel.TriggerDefinition{}, err
	}
	repeat, err := optionalSLADuration(document.RepeatIntervalMicros)
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
	trigger, err := kernel.NewTriggerDefinition(metric, kernel.TriggerDefinitionInput{
		ID: id, Key: key, MetricID: metric.ID(), Kind: document.Kind,
		ConsumedPercent: consumed, Remaining: remaining, Offset: offset,
		RepeatInterval: repeat, TargetState: state,
		Action: kernel.TriggerActionInput{
			Kind: document.ActionKind, ConfigurationID: configurationID,
			Value: actionValue, Text: actionText, AllowRecursiveSLA: document.AllowRecursiveSLA,
		},
	})
	if err != nil || !matchesSLADigest(document.DefinitionDigest, trigger.Digest()) {
		return kernel.TriggerDefinition{}, errors.New("database returned an invalid SLA trigger")
	}
	return trigger, nil
}

func encodeSLAMetric(metric kernel.MetricDefinition, position uint16) slaMetricDocument {
	input := metric.Input()
	document := slaMetricDocument{
		ID: slaUUID(input.ID), Key: input.Key.String(), Label: input.Label,
		Description: input.Description, DurationMicros: input.Duration.Microseconds(),
		Clock: input.Clock, StartEvent: input.StartEvent.String(),
		CompletionEvent: input.CompletionEvent.String(), ResetPolicy: input.ResetPolicy,
		WarningKind: input.Warning.Kind, BreachGraceMicros: input.BreachGrace.Microseconds(),
		DisplayFormat: input.DisplayFormat, CustomerVisible: input.CustomerVisible,
		APIVisible: input.APIVisible, Position: position,
		DefinitionDigest: encodeSLADigest(metric.Digest()),
	}
	if input.CalendarID != nil {
		value := slaUUID(*input.CalendarID)
		document.CalendarID = &value
		version := input.CalendarVersion
		document.CalendarVersion = &version
	}
	document.PauseEvent = slaStringPointer(input.PauseEvent.String())
	document.ResumeEvent = slaStringPointer(input.ResumeEvent.String())
	document.ResetEvent = slaStringPointer(input.ResetEvent.String())
	if input.Warning.Kind == kernel.WarningConsumedPercent {
		value := input.Warning.ConsumedPercent
		document.WarningConsumedPercent = &value
	}
	if input.Warning.Kind == kernel.WarningRemainingDuration {
		value := input.Warning.RemainingDuration.Microseconds()
		document.WarningRemainingMicros = &value
	}
	return document
}

func encodeSLATrigger(trigger kernel.TriggerDefinition, position uint16) slaTriggerDocument {
	input := trigger.Input()
	document := slaTriggerDocument{
		ID: slaUUID(input.ID), MetricDefinitionID: slaUUID(input.MetricID),
		Key: input.Key.String(), Kind: input.Kind, ActionKind: input.Action.Kind,
		ActionValue:       slaStringPointer(input.Action.Value.String()),
		AllowRecursiveSLA: input.Action.AllowRecursiveSLA, Position: position,
		DefinitionDigest: encodeSLADigest(trigger.Digest()),
	}
	if input.Action.Kind == kernel.ActionCreateTask {
		document.ActionValue = slaStringPointer(input.Action.Text)
	}
	if input.Action.ConfigurationID != nil {
		value := slaUUID(*input.Action.ConfigurationID)
		document.ActionConfigurationID = &value
	}
	switch input.Kind {
	case kernel.TriggerConsumedPercent:
		value := input.ConsumedPercent
		document.ConsumedPercent = &value
	case kernel.TriggerRemaining:
		value := input.Remaining.Microseconds()
		document.RemainingMicros = &value
	case kernel.TriggerAfterBreach:
		value := input.Offset.Microseconds()
		document.OffsetMicros = &value
	case kernel.TriggerRepeatedBreach:
		offset, repeat := input.Offset.Microseconds(), input.RepeatInterval.Microseconds()
		document.OffsetMicros, document.RepeatIntervalMicros = &offset, &repeat
	case kernel.TriggerStateChanged:
		value := input.TargetState
		document.TargetState = &value
	}
	return document
}

func encodeSLARule(input *kernel.RuleInput) slaRuleDocument {
	if input == nil {
		return slaRuleDocument{}
	}
	document := slaRuleDocument{Kind: input.Kind}
	if input.Kind == kernel.RulePredicate {
		document.Predicate = &slaPredicateDocument{
			Kind: input.Predicate.Path.Kind, Key: input.Predicate.Path.Key.String(),
			Operator: input.Predicate.Operator, Values: append([]string(nil), input.Predicate.Values...),
		}
		return document
	}
	document.Children = make([]slaRuleDocument, len(input.Children))
	for index, child := range input.Children {
		document.Children[index] = encodeSLARule(child)
	}
	return document
}

func decodeSLARule(document slaRuleDocument) *kernel.RuleInput {
	input := &kernel.RuleInput{Kind: document.Kind}
	if document.Predicate != nil {
		key, _ := kernel.NewKey(document.Predicate.Key)
		input.Predicate = kernel.PredicateInput{
			Path:     kernel.FactPath{Kind: document.Predicate.Kind, Key: key},
			Operator: document.Predicate.Operator,
			Values:   append([]string(nil), document.Predicate.Values...),
		}
	}
	input.Children = make([]*kernel.RuleInput, len(document.Children))
	for index, child := range document.Children {
		input.Children[index] = decodeSLARule(child)
	}
	return input
}

func encodeSLAIntervals(values []kernel.MinuteIntervalInput) []slaMinuteIntervalDocument {
	result := make([]slaMinuteIntervalDocument, len(values))
	for index, value := range values {
		result[index] = slaMinuteIntervalDocument{StartMinute: value.StartMinute, EndMinute: value.EndMinute}
	}
	return result
}

func decodeSLAIntervals(values []slaMinuteIntervalDocument) []kernel.MinuteIntervalInput {
	result := make([]kernel.MinuteIntervalInput, len(values))
	for index, value := range values {
		result[index] = kernel.MinuteIntervalInput{StartMinute: value.StartMinute, EndMinute: value.EndMinute}
	}
	return result
}

func slaIdentity(idValue, tenantID uuid.UUID, keyValue string) (kernel.EntityID, kernel.EntityID, kernel.Key, error) {
	id, err := kernel.ParseEntityID(idValue.String())
	if err != nil || !authorizationUUIDv7(tenantID) {
		return kernel.EntityID{}, kernel.EntityID{}, kernel.Key{}, errors.New("invalid SLA identity")
	}
	tenant, err := kernel.ParseEntityID(tenantID.String())
	if err != nil {
		return kernel.EntityID{}, kernel.EntityID{}, kernel.Key{}, errors.New("invalid SLA tenant")
	}
	key, err := kernel.NewKey(keyValue)
	if err != nil {
		return kernel.EntityID{}, kernel.EntityID{}, kernel.Key{}, errors.New("invalid SLA key")
	}
	return id, tenant, key, nil
}

func marshalSLADocument(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode SLA document: %w", err)
	}
	if len(encoded) == 0 || len(encoded) > maximumSLADocumentBytes {
		return nil, errors.New("SLA document is oversized")
	}
	return encoded, nil
}

func unmarshalSLADocument(raw []byte, target any) error {
	if len(raw) == 0 || len(raw) > maximumSLADocumentBytes || target == nil {
		return errors.New("database returned an invalid SLA document")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode SLA document: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("database returned trailing SLA document data")
	}
	return nil
}

func durationFromMicros(value int64) (time.Duration, error) {
	if value < 0 || value > math.MaxInt64/int64(time.Microsecond) {
		return 0, errors.New("database returned an invalid SLA duration")
	}
	return time.Duration(value) * time.Microsecond, nil
}

func optionalSLADuration(value *int64) (time.Duration, error) {
	if value == nil {
		return 0, nil
	}
	return durationFromMicros(*value)
}

func optionalSLAKey(value *string) (kernel.Key, error) {
	if value == nil {
		return kernel.Key{}, nil
	}
	key, err := kernel.NewKey(*value)
	if err != nil {
		return kernel.Key{}, errors.New("database returned an invalid optional SLA key")
	}
	return key, nil
}

func slaStringPointer(value string) *string {
	if value == "" {
		return nil
	}
	copy := value
	return &copy
}

func slaUUID(id kernel.EntityID) uuid.UUID { return uuid.UUID(id.Bytes()) }

func matchesSLADigest(value string, expected [sha256.Size]byte) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && bytes.Equal(decoded, expected[:])
}

func encodeSLADigest(value [sha256.Size]byte) string { return hex.EncodeToString(value[:]) }

func validSLATimestamps(createdAt, updatedAt time.Time, archivedAt *time.Time) bool {
	valid := func(value time.Time) bool {
		return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond()%1_000 == 0
	}
	if !valid(createdAt) || !valid(updatedAt) || updatedAt.Before(createdAt) {
		return false
	}
	return archivedAt == nil || valid(*archivedAt) && !archivedAt.Before(createdAt) && !archivedAt.After(updatedAt)
}

func normalizeSLADocumentTimes(createdAt, updatedAt *time.Time, archivedAt **time.Time) bool {
	return createdAt != nil && updatedAt != nil && archivedAt != nil &&
		normalizeSLAInstant(createdAt) && normalizeSLAInstant(updatedAt) &&
		normalizeSLAInstantPointer(*archivedAt)
}

func normalizeSLAInstantPointer(value *time.Time) bool {
	return value == nil || normalizeSLAInstant(value)
}

func normalizeSLAInstant(value *time.Time) bool {
	if value == nil || value.IsZero() || value.Year() < 1970 || value.Year() > 9999 || value.Nanosecond()%1_000 != 0 {
		return false
	}
	*value = value.UTC()
	return true
}
