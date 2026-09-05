package postgres

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/sla"
)

type slaWorkerMetricWrite struct {
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

type slaWorkerCursorWrite struct {
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

type slaWorkerOccurrenceWrite struct {
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

type slaWorkerColumnWrite struct {
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

type slaWorkerPlanWrite struct {
	Metrics              []slaWorkerMetricWrite     `json:"metrics"`
	Cursors              []slaWorkerCursorWrite     `json:"cursors"`
	Occurrences          []slaWorkerOccurrenceWrite `json:"occurrences"`
	Columns              []slaWorkerColumnWrite     `json:"columns"`
	NextEvaluationAt     *time.Time                 `json:"next_evaluation_at"`
	AggregateCompletedAt *time.Time                 `json:"aggregate_completed_at"`
}

func encodeSLAWorkerPlan(plan kernel.EnginePlan) ([]byte, error) {
	return encodeSLAPlan(plan, false, false)
}

func encodeSLAEventEnginePlan(plan kernel.EnginePlan) ([]byte, error) {
	return encodeSLAPlan(plan, true, false)
}

func encodeSLAEventAssignmentPlan(plan kernel.EnginePlan) ([]byte, error) {
	return encodeSLAPlan(plan, true, true)
}

func encodeSLAPlan(plan kernel.EnginePlan, eventRequired bool, includeUnchanged bool) ([]byte, error) {
	metricPlans := plan.Metrics()
	if len(metricPlans) == 0 || len(metricPlans) > 32 ||
		!validSLAWorkerInstant(plan.ObservedAt()) || (plan.EventID() != nil) != eventRequired {
		return nil, errors.New("SLA worker plan has an invalid metric inventory")
	}
	document := slaWorkerPlanWrite{
		Metrics: []slaWorkerMetricWrite{}, Cursors: []slaWorkerCursorWrite{},
		Occurrences: []slaWorkerOccurrenceWrite{}, Columns: []slaWorkerColumnWrite{},
	}
	allCompleted := true
	for _, metricPlan := range metricPlans {
		instance := metricPlan.Instance()
		snapshot := instance.Snapshot()
		allCompleted = allCompleted && snapshot.Lifecycle == kernel.LifecycleCompleted
		if metricPlan.Changed() || includeUnchanged {
			metric, err := encodeSLAWorkerMetric(snapshot, metricPlan.Evaluation().State)
			if err != nil ||
				(metricPlan.Changed() && metricPlan.PreviousVersion()+1 != snapshot.Version) ||
				(!metricPlan.Changed() && metricPlan.PreviousVersion() != snapshot.Version) {
				return nil, errors.New("SLA worker plan has an invalid changed metric")
			}
			document.Metrics = append(document.Metrics, metric)
		} else if metricPlan.PreviousVersion() != snapshot.Version {
			return nil, errors.New("SLA worker plan has an invalid unchanged metric")
		}
		for _, cursor := range metricPlan.TriggerCursors() {
			snapshot := cursor.Snapshot()
			encoded := slaWorkerCursorWrite{
				MetricInstanceID:    uuid.UUID(instance.ID().Bytes()),
				TriggerDefinitionID: uuid.UUID(snapshot.TriggerID.Bytes()),
				Initialized:         snapshot.Initialized, LastObservedAt: snapshot.LastObservedAt,
				LastPercentage:      snapshot.LastPercentage,
				LastRemainingMicros: snapshot.LastRemaining.Microseconds(),
				LastRepeatWindow:    snapshot.LastRepeatWindow,
				LastFiredAt:         snapshot.LastFiredAt, FireCount: snapshot.FireCount,
			}
			if snapshot.Initialized {
				state := snapshot.LastState
				encoded.LastState = &state
			}
			document.Cursors = append(document.Cursors, encoded)
		}
		for _, occurrence := range metricPlan.Occurrences() {
			action := occurrence.Action()
			deduplicationDigest := occurrence.DeduplicationKey()
			encoded := slaWorkerOccurrenceWrite{
				ID:                  uuid.UUID(occurrence.ID().Bytes()),
				MetricInstanceID:    uuid.UUID(instance.ID().Bytes()),
				TriggerDefinitionID: uuid.UUID(occurrence.TriggerID().Bytes()),
				ScheduledAt:         occurrence.ScheduledAt(),
				DeduplicationDigest: hex.EncodeToString(deduplicationDigest[:]),
				ActionKind:          action.Kind(), AllowRecursiveSLA: action.AllowRecursiveSLA(),
			}
			if configurationID := action.ConfigurationID(); configurationID != nil {
				value := uuid.UUID(configurationID.Bytes())
				encoded.ActionConfigurationID = &value
			}
			value := action.Value().String()
			if action.Kind() == kernel.ActionCreateTask {
				value = action.Text()
			}
			encoded.ActionValue = slaWorkerStringPointer(value)
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
			document.Columns = append(document.Columns, slaWorkerColumnWrite{
				MetricInstanceID: uuid.UUID(instance.ID().Bytes()),
				ColumnID:         uuid.UUID(value.ColumnID().Bytes()),
				ColumnVersion:    value.ColumnVersion(), StateValue: stateValue,
				InstantValue: value.Instant(), DurationMicros: durationMicros,
				PercentageValue: value.Percentage(),
				StyleKey:        slaWorkerStringPointer(value.StyleKey().String()),
				NextRefreshAt:   value.NextRefreshAt(),
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
	encoded, err := json.Marshal(document)
	if err != nil || len(encoded) == 0 || len(encoded) > maximumSLAWorkerDocumentBytes {
		return nil, errors.New("SLA worker plan is not encodable")
	}
	return encoded, nil
}

func encodeSLAWorkerMetric(
	snapshot kernel.MetricInstanceSnapshot,
	state kernel.MetricState,
) (slaWorkerMetricWrite, error) {
	if snapshot.Extension < 0 || snapshot.Consumed < 0 ||
		snapshot.Extension%time.Microsecond != 0 || snapshot.Consumed%time.Microsecond != 0 ||
		snapshot.Version == 0 || snapshot.Version >= uint64(math.MaxInt64) ||
		!validSLAWorkerInstant(snapshot.CreatedAt) || !validSLAWorkerInstant(snapshot.UpdatedAt) {
		return slaWorkerMetricWrite{}, errors.New("SLA worker metric state is invalid")
	}
	var lastEventID *uuid.UUID
	if snapshot.LastEventID != nil {
		value := uuid.UUID(snapshot.LastEventID.Bytes())
		lastEventID = &value
	}
	var lastOverrideID *uuid.UUID
	if snapshot.LastOverrideID != nil {
		value := uuid.UUID(snapshot.LastOverrideID.Bytes())
		lastOverrideID = &value
	}
	var overrideDigest *string
	if snapshot.LastOverrideDigest != ([32]byte{}) {
		value := hex.EncodeToString(snapshot.LastOverrideDigest[:])
		overrideDigest = &value
	}
	return slaWorkerMetricWrite{
		ID: uuid.UUID(snapshot.ID.Bytes()), DefinitionID: uuid.UUID(snapshot.Definition.ID().Bytes()),
		PolicyID: uuid.UUID(snapshot.PolicyID.Bytes()), PolicyVersion: snapshot.PolicyVersion,
		Version: snapshot.Version, Lifecycle: snapshot.Lifecycle, State: state,
		CreatedAt: snapshot.CreatedAt, UpdatedAt: snapshot.UpdatedAt,
		ExtensionMicros: snapshot.Extension.Microseconds(),
		ConsumedMicros:  snapshot.Consumed.Microseconds(),
		StartedAt:       snapshot.StartedAt, LastResumedAt: snapshot.LastResumedAt,
		PausedAt: snapshot.PausedAt, CompletedAt: snapshot.CompletedAt,
		DueAt: snapshot.DueAt, BreachThresholdAt: snapshot.BreachThresholdAt,
		BreachedAt: snapshot.BreachedAt, LastEventID: lastEventID,
		LastEventKey: slaWorkerStringPointer(snapshot.LastEventKey.String()),
		LastEventAt:  snapshot.LastEventAt, LastOverrideID: lastOverrideID,
		LastOverrideDigestHex: overrideDigest,
	}, nil
}

func slaWorkerStringPointer(value string) *string {
	if value == "" {
		return nil
	}
	copy := value
	return &copy
}

func validSLAWorkerInstant(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Year() >= 1970 &&
		value.Year() <= 9999 && value.Nanosecond()%1_000 == 0
}
