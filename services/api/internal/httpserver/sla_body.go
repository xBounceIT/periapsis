package httpserver

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

// slaRawJSON marks a bounded, duplicate-free subtree whose exact discriminated
// shape is validated by the SLA mapper. It is never persisted or logged raw.
type slaRawJSON json.RawMessage

type slaMinuteIntervalBody struct {
	StartMinute int `json:"startMinute"`
	EndMinute   int `json:"endMinute"`
}

type slaWeeklyScheduleBody struct {
	Weekday   string                  `json:"weekday"`
	Intervals []slaMinuteIntervalBody `json:"intervals"`
}

type slaDateExceptionBody struct {
	Date      string                  `json:"date"`
	Closed    bool                    `json:"closed"`
	Intervals []slaMinuteIntervalBody `json:"intervals"`
}

type slaCalendarCreateBody struct {
	ID              uuid.UUID               `json:"id"`
	Key             string                  `json:"key"`
	Label           string                  `json:"label"`
	Timezone        string                  `json:"timezone"`
	WeeklySchedules []slaWeeklyScheduleBody `json:"weeklySchedules"`
	Exceptions      []slaDateExceptionBody  `json:"exceptions"`
}

type slaCalendarReplaceBody struct {
	Key             string                  `json:"key"`
	Label           string                  `json:"label"`
	Timezone        string                  `json:"timezone"`
	WeeklySchedules []slaWeeklyScheduleBody `json:"weeklySchedules"`
	Exceptions      []slaDateExceptionBody  `json:"exceptions"`
}

type slaArchiveBody struct {
	Reason string `json:"reason"`
}

type slaMetricWriteBody struct {
	ID                uuid.UUID  `json:"id"`
	Key               string     `json:"key"`
	Label             string     `json:"label"`
	Description       string     `json:"description"`
	DurationMicros    int64      `json:"durationMicros"`
	Clock             string     `json:"clock"`
	CalendarID        *uuid.UUID `json:"calendarId,omitempty"`
	CalendarVersion   *int64     `json:"calendarVersion,omitempty"`
	StartEvent        string     `json:"startEvent"`
	PauseEvent        *string    `json:"pauseEvent,omitempty"`
	ResumeEvent       *string    `json:"resumeEvent,omitempty"`
	CompletionEvent   string     `json:"completionEvent"`
	ResetEvent        *string    `json:"resetEvent,omitempty"`
	ResetPolicy       string     `json:"resetPolicy"`
	Warning           slaRawJSON `json:"warning"`
	BreachGraceMicros int64      `json:"breachGraceMicros"`
	DisplayFormat     string     `json:"displayFormat"`
	CustomerVisible   bool       `json:"customerVisible"`
	APIVisible        bool       `json:"apiVisible"`
}

type slaTriggerWriteBody struct {
	ID                   uuid.UUID  `json:"id"`
	Key                  string     `json:"key"`
	MetricDefinitionID   uuid.UUID  `json:"metricDefinitionId"`
	Kind                 string     `json:"kind"`
	ConsumedPercent      *int       `json:"consumedPercent,omitempty"`
	RemainingMicros      *int64     `json:"remainingMicros,omitempty"`
	OffsetMicros         *int64     `json:"offsetMicros,omitempty"`
	RepeatIntervalMicros *int64     `json:"repeatIntervalMicros,omitempty"`
	TargetState          *string    `json:"targetState,omitempty"`
	Action               slaRawJSON `json:"action"`
}

type slaPolicyCreateBody struct {
	ID                     uuid.UUID             `json:"id"`
	Key                    string                `json:"key"`
	Name                   string                `json:"name"`
	Description            string                `json:"description"`
	Priority               int32                 `json:"priority"`
	ObjectTypes            []string              `json:"objectTypes"`
	MatchRule              slaRawJSON            `json:"matchRule"`
	EffectiveFrom          time.Time             `json:"effectiveFrom"`
	EffectiveUntil         *time.Time            `json:"effectiveUntil,omitempty" nullable:"true"`
	Enabled                bool                  `json:"enabled"`
	ApplyToSLAEngineSource bool                  `json:"applyToSlaEngineSource"`
	Metrics                []slaMetricWriteBody  `json:"metrics"`
	Triggers               []slaTriggerWriteBody `json:"triggers"`
}

type slaPolicyReplaceBody struct {
	Key                    string                `json:"key"`
	Name                   string                `json:"name"`
	Description            string                `json:"description"`
	Priority               int32                 `json:"priority"`
	ObjectTypes            []string              `json:"objectTypes"`
	MatchRule              slaRawJSON            `json:"matchRule"`
	EffectiveFrom          time.Time             `json:"effectiveFrom"`
	EffectiveUntil         *time.Time            `json:"effectiveUntil,omitempty" nullable:"true"`
	Enabled                bool                  `json:"enabled"`
	ApplyToSLAEngineSource bool                  `json:"applyToSlaEngineSource"`
	Metrics                []slaMetricWriteBody  `json:"metrics"`
	Triggers               []slaTriggerWriteBody `json:"triggers"`
}

type slaColumnStyleBody struct {
	StyleKey               string   `json:"styleKey"`
	State                  *string  `json:"state,omitempty"`
	MinimumPercentage      *float64 `json:"minimumPercentage,omitempty"`
	MaximumRemainingMicros *int64   `json:"maximumRemainingMicros,omitempty"`
}

type slaColumnCreateBody struct {
	ID                 uuid.UUID            `json:"id"`
	Key                string               `json:"key"`
	Label              string               `json:"label"`
	MetricDefinitionID uuid.UUID            `json:"metricDefinitionId"`
	Calculation        string               `json:"calculation"`
	Format             string               `json:"format"`
	Sortable           bool                 `json:"sortable"`
	Filterable         bool                 `json:"filterable"`
	CustomerVisible    bool                 `json:"customerVisible"`
	VisibleRoleKeys    []string             `json:"visibleRoleKeys"`
	Position           int                  `json:"position"`
	StyleRules         []slaColumnStyleBody `json:"styleRules"`
}

type slaColumnReplaceBody struct {
	Key                string               `json:"key"`
	Label              string               `json:"label"`
	MetricDefinitionID uuid.UUID            `json:"metricDefinitionId"`
	Calculation        string               `json:"calculation"`
	Format             string               `json:"format"`
	Sortable           bool                 `json:"sortable"`
	Filterable         bool                 `json:"filterable"`
	CustomerVisible    bool                 `json:"customerVisible"`
	VisibleRoleKeys    []string             `json:"visibleRoleKeys"`
	Position           int                  `json:"position"`
	StyleRules         []slaColumnStyleBody `json:"styleRules"`
}

type slaFactBody struct {
	Path   slaRawJSON `json:"path"`
	Values []string   `json:"values"`
}

type slaFactSnapshotBody struct {
	ObjectType  string        `json:"objectType"`
	EvaluatedAt time.Time     `json:"evaluatedAt"`
	Timezone    string        `json:"timezone"`
	Facts       []slaFactBody `json:"facts"`
}

type slaSimulationBindingBody struct {
	MetricDefinitionID uuid.UUID `json:"metricDefinitionId"`
	MetricInstanceID   uuid.UUID `json:"metricInstanceId"`
}

type slaSimulationEventBody struct {
	EventID    uuid.UUID `json:"eventId"`
	Key        string    `json:"key"`
	OccurredAt time.Time `json:"occurredAt"`
}

type slaSimulationBody struct {
	PolicyVersion int64                      `json:"policyVersion"`
	Snapshot      slaFactSnapshotBody        `json:"snapshot"`
	SLAInstanceID uuid.UUID                  `json:"slaInstanceId"`
	ObjectID      uuid.UUID                  `json:"objectId"`
	CreatedAt     time.Time                  `json:"createdAt"`
	EvaluateAt    time.Time                  `json:"evaluateAt"`
	Bindings      []slaSimulationBindingBody `json:"metricBindings"`
	Events        []slaSimulationEventBody   `json:"events"`
}

// The union members are optional here solely so the mapper can reject members
// forbidden for the selected kind. Common members remain required.
type slaOverrideBody struct {
	OverrideID                 uuid.UUID  `json:"overrideId"`
	Kind                       string     `json:"kind"`
	Reason                     string     `json:"reason"`
	SLAInstanceID              uuid.UUID  `json:"slaInstanceId"`
	MetricInstanceID           *uuid.UUID `json:"metricInstanceId,omitempty"`
	ExpectedMetricVersion      *int64     `json:"expectedMetricVersion,omitempty"`
	ExpectedAggregateVersion   *int64     `json:"expectedAggregateVersion,omitempty"`
	ExtensionMicros            *int64     `json:"extensionMicros,omitempty"`
	ReplacementCalendarID      *uuid.UUID `json:"replacementCalendarId,omitempty"`
	ReplacementCalendarVersion *int64     `json:"replacementCalendarVersion,omitempty"`
	NewPolicyID                *uuid.UUID `json:"newPolicyId,omitempty"`
	NewPolicyVersion           *int64     `json:"newPolicyVersion,omitempty"`
	SimulationDigest           *string    `json:"simulationDigest,omitempty"`
}

func decodeSLABody(r *http.Request, destination any) error {
	mediaType, err := requestMediaType(r)
	if err != nil || mediaType != "application/json" {
		return errors.New("unsupported SLA request content type")
	}
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, maximumPhase4BodyBytes+1))
	if err != nil || len(body) == 0 || len(body) > maximumPhase4BodyBytes || !utf8.Valid(body) {
		clear(body)
		return errors.New("SLA request body is invalid")
	}
	defer clear(body)
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	count := 0
	if err := scanPhase4JSONValue(decoder, 0, &count); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("SLA request body must contain one JSON value")
	}
	var raw any
	if err := json.Unmarshal(body, &raw); err != nil {
		return errors.New("SLA request body does not match the exact contract shape")
	}
	if err := validateSLAJSONShape(raw, reflect.TypeOf(destination)); err != nil {
		return fmt.Errorf("SLA request body does not match the exact contract shape: %w", err)
	}
	strict := json.NewDecoder(bytes.NewReader(body))
	strict.DisallowUnknownFields()
	if err := strict.Decode(destination); err != nil {
		return errors.New("SLA request body does not match the contract")
	}
	if err := strict.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("SLA request body must contain one JSON value")
	}
	return nil
}

func validateSLAJSONShape(value any, destinationType reflect.Type) error {
	for destinationType.Kind() == reflect.Pointer {
		destinationType = destinationType.Elem()
	}
	if destinationType == reflect.TypeOf(slaRawJSON{}) || destinationType == reflect.TypeOf(json.RawMessage{}) {
		return nil
	}
	if destinationType == reflect.TypeOf(uuid.UUID{}) || destinationType == reflect.TypeOf(time.Time{}) {
		if _, ok := value.(string); !ok {
			return errors.New("expected JSON string")
		}
		return nil
	}
	switch destinationType.Kind() {
	case reflect.Struct:
		object, ok := value.(map[string]any)
		if !ok {
			return errors.New("expected JSON object")
		}
		fields := make(map[string]reflect.StructField, destinationType.NumField())
		for index := 0; index < destinationType.NumField(); index++ {
			field := destinationType.Field(index)
			if !field.IsExported() {
				continue
			}
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			if name == "" {
				name = field.Name
			}
			if name != "-" {
				fields[name] = field
			}
		}
		for name, field := range fields {
			item, present := object[name]
			optional := strings.Contains(field.Tag.Get("json"), "omitempty")
			if !present {
				if !optional {
					return errors.New("required JSON member is absent")
				}
				continue
			}
			if item == nil {
				if field.Tag.Get("nullable") != "true" {
					return errors.New("JSON member is null")
				}
				continue
			}
			if err := validateSLAJSONShape(item, field.Type); err != nil {
				return fmt.Errorf("member %q: %w", name, err)
			}
		}
		for name := range object {
			if _, known := fields[name]; !known {
				return errors.New("unknown JSON member")
			}
		}
	case reflect.Array, reflect.Slice:
		items, ok := value.([]any)
		if !ok {
			return errors.New("expected JSON array")
		}
		for _, item := range items {
			if item == nil {
				return errors.New("JSON array member is null")
			}
			if err := validateSLAJSONShape(item, destinationType.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}
