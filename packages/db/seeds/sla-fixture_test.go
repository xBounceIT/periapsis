package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	kernel "github.com/periapsis-im/periapsis/modules/sla"
)

// These independent wire DTOs follow the publication mapping, not buildKernel.
// Tenant/resource identities and initial version 1 are supplied by the SQL call;
// they are not additional fields in the calendar/policy publication documents.
type fixtureWireDocuments struct {
	Identity fixtureInput        `json:"identity"`
	Calendar fixtureWireCalendar `json:"calendar"`
	Policy   fixtureWirePolicy   `json:"policy"`
	Column   *fixtureWireColumn  `json:"column,omitempty"`
}

type fixtureWireInterval struct {
	StartMinute uint16 `json:"start_minute"`
	EndMinute   uint16 `json:"end_minute"`
}

type fixtureWireCalendar struct {
	Key            string `json:"key"`
	Label          string `json:"label"`
	Timezone       string `json:"timezone"`
	WeeklySchedule []struct {
		Weekday   time.Weekday          `json:"weekday"`
		Intervals []fixtureWireInterval `json:"intervals"`
	} `json:"weekly_schedule"`
	Exceptions []struct {
		Date      string                `json:"date"`
		Closed    bool                  `json:"closed"`
		Intervals []fixtureWireInterval `json:"intervals"`
	} `json:"exceptions"`
	RevisionDigest string `json:"revision_digest"`
}

type fixtureWireRule struct {
	Kind     kernel.RuleKind   `json:"kind"`
	Children []fixtureWireRule `json:"children,omitempty"`
}

type fixtureWirePolicy struct {
	Key                    string               `json:"key"`
	Name                   string               `json:"name"`
	Description            string               `json:"description"`
	Priority               int32                `json:"priority"`
	ObjectTypes            []kernel.ObjectType  `json:"object_types"`
	MatchRule              fixtureWireRule      `json:"match_rule"`
	EffectiveFrom          time.Time            `json:"effective_from"`
	EffectiveUntil         *time.Time           `json:"effective_until"`
	Enabled                bool                 `json:"enabled"`
	ApplyToSLAEngineSource bool                 `json:"apply_to_sla_engine_source"`
	Metrics                []fixtureWireMetric  `json:"metrics"`
	Triggers               []fixtureWireTrigger `json:"triggers"`
	RevisionDigest         string               `json:"revision_digest"`
}

type fixtureWireMetric struct {
	ID                     string             `json:"id"`
	Key                    string             `json:"key"`
	Label                  string             `json:"label"`
	Description            string             `json:"description"`
	DurationMicros         int64              `json:"duration_micros"`
	Clock                  kernel.ClockType   `json:"clock"`
	CalendarID             *string            `json:"calendar_id"`
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
	Position               int                `json:"position"`
	DefinitionDigest       string             `json:"definition_digest"`
}

type fixtureWireTrigger struct {
	ID                    string              `json:"id"`
	MetricDefinitionID    string              `json:"metric_definition_id"`
	Key                   string              `json:"key"`
	Kind                  kernel.TriggerKind  `json:"kind"`
	ConsumedPercent       *uint8              `json:"consumed_percent"`
	RemainingMicros       *int64              `json:"remaining_micros"`
	OffsetMicros          *int64              `json:"offset_micros"`
	RepeatIntervalMicros  *int64              `json:"repeat_interval_micros"`
	TargetState           *kernel.MetricState `json:"target_state"`
	ActionKind            kernel.ActionKind   `json:"action_kind"`
	ActionConfigurationID *string             `json:"action_configuration_id"`
	ActionValue           *string             `json:"action_value"`
	AllowRecursiveSLA     bool                `json:"allow_recursive_sla"`
	Position              int                 `json:"position"`
	DefinitionDigest      string              `json:"definition_digest"`
}

type fixtureWireColumn struct {
	Key                string                   `json:"key"`
	Label              string                   `json:"label"`
	MetricDefinitionID string                   `json:"metric_definition_id"`
	Calculation        kernel.ColumnCalculation `json:"calculation"`
	Format             kernel.ColumnFormat      `json:"format"`
	Sortable           bool                     `json:"sortable"`
	Filterable         bool                     `json:"filterable"`
	CustomerVisible    bool                     `json:"customer_visible"`
	VisibleRoleKeys    []string                 `json:"visible_role_keys"`
	Position           uint16                   `json:"position"`
	StyleRules         []struct {
		StyleKey               string             `json:"style_key"`
		State                  kernel.MetricState `json:"state"`
		MinimumPercentage      *float64           `json:"minimum_percentage"`
		MaximumRemainingMicros *int64             `json:"maximum_remaining_micros"`
	} `json:"style_rules"`
	RevisionDigest string `json:"revision_digest"`
}

func TestSLAFixturePublicationRoundTripAndObjectEvent(t *testing.T) {
	for _, objectType := range []kernel.ObjectType{kernel.ObjectCase, kernel.ObjectAlert} {
		t.Run(string(objectType), func(t *testing.T) {
			input := readFixtureInput(t)
			input.ObjectType = objectType
			if objectType == kernel.ObjectAlert {
				input.KeyPrefix = "performance"
				input.DurationMicros = (90 * time.Minute).Microseconds()
				input.ColumnID = "01993ea0-0000-7000-8000-00000000fff4"
			}
			wire := generatedFixtureWire(t, input)
			calendar, policy, err := restoreFixtureWire(wire)
			if err != nil {
				t.Fatal(err)
			}
			expectedCalendar, expectedPolicy, err := buildKernel(input)
			if err != nil {
				t.Fatal(err)
			}
			if wire.Identity != input || !reflect.DeepEqual(calendar.Input(), expectedCalendar.Input()) ||
				!reflect.DeepEqual(policy.Input(), expectedPolicy.Input()) {
				t.Fatal("publication roundtrip changed a kernel input or fixture identity")
			}
			column, err := restoreFixtureColumn(wire, policy.Metrics()[0])
			if err != nil {
				t.Fatal(err)
			}
			expectedColumn, err := buildColumn(input, expectedPolicy.Metrics()[0])
			if err != nil {
				t.Fatal(err)
			}
			if (column == nil) != (expectedColumn == nil) ||
				column != nil && !reflect.DeepEqual(column.Input(), expectedColumn.Input()) {
				t.Fatal("publication roundtrip changed the optional column definition")
			}

			occurredAt := input.EffectiveFrom.Add(time.Minute)
			snapshot, err := kernel.NewFactSnapshot(kernel.FactSnapshotInput{
				TenantID: policy.TenantID(), ObjectType: objectType, EvaluatedAt: occurredAt, Timezone: "UTC",
			})
			if err != nil {
				t.Fatal(err)
			}
			eventID, err := kernel.ParseEntityID("01993ea0-0000-7000-8000-00000000fff1")
			if err != nil {
				t.Fatal(err)
			}
			objectID, err := kernel.ParseEntityID("01993ea0-0000-7000-8000-00000000fff2")
			if err != nil {
				t.Fatal(err)
			}
			event := kernel.MetricEvent{ID: eventID, TenantID: policy.TenantID(), ObjectID: objectID,
				Key: policy.Metrics()[0].StartEvent(), OccurredAt: occurredAt}
			// The elapsed preset does not reference its separately published demo
			// calendar. Passing that calendar would be an invalid extra projection.
			state := kernel.ObjectEventState{Mode: kernel.ObjectEventStateUnassigned,
				Snapshot: &snapshot, Policies: []kernel.Policy{policy}}
			if column != nil {
				state.Columns = []kernel.ColumnDefinition{*column}
			}
			plan, err := kernel.PlanObjectEvent(event, state)
			if err != nil {
				t.Fatal(err)
			}
			assignment, engine := plan.Assignment(), plan.Engine()
			if assignment == nil || !assignment.Matched() || engine == nil ||
				plan.ExpectedAggregateVersion() != 0 || plan.NextAggregateVersion() != 1 ||
				assignment.Policy().Digest() != policy.Digest() || len(engine.Metrics()) != 1 {
				t.Fatal("restored publication did not produce the expected initial assignment")
			}
			instance := engine.Metrics()[0].Instance().Snapshot()
			expectedDue := occurredAt.Add(time.Duration(input.DurationMicros) * time.Microsecond)
			if instance.TenantID != policy.TenantID() || instance.ObjectType != objectType ||
				instance.ObjectID != objectID || instance.PolicyID != policy.ID() || instance.PolicyVersion != 1 ||
				instance.Definition.Digest() != policy.Metrics()[0].Digest() ||
				instance.Lifecycle != kernel.LifecycleRunning || instance.StartedAt == nil ||
				!instance.StartedAt.Equal(occurredAt) || instance.DueAt == nil || !instance.DueAt.Equal(expectedDue) {
				t.Fatal("assigned instance lost its identity, immutable definition, or elapsed deadline")
			}
			work := assignment.Metrics()
			if len(work) != 1 || len(work[0].Triggers) != 1 ||
				work[0].Triggers[0].Definition.Digest() != policy.Triggers()[0].Digest() {
				t.Fatal("assignment did not retain the published due trigger")
			}
			columns := engine.Metrics()[0].Columns()
			if column == nil {
				if len(columns) != 0 || len(work[0].Columns) != 0 {
					t.Fatal("default Case fixture unexpectedly materialized a column")
				}
			} else {
				if len(columns) != 1 || len(work[0].Columns) != 1 ||
					work[0].Columns[0].Digest() != column.Digest() {
					t.Fatal("Alert assignment lost the published column")
				}
				value := columns[0]
				if value.ColumnID() != column.ID() || value.ColumnVersion() != 1 ||
					value.MetricID() != policy.Metrics()[0].ID() || value.Calculation() != kernel.ColumnDueAt ||
					value.Instant() == nil || !value.Instant().Equal(expectedDue) ||
					!value.MaterializedAt().Equal(occurredAt) || value.Duration() != nil || value.Percentage() != nil {
					t.Fatal("Alert column materialization lost its immutable pin or due-at value")
				}
			}
			replay, err := kernel.PlanObjectEvent(event, state)
			if err != nil || replay.Assignment() == nil ||
				replay.Assignment().SLAInstanceID() != assignment.SLAInstanceID() {
				t.Fatal("same immutable assignment did not retain its deterministic aggregate identity")
			}
		})
	}
}

func TestSLAFixtureRejectsInvalidRuleAndDigestDrift(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*fixtureWireDocuments)
	}{
		{"empty rule", func(w *fixtureWireDocuments) { w.Policy.MatchRule = fixtureWireRule{} }},
		{"calendar digest", func(w *fixtureWireDocuments) { w.Calendar.RevisionDigest = strings.Repeat("0", 64) }},
		{"policy digest", func(w *fixtureWireDocuments) { w.Policy.RevisionDigest = strings.Repeat("0", 64) }},
		{"metric digest", func(w *fixtureWireDocuments) { w.Policy.Metrics[0].DefinitionDigest = strings.Repeat("0", 64) }},
		{"trigger digest", func(w *fixtureWireDocuments) { w.Policy.Triggers[0].DefinitionDigest = strings.Repeat("0", 64) }},
		{"tenant pin", func(w *fixtureWireDocuments) { w.Identity.TenantID = "01993ea0-0000-7000-8000-00000000fff3" }},
		{"trigger metric pin", func(w *fixtureWireDocuments) { w.Policy.Triggers[0].MetricDefinitionID = w.Identity.TriggerID }},
		{"metric position", func(w *fixtureWireDocuments) { w.Policy.Metrics[0].Position = 1 }},
		{"trigger position", func(w *fixtureWireDocuments) { w.Policy.Triggers[0].Position = 1 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			wire := generatedFixtureWire(t, readFixtureInput(t))
			test.mutate(&wire)
			if _, _, err := restoreFixtureWire(wire); err == nil {
				t.Fatal("invalid publication was accepted")
			}
		})
	}
}

func TestSLAFixtureProjectsFullCalendarCatalogBeforeStrictAssignment(t *testing.T) {
	wire := generatedFixtureWire(t, readFixtureInput(t))
	calendar, policy, err := restoreFixtureWire(wire)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		objectType kernel.ObjectType
		strictWant error
	}{
		{kernel.ObjectCase, kernel.ErrInvalidCalendar},
		{kernel.ObjectAlert, kernel.ErrInvalidPolicy},
	} {
		t.Run(string(test.objectType), func(t *testing.T) {
			at := policy.EffectiveFrom().Add(time.Minute)
			snapshot, err := kernel.NewFactSnapshot(kernel.FactSnapshotInput{
				TenantID: policy.TenantID(), ObjectType: test.objectType, EvaluatedAt: at, Timezone: "UTC",
			})
			if err != nil {
				t.Fatal(err)
			}
			eventID, err := kernel.ParseEntityID("01993ea0-0000-7000-8000-00000000fff1")
			if err != nil {
				t.Fatal(err)
			}
			objectID, err := kernel.ParseEntityID("01993ea0-0000-7000-8000-00000000fff2")
			if err != nil {
				t.Fatal(err)
			}
			var policies []kernel.Policy
			if test.objectType == kernel.ObjectCase {
				policies = []kernel.Policy{policy}
			}
			event := kernel.MetricEvent{ID: eventID, TenantID: policy.TenantID(),
				ObjectID: objectID, Key: policy.Metrics()[0].StartEvent(), OccurredAt: at}
			state := kernel.ObjectEventState{
				Mode: kernel.ObjectEventStateUnassigned, Snapshot: &snapshot,
				Policies: policies, Calendars: []kernel.BusinessCalendar{calendar},
			}
			t.Run("event planner projects the full catalog", func(t *testing.T) {
				plan, err := kernel.PlanObjectEvent(event, state)
				if err != nil || plan.Assignment() == nil {
					t.Fatalf("valid full calendar catalog was not planned: %v", err)
				}
				assignment := plan.Assignment()
				if test.objectType == kernel.ObjectCase {
					if !assignment.Matched() || assignment.Policy().Digest() != policy.Digest() ||
						plan.Engine() == nil || plan.NextAggregateVersion() != 1 ||
						len(assignment.Metrics()) != 1 || assignment.Metrics()[0].Calendar != nil {
						t.Fatal("elapsed Case policy did not retain its assignment without an unrelated calendar")
					}
				} else if assignment.Matched() || assignment.Policy() != nil || plan.Engine() != nil ||
					plan.NextAggregateVersion() != 0 || len(assignment.Metrics()) != 0 {
					t.Fatal("Alert without a candidate policy did not retain its no-policy decision")
				}
				if len(state.Calendars) != 1 || state.Calendars[0].Digest() != calendar.Digest() {
					t.Fatal("event planning mutated the immutable source calendar catalog")
				}
			})
			t.Run("strict assignment still rejects extra dependencies", func(t *testing.T) {
				_, err := kernel.PlanAssignment(kernel.AssignmentInput{
					Snapshot: snapshot, Policies: policies, ObjectID: objectID,
					AssignmentEventID: eventID, CreatedAt: at, Calendars: state.Calendars,
				})
				if !errors.Is(err, test.strictWant) {
					t.Fatalf("strict unreferenced calendar error = %v, want %v", err, test.strictWant)
				}
			})
		})
	}
}

func TestSLAFixtureRejectsInvalidInput(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*fixtureInput)
	}{
		{"task", func(i *fixtureInput) { i.ObjectType = kernel.ObjectTask }},
		{"unknown object", func(i *fixtureInput) { i.ObjectType = "unknown" }},
		{"zero duration", func(i *fixtureInput) { i.DurationMicros = 0 }},
		{"negative duration", func(i *fixtureInput) { i.DurationMicros = -1 }},
		{"overflow duration", func(i *fixtureInput) { i.DurationMicros = 1 << 62 }},
		{"invalid identity", func(i *fixtureInput) { i.MetricID = "not-a-uuid" }},
		{"invalid column identity", func(i *fixtureInput) { i.ColumnID = "not-a-uuid" }},
		{"invalid key", func(i *fixtureInput) { i.KeyPrefix = "invalid prefix" }},
		{"missing completion", func(i *fixtureInput) { i.CompletionEvent = "" }},
		{"invalid completion", func(i *fixtureInput) { i.CompletionEvent = "invalid event key" }},
		{"invalid effective time", func(i *fixtureInput) { i.EffectiveFrom = time.Time{} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := readFixtureInput(t)
			test.mutate(&input)
			if _, err := buildFixture(input); err == nil {
				t.Fatal("invalid preset input was accepted")
			}
		})
	}
}

func TestSLAFixtureColumnRejectsDigestAndMetricDrift(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*fixtureWireDocuments)
	}{
		{"digest", func(w *fixtureWireDocuments) { w.Column.RevisionDigest = strings.Repeat("0", 64) }},
		{"metric pin", func(w *fixtureWireDocuments) { w.Column.MetricDefinitionID = w.Identity.TriggerID }},
		{"missing column", func(w *fixtureWireDocuments) { w.Column = nil }},
		{"missing identity", func(w *fixtureWireDocuments) { w.Identity.ColumnID = "" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := readFixtureInput(t)
			input.ObjectType = kernel.ObjectAlert
			input.ColumnID = "01993ea0-0000-7000-8000-00000000fff4"
			wire := generatedFixtureWire(t, input)
			_, policy, err := restoreFixtureWire(wire)
			if err != nil {
				t.Fatal(err)
			}
			test.mutate(&wire)
			if _, err := restoreFixtureColumn(wire, policy.Metrics()[0]); err == nil {
				t.Fatal("invalid column publication was accepted")
			}
		})
	}
}

func TestSLAFixtureCheckIsNonMutatingAndRejectsDrift(t *testing.T) {
	input := readFixtureInput(t)
	document, err := buildFixture(input)
	if err != nil {
		t.Fatal(err)
	}
	inputRaw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	artifactRaw, err := json.MarshalIndent(document, "", "    ")
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	inputPath, artifactPath := filepath.Join(directory, "input.json"), filepath.Join(directory, "artifact.json")
	if err := os.WriteFile(inputPath, inputRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, drift := range []bool{false, true} {
		if drift {
			document.Calendar["revision_digest"] = strings.Repeat("0", 64)
			artifactRaw, err = json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(artifactPath, artifactRaw, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := run(inputPath, "", artifactPath); (err != nil) != drift {
			t.Fatalf("check drift=%t returned %v", drift, err)
		}
		after, err := os.ReadFile(artifactPath)
		if err != nil || !bytes.Equal(after, artifactRaw) {
			t.Fatal("check modified its input artifact")
		}
	}
}

func readFixtureInput(t *testing.T) fixtureInput {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate fixture source")
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(source), "sla-fixture-input.json"))
	if err != nil {
		t.Fatal(err)
	}
	var input fixtureInput
	if err := json.Unmarshal(raw, &input); err != nil {
		t.Fatal(err)
	}
	return input
}

func generatedFixtureWire(t *testing.T, input fixtureInput) fixtureWireDocuments {
	t.Helper()
	document, err := buildFixture(input)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	var wire fixtureWireDocuments
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		t.Fatal(err)
	}
	assertCompleteFixtureWire(t, raw, reflect.TypeOf(wire), "fixture")
	return wire
}

// Zero values alone cannot distinguish a missing field from an explicit null,
// false, zero, or empty list. Check every independently declared JSON field.
func assertCompleteFixtureWire(t *testing.T, raw json.RawMessage, kind reflect.Type, path string) {
	t.Helper()
	if kind.Kind() == reflect.Pointer {
		if bytes.Equal(raw, []byte("null")) {
			return
		}
		kind = kind.Elem()
	}
	if bytes.Equal(raw, []byte("null")) {
		t.Fatalf("%s unexpectedly contains null", path)
	}
	if kind == reflect.TypeOf(time.Time{}) {
		return
	}
	switch kind.Kind() {
	case reflect.Struct:
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			t.Fatal(err)
		}
		for index := 0; index < kind.NumField(); index++ {
			field := kind.Field(index)
			tag := field.Tag.Get("json")
			name := strings.Split(tag, ",")[0]
			value, exists := fields[name]
			if !exists {
				if strings.Contains(tag, ",omitempty") {
					continue
				}
				t.Fatalf("%s.%s is missing", path, name)
			}
			assertCompleteFixtureWire(t, value, field.Type, path+"."+name)
		}
	case reflect.Slice:
		var values []json.RawMessage
		if err := json.Unmarshal(raw, &values); err != nil {
			t.Fatal(err)
		}
		for index, value := range values {
			assertCompleteFixtureWire(t, value, kind.Elem(), fmt.Sprintf("%s[%d]", path, index))
		}
	}
}

// Restore every semantic wire field before checking any digest. This must not
// reuse buildKernel: doing so could hide a missing or incorrect emitted value.
func restoreFixtureWire(w fixtureWireDocuments) (kernel.BusinessCalendar, kernel.Policy, error) {
	d := fixtureWireDecoder{}
	ci := kernel.BusinessCalendarInput{ID: d.id(w.Identity.CalendarID), TenantID: d.id(w.Identity.TenantID),
		Key: d.key(w.Calendar.Key), Label: w.Calendar.Label, Timezone: w.Calendar.Timezone, Version: 1}
	for _, schedule := range w.Calendar.WeeklySchedule {
		ci.WeeklySchedules = append(ci.WeeklySchedules, kernel.WeeklyScheduleInput{
			Weekday: schedule.Weekday, Intervals: fixtureIntervals(schedule.Intervals)})
	}
	for _, exception := range w.Calendar.Exceptions {
		ci.Exceptions = append(ci.Exceptions, kernel.DateExceptionInput{
			Date: exception.Date, Closed: exception.Closed, Intervals: fixtureIntervals(exception.Intervals)})
	}
	calendar, err := kernel.NewBusinessCalendar(ci)
	d.check(err)
	if len(w.Policy.Metrics) != 1 || len(w.Policy.Triggers) != 1 {
		return calendar, kernel.Policy{}, errors.New("preset must publish one metric and one trigger")
	}
	m, tr := w.Policy.Metrics[0], w.Policy.Triggers[0]
	if m.Position != 0 || tr.Position != 0 {
		d.check(errors.New("noncanonical metric/trigger position"))
	}
	metric, err := kernel.NewMetricDefinition(kernel.MetricDefinitionInput{
		ID: d.id(m.ID), Key: d.key(m.Key), Label: m.Label, Description: m.Description,
		Duration: d.micros(m.DurationMicros), Clock: m.Clock, CalendarID: d.optionalID(m.CalendarID),
		CalendarVersion: fixtureValue(m.CalendarVersion), StartEvent: d.key(m.StartEvent),
		PauseEvent: d.optionalKey(m.PauseEvent), ResumeEvent: d.optionalKey(m.ResumeEvent),
		CompletionEvent: d.key(m.CompletionEvent), ResetEvent: d.optionalKey(m.ResetEvent), ResetPolicy: m.ResetPolicy,
		Warning: kernel.WarningThreshold{Kind: m.WarningKind, ConsumedPercent: fixtureValue(m.WarningConsumedPercent),
			RemainingDuration: d.micros(fixtureValue(m.WarningRemainingMicros))},
		BreachGrace: d.micros(m.BreachGraceMicros), DisplayFormat: m.DisplayFormat,
		CustomerVisible: m.CustomerVisible, APIVisible: m.APIVisible,
	})
	d.check(err)
	action := kernel.TriggerActionInput{Kind: tr.ActionKind, ConfigurationID: d.optionalID(tr.ActionConfigurationID),
		AllowRecursiveSLA: tr.AllowRecursiveSLA}
	if tr.ActionKind == kernel.ActionCreateTask {
		action.Text = fixtureValue(tr.ActionValue)
	} else {
		action.Value = d.optionalKey(tr.ActionValue)
	}
	trigger, err := kernel.NewTriggerDefinition(metric, kernel.TriggerDefinitionInput{
		ID: d.id(tr.ID), Key: d.key(tr.Key), MetricID: d.id(tr.MetricDefinitionID), Kind: tr.Kind,
		ConsumedPercent: fixtureValue(tr.ConsumedPercent), Remaining: d.micros(fixtureValue(tr.RemainingMicros)),
		Offset: d.micros(fixtureValue(tr.OffsetMicros)), RepeatInterval: d.micros(fixtureValue(tr.RepeatIntervalMicros)),
		TargetState: fixtureValue(tr.TargetState), Action: action,
	})
	d.check(err)
	rule, err := kernel.NewRule(fixtureRuleInput(w.Policy.MatchRule))
	d.check(err)
	policy, err := kernel.NewPolicy(kernel.PolicyInput{
		ID: d.id(w.Identity.PolicyID), TenantID: d.id(w.Identity.TenantID), Key: d.key(w.Policy.Key),
		Name: w.Policy.Name, Description: w.Policy.Description, Version: 1, Priority: w.Policy.Priority,
		ObjectTypes: w.Policy.ObjectTypes, MatchRule: rule, Metrics: []kernel.MetricDefinition{metric},
		Triggers: []kernel.TriggerDefinition{trigger}, EffectiveFrom: w.Policy.EffectiveFrom,
		EffectiveUntil: w.Policy.EffectiveUntil, Enabled: w.Policy.Enabled,
		ApplyToSLAEngineSource: w.Policy.ApplyToSLAEngineSource,
	})
	d.check(err)
	if d.err != nil {
		return calendar, policy, d.err
	}
	for _, digest := range []struct {
		name string
		wire string
		got  [32]byte
	}{
		{"calendar", w.Calendar.RevisionDigest, calendar.Digest()},
		{"metric", m.DefinitionDigest, metric.Digest()},
		{"trigger", tr.DefinitionDigest, trigger.Digest()},
		{"policy", w.Policy.RevisionDigest, policy.Digest()},
	} {
		if digest.wire != fmt.Sprintf("%x", digest.got) {
			return calendar, policy, fmt.Errorf("%s digest does not bind the restored publication", digest.name)
		}
	}
	return calendar, policy, nil
}

func fixtureRuleInput(w fixtureWireRule) *kernel.RuleInput {
	input := &kernel.RuleInput{Kind: w.Kind}
	for _, child := range w.Children {
		input.Children = append(input.Children, fixtureRuleInput(child))
	}
	return input
}

func restoreFixtureColumn(w fixtureWireDocuments, metric kernel.MetricDefinition) (*kernel.ColumnDefinition, error) {
	if w.Column == nil && w.Identity.ColumnID == "" {
		return nil, nil
	}
	if w.Column == nil || w.Identity.ColumnID == "" {
		return nil, errors.New("column publication and identity must be present together")
	}
	d := fixtureWireDecoder{}
	c := w.Column
	input := kernel.ColumnDefinitionInput{
		ID: d.id(w.Identity.ColumnID), TenantID: d.id(w.Identity.TenantID), Key: d.key(c.Key),
		Label: c.Label, MetricID: d.id(c.MetricDefinitionID), Calculation: c.Calculation, Format: c.Format,
		Sortable: c.Sortable, Filterable: c.Filterable, CustomerVisible: c.CustomerVisible,
		Position: c.Position, Version: 1,
	}
	for _, role := range c.VisibleRoleKeys {
		input.VisibleRoleKeys = append(input.VisibleRoleKeys, d.key(role))
	}
	for _, style := range c.StyleRules {
		var remaining *time.Duration
		if style.MaximumRemainingMicros != nil {
			value := d.micros(*style.MaximumRemainingMicros)
			remaining = &value
		}
		input.StyleRules = append(input.StyleRules, kernel.ColumnStyleRuleInput{
			StyleKey: d.key(style.StyleKey), State: style.State,
			MinimumPercentage: style.MinimumPercentage, MaximumRemaining: remaining,
		})
	}
	column, err := kernel.NewColumnDefinition(metric, input)
	d.check(err)
	if d.err != nil {
		return nil, d.err
	}
	if c.RevisionDigest != fmt.Sprintf("%x", column.Digest()) {
		return nil, errors.New("column digest does not bind the restored publication")
	}
	return &column, nil
}

func fixtureIntervals(w []fixtureWireInterval) []kernel.MinuteIntervalInput {
	intervals := make([]kernel.MinuteIntervalInput, len(w))
	for index, interval := range w {
		intervals[index] = kernel.MinuteIntervalInput{StartMinute: interval.StartMinute, EndMinute: interval.EndMinute}
	}
	return intervals
}

func fixtureValue[T any](value *T) T {
	if value != nil {
		return *value
	}
	var zero T
	return zero
}

type fixtureWireDecoder struct{ err error }

func (d *fixtureWireDecoder) check(err error) {
	if d.err == nil {
		d.err = err
	}
}

func (d *fixtureWireDecoder) id(raw string) kernel.EntityID {
	id, err := kernel.ParseEntityID(raw)
	d.check(err)
	return id
}

func (d *fixtureWireDecoder) optionalID(raw *string) *kernel.EntityID {
	if raw == nil {
		return nil
	}
	id := d.id(*raw)
	return &id
}

func (d *fixtureWireDecoder) key(raw string) kernel.Key {
	key, err := kernel.NewKey(raw)
	d.check(err)
	return key
}

func (d *fixtureWireDecoder) optionalKey(raw *string) kernel.Key {
	if raw == nil {
		return kernel.Key{}
	}
	return d.key(*raw)
}

func (d *fixtureWireDecoder) micros(value int64) time.Duration {
	if value < 0 || value > int64(100*365*24*time.Hour/time.Microsecond) {
		d.check(errors.New("invalid wire microsecond duration"))
		return 0
	}
	return time.Duration(value) * time.Microsecond
}
