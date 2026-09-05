// sla-fixture generates synthetic publication documents through the real SLA
// kernel. It never connects to a database or bypasses a publication/worker ABI.
// See README.md for generation, drift checks, and alternate Alert fixtures.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	kernel "github.com/periapsis-im/periapsis/modules/sla"
)

type fixtureInput struct {
	TenantID        string            `json:"tenant_id"`
	CalendarID      string            `json:"calendar_id"`
	PolicyID        string            `json:"policy_id"`
	MetricID        string            `json:"metric_id"`
	TriggerID       string            `json:"trigger_id"`
	ColumnID        string            `json:"column_id,omitempty"`
	ObjectType      kernel.ObjectType `json:"object_type"`
	KeyPrefix       string            `json:"key_prefix"`
	EffectiveFrom   time.Time         `json:"effective_from"`
	DurationMicros  int64             `json:"duration_micros"`
	CompletionEvent string            `json:"completion_event"`
}

type fixtureDocuments struct {
	Identity fixtureInput   `json:"identity"`
	Calendar map[string]any `json:"calendar"`
	Policy   map[string]any `json:"policy"`
	Column   map[string]any `json:"column,omitempty"`
}

func main() {
	inputPath := flag.String("input", "", "synthetic fixture input JSON (required)")
	outputPath := flag.String("output", "", "write generated JSON; default stdout")
	checkPath := flag.String("check", "", "check an existing generated JSON document without writing")
	flag.Parse()
	if err := run(*inputPath, *outputPath, *checkPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(inputPath, outputPath, checkPath string) error {
	if inputPath == "" || outputPath != "" && checkPath != "" {
		return errors.New("provide --input and at most one of --output or --check")
	}
	raw, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}
	var input fixtureInput
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("fixture input must contain exactly one JSON document")
	}
	document, err := buildFixture(input)
	if err != nil {
		return err
	}
	generated, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return err
	}
	generated = append(generated, '\n')
	if checkPath != "" {
		actual, readErr := os.ReadFile(checkPath)
		if readErr != nil {
			return readErr
		}
		// Formatting is owned by the repository formatter, not by Go. Compare
		// the exact JSON token stream, including field/array ordering and values.
		var expectedCompact, actualCompact bytes.Buffer
		if json.Compact(&expectedCompact, generated) != nil ||
			json.Compact(&actualCompact, actual) != nil ||
			!bytes.Equal(expectedCompact.Bytes(), actualCompact.Bytes()) {
			return errors.New("SLA fixture drift: regenerate from the kernel and format the output")
		}
		return nil
	}
	if outputPath != "" {
		return os.WriteFile(outputPath, generated, 0o644)
	}
	_, err = os.Stdout.Write(generated)
	return err
}

func buildKernel(input fixtureInput) (kernel.BusinessCalendar, kernel.Policy, error) {
	var emptyCalendar kernel.BusinessCalendar
	var emptyPolicy kernel.Policy
	objectLabel := map[kernel.ObjectType]string{kernel.ObjectCase: "Case", kernel.ObjectAlert: "Alert"}[input.ObjectType]
	if objectLabel == "" || input.DurationMicros <= 0 || input.DurationMicros > int64(100*365*24*time.Hour/time.Microsecond) {
		return emptyCalendar, emptyPolicy, errors.New("fixture requires Case/Alert and a bounded positive duration")
	}
	ids := make([]kernel.EntityID, 5)
	for index, value := range []string{input.TenantID, input.CalendarID, input.PolicyID, input.MetricID, input.TriggerID} {
		id, err := kernel.ParseEntityID(value)
		if err != nil {
			return emptyCalendar, emptyPolicy, err
		}
		ids[index] = id
	}
	keys := make([]kernel.Key, 7)
	for index, value := range []string{
		input.KeyPrefix + "-support-hours", input.KeyPrefix + "-" + string(input.ObjectType) + "-response",
		"response-time", "ticket.created", input.CompletionEvent, "due-tag", "sla-breached",
	} {
		key, err := kernel.NewKey(value)
		if err != nil {
			return emptyCalendar, emptyPolicy, err
		}
		keys[index] = key
	}
	calendar, err := kernel.NewBusinessCalendar(kernel.BusinessCalendarInput{
		ID: ids[1], TenantID: ids[0], Key: keys[0], Label: "Demo support hours", Timezone: "UTC", Version: 1,
		WeeklySchedules: []kernel.WeeklyScheduleInput{{Weekday: time.Monday,
			Intervals: []kernel.MinuteIntervalInput{{StartMinute: 0, EndMinute: 1440}}}},
	})
	if err != nil {
		return emptyCalendar, emptyPolicy, err
	}
	metric, err := kernel.NewMetricDefinition(kernel.MetricDefinitionInput{
		ID: ids[3], Key: keys[2], Label: "Response time", Duration: time.Duration(input.DurationMicros) * time.Microsecond,
		Clock: kernel.ClockElapsed, StartEvent: keys[3], CompletionEvent: keys[4], ResetPolicy: kernel.ResetIgnore,
		Warning: kernel.WarningThreshold{Kind: kernel.WarningNone}, DisplayFormat: "duration", CustomerVisible: true, APIVisible: true,
	})
	if err != nil {
		return emptyCalendar, emptyPolicy, err
	}
	trigger, err := kernel.NewTriggerDefinition(metric, kernel.TriggerDefinitionInput{
		ID: ids[4], Key: keys[5], MetricID: metric.ID(), Kind: kernel.TriggerDue,
		Action: kernel.TriggerActionInput{Kind: kernel.ActionAddTag, Value: keys[6]},
	})
	if err != nil {
		return emptyCalendar, emptyPolicy, err
	}
	rule, err := kernel.NewRule(&kernel.RuleInput{Kind: kernel.RuleAll})
	if err != nil {
		return emptyCalendar, emptyPolicy, err
	}
	description := "Synthetic " + objectLabel + " response policy."
	if metric.Duration() == 4*time.Hour {
		description = "Synthetic four-hour " + objectLabel + " response policy."
	}
	policy, err := kernel.NewPolicy(kernel.PolicyInput{
		ID: ids[2], TenantID: ids[0], Key: keys[1], Name: "Demo " + string(input.ObjectType) + " response",
		Description: description,
		Version:     1, ObjectTypes: []kernel.ObjectType{input.ObjectType}, MatchRule: rule,
		Metrics: []kernel.MetricDefinition{metric}, Triggers: []kernel.TriggerDefinition{trigger},
		EffectiveFrom: input.EffectiveFrom, Enabled: true,
	})
	return calendar, policy, err
}

func buildFixture(input fixtureInput) (fixtureDocuments, error) {
	calendar, policy, err := buildKernel(input)
	if err != nil {
		return fixtureDocuments{}, err
	}
	calendarInput := calendar.Input()
	weekly := make([]map[string]any, 0, len(calendarInput.WeeklySchedules))
	for _, schedule := range calendarInput.WeeklySchedules {
		intervals := make([]map[string]any, 0, len(schedule.Intervals))
		for _, interval := range schedule.Intervals {
			intervals = append(intervals, map[string]any{"start_minute": interval.StartMinute, "end_minute": interval.EndMinute})
		}
		weekly = append(weekly, map[string]any{"weekday": schedule.Weekday, "intervals": intervals})
	}
	// This intentionally exports the bounded response-policy preset, not a second
	// general configuration serializer. Every non-null semantic value comes from
	// the constructed kernel value; absent optional fields retain the SQL shape.
	metric := policy.Metrics()[0]
	trigger := policy.Triggers()[0]
	column, err := buildColumn(input, metric)
	if err != nil {
		return fixtureDocuments{}, err
	}
	var columnDocument map[string]any
	if column != nil {
		columnInput := column.Input()
		columnDocument = map[string]any{
			"key": columnInput.Key.String(), "label": columnInput.Label,
			"metric_definition_id": columnInput.MetricID.String(), "calculation": columnInput.Calculation,
			"format": columnInput.Format, "sortable": columnInput.Sortable, "filterable": columnInput.Filterable,
			"customer_visible": columnInput.CustomerVisible, "visible_role_keys": []string{},
			"position": columnInput.Position, "style_rules": []any{}, "revision_digest": fmt.Sprintf("%x", column.Digest()),
		}
	}
	return fixtureDocuments{
		Identity: input,
		Column:   columnDocument,
		Calendar: map[string]any{
			"key": calendar.Key().String(), "label": calendar.Label(), "timezone": calendar.Timezone(),
			"weekly_schedule": weekly, "exceptions": []any{}, "revision_digest": fmt.Sprintf("%x", calendar.Digest()),
		},
		Policy: map[string]any{
			"key": policy.Key().String(), "name": policy.Name(), "description": policy.Description(),
			"priority": policy.Priority(), "object_types": policy.ObjectTypes(),
			"match_rule":     map[string]any{"kind": policy.MatchRule().Input().Kind},
			"effective_from": policy.EffectiveFrom(), "effective_until": policy.EffectiveUntil(),
			"enabled": policy.Enabled(), "apply_to_sla_engine_source": policy.ApplyToSLAEngineSource(),
			"revision_digest": fmt.Sprintf("%x", policy.Digest()),
			"metrics": []map[string]any{{
				"id": metric.ID().String(), "key": metric.Key().String(), "label": metric.Label(), "description": metric.Description(),
				"duration_micros": metric.Duration().Microseconds(), "clock": metric.Clock(), "calendar_id": nil, "calendar_version": nil,
				"start_event": metric.StartEvent().String(), "pause_event": nil, "resume_event": nil,
				"completion_event": metric.CompletionEvent().String(), "reset_event": nil, "reset_policy": metric.ResetPolicy(),
				"warning_kind": metric.Warning().Kind, "warning_consumed_percent": nil, "warning_remaining_micros": nil,
				"breach_grace_micros": metric.BreachGrace().Microseconds(), "display_format": metric.DisplayFormat(),
				"customer_visible": metric.CustomerVisible(), "api_visible": metric.APIVisible(), "position": 0,
				"definition_digest": fmt.Sprintf("%x", metric.Digest()),
			}},
			"triggers": []map[string]any{{
				"id": trigger.ID().String(), "metric_definition_id": trigger.MetricID().String(), "key": trigger.Key().String(),
				"kind": trigger.Kind(), "consumed_percent": nil, "remaining_micros": nil, "offset_micros": nil,
				"repeat_interval_micros": nil, "target_state": nil, "action_kind": trigger.Action().Kind(),
				"action_configuration_id": nil, "action_value": trigger.Action().Value().String(),
				"allow_recursive_sla": trigger.Action().AllowRecursiveSLA(), "position": 0,
				"definition_digest": fmt.Sprintf("%x", trigger.Digest()),
			}},
		},
	}, nil
}

func buildColumn(input fixtureInput, metric kernel.MetricDefinition) (*kernel.ColumnDefinition, error) {
	if input.ColumnID == "" {
		return nil, nil
	}
	id, err := kernel.ParseEntityID(input.ColumnID)
	if err != nil {
		return nil, err
	}
	tenantID, err := kernel.ParseEntityID(input.TenantID)
	if err != nil {
		return nil, err
	}
	key, err := kernel.NewKey(input.KeyPrefix + "-due-at")
	if err != nil {
		return nil, err
	}
	column, err := kernel.NewColumnDefinition(metric, kernel.ColumnDefinitionInput{
		ID: id, TenantID: tenantID, Key: key, Label: "Response due at", MetricID: metric.ID(),
		Calculation: kernel.ColumnDueAt, Format: kernel.FormatDateTime, Sortable: true, Filterable: true, Version: 1,
	})
	return &column, err
}
