package httpserver

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"

	kernel "github.com/periapsis-im/periapsis/modules/sla"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	applicationsla "github.com/periapsis-im/periapsis/services/api/internal/sla"
)

const maximumSLADurationMicros int64 = 3_153_600_000_000_000

func slaEntity(value uuid.UUID) (kernel.EntityID, error) {
	return kernel.ParseEntityID(value.String())
}

func slaKey(value string) (kernel.Key, error) { return kernel.NewKey(value) }

func slaOptionalKey(value *string) (kernel.Key, error) {
	if value == nil {
		return kernel.Key{}, nil
	}
	return slaKey(*value)
}

func slaDuration(micros int64, allowZero bool) (time.Duration, error) {
	if micros < 0 || micros > maximumSLADurationMicros || !allowZero && micros == 0 {
		return 0, applicationsla.ErrInvalidInput
	}
	return time.Duration(micros) * time.Microsecond, nil
}

func slaCalendarInput(
	tenantID uuid.UUID,
	id uuid.UUID,
	version uint64,
	key, label, timezone string,
	weekly []slaWeeklyScheduleBody,
	exceptions []slaDateExceptionBody,
) (kernel.BusinessCalendarInput, error) {
	tenant, tenantErr := slaEntity(tenantID)
	entity, idErr := slaEntity(id)
	parsedKey, keyErr := slaKey(key)
	if tenantErr != nil || idErr != nil || keyErr != nil || version == 0 || version >= uint64(math.MaxInt64) {
		return kernel.BusinessCalendarInput{}, applicationsla.ErrInvalidInput
	}
	result := kernel.BusinessCalendarInput{
		ID: entity, TenantID: tenant, Key: parsedKey, Label: label, Timezone: timezone, Version: version,
		WeeklySchedules: make([]kernel.WeeklyScheduleInput, len(weekly)),
		Exceptions:      make([]kernel.DateExceptionInput, len(exceptions)),
	}
	weekdays := map[string]time.Weekday{
		"sunday": time.Sunday, "monday": time.Monday, "tuesday": time.Tuesday,
		"wednesday": time.Wednesday, "thursday": time.Thursday, "friday": time.Friday, "saturday": time.Saturday,
	}
	for index, source := range weekly {
		weekday, ok := weekdays[source.Weekday]
		if !ok {
			return kernel.BusinessCalendarInput{}, applicationsla.ErrInvalidInput
		}
		intervals, err := slaIntervals(source.Intervals)
		if err != nil {
			return kernel.BusinessCalendarInput{}, err
		}
		result.WeeklySchedules[index] = kernel.WeeklyScheduleInput{Weekday: weekday, Intervals: intervals}
	}
	for index, source := range exceptions {
		intervals, err := slaIntervals(source.Intervals)
		if err != nil {
			return kernel.BusinessCalendarInput{}, err
		}
		result.Exceptions[index] = kernel.DateExceptionInput{Date: source.Date, Closed: source.Closed, Intervals: intervals}
	}
	return result, nil
}

func slaIntervals(values []slaMinuteIntervalBody) ([]kernel.MinuteIntervalInput, error) {
	if len(values) > 32 {
		return nil, applicationsla.ErrInvalidInput
	}
	result := make([]kernel.MinuteIntervalInput, len(values))
	for index, value := range values {
		if value.StartMinute < 0 || value.StartMinute > math.MaxUint16 || value.EndMinute < 0 || value.EndMinute > math.MaxUint16 {
			return nil, applicationsla.ErrInvalidInput
		}
		result[index] = kernel.MinuteIntervalInput{StartMinute: uint16(value.StartMinute), EndMinute: uint16(value.EndMinute)}
	}
	return result, nil
}

func slaPolicyInput(
	tenantID uuid.UUID,
	id uuid.UUID,
	version uint64,
	key, name, description string,
	priority int32,
	objectTypes []string,
	ruleRaw slaRawJSON,
	effectiveFrom time.Time,
	effectiveUntil *time.Time,
	enabled bool,
	applyToEngine bool,
	metricBodies []slaMetricWriteBody,
	triggerBodies []slaTriggerWriteBody,
) (kernel.PolicyInput, error) {
	tenant, tenantErr := slaEntity(tenantID)
	entity, idErr := slaEntity(id)
	parsedKey, keyErr := slaKey(key)
	ruleInput, ruleErr := parseSLARule(ruleRaw)
	if tenantErr != nil || idErr != nil || keyErr != nil || ruleErr != nil || version == 0 || version >= uint64(math.MaxInt64) {
		return kernel.PolicyInput{}, applicationsla.ErrInvalidInput
	}
	rule, err := kernel.NewRule(ruleInput)
	if err != nil {
		return kernel.PolicyInput{}, applicationsla.ErrInvalidInput
	}
	objects := make([]kernel.ObjectType, len(objectTypes))
	for index, value := range objectTypes {
		objects[index] = kernel.ObjectType(value)
		if objects[index] != kernel.ObjectAlert && objects[index] != kernel.ObjectCase {
			return kernel.PolicyInput{}, applicationsla.ErrInvalidInput
		}
	}
	metrics := make([]kernel.MetricDefinition, len(metricBodies))
	metricByID := make(map[kernel.EntityID]kernel.MetricDefinition, len(metricBodies))
	for index, body := range metricBodies {
		input, inputErr := slaMetricInput(body)
		if inputErr != nil {
			return kernel.PolicyInput{}, inputErr
		}
		metric, metricErr := kernel.NewMetricDefinition(input)
		if metricErr != nil {
			return kernel.PolicyInput{}, applicationsla.ErrInvalidInput
		}
		metrics[index] = metric
		metricByID[metric.ID()] = metric
	}
	triggers := make([]kernel.TriggerDefinition, len(triggerBodies))
	for index, body := range triggerBodies {
		metricID, metricIDErr := slaEntity(body.MetricDefinitionID)
		metric, found := metricByID[metricID]
		if metricIDErr != nil || !found {
			return kernel.PolicyInput{}, applicationsla.ErrInvalidInput
		}
		input, inputErr := slaTriggerInput(body)
		if inputErr != nil {
			return kernel.PolicyInput{}, inputErr
		}
		trigger, triggerErr := kernel.NewTriggerDefinition(metric, input)
		if triggerErr != nil {
			return kernel.PolicyInput{}, applicationsla.ErrInvalidInput
		}
		triggers[index] = trigger
	}
	return kernel.PolicyInput{
		ID: entity, TenantID: tenant, Key: parsedKey, Name: name, Description: description,
		Version: version, Priority: priority, ObjectTypes: objects, MatchRule: rule,
		Metrics: metrics, Triggers: triggers, EffectiveFrom: effectiveFrom,
		EffectiveUntil: effectiveUntil, Enabled: enabled, ApplyToSLAEngineSource: applyToEngine,
	}, nil
}

func slaMetricInput(body slaMetricWriteBody) (kernel.MetricDefinitionInput, error) {
	id, idErr := slaEntity(body.ID)
	key, keyErr := slaKey(body.Key)
	start, startErr := slaKey(body.StartEvent)
	completion, completionErr := slaKey(body.CompletionEvent)
	pause, pauseErr := slaOptionalKey(body.PauseEvent)
	resume, resumeErr := slaOptionalKey(body.ResumeEvent)
	reset, resetErr := slaOptionalKey(body.ResetEvent)
	duration, durationErr := slaDuration(body.DurationMicros, false)
	grace, graceErr := slaDuration(body.BreachGraceMicros, true)
	warning, warningErr := parseSLAWarning(body.Warning)
	if idErr != nil || keyErr != nil || startErr != nil || completionErr != nil || pauseErr != nil || resumeErr != nil ||
		resetErr != nil || durationErr != nil || graceErr != nil || warningErr != nil {
		return kernel.MetricDefinitionInput{}, applicationsla.ErrInvalidInput
	}
	var calendarID *kernel.EntityID
	calendarVersion := uint64(0)
	if body.CalendarID != nil {
		value, err := slaEntity(*body.CalendarID)
		if err != nil {
			return kernel.MetricDefinitionInput{}, applicationsla.ErrInvalidInput
		}
		calendarID = &value
	}
	if body.CalendarVersion != nil {
		if *body.CalendarVersion <= 0 {
			return kernel.MetricDefinitionInput{}, applicationsla.ErrInvalidInput
		}
		calendarVersion = uint64(*body.CalendarVersion)
	}
	return kernel.MetricDefinitionInput{
		ID: id, Key: key, Label: body.Label, Description: body.Description, Duration: duration,
		Clock: kernel.ClockType(body.Clock), CalendarID: calendarID, CalendarVersion: calendarVersion,
		StartEvent: start, PauseEvent: pause, ResumeEvent: resume, CompletionEvent: completion,
		ResetEvent: reset, ResetPolicy: kernel.ResetPolicy(body.ResetPolicy), Warning: warning,
		BreachGrace: grace, DisplayFormat: body.DisplayFormat,
		CustomerVisible: body.CustomerVisible, APIVisible: body.APIVisible,
	}, nil
}

func slaTriggerInput(body slaTriggerWriteBody) (kernel.TriggerDefinitionInput, error) {
	id, idErr := slaEntity(body.ID)
	key, keyErr := slaKey(body.Key)
	metricID, metricErr := slaEntity(body.MetricDefinitionID)
	action, actionErr := parseSLATriggerAction(body.Action)
	if idErr != nil || keyErr != nil || metricErr != nil || actionErr != nil {
		return kernel.TriggerDefinitionInput{}, applicationsla.ErrInvalidInput
	}
	result := kernel.TriggerDefinitionInput{ID: id, Key: key, MetricID: metricID, Kind: kernel.TriggerKind(body.Kind), Action: action}
	if body.ConsumedPercent != nil {
		if *body.ConsumedPercent < 0 || *body.ConsumedPercent > math.MaxUint8 {
			return kernel.TriggerDefinitionInput{}, applicationsla.ErrInvalidInput
		}
		result.ConsumedPercent = uint8(*body.ConsumedPercent)
	}
	for source, destination := range map[*int64]*time.Duration{
		body.RemainingMicros: &result.Remaining, body.OffsetMicros: &result.Offset, body.RepeatIntervalMicros: &result.RepeatInterval,
	} {
		if source != nil {
			value, err := slaDuration(*source, true)
			if err != nil {
				return kernel.TriggerDefinitionInput{}, err
			}
			*destination = value
		}
	}
	if body.TargetState != nil {
		result.TargetState = kernel.MetricState(*body.TargetState)
	}
	return result, nil
}

func slaColumnInput(
	tenantID uuid.UUID,
	id uuid.UUID,
	version uint64,
	key, label string,
	metricDefinitionID uuid.UUID,
	calculation, format string,
	sortable, filterable, customerVisible bool,
	visibleRoleKeys []string,
	position int,
	styleBodies []slaColumnStyleBody,
) (kernel.ColumnDefinitionInput, error) {
	tenant, tenantErr := slaEntity(tenantID)
	entity, idErr := slaEntity(id)
	metric, metricErr := slaEntity(metricDefinitionID)
	parsedKey, keyErr := slaKey(key)
	if tenantErr != nil || idErr != nil || metricErr != nil || keyErr != nil || version == 0 ||
		version >= uint64(math.MaxInt64) || position < 0 || position > math.MaxUint16 {
		return kernel.ColumnDefinitionInput{}, applicationsla.ErrInvalidInput
	}
	roles := make([]kernel.Key, len(visibleRoleKeys))
	for index, value := range visibleRoleKeys {
		role, err := slaKey(value)
		if err != nil {
			return kernel.ColumnDefinitionInput{}, applicationsla.ErrInvalidInput
		}
		roles[index] = role
	}
	styles := make([]kernel.ColumnStyleRuleInput, len(styleBodies))
	for index, body := range styleBodies {
		styleKey, err := slaKey(body.StyleKey)
		if err != nil {
			return kernel.ColumnDefinitionInput{}, applicationsla.ErrInvalidInput
		}
		style := kernel.ColumnStyleRuleInput{StyleKey: styleKey, MinimumPercentage: body.MinimumPercentage}
		if body.State != nil {
			style.State = kernel.MetricState(*body.State)
		}
		if body.MaximumRemainingMicros != nil {
			remaining, durationErr := slaDuration(*body.MaximumRemainingMicros, true)
			if durationErr != nil {
				return kernel.ColumnDefinitionInput{}, durationErr
			}
			style.MaximumRemaining = &remaining
		}
		styles[index] = style
	}
	return kernel.ColumnDefinitionInput{
		ID: entity, TenantID: tenant, Key: parsedKey, Label: label, MetricID: metric,
		Calculation: kernel.ColumnCalculation(calculation), Format: kernel.ColumnFormat(format),
		Sortable: sortable, Filterable: filterable, CustomerVisible: customerVisible,
		VisibleRoleKeys: roles, Position: uint16(position), Version: version, StyleRules: styles,
	}, nil
}

func slaSimulationCommand(tenantID uuid.UUID, body slaSimulationBody) (applicationsla.SimulationCommand, error) {
	tenant, tenantErr := slaEntity(tenantID)
	slaInstanceID, slaErr := slaEntity(body.SLAInstanceID)
	objectID, objectErr := slaEntity(body.ObjectID)
	if tenantErr != nil || slaErr != nil || objectErr != nil || body.PolicyVersion <= 0 {
		return applicationsla.SimulationCommand{}, applicationsla.ErrInvalidInput
	}
	facts := make([]kernel.FactInput, len(body.Snapshot.Facts))
	for index, bodyFact := range body.Snapshot.Facts {
		path, err := parseSLAFactPath(bodyFact.Path)
		if err != nil {
			return applicationsla.SimulationCommand{}, err
		}
		facts[index] = kernel.FactInput{Path: path, Values: slices.Clone(bodyFact.Values)}
	}
	snapshot, err := kernel.NewFactSnapshot(kernel.FactSnapshotInput{
		TenantID: tenant, ObjectType: kernel.ObjectType(body.Snapshot.ObjectType), EvaluatedAt: body.Snapshot.EvaluatedAt,
		Timezone: body.Snapshot.Timezone, Facts: facts,
	})
	if err != nil {
		return applicationsla.SimulationCommand{}, applicationsla.ErrInvalidInput
	}
	bindings := make([]kernel.SimulationMetricBinding, len(body.Bindings))
	for index, source := range body.Bindings {
		metricID, metricErr := slaEntity(source.MetricDefinitionID)
		instanceID, instanceErr := slaEntity(source.MetricInstanceID)
		if metricErr != nil || instanceErr != nil {
			return applicationsla.SimulationCommand{}, applicationsla.ErrInvalidInput
		}
		bindings[index] = kernel.SimulationMetricBinding{MetricID: metricID, InstanceID: instanceID}
	}
	events := make([]kernel.MetricEvent, len(body.Events))
	for index, source := range body.Events {
		eventID, eventErr := slaEntity(source.EventID)
		key, keyErr := slaKey(source.Key)
		if eventErr != nil || keyErr != nil {
			return applicationsla.SimulationCommand{}, applicationsla.ErrInvalidInput
		}
		events[index] = kernel.MetricEvent{ID: eventID, TenantID: tenant, ObjectID: objectID, Key: key, OccurredAt: source.OccurredAt}
	}
	return applicationsla.SimulationCommand{
		PolicyVersion: uint64(body.PolicyVersion), Snapshot: snapshot, SLAInstanceID: slaInstanceID,
		ObjectID: objectID, CreatedAt: body.CreatedAt, EvaluateAt: body.EvaluateAt,
		Bindings: bindings, Events: events,
	}, nil
}

func slaOverrideRequest(
	objectType kernel.ObjectType,
	objectID kernel.EntityID,
	aggregateVersion uint64,
	body slaOverrideBody,
	envelope applicationsla.MutationEnvelope,
) (applicationsla.OverrideRequest, error) {
	overrideID, overrideErr := slaEntity(body.OverrideID)
	slaInstanceID, slaErr := slaEntity(body.SLAInstanceID)
	if overrideErr != nil || slaErr != nil || aggregateVersion == 0 {
		return applicationsla.OverrideRequest{}, applicationsla.ErrInvalidInput
	}
	request := applicationsla.OverrideRequest{
		ObjectType: objectType, ObjectID: objectID, SLAInstanceID: slaInstanceID,
		ExpectedAggregateVersion: aggregateVersion, Envelope: envelope,
		Intent: applicationsla.OverrideIntent{ID: overrideID, Kind: kernel.OverrideKind(body.Kind), Reason: body.Reason},
	}
	metricKind := body.Kind != string(kernel.OverrideChangePolicy)
	if metricKind {
		if body.MetricInstanceID == nil || body.ExpectedMetricVersion == nil || *body.ExpectedMetricVersion <= 0 ||
			body.ExpectedAggregateVersion != nil || body.NewPolicyID != nil || body.NewPolicyVersion != nil {
			return applicationsla.OverrideRequest{}, applicationsla.ErrInvalidInput
		}
		metricID, err := slaEntity(*body.MetricInstanceID)
		if err != nil {
			return applicationsla.OverrideRequest{}, applicationsla.ErrInvalidInput
		}
		request.MetricInstanceID = metricID
		request.ExpectedMetricVersion = uint64(*body.ExpectedMetricVersion)
	} else if body.MetricInstanceID != nil || body.ExpectedMetricVersion != nil || body.ExpectedAggregateVersion == nil ||
		*body.ExpectedAggregateVersion <= 0 || uint64(*body.ExpectedAggregateVersion) != aggregateVersion {
		return applicationsla.OverrideRequest{}, applicationsla.ErrInvalidInput
	}

	if body.SimulationDigest != nil {
		digest, err := decodeSLADigest(*body.SimulationDigest)
		if err != nil {
			return applicationsla.OverrideRequest{}, err
		}
		request.Intent.SimulationDigest = digest
	}
	switch request.Intent.Kind {
	case kernel.OverrideExtend:
		if body.ExtensionMicros == nil || body.ReplacementCalendarID != nil || body.ReplacementCalendarVersion != nil ||
			body.SimulationDigest != nil {
			return applicationsla.OverrideRequest{}, applicationsla.ErrInvalidInput
		}
		extension, err := slaDuration(*body.ExtensionMicros, false)
		if err != nil {
			return applicationsla.OverrideRequest{}, err
		}
		request.Intent.Extension = extension
	case kernel.OverrideSuspend, kernel.OverrideResume, kernel.OverrideComplete:
		if body.ExtensionMicros != nil || body.ReplacementCalendarID != nil || body.ReplacementCalendarVersion != nil ||
			body.SimulationDigest != nil {
			return applicationsla.OverrideRequest{}, applicationsla.ErrInvalidInput
		}
	case kernel.OverrideChangeCalendar:
		if body.ExtensionMicros != nil || body.ReplacementCalendarID == nil || body.ReplacementCalendarVersion == nil ||
			*body.ReplacementCalendarVersion <= 0 || body.SimulationDigest == nil {
			return applicationsla.OverrideRequest{}, applicationsla.ErrInvalidInput
		}
		calendarID, err := slaEntity(*body.ReplacementCalendarID)
		if err != nil {
			return applicationsla.OverrideRequest{}, applicationsla.ErrInvalidInput
		}
		request.Intent.ReplacementCalendarID = calendarID
		request.Intent.ReplacementCalendarVersion = uint64(*body.ReplacementCalendarVersion)
	case kernel.OverrideChangePolicy:
		if body.ExtensionMicros != nil || body.ReplacementCalendarID != nil || body.ReplacementCalendarVersion != nil ||
			body.NewPolicyID == nil || body.NewPolicyVersion == nil || *body.NewPolicyVersion <= 0 || body.SimulationDigest == nil {
			return applicationsla.OverrideRequest{}, applicationsla.ErrInvalidInput
		}
		policyID, err := slaEntity(*body.NewPolicyID)
		if err != nil {
			return applicationsla.OverrideRequest{}, applicationsla.ErrInvalidInput
		}
		request.Intent.NewPolicyID = policyID
		request.Intent.NewPolicyVersion = uint64(*body.NewPolicyVersion)
	case kernel.OverrideRecalculate:
		if body.ExtensionMicros != nil || body.ReplacementCalendarID != nil || body.ReplacementCalendarVersion != nil ||
			body.SimulationDigest == nil {
			return applicationsla.OverrideRequest{}, applicationsla.ErrInvalidInput
		}
	default:
		return applicationsla.OverrideRequest{}, applicationsla.ErrInvalidInput
	}
	return request, nil
}

func parseSLARule(raw slaRawJSON) (*kernel.RuleInput, error) {
	nodes := 0
	return parseSLARuleNode(raw, 0, &nodes)
}

func parseSLARuleNode(raw []byte, depth int, nodes *int) (*kernel.RuleInput, error) {
	if depth > 16 || *nodes >= 256 {
		return nil, applicationsla.ErrInvalidInput
	}
	*nodes++
	kind, err := slaRawKind(raw)
	if err != nil {
		return nil, err
	}
	switch kind {
	case string(kernel.RuleAll), string(kernel.RuleAny), string(kernel.RuleNot):
		var body struct {
			Kind     string            `json:"kind"`
			Children []json.RawMessage `json:"children"`
		}
		if strictSLARaw(raw, &body) != nil || body.Kind != kind || body.Children == nil {
			return nil, applicationsla.ErrInvalidInput
		}
		result := &kernel.RuleInput{Kind: kernel.RuleKind(kind), Children: make([]*kernel.RuleInput, len(body.Children))}
		for index, child := range body.Children {
			result.Children[index], err = parseSLARuleNode(child, depth+1, nodes)
			if err != nil {
				return nil, err
			}
		}
		return result, nil
	case string(kernel.RulePredicate):
		var body struct {
			Kind      string `json:"kind"`
			Predicate struct {
				Path     json.RawMessage `json:"path"`
				Operator string          `json:"operator"`
				Values   []string        `json:"values"`
			} `json:"predicate"`
		}
		if strictSLARaw(raw, &body) != nil || body.Kind != kind || body.Predicate.Path == nil || body.Predicate.Values == nil {
			return nil, applicationsla.ErrInvalidInput
		}
		path, pathErr := parseSLAFactPath(body.Predicate.Path)
		if pathErr != nil {
			return nil, pathErr
		}
		return &kernel.RuleInput{Kind: kernel.RulePredicate, Predicate: kernel.PredicateInput{
			Path: path, Operator: kernel.PredicateOperator(body.Predicate.Operator), Values: slices.Clone(body.Predicate.Values),
		}}, nil
	default:
		return nil, applicationsla.ErrInvalidInput
	}
}

func parseSLAFactPath(raw []byte) (kernel.FactPath, error) {
	var body struct {
		Kind string  `json:"kind"`
		Key  *string `json:"key,omitempty"`
	}
	if strictSLARaw(raw, &body) != nil {
		return kernel.FactPath{}, applicationsla.ErrInvalidInput
	}
	path := kernel.FactPath{Kind: kernel.FactKind(body.Kind)}
	if body.Kind == string(kernel.FactCustomField) {
		if body.Key == nil {
			return kernel.FactPath{}, applicationsla.ErrInvalidInput
		}
		key, err := slaKey(*body.Key)
		if err != nil {
			return kernel.FactPath{}, applicationsla.ErrInvalidInput
		}
		path.Key = key
	} else if body.Key != nil {
		return kernel.FactPath{}, applicationsla.ErrInvalidInput
	}
	return path, nil
}

func parseSLAWarning(raw []byte) (kernel.WarningThreshold, error) {
	kind, err := slaRawKind(raw)
	if err != nil {
		return kernel.WarningThreshold{}, err
	}
	switch kind {
	case string(kernel.WarningNone):
		var body struct {
			Kind string `json:"kind"`
		}
		if strictSLARaw(raw, &body) != nil || body.Kind != kind {
			return kernel.WarningThreshold{}, applicationsla.ErrInvalidInput
		}
		return kernel.WarningThreshold{Kind: kernel.WarningNone}, nil
	case string(kernel.WarningConsumedPercent):
		var body struct {
			Kind            string `json:"kind"`
			ConsumedPercent int    `json:"consumedPercent"`
		}
		if strictSLARaw(raw, &body) != nil || body.ConsumedPercent < 0 || body.ConsumedPercent > math.MaxUint8 {
			return kernel.WarningThreshold{}, applicationsla.ErrInvalidInput
		}
		return kernel.WarningThreshold{Kind: kernel.WarningConsumedPercent, ConsumedPercent: uint8(body.ConsumedPercent)}, nil
	case string(kernel.WarningRemainingDuration):
		var body struct {
			Kind            string `json:"kind"`
			RemainingMicros int64  `json:"remainingMicros"`
		}
		if strictSLARaw(raw, &body) != nil {
			return kernel.WarningThreshold{}, applicationsla.ErrInvalidInput
		}
		remaining, durationErr := slaDuration(body.RemainingMicros, false)
		if durationErr != nil {
			return kernel.WarningThreshold{}, durationErr
		}
		return kernel.WarningThreshold{Kind: kernel.WarningRemainingDuration, RemainingDuration: remaining}, nil
	default:
		return kernel.WarningThreshold{}, applicationsla.ErrInvalidInput
	}
}

func parseSLATriggerAction(raw []byte) (kernel.TriggerActionInput, error) {
	kind, err := slaRawKind(raw)
	if err != nil {
		return kernel.TriggerActionInput{}, err
	}
	result := kernel.TriggerActionInput{Kind: kernel.ActionKind(kind)}
	switch result.Kind {
	case kernel.ActionEmail, kernel.ActionWebhook, kernel.ActionAssignTeam:
		var body struct {
			Kind            string    `json:"kind"`
			ConfigurationID uuid.UUID `json:"configurationId"`
		}
		if strictSLARaw(raw, &body) != nil || body.Kind != kind {
			return kernel.TriggerActionInput{}, applicationsla.ErrInvalidInput
		}
		configurationID, idErr := slaEntity(body.ConfigurationID)
		if idErr != nil {
			return kernel.TriggerActionInput{}, applicationsla.ErrInvalidInput
		}
		result.ConfigurationID = &configurationID
	case kernel.ActionAddTag, kernel.ActionChangePriority, kernel.ActionDomainEvent:
		var body struct {
			Kind  string `json:"kind"`
			Value string `json:"value"`
		}
		if strictSLARaw(raw, &body) != nil || body.Kind != kind {
			return kernel.TriggerActionInput{}, applicationsla.ErrInvalidInput
		}
		value, keyErr := slaKey(body.Value)
		if keyErr != nil {
			return kernel.TriggerActionInput{}, applicationsla.ErrInvalidInput
		}
		result.Value = value
	case kernel.ActionCreateTask:
		var body struct {
			Kind string `json:"kind"`
			Text string `json:"text"`
		}
		if strictSLARaw(raw, &body) != nil || body.Kind != kind {
			return kernel.TriggerActionInput{}, applicationsla.ErrInvalidInput
		}
		result.Text = body.Text
	case kernel.ActionCreateSystemAlert:
		var body struct {
			Kind              string `json:"kind"`
			Value             string `json:"value"`
			AllowRecursiveSLA bool   `json:"allowRecursiveSla"`
		}
		if strictSLARaw(raw, &body) != nil || body.Kind != kind {
			return kernel.TriggerActionInput{}, applicationsla.ErrInvalidInput
		}
		value, keyErr := slaKey(body.Value)
		if keyErr != nil {
			return kernel.TriggerActionInput{}, applicationsla.ErrInvalidInput
		}
		result.Value, result.AllowRecursiveSLA = value, body.AllowRecursiveSLA
	default:
		return kernel.TriggerActionInput{}, applicationsla.ErrInvalidInput
	}
	return result, nil
}

func slaRawKind(raw []byte) (string, error) {
	var body struct {
		Kind string `json:"kind"`
	}
	if len(raw) == 0 || json.Unmarshal(raw, &body) != nil || body.Kind == "" {
		return "", applicationsla.ErrInvalidInput
	}
	return body.Kind, nil
}

func strictSLARaw(raw []byte, destination any) error {
	if len(raw) == 0 || len(raw) > maximumPhase4BodyBytes || !json.Valid(raw) {
		return applicationsla.ErrInvalidInput
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	count := 0
	if err := scanPhase4JSONValue(decoder, 0, &count); err != nil {
		return applicationsla.ErrInvalidInput
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return applicationsla.ErrInvalidInput
	}
	decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var shape any
	if json.Unmarshal(raw, &shape) != nil || validateSLAJSONShape(shape, reflect.TypeOf(destination)) != nil {
		return applicationsla.ErrInvalidInput
	}
	if err := decoder.Decode(destination); err != nil {
		return applicationsla.ErrInvalidInput
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return applicationsla.ErrInvalidInput
	}
	return nil
}

func decodeSLADigest(value string) ([32]byte, error) {
	var result [32]byte
	if len(value) != 64 || strings.ToLower(value) != value {
		return result, applicationsla.ErrInvalidInput
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(result) {
		return result, applicationsla.ErrInvalidInput
	}
	copy(result[:], decoded)
	return result, nil
}

func mapSLACalendar(record applicationsla.CalendarRecord) (contract.SLABusinessCalendar, error) {
	input := record.Value.Input()
	weekly := make([]contract.SLAWeeklySchedule, len(input.WeeklySchedules))
	weekdayNames := [...]contract.SLAWeeklyScheduleWeekday{
		"sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday",
	}
	for index, source := range input.WeeklySchedules {
		if source.Weekday < time.Sunday || source.Weekday > time.Saturday {
			return contract.SLABusinessCalendar{}, applicationsla.ErrUnavailable
		}
		weekly[index] = contract.SLAWeeklySchedule{Weekday: weekdayNames[source.Weekday], Intervals: mapSLAIntervals(source.Intervals)}
	}
	exceptions := make([]contract.SLADateException, len(input.Exceptions))
	for index, source := range input.Exceptions {
		date, err := time.Parse("2006-01-02", source.Date)
		if err != nil || date.Format("2006-01-02") != source.Date {
			return contract.SLABusinessCalendar{}, applicationsla.ErrUnavailable
		}
		exceptions[index] = contract.SLADateException{
			Date: openapi_types.Date{Time: date}, Closed: source.Closed, Intervals: mapSLAIntervals(source.Intervals),
		}
	}
	digest := record.Value.Digest()
	return contract.SLABusinessCalendar{
		TenantId: uuid.MustParse(input.TenantID.String()), Id: uuid.MustParse(input.ID.String()),
		Version: int64(input.Version), ResourceVersion: int64(record.ResourceVersion),
		RevisionDigest: hex.EncodeToString(digest[:]), ArchivedAt: record.ArchivedAt,
		CreatedAt: record.CreatedAt, UpdatedAt: record.UpdatedAt, Key: input.Key.String(), Label: input.Label,
		Timezone: input.Timezone, WeeklySchedules: weekly, Exceptions: exceptions,
	}, nil
}

func mapSLAIntervals(values []kernel.MinuteIntervalInput) []contract.SLAMinuteInterval {
	result := make([]contract.SLAMinuteInterval, len(values))
	for index, value := range values {
		result[index] = contract.SLAMinuteInterval{StartMinute: int(value.StartMinute), EndMinute: int(value.EndMinute)}
	}
	return result
}

func mapSLAPolicy(record applicationsla.PolicyRecord) (contract.SLAPolicy, error) {
	input := record.Value.Input()
	rule, err := mapSLARule(input.MatchRule.Input())
	if err != nil {
		return contract.SLAPolicy{}, err
	}
	metrics := make([]contract.SLAMetricDefinition, len(input.Metrics))
	for index, metric := range input.Metrics {
		metrics[index], err = mapSLAMetricDefinition(metric, index)
		if err != nil {
			return contract.SLAPolicy{}, err
		}
	}
	triggers := make([]contract.SLATriggerDefinition, len(input.Triggers))
	for index, trigger := range input.Triggers {
		triggers[index], err = mapSLATriggerDefinition(trigger, index)
		if err != nil {
			return contract.SLAPolicy{}, err
		}
	}
	objectTypes := make([]contract.SLAObjectType, len(input.ObjectTypes))
	for index, value := range input.ObjectTypes {
		objectTypes[index] = contract.SLAObjectType(value)
	}
	digest := record.Value.Digest()
	return contract.SLAPolicy{
		TenantId: uuid.MustParse(input.TenantID.String()), Id: uuid.MustParse(input.ID.String()),
		Version: int64(input.Version), ResourceVersion: int64(record.ResourceVersion), RevisionDigest: hex.EncodeToString(digest[:]),
		ArchivedAt: record.ArchivedAt, CreatedAt: record.CreatedAt, UpdatedAt: record.UpdatedAt,
		Key: input.Key.String(), Name: input.Name, Description: input.Description, Priority: input.Priority,
		ObjectTypes: objectTypes, MatchRule: rule, Metrics: metrics, Triggers: triggers,
		EffectiveFrom: input.EffectiveFrom, EffectiveUntil: input.EffectiveUntil, Enabled: input.Enabled,
		ApplyToSlaEngineSource: input.ApplyToSLAEngineSource,
	}, nil
}

func mapSLAMetricDefinition(value kernel.MetricDefinition, position int) (contract.SLAMetricDefinition, error) {
	input := value.Input()
	warning := map[string]any{"kind": string(input.Warning.Kind)}
	if input.Warning.Kind == kernel.WarningConsumedPercent {
		warning["consumedPercent"] = int(input.Warning.ConsumedPercent)
	}
	if input.Warning.Kind == kernel.WarningRemainingDuration {
		warning["remainingMicros"] = input.Warning.RemainingDuration.Microseconds()
	}
	wire := map[string]any{
		"id": uuid.MustParse(input.ID.String()), "key": input.Key.String(), "label": input.Label,
		"description": input.Description, "durationMicros": input.Duration.Microseconds(), "clock": string(input.Clock),
		"startEvent": input.StartEvent.String(), "completionEvent": input.CompletionEvent.String(),
		"resetPolicy": string(input.ResetPolicy), "warning": warning, "breachGraceMicros": input.BreachGrace.Microseconds(),
		"displayFormat": input.DisplayFormat, "customerVisible": input.CustomerVisible, "apiVisible": input.APIVisible,
		"position": position,
	}
	if input.CalendarID != nil {
		wire["calendarId"] = uuid.MustParse(input.CalendarID.String())
		wire["calendarVersion"] = int64(input.CalendarVersion)
	}
	if input.PauseEvent.String() != "" {
		wire["pauseEvent"], wire["resumeEvent"] = input.PauseEvent.String(), input.ResumeEvent.String()
	}
	if input.ResetEvent.String() != "" {
		wire["resetEvent"] = input.ResetEvent.String()
	}
	return generatedSLAValue[contract.SLAMetricDefinition](wire)
}

func mapSLATriggerDefinition(value kernel.TriggerDefinition, position int) (contract.SLATriggerDefinition, error) {
	input := value.Input()
	action, err := mapSLATriggerAction(value.Action())
	if err != nil {
		return contract.SLATriggerDefinition{}, err
	}
	wire := map[string]any{
		"id": uuid.MustParse(input.ID.String()), "key": input.Key.String(),
		"metricDefinitionId": uuid.MustParse(input.MetricID.String()), "kind": string(input.Kind),
		"action": action, "position": position,
	}
	switch input.Kind {
	case kernel.TriggerConsumedPercent:
		wire["consumedPercent"] = int(input.ConsumedPercent)
	case kernel.TriggerRemaining:
		wire["remainingMicros"] = input.Remaining.Microseconds()
	case kernel.TriggerAfterBreach:
		wire["offsetMicros"] = input.Offset.Microseconds()
	case kernel.TriggerRepeatedBreach:
		wire["offsetMicros"], wire["repeatIntervalMicros"] = input.Offset.Microseconds(), input.RepeatInterval.Microseconds()
	case kernel.TriggerStateChanged:
		wire["targetState"] = string(input.TargetState)
	}
	return generatedSLAValue[contract.SLATriggerDefinition](wire)
}

func mapSLARule(input *kernel.RuleInput) (contract.SLARule, error) {
	if input == nil {
		return contract.SLARule{}, applicationsla.ErrUnavailable
	}
	wire := map[string]any{"kind": string(input.Kind)}
	if input.Kind == kernel.RulePredicate {
		path := map[string]any{"kind": string(input.Predicate.Path.Kind)}
		if input.Predicate.Path.Kind == kernel.FactCustomField {
			path["key"] = input.Predicate.Path.Key.String()
		}
		wire["predicate"] = map[string]any{
			"path": path, "operator": string(input.Predicate.Operator), "values": slices.Clone(input.Predicate.Values),
		}
	} else {
		children := make([]any, len(input.Children))
		for index, child := range input.Children {
			mapped, err := mapSLARule(child)
			if err != nil {
				return contract.SLARule{}, err
			}
			children[index] = mapped
		}
		wire["children"] = children
	}
	return generatedSLAValue[contract.SLARule](wire)
}

func mapSLATriggerAction(value kernel.TriggerAction) (contract.SLATriggerAction, error) {
	wire := map[string]any{"kind": string(value.Kind())}
	if configurationID := value.ConfigurationID(); configurationID != nil {
		wire["configurationId"] = uuid.MustParse(configurationID.String())
	}
	if value.Value().String() != "" {
		wire["value"] = value.Value().String()
	}
	if value.Kind() == kernel.ActionCreateTask {
		wire["text"] = value.Text()
	}
	if value.Kind() == kernel.ActionCreateSystemAlert {
		wire["allowRecursiveSla"] = value.AllowRecursiveSLA()
	}
	return generatedSLAValue[contract.SLATriggerAction](wire)
}

func mapSLAColumn(record applicationsla.ColumnRecord) (contract.SLAColumn, error) {
	input := record.Value.Input()
	styles := make([]map[string]any, len(input.StyleRules))
	for index, style := range input.StyleRules {
		wire := map[string]any{"styleKey": style.StyleKey.String()}
		if style.State != "" {
			wire["state"] = string(style.State)
		}
		if style.MinimumPercentage != nil {
			wire["minimumPercentage"] = *style.MinimumPercentage
		}
		if style.MaximumRemaining != nil {
			wire["maximumRemainingMicros"] = style.MaximumRemaining.Microseconds()
		}
		styles[index] = wire
	}
	roles := make([]string, len(input.VisibleRoleKeys))
	for index, role := range input.VisibleRoleKeys {
		roles[index] = role.String()
	}
	digest := record.Value.Digest()
	wire := map[string]any{
		"tenantId": uuid.MustParse(input.TenantID.String()), "id": uuid.MustParse(input.ID.String()),
		"version": int64(input.Version), "resourceVersion": int64(record.ResourceVersion), "revisionDigest": hex.EncodeToString(digest[:]),
		"createdAt": record.CreatedAt, "updatedAt": record.UpdatedAt, "key": input.Key.String(), "label": input.Label,
		"metricDefinitionId": uuid.MustParse(input.MetricID.String()), "calculation": string(input.Calculation), "format": string(input.Format),
		"sortable": input.Sortable, "filterable": input.Filterable, "customerVisible": input.CustomerVisible,
		"visibleRoleKeys": roles, "position": int(input.Position), "styleRules": styles,
	}
	if record.ArchivedAt != nil {
		wire["archivedAt"] = record.ArchivedAt
	}
	return generatedSLAValue[contract.SLAColumn](wire)
}

func mapSLASimulation(tenantID uuid.UUID, value applicationsla.SimulationResult) (contract.SLASimulationResult, error) {
	metrics := value.Result.Metrics()
	mapped := make([]contract.SLASimulationMetricResult, len(metrics))
	for index, metric := range metrics {
		instance, evaluation := metric.Instance(), metric.Evaluation()
		triggers := metric.Triggers()
		projected := make([]contract.SLAProjectedTrigger, len(triggers))
		for triggerIndex, trigger := range triggers {
			action, err := mapSLATriggerAction(trigger.Action())
			if err != nil {
				return contract.SLASimulationResult{}, err
			}
			projected[triggerIndex] = contract.SLAProjectedTrigger{
				TriggerDefinitionId: uuid.MustParse(trigger.TriggerID().String()), MetricDefinitionId: uuid.MustParse(trigger.MetricID().String()),
				ScheduledAt: trigger.ScheduledAt(), EventDriven: trigger.EventDriven(), Action: action,
			}
		}
		mapped[index] = contract.SLASimulationMetricResult{
			MetricDefinitionId: uuid.MustParse(metric.MetricID().String()), MetricInstanceId: uuid.MustParse(instance.ID().String()),
			MetricKey: metric.MetricKey().String(), State: contract.SLAMetricState(evaluation.State), StartedAt: evaluation.StartedAt,
			DueAt: evaluation.DueAt, RemainingMicros: evaluation.Remaining.Microseconds(), ConsumedPercentage: evaluation.ConsumedPercentage,
			BreachedAt: evaluation.BreachedAt, CompletedAt: evaluation.CompletedAt, ProjectedTriggers: projected,
		}
	}
	return contract.SLASimulationResult{
		TenantId: tenantID, PolicyId: uuid.MustParse(value.Result.PolicyID().String()), PolicyVersion: int64(value.Result.PolicyVersion()),
		SimulationDigest: hex.EncodeToString(value.Digest[:]), Metrics: mapped,
	}, nil
}

func mapSLACustomerObject(value applicationsla.ObjectProjection) (contract.SLACustomerObjectProjection, error) {
	if value.Audience != applicationsla.AudienceCustomer || len(value.Metrics) > 32 || len(value.Columns) > 1024 {
		return contract.SLACustomerObjectProjection{}, applicationsla.ErrUnavailable
	}
	metrics := make([]contract.SLACustomerMetricProjection, len(value.Metrics))
	for index, metric := range value.Metrics {
		if !metric.CustomerVisible || metric.State == kernel.StatePaused || metric.PausedAt != nil {
			return contract.SLACustomerObjectProjection{}, applicationsla.ErrUnavailable
		}
		metrics[index] = contract.SLACustomerMetricProjection{
			Key: metric.Key.String(), Label: metric.Label, State: contract.SLAMetricState(metric.State), StartedAt: metric.StartedAt,
			DueAt: metric.DueAt, RemainingSeconds: metric.RemainingSeconds, ConsumedPercentage: metric.ConsumedPercentage,
			BreachedAt: metric.BreachedAt, CompletedAt: metric.CompletedAt,
		}
	}
	columns := make([]contract.SLACustomerColumnProjection, len(value.Columns))
	for index, column := range value.Columns {
		if !column.CustomerVisible || column.State == kernel.StatePaused {
			return contract.SLACustomerObjectProjection{}, applicationsla.ErrUnavailable
		}
		columns[index] = customerSLAColumn(column)
	}
	return contract.SLACustomerObjectProjection{
		Audience: contract.SLACustomerObjectProjectionAudienceCustomer, TenantId: value.TenantID,
		ObjectType: contract.SLAObjectType(value.ObjectType), ObjectId: uuid.MustParse(value.ObjectID.String()),
		ProjectedAt: value.ProjectedAt, Metrics: metrics, Columns: columns,
	}, nil
}

func mapSLAOperatorObject(value applicationsla.ObjectProjection) (contract.SLAOperatorObjectProjection, error) {
	if value.Audience != applicationsla.AudienceOperator {
		return contract.SLAOperatorObjectProjection{}, applicationsla.ErrUnavailable
	}
	metrics := make([]contract.SLAOperatorMetricProjection, len(value.Metrics))
	for index, metric := range value.Metrics {
		metrics[index] = contract.SLAOperatorMetricProjection{
			MetricDefinitionId: uuid.MustParse(metric.MetricID.String()), MetricInstanceId: uuid.MustParse(metric.MetricInstanceID.String()),
			MetricVersion: int64(metric.MetricVersion), Key: metric.Key.String(), Label: metric.Label,
			CustomerVisible: metric.CustomerVisible, State: contract.SLAMetricState(metric.State), StartedAt: metric.StartedAt,
			PausedAt: metric.PausedAt, DueAt: metric.DueAt, RemainingSeconds: metric.RemainingSeconds,
			ConsumedPercentage: metric.ConsumedPercentage, BreachedAt: metric.BreachedAt, CompletedAt: metric.CompletedAt,
		}
	}
	columns := make([]contract.SLAOperatorColumnProjection, len(value.Columns))
	for index, column := range value.Columns {
		columns[index] = operatorSLAColumn(column)
	}
	return contract.SLAOperatorObjectProjection{
		Audience: contract.SLAOperatorObjectProjectionAudienceOperator, TenantId: value.TenantID,
		ObjectType: contract.SLAObjectType(value.ObjectType), ObjectId: uuid.MustParse(value.ObjectID.String()),
		SlaInstanceId: uuid.MustParse(value.SLAInstanceID.String()), AggregateVersion: int64(value.AggregateVersion),
		PolicyId: uuid.MustParse(value.PolicyID.String()), PolicyVersion: int64(value.PolicyVersion),
		ProjectedAt: value.ProjectedAt, Metrics: metrics, Columns: columns,
	}, nil
}

func operatorSLAColumn(value applicationsla.ColumnProjection) contract.SLAOperatorColumnProjection {
	style := optionalSLAKey(value.StyleKey)
	return contract.SLAOperatorColumnProjection{
		ColumnId: uuid.MustParse(value.ColumnID.String()), Key: value.Key.String(), Label: value.Label,
		Calculation: contract.SLAOperatorColumnProjectionCalculation(value.Calculation), Format: contract.SLAOperatorColumnProjectionFormat(value.Format),
		CustomerVisible: value.CustomerVisible, State: contract.SLAMetricState(value.State), Instant: value.Instant,
		DurationMicros: durationMicrosPointer(value.Duration), Percentage: value.Percentage, StyleKey: style,
		MaterializedAt: value.MaterializedAt,
	}
}

func customerSLAColumn(value applicationsla.ColumnProjection) contract.SLACustomerColumnProjection {
	return contract.SLACustomerColumnProjection{
		Key: value.Key.String(), Label: value.Label,
		Calculation: contract.SLACustomerColumnProjectionCalculation(value.Calculation), Format: contract.SLACustomerColumnProjectionFormat(value.Format),
		State: contract.SLAMetricState(value.State), Instant: value.Instant, DurationMicros: durationMicrosPointer(value.Duration),
		Percentage: value.Percentage, StyleKey: optionalSLAKey(value.StyleKey), MaterializedAt: value.MaterializedAt,
	}
}

func mapSLAOverride(value applicationsla.OverrideResult) contract.SLAOverrideReceipt {
	receipt := value.Receipt
	var metricID *uuid.UUID
	if receipt.MetricInstanceID != nil {
		parsed := uuid.MustParse(receipt.MetricInstanceID.String())
		metricID = &parsed
	}
	var digest *string
	if receipt.SimulationDigest != ([32]byte{}) {
		encoded := hex.EncodeToString(receipt.SimulationDigest[:])
		digest = &encoded
	}
	return contract.SLAOverrideReceipt{
		TenantId: receipt.TenantID, ObjectType: contract.SLAObjectType(receipt.ObjectType), ObjectId: uuid.MustParse(receipt.ObjectID.String()),
		OverrideId: uuid.MustParse(receipt.OverrideID.String()), Outcome: contract.SLAOverrideReceiptOutcome(receipt.Outcome),
		Kind: contract.SLAOverrideReceiptKind(receipt.Kind), SlaInstanceId: uuid.MustParse(receipt.SLAInstanceID.String()),
		MetricInstanceId: metricID, PreviousVersion: int64(receipt.PreviousVersion), CurrentVersion: int64(receipt.CurrentVersion),
		AggregateVersion: int64(receipt.AggregateVersion), PolicyId: uuid.MustParse(receipt.PolicyID.String()),
		PolicyVersion: int64(receipt.PolicyVersion), OccurredAt: receipt.OccurredAt, SimulationDigest: digest, Replayed: value.Replayed,
	}
}

func generatedSLAValue[T any](wire any) (T, error) {
	var result T
	raw, err := json.Marshal(wire)
	if err != nil || json.Unmarshal(raw, &result) != nil {
		return result, applicationsla.ErrUnavailable
	}
	return result, nil
}

func durationMicrosPointer(value *time.Duration) *int64 {
	if value == nil {
		return nil
	}
	micros := value.Microseconds()
	return &micros
}

func optionalSLAKey(value kernel.Key) *string {
	if value.String() == "" {
		return nil
	}
	result := value.String()
	return &result
}
