package sla

import (
	"context"
	"fmt"
	"math"
	"slices"
	"time"
)

type ColumnCalculation string

const (
	ColumnDueAt              ColumnCalculation = "due_at"
	ColumnRemaining          ColumnCalculation = "remaining_seconds"
	ColumnState              ColumnCalculation = "state"
	ColumnConsumedPercentage ColumnCalculation = "consumed_percentage"
	ColumnBreachedAt         ColumnCalculation = "breached_at"
)

type ColumnFormat string

const (
	FormatDateTime   ColumnFormat = "datetime"
	FormatDuration   ColumnFormat = "duration"
	FormatStateBadge ColumnFormat = "state_badge"
	FormatPercentage ColumnFormat = "percentage"
)

type ColumnStyleRuleInput struct {
	StyleKey          Key
	State             MetricState
	MinimumPercentage *float64
	MaximumRemaining  *time.Duration
}

type columnStyleRule struct {
	styleKey          Key
	state             MetricState
	minimumPercentage *float64
	maximumRemaining  *time.Duration
}

type ColumnDefinitionInput struct {
	ID              EntityID
	TenantID        EntityID
	Key             Key
	Label           string
	MetricID        EntityID
	Calculation     ColumnCalculation
	Format          ColumnFormat
	Sortable        bool
	Filterable      bool
	CustomerVisible bool
	VisibleRoleKeys []Key
	Position        uint16
	Version         uint64
	StyleRules      []ColumnStyleRuleInput
}

type ColumnDefinition struct {
	id              EntityID
	tenantID        EntityID
	key             Key
	label           string
	metricID        EntityID
	calculation     ColumnCalculation
	format          ColumnFormat
	sortable        bool
	filterable      bool
	customerVisible bool
	visibleRoleKeys []Key
	position        uint16
	version         uint64
	styleRules      []columnStyleRule
}

func NewColumnDefinition(metric MetricDefinition, input ColumnDefinitionInput) (ColumnDefinition, error) {
	roles, ok := canonicalKeys(input.VisibleRoleKeys, 128)
	styles, styleOK := canonicalColumnStyleRules(input.StyleRules)
	if !metric.valid() || !validEntityID(input.ID) || !validEntityID(input.TenantID) ||
		!validKey(input.Key.value) || !validText(input.Label, maximumLabelBytes, false, false) ||
		input.MetricID != metric.id || !validColumnShape(input.Calculation, input.Format) ||
		input.Version == 0 || input.Version >= maximumVersion || !ok || !styleOK {
		return ColumnDefinition{}, ErrInvalidMetric
	}
	return ColumnDefinition{
		id: input.ID, tenantID: input.TenantID, key: input.Key, label: input.Label,
		metricID: input.MetricID, calculation: input.Calculation, format: input.Format,
		sortable: input.Sortable, filterable: input.Filterable,
		customerVisible: input.CustomerVisible, visibleRoleKeys: roles,
		position: input.Position, version: input.Version, styleRules: styles,
	}, nil
}

func (column ColumnDefinition) ID() EntityID                   { return column.id }
func (column ColumnDefinition) TenantID() EntityID             { return column.tenantID }
func (column ColumnDefinition) Key() Key                       { return column.key }
func (column ColumnDefinition) Label() string                  { return column.label }
func (column ColumnDefinition) MetricID() EntityID             { return column.metricID }
func (column ColumnDefinition) Calculation() ColumnCalculation { return column.calculation }
func (column ColumnDefinition) Format() ColumnFormat           { return column.format }
func (column ColumnDefinition) Sortable() bool                 { return column.sortable }
func (column ColumnDefinition) Filterable() bool               { return column.filterable }
func (column ColumnDefinition) CustomerVisible() bool          { return column.customerVisible }
func (column ColumnDefinition) VisibleRoleKeys() []Key         { return slices.Clone(column.visibleRoleKeys) }
func (column ColumnDefinition) Position() uint16               { return column.position }
func (column ColumnDefinition) Version() uint64                { return column.version }
func (column ColumnDefinition) String() string {
	return fmt.Sprintf(
		"sla.ColumnDefinition{calculation:%s,format:%s,position:%d,version:%d,key:[REDACTED],label:[REDACTED]}",
		column.calculation, column.format, column.position, column.version,
	)
}
func (column ColumnDefinition) GoString() string { return column.String() }

func (column ColumnDefinition) VisibleTo(customer bool, operatorRoleKeys []Key) bool {
	if customer {
		return column.customerVisible
	}
	if len(column.visibleRoleKeys) == 0 {
		return true
	}
	roles, ok := canonicalKeys(operatorRoleKeys, 128)
	return ok && intersectsKeys(column.visibleRoleKeys, roles)
}

type MaterializedColumnValue struct {
	columnID       EntityID
	columnVersion  uint64
	metricID       EntityID
	calculation    ColumnCalculation
	state          MetricState
	instant        *time.Time
	duration       *time.Duration
	percentage     *float64
	styleKey       Key
	materializedAt time.Time
	nextRefreshAt  *time.Time
}

func (value MaterializedColumnValue) ColumnID() EntityID             { return value.columnID }
func (value MaterializedColumnValue) ColumnVersion() uint64          { return value.columnVersion }
func (value MaterializedColumnValue) MetricID() EntityID             { return value.metricID }
func (value MaterializedColumnValue) Calculation() ColumnCalculation { return value.calculation }
func (value MaterializedColumnValue) State() MetricState             { return value.state }
func (value MaterializedColumnValue) Instant() *time.Time            { return cloneTime(value.instant) }
func (value MaterializedColumnValue) Duration() *time.Duration {
	if value.duration == nil {
		return nil
	}
	copy := *value.duration
	return &copy
}
func (value MaterializedColumnValue) Percentage() *float64 {
	if value.percentage == nil {
		return nil
	}
	copy := *value.percentage
	return &copy
}
func (value MaterializedColumnValue) StyleKey() Key             { return value.styleKey }
func (value MaterializedColumnValue) MaterializedAt() time.Time { return value.materializedAt }
func (value MaterializedColumnValue) NextRefreshAt() *time.Time {
	return cloneTime(value.nextRefreshAt)
}

func MaterializeColumn(
	column ColumnDefinition,
	instance MetricInstance,
	at time.Time,
	calendar *BusinessCalendar,
) (MaterializedColumnValue, error) {
	return MaterializeColumnContext(context.Background(), column, instance, at, calendar)
}

// MaterializeColumnContext is MaterializeColumn with cancellation propagated
// into metric evaluation.
func MaterializeColumnContext(
	ctx context.Context,
	column ColumnDefinition,
	instance MetricInstance,
	at time.Time,
	calendar *BusinessCalendar,
) (MaterializedColumnValue, error) {
	if ctx == nil || ctx.Err() != nil {
		return MaterializedColumnValue{}, ErrEngineCanceled
	}
	if column.tenantID != instance.tenantID || column.metricID != instance.definition.id ||
		!validInstant(at) {
		return MaterializedColumnValue{}, ErrInvalidMetric
	}
	evaluation, err := instance.EvaluateContext(ctx, at, calendar)
	if err != nil {
		return MaterializedColumnValue{}, err
	}
	value := MaterializedColumnValue{
		columnID: column.id, columnVersion: column.version,
		metricID: column.metricID, calculation: column.calculation,
		state: evaluation.State, materializedAt: at,
	}
	switch column.calculation {
	case ColumnDueAt:
		value.instant = cloneTime(evaluation.DueAt)
	case ColumnRemaining:
		remaining := evaluation.Remaining
		value.duration = &remaining
	case ColumnState:
		// The typed state field is the value.
	case ColumnConsumedPercentage:
		percentage := evaluation.ConsumedPercentage
		value.percentage = &percentage
	case ColumnBreachedAt:
		value.instant = cloneTime(evaluation.BreachedAt)
	default:
		return MaterializedColumnValue{}, ErrInvalidMetric
	}
	value.styleKey = column.styleFor(evaluation)
	if instance.lifecycle == lifecycleRunning &&
		(column.calculation == ColumnRemaining || column.calculation == ColumnConsumedPercentage || column.calculation == ColumnState) {
		next, err := nextColumnRefresh(ctx, instance, at, calendar)
		if err != nil {
			return MaterializedColumnValue{}, err
		}
		if instance.breachThresholdAt != nil && next.After(*instance.breachThresholdAt) {
			next = *instance.breachThresholdAt
		}
		if validInstant(next) && next.After(at) {
			value.nextRefreshAt = &next
		}
	}
	return value, nil
}

func nextColumnRefresh(
	ctx context.Context,
	instance MetricInstance,
	at time.Time,
	calendar *BusinessCalendar,
) (time.Time, error) {
	nextMinute := at.Add(time.Minute).Truncate(time.Minute)
	if !nextMinute.After(at) {
		nextMinute = nextMinute.Add(time.Minute)
	}
	if instance.definition.clock == ClockElapsed {
		return nextMinute, nil
	}
	if !calendar.IsBusinessTime(at) {
		return calendar.nextBusinessTimeContext(ctx, at)
	}
	return calendar.AddBusinessTimeContext(ctx, at, nextMinute.Sub(at))
}

func (column ColumnDefinition) styleFor(evaluation MetricEvaluation) Key {
	for _, rule := range column.styleRules {
		if validMetricState(rule.state) && evaluation.State != rule.state ||
			rule.minimumPercentage != nil && evaluation.ConsumedPercentage < *rule.minimumPercentage ||
			rule.maximumRemaining != nil && evaluation.Remaining > *rule.maximumRemaining {
			continue
		}
		return rule.styleKey
	}
	return Key{}
}

func validColumnShape(calculation ColumnCalculation, format ColumnFormat) bool {
	switch calculation {
	case ColumnDueAt, ColumnBreachedAt:
		return format == FormatDateTime
	case ColumnRemaining:
		return format == FormatDuration
	case ColumnState:
		return format == FormatStateBadge
	case ColumnConsumedPercentage:
		return format == FormatPercentage
	default:
		return false
	}
}

func canonicalColumnStyleRules(inputs []ColumnStyleRuleInput) ([]columnStyleRule, bool) {
	if len(inputs) > 32 {
		return nil, false
	}
	result := make([]columnStyleRule, len(inputs))
	seen := make(map[Key]struct{}, len(inputs))
	for index, input := range inputs {
		conditions := 0
		if validMetricState(input.State) {
			conditions++
		} else if input.State != "" {
			return nil, false
		}
		if input.MinimumPercentage != nil {
			if math.IsNaN(*input.MinimumPercentage) || math.IsInf(*input.MinimumPercentage, 0) ||
				*input.MinimumPercentage < 0 || *input.MinimumPercentage > 100 {
				return nil, false
			}
			conditions++
		}
		if input.MaximumRemaining != nil {
			if *input.MaximumRemaining < 0 || *input.MaximumRemaining%time.Microsecond != 0 {
				return nil, false
			}
			conditions++
		}
		if !validKey(input.StyleKey.value) || conditions == 0 {
			return nil, false
		}
		if _, duplicate := seen[input.StyleKey]; duplicate {
			return nil, false
		}
		seen[input.StyleKey] = struct{}{}
		result[index] = columnStyleRule{
			styleKey: input.StyleKey, state: input.State,
			minimumPercentage: cloneFloat64(input.MinimumPercentage),
			maximumRemaining:  cloneDuration(input.MaximumRemaining),
		}
	}
	return result, true
}

func canonicalKeys(inputs []Key, maximum int) ([]Key, bool) {
	if len(inputs) > maximum {
		return nil, false
	}
	result := slices.Clone(inputs)
	for _, key := range result {
		if !validKey(key.value) {
			return nil, false
		}
	}
	slices.SortFunc(result, func(left, right Key) int {
		if left.value < right.value {
			return -1
		}
		if left.value > right.value {
			return 1
		}
		return 0
	})
	for index := 1; index < len(result); index++ {
		if result[index-1] == result[index] {
			return nil, false
		}
	}
	return result, true
}

func intersectsKeys(left, right []Key) bool {
	leftIndex, rightIndex := 0, 0
	for leftIndex < len(left) && rightIndex < len(right) {
		if left[leftIndex].value < right[rightIndex].value {
			leftIndex++
		} else if left[leftIndex].value > right[rightIndex].value {
			rightIndex++
		} else {
			return true
		}
	}
	return false
}

func cloneFloat64(value *float64) *float64 {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func cloneDuration(value *time.Duration) *time.Duration {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}
