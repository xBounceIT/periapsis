package ticketing

import (
	"encoding/json"
	"time"

	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
)

const maximumExactConditionInteger = int64(1<<53 - 1)

func transitionConditionFacts(record Record, input MutationInput) (kernel.ConditionFacts, error) {
	builder := conditionFactBuilder{seen: make(map[string]struct{}, 128)}
	for _, item := range []struct {
		field string
		value string
	}{
		{field: "aggregate_kind", value: record.Snapshot.Kind().String()},
		{field: "state", value: record.Snapshot.State().String()},
		{field: "severity", value: record.Severity},
		{field: "priority", value: record.Priority},
		{field: "category", value: record.Category},
		{field: "source", value: record.Source},
		{field: "source_type", value: record.SourceType},
	} {
		if item.value != "" {
			if err := builder.addText(item.field, item.value); err != nil {
				return kernel.ConditionFacts{}, err
			}
		}
	}
	if record.Classification != nil {
		if err := builder.addText("classification", *record.Classification); err != nil {
			return kernel.ConditionFacts{}, err
		}
	}
	assignment := record.Snapshot.Assignment()
	_, assigned := assignment.Team()
	_, hasAssignee := assignment.Assignee()
	for _, item := range []struct {
		field string
		value bool
	}{
		{field: "customer_visible", value: record.Snapshot.CustomerVisible()},
		{field: "assigned", value: assigned},
		{field: "assignee_present", value: hasAssignee},
		{field: "claimed", value: assignment.Claimed()},
		{field: "comment_present", value: input.Comment != ""},
	} {
		if err := builder.add(item.field, kernel.NewBooleanConditionValue(item.value)); err != nil {
			return kernel.ConditionFacts{}, err
		}
	}
	for _, item := range []struct {
		field string
		value time.Time
	}{
		{field: "detected_at", value: record.DetectedAt},
		{field: "received_at", value: record.ReceivedAt},
		{field: "opened_at", value: record.OpenedAt},
		{field: "created_at", value: record.CreatedAt},
		{field: "updated_at", value: record.UpdatedAt},
	} {
		if !item.value.IsZero() {
			value, err := kernel.NewInstantConditionValue(item.value)
			if err != nil {
				return kernel.ConditionFacts{}, ErrUnavailable
			}
			if err := builder.add(item.field, value); err != nil {
				return kernel.ConditionFacts{}, err
			}
		}
	}
	for _, tag := range record.Tags {
		field, err := kernel.NewConditionField("tag." + tag)
		if err != nil {
			continue
		}
		if err := builder.addField(field, kernel.NewBooleanConditionValue(true)); err != nil {
			return kernel.ConditionFacts{}, err
		}
	}

	custom := make(map[string]any, len(record.CustomFields)+len(input.CustomFields))
	for key, value := range record.CustomFields {
		custom[key] = value
	}
	for key, value := range input.CustomFields {
		custom[key] = value
	}
	for key, raw := range custom {
		field, err := kernel.NewConditionField("custom." + key)
		if err != nil {
			continue
		}
		value, representable := scalarConditionValue(raw)
		if !representable {
			if err := builder.addPresence(field); err != nil {
				return kernel.ConditionFacts{}, err
			}
			continue
		}
		if err := builder.addField(field, value); err != nil {
			return kernel.ConditionFacts{}, err
		}
	}
	return kernel.NewConditionFacts(builder.facts...)
}

func (builder *conditionFactBuilder) addPresence(field kernel.ConditionField) error {
	if _, duplicate := builder.seen[field.String()]; duplicate {
		return ErrUnavailable
	}
	fact, err := kernel.NewPresenceConditionFact(field)
	if err != nil {
		return ErrUnavailable
	}
	builder.seen[field.String()] = struct{}{}
	builder.facts = append(builder.facts, fact)
	return nil
}

type conditionFactBuilder struct {
	facts []kernel.ConditionFact
	seen  map[string]struct{}
}

func (builder *conditionFactBuilder) addText(field, raw string) error {
	value, err := kernel.NewTextConditionValue(raw)
	if err != nil {
		return ErrUnavailable
	}
	return builder.add(field, value)
}

func (builder *conditionFactBuilder) add(field string, value kernel.ConditionValue) error {
	parsed, err := kernel.NewConditionField(field)
	if err != nil {
		return ErrUnavailable
	}
	return builder.addField(parsed, value)
}

func (builder *conditionFactBuilder) addField(field kernel.ConditionField, value kernel.ConditionValue) error {
	if _, duplicate := builder.seen[field.String()]; duplicate {
		return ErrUnavailable
	}
	fact, err := kernel.NewConditionFact(field, value)
	if err != nil {
		return ErrUnavailable
	}
	builder.seen[field.String()] = struct{}{}
	builder.facts = append(builder.facts, fact)
	return nil
}

func scalarConditionValue(raw any) (kernel.ConditionValue, bool) {
	switch value := raw.(type) {
	case string:
		result, err := kernel.NewTextConditionValue(value)
		return result, err == nil
	case bool:
		return kernel.NewBooleanConditionValue(value), true
	case json.Number:
		number, err := value.Float64()
		if err != nil {
			return kernel.ConditionValue{}, false
		}
		result, err := kernel.NewNumberConditionValue(number)
		return result, err == nil
	case float32:
		result, err := kernel.NewNumberConditionValue(float64(value))
		return result, err == nil
	case float64:
		result, err := kernel.NewNumberConditionValue(value)
		return result, err == nil
	case int:
		return exactIntegerConditionValue(int64(value))
	case int8:
		return exactIntegerConditionValue(int64(value))
	case int16:
		return exactIntegerConditionValue(int64(value))
	case int32:
		return exactIntegerConditionValue(int64(value))
	case int64:
		return exactIntegerConditionValue(value)
	case uint:
		return exactUnsignedConditionValue(uint64(value))
	case uint8:
		return exactUnsignedConditionValue(uint64(value))
	case uint16:
		return exactUnsignedConditionValue(uint64(value))
	case uint32:
		return exactUnsignedConditionValue(uint64(value))
	case uint64:
		return exactUnsignedConditionValue(value)
	case time.Time:
		result, err := kernel.NewInstantConditionValue(value)
		return result, err == nil
	default:
		return kernel.ConditionValue{}, false
	}
}

func exactIntegerConditionValue(value int64) (kernel.ConditionValue, bool) {
	if value < -maximumExactConditionInteger || value > maximumExactConditionInteger {
		return kernel.ConditionValue{}, false
	}
	result, err := kernel.NewNumberConditionValue(float64(value))
	return result, err == nil
}

func exactUnsignedConditionValue(value uint64) (kernel.ConditionValue, bool) {
	if value > uint64(maximumExactConditionInteger) {
		return kernel.ConditionValue{}, false
	}
	result, err := kernel.NewNumberConditionValue(float64(value))
	return result, err == nil
}
