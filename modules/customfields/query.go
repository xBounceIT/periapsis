package customfields

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
)

type ProjectionSurface string

const (
	SurfaceDetail ProjectionSurface = "detail"
	SurfaceList   ProjectionSurface = "list"
	SurfaceExport ProjectionSurface = "export"
)

func validProjectionSurface(value ProjectionSurface) bool {
	return value == SurfaceDetail || value == SurfaceList || value == SurfaceExport
}

// ProjectValues produces a visibility-safe projection. A stored value pinned to
// an unknown definition or schema version fails the whole projection instead of
// being exposed with stale permissions.
func ProjectValues(
	definitions []Definition,
	values []FieldValue,
	tenantID EntityID,
	objectType ObjectType,
	audience Audience,
	surface ProjectionSurface,
) ([]FieldValue, error) {
	if !validEntityID(tenantID) || !validObjectType(objectType) || !validAudience(audience) ||
		audience == AudienceSystem || !validProjectionSurface(surface) ||
		len(definitions) > maximumOptions || len(values) > maximumOptions {
		return nil, ErrInvalidValidationInput
	}
	byID := make(map[EntityID]Definition, len(definitions))
	byKey := make(map[Key]struct{}, len(definitions))
	for _, definition := range definitions {
		if definition.tenantID != tenantID || definition.objectType != objectType {
			return nil, ErrInvalidValidationInput
		}
		if _, duplicate := byID[definition.id]; duplicate {
			return nil, ErrInvalidValidationInput
		}
		if _, duplicate := byKey[definition.key]; duplicate {
			return nil, ErrInvalidValidationInput
		}
		byID[definition.id] = definition
		byKey[definition.key] = struct{}{}
	}
	seen := make(map[EntityID]struct{}, len(values))
	result := make([]FieldValue, 0, len(values))
	for _, value := range values {
		definition, exists := byID[value.definitionID]
		if !exists || value.tenantID != tenantID || value.objectType != objectType ||
			value.key != definition.key || value.schemaVersion != definition.schemaVersion ||
			value.value.dataType != definition.dataType || value.value.presence == PresenceMissing {
			return nil, ErrInvalidValidationInput
		}
		if _, duplicate := seen[value.definitionID]; duplicate {
			return nil, ErrInvalidValidationInput
		}
		seen[value.definitionID] = struct{}{}
		if !definition.VisibleOn(audience, surface) {
			continue
		}
		result = append(result, FieldValue{
			definitionID: value.definitionID, tenantID: value.tenantID,
			objectType: value.objectType, key: value.key,
			schemaVersion: value.schemaVersion, value: value.value.clone(),
		})
	}
	slices.SortFunc(result, func(left, right FieldValue) int {
		return compareKeys(left.key, right.key)
	})
	return result, nil
}

func (definition Definition) shownOn(surface ProjectionSurface) bool {
	switch surface {
	case SurfaceDetail:
		return definition.placement.ShowInDetail
	case SurfaceList:
		return definition.placement.ShowInList
	case SurfaceExport:
		return definition.placement.ShowInExport
	default:
		return false
	}
}

// VisibleOn applies both audience visibility and placement policy. Callers
// projecting field metadata must use the same decision as value projection so
// a definition hidden from a surface cannot leak through form metadata.
func (definition Definition) VisibleOn(audience Audience, surface ProjectionSurface) bool {
	return validAudience(audience) && audience != AudienceSystem &&
		validProjectionSurface(surface) && definition.VisibleTo(audience) &&
		definition.shownOn(surface)
}

type FilterOperator string

const (
	FilterEqual          FilterOperator = "eq"
	FilterNotEqual       FilterOperator = "neq"
	FilterLessThan       FilterOperator = "lt"
	FilterLessOrEqual    FilterOperator = "lte"
	FilterGreaterThan    FilterOperator = "gt"
	FilterGreaterOrEqual FilterOperator = "gte"
	FilterContains       FilterOperator = "contains"
	FilterStartsWith     FilterOperator = "starts_with"
	FilterIsNull         FilterOperator = "is_null"
	FilterIsMissing      FilterOperator = "is_missing"
)

type FilterInput struct {
	Key      Key
	Operator FilterOperator
	Value    InputValue
}

func (input FilterInput) String() string {
	return "customfields.FilterInput{metadata:[REDACTED],value:[REDACTED]}"
}

func (input FilterInput) GoString() string { return input.String() }

type FilterPlan struct {
	definitionID EntityID
	tenantID     EntityID
	objectType   ObjectType
	key          Key
	dataType     DataType
	operator     FilterOperator
	value        Value
}

// FilterPlanSnapshot is the minimum immutable persistence projection for one
// already-authorized equality filter. Restoring it validates the exact typed
// canonical value, but deliberately does not grant visibility or filtering
// authority: callers must still resolve and compare the live definition before
// executing the plan.
type FilterPlanSnapshot struct {
	DefinitionID EntityID
	TenantID     EntityID
	ObjectType   ObjectType
	Key          Key
	DataType     DataType
	Operator     FilterOperator
	Canonical    json.RawMessage
}

func (snapshot FilterPlanSnapshot) String() string {
	return "customfields.FilterPlanSnapshot{metadata:[REDACTED],value:[REDACTED]}"
}

func (snapshot FilterPlanSnapshot) GoString() string { return snapshot.String() }

func (plan FilterPlan) DefinitionID() EntityID   { return plan.definitionID }
func (plan FilterPlan) TenantID() EntityID       { return plan.tenantID }
func (plan FilterPlan) ObjectType() ObjectType   { return plan.objectType }
func (plan FilterPlan) Key() Key                 { return plan.key }
func (plan FilterPlan) DataType() DataType       { return plan.dataType }
func (plan FilterPlan) Operator() FilterOperator { return plan.operator }
func (plan FilterPlan) Value() Value             { return plan.value.clone() }
func (plan FilterPlan) String() string {
	return fmt.Sprintf(
		"customfields.FilterPlan{object:%s,type:%s,operator:%s,key:[REDACTED],value:[REDACTED]}",
		plan.objectType, plan.dataType, plan.operator,
	)
}

func (plan FilterPlan) GoString() string { return plan.String() }

// RestoreEqualityFilterPlan reconstructs a persisted scalar equality filter
// without trusting its JSON representation. Canonical byte equality is
// required so alternate number, time, URL, network, email, or UUID spellings
// cannot silently change the saved query digest. Live definition policy and
// option membership are rechecked separately when the filter is executed.
func RestoreEqualityFilterPlan(snapshot FilterPlanSnapshot) (FilterPlan, error) {
	if !validEntityID(snapshot.DefinitionID) || !validEntityID(snapshot.TenantID) ||
		!validObjectType(snapshot.ObjectType) || !validKey(snapshot.Key.value) ||
		snapshot.Operator != FilterEqual || !restorableScalarFilterType(snapshot.DataType) ||
		len(snapshot.Canonical) == 0 || len(snapshot.Canonical) > maximumJSONBytes {
		return FilterPlan{}, ErrInvalidValidationInput
	}

	var value Value
	if snapshot.DataType == TypeSingleSelect {
		text, ok := decodeJSONString(snapshot.Canonical)
		key, err := NewKey(text)
		if !ok || err != nil {
			return FilterPlan{}, ErrInvalidValidationInput
		}
		value = Value{
			presence:  PresencePresent,
			dataType:  snapshot.DataType,
			canonical: mustMarshal(text),
			keys:      []Key{key},
		}
	} else {
		definition := Definition{dataType: snapshot.DataType}
		var code string
		value, code = definition.canonicalPresentValue(snapshot.Canonical)
		if code != "" {
			return FilterPlan{}, ErrInvalidValidationInput
		}
	}
	if value.presence != PresencePresent || value.dataType != snapshot.DataType ||
		!bytes.Equal(value.canonical, snapshot.Canonical) {
		return FilterPlan{}, ErrInvalidValidationInput
	}
	return FilterPlan{
		definitionID: snapshot.DefinitionID,
		tenantID:     snapshot.TenantID,
		objectType:   snapshot.ObjectType,
		key:          snapshot.Key,
		dataType:     snapshot.DataType,
		operator:     FilterEqual,
		value:        value.clone(),
	}, nil
}

func restorableScalarFilterType(dataType DataType) bool {
	switch dataType {
	case TypeShortText, TypeLongText,
		TypeInteger, TypeDecimal, TypeBoolean,
		TypeDate, TypeDateTime, TypeDuration,
		TypeSingleSelect, TypeURL, TypeEmail,
		TypeIP, TypeCIDR, TypeUser, TypeOperatorTeam,
		TypeCustomerContact, TypeAssetReference, TypeIOCReference:
		return true
	default:
		return false
	}
}

func PlanFilter(
	definition Definition,
	input FilterInput,
	tenantID EntityID,
	objectType ObjectType,
	audience Audience,
	surface ProjectionSurface,
) (FilterPlan, *FieldError) {
	if tenantID != definition.tenantID || objectType != definition.objectType || input.Key != definition.key ||
		!validAudience(audience) || audience == AudienceSystem || !validProjectionSurface(surface) ||
		definition.archived || !definition.filterable || !definition.VisibleOn(audience, surface) {
		fieldError := definition.fieldError("filter_denied")
		return FilterPlan{}, &fieldError
	}
	noValue := input.Operator == FilterIsNull || input.Operator == FilterIsMissing
	if noValue {
		if input.Value.provided {
			fieldError := definition.fieldError("unexpected_filter_value")
			return FilterPlan{}, &fieldError
		}
		return definition.filterPlan(input.Operator, Value{presence: PresenceMissing, dataType: definition.dataType}), nil
	}
	if input.Operator == FilterContains || input.Operator == FilterStartsWith {
		if !definition.searchable || definition.dataType != TypeShortText && definition.dataType != TypeLongText &&
			definition.dataType != TypeURL && definition.dataType != TypeEmail &&
			definition.dataType != TypeIP && definition.dataType != TypeCIDR {
			fieldError := definition.fieldError("unsupported_filter_operator")
			return FilterPlan{}, &fieldError
		}
	} else if input.Operator == FilterLessThan || input.Operator == FilterLessOrEqual ||
		input.Operator == FilterGreaterThan || input.Operator == FilterGreaterOrEqual {
		if !definition.sortable {
			fieldError := definition.fieldError("unsupported_filter_operator")
			return FilterPlan{}, &fieldError
		}
	} else if input.Operator != FilterEqual && input.Operator != FilterNotEqual {
		fieldError := definition.fieldError("unsupported_filter_operator")
		return FilterPlan{}, &fieldError
	}
	value, fieldError := definition.validateValue(input.Value, true)
	if fieldError != nil {
		return FilterPlan{}, fieldError
	}
	return definition.filterPlan(input.Operator, value), nil
}

func (definition Definition) filterPlan(operator FilterOperator, value Value) FilterPlan {
	return FilterPlan{
		definitionID: definition.id, tenantID: definition.tenantID,
		objectType: definition.objectType, key: definition.key,
		dataType: definition.dataType, operator: operator, value: value.clone(),
	}
}
