package customfields

import (
	"encoding/json"
	"slices"
)

type FieldInput struct {
	Key   Key
	Value InputValue
}

type FieldValue struct {
	definitionID  EntityID
	tenantID      EntityID
	objectType    ObjectType
	key           Key
	schemaVersion uint64
	value         Value
}

func (fieldValue FieldValue) DefinitionID() EntityID { return fieldValue.definitionID }
func (fieldValue FieldValue) TenantID() EntityID     { return fieldValue.tenantID }
func (fieldValue FieldValue) ObjectType() ObjectType { return fieldValue.objectType }
func (fieldValue FieldValue) Key() Key               { return fieldValue.key }
func (fieldValue FieldValue) SchemaVersion() uint64  { return fieldValue.schemaVersion }
func (fieldValue FieldValue) Value() Value           { return fieldValue.value.clone() }

// RestoreFieldValue validates a persisted canonical value against its pinned
// definition before recreating the projection aggregate. Persistence adapters
// must never construct FieldValue by trusting typed database columns alone.
func RestoreFieldValue(definition Definition, canonical json.RawMessage) (FieldValue, error) {
	if !validEntityID(definition.id) || !validEntityID(definition.tenantID) ||
		!validObjectType(definition.objectType) || !validKey(definition.key.value) ||
		definition.schemaVersion == 0 || len(canonical) == 0 {
		return FieldValue{}, ErrInvalidValidationInput
	}
	value, fieldError := definition.validateValue(JSONInputValue(canonical), false)
	if fieldError != nil || value.presence == PresenceMissing || value.dataType != definition.dataType {
		return FieldValue{}, ErrInvalidValidationInput
	}
	return FieldValue{
		definitionID: definition.id, tenantID: definition.tenantID,
		objectType: definition.objectType, key: definition.key,
		schemaVersion: definition.schemaVersion, value: value.clone(),
	}, nil
}

// ValidateSet validates one all-or-nothing Alert or Case custom-field write.
// It returns no values when any field fails, preventing callers from applying a
// partially validated set. Unknown input keys and duplicate definitions fail
// closed with field-specific errors.
func ValidateSet(
	definitions []Definition,
	inputs []FieldInput,
	context ValidationContext,
) ([]FieldValue, []FieldError, error) {
	if len(definitions) > maximumOptions || len(inputs) > maximumOptions ||
		!validEntityID(context.TenantID) || !validObjectType(context.ObjectType) ||
		!validAudience(context.Audience) || !validWritePhase(context.Phase) ||
		(context.Phase == PhaseTransition) != validKey(context.TransitionKey.value) {
		return nil, nil, ErrInvalidValidationInput
	}

	byKey := make(map[Key]Definition, len(definitions))
	byID := make(map[EntityID]struct{}, len(definitions))
	ordered := slices.Clone(definitions)
	for _, definition := range ordered {
		if definition.tenantID != context.TenantID || definition.objectType != context.ObjectType ||
			!validKey(definition.key.value) {
			return nil, nil, ErrInvalidValidationInput
		}
		if _, duplicate := byKey[definition.key]; duplicate {
			return nil, nil, ErrInvalidValidationInput
		}
		if _, duplicate := byID[definition.id]; duplicate {
			return nil, nil, ErrInvalidValidationInput
		}
		byKey[definition.key] = definition
		byID[definition.id] = struct{}{}
	}
	slices.SortFunc(ordered, func(left, right Definition) int {
		return compareKeys(left.key, right.key)
	})

	inputByKey := make(map[Key]InputValue, len(inputs))
	errorsByKey := make([]FieldError, 0)
	for _, input := range inputs {
		if !validKey(input.Key.value) {
			return nil, nil, ErrInvalidValidationInput
		}
		if _, duplicate := inputByKey[input.Key]; duplicate {
			errorsByKey = append(errorsByKey, FieldError{Field: input.Key, Code: "duplicate"})
			continue
		}
		inputByKey[input.Key] = input.Value
		if _, known := byKey[input.Key]; !known {
			errorsByKey = append(errorsByKey, FieldError{Field: input.Key, Code: "unknown"})
		}
	}

	values := make([]FieldValue, 0, len(inputs))
	for _, definition := range ordered {
		input, provided := inputByKey[definition.key]
		if !provided {
			input = MissingInputValue()
		}
		value, fieldError := definition.Validate(input, context)
		if fieldError != nil {
			errorsByKey = append(errorsByKey, *fieldError)
			continue
		}
		if value.presence == PresenceMissing {
			continue
		}
		values = append(values, FieldValue{
			definitionID: definition.id, tenantID: definition.tenantID,
			objectType: definition.objectType, key: definition.key,
			schemaVersion: definition.schemaVersion, value: value.clone(),
		})
	}
	if len(errorsByKey) != 0 {
		slices.SortFunc(errorsByKey, func(left, right FieldError) int {
			if comparison := compareKeys(left.Field, right.Field); comparison != 0 {
				return comparison
			}
			if left.Code < right.Code {
				return -1
			}
			if left.Code > right.Code {
				return 1
			}
			return 0
		})
		return nil, errorsByKey, nil
	}
	return values, nil, nil
}

type BulkFieldError struct {
	Row   uint32
	Field FieldError
}

// ValidateBulk validates every row but never returns a partial accepted batch.
func ValidateBulk(
	definitions []Definition,
	rows [][]FieldInput,
	context ValidationContext,
) ([][]FieldValue, []BulkFieldError, error) {
	if context.Phase != PhaseBulkImport || len(rows) > 10_000 {
		return nil, nil, ErrInvalidValidationInput
	}
	result := make([][]FieldValue, len(rows))
	fieldErrors := make([]BulkFieldError, 0)
	for index, row := range rows {
		values, rowErrors, err := ValidateSet(definitions, row, context)
		if err != nil {
			return nil, nil, err
		}
		if len(rowErrors) != 0 {
			for _, fieldError := range rowErrors {
				fieldErrors = append(fieldErrors, BulkFieldError{Row: uint32(index), Field: fieldError})
			}
			continue
		}
		result[index] = values
	}
	if len(fieldErrors) != 0 {
		return nil, fieldErrors, nil
	}
	return result, nil, nil
}

func compareKeys(left, right Key) int {
	if left.value < right.value {
		return -1
	}
	if left.value > right.value {
		return 1
	}
	return 0
}
