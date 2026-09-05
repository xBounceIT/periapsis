package httpserver

import (
	"encoding/json"
	"errors"
	"math"
	"slices"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/customfields"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	application "github.com/periapsis-im/periapsis/services/api/internal/customfields"
)

func customFieldObjectType(value contract.CustomFieldObjectType) (kernel.ObjectType, error) {
	if !value.Valid() {
		return "", application.ErrInvalidInput
	}
	return kernel.ObjectType(value), nil
}

func customFieldEntityID(value uuid.UUID) (kernel.EntityID, error) {
	id, err := kernel.ParseEntityID(value.String())
	if err != nil {
		return kernel.EntityID{}, application.ErrInvalidInput
	}
	return id, nil
}

func customFieldDefinitionInput(tenantID uuid.UUID, definitionID uuid.UUID, version uint64, archived bool, spec contract.CustomFieldDefinitionSpec) (kernel.DefinitionInput, error) {
	tenant, err := customFieldEntityID(tenantID)
	if err != nil {
		return kernel.DefinitionInput{}, err
	}
	id, err := customFieldEntityID(definitionID)
	if err != nil || !spec.ObjectType.Valid() || !spec.DataType.Valid() || version == 0 {
		return kernel.DefinitionInput{}, application.ErrInvalidInput
	}
	key, err := kernel.NewKey(spec.Key)
	if err != nil {
		return kernel.DefinitionInput{}, application.ErrInvalidInput
	}
	defaultValue := kernel.MissingInputValue()
	if spec.DefaultValue != nil {
		raw, marshalErr := json.Marshal(spec.DefaultValue)
		if marshalErr != nil {
			return kernel.DefinitionInput{}, application.ErrInvalidInput
		}
		defaultValue = kernel.JSONInputValue(raw)
	}
	constraints := kernel.ConstraintsInput{}
	if spec.Constraints != nil {
		constraints.Minimum, constraints.Maximum = dereference(spec.Constraints.Minimum), dereference(spec.Constraints.Maximum)
		constraints.Pattern = dereference(spec.Constraints.Pattern)
		constraints.MinimumLength, err = customFieldUint32(spec.Constraints.MinimumLength)
		if err != nil {
			return kernel.DefinitionInput{}, err
		}
		constraints.MaximumLength, err = customFieldUint32(spec.Constraints.MaximumLength)
		if err != nil {
			return kernel.DefinitionInput{}, err
		}
	}
	options := make([]kernel.OptionInput, 0)
	if spec.Options != nil {
		options = make([]kernel.OptionInput, len(*spec.Options))
		for index, option := range *spec.Options {
			optionID, parseErr := customFieldEntityID(uuid.UUID(option.Id))
			optionKey, keyErr := kernel.NewKey(option.Key)
			if parseErr != nil || keyErr != nil || option.Position < 0 || option.Position > math.MaxUint16 {
				return kernel.DefinitionInput{}, application.ErrInvalidInput
			}
			options[index] = kernel.OptionInput{
				ID: optionID, Key: optionKey, Label: option.Label,
				Position: uint16(option.Position), Archived: option.Archived,
			}
		}
	}
	transitions := make([]kernel.Key, len(spec.RequiredOnTransitions))
	for index, value := range spec.RequiredOnTransitions {
		transitions[index], err = kernel.NewKey(value)
		if err != nil {
			return kernel.DefinitionInput{}, application.ErrInvalidInput
		}
	}
	return kernel.DefinitionInput{
		ID: id, TenantID: tenant, ObjectType: kernel.ObjectType(spec.ObjectType), Key: key,
		Label: spec.Label, Description: spec.Description, DataType: kernel.DataType(spec.DataType),
		Required: spec.Required, Nullable: spec.Nullable, Default: defaultValue,
		Constraints: constraints, Options: options,
		Visibility: kernel.Visibility{Customer: spec.Visibility.Customer, Operator: spec.Visibility.Operator},
		EditPolicy: kernel.EditPolicy{
			CustomerCreate: spec.EditPolicy.CustomerCreate, CustomerUpdate: spec.EditPolicy.CustomerUpdate,
			OperatorCreate: spec.EditPolicy.OperatorCreate, OperatorUpdate: spec.EditPolicy.OperatorUpdate,
		},
		Placement: kernel.Placement{
			ShowInCreate: spec.Placement.ShowInCreate, ShowInDetail: spec.Placement.ShowInDetail,
			ShowInList: spec.Placement.ShowInList, ShowInExport: spec.Placement.ShowInExport,
		},
		RequiredOnTransitions: transitions, Searchable: spec.Searchable, Filterable: spec.Filterable,
		Sortable: spec.Sortable, AllowStructuredJSON: spec.AllowStructuredJson,
		Archived: archived, SchemaVersion: version,
	}, nil
}

func customFieldUint32(value *int) (*uint32, error) {
	if value == nil {
		return nil, nil
	}
	if *value < 0 || uint64(*value) > math.MaxUint32 {
		return nil, application.ErrInvalidInput
	}
	converted := uint32(*value)
	return &converted, nil
}

func customFieldDefinition(value kernel.Definition) (contract.CustomFieldDefinition, error) {
	version := value.SchemaVersion()
	if version == 0 || version > math.MaxInt64 {
		return contract.CustomFieldDefinition{}, application.ErrUnavailable
	}
	spec, err := customFieldDefinitionSpec(value)
	if err != nil {
		return contract.CustomFieldDefinition{}, err
	}
	id, tenantID, err := phase4UUID(value.ID().String(), value.TenantID().String())
	if err != nil {
		return contract.CustomFieldDefinition{}, application.ErrUnavailable
	}
	return contract.CustomFieldDefinition{
		Id: id, TenantId: tenantID, SchemaVersion: int64(version),
		Archived: value.Archived(), Definition: spec,
	}, nil
}

func customFieldDefinitionSpec(value kernel.Definition) (contract.CustomFieldDefinitionSpec, error) {
	constraints := value.Constraints()
	contractConstraints := &contract.CustomFieldConstraints{
		Minimum: optionalString(constraints.Minimum()), Maximum: optionalString(constraints.Maximum()),
		Pattern: optionalString(constraints.Pattern()),
	}
	if minimum := constraints.MinimumLength(); minimum != nil {
		converted := int(*minimum)
		contractConstraints.MinimumLength = &converted
	}
	if maximum := constraints.MaximumLength(); maximum != nil {
		converted := int(*maximum)
		contractConstraints.MaximumLength = &converted
	}
	if *contractConstraints == (contract.CustomFieldConstraints{}) {
		contractConstraints = nil
	}
	options := make([]contract.CustomFieldOption, len(value.Options()))
	for index, option := range value.Options() {
		id, _, err := phase4UUID(option.ID().String(), value.TenantID().String())
		if err != nil {
			return contract.CustomFieldDefinitionSpec{}, application.ErrUnavailable
		}
		options[index] = contract.CustomFieldOption{
			Id: id, Key: option.Key().String(), Label: option.Label(), Position: int(option.Position()), Archived: option.Archived(),
		}
	}
	var contractOptions *[]contract.CustomFieldOption
	if len(options) != 0 {
		contractOptions = &options
	}
	transitions := make([]contract.CustomFieldKey, len(value.RequiredOnTransitions()))
	for index, key := range value.RequiredOnTransitions() {
		transitions[index] = key.String()
	}
	defaultValue, err := customFieldContractValue(value.Default())
	if err != nil {
		return contract.CustomFieldDefinitionSpec{}, err
	}
	visibility, edit, placement := value.Visibility(), value.EditPolicy(), value.Placement()
	return contract.CustomFieldDefinitionSpec{
		ObjectType: contract.CustomFieldObjectType(value.ObjectType()), Key: value.Key().String(),
		Label: value.Label(), Description: value.Description(), DataType: contract.CustomFieldDataType(value.DataType()),
		Required: value.Required(), Nullable: value.Nullable(), DefaultValue: defaultValue,
		Constraints: contractConstraints, Options: contractOptions,
		Visibility: contract.CustomFieldVisibility{Customer: visibility.Customer, Operator: visibility.Operator},
		EditPolicy: contract.CustomFieldEditPolicy{
			CustomerCreate: edit.CustomerCreate, CustomerUpdate: edit.CustomerUpdate,
			OperatorCreate: edit.OperatorCreate, OperatorUpdate: edit.OperatorUpdate,
		},
		Placement: contract.CustomFieldPlacement{
			ShowInCreate: placement.ShowInCreate, ShowInDetail: placement.ShowInDetail,
			ShowInList: placement.ShowInList, ShowInExport: placement.ShowInExport,
		},
		RequiredOnTransitions: transitions, Searchable: value.Searchable(), Filterable: value.Filterable(),
		Sortable: value.Sortable(), AllowStructuredJson: value.AllowStructuredJSON(),
	}, nil
}

func customFieldContractValue(value kernel.Value) (*contract.CustomFieldValue, error) {
	if value.Presence() == kernel.PresenceMissing {
		return nil, nil
	}
	raw := value.CanonicalJSON()
	if len(raw) == 0 {
		return nil, application.ErrUnavailable
	}
	result := new(contract.CustomFieldValue)
	if err := json.Unmarshal(raw, result); err != nil {
		return nil, application.ErrUnavailable
	}
	return result, nil
}

func customFieldProjectedValue(value kernel.FieldValue) (contract.CustomFieldProjectedValue, error) {
	version := value.SchemaVersion()
	if version == 0 || version > math.MaxInt64 {
		return contract.CustomFieldProjectedValue{}, application.ErrUnavailable
	}
	id, _, err := phase4UUID(value.DefinitionID().String(), value.TenantID().String())
	if err != nil {
		return contract.CustomFieldProjectedValue{}, application.ErrUnavailable
	}
	presence := contract.CustomFieldProjectedValuePresenceMissing
	switch value.Value().Presence() {
	case kernel.PresenceNull:
		presence = contract.CustomFieldProjectedValuePresenceNull
	case kernel.PresencePresent:
		presence = contract.CustomFieldProjectedValuePresencePresent
	case kernel.PresenceMissing:
	default:
		return contract.CustomFieldProjectedValue{}, application.ErrUnavailable
	}
	contractValue, err := customFieldContractValue(value.Value())
	if err != nil {
		return contract.CustomFieldProjectedValue{}, err
	}
	return contract.CustomFieldProjectedValue{
		DefinitionId: id, Key: value.Key().String(), SchemaVersion: int64(version),
		Presence: presence, Value: contractValue,
	}, nil
}

func customFieldProjectionValues(values []kernel.FieldValue) ([]contract.CustomFieldProjectedValue, error) {
	result := make([]contract.CustomFieldProjectedValue, len(values))
	for index, value := range values {
		mapped, err := customFieldProjectedValue(value)
		if err != nil {
			return nil, err
		}
		result[index] = mapped
	}
	return result, nil
}

func rawCustomFieldInputs(values contract.CustomFieldValues) ([]application.RawFieldInput, error) {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	result := make([]application.RawFieldInput, 0, len(keys))
	for _, key := range keys {
		value := values[key]
		if value == nil {
			result = append(result, application.RawFieldInput{
				Key: key, RawJSON: []byte("null"), Present: true,
			})
			continue
		}
		raw, err := json.Marshal(value)
		if err != nil {
			return nil, application.ErrInvalidInput
		}
		result = append(result, application.RawFieldInput{Key: key, RawJSON: raw, Present: true})
	}
	return result, nil
}

func phase4UUID(values ...string) (uuid.UUID, uuid.UUID, error) {
	if len(values) != 2 {
		return uuid.Nil, uuid.Nil, errors.New("invalid UUID projection arity")
	}
	first, firstErr := uuid.Parse(values[0])
	second, secondErr := uuid.Parse(values[1])
	if firstErr != nil || secondErr != nil || first == uuid.Nil || second == uuid.Nil {
		return uuid.Nil, uuid.Nil, errors.New("invalid UUID projection")
	}
	return first, second, nil
}

func optionalString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func dereference(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
