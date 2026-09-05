package customfields

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

type OptionInput struct {
	ID       EntityID
	Key      Key
	Label    string
	Position uint16
	Archived bool
}

type Option struct {
	id       EntityID
	key      Key
	label    string
	position uint16
	archived bool
}

func (option Option) ID() EntityID     { return option.id }
func (option Option) Key() Key         { return option.key }
func (option Option) Label() string    { return option.label }
func (option Option) Position() uint16 { return option.position }
func (option Option) Archived() bool   { return option.archived }

type Visibility struct {
	Customer bool
	Operator bool
}

type EditPolicy struct {
	CustomerCreate bool
	CustomerUpdate bool
	OperatorCreate bool
	OperatorUpdate bool
}

type Placement struct {
	ShowInCreate bool
	ShowInDetail bool
	ShowInList   bool
	ShowInExport bool
}

type ConstraintsInput struct {
	MinimumLength *uint32
	MaximumLength *uint32
	Minimum       string
	Maximum       string
	Pattern       string
}

type Constraints struct {
	minimumLength *uint32
	maximumLength *uint32
	minimum       string
	maximum       string
	pattern       string
	compiled      *regexp.Regexp
}

func (constraints Constraints) MinimumLength() *uint32 { return cloneUint32(constraints.minimumLength) }
func (constraints Constraints) MaximumLength() *uint32 { return cloneUint32(constraints.maximumLength) }
func (constraints Constraints) Minimum() string        { return constraints.minimum }
func (constraints Constraints) Maximum() string        { return constraints.maximum }
func (constraints Constraints) Pattern() string        { return constraints.pattern }

type DefinitionInput struct {
	ID                    EntityID
	TenantID              EntityID
	ObjectType            ObjectType
	Key                   Key
	Label                 string
	Description           string
	DataType              DataType
	Required              bool
	Nullable              bool
	Default               InputValue
	Constraints           ConstraintsInput
	Options               []OptionInput
	Visibility            Visibility
	EditPolicy            EditPolicy
	Placement             Placement
	RequiredOnTransitions []Key
	Searchable            bool
	Filterable            bool
	Sortable              bool
	AllowStructuredJSON   bool
	Archived              bool
	SchemaVersion         uint64
}

type Definition struct {
	id                    EntityID
	tenantID              EntityID
	objectType            ObjectType
	key                   Key
	label                 string
	description           string
	dataType              DataType
	required              bool
	nullable              bool
	defaultValue          Value
	constraints           Constraints
	options               []Option
	visibility            Visibility
	editPolicy            EditPolicy
	placement             Placement
	requiredOnTransitions []Key
	searchable            bool
	filterable            bool
	sortable              bool
	allowStructuredJSON   bool
	archived              bool
	schemaVersion         uint64
}

func NewDefinition(input DefinitionInput) (Definition, error) {
	constraints, ok := canonicalConstraints(input.DataType, input.Constraints)
	if !ok {
		return Definition{}, ErrInvalidDefinition
	}
	options, ok := canonicalOptions(input.DataType, input.Options)
	if !ok {
		return Definition{}, ErrInvalidDefinition
	}
	transitions, ok := canonicalKeys(input.RequiredOnTransitions, maximumTransitionKeys)
	if !ok || !validEntityID(input.ID) || !validEntityID(input.TenantID) ||
		!validObjectType(input.ObjectType) || !validKey(input.Key.value) ||
		!validText(input.Label, maximumLabelBytes, false, false) ||
		!validText(input.Description, maximumDescriptionBytes, true, true) ||
		!validDataType(input.DataType) || input.SchemaVersion == 0 ||
		input.SchemaVersion >= maximumDefinitionVersion ||
		!validDefinitionCapabilities(input, options) {
		return Definition{}, ErrInvalidDefinition
	}

	definition := Definition{
		id: input.ID, tenantID: input.TenantID, objectType: input.ObjectType, key: input.Key,
		label: input.Label, description: input.Description, dataType: input.DataType,
		required: input.Required, nullable: input.Nullable, constraints: constraints, options: options,
		visibility: input.Visibility, editPolicy: input.EditPolicy, placement: input.Placement,
		requiredOnTransitions: transitions, searchable: input.Searchable, filterable: input.Filterable,
		sortable: input.Sortable, allowStructuredJSON: input.AllowStructuredJSON,
		archived: input.Archived, schemaVersion: input.SchemaVersion,
	}
	defaultValue, fieldError := definition.validateValue(input.Default, false)
	if fieldError != nil || definition.required && defaultValue.Presence() == PresenceNull {
		return Definition{}, ErrInvalidDefinition
	}
	definition.defaultValue = defaultValue
	return definition, nil
}

func (definition Definition) ID() EntityID              { return definition.id }
func (definition Definition) TenantID() EntityID        { return definition.tenantID }
func (definition Definition) ObjectType() ObjectType    { return definition.objectType }
func (definition Definition) Key() Key                  { return definition.key }
func (definition Definition) Label() string             { return definition.label }
func (definition Definition) Description() string       { return definition.description }
func (definition Definition) DataType() DataType        { return definition.dataType }
func (definition Definition) Required() bool            { return definition.required }
func (definition Definition) Nullable() bool            { return definition.nullable }
func (definition Definition) Default() Value            { return definition.defaultValue.clone() }
func (definition Definition) Constraints() Constraints  { return definition.constraints.clone() }
func (definition Definition) Options() []Option         { return slices.Clone(definition.options) }
func (definition Definition) Visibility() Visibility    { return definition.visibility }
func (definition Definition) EditPolicy() EditPolicy    { return definition.editPolicy }
func (definition Definition) Placement() Placement      { return definition.placement }
func (definition Definition) Searchable() bool          { return definition.searchable }
func (definition Definition) Filterable() bool          { return definition.filterable }
func (definition Definition) Sortable() bool            { return definition.sortable }
func (definition Definition) AllowStructuredJSON() bool { return definition.allowStructuredJSON }
func (definition Definition) Archived() bool            { return definition.archived }
func (definition Definition) SchemaVersion() uint64     { return definition.schemaVersion }
func (definition Definition) RequiredOnTransitions() []Key {
	return slices.Clone(definition.requiredOnTransitions)
}
func (definition Definition) String() string {
	return fmt.Sprintf(
		"customfields.Definition{object:%s,type:%s,required:%t,nullable:%t,archived:%t,schemaVersion:%d,key:[REDACTED],label:[REDACTED],default:[REDACTED]}",
		definition.objectType, definition.dataType, definition.required, definition.nullable,
		definition.archived, definition.schemaVersion,
	)
}
func (definition Definition) GoString() string { return definition.String() }

func (definition Definition) VisibleTo(audience Audience) bool {
	if definition.archived {
		return false
	}
	switch audience {
	case AudienceCustomer:
		return definition.visibility.Customer
	case AudienceOperator, AudienceSystem:
		return definition.visibility.Operator
	default:
		return false
	}
}

func (definition Definition) CanEdit(audience Audience, phase WritePhase) bool {
	if definition.archived || !validAudience(audience) || !validWritePhase(phase) {
		return false
	}
	if audience == AudienceSystem {
		return true
	}
	switch phase {
	case PhaseCreate, PhaseBulkImport:
		return audience == AudienceCustomer && definition.editPolicy.CustomerCreate ||
			audience == AudienceOperator && definition.editPolicy.OperatorCreate
	case PhaseUpdate, PhaseTransition:
		return audience == AudienceCustomer && definition.editPolicy.CustomerUpdate ||
			audience == AudienceOperator && definition.editPolicy.OperatorUpdate
	default:
		return false
	}
}

func (definition Definition) requiredFor(phase WritePhase, transition Key) bool {
	if definition.required && (phase == PhaseCreate || phase == PhaseBulkImport) {
		return true
	}
	return phase == PhaseTransition && slices.Contains(definition.requiredOnTransitions, transition)
}

type MigrationKind string

const (
	MigrationDataType      MigrationKind = "data_type"
	MigrationOptionRemoval MigrationKind = "option_removal"
	MigrationConstraints   MigrationKind = "constraints"
)

type MigrationPin struct {
	ID                EntityID
	TenantID          EntityID
	DefinitionID      EntityID
	Kind              MigrationKind
	FromDataType      DataType
	ToDataType        DataType
	FromSchemaVersion uint64
	ToSchemaVersion   uint64
}

type DefinitionUpdateState struct {
	ExpectedSchemaVersion uint64
	HasStoredValues       bool
	HasStoredNullValues   bool
	HasMissingValues      bool
	HasIncompatibleValues bool
	UsedOptionKeys        []Key
	Migration             *MigrationPin
}

func UpdateDefinition(current Definition, input DefinitionInput, state DefinitionUpdateState) (Definition, error) {
	if state.ExpectedSchemaVersion != current.schemaVersion {
		return Definition{}, ErrDefinitionConflict
	}
	next, err := NewDefinition(input)
	if err != nil || next.id != current.id || next.tenantID != current.tenantID ||
		next.objectType != current.objectType || next.key != current.key ||
		next.schemaVersion != current.schemaVersion+1 {
		return Definition{}, ErrInvalidDefinition
	}

	if next.dataType != current.dataType && state.HasStoredValues &&
		!validMigrationPin(state.Migration, current, next, MigrationDataType) {
		return Definition{}, ErrMigrationRequired
	}
	if next.dataType == current.dataType &&
		(state.HasStoredNullValues && !next.nullable ||
			state.HasMissingValues && next.required || state.HasIncompatibleValues) &&
		!validMigrationPin(state.Migration, current, next, MigrationConstraints) {
		return Definition{}, ErrMigrationRequired
	}
	if state.HasStoredNullValues && !state.HasStoredValues ||
		state.HasIncompatibleValues && !state.HasStoredValues {
		return Definition{}, ErrInvalidDefinition
	}
	used, ok := canonicalKeys(state.UsedOptionKeys, maximumOptions)
	if !ok || !usedOptionsBelongToCurrent(current, used) || !state.HasStoredValues && len(used) != 0 {
		return Definition{}, ErrInvalidDefinition
	}
	if next.dataType == current.dataType && !optionsPreserveIdentity(current.options, next.options) {
		return Definition{}, ErrInvalidDefinition
	}
	if next.dataType == current.dataType && removedUsedOption(current.options, next.options, used) &&
		!validMigrationPin(state.Migration, current, next, MigrationOptionRemoval) {
		return Definition{}, ErrMigrationRequired
	}
	return next, nil
}

func validDefinitionCapabilities(input DefinitionInput, options []Option) bool {
	if !input.Visibility.Customer && !input.Visibility.Operator {
		return false
	}
	if (input.EditPolicy.CustomerCreate || input.EditPolicy.CustomerUpdate) && !input.Visibility.Customer ||
		(input.EditPolicy.OperatorCreate || input.EditPolicy.OperatorUpdate) && !input.Visibility.Operator {
		return false
	}
	if input.DataType == TypeStructuredJSON != input.AllowStructuredJSON {
		return false
	}
	if input.Sortable && !sortableDataType(input.DataType) ||
		input.Searchable && !searchableDataType(input.DataType) ||
		input.Filterable && input.DataType == TypeStructuredJSON {
		return false
	}
	if input.Archived && (input.Placement.ShowInCreate || input.EditPolicy != (EditPolicy{})) {
		return false
	}
	if input.Archived && (input.Required || len(input.RequiredOnTransitions) != 0) {
		return false
	}
	selectType := input.DataType == TypeSingleSelect || input.DataType == TypeMultiSelect
	return selectType == (len(options) > 0)
}

func searchableDataType(value DataType) bool {
	return value == TypeShortText || value == TypeLongText || value == TypeURL ||
		value == TypeEmail || value == TypeIP || value == TypeCIDR
}

func sortableDataType(value DataType) bool {
	return value != TypeLongText && value != TypeMultiSelect && value != TypeStructuredJSON
}

func canonicalOptions(dataType DataType, inputs []OptionInput) ([]Option, bool) {
	if len(inputs) > maximumOptions {
		return nil, false
	}
	result := make([]Option, len(inputs))
	live := 0
	for index, input := range inputs {
		if !validEntityID(input.ID) || !validKey(input.Key.value) ||
			!validText(input.Label, maximumLabelBytes, false, false) {
			return nil, false
		}
		if !input.Archived {
			live++
		}
		result[index] = Option{
			id: input.ID, key: input.Key, label: input.Label,
			position: input.Position, archived: input.Archived,
		}
	}
	slices.SortFunc(result, func(left, right Option) int {
		if left.position < right.position {
			return -1
		}
		if left.position > right.position {
			return 1
		}
		return compareEntityID(left.id, right.id)
	})
	for index := 1; index < len(result); index++ {
		if result[index-1].id == result[index].id || result[index-1].key == result[index].key ||
			result[index-1].position == result[index].position {
			return nil, false
		}
	}
	selectType := dataType == TypeSingleSelect || dataType == TypeMultiSelect
	if selectType && live == 0 {
		return nil, false
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

func canonicalConstraints(dataType DataType, input ConstraintsInput) (Constraints, bool) {
	result := Constraints{
		minimumLength: cloneUint32(input.MinimumLength), maximumLength: cloneUint32(input.MaximumLength),
		minimum: input.Minimum, maximum: input.Maximum, pattern: input.Pattern,
	}
	if result.minimumLength != nil && result.maximumLength != nil && *result.minimumLength > *result.maximumLength {
		return Constraints{}, false
	}
	textType := dataType == TypeShortText || dataType == TypeLongText || dataType == TypeURL || dataType == TypeEmail
	if !textType && (result.minimumLength != nil || result.maximumLength != nil || result.pattern != "") {
		return Constraints{}, false
	}
	if textType {
		maximumLength := maximumTextLength(dataType)
		if result.minimumLength != nil && *result.minimumLength > maximumLength ||
			result.maximumLength != nil && *result.maximumLength > maximumLength {
			return Constraints{}, false
		}
	}
	if result.pattern != "" {
		if !validText(result.pattern, maximumPatternBytes, false, false) {
			return Constraints{}, false
		}
		compiled, err := regexp.Compile(result.pattern)
		if err != nil {
			return Constraints{}, false
		}
		result.compiled = compiled
	}
	numericType := dataType == TypeInteger || dataType == TypeDecimal || dataType == TypeDuration
	if !numericType && (result.minimum != "" || result.maximum != "") {
		return Constraints{}, false
	}
	minimum, minimumOK := canonicalDecimal(result.minimum, true)
	maximum, maximumOK := canonicalDecimal(result.maximum, true)
	if !minimumOK || !maximumOK || minimum != "" && maximum != "" && compareDecimal(minimum, maximum) > 0 {
		return Constraints{}, false
	}
	if (dataType == TypeInteger || dataType == TypeDuration) &&
		(strings.ContainsRune(minimum, '.') || strings.ContainsRune(maximum, '.')) {
		return Constraints{}, false
	}
	result.minimum, result.maximum = minimum, maximum
	return result, true
}

func maximumTextLength(dataType DataType) uint32 {
	switch dataType {
	case TypeShortText:
		return 1_024
	case TypeEmail:
		return 320
	case TypeURL:
		return 8 * 1_024
	case TypeLongText:
		return maximumCanonicalTextBytes
	default:
		return 0
	}
}

func (constraints Constraints) clone() Constraints {
	result := constraints
	result.minimumLength = cloneUint32(constraints.minimumLength)
	result.maximumLength = cloneUint32(constraints.maximumLength)
	return result
}

func cloneUint32(value *uint32) *uint32 {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func removedUsedOption(current, next []Option, used []Key) bool {
	if len(used) == 0 {
		return false
	}
	nextByKey := make(map[Key]Option, len(next))
	for _, option := range next {
		nextByKey[option.key] = option
	}
	for _, usedKey := range used {
		option, exists := nextByKey[usedKey]
		if !exists || option.archived {
			return true
		}
	}
	return false
}

// Options are durable schema identities. Updates may relabel, reorder, or
// archive them, but may not delete an existing option or reuse either its ID or
// key for another identity. Historical values and audit projections rely on
// this one-to-one mapping even when no current row uses the option.
func optionsPreserveIdentity(current, next []Option) bool {
	nextByID := make(map[EntityID]Option, len(next))
	nextByKey := make(map[Key]Option, len(next))
	for _, option := range next {
		nextByID[option.id] = option
		nextByKey[option.key] = option
	}
	for _, option := range current {
		byID, idExists := nextByID[option.id]
		byKey, keyExists := nextByKey[option.key]
		if !idExists || !keyExists || byID.key != option.key || byKey.id != option.id {
			return false
		}
	}
	return true
}

func usedOptionsBelongToCurrent(current Definition, used []Key) bool {
	if len(used) == 0 {
		return true
	}
	if current.dataType != TypeSingleSelect && current.dataType != TypeMultiSelect {
		return false
	}
	known := make(map[Key]struct{}, len(current.options))
	for _, option := range current.options {
		known[option.key] = struct{}{}
	}
	for _, key := range used {
		if _, exists := known[key]; !exists {
			return false
		}
	}
	return true
}

func validMigrationPin(pin *MigrationPin, current, next Definition, kind MigrationKind) bool {
	return pin != nil && validEntityID(pin.ID) && pin.TenantID == current.tenantID &&
		pin.DefinitionID == current.id && pin.Kind == kind &&
		pin.FromDataType == current.dataType && pin.ToDataType == next.dataType &&
		pin.FromSchemaVersion == current.schemaVersion && pin.ToSchemaVersion == next.schemaVersion
}
