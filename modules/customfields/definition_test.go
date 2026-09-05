package customfields

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestDefinitionValidatesEverySupportedTypeCanonically(t *testing.T) {
	reference := fixtureID(90).String()
	tests := []struct {
		dataType DataType
		raw      string
		want     string
	}{
		{TypeShortText, `"hello"`, `"hello"`},
		{TypeLongText, `"line one\nline two"`, `"line one\nline two"`},
		{TypeInteger, `42`, `42`},
		{TypeDecimal, `12.3400`, `12.34`},
		{TypeBoolean, `true`, `true`},
		{TypeDate, `"2026-08-25"`, `"2026-08-25"`},
		{TypeDateTime, `"2026-08-25T14:00:00.123+02:00"`, `"2026-08-25T12:00:00.123Z"`},
		{TypeDuration, `90000`, `90000`},
		{TypeSingleSelect, `"open"`, `"open"`},
		{TypeMultiSelect, `["open","closed"]`, `["closed","open"]`},
		{TypeURL, `"https://Example.COM:443/private?q=1"`, `"https://example.com/private?q=1"`},
		{TypeEmail, `"Analyst@EXAMPLE.COM"`, `"Analyst@example.com"`},
		{TypeIP, `"2001:0db8::1"`, `"2001:db8::1"`},
		{TypeCIDR, `"192.0.2.99/24"`, `"192.0.2.0/24"`},
		{TypeUser, fmt.Sprintf(`%q`, reference), fmt.Sprintf(`%q`, reference)},
		{TypeOperatorTeam, fmt.Sprintf(`%q`, reference), fmt.Sprintf(`%q`, reference)},
		{TypeCustomerContact, fmt.Sprintf(`%q`, reference), fmt.Sprintf(`%q`, reference)},
		{TypeAssetReference, fmt.Sprintf(`%q`, reference), fmt.Sprintf(`%q`, reference)},
		{TypeIOCReference, fmt.Sprintf(`%q`, reference), fmt.Sprintf(`%q`, reference)},
		{TypeStructuredJSON, `{"b":1.00,"a":true}`, `{"a":true,"b":1}`},
	}
	for _, test := range tests {
		t.Run(string(test.dataType), func(t *testing.T) {
			definition := mustDefinition(t, validDefinitionInput(test.dataType))
			value, fieldError := definition.Validate(
				JSONInputValue(json.RawMessage(test.raw)),
				validValidationContext(PhaseUpdate),
			)
			if fieldError != nil {
				t.Fatalf("Validate() error = %v", fieldError)
			}
			if got := string(value.CanonicalJSON()); got != test.want {
				t.Fatalf("CanonicalJSON() = %s, want %s", got, test.want)
			}
		})
	}
}

func TestDefinitionDistinguishesMissingNullAndEmpty(t *testing.T) {
	input := validDefinitionInput(TypeShortText)
	input.Required = true
	definition := mustDefinition(t, input)
	create := validValidationContext(PhaseCreate)

	if _, fieldError := definition.Validate(MissingInputValue(), create); fieldError == nil || fieldError.Code != "required" {
		t.Fatalf("missing required value error = %v", fieldError)
	}
	if _, fieldError := definition.Validate(NullInputValue(), create); fieldError == nil || fieldError.Code != "required" {
		t.Fatalf("null required value error = %v", fieldError)
	}
	if _, fieldError := definition.Validate(JSONInputValue(json.RawMessage(`""`)), create); fieldError == nil || fieldError.Code != "empty_not_allowed" {
		t.Fatalf("empty required value error = %v", fieldError)
	}

	update := validValidationContext(PhaseUpdate)
	missing, fieldError := definition.Validate(MissingInputValue(), update)
	if fieldError != nil || missing.Presence() != PresenceMissing {
		t.Fatalf("update missing result = %#v, error=%v", missing, fieldError)
	}

	nullableInput := validDefinitionInput(TypeShortText)
	nullableInput.Nullable = true
	nullable := mustDefinition(t, nullableInput)
	null, fieldError := nullable.Validate(NullInputValue(), update)
	if fieldError != nil || null.Presence() != PresenceNull || string(null.CanonicalJSON()) != "null" {
		t.Fatalf("explicit null result = %#v, error=%v", null, fieldError)
	}
	empty, fieldError := nullable.Validate(JSONInputValue(json.RawMessage(`""`)), update)
	if fieldError != nil || empty.Presence() != PresencePresent || string(empty.CanonicalJSON()) != `""` {
		t.Fatalf("explicit empty result = %#v, error=%v", empty, fieldError)
	}
}

func TestDefinitionAppliesDefaultOnlyDuringCreationAndBulkImport(t *testing.T) {
	input := validDefinitionInput(TypeInteger)
	input.Required = true
	input.Default = JSONInputValue(json.RawMessage("7"))
	definition := mustDefinition(t, input)
	for _, phase := range []WritePhase{PhaseCreate, PhaseBulkImport} {
		value, fieldError := definition.Validate(MissingInputValue(), validValidationContext(phase))
		if fieldError != nil || string(value.CanonicalJSON()) != "7" {
			t.Fatalf("phase %q default result = %s, error=%v", phase, value.CanonicalJSON(), fieldError)
		}
	}
	value, fieldError := definition.Validate(MissingInputValue(), validValidationContext(PhaseUpdate))
	if fieldError != nil || value.Presence() != PresenceMissing {
		t.Fatalf("update unexpectedly applied default: %#v, error=%v", value, fieldError)
	}
}

func TestDefinitionRejectsMalformedOrUnsafeValues(t *testing.T) {
	tests := []struct {
		dataType DataType
		raw      string
	}{
		{TypeShortText, `"invoice\u202Efdp.exe"`},
		{TypeInteger, `1.0`},
		{TypeDecimal, `1e3`},
		{TypeBoolean, `"true"`},
		{TypeDate, `"2026-02-30"`},
		{TypeDateTime, `"2026-08-25T12:00:00.000000001Z"`},
		{TypeDuration, `-1`},
		{TypeSingleSelect, `"archived"`},
		{TypeMultiSelect, `["open","open"]`},
		{TypeURL, `"https://user:secret@example.test/"`},
		{TypeEmail, `"Analyst <analyst@example.test>"`},
		{TypeIP, `"::ffff:192.0.2.1"`},
		{TypeCIDR, `"192.0.2.1/33"`},
		{TypeUser, fmt.Sprintf(`%q`, strings.ToUpper(fixtureID(90).String()))},
		{TypeStructuredJSON, `{"duplicate":1,"duplicate":2}`},
		{TypeStructuredJSON, `[]`},
	}
	for _, test := range tests {
		t.Run(string(test.dataType)+"_"+test.raw, func(t *testing.T) {
			definition := mustDefinition(t, validDefinitionInput(test.dataType))
			if _, fieldError := definition.Validate(
				JSONInputValue(json.RawMessage(test.raw)), validValidationContext(PhaseUpdate),
			); fieldError == nil {
				t.Fatal("unsafe value was accepted")
			}
		})
	}
}

func TestDefinitionConstraintsAndPermissionAreEnforced(t *testing.T) {
	minimum, maximum := uint32(3), uint32(8)
	input := validDefinitionInput(TypeShortText)
	input.Constraints = ConstraintsInput{
		MinimumLength: &minimum, MaximumLength: &maximum, Pattern: `^[a-z]+$`,
	}
	input.EditPolicy.CustomerUpdate = false
	definition := mustDefinition(t, input)
	customer := validValidationContext(PhaseUpdate)
	customer.Audience = AudienceCustomer
	if _, fieldError := definition.Validate(JSONInputValue(json.RawMessage(`"valid"`)), customer); fieldError == nil || fieldError.Code != "edit_denied" {
		t.Fatalf("customer edit error = %v", fieldError)
	}
	for _, raw := range []string{`"ab"`, `"too-long-value"`, `"Bad"`} {
		if _, fieldError := definition.Validate(JSONInputValue(json.RawMessage(raw)), validValidationContext(PhaseUpdate)); fieldError == nil {
			t.Fatalf("constraint-violating value %s was accepted", raw)
		}
	}
}

func TestDefinitionUpdateRequiresPinnedMigrationForDestructiveChanges(t *testing.T) {
	current := mustDefinition(t, validDefinitionInput(TypeSingleSelect))
	nextInput := validDefinitionInput(TypeSingleSelect)
	nextInput.SchemaVersion = 2
	nextInput.Options[1].Archived = true
	used := []Key{mustKey("closed")}
	state := DefinitionUpdateState{ExpectedSchemaVersion: 1, HasStoredValues: true, UsedOptionKeys: used}
	if _, err := UpdateDefinition(current, nextInput, state); !errors.Is(err, ErrMigrationRequired) {
		t.Fatalf("option removal error = %v, want migration required", err)
	}
	state.Migration = &MigrationPin{
		ID: fixtureID(80), TenantID: current.TenantID(), DefinitionID: current.ID(),
		Kind: MigrationOptionRemoval, FromDataType: TypeSingleSelect, ToDataType: TypeSingleSelect,
		FromSchemaVersion: 1, ToSchemaVersion: 2,
	}
	if _, err := UpdateDefinition(current, nextInput, state); err != nil {
		t.Fatalf("pinned option migration error = %v", err)
	}

	typeInput := validDefinitionInput(TypeShortText)
	typeInput.ID, typeInput.TenantID, typeInput.ObjectType, typeInput.Key =
		current.ID(), current.TenantID(), current.ObjectType(), current.Key()
	typeInput.SchemaVersion = 2
	state.UsedOptionKeys = nil
	state.Migration = nil
	if _, err := UpdateDefinition(current, typeInput, state); !errors.Is(err, ErrMigrationRequired) {
		t.Fatalf("type change error = %v, want migration required", err)
	}
	state.Migration = &MigrationPin{
		ID: fixtureID(81), TenantID: current.TenantID(), DefinitionID: current.ID(),
		Kind: MigrationDataType, FromDataType: TypeSingleSelect, ToDataType: TypeShortText,
		FromSchemaVersion: 1, ToSchemaVersion: 2,
	}
	if _, err := UpdateDefinition(current, typeInput, state); err != nil {
		t.Fatalf("pinned type migration error = %v", err)
	}

	identitySwap := validDefinitionInput(TypeSingleSelect)
	identitySwap.SchemaVersion = 2
	identitySwap.Options[0].ID = fixtureID(88)
	state.UsedOptionKeys = used
	state.Migration = &MigrationPin{
		ID: fixtureID(82), TenantID: current.TenantID(), DefinitionID: current.ID(),
		Kind: MigrationOptionRemoval, FromDataType: TypeSingleSelect, ToDataType: TypeSingleSelect,
		FromSchemaVersion: 1, ToSchemaVersion: 2,
	}
	if _, err := UpdateDefinition(current, identitySwap, state); !errors.Is(err, ErrInvalidDefinition) {
		t.Fatalf("option identity replacement error = %v, want invalid definition", err)
	}

	constrainedInput := validDefinitionInput(TypeShortText)
	constrained := mustDefinition(t, constrainedInput)
	constrainedInput.SchemaVersion = 2
	maximum := uint32(4)
	constrainedInput.Constraints.MaximumLength = &maximum
	constraintState := DefinitionUpdateState{
		ExpectedSchemaVersion: 1, HasStoredValues: true, HasIncompatibleValues: true,
	}
	if _, err := UpdateDefinition(constrained, constrainedInput, constraintState); !errors.Is(err, ErrMigrationRequired) {
		t.Fatalf("constraint tightening error = %v, want migration required", err)
	}
	constraintState.Migration = &MigrationPin{
		ID: fixtureID(83), TenantID: constrained.TenantID(), DefinitionID: constrained.ID(),
		Kind: MigrationConstraints, FromDataType: TypeShortText, ToDataType: TypeShortText,
		FromSchemaVersion: 1, ToSchemaVersion: 2,
	}
	if _, err := UpdateDefinition(constrained, constrainedInput, constraintState); err != nil {
		t.Fatalf("pinned constraint migration error = %v", err)
	}

	state.ExpectedSchemaVersion = 0
	typeInput.ID = EntityID{}
	if _, err := UpdateDefinition(current, typeInput, state); !errors.Is(err, ErrDefinitionConflict) {
		t.Fatalf("stale malformed update error = %v, want conflict", err)
	}
}

func TestDefinitionRejectsUnreachableTextAndFractionalIntegerConstraints(t *testing.T) {
	tooLarge := uint32(maximumCanonicalTextBytes + 1)
	text := validDefinitionInput(TypeShortText)
	text.Constraints.MaximumLength = &tooLarge
	if _, err := NewDefinition(text); !errors.Is(err, ErrInvalidDefinition) {
		t.Fatalf("unreachable text constraint error = %v", err)
	}

	integer := validDefinitionInput(TypeInteger)
	integer.Constraints.Minimum = "1.5"
	if _, err := NewDefinition(integer); !errors.Is(err, ErrInvalidDefinition) {
		t.Fatalf("fractional integer constraint error = %v", err)
	}
}

func TestDefinitionOwnsInputsAndRedactsFormatting(t *testing.T) {
	raw := json.RawMessage(`"private-default"`)
	input := validDefinitionInput(TypeShortText)
	input.Default = JSONInputValue(raw)
	minimum := uint32(3)
	input.Constraints.MinimumLength = &minimum
	definition := mustDefinition(t, input)
	raw[1] = 'X'
	minimum = 99
	if got := string(definition.Default().CanonicalJSON()); got != `"private-default"` {
		t.Fatalf("default retained caller memory: %s", got)
	}
	if got := *definition.Constraints().MinimumLength(); got != 3 {
		t.Fatalf("constraint retained caller pointer: %d", got)
	}
	for _, rendered := range []string{fmt.Sprint(definition), fmt.Sprintf("%#v", definition), fmt.Sprint(definition.Default())} {
		for _, sensitive := range []string{input.Key.String(), input.Label, "private-default"} {
			if strings.Contains(rendered, sensitive) {
				t.Fatalf("formatting leaked %q: %q", sensitive, rendered)
			}
		}
	}
}

func TestLayoutIsTenantAudienceBoundOrderedAndImmutable(t *testing.T) {
	first := mustDefinition(t, validDefinitionInput(TypeShortText))
	secondInput := validDefinitionInput(TypeInteger)
	secondInput.ID = fixtureID(11)
	secondInput.Key = mustKey("impact_score")
	second := mustDefinition(t, secondInput)
	ids := []EntityID{second.ID(), first.ID()}
	layout, err := NewLayout(LayoutInput{
		ID: fixtureID(70), TenantID: first.TenantID(), ObjectType: ObjectAlert,
		Audience: AudienceOperator, SchemaVersion: 1,
		Sections: []LayoutSectionInput{
			{Key: mustKey("secondary"), Label: "Secondary", Position: 2, DefinitionIDs: []EntityID{first.ID()}},
			{Key: mustKey("primary"), Label: "Primary", Position: 1, DefinitionIDs: ids[:1]},
		},
	}, []Definition{first, second})
	if err != nil {
		t.Fatal(err)
	}
	ids[0] = fixtureID(99)
	sections := layout.Sections()
	if sections[0].Key() != mustKey("primary") || !reflect.DeepEqual(sections[0].DefinitionIDs(), []EntityID{second.ID()}) {
		t.Fatal("layout ordering or ownership drifted")
	}
	sections[0].definitionIDs[0] = fixtureID(99)
	if layout.Sections()[0].DefinitionIDs()[0] != second.ID() {
		t.Fatal("layout getter leaked mutable storage")
	}

	if _, err := NewLayout(LayoutInput{
		ID: fixtureID(71), TenantID: first.TenantID(), ObjectType: ObjectAlert,
		Audience: AudienceOperator, SchemaVersion: 1,
		Sections: []LayoutSectionInput{{
			Key: mustKey("duplicate"), Label: "Duplicate", DefinitionIDs: []EntityID{first.ID(), first.ID()},
		}},
	}, []Definition{first}); !errors.Is(err, ErrInvalidLayout) {
		t.Fatalf("duplicate layout field error = %v", err)
	}
}

func validDefinitionInput(dataType DataType) DefinitionInput {
	input := DefinitionInput{
		ID: fixtureID(10), TenantID: fixtureID(1), ObjectType: ObjectAlert,
		Key: mustKey("incident_context"), Label: "Incident context", Description: "Tenant configured field",
		DataType: dataType, Visibility: Visibility{Customer: true, Operator: true},
		EditPolicy: EditPolicy{CustomerCreate: true, CustomerUpdate: true, OperatorCreate: true, OperatorUpdate: true},
		Placement:  Placement{ShowInCreate: true, ShowInDetail: true, ShowInList: true, ShowInExport: true},
		Filterable: dataType != TypeStructuredJSON, Sortable: sortableDataType(dataType), SchemaVersion: 1,
	}
	if dataType == TypeSingleSelect || dataType == TypeMultiSelect {
		input.Options = []OptionInput{
			{ID: fixtureID(20), Key: mustKey("open"), Label: "Open", Position: 1},
			{ID: fixtureID(21), Key: mustKey("closed"), Label: "Closed", Position: 2},
			{ID: fixtureID(22), Key: mustKey("archived"), Label: "Archived", Position: 3, Archived: true},
		}
	}
	if dataType == TypeStructuredJSON {
		input.AllowStructuredJSON = true
		input.Filterable = false
	}
	return input
}

func validValidationContext(phase WritePhase) ValidationContext {
	return ValidationContext{
		TenantID: fixtureID(1), ObjectType: ObjectAlert, Audience: AudienceOperator, Phase: phase,
	}
}

func mustDefinition(t *testing.T, input DefinitionInput) Definition {
	t.Helper()
	definition, err := NewDefinition(input)
	if err != nil {
		t.Fatal(err)
	}
	return definition
}

func mustKey(value string) Key {
	key, err := NewKey(value)
	if err != nil {
		panic(err)
	}
	return key
}

func fixtureID(sequence uint16) EntityID {
	value := [16]byte{0x01, 0x9d, 0x00, 0x00, 0x00, byte(sequence >> 8), 0x70, byte(sequence)}
	value[8] = 0x80
	id, err := NewEntityID(value)
	if err != nil {
		panic(err)
	}
	return id
}
