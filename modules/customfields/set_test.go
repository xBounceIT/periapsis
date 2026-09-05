package customfields

import (
	"encoding/json"
	"testing"
)

func TestValidateSetIsAllOrNothingFieldSpecificAndDeterministic(t *testing.T) {
	requiredInput := validDefinitionInput(TypeShortText)
	requiredInput.Required = true
	requiredInput.Key = mustKey("required_context")
	requiredInput.ID = fixtureID(30)
	required := mustDefinition(t, requiredInput)

	optionalInput := validDefinitionInput(TypeInteger)
	optionalInput.Key = mustKey("impact_score")
	optionalInput.ID = fixtureID(31)
	optional := mustDefinition(t, optionalInput)

	unknown := mustKey("unknown_field")
	values, fieldErrors, err := ValidateSet(
		[]Definition{required, optional},
		[]FieldInput{
			{Key: optional.Key(), Value: JSONInputValue(json.RawMessage(`"not-an-integer"`))},
			{Key: unknown, Value: JSONInputValue(json.RawMessage(`true`))},
		},
		validValidationContext(PhaseCreate),
	)
	if err != nil {
		t.Fatal(err)
	}
	if values != nil {
		t.Fatal("partial values were returned for an invalid set")
	}
	want := []struct{ key, code string }{
		{"impact_score", "invalid_integer"},
		{"required_context", "required"},
		{"unknown_field", "unknown"},
	}
	if len(fieldErrors) != len(want) {
		t.Fatalf("field errors = %#v", fieldErrors)
	}
	for index, expected := range want {
		if fieldErrors[index].Field.String() != expected.key || fieldErrors[index].Code != expected.code {
			t.Fatalf("field error %d = %#v, want %#v", index, fieldErrors[index], expected)
		}
	}
}

func TestRestoreFieldValueRevalidatesPersistedCanonicalValue(t *testing.T) {
	definition := mustDefinition(t, validDefinitionInput(TypeEmail))
	value, err := RestoreFieldValue(definition, []byte(`"Analyst@example.com"`))
	if err != nil || value.Key() != definition.Key() || string(value.Value().CanonicalJSON()) != `"Analyst@example.com"` {
		t.Fatalf("RestoreFieldValue() = %#v, %v", value, err)
	}
	if _, err := RestoreFieldValue(definition, []byte(`"not an email"`)); err == nil {
		t.Fatal("invalid persisted value was restored")
	}
	if _, err := RestoreFieldValue(Definition{}, []byte(`null`)); err == nil {
		t.Fatal("zero definition was accepted")
	}
}

func TestValidateSetRejectsDuplicateInputAndReturnsCanonicalValues(t *testing.T) {
	textInput := validDefinitionInput(TypeShortText)
	textInput.Key = mustKey("context")
	textInput.ID = fixtureID(40)
	text := mustDefinition(t, textInput)
	integerInput := validDefinitionInput(TypeInteger)
	integerInput.Key = mustKey("score")
	integerInput.ID = fixtureID(41)
	integer := mustDefinition(t, integerInput)

	duplicateInputs := []FieldInput{
		{Key: text.Key(), Value: JSONInputValue(json.RawMessage(`"first"`))},
		{Key: text.Key(), Value: JSONInputValue(json.RawMessage(`"second"`))},
	}
	if values, fieldErrors, err := ValidateSet(
		[]Definition{text}, duplicateInputs, validValidationContext(PhaseUpdate),
	); err != nil || values != nil || len(fieldErrors) != 1 || fieldErrors[0].Code != "duplicate" {
		t.Fatalf("duplicate result values=%#v errors=%#v err=%v", values, fieldErrors, err)
	}

	values, fieldErrors, err := ValidateSet(
		[]Definition{integer, text},
		[]FieldInput{
			{Key: integer.Key(), Value: JSONInputValue(json.RawMessage(`9`))},
			{Key: text.Key(), Value: NullInputValue()},
		},
		validValidationContext(PhaseUpdate),
	)
	if err != nil || len(fieldErrors) != 1 || fieldErrors[0].Code != "null_not_allowed" || values != nil {
		t.Fatalf("explicit null result values=%#v errors=%#v err=%v", values, fieldErrors, err)
	}

	textNullableInput := textInput
	textNullableInput.Nullable = true
	text = mustDefinition(t, textNullableInput)
	values, fieldErrors, err = ValidateSet(
		[]Definition{integer, text},
		[]FieldInput{
			{Key: integer.Key(), Value: JSONInputValue(json.RawMessage(`9`))},
			{Key: text.Key(), Value: NullInputValue()},
		},
		validValidationContext(PhaseUpdate),
	)
	if err != nil || len(fieldErrors) != 0 || len(values) != 2 {
		t.Fatalf("valid set values=%#v errors=%#v err=%v", values, fieldErrors, err)
	}
	if values[0].Key().String() != "context" || values[0].Value().Presence() != PresenceNull ||
		values[1].Key().String() != "score" || string(values[1].Value().CanonicalJSON()) != "9" {
		t.Fatalf("canonical value ordering/content = %#v", values)
	}
}

func TestTransitionRequirementAndBulkRowsFailClosed(t *testing.T) {
	input := validDefinitionInput(TypeShortText)
	input.RequiredOnTransitions = []Key{mustKey("resolve")}
	definition := mustDefinition(t, input)
	transition := validValidationContext(PhaseTransition)
	transition.TransitionKey = mustKey("resolve")
	if _, fieldErrors, err := ValidateSet([]Definition{definition}, nil, transition); err != nil ||
		len(fieldErrors) != 1 || fieldErrors[0].Code != "required" {
		t.Fatalf("transition requirement errors=%#v err=%v", fieldErrors, err)
	}

	bulk := validValidationContext(PhaseBulkImport)
	rows, bulkErrors, err := ValidateBulk(
		[]Definition{definition},
		[][]FieldInput{
			{{Key: definition.Key(), Value: JSONInputValue(json.RawMessage(`"valid"`))}},
			{{Key: definition.Key(), Value: JSONInputValue(json.RawMessage("{"))}},
		},
		bulk,
	)
	if err != nil || rows != nil || len(bulkErrors) != 1 || bulkErrors[0].Row != 1 {
		t.Fatalf("bulk result rows=%#v errors=%#v err=%v", rows, bulkErrors, err)
	}
}

func TestHiddenOrArchivedFieldsCannotBlockOrDefaultCustomerWrites(t *testing.T) {
	hiddenInput := validDefinitionInput(TypeShortText)
	hiddenInput.ID = fixtureID(70)
	hiddenInput.Key = mustKey("operator_required")
	hiddenInput.Required = true
	hiddenInput.Visibility.Customer = false
	hiddenInput.EditPolicy.CustomerCreate = false
	hiddenInput.EditPolicy.CustomerUpdate = false
	hidden := mustDefinition(t, hiddenInput)

	archivedInput := validDefinitionInput(TypeShortText)
	archivedInput.ID = fixtureID(71)
	archivedInput.Key = mustKey("archived_default")
	archivedInput.Default = JSONInputValue(json.RawMessage(`"must-not-reappear"`))
	archivedInput.Archived = true
	archivedInput.Placement.ShowInCreate = false
	archivedInput.EditPolicy = EditPolicy{}
	archived := mustDefinition(t, archivedInput)

	context := validValidationContext(PhaseCreate)
	context.Audience = AudienceCustomer
	values, fieldErrors, err := ValidateSet([]Definition{hidden, archived}, nil, context)
	if err != nil || len(fieldErrors) != 0 || len(values) != 0 {
		t.Fatalf("hidden/archived omission values=%#v errors=%#v err=%v", values, fieldErrors, err)
	}

	if _, fieldErrors, err := ValidateSet(
		[]Definition{hidden},
		[]FieldInput{{Key: hidden.Key(), Value: JSONInputValue(json.RawMessage(`"oracle"`))}},
		context,
	); err != nil || len(fieldErrors) != 1 || fieldErrors[0].Code != "edit_denied" {
		t.Fatalf("hidden explicit input errors=%#v err=%v", fieldErrors, err)
	}
}
