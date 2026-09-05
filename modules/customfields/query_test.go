package customfields

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestProjectValuesEnforcesVisibilityPlacementAndSchemaPin(t *testing.T) {
	publicInput := validDefinitionInput(TypeShortText)
	publicInput.Key, publicInput.ID = mustKey("public_context"), fixtureID(50)
	public := mustDefinition(t, publicInput)
	privateInput := validDefinitionInput(TypeInteger)
	privateInput.Key, privateInput.ID = mustKey("private_score"), fixtureID(51)
	privateInput.Visibility.Customer = false
	privateInput.EditPolicy.CustomerCreate = false
	privateInput.EditPolicy.CustomerUpdate = false
	private := mustDefinition(t, privateInput)

	operatorValues, fieldErrors, err := ValidateSet(
		[]Definition{private, public},
		[]FieldInput{
			{Key: public.Key(), Value: JSONInputValue(json.RawMessage(`"customer-safe"`))},
			{Key: private.Key(), Value: JSONInputValue(json.RawMessage(`8`))},
		},
		validValidationContext(PhaseUpdate),
	)
	if err != nil || len(fieldErrors) != 0 {
		t.Fatalf("ValidateSet() errors=%#v err=%v", fieldErrors, err)
	}
	projected, err := ProjectValues(
		[]Definition{public, private}, operatorValues, fixtureID(1), ObjectAlert, AudienceCustomer, SurfaceDetail,
	)
	if err != nil || len(projected) != 1 || projected[0].Key() != public.Key() {
		t.Fatalf("customer projection=%#v error=%v", projected, err)
	}

	drifted := operatorValues
	drifted[0].schemaVersion++
	if _, err := ProjectValues(
		[]Definition{public, private}, drifted, fixtureID(1), ObjectAlert, AudienceOperator, SurfaceDetail,
	); !errors.Is(err, ErrInvalidValidationInput) {
		t.Fatalf("schema-drift projection error = %v", err)
	}
}

func TestPlanFilterUsesTypedCanonicalValueAndCapabilities(t *testing.T) {
	input := validDefinitionInput(TypeDecimal)
	input.Filterable = true
	input.Sortable = true
	definition := mustDefinition(t, input)
	plan, fieldError := PlanFilter(definition, FilterInput{
		Key: definition.Key(), Operator: FilterGreaterOrEqual,
		Value: JSONInputValue(json.RawMessage(`10.500`)),
	}, definition.TenantID(), definition.ObjectType(), AudienceOperator, SurfaceDetail)
	if fieldError != nil || string(plan.Value().CanonicalJSON()) != "10.5" || plan.DefinitionID() != definition.ID() {
		t.Fatalf("filter plan=%#v error=%v", plan, fieldError)
	}

	textInput := validDefinitionInput(TypeShortText)
	textInput.Searchable = false
	text := mustDefinition(t, textInput)
	if _, fieldError := PlanFilter(text, FilterInput{
		Key: text.Key(), Operator: FilterContains, Value: JSONInputValue(json.RawMessage(`"needle"`)),
	}, text.TenantID(), text.ObjectType(), AudienceOperator, SurfaceDetail); fieldError == nil || fieldError.Code != "unsupported_filter_operator" {
		t.Fatalf("unsupported contains error = %v", fieldError)
	}
	if _, fieldError := PlanFilter(text, FilterInput{
		Key: text.Key(), Operator: FilterIsMissing, Value: NullInputValue(),
	}, text.TenantID(), text.ObjectType(), AudienceOperator, SurfaceDetail); fieldError == nil || fieldError.Code != "unexpected_filter_value" {
		t.Fatalf("unexpected is_missing value error = %v", fieldError)
	}

	hiddenInput := validDefinitionInput(TypeShortText)
	hiddenInput.Visibility.Customer = false
	hiddenInput.EditPolicy.CustomerCreate = false
	hiddenInput.EditPolicy.CustomerUpdate = false
	hidden := mustDefinition(t, hiddenInput)
	if _, fieldError := PlanFilter(hidden, FilterInput{
		Key: hidden.Key(), Operator: FilterEqual,
		Value: JSONInputValue(json.RawMessage(`"cardinality-oracle"`)),
	}, hidden.TenantID(), hidden.ObjectType(), AudienceCustomer, SurfaceDetail); fieldError == nil || fieldError.Code != "filter_denied" {
		t.Fatalf("hidden customer filter error = %v", fieldError)
	}
}

func TestRestoreEqualityFilterPlanAcceptsOnlyExactScalarCanonicalValues(t *testing.T) {
	tests := []struct {
		name      string
		dataType  DataType
		canonical string
	}{
		{name: "text", dataType: TypeShortText, canonical: `"triage"`},
		{name: "integer", dataType: TypeInteger, canonical: `42`},
		{name: "decimal", dataType: TypeDecimal, canonical: `10.5`},
		{name: "boolean", dataType: TypeBoolean, canonical: `true`},
		{name: "date", dataType: TypeDate, canonical: `"2026-08-26"`},
		{name: "datetime", dataType: TypeDateTime, canonical: `"2026-08-26T10:11:12Z"`},
		{name: "duration", dataType: TypeDuration, canonical: `300`},
		{name: "single select", dataType: TypeSingleSelect, canonical: `"malware"`},
		{name: "url", dataType: TypeURL, canonical: `"https://example.test/case"`},
		{name: "email", dataType: TypeEmail, canonical: `"analyst@example.test"`},
		{name: "ip", dataType: TypeIP, canonical: `"192.0.2.4"`},
		{name: "cidr", dataType: TypeCIDR, canonical: `"192.0.2.0/24"`},
		{name: "reference", dataType: TypeUser, canonical: `"0198f198-ae1f-7b01-8000-000000000099"`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := FilterPlanSnapshot{
				DefinitionID: fixtureID(80), TenantID: fixtureID(1),
				ObjectType: ObjectAlert, Key: mustKey("saved_filter"),
				DataType: test.dataType, Operator: FilterEqual,
				Canonical: json.RawMessage(test.canonical),
			}
			plan, err := RestoreEqualityFilterPlan(snapshot)
			if err != nil || plan.DefinitionID() != snapshot.DefinitionID ||
				plan.TenantID() != snapshot.TenantID || plan.ObjectType() != ObjectAlert ||
				plan.Key() != snapshot.Key || plan.DataType() != test.dataType ||
				string(plan.Value().CanonicalJSON()) != test.canonical {
				t.Fatalf("RestoreEqualityFilterPlan() = %#v, %v", plan, err)
			}
			if rendered := fmt.Sprintf("%#v", snapshot); strings.Contains(rendered, test.canonical) {
				t.Fatalf("FilterPlanSnapshot GoString leaked canonical value: %s", rendered)
			}
			if len(snapshot.Canonical) > 0 {
				snapshot.Canonical[0] ^= 0x01
			}
			projected := plan.Value().CanonicalJSON()
			if len(projected) > 0 {
				projected[0] ^= 0x01
			}
			if string(plan.Value().CanonicalJSON()) != test.canonical {
				t.Fatal("restored filter plan retained caller-owned canonical bytes")
			}
		})
	}

	invalid := []FilterPlanSnapshot{
		{
			DefinitionID: fixtureID(80), TenantID: fixtureID(1), ObjectType: ObjectAlert,
			Key: mustKey("saved_filter"), DataType: TypeDecimal, Operator: FilterEqual,
			Canonical: json.RawMessage(`10.500`),
		},
		{
			DefinitionID: fixtureID(80), TenantID: fixtureID(1), ObjectType: ObjectAlert,
			Key: mustKey("saved_filter"), DataType: TypeIP, Operator: FilterEqual,
			Canonical: json.RawMessage(`"192.000.002.004"`),
		},
		{
			DefinitionID: fixtureID(80), TenantID: fixtureID(1), ObjectType: ObjectAlert,
			Key: mustKey("saved_filter"), DataType: TypeMultiSelect, Operator: FilterEqual,
			Canonical: json.RawMessage(`["one"]`),
		},
		{
			DefinitionID: fixtureID(80), TenantID: fixtureID(1), ObjectType: ObjectAlert,
			Key: mustKey("saved_filter"), DataType: TypeShortText, Operator: FilterNotEqual,
			Canonical: json.RawMessage(`"triage"`),
		},
	}
	for index, snapshot := range invalid {
		if _, err := RestoreEqualityFilterPlan(snapshot); !errors.Is(err, ErrInvalidValidationInput) {
			t.Fatalf("invalid snapshot %d error = %v", index, err)
		}
	}
}

func TestFilterDiagnosticsRedactKeysAndValues(t *testing.T) {
	definitionInput := validDefinitionInput(TypeShortText)
	definitionInput.Key = mustKey("customer_secret")
	definitionInput.Filterable = true
	definition := mustDefinition(t, definitionInput)
	input := FilterInput{
		Key: definition.Key(), Operator: FilterEqual,
		Value: JSONInputValue(json.RawMessage(`"sensitive-search-value"`)),
	}
	plan, fieldError := PlanFilter(
		definition, input, definition.TenantID(), definition.ObjectType(),
		AudienceOperator, SurfaceDetail,
	)
	if fieldError != nil {
		t.Fatal(fieldError)
	}
	for _, rendered := range []string{fmt.Sprintf("%#v", input), fmt.Sprintf("%#v", plan)} {
		for _, secret := range []string{"customer_secret", "sensitive-search-value"} {
			if strings.Contains(rendered, secret) {
				t.Fatalf("filter diagnostic leaked %q: %s", secret, rendered)
			}
		}
	}
	hostile := input
	hostile.Operator = FilterOperator("eq\nforged-log-entry")
	if rendered := fmt.Sprintf("%#v", hostile); strings.Contains(rendered, "forged-log-entry") {
		t.Fatalf("filter diagnostic admitted log-control metadata: %s", rendered)
	}
}
