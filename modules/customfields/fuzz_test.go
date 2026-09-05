package customfields

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func FuzzDefinitionValueValidation(f *testing.F) {
	for _, seed := range []struct {
		dataType string
		raw      string
	}{
		{string(TypeShortText), `"private-text"`},
		{string(TypeInteger), `42`},
		{string(TypeDecimal), `12.34`},
		{string(TypeDateTime), `"2026-08-25T12:00:00Z"`},
		{string(TypeURL), `"https://example.test/private"`},
		{string(TypeMultiSelect), `["open","closed"]`},
		{string(TypeStructuredJSON), `{"nested":{"value":"private"}}`},
	} {
		f.Add(seed.dataType, seed.raw)
	}
	f.Fuzz(func(t *testing.T, rawType, raw string) {
		dataType := DataType(rawType)
		if !validDataType(dataType) {
			return
		}
		definition, err := NewDefinition(validDefinitionInput(dataType))
		if err != nil {
			t.Fatalf("fixture definition error = %v", err)
		}
		value, fieldError := definition.Validate(
			JSONInputValue(json.RawMessage(raw)), validValidationContext(PhaseUpdate),
		)
		if fieldError != nil {
			return
		}
		if value.Presence() != PresencePresent {
			t.Fatalf("accepted non-present fuzz value: %#v", value)
		}
		if len(raw) >= 8 && strings.Contains(fmt.Sprint(value), raw) {
			t.Fatalf("value formatting leaked raw input %q", raw)
		}
		first := value.CanonicalJSON()
		if len(first) != 0 {
			first[0] ^= 0xff
			if string(first) == string(value.CanonicalJSON()) {
				t.Fatal("CanonicalJSON returned aggregate-owned memory")
			}
		}
	})
}

func FuzzStructuredJSONParserIsBoundedAndDeterministic(f *testing.F) {
	for _, seed := range []string{
		`{}`, `{"a":1,"b":[true,null,"text"]}`, `{"a":1,"a":2}`, `[1,2,3]`, `{"n":1e9}`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		first, firstOK := canonicalJSONObject(json.RawMessage(raw))
		second, secondOK := canonicalJSONObject(json.RawMessage(raw))
		if firstOK != secondOK || string(first) != string(second) {
			t.Fatalf("non-deterministic JSON result: first=(%q,%t), second=(%q,%t)", first, firstOK, second, secondOK)
		}
		if firstOK && (len(first) > maximumJSONBytes || !json.Valid(first)) {
			t.Fatalf("accepted invalid or oversized canonical JSON: %q", first)
		}
	})
}
