package alert

import (
	"encoding/json"
	"testing"
)

func TestAlertJSONComparisonPreservesExactNumbers(t *testing.T) {
	for _, test := range []struct {
		name        string
		left, right any
		equal       bool
	}{
		{"database number", json.Number("1"), float64(1), true},
		{"exponent", json.Number("1e2"), json.Number("100.00"), true},
		{"fraction", json.Number("0.00100"), json.Number("1e-3"), true},
		{"negative", json.Number("-10.0"), json.Number("-1e1"), true},
		{"signed zero", json.Number("-0e1000000000"), json.Number("0"), true},
		{"large integer", json.Number("9007199254740993"), json.Number("9007199254740992"), false},
		{"huge exponent", json.Number("1e1000000000"), json.Number("10e999999999"), true},
		{"different fraction", json.Number("0.001"), json.Number("0.01"), false},
		{"type mismatch", json.Number("1"), "1", false},
		{"array order", []any{1, 2}, []any{2, 1}, false},
		{"nested", []any{map[string]any{"n": json.Number("1.0")}}, []any{map[string]any{"n": 1}}, true},
		{"missing versus null", map[string]any{"n": nil}, map[string]any{}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := equalJSONMaps(map[string]any{"value": test.left}, map[string]any{"value": test.right}); got != test.equal {
				t.Fatalf("equalJSONMaps()=%t, want %t", got, test.equal)
			}
		})
	}
}
