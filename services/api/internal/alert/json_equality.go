package alert

import (
	"bytes"
	"encoding/json"
	"math/big"
	"strings"
)

// PostgreSQL jsonb may change the numeric spelling without changing its value.
// Compare exact decimal coefficients and exponents, never a float64 projection.
func equalJSONMaps(left, right map[string]any) bool {
	decode := func(value map[string]any) (any, bool) {
		encoded, err := json.Marshal(value)
		if err != nil {
			return nil, false
		}
		var result any
		decoder := json.NewDecoder(bytes.NewReader(encoded))
		decoder.UseNumber()
		if decoder.Decode(&result) != nil {
			return nil, false
		}
		return result, true
	}
	l, lok := decode(left)
	r, rok := decode(right)
	return lok && rok && equalJSONValue(l, r)
}

func equalJSONValue(left, right any) bool {
	switch left := left.(type) {
	case map[string]any:
		right, ok := right.(map[string]any)
		if !ok || len(left) != len(right) {
			return false
		}
		for key, value := range left {
			other, exists := right[key]
			if !exists || !equalJSONValue(value, other) {
				return false
			}
		}
		return true
	case []any:
		right, ok := right.([]any)
		if !ok || len(left) != len(right) {
			return false
		}
		for i, value := range left {
			if !equalJSONValue(value, right[i]) {
				return false
			}
		}
		return true
	case json.Number:
		right, ok := right.(json.Number)
		if !ok {
			return false
		}
		lc, le := decimalParts(left)
		rc, re := decimalParts(right)
		return lc == rc && le.Cmp(re) == 0
	default:
		return left == right
	}
}

// The exponent stays symbolic, so even extreme exponents require space only
// proportional to their input length. Inputs have already passed JSON decoding.
func decimalParts(value json.Number) (string, *big.Int) {
	text := strings.ToLower(value.String())
	mantissa, exponent, hasExponent := strings.Cut(text, "e")
	power := new(big.Int)
	if hasExponent {
		power.SetString(exponent, 10)
	}
	negative := strings.HasPrefix(mantissa, "-")
	mantissa = strings.TrimPrefix(mantissa, "-")
	whole, fraction, _ := strings.Cut(mantissa, ".")
	digits := strings.TrimLeft(whole+fraction, "0")
	if digits == "" {
		return "0", new(big.Int)
	}
	coefficient := strings.TrimRight(digits, "0")
	power.Add(power, big.NewInt(int64(len(digits)-len(coefficient)-len(fraction))))
	if negative {
		coefficient = "-" + coefficient
	}
	return coefficient, power
}
