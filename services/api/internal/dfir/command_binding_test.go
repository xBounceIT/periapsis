package dfir

import (
	"crypto/sha256"
	"errors"
	"math"
	"strings"
	"testing"
)

func TestCommandBindingPreservesExactDigestBytes(t *testing.T) {
	for _, tc := range []struct {
		name      string
		payload   any
		canonical string
	}{
		{"null", nil, "null"},
		{"ordered object", map[string]any{"z": 2, "a": "one"}, `{"a":"one","z":2}`},
		{"unicode and escaping", []string{"é", "<", "\x00"}, `["é","\u003c","\u0000"]`},
		{"large payload", strings.Repeat("x", 1<<20), `"` + strings.Repeat("x", 1<<20) + `"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, operation := range []string{operationIOCCreate, operationIOCCreate + ".other", ""} {
				got, err := commandBinding(operation, "fixture-idempotency-key", tc.payload)
				if err != nil {
					t.Fatal(err)
				}
				want := sha256.Sum256([]byte(operation + "\x00" + tc.canonical))
				if got.Operation != operation || got.RequestDigest != want ||
					got.KeyDigest != sha256.Sum256([]byte("fixture-idempotency-key")) {
					t.Fatal("binding changed the existing operation, key or request fingerprint")
				}
				repeated, err := commandBinding(operation, "different-fixture-key", tc.payload)
				if err != nil || repeated.RequestDigest != got.RequestDigest ||
					repeated.KeyDigest == got.KeyDigest {
					t.Fatal("request digest is not stable and independent of the idempotency key")
				}
			}
		})
	}
}

func TestCommandBindingRejectsUnencodablePayload(t *testing.T) {
	for _, payload := range []any{math.NaN(), make(chan int), func() {}} {
		got, err := commandBinding(operationIOCCreate, "fixture-idempotency-key", payload)
		if !errors.Is(err, ErrInvalidInput) || got != (CommandBinding{}) {
			t.Fatal("unencodable input must fail without a partial binding")
		}
	}
}
