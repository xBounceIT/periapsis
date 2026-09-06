package main

import (
	"math"
	"testing"

	"github.com/periapsis-im/periapsis/services/worker/internal/config"
)

func TestRuntimeMaximumAttemptsPreservesConfiguredBounds(t *testing.T) {
	for _, tc := range []struct{ sla, event int }{{1, 1}, {10, 10}, {100, 12}} {
		cfg := config.Config{SLAMaximumAttempts: tc.sla, SLAEventMaximumAttempts: tc.event}
		sla, event, err := runtimeMaximumAttempts(cfg)
		if err != nil || int(sla) != tc.sla || int(event) != tc.event {
			t.Fatal("valid maximum attempts changed during conversion")
		}
	}
}

func TestRuntimeMaximumAttemptsRejectsBeforeNarrowing(t *testing.T) {
	for _, tc := range []struct{ sla, event int }{
		{0, 1}, {-1, 1}, {101, 1}, {math.MaxUint16, 1}, {math.MaxUint16 + 1, 1}, {math.MaxUint16 + 2, 1}, {math.MaxInt, 1},
		{1, 0}, {1, -1}, {1, 13}, {1, math.MaxUint16}, {1, math.MaxUint16 + 1}, {1, math.MaxUint16 + 2}, {1, math.MaxInt},
	} {
		cfg := config.Config{SLAMaximumAttempts: tc.sla, SLAEventMaximumAttempts: tc.event}
		sla, event, err := runtimeMaximumAttempts(cfg)
		if err == nil || sla != 0 || event != 0 {
			t.Fatal("out-of-policy attempts must not yield a wrapped runtime value")
		}
	}
}
