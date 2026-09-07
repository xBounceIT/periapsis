package main

import (
	"testing"
	"time"
)

func TestProbeTimeoutAcceptsBoundedDeploymentBudgets(t *testing.T) {
	for _, value := range []string{"2s", "12s", "1m"} {
		got, err := parseProbeTimeout(value)
		want, _ := time.ParseDuration(value)
		if err != nil || got != want {
			t.Fatalf("timeout %q = %v, %v", value, got, err)
		}
	}
	for _, value := range []string{"", "0s", "-1s", "61s", "unbounded"} {
		if _, err := parseProbeTimeout(value); err == nil {
			t.Fatalf("invalid timeout %q accepted", value)
		}
	}
}
