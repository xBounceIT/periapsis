package dfir

import (
	"fmt"
	"testing"
)

func FuzzIndicatorNormalizationNeverLeaksThroughFormatting(f *testing.F) {
	for _, seed := range []struct {
		kind  string
		value string
	}{
		{"domain", "example.test"},
		{"hostname", "workstation-01"},
		{"url", "https://example.test/path?q=secret"},
		{"email", "user@example.test"},
		{"ipv4", "192.0.2.1"},
		{"ipv6", "2001:db8::1"},
		{"sha256", "abababababababababababababababababababababababababababababababab"},
		{"custom", "custom-secret-observable"},
	} {
		f.Add(seed.kind, seed.value)
	}
	f.Fuzz(func(t *testing.T, rawKind, value string) {
		input := validIndicatorInput(IndicatorType(rawKind), value)
		indicator, err := NewIndicator(input)
		if err != nil {
			return
		}
		comparisonInput := validIndicatorInput(indicator.Type(), comparisonObservable(indicator.Type()))
		comparison, comparisonErr := NewIndicator(comparisonInput)
		if comparisonErr != nil {
			t.Fatalf("invalid comparison fixture for %q: %v", indicator.Type(), comparisonErr)
		}
		if got, want := fmt.Sprint(indicator), fmt.Sprint(comparison); got != want {
			t.Fatalf("String output depends on observable: got %q, want %q", got, want)
		}
		if got, want := fmt.Sprintf("%#v", indicator), fmt.Sprintf("%#v", comparison); got != want {
			t.Fatalf("GoString output depends on observable: got %q, want %q", got, want)
		}
	})
}

func comparisonObservable(kind IndicatorType) string {
	switch kind {
	case IndicatorIPv4:
		return "198.51.100.8"
	case IndicatorIPv6:
		return "2001:db8::8"
	case IndicatorDomain:
		return "comparison.example"
	case IndicatorHostname:
		return "comparison-host"
	case IndicatorURL:
		return "https://comparison.example/redacted"
	case IndicatorEmail:
		return "comparison@example.test"
	case IndicatorMD5:
		return "11111111111111111111111111111111"
	case IndicatorSHA1:
		return "2222222222222222222222222222222222222222"
	case IndicatorSHA256:
		return "3333333333333333333333333333333333333333333333333333333333333333"
	case IndicatorSHA512:
		return "44444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444"
	case IndicatorCVE:
		return "CVE-2026-9999"
	default:
		return "comparison-observable"
	}
}
