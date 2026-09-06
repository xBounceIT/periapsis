package federatedhttp

import (
	"math"
	"testing"
	"time"
)

func TestCanonicalSecondsPreservesCappingWithoutOverflow(t *testing.T) {
	for _, tc := range []struct {
		name, value string
		maximum     time.Duration
		want        time.Duration
	}{
		{"zero", "0", time.Hour, 0},
		{"inside bound", "59", time.Minute, 59 * time.Second},
		{"exact bound", "60", time.Minute, time.Minute},
		{"above bound", "61", time.Minute, time.Minute},
		{"unsigned maximum", "18446744073709551615", time.Hour, time.Hour},
		{"signed maximum", "9223372036854775807", time.Hour, time.Hour},
		{"nanosecond overflow", "9223372037", time.Hour, time.Hour},
		{"zero maximum", "18446744073709551615", 0, 0},
		{"fractional cap", "2", 1500 * time.Millisecond, time.Second},
		{"subsecond cap", "1", time.Nanosecond, 0},
		{"largest duration product", "9223372036", time.Duration(math.MaxInt64), 9223372036 * time.Second},
		{"overflow at largest cap", "18446744073709551615", time.Duration(math.MaxInt64), 9223372036 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseCanonicalSeconds(tc.value, tc.maximum)
			if err != nil || got != tc.want || got < 0 || got > tc.maximum {
				t.Fatalf("duration = %s, error = %v; want %s", got, err, tc.want)
			}
		})
	}
}

func TestCanonicalSecondsRejectsInvalidValuesAndNegativeCaps(t *testing.T) {
	for _, value := range []string{"", "-1", "+1", "01", "1.0", " 1", "1 ", "18446744073709551616"} {
		if got, err := parseCanonicalSeconds(value, time.Hour); err == nil || got != 0 {
			t.Fatal("invalid cache duration was accepted")
		}
	}
	for _, maximum := range []time.Duration{-1, -time.Second, time.Duration(math.MinInt64)} {
		if got, err := parseCanonicalSeconds("18446744073709551615", maximum); err == nil || got != 0 {
			t.Fatal("negative cache cap was accepted")
		}
	}
}
