package contacts

import (
	"errors"
	"testing"
	"time"
)

func TestContactClockNormalizesRuntimePrecisionAndZone(t *testing.T) {
	for _, offset := range []int{0, 7200, -18000} {
		instant := time.Date(2026, 9, 7, 20, 0, 0, 123456789, time.UTC).In(time.FixedZone("runtime", offset))
		service := &Service{clock: func() time.Time { return instant }}
		got, err := service.now()
		if err != nil || got.Location() != time.UTC || !got.Equal(instant.Truncate(time.Microsecond)) {
			t.Fatalf("runtime clock = %v, %v", got, err)
		}
	}
	service := &Service{clock: func() time.Time { return time.Time{} }}
	if _, err := service.now(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("zero clock accepted: %v", err)
	}
}
