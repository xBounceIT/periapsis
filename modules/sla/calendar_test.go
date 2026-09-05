package sla

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestBusinessCalendarSkipsLunchWeekendHolidayAndUsesTenantTimezone(t *testing.T) {
	input := weekdayCalendarInput()
	input.Exceptions = []DateExceptionInput{{Date: "2026-08-31", Closed: true}}
	calendar := mustCalendar(t, input)

	// Friday 16:00 CEST. One business hour remains Friday; Monday is a holiday,
	// so the second hour ends Tuesday at 10:00 CEST.
	start := time.Date(2026, 8, 28, 14, 0, 0, 0, time.UTC)
	due, err := calendar.AddBusinessTime(start, 2*time.Hour)
	want := time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)
	if err != nil || !due.Equal(want) {
		t.Fatalf("AddBusinessTime() = %s, %v; want %s", due, err, want)
	}

	// Tuesday 11:30 CEST plus two business hours crosses the lunch closure.
	start = time.Date(2026, 8, 25, 9, 30, 0, 0, time.UTC)
	due, err = calendar.AddBusinessTime(start, 2*time.Hour)
	want = time.Date(2026, 8, 25, 12, 30, 0, 0, time.UTC)
	if err != nil || !due.Equal(want) {
		t.Fatalf("lunch AddBusinessTime() = %s, %v; want %s", due, err, want)
	}
	elapsed, err := calendar.BusinessElapsed(start, want)
	if err != nil || elapsed != 2*time.Hour {
		t.Fatalf("BusinessElapsed() = %s, %v; want 2h", elapsed, err)
	}
	if !calendar.IsBusinessTime(start) || calendar.IsBusinessTime(time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC)) {
		t.Fatal("business-time membership ignored the lunch interval boundary")
	}
}

func TestBusinessCalendarHandlesSpringForwardAndFallBack(t *testing.T) {
	calendar := mustCalendar(t, allDayCalendarInput("Europe/Rome"))
	tests := []struct {
		name  string
		start time.Time
		end   time.Time
		want  time.Duration
	}{
		{
			name:  "spring forward is 23 actual hours",
			start: time.Date(2026, 3, 28, 23, 0, 0, 0, time.UTC),
			end:   time.Date(2026, 3, 29, 22, 0, 0, 0, time.UTC),
			want:  23 * time.Hour,
		},
		{
			name:  "fall back is 25 actual hours",
			start: time.Date(2026, 10, 24, 22, 0, 0, 0, time.UTC),
			end:   time.Date(2026, 10, 25, 23, 0, 0, 0, time.UTC),
			want:  25 * time.Hour,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			elapsed, err := calendar.BusinessElapsed(test.start, test.end)
			if err != nil || elapsed != test.want {
				t.Fatalf("BusinessElapsed() = %s, %v; want %s", elapsed, err, test.want)
			}
			due, err := calendar.AddBusinessTime(test.start, test.want)
			if err != nil || !due.Equal(test.end) {
				t.Fatalf("AddBusinessTime() = %s, %v; want %s", due, err, test.end)
			}
		})
	}
}

func TestBusinessCalendarResolvesNonexistentAndRepeatedWallIntervals(t *testing.T) {
	input := allDayCalendarInput("Europe/Rome")
	input.WeeklySchedules = []WeeklyScheduleInput{{
		Weekday:   time.Sunday,
		Intervals: []MinuteIntervalInput{{StartMinute: 90, EndMinute: 210}}, // 01:30-03:30
	}}
	calendar := mustCalendar(t, input)

	springStart := time.Date(2026, 3, 29, 0, 30, 0, 0, time.UTC)
	springEnd := time.Date(2026, 3, 29, 1, 30, 0, 0, time.UTC)
	elapsed, err := calendar.BusinessElapsed(springStart, springEnd)
	if err != nil || elapsed != time.Hour {
		t.Fatalf("spring gap elapsed = %s, %v; want 1h", elapsed, err)
	}

	fallStart := time.Date(2026, 10, 24, 23, 30, 0, 0, time.UTC)
	fallEnd := time.Date(2026, 10, 25, 2, 30, 0, 0, time.UTC)
	elapsed, err = calendar.BusinessElapsed(fallStart, fallEnd)
	if err != nil || elapsed != 3*time.Hour {
		t.Fatalf("fall overlap elapsed = %s, %v; want 3h", elapsed, err)
	}
}

func TestBusinessCalendarUnionsAdjacentIntervalsAcrossFallBack(t *testing.T) {
	input := allDayCalendarInput("Europe/Rome")
	input.WeeklySchedules = []WeeklyScheduleInput{{
		Weekday: time.Sunday,
		Intervals: []MinuteIntervalInput{
			{StartMinute: 90, EndMinute: 120},
			{StartMinute: 120, EndMinute: 210},
		},
	}}
	calendar := mustCalendar(t, input)
	date := civilDate{year: 2026, month: time.October, day: 25}
	intervals, err := calendar.utcIntervals(date)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 10, 24, 23, 30, 0, 0, time.UTC)
	end := time.Date(2026, 10, 25, 2, 30, 0, 0, time.UTC)
	if len(intervals) != 1 || !intervals[0].start.Equal(start) || !intervals[0].end.Equal(end) {
		t.Fatalf("canonical UTC intervals = %#v; want [%s,%s)", intervals, start, end)
	}
	elapsed, err := calendar.BusinessElapsed(start, end)
	if err != nil || elapsed != 3*time.Hour {
		t.Fatalf("fall-back elapsed = %s, %v; want 3h", elapsed, err)
	}
	due, err := calendar.AddBusinessTime(start, elapsed)
	if err != nil || !due.Equal(end) {
		t.Fatalf("fall-back inverse due = %s, %v; want %s", due, err, end)
	}
}

func TestBusinessCalendarReplacementExceptionOverridesWeeklySchedule(t *testing.T) {
	input := weekdayCalendarInput()
	input.Exceptions = []DateExceptionInput{{
		Date: "2026-08-25", Intervals: []MinuteIntervalInput{{StartMinute: 18 * 60, EndMinute: 20 * 60}},
	}}
	calendar := mustCalendar(t, input)
	ordinaryMorning := time.Date(2026, 8, 25, 8, 0, 0, 0, time.UTC)
	exceptionEvening := time.Date(2026, 8, 25, 17, 0, 0, 0, time.UTC)
	if calendar.IsBusinessTime(ordinaryMorning) || !calendar.IsBusinessTime(exceptionEvening) {
		t.Fatal("replacement exception was merged with, rather than replacing, the weekly schedule")
	}
}

func TestBusinessCalendarRejectsAmbiguousOrUnsafeConfiguration(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*BusinessCalendarInput)
	}{
		{"abbreviation timezone", func(input *BusinessCalendarInput) { input.Timezone = "CET" }},
		{"unknown timezone", func(input *BusinessCalendarInput) { input.Timezone = "Europe/Unknown" }},
		{"duplicate weekday", func(input *BusinessCalendarInput) {
			input.WeeklySchedules = append(input.WeeklySchedules, input.WeeklySchedules[0])
		}},
		{"overlap", func(input *BusinessCalendarInput) {
			input.WeeklySchedules[0].Intervals = []MinuteIntervalInput{{StartMinute: 60, EndMinute: 180}, {StartMinute: 120, EndMinute: 240}}
		}},
		{"overnight", func(input *BusinessCalendarInput) {
			input.WeeklySchedules[0].Intervals = []MinuteIntervalInput{{StartMinute: 1_200, EndMinute: 60}}
		}},
		{"closed with intervals", func(input *BusinessCalendarInput) {
			input.Exceptions = []DateExceptionInput{{Date: "2026-08-25", Closed: true, Intervals: []MinuteIntervalInput{{StartMinute: 60, EndMinute: 120}}}}
		}},
		{"duplicate exception", func(input *BusinessCalendarInput) {
			input.Exceptions = []DateExceptionInput{{Date: "2026-08-25", Closed: true}, {Date: "2026-08-25", Closed: true}}
		}},
		{"directional label", func(input *BusinessCalendarInput) { input.Label = "Support\u202E" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := weekdayCalendarInput()
			test.mutate(&input)
			if _, err := NewBusinessCalendar(input); !errors.Is(err, ErrInvalidCalendar) {
				t.Fatalf("NewBusinessCalendar() error = %v", err)
			}
		})
	}
}

func TestBusinessCalendarOwnsScheduleAndRedactsFormatting(t *testing.T) {
	input := weekdayCalendarInput()
	calendar := mustCalendar(t, input)
	input.WeeklySchedules[1].Intervals[0].EndMinute = input.WeeklySchedules[1].Intervals[0].StartMinute
	instant := time.Date(2026, 8, 24, 8, 0, 0, 0, time.UTC)
	if !calendar.IsBusinessTime(instant) {
		t.Fatal("calendar retained caller-owned weekly schedule")
	}
	for _, rendered := range []string{fmt.Sprint(calendar), fmt.Sprintf("%#v", calendar)} {
		for _, sensitive := range []string{calendar.Key().String(), calendar.Label()} {
			if strings.Contains(rendered, sensitive) {
				t.Fatalf("calendar formatting leaked %q: %q", sensitive, rendered)
			}
		}
	}
}

func TestBusinessCalendarMaximumSupportedDurationIsBounded(t *testing.T) {
	calendar := mustCalendar(t, allDayCalendarInput("UTC"))
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	duration := 100 * 365 * 24 * time.Hour
	wallStarted := time.Now()
	due, err := calendar.AddBusinessTime(start, duration)
	if err != nil || !due.Equal(start.Add(duration)) {
		t.Fatalf("maximum duration due=%s error=%v", due, err)
	}
	if elapsed := time.Since(wallStarted); elapsed > 10*time.Second {
		t.Fatalf("maximum duration calendar evaluation was not bounded: %s", elapsed)
	}
}

func TestBusinessCalendarRejectsAComputedInstantBeyondTheSupportedRange(t *testing.T) {
	calendar := mustCalendar(t, allDayCalendarInput("UTC"))
	start := time.Date(9999, 12, 31, 23, 59, 59, 999999000, time.UTC)
	if _, err := calendar.AddBusinessTime(start, time.Microsecond); !errors.Is(err, ErrCalendarRange) {
		t.Fatalf("year-10000 business instant error=%v", err)
	}
}

func weekdayCalendarInput() BusinessCalendarInput {
	weekly := make([]WeeklyScheduleInput, 0, 5)
	for weekday := time.Monday; weekday <= time.Friday; weekday++ {
		weekly = append(weekly, WeeklyScheduleInput{
			Weekday: weekday,
			Intervals: []MinuteIntervalInput{
				{StartMinute: 9 * 60, EndMinute: 12 * 60},
				{StartMinute: 13 * 60, EndMinute: 17 * 60},
			},
		})
	}
	return BusinessCalendarInput{
		ID: fixtureID(10), TenantID: fixtureID(1), Key: mustKey("business_hours"),
		Label: "Business hours", Timezone: "Europe/Rome", Version: 1, WeeklySchedules: weekly,
	}
}

func allDayCalendarInput(timezone string) BusinessCalendarInput {
	weekly := make([]WeeklyScheduleInput, 0, 7)
	for weekday := time.Sunday; weekday <= time.Saturday; weekday++ {
		weekly = append(weekly, WeeklyScheduleInput{
			Weekday: weekday, Intervals: []MinuteIntervalInput{{StartMinute: 0, EndMinute: 1_440}},
		})
	}
	return BusinessCalendarInput{
		ID: fixtureID(11), TenantID: fixtureID(1), Key: mustKey("always"),
		Label: "Always open", Timezone: timezone, Version: 1, WeeklySchedules: weekly,
	}
}

func mustCalendar(t *testing.T, input BusinessCalendarInput) BusinessCalendar {
	t.Helper()
	calendar, err := NewBusinessCalendar(input)
	if err != nil {
		t.Fatal(err)
	}
	return calendar
}

func mustKey(value string) Key {
	key, err := NewKey(value)
	if err != nil {
		panic(err)
	}
	return key
}

func fixtureID(sequence uint16) EntityID {
	value := [16]byte{0x01, 0x9d, 0x00, 0x00, 0x00, byte(sequence >> 8), 0x70, byte(sequence)}
	value[8] = 0x80
	id, err := NewEntityID(value)
	if err != nil {
		panic(err)
	}
	return id
}
