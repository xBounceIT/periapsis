package sla

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"
	_ "time/tzdata"
)

type MinuteIntervalInput struct {
	StartMinute uint16
	EndMinute   uint16
}

type WeeklyScheduleInput struct {
	Weekday   time.Weekday
	Intervals []MinuteIntervalInput
}

type DateExceptionInput struct {
	Date      string
	Closed    bool
	Intervals []MinuteIntervalInput
}

type BusinessCalendarInput struct {
	ID              EntityID
	TenantID        EntityID
	Key             Key
	Label           string
	Timezone        string
	Version         uint64
	WeeklySchedules []WeeklyScheduleInput
	Exceptions      []DateExceptionInput
}

type minuteInterval struct {
	start uint16
	end   uint16
}

type civilDate struct {
	year  int
	month time.Month
	day   int
}

type dateException struct {
	date      civilDate
	closed    bool
	intervals []minuteInterval
}

type BusinessCalendar struct {
	id         EntityID
	tenantID   EntityID
	key        Key
	label      string
	timezone   string
	location   *time.Location
	version    uint64
	weekly     [7][]minuteInterval
	exceptions []dateException
}

func NewBusinessCalendar(input BusinessCalendarInput) (BusinessCalendar, error) {
	location, err := loadIANALocation(input.Timezone)
	if err != nil || !validEntityID(input.ID) || !validEntityID(input.TenantID) ||
		!validKey(input.Key.value) || !validText(input.Label, maximumLabelBytes, false, false) ||
		input.Version == 0 || input.Version >= maximumVersion || len(input.WeeklySchedules) > 7 ||
		len(input.Exceptions) > maximumCalendarDays {
		return BusinessCalendar{}, ErrInvalidCalendar
	}
	calendar := BusinessCalendar{
		id: input.ID, tenantID: input.TenantID, key: input.Key, label: input.Label,
		timezone: input.Timezone, location: location, version: input.Version,
	}
	seenWeekdays := [7]bool{}
	weeklyOpenIntervals := 0
	for _, schedule := range input.WeeklySchedules {
		if schedule.Weekday < time.Sunday || schedule.Weekday > time.Saturday || seenWeekdays[schedule.Weekday] {
			return BusinessCalendar{}, ErrInvalidCalendar
		}
		intervals, ok := canonicalMinuteIntervals(schedule.Intervals)
		if !ok {
			return BusinessCalendar{}, ErrInvalidCalendar
		}
		seenWeekdays[schedule.Weekday] = true
		calendar.weekly[schedule.Weekday] = intervals
		weeklyOpenIntervals += len(intervals)
	}
	if weeklyOpenIntervals == 0 {
		return BusinessCalendar{}, ErrInvalidCalendar
	}
	calendar.exceptions = make([]dateException, len(input.Exceptions))
	for index, source := range input.Exceptions {
		date, ok := parseCivilDate(source.Date)
		if !ok || source.Closed == (len(source.Intervals) != 0) {
			return BusinessCalendar{}, ErrInvalidCalendar
		}
		intervals, intervalsOK := canonicalMinuteIntervals(source.Intervals)
		if !intervalsOK {
			return BusinessCalendar{}, ErrInvalidCalendar
		}
		calendar.exceptions[index] = dateException{date: date, closed: source.Closed, intervals: intervals}
	}
	slices.SortFunc(calendar.exceptions, func(left, right dateException) int {
		return compareCivilDate(left.date, right.date)
	})
	for index := 1; index < len(calendar.exceptions); index++ {
		if calendar.exceptions[index-1].date == calendar.exceptions[index].date {
			return BusinessCalendar{}, ErrInvalidCalendar
		}
	}
	return calendar, nil
}

func (calendar BusinessCalendar) ID() EntityID       { return calendar.id }
func (calendar BusinessCalendar) TenantID() EntityID { return calendar.tenantID }
func (calendar BusinessCalendar) Key() Key           { return calendar.key }
func (calendar BusinessCalendar) Label() string      { return calendar.label }
func (calendar BusinessCalendar) Timezone() string   { return calendar.timezone }
func (calendar BusinessCalendar) Version() uint64    { return calendar.version }
func (calendar BusinessCalendar) String() string {
	return fmt.Sprintf(
		"sla.BusinessCalendar{timezone:%s,version:%d,key:[REDACTED],label:[REDACTED],exceptions:%d}",
		calendar.timezone, calendar.version, len(calendar.exceptions),
	)
}
func (calendar BusinessCalendar) GoString() string { return calendar.String() }

func (calendar BusinessCalendar) AddBusinessTime(start time.Time, duration time.Duration) (time.Time, error) {
	return calendar.AddBusinessTimeContext(context.Background(), start, duration)
}

// AddBusinessTimeContext is AddBusinessTime with cooperative cancellation at
// every civil-day boundary. This prevents a corrupted long-range projection
// from monopolizing an engine or worker deadline.
func (calendar BusinessCalendar) AddBusinessTimeContext(
	ctx context.Context,
	start time.Time,
	duration time.Duration,
) (time.Time, error) {
	if ctx == nil || ctx.Err() != nil {
		return time.Time{}, ErrEngineCanceled
	}
	if !calendar.valid() || !validInstant(start) || duration < 0 || duration%time.Microsecond != 0 {
		return time.Time{}, ErrInvalidCalendar
	}
	if duration == 0 {
		return start, nil
	}
	cursor := start
	remaining := duration
	date := civilDateAt(start, calendar.location)
	for days := 0; days < maximumCalendarDays; days++ {
		if ctx.Err() != nil {
			return time.Time{}, ErrEngineCanceled
		}
		intervals, err := calendar.utcIntervals(date)
		if err != nil {
			return time.Time{}, err
		}
		for _, interval := range intervals {
			if !interval.end.After(cursor) {
				continue
			}
			usableStart := interval.start
			if cursor.After(usableStart) {
				usableStart = cursor
			}
			available := interval.end.Sub(usableStart)
			if remaining <= available {
				result := usableStart.Add(remaining)
				if !validInstant(result) {
					return time.Time{}, ErrCalendarRange
				}
				return result, nil
			}
			remaining -= available
			cursor = interval.end
		}
		date = date.next()
		next, ok := calendar.resolveBoundary(date, 0, true)
		if !ok {
			return time.Time{}, ErrCalendarRange
		}
		cursor = next
	}
	return time.Time{}, ErrCalendarRange
}

func (calendar BusinessCalendar) BusinessElapsed(start, end time.Time) (time.Duration, error) {
	return calendar.BusinessElapsedContext(context.Background(), start, end)
}

// BusinessElapsedContext is BusinessElapsed with bounded cooperative
// cancellation for long historical projections.
func (calendar BusinessCalendar) BusinessElapsedContext(
	ctx context.Context,
	start time.Time,
	end time.Time,
) (time.Duration, error) {
	if ctx == nil || ctx.Err() != nil {
		return 0, ErrEngineCanceled
	}
	if !calendar.valid() || !validInstant(start) || !validInstant(end) || end.Before(start) {
		return 0, ErrInvalidCalendar
	}
	if start.Equal(end) {
		return 0, nil
	}
	date := civilDateAt(start, calendar.location)
	lastDate := civilDateAt(end, calendar.location)
	var elapsed time.Duration
	for days := 0; days < maximumCalendarDays; days++ {
		if ctx.Err() != nil {
			return 0, ErrEngineCanceled
		}
		intervals, err := calendar.utcIntervals(date)
		if err != nil {
			return 0, err
		}
		for _, interval := range intervals {
			intersectionStart := interval.start
			if start.After(intersectionStart) {
				intersectionStart = start
			}
			intersectionEnd := interval.end
			if end.Before(intersectionEnd) {
				intersectionEnd = end
			}
			if intersectionEnd.After(intersectionStart) {
				elapsed += intersectionEnd.Sub(intersectionStart)
			}
		}
		if compareCivilDate(date, lastDate) >= 0 {
			return elapsed, nil
		}
		date = date.next()
	}
	return 0, ErrCalendarRange
}

func (calendar BusinessCalendar) IsBusinessTime(instant time.Time) bool {
	if !calendar.valid() || !validInstant(instant) {
		return false
	}
	intervals, err := calendar.utcIntervals(civilDateAt(instant, calendar.location))
	if err != nil {
		return false
	}
	for _, interval := range intervals {
		if !instant.Before(interval.start) && instant.Before(interval.end) {
			return true
		}
	}
	return false
}

type utcInterval struct {
	start time.Time
	end   time.Time
}

func (calendar BusinessCalendar) utcIntervals(date civilDate) ([]utcInterval, error) {
	minutes := calendar.intervalsFor(date)
	result := make([]utcInterval, 0, len(minutes))
	for _, interval := range minutes {
		start, startOK := calendar.resolveBoundary(date, interval.start, true)
		end, endOK := calendar.resolveBoundary(date, interval.end, false)
		if !startOK || !endOK {
			return nil, ErrCalendarRange
		}
		if end.After(start) {
			result = append(result, utcInterval{start: start, end: end})
		}
	}
	return canonicalUTCIntervals(result), nil
}

// nextBusinessTimeContext returns the first business instant at or after the
// supplied instant. It lets projections wake at the next opening instead of
// repeatedly polling while a business clock is stopped.
func (calendar BusinessCalendar) nextBusinessTimeContext(
	ctx context.Context,
	at time.Time,
) (time.Time, error) {
	if ctx == nil || ctx.Err() != nil {
		return time.Time{}, ErrEngineCanceled
	}
	if !calendar.valid() || !validInstant(at) {
		return time.Time{}, ErrInvalidCalendar
	}
	cursor := at
	date := civilDateAt(at, calendar.location)
	for days := 0; days < maximumCalendarDays; days++ {
		if ctx.Err() != nil {
			return time.Time{}, ErrEngineCanceled
		}
		intervals, err := calendar.utcIntervals(date)
		if err != nil {
			return time.Time{}, err
		}
		for _, interval := range intervals {
			if cursor.Before(interval.start) {
				if !validInstant(interval.start) {
					return time.Time{}, ErrCalendarRange
				}
				return interval.start, nil
			}
			if cursor.Before(interval.end) {
				return cursor, nil
			}
		}
		date = date.next()
		next, ok := calendar.resolveBoundary(date, 0, true)
		if !ok || !validInstant(next) {
			return time.Time{}, ErrCalendarRange
		}
		cursor = next
	}
	return time.Time{}, ErrCalendarRange
}

func canonicalUTCIntervals(intervals []utcInterval) []utcInterval {
	if len(intervals) < 2 {
		return intervals
	}
	slices.SortFunc(intervals, func(left, right utcInterval) int {
		if comparison := left.start.Compare(right.start); comparison != 0 {
			return comparison
		}
		return left.end.Compare(right.end)
	})
	merged := intervals[:0]
	for _, interval := range intervals {
		if len(merged) == 0 || interval.start.After(merged[len(merged)-1].end) {
			merged = append(merged, interval)
			continue
		}
		if interval.end.After(merged[len(merged)-1].end) {
			merged[len(merged)-1].end = interval.end
		}
	}
	return merged
}

func (calendar BusinessCalendar) intervalsFor(date civilDate) []minuteInterval {
	index, found := slices.BinarySearchFunc(calendar.exceptions, date, func(exception dateException, target civilDate) int {
		return compareCivilDate(exception.date, target)
	})
	if found {
		if calendar.exceptions[index].closed {
			return nil
		}
		return calendar.exceptions[index].intervals
	}
	weekday := time.Date(date.year, date.month, date.day, 12, 0, 0, 0, time.UTC).Weekday()
	return calendar.weekly[weekday]
}

func (calendar BusinessCalendar) resolveBoundary(date civilDate, minute uint16, opening bool) (time.Time, bool) {
	targetDate := date
	targetMinute := int(minute)
	if targetMinute == 1_440 {
		targetDate = date.next()
		targetMinute = 0
	}
	hour := targetMinute / 60
	minuteOfHour := targetMinute % 60
	wallUTC := time.Date(targetDate.year, targetDate.month, targetDate.day, hour, minuteOfHour, 0, 0, time.UTC)
	approximation := time.Date(targetDate.year, targetDate.month, targetDate.day, hour, minuteOfHour, 0, 0, calendar.location).UTC()
	offsets, transitions := calendar.boundaryCandidates(approximation)
	matches := make([]time.Time, 0, len(offsets))
	for _, offset := range offsets {
		candidate := wallUTC.Add(-time.Duration(offset) * time.Second)
		if exactWallBoundary(candidate.In(calendar.location), targetDate, targetMinute) {
			matches = append(matches, candidate)
		}
	}
	slices.SortFunc(matches, func(left, right time.Time) int { return left.Compare(right) })
	if len(matches) != 0 {
		if opening {
			return matches[0], true
		}
		return matches[len(matches)-1], true
	}

	// A nonexistent local wall time is a gap created by an offset transition.
	// Resolve it to the first real instant after the gap. Transition bounds make
	// this work constant-time per boundary rather than scanning every minute of
	// a 36-hour window for every day in a long-lived SLA.
	var firstLater time.Time
	for _, candidate := range transitions {
		if compareWallBoundary(candidate.In(calendar.location), targetDate, targetMinute) <= 0 {
			continue
		}
		before := candidate.Add(-time.Microsecond).In(calendar.location)
		if compareWallBoundary(before, targetDate, targetMinute) >= 0 {
			continue
		}
		if firstLater.IsZero() || candidate.Before(firstLater) {
			firstLater = candidate
		}
	}
	if !firstLater.IsZero() {
		return firstLater, true
	}
	return time.Time{}, false
}

func (calendar BusinessCalendar) boundaryCandidates(approximation time.Time) ([]int, []time.Time) {
	probes := []time.Time{
		approximation.Add(-7 * 24 * time.Hour), approximation.Add(-48 * time.Hour),
		approximation, approximation.Add(48 * time.Hour), approximation.Add(7 * 24 * time.Hour),
	}
	offsetSet := make(map[int]struct{}, 4)
	transitionSet := make(map[int64]time.Time, 4)
	for _, probe := range probes {
		_, offset := probe.In(calendar.location).Zone()
		offsetSet[offset] = struct{}{}
		start, end := probe.In(calendar.location).ZoneBounds()
		for _, boundary := range []time.Time{start, end} {
			if boundary.IsZero() || boundary.Before(approximation.Add(-8*24*time.Hour)) ||
				boundary.After(approximation.Add(8*24*time.Hour)) {
				continue
			}
			boundary = boundary.UTC().Truncate(time.Microsecond)
			transitionSet[boundary.UnixMicro()] = boundary
			for _, adjacent := range []time.Time{boundary.Add(-time.Microsecond), boundary} {
				_, adjacentOffset := adjacent.In(calendar.location).Zone()
				offsetSet[adjacentOffset] = struct{}{}
			}
		}
	}
	offsets := make([]int, 0, len(offsetSet))
	for offset := range offsetSet {
		offsets = append(offsets, offset)
	}
	slices.Sort(offsets)
	transitions := make([]time.Time, 0, len(transitionSet))
	for _, boundary := range transitionSet {
		transitions = append(transitions, boundary)
	}
	slices.SortFunc(transitions, func(left, right time.Time) int { return left.Compare(right) })
	return offsets, transitions
}

func exactWallBoundary(value time.Time, date civilDate, minute int) bool {
	return compareCivilDate(civilDate{year: value.Year(), month: value.Month(), day: value.Day()}, date) == 0 &&
		value.Hour()*60+value.Minute() == minute && value.Second() == 0 && value.Nanosecond() == 0
}

func compareWallBoundary(value time.Time, date civilDate, minute int) int {
	valueDate := civilDate{year: value.Year(), month: value.Month(), day: value.Day()}
	if comparison := compareCivilMinute(valueDate, value.Hour()*60+value.Minute(), date, minute); comparison != 0 {
		return comparison
	}
	if value.Second() != 0 || value.Nanosecond() != 0 {
		return 1
	}
	return 0
}

func (calendar BusinessCalendar) valid() bool {
	return validEntityID(calendar.id) && validEntityID(calendar.tenantID) && validKey(calendar.key.value) &&
		validText(calendar.label, maximumLabelBytes, false, false) && calendar.location != nil &&
		calendar.location.String() == calendar.timezone && calendar.version > 0 && calendar.version < maximumVersion
}

func canonicalMinuteIntervals(inputs []MinuteIntervalInput) ([]minuteInterval, bool) {
	if len(inputs) > 32 {
		return nil, false
	}
	result := make([]minuteInterval, len(inputs))
	for index, input := range inputs {
		if input.StartMinute >= input.EndMinute || input.EndMinute > 1_440 {
			return nil, false
		}
		result[index] = minuteInterval{start: input.StartMinute, end: input.EndMinute}
	}
	slices.SortFunc(result, func(left, right minuteInterval) int {
		if left.start < right.start {
			return -1
		}
		if left.start > right.start {
			return 1
		}
		return 0
	})
	for index := 1; index < len(result); index++ {
		if result[index].start < result[index-1].end {
			return nil, false
		}
	}
	return result, true
}

func loadIANALocation(name string) (*time.Location, error) {
	if !validText(name, 128, false, false) || name != "UTC" && !strings.Contains(name, "/") {
		return nil, ErrInvalidCalendar
	}
	location, err := time.LoadLocation(name)
	if err != nil || location.String() != name {
		return nil, ErrInvalidCalendar
	}
	return location, nil
}

func parseCivilDate(value string) (civilDate, bool) {
	parsed, err := time.Parse("2006-01-02", value)
	if err != nil || parsed.Format("2006-01-02") != value {
		return civilDate{}, false
	}
	return civilDate{year: parsed.Year(), month: parsed.Month(), day: parsed.Day()}, true
}

func civilDateAt(value time.Time, location *time.Location) civilDate {
	local := value.In(location)
	return civilDate{year: local.Year(), month: local.Month(), day: local.Day()}
}

func (date civilDate) next() civilDate {
	next := time.Date(date.year, date.month, date.day+1, 0, 0, 0, 0, time.UTC)
	return civilDate{year: next.Year(), month: next.Month(), day: next.Day()}
}

func compareCivilDate(left, right civilDate) int {
	if left.year != right.year {
		if left.year < right.year {
			return -1
		}
		return 1
	}
	if left.month != right.month {
		if left.month < right.month {
			return -1
		}
		return 1
	}
	if left.day < right.day {
		return -1
	}
	if left.day > right.day {
		return 1
	}
	return 0
}

func compareCivilMinute(leftDate civilDate, leftMinute int, rightDate civilDate, rightMinute int) int {
	if comparison := compareCivilDate(leftDate, rightDate); comparison != 0 {
		return comparison
	}
	if leftMinute < rightMinute {
		return -1
	}
	if leftMinute > rightMinute {
		return 1
	}
	return 0
}
