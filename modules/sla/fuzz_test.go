package sla

import (
	"testing"
	"time"
)

func FuzzBusinessCalendarAddElapsedRoundTrip(f *testing.F) {
	for _, seed := range []struct {
		unixSeconds int64
		minutes     uint16
	}{
		{time.Date(2026, 3, 29, 0, 0, 0, 0, time.UTC).Unix(), 120},
		{time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC).Unix(), 120},
		{time.Date(2026, 8, 28, 14, 0, 0, 0, time.UTC).Unix(), 600},
	} {
		f.Add(seed.unixSeconds, seed.minutes)
	}
	calendar, err := NewBusinessCalendar(allDayCalendarInput("Europe/Rome"))
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, unixSeconds int64, rawMinutes uint16) {
		start := time.Unix(unixSeconds, 0).UTC()
		if !validInstant(start) || start.Year() < 2000 || start.Year() > 2100 {
			return
		}
		duration := time.Duration(rawMinutes%10_081) * time.Minute
		due, err := calendar.AddBusinessTime(start, duration)
		if err != nil {
			t.Fatalf("AddBusinessTime(%s,%s) error=%v", start, duration, err)
		}
		elapsed, err := calendar.BusinessElapsed(start, due)
		if err != nil || elapsed != duration {
			t.Fatalf("round trip start=%s due=%s duration=%s elapsed=%s error=%v", start, due, duration, elapsed, err)
		}
	})
}

func FuzzMetricEventSequenceIsVersionedAndImmutable(f *testing.F) {
	for _, seed := range []struct {
		actions string
		step    uint16
	}{
		{"sprc", 60},
		{"srrpc", 30},
		{"sxc", 120},
	} {
		f.Add(seed.actions, seed.step)
	}
	f.Fuzz(func(t *testing.T, actions string, rawStep uint16) {
		if len(actions) > 128 {
			return
		}
		definition, err := NewMetricDefinition(elapsedMetricInput())
		if err != nil {
			t.Fatal(err)
		}
		instance, err := NewMetricInstance(MetricInstanceInput{
			ID: fixtureID(200), SLAInstanceID: fixtureID(203), TenantID: fixtureID(1), ObjectType: ObjectCase,
			ObjectID: fixtureID(201), PolicyID: fixtureID(202), PolicyVersion: 1,
			Definition: definition, CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		})
		if err != nil {
			t.Fatal(err)
		}
		step := time.Duration(rawStep%241) * time.Minute
		at := instance.CreatedAt()
		for index := 0; index < len(actions); index++ {
			at = at.Add(step)
			key := "ticket.unrelated"
			switch actions[index] {
			case 's':
				key = definition.StartEvent().String()
			case 'p':
				key = definition.PauseEvent().String()
			case 'r':
				key = definition.ResumeEvent().String()
			case 'c':
				key = definition.CompletionEvent().String()
			case 'x':
				key = definition.ResetEvent().String()
			}
			before := instance.clone()
			updated, changed, applyErr := instance.ApplyEvent(instance.Version(), MetricEvent{
				ID: fixtureID(uint16(300 + index)), TenantID: instance.TenantID(), ObjectID: instance.ObjectID(),
				Key: mustKey(key), OccurredAt: at,
			}, nil)
			if applyErr != nil {
				return
			}
			if before.Version() != instance.Version() || before.Consumed() != instance.Consumed() {
				t.Fatal("ApplyEvent mutated the source aggregate")
			}
			if changed && updated.Version() != instance.Version()+1 || !changed && updated.Version() != instance.Version() {
				t.Fatalf("version drift changed=%t old=%d new=%d", changed, instance.Version(), updated.Version())
			}
			instance = updated
		}
	})
}
