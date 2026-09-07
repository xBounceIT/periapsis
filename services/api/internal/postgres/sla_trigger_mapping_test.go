package postgres

import (
	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/sla"
	"testing"
	"time"
)

func TestDecodeSLATriggerBindingsRestoresPolicySubsetAndCursorInstants(t *testing.T) {
	entity := func() kernel.EntityID {
		id, err := kernel.NewEntityID([16]byte(uuid.Must(uuid.NewV7())))
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	key := func(value string) kernel.Key {
		result, err := kernel.NewKey(value)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	metric, err := kernel.NewMetricDefinition(kernel.MetricDefinitionInput{
		ID: entity(), Key: key("response"), Label: "Response", Duration: time.Hour,
		Clock: kernel.ClockElapsed, StartEvent: key("ticket.created"), CompletionEvent: key("response.first"),
		ResetPolicy: kernel.ResetIgnore, Warning: kernel.WarningThreshold{Kind: kernel.WarningNone}, DisplayFormat: "duration", APIVisible: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	makeTrigger := func(position uint16) slaTriggerDocument {
		trigger, err := kernel.NewTriggerDefinition(metric, kernel.TriggerDefinitionInput{
			ID: entity(), Key: key("due"), MetricID: metric.ID(), Kind: kernel.TriggerDue,
			Action: kernel.TriggerActionInput{Kind: kernel.ActionDomainEvent, Value: key("sla.due")},
		})
		if err != nil {
			t.Fatal(err)
		}
		return encodeSLATrigger(trigger, position)
	}
	for _, test := range []struct {
		name        string
		positions   []uint16
		duplicateID bool
		offset      int
		invalidTime bool
		wantError   bool
	}{
		{name: "nonzero origin", positions: []uint16{2}},
		{name: "sparse subset", positions: []uint16{2, 4}},
		{name: "numeric UTC offset", positions: []uint16{2}, offset: 0},
		{name: "local offset", positions: []uint16{2}, offset: 7200},
		{name: "duplicate position", positions: []uint16{2, 2}, wantError: true},
		{name: "descending position", positions: []uint16{2, 1}, wantError: true},
		{name: "duplicate identity", positions: []uint16{2, 4}, duplicateID: true, wantError: true},
		{name: "submicrosecond cursor", positions: []uint16{2}, invalidTime: true, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			triggers := make([]slaTriggerDocument, len(test.positions))
			for i, p := range test.positions {
				triggers[i] = makeTrigger(p)
			}
			if test.duplicateID {
				triggers[1] = triggers[0]
				triggers[1].Position = test.positions[1]
			}
			now := time.Date(2026, 8, 26, 8, 0, 0, 123000, time.UTC)
			observed := now.In(time.FixedZone("wire offset", test.offset))
			fired := observed.Add(-time.Minute)
			if test.invalidTime {
				observed = observed.Add(time.Nanosecond)
			}
			state := kernel.StateBreached
			cursors := []slaTriggerCursorDocument{{TriggerDefinitionID: triggers[0].ID, Initialized: true, LastObservedAt: &observed, LastFiredAt: &fired, LastState: &state, LastPercentage: 100, LastRepeatWindow: -1, FireCount: 1}}
			bindings, err := decodeSLATriggerBindings(metric, triggers, cursors)
			if (err != nil) != test.wantError {
				t.Fatalf("error=%v, want error=%v", err, test.wantError)
			}
			if test.wantError {
				return
			}
			if len(bindings) != len(triggers) {
				t.Fatal("trigger subset changed")
			}
			cursor := bindings[0].Cursor.Snapshot()
			if cursor.LastObservedAt.Location() != time.UTC || !cursor.LastObservedAt.Equal(now) || cursor.LastFiredAt.Location() != time.UTC || !cursor.LastFiredAt.Equal(now.Add(-time.Minute)) || cursor.FireCount != 1 {
				t.Fatal("cursor history changed")
			}
		})
	}
}
