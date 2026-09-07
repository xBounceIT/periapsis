package postgres

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/sla"
)

func TestDecodeSLAWorkerStateAcceptsExactPinnedProjection(t *testing.T) {
	now := time.Date(2026, time.August, 26, 8, 0, 0, 0, time.UTC)
	raw, tenantID, slaInstanceID, _, objectID := slaWorkerStateFixture(t, now)
	objectType, decodedObjectID, metrics, err := decodeSLAWorkerState(tenantID, slaInstanceID, 7, raw)
	if err != nil || objectType != kernel.ObjectCase || decodedObjectID != objectID || len(metrics) != 1 {
		t.Fatalf("decode = %s, %s, %d, %v", objectType, decodedObjectID, len(metrics), err)
	}
	instance := metrics[0].Instance
	if instance.SLAInstanceID().String() != slaInstanceID.String() || instance.Version() != 1 ||
		instance.Definition().Key().String() != "resolution" || len(metrics[0].Triggers) != 0 ||
		len(metrics[0].Columns) != 0 || metrics[0].Calendar != nil {
		t.Fatalf("metric = %#v", metrics[0])
	}
}

func TestDecodeSLAWorkerStateUsesPolicyTriggerPositions(t *testing.T) {
	for _, test := range []struct {
		name      string
		positions []uint16
		wantError bool
	}{
		{"later metric trigger", []uint16{2}, false},
		{"duplicate position", []uint16{2, 2}, true},
		{"descending position", []uint16{2, 1}, true},
		{"duplicate identity at distinct positions", []uint16{2, 4}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			document, tenantID, instanceID := slaWorkerCursorStateFixture(t, time.Date(2026, time.August, 26, 8, 0, 0, 0, time.UTC))
			trigger := document.Metrics[0].Triggers[0]
			document.Metrics[0].Triggers = nil
			for _, position := range test.positions {
				trigger.Position = position
				document.Metrics[0].Triggers = append(document.Metrics[0].Triggers, trigger)
			}
			raw, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			_, _, metrics, err := decodeSLAWorkerState(tenantID, instanceID, 7, raw)
			if (err != nil) != test.wantError {
				t.Fatalf("decode error = %v, want error %v", err, test.wantError)
			}
			if !test.wantError && len(metrics[0].Triggers) != 1 {
				t.Fatal("trigger was lost")
			}
		})
	}
}

func TestDecodeSLAWorkerStateNormalizesCursorInstantsWithoutChangingTime(t *testing.T) {
	now := time.Date(2026, time.August, 26, 8, 0, 0, 123000, time.UTC)
	for _, test := range []struct {
		name     string
		offset   int
		zeroText bool
	}{
		{name: "UTC"},
		{name: "PostgreSQL numeric UTC offset", zeroText: true},
		{name: "positive offset", offset: 2 * 60 * 60},
		{name: "negative offset", offset: -5 * 60 * 60},
	} {
		t.Run(test.name, func(t *testing.T) {
			document, tenantID, instanceID := slaWorkerCursorStateFixture(t, now)
			observed := now.In(time.FixedZone("wire offset", test.offset))
			fired := now.Add(-time.Minute).In(time.FixedZone("wire offset", test.offset))
			document.Metrics[0].Cursors[0].LastObservedAt = &observed
			document.Metrics[0].Cursors[0].LastFiredAt = &fired
			raw, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			if test.zeroText {
				raw = []byte(strings.ReplaceAll(string(raw), `Z"`, `+00:00"`))
			}
			_, _, metrics, err := decodeSLAWorkerState(tenantID, instanceID, 7, raw)
			if err != nil || len(metrics) != 1 || len(metrics[0].Triggers) != 1 {
				t.Fatalf("cursor projection error=%v", err)
			}
			cursor := metrics[0].Triggers[0].Cursor.Snapshot()
			if cursor.LastObservedAt == nil || cursor.LastFiredAt == nil ||
				cursor.LastObservedAt.Location() != time.UTC || cursor.LastFiredAt.Location() != time.UTC ||
				!cursor.LastObservedAt.Equal(now) || !cursor.LastFiredAt.Equal(now.Add(-time.Minute)) ||
				cursor.FireCount != 1 || !cursor.Initialized {
				t.Fatalf("cursor normalization changed the event history: %#v", cursor)
			}
		})
	}
}

func TestDecodeSLAWorkerStateRejectsInvalidCursorInstants(t *testing.T) {
	now := time.Date(2026, time.August, 26, 8, 0, 0, 123000, time.UTC)
	for _, test := range []struct {
		name   string
		mutate func(*slaWorkerCursor)
	}{
		{"sub-microsecond observation", func(cursor *slaWorkerCursor) { value := now.Add(time.Nanosecond); cursor.LastObservedAt = &value }},
		{"sub-microsecond firing", func(cursor *slaWorkerCursor) {
			value := now.Add(-time.Minute + time.Nanosecond)
			cursor.LastFiredAt = &value
		}},
		{"pre-epoch observation", func(cursor *slaWorkerCursor) {
			value := time.Date(1969, 12, 31, 23, 59, 59, 0, time.UTC)
			cursor.LastObservedAt = &value
		}},
		{"pre-epoch firing", func(cursor *slaWorkerCursor) {
			value := time.Date(1969, 12, 31, 23, 59, 59, 0, time.UTC)
			cursor.LastFiredAt = &value
		}},
		{"zero observation", func(cursor *slaWorkerCursor) { cursor.LastObservedAt = &time.Time{} }},
		{"missing initialized observation", func(cursor *slaWorkerCursor) { cursor.LastObservedAt = nil }},
		{"missing firing history", func(cursor *slaWorkerCursor) { cursor.LastFiredAt = nil }},
		{"firing after observation", func(cursor *slaWorkerCursor) { value := now.Add(time.Microsecond); cursor.LastFiredAt = &value }},
	} {
		t.Run(test.name, func(t *testing.T) {
			document, tenantID, instanceID := slaWorkerCursorStateFixture(t, now)
			test.mutate(&document.Metrics[0].Cursors[0])
			raw, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			objectType, objectID, metrics, err := decodeSLAWorkerState(tenantID, instanceID, 7, raw)
			if err == nil || objectType != "" || objectID != (kernel.EntityID{}) || metrics != nil ||
				strings.Contains(err.Error(), tenantID.String()) {
				t.Fatalf("invalid cursor accepted or leaked partial state: %v", err)
			}
		})
	}
}

func slaWorkerCursorStateFixture(t *testing.T, now time.Time) (slaWorkerStateDocument, uuid.UUID, uuid.UUID) {
	t.Helper()
	raw, tenantID, instanceID, _, _ := slaWorkerStateFixture(t, now)
	var document slaWorkerStateDocument
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	metric := slaWorkerTestMetric(t)
	actionValue := "sla.cursor_due"
	trigger, err := kernel.NewTriggerDefinition(metric, kernel.TriggerDefinitionInput{
		ID: slaWorkerTestEntity(75), Key: slaWorkerTestKey("cursor_due"), MetricID: metric.ID(), Kind: kernel.TriggerDue,
		Action: kernel.TriggerActionInput{Kind: kernel.ActionDomainEvent, Value: slaWorkerTestKey(actionValue)},
	})
	if err != nil {
		t.Fatal(err)
	}
	digest := trigger.Digest()
	document.Metrics[0].Triggers = []slaWorkerTrigger{{
		ID: uuid.UUID(trigger.ID().Bytes()), MetricDefinitionID: uuid.UUID(metric.ID().Bytes()),
		Key: trigger.Key().String(), Kind: kernel.TriggerDue, ActionKind: kernel.ActionDomainEvent,
		ActionValue: &actionValue, DefinitionDigest: hex.EncodeToString(digest[:]),
	}}
	state := kernel.StateBreached
	fired := now.Add(-time.Minute)
	document.Metrics[0].Cursors = []slaWorkerCursor{{
		TriggerDefinitionID: uuid.UUID(trigger.ID().Bytes()), Initialized: true,
		LastObservedAt: &now, LastFiredAt: &fired, LastState: &state,
		LastPercentage: 100, LastRepeatWindow: -1, FireCount: 1,
	}}
	return document, tenantID, instanceID
}

func TestDecodeSLAWorkerStateRejectsHostileProjectionCorpus(t *testing.T) {
	now := time.Date(2026, time.August, 26, 8, 0, 0, 0, time.UTC)
	raw, tenantID, slaInstanceID, metricID, _ := slaWorkerStateFixture(t, now)
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	withMutation := func(mutate func(map[string]any)) []byte {
		copy := cloneSLAWorkerJSON(t, document)
		mutate(copy)
		encoded, err := json.Marshal(copy)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	cases := map[string][]byte{
		"unknown top-level member": withMutation(func(value map[string]any) { value["secret"] = "leak" }),
		"cross tenant aggregate": withMutation(func(value map[string]any) {
			value["aggregate"].(map[string]any)["tenant_id"] = slaWorkerTestUUID(90).String()
		}),
		"tampered definition digest": withMutation(func(value map[string]any) {
			value["metrics"].([]any)[0].(map[string]any)["definition"].(map[string]any)["definition_digest"] = strings.Repeat("0", 64)
		}),
		"duplicate metric identity": withMutation(func(value map[string]any) {
			metrics := value["metrics"].([]any)
			value["metrics"] = append(metrics, cloneSLAWorkerJSON(t, metrics[0].(map[string]any)))
		}),
		"cross definition identity": withMutation(func(value map[string]any) {
			value["metrics"].([]any)[0].(map[string]any)["definition_id"] = slaWorkerTestUUID(91).String()
		}),
	}
	for name, hostile := range cases {
		t.Run(name, func(t *testing.T) {
			_, _, _, err := decodeSLAWorkerState(tenantID, slaInstanceID, 7, hostile)
			if err == nil || strings.Contains(err.Error(), metricID.String()) || strings.Contains(err.Error(), tenantID.String()) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	trailing := append(append([]byte(nil), raw...), []byte(" {}")...)
	if _, _, _, err := decodeSLAWorkerState(tenantID, slaInstanceID, 7, trailing); err == nil {
		t.Fatal("trailing document was accepted")
	}
}

func TestEncodeSLAWorkerPlanPersistsOnlyChangedMetrics(t *testing.T) {
	now := time.Date(2026, time.August, 26, 8, 0, 0, 0, time.UTC)
	metric := slaWorkerTestMetric(t)
	instance, err := kernel.NewMetricInstance(kernel.MetricInstanceInput{
		ID: slaWorkerTestEntity(4), SLAInstanceID: slaWorkerTestEntity(5),
		TenantID: slaWorkerTestEntity(1), ObjectType: kernel.ObjectCase,
		ObjectID: slaWorkerTestEntity(2), PolicyID: slaWorkerTestEntity(3),
		PolicyVersion: 1, Definition: metric, CreatedAt: now.Add(-time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	started, changed, err := instance.ApplyEvent(instance.Version(), kernel.MetricEvent{
		ID: slaWorkerTestEntity(6), TenantID: instance.TenantID(), ObjectID: instance.ObjectID(),
		Key: metric.StartEvent(), OccurredAt: instance.CreatedAt(),
	}, nil)
	if err != nil || !changed {
		t.Fatalf("start changed=%t err=%v", changed, err)
	}
	plan, err := kernel.PlanEngineContext(context.Background(), kernel.EngineInput{
		ObservedAt: now, Metrics: []kernel.MetricWork{{Instance: started}},
	})
	if err != nil || len(plan.Metrics()) != 1 || !plan.Metrics()[0].Changed() {
		t.Fatalf("plan=%#v err=%v", plan, err)
	}
	raw, err := encodeSLAWorkerPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	var document slaWorkerPlanWrite
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Metrics) != 1 || document.Metrics[0].Version != started.Version()+1 ||
		document.AggregateCompletedAt != nil {
		t.Fatalf("document=%#v", document)
	}

	pending, err := kernel.NewMetricInstance(kernel.MetricInstanceInput{
		ID: slaWorkerTestEntity(14), SLAInstanceID: slaWorkerTestEntity(5),
		TenantID: slaWorkerTestEntity(1), ObjectType: kernel.ObjectCase,
		ObjectID: slaWorkerTestEntity(2), PolicyID: slaWorkerTestEntity(3),
		PolicyVersion: 1, Definition: metric, CreatedAt: now.Add(-time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	unchanged, err := kernel.PlanEngineContext(context.Background(), kernel.EngineInput{
		ObservedAt: now, Metrics: []kernel.MetricWork{{Instance: pending}},
	})
	if err != nil || unchanged.Metrics()[0].Changed() {
		t.Fatalf("unchanged plan=%#v err=%v", unchanged, err)
	}
	raw, err = encodeSLAWorkerPlan(unchanged)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Metrics) != 0 {
		t.Fatalf("unchanged metrics persisted: %#v", document.Metrics)
	}
}

func slaWorkerStateFixture(
	t *testing.T,
	now time.Time,
) ([]byte, uuid.UUID, uuid.UUID, uuid.UUID, kernel.EntityID) {
	t.Helper()
	tenantID := slaWorkerTestUUID(1)
	objectID := slaWorkerTestEntity(2)
	policyID := slaWorkerTestUUID(3)
	metricID := slaWorkerTestUUID(4)
	slaInstanceID := slaWorkerTestUUID(5)
	metric := slaWorkerTestMetric(t)
	input := metric.Input()
	metricDigest := metric.Digest()
	document := slaWorkerStateDocument{
		Aggregate: slaWorkerAggregateDocument{
			ID: slaInstanceID, TenantID: tenantID, ObjectType: kernel.ObjectCase,
			ObjectID: uuid.UUID(objectID.Bytes()), PolicyID: policyID,
			PolicyVersion: 1, AggregateVersion: 7,
			CreatedAt: now.Add(-time.Hour), UpdatedAt: now,
		},
		Metrics: []slaWorkerMetricDocument{{
			ID: metricID, TenantID: tenantID, SLAInstanceID: slaInstanceID,
			DefinitionID: uuid.UUID(metric.ID().Bytes()), PolicyID: policyID,
			PolicyVersion: 1, Version: 1, Lifecycle: kernel.LifecyclePending,
			CreatedAt: now.Add(-time.Hour), UpdatedAt: now.Add(-time.Hour),
			Triggers: []slaWorkerTrigger{}, Cursors: []slaWorkerCursor{}, Columns: []slaWorkerColumn{},
			Definition: slaWorkerDefinition{
				ID: uuid.UUID(input.ID.Bytes()), Key: input.Key.String(), Label: input.Label,
				Description: input.Description, DurationMicros: input.Duration.Microseconds(),
				Clock: input.Clock, StartEvent: input.StartEvent.String(),
				CompletionEvent: input.CompletionEvent.String(), ResetPolicy: input.ResetPolicy,
				WarningKind: input.Warning.Kind, BreachGraceMicros: input.BreachGrace.Microseconds(),
				DisplayFormat: input.DisplayFormat, CustomerVisible: input.CustomerVisible,
				APIVisible: input.APIVisible, Position: 0,
				DefinitionDigest: hex.EncodeToString(metricDigest[:]),
			},
		}},
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return raw, tenantID, slaInstanceID, metricID, objectID
}

func slaWorkerTestMetric(t *testing.T) kernel.MetricDefinition {
	t.Helper()
	metric, err := kernel.NewMetricDefinition(kernel.MetricDefinitionInput{
		ID: slaWorkerTestEntity(10), Key: slaWorkerTestKey("resolution"), Label: "Resolution",
		Duration: 4 * time.Hour, Clock: kernel.ClockElapsed,
		StartEvent:      slaWorkerTestKey("ticket.created"),
		CompletionEvent: slaWorkerTestKey("ticket.resolved"), ResetPolicy: kernel.ResetIgnore,
		Warning: kernel.WarningThreshold{Kind: kernel.WarningNone}, DisplayFormat: "duration",
		APIVisible: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return metric
}

func cloneSLAWorkerJSON(t *testing.T, value map[string]any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var clone map[string]any
	if err := json.Unmarshal(raw, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}

func slaWorkerTestUUID(sequence uint16) uuid.UUID {
	value := [16]byte{0x01, 0x9d, 0, 0, 0, byte(sequence >> 8), 0x70, byte(sequence)}
	value[8] = 0x80
	return uuid.UUID(value)
}

func slaWorkerTestEntity(sequence uint16) kernel.EntityID {
	id, err := kernel.ParseEntityID(slaWorkerTestUUID(sequence).String())
	if err != nil {
		panic(err)
	}
	return id
}

func slaWorkerTestKey(value string) kernel.Key {
	key, err := kernel.NewKey(value)
	if err != nil {
		panic(err)
	}
	return key
}

func TestSLAWorkerCodecErrorsStayRedacted(t *testing.T) {
	raw, tenantID, slaInstanceID, metricID, _ := slaWorkerStateFixture(t, time.Now().UTC().Truncate(time.Microsecond))
	raw = append(raw[:len(raw)-1], []byte(`,"unknown":"`+metricID.String()+`"}`)...)
	_, _, _, err := decodeSLAWorkerState(tenantID, slaInstanceID, 7, raw)
	if err == nil || errors.Is(err, context.Canceled) || strings.Contains(err.Error(), metricID.String()) {
		t.Fatalf("error = %v", err)
	}
}
