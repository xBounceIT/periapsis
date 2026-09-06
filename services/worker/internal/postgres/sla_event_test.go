package postgres

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	kernel "github.com/periapsis-im/periapsis/modules/sla"
	"github.com/periapsis-im/periapsis/services/worker/internal/slaevent"
	"go.opentelemetry.io/otel/trace"
)

func TestSLAEventRepositoryClaimMapsFrozenAssignmentSnapshotAndTrace(t *testing.T) {
	now := time.Date(2026, time.August, 27, 8, 0, 0, 0, time.UTC)
	jobID := slaWorkerTestUUID(40)
	tenantID := slaWorkerTestUUID(41)
	objectID := slaWorkerTestUUID(42)
	sourceEventID := slaWorkerTestUUID(43)
	workerID := slaWorkerTestUUID(44)
	digest := make([]byte, 32)
	for index := range digest {
		digest[index] = byte(index + 1)
	}
	stateDocument := slaEventAssignmentFixture(t, tenantID, objectID, now)
	traceID, _ := trace.TraceIDFromHex("33333333333333333333333333333333")
	spanID, _ := trace.SpanIDFromHex("4444444444444444")
	traceState, _ := trace.ParseTraceState("vendor=value")
	requestContext := trace.ContextWithSpanContext(context.Background(), trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: traceID, SpanID: spanID, TraceFlags: trace.FlagsSampled, TraceState: traceState,
	}))
	querier := &slaWorkerQuerierFake{query: func(_ context.Context, query string, arguments ...any) (pgx.Rows, error) {
		if !strings.Contains(query, "claim_sla_object_events_v1") ||
			!strings.Contains(query, "app.traceparent") || len(arguments) != 6 ||
			arguments[0] != "00-33333333333333333333333333333333-4444444444444444-01" ||
			arguments[1] != "vendor=value" || arguments[2] != workerID ||
			arguments[3] != now || arguments[4] != 1 ||
			arguments[5] != int64((30*time.Second)/time.Microsecond) {
			t.Fatalf("query=%q arguments=%#v", query, arguments)
		}
		return &slaWorkerRowsFake{scan: func(destinations ...any) error {
			if len(destinations) != 19 {
				t.Fatalf("destinations=%d", len(destinations))
			}
			*destinations[0].(*uuid.UUID) = jobID
			*destinations[1].(*uuid.UUID) = tenantID
			*destinations[2].(*string) = string(kernel.ObjectCase)
			*destinations[3].(*uuid.UUID) = objectID
			*destinations[4].(*int64) = 1
			*destinations[5].(*uuid.UUID) = sourceEventID
			*destinations[6].(*[]byte) = append([]byte(nil), digest...)
			*destinations[7].(*string) = "ticket.created"
			*destinations[8].(*time.Time) = now
			*destinations[9].(*string) = string(kernel.ObjectEventStateUnassigned)
			*destinations[11].(*int64) = 0
			*destinations[13].(*int64) = 0
			*destinations[14].(*int64) = 9
			*destinations[15].(*int32) = 1
			*destinations[16].(*time.Time) = now
			*destinations[17].(*time.Time) = now.Add(30 * time.Second)
			*destinations[18].(*[]byte) = append([]byte(nil), stateDocument...)
			return nil
		}}, nil
	}}
	repository := NewSLAEventRepository(querier)
	jobs, err := repository.Claim(requestContext, slaevent.ClaimRequest{
		Identity: slaevent.Identity{WorkerID: workerID, Purpose: slaevent.WorkerPurpose},
		Now:      now, BatchSize: 1, LeaseDuration: 30 * time.Second,
	})
	if err != nil || len(jobs) != 1 {
		t.Fatalf("jobs=%#v error=%v", jobs, err)
	}
	job := jobs[0]
	if job.ID.String() != jobID.String() || job.TenantID != tenantID ||
		job.ObjectType != kernel.ObjectCase || job.ObjectID.String() != objectID.String() ||
		job.Sequence != 1 || job.SourceEventID.String() != sourceEventID.String() ||
		job.Event.Key.String() != "ticket.created" || job.State.Mode != kernel.ObjectEventStateUnassigned ||
		job.State.Snapshot == nil || len(job.State.Policies) != 0 || job.InvalidProjection ||
		hex.EncodeToString(job.SourceDigest[:]) != hex.EncodeToString(digest) {
		t.Fatalf("job=%#v", job)
	}
}

func TestSLAEventRepositoryClaimSurfacesInvalidProjectionAsFencedJob(t *testing.T) {
	now := time.Date(2026, time.August, 27, 8, 0, 0, 0, time.UTC)
	querier := &slaWorkerQuerierFake{query: func(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
		return &slaWorkerRowsFake{scan: func(destinations ...any) error {
			*destinations[0].(*uuid.UUID) = slaWorkerTestUUID(40)
			*destinations[1].(*uuid.UUID) = slaWorkerTestUUID(41)
			*destinations[2].(*string) = string(kernel.ObjectCase)
			*destinations[3].(*uuid.UUID) = slaWorkerTestUUID(42)
			*destinations[4].(*int64) = 1
			*destinations[5].(*uuid.UUID) = slaWorkerTestUUID(43)
			*destinations[6].(*[]byte) = make([]byte, 32)
			(*destinations[6].(*[]byte))[0] = 1
			*destinations[7].(*string) = "ticket.created"
			*destinations[8].(*time.Time) = now
			*destinations[9].(*string) = string(kernel.ObjectEventStateUnassigned)
			*destinations[14].(*int64) = 9
			*destinations[15].(*int32) = 1
			*destinations[16].(*time.Time) = now
			*destinations[17].(*time.Time) = now.Add(30 * time.Second)
			*destinations[18].(*[]byte) = []byte(`{"facts":{"secret":"redacted"}}`)
			return nil
		}}, nil
	}}
	jobs, err := NewSLAEventRepository(querier).Claim(context.Background(), slaevent.ClaimRequest{
		Identity: slaevent.Identity{WorkerID: slaWorkerTestUUID(44), Purpose: slaevent.WorkerPurpose},
		Now:      now, BatchSize: 1, LeaseDuration: 30 * time.Second,
	})
	if err != nil || len(jobs) != 1 || !jobs[0].InvalidProjection || jobs[0].State.Mode != "" {
		t.Fatalf("jobs=%#v error=%v", jobs, err)
	}
}

func TestSLAEventRepositoryCommitPersistsNoPolicyReceiptWithFence(t *testing.T) {
	now := time.Date(2026, time.August, 27, 8, 0, 0, 0, time.UTC)
	job := slaEventUnassignedJob(t, now)
	plan, err := kernel.PlanObjectEvent(job.Event, job.State)
	if err != nil || plan.Assignment() == nil || plan.Assignment().Matched() {
		t.Fatalf("plan=%#v error=%v", plan, err)
	}
	workerID := slaWorkerTestUUID(44)
	querier := &slaWorkerQuerierFake{queryRow: func(_ context.Context, query string, arguments ...any) pgx.Row {
		if !strings.Contains(query, "commit_sla_object_event_ingress_v1") ||
			!strings.Contains(query, "decode($7, 'hex')") || len(arguments) != 15 ||
			arguments[0] != "" || arguments[1] != "" || arguments[2] != workerID ||
			arguments[3] != uuid.UUID(job.ID.Bytes()) || arguments[4] != job.TenantID ||
			arguments[5] != job.Fence || arguments[6] != encodeSLAEventDigest(job.SourceDigest) ||
			arguments[7] != string(slaevent.OutcomeNoPolicy) || arguments[8] != nil ||
			arguments[9] != uint64(0) || arguments[10] != uint64(0) ||
			arguments[11] != nil || arguments[12] != uint64(0) || arguments[13] != now.Add(time.Second) {
			t.Fatalf("query=%q arguments=%#v", query, arguments)
		}
		raw, ok := arguments[14].([]byte)
		if !ok {
			t.Fatalf("plan argument=%T", arguments[14])
		}
		var document slaEventPlanDocument
		if decodeErr := json.Unmarshal(raw, &document); decodeErr != nil || len(document.Metrics) != 0 ||
			len(document.Cursors) != 0 || len(document.Occurrences) != 0 || len(document.Columns) != 0 {
			t.Fatalf("document=%#v error=%v", document, decodeErr)
		}
		return slaWorkerRowFake(func(destinations ...any) error {
			*destinations[0].(*string) = "applied"
			*destinations[1].(*string) = string(slaevent.OutcomeNoPolicy)
			*destinations[3].(*int64) = 0
			return nil
		})
	}}
	result, err := NewSLAEventRepository(querier).Commit(context.Background(), slaevent.CommitRequest{
		Identity: slaevent.Identity{WorkerID: workerID, Purpose: slaevent.WorkerPurpose},
		Job:      job, Plan: plan, CompletedAt: now.Add(time.Second),
	})
	if err != nil || result.Outcome != slaevent.OutcomeNoPolicy || result.SLAInstanceID != nil ||
		result.AggregateVersion != 0 || result.Replayed {
		t.Fatalf("result=%#v error=%v", result, err)
	}
}

func TestSLAEventAssignmentPlanPersistsMetricsUnchangedByCreate(t *testing.T) {
	now := time.Date(2026, time.August, 27, 8, 0, 0, 0, time.UTC)
	tenantID := slaWorkerTestEntity(41)
	objectID := slaWorkerTestEntity(42)
	snapshot, err := kernel.NewFactSnapshot(kernel.FactSnapshotInput{
		TenantID: tenantID, ObjectType: kernel.ObjectCase,
		EvaluatedAt: now, Timezone: "UTC",
	})
	if err != nil {
		t.Fatal(err)
	}
	createdMetric := slaEventTestMetric(t, 50, "created_metric", "ticket.created")
	futureMetric := slaEventTestMetric(t, 51, "future_metric", "ticket.acknowledged")
	rule, err := kernel.NewRule(&kernel.RuleInput{Kind: kernel.RuleAll})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := kernel.NewPolicy(kernel.PolicyInput{
		ID: slaWorkerTestEntity(52), TenantID: tenantID,
		Key: slaWorkerTestKey("assignment_policy"), Name: "Assignment policy",
		Version: 1, ObjectTypes: []kernel.ObjectType{kernel.ObjectCase},
		MatchRule: rule, Metrics: []kernel.MetricDefinition{createdMetric, futureMetric},
		EffectiveFrom: now.Add(-time.Hour), Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	event := kernel.MetricEvent{
		ID: slaWorkerTestEntity(53), TenantID: tenantID, ObjectID: objectID,
		Key: slaWorkerTestKey("ticket.created"), OccurredAt: now,
	}
	plan, err := kernel.PlanObjectEvent(event, kernel.ObjectEventState{
		Mode: kernel.ObjectEventStateUnassigned, Snapshot: &snapshot,
		Policies: []kernel.Policy{policy},
	})
	if err != nil || plan.Assignment() == nil || !plan.Assignment().Matched() {
		t.Fatalf("plan=%#v error=%v", plan, err)
	}
	raw, err := encodeSLAEventPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	var document slaWorkerPlanWrite
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Metrics) != 2 {
		t.Fatalf("assignment metric writes=%d", len(document.Metrics))
	}
	var foundPending bool
	for _, metric := range document.Metrics {
		if metric.DefinitionID == uuid.UUID(futureMetric.ID().Bytes()) {
			foundPending = metric.Lifecycle == kernel.LifecyclePending &&
				metric.LastEventID == nil && metric.LastEventKey == nil && metric.LastEventAt == nil
		}
	}
	if !foundPending {
		t.Fatalf("unchanged assignment metric was not durably encoded: %#v", document.Metrics)
	}
}

func TestDecodeSLAEventRuleRejectsInvalidCustomFactKey(t *testing.T) {
	_, err := decodeSLAEventRule(slaEventRuleDocument{
		Kind: kernel.RulePredicate,
		Predicate: &slaEventPredicateDocument{
			Kind: kernel.FactCustomField, Key: "Not-Canonical",
			Operator: kernel.PredicateEquals, Values: []string{"value"},
		},
	})
	if err == nil {
		t.Fatal("invalid custom fact key was silently discarded")
	}
}

func TestDecodeSLAEventAssignmentSnapshotValidatesUnselectedPolicyColumns(t *testing.T) {
	now := time.Date(2026, time.August, 27, 8, 0, 0, 0, time.UTC)
	tenantID, objectID := slaWorkerTestUUID(41), slaWorkerTestUUID(42)
	metric := slaEventTestMetric(t, 60, "case_response", "ticket.created")
	rule, err := kernel.NewRule(&kernel.RuleInput{Kind: kernel.RuleAll})
	if err != nil {
		t.Fatal(err)
	}
	casePolicy, err := kernel.NewPolicy(kernel.PolicyInput{
		ID: slaWorkerTestEntity(61), TenantID: slaWorkerTestEntity(41),
		Key: slaWorkerTestKey("case_policy"), Name: "Case policy", Version: 1,
		ObjectTypes: []kernel.ObjectType{kernel.ObjectCase}, MatchRule: rule,
		Metrics: []kernel.MetricDefinition{metric}, EffectiveFrom: now.Add(-time.Hour), Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	metric = casePolicy.Metrics()[0]
	column, err := kernel.NewColumnDefinition(metric, kernel.ColumnDefinitionInput{
		ID: slaWorkerTestEntity(62), TenantID: casePolicy.TenantID(),
		Key: slaWorkerTestKey("case_response_due"), Label: "Case response due",
		MetricID: metric.ID(), Calculation: kernel.ColumnDueAt, Format: kernel.FormatDateTime,
		Sortable: true, Filterable: true, Version: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	foreignInput := column.Input()
	foreignInput.TenantID = slaWorkerTestEntity(64)
	foreignColumn, err := kernel.NewColumnDefinition(metric, foreignInput)
	if err != nil {
		t.Fatal(err)
	}
	var original slaEventAssignmentSnapshotDocument
	if err := json.Unmarshal(slaEventAssignmentFixture(t, tenantID, objectID, now), &original); err != nil {
		t.Fatal(err)
	}
	// The producer filters policies by object type, but its full tenant column
	// catalog embeds the immutable metric even when that Case policy is absent
	// from this Alert snapshot. The codec must validate, not discard, that column.
	original.Facts.ObjectType = kernel.ObjectAlert
	original.Columns = []slaEventColumnDocument{{
		ID: uuid.UUID(column.ID().Bytes()), TenantID: tenantID,
		Key: column.Key().String(), Label: column.Label(), MetricDefinitionID: uuid.UUID(metric.ID().Bytes()),
		Metric: slaWorkerDefinition{
			ID: uuid.UUID(metric.ID().Bytes()), Key: metric.Key().String(), Label: metric.Label(),
			Description: metric.Description(), DurationMicros: metric.Duration().Microseconds(), Clock: metric.Clock(),
			StartEvent: metric.StartEvent().String(), CompletionEvent: metric.CompletionEvent().String(),
			ResetPolicy: metric.ResetPolicy(), WarningKind: metric.Warning().Kind,
			BreachGraceMicros: metric.BreachGrace().Microseconds(), DisplayFormat: metric.DisplayFormat(),
			CustomerVisible: metric.CustomerVisible(), APIVisible: metric.APIVisible(),
			DefinitionDigest: encodeSLAEventDigest(metric.Digest()),
		},
		Calculation: column.Calculation(), Format: column.Format(), Sortable: column.Sortable(),
		Filterable: column.Filterable(), CustomerVisible: column.CustomerVisible(),
		VisibleRoleKeys: []string{}, StyleRules: []slaWorkerColumnStyle{},
		Position: column.Position(), Version: column.Version(), RevisionDigest: encodeSLAEventDigest(column.Digest()),
	}}
	for _, test := range []struct {
		name   string
		mutate func(*slaEventAssignmentSnapshotDocument)
		want   string
	}{
		{name: "valid other-object policy column with embedded metric"},
		{name: "column digest", mutate: func(document *slaEventAssignmentSnapshotDocument) {
			document.Columns[0].RevisionDigest = strings.Repeat("0", 64)
		}, want: "database returned an invalid SLA worker column"},
		{name: "embedded metric digest", mutate: func(document *slaEventAssignmentSnapshotDocument) {
			document.Columns[0].Metric.DefinitionDigest = strings.Repeat("0", 64)
		}, want: "database returned an invalid SLA event column metric"},
		{name: "embedded metric identity", mutate: func(document *slaEventAssignmentSnapshotDocument) {
			document.Columns[0].MetricDefinitionID = slaWorkerTestUUID(63)
		}, want: "database returned an invalid SLA event column metric"},
		{name: "other tenant with matching digest", mutate: func(document *slaEventAssignmentSnapshotDocument) {
			document.Columns[0].TenantID = uuid.UUID(foreignColumn.TenantID().Bytes())
			document.Columns[0].RevisionDigest = encodeSLAEventDigest(foreignColumn.Digest())
		}, want: "database returned a cross-boundary SLA worker column"},
		{name: "duplicate valid column identity", mutate: func(document *slaEventAssignmentSnapshotDocument) {
			document.Columns = append(document.Columns, document.Columns[0])
		}, want: "database returned duplicate SLA event columns"},
	} {
		t.Run(test.name, func(t *testing.T) {
			document := original
			document.Columns = append([]slaEventColumnDocument(nil), original.Columns...)
			if test.mutate != nil {
				test.mutate(&document)
			}
			raw, marshalErr := json.Marshal(document)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			state, decodeErr := decodeSLAEventAssignmentSnapshot(
				tenantID, kernel.ObjectAlert, slaWorkerTestEntity(42), now, raw,
			)
			if test.want != "" {
				if decodeErr == nil || decodeErr.Error() != test.want || !reflect.DeepEqual(state, kernel.ObjectEventState{}) {
					t.Fatalf("invalid column did not fail closed: state=%#v error=%v", state, decodeErr)
				}
				return
			}
			if decodeErr != nil || state.Mode != kernel.ObjectEventStateUnassigned || state.Snapshot == nil ||
				state.Snapshot.ObjectType() != kernel.ObjectAlert || len(state.Policies) != 0 || len(state.Calendars) != 0 ||
				len(state.Columns) != 1 || state.Columns[0].Digest() != column.Digest() ||
				state.Columns[0].ID() != column.ID() || state.Columns[0].TenantID() != column.TenantID() ||
				state.Columns[0].MetricID() != metric.ID() || state.Columns[0].Version() != column.Version() {
				t.Fatalf("valid unselected column was not restored intact: state=%#v error=%v", state, decodeErr)
			}
		})
	}
}

func TestSLAEventRepositoryFailureReadinessAndQueueMetrics(t *testing.T) {
	now := time.Date(2026, time.August, 27, 8, 0, 0, 0, time.UTC)
	workerID := slaWorkerTestUUID(44)
	jobID := slaWorkerTestEntity(40)
	tenantID := slaWorkerTestUUID(41)
	retryAt := now.Add(10 * time.Second)
	querier := &slaWorkerQuerierFake{queryRow: func(_ context.Context, query string, arguments ...any) pgx.Row {
		switch {
		case strings.Contains(query, "sla_object_event_ingress_schema_readiness_v50"):
			if len(arguments) != 0 {
				t.Fatalf("readiness arguments=%#v", arguments)
			}
			return slaWorkerRowFake(func(destinations ...any) error {
				*destinations[0].(*bool) = true
				return nil
			})
		case strings.Contains(query, "fail_sla_object_event_ingress_v1"):
			if !strings.Contains(query, "FROM trace_context AS trace") {
				t.Fatal("failure query must bind the trace alias used by its worker identity guard")
			}
			if len(arguments) != 11 || arguments[2] != workerID ||
				arguments[3] != uuid.UUID(jobID.Bytes()) || arguments[4] != tenantID ||
				arguments[5] != uint64(9) || arguments[6] != uint16(1) ||
				arguments[7] != "planning_timeout" || arguments[8] != false ||
				arguments[9] != now || arguments[10] != retryAt {
				t.Fatalf("failure arguments=%#v", arguments)
			}
			return slaWorkerRowFake(func(destinations ...any) error {
				*destinations[0].(*string) = "fence_lost"
				return nil
			})
		case strings.Contains(query, "read_sla_object_event_ingress_queue_metrics_v1"):
			return slaWorkerRowFake(func(destinations ...any) error {
				*destinations[0].(*time.Time) = now
				*destinations[1].(*int64) = 7
				*destinations[2].(*int64) = 2
				*destinations[3].(*int64) = 1
				*destinations[4].(*int64) = 15_000_000
				return nil
			})
		default:
			t.Fatalf("unexpected query=%q", query)
			return slaWorkerRowFake(func(...any) error { return errors.New("unexpected query") })
		}
	}}
	repository := NewSLAEventRepository(querier)
	if err := repository.Ready(context.Background()); err != nil {
		t.Fatalf("Ready() error=%v", err)
	}
	err := repository.Fail(context.Background(), slaevent.FailureRequest{
		Identity: slaevent.Identity{WorkerID: workerID, Purpose: slaevent.WorkerPurpose},
		JobID:    jobID, TenantID: tenantID, Fence: 9, Attempt: 1,
		Code: "planning_timeout", FailedAt: now, RetryAt: &retryAt,
	})
	if !errors.Is(err, slaevent.ErrFenceLost) {
		t.Fatalf("Fail() error=%v", err)
	}
	metrics, err := repository.ReadQueueMetrics(context.Background())
	if err != nil || !metrics.ObservedAt.Equal(now) || metrics.PendingEvents != 7 ||
		metrics.ReclaimableEvents != 2 || metrics.DeadLetteredEvents != 1 ||
		metrics.OldestPendingMicros != 15_000_000 {
		t.Fatalf("metrics=%#v error=%v", metrics, err)
	}
}

func slaEventAssignmentFixture(t *testing.T, tenantID, objectID uuid.UUID, now time.Time) []byte {
	t.Helper()
	raw, err := json.Marshal(slaEventAssignmentSnapshotDocument{
		Facts: slaEventFactSnapshotDocument{
			TenantID: tenantID, ObjectType: kernel.ObjectCase, ObjectID: objectID,
			EvaluatedAt: now, Timezone: "UTC", Facts: []slaEventFactDocument{},
		},
		Policies: []slaEventPolicyDocument{}, Calendars: []slaWorkerCalendar{},
		Columns: []slaEventColumnDocument{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func slaEventUnassignedJob(t *testing.T, now time.Time) slaevent.Job {
	t.Helper()
	tenantID := slaWorkerTestUUID(41)
	objectID := slaWorkerTestEntity(42)
	sourceEventID := slaWorkerTestEntity(43)
	state, err := decodeSLAEventAssignmentSnapshot(
		tenantID, kernel.ObjectCase, objectID, now,
		slaEventAssignmentFixture(t, tenantID, uuid.UUID(objectID.Bytes()), now),
	)
	if err != nil {
		t.Fatal(err)
	}
	digest := [32]byte{1}
	return slaevent.Job{
		ID: slaWorkerTestEntity(40), TenantID: tenantID, ObjectType: kernel.ObjectCase,
		ObjectID: objectID, Sequence: 1, SourceEventID: sourceEventID, SourceDigest: digest,
		Event: kernel.MetricEvent{
			ID: sourceEventID, TenantID: slaWorkerTestEntity(41), ObjectID: objectID,
			Key: slaWorkerTestKey("ticket.created"), OccurredAt: now,
		},
		State: state, Fence: 9, Attempt: 1, ClaimedAt: now,
		LeaseExpiresAt: now.Add(30 * time.Second),
	}
}

func slaEventTestMetric(
	t *testing.T,
	sequence uint16,
	key string,
	startEvent string,
) kernel.MetricDefinition {
	t.Helper()
	metric, err := kernel.NewMetricDefinition(kernel.MetricDefinitionInput{
		ID: slaWorkerTestEntity(sequence), Key: slaWorkerTestKey(key), Label: key,
		Duration: time.Hour, Clock: kernel.ClockElapsed,
		StartEvent:      slaWorkerTestKey(startEvent),
		CompletionEvent: slaWorkerTestKey("ticket.resolved"),
		ResetPolicy:     kernel.ResetIgnore,
		Warning:         kernel.WarningThreshold{Kind: kernel.WarningNone},
		DisplayFormat:   "duration", APIVisible: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return metric
}
