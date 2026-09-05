package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	kernel "github.com/periapsis-im/periapsis/modules/sla"
	"github.com/periapsis-im/periapsis/services/worker/internal/slaengine"
	"go.opentelemetry.io/otel/trace"
)

func TestSLARepositoryClaimMapsPinnedDocumentAndExactLease(t *testing.T) {
	now := time.Date(2026, time.August, 26, 8, 0, 0, 0, time.UTC)
	raw, tenantID, slaInstanceID, _, objectID := slaWorkerStateFixture(t, now)
	jobID := slaWorkerTestUUID(30)
	workerID := slaWorkerTestUUID(31)
	traceID, _ := trace.TraceIDFromHex("11111111111111111111111111111111")
	spanID, _ := trace.SpanIDFromHex("2222222222222222")
	traceState, _ := trace.ParseTraceState("vendor=value")
	requestContext := trace.ContextWithSpanContext(context.Background(), trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: traceID, SpanID: spanID, TraceFlags: trace.FlagsSampled, TraceState: traceState,
	}))
	wantTraceParent := "00-11111111111111111111111111111111-2222222222222222-01"
	querier := &slaWorkerQuerierFake{
		query: func(_ context.Context, query string, arguments ...any) (pgx.Rows, error) {
			if !strings.Contains(query, "claim_sla_evaluation_jobs_v3") ||
				!strings.Contains(query, "app.traceparent") || len(arguments) != 6 ||
				arguments[0] != wantTraceParent || arguments[1] != "vendor=value" ||
				arguments[2] != workerID || arguments[3] != now || arguments[4] != 1 ||
				arguments[5] != int64((30*time.Second)/time.Microsecond) {
				t.Fatalf("query=%q arguments=%#v", query, arguments)
			}
			return &slaWorkerRowsFake{scan: func(destinations ...any) error {
				*destinations[0].(*uuid.UUID) = jobID
				*destinations[1].(*uuid.UUID) = tenantID
				*destinations[2].(*uuid.UUID) = slaInstanceID
				*destinations[3].(*int64) = 7
				*destinations[4].(*int64) = 9
				*destinations[5].(*int32) = 1
				*destinations[6].(*time.Time) = now
				*destinations[7].(*time.Time) = now.Add(30 * time.Second)
				*destinations[8].(*[]byte) = append([]byte(nil), raw...)
				return nil
			}}, nil
		},
	}
	repository := NewSLARepository(querier)
	jobs, err := repository.Claim(requestContext, slaengine.ClaimRequest{
		Identity: slaengine.Identity{WorkerID: workerID, Purpose: "sla-engine"},
		Now:      now, BatchSize: 1, LeaseDuration: 30 * time.Second,
	})
	if err != nil || len(jobs) != 1 {
		t.Fatalf("jobs=%#v error=%v", jobs, err)
	}
	job := jobs[0]
	if job.ID.String() != jobID.String() || job.TenantID != tenantID ||
		job.SLAInstanceID.String() != slaInstanceID.String() || job.ObjectID != objectID ||
		job.AggregateVersion != 7 || job.Fence != 9 || job.Attempt != 1 || len(job.Metrics) != 1 {
		t.Fatalf("job=%#v", job)
	}
}

func TestSLARepositoryClaimRejectsMalformedProjectionAndInput(t *testing.T) {
	now := time.Date(2026, time.August, 26, 8, 0, 0, 0, time.UTC)
	workerID := slaWorkerTestUUID(31)
	querier := &slaWorkerQuerierFake{
		query: func(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
			return &slaWorkerRowsFake{scan: func(destinations ...any) error {
				*destinations[0].(*uuid.UUID) = slaWorkerTestUUID(30)
				*destinations[1].(*uuid.UUID) = slaWorkerTestUUID(1)
				*destinations[2].(*uuid.UUID) = slaWorkerTestUUID(5)
				*destinations[3].(*int64) = 7
				*destinations[4].(*int64) = 9
				*destinations[5].(*int32) = 1
				*destinations[6].(*time.Time) = now
				*destinations[7].(*time.Time) = now.Add(30 * time.Second)
				*destinations[8].(*[]byte) = []byte(`{"aggregate":{},"metrics":[],"secret":"raw"}`)
				return nil
			}}, nil
		},
	}
	repository := NewSLARepository(querier)
	_, err := repository.Claim(context.Background(), slaengine.ClaimRequest{
		Identity: slaengine.Identity{WorkerID: workerID, Purpose: "sla-engine"},
		Now:      now, BatchSize: 1, LeaseDuration: 30 * time.Second,
	})
	if !errors.Is(err, slaengine.ErrUnavailable) || strings.Contains(err.Error(), "secret") {
		t.Fatalf("error=%v", err)
	}
	_, err = repository.Claim(context.Background(), slaengine.ClaimRequest{
		Identity: slaengine.Identity{WorkerID: workerID, Purpose: "sla-engine"},
		Now:      now, BatchSize: 101, LeaseDuration: 30 * time.Second,
	})
	if !errors.Is(err, slaengine.ErrInvalidInput) {
		t.Fatalf("input error=%v", err)
	}
}

func TestSLARepositoryReadsAuthoritativeQueueMetrics(t *testing.T) {
	observedAt := time.Date(2026, time.August, 26, 8, 0, 0, 123_000, time.UTC)
	querier := &slaWorkerQuerierFake{
		queryRow: func(_ context.Context, query string, arguments ...any) pgx.Row {
			if !strings.Contains(query, "read_sla_evaluation_queue_metrics_v1") || len(arguments) != 0 {
				t.Fatalf("query=%q arguments=%#v", query, arguments)
			}
			return slaWorkerRowFake(func(destinations ...any) error {
				*destinations[0].(*time.Time) = observedAt
				*destinations[1].(*int64) = 7
				*destinations[2].(*int64) = 125_500_000
				return nil
			})
		},
	}
	metrics, err := NewSLARepository(querier).ReadQueueMetrics(context.Background())
	if err != nil || !metrics.ObservedAt.Equal(observedAt) || metrics.PendingJobs != 7 ||
		metrics.OldestPendingMicros != 125_500_000 {
		t.Fatalf("metrics=%#v error=%v", metrics, err)
	}
}

func TestSLARepositoryRejectsUnavailableOrContradictoryQueueMetrics(t *testing.T) {
	tests := []struct {
		name         string
		observedAt   time.Time
		pendingJobs  int64
		oldestMicros int64
		scanErr      error
	}{
		{name: "scan failure", scanErr: errors.New("tenant secret")},
		{name: "non microsecond time", observedAt: time.Date(2026, 8, 26, 8, 0, 0, 1, time.UTC), pendingJobs: 1},
		{name: "negative depth", observedAt: time.Date(2026, 8, 26, 8, 0, 0, 0, time.UTC), pendingJobs: -1},
		{name: "negative age", observedAt: time.Date(2026, 8, 26, 8, 0, 0, 0, time.UTC), pendingJobs: 1, oldestMicros: -1},
		{name: "empty with age", observedAt: time.Date(2026, 8, 26, 8, 0, 0, 0, time.UTC), oldestMicros: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			querier := &slaWorkerQuerierFake{queryRow: func(_ context.Context, _ string, _ ...any) pgx.Row {
				return slaWorkerRowFake(func(destinations ...any) error {
					if test.scanErr != nil {
						return test.scanErr
					}
					*destinations[0].(*time.Time) = test.observedAt
					*destinations[1].(*int64) = test.pendingJobs
					*destinations[2].(*int64) = test.oldestMicros
					return nil
				})
			}}
			_, err := NewSLARepository(querier).ReadQueueMetrics(context.Background())
			if !errors.Is(err, slaengine.ErrUnavailable) || strings.Contains(err.Error(), "secret") {
				t.Fatalf("error=%v", err)
			}
		})
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NewSLARepository(&slaWorkerQuerierFake{}).ReadQueueMetrics(canceled); !errors.Is(err, slaengine.ErrInvalidInput) {
		t.Fatalf("canceled input error=%v", err)
	}
}

func TestSLARepositoryFinalizeAndFailUseFencedABI(t *testing.T) {
	now := time.Date(2026, time.August, 26, 8, 0, 0, 0, time.UTC)
	plan := slaWorkerChangedPlan(t, now)
	instance := plan.Metrics()[0].Instance()
	workerID := slaWorkerTestUUID(31)
	jobID := slaWorkerTestEntity(30)
	querier := &slaWorkerQuerierFake{
		queryRow: func(_ context.Context, query string, arguments ...any) pgx.Row {
			switch {
			case strings.Contains(query, "finalize_sla_evaluation_job_v1"):
				if !strings.Contains(query, "app.traceparent") || len(arguments) != 10 ||
					arguments[0] != "" || arguments[1] != "" ||
					arguments[2] != workerID || arguments[7] != uint64(9) {
					t.Fatalf("finalize arguments=%#v", arguments)
				}
				if raw, ok := arguments[9].([]byte); !ok || !jsonHasSLAWorkerPlanShape(raw) {
					t.Fatalf("plan argument=%T", arguments[9])
				}
				return slaWorkerRowFake(func(destinations ...any) error {
					*destinations[0].(*int64) = 8
					return nil
				})
			case strings.Contains(query, "fail_sla_evaluation_job_v1"):
				if !strings.Contains(query, "app.traceparent") || len(arguments) != 11 ||
					arguments[0] != "" || arguments[1] != "" ||
					arguments[2] != workerID || arguments[5] != uint64(9) {
					t.Fatalf("fail arguments=%#v", arguments)
				}
				return slaWorkerRowFake(func(destinations ...any) error {
					*destinations[0].(*string) = "retry_scheduled"
					return nil
				})
			default:
				t.Fatalf("unexpected query=%q", query)
				return slaWorkerRowFake(func(...any) error { return errors.New("unexpected") })
			}
		},
	}
	repository := NewSLARepository(querier)
	identity := slaengine.Identity{WorkerID: workerID, Purpose: "sla-engine"}
	if err := repository.Finalize(context.Background(), slaengine.FinalizeRequest{
		Identity: identity, JobID: jobID, TenantID: uuid.UUID(instance.TenantID().Bytes()),
		SLAInstanceID: instance.SLAInstanceID(), ExpectedAggregateVersion: 7,
		Fence: 9, Plan: plan, CompletedAt: now.Add(time.Second),
	}); err != nil {
		t.Fatalf("Finalize() error=%v", err)
	}
	retryAt := now.Add(10 * time.Second)
	if err := repository.Fail(context.Background(), slaengine.FailureRequest{
		Identity: identity, JobID: jobID, TenantID: uuid.UUID(instance.TenantID().Bytes()),
		Fence: 9, Attempt: 1, Code: "evaluation_timeout", FailedAt: now,
		RetryAt: &retryAt,
	}); err != nil {
		t.Fatalf("Fail() error=%v", err)
	}

	foreign := slaengine.FinalizeRequest{
		Identity: identity, JobID: jobID, TenantID: slaWorkerTestUUID(99),
		SLAInstanceID: instance.SLAInstanceID(), ExpectedAggregateVersion: 7,
		Fence: 9, Plan: plan, CompletedAt: now.Add(time.Second),
	}
	if err := repository.Finalize(context.Background(), foreign); !errors.Is(err, slaengine.ErrInvalidInput) {
		t.Fatalf("foreign finalize error=%v", err)
	}
}

func slaWorkerChangedPlan(t *testing.T, now time.Time) kernel.EnginePlan {
	t.Helper()
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
	instance, changed, err := instance.ApplyEvent(instance.Version(), kernel.MetricEvent{
		ID: slaWorkerTestEntity(6), TenantID: instance.TenantID(), ObjectID: instance.ObjectID(),
		Key: metric.StartEvent(), OccurredAt: instance.CreatedAt(),
	}, nil)
	if err != nil || !changed {
		t.Fatalf("start changed=%t error=%v", changed, err)
	}
	plan, err := kernel.PlanEngineContext(context.Background(), kernel.EngineInput{
		ObservedAt: now, Metrics: []kernel.MetricWork{{Instance: instance}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func jsonHasSLAWorkerPlanShape(raw []byte) bool {
	var document slaWorkerPlanWrite
	return json.Unmarshal(raw, &document) == nil && len(document.Metrics) == 1
}

type slaWorkerQuerierFake struct {
	query    func(context.Context, string, ...any) (pgx.Rows, error)
	queryRow func(context.Context, string, ...any) pgx.Row
}

func (fake *slaWorkerQuerierFake) Query(ctx context.Context, query string, arguments ...any) (pgx.Rows, error) {
	if fake.query == nil {
		return nil, errors.New("unexpected query")
	}
	return fake.query(ctx, query, arguments...)
}

func (fake *slaWorkerQuerierFake) QueryRow(ctx context.Context, query string, arguments ...any) pgx.Row {
	if fake.queryRow == nil {
		return slaWorkerRowFake(func(...any) error { return errors.New("unexpected query row") })
	}
	return fake.queryRow(ctx, query, arguments...)
}

type slaWorkerRowFake func(...any) error

func (row slaWorkerRowFake) Scan(destinations ...any) error { return row(destinations...) }

type slaWorkerRowsFake struct {
	scan   func(...any) error
	served bool
	closed bool
	err    error
}

func (rows *slaWorkerRowsFake) Close()                                       { rows.closed = true }
func (rows *slaWorkerRowsFake) Err() error                                   { return rows.err }
func (rows *slaWorkerRowsFake) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (rows *slaWorkerRowsFake) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (rows *slaWorkerRowsFake) Next() bool {
	if rows.closed || rows.served {
		rows.closed = true
		return false
	}
	rows.served = true
	return true
}
func (rows *slaWorkerRowsFake) Scan(destinations ...any) error {
	if rows.scan == nil || !rows.served || rows.closed {
		return errors.New("invalid fake row scan")
	}
	return rows.scan(destinations...)
}
func (rows *slaWorkerRowsFake) Values() ([]any, error) { return nil, errors.New("not supported") }
func (rows *slaWorkerRowsFake) RawValues() [][]byte    { return nil }
func (rows *slaWorkerRowsFake) Conn() *pgx.Conn        { return nil }

var _ pgx.Rows = (*slaWorkerRowsFake)(nil)
var _ pgx.Row = slaWorkerRowFake(nil)
