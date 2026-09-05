package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	kernel "github.com/periapsis-im/periapsis/modules/sla"
	"github.com/periapsis-im/periapsis/services/worker/internal/slaaction"
)

func TestSLAActionRepositoryClaimsClosedFencedProjection(t *testing.T) {
	now := time.Date(2026, time.August, 30, 8, 0, 0, 0, time.UTC)
	workerID, tenantID := slaWorkerTestUUID(90), slaWorkerTestUUID(91)
	querier := &slaWorkerQuerierFake{query: func(_ context.Context, query string, arguments ...any) (pgx.Rows, error) {
		if !strings.Contains(query, "claim_sla_trigger_actions_v1") || !strings.Contains(query, "app.traceparent") ||
			len(arguments) != 7 || arguments[2] != workerID || arguments[3] != tenantID ||
			arguments[4] != now || arguments[5] != 2 || arguments[6] != int64(60_000_000) {
			t.Fatalf("query=%q arguments=%#v", query, arguments)
		}
		return &slaWorkerRowsFake{scan: func(destinations ...any) error {
			*destinations[0].(*uuid.UUID) = slaWorkerTestUUID(92)
			*destinations[1].(*uuid.UUID) = tenantID
			*destinations[2].(*uuid.UUID) = slaWorkerTestUUID(93)
			*destinations[3].(*uuid.UUID) = slaWorkerTestUUID(94)
			*destinations[4].(*uuid.UUID) = slaWorkerTestUUID(95)
			*destinations[5].(*string) = string(kernel.ActionCreateSystemAlert)
			*destinations[6].(*[]byte) = append([]byte{1, 2, 3}, make([]byte, 29)...)
			*destinations[7].(*int64) = 9
			*destinations[8].(*int32) = 2
			*destinations[9].(*time.Time) = now.Add(-time.Second)
			*destinations[10].(*time.Time) = now
			*destinations[11].(*time.Time) = now.Add(time.Minute)
			return nil
		}}, nil
	}}
	repository := NewSLAActionRepository(querier)
	claims, err := repository.Claim(context.Background(), slaaction.ClaimRequest{
		Identity: slaaction.Identity{WorkerID: workerID, Purpose: slaaction.WorkerPurpose},
		Queue:    slaaction.Queue{TenantID: tenantID}, Now: now, Limit: 2, LeaseDuration: time.Minute,
	})
	if err != nil || len(claims) != 1 || claims[0].ActionKind != kernel.ActionCreateSystemAlert ||
		claims[0].Fence != 9 || claims[0].Attempt != 2 || claims[0].DeduplicationDigest[0] != 1 {
		t.Fatalf("claims=%#v error=%v", claims, err)
	}
}

func TestSLAActionRepositoryExecutesExactOccurrenceBinding(t *testing.T) {
	now := time.Date(2026, time.August, 30, 8, 0, 0, 0, time.UTC)
	workerID, tenantID, occurrenceID := slaWorkerTestUUID(90), slaWorkerTestUUID(91), slaWorkerTestUUID(92)
	digest := [32]byte{1, 2, 3}
	querier := &slaWorkerQuerierFake{queryRow: func(_ context.Context, query string, arguments ...any) pgx.Row {
		if !strings.Contains(query, "execute_sla_trigger_action_v1") || !strings.Contains(query, "app.traceparent") ||
			len(arguments) != 9 || arguments[2] != workerID || arguments[3] != tenantID ||
			arguments[4] != occurrenceID || arguments[5] != uint64(7) ||
			arguments[7] != string(kernel.ActionEmail) || arguments[8] != now {
			t.Fatalf("query=%q arguments=%#v", query, arguments)
		}
		gotDigest, ok := arguments[6].([]byte)
		if !ok || string(gotDigest) != string(digest[:]) {
			t.Fatalf("digest=%T %#v", arguments[6], arguments[6])
		}
		return slaWorkerRowFake(func(destinations ...any) error {
			*destinations[0].(*string) = "replayed"
			return nil
		})
	}}
	result, err := NewSLAActionRepository(querier).Execute(context.Background(), slaaction.ExecuteRequest{
		Identity: slaaction.Identity{WorkerID: workerID, Purpose: slaaction.WorkerPurpose},
		Claim: slaaction.Claim{
			OccurrenceID: occurrenceID, TenantID: tenantID, ActionKind: kernel.ActionEmail,
			DeduplicationDigest: digest, Fence: 7,
		},
		AppliedAt: now,
	})
	if err != nil || result.Outcome != slaaction.OutcomeReplayed {
		t.Fatalf("result=%#v error=%v", result, err)
	}
}

func TestSLAActionRepositoryListsExplicitTenantQueuesAndMetrics(t *testing.T) {
	now := time.Date(2026, time.August, 30, 8, 0, 0, 0, time.UTC)
	tenantID := slaWorkerTestUUID(91)
	querier := &slaWorkerQuerierFake{
		query: func(_ context.Context, query string, arguments ...any) (pgx.Rows, error) {
			if !strings.Contains(query, "list_sla_trigger_action_queues_v1") || len(arguments) != 4 ||
				arguments[2] != now || arguments[3] != 25 {
				t.Fatalf("query=%q arguments=%#v", query, arguments)
			}
			return &slaWorkerRowsFake{scan: func(destinations ...any) error {
				*destinations[0].(*uuid.UUID) = tenantID
				return nil
			}}, nil
		},
		queryRow: func(_ context.Context, query string, arguments ...any) pgx.Row {
			if !strings.Contains(query, "read_sla_trigger_action_queue_metrics_v1") || len(arguments) != 0 {
				t.Fatalf("query=%q arguments=%#v", query, arguments)
			}
			return slaWorkerRowFake(func(destinations ...any) error {
				*destinations[0].(*time.Time) = now
				*destinations[1].(*int64) = 3
				*destinations[2].(*int64) = 9_000_000
				return nil
			})
		},
	}
	repository := NewSLAActionRepository(querier)
	queues, err := repository.ListQueues(context.Background(), now, 25)
	if err != nil || len(queues) != 1 || queues[0].TenantID != tenantID {
		t.Fatalf("queues=%#v error=%v", queues, err)
	}
	metrics, err := repository.ReadQueueMetrics(context.Background())
	if err != nil || metrics.PendingActions != 3 || metrics.OldestPendingMicros != 9_000_000 {
		t.Fatalf("metrics=%#v error=%v", metrics, err)
	}
}

func TestSLAActionRepositoryReadinessFailsClosed(t *testing.T) {
	for _, test := range []struct {
		name  string
		ready bool
		err   error
		want  error
	}{
		{name: "ready", ready: true},
		{name: "false", want: slaaction.ErrUnavailable},
		{name: "query failure", err: errors.New("private database detail"), want: slaaction.ErrUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			querier := &slaWorkerQuerierFake{queryRow: func(_ context.Context, query string, arguments ...any) pgx.Row {
				if query != slaActionReadinessQuery || len(arguments) != 0 {
					t.Fatalf("query=%q arguments=%#v", query, arguments)
				}
				return slaWorkerRowFake(func(destinations ...any) error {
					if test.err != nil {
						return test.err
					}
					*destinations[0].(*bool) = test.ready
					return nil
				})
			}}
			err := NewSLAActionRepository(querier).Ready(context.Background())
			if !errors.Is(err, test.want) || test.want == nil && err != nil {
				t.Fatalf("Ready() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestSLAActionRepositoryFailsClosedOnMalformedProjection(t *testing.T) {
	now := time.Date(2026, time.August, 30, 8, 0, 0, 0, time.UTC)
	workerID, tenantID := slaWorkerTestUUID(90), slaWorkerTestUUID(91)
	querier := &slaWorkerQuerierFake{query: func(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
		return &slaWorkerRowsFake{scan: func(destinations ...any) error {
			*destinations[0].(*uuid.UUID) = slaWorkerTestUUID(92)
			*destinations[1].(*uuid.UUID) = tenantID
			*destinations[2].(*uuid.UUID) = slaWorkerTestUUID(93)
			*destinations[3].(*uuid.UUID) = slaWorkerTestUUID(94)
			*destinations[4].(*uuid.UUID) = slaWorkerTestUUID(95)
			*destinations[5].(*string) = "secret_action"
			*destinations[6].(*[]byte) = []byte{1}
			return nil
		}}, nil
	}}
	_, err := NewSLAActionRepository(querier).Claim(context.Background(), slaaction.ClaimRequest{
		Identity: slaaction.Identity{WorkerID: workerID, Purpose: slaaction.WorkerPurpose},
		Queue:    slaaction.Queue{TenantID: tenantID}, Now: now, Limit: 1, LeaseDuration: time.Minute,
	})
	if !errors.Is(err, slaaction.ErrUnavailable) || strings.Contains(err.Error(), "secret") {
		t.Fatalf("error=%v", err)
	}
}
