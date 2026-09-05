package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

type fakeBackend struct {
	queues    []queueCounts
	snapshots []string
	batches   []batchResult
	batchErr  error
	sizes     []int
	closed    bool
}

func (fake *fakeBackend) Queue(context.Context) (queueCounts, error) {
	if len(fake.queues) == 0 {
		return queueCounts{}, nil
	}
	queue := fake.queues[0]
	if len(fake.queues) > 1 {
		fake.queues = fake.queues[1:]
	}
	return queue, nil
}

func (fake *fakeBackend) Snapshot(context.Context) (string, error) {
	if len(fake.snapshots) == 0 {
		return "stable", nil
	}
	value := fake.snapshots[0]
	if len(fake.snapshots) > 1 {
		fake.snapshots = fake.snapshots[1:]
	}
	return value, nil
}

func (fake *fakeBackend) RunBatch(_ context.Context, size int) (batchResult, error) {
	fake.sizes = append(fake.sizes, size)
	if len(fake.batches) == 0 {
		return batchResult{}, fake.batchErr
	}
	value := fake.batches[0]
	fake.batches = fake.batches[1:]
	return value, fake.batchErr
}

func (fake *fakeBackend) Close() { fake.closed = true }

func TestIngressDrainRequiresImmutableSnapshotsAndEmptyWholeQueue(t *testing.T) {
	store := &fakeBackend{
		queues: []queueCounts{{Total: 2, Queued: 2}, {Total: 2, Completed: 2}},
		batches: []batchResult{{counts: counts{Claimed: 2, Completed: 1, Replayed: 1},
			Outcomes: map[string]int{"case/unassigned/assigned": 2}, ReceiptsDigest: strings.Repeat("a", 64)}},
	}
	result := run(context.Background(), options{Mode: "ingress", MaxEvents: 500000}, store)
	if result.Status != "passed" || result.Completed != 1 || result.Replayed != 1 || !result.SnapshotsStable ||
		result.Batches != 1 || result.QueueAfter == nil || !result.QueueAfter.empty() || len(result.ReceiptsDigest) != 64 {
		t.Fatalf("drain report=%+v", result)
	}
	if result.Outcomes["case/unassigned/assigned"] != 2 {
		t.Fatal("lost committed outcomes")
	}
}

func TestIngressDrainHonorsExactEventCeilingBeforeNextClaim(t *testing.T) {
	store := &fakeBackend{
		queues:  []queueCounts{{Total: 101, Queued: 101}, {Total: 101, Queued: 1, Completed: 100}, {Total: 101, Completed: 101}},
		batches: []batchResult{{counts: counts{Claimed: 100, Completed: 100}}, {counts: counts{Claimed: 1, Completed: 1}}},
	}
	result := run(context.Background(), options{Mode: "ingress", MaxEvents: 101}, store)
	if result.Status != "passed" || len(store.sizes) != 2 || store.sizes[0] != 100 || store.sizes[1] != 1 {
		t.Fatalf("event bound report=%+v sizes=%v", result, store.sizes)
	}
	blocked := &fakeBackend{queues: []queueCounts{{Queued: 101}, {Queued: 1}}, batches: []batchResult{{counts: counts{Claimed: 100, Completed: 100}}}}
	result = run(context.Background(), options{Mode: "ingress", MaxEvents: 100}, blocked)
	if result.ErrorCode != "event_limit" || len(blocked.sizes) != 1 {
		t.Fatalf("event cap=%+v", result)
	}
}

func TestIngressDrainDoesNotHideRetryLeaseDeadletterOrSnapshotDrift(t *testing.T) {
	for _, test := range []struct {
		name  string
		queue queueCounts
	}{
		{"retry", queueCounts{RetryScheduled: 1}},
		{"lease", queueCounts{Leased: 1}},
		{"deadletter", queueCounts{DeadLettered: 1}},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &fakeBackend{queues: []queueCounts{test.queue}}
			result := run(context.Background(), options{Mode: "ingress", MaxEvents: 100}, store)
			if result.ErrorCode != "queue_not_clean" || len(store.sizes) != 0 {
				t.Fatalf("unclean queue=%+v", result)
			}
		})
	}
	store := &fakeBackend{snapshots: []string{"before", "after"}}
	result := run(context.Background(), options{Mode: "ingress", MaxEvents: 100}, store)
	if result.ErrorCode != "snapshot_changed" || result.SnapshotsStable {
		t.Fatalf("snapshot drift=%+v", result)
	}
	stalled := &fakeBackend{queues: []queueCounts{{Queued: 1}}}
	result = run(context.Background(), options{Mode: "ingress", MaxEvents: 100}, stalled)
	if result.ErrorCode != "batch_incomplete" {
		t.Fatalf("stalled stream=%+v", result)
	}
}

func TestTimerSampleCountsOnlyItsOwnCommittedWorkAcrossConcurrentQueues(t *testing.T) {
	store := &fakeBackend{
		queues:  []queueCounts{{Queued: 500, Leased: 100}, {Queued: 800, Leased: 200, Completed: 100}},
		batches: []batchResult{{counts: counts{Claimed: 100, Completed: 100}, Outcomes: map[string]int{"timer_completed": 100}}},
	}
	result := run(context.Background(), options{Mode: "timers", MaxEvents: 100, MaxBatches: 1}, store)
	if result.Status != "passed" || result.Completed != 100 || result.Batches != 1 || len(store.sizes) != 1 {
		t.Fatalf("concurrent timer sample=%+v", result)
	}
	if result.SnapshotBefore != "" || result.SnapshotAfter != "" {
		t.Fatal("timer run checked a global ingress snapshot")
	}
}

func TestTimerSampleRejectsIncompleteOrFailedBatchesWithoutHidingCommittedCounts(t *testing.T) {
	for _, test := range []struct {
		name  string
		batch batchResult
		err   error
		want  string
	}{
		{"short", batchResult{counts: counts{Claimed: 99, Completed: 99}}, nil, "batch_incomplete"},
		{"partial failure", batchResult{counts: counts{Claimed: 100, Completed: 3}}, errors.New("private SQL and connection details"), "worker_failed"},
		{"retry", batchResult{counts: counts{Claimed: 100, Completed: 99, RetryScheduled: 1}}, nil, "worker_failed"},
		{"deadletter", batchResult{counts: counts{Claimed: 100, Completed: 99, DeadLettered: 1}}, nil, "worker_failed"},
		{"fence", batchResult{counts: counts{Claimed: 100, Completed: 99, FenceLost: 1}}, nil, "worker_failed"},
		{"oversized", batchResult{counts: counts{Claimed: 101, Completed: 101}}, nil, "worker_failed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &fakeBackend{batches: []batchResult{test.batch}, batchErr: test.err}
			result := run(context.Background(), options{Mode: "timers", MaxEvents: 100, MaxBatches: 1}, store)
			if result.ErrorCode != test.want || result.Completed != test.batch.Completed || result.Status == "passed" {
				t.Fatalf("failed batch=%+v", result)
			}
			raw, err := json.Marshal(result)
			if err != nil || strings.Contains(string(raw), "private") || strings.Contains(string(raw), "SQL") {
				t.Fatal("failure report exposed untrusted error details")
			}
		})
	}
}

func TestCanceledDrainNeverStartsAnotherBatch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	store := &fakeBackend{queues: []queueCounts{{Queued: 1}}}
	result := run(ctx, options{Mode: "ingress", MaxEvents: 100}, store)
	if result.ErrorCode != "canceled" || len(store.sizes) != 0 {
		t.Fatalf("cancellation report=%+v", result)
	}
}
