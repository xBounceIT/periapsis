package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"
)

const batchSize = 100

type queueCounts struct {
	Total          int64 `json:"total"`
	Queued         int64 `json:"queued"`
	Leased         int64 `json:"leased"`
	RetryScheduled int64 `json:"retryScheduled"`
	Completed      int64 `json:"completed"`
	DeadLettered   int64 `json:"deadLettered"`
}

func (queue queueCounts) empty() bool {
	return queue.Queued == 0 && queue.Leased == 0 && queue.RetryScheduled == 0 && queue.DeadLettered == 0
}

type counts struct {
	Claimed        int `json:"claimed"`
	Completed      int `json:"completed"`
	Replayed       int `json:"replayed"`
	RetryScheduled int `json:"retryScheduled"`
	DeadLettered   int `json:"deadLettered"`
	FenceLost      int `json:"fenceLost"`
}

type batchResult struct {
	counts
	Outcomes       map[string]int
	ReceiptsDigest string
}

type report struct {
	SchemaVersion int    `json:"schemaVersion"`
	Status        string `json:"status"`
	Mode          string `json:"mode,omitempty"`
	ErrorCode     string `json:"errorCode,omitempty"`
	Batches       int    `json:"batches"`
	counts
	DurationMS      int64          `json:"durationMs"`
	ProcessingMS    int64          `json:"processingMs"`
	QueueBefore     *queueCounts   `json:"queueBefore,omitempty"`
	QueueAfter      *queueCounts   `json:"queueAfter,omitempty"`
	SnapshotBefore  string         `json:"snapshotBefore,omitempty"`
	SnapshotAfter   string         `json:"snapshotAfter,omitempty"`
	SnapshotsStable bool           `json:"snapshotsStable"`
	ReceiptsDigest  string         `json:"receiptsDigest,omitempty"`
	Outcomes        map[string]int `json:"outcomes,omitempty"`
}

type backend interface {
	Queue(context.Context) (queueCounts, error)
	Snapshot(context.Context) (string, error)
	RunBatch(context.Context, int) (batchResult, error)
	Close()
}

func run(ctx context.Context, opts options, store backend) report {
	result := report{SchemaVersion: 1, Status: "failed", Mode: opts.Mode, Outcomes: make(map[string]int)}
	fail := func(code string) report {
		if ctx.Err() != nil {
			code = "canceled"
		}
		result.ErrorCode = code
		if after, err := store.Queue(ctx); err == nil {
			result.QueueAfter = &after
		}
		return result
	}
	before, err := store.Queue(ctx)
	if err != nil {
		return fail("queue_inspection")
	}
	result.QueueBefore = &before
	if opts.Mode == "ingress" {
		if before.DeadLettered != 0 || before.RetryScheduled != 0 || before.Leased != 0 {
			return fail("queue_not_clean")
		}
		result.SnapshotBefore, err = store.Snapshot(ctx)
		if err != nil {
			return fail("snapshot_inspection")
		}
	}
	receipts := sha256.New()
	queue := before
	for {
		if ctx.Err() != nil {
			return fail("canceled")
		}
		if opts.Mode == "ingress" && queue.empty() || opts.Mode == "timers" && result.Batches == opts.MaxBatches {
			break
		}
		remaining := opts.MaxEvents - result.Claimed
		if remaining <= 0 {
			return fail("event_limit")
		}
		size := min(batchSize, remaining)
		batchCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		started := time.Now()
		batch, batchErr := store.RunBatch(batchCtx, size)
		result.ProcessingMS += time.Since(started).Milliseconds()
		cancel()
		result.Batches++
		result.Claimed += batch.Claimed
		result.Completed += batch.Completed
		result.Replayed += batch.Replayed
		result.RetryScheduled += batch.RetryScheduled
		result.DeadLettered += batch.DeadLettered
		result.FenceLost += batch.FenceLost
		for outcome, count := range batch.Outcomes {
			result.Outcomes[outcome] += count
		}
		if batch.ReceiptsDigest != "" {
			_, _ = receipts.Write([]byte(batch.ReceiptsDigest))
			result.ReceiptsDigest = hex.EncodeToString(receipts.Sum(nil))
		}
		if batchErr != nil || batch.RetryScheduled != 0 || batch.DeadLettered != 0 || batch.FenceLost != 0 ||
			batch.Claimed != batch.Completed+batch.Replayed || batch.Claimed > size {
			return fail("worker_failed")
		}
		if batch.Claimed == 0 || opts.Mode == "timers" && batch.Claimed != batchSize {
			return fail("batch_incomplete")
		}
		if opts.Mode == "ingress" {
			queue, err = store.Queue(ctx)
			if err != nil {
				return fail("queue_inspection")
			}
		}
	}
	after, err := store.Queue(ctx)
	if err != nil {
		return fail("queue_inspection")
	}
	result.QueueAfter = &after
	if opts.Mode == "ingress" {
		if !after.empty() {
			return fail("queue_not_empty")
		}
		result.SnapshotAfter, err = store.Snapshot(ctx)
		if err != nil {
			return fail("snapshot_inspection")
		}
		result.SnapshotsStable = result.SnapshotBefore == result.SnapshotAfter
		if !result.SnapshotsStable {
			return fail("snapshot_changed")
		}
	}
	result.Status = "passed"
	return result
}
