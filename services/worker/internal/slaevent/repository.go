package slaevent

import "context"

// Repository owns the worker-only SLA event ingress ABI. Claim must serialize
// one object stream, use SKIP LOCKED, and issue a new fence. Commit verifies the
// exact source digest and fence, applies the plan, appends the immutable event
// ledger/audit/outbox receipt, and schedules the next timer in one transaction.
// Fail is fence-bound and records retry or dead-letter evidence atomically.
type Repository interface {
	Ready(context.Context) error
	Claim(context.Context, ClaimRequest) ([]Job, error)
	Commit(context.Context, CommitRequest) (CommitResult, error)
	Fail(context.Context, FailureRequest) error
	ReadQueueMetrics(context.Context) (QueueMetrics, error)
}
