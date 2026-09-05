package slaengine

import "context"

// Repository owns worker-role claim authority. Claim must use SKIP LOCKED and
// create a new lease fence. Finalize and Fail compare job, tenant, worker, and
// fence; stale workers must never update a later claim. Finalize persists
// metric state, cursors, occurrences, materialized columns, audit/outbox, and
// the next evaluation atomically.
type Repository interface {
	Claim(context.Context, ClaimRequest) ([]Job, error)
	Finalize(context.Context, FinalizeRequest) error
	Fail(context.Context, FailureRequest) error
}
