package slaaction

import (
	"context"
	"fmt"
	"time"
)

// Repository methods are closed PostgreSQL-function calls. Claim must select
// only due occurrences for the explicit tenant with SKIP LOCKED and establish
// a monotonically increasing fence. Execute must atomically re-read the
// immutable occurrence, compare tenant/worker/fence/digest, apply exactly one
// action effect, append domain activity and tamper-evident audit, enqueue any
// notification/webhook through the transactional outbox, and persist a replay
// receipt before returning.
type Repository interface {
	Claim(context.Context, ClaimRequest) ([]Claim, error)
	Execute(context.Context, ExecuteRequest) (ExecuteResult, error)
}

type ClaimRequest struct {
	Identity      Identity
	Queue         Queue
	Now           time.Time
	LeaseDuration time.Duration
	Limit         int
}

func (request ClaimRequest) String() string {
	return fmt.Sprintf(
		"slaaction.ClaimRequest{queue:%s,limit:%d,lease_duration:%s,identity:[REDACTED],time:[REDACTED]}",
		request.Queue, request.Limit, request.LeaseDuration,
	)
}

func (request ClaimRequest) GoString() string { return request.String() }

type ExecuteRequest struct {
	Identity  Identity
	Claim     Claim
	AppliedAt time.Time
}

func (request ExecuteRequest) String() string {
	return fmt.Sprintf(
		"slaaction.ExecuteRequest{claim:%s,identity:[REDACTED],time:[REDACTED]}",
		request.Claim,
	)
}

func (request ExecuteRequest) GoString() string { return request.String() }

type ExecuteResult struct {
	Outcome Outcome
}

func (result ExecuteResult) String() string {
	return fmt.Sprintf("slaaction.ExecuteResult{outcome:%s}", result.Outcome)
}
func (result ExecuteResult) GoString() string { return result.String() }
