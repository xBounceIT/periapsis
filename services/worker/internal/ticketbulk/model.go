// Package ticketbulk orchestrates bounded, fenced ticket bulk-mutation batches.
//
// Persistence owns target materialization, live authorization, RLS, mutation,
// audit, outbox, and progress accounting. This package only coordinates the
// closed port protocol and never accepts SQL, raw authorization snapshots, or
// customer data.
package ticketbulk

import (
	"errors"
	"fmt"
	"reflect"
	"time"

	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
)

const (
	WorkerPurpose      = "ticket_bulk"
	MaximumBatchSize   = 100
	MinimumLease       = 30 * time.Second
	MaximumLease       = 15 * time.Minute
	MinimumRetry       = time.Second
	MaximumRetry       = time.Hour
	maximumClockSkew   = time.Second
	minimumOperation   = 100 * time.Millisecond
	maximumOperation   = 5 * time.Minute
	maximumLeaseSafety = time.Minute
)

var (
	ErrInvalidConfiguration     = errors.New("ticket bulk worker configuration is invalid")
	ErrInvalidInput             = errors.New("ticket bulk worker input is invalid")
	ErrInvalidProjection        = errors.New("ticket bulk repository projection is invalid")
	ErrUnavailable              = errors.New("ticket bulk dependency is unavailable")
	ErrFenceLost                = errors.New("ticket bulk batch fence was lost")
	ErrInterrupted              = errors.New("ticket bulk batch was interrupted")
	ErrTransitionOutcomeUnknown = errors.New("ticket bulk transition outcome is unknown")
)

type Identity struct {
	ServiceAccountID kernel.EntityID
	WorkerID         kernel.EntityID
	Purpose          string
}

func (identity Identity) String() string {
	return "ticketbulk.Identity{identity:[REDACTED],purpose:[REDACTED]}"
}

func (identity Identity) GoString() string { return identity.String() }

// Queue is one explicit tenant and ticket-kind boundary. A worker never scans
// a global queue without a server-selected tenant.
type Queue struct {
	TenantID kernel.EntityID
	Kind     kernel.AggregateKind
}

func (queue Queue) String() string {
	return fmt.Sprintf("ticketbulk.Queue{kind:%s,tenant:[REDACTED]}", queue.Kind)
}

func (queue Queue) GoString() string { return queue.String() }

type Options struct {
	Repository       Repository
	Identity         Identity
	BatchSize        int
	LeaseDuration    time.Duration
	AttemptTimeout   time.Duration
	OperationTimeout time.Duration
	LeaseSafety      time.Duration
	RetryBase        time.Duration
	RetryMaximum     time.Duration
	Clock            func() time.Time
}

func (options Options) String() string {
	return "ticketbulk.Options{dependencies:[REDACTED],identity:[REDACTED],configuration:[REDACTED]}"
}

func (options Options) GoString() string { return options.String() }

type Outcome uint8

const (
	OutcomeUnknown Outcome = iota
	OutcomeIdle
	OutcomeBatchReleased
	OutcomeJobCompleted
	OutcomeRetryScheduled
	OutcomeBatchTerminalized
	OutcomeJobFailed
	OutcomeCancelled
	OutcomeAuthorizationRevoked
	OutcomeFenceLost
	OutcomeInterrupted
)

func (outcome Outcome) String() string {
	switch outcome {
	case OutcomeUnknown:
		return "unknown"
	case OutcomeIdle:
		return "idle"
	case OutcomeBatchReleased:
		return "batch_released"
	case OutcomeJobCompleted:
		return "job_completed"
	case OutcomeRetryScheduled:
		return "retry_scheduled"
	case OutcomeBatchTerminalized:
		return "batch_terminalized"
	case OutcomeJobFailed:
		return "job_failed"
	case OutcomeCancelled:
		return "cancelled"
	case OutcomeAuthorizationRevoked:
		return "authorization_revoked"
	case OutcomeFenceLost:
		return "fence_lost"
	case OutcomeInterrupted:
		return "interrupted"
	default:
		return "unknown"
	}
}

type Result struct {
	Claimed   bool
	Outcome   Outcome
	Processed uint32
	Failure   BatchFailureCode
	Progress  *kernel.TicketBulkProgressSnapshot
}

func (result Result) String() string {
	processed, total := uint32(0), uint32(0)
	if result.Progress != nil {
		processed = processedTicketBulkSnapshot(*result.Progress)
		total = result.Progress.Total
	}
	return fmt.Sprintf(
		"ticketbulk.Result{claimed:%t,outcome:%s,batch_processed:%d,job_processed:%d,job_total:%d,failure:%s,metadata:[REDACTED]}",
		result.Claimed, result.Outcome, result.Processed, processed, total, result.Failure,
	)
}

func (result Result) GoString() string { return result.String() }

type BatchFailureCode uint8

const (
	BatchFailureNone BatchFailureCode = iota
	BatchFailureTransientDatabase
	BatchFailureInvalidProjection
	BatchFailureLeaseSafety
	BatchFailureInterrupted
	BatchFailureInternal
)

func (code BatchFailureCode) String() string {
	switch code {
	case BatchFailureNone:
		return "none"
	case BatchFailureTransientDatabase:
		return "transient_database"
	case BatchFailureInvalidProjection:
		return "invalid_projection"
	case BatchFailureLeaseSafety:
		return "lease_safety"
	case BatchFailureInterrupted:
		return "interrupted"
	case BatchFailureInternal:
		return "internal"
	default:
		return "unknown"
	}
}

func validBatchFailureCode(code BatchFailureCode) bool {
	return code >= BatchFailureTransientDatabase && code <= BatchFailureInternal
}

func retryableBatchFailureCode(code BatchFailureCode) bool {
	return code == BatchFailureTransientDatabase || code == BatchFailureLeaseSafety ||
		code == BatchFailureInterrupted || code == BatchFailureInternal
}

func validEntityID(id kernel.EntityID) bool {
	rebuilt, err := kernel.NewEntityID(id.Bytes())
	return err == nil && rebuilt == id
}

func validIdentity(identity Identity) bool {
	return validEntityID(identity.ServiceAccountID) && validEntityID(identity.WorkerID) &&
		identity.Purpose == WorkerPurpose
}

func validQueue(queue Queue) bool {
	return validEntityID(queue.TenantID) &&
		(queue.Kind == kernel.AggregateAlert || queue.Kind == kernel.AggregateCase)
}

func validInstant(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Year() >= 1970 && value.Year() <= 9999 &&
		value.Nanosecond()%1_000 == 0
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func processedTicketBulkSnapshot(snapshot kernel.TicketBulkProgressSnapshot) uint32 {
	progress, err := kernel.RestoreTicketBulkProgress(snapshot)
	if err != nil {
		return 0
	}
	return progress.Processed()
}
