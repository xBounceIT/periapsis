// Package slaaction coordinates execution of immutable SLA trigger occurrences.
//
// The database owns tenant isolation, action-specific authorization, effect
// idempotency, audit, outbox emission, and lease fencing. This package only
// validates the closed projection and drives the bounded worker protocol.
package slaaction

import (
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/sla"
)

const (
	WorkerPurpose      = "sla-action"
	MaximumBatchSize   = 100
	MinimumLease       = 30 * time.Second
	MaximumLease       = 15 * time.Minute
	MinimumOperation   = 100 * time.Millisecond
	MaximumOperation   = 5 * time.Minute
	MinimumLeaseSafety = time.Second
	MaximumLeaseSafety = time.Minute
)

var (
	ErrInvalidConfiguration     = errors.New("SLA action worker configuration is invalid")
	ErrInvalidInput             = errors.New("SLA action worker input is invalid")
	ErrInvalidProjection        = errors.New("SLA action repository projection is invalid")
	ErrUnavailable              = errors.New("SLA action dependency is unavailable")
	ErrInterrupted              = errors.New("SLA action execution was interrupted")
	ErrTransitionOutcomeUnknown = errors.New("SLA action transition outcome is unknown")
)

type Identity struct {
	WorkerID uuid.UUID
	Purpose  string
}

func (identity Identity) String() string {
	return "slaaction.Identity{identity:[REDACTED],purpose:[REDACTED]}"
}

func (identity Identity) GoString() string { return identity.String() }

type Options struct {
	Repository       Repository
	Identity         Identity
	BatchSize        int
	LeaseDuration    time.Duration
	OperationTimeout time.Duration
	LeaseSafety      time.Duration
	Clock            func() time.Time
}

func (options Options) String() string {
	return "slaaction.Options{dependencies:[REDACTED],identity:[REDACTED],configuration:[REDACTED]}"
}

func (options Options) GoString() string { return options.String() }

type Queue struct {
	TenantID uuid.UUID
}

func (queue Queue) String() string   { return "slaaction.Queue{tenant:[REDACTED]}" }
func (queue Queue) GoString() string { return queue.String() }

type Claim struct {
	OccurrenceID        uuid.UUID
	TenantID            uuid.UUID
	SLAInstanceID       uuid.UUID
	MetricInstanceID    uuid.UUID
	TriggerDefinitionID uuid.UUID
	ActionKind          kernel.ActionKind
	DeduplicationDigest [32]byte
	Fence               uint64
	Attempt             uint16
	ScheduledAt         time.Time
	ClaimedAt           time.Time
	LeaseExpiresAt      time.Time
}

func (claim Claim) String() string {
	return fmt.Sprintf(
		"slaaction.Claim{action:%s,attempt:%d,fence:%d,identity:[REDACTED],digest:[REDACTED],times:[REDACTED]}",
		claim.ActionKind, claim.Attempt, claim.Fence,
	)
}

func (claim Claim) GoString() string { return claim.String() }

type Outcome uint8

const (
	OutcomeUnknown Outcome = iota
	OutcomeIdle
	OutcomeApplied
	OutcomeReplayed
	OutcomeRetryScheduled
	OutcomeDeadLettered
	OutcomeFenceLost
	OutcomeInterrupted
)

func (outcome Outcome) String() string {
	switch outcome {
	case OutcomeIdle:
		return "idle"
	case OutcomeApplied:
		return "applied"
	case OutcomeReplayed:
		return "replayed"
	case OutcomeRetryScheduled:
		return "retry_scheduled"
	case OutcomeDeadLettered:
		return "dead_lettered"
	case OutcomeFenceLost:
		return "fence_lost"
	case OutcomeInterrupted:
		return "interrupted"
	default:
		return "unknown"
	}
}

type Summary struct {
	Claimed        int
	Applied        int
	Replayed       int
	RetryScheduled int
	DeadLettered   int
	FenceLost      int
}

func (summary Summary) String() string {
	return fmt.Sprintf(
		"slaaction.Summary{claimed:%d,applied:%d,replayed:%d,retry_scheduled:%d,dead_lettered:%d,fence_lost:%d}",
		summary.Claimed, summary.Applied, summary.Replayed, summary.RetryScheduled,
		summary.DeadLettered, summary.FenceLost,
	)
}

func (summary Summary) GoString() string { return summary.String() }

func validIdentity(identity Identity) bool {
	return validUUIDv7(identity.WorkerID) && identity.Purpose == WorkerPurpose
}

func validQueue(queue Queue) bool { return validUUIDv7(queue.TenantID) }

func validUUIDv7(value uuid.UUID) bool {
	return value != uuid.Nil && value.Version() == 7 && value.Variant() == uuid.RFC4122
}

func validInstant(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Year() >= 1970 && value.Year() <= 9999 &&
		value.Nanosecond()%1_000 == 0
}

func validActionKind(kind kernel.ActionKind) bool {
	switch kind {
	case kernel.ActionEmail, kernel.ActionWebhook, kernel.ActionAddTag, kernel.ActionChangePriority,
		kernel.ActionAssignTeam, kernel.ActionCreateTask, kernel.ActionCreateSystemAlert, kernel.ActionDomainEvent:
		return true
	default:
		return false
	}
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
