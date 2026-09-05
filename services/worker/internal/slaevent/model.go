package slaevent

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/sla"
)

const WorkerPurpose = "sla-event-ingress"

var (
	ErrInvalidConfiguration = errors.New("invalid SLA event worker configuration")
	ErrInvalidInput         = errors.New("invalid SLA event worker input")
	ErrInvalidProjection    = errors.New("invalid SLA event projection")
	ErrUnavailable          = errors.New("SLA event worker unavailable")
	ErrFenceLost            = errors.New("SLA event worker fence lost")
)

type Config struct {
	BatchSize         int
	LeaseDuration     time.Duration
	OperationTimeout  time.Duration
	RunTimeout        time.Duration
	MaximumAttempts   uint16
	RetryBaseDelay    time.Duration
	RetryMaximumDelay time.Duration
}

type Identity struct {
	WorkerID uuid.UUID
	Purpose  string
}

func (identity Identity) String() string {
	return fmt.Sprintf("slaevent.Identity{purpose:%s,identity:[REDACTED]}", identity.Purpose)
}

func (identity Identity) GoString() string { return identity.String() }

// Job is one fenced, ordered domain event plus the exact state projection that
// was read under its claim. The initial assignment projection is frozen when
// the source outbox row is inserted; an existing aggregate projection contains
// only immutable pinned definitions and its current runtime state.
type Job struct {
	ID                kernel.EntityID
	TenantID          uuid.UUID
	ObjectType        kernel.ObjectType
	ObjectID          kernel.EntityID
	Sequence          uint64
	SourceEventID     kernel.EntityID
	SourceDigest      [sha256.Size]byte
	Event             kernel.MetricEvent
	State             kernel.ObjectEventState
	SLAInstanceID     *kernel.EntityID
	PolicyID          *kernel.EntityID
	PolicyVersion     uint64
	Fence             uint64
	Attempt           uint16
	ClaimedAt         time.Time
	LeaseExpiresAt    time.Time
	InvalidProjection bool
}

func (job Job) String() string {
	return fmt.Sprintf(
		"slaevent.Job{objectType:%s,sequence:%d,attempt:%d,mode:%s,invalid:%t,identity:[REDACTED],payload:[REDACTED]}",
		job.ObjectType, job.Sequence, job.Attempt, job.State.Mode, job.InvalidProjection,
	)
}

func (job Job) GoString() string { return job.String() }

type ClaimRequest struct {
	Identity      Identity
	Now           time.Time
	BatchSize     int
	LeaseDuration time.Duration
}

type EventOutcome string

const (
	OutcomeNoPolicy EventOutcome = "no_policy"
	OutcomeAssigned EventOutcome = "assigned"
	OutcomeUpdated  EventOutcome = "updated"
)

type CommitRequest struct {
	Identity    Identity
	Job         Job
	Plan        kernel.ObjectEventPlan
	CompletedAt time.Time
}

type CommitResult struct {
	Outcome          EventOutcome
	SLAInstanceID    *kernel.EntityID
	AggregateVersion uint64
	Replayed         bool
}

type FailureRequest struct {
	Identity  Identity
	JobID     kernel.EntityID
	TenantID  uuid.UUID
	Fence     uint64
	Attempt   uint16
	Code      string
	Permanent bool
	FailedAt  time.Time
	RetryAt   *time.Time
}

type RunSummary struct {
	Claimed        int
	Applied        int
	Replayed       int
	RetryScheduled int
	DeadLettered   int
	FenceLost      int
}

func (summary RunSummary) String() string {
	return fmt.Sprintf(
		"slaevent.RunSummary{claimed:%d,applied:%d,replayed:%d,retryScheduled:%d,deadLettered:%d,fenceLost:%d}",
		summary.Claimed, summary.Applied, summary.Replayed, summary.RetryScheduled,
		summary.DeadLettered, summary.FenceLost,
	)
}

func (summary RunSummary) GoString() string { return summary.String() }

type QueueMetrics struct {
	ObservedAt          time.Time
	PendingEvents       int64
	ReclaimableEvents   int64
	DeadLetteredEvents  int64
	OldestPendingMicros int64
}
