// Package ticketexport orchestrates bounded, fenced ticket export attempts.
//
// Persistence and production storage client construction remain outside this
// package. Its ports deliberately carry no SQL, bucket, object-key, credential,
// or presigned-URL fields; the concrete S3 session keeps those behind the port.
package ticketexport

import (
	"errors"
	"fmt"
	"reflect"
	"time"

	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
)

const (
	WorkerPurpose          = "ticket_export"
	MaximumPageSize        = 1_000
	MaximumPageBytes       = 4 * 1024 * 1024
	MaximumCursorBytes     = 512
	maximumCleanupAttempts = 3
)

var (
	ErrInvalidConfiguration      = errors.New("ticket export worker configuration is invalid")
	ErrInvalidInput              = errors.New("ticket export worker input is invalid")
	ErrInvalidProjection         = errors.New("ticket export repository projection is invalid")
	ErrUnavailable               = errors.New("ticket export dependency is unavailable")
	ErrFenceLost                 = errors.New("ticket export lease fence was lost")
	ErrInterrupted               = errors.New("ticket export attempt was interrupted")
	ErrPublicationOutcomeUnknown = errors.New("ticket export publication outcome is unknown")
	ErrCommitOutcomeUnknown      = errors.New("ticket export commit outcome is unknown")
	ErrTransitionOutcomeUnknown  = errors.New("ticket export transition outcome is unknown")
	ErrCleanupPending            = errors.New("ticket export artifact cleanup is pending")
	ErrArtifactConflict          = errors.New("ticket export artifact does not match its durable manifest")
)

// Identity is the least-privileged worker principal. Adapters must resolve the
// service purpose again inside every tenant transaction.
type Identity struct {
	ServiceAccountID kernel.EntityID
	WorkerID         kernel.EntityID
	Purpose          string
}

func (identity Identity) String() string {
	return "ticketexport.Identity{identity:[REDACTED],purpose:[REDACTED]}"
}

func (identity Identity) GoString() string { return identity.String() }

// Queue is one explicit tenant/kind/audience claim boundary. RunOnce never
// performs an unscoped cross-tenant scan.
type Queue struct {
	TenantID kernel.EntityID
	Kind     kernel.AggregateKind
	Audience kernel.TicketExportAudience
}

func (queue Queue) String() string {
	return fmt.Sprintf(
		"ticketexport.Queue{kind:%s,audience:%s,tenant:[REDACTED]}",
		queue.Kind, queue.Audience,
	)
}

func (queue Queue) GoString() string { return queue.String() }

type Options struct {
	Repository       Repository
	Artifacts        ArtifactStore
	Identity         Identity
	PageSize         int
	LeaseDuration    time.Duration
	AttemptTimeout   time.Duration
	OperationTimeout time.Duration
	LeaseSafety      time.Duration
	CleanupTimeout   time.Duration
	CleanupAttempts  int
	RetryBase        time.Duration
	RetryMaximum     time.Duration
	Clock            func() time.Time
	NewArtifactID    func() (kernel.EntityID, error)
}

func (options Options) String() string {
	return "ticketexport.Options{dependencies:[REDACTED],identity:[REDACTED],configuration:[REDACTED]}"
}

func (options Options) GoString() string { return options.String() }

type Outcome uint8

const (
	OutcomeUnknown Outcome = iota
	OutcomeIdle
	OutcomeSucceeded
	OutcomeRetryScheduled
	OutcomeFailed
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
	case OutcomeSucceeded:
		return "succeeded"
	case OutcomeRetryScheduled:
		return "retry_scheduled"
	case OutcomeFailed:
		return "failed"
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
	Claimed     bool
	Outcome     Outcome
	Rows        uint32
	Bytes       uint64
	FailureCode kernel.TicketExportFailureCode
}

func (result Result) String() string {
	return fmt.Sprintf(
		"ticketexport.Result{claimed:%t,outcome:%s,rows:%d,bytes:%d,failure:%s}",
		result.Claimed, result.Outcome, result.Rows, result.Bytes, result.FailureCode,
	)
}

func (result Result) GoString() string { return result.String() }

func validEntityID(id kernel.EntityID) bool {
	rebuilt, err := kernel.NewEntityID(id.Bytes())
	return err == nil && rebuilt == id
}

func validQueue(queue Queue) bool {
	return validEntityID(queue.TenantID) &&
		(queue.Kind == kernel.AggregateAlert || queue.Kind == kernel.AggregateCase) &&
		(queue.Audience == kernel.TicketExportAudienceOperator ||
			queue.Audience == kernel.TicketExportAudienceCustomer)
}

func validIdentity(identity Identity) bool {
	return validEntityID(identity.ServiceAccountID) && validEntityID(identity.WorkerID) &&
		identity.Purpose == WorkerPurpose
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
