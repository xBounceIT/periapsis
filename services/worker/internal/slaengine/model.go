package slaengine

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/sla"
)

var (
	ErrInvalidConfig = errors.New("invalid SLA worker configuration")
	ErrInvalidInput  = errors.New("invalid SLA worker input")
	ErrUnavailable   = errors.New("SLA worker unavailable")
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
	return fmt.Sprintf("slaengine.Identity{purpose:%s,identity:[REDACTED]}", identity.Purpose)
}
func (identity Identity) GoString() string { return identity.String() }

type Job struct {
	ID               kernel.EntityID
	TenantID         uuid.UUID
	ObjectType       kernel.ObjectType
	ObjectID         kernel.EntityID
	SLAInstanceID    kernel.EntityID
	AggregateVersion uint64
	Fence            uint64
	Attempt          uint16
	ObservedAt       time.Time
	LeaseExpiresAt   time.Time
	Metrics          []kernel.MetricWork
}

func (job Job) String() string {
	return fmt.Sprintf(
		"slaengine.Job{objectType:%s,attempt:%d,metrics:%d,identity:[REDACTED],lease:[REDACTED],values:[REDACTED]}",
		job.ObjectType, job.Attempt, len(job.Metrics),
	)
}
func (job Job) GoString() string { return job.String() }

type ClaimRequest struct {
	Identity      Identity
	Now           time.Time
	BatchSize     int
	LeaseDuration time.Duration
}

func (request ClaimRequest) String() string {
	return fmt.Sprintf(
		"slaengine.ClaimRequest{batchSize:%d,leaseDuration:%s,identity:[REDACTED]}",
		request.BatchSize, request.LeaseDuration,
	)
}
func (request ClaimRequest) GoString() string { return request.String() }

type FinalizeRequest struct {
	Identity                 Identity
	JobID                    kernel.EntityID
	TenantID                 uuid.UUID
	SLAInstanceID            kernel.EntityID
	ExpectedAggregateVersion uint64
	Fence                    uint64
	Plan                     kernel.EnginePlan
	CompletedAt              time.Time
}

func (request FinalizeRequest) String() string {
	return fmt.Sprintf(
		"slaengine.FinalizeRequest{expectedAggregateVersion:%d,metrics:%d,identity:[REDACTED],lease:[REDACTED],plan:[REDACTED]}",
		request.ExpectedAggregateVersion, len(request.Plan.Metrics()),
	)
}
func (request FinalizeRequest) GoString() string { return request.String() }

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

func (request FailureRequest) String() string {
	return fmt.Sprintf(
		"slaengine.FailureRequest{attempt:%d,code:%s,permanent:%t,identity:[REDACTED],lease:[REDACTED]}",
		request.Attempt, request.Code, request.Permanent,
	)
}
func (request FailureRequest) GoString() string { return request.String() }

type RunSummary struct {
	Claimed      int
	Completed    int
	Retryable    int
	DeadLettered int
}

func (summary RunSummary) String() string {
	return fmt.Sprintf(
		"slaengine.RunSummary{claimed:%d,completed:%d,retryable:%d,deadLettered:%d}",
		summary.Claimed, summary.Completed, summary.Retryable, summary.DeadLettered,
	)
}
func (summary RunSummary) GoString() string { return summary.String() }
