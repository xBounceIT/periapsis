package ticketbulk

import (
	"context"
	"fmt"
	"time"

	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
)

// Repository implementations own application authorization and RLS in every
// call. ClaimBatch may claim only pending targets inside the supplied tenant
// and kind. ApplyTarget atomically rechecks the original human requester's live
// authority, applies the direct-path mutation, stores one terminal target
// result, increments progress, appends audit/outbox, and CASes the exact fence.
// Release and control finalizers must re-derive counts from target rows. Claim
// progress is the transactionally observed baseline before any returned target
// is accounted; every returned target is unaccounted at that baseline. A replay
// disposition therefore identifies a result committed after that baseline and
// still contributes exactly once to the returned progress floor.
type Repository interface {
	ClaimBatch(context.Context, ClaimRequest) (Claim, bool, error)
	ApplyTarget(context.Context, ApplyTargetRequest) (ApplyTargetResult, error)
	ReleaseBatch(context.Context, ReleaseBatchRequest) (ReleaseBatchResult, error)
	ReportBatchFailure(context.Context, BatchFailureRequest) (BatchFailureResult, error)
	FinalizeCancellation(context.Context, ControlFinalizationRequest) (ControlFinalizationResult, error)
	FinalizeAuthorizationRevocation(context.Context, ControlFinalizationRequest) (ControlFinalizationResult, error)
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
		"ticketbulk.ClaimRequest{queue:%s,limit:%d,lease_duration:%s,identity:[REDACTED],time:[REDACTED]}",
		request.Queue, request.Limit, request.LeaseDuration,
	)
}

func (request ClaimRequest) GoString() string { return request.String() }

type BatchBinding struct {
	TenantID          kernel.EntityID
	JobID             kernel.EntityID
	BatchID           kernel.EntityID
	Kind              kernel.AggregateKind
	WorkerID          kernel.EntityID
	Revision          uint64
	Attempt           uint8
	Fence             [32]byte
	TargetSetDigest   [32]byte
	ProjectionVersion uint64
	ClaimedAt         time.Time
	LeaseExpiresAt    time.Time
	JobExpiresAt      time.Time
}

func (binding BatchBinding) String() string {
	return fmt.Sprintf(
		"ticketbulk.BatchBinding{kind:%s,revision:%d,attempt:%d,identity:[REDACTED],fence:[REDACTED],digest:[REDACTED],times:[REDACTED]}",
		binding.Kind, binding.Revision, binding.Attempt,
	)
}

func (binding BatchBinding) GoString() string { return binding.String() }

type ClaimedTarget struct {
	Sequence uint32
	Pin      kernel.TicketBulkTargetPin
}

func (target ClaimedTarget) String() string {
	return fmt.Sprintf(
		"ticketbulk.ClaimedTarget{sequence:%d,version:%d,identity:[REDACTED]}",
		target.Sequence, target.Pin.Version(),
	)
}

func (target ClaimedTarget) GoString() string { return target.String() }

type Claim struct {
	Definition kernel.TicketBulkDefinition
	Binding    BatchBinding
	Targets    []ClaimedTarget
	Progress   kernel.TicketBulkProgressSnapshot
	ObservedAt time.Time
}

func (claim Claim) String() string {
	return fmt.Sprintf(
		"ticketbulk.Claim{definition:%s,binding:%s,targets:%d,progress:[REDACTED]}",
		claim.Definition, claim.Binding, len(claim.Targets),
	)
}

func (claim Claim) GoString() string { return claim.String() }

type ApplyTargetRequest struct {
	Identity Identity
	Binding  BatchBinding
	Sequence uint32
	Pin      kernel.TicketBulkTargetPin
	Command  kernel.TicketBulkCommand
}

func (request ApplyTargetRequest) String() string {
	return fmt.Sprintf(
		"ticketbulk.ApplyTargetRequest{binding:%s,sequence:%d,version:%d,action:%s,identity:[REDACTED],target:[REDACTED],payload:[REDACTED]}",
		request.Binding, request.Sequence, request.Pin.Version(), request.Command.Action(),
	)
}

func (request ApplyTargetRequest) GoString() string { return request.String() }

type ApplyTargetDisposition uint8

const (
	ApplyTargetApplied ApplyTargetDisposition = iota + 1
	ApplyTargetReplayed
	ApplyTargetCancellationRequested
	ApplyTargetAuthorizationRevoked
	ApplyTargetFenceLost
)

type ApplyTargetResult struct {
	Disposition     ApplyTargetDisposition
	Sequence        uint32
	Result          kernel.TicketBulkTargetResult
	ControlRevision uint64
}

func (result ApplyTargetResult) String() string {
	return fmt.Sprintf(
		"ticketbulk.ApplyTargetResult{disposition:%d,sequence:%d,result:%s,control_revision:%d}",
		result.Disposition, result.Sequence, result.Result, result.ControlRevision,
	)
}

func (result ApplyTargetResult) GoString() string { return result.String() }

type ReleaseBatchRequest struct {
	Identity      Identity
	Binding       BatchBinding
	Processed     uint32
	ReceiptDigest [32]byte
	ReleasedAt    time.Time
}

func (request ReleaseBatchRequest) String() string {
	return fmt.Sprintf(
		"ticketbulk.ReleaseBatchRequest{binding:%s,processed:%d,identity:[REDACTED],receipt:[REDACTED],time:[REDACTED]}",
		request.Binding, request.Processed,
	)
}

func (request ReleaseBatchRequest) GoString() string { return request.String() }

type ReleaseBatchDisposition uint8

const (
	ReleaseBatchReleased ReleaseBatchDisposition = iota + 1
	ReleaseJobCompleted
	ReleaseCancellationRequested
	ReleaseAuthorizationRevoked
	ReleaseFenceLost
	// ReleaseJobFailed is returned when this successful batch makes global
	// progress complete but an earlier batch already recorded internal failures.
	ReleaseJobFailed
)

type ReleaseBatchResult struct {
	Disposition     ReleaseBatchDisposition
	Progress        *kernel.TicketBulkProgressSnapshot
	ControlRevision uint64
}

func (result ReleaseBatchResult) String() string {
	return fmt.Sprintf(
		"ticketbulk.ReleaseBatchResult{disposition:%d,progress:%t,control_revision:%d,metadata:[REDACTED]}",
		result.Disposition, result.Progress != nil, result.ControlRevision,
	)
}

func (result ReleaseBatchResult) GoString() string { return result.String() }

type BatchFailureRequest struct {
	Identity Identity
	Binding  BatchBinding
	Code     BatchFailureCode
	FailedAt time.Time
	RetryAt  *time.Time
}

func (request BatchFailureRequest) String() string {
	return fmt.Sprintf(
		"ticketbulk.BatchFailureRequest{binding:%s,code:%s,retry:%t,identity:[REDACTED],times:[REDACTED]}",
		request.Binding, request.Code, request.RetryAt != nil,
	)
}

func (request BatchFailureRequest) GoString() string { return request.String() }

type BatchFailureDisposition uint8

const (
	FailureRetryScheduled BatchFailureDisposition = iota + 1
	FailureReplayRetry
	FailureBatchTerminalized
	FailureReplayBatchTerminalized
	FailureJobFailed
	FailureReplayJobFailed
	FailureCancellationRequested
	FailureAuthorizationRevoked
	FailureFenceLost
	// Reconciliation dispositions report that every target in the claimed
	// batch already has a durable non-failure result. They are required when an
	// ApplyTarget response is lost after its transaction commits.
	FailureBatchReleased
	FailureReplayBatchReleased
	FailureJobCompleted
	FailureReplayJobCompleted
)

type BatchFailureResult struct {
	Disposition     BatchFailureDisposition
	Progress        *kernel.TicketBulkProgressSnapshot
	ControlRevision uint64
	RetryAt         *time.Time
}

func (result BatchFailureResult) String() string {
	return fmt.Sprintf(
		"ticketbulk.BatchFailureResult{disposition:%d,progress:%t,control_revision:%d,retry:%t,metadata:[REDACTED]}",
		result.Disposition, result.Progress != nil, result.ControlRevision, result.RetryAt != nil,
	)
}

func (result BatchFailureResult) GoString() string { return result.String() }

type ControlFinalizationRequest struct {
	Identity         Identity
	Binding          BatchBinding
	ExpectedRevision uint64
	FinalizedAt      time.Time
}

func (request ControlFinalizationRequest) String() string {
	return fmt.Sprintf(
		"ticketbulk.ControlFinalizationRequest{binding:%s,expected_revision:%d,identity:[REDACTED],time:[REDACTED]}",
		request.Binding, request.ExpectedRevision,
	)
}

func (request ControlFinalizationRequest) GoString() string { return request.String() }

type ControlFinalizationDisposition uint8

const (
	ControlFinalizationApplied ControlFinalizationDisposition = iota + 1
	ControlFinalizationReplayed
	ControlFinalizationFenceLost
)

type ControlFinalizationResult struct {
	Disposition     ControlFinalizationDisposition
	Progress        *kernel.TicketBulkProgressSnapshot
	ControlRevision uint64
}

func (result ControlFinalizationResult) String() string {
	return fmt.Sprintf(
		"ticketbulk.ControlFinalizationResult{disposition:%d,progress:%t,control_revision:%d,metadata:[REDACTED]}",
		result.Disposition, result.Progress != nil, result.ControlRevision,
	)
}

func (result ControlFinalizationResult) GoString() string { return result.String() }
