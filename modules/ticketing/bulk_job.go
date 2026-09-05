package ticketing

import (
	"errors"
	"fmt"
	"reflect"
	"time"
)

const (
	TicketBulkMinimumRetention = 5 * time.Minute
	TicketBulkMaximumRetention = 30 * 24 * time.Hour
)

var (
	ErrInvalidTicketBulkJob = errors.New("invalid ticket bulk job")
	ErrTicketBulkConflict   = errors.New("ticket bulk transition does not apply")
)

// TicketBulkState is deliberately small. A pending job has no live batch and
// may be immediately available or waiting for a bounded retry. Running and
// cancellation-requested jobs have one live fenced batch. Terminal states are
// valid only after every materialized target has a durable result.
type TicketBulkState uint8

const (
	TicketBulkPending TicketBulkState = iota + 1
	TicketBulkRunning
	TicketBulkCancellationRequested
	TicketBulkCompleted
	TicketBulkFailed
	TicketBulkCancelledState
	TicketBulkAuthorizationRevokedState
)

func (state TicketBulkState) String() string {
	switch state {
	case TicketBulkPending:
		return "pending"
	case TicketBulkRunning:
		return "running"
	case TicketBulkCancellationRequested:
		return "cancellation_requested"
	case TicketBulkCompleted:
		return "completed"
	case TicketBulkFailed:
		return "failed"
	case TicketBulkCancelledState:
		return "cancelled"
	case TicketBulkAuthorizationRevokedState:
		return "authorization_revoked"
	default:
		return "unknown"
	}
}

func validTicketBulkState(state TicketBulkState) bool {
	return state >= TicketBulkPending && state <= TicketBulkAuthorizationRevokedState
}

// TicketBulkJobSnapshot is the persistence reconstruction boundary. The
// ActiveBatch flag intentionally reveals no worker, fence, or target identity.
// AvailableAt is the next claim instant for pending jobs and is retained in
// terminal projections as non-authoritative history.
type TicketBulkJobSnapshot struct {
	Definition  TicketBulkDefinition
	State       TicketBulkState
	Revision    uint64
	Progress    TicketBulkProgressSnapshot
	RequestedAt time.Time
	UpdatedAt   time.Time
	AvailableAt time.Time
	ExpiresAt   time.Time
	ActiveBatch bool
	TerminalAt  *time.Time
}

func (snapshot TicketBulkJobSnapshot) String() string {
	return fmt.Sprintf(
		"TicketBulkJobSnapshot{state:%s,revision:%d,progress:%s,active_batch:%t,metadata:[REDACTED]}",
		snapshot.State, snapshot.Revision, snapshot.Progress, snapshot.ActiveBatch,
	)
}

func (snapshot TicketBulkJobSnapshot) GoString() string { return snapshot.String() }

type TicketBulkJob struct {
	definition  TicketBulkDefinition
	state       TicketBulkState
	revision    uint64
	progress    TicketBulkProgress
	requestedAt time.Time
	updatedAt   time.Time
	availableAt time.Time
	expiresAt   time.Time
	activeBatch bool
	terminalAt  *time.Time
}

func RestoreTicketBulkJob(snapshot TicketBulkJobSnapshot) (TicketBulkJob, error) {
	if ValidateTicketBulkDefinition(snapshot.Definition) != nil ||
		!validTicketBulkState(snapshot.State) || snapshot.Revision == 0 || snapshot.Revision > maxVersion ||
		!validTicketBulkInstant(snapshot.RequestedAt) || !validTicketBulkInstant(snapshot.UpdatedAt) ||
		!validTicketBulkInstant(snapshot.AvailableAt) || !validTicketBulkInstant(snapshot.ExpiresAt) ||
		snapshot.UpdatedAt.Before(snapshot.RequestedAt) ||
		snapshot.UpdatedAt.After(snapshot.ExpiresAt) ||
		snapshot.AvailableAt.Before(snapshot.RequestedAt) ||
		!snapshot.ExpiresAt.After(snapshot.RequestedAt) ||
		snapshot.ExpiresAt.Sub(snapshot.RequestedAt) < TicketBulkMinimumRetention ||
		snapshot.ExpiresAt.Sub(snapshot.RequestedAt) > TicketBulkMaximumRetention ||
		snapshot.AvailableAt.After(snapshot.ExpiresAt) ||
		snapshot.Revision == 1 && snapshot.State != TicketBulkPending ||
		snapshot.Revision == maxVersion && !terminalTicketBulkJobState(snapshot.State) {
		return TicketBulkJob{}, ErrInvalidTicketBulkJob
	}
	progress, err := RestoreTicketBulkProgress(snapshot.Progress)
	if err != nil || progress.Total() != snapshot.Definition.selection.targetCount ||
		!validTicketBulkJobShape(snapshot, progress) {
		return TicketBulkJob{}, ErrInvalidTicketBulkJob
	}
	return TicketBulkJob{
		definition: cloneTicketBulkDefinition(snapshot.Definition),
		state:      snapshot.State, revision: snapshot.Revision, progress: progress,
		requestedAt: snapshot.RequestedAt, updatedAt: snapshot.UpdatedAt,
		availableAt: snapshot.AvailableAt, expiresAt: snapshot.ExpiresAt,
		activeBatch: snapshot.ActiveBatch, terminalAt: cloneTicketBulkTime(snapshot.TerminalAt),
	}, nil
}

func terminalTicketBulkJobState(state TicketBulkState) bool {
	return state == TicketBulkCompleted || state == TicketBulkFailed ||
		state == TicketBulkCancelledState || state == TicketBulkAuthorizationRevokedState
}

func validTicketBulkJobShape(snapshot TicketBulkJobSnapshot, progress TicketBulkProgress) bool {
	hasTerminal := snapshot.TerminalAt != nil
	if snapshot.Revision == 1 && (snapshot.State != TicketBulkPending || progress.Processed() != 0 ||
		!snapshot.UpdatedAt.Equal(snapshot.RequestedAt) ||
		!snapshot.AvailableAt.Equal(snapshot.RequestedAt)) {
		return false
	}
	if hasTerminal && (!validTicketBulkInstant(*snapshot.TerminalAt) ||
		snapshot.TerminalAt.Before(snapshot.RequestedAt) ||
		snapshot.TerminalAt.After(snapshot.ExpiresAt) ||
		!snapshot.TerminalAt.Equal(snapshot.UpdatedAt)) {
		return false
	}
	switch snapshot.State {
	case TicketBulkPending:
		return !snapshot.ActiveBatch && !hasTerminal && !progress.Complete() &&
			!snapshot.AvailableAt.Before(snapshot.UpdatedAt) && !ticketBulkControlProgress(progress)
	case TicketBulkRunning:
		return snapshot.ActiveBatch && !hasTerminal && !progress.Complete() &&
			!snapshot.AvailableAt.After(snapshot.UpdatedAt) && !ticketBulkControlProgress(progress)
	case TicketBulkCancellationRequested:
		return snapshot.Revision >= 3 && snapshot.ActiveBatch && !hasTerminal && !progress.Complete() &&
			!snapshot.AvailableAt.After(snapshot.UpdatedAt) && !ticketBulkControlProgress(progress)
	case TicketBulkCompleted:
		return !snapshot.ActiveBatch && hasTerminal && progress.Complete() &&
			progress.Count(TicketBulkTargetCancelled) == 0 &&
			progress.Count(TicketBulkTargetAuthorizationRevoked) == 0 &&
			progress.Count(TicketBulkTargetInternalFailure) == 0
	case TicketBulkFailed:
		return !snapshot.ActiveBatch && hasTerminal && progress.Complete() &&
			progress.Count(TicketBulkTargetInternalFailure) > 0 &&
			progress.Count(TicketBulkTargetCancelled) == 0 &&
			progress.Count(TicketBulkTargetAuthorizationRevoked) == 0
	case TicketBulkCancelledState:
		return !snapshot.ActiveBatch && hasTerminal && progress.Complete() &&
			progress.Count(TicketBulkTargetCancelled) > 0 &&
			progress.Count(TicketBulkTargetAuthorizationRevoked) == 0 &&
			progress.Count(TicketBulkTargetInternalFailure) == 0
	case TicketBulkAuthorizationRevokedState:
		return !snapshot.ActiveBatch && hasTerminal && progress.Complete() &&
			progress.Count(TicketBulkTargetAuthorizationRevoked) > 0 &&
			progress.Count(TicketBulkTargetCancelled) == 0 &&
			progress.Count(TicketBulkTargetInternalFailure) == 0
	default:
		return false
	}
}

func ticketBulkControlProgress(progress TicketBulkProgress) bool {
	return progress.Count(TicketBulkTargetCancelled) != 0 ||
		progress.Count(TicketBulkTargetAuthorizationRevoked) != 0 ||
		progress.Count(TicketBulkTargetInternalFailure) != 0
}

func (job TicketBulkJob) Definition() TicketBulkDefinition {
	return cloneTicketBulkDefinition(job.definition)
}
func (job TicketBulkJob) State() TicketBulkState       { return job.state }
func (job TicketBulkJob) Revision() uint64             { return job.revision }
func (job TicketBulkJob) Progress() TicketBulkProgress { return job.progress }
func (job TicketBulkJob) RequestedAt() time.Time       { return job.requestedAt }
func (job TicketBulkJob) UpdatedAt() time.Time         { return job.updatedAt }
func (job TicketBulkJob) AvailableAt() time.Time       { return job.availableAt }
func (job TicketBulkJob) ExpiresAt() time.Time         { return job.expiresAt }
func (job TicketBulkJob) ActiveBatch() bool            { return job.activeBatch }
func (job TicketBulkJob) TerminalAt() *time.Time       { return cloneTicketBulkTime(job.terminalAt) }
func (job TicketBulkJob) Snapshot() TicketBulkJobSnapshot {
	return TicketBulkJobSnapshot{
		Definition: cloneTicketBulkDefinition(job.definition), State: job.state,
		Revision: job.revision, Progress: job.progress.Snapshot(),
		RequestedAt: job.requestedAt, UpdatedAt: job.updatedAt,
		AvailableAt: job.availableAt, ExpiresAt: job.expiresAt,
		ActiveBatch: job.activeBatch, TerminalAt: cloneTicketBulkTime(job.terminalAt),
	}
}

func (job TicketBulkJob) String() string {
	return fmt.Sprintf(
		"TicketBulkJob{kind:%s,state:%s,revision:%d,progress:%s,metadata:[REDACTED]}",
		job.definition.kind, job.state, job.revision, job.progress,
	)
}

func (job TicketBulkJob) GoString() string { return job.String() }

func ValidateTicketBulkJob(job TicketBulkJob) error {
	rebuilt, err := RestoreTicketBulkJob(job.Snapshot())
	if err != nil || !reflect.DeepEqual(rebuilt, job) {
		return ErrInvalidTicketBulkJob
	}
	return nil
}

func SameTicketBulkJob(left, right TicketBulkJob) bool {
	return reflect.DeepEqual(left.Snapshot(), right.Snapshot())
}

type TicketBulkAction uint8

const (
	TicketBulkCreate TicketBulkAction = iota + 1
	TicketBulkRequestCancellation
)

func (action TicketBulkAction) String() string {
	switch action {
	case TicketBulkCreate:
		return "create"
	case TicketBulkRequestCancellation:
		return "request_cancellation"
	default:
		return "unknown"
	}
}

type TicketBulkPlan struct {
	action           TicketBulkAction
	expectedRevision uint64
	next             TicketBulkJob
}

func (plan TicketBulkPlan) Action() TicketBulkAction { return plan.action }
func (plan TicketBulkPlan) ExpectedRevision() uint64 { return plan.expectedRevision }
func (plan TicketBulkPlan) Next() TicketBulkJob      { return cloneTicketBulkJob(plan.next) }
func (plan TicketBulkPlan) String() string {
	return fmt.Sprintf(
		"TicketBulkPlan{action:%s,expected_revision:%d,next_revision:%d,state:%s,metadata:[REDACTED]}",
		plan.action, plan.expectedRevision, plan.next.revision, plan.next.state,
	)
}
func (plan TicketBulkPlan) GoString() string { return plan.String() }

func PlanTicketBulkCreation(
	definition TicketBulkDefinition,
	requestedAt time.Time,
	expiresAt time.Time,
) (TicketBulkPlan, error) {
	if ValidateTicketBulkDefinition(definition) != nil {
		return TicketBulkPlan{}, ErrInvalidTicketBulkJob
	}
	progress, err := NewTicketBulkProgress(definition.selection.targetCount)
	if err != nil {
		return TicketBulkPlan{}, ErrInvalidTicketBulkJob
	}
	next, err := RestoreTicketBulkJob(TicketBulkJobSnapshot{
		Definition: definition, State: TicketBulkPending, Revision: 1,
		Progress: progress.Snapshot(), RequestedAt: requestedAt, UpdatedAt: requestedAt,
		AvailableAt: requestedAt, ExpiresAt: expiresAt,
	})
	if err != nil {
		return TicketBulkPlan{}, err
	}
	return TicketBulkPlan{action: TicketBulkCreate, next: next}, nil
}

func PlanTicketBulkCancellation(
	current TicketBulkJob,
	expectedRevision uint64,
	now time.Time,
) (TicketBulkPlan, error) {
	if ValidateTicketBulkJob(current) != nil || expectedRevision != current.revision ||
		current.revision == maxVersion || !validTicketBulkInstant(now) || now.Before(current.updatedAt) ||
		!now.Before(current.expiresAt) {
		return TicketBulkPlan{}, ErrInvalidTicketBulkJob
	}
	next := current.Snapshot()
	next.Revision, next.UpdatedAt = current.revision+1, now
	switch current.state {
	case TicketBulkPending:
		progress, err := current.progress.WithRemainder(TicketBulkTargetCancelled)
		if err != nil {
			return TicketBulkPlan{}, ErrInvalidTicketBulkJob
		}
		next.State, next.Progress, next.TerminalAt = TicketBulkCancelledState, progress.Snapshot(), &now
	case TicketBulkRunning:
		next.State = TicketBulkCancellationRequested
	default:
		return TicketBulkPlan{}, ErrTicketBulkConflict
	}
	job, err := RestoreTicketBulkJob(next)
	if err != nil {
		return TicketBulkPlan{}, err
	}
	return TicketBulkPlan{
		action: TicketBulkRequestCancellation, expectedRevision: current.revision, next: job,
	}, nil
}

func validTicketBulkInstant(value time.Time) bool {
	return validInstant(value) && value.Year() >= 1 && value.Year() <= 9_999
}

func cloneTicketBulkDefinition(definition TicketBulkDefinition) TicketBulkDefinition {
	result := definition
	result.selection = cloneTicketBulkSelection(definition.selection)
	result.mutation = cloneTicketBulkMutation(definition.mutation)
	return result
}

func cloneTicketBulkJob(job TicketBulkJob) TicketBulkJob {
	result := job
	result.definition = cloneTicketBulkDefinition(job.definition)
	result.terminalAt = cloneTicketBulkTime(job.terminalAt)
	return result
}

func cloneTicketBulkTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}
