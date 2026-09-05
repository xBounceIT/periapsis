package ticketing

import (
	"errors"
	"fmt"
)

var (
	ErrInvalidTicketBulkProgress = errors.New("invalid ticket bulk progress")
	ErrTicketBulkProgressFull    = errors.New("ticket bulk progress is already complete")
)

// TicketBulkTargetResult is deliberately bounded. Persistence and transports
// may expose these stable codes, but never raw authorization or database
// errors. Not-found and hidden targets share one code to avoid an existence
// oracle.
type TicketBulkTargetResult uint8

const (
	TicketBulkTargetSucceeded TicketBulkTargetResult = iota + 1
	TicketBulkTargetNoChange
	TicketBulkTargetVersionConflict
	TicketBulkTargetNotFoundOrHidden
	TicketBulkTargetAuthorizationDenied
	TicketBulkTargetRejected
	TicketBulkTargetCancelled
	TicketBulkTargetAuthorizationRevoked
	TicketBulkTargetInternalFailure
)

func (result TicketBulkTargetResult) String() string {
	switch result {
	case TicketBulkTargetSucceeded:
		return "succeeded"
	case TicketBulkTargetNoChange:
		return "no_change"
	case TicketBulkTargetVersionConflict:
		return "version_conflict"
	case TicketBulkTargetNotFoundOrHidden:
		return "not_found_or_hidden"
	case TicketBulkTargetAuthorizationDenied:
		return "authorization_denied"
	case TicketBulkTargetRejected:
		return "rejected"
	case TicketBulkTargetCancelled:
		return "cancelled"
	case TicketBulkTargetAuthorizationRevoked:
		return "authorization_revoked"
	case TicketBulkTargetInternalFailure:
		return "internal_failure"
	default:
		return "unknown"
	}
}

func validTicketBulkTargetResult(result TicketBulkTargetResult) bool {
	return result >= TicketBulkTargetSucceeded && result <= TicketBulkTargetInternalFailure
}

// WorkerTicketBulkTargetResult reports whether a single live-authorized
// mutation may produce this result. Control-path finalizers exclusively own
// cancelled, authorization-revoked, and internal-failure accounting.
func WorkerTicketBulkTargetResult(result TicketBulkTargetResult) bool {
	return result >= TicketBulkTargetSucceeded && result <= TicketBulkTargetRejected
}

func ticketBulkRemainderResult(result TicketBulkTargetResult) bool {
	return result == TicketBulkTargetCancelled ||
		result == TicketBulkTargetAuthorizationRevoked ||
		result == TicketBulkTargetInternalFailure
}

// TicketBulkProgressSnapshot is the persistence reconstruction boundary.
// Total is the immutable materialized target count from the job definition.
type TicketBulkProgressSnapshot struct {
	Total                uint32
	Succeeded            uint32
	NoChange             uint32
	VersionConflict      uint32
	NotFoundOrHidden     uint32
	AuthorizationDenied  uint32
	Rejected             uint32
	Cancelled            uint32
	AuthorizationRevoked uint32
	InternalFailure      uint32
}

func (snapshot TicketBulkProgressSnapshot) String() string {
	return fmt.Sprintf(
		"TicketBulkProgressSnapshot{total:%d,processed:%d,metadata:[REDACTED]}",
		snapshot.Total, ticketBulkProcessed(snapshot),
	)
}

func (snapshot TicketBulkProgressSnapshot) GoString() string { return snapshot.String() }

type TicketBulkProgress struct {
	snapshot TicketBulkProgressSnapshot
}

func NewTicketBulkProgress(total uint32) (TicketBulkProgress, error) {
	return RestoreTicketBulkProgress(TicketBulkProgressSnapshot{Total: total})
}

func RestoreTicketBulkProgress(snapshot TicketBulkProgressSnapshot) (TicketBulkProgress, error) {
	if snapshot.Total == 0 || snapshot.Total > TicketBulkMaximumTargets ||
		ticketBulkProcessed(snapshot) > uint64(snapshot.Total) {
		return TicketBulkProgress{}, ErrInvalidTicketBulkProgress
	}
	return TicketBulkProgress{snapshot: snapshot}, nil
}

func (progress TicketBulkProgress) Snapshot() TicketBulkProgressSnapshot {
	return progress.snapshot
}

func (progress TicketBulkProgress) Total() uint32 { return progress.snapshot.Total }

func (progress TicketBulkProgress) Processed() uint32 {
	return uint32(ticketBulkProcessed(progress.snapshot))
}

func (progress TicketBulkProgress) Remaining() uint32 {
	return progress.Total() - progress.Processed()
}

func (progress TicketBulkProgress) Complete() bool {
	return progress.Processed() == progress.Total()
}

func (progress TicketBulkProgress) Count(result TicketBulkTargetResult) uint32 {
	switch result {
	case TicketBulkTargetSucceeded:
		return progress.snapshot.Succeeded
	case TicketBulkTargetNoChange:
		return progress.snapshot.NoChange
	case TicketBulkTargetVersionConflict:
		return progress.snapshot.VersionConflict
	case TicketBulkTargetNotFoundOrHidden:
		return progress.snapshot.NotFoundOrHidden
	case TicketBulkTargetAuthorizationDenied:
		return progress.snapshot.AuthorizationDenied
	case TicketBulkTargetRejected:
		return progress.snapshot.Rejected
	case TicketBulkTargetCancelled:
		return progress.snapshot.Cancelled
	case TicketBulkTargetAuthorizationRevoked:
		return progress.snapshot.AuthorizationRevoked
	case TicketBulkTargetInternalFailure:
		return progress.snapshot.InternalFailure
	default:
		return 0
	}
}

func (progress TicketBulkProgress) WithResult(
	result TicketBulkTargetResult,
) (TicketBulkProgress, error) {
	if !validTicketBulkProgress(progress) || !validTicketBulkTargetResult(result) {
		return TicketBulkProgress{}, ErrInvalidTicketBulkProgress
	}
	if progress.Complete() {
		return TicketBulkProgress{}, ErrTicketBulkProgressFull
	}
	next := progress.snapshot
	incrementTicketBulkResult(&next, result, 1)
	return RestoreTicketBulkProgress(next)
}

// WithRemainder is reserved for a transaction that has stopped future target
// claims and proves that every still-unprocessed target is being finalized
// under the same job lock.
func (progress TicketBulkProgress) WithRemainder(
	result TicketBulkTargetResult,
) (TicketBulkProgress, error) {
	if !validTicketBulkProgress(progress) || !ticketBulkRemainderResult(result) {
		return TicketBulkProgress{}, ErrInvalidTicketBulkProgress
	}
	if progress.Complete() {
		return TicketBulkProgress{}, ErrTicketBulkProgressFull
	}
	next := progress.snapshot
	incrementTicketBulkResult(&next, result, progress.Remaining())
	return RestoreTicketBulkProgress(next)
}

func (progress TicketBulkProgress) String() string {
	return fmt.Sprintf(
		"TicketBulkProgress{total:%d,processed:%d,remaining:%d,metadata:[REDACTED]}",
		progress.Total(), progress.Processed(), progress.Remaining(),
	)
}

func (progress TicketBulkProgress) GoString() string { return progress.String() }

func ValidateTicketBulkProgress(progress TicketBulkProgress) error {
	if !validTicketBulkProgress(progress) {
		return ErrInvalidTicketBulkProgress
	}
	return nil
}

func validTicketBulkProgress(progress TicketBulkProgress) bool {
	rebuilt, err := RestoreTicketBulkProgress(progress.snapshot)
	return err == nil && rebuilt == progress
}

func ticketBulkProcessed(snapshot TicketBulkProgressSnapshot) uint64 {
	return uint64(snapshot.Succeeded) + uint64(snapshot.NoChange) +
		uint64(snapshot.VersionConflict) + uint64(snapshot.NotFoundOrHidden) +
		uint64(snapshot.AuthorizationDenied) + uint64(snapshot.Rejected) +
		uint64(snapshot.Cancelled) + uint64(snapshot.AuthorizationRevoked) +
		uint64(snapshot.InternalFailure)
}

func incrementTicketBulkResult(
	snapshot *TicketBulkProgressSnapshot,
	result TicketBulkTargetResult,
	amount uint32,
) {
	switch result {
	case TicketBulkTargetSucceeded:
		snapshot.Succeeded += amount
	case TicketBulkTargetNoChange:
		snapshot.NoChange += amount
	case TicketBulkTargetVersionConflict:
		snapshot.VersionConflict += amount
	case TicketBulkTargetNotFoundOrHidden:
		snapshot.NotFoundOrHidden += amount
	case TicketBulkTargetAuthorizationDenied:
		snapshot.AuthorizationDenied += amount
	case TicketBulkTargetRejected:
		snapshot.Rejected += amount
	case TicketBulkTargetCancelled:
		snapshot.Cancelled += amount
	case TicketBulkTargetAuthorizationRevoked:
		snapshot.AuthorizationRevoked += amount
	case TicketBulkTargetInternalFailure:
		snapshot.InternalFailure += amount
	}
}
