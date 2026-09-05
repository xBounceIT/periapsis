package customfields

import (
	"fmt"
	"reflect"
	"time"
)

const (
	ImportMinimumRetention = 5 * time.Minute
	ImportMaximumRetention = 30 * 24 * time.Hour
	ImportMaximumBatchRows = 200
	ImportMaximumLease     = 5 * time.Minute
)

type ImportJobState uint8

const (
	ImportJobPending ImportJobState = iota + 1
	ImportJobRunning
	ImportJobCancellationRequested
	ImportJobCompleted
	ImportJobFailed
	ImportJobCancelled
	ImportJobAuthorizationRevoked
	ImportJobExpired
)

func (state ImportJobState) String() string {
	switch state {
	case ImportJobPending:
		return "pending"
	case ImportJobRunning:
		return "running"
	case ImportJobCancellationRequested:
		return "cancellation_requested"
	case ImportJobCompleted:
		return "completed"
	case ImportJobFailed:
		return "failed"
	case ImportJobCancelled:
		return "cancelled"
	case ImportJobAuthorizationRevoked:
		return "authorization_revoked"
	case ImportJobExpired:
		return "expired"
	default:
		return "unknown"
	}
}

func validImportJobState(state ImportJobState) bool {
	return state >= ImportJobPending && state <= ImportJobExpired
}

type ImportJobSnapshot struct {
	Manifest    ImportManifest
	State       ImportJobState
	Revision    uint64
	Attempts    uint8
	Results     []ImportRowResult
	RequestedAt time.Time
	UpdatedAt   time.Time
	AvailableAt time.Time
	ExpiresAt   time.Time
	Fence       *EntityID
	LeaseUntil  *time.Time
	TerminalAt  *time.Time
}

type ImportJob struct {
	manifest    ImportManifest
	state       ImportJobState
	revision    uint64
	attempts    uint8
	results     []ImportRowResult
	progress    ImportProgressSnapshot
	requestedAt time.Time
	updatedAt   time.Time
	availableAt time.Time
	expiresAt   time.Time
	fence       *EntityID
	leaseUntil  *time.Time
	terminalAt  *time.Time
}

func NewImportJob(manifest ImportManifest, requestedAt, expiresAt time.Time) (ImportJob, error) {
	return RestoreImportJob(ImportJobSnapshot{
		Manifest: manifest, State: ImportJobPending, Revision: 1,
		RequestedAt: requestedAt, UpdatedAt: requestedAt,
		AvailableAt: requestedAt, ExpiresAt: expiresAt,
	})
}

func RestoreImportJob(snapshot ImportJobSnapshot) (ImportJob, error) {
	if ValidateImportManifest(snapshot.Manifest) != nil || !validImportJobState(snapshot.State) ||
		snapshot.Revision == 0 || snapshot.Revision >= maximumDefinitionVersion ||
		!validImportInstant(snapshot.RequestedAt) || !validImportInstant(snapshot.UpdatedAt) ||
		!validImportInstant(snapshot.AvailableAt) || !validImportInstant(snapshot.ExpiresAt) ||
		snapshot.UpdatedAt.Before(snapshot.RequestedAt) ||
		snapshot.AvailableAt.Before(snapshot.RequestedAt) ||
		!snapshot.ExpiresAt.After(snapshot.RequestedAt) ||
		snapshot.ExpiresAt.Sub(snapshot.RequestedAt) < ImportMinimumRetention ||
		snapshot.ExpiresAt.Sub(snapshot.RequestedAt) > ImportMaximumRetention ||
		snapshot.AvailableAt.After(snapshot.ExpiresAt) ||
		snapshot.Attempts > snapshot.Manifest.maximumAttempts {
		return ImportJob{}, ErrInvalidImportJob
	}
	results := cloneImportRowResults(snapshot.Results)
	progress, err := importProgress(uint32(len(snapshot.Manifest.rows)), results)
	if err != nil || !validImportResultsForManifest(snapshot.Manifest, results) ||
		!validImportJobSnapshotShape(snapshot, progress) {
		return ImportJob{}, ErrInvalidImportJob
	}
	return ImportJob{
		manifest: cloneImportManifest(snapshot.Manifest), state: snapshot.State,
		revision: snapshot.Revision, attempts: snapshot.Attempts,
		results: results, progress: progress,
		requestedAt: snapshot.RequestedAt, updatedAt: snapshot.UpdatedAt,
		availableAt: snapshot.AvailableAt, expiresAt: snapshot.ExpiresAt,
		fence: cloneImportEntity(snapshot.Fence), leaseUntil: cloneImportTime(snapshot.LeaseUntil),
		terminalAt: cloneImportTime(snapshot.TerminalAt),
	}, nil
}

func (job ImportJob) Manifest() ImportManifest         { return cloneImportManifest(job.manifest) }
func (job ImportJob) State() ImportJobState            { return job.state }
func (job ImportJob) Revision() uint64                 { return job.revision }
func (job ImportJob) Attempts() uint8                  { return job.attempts }
func (job ImportJob) Results() []ImportRowResult       { return cloneImportRowResults(job.results) }
func (job ImportJob) Progress() ImportProgressSnapshot { return job.progress }
func (job ImportJob) RequestedAt() time.Time           { return job.requestedAt }
func (job ImportJob) UpdatedAt() time.Time             { return job.updatedAt }
func (job ImportJob) AvailableAt() time.Time           { return job.availableAt }
func (job ImportJob) ExpiresAt() time.Time             { return job.expiresAt }
func (job ImportJob) Fence() *EntityID                 { return cloneImportEntity(job.fence) }
func (job ImportJob) LeaseUntil() *time.Time           { return cloneImportTime(job.leaseUntil) }
func (job ImportJob) TerminalAt() *time.Time           { return cloneImportTime(job.terminalAt) }
func (job ImportJob) NextRows(limit int) []ImportRow {
	if limit <= 0 || limit > ImportMaximumBatchRows || len(job.results) >= len(job.manifest.rows) {
		return nil
	}
	end := len(job.results) + limit
	if end > len(job.manifest.rows) {
		end = len(job.manifest.rows)
	}
	return cloneImportRows(job.manifest.rows[len(job.results):end])
}
func (job ImportJob) Snapshot() ImportJobSnapshot {
	return ImportJobSnapshot{
		Manifest: cloneImportManifest(job.manifest), State: job.state,
		Revision: job.revision, Attempts: job.attempts, Results: cloneImportRowResults(job.results),
		RequestedAt: job.requestedAt, UpdatedAt: job.updatedAt,
		AvailableAt: job.availableAt, ExpiresAt: job.expiresAt,
		Fence: cloneImportEntity(job.fence), LeaseUntil: cloneImportTime(job.leaseUntil),
		TerminalAt: cloneImportTime(job.terminalAt),
	}
}
func (job ImportJob) String() string {
	return fmt.Sprintf(
		"ImportJob{object:%s,mode:%s,state:%s,revision:%d,attempts:%d,progress:%s,metadata:[REDACTED]}",
		job.manifest.objectType, job.manifest.mode, job.state, job.revision, job.attempts, job.progress,
	)
}
func (job ImportJob) GoString() string { return job.String() }

func ValidateImportJob(job ImportJob) error {
	rebuilt, err := RestoreImportJob(job.Snapshot())
	if err != nil || !reflect.DeepEqual(rebuilt, job) {
		return ErrInvalidImportJob
	}
	return nil
}

func SameImportJob(left, right ImportJob) bool {
	return ValidateImportJob(left) == nil && ValidateImportJob(right) == nil &&
		reflect.DeepEqual(left, right)
}

func ClaimImportJob(
	current ImportJob,
	expectedRevision uint64,
	fence EntityID,
	now, leaseUntil time.Time,
) (ImportJob, error) {
	if ValidateImportJob(current) != nil || expectedRevision != current.revision ||
		!validEntityID(fence) || !validImportInstant(now) || !validImportInstant(leaseUntil) ||
		now.Before(current.updatedAt) || now.Before(current.availableAt) || !now.Before(current.expiresAt) ||
		!leaseUntil.After(now) || leaseUntil.After(current.expiresAt) ||
		leaseUntil.Sub(now) > ImportMaximumLease || current.attempts >= current.manifest.maximumAttempts ||
		current.revision+1 >= maximumDefinitionVersion {
		return ImportJob{}, ErrInvalidImportJob
	}
	claimable := current.state == ImportJobPending ||
		current.state == ImportJobRunning && current.leaseUntil != nil && !now.Before(*current.leaseUntil)
	if !claimable {
		return ImportJob{}, ErrImportJobConflict
	}
	snapshot := current.Snapshot()
	snapshot.State, snapshot.Revision, snapshot.Attempts = ImportJobRunning, current.revision+1, current.attempts+1
	snapshot.UpdatedAt, snapshot.AvailableAt = now, now
	snapshot.Fence, snapshot.LeaseUntil = &fence, &leaseUntil
	return RestoreImportJob(snapshot)
}

func HeartbeatImportJob(
	current ImportJob,
	expectedRevision uint64,
	fence EntityID,
	now, leaseUntil time.Time,
) (ImportJob, error) {
	if ValidateImportJob(current) != nil || expectedRevision != current.revision ||
		current.state != ImportJobRunning ||
		current.fence == nil || *current.fence != fence || current.leaseUntil == nil ||
		!validImportInstant(now) || !validImportInstant(leaseUntil) || now.Before(current.updatedAt) ||
		!now.Before(*current.leaseUntil) || !leaseUntil.After(*current.leaseUntil) ||
		leaseUntil.After(current.expiresAt) ||
		leaseUntil.Sub(now) > ImportMaximumLease || current.revision+1 >= maximumDefinitionVersion {
		return ImportJob{}, ErrImportJobConflict
	}
	snapshot := current.Snapshot()
	snapshot.Revision, snapshot.UpdatedAt, snapshot.LeaseUntil = current.revision+1, now, &leaseUntil
	return RestoreImportJob(snapshot)
}

func RecordImportBatch(
	current ImportJob,
	expectedRevision uint64,
	fence EntityID,
	results []ImportRowResult,
	now time.Time,
) (ImportJob, error) {
	if ValidateImportJob(current) != nil || expectedRevision != current.revision ||
		current.state != ImportJobRunning || current.fence == nil || *current.fence != fence ||
		current.leaseUntil == nil || !validImportInstant(now) || now.Before(current.updatedAt) ||
		!now.Before(*current.leaseUntil) || len(results) == 0 || len(results) > ImportMaximumBatchRows ||
		len(current.results)+len(results) > len(current.manifest.rows) ||
		current.revision+1 >= maximumDefinitionVersion {
		return ImportJob{}, ErrImportJobConflict
	}
	combined := append(cloneImportRowResults(current.results), cloneImportRowResults(results)...)
	if !ordinaryImportResults(results) || !validImportResultsForManifest(current.manifest, combined) {
		return ImportJob{}, ErrInvalidImportRowResult
	}
	snapshot := current.Snapshot()
	snapshot.Results, snapshot.Revision, snapshot.UpdatedAt = combined, current.revision+1, now
	if len(combined) == len(current.manifest.rows) {
		progress, _ := importProgress(uint32(len(current.manifest.rows)), combined)
		snapshot.State = completedImportState(progress)
		snapshot.Fence, snapshot.LeaseUntil, snapshot.TerminalAt = nil, nil, &now
	}
	return RestoreImportJob(snapshot)
}

// ExpireImportJob makes abandoned leases terminal once they can no longer be
// reclaimed. A cancellation request wins over retry exhaustion. Before the
// attempt ceiling, the normal ClaimImportJob reclaim path remains available.
func ExpireImportJob(current ImportJob, expectedRevision uint64, now time.Time) (ImportJob, error) {
	if ValidateImportJob(current) != nil || expectedRevision != current.revision ||
		current.state != ImportJobPending && current.state != ImportJobRunning &&
			current.state != ImportJobCancellationRequested ||
		!validImportInstant(now) || now.Before(current.updatedAt) ||
		current.revision+1 >= maximumDefinitionVersion {
		return ImportJob{}, ErrImportJobConflict
	}
	outcome, terminal := ImportRowExpired, ImportJobExpired
	switch current.state {
	case ImportJobPending:
		if now.Before(current.expiresAt) {
			return ImportJob{}, ErrImportJobConflict
		}
	case ImportJobRunning:
		if current.leaseUntil == nil || now.Before(*current.leaseUntil) {
			return ImportJob{}, ErrImportJobConflict
		}
		if now.Before(current.expiresAt) {
			if current.attempts < current.manifest.maximumAttempts {
				return ImportJob{}, ErrImportJobConflict
			}
			outcome, terminal = ImportRowInternalFailure, ImportJobFailed
		}
	case ImportJobCancellationRequested:
		if current.leaseUntil == nil || now.Before(*current.leaseUntil) {
			return ImportJob{}, ErrImportJobConflict
		}
		outcome, terminal = ImportRowCancelled, ImportJobCancelled
	}
	snapshot := current.Snapshot()
	snapshot.State, snapshot.Revision, snapshot.UpdatedAt = terminal, current.revision+1, now
	snapshot.Results = importRemainderResults(current, outcome)
	snapshot.Fence, snapshot.LeaseUntil, snapshot.TerminalAt = nil, nil, &now
	return RestoreImportJob(snapshot)
}

func RequestImportCancellation(current ImportJob, expectedRevision uint64, now time.Time) (ImportJob, error) {
	if ValidateImportJob(current) != nil || expectedRevision != current.revision ||
		!validImportInstant(now) || now.Before(current.updatedAt) || !now.Before(current.expiresAt) ||
		current.revision+1 >= maximumDefinitionVersion {
		return ImportJob{}, ErrInvalidImportJob
	}
	snapshot := current.Snapshot()
	snapshot.Revision, snapshot.UpdatedAt = current.revision+1, now
	switch current.state {
	case ImportJobPending:
		snapshot.Results = importRemainderResults(current, ImportRowCancelled)
		snapshot.State, snapshot.TerminalAt = ImportJobCancelled, &now
	case ImportJobRunning:
		if current.leaseUntil != nil && !now.Before(*current.leaseUntil) {
			snapshot.Results = importRemainderResults(current, ImportRowCancelled)
			snapshot.State, snapshot.Fence, snapshot.LeaseUntil = ImportJobCancelled, nil, nil
			snapshot.TerminalAt = &now
		} else {
			snapshot.State = ImportJobCancellationRequested
		}
	default:
		return ImportJob{}, ErrImportJobConflict
	}
	return RestoreImportJob(snapshot)
}

func CompleteImportCancellation(
	current ImportJob,
	expectedRevision uint64,
	fence EntityID,
	now time.Time,
) (ImportJob, error) {
	return completeImportControl(
		current, expectedRevision, fence, now,
		ImportJobCancellationRequested, ImportRowCancelled, ImportJobCancelled,
	)
}

func RevokeImportAuthorization(
	current ImportJob,
	expectedRevision uint64,
	fence EntityID,
	now time.Time,
) (ImportJob, error) {
	return completeImportControl(
		current, expectedRevision, fence, now,
		ImportJobRunning, ImportRowAuthorizationRevoked, ImportJobAuthorizationRevoked,
	)
}

func FailImportJob(
	current ImportJob,
	expectedRevision uint64,
	fence EntityID,
	now time.Time,
) (ImportJob, error) {
	return completeImportControl(
		current, expectedRevision, fence, now,
		ImportJobRunning, ImportRowInternalFailure, ImportJobFailed,
	)
}

func completeImportControl(
	current ImportJob,
	expectedRevision uint64,
	fence EntityID,
	now time.Time,
	required ImportJobState,
	outcome ImportRowOutcome,
	terminal ImportJobState,
) (ImportJob, error) {
	if ValidateImportJob(current) != nil || expectedRevision != current.revision ||
		current.state != required || current.fence == nil || *current.fence != fence ||
		current.leaseUntil == nil || !validImportInstant(now) || now.Before(current.updatedAt) ||
		!now.Before(*current.leaseUntil) || current.revision+1 >= maximumDefinitionVersion {
		return ImportJob{}, ErrImportJobConflict
	}
	snapshot := current.Snapshot()
	snapshot.State, snapshot.Revision, snapshot.UpdatedAt = terminal, current.revision+1, now
	snapshot.Results = importRemainderResults(current, outcome)
	snapshot.Fence, snapshot.LeaseUntil, snapshot.TerminalAt = nil, nil, &now
	return RestoreImportJob(snapshot)
}

func importRemainderResults(current ImportJob, outcome ImportRowOutcome) []ImportRowResult {
	results := cloneImportRowResults(current.results)
	for index := len(results); index < len(current.manifest.rows); index++ {
		result, err := NewImportRowResult(uint32(index+1), outcome, 0, nil)
		if err != nil {
			panic(err)
		}
		results = append(results, result)
	}
	return results
}

func validImportResultsForManifest(manifest ImportManifest, results []ImportRowResult) bool {
	if len(results) > len(manifest.rows) {
		return false
	}
	for index, result := range results {
		row := manifest.rows[index]
		if result.sequence != row.sequence {
			return false
		}
		rebuilt, err := NewImportRowResult(
			result.sequence, result.outcome, result.resultingVersion, result.fieldErrors,
		)
		if err != nil || !reflect.DeepEqual(rebuilt, result) {
			return false
		}
	}
	for index, result := range results {
		row := manifest.rows[index]
		switch result.outcome {
		case ImportRowDryRunValid:
			if manifest.mode != ImportDryRun || result.resultingVersion != row.expectedVersion {
				return false
			}
		case ImportRowCommitted:
			if manifest.mode != ImportCommit || row.expectedVersion+1 != result.resultingVersion {
				return false
			}
		case ImportRowNoChange:
			if result.resultingVersion != row.expectedVersion {
				return false
			}
		case ImportRowCancelled, ImportRowAuthorizationRevoked, ImportRowExpired, ImportRowInternalFailure:
			// These are control outcomes and may only appear as one terminal suffix.
			for suffix := index; suffix < len(results); suffix++ {
				if results[suffix].outcome != result.outcome {
					return false
				}
			}
			return len(results) == len(manifest.rows)
		}
	}
	return true
}

func validImportJobSnapshotShape(snapshot ImportJobSnapshot, progress ImportProgressSnapshot) bool {
	hasFence := snapshot.Fence != nil
	hasLease := snapshot.LeaseUntil != nil
	hasTerminal := snapshot.TerminalAt != nil
	if hasFence != hasLease || snapshot.Revision == 1 &&
		(snapshot.State != ImportJobPending || snapshot.Attempts != 0 || len(snapshot.Results) != 0 ||
			!snapshot.UpdatedAt.Equal(snapshot.RequestedAt) || !snapshot.AvailableAt.Equal(snapshot.RequestedAt)) {
		return false
	}
	if hasLease && (!validEntityID(*snapshot.Fence) || !validImportInstant(*snapshot.LeaseUntil) ||
		!snapshot.LeaseUntil.After(snapshot.UpdatedAt) || snapshot.LeaseUntil.After(snapshot.ExpiresAt) ||
		snapshot.LeaseUntil.Sub(snapshot.UpdatedAt) > ImportMaximumLease) {
		return false
	}
	if hasTerminal && (!validImportInstant(*snapshot.TerminalAt) ||
		!snapshot.TerminalAt.Equal(snapshot.UpdatedAt) || snapshot.TerminalAt.Before(snapshot.RequestedAt) ||
		snapshot.TerminalAt.After(snapshot.ExpiresAt) &&
			snapshot.State != ImportJobExpired && snapshot.State != ImportJobCancelled) {
		return false
	}
	switch snapshot.State {
	case ImportJobPending:
		return snapshot.Revision == 1 && snapshot.Attempts == 0 &&
			!hasFence && !hasTerminal && !progress.Complete() &&
			!snapshot.UpdatedAt.After(snapshot.ExpiresAt) &&
			!snapshot.AvailableAt.Before(snapshot.UpdatedAt)
	case ImportJobRunning:
		return hasFence && !hasTerminal && !progress.Complete() && snapshot.Attempts > 0 &&
			!snapshot.UpdatedAt.After(snapshot.ExpiresAt) &&
			!snapshot.AvailableAt.After(snapshot.UpdatedAt) && importControlProgress(progress) == 0
	case ImportJobCancellationRequested:
		return hasFence && !hasTerminal && !progress.Complete() && snapshot.Attempts > 0 &&
			!snapshot.UpdatedAt.After(snapshot.ExpiresAt) && importControlProgress(progress) == 0
	case ImportJobCompleted:
		return !hasFence && hasTerminal && progress.Complete() && importControlProgress(progress) == 0
	case ImportJobFailed:
		return !hasFence && hasTerminal && progress.Complete() && progress.InternalFailure > 0 &&
			progress.Cancelled == 0 && progress.AuthorizationRevoked == 0
	case ImportJobCancelled:
		return !hasFence && hasTerminal && progress.Complete() && progress.Cancelled > 0 &&
			progress.AuthorizationRevoked == 0 && progress.InternalFailure == 0
	case ImportJobAuthorizationRevoked:
		return !hasFence && hasTerminal && progress.Complete() && progress.AuthorizationRevoked > 0 &&
			progress.Cancelled == 0 && progress.Expired == 0 && progress.InternalFailure == 0
	case ImportJobExpired:
		return !hasFence && hasTerminal && progress.Complete() && progress.Expired > 0 &&
			progress.Cancelled == 0 && progress.AuthorizationRevoked == 0 && progress.InternalFailure == 0
	default:
		return false
	}
}

func completedImportState(progress ImportProgressSnapshot) ImportJobState {
	if progress.InternalFailure > 0 {
		return ImportJobFailed
	}
	if progress.AuthorizationRevoked > 0 {
		return ImportJobAuthorizationRevoked
	}
	if progress.Expired > 0 {
		return ImportJobExpired
	}
	if progress.Cancelled > 0 {
		return ImportJobCancelled
	}
	return ImportJobCompleted
}

func ordinaryImportResults(results []ImportRowResult) bool {
	for _, result := range results {
		if result.outcome == ImportRowCancelled || result.outcome == ImportRowAuthorizationRevoked ||
			result.outcome == ImportRowExpired ||
			result.outcome == ImportRowInternalFailure {
			return false
		}
	}
	return true
}

func importControlProgress(progress ImportProgressSnapshot) uint32 {
	return progress.Cancelled + progress.AuthorizationRevoked + progress.Expired + progress.InternalFailure
}

func validImportInstant(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond()%1_000 == 0 &&
		value.Year() >= 1 && value.Year() <= 9_999
}

func cloneImportManifest(manifest ImportManifest) ImportManifest {
	result := manifest
	result.definitions = cloneImportDefinitions(manifest.definitions)
	result.pins = append([]ImportDefinitionPin(nil), manifest.pins...)
	result.rows = cloneImportRows(manifest.rows)
	return result
}

func cloneImportEntity(value *EntityID) *EntityID {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func cloneImportTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}
