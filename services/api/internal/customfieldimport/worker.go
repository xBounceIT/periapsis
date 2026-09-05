package customfieldimport

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/customfields"
	customapp "github.com/periapsis-im/periapsis/services/api/internal/customfields"
)

const WorkerPurpose = "custom_field_import"

type RowAccess struct {
	tenant     uuid.UUID
	requester  uuid.UUID
	membership uuid.UUID
	objectType kernel.ObjectType
	target     uuid.UUID
	scope      customapp.Scope
	allowed    bool
}

func NewRowAccess(
	tenant uuid.UUID,
	requester uuid.UUID,
	membership uuid.UUID,
	objectType kernel.ObjectType,
	target uuid.UUID,
	scope customapp.Scope,
	allowed bool,
) (RowAccess, error) {
	if tenant == uuid.Nil || requester == uuid.Nil || membership == uuid.Nil || target == uuid.Nil ||
		objectType != kernel.ObjectAlert && objectType != kernel.ObjectCase ||
		scope != customapp.ScopeAssigned && scope != customapp.ScopeOperatorTeam && scope != customapp.ScopeTenant {
		return RowAccess{}, ErrInvalidInput
	}
	return RowAccess{
		tenant: tenant, requester: requester, membership: membership,
		objectType: objectType, target: target, scope: scope, allowed: allowed,
	}, nil
}

func (access RowAccess) Tenant() uuid.UUID             { return access.tenant }
func (access RowAccess) Requester() uuid.UUID          { return access.requester }
func (access RowAccess) Membership() uuid.UUID         { return access.membership }
func (access RowAccess) ObjectType() kernel.ObjectType { return access.objectType }
func (access RowAccess) Target() uuid.UUID             { return access.target }
func (access RowAccess) Scope() customapp.Scope        { return access.scope }
func (access RowAccess) Allowed() bool                 { return access.allowed }
func (access RowAccess) String() string                { return "RowAccess{authority:[REDACTED]}" }
func (access RowAccess) GoString() string              { return access.String() }

type RowSnapshot struct {
	Access          RowAccess
	FoundAndVisible bool
	CurrentVersion  uint64
	Definitions     []kernel.Definition
	Existing        []kernel.FieldValue
}

func (snapshot RowSnapshot) String() string {
	return fmt.Sprintf(
		"RowSnapshot{found:%t,current_version:%d,definitions:%d,existing:%d,data:[REDACTED]}",
		snapshot.FoundAndVisible, snapshot.CurrentVersion, len(snapshot.Definitions),
		len(snapshot.Existing),
	)
}
func (snapshot RowSnapshot) GoString() string { return snapshot.String() }

type RowCommandBinding struct {
	KeyHash     [sha256.Size]byte
	Fingerprint [sha256.Size]byte
}

func (binding RowCommandBinding) String() string {
	return "RowCommandBinding{key:[REDACTED],fingerprint:[REDACTED]}"
}
func (binding RowCommandBinding) GoString() string { return binding.String() }

type RowWrite struct {
	Tenant      uuid.UUID
	JobID       uuid.UUID
	JobRevision uint64
	Current     kernel.ImportJob
	Fence       kernel.EntityID
	Manifest    kernel.ImportManifest
	Row         kernel.ImportRow
	Access      RowAccess
	Patches     []kernel.FieldValue
	Intended    kernel.ImportRowResult
	Command     RowCommandBinding
	Audit       AuditContext
	RecordedAt  time.Time
}

func (write RowWrite) String() string {
	return fmt.Sprintf(
		"RowWrite{job_revision:%d,row:%d,outcome:%s,patches:%d,metadata:[REDACTED]}",
		write.JobRevision, write.Row.Sequence(), write.Intended.Outcome(), len(write.Patches),
	)
}
func (write RowWrite) GoString() string { return write.String() }

type RowReceipt struct {
	Result   kernel.ImportRowResult
	Command  RowCommandBinding
	Record   Record
	Replayed bool
}

func (receipt RowReceipt) String() string {
	return fmt.Sprintf("RowReceipt{result:%s,replayed:%t}", receipt.Result, receipt.Replayed)
}
func (receipt RowReceipt) GoString() string { return receipt.String() }

type JobWriteKind uint8

const (
	JobWriteClaim JobWriteKind = iota + 1
	JobWriteHeartbeat
	JobWriteControl
)

type JobWrite struct {
	Tenant  uuid.UUID
	JobID   uuid.UUID
	Kind    JobWriteKind
	Current kernel.ImportJob
	Next    kernel.ImportJob
	Fence   kernel.EntityID
}

func (write JobWrite) String() string {
	return fmt.Sprintf(
		"JobWrite{kind:%d,current_revision:%d,next_revision:%d,metadata:[REDACTED]}",
		write.Kind, write.Current.Revision(), write.Next.Revision(),
	)
}
func (write JobWrite) GoString() string { return write.String() }

// WorkerRepository is the future worker/persistence integration ABI. Row
// commits must revalidate live membership, ticket update scope, the exact
// definition pins, and ticket CAS in the same tenant/RLS transaction. In
// commit mode that transaction must also patch values, increment the ticket
// version, append audit/activity/outbox, insert the unique row receipt, and
// advance the job result/progress revision. Dry-run and rejected rows perform
// the same receipt+job transition without a ticket mutation. Replays return
// that exact stored receipt and job projection; divergent
// `(tenant, job, sequence)` payloads conflict. This coupling prevents a
// concurrent cancellation from hiding a mutation whose progress was not yet
// recorded.
type WorkerRepository interface {
	LoadForClaim(context.Context, uuid.UUID, uuid.UUID) (Record, error)
	LoadClaimed(context.Context, uuid.UUID, uuid.UUID, kernel.EntityID) (Record, error)
	CommitJob(context.Context, JobWrite) (Record, error)
	LoadRow(context.Context, Record, kernel.ImportRow, kernel.EntityID) (RowSnapshot, error)
	CommitRow(context.Context, RowWrite) (RowReceipt, error)
}

type Worker struct {
	repository WorkerRepository
}

func NewWorker(repository WorkerRepository) (*Worker, error) {
	if nilDependency(repository) {
		return nil, errors.New("custom-field import worker repository is required")
	}
	return &Worker{repository: repository}, nil
}

func (worker *Worker) Claim(
	ctx context.Context,
	tenant uuid.UUID,
	jobID uuid.UUID,
	expectedRevision uint64,
	fence kernel.EntityID,
	now, leaseUntil time.Time,
) (Record, error) {
	if ctx == nil || ctx.Err() != nil {
		return Record{}, ErrUnavailable
	}
	if !validWorkerIdentity(tenant, jobID, fence) || expectedRevision == 0 ||
		!validStoredInstant(now) || !validStoredInstant(leaseUntil) {
		return Record{}, ErrInvalidInput
	}
	record, err := worker.repository.LoadForClaim(ctx, tenant, jobID)
	if err != nil {
		return Record{}, repositoryError(err)
	}
	record, err = normalizeWorkerRecord(record, tenant, jobID)
	if err != nil {
		return Record{}, err
	}
	next, err := kernel.ClaimImportJob(record.Job, expectedRevision, fence, now, leaseUntil)
	if err != nil {
		if errors.Is(err, kernel.ErrImportJobConflict) {
			return Record{}, ErrConflict
		}
		return Record{}, ErrPreconditionFailed
	}
	committed, err := worker.repository.CommitJob(ctx, JobWrite{
		Tenant: tenant, JobID: jobID, Kind: JobWriteClaim,
		Current: record.Job, Next: next, Fence: fence,
	})
	if err != nil {
		return Record{}, repositoryError(err)
	}
	committed, err = normalizeWorkerRecord(committed, tenant, jobID)
	if err != nil || !kernel.SameImportJob(committed.Job, next) || committed.RequestedAudit != record.RequestedAudit {
		return Record{}, ErrUnavailable
	}
	return committed, nil
}

func (worker *Worker) Heartbeat(
	ctx context.Context,
	tenant uuid.UUID,
	jobID uuid.UUID,
	expectedRevision uint64,
	fence kernel.EntityID,
	now, leaseUntil time.Time,
) (Record, error) {
	if ctx == nil || ctx.Err() != nil {
		return Record{}, ErrUnavailable
	}
	if !validWorkerIdentity(tenant, jobID, fence) || expectedRevision == 0 ||
		!validStoredInstant(now) || !validStoredInstant(leaseUntil) {
		return Record{}, ErrInvalidInput
	}
	record, err := worker.repository.LoadClaimed(ctx, tenant, jobID, fence)
	if err != nil {
		return Record{}, repositoryError(err)
	}
	record, err = normalizeWorkerRecord(record, tenant, jobID)
	if err != nil {
		return Record{}, err
	}
	next, err := kernel.HeartbeatImportJob(
		record.Job, expectedRevision, fence, now, leaseUntil,
	)
	if err != nil {
		return Record{}, ErrConflict
	}
	return worker.commitJob(ctx, record, next, tenant, jobID, fence, JobWriteHeartbeat)
}

// RecoverExpired terminalizes pending jobs after retention expiry, abandoned
// cancellation requests after their lease, and exhausted/expired running jobs.
// The expected revision is persisted with the transition so a stale reaper
// cannot finalize a newly claimed fence.
func (worker *Worker) RecoverExpired(
	ctx context.Context,
	tenant uuid.UUID,
	jobID uuid.UUID,
	expectedRevision uint64,
	now time.Time,
) (Record, error) {
	if ctx == nil || ctx.Err() != nil {
		return Record{}, ErrUnavailable
	}
	if _, err := entityID(tenant); err != nil {
		return Record{}, ErrInvalidInput
	}
	if _, err := entityID(jobID); err != nil || expectedRevision == 0 || !validStoredInstant(now) {
		return Record{}, ErrInvalidInput
	}
	record, err := worker.repository.LoadForClaim(ctx, tenant, jobID)
	if err != nil {
		return Record{}, repositoryError(err)
	}
	record, err = normalizeWorkerRecord(record, tenant, jobID)
	if err != nil {
		return Record{}, err
	}
	next, err := kernel.ExpireImportJob(record.Job, expectedRevision, now)
	if err != nil {
		return Record{}, ErrConflict
	}
	fence := kernel.EntityID{}
	if record.Job.Fence() != nil {
		fence = *record.Job.Fence()
	}
	return worker.commitJob(ctx, record, next, tenant, jobID, fence, JobWriteControl)
}

func (worker *Worker) Fail(
	ctx context.Context,
	tenant uuid.UUID,
	jobID uuid.UUID,
	expectedRevision uint64,
	fence kernel.EntityID,
	now time.Time,
) (Record, error) {
	if ctx == nil || ctx.Err() != nil {
		return Record{}, ErrUnavailable
	}
	if !validWorkerIdentity(tenant, jobID, fence) || expectedRevision == 0 || !validStoredInstant(now) {
		return Record{}, ErrInvalidInput
	}
	record, err := worker.repository.LoadClaimed(ctx, tenant, jobID, fence)
	if err != nil {
		return Record{}, repositoryError(err)
	}
	record, err = normalizeWorkerRecord(record, tenant, jobID)
	if err != nil {
		return Record{}, err
	}
	next, err := kernel.FailImportJob(record.Job, expectedRevision, fence, now)
	if err != nil {
		return Record{}, ErrConflict
	}
	return worker.commitJob(ctx, record, next, tenant, jobID, fence, JobWriteControl)
}

func (worker *Worker) ProcessBatch(
	ctx context.Context,
	tenant uuid.UUID,
	jobID uuid.UUID,
	fence kernel.EntityID,
	limit int,
	now time.Time,
) (Record, error) {
	if ctx == nil || ctx.Err() != nil {
		return Record{}, ErrUnavailable
	}
	if !validWorkerIdentity(tenant, jobID, fence) ||
		limit <= 0 || limit > kernel.ImportMaximumBatchRows || !validStoredInstant(now) {
		return Record{}, ErrInvalidInput
	}
	record, err := worker.repository.LoadClaimed(ctx, tenant, jobID, fence)
	if err != nil {
		return Record{}, repositoryError(err)
	}
	record, err = normalizeWorkerRecord(record, tenant, jobID)
	if err != nil {
		return Record{}, err
	}
	if record.Job.Fence() == nil || *record.Job.Fence() != fence {
		return Record{}, ErrConflict
	}
	leaseUntil := record.Job.LeaseUntil()
	if leaseUntil == nil || now.Before(record.Job.UpdatedAt()) || !now.Before(*leaseUntil) {
		return Record{}, ErrConflict
	}
	if record.Job.State() == kernel.ImportJobCancellationRequested {
		next, planErr := kernel.CompleteImportCancellation(
			record.Job, record.Job.Revision(), fence, now,
		)
		if planErr != nil {
			return Record{}, ErrConflict
		}
		return worker.commitJob(ctx, record, next, tenant, jobID, fence, JobWriteControl)
	}
	if record.Job.State() != kernel.ImportJobRunning {
		return Record{}, ErrConflict
	}

	rows := record.Job.NextRows(limit)
	if len(rows) == 0 {
		return Record{}, ErrUnavailable
	}
	authorizationRevoked := false
	for _, row := range rows {
		if ctx.Err() != nil {
			return Record{}, ErrUnavailable
		}
		snapshot, loadErr := worker.repository.LoadRow(ctx, record, row, fence)
		if loadErr != nil {
			if errors.Is(loadErr, ErrRepositoryAuthorizationRevoked) {
				authorizationRevoked = true
				break
			}
			return Record{}, repositoryError(loadErr)
		}
		intended, patches, prepareErr := prepareRow(record.Job.Manifest(), row, snapshot)
		if prepareErr != nil {
			return Record{}, prepareErr
		}
		command, bindErr := bindRow(record.Job.Manifest(), row, patches, intended)
		if bindErr != nil {
			return Record{}, bindErr
		}
		receipt, commitErr := worker.repository.CommitRow(ctx, RowWrite{
			Tenant: tenant, JobID: jobID, JobRevision: record.Job.Revision(), Fence: fence,
			Current:  record.Job,
			Manifest: record.Job.Manifest(), Row: row, Access: snapshot.Access,
			Patches: slices.Clone(patches), Intended: intended, Command: command,
			Audit: record.RequestedAudit, RecordedAt: now,
		})
		if commitErr != nil {
			if errors.Is(commitErr, ErrRepositoryAuthorizationRevoked) {
				authorizationRevoked = true
				break
			}
			return Record{}, repositoryError(commitErr)
		}
		nextRecord, receiptErr := validateReceipt(
			record, row, intended, command, receipt, tenant, jobID, fence, now,
		)
		if receiptErr != nil {
			return Record{}, ErrUnavailable
		}
		record = nextRecord
	}
	if authorizationRevoked {
		next, planErr := kernel.RevokeImportAuthorization(
			record.Job, record.Job.Revision(), fence, now,
		)
		if planErr != nil {
			return Record{}, ErrConflict
		}
		return worker.commitJob(ctx, record, next, tenant, jobID, fence, JobWriteControl)
	}
	return record, nil
}

func (worker *Worker) commitJob(
	ctx context.Context,
	record Record,
	next kernel.ImportJob,
	tenant uuid.UUID,
	jobID uuid.UUID,
	fence kernel.EntityID,
	kind JobWriteKind,
) (Record, error) {
	committed, err := worker.repository.CommitJob(ctx, JobWrite{
		Tenant: tenant, JobID: jobID, Kind: kind,
		Current: record.Job, Next: next, Fence: fence,
	})
	if err != nil {
		return Record{}, repositoryError(err)
	}
	committed, err = normalizeWorkerRecord(committed, tenant, jobID)
	if err != nil || !kernel.SameImportJob(committed.Job, next) || committed.RequestedAudit != record.RequestedAudit {
		return Record{}, ErrUnavailable
	}
	return committed, nil
}

func prepareRow(
	manifest kernel.ImportManifest,
	row kernel.ImportRow,
	snapshot RowSnapshot,
) (kernel.ImportRowResult, []kernel.FieldValue, error) {
	if !validRowAccessShape(snapshot.Access) || !rowAccessMatches(manifest, row, snapshot.Access) {
		return kernel.ImportRowResult{}, nil, ErrUnavailable
	}
	if !snapshot.FoundAndVisible {
		result, _ := kernel.NewImportRowResult(row.Sequence(), kernel.ImportRowNotFoundOrHidden, 0, nil)
		return result, nil, nil
	}
	if !snapshot.Access.allowed {
		result, _ := kernel.NewImportRowResult(row.Sequence(), kernel.ImportRowAuthorizationDenied, 0, nil)
		return result, nil, nil
	}
	if snapshot.CurrentVersion != row.ExpectedVersion() {
		result, _ := kernel.NewImportRowResult(row.Sequence(), kernel.ImportRowVersionConflict, 0, nil)
		return result, nil, nil
	}
	if kernel.MatchImportDefinitionPins(manifest, snapshot.Definitions) != nil {
		result, _ := kernel.NewImportRowResult(row.Sequence(), kernel.ImportRowDefinitionChanged, 0, nil)
		return result, nil, nil
	}
	patches, fieldErrors, err := kernel.ValidateImportPatch(manifest, row, snapshot.Existing)
	if err != nil {
		if errors.Is(err, kernel.ErrImportDefinitionConflict) {
			result, _ := kernel.NewImportRowResult(row.Sequence(), kernel.ImportRowDefinitionChanged, 0, nil)
			return result, nil, nil
		}
		return kernel.ImportRowResult{}, nil, ErrUnavailable
	}
	if len(fieldErrors) != 0 {
		result, resultErr := kernel.NewImportRowResult(
			row.Sequence(), kernel.ImportRowValidationFailed, 0, fieldErrors,
		)
		if resultErr != nil {
			return kernel.ImportRowResult{}, nil, ErrUnavailable
		}
		return result, nil, nil
	}
	if len(patches) == 0 {
		result, _ := kernel.NewImportRowResult(
			row.Sequence(), kernel.ImportRowNoChange, row.ExpectedVersion(), nil,
		)
		return result, nil, nil
	}
	if manifest.Mode() == kernel.ImportDryRun {
		result, _ := kernel.NewImportRowResult(
			row.Sequence(), kernel.ImportRowDryRunValid, row.ExpectedVersion(), nil,
		)
		return result, patches, nil
	}
	result, _ := kernel.NewImportRowResult(
		row.Sequence(), kernel.ImportRowCommitted, row.ExpectedVersion()+1, nil,
	)
	return result, patches, nil
}

func bindRow(
	manifest kernel.ImportManifest,
	row kernel.ImportRow,
	patches []kernel.FieldValue,
	intended kernel.ImportRowResult,
) (RowCommandBinding, error) {
	if kernel.ValidateImportManifest(manifest) != nil || row.Sequence() == 0 ||
		intended.Sequence() != row.Sequence() {
		return RowCommandBinding{}, ErrUnavailable
	}
	patchItems := make([]struct {
		Definition string
		Version    uint64
		Presence   kernel.Presence
		Value      json.RawMessage
	}, len(patches))
	for index, patch := range patches {
		patchItems[index].Definition = patch.DefinitionID().String()
		patchItems[index].Version = patch.SchemaVersion()
		patchItems[index].Presence = patch.Value().Presence()
		patchItems[index].Value = patch.Value().CanonicalJSON()
	}
	slices.SortFunc(patchItems, func(left, right struct {
		Definition string
		Version    uint64
		Presence   kernel.Presence
		Value      json.RawMessage
	}) int {
		if left.Definition < right.Definition {
			return -1
		}
		if left.Definition > right.Definition {
			return 1
		}
		return 0
	})
	manifestDigest := manifest.RequestDigest()
	fieldErrors := intended.FieldErrors()
	errorItems := make([]struct {
		Field string
		Code  string
	}, len(fieldErrors))
	for index, fieldError := range fieldErrors {
		errorItems[index].Field = fieldError.Field.String()
		errorItems[index].Code = fieldError.Code
	}
	envelope := struct {
		Domain          string
		ManifestDigest  []byte
		Sequence        uint32
		Target          string
		ExpectedVersion uint64
		Outcome         string
		ResultVersion   uint64
		Patches         any
		FieldErrors     any
	}{
		Domain: "periapsis.custom-field-import-row.v1", ManifestDigest: manifestDigest[:],
		Sequence: row.Sequence(), Target: row.Target().String(), ExpectedVersion: row.ExpectedVersion(),
		Outcome: intended.Outcome().String(), ResultVersion: intended.ResultingVersion(),
		Patches: patchItems, FieldErrors: errorItems,
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return RowCommandBinding{}, ErrUnavailable
	}
	var sequence [4]byte
	binary.BigEndian.PutUint32(sequence[:], row.Sequence())
	manifestID := manifest.ID().Bytes()
	tenantID := manifest.Tenant().Bytes()
	keyInput := append([]byte("periapsis.custom-field-import-row-key.v1\x00"), tenantID[:]...)
	keyInput = append(keyInput, manifestID[:]...)
	keyInput = append(keyInput, sequence[:]...)
	return RowCommandBinding{
		KeyHash: sha256.Sum256(keyInput), Fingerprint: sha256.Sum256(encoded),
	}, nil
}

func validateReceipt(
	current Record,
	row kernel.ImportRow,
	intended kernel.ImportRowResult,
	command RowCommandBinding,
	receipt RowReceipt,
	tenant uuid.UUID,
	jobID uuid.UUID,
	fence kernel.EntityID,
	recordedAt time.Time,
) (Record, error) {
	if !sameRowResult(receipt.Result, row.Sequence()) || receipt.Command != command {
		return Record{}, ErrUnavailable
	}
	manifest := current.Job.Manifest()
	if receipt.Result.Outcome() == intended.Outcome() {
		if !reflect.DeepEqual(receipt.Result.FieldErrors(), intended.FieldErrors()) ||
			receipt.Result.ResultingVersion() != intended.ResultingVersion() {
			return Record{}, ErrUnavailable
		}
	} else {
		if !allowedPersistenceRaceOutcome(manifest.Mode(), intended.Outcome(), receipt.Result.Outcome()) {
			return Record{}, ErrUnavailable
		}
		switch receipt.Result.Outcome() {
		case kernel.ImportRowNoChange:
			if receipt.Result.ResultingVersion() != row.ExpectedVersion() {
				return Record{}, ErrUnavailable
			}
		case kernel.ImportRowDefinitionChanged, kernel.ImportRowVersionConflict,
			kernel.ImportRowNotFoundOrHidden, kernel.ImportRowAuthorizationDenied:
			if receipt.Result.ResultingVersion() != 0 || len(receipt.Result.FieldErrors()) != 0 {
				return Record{}, ErrUnavailable
			}
		default:
			return Record{}, ErrUnavailable
		}
	}
	record, err := normalizeWorkerRecord(receipt.Record, tenant, jobID)
	if err != nil || receipt.Record.RequestedAudit != current.RequestedAudit {
		return Record{}, ErrUnavailable
	}
	transitionAt := recordedAt
	if receipt.Replayed {
		transitionAt = record.Job.UpdatedAt()
	} else if !record.Job.UpdatedAt().Equal(recordedAt) {
		return Record{}, ErrUnavailable
	}
	next, err := kernel.RecordImportBatch(
		current.Job, current.Job.Revision(), fence,
		[]kernel.ImportRowResult{receipt.Result}, transitionAt,
	)
	if err != nil {
		return Record{}, ErrUnavailable
	}
	if !kernel.SameImportJob(record.Job, next) {
		return Record{}, ErrUnavailable
	}
	return record, nil
}

func allowedPersistenceRaceOutcome(
	mode kernel.ImportMode,
	intended kernel.ImportRowOutcome,
	actual kernel.ImportRowOutcome,
) bool {
	if intended == kernel.ImportRowCommitted && mode != kernel.ImportCommit ||
		intended == kernel.ImportRowDryRunValid && mode != kernel.ImportDryRun {
		return false
	}
	if intended == kernel.ImportRowCommitted && mode == kernel.ImportCommit &&
		actual == kernel.ImportRowNoChange {
		return true
	}
	if intended != kernel.ImportRowCommitted && intended != kernel.ImportRowDryRunValid &&
		intended != kernel.ImportRowNoChange && intended != kernel.ImportRowValidationFailed {
		return false
	}
	switch actual {
	case kernel.ImportRowDefinitionChanged, kernel.ImportRowVersionConflict,
		kernel.ImportRowNotFoundOrHidden, kernel.ImportRowAuthorizationDenied:
		return true
	default:
		return false
	}
}

func sameRowResult(result kernel.ImportRowResult, sequence uint32) bool {
	rebuilt, err := kernel.NewImportRowResult(
		result.Sequence(), result.Outcome(), result.ResultingVersion(), result.FieldErrors(),
	)
	return err == nil && result.Sequence() == sequence &&
		result.Outcome() == rebuilt.Outcome() && result.ResultingVersion() == rebuilt.ResultingVersion() &&
		reflect.DeepEqual(result.FieldErrors(), rebuilt.FieldErrors())
}

func validRowAccessShape(access RowAccess) bool {
	rebuilt, err := NewRowAccess(
		access.tenant, access.requester, access.membership, access.objectType,
		access.target, access.scope, access.allowed,
	)
	return err == nil && rebuilt == access
}

func rowAccessMatches(manifest kernel.ImportManifest, row kernel.ImportRow, access RowAccess) bool {
	return access.tenant == uuidFromEntity(manifest.Tenant()) &&
		access.requester == uuidFromEntity(manifest.Requester()) &&
		access.membership == uuidFromEntity(manifest.OwnerMembership()) &&
		access.objectType == manifest.ObjectType() && access.target == uuidFromEntity(row.Target())
}

func normalizeWorkerRecord(record Record, tenant, jobID uuid.UUID) (Record, error) {
	normalized, err := normalizeRecord(record, nil, &jobID)
	if err != nil || uuidFromEntity(normalized.Job.Manifest().Tenant()) != tenant {
		return Record{}, ErrUnavailable
	}
	return normalized, nil
}

func validWorkerIdentity(tenant, jobID uuid.UUID, fence kernel.EntityID) bool {
	if _, err := entityID(tenant); err != nil {
		return false
	}
	if _, err := entityID(jobID); err != nil {
		return false
	}
	rebuilt, err := kernel.ParseEntityID(fence.String())
	return err == nil && rebuilt == fence
}
