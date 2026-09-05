package customfieldimport

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/customfields"
)

type Service struct {
	repository Repository
	clock      func() time.Time
}

func NewService(repository Repository, clock func() time.Time) (*Service, error) {
	if nilDependency(repository) {
		return nil, errors.New("custom-field import repository is required")
	}
	if clock == nil {
		clock = time.Now
	}
	return &Service{repository: repository, clock: clock}, nil
}

func (service *Service) Request(
	ctx context.Context,
	actor Actor,
	tenant uuid.UUID,
	input RequestInput,
) (Result, error) {
	if ctx == nil || ctx.Err() != nil {
		return Result{}, ErrUnavailable
	}
	if err := validEnvelope(actor, tenant, input.IdempotencyKey, input.Audit); err != nil {
		return Result{}, err
	}
	if input.ObjectType != kernel.ObjectAlert && input.ObjectType != kernel.ObjectCase ||
		input.Mode != kernel.ImportDryRun && input.Mode != kernel.ImportCommit ||
		len(input.Rows) == 0 || len(input.Rows) > kernel.ImportMaximumRows ||
		input.Retention < kernel.ImportMinimumRetention || input.Retention > kernel.ImportMaximumRetention ||
		input.Retention%time.Microsecond != 0 {
		return Result{}, ErrInvalidInput
	}
	access, err := service.repository.ResolveAccess(
		ctx, actor, tenant, input.ObjectType, CapabilityRequest,
	)
	if err != nil {
		return Result{}, repositoryError(err)
	}
	if !validAccess(actor, tenant, input.ObjectType, CapabilityRequest, access) {
		return Result{}, ErrForbidden
	}

	manifestRows, err := parseRows(input.Rows)
	if err != nil {
		return Result{}, err
	}
	tenantID, tenantErr := entityID(tenant)
	requesterID, requesterErr := entityID(actor.UserID)
	membershipID, membershipErr := entityID(actor.MembershipID)
	if tenantErr != nil || requesterErr != nil || membershipErr != nil {
		return Result{}, ErrInvalidInput
	}
	// A definition-free manifest yields a canonical digest of the caller's
	// request. Looking it up before loading mutable definitions makes a replay
	// stable even when the tenant definition inventory has since advanced.
	draft, err := kernel.NewImportManifest(kernel.ImportManifestInput{
		ID: tenantID, Tenant: tenantID, Requester: requesterID, OwnerMembership: membershipID,
		ObjectType: input.ObjectType, Mode: input.Mode, Rows: manifestRows,
		ProjectionVersion: kernel.ImportProjectionVersion,
		MaximumAttempts:   kernel.ImportMaximumAttempts,
	})
	if err != nil {
		return Result{}, ErrInvalidInput
	}
	command, err := bindRequest(
		input.IdempotencyKey, actor, tenant, input.ObjectType, input.Mode,
		draft.RequestDigest(), input.Retention,
	)
	if err != nil {
		return Result{}, err
	}
	replay, found, err := service.repository.LookupReplay(ctx, ReplayQuery{
		Actor: actor, Tenant: tenant, ObjectType: input.ObjectType, Command: command,
	})
	if err != nil {
		return Result{}, repositoryError(err)
	}
	if found {
		return validateRequestReplay(replay, draft, access, input.Retention)
	}

	definitions, err := service.repository.LoadDefinitions(
		ctx, actor, tenant, input.ObjectType, access,
	)
	if err != nil {
		return Result{}, repositoryError(err)
	}
	if len(definitions) > kernel.ImportMaximumDefinitions {
		return Result{}, ErrUnavailable
	}
	definitions = operatorVisibleDefinitions(definitions)
	jobID, err := service.repository.ReserveImportID(ctx, tenant)
	if err != nil {
		return Result{}, repositoryError(err)
	}
	manifest, err := kernel.NewImportManifest(kernel.ImportManifestInput{
		ID: jobID, Tenant: tenantID, Requester: requesterID, OwnerMembership: membershipID,
		ObjectType: input.ObjectType, Mode: input.Mode, Definitions: definitions, Rows: manifestRows,
		ProjectionVersion: kernel.ImportProjectionVersion,
		MaximumAttempts:   kernel.ImportMaximumAttempts,
	})
	if err != nil {
		return Result{}, ErrUnavailable
	}
	if !sameRequestShape(manifest, draft) {
		return Result{}, ErrUnavailable
	}
	requestedAt, err := service.now()
	if err != nil {
		return Result{}, err
	}
	job, err := kernel.NewImportJob(manifest, requestedAt, requestedAt.Add(input.Retention))
	if err != nil {
		return Result{}, ErrInvalidInput
	}
	result, err := service.repository.CommitRequest(ctx, RequestWrite{
		Actor: actor, Access: access, Job: job, Command: command, Audit: input.Audit,
	})
	if err != nil {
		return Result{}, repositoryError(err)
	}
	if result.Replayed {
		return validateRequestReplay(result, draft, access, input.Retention)
	}
	return validateCommittedRequest(result, job, draft, access, input.Audit)
}

func (service *Service) Get(
	ctx context.Context,
	actor Actor,
	tenant uuid.UUID,
	objectType kernel.ObjectType,
	jobID uuid.UUID,
) (Record, error) {
	if ctx == nil || ctx.Err() != nil {
		return Record{}, ErrUnavailable
	}
	if !validActor(actor, tenant) {
		return Record{}, ErrForbidden
	}
	if _, err := entityID(jobID); err != nil ||
		objectType != kernel.ObjectAlert && objectType != kernel.ObjectCase {
		return Record{}, ErrInvalidInput
	}
	access, err := service.repository.ResolveAccess(ctx, actor, tenant, objectType, CapabilityRead)
	if err != nil {
		return Record{}, repositoryError(err)
	}
	if !validAccess(actor, tenant, objectType, CapabilityRead, access) {
		return Record{}, ErrForbidden
	}
	record, err := service.repository.Get(ctx, actor, tenant, jobID, access)
	if err != nil {
		return Record{}, repositoryError(err)
	}
	return normalizeRecord(record, &access, &jobID)
}

func (service *Service) ListResults(
	ctx context.Context,
	actor Actor,
	tenant uuid.UUID,
	objectType kernel.ObjectType,
	jobID uuid.UUID,
	after uint32,
	pageSize int,
) (ResultPage, error) {
	if ctx == nil || ctx.Err() != nil {
		return ResultPage{}, ErrUnavailable
	}
	if !validActor(actor, tenant) {
		return ResultPage{}, ErrForbidden
	}
	if _, err := entityID(jobID); err != nil ||
		objectType != kernel.ObjectAlert && objectType != kernel.ObjectCase ||
		after > kernel.ImportMaximumRows || pageSize < 1 || pageSize > 100 {
		return ResultPage{}, ErrInvalidInput
	}
	access, err := service.repository.ResolveAccess(ctx, actor, tenant, objectType, CapabilityRead)
	if err != nil {
		return ResultPage{}, repositoryError(err)
	}
	if !validAccess(actor, tenant, objectType, CapabilityRead, access) {
		return ResultPage{}, ErrForbidden
	}
	page, err := service.repository.ListResults(
		ctx, actor, tenant, jobID, access, after, pageSize,
	)
	if err != nil {
		return ResultPage{}, repositoryError(err)
	}
	if page.Items == nil || len(page.Items) > pageSize || len(page.Items) == 0 && page.NextAfter != nil {
		return ResultPage{}, ErrUnavailable
	}
	expectedSequence := after + 1
	for _, item := range page.Items {
		rebuilt, resultErr := kernel.NewImportRowResult(
			item.Result.Sequence(), item.Result.Outcome(), item.Result.ResultingVersion(),
			item.Result.FieldErrors(),
		)
		if resultErr != nil || rebuilt.Sequence() != item.Sequence || item.Sequence != expectedSequence ||
			item.Target == uuid.Nil || item.Target.Version() != 7 || item.ExpectedVersion == 0 ||
			item.ExpectedVersion >= maximumExpectedVersion || !validStoredInstant(item.RecordedAt) {
			return ResultPage{}, ErrUnavailable
		}
		expectedSequence++
	}
	if page.NextAfter != nil && (len(page.Items) != pageSize ||
		*page.NextAfter != page.Items[len(page.Items)-1].Sequence) {
		return ResultPage{}, ErrUnavailable
	}
	return page, nil
}

func (service *Service) Cancel(
	ctx context.Context,
	actor Actor,
	tenant uuid.UUID,
	objectType kernel.ObjectType,
	jobID uuid.UUID,
	input CancelInput,
) (Result, error) {
	if ctx == nil || ctx.Err() != nil {
		return Result{}, ErrUnavailable
	}
	if err := validEnvelope(actor, tenant, input.IdempotencyKey, input.Audit); err != nil {
		return Result{}, err
	}
	if _, err := entityID(jobID); err != nil || input.ExpectedRevision == 0 ||
		input.ExpectedRevision >= maximumImportRevision ||
		objectType != kernel.ObjectAlert && objectType != kernel.ObjectCase {
		return Result{}, ErrInvalidInput
	}
	access, err := service.repository.ResolveAccess(ctx, actor, tenant, objectType, CapabilityCancel)
	if err != nil {
		return Result{}, repositoryError(err)
	}
	if !validAccess(actor, tenant, objectType, CapabilityCancel, access) {
		return Result{}, ErrForbidden
	}
	command, err := bindCancellation(
		input.IdempotencyKey, actor, tenant, objectType, jobID, input.ExpectedRevision,
	)
	if err != nil {
		return Result{}, err
	}
	replay, found, err := service.repository.LookupReplay(ctx, ReplayQuery{
		Actor: actor, Tenant: tenant, ObjectType: objectType, Command: command,
	})
	if err != nil {
		return Result{}, repositoryError(err)
	}
	if found {
		return validateCancellationReplay(replay, access, jobID, input.ExpectedRevision)
	}
	current, err := service.repository.Get(ctx, actor, tenant, jobID, access)
	if err != nil {
		return Result{}, repositoryError(err)
	}
	current, err = normalizeRecord(current, &access, &jobID)
	if err != nil {
		return Result{}, err
	}
	if current.Job.Revision() != input.ExpectedRevision {
		// A matching cancellation can commit between the initial replay lookup
		// and this read. Re-check the immutable command receipt before returning
		// a stale-revision failure so concurrent identical requests converge on
		// the exact winner response.
		replay, found, lookupErr := service.repository.LookupReplay(ctx, ReplayQuery{
			Actor: actor, Tenant: tenant, ObjectType: objectType, Command: command,
		})
		if lookupErr != nil {
			return Result{}, repositoryError(lookupErr)
		}
		if found {
			return validateCancellationReplay(replay, access, jobID, input.ExpectedRevision)
		}
		return Result{}, ErrPreconditionFailed
	}
	now, err := service.now()
	if err != nil {
		return Result{}, err
	}
	next, err := kernel.RequestImportCancellation(current.Job, input.ExpectedRevision, now)
	if err != nil {
		if errors.Is(err, kernel.ErrImportJobConflict) {
			return Result{}, ErrConflict
		}
		return Result{}, ErrUnavailable
	}
	result, err := service.repository.CommitCancellation(ctx, CancellationWrite{
		Actor: actor, Access: access, Current: current.Job, Next: next,
		Command: command, Audit: input.Audit,
	})
	if err != nil {
		return Result{}, repositoryError(err)
	}
	record, err := normalizeRecord(result.Record, &access, &jobID)
	if err != nil || record.RequestedAudit != current.RequestedAudit {
		return Result{}, ErrUnavailable
	}
	committedNext := next
	if result.Replayed {
		committedNext, err = kernel.RequestImportCancellation(
			current.Job, input.ExpectedRevision, record.Job.UpdatedAt(),
		)
	}
	if err != nil || !kernel.SameImportJob(record.Job, committedNext) {
		return Result{}, ErrUnavailable
	}
	result.Record = record
	return result, nil
}

func validateCancellationReplay(
	replay Result,
	access Access,
	jobID uuid.UUID,
	expectedRevision uint64,
) (Result, error) {
	record, err := normalizeRecord(replay.Record, &access, &jobID)
	if err != nil || record.Job.Revision() != expectedRevision+1 ||
		record.Job.State() != kernel.ImportJobCancellationRequested &&
			record.Job.State() != kernel.ImportJobCancelled {
		return Result{}, ErrUnavailable
	}
	replay.Record, replay.Replayed = record, true
	return replay, nil
}

func (service *Service) now() (time.Time, error) {
	now := service.clock()
	if now.IsZero() {
		return time.Time{}, ErrUnavailable
	}
	now = now.UTC().Truncate(time.Microsecond)
	if !validStoredInstant(now) || now.Year() < 1 || now.Year() > 9_999 {
		return time.Time{}, ErrUnavailable
	}
	return now, nil
}

func nilDependency(value any) bool {
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

func parseRows(inputs []RowInput) ([]kernel.ImportRowInput, error) {
	rows := make([]kernel.ImportRowInput, len(inputs))
	cellCount := 0
	payloadBytes := 0
	for index, input := range inputs {
		target, err := entityID(input.Target)
		if err != nil || input.ExpectedVersion == 0 || input.ExpectedVersion >= maximumExpectedVersion ||
			len(input.Fields) > kernel.ImportMaximumFieldsPerRow {
			return nil, ErrInvalidInput
		}
		cellCount += len(input.Fields)
		if cellCount > kernel.ImportMaximumCells {
			return nil, ErrInvalidInput
		}
		fields := make([]kernel.FieldInput, len(input.Fields))
		for fieldIndex, raw := range input.Fields {
			key, keyErr := kernel.NewKey(raw.Key)
			if keyErr != nil || !raw.Present && len(raw.RawJSON) != 0 ||
				raw.Present && len(raw.RawJSON) == 0 {
				return nil, ErrInvalidInput
			}
			cellBytes := len(raw.Key) + len(raw.RawJSON)
			if cellBytes > kernel.ImportMaximumPayloadBytes-payloadBytes {
				return nil, ErrInvalidInput
			}
			payloadBytes += cellBytes
			value := kernel.MissingInputValue()
			if raw.Present {
				value = kernel.JSONInputValue(raw.RawJSON)
			}
			fields[fieldIndex] = kernel.FieldInput{Key: key, Value: value}
		}
		rows[index] = kernel.ImportRowInput{
			Sequence: uint32(index + 1), Target: target,
			ExpectedVersion: input.ExpectedVersion, Fields: fields,
		}
	}
	return rows, nil
}

func sameRequestShape(actual, draft kernel.ImportManifest) bool {
	if kernel.ValidateImportManifest(actual) != nil || kernel.ValidateImportManifest(draft) != nil {
		return false
	}
	withoutDefinitions, err := kernel.NewImportManifest(kernel.ImportManifestInput{
		ID: actual.ID(), Tenant: actual.Tenant(), Requester: actual.Requester(),
		OwnerMembership: actual.OwnerMembership(), ObjectType: actual.ObjectType(), Mode: actual.Mode(),
		Rows: importRowInputs(actual.Rows()), ProjectionVersion: actual.ProjectionVersion(),
		MaximumAttempts: actual.MaximumAttempts(),
	})
	return err == nil && kernel.SameImportRequest(withoutDefinitions, draft)
}

func importRowInputs(rows []kernel.ImportRow) []kernel.ImportRowInput {
	result := make([]kernel.ImportRowInput, len(rows))
	for index, row := range rows {
		cells := row.Cells()
		fields := make([]kernel.FieldInput, len(cells))
		for fieldIndex, cell := range cells {
			fields[fieldIndex] = kernel.FieldInput{Key: cell.Key(), Value: cell.InputValue()}
		}
		result[index] = kernel.ImportRowInput{
			Sequence: row.Sequence(), Target: row.Target(),
			ExpectedVersion: row.ExpectedVersion(), Fields: fields,
		}
	}
	return result
}

func operatorVisibleDefinitions(definitions []kernel.Definition) []kernel.Definition {
	visible := make([]kernel.Definition, 0, len(definitions))
	for _, definition := range definitions {
		if definition.VisibleTo(kernel.AudienceOperator) {
			visible = append(visible, definition)
		}
	}
	return visible
}

func validateRequestReplay(
	result Result,
	draft kernel.ImportManifest,
	access Access,
	retention time.Duration,
) (Result, error) {
	record, err := normalizeRecord(result.Record, &access, nil)
	if err != nil || !sameRequestShape(record.Job.Manifest(), draft) ||
		record.Job.State() != kernel.ImportJobPending || record.Job.Revision() != 1 ||
		record.Job.ExpiresAt().Sub(record.Job.RequestedAt()) != retention {
		return Result{}, ErrUnavailable
	}
	result.Record, result.Replayed = record, true
	return result, nil
}

func validateCommittedRequest(
	result Result,
	expected kernel.ImportJob,
	draft kernel.ImportManifest,
	access Access,
	audit AuditContext,
) (Result, error) {
	record, err := normalizeRecord(result.Record, &access, nil)
	if err != nil || !kernel.SameImportJob(record.Job, expected) ||
		!sameRequestShape(record.Job.Manifest(), draft) || record.RequestedAudit != audit {
		return Result{}, ErrUnavailable
	}
	result.Record = record
	return result, nil
}

func normalizeRecord(record Record, access *Access, jobID *uuid.UUID) (Record, error) {
	if kernel.ValidateImportJob(record.Job) != nil || !validAudit(record.RequestedAudit) {
		return Record{}, ErrUnavailable
	}
	manifest := record.Job.Manifest()
	if access != nil && (uuidFromEntity(manifest.Tenant()) != access.tenant ||
		uuidFromEntity(manifest.Requester()) != access.actor ||
		uuidFromEntity(manifest.OwnerMembership()) != access.membership ||
		manifest.ObjectType() != access.objectType) {
		return Record{}, ErrUnavailable
	}
	if jobID != nil && uuidFromEntity(manifest.ID()) != *jobID {
		return Record{}, ErrUnavailable
	}
	return record, nil
}

func repositoryError(err error) error {
	switch {
	case errors.Is(err, ErrRepositoryForbidden):
		return ErrForbidden
	case errors.Is(err, ErrRepositoryNotFound):
		return ErrNotFound
	case errors.Is(err, ErrRepositoryConflict):
		return ErrConflict
	case errors.Is(err, ErrRepositoryPrecondition):
		return ErrPreconditionFailed
	default:
		return ErrUnavailable
	}
}
