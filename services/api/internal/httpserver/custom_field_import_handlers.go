package httpserver

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/customfields"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	application "github.com/periapsis-im/periapsis/services/api/internal/customfieldimport"
)

const (
	customFieldImportDefaultRetention = 24 * time.Hour
	customFieldImportMaximumRevision  = int64(2_147_483_646)
	customFieldImportMaximumVersion   = uint64(9_007_199_254_740_990)
)

func (h *Handler) RequestTenantCustomFieldImport(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	params contract.RequestTenantCustomFieldImportParams,
) {
	tenant := uuid.UUID(tenantID)
	actor, audit, _, ok := h.phase4MutationActor(w, r, tenant)
	if !ok {
		return
	}
	idempotencyKey, err := requestIdempotencyKey(r)
	if err != nil || idempotencyKey != string(params.IdempotencyKey) {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	var body customFieldImportRequestBody
	if err := decodeCustomFieldImportRequestBody(r, &body); err != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	input, err := customFieldImportRequestInput(body, idempotencyKey, audit)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	result, err := h.customFieldImports.Request(r.Context(), actor.custom, tenant, input)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapCustomFieldImportMutation(result, tenant, actor.custom.UserID, input.ObjectType)
	if err != nil || mapped.Job.Mode != contract.CustomFieldImportMode(input.Mode.String()) ||
		mapped.Job.State != contract.CustomFieldImportJobStatePending || mapped.Job.Revision != 1 ||
		mapped.Job.Attempts != 0 || mapped.Job.ActiveAttempt ||
		!mapped.Job.RequestedAt.Equal(mapped.Job.UpdatedAt) ||
		!mapped.Job.RequestedAt.Equal(mapped.Job.AvailableAt) ||
		!setVersionETag(w, mapped.Job.Revision) {
		writeDomainError(w, r, application.ErrUnavailable)
		return
	}
	w.Header().Set(idempotentReplayHeader, strconv.FormatBool(mapped.Replayed))
	w.Header().Set(
		"Location",
		"/api/v1/tenants/"+tenant.String()+"/custom-field-imports/"+mapped.Job.Id.String(),
	)
	writePrivateJSON(w, http.StatusAccepted, mapped)
}

func (h *Handler) GetTenantCustomFieldImport(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	jobID uuid.UUID,
	params contract.GetTenantCustomFieldImportParams,
) {
	tenant := uuid.UUID(tenantID)
	actor, ok := h.phase4ReadActor(w, r, tenant)
	if !ok {
		return
	}
	objectType, err := customFieldObjectType(params.ObjectType)
	if err != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	record, err := h.customFieldImports.Get(r.Context(), actor.custom, tenant, objectType, jobID)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapCustomFieldImportJob(record.Job, tenant, actor.custom.UserID, objectType)
	if err != nil || !setVersionETag(w, mapped.Revision) {
		writeDomainError(w, r, application.ErrUnavailable)
		return
	}
	writePrivateJSON(w, http.StatusOK, mapped)
}

func (h *Handler) CancelTenantCustomFieldImport(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	jobID uuid.UUID,
	params contract.CancelTenantCustomFieldImportParams,
) {
	tenant := uuid.UUID(tenantID)
	actor, audit, _, ok := h.phase4MutationActor(w, r, tenant)
	if !ok {
		return
	}
	idempotencyKey, err := requestIdempotencyKey(r)
	if err != nil || idempotencyKey != string(params.IdempotencyKey) {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	var body contract.CustomFieldImportCancelRequest
	if err := decodePhase4Body(r, &body); err != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	expected, ok := customFieldImportPrecondition(
		w, r, string(params.IfMatch), body.ExpectedRevision,
	)
	if !ok {
		return
	}
	objectType, err := customFieldObjectType(body.ObjectType)
	if err != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	result, err := h.customFieldImports.Cancel(
		r.Context(), actor.custom, tenant, objectType, jobID,
		application.CancelInput{
			ExpectedRevision: expected,
			IdempotencyKey:   idempotencyKey,
			Audit:            audit,
		},
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapCustomFieldImportMutation(result, tenant, actor.custom.UserID, objectType)
	if err != nil || mapped.Job.Revision != int64(expected)+1 ||
		mapped.Job.State != contract.CustomFieldImportJobStateCancellationRequested &&
			mapped.Job.State != contract.CustomFieldImportJobStateCancelled ||
		!setVersionETag(w, mapped.Job.Revision) {
		writeDomainError(w, r, application.ErrUnavailable)
		return
	}
	w.Header().Set(idempotentReplayHeader, strconv.FormatBool(mapped.Replayed))
	writePrivateJSON(w, http.StatusOK, mapped)
}

func (h *Handler) ListTenantCustomFieldImportResults(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	jobID uuid.UUID,
	params contract.ListTenantCustomFieldImportResultsParams,
) {
	tenant := uuid.UUID(tenantID)
	actor, ok := h.phase4ReadActor(w, r, tenant)
	if !ok {
		return
	}
	objectType, err := customFieldObjectType(params.ObjectType)
	if err != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	after := int32(0)
	if params.After != nil {
		after = *params.After
	}
	pageSize := int32(100)
	if params.PageSize != nil {
		pageSize = *params.PageSize
	}
	if after < 0 || after > kernel.ImportMaximumRows || pageSize < 1 || pageSize > 100 {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	page, err := h.customFieldImports.ListResults(
		r.Context(), actor.custom, tenant, objectType, jobID, uint32(after), int(pageSize),
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapCustomFieldImportResultPage(page, uint32(after), int(pageSize))
	if err != nil {
		writeDomainError(w, r, application.ErrUnavailable)
		return
	}
	writePrivateJSON(w, http.StatusOK, mapped)
}

func customFieldImportRequestInput(
	body customFieldImportRequestBody,
	idempotencyKey string,
	audit application.AuditContext,
) (application.RequestInput, error) {
	objectType, err := customFieldObjectType(contract.CustomFieldObjectType(body.ObjectType))
	if err != nil {
		return application.RequestInput{}, application.ErrInvalidInput
	}
	var mode kernel.ImportMode
	switch contract.CustomFieldImportMode(body.Mode) {
	case contract.DryRun:
		mode = kernel.ImportDryRun
	case contract.Commit:
		mode = kernel.ImportCommit
	default:
		return application.RequestInput{}, application.ErrInvalidInput
	}
	retention := customFieldImportDefaultRetention
	if body.RetentionSeconds != nil {
		if *body.RetentionSeconds < int64(kernel.ImportMinimumRetention/time.Second) ||
			*body.RetentionSeconds > int64(kernel.ImportMaximumRetention/time.Second) {
			return application.RequestInput{}, application.ErrInvalidInput
		}
		retention = time.Duration(*body.RetentionSeconds) * time.Second
	}
	if len(body.Rows) == 0 || len(body.Rows) > kernel.ImportMaximumRows {
		return application.RequestInput{}, application.ErrInvalidInput
	}
	rows := make([]application.RowInput, len(body.Rows))
	cellCount := 0
	for rowIndex, source := range body.Rows {
		target, parseErr := uuid.Parse(source.TargetID)
		if parseErr != nil || source.ExpectedVersion == 0 ||
			source.ExpectedVersion > customFieldImportMaximumVersion ||
			len(source.Fields) > kernel.ImportMaximumFieldsPerRow {
			return application.RequestInput{}, application.ErrInvalidInput
		}
		cellCount += len(source.Fields)
		if cellCount > kernel.ImportMaximumCells {
			return application.RequestInput{}, application.ErrInvalidInput
		}
		fields := make([]application.CellInput, len(source.Fields))
		for fieldIndex, sourceField := range source.Fields {
			fields[fieldIndex] = application.CellInput{
				Key: sourceField.Key, Present: sourceField.Present,
				RawJSON: append([]byte(nil), sourceField.Value...),
			}
		}
		rows[rowIndex] = application.RowInput{
			Target: target, ExpectedVersion: source.ExpectedVersion, Fields: fields,
		}
	}
	return application.RequestInput{
		ObjectType: objectType, Mode: mode, Rows: rows, Retention: retention,
		IdempotencyKey: idempotencyKey, Audit: audit,
	}, nil
}

func customFieldImportPrecondition(
	w http.ResponseWriter,
	r *http.Request,
	parameter string,
	bodyRevision int64,
) (uint64, bool) {
	version, present, err := strongVersionPrecondition(r)
	if !present {
		writeDomainError(w, r, authorization.ErrPreconditionRequired)
		return 0, false
	}
	canonical, canonicalErr := strongVersionETag(version)
	if err != nil || canonicalErr != nil || canonical != parameter || version < 1 ||
		version > customFieldImportMaximumRevision || bodyRevision < 1 ||
		bodyRevision > customFieldImportMaximumRevision {
		writeDomainError(w, r, application.ErrInvalidInput)
		return 0, false
	}
	if version != bodyRevision {
		writeDomainError(w, r, application.ErrPreconditionFailed)
		return 0, false
	}
	return uint64(version), true
}

func mapCustomFieldImportMutation(
	result application.Result,
	tenantID uuid.UUID,
	requesterID uuid.UUID,
	objectType kernel.ObjectType,
) (contract.CustomFieldImportMutationResult, error) {
	job, err := mapCustomFieldImportJob(result.Record.Job, tenantID, requesterID, objectType)
	if err != nil {
		return contract.CustomFieldImportMutationResult{}, err
	}
	return contract.CustomFieldImportMutationResult{Job: job, Replayed: result.Replayed}, nil
}

func mapCustomFieldImportJob(
	job kernel.ImportJob,
	tenantID uuid.UUID,
	requesterID uuid.UUID,
	objectType kernel.ObjectType,
) (contract.CustomFieldImportJob, error) {
	if kernel.ValidateImportJob(job) != nil || tenantID == uuid.Nil || requesterID == uuid.Nil {
		return contract.CustomFieldImportJob{}, errors.New("invalid custom-field import job")
	}
	manifest := job.Manifest()
	jobID, jobErr := uuid.Parse(manifest.ID().String())
	storedTenant, tenantErr := uuid.Parse(manifest.Tenant().String())
	storedRequester, requesterErr := uuid.Parse(manifest.Requester().String())
	ownerMembership, ownerErr := uuid.Parse(manifest.OwnerMembership().String())
	if jobErr != nil || tenantErr != nil || requesterErr != nil || ownerErr != nil ||
		storedTenant != tenantID || storedRequester != requesterID ||
		manifest.ObjectType() != objectType || job.Revision() > uint64(customFieldImportMaximumRevision) ||
		job.Attempts() > kernel.ImportMaximumAttempts {
		return contract.CustomFieldImportJob{}, errors.New("custom-field import ownership diverged")
	}
	mode := contract.CustomFieldImportMode(manifest.Mode().String())
	state := contract.CustomFieldImportJobState(job.State().String())
	if !mode.Valid() || !state.Valid() {
		return contract.CustomFieldImportJob{}, errors.New("invalid custom-field import state")
	}
	progress := job.Progress()
	processed := progress.Processed()
	succeeded := progress.DryRunValid + progress.Committed
	rejected := progress.ValidationFailed + progress.DefinitionChanged
	if progress.Total > kernel.ImportMaximumRows || processed > progress.Total {
		return contract.CustomFieldImportJob{}, errors.New("invalid custom-field import progress")
	}
	fence, lease := job.Fence(), job.LeaseUntil()
	activeAttempt := fence != nil && lease != nil
	expectedActive := job.State() == kernel.ImportJobRunning ||
		job.State() == kernel.ImportJobCancellationRequested
	if activeAttempt != expectedActive {
		return contract.CustomFieldImportJob{}, errors.New("invalid custom-field import lease")
	}
	terminal := job.TerminalAt()
	var terminalAt *time.Time
	if terminal != nil {
		value := terminal.UTC()
		terminalAt = &value
	}
	return contract.CustomFieldImportJob{
		Id: jobID, TenantId: storedTenant, RequesterUserId: storedRequester,
		OwnerMembershipId: ownerMembership, ObjectType: contract.CustomFieldObjectType(objectType),
		Mode: mode, State: state, Revision: int64(job.Revision()), Attempts: int32(job.Attempts()),
		Progress: contract.CustomFieldImportProgress{
			Total: int32(progress.Total), Processed: int32(processed), Succeeded: int32(succeeded),
			NoChange: int32(progress.NoChange), VersionConflict: int32(progress.VersionConflict),
			NotFoundOrHidden:    int32(progress.NotFoundOrHidden),
			AuthorizationDenied: int32(progress.AuthorizationDenied), Rejected: int32(rejected),
			Cancelled: int32(progress.Cancelled), AuthorizationRevoked: int32(progress.AuthorizationRevoked),
			Expired: int32(progress.Expired), InternalFailure: int32(progress.InternalFailure),
		},
		RequestedAt: job.RequestedAt().UTC(), UpdatedAt: job.UpdatedAt().UTC(),
		AvailableAt: job.AvailableAt().UTC(), ExpiresAt: job.ExpiresAt().UTC(),
		TerminalAt: terminalAt, ActiveAttempt: activeAttempt,
	}, nil
}

func mapCustomFieldImportResultPage(
	page application.ResultPage,
	after uint32,
	pageSize int,
) (contract.CustomFieldImportResultPage, error) {
	if page.Items == nil || len(page.Items) > pageSize || len(page.Items) == 0 && page.NextAfter != nil {
		return contract.CustomFieldImportResultPage{}, errors.New("invalid custom-field import result page")
	}
	items := make([]contract.CustomFieldImportResult, len(page.Items))
	expectedSequence := after + 1
	for index, source := range page.Items {
		if source.Sequence != expectedSequence || source.Result.Sequence() != source.Sequence ||
			source.ExpectedVersion == 0 || source.ExpectedVersion > customFieldImportMaximumVersion ||
			source.Target == uuid.Nil || source.Target.Version() != 7 ||
			!validCustomFieldImportTime(source.RecordedAt) {
			return contract.CustomFieldImportResultPage{}, errors.New("invalid custom-field import result")
		}
		outcome := contract.CustomFieldImportOutcome(source.Result.Outcome().String())
		if !outcome.Valid() || !validCustomFieldImportResultVersion(source) {
			return contract.CustomFieldImportResultPage{}, errors.New("invalid custom-field import result semantics")
		}
		errorsList := source.Result.FieldErrors()
		fieldErrors := make([]contract.CustomFieldImportFieldError, len(errorsList))
		for errorIndex, fieldError := range errorsList {
			code := contract.CustomFieldImportFieldErrorCode(fieldError.Code)
			if !code.Valid() || fieldError.Field.String() == "" {
				return contract.CustomFieldImportResultPage{}, errors.New("invalid custom-field import field error")
			}
			fieldErrors[errorIndex] = contract.CustomFieldImportFieldError{
				Field: fieldError.Field.String(), Code: code,
			}
		}
		items[index] = contract.CustomFieldImportResult{
			Sequence: int32(source.Sequence), TargetId: source.Target,
			ExpectedVersion: int64(source.ExpectedVersion), Outcome: outcome,
			ResultingVersion: int64(source.Result.ResultingVersion()),
			FieldErrors:      fieldErrors, RecordedAt: source.RecordedAt.UTC(),
		}
		expectedSequence++
	}
	var nextAfter *int32
	if page.NextAfter != nil {
		if len(items) != pageSize || *page.NextAfter != page.Items[len(page.Items)-1].Sequence {
			return contract.CustomFieldImportResultPage{}, errors.New("invalid custom-field import cursor")
		}
		value := int32(*page.NextAfter)
		nextAfter = &value
	}
	return contract.CustomFieldImportResultPage{Items: items, NextAfter: nextAfter}, nil
}

func validCustomFieldImportResultVersion(result application.RowResult) bool {
	expected, resulting := result.ExpectedVersion, result.Result.ResultingVersion()
	switch result.Result.Outcome() {
	case kernel.ImportRowDryRunValid, kernel.ImportRowNoChange:
		return resulting == expected
	case kernel.ImportRowCommitted:
		return resulting == expected+1
	default:
		return resulting == 0
	}
}

func validCustomFieldImportTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC &&
		value.Nanosecond()%int(time.Microsecond) == 0
}
