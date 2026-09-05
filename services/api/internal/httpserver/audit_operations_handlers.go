package httpserver

import (
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/auditoperations"
	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
)

func (h *Handler) CreateTenantAuditExport(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	params contract.CreateTenantAuditExportParams,
) {
	session, event, ok := h.auditOperationMutation(w, r)
	if !ok {
		return
	}
	key, reason, ok := auditOperationHeaders(w, r, string(params.IdempotencyKey), string(params.XAuditReason))
	if !ok {
		return
	}
	input, err := auditExportInput(r, key, reason, event, auditoperations.StreamTenant)
	if err != nil {
		writeAuditOperationsError(w, r, err)
		return
	}
	result, err := h.auditOperations.CreateTenantExport(r.Context(), session, uuid.UUID(tenantID), input)
	if err != nil {
		writeAuditOperationsError(w, r, err)
		return
	}
	mapped, err := mapAuditExportMutation(result)
	if err != nil {
		writeAuditOperationsError(w, r, err)
		return
	}
	w.Header().Set("Location", fmt.Sprintf("/api/v1/tenants/%s/audit-exports/%s", tenantID, result.Job.ID))
	writeAuditOperationsJSON(w, http.StatusAccepted, mapped)
}

func (h *Handler) CreatePlatformAuditExport(
	w http.ResponseWriter,
	r *http.Request,
	params contract.CreatePlatformAuditExportParams,
) {
	session, event, ok := h.auditOperationMutation(w, r)
	if !ok {
		return
	}
	key, reason, ok := auditOperationHeaders(w, r, string(params.IdempotencyKey), string(params.XAuditReason))
	if !ok {
		return
	}
	input, err := auditExportInput(r, key, reason, event, auditoperations.StreamPlatform)
	if err != nil {
		writeAuditOperationsError(w, r, err)
		return
	}
	result, err := h.auditOperations.CreatePlatformExport(r.Context(), session, input)
	if err != nil {
		writeAuditOperationsError(w, r, err)
		return
	}
	mapped, err := mapAuditExportMutation(result)
	if err != nil {
		writeAuditOperationsError(w, r, err)
		return
	}
	w.Header().Set("Location", "/api/v1/platform/audit-exports/"+result.Job.ID.String())
	writeAuditOperationsJSON(w, http.StatusAccepted, mapped)
}

func (h *Handler) GetTenantAuditExport(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	exportID contract.AuditExportId,
) {
	session, event, ok := h.auditOperationRead(w, r)
	if !ok {
		return
	}
	job, err := h.auditOperations.GetTenantExport(r.Context(), session, uuid.UUID(tenantID), uuid.UUID(exportID), event)
	if err != nil {
		writeAuditOperationsError(w, r, err)
		return
	}
	mapped, err := mapAuditExportJob(job)
	if err != nil || !setVersionETag(w, job.Revision) {
		writeAuditOperationsError(w, r, auditoperations.ErrUnavailable)
		return
	}
	writeAuditOperationsJSON(w, http.StatusOK, mapped)
}

func (h *Handler) GetPlatformAuditExport(
	w http.ResponseWriter,
	r *http.Request,
	exportID contract.AuditExportId,
) {
	session, event, ok := h.auditOperationRead(w, r)
	if !ok {
		return
	}
	job, err := h.auditOperations.GetPlatformExport(r.Context(), session, uuid.UUID(exportID), event)
	if err != nil {
		writeAuditOperationsError(w, r, err)
		return
	}
	mapped, err := mapAuditExportJob(job)
	if err != nil || !setVersionETag(w, job.Revision) {
		writeAuditOperationsError(w, r, auditoperations.ErrUnavailable)
		return
	}
	writeAuditOperationsJSON(w, http.StatusOK, mapped)
}

func (h *Handler) CancelTenantAuditExport(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	exportID contract.AuditExportId,
	params contract.CancelTenantAuditExportParams,
) {
	session, event, ok := h.auditOperationMutation(w, r)
	if !ok {
		return
	}
	key, reason, ok := auditOperationHeaders(w, r, string(params.IdempotencyKey), string(params.XAuditReason))
	if !ok {
		return
	}
	var body contract.AuditExportCancelRequest
	if decodeAuthorizationBody(r, &body, "application/json") != nil {
		writeAuditOperationsError(w, r, auditoperations.ErrInvalidInput)
		return
	}
	expected, ok := auditOperationPrecondition(w, r, string(params.IfMatch), body.ExpectedRevision)
	if !ok {
		return
	}
	result, err := h.auditOperations.CancelTenantExport(r.Context(), session, uuid.UUID(tenantID), auditoperations.CancelExportInput{
		ExportID: uuid.UUID(exportID), ExpectedRevision: expected,
		IdempotencyKey: key, Reason: reason, Event: event,
	})
	writeAuditExportCancellation(w, r, result, err)
}

func (h *Handler) CancelPlatformAuditExport(
	w http.ResponseWriter,
	r *http.Request,
	exportID contract.AuditExportId,
	params contract.CancelPlatformAuditExportParams,
) {
	session, event, ok := h.auditOperationMutation(w, r)
	if !ok {
		return
	}
	key, reason, ok := auditOperationHeaders(w, r, string(params.IdempotencyKey), string(params.XAuditReason))
	if !ok {
		return
	}
	var body contract.AuditExportCancelRequest
	if decodeAuthorizationBody(r, &body, "application/json") != nil {
		writeAuditOperationsError(w, r, auditoperations.ErrInvalidInput)
		return
	}
	expected, ok := auditOperationPrecondition(w, r, string(params.IfMatch), body.ExpectedRevision)
	if !ok {
		return
	}
	result, err := h.auditOperations.CancelPlatformExport(r.Context(), session, auditoperations.CancelExportInput{
		ExportID: uuid.UUID(exportID), ExpectedRevision: expected,
		IdempotencyKey: key, Reason: reason, Event: event,
	})
	writeAuditExportCancellation(w, r, result, err)
}

func writeAuditExportCancellation(
	w http.ResponseWriter,
	r *http.Request,
	result auditoperations.ExportMutationResult,
	err error,
) {
	if err != nil {
		writeAuditOperationsError(w, r, err)
		return
	}
	mapped, err := mapAuditExportMutation(result)
	if err != nil || !setVersionETag(w, result.Job.Revision) {
		writeAuditOperationsError(w, r, auditoperations.ErrUnavailable)
		return
	}
	writeAuditOperationsJSON(w, http.StatusOK, mapped)
}

func (h *Handler) DownloadTenantAuditExport(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	exportID contract.AuditExportId,
) {
	session, event, ok := h.auditOperationRead(w, r)
	if !ok {
		return
	}
	download, err := h.auditOperations.DownloadTenantExport(r.Context(), session, uuid.UUID(tenantID), uuid.UUID(exportID), event)
	h.writeAuditExportDownload(w, r, download, err)
}

func (h *Handler) DownloadPlatformAuditExport(
	w http.ResponseWriter,
	r *http.Request,
	exportID contract.AuditExportId,
) {
	session, event, ok := h.auditOperationRead(w, r)
	if !ok {
		return
	}
	download, err := h.auditOperations.DownloadPlatformExport(r.Context(), session, uuid.UUID(exportID), event)
	h.writeAuditExportDownload(w, r, download, err)
}

func (h *Handler) writeAuditExportDownload(
	w http.ResponseWriter,
	r *http.Request,
	download auditoperations.Download,
	err error,
) {
	if err != nil {
		writeAuditOperationsError(w, r, err)
		return
	}
	if download.Reader == nil || download.Size < 0 || download.Size > 1_073_741_824 || !safeAuditExportFilename(download.Filename) {
		if download.Reader != nil {
			_ = download.Reader.Close()
		}
		writeAuditOperationsError(w, r, auditoperations.ErrUnavailable)
		return
	}
	defer download.Reader.Close()
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Content-Disposition", `attachment; filename="`+download.Filename+`"`)
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Content-Length", strconv.FormatInt(download.Size, 10))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = io.CopyN(w, download.Reader, download.Size)
}

func (h *Handler) GetTenantAuditRetention(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
) {
	session, event, ok := h.auditOperationRead(w, r)
	if !ok {
		return
	}
	state, err := h.auditOperations.GetTenantRetention(r.Context(), session, uuid.UUID(tenantID), event)
	writeAuditRetentionState(w, r, state, err)
}

func (h *Handler) GetPlatformAuditRetention(w http.ResponseWriter, r *http.Request) {
	session, event, ok := h.auditOperationRead(w, r)
	if !ok {
		return
	}
	state, err := h.auditOperations.GetPlatformRetention(r.Context(), session, event)
	writeAuditRetentionState(w, r, state, err)
}

func writeAuditRetentionState(
	w http.ResponseWriter,
	r *http.Request,
	state auditoperations.RetentionState,
	err error,
) {
	if err != nil {
		writeAuditOperationsError(w, r, err)
		return
	}
	mapped, err := mapAuditRetentionState(state)
	if err != nil || !setVersionETag(w, state.Policy.Revision) {
		writeAuditOperationsError(w, r, auditoperations.ErrUnavailable)
		return
	}
	writeAuditOperationsJSON(w, http.StatusOK, mapped)
}

func (h *Handler) UpdateTenantAuditRetention(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	params contract.UpdateTenantAuditRetentionParams,
) {
	session, event, ok := h.auditOperationMutation(w, r)
	if !ok {
		return
	}
	key, reason, ok := auditOperationHeaders(w, r, string(params.IdempotencyKey), string(params.XAuditReason))
	if !ok {
		return
	}
	input, ok := auditRetentionUpdateInput(w, r, string(params.IfMatch), key, reason, event)
	if !ok {
		return
	}
	result, err := h.auditOperations.UpdateTenantRetention(r.Context(), session, uuid.UUID(tenantID), input)
	writeAuditRetentionMutation(w, r, result, err)
}

func (h *Handler) UpdatePlatformAuditRetention(
	w http.ResponseWriter,
	r *http.Request,
	params contract.UpdatePlatformAuditRetentionParams,
) {
	session, event, ok := h.auditOperationMutation(w, r)
	if !ok {
		return
	}
	key, reason, ok := auditOperationHeaders(w, r, string(params.IdempotencyKey), string(params.XAuditReason))
	if !ok {
		return
	}
	input, ok := auditRetentionUpdateInput(w, r, string(params.IfMatch), key, reason, event)
	if !ok {
		return
	}
	result, err := h.auditOperations.UpdatePlatformRetention(r.Context(), session, input)
	writeAuditRetentionMutation(w, r, result, err)
}

func auditRetentionUpdateInput(
	w http.ResponseWriter,
	r *http.Request,
	ifMatch, key, reason string,
	event authentication.EventContext,
) (auditoperations.UpdateRetentionInput, bool) {
	var body contract.AuditRetentionUpdateRequest
	if decodeAuthorizationBody(r, &body, "application/json") != nil {
		writeAuditOperationsError(w, r, auditoperations.ErrInvalidInput)
		return auditoperations.UpdateRetentionInput{}, false
	}
	expected, ok := auditOperationPrecondition(w, r, ifMatch, body.ExpectedRevision)
	if !ok {
		return auditoperations.UpdateRetentionInput{}, false
	}
	return auditoperations.UpdateRetentionInput{
		ExpectedRevision: expected, RetentionDays: body.RetentionDays,
		IdempotencyKey: key, Reason: reason, Event: event,
	}, true
}

func writeAuditRetentionMutation(
	w http.ResponseWriter,
	r *http.Request,
	result auditoperations.RetentionMutationResult,
	err error,
) {
	if err != nil {
		writeAuditOperationsError(w, r, err)
		return
	}
	mapped, err := mapAuditRetentionMutation(result)
	if err != nil || !setVersionETag(w, result.State.Policy.Revision) {
		writeAuditOperationsError(w, r, auditoperations.ErrUnavailable)
		return
	}
	writeAuditOperationsJSON(w, http.StatusOK, mapped)
}

func (h *Handler) PlaceTenantAuditLegalHold(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	params contract.PlaceTenantAuditLegalHoldParams,
) {
	session, event, ok := h.auditOperationMutation(w, r)
	if !ok {
		return
	}
	key, reason, ok := auditOperationHeaders(w, r, string(params.IdempotencyKey), string(params.XAuditReason))
	if !ok {
		return
	}
	result, err := h.auditOperations.PlaceTenantLegalHold(r.Context(), session, uuid.UUID(tenantID), auditoperations.PlaceLegalHoldInput{
		IdempotencyKey: key, Reason: reason, Event: event,
	})
	writeAuditLegalHoldPlacement(w, r, "/api/v1/tenants/"+uuid.UUID(tenantID).String()+"/audit-legal-holds/", result, err)
}

func (h *Handler) PlacePlatformAuditLegalHold(
	w http.ResponseWriter,
	r *http.Request,
	params contract.PlacePlatformAuditLegalHoldParams,
) {
	session, event, ok := h.auditOperationMutation(w, r)
	if !ok {
		return
	}
	key, reason, ok := auditOperationHeaders(w, r, string(params.IdempotencyKey), string(params.XAuditReason))
	if !ok {
		return
	}
	result, err := h.auditOperations.PlacePlatformLegalHold(r.Context(), session, auditoperations.PlaceLegalHoldInput{
		IdempotencyKey: key, Reason: reason, Event: event,
	})
	writeAuditLegalHoldPlacement(w, r, "/api/v1/platform/audit-legal-holds/", result, err)
}

func writeAuditLegalHoldPlacement(
	w http.ResponseWriter,
	r *http.Request,
	locationPrefix string,
	result auditoperations.LegalHoldMutationResult,
	err error,
) {
	if err != nil {
		writeAuditOperationsError(w, r, err)
		return
	}
	mapped, err := mapAuditLegalHoldMutation(result)
	if err != nil || !setVersionETag(w, result.Hold.Revision) {
		writeAuditOperationsError(w, r, auditoperations.ErrUnavailable)
		return
	}
	w.Header().Set("Location", locationPrefix+result.Hold.ID.String())
	writeAuditOperationsJSON(w, http.StatusCreated, mapped)
}

func (h *Handler) ReleaseTenantAuditLegalHold(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	holdID contract.AuditLegalHoldId,
	params contract.ReleaseTenantAuditLegalHoldParams,
) {
	session, event, ok := h.auditOperationMutation(w, r)
	if !ok {
		return
	}
	key, reason, ok := auditOperationHeaders(w, r, string(params.IdempotencyKey), string(params.XAuditReason))
	if !ok {
		return
	}
	input, ok := auditLegalHoldReleaseInput(w, r, uuid.UUID(holdID), string(params.IfMatch), key, reason, event)
	if !ok {
		return
	}
	result, err := h.auditOperations.ReleaseTenantLegalHold(r.Context(), session, uuid.UUID(tenantID), input)
	writeAuditLegalHoldRelease(w, r, result, err)
}

func (h *Handler) ReleasePlatformAuditLegalHold(
	w http.ResponseWriter,
	r *http.Request,
	holdID contract.AuditLegalHoldId,
	params contract.ReleasePlatformAuditLegalHoldParams,
) {
	session, event, ok := h.auditOperationMutation(w, r)
	if !ok {
		return
	}
	key, reason, ok := auditOperationHeaders(w, r, string(params.IdempotencyKey), string(params.XAuditReason))
	if !ok {
		return
	}
	input, ok := auditLegalHoldReleaseInput(w, r, uuid.UUID(holdID), string(params.IfMatch), key, reason, event)
	if !ok {
		return
	}
	result, err := h.auditOperations.ReleasePlatformLegalHold(r.Context(), session, input)
	writeAuditLegalHoldRelease(w, r, result, err)
}

func auditLegalHoldReleaseInput(
	w http.ResponseWriter,
	r *http.Request,
	holdID uuid.UUID,
	ifMatch, key, reason string,
	event authentication.EventContext,
) (auditoperations.ReleaseLegalHoldInput, bool) {
	var body contract.AuditLegalHoldReleaseRequest
	if decodeAuthorizationBody(r, &body, "application/json") != nil {
		writeAuditOperationsError(w, r, auditoperations.ErrInvalidInput)
		return auditoperations.ReleaseLegalHoldInput{}, false
	}
	expected, ok := auditOperationPrecondition(w, r, ifMatch, int64(body.ExpectedRevision))
	if !ok {
		return auditoperations.ReleaseLegalHoldInput{}, false
	}
	return auditoperations.ReleaseLegalHoldInput{
		HoldID: holdID, ExpectedRevision: expected,
		IdempotencyKey: key, Reason: reason, Event: event,
	}, true
}

func writeAuditLegalHoldRelease(
	w http.ResponseWriter,
	r *http.Request,
	result auditoperations.LegalHoldMutationResult,
	err error,
) {
	if err != nil {
		writeAuditOperationsError(w, r, err)
		return
	}
	mapped, err := mapAuditLegalHoldMutation(result)
	if err != nil || !setVersionETag(w, result.Hold.Revision) {
		writeAuditOperationsError(w, r, auditoperations.ErrUnavailable)
		return
	}
	writeAuditOperationsJSON(w, http.StatusOK, mapped)
}

func (h *Handler) auditOperationRead(
	w http.ResponseWriter,
	r *http.Request,
) (authentication.Session, authentication.EventContext, bool) {
	session, ok := h.platformIdentityProviderSession(w, r, false)
	if !ok {
		return authentication.Session{}, authentication.EventContext{}, false
	}
	event, err := h.eventContext(r)
	if err != nil {
		writeAuditOperationsError(w, r, auditoperations.ErrInvalidInput)
		return authentication.Session{}, authentication.EventContext{}, false
	}
	return session, event, true
}

func (h *Handler) auditOperationMutation(
	w http.ResponseWriter,
	r *http.Request,
) (authentication.Session, authentication.EventContext, bool) {
	session, ok := h.platformIdentityProviderSession(w, r, true)
	if !ok {
		return authentication.Session{}, authentication.EventContext{}, false
	}
	event, err := h.eventContext(r)
	if err != nil {
		writeAuditOperationsError(w, r, auditoperations.ErrInvalidInput)
		return authentication.Session{}, authentication.EventContext{}, false
	}
	return session, event, true
}

func auditOperationHeaders(
	w http.ResponseWriter,
	r *http.Request,
	contractKey, contractReason string,
) (string, string, bool) {
	key, err := requestIdempotencyKey(r)
	if err != nil || key != contractKey {
		writeAuditOperationsError(w, r, auditoperations.ErrInvalidInput)
		return "", "", false
	}
	reason, err := singleHeader(r, "X-Audit-Reason", 500)
	if err != nil || reason != contractReason || !platformIdentityProviderAuditReasonIsHTTPValue(reason) {
		writeAuditOperationsError(w, r, auditoperations.ErrInvalidInput)
		return "", "", false
	}
	return key, reason, true
}

func auditOperationPrecondition(
	w http.ResponseWriter,
	r *http.Request,
	contractValue string,
	bodyRevision int64,
) (int64, bool) {
	version, present, err := strongVersionPrecondition(r)
	if !present {
		w.Header().Set("Cache-Control", "no-store")
		writeProblem(w, r, http.StatusPreconditionRequired, "precondition_required", "Precondition required", "A current strong If-Match entity tag is required.")
		return 0, false
	}
	canonical, canonicalErr := strongVersionETag(version)
	if err != nil || canonicalErr != nil || canonical != contractValue || bodyRevision != version ||
		version < 1 || version > math.MaxInt64-1 {
		writeAuditOperationsError(w, r, auditoperations.ErrInvalidInput)
		return 0, false
	}
	return version, true
}

func auditExportInput(
	r *http.Request,
	key, reason string,
	event authentication.EventContext,
	stream auditoperations.Stream,
) (auditoperations.CreateExportInput, error) {
	var body contract.AuditExportRequest
	if decodeAuthorizationBody(r, &body, "application/json") != nil {
		return auditoperations.CreateExportInput{}, auditoperations.ErrInvalidInput
	}
	filter := mapAuditExportFilterInput(body.Filter)
	if stream == auditoperations.StreamPlatform && filter.ActorServiceAccountID != nil {
		return auditoperations.CreateExportInput{}, auditoperations.ErrInvalidInput
	}
	retentionSeconds := int64(86400)
	if body.RetentionSeconds != nil {
		retentionSeconds = *body.RetentionSeconds
	}
	return auditoperations.CreateExportInput{
		Filter: filter, RetentionSeconds: retentionSeconds,
		IdempotencyKey: key, Reason: reason, Event: event,
	}, nil
}

func mapAuditExportFilterInput(filter contract.AuditExportFilter) auditoperations.ExportFilter {
	result := auditoperations.ExportFilter{
		OccurredFrom: cloneTime(filter.OccurredFrom), OccurredBefore: cloneTime(filter.OccurredBefore),
		ActorUserID:           cloneAuditUUID(filter.ActorUserId),
		ActorServiceAccountID: cloneAuditUUID(filter.ActorServiceAccountId),
		ActionPrefix:          cloneString(filter.ActionPrefix), ResourceType: cloneString(filter.ResourceType),
		ResourceID: cloneAuditUUID(filter.ResourceId), RequestID: cloneAuditUUID(filter.RequestId),
		CorrelationID: cloneAuditUUID(filter.CorrelationId), Search: cloneString(filter.Search),
	}
	if filter.ActorType != nil {
		value := string(*filter.ActorType)
		result.ActorType = &value
	}
	if filter.Outcome != nil {
		value := string(*filter.Outcome)
		result.Outcome = &value
	}
	return result
}

func mapAuditExportMutation(result auditoperations.ExportMutationResult) (contract.AuditExportMutationResult, error) {
	job, err := mapAuditExportJob(result.Job)
	if err != nil {
		return contract.AuditExportMutationResult{}, err
	}
	return contract.AuditExportMutationResult{Job: job, Replayed: result.Replayed}, nil
}

func mapAuditExportJob(job auditoperations.ExportJob) (contract.AuditExportJob, error) {
	if job.Revision < 1 || job.Attempts < 0 || job.MaximumAttempts < 1 {
		return contract.AuditExportJob{}, auditoperations.ErrUnavailable
	}
	filter := contract.AuditExportFilter{
		OccurredFrom: cloneTime(job.Filter.OccurredFrom), OccurredBefore: cloneTime(job.Filter.OccurredBefore),
		ActorUserId:           contractAuditUUID(job.Filter.ActorUserID),
		ActorServiceAccountId: contractAuditUUID(job.Filter.ActorServiceAccountID),
		ActionPrefix:          cloneString(job.Filter.ActionPrefix), ResourceType: cloneString(job.Filter.ResourceType),
		ResourceId: contractAuditUUID(job.Filter.ResourceID), RequestId: contractAuditUUID(job.Filter.RequestID),
		CorrelationId: contractAuditUUID(job.Filter.CorrelationID), Search: cloneString(job.Filter.Search),
	}
	if job.Filter.ActorType != nil {
		value := contract.AuditActorType(*job.Filter.ActorType)
		filter.ActorType = &value
	}
	if job.Filter.Outcome != nil {
		value := contract.AuditOutcome(*job.Filter.Outcome)
		filter.Outcome = &value
	}
	result := contract.AuditExportJob{
		Id: job.ID, Stream: contract.AuditExportJobStream(job.Stream), TenantId: contractAuditUUID(job.TenantID),
		RequesterUserId: job.RequesterUserID, Filter: filter, FilterSha256: job.FilterSHA256,
		ProjectionVersion: contract.AuditExportJobProjectionVersion(job.ProjectionVersion),
		Format:            contract.AuditExportJobFormat(job.Format), State: contract.AuditExportState(job.State),
		Revision: job.Revision, Attempts: job.Attempts, MaximumAttempts: job.MaximumAttempts,
		FailureCode: contract.AuditExportFailureCode(job.FailureCode), RequestedAt: job.RequestedAt,
		UpdatedAt: job.UpdatedAt, AvailableAt: job.AvailableAt, ExpiresAt: job.ExpiresAt,
		TerminalAt: cloneTime(job.TerminalAt),
	}
	if job.Artifact != nil {
		result.Artifact = &contract.AuditExportArtifact{
			Id: job.Artifact.ID, Sha256: job.Artifact.SHA256, Rows: job.Artifact.Rows,
			Bytes: job.Artifact.Bytes, ExpiresAt: job.Artifact.ExpiresAt,
		}
	}
	return result, nil
}

func mapAuditRetentionState(state auditoperations.RetentionState) (contract.AuditRetentionState, error) {
	if state.Policy.Revision < 1 || state.Anchor.Revision < 1 || state.Anchor.RetainedThroughSequence < 0 {
		return contract.AuditRetentionState{}, auditoperations.ErrUnavailable
	}
	result := contract.AuditRetentionState{
		Stream: contract.AuditRetentionStateStream(state.Stream), TenantId: contractAuditUUID(state.TenantID),
		Policy: contract.AuditRetentionPolicy{
			RetentionDays: state.Policy.RetentionDays, Revision: state.Policy.Revision, UpdatedAt: state.Policy.UpdatedAt,
		},
		Anchor: contract.AuditRetentionAnchor{
			RetainedThroughSequence: state.Anchor.RetainedThroughSequence,
			RetainedThroughHash:     state.Anchor.RetainedThroughHash,
			Revision:                state.Anchor.Revision, UpdatedAt: state.Anchor.UpdatedAt,
		},
	}
	if state.ActiveLegalHold != nil {
		hold := mapAuditLegalHold(*state.ActiveLegalHold)
		result.ActiveLegalHold = &hold
	}
	return result, nil
}

func mapAuditRetentionMutation(result auditoperations.RetentionMutationResult) (contract.AuditRetentionMutationResult, error) {
	state, err := mapAuditRetentionState(result.State)
	if err != nil {
		return contract.AuditRetentionMutationResult{}, err
	}
	return contract.AuditRetentionMutationResult{State: state, Replayed: result.Replayed}, nil
}

func mapAuditLegalHoldMutation(result auditoperations.LegalHoldMutationResult) (contract.AuditLegalHoldMutationResult, error) {
	if result.Hold.Revision < 1 {
		return contract.AuditLegalHoldMutationResult{}, auditoperations.ErrUnavailable
	}
	return contract.AuditLegalHoldMutationResult{Hold: mapAuditLegalHold(result.Hold), Replayed: result.Replayed}, nil
}

func mapAuditLegalHold(hold auditoperations.LegalHold) contract.AuditLegalHold {
	return contract.AuditLegalHold{
		Id: hold.ID, State: contract.AuditLegalHoldState(hold.State), Revision: hold.Revision,
		PlacedAt: hold.PlacedAt, ReleasedAt: cloneTime(hold.ReleasedAt),
	}
}

func safeAuditExportFilename(value string) bool {
	if !strings.HasSuffix(value, ".jsonl") || len(value) < 8 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' ||
			character == '-' || character == '.' {
			continue
		}
		return false
	}
	return true
}

func writeAuditOperationsJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Cache-Control", "private, no-store")
	writeJSON(w, status, value)
}

func writeAuditOperationsError(w http.ResponseWriter, r *http.Request, err error) {
	w.Header().Set("Cache-Control", "no-store")
	switch {
	case errors.Is(err, auditoperations.ErrInvalidInput):
		writeProblem(w, r, http.StatusBadRequest, "invalid_request", "Invalid request", "The audit operation request is malformed or fails bounded validation.")
	case errors.Is(err, auditoperations.ErrForbidden), errors.Is(err, authentication.ErrForbidden):
		writeProblem(w, r, http.StatusForbidden, "forbidden", "Forbidden", "The action is not permitted.")
	case errors.Is(err, auditoperations.ErrNotFound):
		writeProblem(w, r, http.StatusNotFound, "not_found", "Resource not found", "The requested audit operation resource does not exist.")
	case errors.Is(err, auditoperations.ErrPrecondition):
		writeProblem(w, r, http.StatusPreconditionFailed, "precondition_failed", "Precondition failed", "The resource changed after the supplied entity tag was issued.")
	case errors.Is(err, auditoperations.ErrConflict):
		writeProblem(w, r, http.StatusConflict, "conflict", "Conflict", "The audit operation conflicts with current protected state or an idempotency key was reused.")
	case errors.Is(err, auditoperations.ErrUnavailable):
		w.Header().Set("Retry-After", "5")
		writeProblem(w, r, http.StatusServiceUnavailable, "service_unavailable", "Service unavailable", "A required protected dependency is unavailable.")
	default:
		writeProblem(w, r, http.StatusInternalServerError, "internal_error", "Internal server error", "The request could not be completed.")
	}
}
