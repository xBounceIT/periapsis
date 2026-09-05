package httpserver

import (
	"net/http"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/dfir"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	application "github.com/periapsis-im/periapsis/services/api/internal/dfir"
)

func (h *Handler) GetTenantAlertDfirWorkspace(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	alertID contract.AlertId,
) {
	tenant, alertUUID := uuid.UUID(tenantID), uuid.UUID(alertID)
	actor, ok := h.phase4ReadActor(w, r, tenant)
	if !ok {
		return
	}
	alertEntity, err := dfirEntityID(alertUUID)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	workspace, err := h.dfir.AlertWorkspace(r.Context(), actor.dfir, tenant, alertEntity)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	investigation, err := h.alertInvestigation.Workspace(r.Context(), actor.dfir, tenant, alertEntity)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapDfirAlertWorkspace(tenant, alertUUID, workspace, investigation)
	if err != nil {
		writeDomainError(w, r, application.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) CreateTenantAlertDfirIndicator(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	alertID contract.AlertId,
	_ contract.CreateTenantAlertDfirIndicatorParams,
) {
	tenant, alertUUID := uuid.UUID(tenantID), uuid.UUID(alertID)
	actor, audit, key, ok := h.dfirMutationContext(w, r, tenant)
	if !ok {
		return
	}
	var body contract.DfirIndicatorCreateRequest
	if decodePhase4Body(r, &body) != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	alertEntity, alertErr := dfirEntityID(alertUUID)
	input, inputErr := dfirIndicatorInput(tenant, uuid.UUID(body.IndicatorId), body.Indicator)
	if alertErr != nil || inputErr != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	result, err := h.dfir.CreateAlertIndicator(r.Context(), actor.dfir, tenant, application.AlertIndicatorCommand{
		AlertID: alertEntity, Input: input,
		Envelope: application.MutationEnvelope{IdempotencyKey: key, Audit: audit},
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapDfirAlertIndicator(result.Resource, alertUUID, 1)
	if err != nil || !setDfirResourceVersionETag(w, mapped.Version) {
		writeDomainError(w, r, application.ErrUnavailable)
		return
	}
	w.Header().Set("Location", r.URL.Path+"/"+uuid.UUID(body.IndicatorId).String())
	writeSensitiveJSON(w, http.StatusCreated, mapped)
}

func (h *Handler) ReplaceTenantAlertDfirIndicator(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	alertID contract.AlertId,
	indicatorID uuid.UUID,
	_ contract.ReplaceTenantAlertDfirIndicatorParams,
) {
	tenant, alertUUID := uuid.UUID(tenantID), uuid.UUID(alertID)
	actor, audit, key, ok := h.dfirMutationContext(w, r, tenant)
	if !ok {
		return
	}
	var body contract.DfirIndicatorReplaceRequest
	if decodePhase4Body(r, &body) != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	if !dfirResourcePrecondition(w, r, int64(body.ExpectedVersion)) {
		return
	}
	alertEntity, alertErr := dfirEntityID(alertUUID)
	input, inputErr := dfirIndicatorInput(tenant, indicatorID, body.Indicator)
	if alertErr != nil || inputErr != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	result, err := h.dfir.ReplaceAlertIndicator(r.Context(), actor.dfir, tenant, application.AlertIndicatorCommand{
		AlertID: alertEntity, Input: input, ExpectedVersion: uint64(body.ExpectedVersion),
		Envelope: application.MutationEnvelope{IdempotencyKey: key, Audit: audit},
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapDfirAlertIndicator(result.Resource, alertUUID, uint64(body.ExpectedVersion)+1)
	if err != nil || !setDfirResourceVersionETag(w, mapped.Version) {
		writeDomainError(w, r, application.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) CreateTenantAlertDfirAsset(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	alertID contract.AlertId,
	_ contract.CreateTenantAlertDfirAssetParams,
) {
	tenant, alertUUID := uuid.UUID(tenantID), uuid.UUID(alertID)
	actor, audit, key, ok := h.dfirMutationContext(w, r, tenant)
	if !ok {
		return
	}
	var body contract.DfirAssetCreateRequest
	if decodePhase4Body(r, &body) != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	alertEntity, alertErr := dfirEntityID(alertUUID)
	input, inputErr := dfirAssetInput(tenant, uuid.UUID(body.AssetId), body.Asset)
	if alertErr != nil || inputErr != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	result, err := h.dfir.CreateAlertAsset(r.Context(), actor.dfir, tenant, application.AlertAssetCommand{
		AlertID: alertEntity, Input: input,
		Envelope: application.MutationEnvelope{IdempotencyKey: key, Audit: audit},
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapDfirAlertAsset(result.Resource, alertUUID, 1)
	if err != nil || !setDfirResourceVersionETag(w, mapped.Version) {
		writeDomainError(w, r, application.ErrUnavailable)
		return
	}
	w.Header().Set("Location", r.URL.Path+"/"+uuid.UUID(body.AssetId).String())
	writeSensitiveJSON(w, http.StatusCreated, mapped)
}

func (h *Handler) ReplaceTenantAlertDfirAsset(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	alertID contract.AlertId,
	assetID uuid.UUID,
	_ contract.ReplaceTenantAlertDfirAssetParams,
) {
	tenant, alertUUID := uuid.UUID(tenantID), uuid.UUID(alertID)
	actor, audit, key, ok := h.dfirMutationContext(w, r, tenant)
	if !ok {
		return
	}
	var body contract.DfirAssetReplaceRequest
	if decodePhase4Body(r, &body) != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	if !dfirResourcePrecondition(w, r, int64(body.ExpectedVersion)) {
		return
	}
	alertEntity, alertErr := dfirEntityID(alertUUID)
	input, inputErr := dfirAssetInput(tenant, assetID, body.Asset)
	if alertErr != nil || inputErr != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	result, err := h.dfir.ReplaceAlertAsset(r.Context(), actor.dfir, tenant, application.AlertAssetCommand{
		AlertID: alertEntity, Input: input, ExpectedVersion: uint64(body.ExpectedVersion),
		Envelope: application.MutationEnvelope{IdempotencyKey: key, Audit: audit},
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapDfirAlertAsset(result.Resource, alertUUID, uint64(body.ExpectedVersion)+1)
	if err != nil || !setDfirResourceVersionETag(w, mapped.Version) {
		writeDomainError(w, r, application.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) CreateTenantAlertDfirTimelineEvent(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	alertID contract.AlertId,
	_ contract.CreateTenantAlertDfirTimelineEventParams,
) {
	tenant, alertUUID := uuid.UUID(tenantID), uuid.UUID(alertID)
	actor, audit, key, ok := h.dfirMutationContext(w, r, tenant)
	if !ok {
		return
	}
	var body contract.DfirAlertTimelineEventCreateRequest
	if decodePhase4Body(r, &body) != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	input, err := dfirAlertTimelineInput(tenant, alertUUID, uuid.UUID(body.TimelineEventId), body.Event)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	result, err := h.dfir.CreateAlertTimelineEvent(r.Context(), actor.dfir, tenant, application.AlertTimelineCommand{
		Input: input, Envelope: application.MutationEnvelope{IdempotencyKey: key, Audit: audit},
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapDfirAlertTimeline(result.Resource, 1)
	if err != nil || !setDfirResourceVersionETag(w, mapped.Version) {
		writeDomainError(w, r, application.ErrUnavailable)
		return
	}
	w.Header().Set("Location", r.URL.Path+"/"+uuid.UUID(body.TimelineEventId).String())
	writeSensitiveJSON(w, http.StatusCreated, mapped)
}

func (h *Handler) PrepareTenantAlertDfirAttachmentUpload(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	alertID contract.AlertId,
	_ contract.PrepareTenantAlertDfirAttachmentUploadParams,
) {
	tenant, alertUUID := uuid.UUID(tenantID), uuid.UUID(alertID)
	actor, audit, key, ok := h.dfirMutationContext(w, r, tenant)
	if !ok {
		return
	}
	var body contract.DfirAttachmentUploadRequest
	if decodePhase4Body(r, &body) != nil || !body.Classification.Valid() || !body.RequestedVisibility.Valid() {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	alertEntity, alertErr := dfirEntityID(alertUUID)
	attachmentID, attachmentErr := dfirEntityID(uuid.UUID(body.AttachmentId))
	storageID, storageErr := dfirEntityID(uuid.UUID(body.StorageObjectId))
	subject, subjectErr := dfirReference(tenant, body.Subject)
	if alertErr != nil || attachmentErr != nil || storageErr != nil || subjectErr != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	prepared, err := h.dfir.PrepareAlertUpload(r.Context(), actor.dfir, tenant, application.AlertPrepareUploadCommand{
		AlertID: alertEntity, AttachmentID: attachmentID, StorageObjectID: storageID,
		Subject: subject, OriginalFilename: body.OriginalFilename,
		Classification:      kernel.EvidenceClassification(body.Classification),
		RequestedVisibility: kernel.Visibility(body.RequestedVisibility),
		SizeBytes:           body.SizeBytes, ContentType: body.ContentType,
		Envelope: application.MutationEnvelope{IdempotencyKey: key, Audit: audit},
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	attachment, err := mapDfirAttachment(prepared.Attachment)
	if err != nil {
		writeDomainError(w, r, application.ErrUnavailable)
		return
	}
	headers := make([]contract.DfirUploadHeader, len(prepared.Grant.Headers))
	for index, header := range prepared.Grant.Headers {
		headers[index] = contract.DfirUploadHeader{Name: header.Name, Value: header.Value}
	}
	w.Header().Set("Location", "/api/v1/tenants/"+tenant.String()+"/alerts/"+alertUUID.String()+
		"/dfir/attachments/"+uuid.UUID(body.AttachmentId).String())
	writeSensitiveJSON(w, http.StatusCreated, contract.DfirPreparedUpload{
		Attachment: attachment, Method: contract.PUT, UploadUrl: prepared.Grant.TargetURL,
		Headers: headers, ExpiresAt: prepared.Grant.ExpiresAt,
	})
}

func (h *Handler) PrepareTenantAlertDfirAttachmentDownload(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	alertID contract.AlertId,
	attachmentID uuid.UUID,
) {
	tenant, alertUUID := uuid.UUID(tenantID), uuid.UUID(alertID)
	actor, _, audit, ok := h.phase4MutationActor(w, r, tenant)
	if !ok {
		return
	}
	var body contract.DfirAttachmentDownloadRequest
	if decodePhase4Body(r, &body) != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	alertEntity, alertErr := dfirEntityID(alertUUID)
	attachmentEntity, attachmentErr := dfirEntityID(attachmentID)
	subject, subjectErr := dfirReference(tenant, body.Subject)
	if alertErr != nil || attachmentErr != nil || subjectErr != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	prepared, err := h.dfir.PrepareAlertDownload(r.Context(), actor.dfir, tenant, application.AlertDownloadCommand{
		AlertID: alertEntity, AttachmentID: attachmentEntity, Subject: subject, Audit: audit,
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapDfirAttachment(prepared.Attachment)
	if err != nil {
		writeDomainError(w, r, application.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, contract.DfirPreparedDownload{
		Attachment: mapped, DownloadUrl: prepared.Grant.TargetURL, ExpiresAt: prepared.Grant.ExpiresAt,
	})
}
