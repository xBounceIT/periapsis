package httpserver

import (
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/dfir"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	application "github.com/periapsis-im/periapsis/services/api/internal/dfir"
)

func (h *Handler) GetTenantCaseDfirWorkspace(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, caseID contract.CaseId) {
	tenant, caseUUID := uuid.UUID(tenantID), uuid.UUID(caseID)
	actor, ok := h.phase4ReadActor(w, r, tenant)
	if !ok {
		return
	}
	caseEntity, err := dfirEntityID(caseUUID)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	workspace, err := h.dfir.Workspace(r.Context(), actor.dfir, tenant, caseEntity)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapDfirWorkspace(tenant, caseUUID, workspace)
	if err != nil {
		writeDomainError(w, r, application.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) CreateTenantCaseDfirIndicator(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, caseID contract.CaseId, _ contract.CreateTenantCaseDfirIndicatorParams) {
	tenant, caseUUID := uuid.UUID(tenantID), uuid.UUID(caseID)
	actor, audit, key, ok := h.dfirMutationContext(w, r, tenant)
	if !ok {
		return
	}
	var body contract.DfirIndicatorCreateRequest
	if decodePhase4Body(r, &body) != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	caseEntity, err := dfirEntityID(caseUUID)
	input, inputErr := dfirIndicatorInput(tenant, uuid.UUID(body.IndicatorId), body.Indicator)
	if err != nil || inputErr != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	result, err := h.dfir.CreateIndicator(r.Context(), actor.dfir, tenant, application.IndicatorCommand{
		CaseID: caseEntity, Input: input, Envelope: application.MutationEnvelope{IdempotencyKey: key, Audit: audit},
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapDfirIndicator(result.Resource, caseUUID, 1)
	if err != nil || !setDfirResourceVersionETag(w, mapped.Version) {
		writeDomainError(w, r, application.ErrUnavailable)
		return
	}
	w.Header().Set("Location", r.URL.Path+"/"+uuid.UUID(body.IndicatorId).String())
	writeSensitiveJSON(w, http.StatusCreated, mapped)
}

func (h *Handler) ReplaceTenantCaseDfirIndicator(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, caseID contract.CaseId, indicatorID uuid.UUID, _ contract.ReplaceTenantCaseDfirIndicatorParams) {
	tenant, caseUUID := uuid.UUID(tenantID), uuid.UUID(caseID)
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
	caseEntity, err := dfirEntityID(caseUUID)
	input, inputErr := dfirIndicatorInput(tenant, indicatorID, body.Indicator)
	if err != nil || inputErr != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	result, err := h.dfir.ReplaceIndicator(r.Context(), actor.dfir, tenant, application.IndicatorCommand{
		CaseID: caseEntity, Input: input, ExpectedVersion: uint64(body.ExpectedVersion),
		Envelope: application.MutationEnvelope{IdempotencyKey: key, Audit: audit},
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapDfirIndicator(result.Resource, caseUUID, uint64(body.ExpectedVersion)+1)
	if err != nil || !setDfirResourceVersionETag(w, mapped.Version) {
		writeDomainError(w, r, application.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) CreateTenantCaseDfirAsset(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, caseID contract.CaseId, _ contract.CreateTenantCaseDfirAssetParams) {
	tenant, caseUUID := uuid.UUID(tenantID), uuid.UUID(caseID)
	actor, audit, key, ok := h.dfirMutationContext(w, r, tenant)
	if !ok {
		return
	}
	var body contract.DfirAssetCreateRequest
	if decodePhase4Body(r, &body) != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	caseEntity, err := dfirEntityID(caseUUID)
	input, inputErr := dfirAssetInput(tenant, uuid.UUID(body.AssetId), body.Asset)
	if err != nil || inputErr != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	result, err := h.dfir.CreateAsset(r.Context(), actor.dfir, tenant, application.AssetCommand{CaseID: caseEntity, Input: input,
		Envelope: application.MutationEnvelope{IdempotencyKey: key, Audit: audit}})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapDfirAsset(result.Resource, caseUUID, 1)
	if err != nil || !setDfirResourceVersionETag(w, mapped.Version) {
		writeDomainError(w, r, application.ErrUnavailable)
		return
	}
	w.Header().Set("Location", r.URL.Path+"/"+uuid.UUID(body.AssetId).String())
	writeSensitiveJSON(w, http.StatusCreated, mapped)
}

func (h *Handler) ReplaceTenantCaseDfirAsset(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, caseID contract.CaseId, assetID uuid.UUID, _ contract.ReplaceTenantCaseDfirAssetParams) {
	tenant, caseUUID := uuid.UUID(tenantID), uuid.UUID(caseID)
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
	caseEntity, err := dfirEntityID(caseUUID)
	input, inputErr := dfirAssetInput(tenant, assetID, body.Asset)
	if err != nil || inputErr != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	result, err := h.dfir.ReplaceAsset(r.Context(), actor.dfir, tenant, application.AssetCommand{CaseID: caseEntity, Input: input,
		ExpectedVersion: uint64(body.ExpectedVersion), Envelope: application.MutationEnvelope{IdempotencyKey: key, Audit: audit}})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapDfirAsset(result.Resource, caseUUID, uint64(body.ExpectedVersion)+1)
	if err != nil || !setDfirResourceVersionETag(w, mapped.Version) {
		writeDomainError(w, r, application.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) CreateTenantCaseDfirTimelineEvent(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, caseID contract.CaseId, _ contract.CreateTenantCaseDfirTimelineEventParams) {
	tenant, caseUUID := uuid.UUID(tenantID), uuid.UUID(caseID)
	actor, audit, key, ok := h.dfirMutationContext(w, r, tenant)
	if !ok {
		return
	}
	var body contract.DfirTimelineEventCreateRequest
	if decodePhase4Body(r, &body) != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	input, err := dfirTimelineInput(tenant, caseUUID, uuid.UUID(body.TimelineEventId), body.Event, time.Time{})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	result, err := h.dfir.CreateTimelineEvent(r.Context(), actor.dfir, tenant, application.TimelineCommand{Input: input,
		Envelope: application.MutationEnvelope{IdempotencyKey: key, Audit: audit}})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapDfirTimeline(result.Resource, 1)
	if err != nil || !setDfirResourceVersionETag(w, mapped.Version) {
		writeDomainError(w, r, application.ErrUnavailable)
		return
	}
	w.Header().Set("Location", r.URL.Path+"/"+uuid.UUID(body.TimelineEventId).String())
	writeSensitiveJSON(w, http.StatusCreated, mapped)
}

func (h *Handler) CreateTenantCaseDfirTask(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, caseID contract.CaseId, _ contract.CreateTenantCaseDfirTaskParams) {
	tenant, caseUUID := uuid.UUID(tenantID), uuid.UUID(caseID)
	actor, audit, key, ok := h.dfirMutationContext(w, r, tenant)
	if !ok {
		return
	}
	var body contract.DfirTaskCreateRequest
	if decodePhase4Body(r, &body) != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	caseEntity, caseErr := dfirEntityID(caseUUID)
	draft, draftErr := dfirTaskDraft(uuid.UUID(body.TaskId), body.Task)
	if caseErr != nil || draftErr != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	result, err := h.dfir.CreateTask(r.Context(), actor.dfir, tenant, application.TaskCreateCommand{CaseID: caseEntity, Input: draft,
		Envelope: application.MutationEnvelope{IdempotencyKey: key, Audit: audit}})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapDfirTask(result.Resource)
	if err != nil || !setDfirResourceVersionETag(w, mapped.Version) {
		writeDomainError(w, r, application.ErrUnavailable)
		return
	}
	w.Header().Set(idempotentReplayHeader, strconv.FormatBool(result.Replayed))
	w.Header().Set("Location", r.URL.Path+"/"+uuid.UUID(body.TaskId).String())
	writeSensitiveJSON(w, http.StatusCreated, mapped)
}

func (h *Handler) TransitionTenantCaseDfirTask(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, caseID contract.CaseId, taskID uuid.UUID, _ contract.TransitionTenantCaseDfirTaskParams) {
	tenant, caseUUID := uuid.UUID(tenantID), uuid.UUID(caseID)
	actor, audit, key, ok := h.dfirMutationContext(w, r, tenant)
	if !ok {
		return
	}
	var body contract.DfirTaskTransitionRequest
	if decodePhase4Body(r, &body) != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	if !dfirResourcePrecondition(w, r, int64(body.ExpectedVersion)) {
		return
	}
	if !body.Target.Valid() {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	caseEntity, caseErr := dfirEntityID(caseUUID)
	taskEntity, taskErr := dfirEntityID(taskID)
	completion, documentErr := dfirDocument(body.CompletionData)
	if caseErr != nil || taskErr != nil || documentErr != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	result, err := h.dfir.TransitionTask(r.Context(), actor.dfir, tenant, application.TaskTransitionCommand{
		CaseID: caseEntity, TaskID: taskEntity, ExpectedVersion: uint64(body.ExpectedVersion),
		Target: kernel.TaskStatus(body.Target), Reason: body.Reason, CompletionData: completion,
		Envelope: application.MutationEnvelope{IdempotencyKey: key, Audit: audit},
	})
	writeCaseTaskMutation(w, r, result, err)
}

func (h *Handler) ReplaceTenantCaseDfirTaskDetails(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, caseID contract.CaseId, taskID uuid.UUID, _ contract.ReplaceTenantCaseDfirTaskDetailsParams) {
	tenant, caseUUID := uuid.UUID(tenantID), uuid.UUID(caseID)
	actor, audit, key, ok := h.dfirMutationContext(w, r, tenant)
	if !ok {
		return
	}
	var body contract.DfirTaskDetailsRequest
	if decodePhase4Body(r, &body) != nil || !body.Priority.Valid() {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	if !dfirResourcePrecondition(w, r, int64(body.ExpectedVersion)) {
		return
	}
	caseEntity, caseErr := dfirEntityID(caseUUID)
	taskEntity, taskErr := dfirEntityID(taskID)
	sla, slaErr := optionalDfirEntityID(body.SlaInstanceId)
	if caseErr != nil || taskErr != nil || slaErr != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	result, err := h.dfir.ReplaceTaskDetails(r.Context(), actor.dfir, tenant, application.TaskDetailsCommand{
		CaseID: caseEntity, TaskID: taskEntity, ExpectedVersion: uint64(body.ExpectedVersion),
		Title: body.Title, Description: body.Description, Priority: kernel.TaskPriority(body.Priority),
		SLAInstanceID: sla, Envelope: application.MutationEnvelope{IdempotencyKey: key, Audit: audit},
	})
	writeCaseTaskMutation(w, r, result, err)
}

func (h *Handler) AssignTenantCaseDfirTask(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, caseID contract.CaseId, taskID uuid.UUID, _ contract.AssignTenantCaseDfirTaskParams) {
	tenant, caseUUID := uuid.UUID(tenantID), uuid.UUID(caseID)
	actor, audit, key, ok := h.dfirMutationContext(w, r, tenant)
	if !ok {
		return
	}
	var body contract.DfirTaskAssignmentRequest
	if decodePhase4Body(r, &body) != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	if !dfirResourcePrecondition(w, r, int64(body.ExpectedVersion)) {
		return
	}
	caseEntity, caseErr := dfirEntityID(caseUUID)
	taskEntity, taskErr := dfirEntityID(taskID)
	team, teamErr := optionalDfirEntityID(body.OperatorTeamId)
	assignee, assigneeErr := optionalDfirEntityID(body.AssigneeId)
	if caseErr != nil || taskErr != nil || teamErr != nil || assigneeErr != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	result, err := h.dfir.AssignTask(r.Context(), actor.dfir, tenant, application.TaskAssignmentCommand{
		CaseID: caseEntity, TaskID: taskEntity, ExpectedVersion: uint64(body.ExpectedVersion),
		OperatorTeamID: team, AssigneeID: assignee,
		Envelope: application.MutationEnvelope{IdempotencyKey: key, Audit: audit},
	})
	writeCaseTaskMutation(w, r, result, err)
}

func (h *Handler) RescheduleTenantCaseDfirTask(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, caseID contract.CaseId, taskID uuid.UUID, _ contract.RescheduleTenantCaseDfirTaskParams) {
	tenant, caseUUID := uuid.UUID(tenantID), uuid.UUID(caseID)
	actor, audit, key, ok := h.dfirMutationContext(w, r, tenant)
	if !ok {
		return
	}
	var body contract.DfirTaskDueDateRequest
	if decodePhase4Body(r, &body) != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	if !dfirResourcePrecondition(w, r, int64(body.ExpectedVersion)) {
		return
	}
	caseEntity, caseErr := dfirEntityID(caseUUID)
	taskEntity, taskErr := dfirEntityID(taskID)
	dueAt, dueErr := canonicalAlertTransportOptionalInstant(body.DueAt)
	if caseErr != nil || taskErr != nil || dueErr != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	result, err := h.dfir.RescheduleTask(r.Context(), actor.dfir, tenant, application.TaskDueDateCommand{
		CaseID: caseEntity, TaskID: taskEntity, ExpectedVersion: uint64(body.ExpectedVersion), DueAt: dueAt,
		Envelope: application.MutationEnvelope{IdempotencyKey: key, Audit: audit},
	})
	writeCaseTaskMutation(w, r, result, err)
}

func (h *Handler) ReplaceTenantCaseDfirTaskChecklist(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, caseID contract.CaseId, taskID uuid.UUID, _ contract.ReplaceTenantCaseDfirTaskChecklistParams) {
	tenant, caseUUID := uuid.UUID(tenantID), uuid.UUID(caseID)
	actor, audit, key, ok := h.dfirMutationContext(w, r, tenant)
	if !ok {
		return
	}
	var body contract.DfirTaskChecklistRequest
	if decodePhase4Body(r, &body) != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	if !dfirResourcePrecondition(w, r, int64(body.ExpectedVersion)) {
		return
	}
	caseEntity, caseErr := dfirEntityID(caseUUID)
	taskEntity, taskErr := dfirEntityID(taskID)
	checklist, checklistErr := taskChecklistIntents(body.Checklist)
	if caseErr != nil || taskErr != nil || checklistErr != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	result, err := h.dfir.ReplaceTaskChecklist(r.Context(), actor.dfir, tenant, application.TaskChecklistCommand{
		CaseID: caseEntity, TaskID: taskEntity, ExpectedVersion: uint64(body.ExpectedVersion), Checklist: checklist,
		Envelope: application.MutationEnvelope{IdempotencyKey: key, Audit: audit},
	})
	writeCaseTaskMutation(w, r, result, err)
}

func (h *Handler) ReplaceTenantCaseDfirTaskComments(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, caseID contract.CaseId, taskID uuid.UUID, _ contract.ReplaceTenantCaseDfirTaskCommentsParams) {
	tenant, caseUUID := uuid.UUID(tenantID), uuid.UUID(caseID)
	actor, audit, key, ok := h.dfirMutationContext(w, r, tenant)
	if !ok {
		return
	}
	var body contract.DfirTaskCommentsRequest
	if decodePhase4Body(r, &body) != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	if !dfirResourcePrecondition(w, r, int64(body.ExpectedVersion)) {
		return
	}
	caseEntity, caseErr := dfirEntityID(caseUUID)
	taskEntity, taskErr := dfirEntityID(taskID)
	comments, commentsErr := dfirEntityIDs(body.CommentIds)
	if caseErr != nil || taskErr != nil || commentsErr != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	result, err := h.dfir.ReplaceTaskComments(r.Context(), actor.dfir, tenant, application.TaskCommentsCommand{
		CaseID: caseEntity, TaskID: taskEntity, ExpectedVersion: uint64(body.ExpectedVersion), CommentIDs: comments,
		Envelope: application.MutationEnvelope{IdempotencyKey: key, Audit: audit},
	})
	writeCaseTaskMutation(w, r, result, err)
}

func writeCaseTaskMutation(w http.ResponseWriter, r *http.Request, result application.MutationResult[kernel.Task], err error) {
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapDfirTask(result.Resource)
	if err != nil || !setDfirResourceVersionETag(w, mapped.Version) {
		writeDomainError(w, r, application.ErrUnavailable)
		return
	}
	w.Header().Set(idempotentReplayHeader, strconv.FormatBool(result.Replayed))
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func dfirResourcePrecondition(w http.ResponseWriter, r *http.Request, bodyVersion int64) bool {
	version, present, err := strongVersionPreconditionUpTo(r, maximumExactJSONResourceVersion)
	if err != nil {
		writeDomainError(w, r, authorization.ErrInvalidInput)
		return false
	}
	if !present {
		writeDomainError(w, r, authorization.ErrPreconditionRequired)
		return false
	}
	if version != bodyVersion || version >= maximumExactJSONResourceVersion {
		writeDomainError(w, r, authorization.ErrInvalidInput)
		return false
	}
	return true
}

func setDfirResourceVersionETag(w http.ResponseWriter, version int64) bool {
	etag, err := strongVersionETagUpTo(version, maximumExactJSONResourceVersion)
	if err != nil {
		return false
	}
	w.Header().Set("ETag", etag)
	return true
}

func (h *Handler) CreateTenantCaseDfirRelationship(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, caseID contract.CaseId, _ contract.CreateTenantCaseDfirRelationshipParams) {
	tenant, caseUUID := uuid.UUID(tenantID), uuid.UUID(caseID)
	actor, audit, key, ok := h.dfirMutationContext(w, r, tenant)
	if !ok {
		return
	}
	var body contract.DfirRelationshipCreateRequest
	if decodePhase4Body(r, &body) != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	tenantEntity, tenantErr := dfirEntityID(tenant)
	caseEntity, caseErr := dfirEntityID(caseUUID)
	id, idErr := dfirEntityID(uuid.UUID(body.RelationshipId))
	createdBy, actorErr := dfirEntityID(actor.dfir.MembershipID)
	source, sourceErr := dfirReference(tenant, body.Source)
	target, targetErr := dfirReference(tenant, body.Target)
	metadata, documentErr := dfirDocument(body.Metadata)
	if tenantErr != nil || caseErr != nil || idErr != nil || actorErr != nil || sourceErr != nil || targetErr != nil || documentErr != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	result, err := h.dfir.CreateRelationship(r.Context(), actor.dfir, tenant, application.RelationshipCommand{CaseID: caseEntity,
		Input: kernel.RelationshipInput{ID: id, TenantID: tenantEntity, Source: source, Target: target, RelationshipType: body.RelationshipType,
			Metadata: metadata, CreatedBy: createdBy}, Envelope: application.MutationEnvelope{IdempotencyKey: key, Audit: audit}})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapDfirRelationship(result.Resource)
	if err != nil || !setDfirResourceVersionETag(w, mapped.Version) {
		writeDomainError(w, r, application.ErrUnavailable)
		return
	}
	w.Header().Set("Location", r.URL.Path+"/"+uuid.UUID(body.RelationshipId).String())
	w.Header().Set(idempotentReplayHeader, strconv.FormatBool(result.Replayed))
	writeSensitiveJSON(w, http.StatusCreated, mapped)
}

func (h *Handler) RetractTenantCaseDfirRelationship(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, caseID contract.CaseId, relationshipID uuid.UUID, _ contract.RetractTenantCaseDfirRelationshipParams) {
	tenant, caseUUID := uuid.UUID(tenantID), uuid.UUID(caseID)
	actor, audit, key, ok := h.dfirMutationContext(w, r, tenant)
	if !ok {
		return
	}
	var body contract.DfirRelationshipRetractRequest
	if decodePhase4Body(r, &body) != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	if !dfirResourcePrecondition(w, r, int64(body.ExpectedVersion)) {
		return
	}
	caseEntity, caseErr := dfirEntityID(caseUUID)
	relationship, relationshipErr := dfirEntityID(relationshipID)
	retraction, retractionErr := dfirEntityID(uuid.UUID(body.RetractionId))
	if caseErr != nil || relationshipErr != nil || retractionErr != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	result, err := h.dfir.RetractRelationship(r.Context(), actor.dfir, tenant, application.RelationshipRetractCommand{
		CaseID: caseEntity, RelationshipID: relationship, ExpectedVersion: uint64(body.ExpectedVersion),
		RetractionID: retraction, Reason: body.Reason,
		Envelope: application.MutationEnvelope{IdempotencyKey: key, Audit: audit},
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapDfirRelationship(result.Resource)
	if err != nil || !setDfirResourceVersionETag(w, mapped.Version) {
		writeDomainError(w, r, application.ErrUnavailable)
		return
	}
	w.Header().Set(idempotentReplayHeader, strconv.FormatBool(result.Replayed))
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) PrepareTenantCaseDfirAttachmentUpload(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, caseID contract.CaseId, _ contract.PrepareTenantCaseDfirAttachmentUploadParams) {
	tenant, caseUUID := uuid.UUID(tenantID), uuid.UUID(caseID)
	actor, audit, key, ok := h.dfirMutationContext(w, r, tenant)
	if !ok {
		return
	}
	var body contract.DfirAttachmentUploadRequest
	if decodePhase4Body(r, &body) != nil || !body.Classification.Valid() || !body.RequestedVisibility.Valid() {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	attachmentID, attachmentErr := dfirEntityID(uuid.UUID(body.AttachmentId))
	storageID, storageErr := dfirEntityID(uuid.UUID(body.StorageObjectId))
	caseEntity, caseErr := dfirEntityID(caseUUID)
	subject, subjectErr := dfirReference(tenant, body.Subject)
	if attachmentErr != nil || storageErr != nil || caseErr != nil || subjectErr != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	prepared, err := h.dfir.PrepareUpload(r.Context(), actor.dfir, tenant, application.PrepareUploadCommand{
		CaseID: caseEntity, AttachmentID: attachmentID, StorageObjectID: storageID, Subject: subject, OriginalFilename: body.OriginalFilename,
		Classification: kernel.EvidenceClassification(body.Classification), RequestedVisibility: kernel.Visibility(body.RequestedVisibility),
		SizeBytes: body.SizeBytes, ContentType: body.ContentType, Envelope: application.MutationEnvelope{IdempotencyKey: key, Audit: audit},
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
	w.Header().Set("Location", "/api/v1/tenants/"+tenant.String()+"/cases/"+uuid.UUID(caseID).String()+"/dfir/attachments/"+uuid.UUID(body.AttachmentId).String())
	writeSensitiveJSON(w, http.StatusCreated, contract.DfirPreparedUpload{Attachment: attachment, Method: contract.PUT,
		UploadUrl: prepared.Grant.TargetURL, Headers: headers, ExpiresAt: prepared.Grant.ExpiresAt})
}

func (h *Handler) PrepareTenantCaseDfirAttachmentDownload(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, caseID contract.CaseId, attachmentID uuid.UUID) {
	tenant, caseUUID := uuid.UUID(tenantID), uuid.UUID(caseID)
	actor, _, audit, ok := h.phase4MutationActor(w, r, tenant)
	if !ok {
		return
	}
	var body contract.DfirAttachmentDownloadRequest
	if decodePhase4Body(r, &body) != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	attachmentEntity, attachmentErr := dfirEntityID(attachmentID)
	caseEntity, caseErr := dfirEntityID(caseUUID)
	subject, subjectErr := dfirReference(tenant, body.Subject)
	if attachmentErr != nil || caseErr != nil || subjectErr != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	prepared, err := h.dfir.PrepareDownload(r.Context(), actor.dfir, tenant, application.DownloadCommand{
		CaseID: caseEntity, AttachmentID: attachmentEntity, Subject: subject, Audit: audit,
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
	writeSensitiveJSON(w, http.StatusOK, contract.DfirPreparedDownload{Attachment: mapped, DownloadUrl: prepared.Grant.TargetURL, ExpiresAt: prepared.Grant.ExpiresAt})
}

func (h *Handler) CollectTenantCaseDfirEvidence(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, caseID contract.CaseId, _ contract.CollectTenantCaseDfirEvidenceParams) {
	tenant, caseUUID := uuid.UUID(tenantID), uuid.UUID(caseID)
	actor, audit, key, ok := h.dfirMutationContext(w, r, tenant)
	if !ok {
		return
	}
	var body contract.DfirEvidenceCollectRequest
	if decodePhase4Body(r, &body) != nil || !body.Classification.Valid() {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	caseEntity, caseErr := dfirEntityID(caseUUID)
	evidenceID, evidenceErr := dfirEntityID(uuid.UUID(body.EvidenceId))
	storageID, storageErr := dfirEntityID(uuid.UUID(body.StorageObjectId))
	custodyID, custodyErr := dfirEntityID(uuid.UUID(body.InitialCustodyEventId))
	if caseErr != nil || evidenceErr != nil || storageErr != nil || custodyErr != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	result, err := h.dfir.CollectEvidence(r.Context(), actor.dfir, tenant, application.EvidenceCommand{CaseID: caseEntity, EvidenceID: evidenceID,
		StorageObjectID: storageID, InitialCustodyEventID: custodyID, Title: body.Title, Description: body.Description, EvidenceType: body.EvidenceType,
		Classification: kernel.EvidenceClassification(body.Classification), CollectedAt: body.CollectedAt, Source: body.Source,
		RetentionUntil: body.RetentionUntil, LegalHold: body.LegalHold, Envelope: application.MutationEnvelope{IdempotencyKey: key, Audit: audit}})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapDfirEvidence(result.Resource)
	if err != nil || !setDfirResourceVersionETag(w, mapped.Version) {
		writeDomainError(w, r, application.ErrUnavailable)
		return
	}
	w.Header().Set("Location", r.URL.Path+"/"+uuid.UUID(body.EvidenceId).String())
	writeSensitiveJSON(w, http.StatusCreated, mapped)
}

func (h *Handler) AppendTenantCaseDfirCustodyEvent(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, caseID contract.CaseId, evidenceID uuid.UUID, _ contract.AppendTenantCaseDfirCustodyEventParams) {
	tenant, caseUUID := uuid.UUID(tenantID), uuid.UUID(caseID)
	actor, audit, key, ok := h.dfirMutationContext(w, r, tenant)
	if !ok {
		return
	}
	var body contract.DfirCustodyAppendRequest
	if decodePhase4Body(r, &body) != nil || !body.Action.Valid() {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	if !dfirResourcePrecondition(w, r, int64(body.ExpectedVersion)) {
		return
	}
	caseEntity, caseErr := dfirEntityID(caseUUID)
	evidenceEntity, evidenceErr := dfirEntityID(evidenceID)
	eventID, eventErr := dfirEntityID(uuid.UUID(body.CustodyEventId))
	actorEntity, actorErr := dfirEntityID(actor.dfir.MembershipID)
	if caseErr != nil || evidenceErr != nil || eventErr != nil || actorErr != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	command := application.CustodyCommand{CaseID: caseEntity, EvidenceID: evidenceEntity, ExpectedVersion: uint64(body.ExpectedVersion),
		Event:     kernel.CustodyEventInput{ID: eventID, ActorID: actorEntity, Action: kernel.CustodyAction(body.Action), Reason: body.Reason},
		LegalHold: body.LegalHold, RetentionUntil: body.RetentionUntil, RetentionSet: body.Action == contract.DfirCustodyActionRetentionChanged,
		Envelope: application.MutationEnvelope{IdempotencyKey: key, Audit: audit}}
	if body.NextScanState != nil {
		command.NextScanState = kernel.ScanState(*body.NextScanState)
	}
	result, err := h.dfir.AppendCustody(r.Context(), actor.dfir, tenant, command)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapDfirEvidence(result.Resource)
	if err != nil || !setDfirResourceVersionETag(w, mapped.Version) {
		writeDomainError(w, r, application.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) dfirMutationContext(w http.ResponseWriter, r *http.Request, tenantID uuid.UUID) (phase4Actor, application.AuditContext, string, bool) {
	actor, _, audit, ok := h.phase4MutationActor(w, r, tenantID)
	if !ok {
		return phase4Actor{}, application.AuditContext{}, "", false
	}
	key, err := requestIdempotencyKey(r)
	if err != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return phase4Actor{}, application.AuditContext{}, "", false
	}
	return actor, audit, key, true
}

func mapDfirWorkspace(tenantID, caseID uuid.UUID, value application.Workspace) (contract.DfirWorkspace, error) {
	sharedResources, err := mapDfirSharedResources(value.SharedResources)
	if err != nil {
		return contract.DfirWorkspace{}, err
	}
	result := contract.DfirWorkspace{TenantId: tenantID, CaseId: caseID,
		SharedResources: sharedResources,
		Indicators:      make([]contract.DfirIndicator, len(value.Indicators)), Assets: make([]contract.DfirAsset, len(value.Assets)),
		Evidence: make([]contract.DfirEvidence, len(value.Evidence)), Timeline: make([]contract.DfirTimelineEvent, len(value.Timeline)),
		Tasks: make([]contract.DfirTask, len(value.Tasks)), Attachments: make([]contract.DfirAttachment, len(value.Attachments)),
		Relationships: make([]contract.DfirRelationship, len(value.Relationships))}
	for index, item := range value.Indicators {
		result.Indicators[index], err = mapDfirIndicator(item.Resource, caseID, item.Version)
		if err != nil {
			return contract.DfirWorkspace{}, err
		}
	}
	for index, item := range value.Assets {
		result.Assets[index], err = mapDfirAsset(item.Resource, caseID, item.Version)
		if err != nil {
			return contract.DfirWorkspace{}, err
		}
	}
	for index, item := range value.Evidence {
		result.Evidence[index], err = mapDfirEvidence(item)
		if err != nil {
			return contract.DfirWorkspace{}, err
		}
	}
	for index, item := range value.Timeline {
		result.Timeline[index], err = mapDfirTimeline(item.Resource, item.Version)
		if err != nil {
			return contract.DfirWorkspace{}, err
		}
	}
	for index, item := range value.Tasks {
		result.Tasks[index], err = mapDfirTask(item)
		if err != nil {
			return contract.DfirWorkspace{}, err
		}
	}
	for index, item := range value.Attachments {
		result.Attachments[index], err = mapDfirAttachment(item)
		if err != nil {
			return contract.DfirWorkspace{}, err
		}
	}
	for index, item := range value.Relationships {
		result.Relationships[index], err = mapDfirRelationship(item)
		if err != nil {
			return contract.DfirWorkspace{}, err
		}
	}
	return result, nil
}
