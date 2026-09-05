package httpserver

import (
	"net/http"
	"strconv"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/dfir"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	application "github.com/periapsis-im/periapsis/services/api/internal/dfir"
)

func (h *Handler) CollectTenantAlertDfirEvidence(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	alertID contract.AlertId,
	_ contract.CollectTenantAlertDfirEvidenceParams,
) {
	tenant, alertUUID := uuid.UUID(tenantID), uuid.UUID(alertID)
	actor, audit, key, ok := h.dfirMutationContext(w, r, tenant)
	if !ok {
		return
	}
	var body contract.DfirAlertEvidenceCollectRequest
	if decodePhase4Body(r, &body) != nil || !body.Classification.Valid() {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	alert, alertErr := dfirEntityID(alertUUID)
	evidence, evidenceErr := dfirEntityID(uuid.UUID(body.EvidenceId))
	storage, storageErr := dfirEntityID(uuid.UUID(body.StorageObjectId))
	custody, custodyErr := dfirEntityID(uuid.UUID(body.InitialCustodyEventId))
	collectedAt, collectedErr := canonicalAlertTransportInstant(body.CollectedAt)
	retentionUntil, retentionErr := canonicalAlertTransportOptionalInstant(body.RetentionUntil)
	if alertErr != nil || evidenceErr != nil || storageErr != nil || custodyErr != nil ||
		collectedErr != nil || retentionErr != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	result, err := h.alertInvestigation.CollectEvidence(r.Context(), actor.dfir, tenant, application.AlertEvidenceCollectCommand{
		AlertID: alert, EvidenceID: evidence, StorageObjectID: storage, InitialCustodyEventID: custody,
		Title: body.Title, Description: body.Description, EvidenceType: body.EvidenceType,
		Classification: kernel.EvidenceClassification(body.Classification), CollectedAt: collectedAt,
		Source: body.Source, RetentionUntil: retentionUntil, LegalHold: body.LegalHold,
		Envelope: application.MutationEnvelope{IdempotencyKey: key, Audit: audit},
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapDfirAlertEvidence(result.Resource, tenant, alertUUID)
	if err != nil || !setDfirResourceVersionETag(w, mapped.Version) {
		writeDomainError(w, r, application.ErrUnavailable)
		return
	}
	w.Header().Set(idempotentReplayHeader, strconv.FormatBool(result.Replayed))
	w.Header().Set("Location", r.URL.Path+"/"+uuid.UUID(body.EvidenceId).String())
	writeSensitiveJSON(w, http.StatusCreated, mapped)
}

func (h *Handler) AppendTenantAlertDfirCustodyEvent(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	alertID contract.AlertId,
	evidenceID uuid.UUID,
	_ contract.AppendTenantAlertDfirCustodyEventParams,
) {
	tenant, alertUUID := uuid.UUID(tenantID), uuid.UUID(alertID)
	actor, audit, key, ok := h.dfirMutationContext(w, r, tenant)
	if !ok {
		return
	}
	var body contract.DfirAlertCustodyAppendRequest
	if decodePhase4Body(r, &body) != nil || !body.Action.Valid() ||
		body.NextScanState != nil && !body.NextScanState.Valid() {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	if !dfirResourcePrecondition(w, r, int64(body.ExpectedVersion)) {
		return
	}
	alert, alertErr := dfirEntityID(alertUUID)
	evidence, evidenceErr := dfirEntityID(evidenceID)
	event, eventErr := dfirEntityID(uuid.UUID(body.CustodyEventId))
	retentionUntil, retentionErr := canonicalAlertTransportOptionalInstant(body.RetentionUntil)
	if alertErr != nil || evidenceErr != nil || eventErr != nil || retentionErr != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	command := application.AlertCustodyCommand{
		AlertID: alert, EvidenceID: evidence, ExpectedVersion: uint64(body.ExpectedVersion), EventID: event,
		Action: kernel.CustodyAction(body.Action), Reason: body.Reason, LegalHold: body.LegalHold,
		RetentionSet:   body.Action == contract.DfirCustodyActionRetentionChanged,
		RetentionUntil: retentionUntil,
		Envelope:       application.MutationEnvelope{IdempotencyKey: key, Audit: audit},
	}
	if body.NextScanState != nil {
		command.NextScanState = kernel.ScanState(*body.NextScanState)
	}
	result, err := h.alertInvestigation.AppendCustody(r.Context(), actor.dfir, tenant, command)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapDfirAlertEvidence(result.Resource, tenant, alertUUID)
	if err != nil || !setDfirResourceVersionETag(w, mapped.Version) {
		writeDomainError(w, r, application.ErrUnavailable)
		return
	}
	w.Header().Set(idempotentReplayHeader, strconv.FormatBool(result.Replayed))
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) CreateTenantAlertDfirTask(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	alertID contract.AlertId,
	_ contract.CreateTenantAlertDfirTaskParams,
) {
	tenant, alertUUID := uuid.UUID(tenantID), uuid.UUID(alertID)
	actor, audit, key, ok := h.dfirMutationContext(w, r, tenant)
	if !ok {
		return
	}
	var body contract.DfirAlertTaskCreateRequest
	if decodePhase4Body(r, &body) != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	alert, alertErr := dfirEntityID(alertUUID)
	draft, draftErr := alertTaskDraft(uuid.UUID(body.TaskId), body.Task)
	if alertErr != nil || draftErr != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	result, err := h.alertInvestigation.CreateTask(r.Context(), actor.dfir, tenant, application.AlertTaskCreateCommand{
		AlertID: alert, Input: draft,
		Envelope: application.MutationEnvelope{IdempotencyKey: key, Audit: audit},
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapDfirAlertTask(result.Resource, tenant, alertUUID)
	if err != nil || !setDfirResourceVersionETag(w, mapped.Version) {
		writeDomainError(w, r, application.ErrUnavailable)
		return
	}
	w.Header().Set(idempotentReplayHeader, strconv.FormatBool(result.Replayed))
	w.Header().Set("Location", r.URL.Path+"/"+uuid.UUID(body.TaskId).String())
	writeSensitiveJSON(w, http.StatusCreated, mapped)
}

func (h *Handler) TransitionTenantAlertDfirTask(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	alertID contract.AlertId,
	taskID uuid.UUID,
	_ contract.TransitionTenantAlertDfirTaskParams,
) {
	tenant, alertUUID := uuid.UUID(tenantID), uuid.UUID(alertID)
	actor, audit, key, ok := h.dfirMutationContext(w, r, tenant)
	if !ok {
		return
	}
	var body contract.DfirAlertTaskTransitionRequest
	if decodePhase4Body(r, &body) != nil || !body.Target.Valid() {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	if !dfirResourcePrecondition(w, r, int64(body.ExpectedVersion)) {
		return
	}
	alert, alertErr := dfirEntityID(alertUUID)
	task, taskErr := dfirEntityID(taskID)
	completion, completionErr := dfirDocument(body.CompletionData)
	if alertErr != nil || taskErr != nil || completionErr != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	result, err := h.alertInvestigation.TransitionTask(r.Context(), actor.dfir, tenant, application.AlertTaskTransitionCommand{
		AlertID: alert, TaskID: task, ExpectedVersion: uint64(body.ExpectedVersion),
		Target: kernel.TaskStatus(body.Target), Reason: body.Reason, CompletionData: completion,
		Envelope: application.MutationEnvelope{IdempotencyKey: key, Audit: audit},
	})
	writeAlertTaskMutation(w, r, result, err, tenant, alertUUID)
}

func (h *Handler) ReplaceTenantAlertDfirTaskDetails(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	alertID contract.AlertId,
	taskID uuid.UUID,
	_ contract.ReplaceTenantAlertDfirTaskDetailsParams,
) {
	tenant, alertUUID := uuid.UUID(tenantID), uuid.UUID(alertID)
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
	alert, alertErr := dfirEntityID(alertUUID)
	task, taskErr := dfirEntityID(taskID)
	sla, slaErr := optionalDfirEntityID(body.SlaInstanceId)
	if alertErr != nil || taskErr != nil || slaErr != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	result, err := h.alertInvestigation.ReplaceTaskDetails(
		r.Context(), actor.dfir, tenant, application.AlertTaskDetailsCommand{
			AlertID: alert, TaskID: task, ExpectedVersion: uint64(body.ExpectedVersion),
			Title: body.Title, Description: body.Description, Priority: kernel.TaskPriority(body.Priority),
			SLAInstanceID: sla,
			Envelope:      application.MutationEnvelope{IdempotencyKey: key, Audit: audit},
		},
	)
	writeAlertTaskMutation(w, r, result, err, tenant, alertUUID)
}

func (h *Handler) AssignTenantAlertDfirTask(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	alertID contract.AlertId,
	taskID uuid.UUID,
	_ contract.AssignTenantAlertDfirTaskParams,
) {
	tenant, alertUUID := uuid.UUID(tenantID), uuid.UUID(alertID)
	actor, audit, key, ok := h.dfirMutationContext(w, r, tenant)
	if !ok {
		return
	}
	var body contract.DfirAlertTaskAssignmentRequest
	if decodePhase4Body(r, &body) != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	if !dfirResourcePrecondition(w, r, int64(body.ExpectedVersion)) {
		return
	}
	alert, alertErr := dfirEntityID(alertUUID)
	task, taskErr := dfirEntityID(taskID)
	team, teamErr := optionalDfirEntityID(body.OperatorTeamId)
	assignee, assigneeErr := optionalDfirEntityID(body.AssigneeId)
	if alertErr != nil || taskErr != nil || teamErr != nil || assigneeErr != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	result, err := h.alertInvestigation.AssignTask(r.Context(), actor.dfir, tenant, application.AlertTaskAssignmentCommand{
		AlertID: alert, TaskID: task, ExpectedVersion: uint64(body.ExpectedVersion),
		OperatorTeamID: team, AssigneeID: assignee,
		Envelope: application.MutationEnvelope{IdempotencyKey: key, Audit: audit},
	})
	writeAlertTaskMutation(w, r, result, err, tenant, alertUUID)
}

func (h *Handler) RescheduleTenantAlertDfirTask(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	alertID contract.AlertId,
	taskID uuid.UUID,
	_ contract.RescheduleTenantAlertDfirTaskParams,
) {
	tenant, alertUUID := uuid.UUID(tenantID), uuid.UUID(alertID)
	actor, audit, key, ok := h.dfirMutationContext(w, r, tenant)
	if !ok {
		return
	}
	var body contract.DfirAlertTaskDueDateRequest
	if decodePhase4Body(r, &body) != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	if !dfirResourcePrecondition(w, r, int64(body.ExpectedVersion)) {
		return
	}
	alert, alertErr := dfirEntityID(alertUUID)
	task, taskErr := dfirEntityID(taskID)
	dueAt, dueErr := canonicalAlertTransportOptionalInstant(body.DueAt)
	if alertErr != nil || taskErr != nil || dueErr != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	result, err := h.alertInvestigation.RescheduleTask(r.Context(), actor.dfir, tenant, application.AlertTaskDueDateCommand{
		AlertID: alert, TaskID: task, ExpectedVersion: uint64(body.ExpectedVersion), DueAt: dueAt,
		Envelope: application.MutationEnvelope{IdempotencyKey: key, Audit: audit},
	})
	writeAlertTaskMutation(w, r, result, err, tenant, alertUUID)
}

func (h *Handler) ReplaceTenantAlertDfirTaskChecklist(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	alertID contract.AlertId,
	taskID uuid.UUID,
	_ contract.ReplaceTenantAlertDfirTaskChecklistParams,
) {
	tenant, alertUUID := uuid.UUID(tenantID), uuid.UUID(alertID)
	actor, audit, key, ok := h.dfirMutationContext(w, r, tenant)
	if !ok {
		return
	}
	var body contract.DfirAlertTaskChecklistRequest
	if decodePhase4Body(r, &body) != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	if !dfirResourcePrecondition(w, r, int64(body.ExpectedVersion)) {
		return
	}
	alert, alertErr := dfirEntityID(alertUUID)
	task, taskErr := dfirEntityID(taskID)
	checklist, checklistErr := alertChecklistIntents(body.Checklist)
	if alertErr != nil || taskErr != nil || checklistErr != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	result, err := h.alertInvestigation.ReplaceTaskChecklist(r.Context(), actor.dfir, tenant, application.AlertTaskChecklistCommand{
		AlertID: alert, TaskID: task, ExpectedVersion: uint64(body.ExpectedVersion), Checklist: checklist,
		Envelope: application.MutationEnvelope{IdempotencyKey: key, Audit: audit},
	})
	writeAlertTaskMutation(w, r, result, err, tenant, alertUUID)
}

func (h *Handler) ReplaceTenantAlertDfirTaskComments(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	alertID contract.AlertId,
	taskID uuid.UUID,
	_ contract.ReplaceTenantAlertDfirTaskCommentsParams,
) {
	tenant, alertUUID := uuid.UUID(tenantID), uuid.UUID(alertID)
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
	alert, alertErr := dfirEntityID(alertUUID)
	task, taskErr := dfirEntityID(taskID)
	comments, commentsErr := dfirEntityIDs(body.CommentIds)
	if alertErr != nil || taskErr != nil || commentsErr != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	result, err := h.alertInvestigation.ReplaceTaskComments(r.Context(), actor.dfir, tenant, application.AlertTaskCommentsCommand{
		AlertID: alert, TaskID: task, ExpectedVersion: uint64(body.ExpectedVersion), CommentIDs: comments,
		Envelope: application.MutationEnvelope{IdempotencyKey: key, Audit: audit},
	})
	writeAlertTaskMutation(w, r, result, err, tenant, alertUUID)
}

func (h *Handler) CreateTenantAlertDfirRelationship(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	alertID contract.AlertId,
	_ contract.CreateTenantAlertDfirRelationshipParams,
) {
	tenant, alertUUID := uuid.UUID(tenantID), uuid.UUID(alertID)
	actor, audit, key, ok := h.dfirMutationContext(w, r, tenant)
	if !ok {
		return
	}
	var body contract.DfirAlertRelationshipCreateRequest
	if decodePhase4Body(r, &body) != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	alert, alertErr := dfirEntityID(alertUUID)
	id, idErr := dfirEntityID(uuid.UUID(body.RelationshipId))
	source, sourceErr := dfirReference(tenant, body.Source)
	target, targetErr := dfirReference(tenant, body.Target)
	metadata, metadataErr := dfirDocument(body.Metadata)
	if alertErr != nil || idErr != nil || sourceErr != nil || targetErr != nil || metadataErr != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	result, err := h.alertInvestigation.CreateRelationship(r.Context(), actor.dfir, tenant, application.AlertRelationshipCreateCommand{
		AlertID: alert,
		Input: application.AlertRelationshipDraft{
			ID: id, Source: source, Target: target, RelationshipType: body.RelationshipType, Metadata: metadata,
		},
		Envelope: application.MutationEnvelope{IdempotencyKey: key, Audit: audit},
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapDfirAlertRelationship(result.Resource, tenant, alertUUID)
	if err != nil || !setDfirResourceVersionETag(w, mapped.Version) {
		writeDomainError(w, r, application.ErrUnavailable)
		return
	}
	w.Header().Set(idempotentReplayHeader, strconv.FormatBool(result.Replayed))
	w.Header().Set("Location", r.URL.Path+"/"+uuid.UUID(body.RelationshipId).String())
	writeSensitiveJSON(w, http.StatusCreated, mapped)
}

func (h *Handler) RetractTenantAlertDfirRelationship(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	alertID contract.AlertId,
	relationshipID uuid.UUID,
	_ contract.RetractTenantAlertDfirRelationshipParams,
) {
	tenant, alertUUID := uuid.UUID(tenantID), uuid.UUID(alertID)
	actor, audit, key, ok := h.dfirMutationContext(w, r, tenant)
	if !ok {
		return
	}
	var body contract.DfirAlertRelationshipRetractRequest
	if decodePhase4Body(r, &body) != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	if !dfirResourcePrecondition(w, r, int64(body.ExpectedVersion)) {
		return
	}
	alert, alertErr := dfirEntityID(alertUUID)
	relationship, relationshipErr := dfirEntityID(relationshipID)
	retraction, retractionErr := dfirEntityID(uuid.UUID(body.RetractionId))
	if alertErr != nil || relationshipErr != nil || retractionErr != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	result, err := h.alertInvestigation.RetractRelationship(r.Context(), actor.dfir, tenant, application.AlertRelationshipRetractCommand{
		AlertID: alert, RelationshipID: relationship, ExpectedVersion: uint64(body.ExpectedVersion),
		RetractionID: retraction, Reason: body.Reason,
		Envelope: application.MutationEnvelope{IdempotencyKey: key, Audit: audit},
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapDfirAlertRelationship(result.Resource, tenant, alertUUID)
	if err != nil || !setDfirResourceVersionETag(w, mapped.Version) {
		writeDomainError(w, r, application.ErrUnavailable)
		return
	}
	w.Header().Set(idempotentReplayHeader, strconv.FormatBool(result.Replayed))
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func writeAlertTaskMutation(
	w http.ResponseWriter,
	r *http.Request,
	result application.MutationResult[kernel.AlertTask],
	err error,
	tenantID uuid.UUID,
	alertID uuid.UUID,
) {
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapDfirAlertTask(result.Resource, tenantID, alertID)
	if err != nil || !setDfirResourceVersionETag(w, mapped.Version) {
		writeDomainError(w, r, application.ErrUnavailable)
		return
	}
	w.Header().Set(idempotentReplayHeader, strconv.FormatBool(result.Replayed))
	writeSensitiveJSON(w, http.StatusOK, mapped)
}
