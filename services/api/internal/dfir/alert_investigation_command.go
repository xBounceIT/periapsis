package dfir

import (
	"encoding/json"
	"slices"
	"time"

	kernel "github.com/periapsis-im/periapsis/modules/dfir"
)

const (
	operationAlertEvidenceCreate       = "dfir.alert.evidence.create"
	operationAlertEvidenceCustody      = "dfir.alert.evidence.custody.append"
	operationAlertTaskCreate           = "dfir.alert.task.create"
	operationAlertTaskTransition       = "dfir.alert.task.transition"
	operationAlertTaskReplaceDetails   = "dfir.alert.task.replace_details"
	operationAlertTaskAssign           = "dfir.alert.task.assign"
	operationAlertTaskReschedule       = "dfir.alert.task.reschedule"
	operationAlertTaskChecklistReplace = "dfir.alert.task.checklist.replace"
	operationAlertTaskCommentsReplace  = "dfir.alert.task.comments.replace"
	operationAlertRelationshipCreate   = "dfir.alert.relationship.create"
	operationAlertRelationshipRetract  = "dfir.alert.relationship.retract"
)

type alertMutationEffects struct {
	activity string
	audit    string
	outbox   string
}

func alertEffects(operation string) (alertMutationEffects, bool) {
	switch operation {
	case operationAlertEvidenceCreate:
		return alertMutationEffects{
			activity: "alert.evidence.added", audit: "dfir.alert.evidence.create", outbox: "alert.evidence.added.v1",
		}, true
	case operationAlertEvidenceCustody:
		return alertMutationEffects{
			activity: "alert.evidence.custody_appended", audit: "dfir.alert.evidence.custody.append",
			outbox: "alert.evidence.custody_appended.v1",
		}, true
	case operationAlertTaskCreate:
		return alertMutationEffects{
			activity: "alert.task.created", audit: "dfir.alert.task.create", outbox: "alert.task.created.v1",
		}, true
	case operationAlertTaskTransition:
		return alertMutationEffects{
			activity: "alert.task.transitioned", audit: "dfir.alert.task.transition",
			outbox: "alert.task.transitioned.v1",
		}, true
	case operationAlertTaskReplaceDetails:
		return alertMutationEffects{
			activity: "alert.task.details_replaced", audit: "dfir.alert.task.replace_details",
			outbox: "alert.task.details_replaced.v1",
		}, true
	case operationAlertTaskAssign:
		return alertMutationEffects{
			activity: "alert.task.assigned", audit: "dfir.alert.task.assign", outbox: "alert.task.assigned.v1",
		}, true
	case operationAlertTaskReschedule:
		return alertMutationEffects{
			activity: "alert.task.rescheduled", audit: "dfir.alert.task.reschedule",
			outbox: "alert.task.rescheduled.v1",
		}, true
	case operationAlertTaskChecklistReplace:
		return alertMutationEffects{
			activity: "alert.task.checklist_replaced", audit: "dfir.alert.task.checklist.replace",
			outbox: "alert.task.checklist_replaced.v1",
		}, true
	case operationAlertTaskCommentsReplace:
		return alertMutationEffects{
			activity: "alert.task.comments_replaced", audit: "dfir.alert.task.comments.replace",
			outbox: "alert.task.comments_replaced.v1",
		}, true
	case operationAlertRelationshipCreate:
		return alertMutationEffects{
			activity: "alert.relationship.created", audit: "dfir.alert.relationship.create",
			outbox: "alert.relationship.created.v1",
		}, true
	case operationAlertRelationshipRetract:
		return alertMutationEffects{
			activity: "alert.relationship.retracted", audit: "dfir.alert.relationship.retract",
			outbox: "alert.relationship.retracted.v1",
		}, true
	default:
		return alertMutationEffects{}, false
	}
}

func newAlertMutationContract(
	actor Actor,
	alertID kernel.EntityID,
	envelope MutationEnvelope,
	access Access,
	capability Capability,
	operation string,
	auditReason string,
	request any,
) (AlertMutationContract, error) {
	effects, ok := alertEffects(operation)
	if !ok || !validAlertSingleLineText(auditReason, 2_000, false) {
		return AlertMutationContract{}, ErrInvalidInput
	}
	base, err := alertBaseWrite(actor, alertID, envelope, operation, alertScopedFingerprint(alertID, request))
	if err != nil {
		return AlertMutationContract{}, err
	}
	return AlertMutationContract{
		BaseWrite: base, Access: access, Capability: capability,
		ActivityType: effects.activity, AuditAction: effects.audit,
		AuditReason: auditReason, OutboxEventType: effects.outbox,
	}, nil
}

func alertEvidenceFingerprint(value kernel.AlertEvidence, expectedVersion uint64) map[string]any {
	state := value.Snapshot()
	custody := make([]map[string]any, len(state.CustodyEvents))
	for index, event := range state.CustodyEvents {
		custody[index] = map[string]any{
			"id": event.ID.String(), "tenantId": event.TenantID.String(),
			"evidenceId": event.EvidenceID.String(), "sequence": event.Sequence,
			"action": event.Action, "actorId": event.ActorID.String(), "reason": event.Reason,
			"stateValue": event.StateValue, "previousHash": event.PreviousHash,
			"eventHash": event.EventHash, "occurredAt": event.OccurredAt,
		}
	}
	return map[string]any{
		"id": state.ID.String(), "tenantId": state.TenantID.String(), "alertId": state.AlertID.String(),
		"storageObjectId": state.StorageObjectID.String(), "title": state.Title,
		"description": state.Description, "evidenceType": state.EvidenceType,
		"classification": state.Classification, "contentSha256": state.ContentSHA256,
		"sizeBytes": state.SizeBytes, "detectedMime": state.DetectedMIME,
		"collectedAt": state.CollectedAt, "collectedBy": state.CollectedBy.String(), "source": state.Source,
		"retentionUntil": state.RetentionUntil, "legalHold": state.LegalHold, "scanState": state.ScanState,
		"sealed": state.Sealed, "destroyed": state.Destroyed, "version": state.Version,
		"expectedVersion": expectedVersion, "custody": custody,
	}
}

func alertEvidenceCollectRequestFingerprint(
	command AlertEvidenceCollectCommand,
	membershipID kernel.EntityID,
	userID kernel.EntityID,
) map[string]any {
	return map[string]any{
		"evidenceId": command.EvidenceID.String(), "storageObjectId": command.StorageObjectID.String(),
		"initialCustodyEventId": command.InitialCustodyEventID.String(), "title": command.Title,
		"description": command.Description, "evidenceType": command.EvidenceType,
		"classification": command.Classification, "collectedAt": command.CollectedAt,
		"collectedByMembershipId": membershipID.String(), "initialCustodyActorUserId": userID.String(),
		"source":         command.Source,
		"retentionUntil": canonicalTimePointer(command.RetentionUntil), "legalHold": command.LegalHold,
	}
}

func alertCustodyRequestFingerprint(command AlertCustodyCommand, actorID kernel.EntityID) map[string]any {
	return map[string]any{
		"evidenceId": command.EvidenceID.String(), "expectedVersion": command.ExpectedVersion,
		"eventId": command.EventID.String(), "actorId": actorID.String(), "action": command.Action,
		"reason": command.Reason, "nextScanState": command.NextScanState,
		"legalHold": command.LegalHold, "retentionSet": command.RetentionSet,
		"retentionUntil": canonicalTimePointer(command.RetentionUntil),
	}
}

func alertTaskFingerprint(value kernel.AlertTask, expectedVersion uint64) map[string]any {
	return map[string]any{
		"id": value.ID().String(), "tenantId": value.TenantID().String(), "alertId": value.AlertID().String(),
		"title": value.Title(), "description": value.Description(), "status": value.Status(),
		"priority": value.Priority(), "assigneeId": optionalID(value.AssigneeID()),
		"operatorTeamId": optionalID(value.OperatorTeamID()), "dueAt": value.DueAt(),
		"checklist": alertChecklistFingerprint(value.Checklist()), "completedAt": value.CompletedAt(),
		"completedBy": optionalID(value.CompletedBy()), "completionData": canonicalRawJSON(value.CompletionData()),
		"commentIds": entityIDs(value.CommentIDs()), "slaInstanceId": optionalID(value.SLAInstanceID()),
		"createdAt": value.CreatedAt(), "updatedAt": value.UpdatedAt(), "version": value.Version(),
		"expectedVersion": expectedVersion,
	}
}

func alertTaskCreateRequestFingerprint(value kernel.AlertTask) map[string]any {
	payload := alertTaskFingerprint(value, 0)
	delete(payload, "createdAt")
	delete(payload, "updatedAt")
	payload["checklist"] = alertChecklistProjectionIntentFingerprint(value.Checklist())
	return payload
}

func alertChecklistFingerprint(values []kernel.ChecklistItem) []map[string]any {
	items := make([]map[string]any, len(values))
	for index, item := range values {
		items[index] = map[string]any{
			"id": item.ID().String(), "title": item.Title(), "completed": item.Completed(),
			"completedAt": item.CompletedAt(), "completedBy": optionalID(item.CompletedBy()),
		}
	}
	return items
}

func alertChecklistIntentFingerprint(values []AlertChecklistItemIntent) []map[string]any {
	items := make([]map[string]any, len(values))
	for index, item := range values {
		items[index] = map[string]any{
			"id": item.ID.String(), "title": item.Title, "completed": item.Completed,
		}
	}
	return items
}

func alertChecklistProjectionIntentFingerprint(values []kernel.ChecklistItem) []map[string]any {
	items := make([]map[string]any, len(values))
	for index, item := range values {
		items[index] = map[string]any{
			"id": item.ID().String(), "title": item.Title(), "completed": item.Completed(),
		}
	}
	return items
}

func alertTaskTransitionRequestFingerprint(command AlertTaskTransitionCommand, actorID kernel.EntityID) map[string]any {
	return map[string]any{
		"taskId": command.TaskID.String(), "expectedVersion": command.ExpectedVersion,
		"target": command.Target, "actorId": actorID.String(), "reason": command.Reason,
		"completionData": canonicalRawJSON(command.CompletionData),
	}
}

func alertTaskDetailsRequestFingerprint(command AlertTaskDetailsCommand) map[string]any {
	return map[string]any{
		"taskId": command.TaskID.String(), "expectedVersion": command.ExpectedVersion,
		"title": command.Title, "description": command.Description, "priority": command.Priority,
		"slaInstanceId": optionalID(command.SLAInstanceID),
	}
}

func alertTaskAssignmentRequestFingerprint(command AlertTaskAssignmentCommand) map[string]any {
	return map[string]any{
		"taskId": command.TaskID.String(), "expectedVersion": command.ExpectedVersion,
		"operatorTeamId": optionalID(command.OperatorTeamID), "assigneeId": optionalID(command.AssigneeID),
	}
}

func alertTaskDueDateRequestFingerprint(command AlertTaskDueDateCommand) map[string]any {
	return map[string]any{
		"taskId": command.TaskID.String(), "expectedVersion": command.ExpectedVersion,
		"dueAt": canonicalTimePointer(command.DueAt),
	}
}

func alertTaskChecklistRequestFingerprint(command AlertTaskChecklistCommand) map[string]any {
	return map[string]any{
		"taskId": command.TaskID.String(), "expectedVersion": command.ExpectedVersion,
		"checklist": alertChecklistIntentFingerprint(command.Checklist),
	}
}

func alertTaskCommentsRequestFingerprint(command AlertTaskCommentsCommand) map[string]any {
	return map[string]any{
		"taskId": command.TaskID.String(), "expectedVersion": command.ExpectedVersion,
		"commentIds": entityIDs(command.CommentIDs),
	}
}

func alertRelationshipFingerprint(value kernel.AlertRelationship, expectedVersion uint64) map[string]any {
	retractions := value.Retractions()
	history := make([]map[string]any, len(retractions))
	for index, retraction := range retractions {
		history[index] = map[string]any{
			"id": retraction.ID.String(), "tenantId": retraction.TenantID.String(),
			"relationshipId": retraction.RelationshipID.String(), "sequence": retraction.Sequence,
			"actorId": retraction.ActorID.String(), "reason": retraction.Reason,
			"occurredAt": retraction.OccurredAt,
		}
	}
	return map[string]any{
		"id": value.ID().String(), "tenantId": value.TenantID().String(), "alertId": value.AlertID().String(),
		"source": referenceFingerprint(value.Source()), "target": referenceFingerprint(value.Target()),
		"relationshipType": value.RelationshipType(), "metadata": canonicalRawJSON(value.Metadata()),
		"createdBy": value.CreatedBy().String(), "createdAt": value.CreatedAt(),
		"version": value.Version(), "expectedVersion": expectedVersion, "retractions": history,
	}
}

func alertRelationshipCreateRequestFingerprint(value kernel.AlertRelationship) map[string]any {
	payload := alertRelationshipFingerprint(value, 0)
	delete(payload, "createdAt")
	return payload
}

func alertRelationshipRetractionRequestFingerprint(
	command AlertRelationshipRetractCommand,
	actorID kernel.EntityID,
) map[string]any {
	return map[string]any{
		"relationshipId": command.RelationshipID.String(), "expectedVersion": command.ExpectedVersion,
		"retractionId": command.RetractionID.String(), "actorId": actorID.String(), "reason": command.Reason,
	}
}

func canonicalTimePointer(value *time.Time) any {
	if value == nil {
		return nil
	}
	return *value
}

func canonicalRawJSON(value json.RawMessage) any {
	if len(value) == 0 {
		return nil
	}
	return slices.Clone(value)
}
