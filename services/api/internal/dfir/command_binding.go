package dfir

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"

	kernel "github.com/periapsis-im/periapsis/modules/dfir"
)

type CommandBinding struct {
	Operation     string
	KeyDigest     [sha256.Size]byte
	RequestDigest [sha256.Size]byte
}

const (
	operationIOCCreate           = "dfir.ioc.create"
	operationIOCReplace          = "dfir.ioc.replace"
	operationAssetCreate         = "dfir.asset.create"
	operationAssetReplace        = "dfir.asset.replace"
	operationTimelineCreate      = "dfir.timeline.create"
	operationTaskCreate          = "case.dfir.task.create"
	operationTaskTransition      = "case.dfir.task.transition"
	operationTaskReplaceDetails  = "case.dfir.task.replace_details"
	operationTaskAssign          = "case.dfir.task.assign"
	operationTaskReschedule      = "case.dfir.task.reschedule"
	operationTaskChecklist       = "case.dfir.task.replace_checklist"
	operationTaskComments        = "case.dfir.task.comments.replace"
	operationRelationshipCreate  = "dfir.relationship.create"
	operationRelationshipRetract = "dfir.relationship.retract"
	operationAttachmentPrepare   = "dfir.attachment.prepare"
	operationEvidenceCreate      = "dfir.evidence.create"
	operationCustodyAppend       = "dfir.evidence.custody.append"
)

func commandBinding(operation, key string, payload any) (CommandBinding, error) {
	canonical, err := json.Marshal(payload)
	if err != nil {
		return CommandBinding{}, ErrInvalidInput
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte(operation))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write(canonical)
	return CommandBinding{
		Operation: operation, KeyDigest: sha256.Sum256([]byte(key)),
		RequestDigest: [sha256.Size]byte(digest.Sum(nil)),
	}, nil
}

func indicatorFingerprint(value kernel.Indicator, expectedVersion uint64) map[string]any {
	return map[string]any{
		"id": value.ID().String(), "tenantId": value.TenantID().String(), "type": value.Type(),
		"value": value.Value(), "normalizedValue": value.NormalizedValue(), "description": value.Description(),
		"source": value.Source(), "confidence": value.Confidence(), "tlp": value.TLP(),
		"firstSeen": value.FirstSeen(), "lastSeen": value.LastSeen(), "malicious": value.MaliciousState(),
		"tags": value.Tags(), "enrichment": value.Enrichment(), "expectedVersion": expectedVersion,
	}
}

func assetFingerprint(value kernel.Asset, expectedVersion uint64) map[string]any {
	addresses := value.IPAddresses()
	ips := make([]map[string]any, len(addresses))
	for index, address := range addresses {
		ips[index] = map[string]any{"original": address.Original(), "normalized": address.Normalized(), "family": address.Family()}
	}
	hardware := value.MACAddresses()
	macs := make([]map[string]any, len(hardware))
	for index, address := range hardware {
		macs[index] = map[string]any{"original": address.Original(), "normalized": address.Normalized()}
	}
	return map[string]any{
		"id": value.ID().String(), "tenantId": value.TenantID().String(),
		"hostname": value.Hostname(), "normalizedHostname": value.NormalizedHostname(),
		"fqdn": value.FQDN(), "normalizedFqdn": value.NormalizedFQDN(), "ipAddresses": ips,
		"macAddresses": macs, "assetType": value.AssetType(), "operatingSystem": value.OperatingSystem(),
		"owner": value.Owner(), "businessUnit": value.BusinessUnit(), "criticality": value.Criticality(),
		"environment": value.Environment(), "externalId": value.ExternalID(), "tags": value.Tags(),
		"firstSeen": value.FirstSeen(), "lastSeen": value.LastSeen(), "customAttributes": value.CustomAttributes(),
		"expectedVersion": expectedVersion,
	}
}

func timelineFingerprint(value kernel.TimelineEvent) map[string]any {
	return map[string]any{
		"id": value.ID().String(), "tenantId": value.TenantID().String(),
		"alertId": optionalTimelineRootID(value.AlertID()), "caseId": optionalTimelineRootID(value.CaseID()),
		"eventTime": value.EventTime(), "ingestedAt": value.IngestedAt(), "originalTimezone": value.OriginalTimezone(),
		"precision": value.Precision(), "source": value.Source(), "category": value.Category(),
		"title": value.Title(), "description": value.Description(), "actorId": optionalID(value.ActorID()),
		"iocIds": entityIDs(value.IOCIDs()), "assetIds": entityIDs(value.AssetIDs()),
		"evidenceIds": entityIDs(value.EvidenceIDs()), "tags": value.Tags(),
	}
}

func optionalTimelineRootID(value kernel.EntityID) any {
	if value == (kernel.EntityID{}) {
		return nil
	}
	return value.String()
}

func timelineRequestFingerprint(value kernel.TimelineEvent) map[string]any {
	payload := timelineFingerprint(value)
	delete(payload, "ingestedAt")
	return payload
}

func taskFingerprint(value kernel.Task, expectedVersion uint64) map[string]any {
	checklist := value.Checklist()
	items := make([]map[string]any, len(checklist))
	for index, item := range checklist {
		items[index] = map[string]any{
			"id": item.ID().String(), "title": item.Title(), "completed": item.Completed(),
			"completedAt": item.CompletedAt(), "completedBy": optionalID(item.CompletedBy()),
		}
	}
	return map[string]any{
		"id": value.ID().String(), "tenantId": value.TenantID().String(), "caseId": value.CaseID().String(),
		"title": value.Title(), "description": value.Description(), "status": value.Status(),
		"priority": value.Priority(), "assigneeId": optionalID(value.AssigneeID()),
		"operatorTeamId": optionalID(value.OperatorTeamID()), "dueAt": value.DueAt(), "checklist": items,
		"completedAt": value.CompletedAt(), "completedBy": optionalID(value.CompletedBy()),
		"completionData": value.CompletionData(), "commentIds": entityIDs(value.CommentIDs()),
		"slaInstanceId": optionalID(value.SLAInstanceID()), "createdAt": value.CreatedAt(),
		"updatedAt": value.UpdatedAt(), "version": value.Version(), "expectedVersion": expectedVersion,
	}
}

func taskCreateRequestFingerprint(value kernel.Task) map[string]any {
	return map[string]any{
		"id": value.ID().String(), "tenantId": value.TenantID().String(), "caseId": value.CaseID().String(),
		"title": value.Title(), "description": value.Description(), "priority": value.Priority(),
		"assigneeId": optionalID(value.AssigneeID()), "operatorTeamId": optionalID(value.OperatorTeamID()),
		"dueAt": value.DueAt(), "checklist": taskChecklistProjectionIntentFingerprint(value.Checklist()),
		"slaInstanceId": optionalID(value.SLAInstanceID()),
	}
}

func taskTransitionRequestFingerprint(command TaskTransitionCommand, actorID kernel.EntityID) map[string]any {
	return map[string]any{
		"taskId": command.TaskID.String(), "expectedVersion": command.ExpectedVersion,
		"target": command.Target, "actorId": actorID.String(),
		"reason": command.Reason, "completionData": canonicalRawJSON(command.CompletionData),
	}
}

func taskDetailsRequestFingerprint(command TaskDetailsCommand) map[string]any {
	return map[string]any{
		"taskId": command.TaskID.String(), "expectedVersion": command.ExpectedVersion,
		"title": command.Title, "description": command.Description, "priority": command.Priority,
		"slaInstanceId": optionalID(command.SLAInstanceID),
	}
}

func taskAssignmentRequestFingerprint(command TaskAssignmentCommand) map[string]any {
	return map[string]any{
		"taskId": command.TaskID.String(), "expectedVersion": command.ExpectedVersion,
		"operatorTeamId": optionalID(command.OperatorTeamID), "assigneeId": optionalID(command.AssigneeID),
	}
}

func taskDueDateRequestFingerprint(command TaskDueDateCommand) map[string]any {
	return map[string]any{
		"taskId": command.TaskID.String(), "expectedVersion": command.ExpectedVersion,
		"dueAt": canonicalTimePointer(command.DueAt),
	}
}

func taskChecklistRequestFingerprint(command TaskChecklistCommand) map[string]any {
	return map[string]any{
		"taskId": command.TaskID.String(), "expectedVersion": command.ExpectedVersion,
		"checklist": taskChecklistIntentFingerprint(command.Checklist),
	}
}

func taskCommentsRequestFingerprint(command TaskCommentsCommand) map[string]any {
	return map[string]any{
		"taskId": command.TaskID.String(), "expectedVersion": command.ExpectedVersion,
		"commentIds": entityIDs(command.CommentIDs),
	}
}

func taskChecklistIntentFingerprint(values []TaskChecklistItemIntent) []map[string]any {
	items := make([]map[string]any, len(values))
	for index, item := range values {
		items[index] = map[string]any{
			"id": item.ID.String(), "title": item.Title, "completed": item.Completed,
		}
	}
	return items
}

func taskChecklistProjectionIntentFingerprint(values []kernel.ChecklistItem) []map[string]any {
	items := make([]map[string]any, len(values))
	for index, item := range values {
		items[index] = map[string]any{
			"id": item.ID().String(), "title": item.Title(), "completed": item.Completed(),
		}
	}
	return items
}

func relationshipFingerprint(value kernel.Relationship) map[string]any {
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
		"id": value.ID().String(), "tenantId": value.TenantID().String(),
		"source": referenceFingerprint(value.Source()), "target": referenceFingerprint(value.Target()),
		"relationshipType": value.RelationshipType(), "metadata": value.Metadata(),
		"createdBy": value.CreatedBy().String(), "createdAt": value.CreatedAt(),
		"version": value.Version(), "retractions": history,
	}
}

func relationshipRequestFingerprint(value kernel.Relationship) map[string]any {
	payload := relationshipFingerprint(value)
	delete(payload, "createdAt")
	return payload
}

func relationshipRetractionRequestFingerprint(
	command RelationshipRetractCommand,
	actorID kernel.EntityID,
) map[string]any {
	return map[string]any{
		"relationshipId": command.RelationshipID.String(), "expectedVersion": command.ExpectedVersion,
		"retractionId": command.RetractionID.String(), "actorId": actorID.String(), "reason": command.Reason,
	}
}

func uploadFingerprint(storage kernel.StorageObject, attachment kernel.Attachment, sizeBytes int64, contentType string) map[string]any {
	return map[string]any{
		"storage": map[string]any{
			"id": storage.ID().String(), "tenantId": storage.TenantID().String(),
			"bucket": storage.Bucket(), "objectKey": storage.ObjectKey(),
			"originalFilename": storage.OriginalFilename(), "classification": storage.Classification(),
			"createdBy": storage.CreatedBy().String(),
		},
		"attachment": map[string]any{
			"id": attachment.ID().String(), "tenantId": attachment.TenantID().String(),
			"subject":          referenceFingerprint(attachment.Subject()),
			"storageObjectId":  attachment.StorageObjectID().String(),
			"originalFilename": attachment.OriginalFilename(), "visibility": attachment.Visibility(),
			"uploadedBy": attachment.UploadedBy().String(),
		},
		"sizeBytes": sizeBytes, "contentType": contentType,
	}
}

func custodyRequestFingerprint(command CustodyCommand) map[string]any {
	payload := map[string]any{
		"evidenceId": command.EvidenceID.String(), "expectedVersion": command.ExpectedVersion,
		"eventId": command.Event.ID.String(), "actorId": command.Event.ActorID.String(),
		"action": command.Event.Action, "reason": command.Event.Reason,
		"retentionSet": command.RetentionSet, "legalHold": command.LegalHold,
		"nextScanState": command.NextScanState,
	}
	if command.RetentionUntil != nil {
		payload["retentionUntil"] = command.RetentionUntil.UTC()
	} else {
		payload["retentionUntil"] = nil
	}
	return payload
}

func evidenceCollectRequestFingerprint(command EvidenceCommand, membershipID kernel.EntityID) map[string]any {
	return map[string]any{
		"evidenceId": command.EvidenceID.String(), "storageObjectId": command.StorageObjectID.String(),
		"initialCustodyEventId": command.InitialCustodyEventID.String(), "title": command.Title,
		"description": command.Description, "evidenceType": command.EvidenceType,
		"classification": command.Classification, "collectedAt": command.CollectedAt,
		"collectedByMembershipId": membershipID.String(), "source": command.Source,
		"retentionUntil": canonicalTimePointer(command.RetentionUntil), "legalHold": command.LegalHold,
	}
}

func evidenceFingerprint(value kernel.Evidence, expectedVersion uint64) map[string]any {
	state := value.Snapshot()
	custody := make([]map[string]any, len(state.CustodyEvents))
	for index, event := range state.CustodyEvents {
		custody[index] = map[string]any{
			"id": event.ID.String(), "tenantId": event.TenantID.String(), "evidenceId": event.EvidenceID.String(),
			"sequence": event.Sequence, "action": event.Action, "actorId": event.ActorID.String(),
			"reason": event.Reason, "stateValue": event.StateValue, "previousHash": event.PreviousHash,
			"eventHash": event.EventHash, "occurredAt": event.OccurredAt,
		}
	}
	return map[string]any{
		"id": state.ID.String(), "tenantId": state.TenantID.String(), "caseId": state.CaseID.String(),
		"storageObjectId": state.StorageObjectID.String(), "title": state.Title, "description": state.Description,
		"evidenceType": state.EvidenceType, "classification": state.Classification,
		"contentSha256": state.ContentSHA256, "sizeBytes": state.SizeBytes, "detectedMime": state.DetectedMIME,
		"collectedAt": state.CollectedAt, "collectedBy": state.CollectedBy.String(), "source": state.Source,
		"retentionUntil": state.RetentionUntil, "legalHold": state.LegalHold, "scanState": state.ScanState,
		"sealed": state.Sealed, "destroyed": state.Destroyed, "version": state.Version,
		"expectedVersion": expectedVersion, "custody": custody,
	}
}

func storageFingerprint(value kernel.StorageObject) map[string]any {
	state := value.Snapshot()
	return map[string]any{
		"id": state.ID.String(), "tenantId": state.TenantID.String(), "bucket": state.Bucket,
		"objectKey": state.ObjectKey, "originalFilename": state.OriginalFilename,
		"classification": state.Classification, "createdBy": state.CreatedBy.String(),
		"expectedSizeBytes": state.ExpectedSizeBytes, "uploadExpiresAt": state.UploadExpiresAt,
		"createdAt": state.CreatedAt, "updatedAt": state.UpdatedAt, "state": state.State,
		"contentSha256": state.ContentSHA256, "sizeBytes": state.SizeBytes,
		"detectedMime": state.DetectedMIME, "verifiedAt": state.VerifiedAt,
		"retentionUntil": state.RetentionUntil, "legalHold": state.LegalHold,
		"version": state.Version,
	}
}

func attachmentFingerprint(value kernel.Attachment) map[string]any {
	return map[string]any{
		"id": value.ID().String(), "tenantId": value.TenantID().String(),
		"subject": referenceFingerprint(value.Subject()), "storageObjectId": value.StorageObjectID().String(),
		"originalFilename": value.OriginalFilename(), "visibility": value.Visibility(),
		"uploadedBy": value.UploadedBy().String(), "uploadedAt": value.UploadedAt(), "scanState": value.ScanState(),
	}
}

func referenceFingerprint(value kernel.EntityReference) map[string]any {
	return map[string]any{
		"tenantId": value.TenantID().String(), "kind": value.Kind(), "id": value.ID().String(),
		"externalType": value.ExternalType(), "externalId": value.ExternalID(),
	}
}

func entityIDs(values []kernel.EntityID) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = value.String()
	}
	return result
}

func optionalID(value *kernel.EntityID) any {
	if value == nil {
		return nil
	}
	return value.String()
}

func sameFingerprint(left, right any) bool {
	leftCanonical, leftErr := json.Marshal(left)
	rightCanonical, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftCanonical, rightCanonical)
}
