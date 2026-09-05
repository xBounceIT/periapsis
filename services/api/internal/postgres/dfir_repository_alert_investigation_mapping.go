package postgres

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"

	kernel "github.com/periapsis-im/periapsis/modules/dfir"
)

const alertInvestigationSnapshotKindEvidence = "alert_evidence"
const alertInvestigationSnapshotKindTask = "alert_task"
const alertInvestigationSnapshotKindRelationship = "alert_relationship"

type alertInvestigationResultSnapshot struct {
	Kind         string                       `json:"kind"`
	Evidence     *alertEvidenceResultSnapshot `json:"evidence,omitempty"`
	Task         *alertTaskResultSnapshot     `json:"task,omitempty"`
	Relationship *alertRelationResultSnapshot `json:"relationship,omitempty"`
}

type alertCustodyResultSnapshot struct {
	ID           uuid.UUID            `json:"id"`
	TenantID     uuid.UUID            `json:"tenantId"`
	EvidenceID   uuid.UUID            `json:"evidenceId"`
	Sequence     uint64               `json:"sequence"`
	Action       kernel.CustodyAction `json:"action"`
	ActorID      uuid.UUID            `json:"actorId"`
	Reason       string               `json:"reason"`
	StateValue   string               `json:"stateValue"`
	PreviousHash []byte               `json:"previousHash"`
	EventHash    []byte               `json:"eventHash"`
	OccurredAt   time.Time            `json:"occurredAt"`
}

type alertEvidenceResultSnapshot struct {
	ID                    uuid.UUID                     `json:"id"`
	TenantID              uuid.UUID                     `json:"tenantId"`
	AlertID               uuid.UUID                     `json:"alertId"`
	StorageObjectID       uuid.UUID                     `json:"storageObjectId"`
	Title                 string                        `json:"title"`
	Description           string                        `json:"description"`
	EvidenceType          string                        `json:"evidenceType"`
	Classification        kernel.EvidenceClassification `json:"classification"`
	ContentSHA256         string                        `json:"contentSha256"`
	SizeBytes             int64                         `json:"sizeBytes"`
	DetectedMIME          string                        `json:"detectedMime"`
	CollectedAt           time.Time                     `json:"collectedAt"`
	CollectedBy           uuid.UUID                     `json:"collectedBy"`
	Source                string                        `json:"source"`
	RetentionUntil        *time.Time                    `json:"retentionUntil,omitempty"`
	LegalHold             bool                          `json:"legalHold"`
	ScanState             kernel.ScanState              `json:"scanState"`
	InitialRetentionUntil *time.Time                    `json:"initialRetentionUntil,omitempty"`
	InitialLegalHold      bool                          `json:"initialLegalHold"`
	InitialScanState      kernel.ScanState              `json:"initialScanState"`
	Sealed                bool                          `json:"sealed"`
	Destroyed             bool                          `json:"destroyed"`
	Version               uint64                        `json:"version"`
	CustodyEvents         []alertCustodyResultSnapshot  `json:"custodyEvents"`
}

type alertChecklistResultSnapshot struct {
	ID          uuid.UUID  `json:"id"`
	Title       string     `json:"title"`
	Completed   bool       `json:"completed"`
	CompletedAt *time.Time `json:"completedAt,omitempty"`
	CompletedBy *uuid.UUID `json:"completedBy,omitempty"`
}

type alertTaskResultSnapshot struct {
	ID             uuid.UUID                      `json:"id"`
	TenantID       uuid.UUID                      `json:"tenantId"`
	AlertID        uuid.UUID                      `json:"alertId"`
	Title          string                         `json:"title"`
	Description    string                         `json:"description"`
	Status         kernel.TaskStatus              `json:"status"`
	Priority       kernel.TaskPriority            `json:"priority"`
	AssigneeID     *uuid.UUID                     `json:"assigneeId,omitempty"`
	OperatorTeamID *uuid.UUID                     `json:"operatorTeamId,omitempty"`
	DueAt          *time.Time                     `json:"dueAt,omitempty"`
	Checklist      []alertChecklistResultSnapshot `json:"checklist"`
	CompletedAt    *time.Time                     `json:"completedAt,omitempty"`
	CompletedBy    *uuid.UUID                     `json:"completedBy,omitempty"`
	CompletionData json.RawMessage                `json:"completionData,omitempty"`
	CommentIDs     []uuid.UUID                    `json:"commentIds"`
	SLAInstanceID  *uuid.UUID                     `json:"slaInstanceId,omitempty"`
	CreatedAt      time.Time                      `json:"createdAt"`
	UpdatedAt      time.Time                      `json:"updatedAt"`
	Version        uint64                         `json:"version"`
}

type alertReferenceResultSnapshot struct {
	Kind         kernel.EntityKind `json:"kind"`
	ID           *uuid.UUID        `json:"id,omitempty"`
	ExternalType string            `json:"externalType,omitempty"`
	ExternalID   string            `json:"externalId,omitempty"`
}

type alertRetractionResultSnapshot struct {
	ID             uuid.UUID `json:"id"`
	TenantID       uuid.UUID `json:"tenantId"`
	RelationshipID uuid.UUID `json:"relationshipId"`
	Sequence       uint64    `json:"sequence"`
	ActorID        uuid.UUID `json:"actorId"`
	Reason         string    `json:"reason"`
	OccurredAt     time.Time `json:"occurredAt"`
}

type alertRelationResultSnapshot struct {
	ID               uuid.UUID                       `json:"id"`
	TenantID         uuid.UUID                       `json:"tenantId"`
	AlertID          uuid.UUID                       `json:"alertId"`
	Source           alertReferenceResultSnapshot    `json:"source"`
	Target           alertReferenceResultSnapshot    `json:"target"`
	RelationshipType string                          `json:"relationshipType"`
	Metadata         json.RawMessage                 `json:"metadata,omitempty"`
	CreatedBy        uuid.UUID                       `json:"createdBy"`
	CreatedAt        time.Time                       `json:"createdAt"`
	Version          uint64                          `json:"version"`
	Retractions      []alertRetractionResultSnapshot `json:"retractions"`
}

func encodeAlertEvidenceResult(value kernel.AlertEvidence) ([]byte, error) {
	state := value.Snapshot()
	custody := make([]alertCustodyResultSnapshot, len(state.CustodyEvents))
	for index, event := range state.CustodyEvents {
		custody[index] = alertCustodyResultSnapshot{
			ID: uuid.UUID(event.ID.Bytes()), TenantID: uuid.UUID(event.TenantID.Bytes()),
			EvidenceID: uuid.UUID(event.EvidenceID.Bytes()), Sequence: event.Sequence,
			Action: event.Action, ActorID: uuid.UUID(event.ActorID.Bytes()), Reason: event.Reason,
			StateValue: event.StateValue, PreviousHash: append([]byte(nil), event.PreviousHash[:]...),
			EventHash: append([]byte(nil), event.EventHash[:]...), OccurredAt: event.OccurredAt,
		}
	}
	snapshot := alertEvidenceResultSnapshot{
		ID: uuid.UUID(state.ID.Bytes()), TenantID: uuid.UUID(state.TenantID.Bytes()),
		AlertID: uuid.UUID(state.AlertID.Bytes()), StorageObjectID: uuid.UUID(state.StorageObjectID.Bytes()),
		Title: state.Title, Description: state.Description, EvidenceType: state.EvidenceType,
		Classification: state.Classification, ContentSHA256: state.ContentSHA256,
		SizeBytes: state.SizeBytes, DetectedMIME: state.DetectedMIME, CollectedAt: state.CollectedAt,
		CollectedBy: uuid.UUID(state.CollectedBy.Bytes()), Source: state.Source,
		RetentionUntil: state.RetentionUntil, LegalHold: state.LegalHold, ScanState: state.ScanState,
		InitialRetentionUntil: state.InitialRetentionUntil, InitialLegalHold: state.InitialLegalHold,
		InitialScanState: state.InitialScanState, Sealed: state.Sealed, Destroyed: state.Destroyed,
		Version: state.Version, CustodyEvents: custody,
	}
	return json.Marshal(alertInvestigationResultSnapshot{Kind: alertInvestigationSnapshotKindEvidence, Evidence: &snapshot})
}

func decodeAlertEvidenceResult(document []byte) (kernel.AlertEvidence, error) {
	var envelope alertInvestigationResultSnapshot
	if err := decodeAlertInvestigationSnapshot(document, &envelope); err != nil ||
		envelope.Kind != alertInvestigationSnapshotKindEvidence || envelope.Evidence == nil ||
		envelope.Task != nil || envelope.Relationship != nil {
		return kernel.AlertEvidence{}, unexpectedDFIRProjection("invalid Alert evidence replay snapshot")
	}
	value := envelope.Evidence
	id, err := parseDFIREntityID(value.ID)
	if err != nil {
		return kernel.AlertEvidence{}, err
	}
	tenant, err := parseDFIREntityID(value.TenantID)
	if err != nil {
		return kernel.AlertEvidence{}, err
	}
	alert, err := parseDFIREntityID(value.AlertID)
	if err != nil {
		return kernel.AlertEvidence{}, err
	}
	storage, err := parseDFIREntityID(value.StorageObjectID)
	if err != nil {
		return kernel.AlertEvidence{}, err
	}
	collector, err := parseDFIREntityID(value.CollectedBy)
	if err != nil {
		return kernel.AlertEvidence{}, err
	}
	custody := make([]kernel.CustodyEventState, len(value.CustodyEvents))
	for index, event := range value.CustodyEvents {
		if len(event.PreviousHash) != 32 || len(event.EventHash) != 32 {
			return kernel.AlertEvidence{}, unexpectedDFIRProjection("invalid Alert custody replay hash")
		}
		eventID, parseErr := parseDFIREntityID(event.ID)
		if parseErr != nil {
			return kernel.AlertEvidence{}, parseErr
		}
		eventTenant, parseErr := parseDFIREntityID(event.TenantID)
		if parseErr != nil {
			return kernel.AlertEvidence{}, parseErr
		}
		evidenceID, parseErr := parseDFIREntityID(event.EvidenceID)
		if parseErr != nil {
			return kernel.AlertEvidence{}, parseErr
		}
		actor, parseErr := parseDFIREntityID(event.ActorID)
		if parseErr != nil {
			return kernel.AlertEvidence{}, parseErr
		}
		custody[index] = kernel.CustodyEventState{
			ID: eventID, TenantID: eventTenant, EvidenceID: evidenceID, Sequence: event.Sequence,
			Action: event.Action, ActorID: actor, Reason: event.Reason, StateValue: event.StateValue,
			OccurredAt: canonicalAlertDatabaseTime(event.OccurredAt),
		}
		copy(custody[index].PreviousHash[:], event.PreviousHash)
		copy(custody[index].EventHash[:], event.EventHash)
	}
	result, err := kernel.RestoreAlertEvidence(kernel.AlertEvidenceState{
		ID: id, TenantID: tenant, AlertID: alert, StorageObjectID: storage,
		Title: value.Title, Description: value.Description, EvidenceType: value.EvidenceType,
		Classification: value.Classification, ContentSHA256: value.ContentSHA256,
		SizeBytes: value.SizeBytes, DetectedMIME: value.DetectedMIME,
		CollectedAt: canonicalAlertDatabaseTime(value.CollectedAt), CollectedBy: collector,
		Source: value.Source, RetentionUntil: canonicalOptionalAlertDatabaseTime(value.RetentionUntil),
		LegalHold: value.LegalHold, ScanState: value.ScanState,
		InitialRetentionUntil: canonicalOptionalAlertDatabaseTime(value.InitialRetentionUntil),
		InitialLegalHold:      value.InitialLegalHold, InitialScanState: value.InitialScanState,
		Sealed: value.Sealed, Destroyed: value.Destroyed, Version: value.Version, CustodyEvents: custody,
	})
	if err != nil {
		return kernel.AlertEvidence{}, unexpectedDFIRProjection("non-canonical Alert evidence replay snapshot")
	}
	return result, nil
}

func encodeAlertTaskResult(value kernel.AlertTask) ([]byte, error) {
	state := value.Snapshot()
	checklist := make([]alertChecklistResultSnapshot, len(state.Checklist))
	for index, item := range state.Checklist {
		checklist[index] = alertChecklistResultSnapshot{
			ID: uuid.UUID(item.ID().Bytes()), Title: item.Title(), Completed: item.Completed(),
			CompletedAt: item.CompletedAt(), CompletedBy: optionalKernelUUIDPointer(item.CompletedBy()),
		}
	}
	snapshot := alertTaskResultSnapshot{
		ID: uuid.UUID(state.ID.Bytes()), TenantID: uuid.UUID(state.TenantID.Bytes()), AlertID: uuid.UUID(state.AlertID.Bytes()),
		Title: state.Title, Description: state.Description, Status: state.Status, Priority: state.Priority,
		AssigneeID: optionalKernelUUIDPointer(state.AssigneeID), OperatorTeamID: optionalKernelUUIDPointer(state.OperatorTeamID),
		DueAt: state.DueAt, Checklist: checklist, CompletedAt: state.CompletedAt,
		CompletedBy: optionalKernelUUIDPointer(state.CompletedBy), CompletionData: state.CompletionData,
		CommentIDs: kernelUUIDs(state.CommentIDs), SLAInstanceID: optionalKernelUUIDPointer(state.SLAInstanceID),
		CreatedAt: state.CreatedAt, UpdatedAt: state.UpdatedAt, Version: state.Version,
	}
	return json.Marshal(alertInvestigationResultSnapshot{Kind: alertInvestigationSnapshotKindTask, Task: &snapshot})
}

func decodeAlertTaskResult(document []byte) (kernel.AlertTask, error) {
	var envelope alertInvestigationResultSnapshot
	if err := decodeAlertInvestigationSnapshot(document, &envelope); err != nil ||
		envelope.Kind != alertInvestigationSnapshotKindTask || envelope.Task == nil ||
		envelope.Evidence != nil || envelope.Relationship != nil {
		return kernel.AlertTask{}, unexpectedDFIRProjection("invalid Alert task replay snapshot")
	}
	value := envelope.Task
	id, err := parseDFIREntityID(value.ID)
	if err != nil {
		return kernel.AlertTask{}, err
	}
	tenant, err := parseDFIREntityID(value.TenantID)
	if err != nil {
		return kernel.AlertTask{}, err
	}
	alert, err := parseDFIREntityID(value.AlertID)
	if err != nil {
		return kernel.AlertTask{}, err
	}
	assignee, err := parseOptionalDFIREntityID(value.AssigneeID)
	if err != nil {
		return kernel.AlertTask{}, err
	}
	team, err := parseOptionalDFIREntityID(value.OperatorTeamID)
	if err != nil {
		return kernel.AlertTask{}, err
	}
	completer, err := parseOptionalDFIREntityID(value.CompletedBy)
	if err != nil {
		return kernel.AlertTask{}, err
	}
	sla, err := parseOptionalDFIREntityID(value.SLAInstanceID)
	if err != nil {
		return kernel.AlertTask{}, err
	}
	checklist := make([]kernel.ChecklistItem, len(value.Checklist))
	for index, item := range value.Checklist {
		itemID, parseErr := parseDFIREntityID(item.ID)
		if parseErr != nil {
			return kernel.AlertTask{}, parseErr
		}
		completedBy, parseErr := parseOptionalDFIREntityID(item.CompletedBy)
		if parseErr != nil {
			return kernel.AlertTask{}, parseErr
		}
		checklist[index], parseErr = kernel.NewChecklistItem(kernel.ChecklistItemInput{
			ID: itemID, Title: item.Title, Completed: item.Completed,
			CompletedAt: canonicalOptionalAlertDatabaseTime(item.CompletedAt), CompletedBy: completedBy,
		})
		if parseErr != nil {
			return kernel.AlertTask{}, unexpectedDFIRProjection("non-canonical Alert checklist replay snapshot")
		}
	}
	comments := make([]kernel.EntityID, len(value.CommentIDs))
	for index, comment := range value.CommentIDs {
		comments[index], err = parseDFIREntityID(comment)
		if err != nil {
			return kernel.AlertTask{}, err
		}
	}
	result, err := kernel.NewAlertTask(kernel.AlertTaskState{
		ID: id, TenantID: tenant, AlertID: alert, Title: value.Title, Description: value.Description,
		Status: value.Status, Priority: value.Priority, AssigneeID: assignee, OperatorTeamID: team,
		DueAt: canonicalOptionalAlertDatabaseTime(value.DueAt), Checklist: checklist,
		CompletedAt: canonicalOptionalAlertDatabaseTime(value.CompletedAt), CompletedBy: completer,
		CompletionData: canonicalJSONObject(value.CompletionData), CommentIDs: comments, SLAInstanceID: sla,
		CreatedAt: canonicalAlertDatabaseTime(value.CreatedAt), UpdatedAt: canonicalAlertDatabaseTime(value.UpdatedAt),
		Version: value.Version,
	})
	if err != nil {
		return kernel.AlertTask{}, unexpectedDFIRProjection("non-canonical Alert task replay snapshot")
	}
	return result, nil
}

func encodeAlertRelationshipResult(value kernel.AlertRelationship) ([]byte, error) {
	state := value.Snapshot()
	retractions := make([]alertRetractionResultSnapshot, len(state.Retractions))
	for index, retraction := range state.Retractions {
		retractions[index] = alertRetractionResultSnapshot{
			ID: uuid.UUID(retraction.ID.Bytes()), TenantID: uuid.UUID(retraction.TenantID.Bytes()),
			RelationshipID: uuid.UUID(retraction.RelationshipID.Bytes()), Sequence: retraction.Sequence,
			ActorID: uuid.UUID(retraction.ActorID.Bytes()), Reason: retraction.Reason, OccurredAt: retraction.OccurredAt,
		}
	}
	snapshot := alertRelationResultSnapshot{
		ID: uuid.UUID(state.ID.Bytes()), TenantID: uuid.UUID(state.TenantID.Bytes()), AlertID: uuid.UUID(state.AlertID.Bytes()),
		Source: alertReferenceSnapshot(state.Source), Target: alertReferenceSnapshot(state.Target),
		RelationshipType: state.RelationshipType, Metadata: state.Metadata,
		CreatedBy: uuid.UUID(state.CreatedBy.Bytes()), CreatedAt: state.CreatedAt,
		Version: state.Version, Retractions: retractions,
	}
	return json.Marshal(alertInvestigationResultSnapshot{Kind: alertInvestigationSnapshotKindRelationship, Relationship: &snapshot})
}

func decodeAlertRelationshipResult(document []byte) (kernel.AlertRelationship, error) {
	var envelope alertInvestigationResultSnapshot
	if err := decodeAlertInvestigationSnapshot(document, &envelope); err != nil ||
		envelope.Kind != alertInvestigationSnapshotKindRelationship || envelope.Relationship == nil ||
		envelope.Evidence != nil || envelope.Task != nil {
		return kernel.AlertRelationship{}, unexpectedDFIRProjection("invalid Alert relationship replay snapshot")
	}
	value := envelope.Relationship
	id, err := parseDFIREntityID(value.ID)
	if err != nil {
		return kernel.AlertRelationship{}, err
	}
	tenant, err := parseDFIREntityID(value.TenantID)
	if err != nil {
		return kernel.AlertRelationship{}, err
	}
	alert, err := parseDFIREntityID(value.AlertID)
	if err != nil {
		return kernel.AlertRelationship{}, err
	}
	createdBy, err := parseDFIREntityID(value.CreatedBy)
	if err != nil {
		return kernel.AlertRelationship{}, err
	}
	source, err := restoreAlertReferenceSnapshot(tenant, value.Source)
	if err != nil {
		return kernel.AlertRelationship{}, err
	}
	target, err := restoreAlertReferenceSnapshot(tenant, value.Target)
	if err != nil {
		return kernel.AlertRelationship{}, err
	}
	retractions := make([]kernel.AlertRelationshipRetractionState, len(value.Retractions))
	for index, retraction := range value.Retractions {
		retractionID, parseErr := parseDFIREntityID(retraction.ID)
		if parseErr != nil {
			return kernel.AlertRelationship{}, parseErr
		}
		retractionTenant, parseErr := parseDFIREntityID(retraction.TenantID)
		if parseErr != nil {
			return kernel.AlertRelationship{}, parseErr
		}
		relationID, parseErr := parseDFIREntityID(retraction.RelationshipID)
		if parseErr != nil {
			return kernel.AlertRelationship{}, parseErr
		}
		actor, parseErr := parseDFIREntityID(retraction.ActorID)
		if parseErr != nil {
			return kernel.AlertRelationship{}, parseErr
		}
		retractions[index] = kernel.AlertRelationshipRetractionState{
			ID: retractionID, TenantID: retractionTenant, RelationshipID: relationID,
			Sequence: retraction.Sequence, ActorID: actor, Reason: retraction.Reason,
			OccurredAt: canonicalAlertDatabaseTime(retraction.OccurredAt),
		}
	}
	result, err := kernel.NewAlertRelationship(kernel.AlertRelationshipState{
		ID: id, TenantID: tenant, AlertID: alert, Source: source, Target: target,
		RelationshipType: value.RelationshipType, Metadata: canonicalJSONObject(value.Metadata),
		CreatedBy: createdBy, CreatedAt: canonicalAlertDatabaseTime(value.CreatedAt),
		Version: value.Version, Retractions: retractions,
	})
	if err != nil {
		return kernel.AlertRelationship{}, unexpectedDFIRProjection("non-canonical Alert relationship replay snapshot")
	}
	return result, nil
}

func decodeAlertInvestigationSnapshot(document []byte, target any) error {
	if len(document) == 0 || len(document) > 16*1024*1024 {
		return errors.New("Alert investigation replay snapshot size is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("Alert investigation replay snapshot has trailing data")
	}
	return nil
}

func alertReferenceSnapshot(value kernel.EntityReference) alertReferenceResultSnapshot {
	result := alertReferenceResultSnapshot{Kind: value.Kind(), ExternalType: value.ExternalType(), ExternalID: value.ExternalID()}
	if value.Kind() != kernel.EntityExternal {
		id := uuid.UUID(value.ID().Bytes())
		result.ID = &id
	}
	return result
}

func restoreAlertReferenceSnapshot(tenant kernel.EntityID, value alertReferenceResultSnapshot) (kernel.EntityReference, error) {
	if value.Kind == kernel.EntityExternal {
		if value.ID != nil {
			return kernel.EntityReference{}, unexpectedDFIRProjection("invalid external Alert reference snapshot")
		}
		result, err := kernel.NewExternalEntityReference(tenant, value.ExternalType, value.ExternalID)
		if err != nil {
			return kernel.EntityReference{}, unexpectedDFIRProjection("non-canonical external Alert reference snapshot")
		}
		return result, nil
	}
	if value.ID == nil || value.ExternalType != "" || value.ExternalID != "" {
		return kernel.EntityReference{}, unexpectedDFIRProjection("invalid local Alert reference snapshot")
	}
	id, err := parseDFIREntityID(*value.ID)
	if err != nil {
		return kernel.EntityReference{}, err
	}
	result, err := kernel.NewEntityReference(tenant, value.Kind, id)
	if err != nil {
		return kernel.EntityReference{}, unexpectedDFIRProjection("non-canonical local Alert reference snapshot")
	}
	return result, nil
}

func optionalKernelUUIDPointer(value *kernel.EntityID) *uuid.UUID {
	if value == nil {
		return nil
	}
	converted := uuid.UUID(value.Bytes())
	return &converted
}

func canonicalAlertDatabaseTime(value time.Time) time.Time {
	return value.UTC().Truncate(time.Microsecond)
}

func canonicalOptionalAlertDatabaseTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	canonical := canonicalAlertDatabaseTime(*value)
	return &canonical
}

func loadDFIRAlertEvidence(ctx context.Context, tx databaseTransaction, tenantID, alertID, id uuid.UUID) (kernel.AlertEvidence, error) {
	var storedID, storedTenant, storedAlert, storageID, collectedBy uuid.UUID
	var title, description, evidenceType, classification, detectedMIME, source string
	var contentDigest, anchorHash, custodyHead []byte
	var sizeBytes int64
	var collectedAt time.Time
	var initialRetention, retention *time.Time
	var initialLegalHold, legalHold bool
	var initialScanState, scanState string
	var sealed, destroyed bool
	var custodyCount, version int64
	err := tx.QueryRow(ctx, `
		SELECT id, tenant_id, alert_id, storage_object_id, title, description,
		       evidence_type, classification::text, content_sha256, size_bytes,
		       detected_mime, collected_at, collected_by_membership_id, source,
		       initial_retention_until, retention_until, initial_legal_hold,
		       legal_hold, initial_scan_state::text, scan_state::text, sealed,
		       destroyed, anchor_hash, custody_head_hash, custody_count, version
		FROM public.dfir_evidence
		WHERE tenant_id = $1 AND alert_id = $2 AND case_id IS NULL AND id = $3`, tenantID, alertID, id).Scan(
		&storedID, &storedTenant, &storedAlert, &storageID, &title, &description,
		&evidenceType, &classification, &contentDigest, &sizeBytes, &detectedMIME,
		&collectedAt, &collectedBy, &source, &initialRetention, &retention,
		&initialLegalHold, &legalHold, &initialScanState, &scanState, &sealed,
		&destroyed, &anchorHash, &custodyHead, &custodyCount, &version,
	)
	if err != nil {
		return kernel.AlertEvidence{}, err
	}
	if len(contentDigest) != 32 || len(anchorHash) != 32 || len(custodyHead) != 32 ||
		version < 1 || version > int64(kernel.MaximumCustodyEvents) || custodyCount != version ||
		custodyCount > int64(kernel.MaximumCustodyEvents) {
		return kernel.AlertEvidence{}, unexpectedDFIRProjection("invalid Alert evidence hash or version")
	}
	identifier, err := parseDFIREntityID(storedID)
	if err != nil {
		return kernel.AlertEvidence{}, err
	}
	tenant, err := parseDFIREntityID(storedTenant)
	if err != nil {
		return kernel.AlertEvidence{}, err
	}
	alert, err := parseDFIREntityID(storedAlert)
	if err != nil {
		return kernel.AlertEvidence{}, err
	}
	storage, err := parseDFIREntityID(storageID)
	if err != nil {
		return kernel.AlertEvidence{}, err
	}
	collector, err := parseDFIREntityID(collectedBy)
	if err != nil {
		return kernel.AlertEvidence{}, err
	}
	custody, err := loadDFIRCustody(ctx, tx, tenantID, storedID, version)
	if err != nil {
		return kernel.AlertEvidence{}, err
	}
	result, err := kernel.RestoreAlertEvidence(kernel.AlertEvidenceState{
		ID: identifier, TenantID: tenant, AlertID: alert, StorageObjectID: storage,
		Title: title, Description: description, EvidenceType: evidenceType,
		Classification: kernel.EvidenceClassification(classification), ContentSHA256: hex.EncodeToString(contentDigest),
		SizeBytes: sizeBytes, DetectedMIME: detectedMIME, CollectedAt: canonicalAlertDatabaseTime(collectedAt),
		CollectedBy: collector, Source: source, RetentionUntil: canonicalOptionalAlertDatabaseTime(retention),
		LegalHold: legalHold, ScanState: kernel.ScanState(scanState),
		InitialRetentionUntil: canonicalOptionalAlertDatabaseTime(initialRetention), InitialLegalHold: initialLegalHold,
		InitialScanState: kernel.ScanState(initialScanState), Sealed: sealed, Destroyed: destroyed,
		Version: uint64(version), CustodyEvents: custody,
	})
	if err != nil {
		return kernel.AlertEvidence{}, unexpectedDFIRProjection("invalid Alert evidence custody chain")
	}
	events := result.CustodyEvents()
	if len(events) == 0 {
		return kernel.AlertEvidence{}, unexpectedDFIRProjection("empty Alert evidence custody chain")
	}
	first, last := events[0].PreviousHash(), events[len(events)-1].EventHash()
	if !bytes.Equal(first[:], anchorHash) || !bytes.Equal(last[:], custodyHead) {
		return kernel.AlertEvidence{}, unexpectedDFIRProjection("Alert evidence custody head mismatch")
	}
	return result, nil
}

func loadDFIRAlertTask(ctx context.Context, tx databaseTransaction, tenantID, alertID, id uuid.UUID) (kernel.AlertTask, error) {
	var storedID, storedTenant, storedAlert uuid.UUID
	var title, description, status, priority string
	var assigneeID, teamID, teamEpochID *uuid.UUID
	var dueAt, completedAt *time.Time
	var checklistJSON, completionData []byte
	var completedBy, slaID *uuid.UUID
	var commentIDs []uuid.UUID
	var createdAt, updatedAt time.Time
	var version int64
	err := tx.QueryRow(ctx, `
		SELECT id, tenant_id, alert_id, title, description, status::text, priority::text,
		       assignee_user_id, operator_team_id, operator_team_epoch_id, due_at,
		       checklist, completed_at, completed_by_user_id, completion_data,
		       comment_ids, sla_instance_id, created_at, updated_at, version
		FROM public.dfir_tasks
		WHERE tenant_id = $1 AND alert_id = $2 AND case_id IS NULL AND id = $3`, tenantID, alertID, id).Scan(
		&storedID, &storedTenant, &storedAlert, &title, &description, &status, &priority,
		&assigneeID, &teamID, &teamEpochID, &dueAt, &checklistJSON, &completedAt,
		&completedBy, &completionData, &commentIDs, &slaID, &createdAt, &updatedAt, &version,
	)
	if err != nil {
		return kernel.AlertTask{}, err
	}
	if teamID == nil != (teamEpochID == nil) || assigneeID != nil && teamID == nil ||
		version < 1 || version > int64(kernel.MaximumAlertResourceVersion) {
		return kernel.AlertTask{}, unexpectedDFIRProjection("invalid Alert task assignment or version")
	}
	identifier, err := parseDFIREntityID(storedID)
	if err != nil {
		return kernel.AlertTask{}, err
	}
	tenant, err := parseDFIREntityID(storedTenant)
	if err != nil {
		return kernel.AlertTask{}, err
	}
	alert, err := parseDFIREntityID(storedAlert)
	if err != nil {
		return kernel.AlertTask{}, err
	}
	assignee, err := parseOptionalDFIREntityID(assigneeID)
	if err != nil {
		return kernel.AlertTask{}, err
	}
	team, err := parseOptionalDFIREntityID(teamID)
	if err != nil {
		return kernel.AlertTask{}, err
	}
	completer, err := parseOptionalDFIREntityID(completedBy)
	if err != nil {
		return kernel.AlertTask{}, err
	}
	sla, err := parseOptionalDFIREntityID(slaID)
	if err != nil {
		return kernel.AlertTask{}, err
	}
	var rows []dfirChecklistJSON
	if err = decodeDFIRJSON(checklistJSON, &rows); err != nil || len(rows) > 100 {
		return kernel.AlertTask{}, unexpectedDFIRProjection("invalid Alert task checklist")
	}
	checklist := make([]kernel.ChecklistItem, len(rows))
	for index, row := range rows {
		itemUUID, parseErr := uuid.Parse(row.ID)
		if parseErr != nil {
			return kernel.AlertTask{}, unexpectedDFIRProjection("invalid Alert checklist identifier")
		}
		itemID, parseErr := parseDFIREntityID(itemUUID)
		if parseErr != nil {
			return kernel.AlertTask{}, parseErr
		}
		var completedAtValue *time.Time
		if row.CompletedAt != nil {
			parsed, timeErr := time.Parse(time.RFC3339Nano, *row.CompletedAt)
			if timeErr != nil {
				return kernel.AlertTask{}, unexpectedDFIRProjection("invalid Alert checklist time")
			}
			completedAtValue = canonicalOptionalAlertDatabaseTime(&parsed)
		}
		var completedByValue *kernel.EntityID
		if row.CompletedBy != nil {
			parsed, idErr := uuid.Parse(*row.CompletedBy)
			if idErr != nil {
				return kernel.AlertTask{}, unexpectedDFIRProjection("invalid Alert checklist actor")
			}
			completedByValue, idErr = parseOptionalDFIREntityID(&parsed)
			if idErr != nil {
				return kernel.AlertTask{}, idErr
			}
		}
		checklist[index], err = kernel.NewChecklistItem(kernel.ChecklistItemInput{
			ID: itemID, Title: row.Title, Completed: row.Completed,
			CompletedAt: completedAtValue, CompletedBy: completedByValue,
		})
		if err != nil {
			return kernel.AlertTask{}, unexpectedDFIRProjection("non-canonical Alert checklist item")
		}
	}
	comments := make([]kernel.EntityID, len(commentIDs))
	for index, value := range commentIDs {
		comments[index], err = parseDFIREntityID(value)
		if err != nil {
			return kernel.AlertTask{}, err
		}
	}
	result, err := kernel.NewAlertTask(kernel.AlertTaskState{
		ID: identifier, TenantID: tenant, AlertID: alert, Title: title, Description: description,
		Status: kernel.TaskStatus(status), Priority: kernel.TaskPriority(priority), AssigneeID: assignee,
		OperatorTeamID: team, DueAt: canonicalOptionalAlertDatabaseTime(dueAt), Checklist: checklist,
		CompletedAt: canonicalOptionalAlertDatabaseTime(completedAt), CompletedBy: completer,
		CompletionData: canonicalJSONObject(completionData), CommentIDs: comments, SLAInstanceID: sla,
		CreatedAt: canonicalAlertDatabaseTime(createdAt), UpdatedAt: canonicalAlertDatabaseTime(updatedAt), Version: uint64(version),
	})
	if err != nil {
		return kernel.AlertTask{}, unexpectedDFIRProjection("non-canonical Alert task")
	}
	return result, nil
}

func loadDFIRAlertRelationship(ctx context.Context, tx databaseTransaction, tenantID, alertID, id uuid.UUID) (kernel.AlertRelationship, error) {
	var storedID, storedTenant, storedAlert, createdBy uuid.UUID
	var sourceKind, targetKind, relationshipType string
	var sourceID, targetID *uuid.UUID
	var sourceExternalType, sourceExternalID, targetExternalType, targetExternalID *string
	var metadata []byte
	var createdAt time.Time
	var version int64
	err := tx.QueryRow(ctx, `
		SELECT id, tenant_id, alert_id, source_kind::text, source_id, source_external_type,
		       source_external_id, target_kind::text, target_id, target_external_type,
		       target_external_id, relationship_type, metadata, created_by_membership_id, created_at, version
		FROM public.dfir_relationships
		WHERE tenant_id = $1 AND alert_id = $2 AND case_id IS NULL AND id = $3`, tenantID, alertID, id).Scan(
		&storedID, &storedTenant, &storedAlert, &sourceKind, &sourceID, &sourceExternalType,
		&sourceExternalID, &targetKind, &targetID, &targetExternalType, &targetExternalID,
		&relationshipType, &metadata, &createdBy, &createdAt, &version,
	)
	if err != nil {
		return kernel.AlertRelationship{}, err
	}
	if version < 1 || version > int64(kernel.MaximumAlertResourceVersion) {
		return kernel.AlertRelationship{}, unexpectedDFIRProjection("invalid Alert relationship version")
	}
	identifier, err := parseDFIREntityID(storedID)
	if err != nil {
		return kernel.AlertRelationship{}, err
	}
	tenant, err := parseDFIREntityID(storedTenant)
	if err != nil {
		return kernel.AlertRelationship{}, err
	}
	alert, err := parseDFIREntityID(storedAlert)
	if err != nil {
		return kernel.AlertRelationship{}, err
	}
	creator, err := parseDFIREntityID(createdBy)
	if err != nil {
		return kernel.AlertRelationship{}, err
	}
	source, err := restoreDFIRReference(tenant, sourceKind, sourceID, sourceExternalType, sourceExternalID)
	if err != nil {
		return kernel.AlertRelationship{}, err
	}
	target, err := restoreDFIRReference(tenant, targetKind, targetID, targetExternalType, targetExternalID)
	if err != nil {
		return kernel.AlertRelationship{}, err
	}
	rows, err := tx.Query(ctx, `
		SELECT id, tenant_id, relationship_id, retracted_by_membership_id, reason, prior_version, result_version, retracted_at
		FROM public.dfir_relationship_retractions
		WHERE tenant_id = $1 AND relationship_id = $2 AND alert_id = $3 AND case_id IS NULL
		ORDER BY result_version LIMIT 2`, tenantID, id, alertID)
	if err != nil {
		return kernel.AlertRelationship{}, err
	}
	defer rows.Close()
	retractions := make([]kernel.AlertRelationshipRetractionState, 0, 1)
	for rows.Next() {
		var retractionID, retractionTenant, relationshipID, actor uuid.UUID
		var reason string
		var priorVersion, resultVersion int64
		var occurredAt time.Time
		if scanErr := rows.Scan(&retractionID, &retractionTenant, &relationshipID, &actor, &reason, &priorVersion, &resultVersion, &occurredAt); scanErr != nil {
			return kernel.AlertRelationship{}, scanErr
		}
		if priorVersion != 1 || resultVersion != 2 {
			return kernel.AlertRelationship{}, unexpectedDFIRProjection("invalid Alert relationship retraction version")
		}
		retractionEntity, parseErr := parseDFIREntityID(retractionID)
		if parseErr != nil {
			return kernel.AlertRelationship{}, parseErr
		}
		retractionTenantEntity, parseErr := parseDFIREntityID(retractionTenant)
		if parseErr != nil {
			return kernel.AlertRelationship{}, parseErr
		}
		relationEntity, parseErr := parseDFIREntityID(relationshipID)
		if parseErr != nil {
			return kernel.AlertRelationship{}, parseErr
		}
		actorEntity, parseErr := parseDFIREntityID(actor)
		if parseErr != nil {
			return kernel.AlertRelationship{}, parseErr
		}
		retractions = append(retractions, kernel.AlertRelationshipRetractionState{
			ID: retractionEntity, TenantID: retractionTenantEntity, RelationshipID: relationEntity,
			Sequence: 1, ActorID: actorEntity, Reason: reason, OccurredAt: canonicalAlertDatabaseTime(occurredAt),
		})
	}
	if rows.Err() != nil {
		return kernel.AlertRelationship{}, rows.Err()
	}
	if version != int64(1+len(retractions)) {
		return kernel.AlertRelationship{}, unexpectedDFIRProjection("Alert relationship history cardinality mismatch")
	}
	result, err := kernel.NewAlertRelationship(kernel.AlertRelationshipState{
		ID: identifier, TenantID: tenant, AlertID: alert, Source: source, Target: target,
		RelationshipType: relationshipType, Metadata: canonicalJSONObject(metadata), CreatedBy: creator,
		CreatedAt: canonicalAlertDatabaseTime(createdAt), Version: uint64(version), Retractions: retractions,
	})
	if err != nil {
		return kernel.AlertRelationship{}, unexpectedDFIRProjection("non-canonical Alert relationship")
	}
	return result, nil
}
