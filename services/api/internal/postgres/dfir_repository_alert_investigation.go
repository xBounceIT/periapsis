package postgres

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	kernel "github.com/periapsis-im/periapsis/modules/dfir"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	application "github.com/periapsis-im/periapsis/services/api/internal/dfir"
)

var _ application.AlertInvestigationRepository = (*DFIRRepository)(nil)

var alertInvestigationWorkspaceCapabilities = [...]application.Capability{
	application.CapabilityEvidenceRead,
	application.CapabilityTaskRead,
	application.CapabilityRelationshipRead,
}

type alertInvestigationOperation struct {
	capability   application.Capability
	activityType string
	auditAction  string
	outboxType   string
	resourceType string
}

var alertInvestigationOperations = map[string]alertInvestigationOperation{
	"dfir.alert.evidence.create": {
		application.CapabilityEvidenceManage, "alert.evidence.added", "dfir.alert.evidence.create",
		"alert.evidence.added.v1", "dfir_evidence",
	},
	"dfir.alert.evidence.custody.append": {
		application.CapabilityEvidenceManage, "alert.evidence.custody_appended",
		"dfir.alert.evidence.custody.append", "alert.evidence.custody_appended.v1", "dfir_evidence",
	},
	"dfir.alert.task.create": {
		application.CapabilityTaskManage, "alert.task.created", "dfir.alert.task.create",
		"alert.task.created.v1", "dfir_task",
	},
	"dfir.alert.task.transition": {
		application.CapabilityTaskManage, "alert.task.transitioned", "dfir.alert.task.transition",
		"alert.task.transitioned.v1", "dfir_task",
	},
	"dfir.alert.task.replace_details": {
		application.CapabilityTaskManage, "alert.task.details_replaced", "dfir.alert.task.replace_details",
		"alert.task.details_replaced.v1", "dfir_task",
	},
	"dfir.alert.task.assign": {
		application.CapabilityTaskManage, "alert.task.assigned", "dfir.alert.task.assign",
		"alert.task.assigned.v1", "dfir_task",
	},
	"dfir.alert.task.reschedule": {
		application.CapabilityTaskManage, "alert.task.rescheduled", "dfir.alert.task.reschedule",
		"alert.task.rescheduled.v1", "dfir_task",
	},
	"dfir.alert.task.checklist.replace": {
		application.CapabilityTaskManage, "alert.task.checklist_replaced", "dfir.alert.task.checklist.replace",
		"alert.task.checklist_replaced.v1", "dfir_task",
	},
	"dfir.alert.task.comments.replace": {
		application.CapabilityTaskManage, "alert.task.comments_replaced", "dfir.alert.task.comments.replace",
		"alert.task.comments_replaced.v1", "dfir_task",
	},
	"dfir.alert.relationship.create": {
		application.CapabilityRelationshipManage, "alert.relationship.created", "dfir.alert.relationship.create",
		"alert.relationship.created.v1", "dfir_relationship",
	},
	"dfir.alert.relationship.retract": {
		application.CapabilityRelationshipManage, "alert.relationship.retracted", "dfir.alert.relationship.retract",
		"alert.relationship.retracted.v1", "dfir_relationship",
	},
}

func (repository *DFIRRepository) LoadAlertInvestigationWorkspace(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	alertID kernel.EntityID,
	claimed application.WorkspaceAccess,
) (application.AlertInvestigationWorkspace, error) {
	if repository == nil || repository.begin == nil || actor.Kind != application.PrincipalHuman ||
		len(claimed) != len(alertInvestigationWorkspaceCapabilities) || alertID == (kernel.EntityID{}) {
		return application.AlertInvestigationWorkspace{}, application.ErrRepositoryForbidden
	}
	result, err := withinTransactionWithOptions(
		ctx, repository.begin, phase4ReadOptions(),
		func(tx databaseTransaction) (application.AlertInvestigationWorkspace, error) {
			authority, authorityErr := phase4Authority(ctx, tx, dfirAuthorizationActor(actor), tenantID)
			if authorityErr != nil {
				return application.AlertInvestigationWorkspace{}, authorityErr
			}
			if err := validateDFIRAuthority(authority, actor); err != nil {
				return application.AlertInvestigationWorkspace{}, err
			}
			alertUUID := uuid.UUID(alertID.Bytes())
			for _, capability := range alertInvestigationWorkspaceCapabilities {
				access, accessErr := dfirAccessForAlert(ctx, tx, authority, actor, capability, alertUUID)
				provided, exists := claimed[capability]
				if accessErr != nil || !exists || !sameDFIRAccess(access, provided) {
					if accessErr != nil {
						return application.AlertInvestigationWorkspace{}, accessErr
					}
					return application.AlertInvestigationWorkspace{}, authorization.ErrForbidden
				}
			}
			return loadAlertInvestigationWorkspace(ctx, tx, tenantID, alertUUID)
		},
	)
	return result, mapDFIRDatabaseError(err)
}

func loadAlertInvestigationWorkspace(
	ctx context.Context,
	tx databaseTransaction,
	tenantID uuid.UUID,
	alertID uuid.UUID,
) (application.AlertInvestigationWorkspace, error) {
	var result application.AlertInvestigationWorkspace
	evidenceIDs, err := queryBoundedDFIRIDs(ctx, tx, `
		SELECT id FROM public.dfir_evidence
		WHERE tenant_id = $1 AND alert_id = $2 AND case_id IS NULL
		ORDER BY collected_at DESC, id LIMIT $3`, tenantID, alertID, 500)
	if err != nil {
		return result, err
	}
	result.Evidence = make([]kernel.AlertEvidence, len(evidenceIDs))
	for index, id := range evidenceIDs {
		result.Evidence[index], err = loadDFIRAlertEvidence(ctx, tx, tenantID, alertID, id)
		if err != nil {
			return application.AlertInvestigationWorkspace{}, err
		}
	}
	taskIDs, err := queryBoundedDFIRIDs(ctx, tx, `
		SELECT id FROM public.dfir_tasks
		WHERE tenant_id = $1 AND alert_id = $2 AND case_id IS NULL
		ORDER BY updated_at DESC, id LIMIT $3`, tenantID, alertID, 500)
	if err != nil {
		return application.AlertInvestigationWorkspace{}, err
	}
	result.Tasks = make([]kernel.AlertTask, len(taskIDs))
	for index, id := range taskIDs {
		result.Tasks[index], err = loadDFIRAlertTask(ctx, tx, tenantID, alertID, id)
		if err != nil {
			return application.AlertInvestigationWorkspace{}, err
		}
	}
	relationshipIDs, err := queryBoundedDFIRIDs(ctx, tx, `
		SELECT id FROM public.dfir_relationships
		WHERE tenant_id = $1 AND alert_id = $2 AND case_id IS NULL
		ORDER BY created_at DESC, id LIMIT $3`, tenantID, alertID, 1000)
	if err != nil {
		return application.AlertInvestigationWorkspace{}, err
	}
	result.Relationships = make([]kernel.AlertRelationship, len(relationshipIDs))
	for index, id := range relationshipIDs {
		result.Relationships[index], err = loadDFIRAlertRelationship(ctx, tx, tenantID, alertID, id)
		if err != nil {
			return application.AlertInvestigationWorkspace{}, err
		}
	}
	return result, nil
}

type alertInvestigationReservation struct {
	commandID uuid.UUID
	snapshot  []byte
	replayed  bool
}

func reserveAlertInvestigationCommand(
	ctx context.Context,
	tx databaseTransaction,
	newCommandID uuid.UUID,
	alertID uuid.UUID,
	contract application.AlertMutationContract,
	resourceID uuid.UUID,
	resultVersion int64,
) (alertInvestigationReservation, error) {
	var result alertInvestigationReservation
	var returnedResourceID uuid.UUID
	var returnedVersion int64
	err := tx.QueryRow(ctx, `
		SELECT command_id, result_resource_id, result_version, result_snapshot, replayed
		FROM app.reserve_alert_investigation_command_v1($1, $2, $3, $4, $5, $6, $7)`,
		newCommandID, alertID, contract.Command.Operation, resourceID, resultVersion,
		contract.Command.KeyDigest[:], contract.Command.RequestDigest[:],
	).Scan(&result.commandID, &returnedResourceID, &returnedVersion, &result.snapshot, &result.replayed)
	if err != nil {
		return alertInvestigationReservation{}, err
	}
	if returnedResourceID != resourceID || returnedVersion != resultVersion ||
		result.commandID == uuid.Nil || result.replayed != (len(result.snapshot) != 0) {
		return alertInvestigationReservation{}, unexpectedDFIRProjection("Alert investigation command reservation mismatch")
	}
	return result, nil
}

func storeAlertInvestigationResult(
	ctx context.Context,
	tx databaseTransaction,
	commandID uuid.UUID,
	document []byte,
) error {
	if len(document) == 0 || len(document) > 16*1024*1024 {
		return application.ErrRepositoryConflict
	}
	var stored bool
	if err := tx.QueryRow(ctx, `SELECT app.store_alert_investigation_command_result_v1($1, $2::jsonb)`,
		commandID, document).Scan(&stored); err != nil {
		return err
	}
	if !stored {
		return unexpectedDFIRProjection("Alert investigation result was not stored")
	}
	return nil
}

func validateAlertInvestigationContract(
	contract application.AlertMutationContract,
	operation string,
	alertID kernel.EntityID,
) (alertInvestigationOperation, error) {
	expected, exists := alertInvestigationOperations[operation]
	if !exists || contract.AlertID != alertID || contract.CaseID != (kernel.EntityID{}) ||
		!validDFIRCommand(contract.Command, operation) || contract.Capability != expected.capability ||
		contract.ActivityType != expected.activityType || contract.AuditAction != expected.auditAction ||
		contract.OutboxEventType != expected.outboxType || contract.Access.Audience != kernel.AudienceOperator ||
		contract.Audit.AuthenticationMethod != contract.Actor.AuthenticationMethod ||
		!validAlertInvestigationAuditReason(contract.AuditReason) {
		return alertInvestigationOperation{}, application.ErrRepositoryConflict
	}
	return expected, nil
}

func validAlertInvestigationAuditReason(value string) bool {
	if value == "" || len(value) > 2000 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || character == '\u2028' || character == '\u2029' ||
			character == '\u200e' || character == '\u200f' ||
			character >= '\u202a' && character <= '\u202e' ||
			character >= '\u2066' && character <= '\u2069' {
			return false
		}
	}
	return true
}

func authorizeAlertInvestigationContract(
	ctx context.Context,
	tx databaseTransaction,
	contract application.AlertMutationContract,
	tenantID uuid.UUID,
	alertID uuid.UUID,
) error {
	access, err := authorizeDFIRAlertWrite(ctx, tx, contract.Actor, tenantID, contract.Capability, alertID)
	if err != nil {
		return err
	}
	if !sameDFIRAccess(access, contract.Access) {
		return authorization.ErrForbidden
	}
	return nil
}

func appendAlertInvestigationEffects(
	ctx context.Context,
	tx databaseTransaction,
	contract application.AlertMutationContract,
	expected alertInvestigationOperation,
	alertID uuid.UUID,
	resourceID uuid.UUID,
	version int64,
	ids []uuid.UUID,
	before any,
	after any,
	metadata any,
) error {
	if len(ids) != 4 {
		return application.ErrRepositoryConflict
	}
	beforeJSON, err := phase4JSON(before)
	if err != nil {
		return err
	}
	afterJSON, err := phase4JSON(after)
	if err != nil {
		return err
	}
	metadataJSON, err := phase4JSON(metadata)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `SELECT app.append_alert_investigation_effects_v1(
		$1, $2, $3, $4, $5, $6, $7, $8, $9,
		$10, $11, $12, $13::jsonb, $14::jsonb, $15::jsonb,
		$16, $17, $18, $19, $20::inet, $21, $22
	)`, alertID, contract.Command.Operation, expected.activityType, expected.auditAction,
		contract.AuditReason, expected.outboxType, expected.resourceType, resourceID, version,
		contract.Command.KeyDigest[:], contract.Command.RequestDigest[:], ids[1],
		beforeJSON, afterJSON, metadataJSON, ids[2], ids[3], contract.Audit.RequestID,
		contract.Audit.CorrelationID, contract.Audit.IPAddress,
		contract.Audit.UserAgent, contract.Actor.AuthenticationMethod)
	return err
}

func (repository *DFIRRepository) CommitAlertEvidence(
	ctx context.Context,
	write application.AlertEvidenceCreateWrite,
) (application.MutationResult[kernel.AlertEvidence], error) {
	expected, contractErr := validateAlertInvestigationContract(
		write.Contract, "dfir.alert.evidence.create", write.Contract.AlertID,
	)
	if !validAlertInvestigationRepository(repository) || contractErr != nil || write.Build == nil || write.EvidenceID == (kernel.EntityID{}) ||
		write.StorageObjectID == (kernel.EntityID{}) {
		return application.MutationResult[kernel.AlertEvidence]{}, application.ErrRepositoryConflict
	}
	tenantID := write.Contract.Actor.TenantID
	alertID := uuid.UUID(write.Contract.AlertID.Bytes())
	storageID := uuid.UUID(write.StorageObjectID.Bytes())
	result, err := withinTransactionWithOptions(ctx, repository.begin, phase4WriteOptions(),
		func(tx databaseTransaction) (application.MutationResult[kernel.AlertEvidence], error) {
			if err := authorizeAlertInvestigationContract(ctx, tx, write.Contract, tenantID, alertID); err != nil {
				return application.MutationResult[kernel.AlertEvidence]{}, err
			}
			ids, err := phase4NewIDs(repository.newID, 4)
			if err != nil {
				return application.MutationResult[kernel.AlertEvidence]{}, err
			}
			resourceID := uuid.UUID(write.EvidenceID.Bytes())
			reservation, err := reserveAlertInvestigationCommand(ctx, tx, ids[0], alertID, write.Contract, resourceID, 1)
			if err != nil {
				return application.MutationResult[kernel.AlertEvidence]{}, err
			}
			if reservation.replayed {
				replayed, decodeErr := decodeAlertEvidenceResult(reservation.snapshot)
				if decodeErr != nil || uuid.UUID(replayed.ID().Bytes()) != resourceID ||
					replayed.TenantID().String() != tenantID.String() || replayed.AlertID() != write.Contract.AlertID ||
					replayed.Version() != 1 {
					if decodeErr != nil {
						return application.MutationResult[kernel.AlertEvidence]{}, decodeErr
					}
					return application.MutationResult[kernel.AlertEvidence]{}, unexpectedDFIRProjection("Alert evidence replay coordinate mismatch")
				}
				return application.MutationResult[kernel.AlertEvidence]{Resource: replayed, Replayed: true}, nil
			}
			var attachedStorage uuid.UUID
			// The security-definer creation function locks and validates storage in
			// this serializable transaction; the API role only reads these tables.
			if err := tx.QueryRow(ctx, `
				SELECT storage.id
				FROM public.dfir_storage_objects AS storage
				JOIN public.dfir_attachments AS attachment
				  ON attachment.tenant_id = storage.tenant_id AND attachment.storage_object_id = storage.id
				WHERE storage.tenant_id = $1 AND storage.id = $2
				  AND attachment.subject_kind = 'alert' AND attachment.alert_id = $3
				  AND attachment.case_id IS NULL AND attachment.ioc_id IS NULL AND attachment.asset_id IS NULL
				  AND attachment.evidence_id IS NULL AND attachment.task_id IS NULL`, tenantID, storageID, alertID).Scan(&attachedStorage); err != nil {
				return application.MutationResult[kernel.AlertEvidence]{}, err
			}
			storage, err := loadDFIRStorageObject(ctx, tx, tenantID, attachedStorage)
			if err != nil {
				return application.MutationResult[kernel.AlertEvidence]{}, err
			}
			evidence, err := write.Build(storage)
			if err != nil {
				return application.MutationResult[kernel.AlertEvidence]{}, err
			}
			if uuid.UUID(evidence.ID().Bytes()) != resourceID || evidence.TenantID().String() != tenantID.String() ||
				evidence.AlertID() != write.Contract.AlertID || evidence.StorageObjectID() != write.StorageObjectID ||
				evidence.Version() != 1 || len(evidence.CustodyEvents()) != 1 || !evidence.VerifyCustodyChain() ||
				evidence.Classification() != storage.Classification() || evidence.ContentSHA256() != storage.ContentSHA256() ||
				evidence.SizeBytes() != storage.SizeBytes() || evidence.DetectedMIME() != storage.DetectedMIME() ||
				evidence.ScanState() != storage.State() || evidence.LegalHold() != storage.LegalHold() ||
				!sameOptionalTime(evidence.RetentionUntil(), storage.RetentionUntil()) {
				return application.MutationResult[kernel.AlertEvidence]{}, application.ErrRepositoryConflict
			}
			if err := insertAlertEvidence(ctx, tx, reservation.commandID, evidence); err != nil {
				return application.MutationResult[kernel.AlertEvidence]{}, err
			}
			stored, err := loadDFIRAlertEvidence(ctx, tx, tenantID, alertID, resourceID)
			if err != nil || !sameAlertEvidence(stored, evidence) {
				if err != nil {
					return application.MutationResult[kernel.AlertEvidence]{}, err
				}
				return application.MutationResult[kernel.AlertEvidence]{}, unexpectedDFIRProjection("divergent Alert evidence after collect")
			}
			if err := appendAlertInvestigationEffects(ctx, tx, write.Contract, expected, alertID, resourceID, 1, ids,
				map[string]any{}, alertEvidenceJournal(stored), map[string]any{"custodyAction": "collected"}); err != nil {
				return application.MutationResult[kernel.AlertEvidence]{}, err
			}
			document, err := encodeAlertEvidenceResult(stored)
			if err != nil {
				return application.MutationResult[kernel.AlertEvidence]{}, err
			}
			if err = storeAlertInvestigationResult(ctx, tx, reservation.commandID, document); err != nil {
				return application.MutationResult[kernel.AlertEvidence]{}, err
			}
			return application.MutationResult[kernel.AlertEvidence]{Resource: stored}, nil
		})
	return result, mapDFIRDatabaseError(err)
}

func insertAlertEvidence(ctx context.Context, tx databaseTransaction, commandID uuid.UUID, value kernel.AlertEvidence) error {
	state := value.Snapshot()
	initial := state.CustodyEvents[0]
	var returnedID uuid.UUID
	var returnedVersion int64
	err := tx.QueryRow(ctx, `SELECT evidence_id, evidence_version
		FROM app.create_alert_dfir_evidence_v1(
			$1, $2, $3, $4, $5, $6, $7, $8::public.dfir_evidence_classification,
			$9, $10, $11, $12, $13, $14, $15
		)`, commandID, uuid.UUID(state.ID.Bytes()), uuid.UUID(state.AlertID.Bytes()),
		uuid.UUID(state.StorageObjectID.Bytes()), state.Title, state.Description, state.EvidenceType,
		string(state.Classification), state.CollectedAt, state.Source, state.RetentionUntil,
		state.LegalHold, uuid.UUID(initial.ID.Bytes()), initial.PreviousHash[:], initial.EventHash[:]).Scan(
		&returnedID, &returnedVersion)
	if err != nil {
		return err
	}
	if returnedID != uuid.UUID(value.ID().Bytes()) || returnedVersion != 1 {
		return unexpectedDFIRProjection("Alert evidence create result mismatch")
	}
	return nil
}

func (repository *DFIRRepository) MutateAlertEvidence(
	ctx context.Context,
	write application.AlertEvidenceMutationWrite,
) (application.MutationResult[kernel.AlertEvidence], error) {
	expected, contractErr := validateAlertInvestigationContract(
		write.Contract, "dfir.alert.evidence.custody.append", write.Contract.AlertID,
	)
	if !validAlertInvestigationRepository(repository) || contractErr != nil || write.Apply == nil || write.EvidenceID == (kernel.EntityID{}) || write.ExpectedVersion == 0 ||
		write.ExpectedVersion >= kernel.MaximumCustodyEvents {
		return application.MutationResult[kernel.AlertEvidence]{}, application.ErrRepositoryPrecondition
	}
	tenantID, alertID := write.Contract.Actor.TenantID, uuid.UUID(write.Contract.AlertID.Bytes())
	evidenceID := uuid.UUID(write.EvidenceID.Bytes())
	result, err := withinTransactionWithOptions(ctx, repository.begin, phase4WriteOptions(),
		func(tx databaseTransaction) (application.MutationResult[kernel.AlertEvidence], error) {
			if err := authorizeAlertInvestigationContract(ctx, tx, write.Contract, tenantID, alertID); err != nil {
				return application.MutationResult[kernel.AlertEvidence]{}, err
			}
			ids, err := phase4NewIDs(repository.newID, 4)
			if err != nil {
				return application.MutationResult[kernel.AlertEvidence]{}, err
			}
			reservation, err := reserveAlertInvestigationCommand(ctx, tx, ids[0], alertID, write.Contract, evidenceID, int64(write.ExpectedVersion+1))
			if err != nil {
				return application.MutationResult[kernel.AlertEvidence]{}, err
			}
			if reservation.replayed {
				replayed, decodeErr := decodeAlertEvidenceResult(reservation.snapshot)
				if decodeErr != nil || replayed.ID() != write.EvidenceID ||
					replayed.TenantID().String() != tenantID.String() || replayed.AlertID() != write.Contract.AlertID ||
					replayed.Version() != write.ExpectedVersion+1 {
					if decodeErr != nil {
						return application.MutationResult[kernel.AlertEvidence]{}, decodeErr
					}
					return application.MutationResult[kernel.AlertEvidence]{}, unexpectedDFIRProjection("Alert custody replay coordinate mismatch")
				}
				return application.MutationResult[kernel.AlertEvidence]{Resource: replayed, Replayed: true}, nil
			}
			// append_alert_dfir_custody_event_v1 locks the row and checks the
			// expected version before appending in this serializable transaction.
			current, err := loadDFIRAlertEvidence(ctx, tx, tenantID, alertID, evidenceID)
			if err != nil {
				return application.MutationResult[kernel.AlertEvidence]{}, err
			}
			if current.Version() != write.ExpectedVersion {
				return application.MutationResult[kernel.AlertEvidence]{}, application.ErrRepositoryPrecondition
			}
			updated, err := write.Apply(current)
			if err != nil {
				return application.MutationResult[kernel.AlertEvidence]{}, err
			}
			if updated.ID() != current.ID() || updated.TenantID() != current.TenantID() || updated.AlertID() != current.AlertID() ||
				updated.Version() != write.ExpectedVersion+1 || len(updated.CustodyEvents()) != len(current.CustodyEvents())+1 ||
				uint64(len(updated.CustodyEvents())) > kernel.MaximumCustodyEvents || !updated.VerifyCustodyChain() {
				return application.MutationResult[kernel.AlertEvidence]{}, application.ErrRepositoryConflict
			}
			if err := appendAlertCustody(ctx, tx, reservation.commandID, updated, write.ExpectedVersion); err != nil {
				return application.MutationResult[kernel.AlertEvidence]{}, err
			}
			stored, err := loadDFIRAlertEvidence(ctx, tx, tenantID, alertID, evidenceID)
			if err != nil || !sameAlertEvidence(stored, updated) {
				if err != nil {
					return application.MutationResult[kernel.AlertEvidence]{}, err
				}
				return application.MutationResult[kernel.AlertEvidence]{}, unexpectedDFIRProjection("divergent Alert evidence after custody append")
			}
			if err := appendAlertInvestigationEffects(ctx, tx, write.Contract, expected, alertID, evidenceID,
				int64(updated.Version()), ids, alertEvidenceJournal(current), alertEvidenceJournal(updated),
				map[string]any{"custodyAction": updated.CustodyEvents()[len(updated.CustodyEvents())-1].Action()}); err != nil {
				return application.MutationResult[kernel.AlertEvidence]{}, err
			}
			document, err := encodeAlertEvidenceResult(stored)
			if err != nil {
				return application.MutationResult[kernel.AlertEvidence]{}, err
			}
			if err = storeAlertInvestigationResult(ctx, tx, reservation.commandID, document); err != nil {
				return application.MutationResult[kernel.AlertEvidence]{}, err
			}
			return application.MutationResult[kernel.AlertEvidence]{Resource: stored}, nil
		})
	return result, mapDFIRDatabaseError(err)
}

func appendAlertCustody(
	ctx context.Context,
	tx databaseTransaction,
	commandID uuid.UUID,
	updated kernel.AlertEvidence,
	expectedVersion uint64,
) error {
	events := updated.CustodyEvents()
	event := events[len(events)-1].Snapshot()
	var returnedID uuid.UUID
	var returnedVersion int64
	err := tx.QueryRow(ctx, `SELECT evidence_id, evidence_version
		FROM app.append_alert_dfir_custody_event_v1(
			$1, $2, $3, $4, $5, $6::public.dfir_custody_action, $7, $8, $9, $10, $11
		)`, commandID, uuid.UUID(updated.ID().Bytes()), uuid.UUID(updated.AlertID().Bytes()), int64(expectedVersion),
		uuid.UUID(event.ID.Bytes()), string(event.Action), event.Reason, event.StateValue,
		event.PreviousHash[:], event.EventHash[:], event.OccurredAt).Scan(
		&returnedID, &returnedVersion)
	if err != nil {
		return err
	}
	if returnedID != uuid.UUID(updated.ID().Bytes()) || returnedVersion != int64(updated.Version()) {
		return unexpectedDFIRProjection("Alert custody append result mismatch")
	}
	return nil
}

func (repository *DFIRRepository) CommitAlertTask(
	ctx context.Context,
	write application.AlertTaskCreateWrite,
) (application.MutationResult[kernel.AlertTask], error) {
	expected, contractErr := validateAlertInvestigationContract(write.Contract, "dfir.alert.task.create", write.Contract.AlertID)
	if !validAlertInvestigationRepository(repository) || contractErr != nil || write.Task.Version() != 1 || write.Task.AlertID() != write.Contract.AlertID ||
		write.Task.TenantID().String() != write.Contract.Actor.TenantID.String() {
		return application.MutationResult[kernel.AlertTask]{}, application.ErrRepositoryConflict
	}
	return repository.writeAlertTask(ctx, write.Contract, write.Task.ID(), 0, expected,
		func() (kernel.AlertTask, error) { return write.Task, nil })
}

func (repository *DFIRRepository) MutateAlertTask(
	ctx context.Context,
	write application.AlertTaskMutationWrite,
) (application.MutationResult[kernel.AlertTask], error) {
	expected, contractErr := validateAlertInvestigationContract(write.Contract, write.Contract.Command.Operation, write.Contract.AlertID)
	if !validAlertInvestigationRepository(repository) || contractErr != nil || expected.resourceType != "dfir_task" || write.Apply == nil ||
		write.TaskID == (kernel.EntityID{}) || write.ExpectedVersion == 0 || write.ExpectedVersion >= kernel.MaximumAlertResourceVersion {
		return application.MutationResult[kernel.AlertTask]{}, application.ErrRepositoryPrecondition
	}
	return repository.mutateAlertTask(ctx, write, expected)
}

func (repository *DFIRRepository) writeAlertTask(
	ctx context.Context,
	contract application.AlertMutationContract,
	taskID kernel.EntityID,
	expectedVersion uint64,
	expected alertInvestigationOperation,
	create func() (kernel.AlertTask, error),
) (application.MutationResult[kernel.AlertTask], error) {
	if expectedVersion != 0 {
		return application.MutationResult[kernel.AlertTask]{}, application.ErrRepositoryConflict
	}
	return repository.commitAlertTaskCreate(ctx, contract, taskID, expected, create)
}

func (repository *DFIRRepository) commitAlertTaskCreate(
	ctx context.Context,
	contract application.AlertMutationContract,
	taskID kernel.EntityID,
	expected alertInvestigationOperation,
	create func() (kernel.AlertTask, error),
) (application.MutationResult[kernel.AlertTask], error) {
	tenantID, alertID := contract.Actor.TenantID, uuid.UUID(contract.AlertID.Bytes())
	id := uuid.UUID(taskID.Bytes())
	result, err := withinTransactionWithOptions(ctx, repository.begin, phase4WriteOptions(),
		func(tx databaseTransaction) (application.MutationResult[kernel.AlertTask], error) {
			if err := authorizeAlertInvestigationContract(ctx, tx, contract, tenantID, alertID); err != nil {
				return application.MutationResult[kernel.AlertTask]{}, err
			}
			ids, err := phase4NewIDs(repository.newID, 4)
			if err != nil {
				return application.MutationResult[kernel.AlertTask]{}, err
			}
			reservation, err := reserveAlertInvestigationCommand(ctx, tx, ids[0], alertID, contract, id, 1)
			if err != nil {
				return application.MutationResult[kernel.AlertTask]{}, err
			}
			if reservation.replayed {
				replayed, decodeErr := decodeAlertTaskResult(reservation.snapshot)
				if decodeErr != nil || replayed.ID() != taskID || replayed.TenantID().String() != tenantID.String() ||
					replayed.AlertID() != contract.AlertID || replayed.Version() != 1 {
					if decodeErr != nil {
						return application.MutationResult[kernel.AlertTask]{}, decodeErr
					}
					return application.MutationResult[kernel.AlertTask]{}, unexpectedDFIRProjection("Alert task replay coordinate mismatch")
				}
				if referenceErr := validateAlertTaskReferences(ctx, tx, tenantID, alertID, replayed); referenceErr != nil {
					return application.MutationResult[kernel.AlertTask]{}, referenceErr
				}
				return application.MutationResult[kernel.AlertTask]{Resource: replayed, Replayed: true}, nil
			}
			task, err := create()
			if err != nil {
				return application.MutationResult[kernel.AlertTask]{}, err
			}
			if err = validateAlertTaskReferences(ctx, tx, tenantID, alertID, task); err != nil {
				return application.MutationResult[kernel.AlertTask]{}, err
			}
			epoch, err := resolveDFIRTaskEpoch(ctx, tx, tenantID, task.OperatorTeamID(), task.AssigneeID())
			if err != nil {
				return application.MutationResult[kernel.AlertTask]{}, err
			}
			if err = insertAlertTask(ctx, tx, contract.Actor.MembershipID, task, epoch); err != nil {
				return application.MutationResult[kernel.AlertTask]{}, err
			}
			stored, err := loadDFIRAlertTask(ctx, tx, tenantID, alertID, id)
			if err != nil || !sameAlertTask(stored, task) {
				if err != nil {
					return application.MutationResult[kernel.AlertTask]{}, err
				}
				return application.MutationResult[kernel.AlertTask]{}, unexpectedDFIRProjection("divergent Alert task after create")
			}
			if err = appendAlertInvestigationEffects(ctx, tx, contract, expected, alertID, id, 1, ids,
				map[string]any{}, alertTaskJournal(stored), map[string]any{}); err != nil {
				return application.MutationResult[kernel.AlertTask]{}, err
			}
			document, err := encodeAlertTaskResult(stored)
			if err != nil {
				return application.MutationResult[kernel.AlertTask]{}, err
			}
			if err = storeAlertInvestigationResult(ctx, tx, reservation.commandID, document); err != nil {
				return application.MutationResult[kernel.AlertTask]{}, err
			}
			return application.MutationResult[kernel.AlertTask]{Resource: stored}, nil
		})
	return result, mapDFIRDatabaseError(err)
}

func (repository *DFIRRepository) mutateAlertTask(
	ctx context.Context,
	write application.AlertTaskMutationWrite,
	expected alertInvestigationOperation,
) (application.MutationResult[kernel.AlertTask], error) {
	tenantID, alertID := write.Contract.Actor.TenantID, uuid.UUID(write.Contract.AlertID.Bytes())
	id := uuid.UUID(write.TaskID.Bytes())
	result, err := withinTransactionWithOptions(ctx, repository.begin, phase4WriteOptions(),
		func(tx databaseTransaction) (application.MutationResult[kernel.AlertTask], error) {
			if err := authorizeAlertInvestigationContract(ctx, tx, write.Contract, tenantID, alertID); err != nil {
				return application.MutationResult[kernel.AlertTask]{}, err
			}
			ids, err := phase4NewIDs(repository.newID, 4)
			if err != nil {
				return application.MutationResult[kernel.AlertTask]{}, err
			}
			reservation, err := reserveAlertInvestigationCommand(ctx, tx, ids[0], alertID, write.Contract, id, int64(write.ExpectedVersion+1))
			if err != nil {
				return application.MutationResult[kernel.AlertTask]{}, err
			}
			if reservation.replayed {
				replayed, decodeErr := decodeAlertTaskResult(reservation.snapshot)
				if decodeErr != nil || replayed.ID() != write.TaskID || replayed.TenantID().String() != tenantID.String() ||
					replayed.AlertID() != write.Contract.AlertID || replayed.Version() != write.ExpectedVersion+1 {
					if decodeErr != nil {
						return application.MutationResult[kernel.AlertTask]{}, decodeErr
					}
					return application.MutationResult[kernel.AlertTask]{}, unexpectedDFIRProjection("Alert task replay coordinate mismatch")
				}
				if referenceErr := validateAlertTaskReferences(ctx, tx, tenantID, alertID, replayed); referenceErr != nil {
					return application.MutationResult[kernel.AlertTask]{}, referenceErr
				}
				return application.MutationResult[kernel.AlertTask]{Resource: replayed, Replayed: true}, nil
			}
			var epoch *uuid.UUID
			if err := tx.QueryRow(ctx, `SELECT operator_team_epoch_id FROM public.dfir_tasks
				WHERE tenant_id = $1 AND alert_id = $2 AND case_id IS NULL AND id = $3 FOR UPDATE`, tenantID, alertID, id).Scan(&epoch); err != nil {
				return application.MutationResult[kernel.AlertTask]{}, err
			}
			current, err := loadDFIRAlertTask(ctx, tx, tenantID, alertID, id)
			if err != nil {
				return application.MutationResult[kernel.AlertTask]{}, err
			}
			if current.Version() != write.ExpectedVersion {
				return application.MutationResult[kernel.AlertTask]{}, application.ErrRepositoryPrecondition
			}
			updated, err := write.Apply(current)
			if err != nil {
				return application.MutationResult[kernel.AlertTask]{}, err
			}
			if !validAlertTaskMutation(current, updated, write.Contract.Command.Operation, write.ExpectedVersion) {
				return application.MutationResult[kernel.AlertTask]{}, application.ErrRepositoryConflict
			}
			if write.Contract.Command.Operation == "dfir.alert.task.assign" {
				epoch, err = resolveDFIRTaskEpoch(ctx, tx, tenantID, updated.OperatorTeamID(), updated.AssigneeID())
				if err != nil {
					return application.MutationResult[kernel.AlertTask]{}, err
				}
			}
			if err = validateAlertTaskReferences(ctx, tx, tenantID, alertID, updated); err != nil {
				return application.MutationResult[kernel.AlertTask]{}, err
			}
			if err = updateAlertTask(ctx, tx, write.Contract.Actor.MembershipID, updated, write.ExpectedVersion, epoch); err != nil {
				return application.MutationResult[kernel.AlertTask]{}, err
			}
			stored, err := loadDFIRAlertTask(ctx, tx, tenantID, alertID, id)
			if err != nil || !sameAlertTask(stored, updated) {
				if err != nil {
					return application.MutationResult[kernel.AlertTask]{}, err
				}
				return application.MutationResult[kernel.AlertTask]{}, unexpectedDFIRProjection("divergent Alert task after mutation")
			}
			if err = appendAlertInvestigationEffects(ctx, tx, write.Contract, expected, alertID, id, int64(updated.Version()), ids,
				alertTaskJournal(current), alertTaskJournal(updated), map[string]any{}); err != nil {
				return application.MutationResult[kernel.AlertTask]{}, err
			}
			document, err := encodeAlertTaskResult(stored)
			if err != nil {
				return application.MutationResult[kernel.AlertTask]{}, err
			}
			if err = storeAlertInvestigationResult(ctx, tx, reservation.commandID, document); err != nil {
				return application.MutationResult[kernel.AlertTask]{}, err
			}
			return application.MutationResult[kernel.AlertTask]{Resource: stored}, nil
		})
	return result, mapDFIRDatabaseError(err)
}

func insertAlertTask(ctx context.Context, tx databaseTransaction, membershipID uuid.UUID, value kernel.AlertTask, epoch *uuid.UUID) error {
	checklist, err := encodeDFIRChecklist(value.Checklist())
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO public.dfir_tasks (
		id, tenant_id, alert_id, case_id, title, description, status, priority,
		assignee_user_id, operator_team_id, operator_team_epoch_id, due_at, checklist,
		completed_at, completed_by_user_id, completion_data, comment_ids, sla_instance_id,
		created_by_membership_id, created_by_service_account_id,
		updated_by_membership_id, updated_by_service_account_id, version, created_at, updated_at
	) VALUES ($1,$2,$3,NULL,$4,$5,$6::public.dfir_task_status,$7::public.dfir_task_priority,
		$8,$9,$10,$11,$12::jsonb,$13,$14,$15::jsonb,$16,$17,$18,NULL,$18,NULL,$19,$20,$21)`,
		uuid.UUID(value.ID().Bytes()), uuid.UUID(value.TenantID().Bytes()), uuid.UUID(value.AlertID().Bytes()),
		value.Title(), value.Description(), string(value.Status()), string(value.Priority()), optionalKernelUUID(value.AssigneeID()),
		optionalKernelUUID(value.OperatorTeamID()), epoch, value.DueAt(), checklist, value.CompletedAt(),
		optionalKernelUUID(value.CompletedBy()), nullableJSON(value.CompletionData()), kernelUUIDs(value.CommentIDs()),
		optionalKernelUUID(value.SLAInstanceID()), membershipID, int64(value.Version()), value.CreatedAt(), value.UpdatedAt())
	return err
}

func updateAlertTask(ctx context.Context, tx databaseTransaction, membershipID uuid.UUID, value kernel.AlertTask, expectedVersion uint64, epoch *uuid.UUID) error {
	checklist, err := encodeDFIRChecklist(value.Checklist())
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE public.dfir_tasks SET
		title=$5, description=$6, status=$7::public.dfir_task_status, priority=$8::public.dfir_task_priority,
		assignee_user_id=$9, operator_team_id=$10, operator_team_epoch_id=$11, due_at=$12,
		checklist=$13::jsonb, completed_at=$14, completed_by_user_id=$15, completion_data=$16::jsonb,
		comment_ids=$17, sla_instance_id=$18, updated_by_membership_id=$19,
		updated_by_service_account_id=NULL, version=$20, updated_at=$21
		WHERE tenant_id=$1 AND alert_id=$2 AND case_id IS NULL AND id=$3 AND version=$4`,
		uuid.UUID(value.TenantID().Bytes()), uuid.UUID(value.AlertID().Bytes()), uuid.UUID(value.ID().Bytes()), int64(expectedVersion),
		value.Title(), value.Description(), string(value.Status()), string(value.Priority()), optionalKernelUUID(value.AssigneeID()),
		optionalKernelUUID(value.OperatorTeamID()), epoch, value.DueAt(), checklist, value.CompletedAt(), optionalKernelUUID(value.CompletedBy()),
		nullableJSON(value.CompletionData()), kernelUUIDs(value.CommentIDs()), optionalKernelUUID(value.SLAInstanceID()),
		membershipID, int64(value.Version()), value.UpdatedAt())
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return application.ErrRepositoryPrecondition
	}
	return nil
}

func validateAlertTaskReferences(ctx context.Context, tx databaseTransaction, tenantID, alertID uuid.UUID, value kernel.AlertTask) error {
	if comments := value.CommentIDs(); len(comments) != 0 {
		var count int64
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM public.ticket_comments
			WHERE tenant_id=$1 AND alert_id=$2 AND case_id IS NULL AND id=ANY($3::uuid[])`,
			tenantID, alertID, kernelUUIDs(comments)).Scan(&count); err != nil {
			return err
		}
		if count != int64(len(comments)) {
			return authorization.ErrForbidden
		}
	}
	if sla := value.SLAInstanceID(); sla != nil {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM public.sla_instances
			WHERE tenant_id=$1 AND id=$2 AND object_type='alert' AND object_id=$3)`,
			tenantID, uuid.UUID(sla.Bytes()), alertID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return authorization.ErrForbidden
		}
	}
	return nil
}

func validAlertTaskMutation(current, updated kernel.AlertTask, operation string, expectedVersion uint64) bool {
	if current.ID() != updated.ID() || current.TenantID() != updated.TenantID() || current.AlertID() != updated.AlertID() ||
		updated.Version() != expectedVersion+1 || current.Version() != expectedVersion ||
		!current.CreatedAt().Equal(updated.CreatedAt()) || updated.UpdatedAt().Before(current.UpdatedAt()) {
		return false
	}
	sameDetails := current.Title() == updated.Title() && current.Description() == updated.Description() &&
		current.Priority() == updated.Priority() && sameOptionalKernelID(current.SLAInstanceID(), updated.SLAInstanceID())
	sameAssignment := sameOptionalKernelID(current.AssigneeID(), updated.AssigneeID()) &&
		sameOptionalKernelID(current.OperatorTeamID(), updated.OperatorTeamID())
	sameDue := sameOptionalTime(current.DueAt(), updated.DueAt())
	leftChecklist, leftErr := encodeDFIRChecklist(current.Checklist())
	rightChecklist, rightErr := encodeDFIRChecklist(updated.Checklist())
	sameChecklist := leftErr == nil && rightErr == nil && bytes.Equal(leftChecklist, rightChecklist)
	sameCompletion := current.Status() == updated.Status() && sameOptionalTime(current.CompletedAt(), updated.CompletedAt()) &&
		sameOptionalKernelID(current.CompletedBy(), updated.CompletedBy()) && bytes.Equal(current.CompletionData(), updated.CompletionData())
	sameComments := slices.Equal(current.CommentIDs(), updated.CommentIDs())
	switch operation {
	case "dfir.alert.task.transition":
		return sameDetails && sameAssignment && sameDue && sameChecklist && sameComments
	case "dfir.alert.task.replace_details":
		return sameAssignment && sameDue && sameChecklist && sameCompletion && sameComments
	case "dfir.alert.task.assign":
		return sameDetails && sameDue && sameChecklist && sameCompletion && sameComments
	case "dfir.alert.task.reschedule":
		return sameDetails && sameAssignment && sameChecklist && sameCompletion && sameComments
	case "dfir.alert.task.checklist.replace":
		return sameDetails && sameAssignment && sameDue && sameCompletion && sameComments
	case "dfir.alert.task.comments.replace":
		return sameDetails && sameAssignment && sameDue && sameChecklist && sameCompletion && !sameComments
	default:
		return false
	}
}

func (repository *DFIRRepository) CommitAlertRelationship(
	ctx context.Context,
	write application.AlertRelationshipCreateWrite,
) (application.MutationResult[kernel.AlertRelationship], error) {
	expected, contractErr := validateAlertInvestigationContract(write.Contract, "dfir.alert.relationship.create", write.Contract.AlertID)
	value := write.Relationship
	if !validAlertInvestigationRepository(repository) || contractErr != nil || value.Version() != 1 || !value.Active() || value.AlertID() != write.Contract.AlertID ||
		value.TenantID().String() != write.Contract.Actor.TenantID.String() ||
		value.CreatedBy().String() != write.Contract.Actor.MembershipID.String() {
		return application.MutationResult[kernel.AlertRelationship]{}, application.ErrRepositoryConflict
	}
	tenantID, alertID, id := write.Contract.Actor.TenantID, uuid.UUID(write.Contract.AlertID.Bytes()), uuid.UUID(value.ID().Bytes())
	result, err := withinTransactionWithOptions(ctx, repository.begin, phase4WriteOptions(),
		func(tx databaseTransaction) (application.MutationResult[kernel.AlertRelationship], error) {
			if err := authorizeAlertInvestigationContract(ctx, tx, write.Contract, tenantID, alertID); err != nil {
				return application.MutationResult[kernel.AlertRelationship]{}, err
			}
			if endpointErr := validateDFIRRelationshipEndpoints(
				ctx, tx, write.Contract.Actor, tenantID, dfirMutationRootAlert, alertID,
				value.Source(), value.Target(),
			); endpointErr != nil {
				return application.MutationResult[kernel.AlertRelationship]{}, endpointErr
			}
			ids, err := phase4NewIDs(repository.newID, 4)
			if err != nil {
				return application.MutationResult[kernel.AlertRelationship]{}, err
			}
			reservation, err := reserveAlertInvestigationCommand(ctx, tx, ids[0], alertID, write.Contract, id, 1)
			if err != nil {
				return application.MutationResult[kernel.AlertRelationship]{}, err
			}
			if reservation.replayed {
				replayed, decodeErr := decodeAlertRelationshipResult(reservation.snapshot)
				if decodeErr != nil || replayed.ID() != value.ID() || replayed.TenantID().String() != tenantID.String() ||
					replayed.AlertID() != write.Contract.AlertID || replayed.Version() != 1 {
					if decodeErr != nil {
						return application.MutationResult[kernel.AlertRelationship]{}, decodeErr
					}
					return application.MutationResult[kernel.AlertRelationship]{}, unexpectedDFIRProjection("Alert relationship replay coordinate mismatch")
				}
				return application.MutationResult[kernel.AlertRelationship]{Resource: replayed, Replayed: true}, nil
			}
			if err = insertAlertRelationship(ctx, tx, reservation.commandID, value); err != nil {
				return application.MutationResult[kernel.AlertRelationship]{}, err
			}
			stored, err := loadDFIRAlertRelationship(ctx, tx, tenantID, alertID, id)
			if err != nil || !sameAlertRelationship(stored, value) {
				if err != nil {
					return application.MutationResult[kernel.AlertRelationship]{}, err
				}
				return application.MutationResult[kernel.AlertRelationship]{}, unexpectedDFIRProjection("divergent Alert relationship after create")
			}
			if err = appendAlertInvestigationEffects(ctx, tx, write.Contract, expected, alertID, id, 1, ids,
				map[string]any{}, alertRelationshipJournal(stored), map[string]any{}); err != nil {
				return application.MutationResult[kernel.AlertRelationship]{}, err
			}
			document, err := encodeAlertRelationshipResult(stored)
			if err != nil {
				return application.MutationResult[kernel.AlertRelationship]{}, err
			}
			if err = storeAlertInvestigationResult(ctx, tx, reservation.commandID, document); err != nil {
				return application.MutationResult[kernel.AlertRelationship]{}, err
			}
			return application.MutationResult[kernel.AlertRelationship]{Resource: stored}, nil
		})
	return result, mapDFIRDatabaseError(err)
}

func insertAlertRelationship(ctx context.Context, tx databaseTransaction, commandID uuid.UUID, value kernel.AlertRelationship) error {
	sourceID, sourceType, sourceExternal := dfirReferenceDatabaseValues(value.Source())
	targetID, targetType, targetExternal := dfirReferenceDatabaseValues(value.Target())
	var returnedID uuid.UUID
	err := tx.QueryRow(ctx, `SELECT relationship_id FROM app.create_alert_dfir_relationship_v1(
		$1,$2,$3,$4::public.dfir_entity_kind,$5,$6,$7,
		$8::public.dfir_entity_kind,$9,$10,$11,$12,$13::jsonb,$14
	)`, commandID, uuid.UUID(value.ID().Bytes()), uuid.UUID(value.AlertID().Bytes()), string(value.Source().Kind()),
		sourceID, sourceType, sourceExternal, string(value.Target().Kind()), targetID, targetType, targetExternal,
		value.RelationshipType(), nullableJSON(value.Metadata()), value.CreatedAt()).Scan(&returnedID)
	if err != nil {
		return err
	}
	if returnedID != uuid.UUID(value.ID().Bytes()) {
		return unexpectedDFIRProjection("Alert relationship create result mismatch")
	}
	return nil
}

func (repository *DFIRRepository) MutateAlertRelationship(
	ctx context.Context,
	write application.AlertRelationshipMutationWrite,
) (application.MutationResult[kernel.AlertRelationship], error) {
	expected, contractErr := validateAlertInvestigationContract(write.Contract, "dfir.alert.relationship.retract", write.Contract.AlertID)
	if !validAlertInvestigationRepository(repository) || contractErr != nil || write.Apply == nil || write.RelationshipID == (kernel.EntityID{}) || write.ExpectedVersion == 0 ||
		write.ExpectedVersion >= kernel.MaximumAlertResourceVersion {
		return application.MutationResult[kernel.AlertRelationship]{}, application.ErrRepositoryPrecondition
	}
	tenantID, alertID, id := write.Contract.Actor.TenantID, uuid.UUID(write.Contract.AlertID.Bytes()), uuid.UUID(write.RelationshipID.Bytes())
	result, err := withinTransactionWithOptions(ctx, repository.begin, phase4WriteOptions(),
		func(tx databaseTransaction) (application.MutationResult[kernel.AlertRelationship], error) {
			if err := authorizeAlertInvestigationContract(ctx, tx, write.Contract, tenantID, alertID); err != nil {
				return application.MutationResult[kernel.AlertRelationship]{}, err
			}
			live, err := loadDFIRAlertRelationship(ctx, tx, tenantID, alertID, id)
			if err != nil {
				return application.MutationResult[kernel.AlertRelationship]{}, err
			}
			if endpointErr := validateDFIRRelationshipEndpoints(
				ctx, tx, write.Contract.Actor, tenantID, dfirMutationRootAlert, alertID,
				live.Source(), live.Target(),
			); endpointErr != nil {
				return application.MutationResult[kernel.AlertRelationship]{}, endpointErr
			}
			ids, err := phase4NewIDs(repository.newID, 4)
			if err != nil {
				return application.MutationResult[kernel.AlertRelationship]{}, err
			}
			reservation, err := reserveAlertInvestigationCommand(ctx, tx, ids[0], alertID, write.Contract, id, int64(write.ExpectedVersion+1))
			if err != nil {
				return application.MutationResult[kernel.AlertRelationship]{}, err
			}
			if reservation.replayed {
				replayed, decodeErr := decodeAlertRelationshipResult(reservation.snapshot)
				if decodeErr != nil || replayed.ID() != write.RelationshipID ||
					replayed.TenantID().String() != tenantID.String() || replayed.AlertID() != write.Contract.AlertID ||
					replayed.Version() != write.ExpectedVersion+1 {
					if decodeErr != nil {
						return application.MutationResult[kernel.AlertRelationship]{}, decodeErr
					}
					return application.MutationResult[kernel.AlertRelationship]{}, unexpectedDFIRProjection("Alert relationship retraction replay coordinate mismatch")
				}
				return application.MutationResult[kernel.AlertRelationship]{Resource: replayed, Replayed: true}, nil
			}
			var locked int
			if err := tx.QueryRow(ctx, `SELECT 1 FROM public.dfir_relationships
				WHERE tenant_id=$1 AND alert_id=$2 AND case_id IS NULL AND id=$3 FOR UPDATE`, tenantID, alertID, id).Scan(&locked); err != nil {
				return application.MutationResult[kernel.AlertRelationship]{}, err
			}
			current, err := loadDFIRAlertRelationship(ctx, tx, tenantID, alertID, id)
			if err != nil {
				return application.MutationResult[kernel.AlertRelationship]{}, err
			}
			if current.Version() != write.ExpectedVersion {
				return application.MutationResult[kernel.AlertRelationship]{}, application.ErrRepositoryPrecondition
			}
			updated, err := write.Apply(current)
			if err != nil {
				return application.MutationResult[kernel.AlertRelationship]{}, err
			}
			if !validAlertRelationshipRetraction(current, updated, write.ExpectedVersion) {
				return application.MutationResult[kernel.AlertRelationship]{}, application.ErrRepositoryConflict
			}
			retraction := updated.Retractions()[0]
			if err = retractAlertRelationship(ctx, tx, reservation.commandID, updated, retraction, write.ExpectedVersion); err != nil {
				return application.MutationResult[kernel.AlertRelationship]{}, err
			}
			stored, err := loadDFIRAlertRelationship(ctx, tx, tenantID, alertID, id)
			if err != nil || !sameAlertRelationship(stored, updated) {
				if err != nil {
					return application.MutationResult[kernel.AlertRelationship]{}, err
				}
				return application.MutationResult[kernel.AlertRelationship]{}, unexpectedDFIRProjection("divergent Alert relationship after retraction")
			}
			if err = appendAlertInvestigationEffects(ctx, tx, write.Contract, expected, alertID, id, int64(updated.Version()), ids,
				alertRelationshipJournal(current), alertRelationshipJournal(updated), map[string]any{"retractionId": retraction.ID.String()}); err != nil {
				return application.MutationResult[kernel.AlertRelationship]{}, err
			}
			document, err := encodeAlertRelationshipResult(stored)
			if err != nil {
				return application.MutationResult[kernel.AlertRelationship]{}, err
			}
			if err = storeAlertInvestigationResult(ctx, tx, reservation.commandID, document); err != nil {
				return application.MutationResult[kernel.AlertRelationship]{}, err
			}
			return application.MutationResult[kernel.AlertRelationship]{Resource: stored}, nil
		})
	return result, mapDFIRDatabaseError(err)
}

func retractAlertRelationship(ctx context.Context, tx databaseTransaction, commandID uuid.UUID, value kernel.AlertRelationship,
	retraction kernel.AlertRelationshipRetractionState, expectedVersion uint64) error {
	var returnedID uuid.UUID
	var returnedVersion int64
	err := tx.QueryRow(ctx, `SELECT relationship_id, relationship_version FROM app.retract_alert_dfir_relationship_v1(
		$1,$2,$3,$4,$5,$6,$7
	)`, commandID, uuid.UUID(value.ID().Bytes()), uuid.UUID(value.AlertID().Bytes()), int64(expectedVersion),
		uuid.UUID(retraction.ID.Bytes()), retraction.Reason, retraction.OccurredAt).Scan(&returnedID, &returnedVersion)
	if err != nil {
		return err
	}
	if returnedID != uuid.UUID(value.ID().Bytes()) || returnedVersion != int64(value.Version()) {
		return unexpectedDFIRProjection("Alert relationship retraction result mismatch")
	}
	return nil
}

func validAlertRelationshipRetraction(current, updated kernel.AlertRelationship, expectedVersion uint64) bool {
	if current.ID() != updated.ID() || current.TenantID() != updated.TenantID() || current.AlertID() != updated.AlertID() ||
		current.Source() != updated.Source() || current.Target() != updated.Target() ||
		current.RelationshipType() != updated.RelationshipType() || !bytes.Equal(current.Metadata(), updated.Metadata()) ||
		current.CreatedBy() != updated.CreatedBy() || !current.CreatedAt().Equal(updated.CreatedAt()) ||
		!current.Active() || updated.Active() || current.Version() != expectedVersion || updated.Version() != expectedVersion+1 {
		return false
	}
	return len(current.Retractions()) == 0 && len(updated.Retractions()) == 1
}

func sameAlertEvidence(left, right kernel.AlertEvidence) bool {
	leftJSON, leftErr := encodeAlertEvidenceResult(left)
	rightJSON, rightErr := encodeAlertEvidenceResult(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}

func validAlertInvestigationRepository(repository *DFIRRepository) bool {
	return repository != nil && repository.begin != nil && repository.newID != nil
}

func sameAlertTask(left, right kernel.AlertTask) bool {
	leftJSON, leftErr := encodeAlertTaskResult(left)
	rightJSON, rightErr := encodeAlertTaskResult(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}

func sameAlertRelationship(left, right kernel.AlertRelationship) bool {
	leftJSON, leftErr := encodeAlertRelationshipResult(left)
	rightJSON, rightErr := encodeAlertRelationshipResult(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}

func alertEvidenceJournal(value kernel.AlertEvidence) map[string]any {
	return map[string]any{
		"version": value.Version(), "classification": value.Classification(), "scanState": value.ScanState(),
		"legalHold": value.LegalHold(), "sealed": value.Sealed(), "destroyed": value.Destroyed(),
		"custodyCount": len(value.CustodyEvents()),
	}
}

func alertTaskJournal(value kernel.AlertTask) map[string]any {
	return map[string]any{
		"version": value.Version(), "status": value.Status(), "priority": value.Priority(),
		"assigned": value.AssigneeID() != nil, "teamAssigned": value.OperatorTeamID() != nil,
		"checklistCount": len(value.Checklist()), "commentCount": len(value.CommentIDs()),
		"hasSla": value.SLAInstanceID() != nil,
	}
}

func alertRelationshipJournal(value kernel.AlertRelationship) map[string]any {
	return map[string]any{
		"version": value.Version(), "relationshipType": value.RelationshipType(), "active": value.Active(),
		"sourceKind": value.Source().Kind(), "targetKind": value.Target().Kind(),
	}
}
