package postgres

import (
	"context"

	"github.com/google/uuid"

	kernel "github.com/periapsis-im/periapsis/modules/dfir"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	application "github.com/periapsis-im/periapsis/services/api/internal/dfir"
)

func (repository *DFIRRepository) CreateEvidence(
	ctx context.Context,
	write application.EvidenceWrite,
) (application.MutationResult[kernel.Evidence], error) {
	if !validDFIRCommand(write.Command, "dfir.evidence.create") || write.Build == nil ||
		write.EvidenceID == (kernel.EntityID{}) || write.StorageObjectID == (kernel.EntityID{}) ||
		write.InitialCustodyEventID == (kernel.EntityID{}) {
		return application.MutationResult[kernel.Evidence]{}, application.ErrRepositoryConflict
	}
	tenantID := write.Actor.TenantID
	caseID := uuid.UUID(write.CaseID.Bytes())
	id := uuid.UUID(write.EvidenceID.Bytes())
	storageID := uuid.UUID(write.StorageObjectID.Bytes())
	initialEventID := uuid.UUID(write.InitialCustodyEventID.Bytes())
	result, err := withinTransactionWithOptions(
		ctx, repository.begin, phase4WriteOptions(),
		func(tx databaseTransaction) (application.MutationResult[kernel.Evidence], error) {
			if _, accessErr := authorizeDFIRWrite(ctx, tx, write.Actor, tenantID, application.CapabilityEvidenceManage, caseID); accessErr != nil {
				return application.MutationResult[kernel.Evidence]{}, accessErr
			}
			ids, idErr := phase4NewIDs(repository.newID, 4)
			if idErr != nil {
				return application.MutationResult[kernel.Evidence]{}, idErr
			}
			coordinate := dfirMutationCoordinate{
				tenantID: tenantID, rootKind: dfirMutationRootCase, rootID: caseID, operation: write.Command.Operation,
				resourceKind: dfirMutationKindEvidence, resourceID: id,
				secondaryResourceID: &initialEventID, resultVersion: 1,
			}
			reservation, reserveErr := reserveDFIRMutationCommand(ctx, tx, ids[0], coordinate, write.Command)
			if reserveErr != nil {
				return application.MutationResult[kernel.Evidence]{}, reserveErr
			}
			if reservation.replayed {
				historical, decodeErr := decodeDFIREvidenceResult(reservation.snapshot, coordinate)
				if decodeErr != nil {
					return application.MutationResult[kernel.Evidence]{}, decodeErr
				}
				return application.MutationResult[kernel.Evidence]{Resource: historical, Replayed: true}, nil
			}
			var attachedStorage uuid.UUID
			// The security-definer creation function locks and validates storage in
			// this serializable transaction; the API role only reads these tables.
			if lockErr := tx.QueryRow(ctx, `
				SELECT storage.id
				FROM public.dfir_storage_objects AS storage
				JOIN public.dfir_attachments AS attachment
				  ON attachment.tenant_id = storage.tenant_id AND attachment.storage_object_id = storage.id
				WHERE storage.tenant_id = $1 AND storage.id = $2
				  AND app.dfir_attachment_belongs_to_root_v1($1, 'case', $3, attachment.id)`, tenantID, storageID, caseID).Scan(&attachedStorage); lockErr != nil {
				return application.MutationResult[kernel.Evidence]{}, lockErr
			}
			storage, storageErr := loadDFIRStorageObject(ctx, tx, tenantID, attachedStorage)
			if storageErr != nil {
				return application.MutationResult[kernel.Evidence]{}, storageErr
			}
			evidence, buildErr := write.Build(storage)
			if buildErr != nil {
				return application.MutationResult[kernel.Evidence]{}, buildErr
			}
			if evidence.ID() != write.EvidenceID || evidence.TenantID().String() != tenantID.String() ||
				evidence.CaseID() != write.CaseID || evidence.StorageObjectID() != write.StorageObjectID ||
				evidence.Version() != 1 || len(evidence.CustodyEvents()) != 1 ||
				evidence.CustodyEvents()[0].ID() != write.InitialCustodyEventID || !evidence.VerifyCustodyChain() ||
				storage.ContentSHA256() != evidence.ContentSHA256() || storage.SizeBytes() != evidence.SizeBytes() ||
				storage.DetectedMIME() != evidence.DetectedMIME() || storage.Classification() != evidence.Classification() ||
				storage.State() != evidence.ScanState() || storage.LegalHold() != evidence.LegalHold() ||
				!sameOptionalTime(storage.RetentionUntil(), evidence.RetentionUntil()) {
				return application.MutationResult[kernel.Evidence]{}, application.ErrRepositoryConflict
			}
			state := evidence.Snapshot()
			initial := state.CustodyEvents[0]
			var returnedID uuid.UUID
			var returnedVersion int64
			var replayed bool
			queryErr := tx.QueryRow(ctx, `SELECT evidence_id, evidence_version, replayed
				FROM app.create_dfir_evidence_v1(
					$1, $2, $3, $4, $5, $6, $7::public.dfir_evidence_classification,
					$8, $9, $10, $11, $12, $13, $14, $15, $16, $17,
					$18, $19, $20::inet, $21, $22
				)`, id, caseID, uuid.UUID(state.StorageObjectID.Bytes()), state.Title,
				state.Description, state.EvidenceType, string(state.Classification), state.CollectedAt,
				state.Source, state.RetentionUntil, state.LegalHold, uuid.UUID(initial.ID.Bytes()),
				initial.PreviousHash[:], initial.EventHash[:], ids[2], ids[1], ids[3],
				write.Audit.RequestID, write.Audit.CorrelationID, write.Audit.IPAddress,
				write.Audit.UserAgent, write.Actor.AuthenticationMethod).Scan(&returnedID, &returnedVersion, &replayed)
			if queryErr != nil {
				return application.MutationResult[kernel.Evidence]{}, queryErr
			}
			if returnedID != id || returnedVersion != 1 {
				return application.MutationResult[kernel.Evidence]{}, application.ErrRepositoryConflict
			}
			if replayed {
				return application.MutationResult[kernel.Evidence]{}, application.ErrRepositoryConflict
			}
			stored, loadErr := loadDFIREvidence(ctx, tx, tenantID, caseID, id)
			if loadErr != nil || !sameDFIREvidence(stored, evidence) {
				if loadErr != nil {
					return application.MutationResult[kernel.Evidence]{}, loadErr
				}
				return application.MutationResult[kernel.Evidence]{}, unexpectedDFIRProjection("divergent evidence after collect")
			}
			document, snapshotErr := encodeDFIREvidenceResult(coordinate, stored)
			if snapshotErr != nil {
				return application.MutationResult[kernel.Evidence]{}, snapshotErr
			}
			if storeErr := storeDFIRMutationResult(ctx, tx, reservation.commandID, document); storeErr != nil {
				return application.MutationResult[kernel.Evidence]{}, storeErr
			}
			return application.MutationResult[kernel.Evidence]{Resource: stored}, nil
		},
	)
	return result, mapDFIRDatabaseError(err)
}

func (repository *DFIRRepository) GetEvidence(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	caseID kernel.EntityID,
	evidenceID kernel.EntityID,
	claimed application.Access,
) (kernel.Evidence, error) {
	result, err := withinTransactionWithOptions(
		ctx, repository.begin, phase4ReadOptions(),
		func(tx databaseTransaction) (kernel.Evidence, error) {
			access, accessErr := resolveDFIRAccessInTransaction(ctx, tx, actor, tenantID, application.CapabilityEvidenceManage, caseID)
			if accessErr != nil || !sameDFIRAccess(access, claimed) {
				if accessErr != nil {
					return kernel.Evidence{}, accessErr
				}
				return kernel.Evidence{}, authorization.ErrForbidden
			}
			return loadDFIREvidence(ctx, tx, tenantID, uuid.UUID(caseID.Bytes()), uuid.UUID(evidenceID.Bytes()))
		},
	)
	return result, mapDFIRDatabaseError(err)
}

func (repository *DFIRRepository) AppendCustody(
	ctx context.Context,
	write application.CustodyWrite,
) (application.MutationResult[kernel.Evidence], error) {
	if !validDFIRCommand(write.Command, "dfir.evidence.custody.append") || write.ExpectedVersion == 0 ||
		write.ExpectedVersion >= kernel.MaximumCustodyEvents || write.Apply == nil ||
		write.EvidenceID == (kernel.EntityID{}) || write.EventID == (kernel.EntityID{}) {
		return application.MutationResult[kernel.Evidence]{}, application.ErrRepositoryPrecondition
	}
	tenantID := write.Actor.TenantID
	caseID := uuid.UUID(write.CaseID.Bytes())
	id := uuid.UUID(write.EvidenceID.Bytes())
	eventID := uuid.UUID(write.EventID.Bytes())
	result, err := withinTransactionWithOptions(
		ctx, repository.begin, phase4WriteOptions(),
		func(tx databaseTransaction) (application.MutationResult[kernel.Evidence], error) {
			if _, accessErr := authorizeDFIRWrite(ctx, tx, write.Actor, tenantID, application.CapabilityEvidenceManage, caseID); accessErr != nil {
				return application.MutationResult[kernel.Evidence]{}, accessErr
			}
			ids, idErr := phase4NewIDs(repository.newID, 4)
			if idErr != nil {
				return application.MutationResult[kernel.Evidence]{}, idErr
			}
			coordinate := dfirMutationCoordinate{
				tenantID: tenantID, rootKind: dfirMutationRootCase, rootID: caseID, operation: write.Command.Operation,
				resourceKind: dfirMutationKindEvidence, resourceID: id,
				secondaryResourceID: &eventID, resultVersion: write.ExpectedVersion + 1,
			}
			reservation, reserveErr := reserveDFIRMutationCommand(ctx, tx, ids[0], coordinate, write.Command)
			if reserveErr != nil {
				return application.MutationResult[kernel.Evidence]{}, reserveErr
			}
			if reservation.replayed {
				historical, decodeErr := decodeDFIREvidenceResult(reservation.snapshot, coordinate)
				if decodeErr != nil {
					return application.MutationResult[kernel.Evidence]{}, decodeErr
				}
				return application.MutationResult[kernel.Evidence]{Resource: historical, Replayed: true}, nil
			}
			// append_dfir_custody_event_v1 locks the row and checks the expected
			// version before appending in this serializable transaction.
			stored, loadErr := loadDFIREvidence(ctx, tx, tenantID, caseID, id)
			if loadErr != nil {
				return application.MutationResult[kernel.Evidence]{}, loadErr
			}
			if stored.Version() != write.ExpectedVersion {
				return application.MutationResult[kernel.Evidence]{}, application.ErrRepositoryPrecondition
			}
			updated, applyErr := write.Apply(stored)
			if applyErr != nil {
				return application.MutationResult[kernel.Evidence]{}, applyErr
			}
			currentEvents, updatedEvents := stored.CustodyEvents(), updated.CustodyEvents()
			if updated.ID() != stored.ID() || updated.TenantID() != stored.TenantID() ||
				updated.CaseID() != stored.CaseID() || updated.Version() != write.ExpectedVersion+1 ||
				len(updatedEvents) != len(currentEvents)+1 || uint64(len(updatedEvents)) > kernel.MaximumCustodyEvents ||
				updatedEvents[len(updatedEvents)-1].ID() != write.EventID || !updated.VerifyCustodyChain() {
				return application.MutationResult[kernel.Evidence]{}, application.ErrRepositoryConflict
			}
			event := updatedEvents[len(updatedEvents)-1].Snapshot()
			var returnedID uuid.UUID
			var returnedVersion int64
			var replayed bool
			queryErr := tx.QueryRow(ctx, `SELECT evidence_id, evidence_version, replayed
				FROM app.append_dfir_custody_event_v1(
					$1, $2, $3, $4::public.dfir_custody_action, $5, $6,
					$7, $8, $9, $10, $11, $12, $13, $14, $15::inet, $16, $17
				)`, id, int64(write.ExpectedVersion), uuid.UUID(event.ID.Bytes()), string(event.Action),
				event.Reason, event.StateValue, event.PreviousHash[:], event.EventHash[:], event.OccurredAt,
				ids[2], ids[1], ids[3], write.Audit.RequestID, write.Audit.CorrelationID,
				write.Audit.IPAddress, write.Audit.UserAgent, write.Actor.AuthenticationMethod).Scan(
				&returnedID, &returnedVersion, &replayed,
			)
			if queryErr != nil {
				return application.MutationResult[kernel.Evidence]{}, queryErr
			}
			if returnedID != id || returnedVersion != int64(updated.Version()) {
				return application.MutationResult[kernel.Evidence]{}, application.ErrRepositoryPrecondition
			}
			if replayed {
				return application.MutationResult[kernel.Evidence]{}, application.ErrRepositoryConflict
			}
			stored, loadErr = loadDFIREvidence(ctx, tx, tenantID, caseID, id)
			if loadErr != nil || !sameDFIREvidence(stored, updated) {
				if loadErr != nil {
					return application.MutationResult[kernel.Evidence]{}, loadErr
				}
				return application.MutationResult[kernel.Evidence]{}, unexpectedDFIRProjection("divergent evidence after custody append")
			}
			document, snapshotErr := encodeDFIREvidenceResult(coordinate, stored)
			if snapshotErr != nil {
				return application.MutationResult[kernel.Evidence]{}, snapshotErr
			}
			if storeErr := storeDFIRMutationResult(ctx, tx, reservation.commandID, document); storeErr != nil {
				return application.MutationResult[kernel.Evidence]{}, storeErr
			}
			return application.MutationResult[kernel.Evidence]{Resource: stored}, nil
		},
	)
	return result, mapDFIRDatabaseError(err)
}

func sameDFIREvidence(left, right kernel.Evidence) bool {
	leftState, rightState := left.Snapshot(), right.Snapshot()
	if leftState.ID != rightState.ID || leftState.TenantID != rightState.TenantID ||
		leftState.CaseID != rightState.CaseID || leftState.StorageObjectID != rightState.StorageObjectID ||
		leftState.Title != rightState.Title || leftState.Description != rightState.Description ||
		leftState.EvidenceType != rightState.EvidenceType || leftState.Classification != rightState.Classification ||
		leftState.ContentSHA256 != rightState.ContentSHA256 || leftState.SizeBytes != rightState.SizeBytes ||
		leftState.DetectedMIME != rightState.DetectedMIME || !leftState.CollectedAt.Equal(rightState.CollectedAt) ||
		leftState.CollectedBy != rightState.CollectedBy || leftState.Source != rightState.Source ||
		!sameOptionalTime(leftState.RetentionUntil, rightState.RetentionUntil) ||
		!sameOptionalTime(leftState.InitialRetentionUntil, rightState.InitialRetentionUntil) ||
		leftState.LegalHold != rightState.LegalHold || leftState.InitialLegalHold != rightState.InitialLegalHold ||
		leftState.ScanState != rightState.ScanState || leftState.InitialScanState != rightState.InitialScanState ||
		leftState.Sealed != rightState.Sealed || leftState.Destroyed != rightState.Destroyed ||
		leftState.Version != rightState.Version || len(leftState.CustodyEvents) != len(rightState.CustodyEvents) {
		return false
	}
	for index := range leftState.CustodyEvents {
		leftEvent, rightEvent := leftState.CustodyEvents[index], rightState.CustodyEvents[index]
		if leftEvent.ID != rightEvent.ID || leftEvent.TenantID != rightEvent.TenantID ||
			leftEvent.EvidenceID != rightEvent.EvidenceID || leftEvent.Sequence != rightEvent.Sequence ||
			leftEvent.Action != rightEvent.Action || leftEvent.ActorID != rightEvent.ActorID ||
			leftEvent.Reason != rightEvent.Reason || leftEvent.StateValue != rightEvent.StateValue ||
			leftEvent.PreviousHash != rightEvent.PreviousHash || leftEvent.EventHash != rightEvent.EventHash ||
			!leftEvent.OccurredAt.Equal(rightEvent.OccurredAt) {
			return false
		}
	}
	return true
}
