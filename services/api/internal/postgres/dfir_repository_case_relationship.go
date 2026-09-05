package postgres

import (
	"bytes"
	"context"

	"github.com/google/uuid"

	kernel "github.com/periapsis-im/periapsis/modules/dfir"
	application "github.com/periapsis-im/periapsis/services/api/internal/dfir"
)

// MutateRelationship terminally retracts one Case-rooted relationship. Live
// Case authority and both current endpoints are checked before receipt replay;
// a fresh command then locks and compare-and-swaps the immutable aggregate.
func (repository *DFIRRepository) MutateRelationship(
	ctx context.Context,
	write application.RelationshipMutationWrite,
) (application.MutationResult[kernel.Relationship], error) {
	if repository == nil || repository.begin == nil || repository.newID == nil || write.Apply == nil ||
		!validDFIRCommand(write.Command, "dfir.relationship.retract") ||
		write.CaseID == (kernel.EntityID{}) || write.AlertID != (kernel.EntityID{}) ||
		write.RelationshipID == (kernel.EntityID{}) || write.RetractionID == (kernel.EntityID{}) ||
		write.ExpectedVersion == 0 || write.ExpectedVersion >= kernel.MaximumResourceVersion ||
		write.Actor.TenantID == uuid.Nil || write.Actor.MembershipID == uuid.Nil {
		return application.MutationResult[kernel.Relationship]{}, application.ErrRepositoryPrecondition
	}
	tenantID := write.Actor.TenantID
	caseID := uuid.UUID(write.CaseID.Bytes())
	relationshipID := uuid.UUID(write.RelationshipID.Bytes())
	retractionID := uuid.UUID(write.RetractionID.Bytes())
	coordinate := dfirMutationCoordinate{
		tenantID: tenantID, rootKind: dfirMutationRootCase, rootID: caseID,
		operation: "dfir.relationship.retract", resourceKind: dfirMutationKindRelationship,
		resourceID: relationshipID, secondaryResourceID: &retractionID,
		resultVersion: write.ExpectedVersion + 1,
	}
	if !validDFIRMutationCoordinate(coordinate) {
		return application.MutationResult[kernel.Relationship]{}, application.ErrRepositoryPrecondition
	}

	result, err := withinTransactionWithOptions(
		ctx, repository.begin, phase4WriteOptions(),
		func(tx databaseTransaction) (application.MutationResult[kernel.Relationship], error) {
			if _, accessErr := authorizeDFIRWrite(
				ctx, tx, write.Actor, tenantID, application.CapabilityRelationshipManage, caseID,
			); accessErr != nil {
				return application.MutationResult[kernel.Relationship]{}, accessErr
			}
			live, loadErr := loadDFIRRelationship(ctx, tx, tenantID, caseID, relationshipID)
			if loadErr != nil {
				return application.MutationResult[kernel.Relationship]{}, loadErr
			}
			if endpointErr := validateDFIRRelationshipEndpoints(
				ctx, tx, write.Actor, tenantID, dfirMutationRootCase, caseID,
				live.Source(), live.Target(),
			); endpointErr != nil {
				return application.MutationResult[kernel.Relationship]{}, endpointErr
			}

			ids, idErr := phase4NewIDs(repository.newID, 4)
			if idErr != nil {
				return application.MutationResult[kernel.Relationship]{}, idErr
			}
			reservation, reserveErr := reserveDFIRMutationCommand(ctx, tx, ids[0], coordinate, write.Command)
			if reserveErr != nil {
				return application.MutationResult[kernel.Relationship]{}, reserveErr
			}
			if reservation.replayed {
				historical, decodeErr := decodeDFIRRelationshipResult(reservation.snapshot, coordinate)
				if decodeErr != nil {
					return application.MutationResult[kernel.Relationship]{}, decodeErr
				}
				return application.MutationResult[kernel.Relationship]{Resource: historical, Replayed: true}, nil
			}

			var lockedVersion int64
			if lockErr := tx.QueryRow(ctx, `SELECT version FROM public.dfir_relationships
				WHERE tenant_id=$1 AND case_id=$2 AND alert_id IS NULL AND id=$3 FOR UPDATE`,
				tenantID, caseID, relationshipID,
			).Scan(&lockedVersion); lockErr != nil {
				return application.MutationResult[kernel.Relationship]{}, lockErr
			}
			current, loadErr := loadDFIRRelationship(ctx, tx, tenantID, caseID, relationshipID)
			if loadErr != nil {
				return application.MutationResult[kernel.Relationship]{}, loadErr
			}
			if lockedVersion != int64(write.ExpectedVersion) || current.Version() != write.ExpectedVersion {
				return application.MutationResult[kernel.Relationship]{}, application.ErrRepositoryPrecondition
			}
			updated, applyErr := write.Apply(current)
			if applyErr != nil {
				return application.MutationResult[kernel.Relationship]{}, applyErr
			}
			if !validCaseRelationshipRetraction(current, updated, write) {
				return application.MutationResult[kernel.Relationship]{}, application.ErrRepositoryConflict
			}
			retraction := updated.Retractions()[0]
			if mutationErr := retractCaseRelationship(
				ctx, tx, reservation.commandID, caseID, updated, retraction, write.ExpectedVersion,
			); mutationErr != nil {
				return application.MutationResult[kernel.Relationship]{}, mutationErr
			}
			stored, loadErr := loadDFIRRelationship(ctx, tx, tenantID, caseID, relationshipID)
			if loadErr != nil || !sameDFIRRelationship(stored, updated) {
				if loadErr != nil {
					return application.MutationResult[kernel.Relationship]{}, loadErr
				}
				return application.MutationResult[kernel.Relationship]{}, unexpectedDFIRProjection("divergent Case relationship after retraction")
			}
			kind := string(kernel.EntityCase)
			if effectErr := appendDFIRMutationEffects(
				ctx, tx, write.BaseWrite, ids[1:], phase4MutationEffects{
					PermissionKey: string(application.CapabilityRelationshipManage),
					Action:        "dfir.relationship.retracted", ResourceType: "dfir_relationship",
					ResourceID: relationshipID, ResourceVersion: int64(stored.Version()),
					CaseID: &caseID, ActivityResourceKind: &kind, ActivityResourceID: &caseID,
					Summary: "DFIR relationship retracted",
					Before:  caseRelationshipJournal(current), After: caseRelationshipJournal(stored),
					Metadata: map[string]any{
						"commandOperation": write.Command.Operation,
						"retractionId":     retraction.ID.String(),
						"reason":           retraction.Reason,
					},
				},
			); effectErr != nil {
				return application.MutationResult[kernel.Relationship]{}, effectErr
			}
			document, snapshotErr := encodeDFIRRelationshipResult(coordinate, stored)
			if snapshotErr != nil {
				return application.MutationResult[kernel.Relationship]{}, snapshotErr
			}
			if storeErr := storeDFIRMutationResult(ctx, tx, reservation.commandID, document); storeErr != nil {
				return application.MutationResult[kernel.Relationship]{}, storeErr
			}
			return application.MutationResult[kernel.Relationship]{Resource: stored}, nil
		},
	)
	return result, mapDFIRDatabaseError(err)
}

func retractCaseRelationship(
	ctx context.Context,
	tx databaseTransaction,
	commandID uuid.UUID,
	caseID uuid.UUID,
	value kernel.Relationship,
	retraction kernel.RelationshipRetractionState,
	expectedVersion uint64,
) error {
	var returnedID uuid.UUID
	var returnedVersion int64
	err := tx.QueryRow(ctx, `SELECT relationship_id, relationship_version
		FROM app.retract_case_dfir_relationship_v1($1,$2,$3,$4,$5,$6,$7)`,
		commandID, uuid.UUID(value.ID().Bytes()),
		caseID, int64(expectedVersion), uuid.UUID(retraction.ID.Bytes()),
		retraction.Reason, retraction.OccurredAt,
	).Scan(&returnedID, &returnedVersion)
	if err != nil {
		return err
	}
	if returnedID != uuid.UUID(value.ID().Bytes()) || returnedVersion != int64(value.Version()) {
		return unexpectedDFIRProjection("Case relationship retraction result mismatch")
	}
	return nil
}

func validCaseRelationshipRetraction(
	current kernel.Relationship,
	updated kernel.Relationship,
	write application.RelationshipMutationWrite,
) bool {
	if current.ID() != updated.ID() || current.ID() != write.RelationshipID ||
		current.TenantID() != updated.TenantID() || current.Source() != updated.Source() ||
		current.Target() != updated.Target() || current.RelationshipType() != updated.RelationshipType() ||
		!bytes.Equal(current.Metadata(), updated.Metadata()) || current.CreatedBy() != updated.CreatedBy() ||
		!current.CreatedAt().Equal(updated.CreatedAt()) || !current.Active() || updated.Active() ||
		current.Version() != write.ExpectedVersion || updated.Version() != write.ExpectedVersion+1 ||
		len(current.Retractions()) != 0 || len(updated.Retractions()) != 1 {
		return false
	}
	retraction := updated.Retractions()[0]
	return retraction.ID == write.RetractionID && retraction.TenantID == current.TenantID() &&
		retraction.RelationshipID == current.ID() && retraction.Sequence == 1 &&
		retraction.ActorID.String() == write.Actor.MembershipID.String()
}

func caseRelationshipJournal(value kernel.Relationship) map[string]any {
	return map[string]any{
		"version": value.Version(), "active": value.Active(),
		"relationshipType": value.RelationshipType(), "retractionCount": len(value.Retractions()),
	}
}
