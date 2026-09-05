package postgres

import (
	"context"
	"slices"

	"github.com/google/uuid"

	kernel "github.com/periapsis-im/periapsis/modules/dfir"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	application "github.com/periapsis-im/periapsis/services/api/internal/dfir"
)

func (repository *DFIRRepository) ChangeIndicatorLink(ctx context.Context, write application.SharedResourceLinkWrite) (application.MutationResult[kernel.Indicator], error) {
	coordinate, reservation, err := repository.changeSharedResourceLink(ctx, write, kernel.EntityIOC)
	if err != nil {
		return application.MutationResult[kernel.Indicator]{}, err
	}
	value, err := decodeDFIRIndicatorResult(reservation.snapshot, coordinate)
	return application.MutationResult[kernel.Indicator]{Resource: value, Replayed: reservation.replayed}, err
}

func (repository *DFIRRepository) ChangeAssetLink(ctx context.Context, write application.SharedResourceLinkWrite) (application.MutationResult[kernel.Asset], error) {
	coordinate, reservation, err := repository.changeSharedResourceLink(ctx, write, kernel.EntityAsset)
	if err != nil {
		return application.MutationResult[kernel.Asset]{}, err
	}
	value, err := decodeDFIRAssetResult(reservation.snapshot, coordinate)
	return application.MutationResult[kernel.Asset]{Resource: value, Replayed: reservation.replayed}, err
}

func (repository *DFIRRepository) changeSharedResourceLink(ctx context.Context, write application.SharedResourceLinkWrite, kind kernel.EntityKind) (dfirMutationCoordinate, dfirMutationReservation, error) {
	root := dfirSharedRoot{kind: kernel.EntityCase, id: uuid.UUID(write.CaseID.Bytes())}
	if write.AlertID != (kernel.EntityID{}) {
		if write.CaseID != (kernel.EntityID{}) {
			return dfirMutationCoordinate{}, dfirMutationReservation{}, application.ErrRepositoryForbidden
		}
		root = dfirSharedRoot{kind: kernel.EntityAlert, id: uuid.UUID(write.AlertID.Bytes())}
	}
	operation := "dfir." + string(kind) + ".unlink"
	if write.Linked {
		operation = "dfir." + string(kind) + ".link"
	}
	resourceID, eventID := uuid.UUID(write.ResourceID.Bytes()), uuid.UUID(write.EventID.Bytes())
	coordinate := dfirMutationCoordinate{
		tenantID: write.Actor.TenantID, rootKind: string(root.kind), rootID: root.id, operation: operation,
		resourceKind: string(kind), resourceID: resourceID, secondaryResourceID: &eventID, resultVersion: write.ExpectedVersion + 1,
	}
	if !validDFIRCommand(write.Command, operation) || !validDFIRMutationCoordinate(coordinate) ||
		write.ExpectedVersion == 0 || write.ExpectedVersion >= kernel.MaximumResourceVersion {
		return coordinate, dfirMutationReservation{}, application.ErrRepositoryConflict
	}
	reservation, err := withinTransactionWithOptions(ctx, repository.begin, phase4WriteOptions(), func(tx databaseTransaction) (dfirMutationReservation, error) {
		authority, err := phase4Authority(ctx, tx, dfirAuthorizationActor(write.Actor), coordinate.tenantID)
		if err != nil {
			return dfirMutationReservation{}, err
		}
		if write.Actor.Kind != application.PrincipalHuman {
			return dfirMutationReservation{}, authorization.ErrForbidden
		}
		if err := validateDFIRAuthority(authority, write.Actor); err != nil {
			return dfirMutationReservation{}, err
		}
		capability := application.CapabilityIOCManage
		if kind == kernel.EntityAsset {
			capability = application.CapabilityAssetManage
		}
		roots, err := loadDFIRSharedRoots(ctx, tx, coordinate.tenantID, kind, resourceID, true)
		if err != nil {
			return dfirMutationReservation{}, err
		}
		// A link adds a previously absent path; an unlink replay may have already
		// removed it. Authorize the union before inspecting the receipt.
		authorizationRoots := slices.Clone(roots)
		linked := slices.Contains(roots, root)
		if !linked {
			authorizationRoots = append(authorizationRoots, root)
		}
		slices.SortFunc(authorizationRoots, compareDFIRSharedRoots)
		for _, candidate := range authorizationRoots {
			if _, err := dfirSharedRootAccess(ctx, tx, authority, write.Actor, capability, candidate); err != nil {
				return dfirMutationReservation{}, err
			}
		}
		ids, err := phase4NewIDs(repository.newID, 3)
		if err != nil {
			return dfirMutationReservation{}, err
		}
		reserved, err := reserveDFIRMutationCommand(ctx, tx, ids[0], coordinate, write.Command)
		if err != nil || reserved.replayed {
			return reserved, err
		}
		if write.Linked == linked || (write.Linked && len(roots) >= maximumDFIRSharedRoots) || (!write.Linked && len(roots) < 2) {
			return dfirMutationReservation{}, application.ErrRepositoryConflict
		}
		_, err = tx.Exec(ctx, `SELECT app.change_dfir_shared_link_v1(
			$1, $2, $3, $4, $5, $6::inet, $7, $8)`,
			reserved.commandID, ids[1], ids[2], write.Audit.RequestID, write.Audit.CorrelationID,
			write.Audit.IPAddress, write.Audit.UserAgent, write.Actor.AuthenticationMethod)
		if err != nil {
			return dfirMutationReservation{}, err
		}
		var document []byte
		var version uint64
		if kind == kernel.EntityIOC {
			var resource kernel.Indicator
			resource, version, err = loadDFIRIndicator(ctx, tx, coordinate.tenantID, resourceID)
			if err == nil {
				document, err = encodeDFIRIndicatorResult(coordinate, resource)
			}
		} else {
			var resource kernel.Asset
			resource, version, err = loadDFIRAsset(ctx, tx, coordinate.tenantID, resourceID)
			if err == nil {
				document, err = encodeDFIRAssetResult(coordinate, resource)
			}
		}
		if err != nil {
			return dfirMutationReservation{}, err
		}
		if version != coordinate.resultVersion {
			return dfirMutationReservation{}, unexpectedDFIRProjection("shared link resource version mismatch")
		}
		if err := storeDFIRMutationResult(ctx, tx, reserved.commandID, document); err != nil {
			return dfirMutationReservation{}, err
		}
		reserved.snapshot = document
		return reserved, nil
	})
	return coordinate, reservation, mapDFIRDatabaseError(err)
}

func compareDFIRSharedRoots(left, right dfirSharedRoot) int {
	if left.kind < right.kind {
		return -1
	}
	if left.kind > right.kind {
		return 1
	}
	return slices.Compare(left.id[:], right.id[:])
}

// The primary effect has already written audit/outbox and path activity.
// Additional activity is bound to the same pending immutable command and
// contains only this resource identifier and revision.
func (repository *DFIRRepository) appendSharedResourceActivities(ctx context.Context, tx databaseTransaction, commandID uuid.UUID, base application.BaseWrite, kind kernel.EntityKind, resourceID uuid.UUID) error {
	roots, err := loadDFIRSharedRoots(ctx, tx, base.Actor.TenantID, kind, resourceID, true)
	if err != nil {
		return err
	}
	root := dfirSharedRoot{kind: kernel.EntityCase, id: uuid.UUID(base.CaseID.Bytes())}
	if base.AlertID != (kernel.EntityID{}) {
		root = dfirSharedRoot{kind: kernel.EntityAlert, id: uuid.UUID(base.AlertID.Bytes())}
	}
	if !slices.Contains(roots, root) {
		return authorization.ErrForbidden
	}
	if len(roots) == 1 {
		return nil
	}
	ids, err := phase4NewIDs(repository.newID, len(roots)-1)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `SELECT app.append_shared_dfir_activities_v1($1, $2::uuid[])`, commandID, ids)
	return err
}
