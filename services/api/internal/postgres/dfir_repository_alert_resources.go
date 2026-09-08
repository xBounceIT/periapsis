package postgres

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	kernel "github.com/periapsis-im/periapsis/modules/dfir"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	application "github.com/periapsis-im/periapsis/services/api/internal/dfir"
)

func (repository *DFIRRepository) writeAlertIndicator(
	ctx context.Context,
	write application.IndicatorWrite,
	replace bool,
) (application.MutationResult[kernel.Indicator], error) {
	tenantID := uuid.UUID(write.Indicator.TenantID().Bytes())
	alertID := uuid.UUID(write.AlertID.Bytes())
	id := uuid.UUID(write.Indicator.ID().Bytes())
	result, err := withinTransactionWithOptions(
		ctx, repository.begin, phase4WriteOptions(),
		func(tx databaseTransaction) (application.MutationResult[kernel.Indicator], error) {
			if _, accessErr := authorizeDFIRAlertWrite(
				ctx, tx, write.Actor, tenantID, application.CapabilityIOCManage, alertID,
			); accessErr != nil {
				return application.MutationResult[kernel.Indicator]{}, accessErr
			}
			root := dfirSharedRoot{kind: kernel.EntityAlert, id: alertID}
			if replace {
				if _, accessErr := authorizeDFIRSharedMutation(ctx, tx, write.Actor, tenantID, kernel.EntityIOC, id, root); accessErr != nil {
					return application.MutationResult[kernel.Indicator]{}, accessErr
				}
			}
			idsNeeded := 4
			if !replace {
				idsNeeded++
			}
			ids, idErr := phase4NewIDs(repository.newID, idsNeeded)
			if idErr != nil {
				return application.MutationResult[kernel.Indicator]{}, idErr
			}
			resultVersion := uint64(1)
			if replace {
				resultVersion = write.ExpectedVersion + 1
			}
			coordinate := dfirMutationCoordinate{
				tenantID: tenantID, rootKind: dfirMutationRootAlert, rootID: alertID, operation: write.Command.Operation,
				resourceKind: dfirMutationKindIOC, resourceID: id, resultVersion: resultVersion,
			}
			reservation, reserveErr := reserveDFIRMutationCommand(ctx, tx, ids[0], coordinate, write.Command)
			if reserveErr != nil {
				return application.MutationResult[kernel.Indicator]{}, reserveErr
			}
			if reservation.replayed {
				if !replace {
					if _, accessErr := authorizeDFIRSharedMutation(ctx, tx, write.Actor, tenantID, kernel.EntityIOC, id, root); accessErr != nil {
						return application.MutationResult[kernel.Indicator]{}, accessErr
					}
				}
				historical, decodeErr := decodeDFIRIndicatorResult(reservation.snapshot, coordinate)
				if decodeErr != nil {
					return application.MutationResult[kernel.Indicator]{}, decodeErr
				}
				return application.MutationResult[kernel.Indicator]{Resource: historical, Replayed: true}, nil
			}
			current, currentVersion, loadErr := loadDFIRIndicator(ctx, tx, tenantID, id)
			if loadErr == nil {
				if !replace {
					return application.MutationResult[kernel.Indicator]{}, application.ErrRepositoryConflict
				}
				linked, linkErr := dfirResourceLinkedToAlert(
					ctx, tx, "public.dfir_ioc_links", "ioc_id", tenantID, alertID, id,
				)
				if linkErr != nil {
					return application.MutationResult[kernel.Indicator]{}, linkErr
				}
				if !linked {
					return application.MutationResult[kernel.Indicator]{}, authorization.ErrForbidden
				}
				if currentVersion != write.ExpectedVersion {
					return application.MutationResult[kernel.Indicator]{}, application.ErrRepositoryPrecondition
				}
			} else if !errors.Is(loadErr, pgx.ErrNoRows) {
				return application.MutationResult[kernel.Indicator]{}, loadErr
			} else if replace {
				return application.MutationResult[kernel.Indicator]{}, pgx.ErrNoRows
			}

			if replace {
				if updateErr := updateDFIRIndicator(ctx, tx, write); updateErr != nil {
					return application.MutationResult[kernel.Indicator]{}, updateErr
				}
			} else {
				if insertErr := insertDFIRIndicator(ctx, tx, write); insertErr != nil {
					return application.MutationResult[kernel.Indicator]{}, insertErr
				}
				if _, linkErr := tx.Exec(ctx, `INSERT INTO public.dfir_ioc_links
					(id, tenant_id, ioc_id, alert_id, created_by_membership_id)
					VALUES ($1, $2, $3, $4, $5)`, ids[4], tenantID, id, alertID, write.Actor.MembershipID); linkErr != nil {
					return application.MutationResult[kernel.Indicator]{}, linkErr
				}
			}
			action := "dfir.ioc.created"
			before := map[string]any{}
			if replace {
				action = "dfir.ioc.replaced"
				before = dfirIndicatorJournal(current, currentVersion)
			}
			if effectErr := appendAlertDFIRMutationEffects(ctx, tx, write.BaseWrite, alertID, alertDFIRMutationEffect{
				PermissionKey: "dfir.ioc.manage", Action: action, ResourceType: "dfir_ioc",
				ResourceID: id, ResourceVersion: int64(resultVersion), ActivityID: ids[1],
				Before: before, After: dfirIndicatorJournal(write.Indicator, uint64(resultVersion)),
				Metadata:     map[string]any{"commandOperation": write.Command.Operation, "rootKind": "alert"},
				AuditEventID: ids[2], OutboxEventID: ids[3],
			}); effectErr != nil {
				return application.MutationResult[kernel.Indicator]{}, effectErr
			}
			stored, storedVersion, storedErr := loadDFIRIndicator(ctx, tx, tenantID, id)
			if storedErr != nil || storedVersion != resultVersion || !sameDFIRIndicator(stored, write.Indicator) {
				if storedErr != nil {
					return application.MutationResult[kernel.Indicator]{}, storedErr
				}
				return application.MutationResult[kernel.Indicator]{}, unexpectedDFIRProjection("divergent Alert IOC after mutation")
			}
			if activityErr := repository.appendSharedResourceActivities(ctx, tx, reservation.commandID, write.BaseWrite, kernel.EntityIOC, id); activityErr != nil {
				return application.MutationResult[kernel.Indicator]{}, activityErr
			}
			document, snapshotErr := encodeDFIRIndicatorResult(coordinate, stored)
			if snapshotErr != nil {
				return application.MutationResult[kernel.Indicator]{}, snapshotErr
			}
			if storeErr := storeDFIRMutationResult(ctx, tx, reservation.commandID, document); storeErr != nil {
				return application.MutationResult[kernel.Indicator]{}, storeErr
			}
			return application.MutationResult[kernel.Indicator]{Resource: stored}, nil
		},
	)
	return result, mapDFIRDatabaseError(err)
}

func (repository *DFIRRepository) writeAlertAsset(
	ctx context.Context,
	write application.AssetWrite,
	replace bool,
) (application.MutationResult[kernel.Asset], error) {
	tenantID := uuid.UUID(write.Asset.TenantID().Bytes())
	alertID := uuid.UUID(write.AlertID.Bytes())
	id := uuid.UUID(write.Asset.ID().Bytes())
	result, err := withinTransactionWithOptions(
		ctx, repository.begin, phase4WriteOptions(),
		func(tx databaseTransaction) (application.MutationResult[kernel.Asset], error) {
			if _, accessErr := authorizeDFIRAlertWrite(
				ctx, tx, write.Actor, tenantID, application.CapabilityAssetManage, alertID,
			); accessErr != nil {
				return application.MutationResult[kernel.Asset]{}, accessErr
			}
			root := dfirSharedRoot{kind: kernel.EntityAlert, id: alertID}
			if replace {
				if _, accessErr := authorizeDFIRSharedMutation(ctx, tx, write.Actor, tenantID, kernel.EntityAsset, id, root); accessErr != nil {
					return application.MutationResult[kernel.Asset]{}, accessErr
				}
			}
			idsNeeded := 4
			if !replace {
				idsNeeded++
			}
			ids, idErr := phase4NewIDs(repository.newID, idsNeeded)
			if idErr != nil {
				return application.MutationResult[kernel.Asset]{}, idErr
			}
			resultVersion := uint64(1)
			if replace {
				resultVersion = write.ExpectedVersion + 1
			}
			coordinate := dfirMutationCoordinate{
				tenantID: tenantID, rootKind: dfirMutationRootAlert, rootID: alertID, operation: write.Command.Operation,
				resourceKind: dfirMutationKindAsset, resourceID: id, resultVersion: resultVersion,
			}
			reservation, reserveErr := reserveDFIRMutationCommand(ctx, tx, ids[0], coordinate, write.Command)
			if reserveErr != nil {
				return application.MutationResult[kernel.Asset]{}, reserveErr
			}
			if reservation.replayed {
				if !replace {
					if _, accessErr := authorizeDFIRSharedMutation(ctx, tx, write.Actor, tenantID, kernel.EntityAsset, id, root); accessErr != nil {
						return application.MutationResult[kernel.Asset]{}, accessErr
					}
				}
				historical, decodeErr := decodeDFIRAssetResult(reservation.snapshot, coordinate)
				if decodeErr != nil {
					return application.MutationResult[kernel.Asset]{}, decodeErr
				}
				return application.MutationResult[kernel.Asset]{Resource: historical, Replayed: true}, nil
			}
			current, currentVersion, loadErr := loadDFIRAsset(ctx, tx, tenantID, id)
			if loadErr == nil {
				if !replace {
					return application.MutationResult[kernel.Asset]{}, application.ErrRepositoryConflict
				}
				linked, linkErr := dfirResourceLinkedToAlert(
					ctx, tx, "public.dfir_asset_links", "asset_id", tenantID, alertID, id,
				)
				if linkErr != nil {
					return application.MutationResult[kernel.Asset]{}, linkErr
				}
				if !linked {
					return application.MutationResult[kernel.Asset]{}, authorization.ErrForbidden
				}
				if currentVersion != write.ExpectedVersion {
					return application.MutationResult[kernel.Asset]{}, application.ErrRepositoryPrecondition
				}
			} else if !errors.Is(loadErr, pgx.ErrNoRows) {
				return application.MutationResult[kernel.Asset]{}, loadErr
			} else if replace {
				return application.MutationResult[kernel.Asset]{}, pgx.ErrNoRows
			}
			if replace {
				if updateErr := updateDFIRAsset(ctx, tx, write); updateErr != nil {
					return application.MutationResult[kernel.Asset]{}, updateErr
				}
			} else {
				if insertErr := insertDFIRAsset(ctx, tx, write); insertErr != nil {
					return application.MutationResult[kernel.Asset]{}, insertErr
				}
				if _, linkErr := tx.Exec(ctx, `INSERT INTO public.dfir_asset_links
					(id, tenant_id, asset_id, alert_id, created_by_membership_id)
					VALUES ($1, $2, $3, $4, $5)`, ids[4], tenantID, id, alertID, write.Actor.MembershipID); linkErr != nil {
					return application.MutationResult[kernel.Asset]{}, linkErr
				}
			}
			action := "dfir.asset.created"
			before := map[string]any{}
			if replace {
				action = "dfir.asset.replaced"
				before = dfirAssetJournal(current, currentVersion)
			}
			if effectErr := appendAlertDFIRMutationEffects(ctx, tx, write.BaseWrite, alertID, alertDFIRMutationEffect{
				PermissionKey: "dfir.asset.manage", Action: action, ResourceType: "dfir_asset",
				ResourceID: id, ResourceVersion: int64(resultVersion), ActivityID: ids[1],
				Before: before, After: dfirAssetJournal(write.Asset, uint64(resultVersion)),
				Metadata:     map[string]any{"commandOperation": write.Command.Operation, "rootKind": "alert"},
				AuditEventID: ids[2], OutboxEventID: ids[3],
			}); effectErr != nil {
				return application.MutationResult[kernel.Asset]{}, effectErr
			}
			stored, storedVersion, storedErr := loadDFIRAsset(ctx, tx, tenantID, id)
			if storedErr != nil || storedVersion != resultVersion || !sameDFIRAsset(stored, write.Asset) {
				if storedErr != nil {
					return application.MutationResult[kernel.Asset]{}, storedErr
				}
				return application.MutationResult[kernel.Asset]{}, unexpectedDFIRProjection("divergent Alert asset after mutation")
			}
			if activityErr := repository.appendSharedResourceActivities(ctx, tx, reservation.commandID, write.BaseWrite, kernel.EntityAsset, id); activityErr != nil {
				return application.MutationResult[kernel.Asset]{}, activityErr
			}
			document, snapshotErr := encodeDFIRAssetResult(coordinate, stored)
			if snapshotErr != nil {
				return application.MutationResult[kernel.Asset]{}, snapshotErr
			}
			if storeErr := storeDFIRMutationResult(ctx, tx, reservation.commandID, document); storeErr != nil {
				return application.MutationResult[kernel.Asset]{}, storeErr
			}
			return application.MutationResult[kernel.Asset]{Resource: stored}, nil
		},
	)
	return result, mapDFIRDatabaseError(err)
}

func (repository *DFIRRepository) createAlertTimelineEvent(
	ctx context.Context,
	write application.TimelineWrite,
) (application.MutationResult[kernel.TimelineEvent], error) {
	tenantID := uuid.UUID(write.Event.TenantID().Bytes())
	alertID := uuid.UUID(write.AlertID.Bytes())
	id := uuid.UUID(write.Event.ID().Bytes())
	result, err := withinTransactionWithOptions(
		ctx, repository.begin, phase4WriteOptions(),
		func(tx databaseTransaction) (application.MutationResult[kernel.TimelineEvent], error) {
			if _, accessErr := authorizeDFIRAlertWrite(
				ctx, tx, write.Actor, tenantID, application.CapabilityTimelineManage, alertID,
			); accessErr != nil {
				return application.MutationResult[kernel.TimelineEvent]{}, accessErr
			}
			if linkErr := validateAlertTimelineLinks(ctx, tx, tenantID, alertID, write.Event); linkErr != nil {
				return application.MutationResult[kernel.TimelineEvent]{}, linkErr
			}
			ids, idErr := phase4NewIDs(repository.newID, 4)
			if idErr != nil {
				return application.MutationResult[kernel.TimelineEvent]{}, idErr
			}
			coordinate := dfirMutationCoordinate{
				tenantID: tenantID, rootKind: dfirMutationRootAlert, rootID: alertID, operation: write.Command.Operation,
				resourceKind: dfirMutationKindTimeline, resourceID: id, resultVersion: 1,
			}
			reservation, reserveErr := reserveDFIRMutationCommand(ctx, tx, ids[0], coordinate, write.Command)
			if reserveErr != nil {
				return application.MutationResult[kernel.TimelineEvent]{}, reserveErr
			}
			if reservation.replayed {
				historical, decodeErr := decodeDFIRTimelineResult(reservation.snapshot, coordinate)
				if decodeErr != nil {
					return application.MutationResult[kernel.TimelineEvent]{}, decodeErr
				}
				return application.MutationResult[kernel.TimelineEvent]{Resource: historical, Replayed: true}, nil
			}
			_, _, loadErr := loadDFIRTimelineEvent(ctx, tx, tenantID, id)
			if loadErr == nil {
				return application.MutationResult[kernel.TimelineEvent]{}, application.ErrRepositoryConflict
			}
			if !errors.Is(loadErr, pgx.ErrNoRows) {
				return application.MutationResult[kernel.TimelineEvent]{}, loadErr
			}
			if insertErr := insertDFIRTimelineEvent(ctx, tx, write); insertErr != nil {
				return application.MutationResult[kernel.TimelineEvent]{}, insertErr
			}
			if linkErr := insertDFIRTimelineLinks(ctx, tx, write.Event); linkErr != nil {
				return application.MutationResult[kernel.TimelineEvent]{}, linkErr
			}
			if effectErr := appendAlertDFIRMutationEffects(ctx, tx, write.BaseWrite, alertID, alertDFIRMutationEffect{
				PermissionKey: "dfir.timeline.manage", Action: "dfir.timeline.created",
				ResourceType: "dfir_timeline_event", ResourceID: id, ResourceVersion: 1,
				ActivityID: ids[1], Before: map[string]any{}, After: dfirTimelineJournal(write.Event),
				Metadata:     map[string]any{"commandOperation": write.Command.Operation, "rootKind": "alert"},
				AuditEventID: ids[2], OutboxEventID: ids[3],
			}); effectErr != nil {
				return application.MutationResult[kernel.TimelineEvent]{}, effectErr
			}
			stored, version, storedErr := loadDFIRTimelineEvent(ctx, tx, tenantID, id)
			if storedErr != nil || version != 1 || !sameDFIRTimelineEvent(stored, write.Event) {
				if storedErr != nil {
					return application.MutationResult[kernel.TimelineEvent]{}, storedErr
				}
				return application.MutationResult[kernel.TimelineEvent]{}, unexpectedDFIRProjection("divergent Alert timeline after create")
			}
			document, snapshotErr := encodeDFIRTimelineResult(coordinate, stored)
			if snapshotErr != nil {
				return application.MutationResult[kernel.TimelineEvent]{}, snapshotErr
			}
			if storeErr := storeDFIRMutationResult(ctx, tx, reservation.commandID, document); storeErr != nil {
				return application.MutationResult[kernel.TimelineEvent]{}, storeErr
			}
			return application.MutationResult[kernel.TimelineEvent]{Resource: stored}, nil
		},
	)
	return result, mapDFIRDatabaseError(err)
}

func (repository *DFIRRepository) createAlertStorageObject(
	ctx context.Context,
	write application.StorageWrite,
) (application.PreparedUploadRecord, error) {
	tenantID := uuid.UUID(write.Storage.TenantID().Bytes())
	alertID := uuid.UUID(write.AlertID.Bytes())
	storageID := uuid.UUID(write.Storage.ID().Bytes())
	attachmentID := uuid.UUID(write.Attachment.ID().Bytes())
	result, err := withinTransactionWithOptions(
		ctx, repository.begin, phase4WriteOptions(),
		func(tx databaseTransaction) (application.PreparedUploadRecord, error) {
			authority, authorityErr := phase4Authority(ctx, tx, dfirAuthorizationActor(write.Actor), tenantID)
			if authorityErr != nil {
				return application.PreparedUploadRecord{}, authorityErr
			}
			if err := validateDFIRAuthority(authority, write.Actor); err != nil || write.Actor.Kind != application.PrincipalHuman {
				if err != nil {
					return application.PreparedUploadRecord{}, err
				}
				return application.PreparedUploadRecord{}, authorization.ErrForbidden
			}
			sharedRoots, sharedErr := authorizeDFIRSharedAttachment(ctx, tx, authority, write)
			if sharedErr != nil {
				return application.PreparedUploadRecord{}, sharedErr
			}
			inheritedVisibility, subjectErr := resolveDFIRAlertSubject(
				ctx, tx, tenantID, alertID, write.Attachment.Subject(),
			)
			if subjectErr != nil || write.Attachment.Visibility() == kernel.VisibilityPublic && inheritedVisibility == kernel.VisibilityPrivate {
				if subjectErr != nil {
					return application.PreparedUploadRecord{}, subjectErr
				}
				return application.PreparedUploadRecord{}, authorization.ErrForbidden
			}
			access, accessErr := dfirAccessForAlert(
				ctx, tx, authority, write.Actor, application.CapabilityAttachmentManage, alertID,
			)
			if accessErr != nil || access.Audience != kernel.AudienceOperator {
				if accessErr != nil {
					return application.PreparedUploadRecord{}, accessErr
				}
				return application.PreparedUploadRecord{}, authorization.ErrForbidden
			}
			if traceErr := installPersistedTraceContext(ctx, tx); traceErr != nil {
				return application.PreparedUploadRecord{}, traceErr
			}
			ids, idErr := phase4NewIDs(repository.newID, 5)
			if idErr != nil {
				return application.PreparedUploadRecord{}, idErr
			}
			coordinate := dfirMutationCoordinate{
				tenantID: tenantID, rootKind: dfirMutationRootAlert, rootID: alertID, operation: write.Command.Operation,
				resourceKind: dfirMutationKindStorage, resourceID: storageID,
				secondaryResourceID: &attachmentID, resultVersion: 1,
			}
			reservation, reserveErr := reserveDFIRMutationCommand(ctx, tx, ids[0], coordinate, write.Command)
			if reserveErr != nil {
				return application.PreparedUploadRecord{}, reserveErr
			}
			if reservation.replayed {
				receipt, historicalAttachment, decodeErr := decodeDFIRPreparedUploadResult(reservation.snapshot, coordinate)
				if decodeErr != nil {
					return application.PreparedUploadRecord{}, decodeErr
				}
				storedObject, storageErr := loadDFIRStorageObject(ctx, tx, tenantID, storageID)
				storedAttachment, attachmentErr := loadDFIRAlertAttachment(ctx, tx, tenantID, alertID, attachmentID)
				attachmentVersion, versionErr := loadDFIRAttachmentVersion(ctx, tx, tenantID, attachmentID)
				if storageErr != nil || attachmentErr != nil || versionErr != nil {
					if storageErr != nil {
						return application.PreparedUploadRecord{}, storageErr
					}
					if attachmentErr != nil {
						return application.PreparedUploadRecord{}, attachmentErr
					}
					return application.PreparedUploadRecord{}, versionErr
				}
				if !validDFIRPreparedUploadReplay(receipt, historicalAttachment, storedObject, storedAttachment,
					attachmentVersion, write, write.Storage.CreatedAt()) {
					return application.PreparedUploadRecord{}, application.ErrRepositoryConflict
				}
				return application.PreparedUploadRecord{Storage: storedObject, Attachment: historicalAttachment, Replayed: true}, nil
			}
			if insertErr := insertDFIRStorageObject(ctx, tx, write); insertErr != nil {
				return application.PreparedUploadRecord{}, insertErr
			}
			if insertErr := insertDFIRAttachment(ctx, tx, write); insertErr != nil {
				return application.PreparedUploadRecord{}, insertErr
			}
			if effectErr := appendAlertDFIRMutationEffects(ctx, tx, write.BaseWrite, alertID, alertDFIRMutationEffect{
				PermissionKey: "dfir.attachment.manage", Action: "dfir.attachment.prepared",
				ResourceType: "dfir_storage_object", ResourceID: storageID, ResourceVersion: 1,
				ActivityID: ids[1], Before: map[string]any{}, After: map[string]any{
					"storageVersion": 1, "attachmentVersion": 1,
					"classification": write.Storage.Classification(), "visibility": write.Attachment.Visibility(),
					"scanState": write.Storage.State(),
				}, Metadata: map[string]any{
					"commandOperation": write.Command.Operation, "rootKind": "alert", "objectLocationRedacted": true,
				}, AuditEventID: ids[2], OutboxEventID: ids[3],
			}); effectErr != nil {
				return application.PreparedUploadRecord{}, effectErr
			}
			if effectErr := repository.appendSharedAttachmentActivities(ctx, tx, reservation.commandID, sharedRoots); effectErr != nil {
				return application.PreparedUploadRecord{}, effectErr
			}
			if enqueueErr := enqueueDFIRStorageScan(ctx, tx, write, ids[4], ids[3]); enqueueErr != nil {
				return application.PreparedUploadRecord{}, enqueueErr
			}
			storedObject, storageErr := loadDFIRStorageObject(ctx, tx, tenantID, storageID)
			storedAttachment, attachmentErr := loadDFIRAlertAttachment(ctx, tx, tenantID, alertID, attachmentID)
			if storageErr != nil || attachmentErr != nil || !sameDFIRStorageObject(storedObject, write.Storage) ||
				!sameDFIRAttachment(storedAttachment, write.Attachment) {
				if storageErr != nil {
					return application.PreparedUploadRecord{}, storageErr
				}
				if attachmentErr != nil {
					return application.PreparedUploadRecord{}, attachmentErr
				}
				return application.PreparedUploadRecord{}, unexpectedDFIRProjection("divergent Alert prepared upload")
			}
			document, snapshotErr := encodeDFIRPreparedUploadResult(coordinate, storedObject, storedAttachment)
			if snapshotErr != nil {
				return application.PreparedUploadRecord{}, snapshotErr
			}
			if storeErr := storeDFIRMutationResult(ctx, tx, reservation.commandID, document); storeErr != nil {
				return application.PreparedUploadRecord{}, storeErr
			}
			return application.PreparedUploadRecord{Storage: storedObject, Attachment: storedAttachment}, nil
		},
	)
	return result, mapDFIRDatabaseError(err)
}

func authorizeDFIRAlertWrite(
	ctx context.Context,
	tx databaseTransaction,
	actor application.Actor,
	tenantID uuid.UUID,
	capability application.Capability,
	alertID uuid.UUID,
) (application.Access, error) {
	if actor.TenantID != tenantID || actor.Kind != application.PrincipalHuman || !authorizationUUIDv7(alertID) {
		return application.Access{}, authorization.ErrForbidden
	}
	authority, err := phase4Authority(ctx, tx, dfirAuthorizationActor(actor), tenantID)
	if err != nil {
		return application.Access{}, err
	}
	if err = validateDFIRAuthority(authority, actor); err != nil {
		return application.Access{}, err
	}
	access, err := dfirAccessForAlert(ctx, tx, authority, actor, capability, alertID)
	if err != nil {
		return application.Access{}, err
	}
	if err = installPersistedTraceContext(ctx, tx); err != nil {
		return application.Access{}, err
	}
	return access, nil
}

type alertDFIRMutationEffect struct {
	PermissionKey   string
	Action          string
	ResourceType    string
	ResourceID      uuid.UUID
	ResourceVersion int64
	ActivityID      uuid.UUID
	Before          any
	After           any
	Metadata        any
	AuditEventID    uuid.UUID
	OutboxEventID   uuid.UUID
}

func appendAlertDFIRMutationEffects(
	ctx context.Context,
	tx databaseTransaction,
	base application.BaseWrite,
	alertID uuid.UUID,
	effect alertDFIRMutationEffect,
) error {
	before, err := phase4JSON(effect.Before)
	if err != nil {
		return err
	}
	after, err := phase4JSON(effect.After)
	if err != nil {
		return err
	}
	metadata, err := phase4JSON(effect.Metadata)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		SELECT app.append_alert_dfir_mutation_effects_v1(
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
			$11::jsonb, $12::jsonb, $13::jsonb, $14, $15,
			$16, $17, $18::inet, $19, $20
		)`, alertID, effect.PermissionKey, effect.Action, effect.ResourceType,
		effect.ResourceID, effect.ResourceVersion, base.Command.Operation,
		base.Command.KeyDigest[:], base.Command.RequestDigest[:], effect.ActivityID,
		before, after, metadata, effect.AuditEventID, effect.OutboxEventID,
		base.Audit.RequestID, base.Audit.CorrelationID, base.Audit.IPAddress,
		base.Audit.UserAgent, base.Actor.AuthenticationMethod,
	)
	return err
}

func dfirResourceLinkedToAlert(
	ctx context.Context,
	tx databaseTransaction,
	table string,
	resourceColumn string,
	tenantID uuid.UUID,
	alertID uuid.UUID,
	resourceID uuid.UUID,
) (bool, error) {
	var exists bool
	err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM "+table+" WHERE tenant_id = $1 AND alert_id = $2 AND "+resourceColumn+" = $3)",
		tenantID, alertID, resourceID).Scan(&exists)
	return exists, err
}

func validateAlertTimelineLinks(
	ctx context.Context,
	tx databaseTransaction,
	tenantID uuid.UUID,
	alertID uuid.UUID,
	event kernel.TimelineEvent,
) error {
	for _, candidate := range []struct {
		linkTable, resourceTable, column, livePredicate string
		ids                                             []kernel.EntityID
	}{
		{linkTable: "public.dfir_ioc_links", resourceTable: "public.dfir_iocs", column: "ioc_id", livePredicate: "resource.archived_at IS NULL", ids: event.IOCIDs()},
		{linkTable: "public.dfir_asset_links", resourceTable: "public.dfir_assets", column: "asset_id", livePredicate: "resource.archived_at IS NULL", ids: event.AssetIDs()},
	} {
		if len(candidate.ids) == 0 {
			continue
		}
		ids := kernelUUIDs(candidate.ids)
		var count int64
		err := tx.QueryRow(ctx, "SELECT count(DISTINCT link."+candidate.column+") FROM "+candidate.linkTable+" AS link"+
			" JOIN "+candidate.resourceTable+" AS resource ON resource.tenant_id = link.tenant_id AND resource.id = link."+candidate.column+
			" WHERE link.tenant_id = $1 AND link.alert_id = $2 AND link."+candidate.column+" = ANY($3::uuid[])"+
			" AND "+candidate.livePredicate,
			tenantID, alertID, ids).Scan(&count)
		if err != nil {
			return err
		}
		if count != int64(len(ids)) {
			return authorization.ErrForbidden
		}
	}
	if evidenceIDs := event.EvidenceIDs(); len(evidenceIDs) != 0 {
		ids := kernelUUIDs(evidenceIDs)
		var count int64
		if err := tx.QueryRow(ctx, `SELECT count(DISTINCT evidence.id)
			FROM public.dfir_evidence AS evidence
			WHERE evidence.tenant_id = $1 AND evidence.alert_id = $2
			  AND evidence.case_id IS NULL AND evidence.id = ANY($3::uuid[])
			  AND evidence.destroyed = false`, tenantID, alertID, ids).Scan(&count); err != nil {
			return err
		}
		if count != int64(len(ids)) {
			return authorization.ErrForbidden
		}
	}
	return nil
}
