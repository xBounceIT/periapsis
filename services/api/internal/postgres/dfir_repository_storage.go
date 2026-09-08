package postgres

import (
	"context"
	"encoding/hex"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	kernel "github.com/periapsis-im/periapsis/modules/dfir"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	application "github.com/periapsis-im/periapsis/services/api/internal/dfir"
)

func (repository *DFIRRepository) CreateStorageObject(
	ctx context.Context,
	write application.StorageWrite,
) (application.PreparedUploadRecord, error) {
	if !validDFIRCommand(write.Command, "dfir.attachment.prepare") ||
		write.Storage.Version() != 1 || write.Storage.State() != kernel.ScanPendingUpload ||
		write.Attachment.ScanState() != kernel.ScanPendingUpload ||
		write.Storage.ID() != write.Attachment.StorageObjectID() ||
		write.DeclaredMIME == "" || len(write.DeclaredMIME) > kernel.MaximumFileTypeMIMEBytes {
		return application.PreparedUploadRecord{}, application.ErrRepositoryConflict
	}
	if write.AlertID != (kernel.EntityID{}) {
		if write.CaseID != (kernel.EntityID{}) {
			return application.PreparedUploadRecord{}, application.ErrRepositoryConflict
		}
		return repository.createAlertStorageObject(ctx, write)
	}
	if write.CaseID == (kernel.EntityID{}) {
		return application.PreparedUploadRecord{}, application.ErrRepositoryForbidden
	}
	tenantID := uuid.UUID(write.Storage.TenantID().Bytes())
	caseID := uuid.UUID(write.CaseID.Bytes())
	storageID := uuid.UUID(write.Storage.ID().Bytes())
	attachmentID := uuid.UUID(write.Attachment.ID().Bytes())
	result, err := withinTransactionWithOptions(
		ctx, repository.begin, phase4WriteOptions(),
		func(tx databaseTransaction) (application.PreparedUploadRecord, error) {
			authority, authorityErr := phase4Authority(ctx, tx, dfirAuthorizationActor(write.Actor), tenantID)
			if authorityErr != nil {
				return application.PreparedUploadRecord{}, authorityErr
			}
			if err := validateDFIRAuthority(authority, write.Actor); err != nil {
				return application.PreparedUploadRecord{}, err
			}
			sharedRoots, sharedErr := authorizeDFIRSharedAttachment(ctx, tx, authority, write)
			if sharedErr != nil {
				return application.PreparedUploadRecord{}, sharedErr
			}
			inheritedVisibility, subjectErr := resolveDFIRCaseSubject(
				ctx, tx, tenantID, caseID, write.Attachment.Subject(),
			)
			if subjectErr != nil ||
				write.Attachment.Visibility() == kernel.VisibilityPublic && inheritedVisibility == kernel.VisibilityPrivate {
				if subjectErr != nil {
					return application.PreparedUploadRecord{}, subjectErr
				}
				return application.PreparedUploadRecord{}, authorization.ErrForbidden
			}
			access, accessErr := dfirAccessForCase(ctx, tx, authority, write.Actor, application.CapabilityAttachmentManage, caseID)
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
				tenantID: tenantID, rootKind: dfirMutationRootCase, rootID: caseID, operation: write.Command.Operation,
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
				storedAttachment, attachmentErr := loadDFIRAttachment(ctx, tx, tenantID, caseID, attachmentID)
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
			kind := string(kernel.EntityAttachment)
			if effectErr := appendDFIRMutationEffects(ctx, tx, write.BaseWrite, ids[1:4], phase4MutationEffects{
				PermissionKey: "dfir.attachment.manage", Action: "dfir.attachment.prepared",
				ResourceType: "dfir_storage_object", ResourceID: storageID, ResourceVersion: 1,
				CaseID: &caseID, ActivityResourceKind: &kind, ActivityResourceID: &attachmentID,
				Summary: "DFIR attachment upload prepared", Before: map[string]any{},
				After: map[string]any{
					"storageVersion": 1, "attachmentVersion": 1,
					"classification": write.Storage.Classification(), "visibility": write.Attachment.Visibility(),
					"scanState": write.Storage.State(),
				},
				Metadata: map[string]any{"commandOperation": write.Command.Operation, "objectLocationRedacted": true},
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
			storedAttachment, attachmentErr := loadDFIRAttachment(ctx, tx, tenantID, caseID, attachmentID)
			if storageErr != nil || attachmentErr != nil || !sameDFIRStorageObject(storedObject, write.Storage) ||
				!sameDFIRAttachment(storedAttachment, write.Attachment) {
				if storageErr != nil {
					return application.PreparedUploadRecord{}, storageErr
				}
				if attachmentErr != nil {
					return application.PreparedUploadRecord{}, attachmentErr
				}
				return application.PreparedUploadRecord{}, unexpectedDFIRProjection("divergent prepared upload")
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

func enqueueDFIRStorageScan(
	ctx context.Context,
	tx databaseTransaction,
	write application.StorageWrite,
	eventID uuid.UUID,
	causationID uuid.UUID,
) error {
	var enqueued bool
	err := tx.QueryRow(ctx, `SELECT app.enqueue_dfir_storage_scan_v1($1, $2, $3, $4, $5, $6)`,
		eventID, uuid.UUID(write.Storage.ID().Bytes()), write.DeclaredMIME,
		write.Storage.CreatedAt(), write.Audit.CorrelationID, causationID,
	).Scan(&enqueued)
	if err != nil {
		return err
	}
	if !enqueued {
		return unexpectedDFIRProjection("DFIR storage scan job was not enqueued")
	}
	return nil
}

func insertDFIRStorageObject(ctx context.Context, tx databaseTransaction, write application.StorageWrite) error {
	value := write.Storage
	_, err := tx.Exec(ctx, `
		INSERT INTO public.dfir_storage_objects (
			id, tenant_id, bucket, object_key, original_filename, classification,
			expected_size_bytes, upload_expires_at, state,
			created_by_membership_id, version, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6::public.dfir_evidence_classification,
			$7, $8, $9::public.dfir_scan_state, $10, $11, $12, $13)`,
		uuid.UUID(value.ID().Bytes()), uuid.UUID(value.TenantID().Bytes()), value.Bucket(),
		value.ObjectKey(), value.OriginalFilename(), string(value.Classification()),
		value.ExpectedSizeBytes(), value.UploadExpiresAt(), string(value.State()),
		write.Actor.MembershipID, int64(value.Version()),
		value.CreatedAt(), value.UpdatedAt())
	return err
}

func insertDFIRAttachment(ctx context.Context, tx databaseTransaction, write application.StorageWrite) error {
	value := write.Attachment
	alertID, caseID, iocID, assetID, evidenceID, taskID := dfirAttachmentDatabaseSubject(value.Subject())
	_, err := tx.Exec(ctx, `
		INSERT INTO public.dfir_attachments (
			id, tenant_id, subject_kind, alert_id, case_id, ioc_id, asset_id,
			evidence_id, task_id, storage_object_id, original_filename,
			visibility, scan_state, uploaded_by_membership_id, uploaded_at, version
		) VALUES ($1, $2, $3::public.dfir_entity_kind, $4, $5, $6, $7,
			$8, $9, $10, $11, $12::public.dfir_visibility,
			$13::public.dfir_scan_state, $14, $15, 1)`,
		uuid.UUID(value.ID().Bytes()), uuid.UUID(value.TenantID().Bytes()), string(value.Subject().Kind()),
		alertID, caseID, iocID, assetID, evidenceID, taskID,
		uuid.UUID(value.StorageObjectID().Bytes()), value.OriginalFilename(), string(value.Visibility()),
		string(value.ScanState()), write.Actor.MembershipID, value.UploadedAt())
	return err
}

func dfirAttachmentDatabaseSubject(value kernel.EntityReference) (any, any, any, any, any, any) {
	id := uuid.UUID(value.ID().Bytes())
	switch value.Kind() {
	case kernel.EntityAlert:
		return id, nil, nil, nil, nil, nil
	case kernel.EntityCase:
		return nil, id, nil, nil, nil, nil
	case kernel.EntityIOC:
		return nil, nil, id, nil, nil, nil
	case kernel.EntityAsset:
		return nil, nil, nil, id, nil, nil
	case kernel.EntityEvidence:
		return nil, nil, nil, nil, id, nil
	case kernel.EntityTask:
		return nil, nil, nil, nil, nil, id
	default:
		return nil, nil, nil, nil, nil, nil
	}
}

func (repository *DFIRRepository) GetCaseStorageObject(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	caseID kernel.EntityID,
	attachmentID kernel.EntityID,
	storageID kernel.EntityID,
	claimed application.Access,
) (kernel.StorageObject, error) {
	result, err := withinTransactionWithOptions(
		ctx, repository.begin, phase4ReadOptions(),
		func(tx databaseTransaction) (kernel.StorageObject, error) {
			access, accessErr := resolveDFIRAccessInTransaction(
				ctx, tx, actor, tenantID, application.CapabilityAttachmentRead, caseID,
			)
			if accessErr != nil || !sameDFIRAccess(access, claimed) {
				if accessErr != nil {
					return kernel.StorageObject{}, accessErr
				}
				return kernel.StorageObject{}, authorization.ErrForbidden
			}
			return loadExactDFIRStorageObjectForRoot(
				ctx, tx, tenantID, kernel.EntityCase, uuid.UUID(caseID.Bytes()),
				uuid.UUID(attachmentID.Bytes()), uuid.UUID(storageID.Bytes()),
			)
		},
	)
	return result, mapDFIRDatabaseError(err)
}

func (repository *DFIRRepository) GetAlertStorageObject(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	alertID kernel.EntityID,
	attachmentID kernel.EntityID,
	storageID kernel.EntityID,
	claimed application.Access,
) (kernel.StorageObject, error) {
	result, err := withinTransactionWithOptions(
		ctx, repository.begin, phase4ReadOptions(),
		func(tx databaseTransaction) (kernel.StorageObject, error) {
			access, accessErr := resolveDFIRAlertAccessInTransaction(
				ctx, tx, actor, tenantID, application.CapabilityAttachmentRead, alertID,
			)
			if accessErr != nil || !sameDFIRAccess(access, claimed) {
				if accessErr != nil {
					return kernel.StorageObject{}, accessErr
				}
				return kernel.StorageObject{}, authorization.ErrForbidden
			}
			return loadExactDFIRAlertStorageObject(
				ctx, tx, tenantID, uuid.UUID(alertID.Bytes()),
				uuid.UUID(attachmentID.Bytes()), uuid.UUID(storageID.Bytes()),
			)
		},
	)
	return result, mapDFIRDatabaseError(err)
}

func loadExactDFIRAlertStorageObject(
	ctx context.Context,
	tx databaseTransaction,
	tenantID uuid.UUID,
	alertID uuid.UUID,
	attachmentID uuid.UUID,
	storageID uuid.UUID,
) (kernel.StorageObject, error) {
	return loadExactDFIRStorageObjectForRoot(ctx, tx, tenantID, kernel.EntityAlert, alertID, attachmentID, storageID)
}

func loadExactDFIRStorageObjectForRoot(
	ctx context.Context,
	tx databaseTransaction,
	tenantID uuid.UUID,
	rootKind kernel.EntityKind,
	rootID uuid.UUID,
	attachmentID uuid.UUID,
	storageID uuid.UUID,
) (kernel.StorageObject, error) {
	if !authorizationUUIDv7(tenantID) || !authorizationUUIDv7(rootID) ||
		!authorizationUUIDv7(attachmentID) || !authorizationUUIDv7(storageID) ||
		(rootKind != kernel.EntityCase && rootKind != kernel.EntityAlert) {
		return kernel.StorageObject{}, authorization.ErrForbidden
	}
	var exactAttachmentID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM public.dfir_attachments
		WHERE tenant_id = $1 AND id = $2 AND storage_object_id = $3`,
		tenantID, attachmentID, storageID).Scan(&exactAttachmentID); err != nil {
		return kernel.StorageObject{}, err
	}
	if exactAttachmentID != attachmentID {
		return kernel.StorageObject{}, unexpectedDFIRProjection("attachment storage purpose mismatch")
	}
	if _, err := loadDFIRAttachmentForRoot(ctx, tx, tenantID, rootKind, rootID, exactAttachmentID); err != nil {
		return kernel.StorageObject{}, err
	}
	return loadDFIRStorageObject(ctx, tx, tenantID, storageID)
}

func (repository *DFIRRepository) GetAttachment(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	caseID kernel.EntityID,
	attachmentID kernel.EntityID,
	claimed application.Access,
) (application.AttachmentDownloadRecord, error) {
	result, err := withinTransactionWithOptions(
		ctx, repository.begin, phase4ReadOptions(),
		func(tx databaseTransaction) (application.AttachmentDownloadRecord, error) {
			access, accessErr := resolveDFIRAccessInTransaction(ctx, tx, actor, tenantID, application.CapabilityAttachmentRead, caseID)
			if accessErr != nil || !sameDFIRAccess(access, claimed) {
				if accessErr != nil {
					return application.AttachmentDownloadRecord{}, accessErr
				}
				return application.AttachmentDownloadRecord{}, authorization.ErrForbidden
			}
			attachment, loadErr := loadDFIRAttachment(ctx, tx, tenantID, uuid.UUID(caseID.Bytes()), uuid.UUID(attachmentID.Bytes()))
			if loadErr != nil {
				return application.AttachmentDownloadRecord{}, loadErr
			}
			if claimed.Audience == kernel.AudienceCustomer && attachment.Visibility() != kernel.VisibilityPublic {
				return application.AttachmentDownloadRecord{}, pgx.ErrNoRows
			}
			attachmentVersion, rootVersion, versionErr := loadDFIRDownloadVersions(
				ctx, tx, tenantID, application.PortalTicketCase, uuid.UUID(caseID.Bytes()), uuid.UUID(attachmentID.Bytes()),
			)
			if versionErr != nil {
				return application.AttachmentDownloadRecord{}, versionErr
			}
			return application.AttachmentDownloadRecord{
				Attachment: attachment, AttachmentVersion: attachmentVersion, RootVersion: rootVersion,
			}, nil
		},
	)
	return result, mapDFIRDatabaseError(err)
}

func (repository *DFIRRepository) GetAlertAttachment(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	alertID kernel.EntityID,
	attachmentID kernel.EntityID,
	claimed application.Access,
) (application.AttachmentDownloadRecord, error) {
	result, err := withinTransactionWithOptions(
		ctx, repository.begin, phase4ReadOptions(),
		func(tx databaseTransaction) (application.AttachmentDownloadRecord, error) {
			access, accessErr := resolveDFIRAlertAccessInTransaction(
				ctx, tx, actor, tenantID, application.CapabilityAttachmentRead, alertID,
			)
			if accessErr != nil || !sameDFIRAccess(access, claimed) {
				if accessErr != nil {
					return application.AttachmentDownloadRecord{}, accessErr
				}
				return application.AttachmentDownloadRecord{}, authorization.ErrForbidden
			}
			attachment, loadErr := loadDFIRAlertAttachment(
				ctx, tx, tenantID, uuid.UUID(alertID.Bytes()), uuid.UUID(attachmentID.Bytes()),
			)
			if loadErr != nil {
				return application.AttachmentDownloadRecord{}, loadErr
			}
			attachmentVersion, rootVersion, versionErr := loadDFIRDownloadVersions(
				ctx, tx, tenantID, application.PortalTicketAlert, uuid.UUID(alertID.Bytes()), uuid.UUID(attachmentID.Bytes()),
			)
			if versionErr != nil {
				return application.AttachmentDownloadRecord{}, versionErr
			}
			return application.AttachmentDownloadRecord{
				Attachment: attachment, AttachmentVersion: attachmentVersion, RootVersion: rootVersion,
			}, nil
		},
	)
	return result, mapDFIRDatabaseError(err)
}

func loadDFIRDownloadVersions(
	ctx context.Context,
	tx databaseTransaction,
	tenantID uuid.UUID,
	rootKind application.PortalTicketKind,
	rootID uuid.UUID,
	attachmentID uuid.UUID,
) (uint64, uint64, error) {
	var attachmentVersion int64
	if err := tx.QueryRow(ctx, `SELECT version FROM public.dfir_attachments
		WHERE tenant_id = $1 AND id = $2`, tenantID, attachmentID).Scan(&attachmentVersion); err != nil {
		return 0, 0, err
	}
	rootStatement := ""
	switch rootKind {
	case application.PortalTicketCase:
		rootStatement = `SELECT version FROM public.cases WHERE tenant_id = $1 AND id = $2`
	case application.PortalTicketAlert:
		rootStatement = `SELECT version FROM public.alerts WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL`
	default:
		return 0, 0, application.ErrRepositoryForbidden
	}
	var rootVersion int64
	if err := tx.QueryRow(ctx, rootStatement, tenantID, rootID).Scan(&rootVersion); err != nil {
		return 0, 0, err
	}
	if attachmentVersion < 1 || rootVersion < 1 {
		return 0, 0, unexpectedDFIRProjection("invalid download revision")
	}
	return uint64(attachmentVersion), uint64(rootVersion), nil
}

func (repository *DFIRRepository) GetStorageObjectAsWorker(
	ctx context.Context,
	worker application.WorkerContext,
	storageID kernel.EntityID,
) (kernel.StorageObject, error) {
	if repository == nil || repository.begin == nil || !validDFIRWorkerContext(worker) {
		return kernel.StorageObject{}, application.ErrRepositoryForbidden
	}
	result, err := withinTransactionWithOptions(
		ctx, repository.begin, phase4ReadOptions(),
		func(tx databaseTransaction) (kernel.StorageObject, error) {
			if installErr := installDFIRWorkerTenant(ctx, tx, worker.TenantID); installErr != nil {
				return kernel.StorageObject{}, installErr
			}
			return loadDFIRStorageObject(ctx, tx, worker.TenantID, uuid.UUID(storageID.Bytes()))
		},
	)
	return result, mapDFIRDatabaseError(err)
}

func (repository *DFIRRepository) MarkStorageUploadedAsWorker(ctx context.Context, write application.WorkerStorageWrite) (kernel.StorageObject, error) {
	return repository.advanceStorageAsWorker(ctx, write)
}

func (repository *DFIRRepository) BeginStorageVerification(ctx context.Context, write application.WorkerStorageWrite) (kernel.StorageObject, error) {
	return repository.advanceStorageAsWorker(ctx, write)
}

func (repository *DFIRRepository) CompleteStorageVerification(ctx context.Context, write application.WorkerStorageWrite) (kernel.StorageObject, error) {
	return repository.advanceStorageAsWorker(ctx, write)
}

func (repository *DFIRRepository) RejectStorageVerification(ctx context.Context, write application.WorkerStorageWrite) error {
	_, err := repository.advanceStorageAsWorker(ctx, write)
	return err
}

func (repository *DFIRRepository) BeginStorageScan(ctx context.Context, write application.WorkerStorageWrite) (kernel.StorageObject, error) {
	return repository.advanceStorageAsWorker(ctx, write)
}

func (repository *DFIRRepository) CompleteStorageScan(ctx context.Context, write application.WorkerStorageWrite) (kernel.StorageObject, error) {
	return repository.advanceStorageAsWorker(ctx, write)
}

func (repository *DFIRRepository) advanceStorageAsWorker(
	ctx context.Context,
	write application.WorkerStorageWrite,
) (kernel.StorageObject, error) {
	if repository == nil || repository.begin == nil || !validDFIRWorkerContext(write.Worker) ||
		write.ExpectedVersion == 0 || write.ExpectedVersion >= kernel.MaximumResourceVersion ||
		write.Current.Version() != write.ExpectedVersion ||
		write.Updated.Version() != write.ExpectedVersion+1 ||
		write.Current.ID() != write.Updated.ID() || write.Current.TenantID() != write.Updated.TenantID() ||
		uuid.UUID(write.Current.TenantID().Bytes()) != write.Worker.TenantID {
		return kernel.StorageObject{}, application.ErrRepositoryConflict
	}
	result, err := withinTransactionWithOptions(
		ctx, repository.begin, phase4WriteOptions(),
		func(tx databaseTransaction) (kernel.StorageObject, error) {
			if contextErr := installDFIRWorkerMutationContext(ctx, tx, write.Worker.TenantID); contextErr != nil {
				return kernel.StorageObject{}, contextErr
			}
			storageID := uuid.UUID(write.Current.ID().Bytes())
			stored, loadErr := loadDFIRStorageObject(ctx, tx, write.Worker.TenantID, storageID)
			if loadErr != nil {
				return kernel.StorageObject{}, loadErr
			}
			if sameDFIRStorageObject(stored, write.Updated) {
				return stored, nil
			}
			if !sameDFIRStorageObject(stored, write.Current) {
				return kernel.StorageObject{}, application.ErrRepositoryPrecondition
			}
			ids, idErr := phase4NewIDs(repository.newID, 3)
			if idErr != nil {
				return kernel.StorageObject{}, idErr
			}
			updated := write.Updated.Snapshot()
			var digest any
			var size any
			var detected any
			if updated.ContentSHA256 != "" {
				decoded, decodeErr := hex.DecodeString(updated.ContentSHA256)
				if decodeErr != nil || len(decoded) != 32 {
					return kernel.StorageObject{}, application.ErrRepositoryConflict
				}
				digest, size, detected = decoded, updated.SizeBytes, updated.DetectedMIME
			}
			var returnedID uuid.UUID
			var returnedVersion int64
			var replayed bool
			queryErr := tx.QueryRow(ctx, `SELECT storage_object_id, storage_version, replayed
				FROM app.advance_dfir_storage_object_as_worker_v3(
					$1, $2, $3::public.dfir_scan_state, $4, $5, $6, $7,
					$8, $9, $10, $11, $12
				)`, storageID, int64(write.ExpectedVersion), string(updated.State), digest, size,
				detected, updated.UpdatedAt, ids[2], ids[0], ids[1], write.Worker.OperationID,
				write.Worker.CorrelationID).Scan(&returnedID, &returnedVersion, &replayed)
			if queryErr != nil {
				return kernel.StorageObject{}, queryErr
			}
			if returnedID != storageID || returnedVersion != int64(write.Updated.Version()) {
				return kernel.StorageObject{}, unexpectedDFIRProjection("worker storage transition result mismatch")
			}
			stored, loadErr = loadDFIRStorageObject(ctx, tx, write.Worker.TenantID, storageID)
			if loadErr != nil || !sameDFIRStorageObject(stored, write.Updated) {
				if loadErr != nil {
					return kernel.StorageObject{}, loadErr
				}
				return kernel.StorageObject{}, unexpectedDFIRProjection("divergent storage object after worker transition")
			}
			_ = replayed
			return stored, nil
		},
	)
	return result, mapDFIRDatabaseError(err)
}

func installDFIRWorkerMutationContext(ctx context.Context, tx databaseTransaction, tenantID uuid.UUID) error {
	if err := installDFIRWorkerTenant(ctx, tx, tenantID); err != nil {
		return err
	}
	return installPersistedTraceContext(ctx, tx)
}

func installDFIRWorkerTenant(ctx context.Context, tx databaseTransaction, tenantID uuid.UUID) error {
	if !authorizationUUIDv7(tenantID) {
		return authorization.ErrForbidden
	}
	var installed string
	err := tx.QueryRow(ctx, `SELECT set_config('app.tenant_id', $1, true)`, tenantID.String()).Scan(&installed)
	if err != nil {
		return err
	}
	if installed != tenantID.String() {
		return unexpectedDFIRProjection("worker tenant context mismatch")
	}
	return nil
}

func validDFIRWorkerContext(worker application.WorkerContext) bool {
	return authorizationUUIDv7(worker.TenantID) && authorizationUUIDv7(worker.OperationID) &&
		authorizationUUIDv7(worker.CorrelationID)
}

func sameDFIRStorageObject(left, right kernel.StorageObject) bool {
	leftState, rightState := left.Snapshot(), right.Snapshot()
	return leftState.ID == rightState.ID && leftState.TenantID == rightState.TenantID &&
		leftState.Bucket == rightState.Bucket && leftState.ObjectKey == rightState.ObjectKey &&
		leftState.OriginalFilename == rightState.OriginalFilename && leftState.Classification == rightState.Classification &&
		leftState.ExpectedSizeBytes == rightState.ExpectedSizeBytes && leftState.UploadExpiresAt.Equal(rightState.UploadExpiresAt) &&
		leftState.CreatedBy == rightState.CreatedBy && leftState.CreatedAt.Equal(rightState.CreatedAt) &&
		leftState.UpdatedAt.Equal(rightState.UpdatedAt) && leftState.State == rightState.State &&
		leftState.ContentSHA256 == rightState.ContentSHA256 && leftState.SizeBytes == rightState.SizeBytes &&
		leftState.DetectedMIME == rightState.DetectedMIME && sameOptionalTime(leftState.VerifiedAt, rightState.VerifiedAt) &&
		sameOptionalTime(leftState.RetentionUntil, rightState.RetentionUntil) &&
		leftState.LegalHold == rightState.LegalHold && leftState.Version == rightState.Version
}

func sameDFIRPreparedUploadRequest(
	storage kernel.StorageObject,
	attachment kernel.Attachment,
	write application.StorageWrite,
) bool {
	wantStorage := write.Storage
	wantAttachment := write.Attachment
	return storage.Version() == 1 && storage.State() == kernel.ScanPendingUpload &&
		storage.ID() == wantStorage.ID() && storage.TenantID() == wantStorage.TenantID() &&
		storage.Bucket() == wantStorage.Bucket() && storage.ObjectKey() == wantStorage.ObjectKey() &&
		storage.OriginalFilename() == wantStorage.OriginalFilename() &&
		storage.Classification() == wantStorage.Classification() &&
		storage.ExpectedSizeBytes() == wantStorage.ExpectedSizeBytes() &&
		storage.CreatedBy() == wantStorage.CreatedBy() &&
		attachment.ID() == wantAttachment.ID() && attachment.TenantID() == wantAttachment.TenantID() &&
		sameDFIRReference(attachment.Subject(), wantAttachment.Subject()) &&
		attachment.StorageObjectID() == wantAttachment.StorageObjectID() &&
		attachment.OriginalFilename() == wantAttachment.OriginalFilename() &&
		attachment.Visibility() == wantAttachment.Visibility() &&
		attachment.UploadedBy() == wantAttachment.UploadedBy() &&
		attachment.ScanState() == kernel.ScanPendingUpload
}

func loadDFIRAttachmentVersion(
	ctx context.Context,
	tx databaseTransaction,
	tenantID uuid.UUID,
	attachmentID uuid.UUID,
) (uint64, error) {
	var version int64
	if err := tx.QueryRow(ctx, `SELECT version FROM public.dfir_attachments
		WHERE tenant_id = $1 AND id = $2 FOR SHARE`, tenantID, attachmentID).Scan(&version); err != nil {
		return 0, err
	}
	if !validDFIRDatabaseResourceVersion(version) {
		return 0, unexpectedDFIRProjection("attachment version is invalid")
	}
	return uint64(version), nil
}

func validDFIRPreparedUploadReplay(
	receipt dfirPreparedUploadResultSnapshot,
	historicalAttachment kernel.Attachment,
	liveStorage kernel.StorageObject,
	liveAttachment kernel.Attachment,
	liveAttachmentVersion uint64,
	write application.StorageWrite,
	now time.Time,
) bool {
	return receipt.StorageID == uuid.UUID(liveStorage.ID().Bytes()) &&
		receipt.TenantID == uuid.UUID(liveStorage.TenantID().Bytes()) &&
		receipt.CreatedBy == uuid.UUID(liveStorage.CreatedBy().Bytes()) &&
		receipt.CreatedAt.Equal(liveStorage.CreatedAt()) &&
		receipt.UploadExpiresAt.Equal(liveStorage.UploadExpiresAt()) &&
		receipt.StorageVersion == 1 && receipt.StorageState == kernel.ScanPendingUpload &&
		receipt.Attachment.ID == uuid.UUID(historicalAttachment.ID().Bytes()) &&
		receipt.Attachment.StorageObjectID == receipt.StorageID &&
		liveStorage.Version() == 1 && liveStorage.State() == kernel.ScanPendingUpload &&
		liveStorage.UploadExpiresAt().After(now) && liveAttachmentVersion == 1 &&
		liveAttachment.ScanState() == kernel.ScanPendingUpload &&
		sameDFIRPreparedUploadRequest(liveStorage, historicalAttachment, write) &&
		sameDFIRAttachment(liveAttachment, historicalAttachment)
}

func sameDFIRAttachment(left, right kernel.Attachment) bool {
	return left.ID() == right.ID() && left.TenantID() == right.TenantID() &&
		sameDFIRReference(left.Subject(), right.Subject()) && left.StorageObjectID() == right.StorageObjectID() &&
		left.OriginalFilename() == right.OriginalFilename() && left.Visibility() == right.Visibility() &&
		left.UploadedBy() == right.UploadedBy() && left.UploadedAt().Equal(right.UploadedAt()) &&
		left.ScanState() == right.ScanState()
}

func sameDFIRReference(left, right kernel.EntityReference) bool {
	return left.TenantID() == right.TenantID() && left.Kind() == right.Kind() && left.ID() == right.ID() &&
		left.ExternalType() == right.ExternalType() && left.ExternalID() == right.ExternalID()
}

func sameOptionalTime(left, right *time.Time) bool {
	return left == nil && right == nil || left != nil && right != nil && left.Equal(*right)
}
