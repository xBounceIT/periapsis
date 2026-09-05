package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	kernel "github.com/periapsis-im/periapsis/modules/dfir"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	application "github.com/periapsis-im/periapsis/services/api/internal/dfir"
)

func (repository *DFIRRepository) ListPortalAttachments(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	query application.PortalAttachmentListQuery,
) ([]kernel.Attachment, error) {
	if repository == nil || repository.begin == nil || !validDFIRPortalAttachmentQuery(actor, tenantID, query) {
		return nil, application.ErrRepositoryForbidden
	}
	result, err := withinTransactionWithOptions(ctx, repository.begin, phase4ReadOptions(),
		func(tx databaseTransaction) ([]kernel.Attachment, error) {
			if accessErr := validateDFIRPortalAttachmentAccess(ctx, tx, actor, tenantID, query.Authorization); accessErr != nil {
				return nil, accessErr
			}
			rootID := uuid.UUID(query.Root.ID.Bytes())
			statement, statementErr := portalAttachmentListStatement(query.Root.Kind)
			if statementErr != nil {
				return nil, statementErr
			}
			var afterTime any
			var afterID any
			if query.After != nil {
				afterTime = query.After.UploadedAt
				afterID = uuid.UUID(query.After.ID.Bytes())
			}
			rows, queryErr := tx.Query(ctx, statement, tenantID, rootID, afterTime, afterID, query.Bucket, query.Limit)
			if queryErr != nil {
				return nil, queryErr
			}
			defer rows.Close()
			type attachmentRow struct {
				id         uuid.UUID
				uploadedAt time.Time
			}
			values := make([]attachmentRow, 0, query.Limit)
			seen := make(map[uuid.UUID]struct{}, query.Limit)
			for rows.Next() {
				var value attachmentRow
				if scanErr := rows.Scan(&value.id, &value.uploadedAt); scanErr != nil {
					return nil, scanErr
				}
				if !authorizationUUIDv7(value.id) || value.uploadedAt.IsZero() || value.uploadedAt.Location() != time.UTC ||
					value.uploadedAt.Nanosecond()%1_000 != 0 {
					return nil, unexpectedDFIRProjection("invalid customer attachment page position")
				}
				if _, duplicate := seen[value.id]; duplicate {
					return nil, unexpectedDFIRProjection("duplicate customer attachment page item")
				}
				seen[value.id] = struct{}{}
				values = append(values, value)
			}
			if rows.Err() != nil {
				return nil, rows.Err()
			}
			if len(values) > query.Limit {
				return nil, unexpectedDFIRProjection("customer attachment page bound exceeded")
			}
			attachments := make([]kernel.Attachment, len(values))
			for index, value := range values {
				var loadErr error
				switch query.Root.Kind {
				case application.PortalTicketAlert:
					attachments[index], loadErr = loadDFIRAlertAttachment(ctx, tx, tenantID, rootID, value.id)
				case application.PortalTicketCase:
					attachments[index], loadErr = loadDFIRAttachment(ctx, tx, tenantID, rootID, value.id)
				default:
					loadErr = authorization.ErrForbidden
				}
				if loadErr != nil {
					return nil, loadErr
				}
				if !attachments[index].UploadedAt().Equal(value.uploadedAt) ||
					!attachments[index].CanIssueDownload(kernel.AudienceCustomer) {
					return nil, unexpectedDFIRProjection("customer attachment page projection mismatch")
				}
			}
			return attachments, nil
		},
	)
	return result, mapDFIRDatabaseError(err)
}

func (repository *DFIRRepository) GetPortalAttachmentDownload(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	query application.PortalAttachmentDownloadQuery,
) (application.PortalAttachmentDownloadRecord, error) {
	if repository == nil || repository.begin == nil || !validDFIRPortalAttachmentDownloadQuery(actor, tenantID, query) {
		return application.PortalAttachmentDownloadRecord{}, application.ErrRepositoryForbidden
	}
	result, err := withinTransactionWithOptions(ctx, repository.begin, phase4ReadOptions(),
		func(tx databaseTransaction) (application.PortalAttachmentDownloadRecord, error) {
			if accessErr := validateDFIRPortalAttachmentAccess(ctx, tx, actor, tenantID, query.Authorization); accessErr != nil {
				return application.PortalAttachmentDownloadRecord{}, accessErr
			}
			rootID := uuid.UUID(query.Root.ID.Bytes())
			attachmentID := uuid.UUID(query.AttachmentID.Bytes())
			var attachment kernel.Attachment
			var loadErr error
			switch query.Root.Kind {
			case application.PortalTicketAlert:
				attachment, loadErr = loadDFIRAlertAttachment(ctx, tx, tenantID, rootID, attachmentID)
			case application.PortalTicketCase:
				attachment, loadErr = loadDFIRAttachment(ctx, tx, tenantID, rootID, attachmentID)
			default:
				loadErr = authorization.ErrForbidden
			}
			if loadErr != nil {
				return application.PortalAttachmentDownloadRecord{}, loadErr
			}
			if !attachment.CanIssueDownload(kernel.AudienceCustomer) {
				return application.PortalAttachmentDownloadRecord{}, pgx.ErrNoRows
			}
			storage, storageErr := loadDFIRStorageObject(ctx, tx, tenantID, uuid.UUID(attachment.StorageObjectID().Bytes()))
			if storageErr != nil {
				return application.PortalAttachmentDownloadRecord{}, storageErr
			}
			if !storage.CanIssueDownload() {
				return application.PortalAttachmentDownloadRecord{}, pgx.ErrNoRows
			}
			if !sameDFIRPortalAttachmentStorage(attachment, storage) {
				return application.PortalAttachmentDownloadRecord{}, unexpectedDFIRProjection("customer attachment storage purpose mismatch")
			}
			attachmentVersion, rootVersion, versionErr := loadDFIRDownloadVersions(
				ctx, tx, tenantID, query.Root.Kind, rootID, attachmentID,
			)
			if versionErr != nil {
				return application.PortalAttachmentDownloadRecord{}, versionErr
			}
			return application.PortalAttachmentDownloadRecord{
				Attachment: attachment, AttachmentVersion: attachmentVersion,
				RootVersion: rootVersion, Storage: storage,
			}, nil
		},
	)
	return result, mapDFIRDatabaseError(err)
}

func validDFIRPortalAttachmentQuery(actor application.Actor, tenantID uuid.UUID, query application.PortalAttachmentListQuery) bool {
	if query.Limit < 1 || query.Limit > 101 || len(query.Bucket) < 3 || len(query.Bucket) > 63 ||
		!validDFIRPortalAttachmentBase(actor, tenantID, query.Root, query.Authorization) {
		return false
	}
	if query.After == nil {
		return true
	}
	return authorizationUUIDv7(uuid.UUID(query.After.ID.Bytes())) && !query.After.UploadedAt.IsZero() &&
		query.After.UploadedAt.Location() == time.UTC && query.After.UploadedAt.Nanosecond()%1_000 == 0
}

func validDFIRPortalAttachmentDownloadQuery(actor application.Actor, tenantID uuid.UUID, query application.PortalAttachmentDownloadQuery) bool {
	return authorizationUUIDv7(uuid.UUID(query.AttachmentID.Bytes())) &&
		validDFIRPortalAttachmentBase(actor, tenantID, query.Root, query.Authorization)
}

func validDFIRPortalAttachmentBase(
	actor application.Actor,
	tenantID uuid.UUID,
	root application.PortalAttachmentRoot,
	claimed application.PortalAttachmentAuthorization,
) bool {
	return actor.Kind == application.PrincipalCustomer && actor.TenantID == tenantID && actor.ActiveTenantID == tenantID &&
		actor.UserID != uuid.Nil && actor.SessionID != uuid.Nil && actor.MembershipID != uuid.Nil &&
		(root.Kind == application.PortalTicketAlert || root.Kind == application.PortalTicketCase) &&
		authorizationUUIDv7(uuid.UUID(root.ID.Bytes())) && claimed.TenantID == tenantID && claimed.Root == root &&
		authorizationUUIDv7(claimed.ContactID) && claimed.TicketVersion > 0
}

func validateDFIRPortalAttachmentAccess(
	ctx context.Context,
	tx databaseTransaction,
	actor application.Actor,
	tenantID uuid.UUID,
	claimed application.PortalAttachmentAuthorization,
) error {
	authority, err := phase4Authority(ctx, tx, dfirAuthorizationActor(actor), tenantID)
	if err != nil {
		return err
	}
	if validateDFIRAuthority(authority, actor) != nil || actor.Kind != application.PrincipalCustomer ||
		!phase4HasPermission(authority, "portal.attachment.read", authorization.ScopeOwn) {
		return authorization.ErrForbidden
	}
	table, column, aggregate, rootPermission, err := dfirPortalTicketTable(claimed.Root.Kind)
	if err != nil || !phase4HasPermission(authority, rootPermission, authorization.ScopeOwn) {
		return authorization.ErrForbidden
	}
	rootID := uuid.UUID(claimed.Root.ID.Bytes())
	deletedPredicate := ""
	if claimed.Root.Kind == application.PortalTicketAlert {
		deletedPredicate = " AND ticket.deleted_at IS NULL"
	}
	statement := fmt.Sprintf(`
		SELECT contact.id, contact.version, ticket.version,
		       ticket.customer_visible AND EXISTS (
		         SELECT 1 FROM jsonb_array_elements(workflow.states) AS state(value)
		         WHERE state.value ->> 'key' = ticket.state_key
		           AND state.value ->> 'visibility' = 'customer'
		       ),
		       contact.active AND contact.archived_at IS NULL,
		       link.archived_at IS NULL
		FROM public.customer_contacts AS contact
		JOIN public.ticket_customer_contacts AS link
		  ON link.tenant_id = contact.tenant_id
		 AND link.contact_id = contact.id
		 AND link.%s = $5
		JOIN public.%s AS ticket
		  ON ticket.tenant_id = link.tenant_id
		 AND ticket.id = link.%s
		JOIN public.ticket_workflow_versions AS workflow
		  ON workflow.tenant_id = ticket.tenant_id
		 AND workflow.workflow_id = ticket.workflow_id
		 AND workflow.version = ticket.workflow_version
		 AND workflow.aggregate_kind = $6::public.ticket_aggregate_kind
		WHERE contact.tenant_id = $1
		  AND contact.id = $2
		  AND contact.linked_membership_id = $3
		  AND contact.linked_user_id = $4%s`, column, table, column, deletedPredicate)
	var contactID uuid.UUID
	var contactVersion, ticketVersion int64
	var customerVisible, contactActive, linked bool
	if err = tx.QueryRow(ctx, statement, tenantID, claimed.ContactID, authority.MembershipID, actor.UserID, rootID, aggregate).Scan(
		&contactID, &contactVersion, &ticketVersion, &customerVisible, &contactActive, &linked,
	); err != nil {
		return err
	}
	if contactID != claimed.ContactID || contactVersion < 1 || ticketVersion < 1 ||
		uint64(ticketVersion) != claimed.TicketVersion || !customerVisible || !contactActive || !linked {
		return authorization.ErrForbidden
	}
	return nil
}

func dfirPortalTicketTable(kind application.PortalTicketKind) (table, column, aggregate, permission string, err error) {
	switch kind {
	case application.PortalTicketAlert:
		return "alerts", "alert_id", "alert", "portal.alert.read", nil
	case application.PortalTicketCase:
		return "cases", "case_id", "case", "portal.case.read", nil
	default:
		return "", "", "", "", application.ErrRepositoryForbidden
	}
}

func portalAttachmentListStatement(kind application.PortalTicketKind) (string, error) {
	association := ""
	switch kind {
	case application.PortalTicketAlert:
		association = `(attachment.alert_id = $2 OR EXISTS (
			SELECT 1 FROM public.dfir_ioc_links AS link
			JOIN public.dfir_iocs AS resource ON resource.tenant_id = link.tenant_id
			 AND resource.id = link.ioc_id AND resource.archived_at IS NULL
			WHERE link.tenant_id = attachment.tenant_id AND link.alert_id = $2
			 AND link.ioc_id = attachment.ioc_id
		) OR EXISTS (
			SELECT 1 FROM public.dfir_asset_links AS link
			JOIN public.dfir_assets AS resource ON resource.tenant_id = link.tenant_id
			 AND resource.id = link.asset_id AND resource.archived_at IS NULL
			WHERE link.tenant_id = attachment.tenant_id AND link.alert_id = $2
			 AND link.asset_id = attachment.asset_id
		))`
	case application.PortalTicketCase:
		association = `(attachment.case_id = $2 OR EXISTS (
			SELECT 1 FROM public.dfir_evidence AS evidence
			WHERE evidence.tenant_id = attachment.tenant_id AND evidence.id = attachment.evidence_id
			 AND evidence.case_id = $2
		) OR EXISTS (
			SELECT 1 FROM public.dfir_tasks AS task
			WHERE task.tenant_id = attachment.tenant_id AND task.id = attachment.task_id
			 AND task.case_id = $2
		) OR EXISTS (
			SELECT 1 FROM public.dfir_ioc_links AS link
			JOIN public.dfir_iocs AS resource ON resource.tenant_id = link.tenant_id
			 AND resource.id = link.ioc_id AND resource.archived_at IS NULL
			WHERE link.tenant_id = attachment.tenant_id AND link.ioc_id = attachment.ioc_id
			 AND link.case_id = $2
		) OR EXISTS (
			SELECT 1 FROM public.dfir_asset_links AS link
			JOIN public.dfir_assets AS resource ON resource.tenant_id = link.tenant_id
			 AND resource.id = link.asset_id AND resource.archived_at IS NULL
			WHERE link.tenant_id = attachment.tenant_id AND link.asset_id = attachment.asset_id
			 AND link.case_id = $2
		) OR EXISTS (
			SELECT 1 FROM public.dfir_attachment_case_links AS link
			WHERE link.tenant_id = attachment.tenant_id AND link.attachment_id = attachment.id
			 AND link.case_id = $2
		))`
	default:
		return "", application.ErrRepositoryForbidden
	}
	return `
		SELECT attachment.id, attachment.uploaded_at
		FROM public.dfir_attachments AS attachment
		JOIN public.dfir_storage_objects AS storage
		  ON storage.tenant_id = attachment.tenant_id
		 AND storage.id = attachment.storage_object_id
		WHERE attachment.tenant_id = $1
		  AND ` + association + `
		  AND attachment.visibility = 'public'::public.dfir_visibility
		  AND attachment.scan_state = 'available'::public.dfir_scan_state
		  AND storage.state = attachment.scan_state
		  AND storage.bucket = $5
		  AND storage.object_key = $1::text || '/' || storage.id::text
		  AND storage.original_filename = attachment.original_filename
		  AND storage.created_by_membership_id = attachment.uploaded_by_membership_id
		  AND storage.created_at = attachment.uploaded_at
		  AND ($3::timestamptz IS NULL OR
		       (attachment.uploaded_at, attachment.id) < ($3::timestamptz, $4::uuid))
		ORDER BY attachment.uploaded_at DESC, attachment.id DESC
		LIMIT $6`, nil
}

func sameDFIRPortalAttachmentStorage(attachment kernel.Attachment, storage kernel.StorageObject) bool {
	return attachment.TenantID() == storage.TenantID() && attachment.StorageObjectID() == storage.ID() &&
		attachment.OriginalFilename() == storage.OriginalFilename() && attachment.UploadedBy() == storage.CreatedBy() &&
		attachment.UploadedAt().Equal(storage.CreatedAt()) && attachment.ScanState() == storage.State()
}

var _ application.PortalAttachmentRepository = (*DFIRRepository)(nil)
