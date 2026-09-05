package postgres

import (
	"context"
	"errors"

	"github.com/google/uuid"

	kernel "github.com/periapsis-im/periapsis/modules/dfir"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	application "github.com/periapsis-im/periapsis/services/api/internal/dfir"
)

var dfirWorkspaceCapabilities = [...]application.Capability{
	application.CapabilityIOCRead,
	application.CapabilityAssetRead,
	application.CapabilityEvidenceRead,
	application.CapabilityTimelineRead,
	application.CapabilityTaskRead,
	application.CapabilityAttachmentRead,
	application.CapabilityRelationshipRead,
}

func (repository *DFIRRepository) LoadWorkspace(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	caseID kernel.EntityID,
	claimed application.WorkspaceAccess,
) (application.Workspace, error) {
	if repository == nil || repository.begin == nil || len(claimed) != len(dfirWorkspaceCapabilities) {
		return application.Workspace{}, application.ErrRepositoryForbidden
	}
	result, err := withinTransactionWithOptions(
		ctx, repository.begin, phase4ReadOptions(),
		func(tx databaseTransaction) (application.Workspace, error) {
			authority, authorityErr := phase4Authority(ctx, tx, dfirAuthorizationActor(actor), tenantID)
			if authorityErr != nil {
				return application.Workspace{}, authorityErr
			}
			if err := validateDFIRAuthority(authority, actor); err != nil {
				return application.Workspace{}, err
			}
			caseUUID := uuid.UUID(caseID.Bytes())
			for _, capability := range dfirWorkspaceCapabilities {
				access, accessErr := dfirAccessForCase(ctx, tx, authority, actor, capability, caseUUID)
				provided, exists := claimed[capability]
				if accessErr != nil || !exists || !sameDFIRAccess(access, provided) {
					if accessErr != nil {
						return application.Workspace{}, accessErr
					}
					return application.Workspace{}, authorization.ErrForbidden
				}
			}
			customer := actor.Kind == application.PrincipalCustomer
			workspace, loadErr := loadDFIRWorkspace(ctx, tx, tenantID, caseUUID, customer)
			if loadErr != nil {
				return application.Workspace{}, loadErr
			}
			workspace.SharedResources, loadErr = loadDFIRWorkspaceSharedResources(ctx, tx, authority, actor, workspace.Indicators, workspace.Assets)
			if loadErr != nil {
				return application.Workspace{}, loadErr
			}
			return workspace, nil
		},
	)
	return result, mapDFIRDatabaseError(err)
}

func loadDFIRWorkspace(
	ctx context.Context,
	tx databaseTransaction,
	tenantID uuid.UUID,
	caseID uuid.UUID,
	customer bool,
) (application.Workspace, error) {
	var result application.Workspace

	indicatorIDs, err := queryBoundedDFIRIDs(ctx, tx, `
		SELECT ioc.id
		FROM public.dfir_ioc_links AS link
		JOIN public.dfir_iocs AS ioc
		  ON ioc.tenant_id = link.tenant_id AND ioc.id = link.ioc_id
		WHERE link.tenant_id = $1 AND link.case_id = $2 AND ioc.archived_at IS NULL
		ORDER BY ioc.updated_at DESC, ioc.id
		LIMIT $3`, tenantID, caseID, 500)
	if err != nil {
		return application.Workspace{}, err
	}
	result.Indicators = make([]application.Versioned[kernel.Indicator], len(indicatorIDs))
	for index, id := range indicatorIDs {
		value, version, loadErr := loadDFIRIndicator(ctx, tx, tenantID, id)
		if loadErr != nil {
			return application.Workspace{}, loadErr
		}
		result.Indicators[index] = application.Versioned[kernel.Indicator]{Resource: value, Version: version}
	}

	assetIDs, err := queryBoundedDFIRIDs(ctx, tx, `
		SELECT asset.id
		FROM public.dfir_asset_links AS link
		JOIN public.dfir_assets AS asset
		  ON asset.tenant_id = link.tenant_id AND asset.id = link.asset_id
		WHERE link.tenant_id = $1 AND link.case_id = $2 AND asset.archived_at IS NULL
		ORDER BY asset.updated_at DESC, asset.id
		LIMIT $3`, tenantID, caseID, 500)
	if err != nil {
		return application.Workspace{}, err
	}
	result.Assets = make([]application.Versioned[kernel.Asset], len(assetIDs))
	for index, id := range assetIDs {
		value, version, loadErr := loadDFIRAsset(ctx, tx, tenantID, id)
		if loadErr != nil {
			return application.Workspace{}, loadErr
		}
		result.Assets[index] = application.Versioned[kernel.Asset]{Resource: value, Version: version}
	}

	evidenceQuery := `SELECT id FROM public.dfir_evidence
		WHERE tenant_id = $1 AND case_id = $2`
	if customer {
		evidenceQuery += ` AND classification = 'public'::public.dfir_evidence_classification
			AND NOT destroyed`
	}
	evidenceQuery += ` ORDER BY collected_at DESC, id LIMIT $3`
	evidenceIDs, err := queryBoundedDFIRIDs(ctx, tx, evidenceQuery, tenantID, caseID, 500)
	if err != nil {
		return application.Workspace{}, err
	}
	result.Evidence = make([]kernel.Evidence, len(evidenceIDs))
	for index, id := range evidenceIDs {
		result.Evidence[index], err = loadDFIREvidence(ctx, tx, tenantID, caseID, id)
		if err != nil {
			return application.Workspace{}, err
		}
	}

	timelineIDs, err := queryBoundedDFIRIDs(ctx, tx, `SELECT id
		FROM public.dfir_timeline_events
		WHERE tenant_id = $1 AND case_id = $2
		ORDER BY event_time DESC, id LIMIT $3`, tenantID, caseID, 1000)
	if err != nil {
		return application.Workspace{}, err
	}
	result.Timeline = make([]application.Versioned[kernel.TimelineEvent], len(timelineIDs))
	for index, id := range timelineIDs {
		value, version, loadErr := loadDFIRTimelineEvent(ctx, tx, tenantID, id)
		if loadErr != nil {
			return application.Workspace{}, loadErr
		}
		result.Timeline[index] = application.Versioned[kernel.TimelineEvent]{Resource: value, Version: version}
	}

	taskIDs, err := queryBoundedDFIRIDs(ctx, tx, `SELECT id
		FROM public.dfir_tasks
		WHERE tenant_id = $1 AND case_id = $2
		ORDER BY status, due_at NULLS LAST, id LIMIT $3`, tenantID, caseID, 500)
	if err != nil {
		return application.Workspace{}, err
	}
	result.Tasks = make([]kernel.Task, len(taskIDs))
	for index, id := range taskIDs {
		result.Tasks[index], err = loadDFIRTask(ctx, tx, tenantID, caseID, id)
		if err != nil {
			return application.Workspace{}, err
		}
		if customer {
			result.Tasks[index], err = filterCustomerCaseTaskComments(
				ctx, tx, tenantID, caseID, result.Tasks[index],
			)
			if err != nil {
				return application.Workspace{}, err
			}
		}
	}

	attachmentQuery := `SELECT DISTINCT attachment.id
		FROM public.dfir_attachments AS attachment
		LEFT JOIN public.dfir_evidence AS evidence
		  ON evidence.tenant_id = attachment.tenant_id AND evidence.id = attachment.evidence_id
		LEFT JOIN public.dfir_tasks AS task
		  ON task.tenant_id = attachment.tenant_id AND task.id = attachment.task_id
		LEFT JOIN public.dfir_ioc_links AS ioc_link
		  ON ioc_link.tenant_id = attachment.tenant_id AND ioc_link.ioc_id = attachment.ioc_id
		 AND ioc_link.case_id = $2
		LEFT JOIN public.dfir_iocs AS ioc
		  ON ioc.tenant_id = ioc_link.tenant_id AND ioc.id = ioc_link.ioc_id
		 AND ioc.archived_at IS NULL
		LEFT JOIN public.dfir_asset_links AS asset_link
		  ON asset_link.tenant_id = attachment.tenant_id AND asset_link.asset_id = attachment.asset_id
		 AND asset_link.case_id = $2
		LEFT JOIN public.dfir_assets AS asset
		  ON asset.tenant_id = asset_link.tenant_id AND asset.id = asset_link.asset_id
		 AND asset.archived_at IS NULL
		LEFT JOIN public.alert_case_links AS alert_link
		  ON alert_link.tenant_id = attachment.tenant_id AND alert_link.alert_id = attachment.alert_id
		 AND alert_link.case_id = $2
		 AND NOT EXISTS (
		   SELECT 1 FROM public.alert_case_link_retractions AS retraction
		   WHERE retraction.tenant_id = alert_link.tenant_id
		     AND retraction.link_id = alert_link.id
		 )
		LEFT JOIN public.alerts AS source_alert
		  ON source_alert.tenant_id = alert_link.tenant_id AND source_alert.id = alert_link.alert_id
		 AND source_alert.deleted_at IS NULL
		WHERE attachment.tenant_id = $1
		  AND (attachment.case_id = $2 OR evidence.case_id = $2 OR task.case_id = $2
		       OR ioc.id IS NOT NULL OR asset.id IS NOT NULL OR source_alert.id IS NOT NULL
		       OR EXISTS (
		         SELECT 1 FROM public.dfir_attachment_case_links AS copied
		         WHERE copied.tenant_id = attachment.tenant_id
		           AND copied.attachment_id = attachment.id
		           AND copied.case_id = $2
		       ))`
	if customer {
		attachmentQuery += ` AND attachment.visibility = 'public'::public.dfir_visibility`
	}
	attachmentQuery += ` ORDER BY attachment.id LIMIT $3`
	attachmentIDs, err := queryBoundedDFIRIDs(ctx, tx, attachmentQuery, tenantID, caseID, 500)
	if err != nil {
		return application.Workspace{}, err
	}
	result.Attachments = make([]kernel.Attachment, len(attachmentIDs))
	for index, id := range attachmentIDs {
		result.Attachments[index], err = loadDFIRAttachment(ctx, tx, tenantID, caseID, id)
		if err != nil {
			return application.Workspace{}, err
		}
	}

	relationshipIDs, err := queryBoundedDFIRIDs(ctx, tx, `SELECT id
		FROM public.dfir_relationships
		WHERE tenant_id = $1 AND case_id = $2 AND alert_id IS NULL
		ORDER BY created_at DESC, id LIMIT $3`, tenantID, caseID, 1000)
	if err != nil {
		return application.Workspace{}, err
	}
	result.Relationships = make([]kernel.Relationship, len(relationshipIDs))
	for index, id := range relationshipIDs {
		result.Relationships[index], err = loadDFIRRelationship(ctx, tx, tenantID, caseID, id)
		if err != nil {
			return application.Workspace{}, err
		}
	}
	return result, nil
}

func filterCustomerCaseTaskComments(
	ctx context.Context,
	tx databaseTransaction,
	tenantID uuid.UUID,
	caseID uuid.UUID,
	task kernel.Task,
) (kernel.Task, error) {
	commentIDs := task.CommentIDs()
	if len(commentIDs) == 0 {
		return task, nil
	}
	requested := make([]uuid.UUID, len(commentIDs))
	allowed := make(map[uuid.UUID]struct{}, len(commentIDs))
	for index, id := range commentIDs {
		value := uuid.UUID(id.Bytes())
		requested[index] = value
		allowed[value] = struct{}{}
	}
	rows, err := tx.Query(ctx, `
		SELECT comment.id
		FROM unnest($3::uuid[]) AS requested(id)
		JOIN public.ticket_comments AS comment
		  ON comment.tenant_id = $1 AND comment.case_id = $2
		 AND comment.alert_id IS NULL AND comment.id = requested.id
		WHERE comment.visibility = 'public'::public.ticket_comment_visibility
		ORDER BY comment.id
		LIMIT 1001`, tenantID, caseID, requested)
	if err != nil {
		return kernel.Task{}, err
	}
	defer rows.Close()
	visible := make([]kernel.EntityID, 0, len(commentIDs))
	seen := make(map[uuid.UUID]struct{}, len(commentIDs))
	for rows.Next() {
		var id uuid.UUID
		if err = rows.Scan(&id); err != nil {
			return kernel.Task{}, err
		}
		if !authorizationUUIDv7(id) {
			return kernel.Task{}, unexpectedDFIRProjection("non-UUIDv7 customer task comment")
		}
		if _, ok := allowed[id]; !ok {
			return kernel.Task{}, unexpectedDFIRProjection("unassociated customer task comment")
		}
		if _, duplicate := seen[id]; duplicate {
			return kernel.Task{}, unexpectedDFIRProjection("duplicate customer task comment")
		}
		seen[id] = struct{}{}
		entity, parseErr := parseDFIREntityID(id)
		if parseErr != nil {
			return kernel.Task{}, parseErr
		}
		visible = append(visible, entity)
	}
	if rows.Err() != nil {
		return kernel.Task{}, rows.Err()
	}
	if len(visible) > 1_000 {
		return kernel.Task{}, unexpectedDFIRProjection("customer task comment bound exceeded")
	}
	filtered, err := kernel.NewTask(kernel.TaskInput{
		ID: task.ID(), TenantID: task.TenantID(), CaseID: task.CaseID(),
		Title: task.Title(), Description: task.Description(), Status: task.Status(), Priority: task.Priority(),
		AssigneeID: task.AssigneeID(), OperatorTeamID: task.OperatorTeamID(), DueAt: task.DueAt(),
		Checklist: task.Checklist(), CompletedAt: task.CompletedAt(), CompletedBy: task.CompletedBy(),
		CompletionData: task.CompletionData(), CommentIDs: visible, SLAInstanceID: task.SLAInstanceID(),
		CreatedAt: task.CreatedAt(), UpdatedAt: task.UpdatedAt(), Version: task.Version(),
	})
	if err != nil {
		return kernel.Task{}, unexpectedDFIRProjection("invalid customer task projection")
	}
	return filtered, nil
}

func queryBoundedDFIRIDs(
	ctx context.Context,
	tx databaseTransaction,
	query string,
	tenantID uuid.UUID,
	rootID uuid.UUID,
	maximum int,
) ([]uuid.UUID, error) {
	if maximum < 1 || maximum > 1000 {
		return nil, errors.New("invalid DFIR workspace bound")
	}
	rows, err := tx.Query(ctx, query, tenantID, rootID, maximum+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]uuid.UUID, 0, maximum)
	seen := make(map[uuid.UUID]struct{}, maximum)
	for rows.Next() {
		var id uuid.UUID
		if scanErr := rows.Scan(&id); scanErr != nil {
			return nil, scanErr
		}
		if !authorizationUUIDv7(id) {
			return nil, unexpectedDFIRProjection("non-UUIDv7 workspace resource")
		}
		if _, duplicate := seen[id]; duplicate {
			return nil, unexpectedDFIRProjection("duplicate workspace resource")
		}
		seen[id] = struct{}{}
		result = append(result, id)
	}
	if rows.Err() != nil {
		return nil, rows.Err()
	}
	if len(result) > maximum {
		return nil, unexpectedDFIRProjection("workspace resource bound exceeded")
	}
	return result, nil
}
