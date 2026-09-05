package postgres

import (
	"context"

	"github.com/google/uuid"

	kernel "github.com/periapsis-im/periapsis/modules/dfir"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	application "github.com/periapsis-im/periapsis/services/api/internal/dfir"
)

var dfirAlertWorkspaceCapabilities = [...]application.Capability{
	application.CapabilityIOCRead,
	application.CapabilityAssetRead,
	application.CapabilityTimelineRead,
	application.CapabilityAttachmentRead,
}

func (repository *DFIRRepository) LoadAlertWorkspace(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	alertID kernel.EntityID,
	claimed application.WorkspaceAccess,
) (application.AlertWorkspace, error) {
	if repository == nil || repository.begin == nil || actor.Kind != application.PrincipalHuman ||
		len(claimed) != len(dfirAlertWorkspaceCapabilities) {
		return application.AlertWorkspace{}, application.ErrRepositoryForbidden
	}
	result, err := withinTransactionWithOptions(
		ctx, repository.begin, phase4ReadOptions(),
		func(tx databaseTransaction) (application.AlertWorkspace, error) {
			authority, authorityErr := phase4Authority(ctx, tx, dfirAuthorizationActor(actor), tenantID)
			if authorityErr != nil {
				return application.AlertWorkspace{}, authorityErr
			}
			if err := validateDFIRAuthority(authority, actor); err != nil {
				return application.AlertWorkspace{}, err
			}
			alertUUID := uuid.UUID(alertID.Bytes())
			for _, capability := range dfirAlertWorkspaceCapabilities {
				access, accessErr := dfirAccessForAlert(ctx, tx, authority, actor, capability, alertUUID)
				provided, exists := claimed[capability]
				if accessErr != nil || !exists || !sameDFIRAccess(access, provided) {
					if accessErr != nil {
						return application.AlertWorkspace{}, accessErr
					}
					return application.AlertWorkspace{}, authorization.ErrForbidden
				}
			}
			workspace, loadErr := loadDFIRAlertWorkspace(ctx, tx, tenantID, alertUUID)
			if loadErr != nil {
				return application.AlertWorkspace{}, loadErr
			}
			workspace.SharedResources, loadErr = loadDFIRWorkspaceSharedResources(ctx, tx, authority, actor, workspace.Indicators, workspace.Assets)
			if loadErr != nil {
				return application.AlertWorkspace{}, loadErr
			}
			return workspace, nil
		},
	)
	return result, mapDFIRDatabaseError(err)
}

func loadDFIRAlertWorkspace(
	ctx context.Context,
	tx databaseTransaction,
	tenantID uuid.UUID,
	alertID uuid.UUID,
) (application.AlertWorkspace, error) {
	var result application.AlertWorkspace

	indicatorIDs, err := queryBoundedDFIRIDs(ctx, tx, `
		SELECT ioc.id
		FROM public.dfir_ioc_links AS link
		JOIN public.dfir_iocs AS ioc
		  ON ioc.tenant_id = link.tenant_id AND ioc.id = link.ioc_id
		WHERE link.tenant_id = $1 AND link.alert_id = $2 AND ioc.archived_at IS NULL
		ORDER BY ioc.updated_at DESC, ioc.id
		LIMIT $3`, tenantID, alertID, 500)
	if err != nil {
		return application.AlertWorkspace{}, err
	}
	result.Indicators = make([]application.Versioned[kernel.Indicator], len(indicatorIDs))
	for index, id := range indicatorIDs {
		value, version, loadErr := loadDFIRIndicator(ctx, tx, tenantID, id)
		if loadErr != nil {
			return application.AlertWorkspace{}, loadErr
		}
		result.Indicators[index] = application.Versioned[kernel.Indicator]{Resource: value, Version: version}
	}

	assetIDs, err := queryBoundedDFIRIDs(ctx, tx, `
		SELECT asset.id
		FROM public.dfir_asset_links AS link
		JOIN public.dfir_assets AS asset
		  ON asset.tenant_id = link.tenant_id AND asset.id = link.asset_id
		WHERE link.tenant_id = $1 AND link.alert_id = $2 AND asset.archived_at IS NULL
		ORDER BY asset.updated_at DESC, asset.id
		LIMIT $3`, tenantID, alertID, 500)
	if err != nil {
		return application.AlertWorkspace{}, err
	}
	result.Assets = make([]application.Versioned[kernel.Asset], len(assetIDs))
	for index, id := range assetIDs {
		value, version, loadErr := loadDFIRAsset(ctx, tx, tenantID, id)
		if loadErr != nil {
			return application.AlertWorkspace{}, loadErr
		}
		result.Assets[index] = application.Versioned[kernel.Asset]{Resource: value, Version: version}
	}

	timelineIDs, err := queryBoundedDFIRIDs(ctx, tx, `
		SELECT event.id
		FROM public.dfir_timeline_events AS event
		WHERE event.tenant_id = $1 AND event.alert_id = $2
		ORDER BY event.event_time DESC, event.id
		LIMIT $3`, tenantID, alertID, 1000)
	if err != nil {
		return application.AlertWorkspace{}, err
	}
	result.Timeline = make([]application.Versioned[kernel.TimelineEvent], len(timelineIDs))
	for index, id := range timelineIDs {
		value, version, loadErr := loadDFIRTimelineEvent(ctx, tx, tenantID, id)
		if loadErr != nil {
			return application.AlertWorkspace{}, loadErr
		}
		result.Timeline[index] = application.Versioned[kernel.TimelineEvent]{Resource: value, Version: version}
	}

	attachmentIDs, err := queryBoundedDFIRIDs(ctx, tx, `
		SELECT DISTINCT attachment.id
		FROM public.dfir_attachments AS attachment
		LEFT JOIN public.dfir_ioc_links AS ioc_link
		  ON ioc_link.tenant_id = attachment.tenant_id
		 AND ioc_link.ioc_id = attachment.ioc_id
		 AND ioc_link.alert_id = $2
		LEFT JOIN public.dfir_iocs AS ioc
		  ON ioc.tenant_id = ioc_link.tenant_id
		 AND ioc.id = ioc_link.ioc_id
		 AND ioc.archived_at IS NULL
		LEFT JOIN public.dfir_asset_links AS asset_link
		  ON asset_link.tenant_id = attachment.tenant_id
		 AND asset_link.asset_id = attachment.asset_id
		 AND asset_link.alert_id = $2
		LEFT JOIN public.dfir_assets AS asset
		  ON asset.tenant_id = asset_link.tenant_id
		 AND asset.id = asset_link.asset_id
		 AND asset.archived_at IS NULL
		WHERE attachment.tenant_id = $1
		  AND (attachment.alert_id = $2 OR ioc.id IS NOT NULL OR asset.id IS NOT NULL)
		ORDER BY attachment.id
		LIMIT $3`, tenantID, alertID, 500)
	if err != nil {
		return application.AlertWorkspace{}, err
	}
	result.Attachments = make([]kernel.Attachment, len(attachmentIDs))
	for index, id := range attachmentIDs {
		result.Attachments[index], err = loadDFIRAlertAttachment(ctx, tx, tenantID, alertID, id)
		if err != nil {
			return application.AlertWorkspace{}, err
		}
	}
	return result, nil
}
