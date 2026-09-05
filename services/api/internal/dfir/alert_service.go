package dfir

import (
	"context"
	"slices"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/dfir"
)

var alertWorkspaceReadCapabilities = [...]Capability{
	CapabilityIOCRead,
	CapabilityAssetRead,
	CapabilityTimelineRead,
	CapabilityAttachmentRead,
}

// AlertWorkspace returns only resources linked directly to the requested
// autonomous Alert. A Case relationship never expands this projection.
func (service *Service) AlertWorkspace(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	alertID kernel.EntityID,
) (AlertWorkspace, error) {
	if !validActor(actor, tenantID) || actor.Kind != PrincipalHuman || alertID == (kernel.EntityID{}) {
		return AlertWorkspace{}, ErrForbidden
	}
	accesses := make(WorkspaceAccess, len(alertWorkspaceReadCapabilities))
	for _, capability := range alertWorkspaceReadCapabilities {
		access, err := service.resolveAlertAccess(ctx, actor, tenantID, capability, alertID, false)
		if err != nil {
			return AlertWorkspace{}, err
		}
		accesses[capability] = access
	}
	workspace, err := service.repository.LoadAlertWorkspace(ctx, actor, tenantID, alertID, accesses)
	if err != nil {
		return AlertWorkspace{}, repositoryError(err)
	}
	if !validAlertWorkspace(workspace, tenantID, alertID) {
		return AlertWorkspace{}, ErrUnavailable
	}
	workspace.Indicators = slices.Clone(workspace.Indicators)
	workspace.Assets = slices.Clone(workspace.Assets)
	workspace.Timeline = slices.Clone(workspace.Timeline)
	workspace.Attachments = slices.Clone(workspace.Attachments)
	return workspace, nil
}

func (service *Service) CreateAlertTimelineEvent(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	command AlertTimelineCommand,
) (MutationResult[kernel.TimelineEvent], error) {
	if err := service.authorizeAlertMutation(
		ctx, actor, tenantID, CapabilityTimelineManage, command.Input.AlertID, command.Envelope,
	); err != nil {
		return MutationResult[kernel.TimelineEvent]{}, err
	}
	if command.Input.CaseID != (kernel.EntityID{}) {
		return MutationResult[kernel.TimelineEvent]{}, ErrInvalidInput
	}
	command.Input.IngestedAt = service.now()
	event, err := kernel.NewTimelineEvent(command.Input)
	if err != nil || !entityTenantMatches(event.TenantID(), tenantID) || event.AlertID() == (kernel.EntityID{}) {
		return MutationResult[kernel.TimelineEvent]{}, ErrInvalidInput
	}
	base, err := alertBaseWrite(actor, event.AlertID(), command.Envelope, operationTimelineCreate,
		alertScopedFingerprint(event.AlertID(), timelineRequestFingerprint(event)))
	if err != nil {
		return MutationResult[kernel.TimelineEvent]{}, err
	}
	result, err := service.repository.CreateTimelineEvent(ctx, TimelineWrite{BaseWrite: base, Event: event})
	if err != nil {
		return MutationResult[kernel.TimelineEvent]{}, repositoryError(err)
	}
	if !sameFingerprint(timelineRequestFingerprint(result.Resource), timelineRequestFingerprint(event)) {
		return MutationResult[kernel.TimelineEvent]{}, ErrUnavailable
	}
	return result, nil
}

func (service *Service) CreateAlertIndicator(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	command AlertIndicatorCommand,
) (MutationResult[kernel.Indicator], error) {
	if err := service.authorizeAlertMutation(ctx, actor, tenantID, CapabilityIOCManage, command.AlertID, command.Envelope); err != nil {
		return MutationResult[kernel.Indicator]{}, err
	}
	indicator, err := kernel.NewIndicator(command.Input)
	if err != nil || !entityTenantMatches(indicator.TenantID(), tenantID) || command.ExpectedVersion != 0 {
		return MutationResult[kernel.Indicator]{}, ErrInvalidInput
	}
	base, err := alertBaseWrite(actor, command.AlertID, command.Envelope, operationIOCCreate,
		alertScopedFingerprint(command.AlertID, indicatorFingerprint(indicator, 0)))
	if err != nil {
		return MutationResult[kernel.Indicator]{}, err
	}
	result, err := service.repository.CreateIndicator(ctx, IndicatorWrite{BaseWrite: base, Indicator: indicator})
	if err != nil {
		return MutationResult[kernel.Indicator]{}, repositoryError(err)
	}
	if !sameFingerprint(indicatorFingerprint(result.Resource, 0), indicatorFingerprint(indicator, 0)) {
		return MutationResult[kernel.Indicator]{}, ErrUnavailable
	}
	return result, nil
}

func (service *Service) ReplaceAlertIndicator(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	command AlertIndicatorCommand,
) (MutationResult[kernel.Indicator], error) {
	if err := service.authorizeAlertMutation(ctx, actor, tenantID, CapabilityIOCManage, command.AlertID, command.Envelope); err != nil {
		return MutationResult[kernel.Indicator]{}, err
	}
	indicator, err := kernel.NewIndicator(command.Input)
	if err != nil || !entityTenantMatches(indicator.TenantID(), tenantID) ||
		!validResourceMutationVersion(command.ExpectedVersion) {
		return MutationResult[kernel.Indicator]{}, ErrInvalidInput
	}
	base, err := alertBaseWrite(actor, command.AlertID, command.Envelope, operationIOCReplace,
		alertScopedFingerprint(command.AlertID, indicatorFingerprint(indicator, command.ExpectedVersion)))
	if err != nil {
		return MutationResult[kernel.Indicator]{}, err
	}
	result, err := service.repository.ReplaceIndicator(ctx, IndicatorWrite{
		BaseWrite: base, Indicator: indicator, ExpectedVersion: command.ExpectedVersion,
	})
	if err != nil {
		return MutationResult[kernel.Indicator]{}, repositoryError(err)
	}
	if !sameFingerprint(
		indicatorFingerprint(result.Resource, command.ExpectedVersion),
		indicatorFingerprint(indicator, command.ExpectedVersion),
	) {
		return MutationResult[kernel.Indicator]{}, ErrUnavailable
	}
	return result, nil
}

func (service *Service) CreateAlertAsset(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	command AlertAssetCommand,
) (MutationResult[kernel.Asset], error) {
	if err := service.authorizeAlertMutation(ctx, actor, tenantID, CapabilityAssetManage, command.AlertID, command.Envelope); err != nil {
		return MutationResult[kernel.Asset]{}, err
	}
	asset, err := kernel.NewAsset(command.Input)
	if err != nil || !entityTenantMatches(asset.TenantID(), tenantID) || command.ExpectedVersion != 0 {
		return MutationResult[kernel.Asset]{}, ErrInvalidInput
	}
	base, err := alertBaseWrite(actor, command.AlertID, command.Envelope, operationAssetCreate,
		alertScopedFingerprint(command.AlertID, assetFingerprint(asset, 0)))
	if err != nil {
		return MutationResult[kernel.Asset]{}, err
	}
	result, err := service.repository.CreateAsset(ctx, AssetWrite{BaseWrite: base, Asset: asset})
	if err != nil {
		return MutationResult[kernel.Asset]{}, repositoryError(err)
	}
	if !sameFingerprint(assetFingerprint(result.Resource, 0), assetFingerprint(asset, 0)) {
		return MutationResult[kernel.Asset]{}, ErrUnavailable
	}
	return result, nil
}

func (service *Service) ReplaceAlertAsset(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	command AlertAssetCommand,
) (MutationResult[kernel.Asset], error) {
	if err := service.authorizeAlertMutation(ctx, actor, tenantID, CapabilityAssetManage, command.AlertID, command.Envelope); err != nil {
		return MutationResult[kernel.Asset]{}, err
	}
	asset, err := kernel.NewAsset(command.Input)
	if err != nil || !entityTenantMatches(asset.TenantID(), tenantID) ||
		!validResourceMutationVersion(command.ExpectedVersion) {
		return MutationResult[kernel.Asset]{}, ErrInvalidInput
	}
	base, err := alertBaseWrite(actor, command.AlertID, command.Envelope, operationAssetReplace,
		alertScopedFingerprint(command.AlertID, assetFingerprint(asset, command.ExpectedVersion)))
	if err != nil {
		return MutationResult[kernel.Asset]{}, err
	}
	result, err := service.repository.ReplaceAsset(ctx, AssetWrite{
		BaseWrite: base, Asset: asset, ExpectedVersion: command.ExpectedVersion,
	})
	if err != nil {
		return MutationResult[kernel.Asset]{}, repositoryError(err)
	}
	if !sameFingerprint(
		assetFingerprint(result.Resource, command.ExpectedVersion),
		assetFingerprint(asset, command.ExpectedVersion),
	) {
		return MutationResult[kernel.Asset]{}, ErrUnavailable
	}
	return result, nil
}

func (service *Service) PrepareAlertUpload(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	command AlertPrepareUploadCommand,
) (PreparedUpload, error) {
	if err := ctx.Err(); err != nil {
		return PreparedUpload{}, err
	}
	if !validActor(actor, tenantID) || actor.Kind != PrincipalHuman {
		return PreparedUpload{}, ErrForbidden
	}
	if !validEnvelope(command.Envelope) {
		return PreparedUpload{}, ErrInvalidInput
	}
	subjectAccess, err := service.resolveAlertSubjectAccess(
		ctx, actor, tenantID, CapabilityAttachmentManage, command.AlertID, command.Subject, true,
	)
	if err != nil {
		return PreparedUpload{}, err
	}
	if subjectAccess.AlertID != command.AlertID {
		return PreparedUpload{}, ErrNotFound
	}
	if !hasUsableDeadline(ctx, service.clock()) || command.SizeBytes <= 0 ||
		command.SizeBytes > service.maximumSize || !validSingleLine(command.ContentType, 512, false) {
		return PreparedUpload{}, ErrInvalidInput
	}
	tenantEntity, actorEntity, err := actorEntities(actor)
	if err != nil || command.Subject.TenantID() != tenantEntity {
		return PreparedUpload{}, ErrInvalidInput
	}
	location := ObjectLocation{Bucket: service.bucket, Key: tenantID.String() + "/" + command.StorageObjectID.String()}
	now := service.clock().UTC().Truncate(time.Microsecond)
	expiresAt := now.Add(15 * time.Minute)
	object, err := kernel.NewStorageObject(kernel.StorageObjectInput{
		ID: command.StorageObjectID, TenantID: tenantEntity, Bucket: location.Bucket,
		ObjectKey: location.Key, OriginalFilename: command.OriginalFilename,
		Classification: command.Classification, ExpectedSizeBytes: command.SizeBytes,
		UploadExpiresAt: expiresAt, CreatedBy: actorEntity, CreatedAt: now,
	})
	if err != nil {
		return PreparedUpload{}, ErrInvalidInput
	}
	attachment, err := kernel.NewAttachment(kernel.AttachmentInput{
		ID: command.AttachmentID, TenantID: tenantEntity, Subject: command.Subject,
		StorageObjectID: command.StorageObjectID, OriginalFilename: command.OriginalFilename,
		RequestedVisibility: command.RequestedVisibility, SubjectVisibility: subjectAccess.SubjectVisibility,
		UploadedBy: actorEntity, UploadedAt: now, ScanState: object.State(),
	})
	if err != nil {
		return PreparedUpload{}, ErrInvalidInput
	}
	base, err := alertBaseWrite(actor, subjectAccess.AlertID, command.Envelope, operationAttachmentPrepare,
		alertScopedFingerprint(command.AlertID, uploadFingerprint(object, attachment, command.SizeBytes, command.ContentType)))
	if err != nil {
		return PreparedUpload{}, err
	}
	result, err := service.repository.CreateStorageObject(ctx, StorageWrite{
		BaseWrite: base, Storage: object, Attachment: attachment, DeclaredMIME: command.ContentType,
	})
	if err != nil {
		return PreparedUpload{}, repositoryError(err)
	}
	if !validPreparedUploadProjection(result, object, attachment, command.SizeBytes, command.ContentType, now, expiresAt) {
		return PreparedUpload{}, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return PreparedUpload{}, err
	}
	grantExpiry := result.Storage.UploadExpiresAt()
	grant, err := service.storage.PrepareUpload(ctx, location, command.SizeBytes, command.ContentType, grantExpiry)
	if contextErr := ctx.Err(); contextErr != nil {
		return PreparedUpload{}, contextErr
	}
	if err != nil || !validUploadGrant(grant, now, grantExpiry) {
		return PreparedUpload{}, ErrUnavailable
	}
	return PreparedUpload{Object: result.Storage, Attachment: result.Attachment, Grant: grant.clone()}, nil
}

func (service *Service) PrepareAlertDownload(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	command AlertDownloadCommand,
) (PreparedDownload, error) {
	if err := ctx.Err(); err != nil {
		return PreparedDownload{}, err
	}
	if !validActor(actor, tenantID) || actor.Kind != PrincipalHuman {
		return PreparedDownload{}, ErrForbidden
	}
	if !hasUsableDeadline(ctx, service.clock()) || !validDownloadAudit(actor, command.Audit) {
		return PreparedDownload{}, ErrInvalidInput
	}
	subjectAccess, err := service.resolveAlertSubjectAccess(
		ctx, actor, tenantID, CapabilityAttachmentRead, command.AlertID, command.Subject, false,
	)
	if err != nil {
		return PreparedDownload{}, err
	}
	if subjectAccess.AlertID != command.AlertID {
		return PreparedDownload{}, ErrNotFound
	}
	record, err := service.repository.GetAlertAttachment(
		ctx, actor, tenantID, command.AlertID, command.AttachmentID, subjectAccess.Access,
	)
	if err != nil {
		return PreparedDownload{}, repositoryError(err)
	}
	attachment := record.Attachment
	if !entityTenantMatches(attachment.TenantID(), tenantID) || attachment.ID() != command.AttachmentID ||
		!sameEntityReference(attachment.Subject(), command.Subject) ||
		!attachment.CanIssueDownload(subjectAccess.Access.Audience) ||
		record.AttachmentVersion == 0 || record.AttachmentVersion > maximumDownloadGrantRevision ||
		record.RootVersion == 0 || record.RootVersion > maximumDownloadGrantRevision {
		return PreparedDownload{}, ErrNotFound
	}
	storage, err := service.repository.GetAlertStorageObject(
		ctx, actor, tenantID, command.AlertID, attachment.ID(), attachment.StorageObjectID(), subjectAccess.Access,
	)
	if err != nil {
		return PreparedDownload{}, repositoryError(err)
	}
	if !service.validStoredObjectLocation(storage, tenantID, attachment.StorageObjectID()) ||
		!validAttachmentStoragePair(attachment, storage) || !storage.CanIssueDownload() ||
		!validAttachmentDownloadRevisions(record, storage) {
		return PreparedDownload{}, ErrNotFound
	}
	if err := ctx.Err(); err != nil {
		return PreparedDownload{}, err
	}
	now := service.now()
	expiresAt := now.Add(5 * time.Minute)
	grant, err := service.storage.PrepareDownload(
		ctx, ObjectLocation{Bucket: storage.Bucket(), Key: storage.ObjectKey()}, expiresAt,
	)
	if contextErr := ctx.Err(); contextErr != nil {
		return PreparedDownload{}, contextErr
	}
	if err != nil || !validPresignedURL(grant.TargetURL) || !grant.ExpiresAt.After(now) || grant.ExpiresAt.After(expiresAt) {
		return PreparedDownload{}, ErrUnavailable
	}
	if err = service.repository.AuditDownloadGrant(ctx, DownloadGrantAuditWrite{
		Actor: actor, Audit: command.Audit, Root: PortalAttachmentRoot{Kind: PortalTicketAlert, ID: command.AlertID},
		RootVersion: record.RootVersion, Subject: command.Subject, AttachmentID: attachment.ID(),
		AttachmentVersion: record.AttachmentVersion, AttachmentState: attachment.ScanState(),
		StorageObjectID: storage.ID(), StorageVersion: storage.Version(), StorageState: storage.State(),
		Access: subjectAccess.Access, ExpiresAt: grant.ExpiresAt,
	}); err != nil {
		return PreparedDownload{}, repositoryError(err)
	}
	return PreparedDownload{Attachment: attachment, Grant: grant}, nil
}

func (service *Service) authorizeAlertMutation(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	capability Capability,
	alertID kernel.EntityID,
	envelope MutationEnvelope,
) error {
	if !validActor(actor, tenantID) || actor.Kind != PrincipalHuman {
		return ErrForbidden
	}
	if !validEnvelope(envelope) {
		return ErrInvalidInput
	}
	_, err := service.resolveAlertAccess(ctx, actor, tenantID, capability, alertID, true)
	return err
}

func (service *Service) resolveAlertAccess(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	capability Capability,
	alertID kernel.EntityID,
	manage bool,
) (Access, error) {
	access, err := service.repository.ResolveAlertAccess(
		ctx, actor, tenantID, capability, AlertResourceScope{AlertID: alertID},
	)
	if err != nil {
		return Access{}, repositoryError(err)
	}
	if !validAccess(actor, access, manage) || access.Audience != kernel.AudienceOperator {
		return Access{}, ErrForbidden
	}
	return access, nil
}

func (service *Service) resolveAlertSubjectAccess(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	capability Capability,
	alertID kernel.EntityID,
	subject kernel.EntityReference,
	manage bool,
) (AlertSubjectAccess, error) {
	tenantEntity, _, conversionErr := actorEntities(actor)
	if conversionErr != nil || subject.TenantID() != tenantEntity || subject.ID() == (kernel.EntityID{}) ||
		(subject.Kind() != kernel.EntityAlert && subject.Kind() != kernel.EntityIOC && subject.Kind() != kernel.EntityAsset) {
		return AlertSubjectAccess{}, ErrInvalidInput
	}
	access, err := service.repository.ResolveAlertSubjectAccess(ctx, actor, tenantID, capability, alertID, subject)
	if err != nil {
		return AlertSubjectAccess{}, repositoryError(err)
	}
	if access.AlertID == (kernel.EntityID{}) || access.AlertID != alertID ||
		!validAccess(actor, access.Access, manage) || access.Access.Audience != kernel.AudienceOperator ||
		access.SubjectVisibility != kernel.VisibilityPublic && access.SubjectVisibility != kernel.VisibilityPrivate {
		return AlertSubjectAccess{}, ErrForbidden
	}
	return access, nil
}

func alertBaseWrite(
	actor Actor,
	alertID kernel.EntityID,
	envelope MutationEnvelope,
	operation string,
	payload any,
) (BaseWrite, error) {
	command, err := commandBinding(operation, envelope.IdempotencyKey, payload)
	if err != nil {
		return BaseWrite{}, err
	}
	return BaseWrite{Actor: actor, AlertID: alertID, Command: command, Audit: envelope.Audit}, nil
}

func alertScopedFingerprint(alertID kernel.EntityID, resource any) map[string]any {
	return map[string]any{"alertId": alertID.String(), "resource": resource}
}
