package dfir

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/netip"
	"net/textproto"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/dfir"
)

// maximumObjectBytes is the portable S3-compatible single PutObject ceiling.
// Larger evidence requires a distinct multipart ceremony and is rejected
// before pending storage metadata is created.
const maximumObjectBytes int64 = 5_000_000_000

type Service struct {
	repository       Repository
	portalRepository PortalAttachmentRepository
	portalAuthorizer PortalAttachmentAuthorizer
	storage          ObjectStorage
	scanner          MalwareScanner
	bucket           string
	clock            func() time.Time
	maximumSize      int64
}

var workspaceReadCapabilities = [...]Capability{
	CapabilityIOCRead, CapabilityAssetRead, CapabilityEvidenceRead,
	CapabilityTimelineRead, CapabilityTaskRead, CapabilityAttachmentRead,
	CapabilityRelationshipRead,
}

// Workspace returns a single bounded Case projection only after every
// capability represented in that projection has been independently resolved.
func (service *Service) Workspace(ctx context.Context, actor Actor, tenantID uuid.UUID, caseID kernel.EntityID) (Workspace, error) {
	if !validActor(actor, tenantID) || caseID == (kernel.EntityID{}) {
		return Workspace{}, ErrForbidden
	}
	accesses := make(WorkspaceAccess, len(workspaceReadCapabilities))
	for _, capability := range workspaceReadCapabilities {
		access, err := service.resolveAccess(ctx, actor, tenantID, capability, caseID, false)
		if err != nil {
			return Workspace{}, err
		}
		accesses[capability] = access
	}
	workspace, err := service.repository.LoadWorkspace(ctx, actor, tenantID, caseID, accesses)
	if err != nil {
		return Workspace{}, repositoryError(err)
	}
	if !validWorkspace(workspace, tenantID, caseID) {
		return Workspace{}, ErrUnavailable
	}
	workspace.Indicators = slices.Clone(workspace.Indicators)
	workspace.Assets = slices.Clone(workspace.Assets)
	workspace.Evidence = slices.Clone(workspace.Evidence)
	workspace.Timeline = slices.Clone(workspace.Timeline)
	workspace.Tasks = slices.Clone(workspace.Tasks)
	workspace.Attachments = slices.Clone(workspace.Attachments)
	workspace.Relationships = slices.Clone(workspace.Relationships)
	return workspace, nil
}

type ServiceConfig struct {
	Bucket           string
	MaximumSize      int64
	Clock            func() time.Time
	PortalAuthorizer PortalAttachmentAuthorizer
}

func NewService(repository Repository, storage ObjectStorage, scanner MalwareScanner, config ServiceConfig) (*Service, error) {
	if repository == nil || storage == nil || scanner == nil ||
		!validObjectBucket(config.Bucket) || config.MaximumSize < 0 || config.MaximumSize > maximumObjectBytes {
		return nil, errors.New("complete DFIR dependencies and valid storage configuration are required")
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	if config.MaximumSize == 0 {
		config.MaximumSize = maximumObjectBytes
	}
	portalRepository, _ := repository.(PortalAttachmentRepository)
	return &Service{
		repository: repository, portalRepository: portalRepository, portalAuthorizer: config.PortalAuthorizer,
		storage: storage, scanner: scanner, bucket: config.Bucket, clock: config.Clock, maximumSize: config.MaximumSize,
	}, nil
}

func (service *Service) CreateIndicator(ctx context.Context, actor Actor, tenantID uuid.UUID, command IndicatorCommand) (MutationResult[kernel.Indicator], error) {
	if err := service.authorizeMutation(ctx, actor, tenantID, CapabilityIOCManage, command.CaseID, command.Envelope); err != nil {
		return MutationResult[kernel.Indicator]{}, err
	}
	indicator, err := kernel.NewIndicator(command.Input)
	if err != nil || !entityTenantMatches(indicator.TenantID(), tenantID) || command.ExpectedVersion != 0 {
		return MutationResult[kernel.Indicator]{}, ErrInvalidInput
	}
	base, err := baseWrite(actor, command.CaseID, command.Envelope, operationIOCCreate, indicatorFingerprint(indicator, 0))
	if err != nil {
		return MutationResult[kernel.Indicator]{}, err
	}
	result, err := service.repository.CreateIndicator(ctx, IndicatorWrite{
		BaseWrite: base, Indicator: indicator,
	})
	if err != nil {
		return MutationResult[kernel.Indicator]{}, repositoryError(err)
	}
	if !sameFingerprint(indicatorFingerprint(result.Resource, 0), indicatorFingerprint(indicator, 0)) {
		return MutationResult[kernel.Indicator]{}, ErrUnavailable
	}
	return result, nil
}

func (service *Service) ReplaceIndicator(ctx context.Context, actor Actor, tenantID uuid.UUID, command IndicatorCommand) (MutationResult[kernel.Indicator], error) {
	if err := service.authorizeMutation(ctx, actor, tenantID, CapabilityIOCManage, command.CaseID, command.Envelope); err != nil {
		return MutationResult[kernel.Indicator]{}, err
	}
	indicator, err := kernel.NewIndicator(command.Input)
	if err != nil || !entityTenantMatches(indicator.TenantID(), tenantID) ||
		!validResourceMutationVersion(command.ExpectedVersion) {
		return MutationResult[kernel.Indicator]{}, ErrInvalidInput
	}
	base, err := baseWrite(actor, command.CaseID, command.Envelope, operationIOCReplace, indicatorFingerprint(indicator, command.ExpectedVersion))
	if err != nil {
		return MutationResult[kernel.Indicator]{}, err
	}
	result, err := service.repository.ReplaceIndicator(ctx, IndicatorWrite{
		BaseWrite: base, Indicator: indicator,
		ExpectedVersion: command.ExpectedVersion,
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

func (service *Service) CreateAsset(ctx context.Context, actor Actor, tenantID uuid.UUID, command AssetCommand) (MutationResult[kernel.Asset], error) {
	if err := service.authorizeMutation(ctx, actor, tenantID, CapabilityAssetManage, command.CaseID, command.Envelope); err != nil {
		return MutationResult[kernel.Asset]{}, err
	}
	asset, err := kernel.NewAsset(command.Input)
	if err != nil || !entityTenantMatches(asset.TenantID(), tenantID) || command.ExpectedVersion != 0 {
		return MutationResult[kernel.Asset]{}, ErrInvalidInput
	}
	base, err := baseWrite(actor, command.CaseID, command.Envelope, operationAssetCreate, assetFingerprint(asset, 0))
	if err != nil {
		return MutationResult[kernel.Asset]{}, err
	}
	result, err := service.repository.CreateAsset(ctx, AssetWrite{
		BaseWrite: base, Asset: asset,
	})
	if err != nil {
		return MutationResult[kernel.Asset]{}, repositoryError(err)
	}
	if !sameFingerprint(assetFingerprint(result.Resource, 0), assetFingerprint(asset, 0)) {
		return MutationResult[kernel.Asset]{}, ErrUnavailable
	}
	return result, nil
}

func (service *Service) ReplaceAsset(ctx context.Context, actor Actor, tenantID uuid.UUID, command AssetCommand) (MutationResult[kernel.Asset], error) {
	if err := service.authorizeMutation(ctx, actor, tenantID, CapabilityAssetManage, command.CaseID, command.Envelope); err != nil {
		return MutationResult[kernel.Asset]{}, err
	}
	asset, err := kernel.NewAsset(command.Input)
	if err != nil || !entityTenantMatches(asset.TenantID(), tenantID) ||
		!validResourceMutationVersion(command.ExpectedVersion) {
		return MutationResult[kernel.Asset]{}, ErrInvalidInput
	}
	base, err := baseWrite(actor, command.CaseID, command.Envelope, operationAssetReplace, assetFingerprint(asset, command.ExpectedVersion))
	if err != nil {
		return MutationResult[kernel.Asset]{}, err
	}
	result, err := service.repository.ReplaceAsset(ctx, AssetWrite{
		BaseWrite: base, Asset: asset,
		ExpectedVersion: command.ExpectedVersion,
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

func (service *Service) CreateTimelineEvent(ctx context.Context, actor Actor, tenantID uuid.UUID, command TimelineCommand) (MutationResult[kernel.TimelineEvent], error) {
	if err := service.authorizeMutation(ctx, actor, tenantID, CapabilityTimelineManage, command.Input.CaseID, command.Envelope); err != nil {
		return MutationResult[kernel.TimelineEvent]{}, err
	}
	command.Input.IngestedAt = service.now()
	event, err := kernel.NewTimelineEvent(command.Input)
	if err != nil || !entityTenantMatches(event.TenantID(), tenantID) {
		return MutationResult[kernel.TimelineEvent]{}, ErrInvalidInput
	}
	base, err := baseWrite(actor, event.CaseID(), command.Envelope, operationTimelineCreate, timelineRequestFingerprint(event))
	if err != nil {
		return MutationResult[kernel.TimelineEvent]{}, err
	}
	result, err := service.repository.CreateTimelineEvent(ctx, TimelineWrite{
		BaseWrite: base, Event: event,
	})
	if err != nil {
		return MutationResult[kernel.TimelineEvent]{}, repositoryError(err)
	}
	if !sameFingerprint(timelineRequestFingerprint(result.Resource), timelineRequestFingerprint(event)) {
		return MutationResult[kernel.TimelineEvent]{}, ErrUnavailable
	}
	return result, nil
}

func (service *Service) CreateRelationship(ctx context.Context, actor Actor, tenantID uuid.UUID, command RelationshipCommand) (MutationResult[kernel.Relationship], error) {
	if err := service.authorizeMutation(ctx, actor, tenantID, CapabilityRelationshipManage, command.CaseID, command.Envelope); err != nil {
		return MutationResult[kernel.Relationship]{}, err
	}
	command.Input.CreatedAt = service.now()
	relationship, err := kernel.NewRelationship(command.Input)
	if err != nil || !entityTenantMatches(relationship.TenantID(), tenantID) {
		return MutationResult[kernel.Relationship]{}, ErrInvalidInput
	}
	base, err := baseWrite(actor, command.CaseID, command.Envelope, operationRelationshipCreate, relationshipRequestFingerprint(relationship))
	if err != nil {
		return MutationResult[kernel.Relationship]{}, err
	}
	result, err := service.repository.CreateRelationship(ctx, RelationshipWrite{
		BaseWrite: base, Relationship: relationship,
	})
	if err != nil {
		return MutationResult[kernel.Relationship]{}, repositoryError(err)
	}
	resultFingerprint := relationshipFingerprint(result.Resource)
	wantFingerprint := relationshipFingerprint(relationship)
	if result.Replayed {
		resultFingerprint = relationshipRequestFingerprint(result.Resource)
		wantFingerprint = relationshipRequestFingerprint(relationship)
	}
	if !sameFingerprint(resultFingerprint, wantFingerprint) {
		return MutationResult[kernel.Relationship]{}, ErrUnavailable
	}
	return result, nil
}

func (service *Service) PrepareUpload(ctx context.Context, actor Actor, tenantID uuid.UUID, command PrepareUploadCommand) (PreparedUpload, error) {
	if !validActor(actor, tenantID) {
		return PreparedUpload{}, ErrForbidden
	}
	if !validEnvelope(command.Envelope) {
		return PreparedUpload{}, ErrInvalidInput
	}
	subjectAccess, err := service.resolveSubjectAccess(
		ctx, actor, tenantID, CapabilityAttachmentManage, command.CaseID, command.Subject, true,
	)
	if err != nil {
		return PreparedUpload{}, err
	}
	if subjectAccess.CaseID != command.CaseID {
		return PreparedUpload{}, ErrNotFound
	}
	if !hasUsableDeadline(ctx, service.clock()) ||
		command.SizeBytes <= 0 || command.SizeBytes > service.maximumSize ||
		!validSingleLine(command.ContentType, 512, false) {
		return PreparedUpload{}, ErrInvalidInput
	}
	tenantEntity, actorEntity, err := actorEntities(actor)
	if err != nil || command.Subject.TenantID() != tenantEntity {
		return PreparedUpload{}, ErrInvalidInput
	}
	location := ObjectLocation{
		Bucket: service.bucket,
		Key:    tenantID.String() + "/" + command.StorageObjectID.String(),
	}
	now := service.clock().UTC().Truncate(time.Microsecond)
	expiresAt := now.Add(15 * time.Minute)
	object, err := kernel.NewStorageObject(kernel.StorageObjectInput{
		ID: command.StorageObjectID, TenantID: tenantEntity,
		Bucket: location.Bucket, ObjectKey: location.Key,
		OriginalFilename: command.OriginalFilename, Classification: command.Classification,
		ExpectedSizeBytes: command.SizeBytes, UploadExpiresAt: expiresAt,
		CreatedBy: actorEntity, CreatedAt: now,
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
	base, err := baseWrite(actor, subjectAccess.CaseID, command.Envelope, operationAttachmentPrepare,
		uploadFingerprint(object, attachment, command.SizeBytes, command.ContentType))
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
	grantExpiry := result.Storage.UploadExpiresAt()
	grant, err := service.storage.PrepareUpload(ctx, location, command.SizeBytes, command.ContentType, grantExpiry)
	if err != nil || !validUploadGrant(grant, now, grantExpiry) {
		return PreparedUpload{}, ErrUnavailable
	}
	return PreparedUpload{Object: result.Storage, Attachment: result.Attachment, Grant: grant.clone()}, nil
}

func (service *Service) VerifyUploadedObject(ctx context.Context, worker WorkerContext, storageID kernel.EntityID) (kernel.StorageObject, error) {
	if !validWorker(worker) || !hasUsableDeadline(ctx, service.clock()) {
		return kernel.StorageObject{}, ErrInvalidInput
	}
	current, err := service.repository.GetStorageObjectAsWorker(ctx, worker, storageID)
	if err != nil {
		return kernel.StorageObject{}, repositoryError(err)
	}
	if !service.validStoredObjectLocation(current, worker.TenantID, storageID) {
		return kernel.StorageObject{}, ErrUnavailable
	}
	if current.State() == kernel.ScanPendingUpload &&
		!current.UploadExpiresAt().After(service.now()) {
		return kernel.StorageObject{}, ErrUnavailable
	}
	var reader ObjectReader
	readerOpened := false
	if current.State() == kernel.ScanPendingUpload {
		reader, err = service.storage.Open(ctx, ObjectLocation{Bucket: current.Bucket(), Key: current.ObjectKey()})
		if err != nil || reader.Body == nil || reader.SizeBytes != current.ExpectedSizeBytes() {
			if reader.Body != nil {
				_ = reader.Body.Close()
			}
			return kernel.StorageObject{}, ErrUnavailable
		}
		readerOpened = true
		defer reader.Body.Close()
		uploaded, transitionErr := current.MarkUploaded(current.Version(), service.now())
		if transitionErr != nil {
			return kernel.StorageObject{}, ErrConflict
		}
		stored, transitionErr := service.repository.MarkStorageUploadedAsWorker(ctx, WorkerStorageWrite{
			Worker: worker, Current: current, Updated: uploaded, ExpectedVersion: current.Version(),
		})
		if transitionErr != nil {
			return kernel.StorageObject{}, repositoryError(transitionErr)
		}
		if !validStorageTransition(stored, uploaded) {
			return kernel.StorageObject{}, ErrUnavailable
		}
		current = stored
	}
	if current.State() == kernel.ScanUploaded {
		verifying, transitionErr := current.BeginVerification(current.Version(), service.now())
		if transitionErr != nil {
			return kernel.StorageObject{}, ErrConflict
		}
		current, err = service.repository.BeginStorageVerification(ctx, WorkerStorageWrite{
			Worker: worker, Current: current, Updated: verifying, ExpectedVersion: current.Version(),
		})
		if err != nil {
			return kernel.StorageObject{}, repositoryError(err)
		}
		if !validStorageTransition(current, verifying) {
			return kernel.StorageObject{}, ErrUnavailable
		}
	}
	if current.State() != kernel.ScanVerifying {
		return kernel.StorageObject{}, ErrConflict
	}
	if !readerOpened {
		reader, err = service.storage.Open(ctx, ObjectLocation{Bucket: current.Bucket(), Key: current.ObjectKey()})
		if err != nil || reader.Body == nil || reader.SizeBytes != current.ExpectedSizeBytes() {
			if reader.Body != nil {
				_ = reader.Body.Close()
			}
			service.rejectVerification(ctx, worker, current)
			return kernel.StorageObject{}, ErrUnavailable
		}
		defer reader.Body.Close()
	}
	digest, size, detectedMIME, err := hashBoundedObject(ctx, reader.Body, current.ExpectedSizeBytes())
	if err != nil || size != current.ExpectedSizeBytes() {
		service.rejectVerification(ctx, worker, current)
		return kernel.StorageObject{}, ErrUnavailable
	}
	completed, err := current.CompleteVerification(
		current.Version(), digest, size, detectedMIME,
		service.now(),
	)
	if err != nil {
		service.rejectVerification(ctx, worker, current)
		return kernel.StorageObject{}, ErrInvalidInput
	}
	stored, err := service.repository.CompleteStorageVerification(ctx, WorkerStorageWrite{
		Worker: worker, Current: current, Updated: completed, ExpectedVersion: current.Version(),
	})
	if err != nil {
		return kernel.StorageObject{}, repositoryError(err)
	}
	if !validStorageTransition(stored, completed) {
		return kernel.StorageObject{}, ErrUnavailable
	}
	return stored, nil
}

func (service *Service) ScanVerifiedObject(ctx context.Context, worker WorkerContext, storageID kernel.EntityID) (kernel.StorageObject, error) {
	if !validWorker(worker) || !hasUsableDeadline(ctx, service.clock()) {
		return kernel.StorageObject{}, ErrInvalidInput
	}
	current, err := service.repository.GetStorageObjectAsWorker(ctx, worker, storageID)
	if err != nil {
		return kernel.StorageObject{}, repositoryError(err)
	}
	if !service.validStoredObjectLocation(current, worker.TenantID, storageID) {
		return kernel.StorageObject{}, ErrUnavailable
	}
	if current.State() == kernel.ScanQuarantined {
		scanning, transitionErr := current.BeginScan(current.Version(), service.now())
		if transitionErr != nil {
			return kernel.StorageObject{}, ErrConflict
		}
		current, err = service.repository.BeginStorageScan(ctx, WorkerStorageWrite{
			Worker: worker, Current: current, Updated: scanning, ExpectedVersion: current.Version(),
		})
		if err != nil {
			return kernel.StorageObject{}, repositoryError(err)
		}
		if !validStorageTransition(current, scanning) {
			return kernel.StorageObject{}, ErrUnavailable
		}
	}
	if current.State() != kernel.ScanScanning || current.SizeBytes() < 0 || current.SizeBytes() > service.maximumSize {
		return kernel.StorageObject{}, ErrConflict
	}
	reader, err := service.storage.Open(ctx, ObjectLocation{Bucket: current.Bucket(), Key: current.ObjectKey()})
	if err != nil || reader.Body == nil || reader.SizeBytes != current.SizeBytes() {
		return service.completeFailedScan(ctx, worker, current, ErrUnavailable)
	}
	defer reader.Body.Close()
	verdict, scanErr := service.scanner.Scan(ctx, contextReader{ctx: ctx, reader: reader.Body}, service.maximumSize)
	if scanErr != nil || !validScanVerdict(verdict) {
		return service.completeFailedScan(ctx, worker, current, ErrUnavailable)
	}
	nextState := kernel.ScanAvailable
	if verdict == ScanVerdictMalicious {
		nextState = kernel.ScanRejected
	} else if verdict == ScanVerdictFailed {
		nextState = kernel.ScanFailed
	}
	completed, err := current.CompleteScan(current.Version(), nextState, service.now())
	if err != nil {
		return kernel.StorageObject{}, ErrConflict
	}
	stored, err := service.repository.CompleteStorageScan(ctx, WorkerStorageWrite{
		Worker: worker, Current: current, Updated: completed, ExpectedVersion: current.Version(),
	})
	if err != nil {
		return kernel.StorageObject{}, repositoryError(err)
	}
	if !validStorageTransition(stored, completed) {
		return kernel.StorageObject{}, ErrUnavailable
	}
	return stored, nil
}

func (service *Service) PrepareDownload(ctx context.Context, actor Actor, tenantID uuid.UUID, command DownloadCommand) (PreparedDownload, error) {
	if !validActor(actor, tenantID) || actor.Kind != PrincipalHuman {
		return PreparedDownload{}, ErrForbidden
	}
	if !hasUsableDeadline(ctx, service.clock()) || !validDownloadAudit(actor, command.Audit) {
		return PreparedDownload{}, ErrInvalidInput
	}
	if command.CaseID == (kernel.EntityID{}) || command.AttachmentID == (kernel.EntityID{}) ||
		!entityTenantMatches(command.Subject.TenantID(), tenantID) || command.Subject.ID() == (kernel.EntityID{}) {
		return PreparedDownload{}, ErrInvalidInput
	}
	access, err := service.resolveAccess(
		ctx, actor, tenantID, CapabilityAttachmentRead, command.CaseID, false,
	)
	if err != nil {
		return PreparedDownload{}, err
	}
	record, err := service.repository.GetAttachment(ctx, actor, tenantID, command.CaseID, command.AttachmentID, access)
	if err != nil {
		return PreparedDownload{}, repositoryError(err)
	}
	attachment := record.Attachment
	if !entityTenantMatches(attachment.TenantID(), tenantID) || attachment.ID() != command.AttachmentID ||
		!sameEntityReference(attachment.Subject(), command.Subject) || !attachment.CanIssueDownload(access.Audience) ||
		record.AttachmentVersion == 0 || record.AttachmentVersion > maximumDownloadGrantRevision ||
		record.RootVersion == 0 || record.RootVersion > maximumDownloadGrantRevision {
		return PreparedDownload{}, ErrNotFound
	}
	storage, err := service.repository.GetCaseStorageObject(
		ctx, actor, tenantID, command.CaseID, command.AttachmentID, attachment.StorageObjectID(), access,
	)
	if err != nil {
		return PreparedDownload{}, repositoryError(err)
	}
	if !service.validStoredObjectLocation(storage, tenantID, attachment.StorageObjectID()) ||
		!validAttachmentStoragePair(attachment, storage) || !storage.CanIssueDownload() ||
		!validAttachmentDownloadRevisions(record, storage) {
		return PreparedDownload{}, ErrNotFound
	}
	now := service.now()
	expiresAt := now.Add(5 * time.Minute)
	grant, err := service.storage.PrepareDownload(
		ctx, ObjectLocation{Bucket: storage.Bucket(), Key: storage.ObjectKey()}, expiresAt,
	)
	if err != nil || !validPresignedURL(grant.TargetURL) || !grant.ExpiresAt.After(now) || grant.ExpiresAt.After(expiresAt) {
		return PreparedDownload{}, ErrUnavailable
	}
	if err = ctx.Err(); err != nil {
		return PreparedDownload{}, err
	}
	if err = service.repository.AuditDownloadGrant(ctx, DownloadGrantAuditWrite{
		Actor: actor, Audit: command.Audit, Root: PortalAttachmentRoot{Kind: PortalTicketCase, ID: command.CaseID},
		RootVersion: record.RootVersion, Subject: command.Subject, AttachmentID: attachment.ID(),
		AttachmentVersion: record.AttachmentVersion, AttachmentState: attachment.ScanState(),
		StorageObjectID: storage.ID(), StorageVersion: storage.Version(), StorageState: storage.State(),
		Access: access, ExpiresAt: grant.ExpiresAt,
	}); err != nil {
		return PreparedDownload{}, repositoryError(err)
	}
	return PreparedDownload{Attachment: attachment, Grant: grant}, nil
}

func (service *Service) CollectEvidence(ctx context.Context, actor Actor, tenantID uuid.UUID, command EvidenceCommand) (MutationResult[kernel.Evidence], error) {
	command.RetentionUntil = cloneTime(command.RetentionUntil)
	if err := service.authorizeMutation(ctx, actor, tenantID, CapabilityEvidenceManage, command.CaseID, command.Envelope); err != nil {
		return MutationResult[kernel.Evidence]{}, err
	}
	tenantEntity, actorEntity, err := actorEntities(actor)
	if err != nil {
		return MutationResult[kernel.Evidence]{}, ErrForbidden
	}
	base, err := baseWrite(actor, command.CaseID, command.Envelope, operationEvidenceCreate,
		evidenceCollectRequestFingerprint(command, actorEntity))
	if err != nil {
		return MutationResult[kernel.Evidence]{}, err
	}
	var built alertCallbackCapture[kernel.Evidence]
	result, err := service.repository.CreateEvidence(ctx, EvidenceWrite{
		BaseWrite: base, EvidenceID: command.EvidenceID, StorageObjectID: command.StorageObjectID,
		InitialCustodyEventID: command.InitialCustodyEventID,
		Build: func(storage kernel.StorageObject) (kernel.Evidence, error) {
			built.begin()
			if err := ctx.Err(); err != nil {
				return kernel.Evidence{}, err
			}
			if !service.validStoredObjectLocation(storage, tenantID, command.StorageObjectID) ||
				storage.ContentSHA256() == "" {
				return kernel.Evidence{}, ErrUnavailable
			}
			evidence, buildErr := kernel.NewEvidence(kernel.EvidenceInput{
				ID: command.EvidenceID, TenantID: tenantEntity, CaseID: command.CaseID,
				StorageObjectID: command.StorageObjectID, InitialCustodyEventID: command.InitialCustodyEventID,
				Title: command.Title, Description: command.Description, EvidenceType: command.EvidenceType,
				Classification: command.Classification, ContentSHA256: storage.ContentSHA256(),
				SizeBytes: storage.SizeBytes(), DetectedMIME: storage.DetectedMIME(),
				CollectedAt: command.CollectedAt, CollectedBy: actorEntity, Source: command.Source,
				RetentionUntil: command.RetentionUntil, LegalHold: command.LegalHold, ScanState: storage.State(),
			})
			if buildErr != nil || evidence.Classification() != storage.Classification() {
				return kernel.Evidence{}, ErrInvalidInput
			}
			built.complete(evidence)
			return evidence, nil
		},
	})
	if err != nil {
		return MutationResult[kernel.Evidence]{}, alertInvestigationMutationError(err)
	}
	if !validCaseEvidenceCreateResult(result.Resource, tenantEntity, command, actorEntity) {
		return MutationResult[kernel.Evidence]{}, ErrUnavailable
	}
	builtEvidence, buildCalls := built.snapshot()
	if result.Replayed && buildCalls != 0 || !result.Replayed &&
		(buildCalls != 1 || !sameFingerprint(
			evidenceFingerprint(result.Resource, 0), evidenceFingerprint(builtEvidence, 0),
		)) {
		return MutationResult[kernel.Evidence]{}, ErrUnavailable
	}
	return result, nil
}

func (service *Service) AppendCustody(ctx context.Context, actor Actor, tenantID uuid.UUID, command CustodyCommand) (MutationResult[kernel.Evidence], error) {
	command.LegalHold = cloneBool(command.LegalHold)
	command.RetentionUntil = cloneTime(command.RetentionUntil)
	if err := service.authorizeMutation(ctx, actor, tenantID, CapabilityEvidenceManage, command.CaseID, command.Envelope); err != nil {
		return MutationResult[kernel.Evidence]{}, err
	}
	_, actorEntity, err := actorEntities(actor)
	if err != nil {
		return MutationResult[kernel.Evidence]{}, ErrForbidden
	}
	if !validResourceMutationVersion(command.ExpectedVersion) || command.ExpectedVersion >= kernel.MaximumCustodyEvents ||
		command.EvidenceID == (kernel.EntityID{}) ||
		command.Event.ID == (kernel.EntityID{}) {
		return MutationResult[kernel.Evidence]{}, ErrInvalidInput
	}
	command.Event.ActorID = actorEntity
	command.Event.OccurredAt = service.now()
	base, err := baseWrite(actor, command.CaseID, command.Envelope, operationCustodyAppend,
		custodyRequestFingerprint(command))
	if err != nil {
		return MutationResult[kernel.Evidence]{}, err
	}
	var applied alertCallbackCapture[kernel.Evidence]
	result, err := service.repository.AppendCustody(ctx, CustodyWrite{
		BaseWrite: base, EvidenceID: command.EvidenceID, EventID: command.Event.ID,
		ExpectedVersion: command.ExpectedVersion,
		Apply: func(current kernel.Evidence) (kernel.Evidence, error) {
			applied.begin()
			if err := ctx.Err(); err != nil {
				return kernel.Evidence{}, err
			}
			if !entityTenantMatches(current.TenantID(), tenantID) || current.CaseID() != command.CaseID ||
				current.ID() != command.EvidenceID || !current.VerifyCustodyChain() {
				return kernel.Evidence{}, ErrUnavailable
			}
			events := current.CustodyEvents()
			if len(events) == 0 || command.Event.OccurredAt.Before(events[len(events)-1].OccurredAt()) {
				return kernel.Evidence{}, ErrUnavailable
			}
			updated, applyErr := applyCustody(current, command)
			if applyErr == nil {
				applied.complete(updated)
			}
			return updated, applyErr
		},
	})
	if err != nil {
		return MutationResult[kernel.Evidence]{}, alertInvestigationMutationError(err)
	}
	if !validCaseEvidenceCustodyResult(result.Resource, tenantID, command) {
		return MutationResult[kernel.Evidence]{}, ErrUnavailable
	}
	appliedEvidence, applyCalls := applied.snapshot()
	if result.Replayed && applyCalls != 0 || !result.Replayed &&
		(applyCalls != 1 || !sameFingerprint(
			evidenceFingerprint(result.Resource, command.ExpectedVersion),
			evidenceFingerprint(appliedEvidence, command.ExpectedVersion),
		)) {
		return MutationResult[kernel.Evidence]{}, ErrUnavailable
	}
	return result, nil
}

func validCaseEvidenceCreateResult(
	evidence kernel.Evidence,
	tenantID kernel.EntityID,
	command EvidenceCommand,
	actorID kernel.EntityID,
) bool {
	if evidence.ID() != command.EvidenceID || evidence.TenantID() != tenantID || evidence.CaseID() != command.CaseID ||
		evidence.StorageObjectID() != command.StorageObjectID || evidence.Version() != 1 ||
		evidence.Title() != command.Title || evidence.Description() != command.Description ||
		evidence.EvidenceType() != command.EvidenceType || evidence.Classification() != command.Classification ||
		!evidence.CollectedAt().Equal(command.CollectedAt) || evidence.CollectedBy() != actorID ||
		evidence.Source() != command.Source || evidence.LegalHold() != command.LegalHold || !evidence.VerifyCustodyChain() {
		return false
	}
	events := evidence.CustodyEvents()
	if len(events) != 1 || events[0].ID() != command.InitialCustodyEventID || events[0].ActorID() != actorID {
		return false
	}
	left, right := evidence.RetentionUntil(), command.RetentionUntil
	return left == nil && right == nil || left != nil && right != nil && left.Equal(*right)
}

func validCaseEvidenceCustodyResult(evidence kernel.Evidence, tenantID uuid.UUID, command CustodyCommand) bool {
	if !entityTenantMatches(evidence.TenantID(), tenantID) || evidence.CaseID() != command.CaseID ||
		evidence.ID() != command.EvidenceID || evidence.Version() != command.ExpectedVersion+1 ||
		!evidence.VerifyCustodyChain() {
		return false
	}
	events := evidence.CustodyEvents()
	if len(events) == 0 {
		return false
	}
	last := events[len(events)-1]
	if last.ID() != command.Event.ID || last.ActorID() != command.Event.ActorID ||
		last.Action() != command.Event.Action || last.Reason() != command.Event.Reason {
		return false
	}
	switch command.Event.Action {
	case kernel.CustodyScanStateChanged:
		return evidence.ScanState() == command.NextScanState
	case kernel.CustodyLegalHoldPlaced, kernel.CustodyLegalHoldReleased:
		return command.LegalHold != nil && evidence.LegalHold() == *command.LegalHold
	case kernel.CustodyRetentionChanged:
		left, right := evidence.RetentionUntil(), command.RetentionUntil
		return left == nil && right == nil || left != nil && right != nil && left.Equal(*right)
	case kernel.CustodyDestroyed:
		return evidence.Destroyed() && evidence.ScanState() == kernel.ScanDeleted
	default:
		return true
	}
}

func (service *Service) authorizeMutation(ctx context.Context, actor Actor, tenantID uuid.UUID, capability Capability, caseID kernel.EntityID, envelope MutationEnvelope) error {
	if !validActor(actor, tenantID) {
		return ErrForbidden
	}
	if !validEnvelope(envelope) {
		return ErrInvalidInput
	}
	_, err := service.resolveAccess(ctx, actor, tenantID, capability, caseID, true)
	return err
}

func validResourceMutationVersion(expectedVersion uint64) bool {
	return expectedVersion > 0 && expectedVersion < kernel.MaximumResourceVersion
}

func (service *Service) resolveAccess(ctx context.Context, actor Actor, tenantID uuid.UUID, capability Capability, caseID kernel.EntityID, manage bool) (Access, error) {
	access, err := service.repository.ResolveAccess(ctx, actor, tenantID, capability, ResourceScope{CaseID: caseID})
	if err != nil {
		return Access{}, repositoryError(err)
	}
	if !validAccess(actor, access, manage) {
		return Access{}, ErrForbidden
	}
	return access, nil
}

func (service *Service) resolveSubjectAccess(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	capability Capability,
	caseID kernel.EntityID,
	subject kernel.EntityReference,
	manage bool,
) (SubjectAccess, error) {
	tenantEntity, _, conversionErr := actorEntities(actor)
	if conversionErr != nil || subject.TenantID() != tenantEntity || subject.Kind() == kernel.EntityExternal ||
		subject.ID() == (kernel.EntityID{}) || caseID == (kernel.EntityID{}) {
		return SubjectAccess{}, ErrInvalidInput
	}
	access, err := service.repository.ResolveSubjectAccess(ctx, actor, tenantID, capability, caseID, subject)
	if err != nil {
		return SubjectAccess{}, repositoryError(err)
	}
	if !validAccess(actor, access.Access, manage) || access.SubjectVisibility != kernel.VisibilityPublic &&
		access.SubjectVisibility != kernel.VisibilityPrivate || access.CaseID == (kernel.EntityID{}) {
		return SubjectAccess{}, ErrForbidden
	}
	return access, nil
}

func baseWrite(actor Actor, caseID kernel.EntityID, envelope MutationEnvelope, operation string, payload any) (BaseWrite, error) {
	command, err := commandBinding(operation, envelope.IdempotencyKey, payload)
	if err != nil {
		return BaseWrite{}, err
	}
	return BaseWrite{Actor: actor, CaseID: caseID, Command: command, Audit: envelope.Audit}, nil
}

func entityTenantMatches(tenant kernel.EntityID, tenantID uuid.UUID) bool {
	return tenant.String() == tenantID.String()
}

func (service *Service) validStoredObjectLocation(object kernel.StorageObject, tenantID uuid.UUID, objectID kernel.EntityID) bool {
	return entityTenantMatches(object.TenantID(), tenantID) && object.ID() == objectID &&
		object.Bucket() == service.bucket && object.ObjectKey() == tenantID.String()+"/"+objectID.String()
}

func validPreparedUploadProjection(
	result PreparedUploadRecord,
	wantStorage kernel.StorageObject,
	wantAttachment kernel.Attachment,
	sizeBytes int64,
	contentType string,
	now time.Time,
	maximumExpiry time.Time,
) bool {
	return result.Storage.Version() == 1 && result.Storage.State() == kernel.ScanPendingUpload &&
		result.Storage.ExpectedSizeBytes() == sizeBytes &&
		result.Attachment.ScanState() == kernel.ScanPendingUpload &&
		result.Storage.CreatedAt().Equal(result.Storage.UpdatedAt()) &&
		result.Attachment.UploadedAt().Equal(result.Storage.CreatedAt()) &&
		!result.Storage.CreatedAt().After(now) && result.Storage.UploadExpiresAt().After(now) &&
		!result.Storage.UploadExpiresAt().After(maximumExpiry) &&
		validAttachmentStoragePair(result.Attachment, result.Storage) &&
		sameFingerprint(
			uploadFingerprint(result.Storage, result.Attachment, sizeBytes, contentType),
			uploadFingerprint(wantStorage, wantAttachment, sizeBytes, contentType),
		)
}

func validAttachmentStoragePair(attachment kernel.Attachment, storage kernel.StorageObject) bool {
	return attachment.TenantID() == storage.TenantID() &&
		attachment.StorageObjectID() == storage.ID() &&
		attachment.OriginalFilename() == storage.OriginalFilename() &&
		attachment.UploadedBy() == storage.CreatedBy() &&
		attachment.UploadedAt().Equal(storage.CreatedAt()) &&
		attachment.ScanState() == storage.State()
}

func actorEntities(actor Actor) (kernel.EntityID, kernel.EntityID, error) {
	tenant, err := kernel.NewEntityID([16]byte(actor.TenantID))
	if err != nil {
		return kernel.EntityID{}, kernel.EntityID{}, err
	}
	membership, err := kernel.NewEntityID([16]byte(actor.MembershipID))
	if err != nil {
		return kernel.EntityID{}, kernel.EntityID{}, err
	}
	return tenant, membership, nil
}

func validUploadGrant(grant UploadGrant, now, maximumExpiry time.Time) bool {
	if grant.Method != "PUT" || !validPresignedURL(grant.TargetURL) || !grant.ExpiresAt.After(now) || grant.ExpiresAt.After(maximumExpiry) ||
		len(grant.Headers) > 32 {
		return false
	}
	seen := make(map[string]struct{}, len(grant.Headers))
	for _, header := range grant.Headers {
		name := httpCanonicalHeader(header.Name)
		if name == "" || !validSingleLine(header.Value, 4_096, true) {
			return false
		}
		if _, duplicate := seen[name]; duplicate {
			return false
		}
		seen[name] = struct{}{}
	}
	return true
}

var objectBucketPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)

func validObjectBucket(value string) bool {
	if !objectBucketPattern.MatchString(value) || strings.Contains(value, "..") ||
		strings.Contains(value, ".-") || strings.Contains(value, "-.") {
		return false
	}
	_, err := netip.ParseAddr(value)
	return err != nil
}

func validPresignedURL(value string) bool {
	if !validSingleLine(value, 16*1024, false) {
		return false
	}
	parsed, err := url.Parse(value)
	return err == nil && (parsed.Scheme == "https" || parsed.Scheme == "http") &&
		parsed.Host != "" && parsed.User == nil && parsed.Fragment == ""
}

func validScanVerdict(verdict ScanVerdict) bool {
	return verdict == ScanVerdictClean || verdict == ScanVerdictMalicious || verdict == ScanVerdictFailed
}

func validStorageTransition(result, expected kernel.StorageObject) bool {
	return sameFingerprint(storageFingerprint(result), storageFingerprint(expected))
}

func sameEntityReference(left, right kernel.EntityReference) bool {
	return left.TenantID() == right.TenantID() && left.Kind() == right.Kind() && left.ID() == right.ID() &&
		left.ExternalType() == right.ExternalType() && left.ExternalID() == right.ExternalID()
}

func (service *Service) now() time.Time {
	return service.clock().UTC().Truncate(time.Microsecond)
}

func httpCanonicalHeader(value string) string {
	if !validSingleLine(value, 128, false) {
		return ""
	}
	for _, character := range value {
		if character <= 0x20 || character >= 0x7f || character == ':' {
			return ""
		}
	}
	return textproto.CanonicalMIMEHeaderKey(value)
}

func hasUsableDeadline(ctx context.Context, now time.Time) bool {
	if ctx.Err() != nil {
		return false
	}
	deadline, ok := ctx.Deadline()
	return ok && deadline.After(now) && deadline.Sub(now) <= 30*time.Minute
}

func hashBoundedObject(ctx context.Context, body io.Reader, maximum int64) (string, int64, string, error) {
	if maximum <= 0 || maximum > maximumObjectBytes {
		return "", 0, "", ErrInvalidInput
	}
	hash := sha256.New()
	prefix := make([]byte, 512)
	read, err := io.ReadFull(contextReader{ctx: ctx, reader: body}, prefix)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return "", 0, "", err
	}
	if _, err = hash.Write(prefix[:read]); err != nil {
		return "", 0, "", err
	}
	remaining := maximum - int64(read) + 1
	copied, err := io.Copy(hash, io.LimitReader(contextReader{ctx: ctx, reader: body}, remaining))
	if err != nil {
		return "", 0, "", err
	}
	size := int64(read) + copied
	if size > maximum {
		return "", 0, "", ErrInvalidInput
	}
	return hex.EncodeToString(hash.Sum(nil)), size, sniffMediaType(prefix[:read]), nil
}

func (service *Service) rejectVerification(ctx context.Context, worker WorkerContext, current kernel.StorageObject) {
	rejected, err := current.RejectVerification(current.Version(), service.now())
	if err == nil {
		_ = service.repository.RejectStorageVerification(ctx, WorkerStorageWrite{
			Worker: worker, Current: current, Updated: rejected, ExpectedVersion: current.Version(),
		})
	}
}

func (service *Service) completeFailedScan(
	ctx context.Context,
	worker WorkerContext,
	current kernel.StorageObject,
	cause error,
) (kernel.StorageObject, error) {
	failed, err := current.CompleteScan(current.Version(), kernel.ScanFailed, service.now())
	if err != nil {
		return kernel.StorageObject{}, ErrConflict
	}
	stored, err := service.repository.CompleteStorageScan(ctx, WorkerStorageWrite{
		Worker: worker, Current: current, Updated: failed, ExpectedVersion: current.Version(),
	})
	if err != nil || !validStorageTransition(stored, failed) {
		return kernel.StorageObject{}, ErrUnavailable
	}
	return stored, cause
}

func applyCustody(current kernel.Evidence, command CustodyCommand) (kernel.Evidence, error) {
	switch command.Event.Action {
	case kernel.CustodyAccessed, kernel.CustodyTransferred, kernel.CustodySealed, kernel.CustodyUnsealed:
		if command.NextScanState != "" || command.LegalHold != nil || command.RetentionSet {
			return kernel.Evidence{}, kernel.ErrInvalidEvidence
		}
		return current.AppendCustodyEvent(command.ExpectedVersion, command.Event)
	case kernel.CustodyScanStateChanged:
		if command.NextScanState == "" || command.LegalHold != nil || command.RetentionSet {
			return kernel.Evidence{}, kernel.ErrInvalidEvidence
		}
		return current.ChangeScanState(command.ExpectedVersion, command.Event, command.NextScanState)
	case kernel.CustodyLegalHoldPlaced, kernel.CustodyLegalHoldReleased:
		if command.LegalHold == nil || command.NextScanState != "" || command.RetentionSet {
			return kernel.Evidence{}, kernel.ErrInvalidEvidence
		}
		return current.ChangeLegalHold(command.ExpectedVersion, command.Event, *command.LegalHold)
	case kernel.CustodyRetentionChanged:
		if !command.RetentionSet || command.NextScanState != "" || command.LegalHold != nil {
			return kernel.Evidence{}, kernel.ErrInvalidEvidence
		}
		return current.ChangeRetention(command.ExpectedVersion, command.Event, command.RetentionUntil)
	case kernel.CustodyDestroyed:
		if command.NextScanState != "" || command.LegalHold != nil || command.RetentionSet {
			return kernel.Evidence{}, kernel.ErrInvalidEvidence
		}
		return current.Destroy(command.ExpectedVersion, command.Event)
	default:
		return kernel.Evidence{}, kernel.ErrInvalidEvidence
	}
}

func repositoryError(err error) error {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, ErrRepositoryForbidden):
		return ErrForbidden
	case errors.Is(err, ErrRepositoryNotFound):
		return ErrNotFound
	case errors.Is(err, ErrRepositoryConflict):
		return ErrConflict
	case errors.Is(err, ErrRepositoryPrecondition):
		return ErrPreconditionFailed
	default:
		return ErrUnavailable
	}
}
