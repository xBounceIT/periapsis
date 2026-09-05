package dfir

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"slices"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/dfir"
)

const (
	defaultPortalAttachmentPageLimit = 50
	maximumPortalAttachmentPageLimit = 100
	portalAttachmentCursorVersion    = byte(1)
	portalAttachmentCursorSize       = 1 + 16 + 8 + 16
)

type PortalTicketKind string

const (
	PortalTicketAlert PortalTicketKind = "alert"
	PortalTicketCase  PortalTicketKind = "case"
)

type PortalAttachmentRoot struct {
	Kind PortalTicketKind
	ID   kernel.EntityID
}

// CustomerPortalAttachment is an application-level allowlist. Storage,
// tenant, uploader, subject, classification, visibility, and scan metadata
// deliberately cannot cross this boundary.
type CustomerPortalAttachment struct {
	ID               kernel.EntityID
	ResourceKind     PortalTicketKind
	ResourceID       kernel.EntityID
	OriginalFilename string
	UploadedAt       time.Time
}

type CustomerPortalAttachmentPage struct {
	Items      []CustomerPortalAttachment
	NextCursor string
}

type CustomerPortalAttachmentListInput struct {
	After string
	Limit int
}

type CustomerPortalPreparedDownload struct {
	Attachment CustomerPortalAttachment
	Grant      DownloadGrant
}

type PortalAttachmentAuthorization struct {
	TenantID      uuid.UUID
	Root          PortalAttachmentRoot
	ContactID     uuid.UUID
	TicketVersion uint64
}

type PortalAttachmentPosition struct {
	UploadedAt time.Time
	ID         kernel.EntityID
}

type PortalAttachmentListQuery struct {
	Root          PortalAttachmentRoot
	Authorization PortalAttachmentAuthorization
	After         *PortalAttachmentPosition
	Bucket        string
	Limit         int
}

type PortalAttachmentDownloadQuery struct {
	Root          PortalAttachmentRoot
	AttachmentID  kernel.EntityID
	Authorization PortalAttachmentAuthorization
}

type PortalAttachmentDownloadRecord struct {
	Attachment        kernel.Attachment
	AttachmentVersion uint64
	RootVersion       uint64
	Storage           kernel.StorageObject
}

type PortalAttachmentAuthorizer interface {
	AuthorizePortalAttachment(context.Context, Actor, uuid.UUID, PortalAttachmentRoot) (PortalAttachmentAuthorization, error)
}

// PortalAttachmentRepository is kept separate from the operator Repository so
// an adapter must opt in to the customer projection and its stronger live-link
// checks. Services built with older/test repositories fail closed.
type PortalAttachmentRepository interface {
	ListPortalAttachments(context.Context, Actor, uuid.UUID, PortalAttachmentListQuery) ([]kernel.Attachment, error)
	GetPortalAttachmentDownload(context.Context, Actor, uuid.UUID, PortalAttachmentDownloadQuery) (PortalAttachmentDownloadRecord, error)
}

func (service *Service) ListCustomerPortalAttachments(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	root PortalAttachmentRoot,
	input CustomerPortalAttachmentListInput,
) (CustomerPortalAttachmentPage, error) {
	if err := ctx.Err(); err != nil {
		return CustomerPortalAttachmentPage{}, err
	}
	if !validPortalActorRoot(actor, tenantID, root) {
		return CustomerPortalAttachmentPage{}, ErrForbidden
	}
	if service.portalAuthorizer == nil || service.portalRepository == nil {
		return CustomerPortalAttachmentPage{}, ErrUnavailable
	}
	limit := input.Limit
	if limit == 0 {
		limit = defaultPortalAttachmentPageLimit
	}
	if limit < 1 || limit > maximumPortalAttachmentPageLimit || len(input.After) > 512 {
		return CustomerPortalAttachmentPage{}, ErrInvalidInput
	}
	authorization, err := service.portalAuthorizer.AuthorizePortalAttachment(ctx, actor, tenantID, root)
	if err != nil {
		return CustomerPortalAttachmentPage{}, portalAuthorizationError(err)
	}
	if !validPortalAttachmentAuthorization(authorization, tenantID, root) {
		return CustomerPortalAttachmentPage{}, ErrForbidden
	}
	position, err := decodePortalAttachmentCursor(input.After, portalAttachmentCursorFingerprint(actor, authorization))
	if err != nil {
		return CustomerPortalAttachmentPage{}, err
	}
	items, err := service.portalRepository.ListPortalAttachments(ctx, actor, tenantID, PortalAttachmentListQuery{
		Root: root, Authorization: authorization, After: position, Bucket: service.bucket, Limit: limit + 1,
	})
	if err != nil {
		return CustomerPortalAttachmentPage{}, repositoryError(err)
	}
	if err = ctx.Err(); err != nil {
		return CustomerPortalAttachmentPage{}, err
	}
	if len(items) > limit+1 {
		return CustomerPortalAttachmentPage{}, ErrUnavailable
	}
	for index := range items {
		if !validCustomerPortalAttachmentRecord(items[index], tenantID) ||
			(index > 0 && !portalAttachmentBefore(items[index-1], items[index])) {
			return CustomerPortalAttachmentPage{}, ErrUnavailable
		}
	}
	hasMore := len(items) > limit
	if hasMore {
		items = items[:limit]
	}
	page := CustomerPortalAttachmentPage{Items: make([]CustomerPortalAttachment, len(items))}
	for index, attachment := range items {
		page.Items[index] = customerPortalAttachment(root, attachment)
	}
	if hasMore {
		page.NextCursor = encodePortalAttachmentCursor(
			portalAttachmentCursorFingerprint(actor, authorization),
			PortalAttachmentPosition{UploadedAt: items[len(items)-1].UploadedAt(), ID: items[len(items)-1].ID()},
		)
		if page.NextCursor == "" {
			return CustomerPortalAttachmentPage{}, ErrUnavailable
		}
	}
	page.Items = slices.Clone(page.Items)
	return page, nil
}

func (service *Service) PrepareCustomerPortalAttachmentDownload(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	root PortalAttachmentRoot,
	attachmentID kernel.EntityID,
	audit AuditContext,
) (CustomerPortalPreparedDownload, error) {
	if err := ctx.Err(); err != nil {
		return CustomerPortalPreparedDownload{}, err
	}
	if !validPortalActorRoot(actor, tenantID, root) {
		return CustomerPortalPreparedDownload{}, ErrForbidden
	}
	if !validPortalEntityID(attachmentID) || !validDownloadAudit(actor, audit) {
		return CustomerPortalPreparedDownload{}, ErrInvalidInput
	}
	if service.portalAuthorizer == nil || service.portalRepository == nil {
		return CustomerPortalPreparedDownload{}, ErrUnavailable
	}
	if !hasUsableDeadline(ctx, service.clock()) {
		return CustomerPortalPreparedDownload{}, ErrInvalidInput
	}
	authorization, err := service.portalAuthorizer.AuthorizePortalAttachment(ctx, actor, tenantID, root)
	if err != nil {
		return CustomerPortalPreparedDownload{}, portalAuthorizationError(err)
	}
	if !validPortalAttachmentAuthorization(authorization, tenantID, root) {
		return CustomerPortalPreparedDownload{}, ErrForbidden
	}
	record, err := service.portalRepository.GetPortalAttachmentDownload(ctx, actor, tenantID, PortalAttachmentDownloadQuery{
		Root: root, AttachmentID: attachmentID, Authorization: authorization,
	})
	if err != nil {
		return CustomerPortalPreparedDownload{}, repositoryError(err)
	}
	if !service.validCustomerPortalDownloadRecord(record, tenantID, attachmentID) ||
		record.RootVersion != authorization.TicketVersion {
		return CustomerPortalPreparedDownload{}, ErrNotFound
	}
	// Re-resolve the contact link and both permissions immediately before the
	// external capability is minted. A concurrent ticket/link change fails
	// closed instead of reusing the earlier authorization evidence.
	rechecked, err := service.portalAuthorizer.AuthorizePortalAttachment(ctx, actor, tenantID, root)
	if err != nil {
		return CustomerPortalPreparedDownload{}, portalAuthorizationError(err)
	}
	if rechecked != authorization || ctx.Err() != nil {
		if ctx.Err() != nil {
			return CustomerPortalPreparedDownload{}, ctx.Err()
		}
		return CustomerPortalPreparedDownload{}, ErrConflict
	}
	recheckedRecord, err := service.portalRepository.GetPortalAttachmentDownload(ctx, actor, tenantID, PortalAttachmentDownloadQuery{
		Root: root, AttachmentID: attachmentID, Authorization: rechecked,
	})
	if err != nil {
		return CustomerPortalPreparedDownload{}, repositoryError(err)
	}
	if !service.validCustomerPortalDownloadRecord(recheckedRecord, tenantID, attachmentID) ||
		recheckedRecord.RootVersion != rechecked.TicketVersion ||
		!samePortalDownloadRecord(record, recheckedRecord) {
		return CustomerPortalPreparedDownload{}, ErrConflict
	}
	if err = ctx.Err(); err != nil {
		return CustomerPortalPreparedDownload{}, err
	}
	now := service.now()
	expiresAt := now.Add(5 * time.Minute)
	grant, err := service.storage.PrepareDownload(ctx, ObjectLocation{
		Bucket: recheckedRecord.Storage.Bucket(), Key: recheckedRecord.Storage.ObjectKey(),
	}, expiresAt)
	if err != nil || !validPresignedURL(grant.TargetURL) || !grant.ExpiresAt.After(now) || grant.ExpiresAt.After(expiresAt) {
		return CustomerPortalPreparedDownload{}, ErrUnavailable
	}
	if err = ctx.Err(); err != nil {
		return CustomerPortalPreparedDownload{}, err
	}
	portalAuthorization := rechecked
	if err = service.repository.AuditDownloadGrant(ctx, DownloadGrantAuditWrite{
		Actor: actor, Audit: audit, Root: root, RootVersion: recheckedRecord.RootVersion,
		Subject: recheckedRecord.Attachment.Subject(), AttachmentID: recheckedRecord.Attachment.ID(),
		AttachmentVersion: recheckedRecord.AttachmentVersion, AttachmentState: recheckedRecord.Attachment.ScanState(),
		StorageObjectID: recheckedRecord.Storage.ID(), StorageVersion: recheckedRecord.Storage.Version(),
		StorageState: recheckedRecord.Storage.State(), Access: Access{Audience: kernel.AudienceCustomer, Scope: ScopeOwn},
		PortalAuthorization: &portalAuthorization, ExpiresAt: grant.ExpiresAt,
	}); err != nil {
		return CustomerPortalPreparedDownload{}, repositoryError(err)
	}
	return CustomerPortalPreparedDownload{
		Attachment: customerPortalAttachment(root, recheckedRecord.Attachment), Grant: grant,
	}, nil
}

func validPortalActorRoot(actor Actor, tenantID uuid.UUID, root PortalAttachmentRoot) bool {
	return validActor(actor, tenantID) && actor.Kind == PrincipalCustomer &&
		(root.Kind == PortalTicketAlert || root.Kind == PortalTicketCase) && validPortalEntityID(root.ID)
}

func validPortalEntityID(id kernel.EntityID) bool {
	value := uuid.UUID(id.Bytes())
	return value != uuid.Nil && value.Version() == 7
}

func validPortalAttachmentAuthorization(value PortalAttachmentAuthorization, tenantID uuid.UUID, root PortalAttachmentRoot) bool {
	return value.TenantID == tenantID && value.Root == root && value.ContactID != uuid.Nil &&
		value.ContactID.Version() == 7 && value.TicketVersion > 0
}

func validCustomerPortalAttachmentRecord(value kernel.Attachment, tenantID uuid.UUID) bool {
	return validPortalEntityID(value.ID()) && entityTenantMatches(value.TenantID(), tenantID) &&
		value.CanIssueDownload(kernel.AudienceCustomer) && !value.UploadedAt().IsZero() &&
		value.UploadedAt().Location() == time.UTC && value.UploadedAt().Nanosecond()%1_000 == 0
}

func (service *Service) validCustomerPortalDownloadRecord(value PortalAttachmentDownloadRecord, tenantID uuid.UUID, attachmentID kernel.EntityID) bool {
	return value.Attachment.ID() == attachmentID && validCustomerPortalAttachmentRecord(value.Attachment, tenantID) &&
		validAttachmentDownloadRevisions(AttachmentDownloadRecord{
			Attachment: value.Attachment, AttachmentVersion: value.AttachmentVersion, RootVersion: value.RootVersion,
		}, value.Storage) &&
		service.validStoredObjectLocation(value.Storage, tenantID, value.Attachment.StorageObjectID()) &&
		validAttachmentStoragePair(value.Attachment, value.Storage) && value.Storage.CanIssueDownload()
}

func samePortalDownloadRecord(left, right PortalAttachmentDownloadRecord) bool {
	return left.Attachment.ID() == right.Attachment.ID() &&
		left.AttachmentVersion == right.AttachmentVersion && left.RootVersion == right.RootVersion &&
		left.Attachment.TenantID() == right.Attachment.TenantID() &&
		sameEntityReference(left.Attachment.Subject(), right.Attachment.Subject()) &&
		left.Attachment.StorageObjectID() == right.Attachment.StorageObjectID() &&
		left.Attachment.OriginalFilename() == right.Attachment.OriginalFilename() &&
		left.Attachment.Visibility() == right.Attachment.Visibility() &&
		left.Attachment.ScanState() == right.Attachment.ScanState() &&
		left.Attachment.UploadedBy() == right.Attachment.UploadedBy() &&
		left.Attachment.UploadedAt().Equal(right.Attachment.UploadedAt()) &&
		left.Storage.ID() == right.Storage.ID() && left.Storage.Version() == right.Storage.Version() &&
		left.Storage.TenantID() == right.Storage.TenantID() && left.Storage.State() == right.Storage.State() &&
		left.Storage.Bucket() == right.Storage.Bucket() && left.Storage.ObjectKey() == right.Storage.ObjectKey() &&
		left.Storage.OriginalFilename() == right.Storage.OriginalFilename() &&
		left.Storage.CreatedBy() == right.Storage.CreatedBy() && left.Storage.CreatedAt().Equal(right.Storage.CreatedAt())
}

func customerPortalAttachment(root PortalAttachmentRoot, attachment kernel.Attachment) CustomerPortalAttachment {
	return CustomerPortalAttachment{
		ID: attachment.ID(), ResourceKind: root.Kind, ResourceID: root.ID,
		OriginalFilename: attachment.OriginalFilename(), UploadedAt: attachment.UploadedAt(),
	}
}

func portalAttachmentBefore(previous, current kernel.Attachment) bool {
	if previous.UploadedAt().Equal(current.UploadedAt()) {
		return previous.ID().String() > current.ID().String()
	}
	return previous.UploadedAt().After(current.UploadedAt())
}

func portalAttachmentCursorFingerprint(actor Actor, authorization PortalAttachmentAuthorization) [16]byte {
	digest := sha256.New()
	digest.Write([]byte("periapsis.customer-portal-attachment.cursor.v1\x00"))
	digest.Write(actor.TenantID[:])
	digest.Write(actor.UserID[:])
	digest.Write(actor.MembershipID[:])
	digest.Write([]byte{byte(len(authorization.Root.Kind))})
	digest.Write([]byte(authorization.Root.Kind))
	rootID := authorization.Root.ID.Bytes()
	digest.Write(rootID[:])
	digest.Write(authorization.ContactID[:])
	var version [8]byte
	binary.BigEndian.PutUint64(version[:], authorization.TicketVersion)
	digest.Write(version[:])
	var result [16]byte
	copy(result[:], digest.Sum(nil))
	return result
}

func encodePortalAttachmentCursor(fingerprint [16]byte, position PortalAttachmentPosition) string {
	if !validPortalEntityID(position.ID) || position.UploadedAt.IsZero() || position.UploadedAt.Location() != time.UTC ||
		position.UploadedAt.Nanosecond()%1_000 != 0 {
		return ""
	}
	payload := make([]byte, portalAttachmentCursorSize)
	payload[0] = portalAttachmentCursorVersion
	copy(payload[1:17], fingerprint[:])
	binary.BigEndian.PutUint64(payload[17:25], uint64(position.UploadedAt.UnixMicro()))
	id := position.ID.Bytes()
	copy(payload[25:], id[:])
	return base64.RawURLEncoding.EncodeToString(payload)
}

func decodePortalAttachmentCursor(value string, fingerprint [16]byte) (*PortalAttachmentPosition, error) {
	if value == "" {
		return nil, nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(payload) != portalAttachmentCursorSize || payload[0] != portalAttachmentCursorVersion ||
		base64.RawURLEncoding.EncodeToString(payload) != value || !slices.Equal(payload[1:17], fingerprint[:]) {
		return nil, ErrInvalidInput
	}
	id, err := kernel.NewEntityID([16]byte(payload[25:41]))
	if err != nil || !validPortalEntityID(id) {
		return nil, ErrInvalidInput
	}
	uploadedAt := time.UnixMicro(int64(binary.BigEndian.Uint64(payload[17:25]))).UTC()
	if uploadedAt.IsZero() || uploadedAt.Nanosecond()%1_000 != 0 {
		return nil, ErrInvalidInput
	}
	return &PortalAttachmentPosition{UploadedAt: uploadedAt, ID: id}, nil
}

func portalAuthorizationError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded),
		errors.Is(err, ErrInvalidInput), errors.Is(err, ErrForbidden), errors.Is(err, ErrNotFound),
		errors.Is(err, ErrConflict), errors.Is(err, ErrPreconditionFailed), errors.Is(err, ErrUnavailable):
		return err
	default:
		return ErrUnavailable
	}
}
