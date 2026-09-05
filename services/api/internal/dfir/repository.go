package dfir

import (
	"context"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/dfir"
)

// Repository resolves live authority and commits each resource mutation with
// its redacted activity, audit, and outbox effects in one transaction.
type Repository interface {
	ResolveAccess(context.Context, Actor, uuid.UUID, Capability, ResourceScope) (Access, error)
	ResolveAlertAccess(context.Context, Actor, uuid.UUID, Capability, AlertResourceScope) (Access, error)
	ResolveSubjectAccess(context.Context, Actor, uuid.UUID, Capability, kernel.EntityID, kernel.EntityReference) (SubjectAccess, error)
	ResolveAlertSubjectAccess(context.Context, Actor, uuid.UUID, Capability, kernel.EntityID, kernel.EntityReference) (AlertSubjectAccess, error)
	LoadWorkspace(context.Context, Actor, uuid.UUID, kernel.EntityID, WorkspaceAccess) (Workspace, error)
	LoadAlertWorkspace(context.Context, Actor, uuid.UUID, kernel.EntityID, WorkspaceAccess) (AlertWorkspace, error)
	CreateIndicator(context.Context, IndicatorWrite) (MutationResult[kernel.Indicator], error)
	ReplaceIndicator(context.Context, IndicatorWrite) (MutationResult[kernel.Indicator], error)
	CreateAsset(context.Context, AssetWrite) (MutationResult[kernel.Asset], error)
	ReplaceAsset(context.Context, AssetWrite) (MutationResult[kernel.Asset], error)
	CreateTimelineEvent(context.Context, TimelineWrite) (MutationResult[kernel.TimelineEvent], error)
	CommitTask(context.Context, TaskCreateWrite) (MutationResult[kernel.Task], error)
	MutateTask(context.Context, TaskMutationWrite) (MutationResult[kernel.Task], error)
	CreateRelationship(context.Context, RelationshipWrite) (MutationResult[kernel.Relationship], error)
	MutateRelationship(context.Context, RelationshipMutationWrite) (MutationResult[kernel.Relationship], error)
	CreateStorageObject(context.Context, StorageWrite) (PreparedUploadRecord, error)
	GetCaseStorageObject(context.Context, Actor, uuid.UUID, kernel.EntityID, kernel.EntityID, kernel.EntityID, Access) (kernel.StorageObject, error)
	GetAlertStorageObject(context.Context, Actor, uuid.UUID, kernel.EntityID, kernel.EntityID, kernel.EntityID, Access) (kernel.StorageObject, error)
	GetStorageObjectAsWorker(context.Context, WorkerContext, kernel.EntityID) (kernel.StorageObject, error)
	MarkStorageUploadedAsWorker(context.Context, WorkerStorageWrite) (kernel.StorageObject, error)
	BeginStorageVerification(context.Context, WorkerStorageWrite) (kernel.StorageObject, error)
	CompleteStorageVerification(context.Context, WorkerStorageWrite) (kernel.StorageObject, error)
	RejectStorageVerification(context.Context, WorkerStorageWrite) error
	BeginStorageScan(context.Context, WorkerStorageWrite) (kernel.StorageObject, error)
	CompleteStorageScan(context.Context, WorkerStorageWrite) (kernel.StorageObject, error)
	GetAttachment(context.Context, Actor, uuid.UUID, kernel.EntityID, kernel.EntityID, Access) (AttachmentDownloadRecord, error)
	GetAlertAttachment(context.Context, Actor, uuid.UUID, kernel.EntityID, kernel.EntityID, Access) (AttachmentDownloadRecord, error)
	AuditDownloadGrant(context.Context, DownloadGrantAuditWrite) error
	CreateEvidence(context.Context, EvidenceWrite) (MutationResult[kernel.Evidence], error)
	GetEvidence(context.Context, Actor, uuid.UUID, kernel.EntityID, kernel.EntityID, Access) (kernel.Evidence, error)
	AppendCustody(context.Context, CustodyWrite) (MutationResult[kernel.Evidence], error)
}

type SubjectAccess struct {
	CaseID            kernel.EntityID
	Access            Access
	SubjectVisibility kernel.Visibility
}

type AlertSubjectAccess struct {
	AlertID           kernel.EntityID
	Access            Access
	SubjectVisibility kernel.Visibility
}

type BaseWrite struct {
	Actor   Actor
	CaseID  kernel.EntityID
	AlertID kernel.EntityID
	Command CommandBinding
	Audit   AuditContext
}

type IndicatorWrite struct {
	BaseWrite
	Indicator       kernel.Indicator
	ExpectedVersion uint64
}

type AssetWrite struct {
	BaseWrite
	Asset           kernel.Asset
	ExpectedVersion uint64
}

type TimelineWrite struct {
	BaseWrite
	Event kernel.TimelineEvent
}

// TaskMutationContract carries the server-owned effects and the preflight
// access tuple. The repository must revalidate live Case authority inside the
// write transaction before consulting or creating an idempotency receipt.
type TaskMutationContract struct {
	BaseWrite
	Access          Access
	Capability      Capability
	ActivityType    string
	ActivitySummary string
	AuditAction     string
	AuditReason     string
	OutboxEventType string
}

type TaskCreateWrite struct {
	Contract TaskMutationContract
	Task     kernel.Task
}

// TaskMutationWrite keeps aggregate transition logic behind the repository's
// authority, receipt, row-lock, and compare-and-swap boundary. Apply is called
// exactly once for a fresh command and never for an exact replay.
type TaskMutationWrite struct {
	Contract        TaskMutationContract
	TaskID          kernel.EntityID
	ExpectedVersion uint64
	Apply           func(kernel.Task) (kernel.Task, error)
}

type RelationshipWrite struct {
	BaseWrite
	Relationship kernel.Relationship
}

// RelationshipMutationWrite keeps the terminal Case relationship transition
// behind the repository's live authority, endpoint validation, durable caller
// identifier, receipt, row-lock, CAS, and journal boundary. Apply executes once
// for a fresh command and never for an exact replay.
type RelationshipMutationWrite struct {
	BaseWrite
	RelationshipID  kernel.EntityID
	RetractionID    kernel.EntityID
	ExpectedVersion uint64
	Apply           func(kernel.Relationship) (kernel.Relationship, error)
}

type StorageWrite struct {
	BaseWrite
	Storage      kernel.StorageObject
	Attachment   kernel.Attachment
	DeclaredMIME string
}

type PreparedUploadRecord struct {
	Storage    kernel.StorageObject
	Attachment kernel.Attachment
	Replayed   bool
}

// AttachmentDownloadRecord preserves the exact mutable database revisions
// observed before a signed capability is created. The final audit transaction
// must recheck both revisions and the root revision before the capability may
// cross the service boundary.
type AttachmentDownloadRecord struct {
	Attachment        kernel.Attachment
	AttachmentVersion uint64
	RootVersion       uint64
}

const maximumDownloadGrantRevision = uint64(9_007_199_254_740_991)

func validAttachmentDownloadRevisions(record AttachmentDownloadRecord, storage kernel.StorageObject) bool {
	return record.AttachmentVersion > 0 && record.AttachmentVersion <= maximumDownloadGrantRevision &&
		record.RootVersion > 0 && record.RootVersion <= maximumDownloadGrantRevision &&
		storage.Version() > 0 && storage.Version() <= maximumDownloadGrantRevision
}

// DownloadGrantAuditWrite is deliberately an allowlisted projection. Signed
// URLs, object locations, filenames, content hashes, and other customer data
// cannot be represented at this persistence boundary.
type DownloadGrantAuditWrite struct {
	Actor               Actor
	Audit               AuditContext
	Root                PortalAttachmentRoot
	RootVersion         uint64
	Subject             kernel.EntityReference
	AttachmentID        kernel.EntityID
	AttachmentVersion   uint64
	AttachmentState     kernel.ScanState
	StorageObjectID     kernel.EntityID
	StorageVersion      uint64
	StorageState        kernel.ScanState
	Access              Access
	PortalAuthorization *PortalAttachmentAuthorization
	ExpiresAt           time.Time
}

type EvidenceWrite struct {
	BaseWrite
	EvidenceID            kernel.EntityID
	StorageObjectID       kernel.EntityID
	InitialCustodyEventID kernel.EntityID
	Build                 func(kernel.StorageObject) (kernel.Evidence, error)
}

type CustodyWrite struct {
	BaseWrite
	EvidenceID      kernel.EntityID
	EventID         kernel.EntityID
	ExpectedVersion uint64
	Apply           func(kernel.Evidence) (kernel.Evidence, error)
}

type WorkerStorageWrite struct {
	Worker          WorkerContext
	Current         kernel.StorageObject
	Updated         kernel.StorageObject
	ExpectedVersion uint64
}
