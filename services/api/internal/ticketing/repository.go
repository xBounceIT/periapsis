package ticketing

import (
	"context"
	"crypto/sha256"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
)

// Repository is the persistence and live-authorization port. Implementations
// must filter authorized/customer-visible rows before pagination and commit a
// mutation plan, activity, audit, SLA changes, and notifications atomically.
type Repository interface {
	ResolveAccess(context.Context, Actor, uuid.UUID, Capability) (LiveAccess, error)
	Workflow(context.Context, uuid.UUID, uuid.UUID, kernel.AggregateKind, *uuid.UUID) (kernel.WorkflowDefinition, error)
	ReserveID(context.Context, uuid.UUID) (kernel.EntityID, error)
	List(context.Context, uuid.UUID, kernel.AggregateKind, ListInput, LiveAccess) (RecordPage, error)
	Get(context.Context, uuid.UUID, uuid.UUID, kernel.AggregateKind, uuid.UUID) (Record, error)
	GetForAccess(context.Context, uuid.UUID, kernel.AggregateKind, uuid.UUID, LiveAccess) (Record, error)
	CreateCase(context.Context, CreateCaseWrite) (WriteResult, error)
	ApplyMutation(context.Context, MutationWrite) (WriteResult, error)
	LookupMutationReplay(context.Context, MutationReplayQuery) (WriteResult, bool, error)
	ReplaceMetadata(context.Context, MetadataWrite) (MetadataMutationResult, error)
	ListWatchers(context.Context, WatcherListQuery) (TicketWatcherProjection, error)
	MutateWatcher(context.Context, WatcherMutationWrite) (WatcherMutationResult, error)
	DeleteAlert(context.Context, DeleteAlertWrite) (DeleteAlertReceipt, error)
	LookupAlertDeleteReplay(context.Context, DeleteAlertReplayQuery) (DeleteAlertReceipt, bool, error)
	ListComments(context.Context, Record, CursorPageInput, LiveAccess) (StoredCommentPage, error)
	PreviewComment(context.Context, CommentPreviewQuery) (StoredCommentPreview, error)
	ListCommentMentionCandidates(context.Context, CommentMentionCandidateQuery) ([]CommentMentionCandidate, error)
	ExportPortal(context.Context, uuid.UUID, kernel.AggregateKind, uuid.UUID, LiveAccess, int) (CustomerPortalExport, error)
	CreateComment(context.Context, CommentWrite) (CommentWriteResult, error)
	PreflightCommentEdit(context.Context, CommentEditWrite) (CommentEditPreflight, error)
	EditComment(context.Context, CommentEditWrite) (CommentWriteResult, error)
	ListCommentRevisions(context.Context, CommentRevisionQuery) (StoredCommentRevisionPage, error)
	ListActivities(context.Context, Record, CursorPageInput, LiveAccess) (StoredActivityPage, error)
	ListActivityFeed(context.Context, uuid.UUID, kernel.AggregateKind, CursorPageInput, LiveAccess) (StoredActivityPage, error)
	ListLinks(context.Context, Record, CursorPageInput, LiveAccess, LiveAccess) (StoredLinkPage, error)
	ResolveLinkLifecycle(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID) (LinkLifecycle, error)
	ResolveEscalationSelection(context.Context, uuid.UUID, Record, CopySelection) (SelectionEvidence, error)
	CommitEscalation(context.Context, EscalationWrite) (EscalationWriteResult, error)
	LookupEscalationReplay(context.Context, EscalationReplayQuery) (EscalationWriteResult, bool, error)
	CommitUnlink(context.Context, UnlinkWrite) (UnlinkReceipt, error)
	LookupUnlinkReplay(context.Context, UnlinkReplayQuery) (UnlinkReceipt, bool, error)
	ListAlertRelations(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, CursorPageInput, LiveAccess) (StoredAlertRelationPage, error)
	GetAlertRelation(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID, LiveAccess) (AlertRelationRecord, error)
	CommitAlertRelationCreate(context.Context, AlertRelationCreateWrite) (AlertRelationMutationReceipt, error)
	LookupAlertRelationCreateReplay(context.Context, AlertRelationReplayQuery) (AlertRelationMutationReceipt, bool, error)
	CommitAlertRelationRetraction(context.Context, AlertRelationRetractionWrite) (AlertRelationMutationReceipt, error)
	LookupAlertRelationRetractionReplay(context.Context, AlertRelationReplayQuery) (AlertRelationMutationReceipt, bool, error)
}

type RecordPage struct {
	Items       []Record
	NextCursor  string
	AppliedView *SavedViewRecord
}

type CreateCaseWrite struct {
	Actor           Actor
	Content         CreateCaseInput
	Plans           []kernel.MutationPlan
	IdempotencyHash [sha256.Size]byte
	Audit           AuditContext
}

type MutationWrite struct {
	Actor           Actor
	Current         Record
	Plan            kernel.MutationPlan
	TransitionKey   string
	Reason          string
	CustomFields    map[string]any
	IdempotencyHash [sha256.Size]byte
	Fingerprint     [sha256.Size]byte
	Audit           AuditContext
}

type MutationReplayQuery struct {
	TenantID    uuid.UUID
	ActorID     uuid.UUID
	TicketID    uuid.UUID
	Kind        kernel.AggregateKind
	Action      kernel.Action
	KeyHash     [sha256.Size]byte
	Fingerprint [sha256.Size]byte
}

type WriteResult struct {
	Record   Record
	Replayed bool
}

type MetadataWrite struct {
	Actor           Actor
	TenantID        uuid.UUID
	Kind            kernel.AggregateKind
	TicketID        uuid.UUID
	Content         EditableMetadata
	ExpectedVersion uint64
	KeyHash         [sha256.Size]byte
	Fingerprint     [sha256.Size]byte
	Audit           AuditContext
}

type DeleteAlertWrite struct {
	Actor       Actor
	Current     Record
	Input       DeleteAlertInput
	KeyHash     [sha256.Size]byte
	Fingerprint [sha256.Size]byte
	Audit       AuditContext
}

type DeleteAlertReplayQuery struct {
	Actor       Actor
	TenantID    uuid.UUID
	AlertID     uuid.UUID
	KeyHash     [sha256.Size]byte
	Fingerprint [sha256.Size]byte
}

type StoredCommentPage struct {
	Items      []Comment
	NextCursor *uuid.UUID
}

type CommentWrite struct {
	Actor         Actor
	Record        Record
	Draft         kernel.CommentDraft
	BodyHTML      string
	AttachmentIDs []uuid.UUID
	MentionedIDs  []uuid.UUID
	// AuthorContactID is present only for a customer-portal comment. The
	// repository must re-resolve the exact active membership/user/contact/link
	// tuple and persist the author audience snapshot in the same transaction.
	AuthorContactID *uuid.UUID
	IdempotencyHash [sha256.Size]byte
	Audit           AuditContext
}

type CommentWriteResult struct {
	Comment  Comment
	Replayed bool
}

type CommentPreviewQuery struct {
	Actor           Actor
	Record          Record
	Visibility      kernel.CommentVisibility
	AttachmentIDs   []uuid.UUID
	MentionedIDs    []uuid.UUID
	AuthorContactID *uuid.UUID
}

type StoredCommentPreview struct {
	Attachments []CommentAttachment
	Mentions    []CommentMention
}

type CommentMentionCandidateQuery struct {
	Actor  Actor
	Record Record
	Search string
	Limit  int
}

type CommentEditWrite struct {
	Actor            Actor
	Record           Record
	CommentID        uuid.UUID
	ExpectedRevision int
	BodyMarkdown     string
	BodyHTML         string
	AttachmentIDs    []uuid.UUID
	MentionedIDs     []uuid.UUID
	Reason           string
	AuthorContactID  *uuid.UUID
	IdempotencyHash  [sha256.Size]byte
	Audit            AuditContext
}

type CommentEditPreflight struct {
	State          CommentEditState
	Replayed       bool
	ReplayRevision *int
}

type CommentRevisionQuery struct {
	Actor     Actor
	Record    Record
	CommentID uuid.UUID
	Page      CommentRevisionPageInput
	Access    LiveAccess
}

type StoredCommentRevisionPage struct {
	Items             []CommentRevision
	NextAfterRevision *int
}

type StoredActivityPage struct {
	Items      []Activity
	NextCursor *uuid.UUID
}

type StoredLinkPage struct {
	Items      []LinkRecord
	NextCursor *uuid.UUID
}

type LinkRecord struct {
	Link  Link
	Other Record
}

type LinkLifecycle struct {
	LinkID    uuid.UUID
	Retracted bool
}

type CopySelection struct {
	Fields           []kernel.CopyField
	CustomFields     []kernel.Key
	ItemIDs          map[kernel.CopyField][]uuid.UUID
	PublicCommentIDs []uuid.UUID
}

type SelectionEvidence struct {
	Items    []kernel.CopyItemReference
	Comments []kernel.CommentReference
}

type EscalationOperation string

const (
	EscalationOperationEscalate EscalationOperation = "escalate"
	EscalationOperationLink     EscalationOperation = "link"
)

type EscalationWrite struct {
	Operation          EscalationOperation
	Actor              Actor
	Content            EscalationInput
	Plan               kernel.EscalationPlan
	CaseAssignmentPlan *kernel.MutationPlan
	Fingerprint        [sha256.Size]byte
	Effects            []string
	Audit              AuditContext
}

type EscalationReplayQuery struct {
	Operation   EscalationOperation
	Identity    kernel.EscalationReplayIdentity
	Fingerprint [sha256.Size]byte
}

type EscalationWriteResult struct {
	Alert    Record
	Case     Record
	Links    []Link
	Effects  []string
	Replayed bool
}

type UnlinkWrite struct {
	Actor       Actor
	Alert       Record
	Case        Record
	AlertPlan   kernel.MutationPlan
	CasePlan    kernel.MutationPlan
	LinkID      uuid.UUID
	Input       UnlinkInput
	KeyHash     [sha256.Size]byte
	Fingerprint [sha256.Size]byte
	Effects     []string
	Audit       AuditContext
}

type UnlinkReplayQuery struct {
	Actor       Actor
	TenantID    uuid.UUID
	AlertID     uuid.UUID
	CaseID      uuid.UUID
	KeyHash     [sha256.Size]byte
	Fingerprint [sha256.Size]byte
}
