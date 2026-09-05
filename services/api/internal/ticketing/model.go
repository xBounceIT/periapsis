package ticketing

import (
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
)

const (
	DefaultPageSize           = 50
	MaximumPageSize           = 100
	maximumCommentCharacters  = 20_000
	maximumCommentAttachments = 20
	maximumCommentMentions    = 50
)

// Actor is the authenticated human identity supplied by the HTTP boundary.
// Principal class and permissions are always re-resolved by Repository.
type Actor struct {
	UserID               uuid.UUID
	SessionID            uuid.UUID
	ActiveTenantID       uuid.UUID
	AuthenticationMethod string
	Audit                AuditContext
}

type AuditContext struct {
	RequestID     uuid.UUID
	CorrelationID uuid.UUID
	RemoteAddress netip.Addr
	UserAgent     string
}

type Capability string

const (
	CapabilityAlertRead         Capability = "alert.read"
	CapabilityAlertActivityRead Capability = "alert.activity.read"
	// Activity-feed capabilities are trusted compound use-case intents. The
	// PostgreSQL adapter resolves the matching read and activity grants from one
	// live authority snapshot and intersects their resource scopes.
	CapabilityAlertActivityFeed Capability = "alert.activity.feed"
	// Alert-relation management is a trusted compound use-case intent. It
	// resolves alert.read and alert.update at one exact scope.
	CapabilityAlertRelationManage Capability = "alert.relation.manage"
	CapabilityAlertCommentRead    Capability = "alert.comment.read"
	CapabilityAlertLinkRead       Capability = "alert.link.read"
	CapabilityAlertAssign         Capability = "alert.assign"
	CapabilityAlertClaim          Capability = "alert.claim"
	CapabilityAlertUpdate         Capability = "alert.update"
	CapabilityAlertDelete         Capability = "alert.delete"
	CapabilityAlertEscalate       Capability = "alert.escalate"
	CapabilityAlertCommentPublic  Capability = "alert.comment.public"
	CapabilityAlertCommentPrivate Capability = "alert.comment.private"
	CapabilityCaseRead            Capability = "case.read"
	CapabilityCaseActivityRead    Capability = "case.activity.read"
	CapabilityCaseActivityFeed    Capability = "case.activity.feed"
	CapabilityCaseCommentRead     Capability = "case.comment.read"
	CapabilityCaseLinkRead        Capability = "case.link.read"
	CapabilityCaseCreate          Capability = "case.create"
	CapabilityCaseUpdate          Capability = "case.update"
	CapabilityCaseClaim           Capability = "case.claim"
	CapabilityCaseTransfer        Capability = "case.transfer"
	CapabilityCaseTransition      Capability = "case.transition"
	CapabilityCaseCommentPublic   Capability = "case.comment.public"
	CapabilityCaseCommentPrivate  Capability = "case.comment.private"
	CapabilityDFIRIOCRead         Capability = "dfir.ioc.read"
	CapabilityDFIRAssetRead       Capability = "dfir.asset.read"
	CapabilityDFIRAttachmentRead  Capability = "dfir.attachment.read"
	CapabilityPortalAlertRead     Capability = "portal.alert.read"
	CapabilityPortalCaseRead      Capability = "portal.case.read"
	CapabilityPortalCommentPublic Capability = "portal.comment.public"
	// Export capabilities are trusted use-case intents, not persisted grants.
	// The PostgreSQL adapter resolves each one from the corresponding portal
	// read grant and portal.comment.public in one live authority snapshot.
	CapabilityPortalAlertExport Capability = "portal.alert.export"
	CapabilityPortalCaseExport  Capability = "portal.case.export"
)

type Scope string

const (
	ScopeOwn          Scope = "own"
	ScopeAssigned     Scope = "assigned"
	ScopeOperatorTeam Scope = "operator_team"
	ScopeTenant       Scope = "tenant"
)

// LiveAccess is a fresh backend-resolved authorization snapshot. Scopes are
// resource relations, never UI hints. OperatorTeams contains only current live
// assignment/roster relationships admitted for operator_team scope.
type LiveAccess struct {
	Authority     kernel.AuthorizationSnapshot
	Scopes        []Scope
	OperatorTeams []kernel.EntityID
	// MembershipID is fresh tenant-scoped identity evidence. It is required
	// when a private saved view is applied and is included in cursor binding.
	MembershipID kernel.EntityID
	// CustomerContactID is fresh DB evidence for the exact active
	// membership+user+contact tuple. It is mandatory for customer projections
	// and is bound into list cursors; handlers cannot manufacture it.
	CustomerContactID *kernel.EntityID
}

type Creator struct {
	Kind kernel.PrincipalKind
	// ID is the tenant-scoped membership ID for a human creator and the
	// service-account ID for a service creator. UserID is retained separately
	// because own-scope authorization is evaluated against the authenticated
	// user, never against a response projection identifier.
	ID          uuid.UUID
	UserID      *uuid.UUID
	DisplayName string
}

// Record keeps business content beside the validated kernel snapshot. A
// repository must load Workflow and Snapshot from the same pinned version.
type Record struct {
	Workflow             kernel.WorkflowDefinition
	Snapshot             kernel.TicketSnapshot
	Number               string
	Title                string
	Description          string
	Summary              string
	Severity             string
	Priority             string
	Category             string
	Classification       *string
	Source               string
	SourceType           string
	ExternalID           *string
	DeduplicationKey     *string
	Tags                 []string
	CustomFields         map[string]any
	CustomerCustomFields map[string]any
	RawPayload           map[string]any
	Creator              Creator
	DetectedAt           time.Time
	ReceivedAt           time.Time
	DetectionTime        time.Time
	OpenedAt             time.Time
	CreatedAt            time.Time
	UpdatedAt            time.Time
	AcknowledgedAt       *time.Time
	ClosedAt             *time.Time
	AssignedAt           *time.Time
	FirstResponseAt      *time.Time
	ResolvedAt           *time.Time
	ClaimedAt            *time.Time
	// DynamicColumns contains only the exact custom-field/SLA definitions
	// pinned by an applied saved view. Keys are "source:definition-uuid" and
	// values are canonical JSON scalars or null; arbitrary objects and arrays
	// are never admitted on the ticket list surface.
	DynamicColumns map[string]DynamicColumnValue
}

type DynamicColumnValue struct {
	Source            SavedViewDefinitionSource
	DefinitionID      uuid.UUID
	DefinitionVersion uint64
	Value             json.RawMessage
	StyleKey          string
	MaterializedAt    *time.Time
}

// DeleteAlertInput requests a reversible database tombstone. ExpectedVersion
// is the live Alert version before deletion; the idempotency key is bound to
// the full request and can replay only the exact same tombstone.
type DeleteAlertInput struct {
	ExpectedVersion uint64
	Reason          string
	IdempotencyKey  string
}

type DeleteAlertReceipt struct {
	TenantID         uuid.UUID
	AlertID          uuid.UUID
	PreviousVersion  uint64
	TombstoneVersion uint64
	DeletedAt        time.Time
	Replayed         bool
}

type Projection uint8

const (
	ProjectionOperator Projection = iota + 1
	ProjectionCustomer
)

type View struct {
	Record     Record
	Projection Projection
}

type ListInput struct {
	After            string
	Limit            int
	SavedViewID      *uuid.UUID
	States           []kernel.Key
	Severities       []string
	Priorities       []string
	AssignedTeamID   *uuid.UUID
	AssigneeUserID   *uuid.UUID
	ClaimedBy        *uuid.UUID
	Queue            string
	CustomerVisible  *bool
	Search           string
	CustomFieldKey   *kernel.Key
	CustomFieldValue *string
	Sort             string
}

type Page struct {
	Items       []View
	NextCursor  string
	AppliedView *SavedViewRecord
}

type CursorPageInput struct {
	After *uuid.UUID
	Limit int
}

type CommentOrigin string

const (
	CommentOriginAPI            CommentOrigin = "api"
	CommentOriginCustomerPortal CommentOrigin = "customer_portal"
	CommentOriginEscalationCopy CommentOrigin = "escalation_copy"
	CommentOriginSystem         CommentOrigin = "system"
)

type CommentAuthorAudience string

const (
	CommentAudienceOperator CommentAuthorAudience = "operator"
	CommentAudienceCustomer CommentAuthorAudience = "customer"
)

type CommentAuthor struct {
	MembershipID uuid.UUID
	ContactID    *uuid.UUID
	DisplayName  string
	Audience     CommentAuthorAudience
}

type CommentAttachment struct {
	ID               uuid.UUID
	OriginalFilename string
	Visibility       kernel.CommentVisibility
}

type CommentMention struct {
	MembershipID uuid.UUID
	DisplayName  string
}

type Comment struct {
	ID            uuid.UUID
	TenantID      uuid.UUID
	ResourceID    uuid.UUID
	ResourceKind  kernel.AggregateKind
	Visibility    kernel.CommentVisibility
	BodyMarkdown  string
	BodyHTML      string
	Author        CommentAuthor
	Origin        CommentOrigin
	Attachments   []CommentAttachment
	Mentions      []CommentMention
	Revision      int
	CreatedAt     time.Time
	UpdatedAt     time.Time
	EditableUntil time.Time
	CanEdit       bool
}

// CommentEditState is the minimum private repository projection needed to
// authorize an edit before the append-only write. It is never serialized to a
// customer-facing response.
type CommentEditState struct {
	Visibility         kernel.CommentVisibility
	AuthorMembershipID uuid.UUID
	AuthorContactID    *uuid.UUID
	Origin             CommentOrigin
	AuthorAudience     CommentAuthorAudience
	Revision           int
	CreatedAt          time.Time
	EditableUntil      time.Time
}

type CommentPage struct {
	Items      []Comment
	Projection Projection
	NextCursor *uuid.UUID
}

type CommentPreview struct {
	Visibility   kernel.CommentVisibility
	BodyMarkdown string
	BodyHTML     string
	Attachments  []CommentAttachment
	Mentions     []CommentMention
	Projection   Projection
}

type CommentMentionCandidate struct {
	MembershipID uuid.UUID
	DisplayName  string
}

type CommentMentionCandidateList struct {
	Items []CommentMentionCandidate
}

type CommentRevision struct {
	Revision     int
	BodyMarkdown string
	BodyHTML     string
	Reason       string
	EditedAt     time.Time
	Attachments  []CommentAttachment
	Mentions     []CommentMention
}

type CommentRevisionPageInput struct {
	AfterRevision *int
	Limit         int
}

type CommentRevisionPage struct {
	Items             []CommentRevision
	Projection        Projection
	NextAfterRevision *int
}

type Activity struct {
	ID           uuid.UUID
	TenantID     uuid.UUID
	ResourceID   uuid.UUID
	ResourceKind kernel.AggregateKind
	Kind         string
	Summary      string
	ActorKind    ActivityActorKind
	ActorID      uuid.UUID
	DisplayName  string
	Origin       string
	Details      map[string]any
	OccurredAt   time.Time
}

type ActivityActorKind uint8

const (
	ActivityActorHuman ActivityActorKind = iota + 1
	ActivityActorServiceAccount
	ActivityActorSystem
	// ActivityActorRedacted is an internal marker used only by customer-safe
	// repository projections. It has no identity and is never serialized as an
	// operator actor union.
	ActivityActorRedacted
)

func (kind ActivityActorKind) String() string {
	switch kind {
	case ActivityActorHuman:
		return "human"
	case ActivityActorServiceAccount:
		return "service_account"
	case ActivityActorSystem:
		return "system"
	case ActivityActorRedacted:
		return "redacted"
	default:
		return "unknown"
	}
}

type ActivityPage struct {
	Items      []Activity
	Projection Projection
	NextCursor *uuid.UUID
}

type Link struct {
	ID                  uuid.UUID
	TenantID            uuid.UUID
	AlertID             uuid.UUID
	CaseID              uuid.UUID
	Relation            string
	Reason              string
	LinkedBy            uuid.UUID
	LinkedAt            time.Time
	SourceAlertVersion  uint64
	CopyFields          []string
	CustomFieldKeys     []string
	ItemIDs             map[string][]uuid.UUID
	PublicCommentIDs    []uuid.UUID
	CopiedFieldSnapshot map[string]any
}

type LinkView struct {
	Link       Link
	Other      Record
	Projection Projection
}

type LinkPage struct {
	Items      []LinkView
	NextCursor *uuid.UUID
}

type MutationInput struct {
	ExpectedVersion  uint64
	TeamID           *uuid.UUID
	AssigneeID       *uuid.UUID
	TransitionIntent kernel.TransitionIntent
	TransitionKey    string
	TargetStateKey   string
	Comment          string
	CustomFieldKeys  []string
	CustomFields     map[string]any
	Reason           string
	IdempotencyKey   string
}

type MutationResult struct {
	View        View
	Effects     []string
	Replayed    bool
	ClaimWinner *ClaimWinner
}

type ClaimWinner struct {
	ClaimedBy uuid.UUID
	ClaimedAt time.Time
	Version   uint64
}

type CreateCaseInput struct {
	WorkflowID      *uuid.UUID
	Title           string
	Description     string
	Summary         string
	Severity        string
	Priority        string
	Category        string
	Classification  *string
	Tags            []string
	CustomFields    map[string]any
	CustomerVisible bool
	DetectionTime   time.Time
	AssignedTeamID  *uuid.UUID
	AssigneeUserID  *uuid.UUID
	IdempotencyKey  string
}

type CommentInput struct {
	Visibility     kernel.CommentVisibility
	BodyMarkdown   string
	AttachmentIDs  []uuid.UUID
	MentionedIDs   []uuid.UUID
	IdempotencyKey string
}

type CommentPreviewInput struct {
	Visibility    kernel.CommentVisibility
	BodyMarkdown  string
	AttachmentIDs []uuid.UUID
	MentionedIDs  []uuid.UUID
}

type CommentEditInput struct {
	BodyMarkdown     string
	AttachmentIDs    []uuid.UUID
	MentionedIDs     []uuid.UUID
	Reason           string
	ExpectedRevision int
	IdempotencyKey   string
}

type CommentMentionCandidateInput struct {
	Search string
	Limit  int
}

func entityID(value uuid.UUID) (kernel.EntityID, error) {
	return kernel.NewEntityID([16]byte(value))
}

func uuidFromEntity(value kernel.EntityID) uuid.UUID { return uuid.UUID(value.Bytes()) }

func validActor(actor Actor, tenant uuid.UUID) bool {
	_, actorErr := entityID(actor.UserID)
	_, tenantErr := entityID(tenant)
	return actorErr == nil && tenantErr == nil && actor.SessionID != uuid.Nil &&
		actor.SessionID.Version() == 7 && actor.ActiveTenantID == tenant &&
		validText(actor.AuthenticationMethod, 64, true)
}

func validMutationActor(actor Actor, tenant uuid.UUID) bool {
	return validActor(actor, tenant) && validAuditContext(actor.Audit)
}

func validAuditContext(audit AuditContext) bool {
	return audit.RequestID != uuid.Nil && audit.RequestID.Version() == 7 && audit.RequestID.Variant() == uuid.RFC4122 &&
		audit.CorrelationID != uuid.Nil && audit.CorrelationID.Version() == 7 && audit.CorrelationID.Variant() == uuid.RFC4122 &&
		audit.RemoteAddress.IsValid() && audit.RemoteAddress.Zone() == "" && validAuditUserAgent(audit.UserAgent)
}

func validAuditUserAgent(value string) bool {
	if value == "" || len(value) > 512 || !utf8.ValidString(value) || strings.Trim(value, " ") == "" {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validCapability(capability Capability) bool {
	switch capability {
	case CapabilityAlertRead, CapabilityAlertActivityRead, CapabilityAlertActivityFeed, CapabilityAlertRelationManage, CapabilityAlertCommentRead,
		CapabilityAlertLinkRead, CapabilityAlertAssign, CapabilityAlertClaim,
		CapabilityAlertUpdate, CapabilityAlertDelete, CapabilityAlertEscalate, CapabilityAlertCommentPublic,
		CapabilityAlertCommentPrivate, CapabilityCaseRead, CapabilityCaseActivityRead, CapabilityCaseActivityFeed,
		CapabilityCaseCommentRead, CapabilityCaseLinkRead, CapabilityCaseCreate, CapabilityCaseUpdate,
		CapabilityCaseClaim, CapabilityCaseTransfer, CapabilityCaseTransition,
		CapabilityCaseCommentPublic, CapabilityCaseCommentPrivate,
		CapabilityDFIRIOCRead, CapabilityDFIRAssetRead, CapabilityDFIRAttachmentRead,
		CapabilityPortalAlertRead, CapabilityPortalCaseRead, CapabilityPortalCommentPublic,
		CapabilityPortalAlertExport, CapabilityPortalCaseExport:
		return true
	default:
		return false
	}
}

func validText(value string, maximum int, required bool) bool {
	if !utf8.ValidString(value) || len(value) > maximum || strings.TrimSpace(value) != value || required && value == "" {
		return false
	}
	for _, character := range value {
		if character != '\n' && character != '\t' && unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validEnum(value string, allowed ...string) bool { return slices.Contains(allowed, value) }

func validOpaqueCursor(value string) bool {
	if value == "" {
		return true
	}
	if len(value) > 512 || strings.Contains(value, "=") {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil
}

func validJSONMap(value map[string]any, maximum int) bool {
	if value == nil {
		return true
	}
	encoded, err := json.Marshal(value)
	return err == nil && len(encoded) <= maximum
}
