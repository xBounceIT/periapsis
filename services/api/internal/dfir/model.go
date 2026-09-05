package dfir

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/dfir"
)

type Capability string

const (
	CapabilityIOCRead            Capability = "dfir.ioc.read"
	CapabilityIOCManage          Capability = "dfir.ioc.manage"
	CapabilityAssetRead          Capability = "dfir.asset.read"
	CapabilityAssetManage        Capability = "dfir.asset.manage"
	CapabilityEvidenceRead       Capability = "dfir.evidence.read"
	CapabilityEvidenceManage     Capability = "dfir.evidence.manage"
	CapabilityTimelineRead       Capability = "dfir.timeline.read"
	CapabilityTimelineManage     Capability = "dfir.timeline.manage"
	CapabilityTaskRead           Capability = "dfir.task.read"
	CapabilityTaskManage         Capability = "dfir.task.manage"
	CapabilityAttachmentRead     Capability = "dfir.attachment.read"
	CapabilityAttachmentManage   Capability = "dfir.attachment.manage"
	CapabilityRelationshipRead   Capability = "dfir.relationship.read"
	CapabilityRelationshipManage Capability = "dfir.relationship.manage"
)

type Scope string

const (
	ScopeOwn          Scope = "own"
	ScopeAssigned     Scope = "assigned"
	ScopeOperatorTeam Scope = "operator_team"
	ScopeTenant       Scope = "tenant"
)

type PrincipalKind string

const (
	PrincipalHuman    PrincipalKind = "human"
	PrincipalCustomer PrincipalKind = "customer"
)

type Actor struct {
	TenantID             uuid.UUID
	UserID               uuid.UUID
	SessionID            uuid.UUID
	ActiveTenantID       uuid.UUID
	MembershipID         uuid.UUID
	AuthenticationMethod string
	Kind                 PrincipalKind
}

type AuditContext struct {
	RequestID            uuid.UUID
	CorrelationID        uuid.UUID
	IPAddress            netip.Addr
	UserAgent            string
	AuthenticationMethod string
}

type MutationEnvelope struct {
	IdempotencyKey string
	Audit          AuditContext
}

type Access struct {
	Audience kernel.Audience
	Scope    Scope
}

type ResourceScope struct {
	CaseID kernel.EntityID
}

type AlertResourceScope struct {
	AlertID kernel.EntityID
}

type MutationResult[T any] struct {
	Resource T
	Replayed bool
}

type Versioned[T any] struct {
	Resource T
	Version  uint64
}

// RelatedRoot contains only the identity of a currently readable ticket.
// Hidden roots and their count must never cross this projection boundary.
type RelatedRoot struct {
	Kind kernel.EntityKind
	ID   kernel.EntityID
}

type SharedResource struct {
	ResourceKind kernel.EntityKind
	ResourceID   kernel.EntityID
	Roots        []RelatedRoot
}

// Workspace is the bounded, already-authorized Case investigation projection.
// Repository implementations must omit resources that are not visible through
// the corresponding capability-specific access tuple.
type Workspace struct {
	SharedResources []SharedResource
	Indicators      []Versioned[kernel.Indicator]
	Assets          []Versioned[kernel.Asset]
	Evidence        []kernel.Evidence
	Timeline        []Versioned[kernel.TimelineEvent]
	Tasks           []kernel.Task
	Attachments     []kernel.Attachment
	Relationships   []kernel.Relationship
}

// AlertWorkspace is the bounded operator investigation projection for an
// autonomous Alert. It intentionally excludes Case-only evidence, task, and
// relationship resources.
type AlertWorkspace struct {
	SharedResources []SharedResource
	Indicators      []Versioned[kernel.Indicator]
	Assets          []Versioned[kernel.Asset]
	Timeline        []Versioned[kernel.TimelineEvent]
	Attachments     []kernel.Attachment
}

type WorkspaceAccess map[Capability]Access

type IndicatorCommand struct {
	CaseID          kernel.EntityID
	Input           kernel.IndicatorInput
	ExpectedVersion uint64
	Envelope        MutationEnvelope
}

type AssetCommand struct {
	CaseID          kernel.EntityID
	Input           kernel.AssetInput
	ExpectedVersion uint64
	Envelope        MutationEnvelope
}

type AlertIndicatorCommand struct {
	AlertID         kernel.EntityID
	Input           kernel.IndicatorInput
	ExpectedVersion uint64
	Envelope        MutationEnvelope
}

type AlertAssetCommand struct {
	AlertID         kernel.EntityID
	Input           kernel.AssetInput
	ExpectedVersion uint64
	Envelope        MutationEnvelope
}

type TimelineCommand struct {
	Input    kernel.TimelineEventInput
	Envelope MutationEnvelope
}

type AlertTimelineCommand struct {
	Input    kernel.TimelineEventInput
	Envelope MutationEnvelope
}

// TaskDraft is the caller-controlled portion of a new Case task. Lifecycle
// state, completion provenance, comments, timestamps, and the initial version
// are deliberately server-owned.
type TaskDraft struct {
	ID             kernel.EntityID
	Title          string
	Description    string
	Priority       kernel.TaskPriority
	AssigneeID     *kernel.EntityID
	OperatorTeamID *kernel.EntityID
	DueAt          *time.Time
	Checklist      []TaskChecklistItemIntent
	SLAInstanceID  *kernel.EntityID
}

// TaskChecklistItemIntent contains only fields a caller may choose. The
// service assigns and preserves completion actor/time provenance.
type TaskChecklistItemIntent struct {
	ID        kernel.EntityID
	Title     string
	Completed bool
}

type TaskCreateCommand struct {
	CaseID   kernel.EntityID
	Input    TaskDraft
	Envelope MutationEnvelope
}

type TaskTransitionCommand struct {
	CaseID          kernel.EntityID
	TaskID          kernel.EntityID
	ExpectedVersion uint64
	Target          kernel.TaskStatus
	Reason          string
	CompletionData  json.RawMessage
	Envelope        MutationEnvelope
}

type TaskDetailsCommand struct {
	CaseID          kernel.EntityID
	TaskID          kernel.EntityID
	ExpectedVersion uint64
	Title           string
	Description     string
	Priority        kernel.TaskPriority
	SLAInstanceID   *kernel.EntityID
	Envelope        MutationEnvelope
}

type TaskAssignmentCommand struct {
	CaseID          kernel.EntityID
	TaskID          kernel.EntityID
	ExpectedVersion uint64
	OperatorTeamID  *kernel.EntityID
	AssigneeID      *kernel.EntityID
	Envelope        MutationEnvelope
}

type TaskDueDateCommand struct {
	CaseID          kernel.EntityID
	TaskID          kernel.EntityID
	ExpectedVersion uint64
	DueAt           *time.Time
	Envelope        MutationEnvelope
}

type TaskChecklistCommand struct {
	CaseID          kernel.EntityID
	TaskID          kernel.EntityID
	ExpectedVersion uint64
	Checklist       []TaskChecklistItemIntent
	Envelope        MutationEnvelope
}

type TaskCommentsCommand struct {
	CaseID          kernel.EntityID
	TaskID          kernel.EntityID
	ExpectedVersion uint64
	CommentIDs      []kernel.EntityID
	Envelope        MutationEnvelope
}

type RelationshipCommand struct {
	CaseID   kernel.EntityID
	Input    kernel.RelationshipInput
	Envelope MutationEnvelope
}

type RelationshipRetractCommand struct {
	CaseID          kernel.EntityID
	RelationshipID  kernel.EntityID
	ExpectedVersion uint64
	RetractionID    kernel.EntityID
	Reason          string
	Envelope        MutationEnvelope
}

type PrepareUploadCommand struct {
	CaseID              kernel.EntityID
	AttachmentID        kernel.EntityID
	StorageObjectID     kernel.EntityID
	Subject             kernel.EntityReference
	OriginalFilename    string
	Classification      kernel.EvidenceClassification
	RequestedVisibility kernel.Visibility
	SizeBytes           int64
	ContentType         string
	Envelope            MutationEnvelope
}

type AlertPrepareUploadCommand struct {
	AlertID             kernel.EntityID
	AttachmentID        kernel.EntityID
	StorageObjectID     kernel.EntityID
	Subject             kernel.EntityReference
	OriginalFilename    string
	Classification      kernel.EvidenceClassification
	RequestedVisibility kernel.Visibility
	SizeBytes           int64
	ContentType         string
	Envelope            MutationEnvelope
}

type PreparedUpload struct {
	Object     kernel.StorageObject
	Attachment kernel.Attachment
	Grant      UploadGrant
}

type DownloadCommand struct {
	CaseID       kernel.EntityID
	AttachmentID kernel.EntityID
	Subject      kernel.EntityReference
	Audit        AuditContext
}

type AlertDownloadCommand struct {
	AlertID      kernel.EntityID
	AttachmentID kernel.EntityID
	Subject      kernel.EntityReference
	Audit        AuditContext
}

type PreparedDownload struct {
	Attachment kernel.Attachment
	Grant      DownloadGrant
}

type EvidenceCommand struct {
	CaseID                kernel.EntityID
	EvidenceID            kernel.EntityID
	StorageObjectID       kernel.EntityID
	InitialCustodyEventID kernel.EntityID
	Title                 string
	Description           string
	EvidenceType          string
	Classification        kernel.EvidenceClassification
	CollectedAt           time.Time
	Source                string
	RetentionUntil        *time.Time
	LegalHold             bool
	Envelope              MutationEnvelope
}

type CustodyCommand struct {
	CaseID          kernel.EntityID
	EvidenceID      kernel.EntityID
	ExpectedVersion uint64
	Event           kernel.CustodyEventInput
	NextScanState   kernel.ScanState
	LegalHold       *bool
	RetentionSet    bool
	RetentionUntil  *time.Time
	Envelope        MutationEnvelope
}

type WorkerContext struct {
	TenantID      uuid.UUID
	OperationID   uuid.UUID
	CorrelationID uuid.UUID
}

func StrongETag(id kernel.EntityID, version uint64) string {
	digest := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", id.String(), version)))
	return `"dfir-` + base64.RawURLEncoding.EncodeToString(digest[:16]) + `"`
}

func validActor(actor Actor, tenantID uuid.UUID) bool {
	return tenantID != uuid.Nil && actor.TenantID == tenantID && actor.ActiveTenantID == tenantID &&
		actor.UserID != uuid.Nil && actor.SessionID != uuid.Nil && actor.MembershipID != uuid.Nil &&
		validStableKey(actor.AuthenticationMethod, 64) &&
		(actor.Kind == PrincipalHuman || actor.Kind == PrincipalCustomer)
}

func validAccess(actor Actor, access Access, manage bool) bool {
	validScope := access.Scope == ScopeAssigned || access.Scope == ScopeOperatorTeam || access.Scope == ScopeTenant
	if !validScope {
		return false
	}
	if actor.Kind == PrincipalCustomer {
		return !manage && access.Audience == kernel.AudienceCustomer && access.Scope == ScopeAssigned
	}
	return access.Audience == kernel.AudienceOperator
}

func validEnvelope(envelope MutationEnvelope) bool {
	return idempotencyKeyPattern.MatchString(envelope.IdempotencyKey) &&
		envelope.Audit.RequestID != uuid.Nil && envelope.Audit.CorrelationID != uuid.Nil &&
		envelope.Audit.IPAddress.IsValid() && validSingleLine(envelope.Audit.UserAgent, 1_024, true) &&
		validStableKey(envelope.Audit.AuthenticationMethod, 64)
}

func validDownloadAudit(actor Actor, audit AuditContext) bool {
	return audit.RequestID != uuid.Nil && audit.RequestID.Version() == 7 && audit.RequestID.Variant() == uuid.RFC4122 &&
		audit.CorrelationID != uuid.Nil && audit.CorrelationID.Version() == 7 && audit.CorrelationID.Variant() == uuid.RFC4122 &&
		audit.IPAddress.IsValid() && audit.IPAddress.Zone() == "" && validSingleLine(audit.UserAgent, 512, false) &&
		validStableKey(audit.AuthenticationMethod, 64) && audit.AuthenticationMethod == actor.AuthenticationMethod
}

var idempotencyKeyPattern = regexp.MustCompile(`^[A-Za-z0-9._~-]{16,128}$`)

func validSingleLine(value string, maximum int, optional bool) bool {
	if value == "" {
		return optional
	}
	if len(value) > maximum || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f || character >= 0x202a && character <= 0x202e ||
			character >= 0x2066 && character <= 0x2069 {
			return false
		}
	}
	return true
}

func validStableKey(value string, maximum int) bool {
	if value == "" || len(value) > maximum || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' ||
			character == '_' || character == '-' || character == '.' {
			continue
		}
		return false
	}
	return true
}

func validWorker(worker WorkerContext) bool {
	return worker.TenantID != uuid.Nil && worker.OperationID != uuid.Nil && worker.CorrelationID != uuid.Nil
}
