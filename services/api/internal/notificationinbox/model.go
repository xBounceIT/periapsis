package notificationinbox

import (
	"crypto/sha256"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
)

const (
	DefaultPageLimit    = 50
	MaximumPageLimit    = 100
	MaximumUnreadCount  = uint64(1_000_000)
	MaximumRevision     = uint64(2_147_483_647)
	MaximumAccessAge    = time.Minute
	maximumClockSkew    = time.Minute
	maximumTitleBytes   = 240
	maximumSummaryBytes = 2_000
)

type Principal uint8

const (
	PrincipalOperator Principal = iota + 1
	PrincipalCustomer
)

func (value Principal) String() string {
	switch value {
	case PrincipalOperator:
		return "operator"
	case PrincipalCustomer:
		return "customer"
	default:
		return "invalid"
	}
}

type Audience string

const (
	AudienceOperator Audience = "operator"
	AudienceCustomer Audience = "customer"
)

type EventType string

const (
	EventAlertCreated        EventType = "alert.created"
	EventAlertAssigned       EventType = "alert.assigned"
	EventAlertClaimed        EventType = "alert.claimed"
	EventAlertStatusChanged  EventType = "alert.status_changed"
	EventAlertEscalated      EventType = "alert.escalated"
	EventAlertWatcherAdded   EventType = "alert.watcher_added"
	EventAlertWatcherRemoved EventType = "alert.watcher_removed"
	EventCaseCreated         EventType = "case.created"
	EventCaseAssigned        EventType = "case.assigned"
	EventCaseClaimed         EventType = "case.claimed"
	EventCaseTransferred     EventType = "case.transferred"
	EventCaseStatusChanged   EventType = "case.status_changed"
	EventCaseWatcherAdded    EventType = "case.watcher_added"
	EventCaseWatcherRemoved  EventType = "case.watcher_removed"
	EventCommentPublicAdded  EventType = "comment.public_added"
	EventCommentPrivateAdded EventType = "comment.private_added"
	EventContactChanged      EventType = "contact.changed"
	EventSLAWarning          EventType = "sla.warning"
	EventSLABreached         EventType = "sla.breached"
	EventTaskAssigned        EventType = "task.assigned"
	EventEvidenceAdded       EventType = "evidence.added"
	EventWebhookCustom       EventType = "webhook.custom"
)

type ResourceKind string

const (
	ResourceAlert    ResourceKind = "alert"
	ResourceCase     ResourceKind = "case"
	ResourceTask     ResourceKind = "task"
	ResourceEvidence ResourceKind = "evidence"
	ResourceContact  ResourceKind = "contact"
)

// AuditMetadata contains request correlation data only. It must never contain
// notification context, recipient data, credentials, or other customer data.
type AuditMetadata struct {
	RequestID     uuid.UUID
	CorrelationID uuid.UUID
	RemoteAddress netip.Addr
	UserAgent     string
}

func (AuditMetadata) String() string   { return "notificationinbox.AuditMetadata{redacted}" }
func (AuditMetadata) GoString() string { return "notificationinbox.AuditMetadata{redacted}" }

// Actor identifies the authenticated personal inbox coordinate. Principal is
// intentionally not trusted here; it is supplied by fresh repository evidence.
type Actor struct {
	UserID         uuid.UUID
	SessionID      uuid.UUID
	ActiveTenantID uuid.UUID
	Audit          AuditMetadata
}

func (Actor) String() string   { return "notificationinbox.Actor{redacted}" }
func (Actor) GoString() string { return "notificationinbox.Actor{redacted}" }

// AccessEvidence is a fresh database-derived assertion for exactly one
// tenant/user/session inbox. Both operator and customer principals are valid.
type AccessEvidence struct {
	TenantID      uuid.UUID
	UserID        uuid.UUID
	SessionID     uuid.UUID
	Principal     Principal
	Authenticated bool
	Active        bool
	EvaluatedAt   time.Time
}

func (AccessEvidence) String() string   { return "notificationinbox.AccessEvidence{redacted}" }
func (AccessEvidence) GoString() string { return "notificationinbox.AccessEvidence{redacted}" }

// Item is the complete outward projection allowlist. Persistence-only context,
// templates, recipient addresses, delivery metadata, and secrets have no place
// in this type.
type Item struct {
	ID              uuid.UUID    `json:"id"`
	TenantID        uuid.UUID    `json:"tenantId"`
	UserID          uuid.UUID    `json:"userId"`
	Audience        Audience     `json:"audience"`
	EventType       EventType    `json:"eventType"`
	ResourceKind    ResourceKind `json:"resourceKind"`
	ResourceID      uuid.UUID    `json:"resourceId"`
	ResourceVersion uint64       `json:"resourceVersion"`
	Title           string       `json:"title"`
	Summary         string       `json:"summary"`
	OccurredAt      time.Time    `json:"occurredAt"`
	ReadAt          *time.Time   `json:"readAt"`
	Revision        uint64       `json:"revision"`
}

func (Item) String() string   { return "notificationinbox.Item{redacted}" }
func (Item) GoString() string { return "notificationinbox.Item{redacted}" }

type ListInput struct {
	After      *uuid.UUID
	Limit      int
	UnreadOnly bool
}

func (ListInput) String() string   { return "notificationinbox.ListInput{redacted}" }
func (ListInput) GoString() string { return "notificationinbox.ListInput{redacted}" }

type Page struct {
	TenantID      uuid.UUID
	UserID        uuid.UUID
	Items         []Item
	NextCursor    *uuid.UUID
	InboxRevision uint64
}

func (value Page) String() string {
	return fmt.Sprintf("notificationinbox.Page{items:%d,redacted}", len(value.Items))
}
func (value Page) GoString() string { return value.String() }

type UnreadState struct {
	TenantID      uuid.UUID
	UserID        uuid.UUID
	Count         uint64
	InboxRevision uint64
}

func (UnreadState) String() string   { return "notificationinbox.UnreadState{redacted}" }
func (UnreadState) GoString() string { return "notificationinbox.UnreadState{redacted}" }

type SetReadStateInput struct {
	ItemID           uuid.UUID
	Read             bool
	ExpectedRevision uint64
	IdempotencyKey   string
}

func (SetReadStateInput) String() string   { return "notificationinbox.SetReadStateInput{redacted}" }
func (SetReadStateInput) GoString() string { return "notificationinbox.SetReadStateInput{redacted}" }

type MarkAllReadInput struct {
	ExpectedRevision uint64
	IdempotencyKey   string
}

func (MarkAllReadInput) String() string   { return "notificationinbox.MarkAllReadInput{redacted}" }
func (MarkAllReadInput) GoString() string { return "notificationinbox.MarkAllReadInput{redacted}" }

// CommandBinding stores only one-way digests. Adapters must persist both
// digests and reject reuse of the same key digest with another request digest.
type CommandBinding struct {
	Operation     string
	KeyDigest     [sha256.Size]byte
	RequestDigest [sha256.Size]byte
}

func (CommandBinding) String() string   { return "notificationinbox.CommandBinding{redacted}" }
func (CommandBinding) GoString() string { return "notificationinbox.CommandBinding{redacted}" }

type ReadStateResult struct {
	Item          Item
	InboxRevision uint64
	Changed       bool
	Replayed      bool
}

func (ReadStateResult) String() string   { return "notificationinbox.ReadStateResult{redacted}" }
func (ReadStateResult) GoString() string { return "notificationinbox.ReadStateResult{redacted}" }

type MarkAllReadResult struct {
	TenantID      uuid.UUID
	UserID        uuid.UUID
	Affected      uint64
	InboxRevision uint64
	Changed       bool
	Replayed      bool
}

func (MarkAllReadResult) String() string   { return "notificationinbox.MarkAllReadResult{redacted}" }
func (MarkAllReadResult) GoString() string { return "notificationinbox.MarkAllReadResult{redacted}" }
