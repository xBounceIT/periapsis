package notificationinbox

import (
	"context"

	"github.com/google/uuid"
)

// Repository is the live-authorization and transactional boundary for the
// personal notification inbox.
//
// Every method must set transaction-local tenant and user coordinates and rely
// on forced RLS in addition to application predicates. ResolveAccess must read
// current authentication/session/membership state. List must apply the exact
// tenant+user+audience scope and unread predicate before the UUIDv7 cursor and
// LIMIT, returning strict ID DESC order with at most FetchLimit rows.
//
// Mutations must revalidate Access inside the same transaction and atomically
// perform CAS, the item/inbox revision update, minimized audit append, and
// idempotency result persistence. A desired state already present is a no-op:
// it writes no state or audit but persists/replays the command result. Replays
// return the original outcome with Replayed set. The adapter must invoke
// ValidateResult before committing; a validation error must roll back.
type Repository interface {
	ResolveAccess(context.Context, Actor, uuid.UUID) (AccessEvidence, error)
	List(context.Context, ListParams) (ListSnapshot, error)
	CountUnread(context.Context, CountUnreadParams) (UnreadState, error)
	SetReadState(context.Context, SetReadStateParams) (ReadStateResult, error)
	MarkAllRead(context.Context, MarkAllReadParams) (MarkAllReadResult, error)
}

type ListParams struct {
	Actor      Actor
	Access     AccessEvidence
	TenantID   uuid.UUID
	UserID     uuid.UUID
	After      *uuid.UUID
	FetchLimit int
	UnreadOnly bool
}

func (ListParams) String() string   { return "notificationinbox.ListParams{redacted}" }
func (ListParams) GoString() string { return "notificationinbox.ListParams{redacted}" }

type ListSnapshot struct {
	TenantID      uuid.UUID
	UserID        uuid.UUID
	Items         []Item
	InboxRevision uint64
}

func (ListSnapshot) String() string   { return "notificationinbox.ListSnapshot{redacted}" }
func (ListSnapshot) GoString() string { return "notificationinbox.ListSnapshot{redacted}" }

type CountUnreadParams struct {
	Actor    Actor
	Access   AccessEvidence
	TenantID uuid.UUID
	UserID   uuid.UUID
}

func (CountUnreadParams) String() string   { return "notificationinbox.CountUnreadParams{redacted}" }
func (CountUnreadParams) GoString() string { return "notificationinbox.CountUnreadParams{redacted}" }

type ReadStateValidator func(ReadStateResult) error

type SetReadStateParams struct {
	Actor            Actor
	Access           AccessEvidence
	TenantID         uuid.UUID
	UserID           uuid.UUID
	ItemID           uuid.UUID
	Read             bool
	ExpectedRevision uint64
	Command          CommandBinding
	Audit            AuditMetadata
	ValidateResult   ReadStateValidator
}

func (SetReadStateParams) String() string   { return "notificationinbox.SetReadStateParams{redacted}" }
func (SetReadStateParams) GoString() string { return "notificationinbox.SetReadStateParams{redacted}" }

type MarkAllReadValidator func(MarkAllReadResult) error

type MarkAllReadParams struct {
	Actor            Actor
	Access           AccessEvidence
	TenantID         uuid.UUID
	UserID           uuid.UUID
	ExpectedRevision uint64
	Command          CommandBinding
	Audit            AuditMetadata
	ValidateResult   MarkAllReadValidator
}

func (MarkAllReadParams) String() string   { return "notificationinbox.MarkAllReadParams{redacted}" }
func (MarkAllReadParams) GoString() string { return "notificationinbox.MarkAllReadParams{redacted}" }
