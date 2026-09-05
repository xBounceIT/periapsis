package contacts

import (
	"context"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/contacts"
)

// Repository is the live-authorization and transactional persistence boundary.
// Every write must revalidate access in the same tenant transaction and commit
// state, activity, minimized/redacted audit, outbox intent, and idempotency
// result atomically. Customer pagination is filtered by exact contact/ticket
// relationships before limits or cursors are applied.
type Repository interface {
	ResolveAccess(context.Context, Actor, uuid.UUID, Capability) (Access, error)
	ResolveSelfContact(context.Context, Actor, uuid.UUID, Capability) (kernel.Contact, Access, error)
	ListContacts(context.Context, Actor, uuid.UUID, ContactListInput, Access) (ContactPage, error)
	GetContact(context.Context, Actor, uuid.UUID, uuid.UUID, Access) (kernel.Contact, error)
	ReserveID(context.Context, uuid.UUID) (kernel.EntityID, error)
	ReplayContact(context.Context, Actor, uuid.UUID, uuid.UUID, CommandBinding) (ContactResult, bool, error)
	CommitContact(context.Context, ContactWrite) (ContactResult, error)

	ListGroups(context.Context, Actor, uuid.UUID, GroupListInput, Access) (GroupPage, error)
	GetGroup(context.Context, Actor, uuid.UUID, uuid.UUID, Access) (kernel.RecipientGroup, error)
	ReplayGroup(context.Context, Actor, uuid.UUID, uuid.UUID, CommandBinding) (GroupResult, bool, error)
	CommitGroup(context.Context, GroupWrite) (GroupResult, error)

	ResolveExactLinkAccess(context.Context, Actor, uuid.UUID, kernel.TicketKind, uuid.UUID, uuid.UUID, uint64) (ExactLinkAccess, error)
	ListLinks(context.Context, Actor, uuid.UUID, LinkListInput) (LinkPage, error)
	GetLinkForArchive(context.Context, Actor, uuid.UUID, uuid.UUID, kernel.TicketKind, uuid.UUID) (kernel.TicketContactLink, error)
	ReplayLink(context.Context, Actor, uuid.UUID, uuid.UUID, kernel.TicketKind, uuid.UUID, CommandBinding) (LinkResult, bool, error)
	CommitLink(context.Context, LinkWrite) (LinkResult, error)

	ResolvePortalResource(context.Context, Actor, uuid.UUID, PortalResourceInput) (PortalResourceEvidence, error)
}

type ContactWrite struct {
	Actor           Actor
	Access          Access
	Current         *kernel.Contact
	Next            kernel.Contact
	ExpectedVersion uint64
	Command         CommandBinding
	Reason          string
	Audit           AuditContext
}

type GroupWrite struct {
	Actor           Actor
	Access          Access
	Current         *kernel.RecipientGroup
	Next            kernel.RecipientGroup
	ExpectedVersion uint64
	Command         CommandBinding
	Reason          string
	Audit           AuditContext
}

type LinkWrite struct {
	Actor                 Actor
	Access                ExactLinkAccess
	Current               *kernel.TicketContactLink
	Next                  kernel.TicketContactLink
	ExpectedLinkVersion   uint64
	ExpectedTicketVersion uint64
	Command               CommandBinding
	Reason                string
	Audit                 AuditContext
}
