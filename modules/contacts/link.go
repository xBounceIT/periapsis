package contacts

import (
	"fmt"
	"time"
)

type TicketKind uint8

const (
	TicketAlert TicketKind = iota + 1
	TicketCase
)

func (kind TicketKind) String() string {
	switch kind {
	case TicketAlert:
		return "alert"
	case TicketCase:
		return "case"
	default:
		return "unknown"
	}
}

type ContactRole uint8

const (
	RolePrimary ContactRole = iota + 1
	RoleEscalation
	RoleWatcher
)

func (role ContactRole) String() string {
	switch role {
	case RolePrimary:
		return "primary"
	case RoleEscalation:
		return "escalation"
	case RoleWatcher:
		return "watcher"
	default:
		return "unknown"
	}
}

type LinkOrigin uint8

const (
	OriginManual LinkOrigin = iota + 1
	OriginEscalationCopy
)

func (origin LinkOrigin) String() string {
	switch origin {
	case OriginManual:
		return "manual"
	case OriginEscalationCopy:
		return "escalation_copy"
	default:
		return "unknown"
	}
}

type EscalationProvenance struct {
	sourceAlertID      EntityID
	sourceAlertVersion uint64
}

func NewEscalationProvenance(sourceAlertID EntityID, sourceAlertVersion uint64) (EscalationProvenance, error) {
	if !validEntityID(sourceAlertID) || sourceAlertVersion == 0 {
		return EscalationProvenance{}, ErrInvalidTarget
	}
	return EscalationProvenance{sourceAlertID: sourceAlertID, sourceAlertVersion: sourceAlertVersion}, nil
}

func (value EscalationProvenance) SourceAlertID() EntityID    { return value.sourceAlertID }
func (value EscalationProvenance) SourceAlertVersion() uint64 { return value.sourceAlertVersion }

type TicketContactLink struct {
	id         EntityID
	tenantID   EntityID
	ticketKind TicketKind
	ticketID   EntityID
	contactID  EntityID
	role       ContactRole
	origin     LinkOrigin
	provenance *EscalationProvenance
	version    uint64
	createdAt  time.Time
	archivedAt *time.Time
}

func NewTicketContactLink(
	id, tenantID EntityID,
	ticketKind TicketKind,
	ticketID, contactID EntityID,
	role ContactRole,
	origin LinkOrigin,
	provenance *EscalationProvenance,
	at time.Time,
) (TicketContactLink, error) {
	return RehydrateTicketContactLink(id, tenantID, ticketKind, ticketID, contactID, role, origin, provenance, 1, at, nil)
}

func RehydrateTicketContactLink(
	id, tenantID EntityID,
	ticketKind TicketKind,
	ticketID, contactID EntityID,
	role ContactRole,
	origin LinkOrigin,
	provenance *EscalationProvenance,
	version uint64,
	createdAt time.Time,
	archivedAt *time.Time,
) (TicketContactLink, error) {
	validTicketKind := ticketKind == TicketAlert || ticketKind == TicketCase
	validRole := role == RolePrimary || role == RoleEscalation || role == RoleWatcher
	validOrigin := origin == OriginManual && provenance == nil ||
		origin == OriginEscalationCopy && ticketKind == TicketCase && provenance != nil &&
			validEntityID(provenance.sourceAlertID) && provenance.sourceAlertVersion > 0
	if !validEntityID(id) || !validEntityID(tenantID) || !validTicketKind || !validEntityID(ticketID) ||
		!validEntityID(contactID) || !validRole || !validOrigin || version == 0 || !validInstant(createdAt) ||
		archivedAt != nil && (!validInstant(*archivedAt) || archivedAt.Before(createdAt)) {
		return TicketContactLink{}, ErrInvalidTarget
	}
	return TicketContactLink{
		id: id, tenantID: tenantID, ticketKind: ticketKind, ticketID: ticketID, contactID: contactID,
		role: role, origin: origin, provenance: cloneProvenance(provenance), version: version,
		createdAt: createdAt, archivedAt: cloneInstant(archivedAt),
	}, nil
}

func ArchiveTicketContactLink(current TicketContactLink, expectedVersion uint64, at time.Time) (TicketContactLink, error) {
	if !validTicketContactLink(current) || expectedVersion != current.version {
		return TicketContactLink{}, ErrVersionConflict
	}
	if current.archivedAt != nil || !validInstant(at) || at.Before(current.createdAt) {
		return TicketContactLink{}, ErrInvalidTarget
	}
	return RehydrateTicketContactLink(
		current.id, current.tenantID, current.ticketKind, current.ticketID, current.contactID,
		current.role, current.origin, current.provenance, current.version+1, current.createdAt, &at,
	)
}

func validTicketContactLink(value TicketContactLink) bool {
	canonical, err := RehydrateTicketContactLink(
		value.id, value.tenantID, value.ticketKind, value.ticketID, value.contactID, value.role,
		value.origin, value.provenance, value.version, value.createdAt, value.archivedAt,
	)
	return err == nil && canonical.id == value.id && canonical.tenantID == value.tenantID &&
		canonical.ticketKind == value.ticketKind && canonical.ticketID == value.ticketID &&
		canonical.contactID == value.contactID && canonical.role == value.role && canonical.origin == value.origin &&
		sameProvenance(canonical.provenance, value.provenance)
}

func cloneProvenance(value *EscalationProvenance) *EscalationProvenance {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func sameProvenance(left, right *EscalationProvenance) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func (link TicketContactLink) ID() EntityID           { return link.id }
func (link TicketContactLink) TenantID() EntityID     { return link.tenantID }
func (link TicketContactLink) TicketKind() TicketKind { return link.ticketKind }
func (link TicketContactLink) TicketID() EntityID     { return link.ticketID }
func (link TicketContactLink) ContactID() EntityID    { return link.contactID }
func (link TicketContactLink) Role() ContactRole      { return link.role }
func (link TicketContactLink) Origin() LinkOrigin     { return link.origin }
func (link TicketContactLink) Provenance() *EscalationProvenance {
	return cloneProvenance(link.provenance)
}
func (link TicketContactLink) Version() uint64        { return link.version }
func (link TicketContactLink) CreatedAt() time.Time   { return link.createdAt }
func (link TicketContactLink) ArchivedAt() *time.Time { return cloneInstant(link.archivedAt) }
func (link TicketContactLink) String() string {
	return fmt.Sprintf("ticket_contact_link(id=%s,tenant=%s,ticket=%s/%s,contact=%s,version=%d,archived=%t)",
		link.id, link.tenantID, link.ticketKind, link.ticketID, link.contactID, link.version, link.archivedAt != nil)
}

type AuthorAudience uint8

const (
	AuthorOperator AuthorAudience = iota + 1
	AuthorCustomer
)

func (audience AuthorAudience) String() string {
	switch audience {
	case AuthorOperator:
		return "operator"
	case AuthorCustomer:
		return "customer"
	default:
		return "unknown"
	}
}

// CommentAuthorSnapshot is persisted at comment commit and must never be
// reconstructed from a later role or membership state.
type CommentAuthorSnapshot struct {
	audience     AuthorAudience
	membershipID EntityID
	userID       EntityID
	contactID    *EntityID
}

func NewCommentAuthorSnapshot(
	audience AuthorAudience,
	membershipID, userID EntityID,
	contactID *EntityID,
) (CommentAuthorSnapshot, error) {
	validShape := audience == AuthorOperator && contactID == nil ||
		audience == AuthorCustomer && contactID != nil && validEntityID(*contactID)
	if !validShape || !validEntityID(membershipID) || !validEntityID(userID) {
		return CommentAuthorSnapshot{}, ErrResolutionDenied
	}
	var contactCopy *EntityID
	if contactID != nil {
		copy := *contactID
		contactCopy = &copy
	}
	return CommentAuthorSnapshot{
		audience: audience, membershipID: membershipID, userID: userID, contactID: contactCopy,
	}, nil
}

func (snapshot CommentAuthorSnapshot) Audience() AuthorAudience { return snapshot.audience }
func (snapshot CommentAuthorSnapshot) MembershipID() EntityID   { return snapshot.membershipID }
func (snapshot CommentAuthorSnapshot) UserID() EntityID         { return snapshot.userID }
func (snapshot CommentAuthorSnapshot) ContactID() *EntityID {
	if snapshot.contactID == nil {
		return nil
	}
	copy := *snapshot.contactID
	return &copy
}

func (snapshot CommentAuthorSnapshot) String() string {
	return fmt.Sprintf("comment_author(audience=%s,membership=%s,user=%s,contact_linked=%t)",
		snapshot.audience, snapshot.membershipID, snapshot.userID, snapshot.contactID != nil)
}
