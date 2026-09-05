package contacts

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"slices"
	"strings"
	"time"
)

const TargetSelectorSchemaVersion uint16 = 1

type TargetKind uint8

const (
	TargetCustomerContacts TargetKind = iota + 1
	TargetContactGroup
	TargetContactTag
)

func (kind TargetKind) String() string {
	switch kind {
	case TargetCustomerContacts:
		return "customer_contacts"
	case TargetContactGroup:
		return "contact_group"
	case TargetContactTag:
		return "contact_tag"
	default:
		return "unknown"
	}
}

// TargetSelector is the contact-domain arm consumed by the notification rule
// engine. A group target always pins the immutable group version selected when
// the notification rule version is created.
type TargetSelector struct {
	schemaVersion uint16
	kind          TargetKind
	groupID       EntityID
	groupVersion  uint64
	tag           Key
}

func AllCustomerContactsTarget() TargetSelector {
	return TargetSelector{schemaVersion: TargetSelectorSchemaVersion, kind: TargetCustomerContacts}
}

func NewContactGroupTarget(groupID EntityID, groupVersion uint64) (TargetSelector, error) {
	if !validEntityID(groupID) || groupVersion == 0 {
		return TargetSelector{}, ErrInvalidTarget
	}
	return TargetSelector{
		schemaVersion: TargetSelectorSchemaVersion, kind: TargetContactGroup,
		groupID: groupID, groupVersion: groupVersion,
	}, nil
}

func NewContactTagTarget(tag Key) (TargetSelector, error) {
	if !validKey(tag.value) {
		return TargetSelector{}, ErrInvalidTarget
	}
	return TargetSelector{schemaVersion: TargetSelectorSchemaVersion, kind: TargetContactTag, tag: tag}, nil
}

func (selector TargetSelector) SchemaVersion() uint16 { return selector.schemaVersion }
func (selector TargetSelector) Kind() TargetKind      { return selector.kind }
func (selector TargetSelector) GroupID() EntityID     { return selector.groupID }
func (selector TargetSelector) GroupVersion() uint64  { return selector.groupVersion }
func (selector TargetSelector) Tag() Key              { return selector.tag }

func validTarget(selector TargetSelector) bool {
	if selector.schemaVersion != TargetSelectorSchemaVersion {
		return false
	}
	switch selector.kind {
	case TargetCustomerContacts:
		return selector.groupID == (EntityID{}) && selector.groupVersion == 0 && selector.tag == (Key{})
	case TargetContactGroup:
		return validEntityID(selector.groupID) && selector.groupVersion > 0 && selector.tag == (Key{})
	case TargetContactTag:
		return selector.groupID == (EntityID{}) && selector.groupVersion == 0 && validKey(selector.tag.value)
	default:
		return false
	}
}

func (selector TargetSelector) String() string {
	switch selector.kind {
	case TargetContactGroup:
		return fmt.Sprintf("target(kind=%s,schema=%d,group=%s,version=%d)",
			selector.kind, selector.schemaVersion, selector.groupID, selector.groupVersion)
	case TargetContactTag:
		return fmt.Sprintf("target(kind=%s,schema=%d,tag=%s)", selector.kind, selector.schemaVersion, selector.tag.value)
	default:
		return fmt.Sprintf("target(kind=%s,schema=%d)", selector.kind, selector.schemaVersion)
	}
}

type ResolutionSurface uint8

const (
	SurfaceTenantEvent ResolutionSurface = iota + 1
	SurfaceTicketEvent
)

type ResolutionInput struct {
	TenantID   EntityID
	Selector   TargetSelector
	Category   Key
	OccurredAt time.Time
	Surface    ResolutionSurface
	// TicketContactIDs must be non-nil for ticket events. It is the exact
	// tenant-checked link result, not an untrusted client selection.
	TicketContactIDs []EntityID
	Contacts         []Contact
	// GroupVersions is empty for non-group targets and contains exactly the
	// requested immutable version for a group target.
	GroupVersions []GroupVersion
}

// Recipient represents one destination decision. Several contacts may share a
// mailbox; they are deliberately collapsed into one destination and their
// contributing IDs remain sorted for policy evidence.
type Recipient struct {
	email      Email
	contactIDs []EntityID
}

func (recipient Recipient) Email() Email           { return recipient.email }
func (recipient Recipient) ContactIDs() []EntityID { return slices.Clone(recipient.contactIDs) }
func (recipient Recipient) String() string {
	return fmt.Sprintf("contact_recipient(contacts=%d,destination=<redacted>)", len(recipient.contactIDs))
}

type ResolutionPlan struct {
	tenantID   EntityID
	selector   TargetSelector
	category   Key
	occurredAt time.Time
	recipients []Recipient
	digest     [sha256.Size]byte
}

func (plan ResolutionPlan) TenantID() EntityID        { return plan.tenantID }
func (plan ResolutionPlan) Selector() TargetSelector  { return plan.selector }
func (plan ResolutionPlan) Category() Key             { return plan.category }
func (plan ResolutionPlan) OccurredAt() time.Time     { return plan.occurredAt }
func (plan ResolutionPlan) Recipients() []Recipient   { return cloneRecipients(plan.recipients) }
func (plan ResolutionPlan) Digest() [sha256.Size]byte { return plan.digest }

func cloneRecipients(values []Recipient) []Recipient {
	result := make([]Recipient, len(values))
	for index, value := range values {
		result[index] = Recipient{email: value.email, contactIDs: slices.Clone(value.contactIDs)}
	}
	return result
}

func ResolveTargets(input ResolutionInput) (ResolutionPlan, error) {
	if !validEntityID(input.TenantID) || !validTarget(input.Selector) || !validKey(input.Category.value) ||
		!validInstant(input.OccurredAt) || input.Surface != SurfaceTenantEvent && input.Surface != SurfaceTicketEvent ||
		len(input.Contacts) > maximumResolutionContacts {
		return ResolutionPlan{}, ErrInvalidTarget
	}
	contactsByID := make(map[EntityID]Contact, len(input.Contacts))
	for _, contact := range input.Contacts {
		if !validContact(contact) || contact.tenantID != input.TenantID {
			return ResolutionPlan{}, ErrResolutionDrift
		}
		if _, duplicate := contactsByID[contact.id]; duplicate {
			return ResolutionPlan{}, ErrResolutionDrift
		}
		contactsByID[contact.id] = contact
	}

	var authorized map[EntityID]struct{}
	if input.Surface == SurfaceTicketEvent {
		if input.TicketContactIDs == nil {
			return ResolutionPlan{}, ErrResolutionDenied
		}
		canonical, ok := canonicalIDs(input.TicketContactIDs, maximumResolutionContacts)
		if !ok {
			return ResolutionPlan{}, ErrResolutionDrift
		}
		authorized = make(map[EntityID]struct{}, len(canonical))
		for _, contactID := range canonical {
			if _, found := contactsByID[contactID]; !found {
				return ResolutionPlan{}, ErrResolutionDrift
			}
			authorized[contactID] = struct{}{}
		}
		for contactID := range contactsByID {
			if _, linked := authorized[contactID]; !linked {
				return ResolutionPlan{}, ErrResolutionDrift
			}
		}
	} else if input.TicketContactIDs != nil {
		return ResolutionPlan{}, ErrInvalidTarget
	}

	group, err := exactGroupVersion(input.Selector, input.GroupVersions, input.TenantID)
	if err != nil {
		return ResolutionPlan{}, err
	}

	selected := make([]Contact, 0, len(input.Contacts))
	for _, contact := range input.Contacts {
		if authorized != nil {
			if _, linked := authorized[contact.id]; !linked {
				continue
			}
		}
		if !matchesTarget(contact, input.Selector, group) || !contact.eligible(input.Category, input.OccurredAt) {
			continue
		}
		selected = append(selected, contact)
	}
	slices.SortFunc(selected, func(left, right Contact) int {
		if compared := strings.Compare(left.fields.Email.canonical, right.fields.Email.canonical); compared != 0 {
			return compared
		}
		return compareEntityID(left.id, right.id)
	})

	recipients := make([]Recipient, 0, len(selected))
	for _, contact := range selected {
		last := len(recipients) - 1
		if last >= 0 && recipients[last].email == contact.fields.Email {
			recipients[last].contactIDs = append(recipients[last].contactIDs, contact.id)
			continue
		}
		recipients = append(recipients, Recipient{email: contact.fields.Email, contactIDs: []EntityID{contact.id}})
	}
	plan := ResolutionPlan{
		tenantID: input.TenantID, selector: input.Selector, category: input.Category,
		occurredAt: input.OccurredAt, recipients: recipients,
	}
	plan.digest = resolutionDigest(plan)
	return plan, nil
}

func exactGroupVersion(selector TargetSelector, versions []GroupVersion, tenantID EntityID) (*GroupVersion, error) {
	if selector.kind != TargetContactGroup {
		if len(versions) != 0 {
			return nil, ErrResolutionDrift
		}
		return nil, nil
	}
	if len(versions) != 1 || !validGroupVersion(versions[0]) || versions[0].tenantID != tenantID ||
		versions[0].groupID != selector.groupID || versions[0].version != selector.groupVersion {
		return nil, ErrResolutionDrift
	}
	copy := cloneGroupVersion(versions[0])
	return &copy, nil
}

func matchesTarget(contact Contact, selector TargetSelector, group *GroupVersion) bool {
	switch selector.kind {
	case TargetCustomerContacts:
		return true
	case TargetContactTag:
		return slices.Contains(contact.fields.Tags, selector.tag)
	case TargetContactGroup:
		if group == nil {
			return false
		}
		if group.mode == GroupManual {
			return slices.Contains(group.members, contact.id)
		}
		return group.mode == GroupDynamic && group.rule.matches(contact)
	default:
		return false
	}
}

func resolutionDigest(plan ResolutionPlan) [sha256.Size]byte {
	hash := sha256.New()
	hash.Write([]byte("periapsis.contact-recipient-plan.v1\x00"))
	hash.Write(plan.tenantID.value[:])
	var integer [8]byte
	binary.BigEndian.PutUint16(integer[:2], plan.selector.schemaVersion)
	hash.Write(integer[:2])
	hash.Write([]byte{byte(plan.selector.kind)})
	if plan.selector.kind == TargetContactGroup {
		hash.Write(plan.selector.groupID.value[:])
		binary.BigEndian.PutUint64(integer[:], plan.selector.groupVersion)
		hash.Write(integer[:])
	} else if plan.selector.kind == TargetContactTag {
		writeDigestText(hash, plan.selector.tag.value)
	}
	writeDigestText(hash, plan.category.value)
	binary.BigEndian.PutUint64(integer[:], uint64(plan.occurredAt.UnixMilli()))
	hash.Write(integer[:])
	for _, recipient := range plan.recipients {
		// The digest binds the destination without exposing it to logs or the
		// outbox envelope. Persistence stores the address only through the
		// privileged/encrypted notification boundary.
		destinationDigest := sha256.Sum256([]byte(recipient.email.canonical))
		hash.Write(destinationDigest[:])
		for _, contactID := range recipient.contactIDs {
			hash.Write(contactID.value[:])
		}
	}
	var result [sha256.Size]byte
	copy(result[:], hash.Sum(nil))
	return result
}

type digestWriter interface{ Write([]byte) (int, error) }

func writeDigestText(writer digestWriter, value string) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	writer.Write(length[:])
	writer.Write([]byte(value))
}
