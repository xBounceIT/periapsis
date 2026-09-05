package contacts

import (
	"crypto/sha256"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/contacts"
)

type Capability string

const (
	CapabilityContactRead             Capability = "contact.read"
	CapabilityContactManage           Capability = "contact.manage"
	CapabilityContactPreferenceManage Capability = "contact.preference.manage"
	CapabilityContactGroupRead        Capability = "contact_group.read"
	CapabilityContactGroupManage      Capability = "contact_group.manage"
	CapabilityPortalAlertRead         Capability = "portal.alert.read"
	CapabilityPortalCaseRead          Capability = "portal.case.read"
	CapabilityPortalCommentPublic     Capability = "portal.comment.public"
	CapabilityPortalAttachmentRead    Capability = "portal.attachment.read"
	CapabilityPortalPreferenceManage  Capability = "portal.contact.preference.manage"
	CapabilityAlertUpdate             Capability = "alert.update"
	CapabilityCaseUpdate              Capability = "case.update"
)

func validCapability(value Capability) bool {
	switch value {
	case CapabilityContactRead, CapabilityContactManage, CapabilityContactPreferenceManage,
		CapabilityContactGroupRead, CapabilityContactGroupManage, CapabilityPortalAlertRead,
		CapabilityPortalCaseRead, CapabilityPortalCommentPublic, CapabilityPortalAttachmentRead,
		CapabilityPortalPreferenceManage, CapabilityAlertUpdate, CapabilityCaseUpdate:
		return true
	default:
		return false
	}
}

type PrincipalKind uint8

const (
	PrincipalOperator PrincipalKind = iota + 1
	PrincipalCustomer
)

type Actor struct {
	TenantID             uuid.UUID
	ActiveTenantID       uuid.UUID
	UserID               uuid.UUID
	MembershipID         uuid.UUID
	SessionID            uuid.UUID
	Kind                 PrincipalKind
	AuthenticationMethod string
	Audit                AuditContext
}

type AuditContext struct {
	RequestID     uuid.UUID
	CorrelationID uuid.UUID
	RemoteAddress netip.Addr
	UserAgent     string
}

type Scope uint8

const (
	ScopeTenant Scope = iota + 1
	// ScopeContactSelf is valid only with repository evidence for the exact
	// linked membership+user+contact tuple. It is not interchangeable with a
	// generic "own" permission scope.
	ScopeContactSelf
	ScopeResourceLink
)

type Projection uint8

const (
	ProjectionOperator Projection = iota + 1
	ProjectionCustomer
)

type Access struct {
	Capability Capability
	Scope      Scope
	Projection Projection
	ContactID  uuid.UUID
}

type ContactPage struct {
	Items      []kernel.Contact
	NextCursor string
}

type ContactListInput struct {
	After           string
	Limit           int
	Search          string
	Active          *bool
	IncludeArchived bool
	Class           string
	Tag             string
}

type GroupPage struct {
	Items      []kernel.RecipientGroup
	NextCursor string
}

type GroupListInput struct {
	After           string
	Limit           int
	Search          string
	IncludeArchived bool
}

type CreateContactInput struct {
	Fields         kernel.ContactFields
	IdempotencyKey string
	Audit          AuditContext
}

type ReplaceContactInput struct {
	Fields          kernel.ContactFields
	ExpectedVersion uint64
	IdempotencyKey  string
	Audit           AuditContext
}

type PreferenceInput struct {
	Categories      []kernel.Key
	Windows         []kernel.NotificationWindow
	EmailAllowed    bool
	ExpectedVersion uint64
	IdempotencyKey  string
	Audit           AuditContext
}

type ArchiveInput struct {
	ExpectedVersion uint64
	Reason          string
	IdempotencyKey  string
	Audit           AuditContext
}

type CreateGroupInput struct {
	Key            kernel.Key
	Name           string
	Description    string
	Mode           kernel.GroupMode
	Rule           kernel.RuleNode
	MemberIDs      []uuid.UUID
	IdempotencyKey string
	Audit          AuditContext
}

type VersionGroupInput struct {
	Name            string
	Description     string
	Mode            kernel.GroupMode
	Rule            kernel.RuleNode
	MemberIDs       []uuid.UUID
	ExpectedVersion uint64
	IdempotencyKey  string
	Audit           AuditContext
}

type ContactResult struct {
	Contact            kernel.Contact
	CustomerProjection *kernel.CustomerSafeContact
	Replayed           bool
}

type GroupResult struct {
	Group    kernel.RecipientGroup
	Replayed bool
}

type LinkResult struct {
	Link     kernel.TicketContactLink
	Replayed bool
}

type LinkPage struct {
	Items      []kernel.TicketContactLink
	NextCursor string
}

type LinkListInput struct {
	TicketKind kernel.TicketKind
	TicketID   uuid.UUID
	After      string
	Limit      int
}

type LinkInput struct {
	TicketKind            kernel.TicketKind
	TicketID              uuid.UUID
	ContactID             uuid.UUID
	Role                  kernel.ContactRole
	ExpectedTicketVersion uint64
	IdempotencyKey        string
	Audit                 AuditContext
}

type ArchiveLinkInput struct {
	TicketKind            kernel.TicketKind
	TicketID              uuid.UUID
	ExpectedLinkVersion   uint64
	ExpectedTicketVersion uint64
	Reason                string
	IdempotencyKey        string
	Audit                 AuditContext
}

// ExactLinkAccess is fresh DB evidence that both capabilities and both
// tenant-owned resources were checked. A handler-supplied identifier cannot
// manufacture this evidence.
type ExactLinkAccess struct {
	TenantID           uuid.UUID
	TicketKind         kernel.TicketKind
	TicketID           uuid.UUID
	ContactID          uuid.UUID
	TicketVersion      uint64
	ContactVersion     uint64
	ResourceCapability Capability
	ContactReadable    bool
	ResourceWritable   bool
}

type PortalResourceEvidence struct {
	TenantID           uuid.UUID
	TicketKind         kernel.TicketKind
	TicketID           uuid.UUID
	ContactID          uuid.UUID
	ContactVersion     uint64
	TicketVersion      uint64
	CustomerVisible    bool
	ContactActive      bool
	Linked             bool
	Capability         Capability
	RequiredCapability Capability
}

type PortalResourceInput struct {
	TicketKind         kernel.TicketKind
	TicketID           uuid.UUID
	Capability         Capability
	RequiredCapability Capability
}

type PortalAuthorization struct {
	TicketKind    kernel.TicketKind
	TicketID      uuid.UUID
	ContactID     uuid.UUID
	TicketVersion uint64
}

type CommandBinding struct {
	Operation     string
	KeyDigest     [sha256.Size]byte
	RequestDigest [sha256.Size]byte
}

func StrongContactETag(contact kernel.Contact) string {
	return fmt.Sprintf(`"v%d"`, contact.Version())
}

func StrongGroupETag(group kernel.RecipientGroup) string {
	return fmt.Sprintf(`"v%d"`, group.Current().Version())
}

const (
	defaultPageLimit = 50
	maximumPageLimit = 200
)

var (
	cursorPattern         = regexp.MustCompile(`^[A-Za-z0-9_-]{1,512}$`)
	idempotencyKeyPattern = regexp.MustCompile(`^[A-Za-z0-9._~-]{16,128}$`)
)

func validActor(actor Actor, tenantID uuid.UUID) bool {
	return validUUIDv7(tenantID) && actor.TenantID == tenantID && actor.ActiveTenantID == tenantID &&
		validUUIDv7(actor.UserID) && validUUIDv7(actor.MembershipID) && validUUIDv7(actor.SessionID) &&
		(actor.Kind == PrincipalOperator || actor.Kind == PrincipalCustomer) &&
		validStableKey(actor.AuthenticationMethod, 64)
}

func validAudit(value AuditContext) bool {
	return value.RequestID != uuid.Nil && value.RequestID.Variant() == uuid.RFC4122 &&
		value.CorrelationID != uuid.Nil && value.CorrelationID.Variant() == uuid.RFC4122 &&
		value.RemoteAddress.IsValid() && value.RemoteAddress.Zone() == "" &&
		validBoundedText(value.UserAgent, 1_024, true)
}

func validMutationEnvelope(actor Actor, tenantID uuid.UUID, key string, audit AuditContext) error {
	if !validActor(actor, tenantID) {
		return ErrForbidden
	}
	if !idempotencyKeyPattern.MatchString(key) || !validAudit(audit) || actor.Audit != (AuditContext{}) && actor.Audit != audit {
		return ErrInvalidInput
	}
	return nil
}

func normalizeContactList(input ContactListInput) (ContactListInput, error) {
	if input.Limit < 0 || input.Limit > maximumPageLimit || input.After != "" && !cursorPattern.MatchString(input.After) ||
		!validBoundedText(input.Search, 240, true) || input.Class != "" && !validStableKey(input.Class, 64) ||
		input.Tag != "" && !validStableKey(input.Tag, 64) {
		return ContactListInput{}, ErrInvalidInput
	}
	if input.Limit == 0 {
		input.Limit = defaultPageLimit
	}
	return input, nil
}

func normalizeGroupList(input GroupListInput) (GroupListInput, error) {
	if input.Limit < 0 || input.Limit > maximumPageLimit || input.After != "" && !cursorPattern.MatchString(input.After) ||
		!validBoundedText(input.Search, 240, true) {
		return GroupListInput{}, ErrInvalidInput
	}
	if input.Limit == 0 {
		input.Limit = defaultPageLimit
	}
	return input, nil
}

func validUUIDv7(value uuid.UUID) bool {
	return value != uuid.Nil && value.Version() == 7 && value.Variant() == uuid.RFC4122
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

func validBoundedText(value string, maximum int, optional bool) bool {
	if value == "" {
		return optional
	}
	if len(value) > maximum || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || character == '\u200e' || character == '\u200f' ||
			character >= '\u202a' && character <= '\u202e' || character >= '\u2066' && character <= '\u2069' {
			return false
		}
	}
	return true
}

func validReason(value string) bool { return validBoundedText(value, 500, false) }

func entityID(value uuid.UUID) (kernel.EntityID, error) { return kernel.NewEntityID([16]byte(value)) }
func uuidFromEntity(value kernel.EntityID) uuid.UUID    { return uuid.UUID(value.Bytes()) }

func entityIDs(values []uuid.UUID, maximum int) ([]kernel.EntityID, error) {
	if len(values) > maximum {
		return nil, ErrInvalidInput
	}
	result := make([]kernel.EntityID, len(values))
	for index, value := range values {
		converted, err := entityID(value)
		if err != nil {
			return nil, ErrInvalidInput
		}
		result[index] = converted
	}
	slices.SortFunc(result, func(left, right kernel.EntityID) int { return strings.Compare(left.String(), right.String()) })
	for index := 1; index < len(result); index++ {
		if result[index-1] == result[index] {
			return nil, ErrInvalidInput
		}
	}
	return result, nil
}

func validResourceCapability(kind kernel.TicketKind, capability Capability) bool {
	return kind == kernel.TicketAlert && capability == CapabilityAlertUpdate ||
		kind == kernel.TicketCase && capability == CapabilityCaseUpdate
}

func validPortalCapability(kind kernel.TicketKind, capability Capability) bool {
	switch capability {
	case CapabilityPortalAlertRead:
		return kind == kernel.TicketAlert
	case CapabilityPortalCaseRead:
		return kind == kernel.TicketCase
	case CapabilityPortalCommentPublic, CapabilityPortalAttachmentRead:
		return kind == kernel.TicketAlert || kind == kernel.TicketCase
	default:
		return false
	}
}

func validPortalCapabilitySet(kind kernel.TicketKind, capability, required Capability) bool {
	if !validPortalCapability(kind, capability) {
		return false
	}
	if required == "" {
		return true
	}
	return capability == CapabilityPortalAttachmentRead &&
		(kind == kernel.TicketAlert && required == CapabilityPortalAlertRead ||
			kind == kernel.TicketCase && required == CapabilityPortalCaseRead)
}

func validInstant(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond()%1_000 == 0
}
