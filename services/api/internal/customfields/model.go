package customfields

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/customfields"
)

type Capability string

const (
	CapabilityRead   Capability = "custom_field.read"
	CapabilityManage Capability = "custom_field.manage"
)

type Scope string

const (
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
	Audit                AuditContext
}

type AuditContext struct {
	RequestID            uuid.UUID
	CorrelationID        uuid.UUID
	IPAddress            netip.Addr
	UserAgent            string
	AuthenticationMethod string
}

type Access struct {
	Audience kernel.Audience
	Scope    Scope
	// DefinitionInventory marks the administrative definition read route. It
	// lets repositories distinguish a read+manage projection from a manage-only
	// mutation lookup and revalidate the exact compound authority accordingly.
	DefinitionInventory bool
	// Manage distinguishes the tenant-wide definition-management projection
	// from an ordinary read. Customer-only definitions must remain hidden from
	// operator readers while still being manageable by an authorized tenant
	// administrator.
	Manage bool
	// Write marks a resource-scoped Alert/Case value mutation authorization.
	// It is never inferred from UI visibility or from definition management.
	Write bool
}

type DefinitionPage struct {
	Items      []kernel.Definition
	NextCursor string
}

type DefinitionListInput struct {
	ObjectType      kernel.ObjectType
	IncludeArchived bool
	Limit           int
	After           string
}

type CreateDefinitionInput struct {
	Definition     kernel.DefinitionInput
	IdempotencyKey string
	Audit          AuditContext
}

type ReplaceDefinitionInput struct {
	Definition      kernel.DefinitionInput
	ExpectedVersion uint64
	IdempotencyKey  string
	Audit           AuditContext
}

type ArchiveDefinitionInput struct {
	ExpectedVersion uint64
	Reason          string
	IdempotencyKey  string
	Audit           AuditContext
}

type DefinitionResult struct {
	Definition kernel.Definition
	Replayed   bool
}

type ObjectWriteInput struct {
	ObjectType      kernel.ObjectType
	ObjectID        uuid.UUID
	Phase           kernel.WritePhase
	TransitionKey   string
	Fields          []RawFieldInput
	ExpectedVersion uint64
	IdempotencyKey  string
	Audit           AuditContext
}

type RawFieldInput struct {
	Key     string
	RawJSON []byte
	Present bool
}

type ObjectWriteResult struct {
	Values   []kernel.FieldValue
	Version  uint64
	Replayed bool
}

type ProjectionInput struct {
	ObjectType kernel.ObjectType
	ObjectID   uuid.UUID
	Surface    kernel.ProjectionSurface
}

type Projection struct {
	Definitions []kernel.Definition
	Values      []kernel.FieldValue
	Version     uint64
}

type FieldValidationError struct {
	Fields []kernel.FieldError
}

func (validationError *FieldValidationError) Error() string {
	return fmt.Sprintf("custom-field validation failed for %d field(s)", len(validationError.Fields))
}

func (validationError *FieldValidationError) Unwrap() error { return ErrInvalidInput }

func StrongETag(definition kernel.Definition) string {
	payload := fmt.Sprintf("%s:%d", definition.ID().String(), definition.SchemaVersion())
	digest := sha256.Sum256([]byte(payload))
	return `"cf-` + base64.RawURLEncoding.EncodeToString(digest[:16]) + `"`
}

const (
	defaultPageLimit = 50
	maximumPageLimit = 200
)

var cursorPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,256}$`)
var idempotencyKeyPattern = regexp.MustCompile(`^[A-Za-z0-9._~-]{16,128}$`)

func validActor(actor Actor, tenantID uuid.UUID) bool {
	return tenantID != uuid.Nil && actor.TenantID == tenantID &&
		actor.ActiveTenantID == tenantID && actor.UserID != uuid.Nil && actor.SessionID != uuid.Nil &&
		actor.MembershipID != uuid.Nil && validStableKey(actor.AuthenticationMethod, 64) &&
		(actor.Kind == PrincipalHuman || actor.Kind == PrincipalCustomer)
}

func validAudit(value AuditContext) bool {
	return value.RequestID != uuid.Nil && value.CorrelationID != uuid.Nil &&
		value.IPAddress.IsValid() && validBoundedSingleLine(value.UserAgent, 1_024, true) &&
		validStableKey(value.AuthenticationMethod, 64)
}

func validIdempotencyKey(value string) bool {
	return idempotencyKeyPattern.MatchString(value)
}

func validReason(value string) bool {
	return validBoundedSingleLine(value, 500, false)
}

func validBoundedSingleLine(value string, maximum int, allowEmpty bool) bool {
	if value == "" {
		return allowEmpty
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

func normalizeListInput(input DefinitionListInput) (DefinitionListInput, error) {
	if input.ObjectType != kernel.ObjectAlert && input.ObjectType != kernel.ObjectCase ||
		input.Limit < 0 || input.Limit > maximumPageLimit ||
		input.After != "" && !cursorPattern.MatchString(input.After) {
		return DefinitionListInput{}, ErrInvalidInput
	}
	if input.Limit == 0 {
		input.Limit = defaultPageLimit
	}
	return input, nil
}

func validInstant(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond()%1_000 == 0
}
