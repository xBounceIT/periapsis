package customfieldimport

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/customfields"
	customapp "github.com/periapsis-im/periapsis/services/api/internal/customfields"
)

type Actor = customapp.Actor
type AuditContext = customapp.AuditContext

type Capability uint8

const (
	CapabilityRequest Capability = iota + 1
	CapabilityRead
	CapabilityCancel
)

func (capability Capability) String() string {
	switch capability {
	case CapabilityRequest:
		return "request"
	case CapabilityRead:
		return "read"
	case CapabilityCancel:
		return "cancel"
	default:
		return "unknown"
	}
}

func validCapability(capability Capability) bool {
	return capability >= CapabilityRequest && capability <= CapabilityCancel
}

// Access is fresh, operation-specific authority evidence. Private fields stop
// callers from assembling a permissive token outside the constructor.
type Access struct {
	tenant     uuid.UUID
	actor      uuid.UUID
	membership uuid.UUID
	objectType kernel.ObjectType
	capability Capability
	scope      customapp.Scope
	allowed    bool
}

func NewAccess(
	tenant uuid.UUID,
	actor uuid.UUID,
	membership uuid.UUID,
	objectType kernel.ObjectType,
	capability Capability,
	scope customapp.Scope,
	allowed bool,
) (Access, error) {
	if tenant == uuid.Nil || actor == uuid.Nil || membership == uuid.Nil ||
		objectType != kernel.ObjectAlert && objectType != kernel.ObjectCase ||
		!validCapability(capability) ||
		scope != customapp.ScopeAssigned && scope != customapp.ScopeOperatorTeam && scope != customapp.ScopeTenant {
		return Access{}, ErrInvalidInput
	}
	return Access{
		tenant: tenant, actor: actor, membership: membership, objectType: objectType,
		capability: capability, scope: scope, allowed: allowed,
	}, nil
}

func (access Access) Tenant() uuid.UUID             { return access.tenant }
func (access Access) Actor() uuid.UUID              { return access.actor }
func (access Access) Membership() uuid.UUID         { return access.membership }
func (access Access) ObjectType() kernel.ObjectType { return access.objectType }
func (access Access) Capability() Capability        { return access.capability }
func (access Access) Scope() customapp.Scope        { return access.scope }
func (access Access) Allowed() bool                 { return access.allowed }
func (access Access) String() string                { return "CustomFieldImportAccess{authority:[REDACTED]}" }
func (access Access) GoString() string              { return access.String() }

type CellInput struct {
	Key     string
	Present bool
	RawJSON json.RawMessage
}

func (input CellInput) String() string {
	presence := "missing"
	if input.Present {
		presence = "present"
	}
	return fmt.Sprintf("CellInput{presence:%s,key:[REDACTED],value:[REDACTED]}", presence)
}
func (input CellInput) GoString() string { return input.String() }

type RowInput struct {
	Target          uuid.UUID
	ExpectedVersion uint64
	Fields          []CellInput
}

func (input RowInput) String() string {
	return fmt.Sprintf(
		"RowInput{expected_version:%d,fields:%d,target:[REDACTED],values:[REDACTED]}",
		input.ExpectedVersion, len(input.Fields),
	)
}
func (input RowInput) GoString() string { return input.String() }

type RequestInput struct {
	ObjectType     kernel.ObjectType
	Mode           kernel.ImportMode
	Rows           []RowInput
	Retention      time.Duration
	IdempotencyKey string
	Audit          AuditContext
}

func (input RequestInput) String() string {
	return fmt.Sprintf(
		"RequestInput{object:%s,mode:%s,rows:%d,retention:%s,idempotency:[REDACTED],payload:[REDACTED]}",
		input.ObjectType, input.Mode, len(input.Rows), input.Retention,
	)
}
func (input RequestInput) GoString() string { return input.String() }

type CancelInput struct {
	ExpectedRevision uint64
	IdempotencyKey   string
	Audit            AuditContext
}

func (input CancelInput) String() string {
	return fmt.Sprintf(
		"CancelInput{expected_revision:%d,idempotency:[REDACTED]}", input.ExpectedRevision,
	)
}
func (input CancelInput) GoString() string { return input.String() }

type Record struct {
	Job            kernel.ImportJob
	RequestedAudit AuditContext
}

func (record Record) String() string {
	return fmt.Sprintf("Record{job:%s,audit:[REDACTED]}", record.Job)
}
func (record Record) GoString() string { return record.String() }

type Result struct {
	Record   Record
	Replayed bool
}

func (result Result) String() string {
	return fmt.Sprintf("Result{record:%s,replayed:%t}", result.Record, result.Replayed)
}
func (result Result) GoString() string { return result.String() }

type RowResult struct {
	Sequence        uint32
	Target          uuid.UUID
	ExpectedVersion uint64
	Result          kernel.ImportRowResult
	RecordedAt      time.Time
}

func (result RowResult) String() string {
	return fmt.Sprintf(
		"CustomFieldImportRowResult{sequence:%d,outcome:%s,target:[REDACTED]}",
		result.Sequence, result.Result.Outcome(),
	)
}
func (result RowResult) GoString() string { return result.String() }

type ResultPage struct {
	Items     []RowResult
	NextAfter *uint32
}

type ReplayQuery struct {
	Actor      Actor
	Tenant     uuid.UUID
	ObjectType kernel.ObjectType
	Command    CommandBinding
}

type RequestWrite struct {
	Actor   Actor
	Access  Access
	Job     kernel.ImportJob
	Command CommandBinding
	Audit   AuditContext
}

type CancellationWrite struct {
	Actor   Actor
	Access  Access
	Current kernel.ImportJob
	Next    kernel.ImportJob
	Command CommandBinding
	Audit   AuditContext
}

const (
	// HTTP int64 values are also consumed losslessly by browser clients. Ticket
	// versions may advance once during a commit, while import revisions remain
	// within the signed 32-bit ETag contract.
	maximumExpectedVersion = uint64(9_007_199_254_740_991) // exclusive
	maximumImportRevision  = uint64(2_147_483_647)         // exclusive
)

var idempotencyKeyPattern = regexp.MustCompile(`^[A-Za-z0-9._~-]{16,128}$`)

func validActor(actor Actor, tenant uuid.UUID) bool {
	return tenant != uuid.Nil && actor.TenantID == tenant && actor.ActiveTenantID == tenant &&
		actor.UserID != uuid.Nil && actor.SessionID != uuid.Nil && actor.MembershipID != uuid.Nil &&
		actor.Kind == customapp.PrincipalHuman && validStableKey(actor.AuthenticationMethod, 64)
}

func validAudit(audit AuditContext) bool {
	return audit.RequestID != uuid.Nil && audit.CorrelationID != uuid.Nil && audit.IPAddress.IsValid() &&
		validSingleLine(audit.UserAgent, 1_024, true) && validStableKey(audit.AuthenticationMethod, 64)
}

func validAccess(actor Actor, tenant uuid.UUID, objectType kernel.ObjectType, capability Capability, access Access) bool {
	if !validActor(actor, tenant) || !validAccessShape(access) {
		return false
	}
	return access.allowed && access.tenant == tenant && access.actor == actor.UserID &&
		access.membership == actor.MembershipID && access.objectType == objectType &&
		access.capability == capability
}

func validAccessShape(access Access) bool {
	rebuilt, err := NewAccess(
		access.tenant, access.actor, access.membership, access.objectType,
		access.capability, access.scope, access.allowed,
	)
	return err == nil && rebuilt == access
}

func validEnvelope(actor Actor, tenant uuid.UUID, key string, audit AuditContext) error {
	if !validActor(actor, tenant) {
		return ErrForbidden
	}
	if !idempotencyKeyPattern.MatchString(key) || !validAudit(audit) ||
		actor.Audit != (AuditContext{}) && actor.Audit != audit {
		return ErrInvalidInput
	}
	return nil
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

func validSingleLine(value string, maximum int, allowEmpty bool) bool {
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

func validStoredInstant(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond()%1_000 == 0
}

func entityID(id uuid.UUID) (kernel.EntityID, error) {
	parsed, err := kernel.ParseEntityID(id.String())
	if err != nil {
		return kernel.EntityID{}, ErrInvalidInput
	}
	return parsed, nil
}

func uuidFromEntity(id kernel.EntityID) uuid.UUID {
	return uuid.MustParse(id.String())
}
