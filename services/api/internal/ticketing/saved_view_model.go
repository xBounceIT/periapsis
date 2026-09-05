package ticketing

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	customkernel "github.com/periapsis-im/periapsis/modules/customfields"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
)

type SavedViewCapability string

const (
	SavedViewCapabilityRead   SavedViewCapability = "saved_view.read"
	SavedViewCapabilityManage SavedViewCapability = "saved_view.manage"
)

func validSavedViewCapability(capability SavedViewCapability) bool {
	return capability == SavedViewCapabilityRead || capability == SavedViewCapabilityManage
}

// SavedViewAccess is current, repository-resolved proof for one exact human
// membership and ticket kind. It never grants authority by itself: every write
// re-resolves the same facts inside the commit transaction.
type SavedViewAccess struct {
	tenant     uuid.UUID
	actor      uuid.UUID
	membership uuid.UUID
	kind       kernel.AggregateKind
	capability SavedViewCapability
	principal  kernel.PrincipalKind
	allowed    bool
}

func NewSavedViewAccess(
	tenant uuid.UUID,
	actor uuid.UUID,
	membership uuid.UUID,
	kind kernel.AggregateKind,
	capability SavedViewCapability,
	principal kernel.PrincipalKind,
	allowed bool,
) (SavedViewAccess, error) {
	if !validWorkflowUUID(tenant) || !validWorkflowUUID(actor) || !validWorkflowUUID(membership) ||
		kind != kernel.AggregateAlert && kind != kernel.AggregateCase ||
		!validSavedViewCapability(capability) ||
		principal != kernel.PrincipalOperator && principal != kernel.PrincipalCustomer &&
			principal != kernel.PrincipalServiceAccount {
		return SavedViewAccess{}, ErrInvalidInput
	}
	return SavedViewAccess{
		tenant: tenant, actor: actor, membership: membership, kind: kind,
		capability: capability, principal: principal, allowed: allowed,
	}, nil
}

func (access SavedViewAccess) Tenant() uuid.UUID               { return access.tenant }
func (access SavedViewAccess) Actor() uuid.UUID                { return access.actor }
func (access SavedViewAccess) Membership() uuid.UUID           { return access.membership }
func (access SavedViewAccess) Kind() kernel.AggregateKind      { return access.kind }
func (access SavedViewAccess) Capability() SavedViewCapability { return access.capability }
func (access SavedViewAccess) Principal() kernel.PrincipalKind { return access.principal }
func (access SavedViewAccess) Allowed() bool                   { return access.allowed }

type SavedViewDefinitionSource string

const (
	SavedViewDefinitionCore        SavedViewDefinitionSource = "core"
	SavedViewDefinitionCustomField SavedViewDefinitionSource = "custom_field"
	SavedViewDefinitionSLA         SavedViewDefinitionSource = "sla"
)

func validSavedViewDefinitionSource(source SavedViewDefinitionSource) bool {
	return source == SavedViewDefinitionCore || source == SavedViewDefinitionCustomField ||
		source == SavedViewDefinitionSLA
}

type SavedViewCustomFilterInput struct {
	DefinitionID              uuid.UUID
	ExpectedDefinitionVersion uint64
	Operator                  customkernel.FilterOperator
	Value                     json.RawMessage
}

func (input SavedViewCustomFilterInput) String() string {
	return fmt.Sprintf(
		"SavedViewCustomFilterInput{version:%d,metadata:[REDACTED],value:[REDACTED]}",
		input.ExpectedDefinitionVersion,
	)
}

func (input SavedViewCustomFilterInput) GoString() string { return input.String() }

type SavedViewFiltersInput struct {
	States          []string
	Severities      []string
	Priorities      []string
	AssignedTeamID  *uuid.UUID
	AssigneeUserID  *uuid.UUID
	ClaimedBy       *uuid.UUID
	Queue           string
	CustomerVisible *bool
	Search          string
	Custom          []SavedViewCustomFilterInput
}

func (input SavedViewFiltersInput) String() string {
	return fmt.Sprintf(
		"SavedViewFiltersInput{states:%d,severities:%d,priorities:%d,custom:%d,queue:[REDACTED],search:[REDACTED]}",
		len(input.States), len(input.Severities), len(input.Priorities), len(input.Custom),
	)
}

func (input SavedViewFiltersInput) GoString() string { return input.String() }

type SavedViewColumnInput struct {
	Source                    SavedViewDefinitionSource
	CoreKey                   string
	DefinitionID              *uuid.UUID
	ExpectedDefinitionVersion uint64
	Width                     uint16
	Visible                   bool
	Pin                       string
}

type SavedViewSortInput struct {
	Source                    SavedViewDefinitionSource
	CoreKey                   string
	DefinitionID              *uuid.UUID
	ExpectedDefinitionVersion uint64
	Direction                 string
	Nulls                     string
}

type SavedViewSpecInput struct {
	Filters SavedViewFiltersInput
	Sort    SavedViewSortInput
	Columns []SavedViewColumnInput
}

func (input SavedViewSpecInput) String() string {
	return fmt.Sprintf(
		"SavedViewSpecInput{states:%d,severities:%d,priorities:%d,custom:%d,columns:%d,search:[REDACTED]}",
		len(input.Filters.States), len(input.Filters.Severities), len(input.Filters.Priorities),
		len(input.Filters.Custom), len(input.Columns),
	)
}

func (input SavedViewSpecInput) GoString() string { return input.String() }

type SavedViewCreateInput struct {
	Name           string
	Spec           SavedViewSpecInput
	IdempotencyKey string
}

func (input SavedViewCreateInput) String() string {
	return fmt.Sprintf(
		"SavedViewCreateInput{spec:%s,name:[REDACTED],idempotency_key:[REDACTED]}",
		input.Spec,
	)
}

func (input SavedViewCreateInput) GoString() string { return input.String() }

type SavedViewReplaceInput struct {
	ExpectedRevision uint64
	ExpectedETag     string
	Name             string
	Spec             SavedViewSpecInput
	IdempotencyKey   string
}

func (input SavedViewReplaceInput) String() string {
	return fmt.Sprintf(
		"SavedViewReplaceInput{expected_revision:%d,spec:%s,name:[REDACTED],idempotency_key:[REDACTED]}",
		input.ExpectedRevision, input.Spec,
	)
}

func (input SavedViewReplaceInput) GoString() string { return input.String() }

type SavedViewLifecycleInput struct {
	ExpectedRevision uint64
	ExpectedETag     string
	IdempotencyKey   string
}

func (input SavedViewLifecycleInput) String() string {
	return fmt.Sprintf(
		"SavedViewLifecycleInput{expected_revision:%d,idempotency_key:[REDACTED]}",
		input.ExpectedRevision,
	)
}

func (input SavedViewLifecycleInput) GoString() string { return input.String() }

type SavedViewListInput struct {
	After           string
	Limit           int
	IncludeArchived bool
}

func (input SavedViewListInput) String() string {
	return fmt.Sprintf(
		"SavedViewListInput{limit:%d,include_archived:%t,cursor:[REDACTED]}",
		input.Limit, input.IncludeArchived,
	)
}

func (input SavedViewListInput) GoString() string { return input.String() }

type SavedViewRecord struct {
	View       kernel.SavedView
	SpecDigest [sha256.Size]byte
	CreatedAt  time.Time
	UpdatedAt  time.Time
	ArchivedAt *time.Time
}

func (record SavedViewRecord) String() string {
	return fmt.Sprintf(
		"SavedViewRecord{kind:%s,status:%s,revision:%d,digest:[REDACTED],metadata:[REDACTED]}",
		record.View.Kind(), record.View.Status(), record.View.Revision(),
	)
}

func (record SavedViewRecord) GoString() string { return record.String() }

type SavedViewPage struct {
	Items      []SavedViewRecord
	NextCursor string
}

func (page SavedViewPage) String() string {
	return fmt.Sprintf(
		"SavedViewPage{items:%d,next_cursor:[REDACTED]}",
		len(page.Items),
	)
}

func (page SavedViewPage) GoString() string { return page.String() }

type SavedViewMutationResult struct {
	Record   SavedViewRecord
	Replayed bool
}

func (result SavedViewMutationResult) String() string {
	return fmt.Sprintf("SavedViewMutationResult{replayed:%t,record:[REDACTED]}", result.Replayed)
}

func (result SavedViewMutationResult) GoString() string { return result.String() }

type SavedViewCommandBinding struct {
	Action      kernel.SavedViewAction
	KeyHash     [sha256.Size]byte
	Fingerprint [sha256.Size]byte
}

func (binding SavedViewCommandBinding) String() string {
	return fmt.Sprintf(
		"SavedViewCommandBinding{action:%s,key_hash:[REDACTED],fingerprint:[REDACTED]}",
		binding.Action,
	)
}

func (binding SavedViewCommandBinding) GoString() string { return binding.String() }

type SavedViewReplayQuery struct {
	TenantID          uuid.UUID
	ActorID           uuid.UUID
	OwnerMembershipID uuid.UUID
	Kind              kernel.AggregateKind
	Action            kernel.SavedViewAction
	KeyHash           [sha256.Size]byte
	Fingerprint       [sha256.Size]byte
}

func (query SavedViewReplayQuery) String() string {
	return fmt.Sprintf(
		"SavedViewReplayQuery{kind:%s,action:%s,identity:[REDACTED],digests:[REDACTED]}",
		query.Kind, query.Action,
	)
}

func (query SavedViewReplayQuery) GoString() string { return query.String() }

func SavedViewStrongETag(record SavedViewRecord) string {
	payload := fmt.Sprintf(
		"saved-view:%s:%d:%x", record.View.ID(), record.View.Revision(), record.SpecDigest,
	)
	digest := sha256.Sum256([]byte(payload))
	return fmt.Sprintf("\"sha256-%x\"", digest)
}

// ValidSavedViewStrongETag accepts only the representation-bound validator
// emitted by SavedViewStrongETag. Weak, wildcard, list, and version-only
// validators fail closed before the repository is consulted.
func ValidSavedViewStrongETag(value string) bool {
	const prefix = `"sha256-`
	if len(value) != len(prefix)+sha256.Size*2+1 || value[:len(prefix)] != prefix || value[len(value)-1] != '"' {
		return false
	}
	for _, character := range value[len(prefix) : len(value)-1] {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return true
}
