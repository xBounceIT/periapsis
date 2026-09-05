package ticketing

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
)

type WorkflowAdminCapability string

const (
	WorkflowCapabilityRead   WorkflowAdminCapability = "workflow.read"
	WorkflowCapabilityManage WorkflowAdminCapability = "workflow.manage"
)

func validWorkflowAdminCapability(capability WorkflowAdminCapability) bool {
	return capability == WorkflowCapabilityRead || capability == WorkflowCapabilityManage
}

// WorkflowAdminAccess is fresh repository evidence. The service validates the
// exact actor, tenant, capability, and principal on every call.
type WorkflowAdminAccess struct {
	tenant     uuid.UUID
	actor      uuid.UUID
	capability WorkflowAdminCapability
	principal  kernel.PrincipalKind
	allowed    bool
}

func NewWorkflowAdminAccess(
	tenant uuid.UUID,
	actor uuid.UUID,
	capability WorkflowAdminCapability,
	principal kernel.PrincipalKind,
	allowed bool,
) (WorkflowAdminAccess, error) {
	if _, err := entityID(tenant); err != nil {
		return WorkflowAdminAccess{}, ErrInvalidInput
	}
	if _, err := entityID(actor); err != nil || !validWorkflowAdminCapability(capability) ||
		principal != kernel.PrincipalOperator && principal != kernel.PrincipalCustomer &&
			principal != kernel.PrincipalServiceAccount {
		return WorkflowAdminAccess{}, ErrInvalidInput
	}
	return WorkflowAdminAccess{
		tenant: tenant, actor: actor, capability: capability, principal: principal, allowed: allowed,
	}, nil
}

func (access WorkflowAdminAccess) Tenant() uuid.UUID                   { return access.tenant }
func (access WorkflowAdminAccess) Actor() uuid.UUID                    { return access.actor }
func (access WorkflowAdminAccess) Capability() WorkflowAdminCapability { return access.capability }
func (access WorkflowAdminAccess) Principal() kernel.PrincipalKind     { return access.principal }
func (access WorkflowAdminAccess) Allowed() bool                       { return access.allowed }

type WorkflowAdminRecord struct {
	Workflow   kernel.ManagedWorkflow
	CreatedAt  time.Time
	UpdatedAt  time.Time
	ArchivedAt *time.Time
}

func (record WorkflowAdminRecord) String() string {
	return fmt.Sprintf(
		"WorkflowAdminRecord{kind:%s,status:%s,published_version:%d,revision:%d,metadata:[REDACTED]}",
		record.Workflow.Kind(), record.Workflow.Status(), record.Workflow.CurrentVersion(), record.Workflow.Revision(),
	)
}

type WorkflowVersionRecord struct {
	TenantID                uuid.UUID
	Definition              kernel.WorkflowDefinition
	PublishedByMembershipID *uuid.UUID
	PublisherDisplayName    string
	PublishedAt             time.Time
}

func (record WorkflowVersionRecord) String() string {
	return fmt.Sprintf(
		"WorkflowVersionRecord{kind:%s,version:%d,publisher:[REDACTED]}",
		record.Definition.Kind(), record.Definition.Version(),
	)
}

type WorkflowAdminListInput struct {
	After       string
	Limit       int
	Kind        *kernel.AggregateKind
	Status      *kernel.WorkflowStatus
	Search      string
	DefaultOnly bool
}

func (input WorkflowAdminListInput) String() string {
	kind, status := "all", "all"
	if input.Kind != nil {
		kind = input.Kind.String()
	}
	if input.Status != nil {
		status = input.Status.String()
	}
	return fmt.Sprintf(
		"WorkflowAdminListInput{kind:%s,status:%s,default_only:%t,limit:%d,cursor:[REDACTED],search:[REDACTED]}",
		kind, status, input.DefaultOnly, input.Limit,
	)
}

type WorkflowAdminPage struct {
	Items      []WorkflowAdminRecord
	NextCursor string
}

type WorkflowVersionListInput struct {
	AfterVersion uint64
	Limit        int
}

type WorkflowVersionPage struct {
	Items       []WorkflowVersionRecord
	NextVersion uint64
}

type WorkflowDesignInput struct {
	States      []kernel.StateDefinition
	Transitions []kernel.TransitionDefinition
}

type WorkflowCreateInput struct {
	Kind           kernel.AggregateKind
	Key            string
	DisplayName    string
	Description    string
	Design         WorkflowDesignInput
	IdempotencyKey string
}

func (input WorkflowCreateInput) String() string {
	return fmt.Sprintf(
		"WorkflowCreateInput{kind:%s,key:[REDACTED],states:%d,transitions:%d,metadata:[REDACTED],idempotency:[REDACTED]}",
		input.Kind, len(input.Design.States), len(input.Design.Transitions),
	)
}

type WorkflowPublishInput struct {
	ExpectedRevision uint64
	Design           WorkflowDesignInput
	IdempotencyKey   string
}

func (input WorkflowPublishInput) String() string {
	return fmt.Sprintf(
		"WorkflowPublishInput{expected_revision:%d,states:%d,transitions:%d,idempotency:[REDACTED]}",
		input.ExpectedRevision, len(input.Design.States), len(input.Design.Transitions),
	)
}

type WorkflowMetadataInput struct {
	ExpectedRevision uint64
	DisplayName      string
	Description      string
	IdempotencyKey   string
}

func (input WorkflowMetadataInput) String() string {
	return fmt.Sprintf(
		"WorkflowMetadataInput{expected_revision:%d,metadata:[REDACTED],idempotency:[REDACTED]}",
		input.ExpectedRevision,
	)
}

type WorkflowLifecycleInput struct {
	ExpectedRevision uint64
	IdempotencyKey   string
}

func (input WorkflowLifecycleInput) String() string {
	return fmt.Sprintf(
		"WorkflowLifecycleInput{expected_revision:%d,idempotency:[REDACTED]}", input.ExpectedRevision,
	)
}

type WorkflowSimulationInput struct {
	Version              uint64
	State                kernel.Key
	CommentPresent       bool
	Roles                []kernel.Key
	Permissions          []kernel.Permission
	ProvidedCustomFields []kernel.Key
	Facts                kernel.ConditionFacts
}

func (input WorkflowSimulationInput) String() string {
	return fmt.Sprintf(
		"WorkflowSimulationInput{version:%d,state:[REDACTED],comment:%t,roles:%d,permissions:%d,custom_fields:%d,facts:[REDACTED]}",
		input.Version, input.CommentPresent, len(input.Roles), len(input.Permissions),
		len(input.ProvidedCustomFields),
	)
}

type WorkflowSimulationResult struct {
	WorkflowID uuid.UUID
	Kind       kernel.AggregateKind
	Version    uint64
	Results    []kernel.TransitionSimulation
}

type WorkflowAdminMutationResult struct {
	Record   WorkflowAdminRecord
	Replayed bool
}

type WorkflowAdminCommandBinding struct {
	Action      kernel.WorkflowAdministrationAction
	KeyHash     [sha256.Size]byte
	Fingerprint [sha256.Size]byte
}

type WorkflowAdminReplayQuery struct {
	TenantID    uuid.UUID
	ActorID     uuid.UUID
	Action      kernel.WorkflowAdministrationAction
	KeyHash     [sha256.Size]byte
	Fingerprint [sha256.Size]byte
}

func WorkflowAdminStrongETag(record WorkflowAdminRecord) string {
	return WorkflowAdminStrongETagFor(uuidFromEntity(record.Workflow.ID()), record.Workflow.Revision())
}

// WorkflowAdminStrongETagFor binds a validator to both the tenant-owned
// lineage identity and its independent catalog revision. HTTP adapters can
// compare If-Match to the body expectedRevision without rereading mutable
// state, preserving exact idempotency replay semantics; the repository still
// performs the authoritative CAS inside the mutation transaction.
func WorkflowAdminStrongETagFor(workflowID uuid.UUID, revision uint64) string {
	digest := sha256.Sum256([]byte("periapsis.workflow-admin.etag.v1\x00" + workflowID.String()))
	return fmt.Sprintf("\"v%d-%s\"", revision, base64.RawURLEncoding.EncodeToString(digest[:]))
}
