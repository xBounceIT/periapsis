package ticketing

import (
	"context"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
)

// WorkflowAdminRepository is the tenant/RLS and transaction boundary for
// administration. CommitWorkflow must re-resolve the required capability in
// its transaction, CAS every plan revision, and atomically append redacted
// audit/outbox records. The earlier access proof only bounds reads;
// it is never sufficient authority for a write. Published version rows are
// append-only. A default displacement, when present, is part of the same CAS.
// Exact replays return the immutable representation committed by the original
// command without applying it again; payload drift is a conflict.
type WorkflowAdminRepository interface {
	ResolveWorkflowAdminAccess(
		context.Context,
		Actor,
		uuid.UUID,
		WorkflowAdminCapability,
	) (WorkflowAdminAccess, error)
	ReserveWorkflowID(context.Context, uuid.UUID) (kernel.EntityID, error)
	ListWorkflows(
		context.Context,
		Actor,
		uuid.UUID,
		WorkflowAdminListInput,
		WorkflowAdminAccess,
	) (WorkflowAdminPage, error)
	GetWorkflow(
		context.Context,
		Actor,
		uuid.UUID,
		uuid.UUID,
		WorkflowAdminAccess,
	) (WorkflowAdminRecord, error)
	GetDefaultWorkflow(
		context.Context,
		Actor,
		uuid.UUID,
		kernel.AggregateKind,
		WorkflowAdminAccess,
	) (WorkflowAdminRecord, bool, error)
	ListWorkflowVersions(
		context.Context,
		Actor,
		uuid.UUID,
		uuid.UUID,
		WorkflowVersionListInput,
		WorkflowAdminAccess,
	) (WorkflowVersionPage, error)
	GetWorkflowVersion(
		context.Context,
		Actor,
		uuid.UUID,
		uuid.UUID,
		uint64,
		WorkflowAdminAccess,
	) (WorkflowVersionRecord, error)
	LookupWorkflowAdminReplay(
		context.Context,
		WorkflowAdminReplayQuery,
	) (WorkflowAdminMutationResult, bool, error)
	CommitWorkflow(
		context.Context,
		WorkflowAdminWrite,
	) (WorkflowAdminMutationResult, error)
}

type WorkflowAdminWrite struct {
	Actor              Actor
	RequiredCapability WorkflowAdminCapability
	Plan               kernel.WorkflowAdministrationPlan
	Command            WorkflowAdminCommandBinding
	Audit              AuditContext
}
