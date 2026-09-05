package dfir

import (
	"context"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/dfir"
)

// AlertMutationContract carries the server-owned transaction effects. A
// repository must not trust the preflight Access value: inside one transaction
// it must install the transaction-local tenant/actor context, locate the
// command receipt and reject a same-key/different-digest collision, revalidate
// the live session, membership, exact Alert scope and capability, and only then
// return an exact replay or continue to create/CAS. A fresh mutation atomically
// commits the resource, redacted activity, audit record, and outbox event.
// Replays return the original stored projection with Replayed=true and create
// no additional effects; revoked actors cannot use a receipt as a read path.
type AlertMutationContract struct {
	BaseWrite
	Access          Access
	Capability      Capability
	ActivityType    string
	AuditAction     string
	AuditReason     string
	OutboxEventType string
}

type AlertEvidenceCreateWrite struct {
	Contract        AlertMutationContract
	EvidenceID      kernel.EntityID
	StorageObjectID kernel.EntityID
	Build           func(kernel.StorageObject) (kernel.AlertEvidence, error)
}

// CommitAlertEvidence checks an exact replay before touching storage. For a
// fresh command it locks the Alert-owned storage/attachment pair and passes
// that snapshot to Build; the returned evidence and the storage classification,
// detected MIME, size, SHA-256, and scan state are committed atomically.

type AlertEvidenceMutationWrite struct {
	Contract        AlertMutationContract
	EvidenceID      kernel.EntityID
	ExpectedVersion uint64
	Apply           func(kernel.AlertEvidence) (kernel.AlertEvidence, error)
}

type AlertTaskCreateWrite struct {
	Contract AlertMutationContract
	Task     kernel.AlertTask
}

// Task commits must validate team, assignee, comments, and optional SLA
// references against the same tenant and live Alert scope inside the mutation
// transaction. An assignee is valid only within the selected operator team.

type AlertTaskMutationWrite struct {
	Contract        AlertMutationContract
	TaskID          kernel.EntityID
	ExpectedVersion uint64
	Apply           func(kernel.AlertTask) (kernel.AlertTask, error)
}

type AlertRelationshipCreateWrite struct {
	Contract     AlertMutationContract
	Relationship kernel.AlertRelationship
}

// Relationship commits resolve every local endpoint inside the tenant without
// traversing it into the Alert projection. A duplicate active identity is a
// conflict: the repository never substitutes, reverses, or merges another row.

type AlertRelationshipMutationWrite struct {
	Contract        AlertMutationContract
	RelationshipID  kernel.EntityID
	ExpectedVersion uint64
	Apply           func(kernel.AlertRelationship) (kernel.AlertRelationship, error)
}

// AlertInvestigationRepository is intentionally separate from Repository so
// migration 0226 can land atomically without widening the released adapter
// interface first. Mutation callbacks execute only after exact-replay lookup
// and live authority revalidation, while the repository transaction owns the
// subsequent compare-and-swap and all mandatory effects. A fresh write invokes
// its callback exactly once; an exact replay never invokes it. Context
// cancellation aborts and rolls back the complete transaction.
type AlertInvestigationRepository interface {
	ResolveAlertAccess(context.Context, Actor, uuid.UUID, Capability, AlertResourceScope) (Access, error)
	// LoadAlertInvestigationWorkspace must install the transaction-local tenant
	// and actor context and revalidate the live session, membership, exact Alert
	// scope, and every capability in WorkspaceAccess before selecting any row.
	// The preflight decisions are not authority and partial-family fallbacks are
	// forbidden.
	LoadAlertInvestigationWorkspace(
		context.Context,
		Actor,
		uuid.UUID,
		kernel.EntityID,
		WorkspaceAccess,
	) (AlertInvestigationWorkspace, error)
	CommitAlertEvidence(context.Context, AlertEvidenceCreateWrite) (MutationResult[kernel.AlertEvidence], error)
	MutateAlertEvidence(context.Context, AlertEvidenceMutationWrite) (MutationResult[kernel.AlertEvidence], error)
	CommitAlertTask(context.Context, AlertTaskCreateWrite) (MutationResult[kernel.AlertTask], error)
	MutateAlertTask(context.Context, AlertTaskMutationWrite) (MutationResult[kernel.AlertTask], error)
	CommitAlertRelationship(
		context.Context,
		AlertRelationshipCreateWrite,
	) (MutationResult[kernel.AlertRelationship], error)
	MutateAlertRelationship(
		context.Context,
		AlertRelationshipMutationWrite,
	) (MutationResult[kernel.AlertRelationship], error)
}
