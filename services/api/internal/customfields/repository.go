package customfields

import (
	"context"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/customfields"
)

// Repository is both the live-authorization and transactional persistence
// boundary. Implementations must apply tenant/RLS context before every query.
// Definition and value writes must commit the resource row, append-only audit,
// and outbox entry in one transaction.
type Repository interface {
	ResolveAccess(context.Context, Actor, uuid.UUID, Capability) (Access, error)
	ResolveDefinitionInventoryAccess(context.Context, Actor, uuid.UUID) (Access, error)
	ListDefinitions(context.Context, Actor, uuid.UUID, DefinitionListInput, Access) (DefinitionPage, error)
	GetDefinition(context.Context, Actor, uuid.UUID, kernel.ObjectType, kernel.EntityID, Access) (kernel.Definition, error)
	InspectDefinitionUpdate(context.Context, Actor, uuid.UUID, kernel.Definition, kernel.DefinitionInput, uint64) (kernel.DefinitionUpdateState, error)
	CreateDefinition(context.Context, DefinitionWrite) (DefinitionResult, error)
	ReplaceDefinition(context.Context, DefinitionWrite) (DefinitionResult, error)
	ArchiveDefinition(context.Context, DefinitionArchive) (DefinitionResult, error)
	ResolveObjectWriteAccess(context.Context, Actor, uuid.UUID, kernel.ObjectType, uuid.UUID) (Access, error)
	LoadObjectFields(context.Context, Actor, uuid.UUID, kernel.ObjectType, uuid.UUID, Access) ([]kernel.Definition, []kernel.FieldValue, uint64, error)
	CommitObjectFields(context.Context, ObjectFieldWrite) (ObjectWriteResult, error)
}

type DefinitionWrite struct {
	Actor           Actor
	Definition      kernel.Definition
	ExpectedVersion uint64
	Command         CommandBinding
	Audit           AuditContext
}

type DefinitionArchive struct {
	Actor           Actor
	Current         kernel.Definition
	Archived        kernel.Definition
	ExpectedVersion uint64
	Reason          string
	Command         CommandBinding
	Audit           AuditContext
}

type ObjectFieldWrite struct {
	Actor           Actor
	TenantID        uuid.UUID
	ObjectType      kernel.ObjectType
	ObjectID        uuid.UUID
	ExpectedVersion uint64
	Values          []kernel.FieldValue
	Command         CommandBinding
	Audit           AuditContext
}
