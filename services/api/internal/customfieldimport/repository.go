package customfieldimport

import (
	"context"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/customfields"
)

// Repository is tenant-explicit. Every implementation must establish the RLS
// tenant context for each call and revalidate the live membership/capability
// inside each mutation transaction. Request commit stores the immutable
// manifest, definition snapshots and pins, rows, command, audit event, and
// outbox event atomically. LookupReplay returns the immutable response snapshot
// stored with that command, not the job's current mutable projection.
// Cancellation atomically stores its command response and applies an
// optimistic-CAS mutation of the job revision.
type Repository interface {
	ResolveAccess(context.Context, Actor, uuid.UUID, kernel.ObjectType, Capability) (Access, error)
	LoadDefinitions(
		context.Context,
		Actor,
		uuid.UUID,
		kernel.ObjectType,
		Access,
	) ([]kernel.Definition, error)
	ReserveImportID(context.Context, uuid.UUID) (kernel.EntityID, error)
	LookupReplay(context.Context, ReplayQuery) (Result, bool, error)
	CommitRequest(context.Context, RequestWrite) (Result, error)
	Get(context.Context, Actor, uuid.UUID, uuid.UUID, Access) (Record, error)
	ListResults(context.Context, Actor, uuid.UUID, uuid.UUID, Access, uint32, int) (ResultPage, error)
	CommitCancellation(context.Context, CancellationWrite) (Result, error)
}
