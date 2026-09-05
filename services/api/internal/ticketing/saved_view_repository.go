package ticketing

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
)

// SavedViewRepository owns the private-view tenant/RLS boundary.
//
// ResolveSavedViewSpec must resolve every custom-field and SLA reference from
// the same tenant/kind, require its current filter/list/sort capability, and
// return exact version+digest pins. List/Get expose only the current human
// membership's own rows. CommitSavedView re-resolves the live operator ticket
// read permission and membership, CASes the exact revision, and appends
// redacted audit plus immutable idempotency evidence in one transaction.
// Create/replace/restore also recheck every dynamic pin. Archive deliberately
// preserves and retires even a stale spec so an owner is never trapped with an
// invalid catalog reference. Exact create replays may return the winner's
// generated ID; all other actions remain resource-identity bound. Get must
// collapse missing, foreign-tenant, foreign-kind, and non-owned identifiers to
// ErrNotFound. LookupSavedViewReplay must return ErrConflict for a reused key
// with a different fingerprint and must never return another owner or actor's
// snapshot. The service validates and defensively copies every returned row,
// so repository implementations may not use object identity as authority.
type SavedViewRepository interface {
	ResolveSavedViewAccess(
		context.Context,
		Actor,
		uuid.UUID,
		kernel.AggregateKind,
		SavedViewCapability,
	) (SavedViewAccess, error)
	ResolveSavedViewSpec(
		context.Context,
		Actor,
		uuid.UUID,
		kernel.AggregateKind,
		SavedViewSpecInput,
		SavedViewAccess,
	) (kernel.SavedViewSpec, error)
	ReserveSavedViewID(context.Context, uuid.UUID) (kernel.EntityID, error)
	ListSavedViews(
		context.Context,
		Actor,
		uuid.UUID,
		kernel.AggregateKind,
		SavedViewListInput,
		SavedViewAccess,
	) (SavedViewPage, error)
	GetSavedView(
		context.Context,
		Actor,
		uuid.UUID,
		uuid.UUID,
		SavedViewAccess,
	) (SavedViewRecord, error)
	LookupSavedViewReplay(
		context.Context,
		SavedViewReplayQuery,
	) (SavedViewMutationResult, bool, error)
	CommitSavedView(context.Context, SavedViewWrite) (SavedViewMutationResult, error)
}

type SavedViewWrite struct {
	Actor              Actor
	RequiredCapability SavedViewCapability
	OwnerMembershipID  uuid.UUID
	Plan               kernel.SavedViewPlan
	Command            SavedViewCommandBinding
	Audit              AuditContext
}

func (write SavedViewWrite) String() string {
	return fmt.Sprintf(
		"SavedViewWrite{action:%s,capability:[REDACTED],identity:[REDACTED],command:[REDACTED],audit:[REDACTED]}",
		write.Plan.Action(),
	)
}

func (write SavedViewWrite) GoString() string { return write.String() }
