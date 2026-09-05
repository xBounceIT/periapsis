package ticketing

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
)

// TicketBulkRepository is the tenant-explicit persistence ABI. Implementations
// use a least-privileged transaction with FORCE RLS on every call. The request
// commit repeats live membership, route intent, mutation permission, team and
// workflow constraints, saved-view/catalog pins, and ticket visibility. Query
// targets are materialized in that same transaction; a worker never reruns the
// mutable query. Job, target rows, idempotency, audit, and outbox commit as one
// unit. Missing, foreign, and hidden resources are non-oracular after route
// access is established.
type TicketBulkRepository interface {
	ResolveTicketBulkAccess(
		context.Context,
		Actor,
		uuid.UUID,
		kernel.AggregateKind,
		TicketBulkCapability,
		kernel.Action,
	) (TicketBulkAccess, error)
	ResolveTicketBulkQuery(
		context.Context,
		Actor,
		uuid.UUID,
		kernel.AggregateKind,
		TicketBulkQuerySourceInput,
		TicketBulkAccess,
	) (TicketBulkQuerySnapshot, error)
	ReserveTicketBulkID(context.Context, uuid.UUID) (kernel.EntityID, error)
	LookupTicketBulkReplay(context.Context, TicketBulkReplayQuery) (TicketBulkResult, bool, error)
	CommitTicketBulkRequest(context.Context, TicketBulkRequestWrite) (TicketBulkResult, error)
	GetTicketBulk(
		context.Context,
		Actor,
		uuid.UUID,
		uuid.UUID,
		TicketBulkAccess,
	) (TicketBulkRecord, error)
	CommitTicketBulkCancellation(context.Context, TicketBulkCancellationWrite) (TicketBulkResult, error)
	ListTicketBulkResults(context.Context, TicketBulkResultQuery) (TicketBulkResultPage, error)
}

type TicketBulkReplayQuery struct {
	TenantID          uuid.UUID
	ActorID           uuid.UUID
	OwnerMembershipID uuid.UUID
	Kind              kernel.AggregateKind
	Action            TicketBulkCommandAction
	KeyHash           [sha256.Size]byte
	Fingerprint       [sha256.Size]byte
}

func (query TicketBulkReplayQuery) String() string {
	return fmt.Sprintf(
		"TicketBulkReplayQuery{kind:%s,action:%s,identity:[REDACTED],digests:[REDACTED]}",
		query.Kind, query.Action,
	)
}
func (query TicketBulkReplayQuery) GoString() string { return query.String() }

type TicketBulkRequestWrite struct {
	Actor              Actor
	Access             TicketBulkAccess
	RequiredCapability TicketBulkCapability
	JobID              kernel.EntityID
	ExplicitSelection  *kernel.TicketBulkSelection
	Query              *TicketBulkQuerySnapshot
	Mutation           kernel.TicketBulkMutation
	RequestedAt        time.Time
	ExpiresAt          time.Time
	Command            TicketBulkCommandBinding
	Audit              AuditContext
}

func (write TicketBulkRequestWrite) String() string {
	return fmt.Sprintf(
		"TicketBulkRequestWrite{kind:%s,action:%s,query:%t,metadata:[REDACTED]}",
		write.Access.kind, write.Mutation.Action(), write.Query != nil,
	)
}
func (write TicketBulkRequestWrite) GoString() string { return write.String() }

type TicketBulkCancellationWrite struct {
	Actor              Actor
	Access             TicketBulkAccess
	RequiredCapability TicketBulkCapability
	Plan               kernel.TicketBulkPlan
	Command            TicketBulkCommandBinding
	Audit              AuditContext
}

func (write TicketBulkCancellationWrite) String() string {
	return fmt.Sprintf("TicketBulkCancellationWrite{plan:%s,metadata:[REDACTED]}", write.Plan)
}
func (write TicketBulkCancellationWrite) GoString() string { return write.String() }

type TicketBulkResultQuery struct {
	Actor    Actor
	Access   TicketBulkAccess
	TenantID uuid.UUID
	JobID    uuid.UUID
	Limit    int
	After    string
}

func (query TicketBulkResultQuery) String() string {
	return fmt.Sprintf(
		"TicketBulkResultQuery{kind:%s,limit:%d,identity:[REDACTED],cursor:[REDACTED]}",
		query.Access.kind, query.Limit,
	)
}
func (query TicketBulkResultQuery) GoString() string { return query.String() }
