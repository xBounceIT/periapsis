package ticketing

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
)

// AsyncExportRepository is the future SQL/object-storage ABI boundary.
//
// Every method is tenant explicit. Implementations begin a least-privileged
// transaction, install transaction-local tenant/actor-or-service context, and
// rely on FORCE RLS in addition to the live checks described below.
//
// ResolveAsyncExportQuery resolves an inline query or an active saved view from
// the same tenant, kind, and exact owner. It verifies every current dynamic
// definition/version/digest and filter/list visibility. Customer queries must
// be linked-contact filtered before limiting and return only the fixed customer
// shape. A saved view is never accepted for a customer audience.
//
// CommitAsyncExportRequest and CommitAsyncExportOwnerTransition repeat human
// membership, route-intent capability/scope, linked-contact (customer), public
// comment and private comment (operator when requested), saved-view ownership/status/revision, and
// every query pin in the same transaction as CAS, audit, and idempotency.
// LookupAsyncExportReplay also repeats that live principal+resource/query
// authorization before returning an immutable operation-shaped snapshot.
// Exact replay is returned only for the same tenant+actor+membership+audience+
// kind+key hash+fingerprint; divergent reuse is ErrConflict. Once route access
// is established, missing, foreign, or relation-revoked resources share one
// non-oracular result.
//
// Claim candidates are selected in bounded tenant/kind/audience queues with
// FOR UPDATE SKIP LOCKED. CommitAsyncExportWorkerTransition repeats the exact
// service purpose grant and the original requester's current resource/query
// authorization, then CASes revision+state+lease worker+fence. Get-for-worker
// and every page read repeat the same original-request authorization. The
// separate GetRevokedAsyncExportForWorker path returns the job envelope only
// (never the canonical query snapshot) after the adapter proves that
// authorization is now denied. Its only valid commit is an exact-revision
// terminal CommitAsyncExportRevocation plan and it never reads source rows.
// The plan action is authorization_revoked before retention, or expire when
// the immutable deadline has already elapsed; no other action is accepted. A
// stale fence can never renew, read, acknowledge cancellation, fail, or publish
// an artifact.
//
// ReadAsyncExportPage binds cursors to job ID, exact job revision, query/catalog
// digests, projection version, current lease fence, and page size. It applies
// the saved query before pagination, caps statement time/result size, and never
// returns private rows for a customer/public-only job. Artifact metadata is
// tenant-owned; possession of an object key or artifact ID is not download authority.
type AsyncExportRepository interface {
	ResolveAsyncExportAccess(
		context.Context,
		Actor,
		uuid.UUID,
		kernel.AggregateKind,
		kernel.TicketExportAudience,
		AsyncExportCapability,
	) (AsyncExportAccess, error)
	ResolveAsyncExportWorkerAccess(
		context.Context,
		AsyncExportWorker,
		uuid.UUID,
		kernel.AggregateKind,
		kernel.TicketExportAudience,
		AsyncExportCapability,
	) (AsyncExportWorkerAccess, error)
	ResolveAsyncExportQuery(
		context.Context,
		Actor,
		uuid.UUID,
		kernel.AggregateKind,
		kernel.TicketExportAudience,
		AsyncExportSourceInput,
		AsyncExportAccess,
	) (AsyncExportQuerySnapshot, error)
	ReserveAsyncExportID(context.Context, uuid.UUID) (kernel.EntityID, error)
	LookupAsyncExportReplay(context.Context, AsyncExportReplayQuery) (AsyncExportResult, bool, error)
	CommitAsyncExportRequest(context.Context, AsyncExportRequestWrite) (AsyncExportResult, error)
	GetAsyncExport(
		context.Context,
		Actor,
		uuid.UUID,
		uuid.UUID,
		AsyncExportAccess,
	) (AsyncExportRecord, error)
	CommitAsyncExportOwnerTransition(
		context.Context,
		AsyncExportOwnerWrite,
	) (AsyncExportResult, error)
	SelectAsyncExportClaimCandidate(
		context.Context,
		AsyncExportWorker,
		AsyncExportWorkerAccess,
		time.Time,
	) (AsyncExportRecord, bool, error)
	GetAsyncExportForWorker(
		context.Context,
		AsyncExportWorker,
		uuid.UUID,
		uuid.UUID,
		AsyncExportWorkerAccess,
	) (AsyncExportRecord, error)
	GetRevokedAsyncExportForWorker(
		context.Context,
		AsyncExportWorker,
		uuid.UUID,
		uuid.UUID,
		AsyncExportWorkerAccess,
	) (kernel.TicketExportJob, error)
	CommitAsyncExportWorkerTransition(
		context.Context,
		AsyncExportWorkerWrite,
	) (AsyncExportResult, error)
	CommitAsyncExportRevocation(
		context.Context,
		AsyncExportRevocationWrite,
	) (kernel.TicketExportJob, error)
	ReadAsyncExportPage(context.Context, AsyncExportPageQuery) (AsyncExportPage, error)
}

type AsyncExportReplayQuery struct {
	TenantID          uuid.UUID
	ActorID           uuid.UUID
	OwnerMembershipID uuid.UUID
	Kind              kernel.AggregateKind
	Audience          kernel.TicketExportAudience
	Action            AsyncExportCommandAction
	KeyHash           [sha256.Size]byte
	Fingerprint       [sha256.Size]byte
}

func (query AsyncExportReplayQuery) String() string {
	return fmt.Sprintf(
		"AsyncExportReplayQuery{kind:%s,audience:%s,action:%s,identity:[REDACTED],digests:[REDACTED]}",
		query.Kind, query.Audience, query.Action,
	)
}
func (query AsyncExportReplayQuery) GoString() string { return query.String() }

type AsyncExportRequestWrite struct {
	Actor              Actor
	Access             AsyncExportAccess
	RequiredCapability AsyncExportCapability
	Query              AsyncExportQuerySnapshot
	Plan               kernel.TicketExportPlan
	Command            AsyncExportCommandBinding
	Audit              AuditContext
}

func (write AsyncExportRequestWrite) String() string {
	return fmt.Sprintf("AsyncExportRequestWrite{action:%s,metadata:[REDACTED]}", write.Plan.Action())
}
func (write AsyncExportRequestWrite) GoString() string { return write.String() }

type AsyncExportOwnerWrite struct {
	Actor              Actor
	Access             AsyncExportAccess
	RequiredCapability AsyncExportCapability
	Query              AsyncExportQuerySnapshot
	Plan               kernel.TicketExportPlan
	Command            AsyncExportCommandBinding
	Audit              AuditContext
}

func (write AsyncExportOwnerWrite) String() string {
	return fmt.Sprintf("AsyncExportOwnerWrite{action:%s,metadata:[REDACTED]}", write.Plan.Action())
}
func (write AsyncExportOwnerWrite) GoString() string { return write.String() }

type AsyncExportWorkerWrite struct {
	Worker             AsyncExportWorker
	Access             AsyncExportWorkerAccess
	RequiredCapability AsyncExportCapability
	Query              AsyncExportQuerySnapshot
	Plan               kernel.TicketExportPlan
}

func (write AsyncExportWorkerWrite) String() string {
	return fmt.Sprintf("AsyncExportWorkerWrite{action:%s,metadata:[REDACTED]}", write.Plan.Action())
}
func (write AsyncExportWorkerWrite) GoString() string { return write.String() }

type AsyncExportRevocationWrite struct {
	Worker             AsyncExportWorker
	Access             AsyncExportWorkerAccess
	RequiredCapability AsyncExportCapability
	Plan               kernel.TicketExportPlan
}

func (write AsyncExportRevocationWrite) String() string {
	return fmt.Sprintf("AsyncExportRevocationWrite{action:%s,metadata:[REDACTED]}", write.Plan.Action())
}
func (write AsyncExportRevocationWrite) GoString() string { return write.String() }

type AsyncExportPageQuery struct {
	Worker            AsyncExportWorker
	Access            AsyncExportWorkerAccess
	TenantID          uuid.UUID
	JobID             uuid.UUID
	ExpectedRevision  uint64
	Fence             [sha256.Size]byte
	QueryDigest       [sha256.Size]byte
	CatalogDigest     [sha256.Size]byte
	ProjectionVersion uint64
	After             string
	Limit             int
}

func (query AsyncExportPageQuery) String() string {
	return fmt.Sprintf(
		"AsyncExportPageQuery{expected_revision:%d,limit:%d,identity:[REDACTED],fence:[REDACTED],digests:[REDACTED],cursor:[REDACTED]}",
		query.ExpectedRevision, query.Limit,
	)
}
func (query AsyncExportPageQuery) GoString() string { return query.String() }
