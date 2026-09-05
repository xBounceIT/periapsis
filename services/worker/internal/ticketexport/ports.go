package ticketexport

import (
	"context"
	"fmt"
	"io"
	"time"

	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
)

// Repository implementations own every application-authorization and RLS
// recheck. Claim is tenant/kind/audience scoped and fenced. Page reads bind the
// exact revision, fence, query/catalog digests, projection version, cursor, and
// page size. Every terminal/control transition is idempotent and CASes the
// exact worker fence. An implementation must never return raw query documents
// or source rows through a control-only revocation path. Every returned value
// transfers ownership to the caller and must not be retained or mutated after
// the call returns.
type Repository interface {
	Claim(context.Context, ClaimRequest) (Claim, bool, error)
	ReadPage(context.Context, PageRequest) (PageResult, error)
	RecordManifest(context.Context, ManifestRequest) (ManifestResult, error)
	CommitSuccess(context.Context, SuccessRequest) (CommitResult, error)
	ReportFailure(context.Context, FailureRequest) (FailureResult, error)
	AcknowledgeCancellation(context.Context, CancellationRequest) (TransitionResult, error)
	RejectRevoked(context.Context, RevocationRequest) (TransitionResult, error)
}

type ClaimRequest struct {
	Identity      Identity
	Queue         Queue
	ArtifactID    kernel.EntityID
	Now           time.Time
	LeaseDuration time.Duration
}

func (request ClaimRequest) String() string {
	return fmt.Sprintf(
		"ticketexport.ClaimRequest{queue:%s,lease_duration:%s,identity:[REDACTED],time:[REDACTED]}",
		request.Queue, request.LeaseDuration,
	)
}

func (request ClaimRequest) GoString() string { return request.String() }

// Claim contains only the validated immutable job envelope and exact visible
// CSV header. The canonical query remains repository-owned.
type Claim struct {
	Job        kernel.TicketExportJob
	ArtifactID kernel.EntityID
	Header     []string
	ObservedAt time.Time
}

func (claim Claim) String() string {
	return fmt.Sprintf(
		"ticketexport.Claim{job:%s,columns:%d,query:[REDACTED]}",
		claim.Job, len(claim.Header),
	)
}

func (claim Claim) GoString() string { return claim.String() }

// LeaseBinding is copied into every adapter call. It intentionally excludes
// object locations, cursors, row values, and human query text from diagnostics.
type LeaseBinding struct {
	TenantID          kernel.EntityID
	JobID             kernel.EntityID
	Kind              kernel.AggregateKind
	Audience          kernel.TicketExportAudience
	WorkerID          kernel.EntityID
	Revision          uint64
	Attempt           uint8
	Fence             [32]byte
	QueryDigest       [32]byte
	CatalogDigest     [32]byte
	ProjectionVersion uint64
	LeaseClaimedAt    time.Time
	LeaseExpiresAt    time.Time
	JobExpiresAt      time.Time
}

func (binding LeaseBinding) String() string {
	return fmt.Sprintf(
		"ticketexport.LeaseBinding{kind:%s,audience:%s,revision:%d,attempt:%d,identity:[REDACTED],fence:[REDACTED],digests:[REDACTED],times:[REDACTED]}",
		binding.Kind, binding.Audience, binding.Revision, binding.Attempt,
	)
}

func (binding LeaseBinding) GoString() string { return binding.String() }

type PageRequest struct {
	Identity Identity
	Binding  LeaseBinding
	After    string
	Limit    int
}

func (request PageRequest) String() string {
	return fmt.Sprintf(
		"ticketexport.PageRequest{binding:%s,limit:%d,identity:[REDACTED],cursor:[REDACTED]}",
		request.Binding, request.Limit,
	)
}

func (request PageRequest) GoString() string { return request.String() }

type RowKind uint8

const (
	RowTicket RowKind = iota + 1
	RowPublicComment
	RowPrivateComment
)

func (kind RowKind) String() string {
	switch kind {
	case RowTicket:
		return "ticket"
	case RowPublicComment:
		return "public_comment"
	case RowPrivateComment:
		return "private_comment"
	default:
		return "unknown"
	}
}

type Row struct {
	Kind RowKind
	// SnapshotKey is a repository-derived opaque identity for the canonical
	// source row. It must be non-zero and unique across the pinned snapshot.
	SnapshotKey [32]byte
	Cells       []string
}

func (row Row) String() string {
	return fmt.Sprintf(
		"ticketexport.Row{kind:%s,cells:%d,identity:[REDACTED],values:[REDACTED]}",
		row.Kind, len(row.Cells),
	)
}

func (row Row) GoString() string { return row.String() }

type Page struct {
	Rows       []Row
	NextCursor string
}

func (page Page) String() string {
	return fmt.Sprintf("ticketexport.Page{rows:%d,cursor:[REDACTED]}", len(page.Rows))
}

func (page Page) GoString() string { return page.String() }

type PageControl uint8

const (
	PageReady PageControl = iota + 1
	PageCancellationRequested
	PageAuthorizationRevoked
	PageFenceLost
	PageSnapshotStale
)

type PageResult struct {
	Control         PageControl
	ControlRevision uint64
	Page            Page
}

func (result PageResult) String() string {
	return fmt.Sprintf(
		"ticketexport.PageResult{control:%d,control_revision:%d,page:%s}",
		result.Control, result.ControlRevision, result.Page,
	)
}

func (result PageResult) GoString() string { return result.String() }

type SuccessRequest struct {
	Identity    Identity
	Binding     LeaseBinding
	ArtifactID  kernel.EntityID
	Digest      [32]byte
	Rows        uint32
	Bytes       uint64
	ExpiresAt   time.Time
	CompletedAt time.Time
}

// ManifestRequest durably binds the exact artifact identity and content
// manifest to the current fenced attempt before object storage is mutated.
// This ledger entry is what makes post-crash orphan reconciliation safe.
type ManifestRequest struct {
	Identity   Identity
	Binding    LeaseBinding
	ArtifactID kernel.EntityID
	Digest     [32]byte
	Rows       uint32
	Bytes      uint64
	RecordedAt time.Time
}

func (request ManifestRequest) String() string {
	return fmt.Sprintf(
		"ticketexport.ManifestRequest{binding:%s,rows:%d,bytes:%d,identity:[REDACTED],artifact:[REDACTED],digest:[REDACTED],time:[REDACTED]}",
		request.Binding, request.Rows, request.Bytes,
	)
}

func (request ManifestRequest) GoString() string { return request.String() }

type ManifestDisposition uint8

const (
	ManifestRecorded ManifestDisposition = iota + 1
	ManifestCancellationRequested
	ManifestAuthorizationRevoked
	ManifestFenceLost
	ManifestSnapshotStale
)

type ManifestResult struct {
	// ManifestRecorded echoes the unchanged running revision and exact durable
	// manifest. Every control disposition returns a zero Manifest.
	Disposition     ManifestDisposition
	CurrentRevision uint64
	Manifest        StreamManifest
}

func (result ManifestResult) String() string {
	return fmt.Sprintf(
		"ticketexport.ManifestResult{disposition:%d,current_revision:%d,manifest:%s}",
		result.Disposition, result.CurrentRevision, result.Manifest,
	)
}

func (result ManifestResult) GoString() string { return result.String() }

func (request SuccessRequest) String() string {
	return fmt.Sprintf(
		"ticketexport.SuccessRequest{binding:%s,rows:%d,bytes:%d,identity:[REDACTED],artifact:[REDACTED],digest:[REDACTED],times:[REDACTED]}",
		request.Binding, request.Rows, request.Bytes,
	)
}

func (request SuccessRequest) GoString() string { return request.String() }

type CommitDisposition uint8

const (
	CommitApplied CommitDisposition = iota + 1
	CommitReplayed
	CommitCancellationRequested
	CommitAuthorizationRevoked
	CommitFenceLost
	CommitSnapshotStale
)

type CommitResult struct {
	// Applied/replayed success echoes the successor revision and exact manifest.
	// Every non-success disposition returns a zero Manifest.
	Disposition     CommitDisposition
	CurrentRevision uint64
	Manifest        StreamManifest
}

func (result CommitResult) String() string {
	return fmt.Sprintf(
		"ticketexport.CommitResult{disposition:%d,current_revision:%d,manifest:%s}",
		result.Disposition, result.CurrentRevision, result.Manifest,
	)
}

func (result CommitResult) GoString() string { return result.String() }

type FailureRequest struct {
	Identity Identity
	Binding  LeaseBinding
	Code     kernel.TicketExportFailureCode
	FailedAt time.Time
	RetryAt  time.Time
}

func (request FailureRequest) String() string {
	return fmt.Sprintf(
		"ticketexport.FailureRequest{binding:%s,code:%s,retry:%t,identity:[REDACTED],times:[REDACTED]}",
		request.Binding, request.Code, !request.RetryAt.IsZero(),
	)
}

func (request FailureRequest) GoString() string { return request.String() }

type FailureDisposition uint8

const (
	FailureRetryScheduled FailureDisposition = iota + 1
	FailureTerminal
	FailureReplayRetry
	FailureReplayTerminal
	FailureCancellationRequested
	FailureAuthorizationRevoked
	FailureFenceLost
)

type FailureResult struct {
	// A failure transition echoes its successor revision, code, and optional
	// retry instant. Control/fence dispositions return zero code/retry values.
	Disposition     FailureDisposition
	CurrentRevision uint64
	Code            kernel.TicketExportFailureCode
	RetryAt         time.Time
}

func (result FailureResult) String() string {
	return fmt.Sprintf(
		"ticketexport.FailureResult{disposition:%d,current_revision:%d,code:%s,retry:%t}",
		result.Disposition, result.CurrentRevision, result.Code, !result.RetryAt.IsZero(),
	)
}

func (result FailureResult) GoString() string { return result.String() }

type CancellationRequest struct {
	Identity         Identity
	Binding          LeaseBinding
	ExpectedRevision uint64
	AcknowledgedAt   time.Time
}

func (request CancellationRequest) String() string {
	return fmt.Sprintf(
		"ticketexport.CancellationRequest{binding:%s,expected_revision:%d,identity:[REDACTED],time:[REDACTED]}",
		request.Binding, request.ExpectedRevision,
	)
}

func (request CancellationRequest) GoString() string { return request.String() }

type RevocationRequest struct {
	Identity         Identity
	Binding          LeaseBinding
	ExpectedRevision uint64
	RejectedAt       time.Time
}

func (request RevocationRequest) String() string {
	return fmt.Sprintf(
		"ticketexport.RevocationRequest{binding:%s,expected_revision:%d,identity:[REDACTED],time:[REDACTED]}",
		request.Binding, request.ExpectedRevision,
	)
}

func (request RevocationRequest) GoString() string { return request.String() }

type TransitionDisposition uint8

const (
	TransitionApplied TransitionDisposition = iota + 1
	TransitionReplayed
	TransitionFenceLost
)

type TransitionResult struct {
	// Applied/replayed transitions echo ExpectedRevision+1. Fence loss returns
	// a zero CurrentRevision to avoid treating unrelated state as authoritative.
	Disposition     TransitionDisposition
	CurrentRevision uint64
}

func (result TransitionResult) String() string {
	return fmt.Sprintf(
		"ticketexport.TransitionResult{disposition:%d,current_revision:%d}",
		result.Disposition, result.CurrentRevision,
	)
}

func (result TransitionResult) GoString() string { return result.String() }

// ArtifactStore opens a tenant-bound temporary object. OpenTemporary's first
// context bounds only the open operation; its second context is the lifetime
// for subsequent Write calls, so canceling the open context after return must
// not close the session. Adapters must make a blocked stream write return when
// the lifetime context is cancelled. OpenTemporary and Write may mutate only a
// local spool: the first object-store PUT is Seal, after the repository has
// durably recorded the manifest. The returned session encapsulates every
// bucket/key detail. Promote must be idempotent for the supplied artifact ID.
// Abort and Purge must be idempotent cleanup operations.
type ArtifactStore interface {
	OpenTemporary(context.Context, context.Context, TemporaryRequest) (TemporaryArtifact, error)
}

type TemporaryRequest struct {
	Identity     Identity
	Binding      LeaseBinding
	ArtifactID   kernel.EntityID
	MaximumBytes uint64
}

func (request TemporaryRequest) String() string {
	return fmt.Sprintf(
		"ticketexport.TemporaryRequest{binding:%s,maximum_bytes:%d,identity:[REDACTED],artifact:[REDACTED]}",
		request.Binding, request.MaximumBytes,
	)
}

func (request TemporaryRequest) GoString() string { return request.String() }

type StreamManifest struct {
	ArtifactID kernel.EntityID
	Digest     [32]byte
	Rows       uint32
	Bytes      uint64
}

func (manifest StreamManifest) String() string {
	return fmt.Sprintf(
		"ticketexport.StreamManifest{rows:%d,bytes:%d,artifact:[REDACTED],digest:[REDACTED]}",
		manifest.Rows, manifest.Bytes,
	)
}

func (manifest StreamManifest) GoString() string { return manifest.String() }

type PromotionDisposition uint8

const (
	PromotionApplied PromotionDisposition = iota + 1
	PromotionReplayed
	PromotionRejected
)

type TemporaryArtifact interface {
	io.Writer
	Seal(context.Context, StreamManifest) error
	Promote(context.Context, kernel.EntityID) (PromotionDisposition, error)
	Abort(context.Context) error
	Purge(context.Context, kernel.EntityID) error
}
