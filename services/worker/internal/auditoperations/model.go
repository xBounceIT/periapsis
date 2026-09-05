// Package auditoperations materializes redacted audit exports and preserves
// signed retention segments through worker-only database capabilities.
package auditoperations

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
)

const (
	MaximumPageSize        = 1_000
	MaximumArtifactRows    = 1_000_000
	MaximumArtifactBytes   = int64(1_073_741_824)
	MaximumTenantBatch     = 1_000
	MaximumRetentionRows   = 100_000
	DefaultOperationReason = "scheduled audit retention"
)

var (
	ErrInvalidConfiguration = errors.New("invalid audit operations worker configuration")
	ErrInvalidInput         = errors.New("invalid audit operations input")
	ErrInvalidProjection    = errors.New("invalid redacted audit projection")
	ErrAuthorizationRevoked = errors.New("audit export authorization was revoked")
	ErrFenceLost            = errors.New("audit export lease was lost")
	ErrArtifactConflict     = errors.New("audit artifact conflicts with protected storage")
	ErrUnavailable          = errors.New("audit operations dependency unavailable")
)

type Stream string

const (
	TenantStream   Stream = "tenant"
	PlatformStream Stream = "platform"
)

func (stream Stream) Valid() bool { return stream == TenantStream || stream == PlatformStream }

type ExportClaim struct {
	Stream            Stream
	TenantID          uuid.UUID
	JobID             uuid.UUID
	WorkerID          uuid.UUID
	Fence             [32]byte
	NormalizedFilter  json.RawMessage
	ProjectionVersion int32
	Format            string
	ObjectKey         string
	ExpiresAt         time.Time
	LeaseExpiresAt    time.Time
}

type PageRow struct {
	Sequence int64
	Document json.RawMessage
}

type ExportFinalization struct {
	State string
}

type Segment struct {
	Stream       Stream
	TenantID     uuid.UUID
	ID           uuid.UUID
	State        string
	Revision     int64
	Start        int64
	End          int64
	PreviousHash string
	EndHash      string
	EventCount   int64
	ObjectKey    string
	Digest       [32]byte
	Bytes        int64
	SigningKeyID string
	Signature    [64]byte
}

type ArtifactKind string

const (
	ExportArtifactKind  ArtifactKind = "export"
	SegmentArtifactKind ArtifactKind = "segment"
)

type Artifact struct {
	Kind              ArtifactKind
	Stream            Stream
	TenantID          uuid.UUID
	JobID             uuid.UUID
	ArtifactID        uuid.UUID
	SegmentID         uuid.UUID
	StartSequence     int64
	EndSequence       int64
	ProjectionVersion int32
	Format            string
	ObjectKey         string
	Digest            [32]byte
	Rows              int64
	Bytes             int64
	SigningKeyID      string
	Signature         [64]byte
	Path              string
}

type Repository interface {
	ClaimExport(context.Context, Stream, uuid.UUID, [32]byte, time.Duration, uuid.UUID) (ExportClaim, bool, error)
	ReadExportPage(context.Context, ExportClaim, int64, int) ([]PageRow, error)
	FinalizeExport(context.Context, ExportClaim, uuid.UUID, [32]byte, int64, int64, uuid.UUID) (ExportFinalization, error)
	ListTenantRetentionCandidates(context.Context, uuid.UUID, int) ([]uuid.UUID, error)
	GetRetentionWork(context.Context, Stream, uuid.UUID, uuid.UUID) (Segment, bool, error)
	CloseRetentionSegment(context.Context, Stream, uuid.UUID, uuid.UUID, int, string, uuid.UUID) (Segment, bool, error)
	ReadRetentionPage(context.Context, Segment, uuid.UUID, int64, int) ([]PageRow, error)
	PreserveRetentionSegment(context.Context, Segment, uuid.UUID, [32]byte, int64, string, [64]byte, string, uuid.UUID) error
	PruneRetentionSegment(context.Context, Segment, uuid.UUID, Artifact, string, uuid.UUID) error
	PruneTenantReceipts(context.Context, uuid.UUID, uuid.UUID, int, string, uuid.UUID) (int, error)
	PrunePlatformReceipts(context.Context, uuid.UUID, int, string, uuid.UUID) (int, error)
}

type ArtifactStore interface {
	Check(context.Context) error
	Put(context.Context, Artifact) error
	Verify(context.Context, Artifact) error
	DeleteExact(context.Context, Artifact) error
}

type SegmentSigner interface {
	KeyID() string
	Sign(Segment, [32]byte, int64) ([64]byte, error)
	Verify(Segment, [32]byte, int64, [64]byte) bool
}

type Options struct {
	Repository       Repository
	Artifacts        ArtifactStore
	Signer           SegmentSigner
	WorkerID         uuid.UUID
	PageSize         int
	TenantBatch      int
	RetentionRows    int
	ReceiptBatch     int
	LeaseDuration    time.Duration
	OperationTimeout time.Duration
	SpoolDirectory   string
	NewID            func() (uuid.UUID, error)
}

type Summary struct {
	ExportsClaimed    int
	ExportsSucceeded  int
	ExportsDiscarded  int
	SegmentsPreserved int
	SegmentsPruned    int
	ReceiptsPruned    int
}

func (summary Summary) DidWork() bool {
	return summary.ExportsClaimed != 0 || summary.SegmentsPreserved != 0 ||
		summary.SegmentsPruned != 0 || summary.ReceiptsPruned != 0
}
