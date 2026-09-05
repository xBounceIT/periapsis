// Package auditoperations implements the human-facing audit export and
// retention use cases. Storage locators and worker-only lease material never
// cross the HTTP contract.
package auditoperations

import (
	"crypto/sha256"
	"encoding/json"
	"io"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

type Stream string

const (
	StreamTenant   Stream = "tenant"
	StreamPlatform Stream = "platform"
)

type ExportFilter struct {
	OccurredFrom          *time.Time `json:"occurredFrom,omitempty"`
	OccurredBefore        *time.Time `json:"occurredBefore,omitempty"`
	ActorType             *string    `json:"actorType,omitempty"`
	ActorUserID           *uuid.UUID `json:"actorUserId,omitempty"`
	ActorServiceAccountID *uuid.UUID `json:"actorServiceAccountId,omitempty"`
	ActionPrefix          *string    `json:"actionPrefix,omitempty"`
	ResourceType          *string    `json:"resourceType,omitempty"`
	ResourceID            *uuid.UUID `json:"resourceId,omitempty"`
	RequestID             *uuid.UUID `json:"requestId,omitempty"`
	CorrelationID         *uuid.UUID `json:"correlationId,omitempty"`
	Outcome               *string    `json:"outcome,omitempty"`
	Search                *string    `json:"search,omitempty"`
}

type ExportArtifact struct {
	ID        uuid.UUID `json:"id"`
	SHA256    string    `json:"sha256"`
	Rows      int64     `json:"rows"`
	Bytes     int64     `json:"bytes"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type ExportJob struct {
	ID                uuid.UUID       `json:"id"`
	Stream            Stream          `json:"stream"`
	TenantID          *uuid.UUID      `json:"tenantId,omitempty"`
	RequesterUserID   uuid.UUID       `json:"requesterUserId"`
	Filter            ExportFilter    `json:"filter"`
	FilterSHA256      string          `json:"filterSha256"`
	ProjectionVersion int32           `json:"projectionVersion"`
	Format            string          `json:"format"`
	State             string          `json:"state"`
	Revision          int64           `json:"revision"`
	Attempts          int32           `json:"attempts"`
	MaximumAttempts   int32           `json:"maximumAttempts"`
	FailureCode       string          `json:"failureCode"`
	RequestedAt       time.Time       `json:"requestedAt"`
	UpdatedAt         time.Time       `json:"updatedAt"`
	AvailableAt       time.Time       `json:"availableAt"`
	ExpiresAt         time.Time       `json:"expiresAt"`
	TerminalAt        *time.Time      `json:"terminalAt,omitempty"`
	Artifact          *ExportArtifact `json:"artifact,omitempty"`
}

type ExportMutationResult struct {
	Job      ExportJob `json:"job"`
	Replayed bool      `json:"replayed"`
}

type LegalHold struct {
	ID         uuid.UUID  `json:"id"`
	State      string     `json:"state"`
	Revision   int64      `json:"revision"`
	PlacedAt   time.Time  `json:"placedAt"`
	ReleasedAt *time.Time `json:"releasedAt,omitempty"`
}

type RetentionPolicy struct {
	RetentionDays int32     `json:"retentionDays"`
	Revision      int64     `json:"revision"`
	UpdatedAt     time.Time `json:"updatedAt"`
}

type RetentionAnchor struct {
	RetainedThroughSequence int64     `json:"retainedThroughSequence"`
	RetainedThroughHash     string    `json:"retainedThroughHash"`
	Revision                int64     `json:"revision"`
	UpdatedAt               time.Time `json:"updatedAt"`
}

type RetentionState struct {
	Stream          Stream          `json:"stream"`
	TenantID        *uuid.UUID      `json:"tenantId,omitempty"`
	Policy          RetentionPolicy `json:"policy"`
	Anchor          RetentionAnchor `json:"anchor"`
	ActiveLegalHold *LegalHold      `json:"activeLegalHold,omitempty"`
}

type RetentionMutationResult struct {
	State    RetentionState `json:"state"`
	Replayed bool           `json:"replayed"`
}

type LegalHoldMutationResult struct {
	Hold     LegalHold `json:"hold"`
	Replayed bool      `json:"replayed"`
}

type CreateExportInput struct {
	Filter           ExportFilter
	RetentionSeconds int64
	IdempotencyKey   string
	Reason           string
	Event            authentication.EventContext
}

type CancelExportInput struct {
	ExportID         uuid.UUID
	ExpectedRevision int64
	IdempotencyKey   string
	Reason           string
	Event            authentication.EventContext
}

type UpdateRetentionInput struct {
	ExpectedRevision int64
	RetentionDays    int32
	IdempotencyKey   string
	Reason           string
	Event            authentication.EventContext
}

type PlaceLegalHoldInput struct {
	IdempotencyKey string
	Reason         string
	Event          authentication.EventContext
}

type ReleaseLegalHoldInput struct {
	HoldID           uuid.UUID
	ExpectedRevision int64
	IdempotencyKey   string
	Reason           string
	Event            authentication.EventContext
}

type TenantSessionParams struct {
	Actor    authorization.Actor
	TenantID uuid.UUID
	Session  authentication.Session
}

type PlatformSessionParams struct {
	Session authentication.Session
}

type OperationEnvelope struct {
	KeyDigest [sha256.Size]byte
	AuditID   uuid.UUID
	Event     authentication.EventContext
}

type ExportMutationValidator func(ExportMutationResult) (ExportMutationResult, error)
type ExportJobValidator func(ExportJob) (ExportJob, error)
type ArtifactLocationValidator func(ArtifactLocation) (ArtifactLocation, error)
type RetentionStateValidator func(RetentionState) (RetentionState, error)
type RetentionMutationValidator func(RetentionMutationResult) (RetentionMutationResult, error)
type LegalHoldMutationValidator func(LegalHoldMutationResult) (LegalHoldMutationResult, error)

type CreateExportParams struct {
	TenantSession    *TenantSessionParams
	PlatformSession  *PlatformSessionParams
	JobID            uuid.UUID
	FilterJSON       json.RawMessage
	RetentionSeconds int64
	Reason           string
	Envelope         OperationEnvelope
	ValidateResult   ExportMutationValidator
}

type ReadExportParams struct {
	TenantSession    *TenantSessionParams
	PlatformSession  *PlatformSessionParams
	ExportID         uuid.UUID
	AuditID          uuid.UUID
	Event            authentication.EventContext
	ValidateJob      ExportJobValidator
	ValidateLocation ArtifactLocationValidator
}

type CancelExportParams struct {
	TenantSession    *TenantSessionParams
	PlatformSession  *PlatformSessionParams
	ExportID         uuid.UUID
	ExpectedRevision int64
	Reason           string
	Envelope         OperationEnvelope
	ValidateResult   ExportMutationValidator
}

type ReadRetentionParams struct {
	TenantSession   *TenantSessionParams
	PlatformSession *PlatformSessionParams
	AuditID         uuid.UUID
	Event           authentication.EventContext
	ValidateState   RetentionStateValidator
}

type UpdateRetentionParams struct {
	TenantSession    *TenantSessionParams
	PlatformSession  *PlatformSessionParams
	ExpectedRevision int64
	RetentionDays    int32
	Reason           string
	Envelope         OperationEnvelope
	ValidateResult   RetentionMutationValidator
}

type PlaceLegalHoldParams struct {
	TenantSession   *TenantSessionParams
	PlatformSession *PlatformSessionParams
	HoldID          uuid.UUID
	Reason          string
	Envelope        OperationEnvelope
	ValidateResult  LegalHoldMutationValidator
}

type ReleaseLegalHoldParams struct {
	TenantSession    *TenantSessionParams
	PlatformSession  *PlatformSessionParams
	HoldID           uuid.UUID
	ExpectedRevision int64
	Reason           string
	Envelope         OperationEnvelope
	ValidateResult   LegalHoldMutationValidator
}

// ArtifactLocation is returned only by the protected repository and consumed
// immediately by the API-side object adapter. Its String forms redact the key.
type ArtifactLocation struct {
	Stream     Stream
	TenantID   *uuid.UUID
	ExportID   uuid.UUID
	ArtifactID uuid.UUID
	ObjectKey  string
	Digest     [sha256.Size]byte
	Rows       int64
	Bytes      int64
	ExpiresAt  time.Time
	Filename   string
}

func (ArtifactLocation) String() string {
	return "auditoperations.ArtifactLocation{material:[REDACTED]}"
}
func (location ArtifactLocation) GoString() string { return location.String() }

type ArtifactReader struct {
	Body io.ReadCloser
	Size int64
}

type Download struct {
	Reader   io.ReadCloser
	Size     int64
	Filename string
}
