package ticketing

import (
	"context"
	"fmt"
	"net/url"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
)

const AsyncExportDownloadMaximumLifetime = 5 * time.Minute

// AsyncExportArtifactLocation is the complete immutable binding that the
// storage adapter must verify with HEAD before minting a browser capability.
// It deliberately contains no object key: that key is derived from the shared
// ticketing storage contract.
type AsyncExportArtifactLocation struct {
	TenantID   kernel.EntityID
	JobID      kernel.EntityID
	ArtifactID kernel.EntityID
	Revision   uint64
	Attempt    uint8
	Projection uint64
	Digest     [32]byte
	Rows       uint32
	Bytes      uint64
}

func (location AsyncExportArtifactLocation) String() string {
	return fmt.Sprintf(
		"AsyncExportArtifactLocation{revision:%d,attempt:%d,projection:%d,rows:%d,bytes:%d,identity:[REDACTED],digest:[REDACTED]}",
		location.Revision,
		location.Attempt,
		location.Projection,
		location.Rows,
		location.Bytes,
	)
}
func (location AsyncExportArtifactLocation) GoString() string { return location.String() }

type AsyncExportDownloadGrant struct {
	TargetURL string
	ExpiresAt time.Time
}

func (grant AsyncExportDownloadGrant) String() string {
	return "AsyncExportDownloadGrant{capability:[REDACTED]}"
}
func (grant AsyncExportDownloadGrant) GoString() string { return grant.String() }

type AsyncExportPreparedDownload struct {
	// Record carries the exact authorized owner projection so transports can
	// independently fail closed on cross-tenant, cross-kind, or cross-owner
	// service responses before releasing the storage capability.
	Record   AsyncExportRecord
	Artifact kernel.TicketExportArtifact
	Grant    AsyncExportDownloadGrant
}

func (prepared AsyncExportPreparedDownload) String() string {
	return fmt.Sprintf("AsyncExportPreparedDownload{artifact:%s,grant:[REDACTED]}", prepared.Artifact)
}
func (prepared AsyncExportPreparedDownload) GoString() string { return prepared.String() }

type AsyncExportDownloadStorage interface {
	PrepareAsyncExportDownload(
		context.Context,
		AsyncExportArtifactLocation,
		time.Time,
	) (AsyncExportDownloadGrant, error)
}

// PrepareDownload repeats the exact live read/ownership authorization for each
// grant, accepts only an unexpired successful job, and binds the storage probe
// to the immutable manifest returned by the database.
func (service *AsyncExportService) PrepareDownload(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	audience kernel.TicketExportAudience,
	jobID uuid.UUID,
) (AsyncExportPreparedDownload, error) {
	if service == nil || nilTicketingDependency(service.downloadStorage) {
		return AsyncExportPreparedDownload{}, ErrUnavailable
	}
	record, err := service.Get(ctx, actor, tenantID, kind, audience, jobID)
	if err != nil {
		return AsyncExportPreparedDownload{}, err
	}
	job := record.Job
	artifact := job.Artifact()
	if job.State() != kernel.TicketExportSucceeded || artifact == nil {
		return AsyncExportPreparedDownload{}, ErrConflict
	}
	now, err := service.now()
	if err != nil {
		return AsyncExportPreparedDownload{}, err
	}
	expiresAt := artifact.ExpiresAt().UTC()
	if !expiresAt.After(now) || !job.ExpiresAt().Equal(expiresAt) {
		return AsyncExportPreparedDownload{}, ErrConflict
	}
	if maximum := now.Add(AsyncExportDownloadMaximumLifetime); expiresAt.After(maximum) {
		expiresAt = maximum
	}
	if !expiresAt.After(now) {
		return AsyncExportPreparedDownload{}, ErrConflict
	}
	definition := job.Definition()
	location := AsyncExportArtifactLocation{
		TenantID: definition.Tenant(), JobID: definition.ID(), ArtifactID: artifact.ID(),
		Revision: job.Revision(), Attempt: job.Attempts(), Projection: definition.ProjectionVersion(),
		Digest: artifact.Digest(), Rows: artifact.Rows(), Bytes: artifact.Bytes(),
	}
	if _, _, keyErr := kernel.TicketExportArtifactObjectKeys(
		location.TenantID,
		location.JobID,
		location.ArtifactID,
	); keyErr != nil || location.Revision == 0 || location.Attempt == 0 ||
		location.Projection == 0 || location.Digest == ([32]byte{}) || location.Bytes == 0 {
		return AsyncExportPreparedDownload{}, ErrUnavailable
	}
	grant, err := service.downloadStorage.PrepareAsyncExportDownload(ctx, location, expiresAt)
	if err != nil {
		return AsyncExportPreparedDownload{}, ErrUnavailable
	}
	if !validAsyncExportDownloadGrant(grant, now, expiresAt) {
		return AsyncExportPreparedDownload{}, ErrUnavailable
	}
	return AsyncExportPreparedDownload{Record: record, Artifact: *artifact, Grant: grant}, nil
}

func validAsyncExportDownloadGrant(
	grant AsyncExportDownloadGrant,
	now time.Time,
	maximumExpiry time.Time,
) bool {
	if !validAsyncExportDownloadURL(grant.TargetURL) || !validStoredInstant(grant.ExpiresAt) ||
		!grant.ExpiresAt.After(now) || grant.ExpiresAt.After(maximumExpiry) {
		return false
	}
	return true
}

func validAsyncExportDownloadURL(raw string) bool {
	if raw == "" || len(raw) > 8_192 || !utf8.ValidString(raw) {
		return false
	}
	for _, character := range raw {
		if unicode.IsControl(character) {
			return false
		}
	}
	parsed, err := url.Parse(raw)
	return err == nil && parsed.IsAbs() && parsed.Host != "" && parsed.User == nil &&
		parsed.Fragment == "" && (parsed.Scheme == "https" || parsed.Scheme == "http")
}
