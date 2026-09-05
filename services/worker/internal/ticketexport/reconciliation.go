package ticketexport

import (
	"context"
	"crypto/sha256"
	"fmt"
	"math"

	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
)

// ReconcileArtifact is the complete non-secret manifest needed to derive and
// authenticate both object keys after the database has fenced an expired or
// orphaned artifact. Object locations are deliberately never accepted from a
// database response.
type ReconcileArtifact struct {
	TenantID          kernel.EntityID
	JobID             kernel.EntityID
	ArtifactID        kernel.EntityID
	Kind              kernel.AggregateKind
	Audience          kernel.TicketExportAudience
	ObjectRevision    uint64
	ObjectAttempt     uint8
	ProjectionVersion uint64
	Digest            [sha256.Size]byte
	Rows              uint32
	Bytes             uint64
}

func (artifact ReconcileArtifact) String() string {
	return fmt.Sprintf(
		"ticketexport.ReconcileArtifact{kind:%s,audience:%s,revision:%d,attempt:%d,rows:%d,bytes:%d,identity:[REDACTED],digest:[REDACTED]}",
		artifact.Kind, artifact.Audience, artifact.ObjectRevision, artifact.ObjectAttempt,
		artifact.Rows, artifact.Bytes,
	)
}

func (artifact ReconcileArtifact) GoString() string { return artifact.String() }

// ArtifactReconciler deletes only exact tenant/job/artifact-derived objects
// whose immutable metadata and checksum match the database-owned manifest. A
// missing object is an idempotent success; a mismatched object must fail closed.
type ArtifactReconciler interface {
	PurgeArtifact(context.Context, ReconcileArtifact) error
}

func validReconcileArtifact(artifact ReconcileArtifact) bool {
	return validEntityID(artifact.TenantID) && validEntityID(artifact.JobID) &&
		validEntityID(artifact.ArtifactID) &&
		(artifact.Kind == kernel.AggregateAlert || artifact.Kind == kernel.AggregateCase) &&
		(artifact.Audience == kernel.TicketExportAudienceOperator ||
			artifact.Audience == kernel.TicketExportAudienceCustomer) &&
		artifact.ObjectRevision > 0 && artifact.ObjectRevision <= math.MaxInt32 &&
		artifact.ObjectAttempt > 0 && artifact.ObjectAttempt <= kernel.TicketExportMaximumAttempts &&
		artifact.ProjectionVersion == kernel.TicketExportProjectionVersion &&
		artifact.Digest != ([sha256.Size]byte{}) && artifact.Bytes > 0 &&
		artifact.Bytes <= s3ArtifactMaximumBytes(artifact.Audience) &&
		artifact.Rows <= s3ArtifactMaximumRows(artifact.Audience)
}
