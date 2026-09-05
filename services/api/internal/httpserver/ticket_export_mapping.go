package httpserver

import (
	"encoding/hex"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	application "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

func mapTicketExportMutationResult(
	result application.AsyncExportResult,
) (contract.TicketExportJobMutationResult, error) {
	job, err := mapTicketExportJob(result.Record)
	if err != nil {
		return contract.TicketExportJobMutationResult{}, err
	}
	return contract.TicketExportJobMutationResult{Job: job, Replayed: result.Replayed}, nil
}

func mapOwnedTicketExportMutationResult(
	result application.AsyncExportResult,
	tenantID, requesterID uuid.UUID,
	kind kernel.AggregateKind,
) (contract.TicketExportJobMutationResult, error) {
	mapped, err := mapTicketExportMutationResult(result)
	if err != nil || !ownedTicketExportCoordinates(mapped.Job, tenantID, requesterID, kind) {
		return contract.TicketExportJobMutationResult{}, application.ErrUnavailable
	}
	return mapped, nil
}

func mapRequestedTicketExportMutationResult(
	result application.AsyncExportResult,
	tenantID, requesterID uuid.UUID,
	kind kernel.AggregateKind,
	input application.AsyncExportRequestInput,
) (contract.TicketExportJobMutationResult, error) {
	mapped, err := mapOwnedTicketExportMutationResult(result, tenantID, requesterID, kind)
	if err != nil || !matchesTicketExportRequest(mapped.Job, input) {
		return contract.TicketExportJobMutationResult{}, application.ErrUnavailable
	}
	return mapped, nil
}

func mapCancelledTicketExportMutationResult(
	result application.AsyncExportResult,
	tenantID, requesterID uuid.UUID,
	kind kernel.AggregateKind,
	expectedRevision uint64,
) (contract.TicketExportJobMutationResult, error) {
	mapped, err := mapOwnedTicketExportMutationResult(result, tenantID, requesterID, kind)
	if err != nil || uint64(mapped.Job.Revision) != expectedRevision+1 ||
		mapped.Job.State != contract.TicketExportStateCancelled &&
			mapped.Job.State != contract.TicketExportStateCancellationRequested {
		return contract.TicketExportJobMutationResult{}, application.ErrUnavailable
	}
	return mapped, nil
}

func matchesTicketExportRequest(
	job contract.TicketExportJob,
	input application.AsyncExportRequestInput,
) bool {
	rows := input.MaximumRows
	if rows == 0 {
		rows = application.AsyncExportDefaultRows
	}
	bytes := input.MaximumBytes
	if bytes == 0 {
		bytes = application.AsyncExportDefaultBytes
	}
	retention := input.Retention
	if retention == 0 {
		retention = application.AsyncExportDefaultRetention
	}
	if job.Comments != contract.TicketExportCommentScope(input.Comments.String()) ||
		job.MaximumRows != int32(rows) || job.MaximumBytes != int64(bytes) ||
		job.MaximumAttempts != int32(kernel.TicketExportMaximumAttempts) ||
		job.State != contract.TicketExportStatePending || job.Revision != 1 || job.Attempts != 0 ||
		job.FailureCode != contract.TicketExportFailureCodeNone ||
		job.ExpiresAt.Sub(job.RequestedAt) != retention {
		return false
	}
	if input.Source.Inline != nil {
		return input.Source.SavedView == nil &&
			job.Query.Source == contract.TicketExportQuerySnapshotSourceInline && job.Query.SavedView == nil
	}
	saved := input.Source.SavedView
	pin := job.Query.SavedView
	return saved != nil && pin != nil && job.Query.Source == contract.TicketExportQuerySnapshotSourceSavedView &&
		pin.Id == saved.ID && pin.Revision == int64(saved.ExpectedRevision) &&
		pin.SpecSha256 == ticketExportDigestString(saved.ExpectedSpecDigest) &&
		job.Query.QuerySha256 == pin.SpecSha256
}

func mapOwnedTicketExportJob(
	record application.AsyncExportRecord,
	tenantID, requesterID uuid.UUID,
	kind kernel.AggregateKind,
) (contract.TicketExportJob, error) {
	mapped, err := mapTicketExportJob(record)
	if err != nil || !ownedTicketExportCoordinates(mapped, tenantID, requesterID, kind) {
		return contract.TicketExportJob{}, application.ErrUnavailable
	}
	return mapped, nil
}

func ownedTicketExportCoordinates(
	job contract.TicketExportJob,
	tenantID, requesterID uuid.UUID,
	kind kernel.AggregateKind,
) bool {
	return job.TenantId == tenantID && job.RequesterUserId == requesterID &&
		string(job.Kind) == kind.String() && job.Audience == contract.TicketExportJobAudienceOperator
}

func mapTicketExportJob(record application.AsyncExportRecord) (contract.TicketExportJob, error) {
	job := record.Job
	if err := kernel.ValidateTicketExportJob(job); err != nil {
		return contract.TicketExportJob{}, application.ErrUnavailable
	}
	definition := job.Definition()
	if definition.Audience() != kernel.TicketExportAudienceOperator ||
		definition.CustomerContact() != nil || definition.ProjectionVersion() != kernel.TicketExportProjectionVersion ||
		definition.Format() != kernel.TicketExportCSV || definition.MaximumRows() > kernel.TicketExportOperatorMaximumRows ||
		definition.MaximumBytes() > kernel.TicketExportOperatorMaximumBytes ||
		definition.MaximumAttempts() == 0 || definition.MaximumAttempts() > kernel.TicketExportMaximumAttempts ||
		job.Revision() == 0 || job.Revision() > uint64(maximumResourceVersion) ||
		job.Attempts() > definition.MaximumAttempts() {
		return contract.TicketExportJob{}, application.ErrUnavailable
	}
	kind := contract.TicketResourceKind(definition.Kind().String())
	audience := contract.TicketExportJobAudience(definition.Audience().String())
	comments := contract.TicketExportCommentScope(definition.Comments().String())
	format := contract.TicketExportJobFormat(definition.Format().String())
	projectionVersion := contract.TicketExportJobProjectionVersion(definition.ProjectionVersion())
	state := contract.TicketExportState(job.State().String())
	failureCode := contract.TicketExportFailureCode(job.FailureCode().String())
	if !kind.Valid() || !audience.Valid() || !comments.Valid() || !format.Valid() ||
		!projectionVersion.Valid() || !state.Valid() || !failureCode.Valid() {
		return contract.TicketExportJob{}, application.ErrUnavailable
	}
	query, err := mapTicketExportQuery(record.Query, definition)
	if err != nil {
		return contract.TicketExportJob{}, err
	}
	result := contract.TicketExportJob{
		Id: uuid.UUID(definition.ID().Bytes()), TenantId: uuid.UUID(definition.Tenant().Bytes()),
		RequesterUserId:   uuid.UUID(definition.Requester().Bytes()),
		OwnerMembershipId: uuid.UUID(definition.OwnerMembership().Bytes()),
		Kind:              kind, Audience: audience, Comments: comments, Query: query,
		ProjectionVersion: projectionVersion, Format: format,
		MaximumRows: int32(definition.MaximumRows()), MaximumBytes: int64(definition.MaximumBytes()),
		MaximumAttempts: int32(definition.MaximumAttempts()), State: state,
		Revision: int64(job.Revision()), Attempts: int32(job.Attempts()), FailureCode: failureCode,
		RequestedAt: job.RequestedAt(), UpdatedAt: job.UpdatedAt(), AvailableAt: job.AvailableAt(),
		ExpiresAt: job.ExpiresAt(),
	}
	if terminal := job.TerminalAt(); terminal != nil {
		value := *terminal
		result.TerminalAt = &value
	}
	artifact := job.Artifact()
	if (artifact != nil) != (job.State() == kernel.TicketExportSucceeded) {
		return contract.TicketExportJob{}, application.ErrUnavailable
	}
	if artifact != nil {
		mapped, err := mapTicketExportArtifact(*artifact, definition)
		if err != nil {
			return contract.TicketExportJob{}, err
		}
		result.Artifact = &mapped
	}
	return result, nil
}

func mapTicketExportQuery(
	query application.AsyncExportQuerySnapshot,
	definition kernel.TicketExportDefinition,
) (contract.TicketExportQuerySnapshot, error) {
	if query.Tenant() != uuid.UUID(definition.Tenant().Bytes()) || query.Kind() != definition.Kind() ||
		query.Source() != definition.QuerySource() || query.QueryDigest() != definition.QueryDigest() ||
		query.CatalogDigest() != definition.CatalogDigest() {
		return contract.TicketExportQuerySnapshot{}, application.ErrUnavailable
	}
	effectiveSpec, err := mapSavedTicketViewSpec(query.Spec())
	if err != nil {
		return contract.TicketExportQuerySnapshot{}, application.ErrUnavailable
	}
	source := contract.TicketExportQuerySnapshotSource(query.Source().String())
	if !source.Valid() || query.QueryDigest() == ([32]byte{}) || query.CatalogDigest() == ([32]byte{}) {
		return contract.TicketExportQuerySnapshot{}, application.ErrUnavailable
	}
	result := contract.TicketExportQuerySnapshot{
		Source: source, EffectiveSpec: effectiveSpec,
		QuerySha256:   ticketExportDigestString(query.QueryDigest()),
		CatalogSha256: ticketExportDigestString(query.CatalogDigest()),
	}
	queryPin, definitionPin := query.SavedView(), definition.SavedView()
	if (queryPin == nil) != (definitionPin == nil) {
		return contract.TicketExportQuerySnapshot{}, application.ErrUnavailable
	}
	if query.Source() == kernel.TicketExportQueryInline {
		if queryPin != nil {
			return contract.TicketExportQuerySnapshot{}, application.ErrUnavailable
		}
		return result, nil
	}
	if query.Source() != kernel.TicketExportQuerySavedView || queryPin == nil ||
		queryPin.ID() != definitionPin.ID() || queryPin.Owner() != definitionPin.Owner() ||
		queryPin.Revision() != definitionPin.Revision() || queryPin.Digest() != definitionPin.Digest() ||
		queryPin.Revision() == 0 || queryPin.Revision() > uint64(maximumResourceVersion) {
		return contract.TicketExportQuerySnapshot{}, application.ErrUnavailable
	}
	result.SavedView = &contract.TicketExportSavedViewPin{
		Id: uuid.UUID(queryPin.ID().Bytes()), OwnerMembershipId: uuid.UUID(queryPin.Owner().Bytes()),
		Revision: int64(queryPin.Revision()), SpecSha256: ticketExportDigestString(queryPin.Digest()),
	}
	return result, nil
}

func mapTicketExportArtifact(
	artifact kernel.TicketExportArtifact,
	definition kernel.TicketExportDefinition,
) (contract.TicketExportArtifact, error) {
	if artifact.Digest() == ([32]byte{}) || artifact.Rows() > definition.MaximumRows() ||
		artifact.Bytes() == 0 || artifact.Bytes() > definition.MaximumBytes() ||
		artifact.ExpiresAt().IsZero() {
		return contract.TicketExportArtifact{}, application.ErrUnavailable
	}
	return contract.TicketExportArtifact{
		Id: uuid.UUID(artifact.ID().Bytes()), Sha256: ticketExportDigestString(artifact.Digest()),
		Rows: int32(artifact.Rows()), Bytes: int64(artifact.Bytes()), ExpiresAt: artifact.ExpiresAt(),
	}, nil
}

func ticketExportDigestString(value [32]byte) string {
	return hex.EncodeToString(value[:])
}
