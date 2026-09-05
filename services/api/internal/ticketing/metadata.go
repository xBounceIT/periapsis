package ticketing

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
)

// EditableMetadata is the complete mutable core-field allowlist. Workflow,
// assignment, ingest provenance, timestamps, and identity fields deliberately
// do not appear here.
type EditableMetadata struct {
	Title           string   `json:"title"`
	Description     string   `json:"description"`
	Summary         string   `json:"summary"`
	Severity        string   `json:"severity"`
	Priority        string   `json:"priority"`
	Category        string   `json:"category"`
	Classification  *string  `json:"classification"`
	CustomerVisible bool     `json:"customerVisible"`
	Tags            []string `json:"tags"`
}

type MetadataReplaceInput struct {
	EditableMetadata
	ExpectedVersion uint64
	IdempotencyKey  string
}

// TicketMetadata is an immutable command-result projection. Keeping the
// response bounded to editable metadata permits an exact replay even after a
// later, unrelated workflow or assignment mutation advances the ticket.
type TicketMetadata struct {
	TenantID uuid.UUID
	TicketID uuid.UUID
	Kind     kernel.AggregateKind
	EditableMetadata
	Version   uint64
	UpdatedAt time.Time
}

type MetadataMutationResult struct {
	Metadata TicketMetadata
	Replayed bool
}

const maximumMetadataFingerprintBytes = 256 * 1024

func (service *Service) ReplaceAlertMetadata(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	alertID uuid.UUID,
	input MetadataReplaceInput,
) (MetadataMutationResult, error) {
	return service.replaceMetadata(ctx, actor, tenantID, kernel.AggregateAlert, alertID, input)
}

func (service *Service) ReplaceCaseMetadata(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	caseID uuid.UUID,
	input MetadataReplaceInput,
) (MetadataMutationResult, error) {
	return service.replaceMetadata(ctx, actor, tenantID, kernel.AggregateCase, caseID, input)
}

func (service *Service) replaceMetadata(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	ticketID uuid.UUID,
	input MetadataReplaceInput,
) (MetadataMutationResult, error) {
	if ctx == nil || ctx.Err() != nil {
		return MetadataMutationResult{}, ErrUnavailable
	}
	if !validMutationActor(actor, tenantID) {
		return MetadataMutationResult{}, ErrForbidden
	}
	input.EditableMetadata = normalizeEditableMetadata(input.EditableMetadata)
	if _, err := entityID(ticketID); err != nil ||
		input.ExpectedVersion == 0 || input.ExpectedVersion >= maxResourceVersion ||
		!validIdempotencyKey(input.IdempotencyKey) ||
		!validEditableMetadata(kind, input.EditableMetadata) {
		return MetadataMutationResult{}, ErrInvalidInput
	}
	fingerprint, err := metadataFingerprint(tenantID, actor.UserID, ticketID, kind, input)
	if err != nil {
		return MetadataMutationResult{}, err
	}
	capability := CapabilityCaseUpdate
	if kind == kernel.AggregateAlert {
		capability = CapabilityAlertUpdate
	}
	access, err := service.access(ctx, actor, tenantID, capability)
	if err != nil {
		return MetadataMutationResult{}, err
	}
	if access.Authority.Principal() != kernel.PrincipalOperator {
		return MetadataMutationResult{}, ErrForbidden
	}
	view, err := service.getAuthorized(ctx, tenantID, kind, ticketID, access)
	if err != nil {
		return MetadataMutationResult{}, err
	}
	if view.Projection != ProjectionOperator {
		return MetadataMutationResult{}, ErrForbidden
	}
	if view.Record.Snapshot.Version() == input.ExpectedVersion &&
		sameEditableMetadata(metadataFromRecord(view.Record), input.EditableMetadata) {
		return MetadataMutationResult{}, ErrConflict
	}
	if ctx.Err() != nil {
		return MetadataMutationResult{}, ErrUnavailable
	}
	result, err := service.repository.ReplaceMetadata(ctx, MetadataWrite{
		Actor: actor, TenantID: tenantID, Kind: kind, TicketID: ticketID,
		Content: input.EditableMetadata, ExpectedVersion: input.ExpectedVersion,
		KeyHash: sha256.Sum256([]byte(input.IdempotencyKey)), Fingerprint: fingerprint,
		Audit: actor.Audit,
	})
	if err != nil {
		return MetadataMutationResult{}, repositoryError(err)
	}
	result.Metadata.EditableMetadata = normalizeEditableMetadata(result.Metadata.EditableMetadata)
	if !validMetadataResult(result, tenantID, kind, ticketID, input) ||
		!result.Replayed && result.Metadata.UpdatedAt.Before(view.Record.UpdatedAt) {
		return MetadataMutationResult{}, ErrUnavailable
	}
	return result, nil
}

func normalizeEditableMetadata(value EditableMetadata) EditableMetadata {
	result := value
	result.Tags = append([]string{}, value.Tags...)
	if value.Classification != nil {
		classification := *value.Classification
		result.Classification = &classification
	}
	return result
}

func validEditableMetadata(kind kernel.AggregateKind, value EditableMetadata) bool {
	if kind != kernel.AggregateAlert && kind != kernel.AggregateCase ||
		!validMetadataText(value.Title, 240, true, false) ||
		!validMetadataText(value.Description, descriptionLimit(kind), false, true) ||
		!validMetadataText(value.Summary, 2_000, false, true) ||
		!validMetadataText(value.Category, 120, true, false) ||
		!validOptionalMetadataText(value.Classification, 120) ||
		!validEnum(value.Severity, "informational", "low", "medium", "high", "critical") ||
		!validEnum(value.Priority, "low", "medium", "high", "urgent", "critical") ||
		!validTags(value.Tags) {
		return false
	}
	return kind != kernel.AggregateAlert || value.Summary == ""
}

func validOptionalMetadataText(value *string, maximum int) bool {
	return value == nil || validMetadataText(*value, maximum, true, false)
}

func validMetadataText(value string, maximum int, required, multiline bool) bool {
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) > maximum ||
		strings.TrimSpace(value) != value || required && value == "" {
		return false
	}
	for _, character := range value {
		if !unicode.IsControl(character) || multiline && (character == '\t' || character == '\n' || character == '\r') {
			continue
		}
		return false
	}
	return true
}

func metadataFromRecord(record Record) EditableMetadata {
	return normalizeEditableMetadata(EditableMetadata{
		Title: record.Title, Description: record.Description, Summary: record.Summary,
		Severity: record.Severity, Priority: record.Priority, Category: record.Category,
		Classification:  record.Classification,
		CustomerVisible: record.Snapshot.CustomerVisible(), Tags: record.Tags,
	})
}

func sameEditableMetadata(left, right EditableMetadata) bool {
	return left.Title == right.Title && left.Description == right.Description &&
		left.Summary == right.Summary && left.Severity == right.Severity &&
		left.Priority == right.Priority && left.Category == right.Category &&
		equalOptionalString(left.Classification, right.Classification) &&
		left.CustomerVisible == right.CustomerVisible && slices.Equal(left.Tags, right.Tags)
}

func metadataFingerprint(
	tenantID uuid.UUID,
	actorID uuid.UUID,
	ticketID uuid.UUID,
	kind kernel.AggregateKind,
	input MetadataReplaceInput,
) ([sha256.Size]byte, error) {
	document := struct {
		SchemaVersion   int       `json:"schemaVersion"`
		TenantID        uuid.UUID `json:"tenantId"`
		ActorID         uuid.UUID `json:"actorId"`
		TicketID        uuid.UUID `json:"ticketId"`
		Kind            string    `json:"kind"`
		ExpectedVersion uint64    `json:"expectedVersion"`
		EditableMetadata
	}{1, tenantID, actorID, ticketID, kind.String(), input.ExpectedVersion, input.EditableMetadata}
	encoded, err := json.Marshal(document)
	if err != nil || len(encoded) > maximumMetadataFingerprintBytes {
		return [sha256.Size]byte{}, ErrInvalidInput
	}
	return sha256.Sum256(encoded), nil
}

func validMetadataResult(
	result MetadataMutationResult,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	ticketID uuid.UUID,
	input MetadataReplaceInput,
) bool {
	metadata := result.Metadata
	return metadata.TenantID == tenantID && metadata.TicketID == ticketID && metadata.Kind == kind &&
		metadata.Version == input.ExpectedVersion+1 && validStoredInstant(metadata.UpdatedAt) &&
		validEditableMetadata(kind, metadata.EditableMetadata) &&
		sameEditableMetadata(metadata.EditableMetadata, input.EditableMetadata)
}
