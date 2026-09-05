package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	application "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

type ticketMetadataResultPayload struct {
	SchemaVersion   int       `json:"schema_version"`
	TenantID        uuid.UUID `json:"tenant_id"`
	TicketID        uuid.UUID `json:"ticket_id"`
	AggregateKind   string    `json:"aggregate_kind"`
	Title           string    `json:"title"`
	Description     string    `json:"description"`
	Summary         string    `json:"summary"`
	Severity        string    `json:"severity"`
	Priority        string    `json:"priority"`
	Category        string    `json:"category"`
	Classification  *string   `json:"classification"`
	CustomerVisible bool      `json:"customer_visible"`
	Tags            []string  `json:"tags"`
	Version         int64     `json:"version"`
	UpdatedAt       time.Time `json:"updated_at"`
}

const maximumTicketMetadataResultBytes = 256 * 1024

var ticketMetadataResultFields = [...]string{
	"schema_version", "tenant_id", "ticket_id", "aggregate_kind", "title",
	"description", "summary", "severity", "priority", "category",
	"classification", "customer_visible", "tags", "version", "updated_at",
}

func (repository *TicketingRepository) ReplaceMetadata(
	ctx context.Context,
	write application.MetadataWrite,
) (application.MetadataMutationResult, error) {
	if ctx == nil || ctx.Err() != nil {
		return application.MetadataMutationResult{}, application.ErrUnavailable
	}
	if repository == nil || repository.begin == nil || write.TenantID == uuid.Nil || write.TicketID == uuid.Nil ||
		write.Actor.ActiveTenantID != write.TenantID || write.Audit != write.Actor.Audit ||
		write.ExpectedVersion == 0 || write.KeyHash == ([sha256.Size]byte{}) ||
		write.Fingerprint == ([sha256.Size]byte{}) ||
		write.Kind != kernel.AggregateAlert && write.Kind != kernel.AggregateCase {
		return application.MetadataMutationResult{}, application.ErrInvalidInput
	}
	var summary *string
	if write.Kind == kernel.AggregateCase {
		summary = &write.Content.Summary
	}
	result, err := withinTicketWriteTransaction(ctx, repository, write.Actor, write.TenantID,
		func(tx databaseTransaction) (application.MetadataMutationResult, error) {
			var resultVersion int64
			var resultUpdatedAt time.Time
			var rawMetadata []byte
			var replayed bool
			queryErr := tx.QueryRow(ctx, `
				SELECT result_version, result_updated_at, result_metadata, replayed
				FROM app.replace_tenant_ticket_metadata_v1(
				  $1::public.ticket_aggregate_kind,$2,$3,$4,$5,$6,$7,$8,$9,$10,
				  $11,$12,$13,$14,$15,$16,$17,$18,$19
				)`,
				write.Kind.String(), write.TicketID, int64(write.ExpectedVersion),
				write.Content.Title, write.Content.Description, summary,
				write.Content.Severity, write.Content.Priority, write.Content.Category,
				write.Content.Classification, write.Content.CustomerVisible, write.Content.Tags,
				write.KeyHash[:], write.Fingerprint[:], write.Audit.RequestID,
				write.Audit.CorrelationID, write.Audit.RemoteAddress.Unmap(), write.Audit.UserAgent,
				write.Actor.AuthenticationMethod,
			).Scan(&resultVersion, &resultUpdatedAt, &rawMetadata, &replayed)
			if queryErr != nil {
				if postgresCode(queryErr) == "40001" {
					return application.MetadataMutationResult{}, application.ErrPreconditionFailed
				}
				return application.MetadataMutationResult{}, mapTicketDatabaseError(queryErr)
			}
			return decodeTicketMetadataResult(
				rawMetadata, resultVersion, resultUpdatedAt, replayed,
				write.TenantID, write.TicketID, write.Kind,
			)
		},
	)
	return result, mapTicketDatabaseError(err)
}

func decodeTicketMetadataResult(
	raw []byte,
	resultVersion int64,
	resultUpdatedAt time.Time,
	replayed bool,
	tenantID uuid.UUID,
	ticketID uuid.UUID,
	kind kernel.AggregateKind,
) (application.MetadataMutationResult, error) {
	if len(raw) == 0 || len(raw) > maximumTicketMetadataResultBytes ||
		resultVersion < 2 || resultVersion > 2_147_483_647 {
		return application.MetadataMutationResult{}, application.ErrUnavailable
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || len(fields) != len(ticketMetadataResultFields) {
		return application.MetadataMutationResult{}, application.ErrUnavailable
	}
	for _, field := range ticketMetadataResultFields {
		if _, present := fields[field]; !present {
			return application.MetadataMutationResult{}, application.ErrUnavailable
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var payload ticketMetadataResultPayload
	if err := decoder.Decode(&payload); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return application.MetadataMutationResult{}, application.ErrUnavailable
	}
	updatedAt := ticketTime(resultUpdatedAt)
	payloadUpdatedAt := ticketTime(payload.UpdatedAt)
	if payload.SchemaVersion != 1 || payload.TenantID != tenantID || payload.TicketID != ticketID ||
		payload.AggregateKind != kind.String() || payload.Version != resultVersion ||
		payloadUpdatedAt.IsZero() || !payloadUpdatedAt.Equal(updatedAt) || payload.Tags == nil {
		return application.MetadataMutationResult{}, application.ErrUnavailable
	}
	metadata := application.TicketMetadata{
		TenantID: tenantID, TicketID: ticketID, Kind: kind,
		EditableMetadata: application.EditableMetadata{
			Title: payload.Title, Description: payload.Description, Summary: payload.Summary,
			Severity: payload.Severity, Priority: payload.Priority, Category: payload.Category,
			Classification: payload.Classification, CustomerVisible: payload.CustomerVisible,
			Tags: append([]string{}, payload.Tags...),
		},
		Version: uint64(resultVersion), UpdatedAt: updatedAt,
	}
	return application.MetadataMutationResult{Metadata: metadata, Replayed: replayed}, nil
}
