package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	application "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

const (
	maximumTicketWatcherProjectionBytes = 1024 * 1024
	maximumTicketWatcherItems           = 1_000
)

type ticketWatcherProjectionPayload struct {
	SchemaVersion int                    `json:"schema_version"`
	TenantID      uuid.UUID              `json:"tenant_id"`
	TicketID      uuid.UUID              `json:"ticket_id"`
	AggregateKind string                 `json:"aggregate_kind"`
	Version       int64                  `json:"version"`
	UpdatedAt     time.Time              `json:"updated_at"`
	Watchers      []ticketWatcherPayload `json:"watchers"`
}

type ticketWatcherPayload struct {
	UserID      uuid.UUID `json:"user_id"`
	DisplayName string    `json:"display_name"`
	AddedAt     time.Time `json:"added_at"`
}

var ticketWatcherProjectionFields = [...]string{
	"schema_version", "tenant_id", "ticket_id", "aggregate_kind", "version", "updated_at", "watchers",
}

func (repository *TicketingRepository) ListWatchers(
	ctx context.Context,
	query application.WatcherListQuery,
) (application.TicketWatcherProjection, error) {
	if ctx == nil || ctx.Err() != nil {
		return application.TicketWatcherProjection{}, application.ErrUnavailable
	}
	if repository == nil || repository.begin == nil || !validTicketWatcherReadActor(query.Actor, query.TenantID) ||
		!ticketWatcherUUIDv7(query.TicketID) || !validTicketWatcherKind(query.Kind) {
		return application.TicketWatcherProjection{}, application.ErrInvalidInput
	}
	result, err := withinTicketReadTransaction(
		ctx, repository, query.Actor.UserID, query.TenantID,
		func(tx databaseTransaction) (application.TicketWatcherProjection, error) {
			var resultVersion int64
			var resultUpdatedAt time.Time
			var rawProjection []byte
			queryErr := tx.QueryRow(ctx, `
				SELECT result_version, result_updated_at, result_projection
				FROM app.list_tenant_ticket_watchers_v1(
				  $1::public.ticket_aggregate_kind,$2
				)`, query.Kind.String(), query.TicketID,
			).Scan(&resultVersion, &resultUpdatedAt, &rawProjection)
			if queryErr != nil {
				return application.TicketWatcherProjection{}, mapTicketDatabaseError(queryErr)
			}
			return decodeTicketWatcherProjection(
				rawProjection, resultVersion, resultUpdatedAt,
				query.TenantID, query.TicketID, query.Kind,
			)
		},
	)
	return result, mapTicketDatabaseError(err)
}

func (repository *TicketingRepository) MutateWatcher(
	ctx context.Context,
	write application.WatcherMutationWrite,
) (application.WatcherMutationResult, error) {
	if ctx == nil || ctx.Err() != nil {
		return application.WatcherMutationResult{}, application.ErrUnavailable
	}
	if repository == nil || repository.begin == nil || !validTicketWatcherMutationWrite(write) {
		return application.WatcherMutationResult{}, application.ErrInvalidInput
	}
	result, err := withinTicketWriteTransaction(
		ctx, repository, write.Actor, write.TenantID,
		func(tx databaseTransaction) (application.WatcherMutationResult, error) {
			var resultVersion int64
			var resultUpdatedAt time.Time
			var rawProjection []byte
			var replayed bool
			queryErr := tx.QueryRow(ctx, `
				SELECT result_version, result_updated_at, result_projection, replayed
				FROM app.mutate_tenant_ticket_watcher_v1(
				  $1::public.ticket_aggregate_kind,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12
				)`,
				write.Kind.String(), write.TicketID, int64(write.ExpectedVersion), string(write.Action),
				write.TargetUserID, write.KeyHash[:], write.Fingerprint[:], write.Audit.RequestID,
				write.Audit.CorrelationID, write.Audit.RemoteAddress.Unmap(), write.Audit.UserAgent,
				write.Actor.AuthenticationMethod,
			).Scan(&resultVersion, &resultUpdatedAt, &rawProjection, &replayed)
			if queryErr != nil {
				if postgresCode(queryErr) == "40001" {
					return application.WatcherMutationResult{}, application.ErrPreconditionFailed
				}
				return application.WatcherMutationResult{}, mapTicketDatabaseError(queryErr)
			}
			projection, decodeErr := decodeTicketWatcherProjection(
				rawProjection, resultVersion, resultUpdatedAt,
				write.TenantID, write.TicketID, write.Kind,
			)
			if decodeErr != nil {
				return application.WatcherMutationResult{}, decodeErr
			}
			return application.WatcherMutationResult{Projection: projection, Replayed: replayed}, nil
		},
	)
	return result, mapTicketDatabaseError(err)
}

func decodeTicketWatcherProjection(
	raw []byte,
	resultVersion int64,
	resultUpdatedAt time.Time,
	tenantID uuid.UUID,
	ticketID uuid.UUID,
	kind kernel.AggregateKind,
) (application.TicketWatcherProjection, error) {
	if len(raw) == 0 || len(raw) > maximumTicketWatcherProjectionBytes ||
		resultVersion < 1 || resultVersion > 2_147_483_647 {
		return application.TicketWatcherProjection{}, application.ErrUnavailable
	}
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return application.TicketWatcherProjection{}, application.ErrUnavailable
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || len(fields) != len(ticketWatcherProjectionFields) {
		return application.TicketWatcherProjection{}, application.ErrUnavailable
	}
	for _, field := range ticketWatcherProjectionFields {
		if _, present := fields[field]; !present {
			return application.TicketWatcherProjection{}, application.ErrUnavailable
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var payload ticketWatcherProjectionPayload
	if err := decoder.Decode(&payload); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return application.TicketWatcherProjection{}, application.ErrUnavailable
	}
	updatedAt := ticketTime(resultUpdatedAt)
	payloadUpdatedAt := ticketTime(payload.UpdatedAt)
	if payload.SchemaVersion != 1 || payload.TenantID != tenantID || payload.TicketID != ticketID ||
		payload.AggregateKind != kind.String() || payload.Version != resultVersion ||
		payload.UpdatedAt.IsZero() || !payloadUpdatedAt.Equal(updatedAt) || payload.Watchers == nil ||
		len(payload.Watchers) > maximumTicketWatcherItems {
		return application.TicketWatcherProjection{}, application.ErrUnavailable
	}
	watchers := make([]application.TicketWatcher, 0, len(payload.Watchers))
	seen := make(map[uuid.UUID]struct{}, len(payload.Watchers))
	for index, value := range payload.Watchers {
		addedAt := ticketTime(value.AddedAt)
		if !ticketWatcherUUIDv7(value.UserID) || !validTicketWatcherDisplayName(value.DisplayName) ||
			value.AddedAt.IsZero() || addedAt.After(updatedAt) {
			return application.TicketWatcherProjection{}, application.ErrUnavailable
		}
		if _, duplicate := seen[value.UserID]; duplicate {
			return application.TicketWatcherProjection{}, application.ErrUnavailable
		}
		if index > 0 && compareTicketWatcherPayloads(payload.Watchers[index-1], value) >= 0 {
			return application.TicketWatcherProjection{}, application.ErrUnavailable
		}
		seen[value.UserID] = struct{}{}
		watchers = append(watchers, application.TicketWatcher{
			UserID: value.UserID, DisplayName: value.DisplayName, AddedAt: addedAt,
		})
	}
	return application.TicketWatcherProjection{
		TenantID: tenantID, TicketID: ticketID, Kind: kind, Items: watchers,
		Version: uint64(resultVersion), UpdatedAt: updatedAt,
	}, nil
}

func compareTicketWatcherPayloads(left, right ticketWatcherPayload) int {
	if displayOrder := strings.Compare(left.DisplayName, right.DisplayName); displayOrder != 0 {
		return displayOrder
	}
	return strings.Compare(left.UserID.String(), right.UserID.String())
}

func validTicketWatcherReadActor(actor application.Actor, tenantID uuid.UUID) bool {
	return ticketWatcherUUIDv7(tenantID) && ticketWatcherUUIDv7(actor.UserID) &&
		ticketWatcherUUIDv7(actor.SessionID) && actor.ActiveTenantID == tenantID &&
		validTicketWatcherText(actor.AuthenticationMethod, 1, 64)
}

func validTicketWatcherMutationWrite(write application.WatcherMutationWrite) bool {
	return validTicketWatcherReadActor(write.Actor, write.TenantID) &&
		ticketWatcherUUIDv7(write.TicketID) && ticketWatcherUUIDv7(write.TargetUserID) &&
		validTicketWatcherKind(write.Kind) &&
		(write.Action == application.WatcherAdd || write.Action == application.WatcherRemove) &&
		write.ExpectedVersion > 0 && write.ExpectedVersion < 2_147_483_647 &&
		write.KeyHash != ([sha256.Size]byte{}) && write.Fingerprint != ([sha256.Size]byte{}) &&
		write.Audit == write.Actor.Audit && validTicketWatcherAudit(write.Audit)
}

func validTicketWatcherAudit(audit application.AuditContext) bool {
	return ticketWatcherUUIDv7(audit.RequestID) && ticketWatcherUUIDv7(audit.CorrelationID) &&
		audit.RemoteAddress.IsValid() && audit.RemoteAddress.Zone() == "" &&
		validTicketWatcherText(audit.UserAgent, 1, 512)
}

func validTicketWatcherKind(kind kernel.AggregateKind) bool {
	return kind == kernel.AggregateAlert || kind == kernel.AggregateCase
}

func ticketWatcherUUIDv7(value uuid.UUID) bool {
	return value != uuid.Nil && value.Version() == 7 && value.Variant() == uuid.RFC4122
}

func validTicketWatcherDisplayName(value string) bool {
	return validTicketWatcherText(value, 1, 160) && strings.TrimSpace(value) == value
}

func validTicketWatcherText(value string, minimum, maximum int) bool {
	length := utf8.RuneCountInString(value)
	if !utf8.ValidString(value) || length < minimum || length > maximum {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}
