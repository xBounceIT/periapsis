package postgres

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	application "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

func (repository *TicketingRepository) DeleteAlert(
	ctx context.Context,
	write application.DeleteAlertWrite,
) (application.DeleteAlertReceipt, error) {
	if !validAlertDeleteWrite(write) {
		return application.DeleteAlertReceipt{}, application.ErrInvalidInput
	}
	tenantID := uuid.UUID(write.Current.Snapshot.Tenant().Bytes())
	alertID := uuid.UUID(write.Current.Snapshot.ID().Bytes())
	receipt, err := withinTicketWriteTransaction(ctx, repository, write.Actor, tenantID,
		func(tx databaseTransaction) (application.DeleteAlertReceipt, error) {
			var value application.DeleteAlertReceipt
			var previousVersion, tombstoneVersion int64
			queryErr := tx.QueryRow(ctx, `
				SELECT alert_id, previous_version, tombstone_version, deleted_at, replayed
				FROM app.delete_tenant_alert_v1(
				  $1,$2,$3,$4,$5,$6,$7,$8,$9,$10
				)`,
				alertID, int64(write.Input.ExpectedVersion), write.Input.Reason,
				write.KeyHash[:], write.Fingerprint[:], write.Audit.RequestID,
				write.Audit.CorrelationID, write.Audit.RemoteAddress.Unmap(),
				write.Audit.UserAgent, write.Actor.AuthenticationMethod,
			).Scan(
				&value.AlertID, &previousVersion, &tombstoneVersion, &value.DeletedAt, &value.Replayed,
			)
			if queryErr != nil {
				return application.DeleteAlertReceipt{}, mapTicketDatabaseError(queryErr)
			}
			if previousVersion < 1 || tombstoneVersion != previousVersion+1 || tombstoneVersion > math.MaxInt32 ||
				!normalizeTicketDatabaseTime(&value.DeletedAt) {
				return application.DeleteAlertReceipt{}, application.ErrUnavailable
			}
			value.TenantID = tenantID
			value.PreviousVersion = uint64(previousVersion)
			value.TombstoneVersion = uint64(tombstoneVersion)
			return value, nil
		},
	)
	return receipt, mapTicketDatabaseError(err)
}

func (repository *TicketingRepository) LookupAlertDeleteReplay(
	ctx context.Context,
	query application.DeleteAlertReplayQuery,
) (application.DeleteAlertReceipt, bool, error) {
	if repository == nil || repository.begin == nil || !ticketDeleteUUIDv7(query.TenantID) ||
		!ticketDeleteUUIDv7(query.AlertID) || !ticketDeleteUUIDv7(query.Actor.UserID) ||
		query.KeyHash == ([32]byte{}) || query.Fingerprint == ([32]byte{}) {
		return application.DeleteAlertReceipt{}, false, application.ErrInvalidInput
	}
	receipt, err := withinTicketActorTransaction(ctx, repository, query.Actor, query.TenantID,
		func(tx databaseTransaction) (application.DeleteAlertReceipt, error) {
			var value application.DeleteAlertReceipt
			var previousVersion, tombstoneVersion int64
			err := tx.QueryRow(ctx, `
				SELECT alert_id, previous_version, tombstone_version, deleted_at
				FROM app.lookup_tenant_alert_delete_replay_v1($1,$2,$3)
			`, query.AlertID, query.KeyHash[:], query.Fingerprint[:]).Scan(
				&value.AlertID, &previousVersion, &tombstoneVersion, &value.DeletedAt,
			)
			if err != nil {
				return application.DeleteAlertReceipt{}, err
			}
			if value.AlertID != query.AlertID || previousVersion < 1 || tombstoneVersion != previousVersion+1 ||
				tombstoneVersion > math.MaxInt32 || !normalizeTicketDatabaseTime(&value.DeletedAt) {
				return application.DeleteAlertReceipt{}, application.ErrUnavailable
			}
			value.TenantID = query.TenantID
			value.PreviousVersion = uint64(previousVersion)
			value.TombstoneVersion = uint64(tombstoneVersion)
			value.Replayed = true
			return value, nil
		},
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return application.DeleteAlertReceipt{}, false, nil
	}
	if err != nil {
		return application.DeleteAlertReceipt{}, false, mapTicketDatabaseError(err)
	}
	return receipt, true, nil
}

func validAlertDeleteWrite(write application.DeleteAlertWrite) bool {
	snapshot := write.Current.Snapshot
	return snapshot.Kind() == kernel.AggregateAlert && snapshot.Version() == write.Input.ExpectedVersion &&
		write.Input.ExpectedVersion > 0 && write.Input.ExpectedVersion < math.MaxInt32 &&
		write.KeyHash != ([32]byte{}) && write.Fingerprint != ([32]byte{}) &&
		ticketDeleteUUIDv7(write.Actor.UserID) && ticketDeleteUUIDv7(write.Actor.SessionID) &&
		write.Actor.ActiveTenantID == uuid.UUID(snapshot.Tenant().Bytes()) &&
		write.Current.Creator.ID != uuid.Nil && write.Input.Reason != "" &&
		write.Audit.RemoteAddress.IsValid()
}

func ticketDeleteUUIDv7(value uuid.UUID) bool {
	return value != uuid.Nil && value.Version() == 7 && value.Variant() == uuid.RFC4122
}

func normalizeTicketDatabaseTime(value *time.Time) bool {
	if value == nil || value.IsZero() {
		return false
	}
	*value = value.UTC().Truncate(time.Microsecond)
	return value.Year() >= 1970 && value.Year() <= 9999
}
