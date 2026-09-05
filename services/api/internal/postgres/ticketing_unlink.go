package postgres

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	application "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

func (repository *TicketingRepository) ResolveLinkLifecycle(
	ctx context.Context,
	actorID uuid.UUID,
	tenantID uuid.UUID,
	alertID uuid.UUID,
	caseID uuid.UUID,
) (application.LinkLifecycle, error) {
	result, err := withinTicketReadTransaction(ctx, repository, actorID, tenantID,
		func(tx databaseTransaction) (application.LinkLifecycle, error) {
			var lifecycle application.LinkLifecycle
			err := tx.QueryRow(ctx, `
				SELECT link.id, retraction.id IS NOT NULL
				FROM public.alert_case_links AS link
				LEFT JOIN public.alert_case_link_retractions AS retraction
				  ON retraction.tenant_id = link.tenant_id
				 AND retraction.link_id = link.id
				WHERE link.tenant_id = $1 AND link.alert_id = $2
				  AND link.case_id = $3`, tenantID, alertID, caseID,
			).Scan(&lifecycle.LinkID, &lifecycle.Retracted)
			return lifecycle, err
		},
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return application.LinkLifecycle{}, application.ErrConflict
	}
	return result, mapTicketDatabaseError(err)
}

func (repository *TicketingRepository) CommitUnlink(
	ctx context.Context,
	write application.UnlinkWrite,
) (application.UnlinkReceipt, error) {
	tenantID := uuid.UUID(write.Alert.Snapshot.Tenant().Bytes())
	result, err := withinTicketWriteTransaction(ctx, repository, write.Actor, tenantID,
		func(tx databaseTransaction) (application.UnlinkReceipt, error) {
			return queryUnlinkReceipt(ctx, tx, tenantID, `
				SELECT result_link_id, previous_alert_version,
				       result_alert_version, previous_case_version,
				       result_case_version, retracted_at, replayed
				FROM app.commit_tenant_alert_case_unlink_v1(
				  $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,
				  $17,$18,$19,$20,$21,$22
				)`, uuid.UUID(write.Alert.Snapshot.ID().Bytes()), write.Input.CaseID, write.LinkID,
				uuid.UUID(write.AlertPlan.WorkflowID().Bytes()), write.AlertPlan.WorkflowVersion(),
				write.AlertPlan.FromState().String(), write.AlertPlan.ExpectedVersion(), write.AlertPlan.NextVersion(),
				uuid.UUID(write.CasePlan.WorkflowID().Bytes()), write.CasePlan.WorkflowVersion(),
				write.CasePlan.FromState().String(), write.CasePlan.ExpectedVersion(), write.CasePlan.NextVersion(),
				write.Input.Reason, write.KeyHash[:], write.Fingerprint[:], write.Effects,
				write.Audit.RequestID, write.Audit.CorrelationID, write.Audit.RemoteAddress.Unmap(),
				write.Audit.UserAgent, write.Actor.AuthenticationMethod,
			)
		},
	)
	return result, mapTicketDatabaseError(err)
}

func (repository *TicketingRepository) LookupUnlinkReplay(
	ctx context.Context,
	query application.UnlinkReplayQuery,
) (application.UnlinkReceipt, bool, error) {
	result, err := withinTicketActorTransaction(ctx, repository, query.Actor, query.TenantID,
		func(tx databaseTransaction) (application.UnlinkReceipt, error) {
			return queryUnlinkReceipt(ctx, tx, query.TenantID, `
				SELECT result_link_id, previous_alert_version,
				       result_alert_version, previous_case_version,
				       result_case_version, retracted_at, true
				FROM app.lookup_tenant_alert_case_unlink_replay_v1($1,$2,$3,$4)`,
				query.AlertID, query.CaseID, query.KeyHash[:], query.Fingerprint[:],
			)
		},
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return application.UnlinkReceipt{}, false, nil
	}
	if err != nil {
		return application.UnlinkReceipt{}, false, mapTicketDatabaseError(err)
	}
	if result.AlertID != query.AlertID {
		return application.UnlinkReceipt{}, false, application.ErrUnavailable
	}
	return result, true, nil
}

func queryUnlinkReceipt(
	ctx context.Context,
	tx databaseTransaction,
	expectedTenantID uuid.UUID,
	statement string,
	arguments ...any,
) (application.UnlinkReceipt, error) {
	var receipt application.UnlinkReceipt
	var previousAlert, alertVersion, previousCase, caseVersion int32
	err := tx.QueryRow(ctx, statement, arguments...).Scan(
		&receipt.LinkID, &previousAlert, &alertVersion, &previousCase,
		&caseVersion, &receipt.RetractedAt, &receipt.Replayed,
	)
	if err != nil {
		return application.UnlinkReceipt{}, err
	}
	if previousAlert < 1 || alertVersion != previousAlert+1 ||
		previousCase < 1 || caseVersion != previousCase+1 {
		return application.UnlinkReceipt{}, application.ErrUnavailable
	}
	// The database receipt intentionally omits duplicate public identifiers;
	// its immutable ticket command and retraction are loaded below to attest the
	// exact tuple under the same transaction.
	var tenantID, alertID, caseID uuid.UUID
	err = tx.QueryRow(ctx, `
		SELECT retraction.tenant_id, retraction.alert_id, retraction.case_id
		FROM public.alert_case_link_retractions AS retraction
		WHERE retraction.link_id = $1 AND retraction.tenant_id = $2`,
		receipt.LinkID, expectedTenantID,
	).Scan(&tenantID, &alertID, &caseID)
	if err != nil {
		return application.UnlinkReceipt{}, err
	}
	if tenantID != expectedTenantID {
		return application.UnlinkReceipt{}, application.ErrUnavailable
	}
	receipt.TenantID, receipt.AlertID, receipt.CaseID = tenantID, alertID, caseID
	receipt.PreviousAlertVersion, receipt.AlertVersion = uint64(previousAlert), uint64(alertVersion)
	receipt.PreviousCaseVersion, receipt.CaseVersion = uint64(previousCase), uint64(caseVersion)
	receipt.RetractedAt = ticketTime(receipt.RetractedAt)
	return receipt, nil
}
