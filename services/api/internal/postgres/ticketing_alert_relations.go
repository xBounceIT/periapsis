package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	application "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

func (repository *TicketingRepository) ListAlertRelations(
	ctx context.Context,
	actorID uuid.UUID,
	tenantID uuid.UUID,
	alertID uuid.UUID,
	page application.CursorPageInput,
	access application.LiveAccess,
) (application.StoredAlertRelationPage, error) {
	return withinTicketReadTransaction(ctx, repository, actorID, tenantID,
		func(tx databaseTransaction) (application.StoredAlertRelationPage, error) {
			arguments := []any{tenantID, alertID}
			add := func(value any) string {
				arguments = append(arguments, value)
				return fmt.Sprintf("$%d", len(arguments))
			}
			predicate, err := alertRelationCommonAccessPredicate(access, "source_alert", "target_alert", add)
			if err != nil {
				return application.StoredAlertRelationPage{}, err
			}
			query := alertRelationSelect + `
				WHERE relation.tenant_id = $1
				  AND (relation.source_alert_id = $2 OR relation.target_alert_id = $2)
				  AND source_alert.deleted_at IS NULL
				  AND target_alert.deleted_at IS NULL
				  AND ` + predicate
			if page.After != nil {
				query += " AND relation.id < " + add(*page.After)
			}
			query += " ORDER BY relation.id DESC LIMIT " + add(page.Limit+1)
			rows, err := tx.Query(ctx, query, arguments...)
			if err != nil {
				return application.StoredAlertRelationPage{}, mapTicketDatabaseError(err)
			}
			defer rows.Close()
			type scannedRelation struct {
				record    application.AlertRelationRecord
				relatedID uuid.UUID
			}
			scanned := make([]scannedRelation, 0, page.Limit+1)
			for rows.Next() {
				item, relatedID, scanErr := scanAlertRelation(rows, tenantID, alertID)
				if scanErr != nil {
					return application.StoredAlertRelationPage{}, scanErr
				}
				scanned = append(scanned, scannedRelation{record: item, relatedID: relatedID})
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return application.StoredAlertRelationPage{}, mapTicketDatabaseError(err)
			}
			var next *uuid.UUID
			if len(scanned) > page.Limit {
				scanned = scanned[:page.Limit]
				value := scanned[len(scanned)-1].record.Relation.ID
				next = &value
			}
			items := make([]application.AlertRelationRecord, len(scanned))
			for index, value := range scanned {
				related, getErr := getTicketRecord(ctx, tx, tenantID, kernel.AggregateAlert, value.relatedID)
				if getErr != nil {
					return application.StoredAlertRelationPage{}, getErr
				}
				value.record.Related = related
				items[index] = value.record
			}
			return application.StoredAlertRelationPage{Items: items, NextCursor: next}, nil
		},
	)
}

func (repository *TicketingRepository) GetAlertRelation(
	ctx context.Context,
	actorID uuid.UUID,
	tenantID uuid.UUID,
	alertID uuid.UUID,
	relationID uuid.UUID,
	access application.LiveAccess,
) (application.AlertRelationRecord, error) {
	return withinTicketReadTransaction(ctx, repository, actorID, tenantID,
		func(tx databaseTransaction) (application.AlertRelationRecord, error) {
			arguments := []any{tenantID, alertID, relationID}
			add := func(value any) string {
				arguments = append(arguments, value)
				return fmt.Sprintf("$%d", len(arguments))
			}
			predicate, err := alertRelationCommonAccessPredicate(access, "source_alert", "target_alert", add)
			if err != nil {
				return application.AlertRelationRecord{}, err
			}
			row := tx.QueryRow(ctx, alertRelationSelect+`
				WHERE relation.tenant_id = $1
				  AND (relation.source_alert_id = $2 OR relation.target_alert_id = $2)
				  AND relation.id = $3
				  AND source_alert.deleted_at IS NULL
				  AND target_alert.deleted_at IS NULL
				  AND `+predicate, arguments...)
			item, relatedID, err := scanAlertRelation(row, tenantID, alertID)
			if err != nil {
				return application.AlertRelationRecord{}, err
			}
			related, err := getTicketRecord(ctx, tx, tenantID, kernel.AggregateAlert, relatedID)
			if err != nil {
				return application.AlertRelationRecord{}, err
			}
			item.Related = related
			return item, nil
		},
	)
}

const alertRelationSelect = `
	SELECT relation.id, relation.source_alert_id, relation.target_alert_id,
	       relation.relation_type, relation.reason,
	       relation.prior_source_version, relation.result_source_version,
	       relation.prior_target_version, relation.result_target_version,
	       relation.linked_at,
	       retraction.reason, retraction.prior_source_version,
	       retraction.result_source_version,
	       retraction.prior_target_version,
	       retraction.result_target_version, retraction.retracted_at,
	       CASE WHEN relation.source_alert_id = $2
	            THEN relation.target_alert_id ELSE relation.source_alert_id END
	FROM public.alert_relations AS relation
	JOIN public.alerts AS source_alert
	  ON source_alert.tenant_id = relation.tenant_id
	 AND source_alert.id = relation.source_alert_id
	JOIN public.alerts AS target_alert
	  ON target_alert.tenant_id = relation.tenant_id
	 AND target_alert.id = relation.target_alert_id
	LEFT JOIN public.alert_relation_retractions AS retraction
	  ON retraction.tenant_id = relation.tenant_id
	 AND retraction.relation_id = relation.id`

func scanAlertRelation(
	row ticketRecordScanner,
	tenantID uuid.UUID,
	pathAlertID uuid.UUID,
) (application.AlertRelationRecord, uuid.UUID, error) {
	var relation application.AlertRelation
	var priorSource, sourceVersion, priorTarget, targetVersion int32
	var retractionReason pgtype.Text
	var retractionPriorSource, retractionSourceVersion pgtype.Int4
	var retractionPriorTarget, retractionTargetVersion pgtype.Int4
	var retractedAt pgtype.Timestamptz
	var relatedID uuid.UUID
	if err := row.Scan(
		&relation.ID, &relation.SourceAlertID, &relation.TargetAlertID,
		&relation.Type, &relation.Reason, &priorSource, &sourceVersion,
		&priorTarget, &targetVersion, &relation.LinkedAt,
		&retractionReason, &retractionPriorSource, &retractionSourceVersion,
		&retractionPriorTarget, &retractionTargetVersion, &retractedAt,
		&relatedID,
	); err != nil {
		return application.AlertRelationRecord{}, uuid.Nil, mapTicketDatabaseError(err)
	}
	if priorSource < 1 || sourceVersion != priorSource+1 ||
		priorTarget < 1 || targetVersion != priorTarget+1 {
		return application.AlertRelationRecord{}, uuid.Nil, application.ErrUnavailable
	}
	relation.TenantID = tenantID
	relation.PreviousSourceVersion, relation.SourceVersion = uint64(priorSource), uint64(sourceVersion)
	relation.PreviousTargetVersion, relation.TargetVersion = uint64(priorTarget), uint64(targetVersion)
	relation.LinkedAt = ticketTime(relation.LinkedAt)
	if retractionReason.Valid != retractedAt.Valid ||
		retractionReason.Valid != retractionPriorSource.Valid ||
		retractionReason.Valid != retractionSourceVersion.Valid ||
		retractionReason.Valid != retractionPriorTarget.Valid ||
		retractionReason.Valid != retractionTargetVersion.Valid {
		return application.AlertRelationRecord{}, uuid.Nil, application.ErrUnavailable
	}
	if retractionReason.Valid {
		if retractionPriorSource.Int32 < 1 || retractionSourceVersion.Int32 != retractionPriorSource.Int32+1 ||
			retractionPriorTarget.Int32 < 1 || retractionTargetVersion.Int32 != retractionPriorTarget.Int32+1 {
			return application.AlertRelationRecord{}, uuid.Nil, application.ErrUnavailable
		}
		relation.Retraction = &application.AlertRelationRetraction{
			Reason:                retractionReason.String,
			PreviousSourceVersion: uint64(retractionPriorSource.Int32),
			SourceVersion:         uint64(retractionSourceVersion.Int32),
			PreviousTargetVersion: uint64(retractionPriorTarget.Int32),
			TargetVersion:         uint64(retractionTargetVersion.Int32),
			RetractedAt:           ticketTime(retractedAt.Time),
		}
	}
	direction := application.AlertRelationSymmetric
	if relation.Type == application.AlertRelationDuplicateOf {
		if relation.SourceAlertID == pathAlertID {
			direction = application.AlertRelationOutgoing
		} else {
			direction = application.AlertRelationIncoming
		}
	}
	if _, err := ticketEntityID(relatedID); err != nil {
		return application.AlertRelationRecord{}, uuid.Nil, err
	}
	return application.AlertRelationRecord{
		Relation: relation, Direction: direction,
	}, relatedID, nil
}

func alertRelationCommonAccessPredicate(
	access application.LiveAccess,
	sourceAlias string,
	targetAlias string,
	add func(any) string,
) (string, error) {
	if access.Authority.Principal() != kernel.PrincipalOperator {
		return "FALSE", application.ErrForbidden
	}
	parts := make([]string, 0, len(access.Scopes))
	for _, scope := range access.Scopes {
		switch scope {
		case application.ScopeTenant:
			parts = append(parts, "TRUE")
		case application.ScopeOwn:
			actor := add(uuid.UUID(access.Authority.Actor().Bytes()))
			parts = append(parts, "("+sourceAlias+".created_by = "+actor+" AND "+targetAlias+".created_by = "+actor+")")
		case application.ScopeAssigned:
			actor := add(uuid.UUID(access.Authority.Actor().Bytes()))
			parts = append(parts, "("+actor+" IN ("+sourceAlias+".assignee_user_id, "+sourceAlias+".claimed_by_user_id) AND "+actor+" IN ("+targetAlias+".assignee_user_id, "+targetAlias+".claimed_by_user_id))")
		case application.ScopeOperatorTeam:
			teams := make([]uuid.UUID, len(access.OperatorTeams))
			for index, team := range access.OperatorTeams {
				teams[index] = uuid.UUID(team.Bytes())
			}
			parameter := add(teams)
			parts = append(parts, "("+sourceAlias+".assigned_team_id = ANY("+parameter+"::uuid[]) AND "+targetAlias+".assigned_team_id = ANY("+parameter+"::uuid[]))")
		default:
			return "", application.ErrForbidden
		}
	}
	if len(parts) == 0 {
		return "FALSE", application.ErrForbidden
	}
	return "(" + strings.Join(parts, " OR ") + ")", nil
}

func (repository *TicketingRepository) CommitAlertRelationCreate(
	ctx context.Context,
	write application.AlertRelationCreateWrite,
) (application.AlertRelationMutationReceipt, error) {
	tenantID := uuid.UUID(write.Source.Snapshot.Tenant().Bytes())
	result, err := withinTicketWriteTransaction(ctx, repository, write.Actor, tenantID,
		func(tx databaseTransaction) (application.AlertRelationMutationReceipt, error) {
			return queryAlertRelationReceipt(ctx, tx, tenantID, uuid.UUID(write.Source.Snapshot.ID().Bytes()), uuid.UUID(write.Target.Snapshot.ID().Bytes()), uuid.Nil, `
				SELECT result_relation_id, result_relation_type,
				       previous_source_version, result_source_version,
				       previous_target_version, result_target_version,
				       linked_at, replayed
				FROM app.commit_tenant_alert_relation_create_v1(
				  $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13
				)`, uuid.UUID(write.Source.Snapshot.ID().Bytes()), uuid.UUID(write.Target.Snapshot.ID().Bytes()),
				string(write.Input.RelationType), write.Plan.PreviousSourceVersion(), write.Plan.PreviousTargetVersion(),
				write.Input.Reason, write.KeyHash[:], write.Fingerprint[:], write.Audit.RequestID,
				write.Audit.CorrelationID, write.Audit.RemoteAddress.Unmap(), write.Audit.UserAgent,
				write.Actor.AuthenticationMethod,
			)
		},
	)
	return result, mapTicketDatabaseError(err)
}

func (repository *TicketingRepository) LookupAlertRelationCreateReplay(
	ctx context.Context,
	query application.AlertRelationReplayQuery,
) (application.AlertRelationMutationReceipt, bool, error) {
	result, err := withinTicketActorTransaction(ctx, repository, query.Actor, query.TenantID,
		func(tx databaseTransaction) (application.AlertRelationMutationReceipt, error) {
			return queryAlertRelationReceipt(ctx, tx, query.TenantID, query.AlertID, query.RelatedAlertID, uuid.Nil, `
				SELECT result_relation_id, relation_type,
				       previous_source_version, result_source_version,
				       previous_target_version, result_target_version,
				       linked_at, true
				FROM app.lookup_tenant_alert_relation_create_replay_v1($1,$2,$3,$4)`,
				query.AlertID, query.RelatedAlertID, query.KeyHash[:], query.Fingerprint[:],
			)
		},
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return application.AlertRelationMutationReceipt{}, false, nil
	}
	if err != nil {
		return application.AlertRelationMutationReceipt{}, false, mapTicketDatabaseError(err)
	}
	return result, true, nil
}

func (repository *TicketingRepository) CommitAlertRelationRetraction(
	ctx context.Context,
	write application.AlertRelationRetractionWrite,
) (application.AlertRelationMutationReceipt, error) {
	tenantID := uuid.UUID(write.Alert.Snapshot.Tenant().Bytes())
	result, err := withinTicketWriteTransaction(ctx, repository, write.Actor, tenantID,
		func(tx databaseTransaction) (application.AlertRelationMutationReceipt, error) {
			return queryAlertRelationReceipt(ctx, tx, tenantID, uuid.UUID(write.Alert.Snapshot.ID().Bytes()), uuid.UUID(write.Related.Snapshot.ID().Bytes()), write.Relation.ID, `
				SELECT result_relation_id, result_relation_type,
				       previous_alert_version, result_alert_version,
				       previous_related_alert_version,
				       result_related_alert_version, retracted_at, replayed
				FROM app.commit_tenant_alert_relation_retract_v1(
				  $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13
				)`, uuid.UUID(write.Alert.Snapshot.ID().Bytes()), uuid.UUID(write.Related.Snapshot.ID().Bytes()),
				write.Relation.ID, write.Plan.PreviousSourceVersion(), write.Plan.PreviousTargetVersion(),
				write.Input.Reason, write.KeyHash[:], write.Fingerprint[:], write.Audit.RequestID,
				write.Audit.CorrelationID, write.Audit.RemoteAddress.Unmap(), write.Audit.UserAgent,
				write.Actor.AuthenticationMethod,
			)
		},
	)
	return result, mapTicketDatabaseError(err)
}

func (repository *TicketingRepository) LookupAlertRelationRetractionReplay(
	ctx context.Context,
	query application.AlertRelationReplayQuery,
) (application.AlertRelationMutationReceipt, bool, error) {
	result, err := withinTicketActorTransaction(ctx, repository, query.Actor, query.TenantID,
		func(tx databaseTransaction) (application.AlertRelationMutationReceipt, error) {
			return queryAlertRelationReceipt(ctx, tx, query.TenantID, query.AlertID, query.RelatedAlertID, query.RelationID, `
				SELECT result_relation_id, relation_type,
				       previous_alert_version, result_alert_version,
				       previous_related_alert_version,
				       result_related_alert_version, retracted_at, true
				FROM app.lookup_tenant_alert_relation_retract_replay_v1($1,$2,$3,$4,$5)`,
				query.AlertID, query.RelatedAlertID, query.RelationID, query.KeyHash[:], query.Fingerprint[:],
			)
		},
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return application.AlertRelationMutationReceipt{}, false, nil
	}
	if err != nil {
		return application.AlertRelationMutationReceipt{}, false, mapTicketDatabaseError(err)
	}
	return result, true, nil
}

func queryAlertRelationReceipt(
	ctx context.Context,
	tx databaseTransaction,
	tenantID uuid.UUID,
	pathAlertID uuid.UUID,
	relatedAlertID uuid.UUID,
	expectedRelationID uuid.UUID,
	statement string,
	arguments ...any,
) (application.AlertRelationMutationReceipt, error) {
	var receipt application.AlertRelationMutationReceipt
	var previousAlert, alertVersion, previousRelated, relatedVersion int32
	if err := tx.QueryRow(ctx, statement, arguments...).Scan(
		&receipt.RelationID, &receipt.RelationType,
		&previousAlert, &alertVersion, &previousRelated, &relatedVersion,
		&receipt.OccurredAt, &receipt.Replayed,
	); err != nil {
		return application.AlertRelationMutationReceipt{}, err
	}
	if previousAlert < 1 || alertVersion != previousAlert+1 ||
		previousRelated < 1 || relatedVersion != previousRelated+1 ||
		expectedRelationID != uuid.Nil && receipt.RelationID != expectedRelationID {
		return application.AlertRelationMutationReceipt{}, application.ErrUnavailable
	}
	var storedTenantID, sourceAlertID, targetAlertID uuid.UUID
	var storedType application.AlertRelationType
	if err := tx.QueryRow(ctx, `
		SELECT tenant_id, source_alert_id, target_alert_id, relation_type
		FROM public.alert_relations
		WHERE tenant_id = $1 AND id = $2`, tenantID, receipt.RelationID,
	).Scan(&storedTenantID, &sourceAlertID, &targetAlertID, &storedType); err != nil {
		return application.AlertRelationMutationReceipt{}, err
	}
	if storedTenantID != tenantID || storedType != receipt.RelationType ||
		!((sourceAlertID == pathAlertID && targetAlertID == relatedAlertID) ||
			(sourceAlertID == relatedAlertID && targetAlertID == pathAlertID)) {
		return application.AlertRelationMutationReceipt{}, application.ErrUnavailable
	}
	receipt.TenantID, receipt.AlertID, receipt.RelatedAlertID = tenantID, pathAlertID, relatedAlertID
	receipt.PreviousAlertVersion, receipt.AlertVersion = uint64(previousAlert), uint64(alertVersion)
	receipt.PreviousRelatedAlertVersion = uint64(previousRelated)
	receipt.RelatedAlertVersion = uint64(relatedVersion)
	receipt.OccurredAt = ticketTime(receipt.OccurredAt)
	return receipt, nil
}
