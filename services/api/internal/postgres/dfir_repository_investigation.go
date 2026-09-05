package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	kernel "github.com/periapsis-im/periapsis/modules/dfir"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	application "github.com/periapsis-im/periapsis/services/api/internal/dfir"
)

func (repository *DFIRRepository) CreateTimelineEvent(
	ctx context.Context,
	write application.TimelineWrite,
) (application.MutationResult[kernel.TimelineEvent], error) {
	if !validDFIRCommand(write.Command, "dfir.timeline.create") {
		return application.MutationResult[kernel.TimelineEvent]{}, application.ErrRepositoryConflict
	}
	if write.AlertID != (kernel.EntityID{}) {
		if write.CaseID != (kernel.EntityID{}) || write.Event.AlertID() != write.AlertID ||
			write.Event.CaseID() != (kernel.EntityID{}) {
			return application.MutationResult[kernel.TimelineEvent]{}, application.ErrRepositoryConflict
		}
		return repository.createAlertTimelineEvent(ctx, write)
	}
	if write.CaseID == (kernel.EntityID{}) || write.Event.CaseID() != write.CaseID ||
		write.Event.AlertID() != (kernel.EntityID{}) {
		return application.MutationResult[kernel.TimelineEvent]{}, application.ErrRepositoryConflict
	}
	tenantID := uuid.UUID(write.Event.TenantID().Bytes())
	caseID := uuid.UUID(write.CaseID.Bytes())
	id := uuid.UUID(write.Event.ID().Bytes())
	result, err := withinTransactionWithOptions(
		ctx, repository.begin, phase4WriteOptions(),
		func(tx databaseTransaction) (application.MutationResult[kernel.TimelineEvent], error) {
			if _, accessErr := authorizeDFIRWrite(ctx, tx, write.Actor, tenantID, application.CapabilityTimelineManage, caseID); accessErr != nil {
				return application.MutationResult[kernel.TimelineEvent]{}, accessErr
			}
			if linkErr := validateCaseTimelineLinks(ctx, tx, tenantID, caseID, write.Event); linkErr != nil {
				return application.MutationResult[kernel.TimelineEvent]{}, linkErr
			}
			ids, idErr := phase4NewIDs(repository.newID, 4)
			if idErr != nil {
				return application.MutationResult[kernel.TimelineEvent]{}, idErr
			}
			coordinate := dfirMutationCoordinate{
				tenantID: tenantID, rootKind: dfirMutationRootCase, rootID: caseID, operation: write.Command.Operation,
				resourceKind: dfirMutationKindTimeline, resourceID: id, resultVersion: 1,
			}
			reservation, reserveErr := reserveDFIRMutationCommand(ctx, tx, ids[0], coordinate, write.Command)
			if reserveErr != nil {
				return application.MutationResult[kernel.TimelineEvent]{}, reserveErr
			}
			if reservation.replayed {
				historical, decodeErr := decodeDFIRTimelineResult(reservation.snapshot, coordinate)
				if decodeErr != nil {
					return application.MutationResult[kernel.TimelineEvent]{}, decodeErr
				}
				return application.MutationResult[kernel.TimelineEvent]{Resource: historical, Replayed: true}, nil
			}
			_, _, loadErr := loadDFIRTimelineEvent(ctx, tx, tenantID, id)
			if loadErr == nil {
				return application.MutationResult[kernel.TimelineEvent]{}, application.ErrRepositoryConflict
			}
			if !errors.Is(loadErr, pgx.ErrNoRows) {
				return application.MutationResult[kernel.TimelineEvent]{}, loadErr
			}
			if insertErr := insertDFIRTimelineEvent(ctx, tx, write); insertErr != nil {
				return application.MutationResult[kernel.TimelineEvent]{}, insertErr
			}
			if linkErr := insertDFIRTimelineLinks(ctx, tx, write.Event); linkErr != nil {
				return application.MutationResult[kernel.TimelineEvent]{}, linkErr
			}
			kind := string(kernel.EntityCase)
			if effectErr := appendDFIRMutationEffects(ctx, tx, write.BaseWrite, ids[1:4], phase4MutationEffects{
				PermissionKey: "dfir.timeline.manage", Action: "dfir.timeline.created",
				ResourceType: "dfir_timeline_event", ResourceID: id, ResourceVersion: 1,
				CaseID: &caseID, ActivityResourceKind: &kind, ActivityResourceID: &caseID,
				Summary: "DFIR timeline event created", Before: map[string]any{},
				After:    dfirTimelineJournal(write.Event),
				Metadata: map[string]any{"commandOperation": write.Command.Operation},
			}); effectErr != nil {
				return application.MutationResult[kernel.TimelineEvent]{}, effectErr
			}
			stored, version, storedErr := loadDFIRTimelineEvent(ctx, tx, tenantID, id)
			if storedErr != nil || version != 1 || !sameDFIRTimelineEvent(stored, write.Event) {
				if storedErr != nil {
					return application.MutationResult[kernel.TimelineEvent]{}, storedErr
				}
				return application.MutationResult[kernel.TimelineEvent]{}, unexpectedDFIRProjection("divergent timeline event after create")
			}
			document, snapshotErr := encodeDFIRTimelineResult(coordinate, stored)
			if snapshotErr != nil {
				return application.MutationResult[kernel.TimelineEvent]{}, snapshotErr
			}
			if storeErr := storeDFIRMutationResult(ctx, tx, reservation.commandID, document); storeErr != nil {
				return application.MutationResult[kernel.TimelineEvent]{}, storeErr
			}
			return application.MutationResult[kernel.TimelineEvent]{Resource: stored}, nil
		},
	)
	return result, mapDFIRDatabaseError(err)
}

func insertDFIRTimelineEvent(ctx context.Context, tx databaseTransaction, write application.TimelineWrite) error {
	value := write.Event
	_, err := tx.Exec(ctx, `
		INSERT INTO public.dfir_timeline_events (
			id, tenant_id, alert_id, case_id, event_time, ingested_at, original_timezone,
			precision, source, category, title, description, actor_user_id,
			tags, created_by_membership_id, version
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8::public.dfir_temporal_precision,
			$9, $10, $11, $12, $13, $14, $15, 1)`,
		uuid.UUID(value.ID().Bytes()), uuid.UUID(value.TenantID().Bytes()),
		timelineRootUUID(value.AlertID()), timelineRootUUID(value.CaseID()), value.EventTime(), value.IngestedAt(),
		value.OriginalTimezone(), string(value.Precision()), value.Source(), value.Category(),
		value.Title(), value.Description(), optionalKernelUUID(value.ActorID()), append([]string{}, value.Tags()...),
		write.Actor.MembershipID)
	return err
}

func timelineRootUUID(value kernel.EntityID) any {
	if value == (kernel.EntityID{}) {
		return nil
	}
	return uuid.UUID(value.Bytes())
}

func insertDFIRTimelineLinks(ctx context.Context, tx databaseTransaction, value kernel.TimelineEvent) error {
	sets := []struct {
		table, column string
		values        []kernel.EntityID
	}{
		{"public.dfir_timeline_ioc_links", "ioc_id", value.IOCIDs()},
		{"public.dfir_timeline_asset_links", "asset_id", value.AssetIDs()},
		{"public.dfir_timeline_evidence_links", "evidence_id", value.EvidenceIDs()},
	}
	for _, set := range sets {
		for _, identifier := range set.values {
			if _, err := tx.Exec(ctx, "INSERT INTO "+set.table+" (tenant_id, timeline_event_id, "+set.column+") VALUES ($1, $2, $3)",
				uuid.UUID(value.TenantID().Bytes()), uuid.UUID(value.ID().Bytes()), uuid.UUID(identifier.Bytes())); err != nil {
				return err
			}
		}
	}
	return nil
}

func resolveDFIRTaskEpoch(
	ctx context.Context,
	tx databaseTransaction,
	tenantID uuid.UUID,
	teamID *kernel.EntityID,
	assigneeID *kernel.EntityID,
) (*uuid.UUID, error) {
	if teamID == nil {
		if assigneeID != nil {
			return nil, authorization.ErrForbidden
		}
		return nil, nil
	}
	teamUUID := uuid.UUID(teamID.Bytes())
	rows, err := tx.Query(ctx, `SELECT id FROM public.operator_team_assignment_epochs
		WHERE tenant_id = $1 AND operator_team_id = $2 AND ended_at IS NULL
		ORDER BY assigned_at DESC, id DESC LIMIT 2`, tenantID, teamUUID)
	if err != nil {
		return nil, err
	}
	var epochs []uuid.UUID
	for rows.Next() {
		var value uuid.UUID
		if scanErr := rows.Scan(&value); scanErr != nil {
			rows.Close()
			return nil, scanErr
		}
		epochs = append(epochs, value)
	}
	rows.Close()
	if rows.Err() != nil {
		return nil, rows.Err()
	}
	if len(epochs) != 1 {
		return nil, authorization.ErrForbidden
	}
	if assigneeID != nil {
		var allowed bool
		err = tx.QueryRow(ctx, `SELECT EXISTS (
			SELECT 1 FROM public.tenant_memberships AS membership
			JOIN public.operator_team_roster_entries AS roster
			  ON roster.tenant_id = membership.tenant_id
			 AND roster.membership_id = membership.id
			JOIN public.tenant_authorization_sources AS source
			  ON source.tenant_id = roster.tenant_id AND source.id = roster.source_id
			WHERE membership.tenant_id = $1 AND membership.user_id = $2
			  AND membership.status = 'active'
			  AND roster.assignment_epoch_id = $3 AND roster.revoked_at IS NULL
			  AND (roster.expires_at IS NULL OR roster.expires_at > transaction_timestamp())
			  AND source.retired_at IS NULL
		)`, tenantID, uuid.UUID(assigneeID.Bytes()), epochs[0]).Scan(&allowed)
		if err != nil {
			return nil, err
		}
		if !allowed {
			return nil, authorization.ErrForbidden
		}
	}
	return &epochs[0], nil
}

func encodeDFIRChecklist(values []kernel.ChecklistItem) ([]byte, error) {
	result := make([]dfirChecklistJSON, len(values))
	for index, value := range values {
		result[index] = dfirChecklistJSON{ID: value.ID().String(), Title: value.Title(), Completed: value.Completed()}
		if completedAt := value.CompletedAt(); completedAt != nil {
			formatted := completedAt.UTC().Format(time.RFC3339Nano)
			result[index].CompletedAt = &formatted
		}
		if completedBy := value.CompletedBy(); completedBy != nil {
			formatted := completedBy.String()
			result[index].CompletedBy = &formatted
		}
	}
	return json.Marshal(result)
}

func (repository *DFIRRepository) CreateRelationship(
	ctx context.Context,
	write application.RelationshipWrite,
) (application.MutationResult[kernel.Relationship], error) {
	if !validDFIRCommand(write.Command, "dfir.relationship.create") {
		return application.MutationResult[kernel.Relationship]{}, application.ErrRepositoryConflict
	}
	tenantID := uuid.UUID(write.Relationship.TenantID().Bytes())
	caseID := uuid.UUID(write.CaseID.Bytes())
	id := uuid.UUID(write.Relationship.ID().Bytes())
	if !authorizationUUIDv7(caseID) || write.AlertID != (kernel.EntityID{}) {
		return application.MutationResult[kernel.Relationship]{}, application.ErrRepositoryForbidden
	}
	result, err := withinTransactionWithOptions(
		ctx, repository.begin, phase4WriteOptions(),
		func(tx databaseTransaction) (application.MutationResult[kernel.Relationship], error) {
			if _, accessErr := authorizeDFIRWrite(ctx, tx, write.Actor, tenantID, application.CapabilityRelationshipManage, caseID); accessErr != nil {
				return application.MutationResult[kernel.Relationship]{}, accessErr
			}
			if endpointErr := validateDFIRRelationshipEndpoints(
				ctx, tx, write.Actor, tenantID, dfirMutationRootCase, caseID,
				write.Relationship.Source(), write.Relationship.Target(),
			); endpointErr != nil {
				return application.MutationResult[kernel.Relationship]{}, endpointErr
			}
			ids, idErr := phase4NewIDs(repository.newID, 4)
			if idErr != nil {
				return application.MutationResult[kernel.Relationship]{}, idErr
			}
			coordinate := dfirMutationCoordinate{
				tenantID: tenantID, rootKind: dfirMutationRootCase, rootID: caseID, operation: write.Command.Operation,
				resourceKind: dfirMutationKindRelationship, resourceID: id, resultVersion: 1,
			}
			reservation, reserveErr := reserveDFIRMutationCommand(ctx, tx, ids[0], coordinate, write.Command)
			if reserveErr != nil {
				return application.MutationResult[kernel.Relationship]{}, reserveErr
			}
			if reservation.replayed {
				historical, decodeErr := decodeDFIRRelationshipResult(reservation.snapshot, coordinate)
				if decodeErr != nil {
					return application.MutationResult[kernel.Relationship]{}, decodeErr
				}
				return application.MutationResult[kernel.Relationship]{Resource: historical, Replayed: true}, nil
			}
			_, loadErr := loadDFIRRelationship(ctx, tx, tenantID, caseID, id)
			if loadErr == nil {
				return application.MutationResult[kernel.Relationship]{}, application.ErrRepositoryConflict
			}
			if !errors.Is(loadErr, pgx.ErrNoRows) {
				return application.MutationResult[kernel.Relationship]{}, loadErr
			}
			if insertErr := insertDFIRRelationship(ctx, tx, write); insertErr != nil {
				return application.MutationResult[kernel.Relationship]{}, insertErr
			}
			kind := string(kernel.EntityCase)
			if effectErr := appendDFIRMutationEffects(ctx, tx, write.BaseWrite, ids[1:4], phase4MutationEffects{
				PermissionKey: "dfir.relationship.manage", Action: "dfir.relationship.created",
				ResourceType: "dfir_relationship", ResourceID: id, ResourceVersion: 1,
				CaseID: &caseID, ActivityResourceKind: &kind, ActivityResourceID: &caseID,
				Summary: "DFIR relationship created", Before: map[string]any{},
				After:    map[string]any{"version": 1, "relationshipType": write.Relationship.RelationshipType()},
				Metadata: map[string]any{"commandOperation": write.Command.Operation},
			}); effectErr != nil {
				return application.MutationResult[kernel.Relationship]{}, effectErr
			}
			stored, storedErr := loadDFIRRelationship(ctx, tx, tenantID, caseID, id)
			if storedErr != nil || !sameDFIRRelationship(stored, write.Relationship) {
				if storedErr != nil {
					return application.MutationResult[kernel.Relationship]{}, storedErr
				}
				return application.MutationResult[kernel.Relationship]{}, unexpectedDFIRProjection("divergent relationship after create")
			}
			document, snapshotErr := encodeDFIRRelationshipResult(coordinate, stored)
			if snapshotErr != nil {
				return application.MutationResult[kernel.Relationship]{}, snapshotErr
			}
			if storeErr := storeDFIRMutationResult(ctx, tx, reservation.commandID, document); storeErr != nil {
				return application.MutationResult[kernel.Relationship]{}, storeErr
			}
			return application.MutationResult[kernel.Relationship]{Resource: stored}, nil
		},
	)
	return result, mapDFIRDatabaseError(err)
}

func insertDFIRRelationship(ctx context.Context, tx databaseTransaction, write application.RelationshipWrite) error {
	value := write.Relationship
	sourceID, sourceType, sourceExternal := dfirReferenceDatabaseValues(value.Source())
	targetID, targetType, targetExternal := dfirReferenceDatabaseValues(value.Target())
	_, err := tx.Exec(ctx, `
		INSERT INTO public.dfir_relationships (
			id, tenant_id, alert_id, case_id, source_kind, source_id, source_external_type,
			source_external_id, target_kind, target_id, target_external_type,
			target_external_id, relationship_type, metadata,
			created_by_membership_id, version, created_at
		) VALUES ($1, $2, NULL, $3, $4::public.dfir_entity_kind, $5, $6, $7,
			$8::public.dfir_entity_kind, $9, $10, $11, $12, $13::jsonb, $14, 1, $15)`,
		uuid.UUID(value.ID().Bytes()), uuid.UUID(value.TenantID().Bytes()), uuid.UUID(write.CaseID.Bytes()),
		string(value.Source().Kind()), sourceID, sourceType, sourceExternal, string(value.Target().Kind()), targetID,
		targetType, targetExternal, value.RelationshipType(), nullableJSON(value.Metadata()),
		write.Actor.MembershipID, value.CreatedAt())
	return err
}

func dfirReferenceDatabaseValues(value kernel.EntityReference) (any, any, any) {
	if value.Kind() == kernel.EntityExternal {
		return nil, value.ExternalType(), value.ExternalID()
	}
	return uuid.UUID(value.ID().Bytes()), nil, nil
}

const maximumDFIRRelationshipEndpointFanout = 64

// validateDFIRRelationshipEndpoints re-resolves every endpoint inside the
// mutation transaction before reserving an idempotency key. A receipt can
// therefore never preserve a relationship to a stale, cross-root, or
// currently unauthorized resource.
func validateDFIRRelationshipEndpoints(
	ctx context.Context,
	tx databaseTransaction,
	actor application.Actor,
	tenantID uuid.UUID,
	rootKind string,
	rootID uuid.UUID,
	references ...kernel.EntityReference,
) error {
	if (rootKind != dfirMutationRootCase && rootKind != dfirMutationRootAlert) ||
		!authorizationUUIDv7(rootID) || len(references) == 0 ||
		len(references) > maximumDFIRRelationshipEndpointFanout {
		return authorization.ErrForbidden
	}
	for _, reference := range references {
		if uuid.UUID(reference.TenantID().Bytes()) != tenantID {
			return authorization.ErrForbidden
		}
		if reference.Kind() == kernel.EntityExternal {
			continue
		}
		if reference.ID() == (kernel.EntityID{}) {
			return authorization.ErrForbidden
		}
		identifier := uuid.UUID(reference.ID().Bytes())
		switch reference.Kind() {
		case kernel.EntityCase:
			if rootKind == dfirMutationRootCase && identifier == rootID {
				continue
			}
			if _, err := resolveDFIRAccessInTransaction(
				ctx, tx, actor, tenantID, application.CapabilityRelationshipManage, reference.ID(),
			); err != nil {
				return hideDFIRRelationshipEndpointError(err)
			}
		case kernel.EntityAlert:
			if rootKind == dfirMutationRootAlert && identifier == rootID {
				continue
			}
			if _, err := resolveDFIRAlertAccessInTransaction(
				ctx, tx, actor, tenantID, application.CapabilityRelationshipManage, reference.ID(),
			); err != nil {
				return hideDFIRRelationshipEndpointError(err)
			}
		case kernel.EntityIOC, kernel.EntityAsset, kernel.EntityEvidence,
			kernel.EntityTask, kernel.EntityAttachment:
			valid, err := validateDFIRRelationshipResourceEndpoint(
				ctx, tx, tenantID, rootKind, rootID, reference.Kind(), identifier,
			)
			if err != nil {
				return err
			}
			if !valid {
				return authorization.ErrForbidden
			}
		default:
			return authorization.ErrForbidden
		}
	}
	return nil
}

func hideDFIRRelationshipEndpointError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, authorization.ErrForbidden) ||
		errors.Is(err, authorization.ErrNotFound) || errors.Is(err, application.ErrRepositoryForbidden) ||
		errors.Is(err, application.ErrRepositoryNotFound) {
		return authorization.ErrForbidden
	}
	return err
}

func validateDFIRRelationshipResourceEndpoint(
	ctx context.Context,
	tx databaseTransaction,
	tenantID uuid.UUID,
	rootKind string,
	rootID uuid.UUID,
	resourceKind kernel.EntityKind,
	resourceID uuid.UUID,
) (bool, error) {
	var valid bool
	err := tx.QueryRow(ctx, `
		SELECT CASE
		  WHEN $2 = 'case' AND $4 = 'ioc' THEN EXISTS (
		    SELECT 1 FROM public.dfir_ioc_links AS link
		    JOIN public.dfir_iocs AS resource
		      ON resource.tenant_id = link.tenant_id AND resource.id = link.ioc_id
		    WHERE link.tenant_id = $1 AND link.case_id = $3 AND link.alert_id IS NULL
		      AND link.ioc_id = $5 AND resource.archived_at IS NULL
		  )
		  WHEN $2 = 'alert' AND $4 = 'ioc' THEN EXISTS (
		    SELECT 1 FROM public.dfir_ioc_links AS link
		    JOIN public.dfir_iocs AS resource
		      ON resource.tenant_id = link.tenant_id AND resource.id = link.ioc_id
		    WHERE link.tenant_id = $1 AND link.alert_id = $3 AND link.case_id IS NULL
		      AND link.ioc_id = $5 AND resource.archived_at IS NULL
		  )
		  WHEN $2 = 'case' AND $4 = 'asset' THEN EXISTS (
		    SELECT 1 FROM public.dfir_asset_links AS link
		    JOIN public.dfir_assets AS resource
		      ON resource.tenant_id = link.tenant_id AND resource.id = link.asset_id
		    WHERE link.tenant_id = $1 AND link.case_id = $3 AND link.alert_id IS NULL
		      AND link.asset_id = $5 AND resource.archived_at IS NULL
		  )
		  WHEN $2 = 'alert' AND $4 = 'asset' THEN EXISTS (
		    SELECT 1 FROM public.dfir_asset_links AS link
		    JOIN public.dfir_assets AS resource
		      ON resource.tenant_id = link.tenant_id AND resource.id = link.asset_id
		    WHERE link.tenant_id = $1 AND link.alert_id = $3 AND link.case_id IS NULL
		      AND link.asset_id = $5 AND resource.archived_at IS NULL
		  )
		  WHEN $2 = 'case' AND $4 = 'evidence' THEN EXISTS (
		    SELECT 1 FROM public.dfir_evidence AS resource
		    WHERE resource.tenant_id = $1 AND resource.case_id = $3 AND resource.alert_id IS NULL
		      AND resource.id = $5 AND resource.destroyed = false AND resource.scan_state <> 'deleted'
		  )
		  WHEN $2 = 'alert' AND $4 = 'evidence' THEN EXISTS (
		    SELECT 1 FROM public.dfir_evidence AS resource
		    WHERE resource.tenant_id = $1 AND resource.alert_id = $3 AND resource.case_id IS NULL
		      AND resource.id = $5 AND resource.destroyed = false AND resource.scan_state <> 'deleted'
		  )
		  WHEN $2 = 'case' AND $4 = 'task' THEN EXISTS (
		    SELECT 1 FROM public.dfir_tasks AS resource
		    WHERE resource.tenant_id = $1 AND resource.case_id = $3 AND resource.alert_id IS NULL
		      AND resource.id = $5
		  )
		  WHEN $2 = 'alert' AND $4 = 'task' THEN EXISTS (
		    SELECT 1 FROM public.dfir_tasks AS resource
		    WHERE resource.tenant_id = $1 AND resource.alert_id = $3 AND resource.case_id IS NULL
		      AND resource.id = $5
		  )
		  WHEN $4 = 'attachment' THEN app.dfir_attachment_belongs_to_root_v1($1, $2, $3, $5)
		  ELSE false
		END`, tenantID, rootKind, rootID, string(resourceKind), resourceID).Scan(&valid)
	return valid, err
}

func validateCaseTimelineLinks(
	ctx context.Context,
	tx databaseTransaction,
	tenantID uuid.UUID,
	caseID uuid.UUID,
	event kernel.TimelineEvent,
) error {
	for _, candidate := range []struct {
		linkTable, resourceTable, column string
		ids                              []kernel.EntityID
	}{
		{linkTable: "public.dfir_ioc_links", resourceTable: "public.dfir_iocs", column: "ioc_id", ids: event.IOCIDs()},
		{linkTable: "public.dfir_asset_links", resourceTable: "public.dfir_assets", column: "asset_id", ids: event.AssetIDs()},
	} {
		if len(candidate.ids) == 0 {
			continue
		}
		ids := kernelUUIDs(candidate.ids)
		var count int64
		err := tx.QueryRow(ctx, "SELECT count(DISTINCT link."+candidate.column+") FROM "+candidate.linkTable+" AS link"+
			" JOIN "+candidate.resourceTable+" AS resource ON resource.tenant_id = link.tenant_id AND resource.id = link."+candidate.column+
			" WHERE link.tenant_id = $1 AND link.case_id = $2 AND link.alert_id IS NULL AND link."+candidate.column+" = ANY($3::uuid[])"+
			" AND resource.archived_at IS NULL", tenantID, caseID, ids).Scan(&count)
		if err != nil {
			return err
		}
		if count != int64(len(ids)) {
			return authorization.ErrForbidden
		}
	}
	if evidenceIDs := event.EvidenceIDs(); len(evidenceIDs) != 0 {
		ids := kernelUUIDs(evidenceIDs)
		var count int64
		if err := tx.QueryRow(ctx, `SELECT count(DISTINCT evidence.id)
			FROM public.dfir_evidence AS evidence
			WHERE evidence.tenant_id = $1 AND evidence.case_id = $2
			  AND evidence.alert_id IS NULL AND evidence.id = ANY($3::uuid[])
			  AND evidence.destroyed = false AND evidence.scan_state <> 'deleted'`, tenantID, caseID, ids).Scan(&count); err != nil {
			return err
		}
		if count != int64(len(ids)) {
			return authorization.ErrForbidden
		}
	}
	return nil
}

func sameDFIRTimelineEvent(left, right kernel.TimelineEvent) bool {
	return sameDFIRTimelineRequest(left, right) && left.IngestedAt().Equal(right.IngestedAt())
}

func sameDFIRTimelineRequest(left, right kernel.TimelineEvent) bool {
	return left.ID() == right.ID() && left.TenantID() == right.TenantID() &&
		left.AlertID() == right.AlertID() && left.CaseID() == right.CaseID() &&
		left.EventTime().Equal(right.EventTime()) &&
		left.OriginalTimezone() == right.OriginalTimezone() && left.Precision() == right.Precision() &&
		left.Source() == right.Source() && left.Category() == right.Category() && left.Title() == right.Title() &&
		left.Description() == right.Description() && sameOptionalKernelID(left.ActorID(), right.ActorID()) &&
		slices.Equal(left.IOCIDs(), right.IOCIDs()) && slices.Equal(left.AssetIDs(), right.AssetIDs()) &&
		slices.Equal(left.EvidenceIDs(), right.EvidenceIDs()) && slices.Equal(left.Tags(), right.Tags())
}

func sameDFIRTask(left, right kernel.Task) bool {
	leftJSON, leftErr := json.Marshal(dfirTaskComparable(left))
	rightJSON, rightErr := json.Marshal(dfirTaskComparable(right))
	return leftErr == nil && rightErr == nil && slices.Equal(leftJSON, rightJSON)
}

func dfirTaskComparable(value kernel.Task) map[string]any {
	checklist, _ := encodeDFIRChecklist(value.Checklist())
	return map[string]any{
		"id": value.ID().String(), "tenant": value.TenantID().String(), "case": value.CaseID().String(),
		"title": value.Title(), "description": value.Description(), "status": value.Status(),
		"priority": value.Priority(), "assignee": optionalKernelIDString(value.AssigneeID()),
		"team": optionalKernelIDString(value.OperatorTeamID()), "dueAt": value.DueAt(),
		"checklist": json.RawMessage(checklist), "completedAt": value.CompletedAt(),
		"completedBy": optionalKernelIDString(value.CompletedBy()), "completionData": value.CompletionData(),
		"comments": kernelUUIDs(value.CommentIDs()), "sla": optionalKernelIDString(value.SLAInstanceID()),
		"createdAt": value.CreatedAt(), "updatedAt": value.UpdatedAt(), "version": value.Version(),
	}
}

func sameDFIRRelationship(left, right kernel.Relationship) bool {
	leftJSON, leftErr := json.Marshal(dfirRelationshipSnapshot(left))
	rightJSON, rightErr := json.Marshal(dfirRelationshipSnapshot(right))
	return leftErr == nil && rightErr == nil && slices.Equal(leftJSON, rightJSON)
}

func dfirReferenceComparable(value kernel.EntityReference) map[string]string {
	return map[string]string{
		"tenant": value.TenantID().String(), "kind": string(value.Kind()), "id": value.ID().String(),
		"externalType": value.ExternalType(), "externalId": value.ExternalID(),
	}
}

func dfirTimelineJournal(value kernel.TimelineEvent) map[string]any {
	return map[string]any{
		"version": 1, "precision": value.Precision(), "category": value.Category(),
		"iocCount": len(value.IOCIDs()), "assetCount": len(value.AssetIDs()),
		"evidenceCount": len(value.EvidenceIDs()), "tagCount": len(value.Tags()),
	}
}

func dfirTaskJournal(value kernel.Task) map[string]any {
	return map[string]any{
		"version": value.Version(), "status": value.Status(), "priority": value.Priority(),
		"assigned": value.AssigneeID() != nil, "teamAssigned": value.OperatorTeamID() != nil,
		"checklistCount": len(value.Checklist()), "commentCount": len(value.CommentIDs()),
		"hasSla": value.SLAInstanceID() != nil,
	}
}

func optionalKernelUUID(value *kernel.EntityID) any {
	if value == nil {
		return nil
	}
	return uuid.UUID(value.Bytes())
}

func optionalKernelIDString(value *kernel.EntityID) any {
	if value == nil {
		return nil
	}
	return value.String()
}

func sameOptionalKernelID(left, right *kernel.EntityID) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func kernelUUIDs(values []kernel.EntityID) []uuid.UUID {
	result := make([]uuid.UUID, len(values))
	for index, value := range values {
		result[index] = uuid.UUID(value.Bytes())
	}
	return result
}
