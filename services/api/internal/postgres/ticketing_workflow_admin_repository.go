package postgres

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	application "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

const workflowAdminRecordProjection = `
workflow.id, workflow.aggregate_kind::text, workflow.key,
workflow.display_name, workflow.description, workflow.is_default,
workflow.current_version, workflow.revision, workflow.archived_at,
workflow.created_at, workflow.updated_at,
version.states, version.transitions`

var _ application.WorkflowAdminRepository = (*TicketingRepository)(nil)

func (repository *TicketingRepository) ResolveWorkflowAdminAccess(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	capability application.WorkflowAdminCapability,
) (application.WorkflowAdminAccess, error) {
	return withinTicketActorTransactionWithOptions(
		ctx, repository, actor, tenantID,
		pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadOnly},
		func(tx databaseTransaction) (application.WorkflowAdminAccess, error) {
			return resolveWorkflowAdminAccessInTransaction(ctx, tx, actor, tenantID, capability)
		},
	)
}

func (repository *TicketingRepository) ReserveWorkflowID(
	_ context.Context,
	tenantID uuid.UUID,
) (kernel.EntityID, error) {
	if repository == nil || repository.newID == nil || !authorizationUUIDv7(tenantID) {
		return kernel.EntityID{}, application.ErrConflict
	}
	identifier, err := repository.newID()
	if err != nil || !authorizationUUIDv7(identifier) {
		return kernel.EntityID{}, application.ErrConflict
	}
	return ticketEntityID(identifier)
}

func (repository *TicketingRepository) ListWorkflows(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	input application.WorkflowAdminListInput,
	claimed application.WorkflowAdminAccess,
) (application.WorkflowAdminPage, error) {
	after, err := decodeWorkflowAdminCursor(input.After)
	if err != nil {
		return application.WorkflowAdminPage{}, err
	}
	return withinTicketActorTransactionWithOptions(
		ctx, repository, actor, tenantID,
		pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadOnly},
		func(tx databaseTransaction) (application.WorkflowAdminPage, error) {
			if err := recheckWorkflowAdminAccess(ctx, tx, actor, tenantID, application.WorkflowCapabilityRead, claimed); err != nil {
				return application.WorkflowAdminPage{}, err
			}
			var kind, status any
			if input.Kind != nil {
				kind = input.Kind.String()
			}
			if input.Status != nil {
				status = input.Status.String()
			}
			rows, err := tx.Query(ctx, `
				SELECT `+workflowAdminRecordProjection+`
				FROM public.ticket_workflows AS workflow
				JOIN public.ticket_workflow_versions AS version
				  ON version.tenant_id = workflow.tenant_id
				 AND version.workflow_id = workflow.id
				 AND version.aggregate_kind = workflow.aggregate_kind
				 AND version.version = workflow.current_version
				WHERE workflow.tenant_id = $1
				  AND ($2::public.ticket_aggregate_kind IS NULL OR workflow.aggregate_kind = $2)
				  AND ($3::text IS NULL OR
				       CASE WHEN workflow.archived_at IS NULL THEN 'active' ELSE 'archived' END = $3)
				  AND (NOT $4 OR workflow.is_default)
				  AND ($5::text = '' OR position(lower($5) in lower(
				       workflow.key || ' ' || workflow.display_name || ' ' || workflow.description)) > 0)
				  AND ($6::uuid IS NULL OR workflow.id > $6)
				ORDER BY workflow.id
				LIMIT $7`, tenantID, kind, status, input.DefaultOnly, input.Search,
				nullableWorkflowAdminUUID(after), input.Limit+1)
			if err != nil {
				return application.WorkflowAdminPage{}, mapWorkflowAdminDatabaseError(err)
			}
			defer rows.Close()
			items := make([]application.WorkflowAdminRecord, 0, input.Limit+1)
			for rows.Next() {
				record, err := scanWorkflowAdminRecord(rows, tenantID)
				if err != nil {
					return application.WorkflowAdminPage{}, err
				}
				items = append(items, record)
			}
			if err := rows.Err(); err != nil {
				return application.WorkflowAdminPage{}, mapWorkflowAdminDatabaseError(err)
			}
			page := application.WorkflowAdminPage{Items: items}
			if len(items) > input.Limit {
				page.Items = items[:input.Limit]
				page.NextCursor = encodeWorkflowAdminCursor(workflowAdminUUID(page.Items[len(page.Items)-1].Workflow.ID()))
			}
			return page, nil
		},
	)
}

func (repository *TicketingRepository) GetWorkflow(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	workflowID uuid.UUID,
	claimed application.WorkflowAdminAccess,
) (application.WorkflowAdminRecord, error) {
	return repository.getWorkflowWithAccess(ctx, actor, tenantID, workflowID, claimed, application.WorkflowCapabilityRead)
}

func (repository *TicketingRepository) GetDefaultWorkflow(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	claimed application.WorkflowAdminAccess,
) (application.WorkflowAdminRecord, bool, error) {
	type defaultResult struct {
		record application.WorkflowAdminRecord
		found  bool
	}
	result, err := withinTicketActorTransactionWithOptions(
		ctx, repository, actor, tenantID,
		pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadOnly},
		func(tx databaseTransaction) (defaultResult, error) {
			if err := recheckWorkflowAdminAccess(ctx, tx, actor, tenantID, application.WorkflowCapabilityManage, claimed); err != nil {
				return defaultResult{}, err
			}
			record, err := readWorkflowAdminRecord(ctx, tx, tenantID, uuid.Nil, kind, true)
			if errors.Is(err, application.ErrNotFound) {
				return defaultResult{}, nil
			}
			if err != nil {
				return defaultResult{}, err
			}
			return defaultResult{record: record, found: true}, nil
		},
	)
	return result.record, result.found, err
}

func (repository *TicketingRepository) ListWorkflowVersions(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	workflowID uuid.UUID,
	input application.WorkflowVersionListInput,
	claimed application.WorkflowAdminAccess,
) (application.WorkflowVersionPage, error) {
	return withinTicketActorTransactionWithOptions(
		ctx, repository, actor, tenantID,
		pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadOnly},
		func(tx databaseTransaction) (application.WorkflowVersionPage, error) {
			if err := recheckWorkflowAdminAccess(ctx, tx, actor, tenantID, application.WorkflowCapabilityRead, claimed); err != nil {
				return application.WorkflowVersionPage{}, err
			}
			after := int64(math.MaxInt32) + 1
			if input.AfterVersion != 0 {
				after = int64(input.AfterVersion)
			}
			rows, err := tx.Query(ctx, `
				SELECT version.workflow_id, version.aggregate_kind::text, version.version,
				       version.states, version.transitions,
				       version.published_by_membership_id, publisher.display_name,
				       version.published_at
				FROM public.ticket_workflow_versions AS version
				LEFT JOIN public.tenant_user_profiles AS publisher
				  ON publisher.tenant_id = version.tenant_id
				 AND publisher.membership_id = version.published_by_membership_id
				WHERE version.tenant_id = $1 AND version.workflow_id = $2
				  AND version.version < $3
				ORDER BY version.version DESC
				LIMIT $4`, tenantID, workflowID, after, input.Limit+1)
			if err != nil {
				return application.WorkflowVersionPage{}, mapWorkflowAdminDatabaseError(err)
			}
			defer rows.Close()
			items := make([]application.WorkflowVersionRecord, 0, input.Limit+1)
			for rows.Next() {
				version, err := scanWorkflowVersionRecord(rows, tenantID)
				if err != nil {
					return application.WorkflowVersionPage{}, err
				}
				items = append(items, version)
			}
			if err := rows.Err(); err != nil {
				return application.WorkflowVersionPage{}, mapWorkflowAdminDatabaseError(err)
			}
			page := application.WorkflowVersionPage{Items: items}
			if len(items) > input.Limit {
				page.Items = items[:input.Limit]
				page.NextVersion = page.Items[len(page.Items)-1].Definition.Version()
			}
			return page, nil
		},
	)
}

func (repository *TicketingRepository) GetWorkflowVersion(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	workflowID uuid.UUID,
	version uint64,
	claimed application.WorkflowAdminAccess,
) (application.WorkflowVersionRecord, error) {
	return withinTicketActorTransactionWithOptions(
		ctx, repository, actor, tenantID,
		pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadOnly},
		func(tx databaseTransaction) (application.WorkflowVersionRecord, error) {
			if err := recheckWorkflowAdminAccess(ctx, tx, actor, tenantID, application.WorkflowCapabilityRead, claimed); err != nil {
				return application.WorkflowVersionRecord{}, err
			}
			row := tx.QueryRow(ctx, `
				SELECT version.workflow_id, version.aggregate_kind::text, version.version,
				       version.states, version.transitions,
				       version.published_by_membership_id, publisher.display_name,
				       version.published_at
				FROM public.ticket_workflow_versions AS version
				LEFT JOIN public.tenant_user_profiles AS publisher
				  ON publisher.tenant_id = version.tenant_id
				 AND publisher.membership_id = version.published_by_membership_id
				WHERE version.tenant_id = $1 AND version.workflow_id = $2 AND version.version = $3`,
				tenantID, workflowID, version)
			return scanWorkflowVersionRecord(row, tenantID)
		},
	)
}

func (repository *TicketingRepository) LookupWorkflowAdminReplay(
	ctx context.Context,
	query application.WorkflowAdminReplayQuery,
) (application.WorkflowAdminMutationResult, bool, error) {
	if repository == nil || repository.begin == nil || !authorizationUUIDv7(query.TenantID) ||
		!authorizationUUIDv7(query.ActorID) || query.Action.String() == "unknown" {
		return application.WorkflowAdminMutationResult{}, false, application.ErrConflict
	}
	type replayResult struct {
		mutation application.WorkflowAdminMutationResult
		found    bool
	}
	actor := application.Actor{UserID: query.ActorID, ActiveTenantID: query.TenantID}
	result, err := withinTicketActorTransactionWithOptions(
		ctx, repository, actor, query.TenantID,
		pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly},
		func(tx databaseTransaction) (replayResult, error) {
			var fingerprint []byte
			var workflowID uuid.UUID
			var resultRevision int64
			var snapshot []byte
			err := tx.QueryRow(ctx, `
				SELECT workflow_id, request_fingerprint, result_revision, result_snapshot
				FROM app.lookup_ticket_workflow_admin_replay_v1($1, $2, $3, $4)`,
				query.TenantID, query.ActorID, query.Action.String(), query.KeyHash[:],
			).Scan(&workflowID, &fingerprint, &resultRevision, &snapshot)
			if errors.Is(err, pgx.ErrNoRows) {
				return replayResult{}, nil
			}
			if err != nil {
				return replayResult{}, mapWorkflowAdminDatabaseError(err)
			}
			if len(fingerprint) != len(query.Fingerprint) ||
				subtle.ConstantTimeCompare(fingerprint, query.Fingerprint[:]) != 1 ||
				!authorizationUUIDv7(workflowID) {
				return replayResult{}, application.ErrConflict
			}
			record, err := mapWorkflowAdminCommandSnapshot(
				snapshot, query.TenantID, query.Action.String(), workflowID, resultRevision,
			)
			if err != nil {
				return replayResult{}, err
			}
			return replayResult{
				mutation: application.WorkflowAdminMutationResult{Record: record, Replayed: true},
				found:    true,
			}, nil
		},
	)
	if err != nil {
		return application.WorkflowAdminMutationResult{}, false, mapWorkflowAdminDatabaseError(err)
	}
	return result.mutation, result.found, nil
}

func (repository *TicketingRepository) CommitWorkflow(
	ctx context.Context,
	write application.WorkflowAdminWrite,
) (application.WorkflowAdminMutationResult, error) {
	if repository == nil || repository.begin == nil || repository.newID == nil ||
		write.RequiredCapability != application.WorkflowCapabilityManage ||
		write.Command.Action != write.Plan.Action() || write.Command.Action.String() == "unknown" {
		return application.WorkflowAdminMutationResult{}, application.ErrConflict
	}
	next := write.Plan.Next()
	tenantID := workflowAdminUUID(next.Tenant())
	workflowID := workflowAdminUUID(next.ID())
	if !authorizationUUIDv7(tenantID) || !authorizationUUIDv7(workflowID) ||
		write.Actor.ActiveTenantID != tenantID {
		return application.WorkflowAdminMutationResult{}, application.ErrForbidden
	}
	states, transitions, err := marshalTicketWorkflow(next.Current())
	if err != nil {
		return application.WorkflowAdminMutationResult{}, application.ErrConflict
	}
	displaced, displacedExpected, hasDisplaced := write.Plan.DisplacedDefault()
	var displacedID any
	var displacedNextRevision int64
	if hasDisplaced {
		identifier := workflowAdminUUID(displaced.ID())
		if !authorizationUUIDv7(identifier) || displaced.Tenant() != next.Tenant() ||
			displaced.Kind() != next.Kind() || displacedExpected == 0 ||
			displaced.Revision() != displacedExpected+1 {
			return application.WorkflowAdminMutationResult{}, application.ErrConflict
		}
		displacedID = identifier
		displacedNextRevision = int64(displaced.Revision())
	}
	ids, err := phase4NewIDs(repository.newID, 4)
	if err != nil {
		return application.WorkflowAdminMutationResult{}, application.ErrUnavailable
	}
	// The database ABI serializes each idempotency lineage before reading the
	// command ledger, then protects workflow rows with explicit locks and CAS.
	// READ COMMITTED is intentional: after waiting for a concurrent lineage
	// owner, the replay lookup must take a fresh snapshot and observe the
	// immutable result it committed. A transaction-wide snapshot could instead
	// turn an exact concurrent replay into a serialization failure.
	result, err := withinTicketActorTransactionWithOptions(
		ctx, repository, write.Actor, tenantID,
		pgx.TxOptions{IsoLevel: pgx.ReadCommitted},
		func(tx databaseTransaction) (application.WorkflowAdminMutationResult, error) {
			var returnedID uuid.UUID
			var returnedRevision int64
			var replayed bool
			var snapshot []byte
			err := tx.QueryRow(ctx, `
				SELECT workflow_id, revision, replayed, result_snapshot
				FROM app.commit_ticket_workflow_admin_v1(
					$1, $2, $3, $4, $5::public.ticket_aggregate_kind,
					$6, $7, $8, $9, $10, $11, $12,
					$13::jsonb, $14::jsonb, $15, $16,
					$17, $18, $19, $20,
					$21, $22, $23, $24, $25,
					$26, $27, $28::inet, $29, $30
				)`,
				tenantID, write.Actor.UserID, write.Command.Action.String(), workflowID, next.Kind().String(),
				next.Key().String(), next.DisplayName(), next.Description(), next.IsDefault(), next.Status().String(),
				next.Revision(), next.CurrentVersion(), states, transitions, write.Plan.ExpectedRevision(), write.Plan.PublishesDefinition(),
				displacedID, displacedExpected, displacedNextRevision, write.Command.KeyHash[:],
				write.Command.Fingerprint[:], ids[0], ids[1], ids[2], ids[3],
				write.Audit.RequestID, write.Audit.CorrelationID, write.Audit.RemoteAddress,
				write.Audit.UserAgent, write.Actor.AuthenticationMethod,
			).Scan(&returnedID, &returnedRevision, &replayed, &snapshot)
			if err != nil {
				return application.WorkflowAdminMutationResult{}, mapWorkflowAdminDatabaseError(err)
			}
			if !validWorkflowAdminCommitResult(
				write.Command.Action, workflowID, returnedID,
				returnedRevision, next.Revision(), replayed,
			) {
				return application.WorkflowAdminMutationResult{}, application.ErrConflict
			}
			record, err := mapWorkflowAdminCommandSnapshot(
				snapshot, tenantID, write.Command.Action.String(), returnedID, returnedRevision,
			)
			if err != nil {
				return application.WorkflowAdminMutationResult{}, err
			}
			return application.WorkflowAdminMutationResult{Record: record, Replayed: replayed}, nil
		},
	)
	return result, err
}

func validWorkflowAdminCommitResult(
	action kernel.WorkflowAdministrationAction,
	plannedID uuid.UUID,
	returnedID uuid.UUID,
	returnedRevision int64,
	nextRevision uint64,
	replayed bool,
) bool {
	if !authorizationUUIDv7(plannedID) || !authorizationUUIDv7(returnedID) ||
		returnedRevision < 1 || returnedRevision > math.MaxInt32 {
		return false
	}
	if !replayed {
		return returnedID == plannedID && uint64(returnedRevision) == nextRevision
	}
	// Concurrent creates can both miss the preflight lookup after reserving
	// different UUIDs. The losing transaction must return the immutable result
	// owned by the winning command rather than turn an exact replay into a
	// conflict. Existing-resource actions remain identity-bound.
	return action == kernel.WorkflowAdministrationCreate || returnedID == plannedID
}

func (repository *TicketingRepository) getWorkflowWithAccess(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	workflowID uuid.UUID,
	claimed application.WorkflowAdminAccess,
	capability application.WorkflowAdminCapability,
) (application.WorkflowAdminRecord, error) {
	return withinTicketActorTransactionWithOptions(
		ctx, repository, actor, tenantID,
		pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadOnly},
		func(tx databaseTransaction) (application.WorkflowAdminRecord, error) {
			if err := recheckWorkflowAdminAccess(ctx, tx, actor, tenantID, capability, claimed); err != nil {
				return application.WorkflowAdminRecord{}, err
			}
			return readWorkflowAdminRecord(ctx, tx, tenantID, workflowID, 0, false)
		},
	)
}

func resolveWorkflowAdminAccessInTransaction(
	ctx context.Context,
	tx databaseTransaction,
	actor application.Actor,
	tenantID uuid.UUID,
	capability application.WorkflowAdminCapability,
) (application.WorkflowAdminAccess, error) {
	authority, err := phase4Authority(ctx, tx, authorization.Actor{
		UserID: actor.UserID, SessionID: actor.SessionID, ActiveTenantID: actor.ActiveTenantID,
		AuthenticationMethod: actor.AuthenticationMethod,
	}, tenantID)
	if err != nil || !authorizationUUIDv7(authority.MembershipID) ||
		!validPhase4Authority(authority, authority.MembershipID) || authority.Principal.ID != actor.UserID {
		if err != nil {
			return application.WorkflowAdminAccess{}, mapWorkflowAdminDatabaseError(err)
		}
		return application.WorkflowAdminAccess{}, application.ErrForbidden
	}
	principal, err := workflowAdminPrincipal(authority)
	if err != nil {
		return application.WorkflowAdminAccess{}, err
	}
	allowed := phase4HasPermission(authority, string(capability), authorization.ScopeTenant)
	access, err := application.NewWorkflowAdminAccess(tenantID, actor.UserID, capability, principal, allowed)
	if err != nil {
		return application.WorkflowAdminAccess{}, application.ErrConflict
	}
	return access, nil
}

// Workflow administration is an explicitly human administrative route. Its
// audience is established by that route intent plus the live workflow
// capability above; a legacy membership label is neither an authorization
// grant nor an audience classifier for custom-role or federated-JIT users.
func workflowAdminPrincipal(
	authority authorization.TenantAuthority,
) (kernel.PrincipalKind, error) {
	if authority.Principal.Kind != authorization.PrincipalKindHuman {
		return 0, application.ErrForbidden
	}
	return kernel.PrincipalOperator, nil
}

func recheckWorkflowAdminAccess(
	ctx context.Context,
	tx databaseTransaction,
	actor application.Actor,
	tenantID uuid.UUID,
	capability application.WorkflowAdminCapability,
	claimed application.WorkflowAdminAccess,
) error {
	current, err := resolveWorkflowAdminAccessInTransaction(ctx, tx, actor, tenantID, capability)
	if err != nil {
		return err
	}
	if current.Tenant() != claimed.Tenant() || current.Actor() != claimed.Actor() ||
		current.Capability() != claimed.Capability() || current.Principal() != claimed.Principal() ||
		!current.Allowed() || !claimed.Allowed() {
		return application.ErrForbidden
	}
	return nil
}

func readWorkflowAdminRecord(
	ctx context.Context,
	tx databaseTransaction,
	tenantID uuid.UUID,
	workflowID uuid.UUID,
	kind kernel.AggregateKind,
	defaultOnly bool,
) (application.WorkflowAdminRecord, error) {
	query := `
		SELECT ` + workflowAdminRecordProjection + `
		FROM public.ticket_workflows AS workflow
		JOIN public.ticket_workflow_versions AS version
		  ON version.tenant_id = workflow.tenant_id
		 AND version.workflow_id = workflow.id
		 AND version.aggregate_kind = workflow.aggregate_kind
		 AND version.version = workflow.current_version
		WHERE workflow.tenant_id = $1`
	args := []any{tenantID}
	if defaultOnly {
		query += ` AND workflow.aggregate_kind = $2::public.ticket_aggregate_kind
		           AND workflow.is_default AND workflow.archived_at IS NULL`
		args = append(args, kind.String())
	} else {
		query += ` AND workflow.id = $2`
		args = append(args, workflowID)
	}
	return scanWorkflowAdminRecord(tx.QueryRow(ctx, query, args...), tenantID)
}

type workflowAdminScanner interface {
	Scan(...any) error
}

func scanWorkflowAdminRecord(
	row workflowAdminScanner,
	tenantID uuid.UUID,
) (application.WorkflowAdminRecord, error) {
	var id uuid.UUID
	var kindText, keyText, displayName, description string
	var isDefault bool
	var currentVersion int32
	var revision int64
	var archivedAt pgtype.Timestamptz
	var createdAt, updatedAt time.Time
	var states, transitions []byte
	if err := row.Scan(
		&id, &kindText, &keyText, &displayName, &description, &isDefault,
		&currentVersion, &revision, &archivedAt, &createdAt, &updatedAt,
		&states, &transitions,
	); err != nil {
		return application.WorkflowAdminRecord{}, mapWorkflowAdminDatabaseError(err)
	}
	kind, err := workflowAdminKind(kindText)
	if err != nil || currentVersion < 1 || revision < 1 || revision > math.MaxInt32 {
		return application.WorkflowAdminRecord{}, application.ErrConflict
	}
	definition, err := mapTicketWorkflow(id, kind, currentVersion, states, transitions)
	if err != nil {
		return application.WorkflowAdminRecord{}, application.ErrConflict
	}
	tenant, err := ticketEntityID(tenantID)
	if err != nil {
		return application.WorkflowAdminRecord{}, application.ErrConflict
	}
	key, err := kernel.NewKey(keyText)
	if err != nil {
		return application.WorkflowAdminRecord{}, application.ErrConflict
	}
	status := kernel.WorkflowActive
	var archived *time.Time
	if archivedAt.Valid {
		status = kernel.WorkflowArchived
		value := ticketTime(archivedAt.Time)
		archived = &value
	}
	workflow, err := kernel.NewManagedWorkflow(
		tenant, key, displayName, description, isDefault, status, uint64(revision), definition,
	)
	if err != nil {
		return application.WorkflowAdminRecord{}, application.ErrConflict
	}
	return application.WorkflowAdminRecord{
		Workflow: workflow, CreatedAt: ticketTime(createdAt), UpdatedAt: ticketTime(updatedAt), ArchivedAt: archived,
	}, nil
}

func scanWorkflowVersionRecord(
	row workflowAdminScanner,
	tenantID uuid.UUID,
) (application.WorkflowVersionRecord, error) {
	var workflowID uuid.UUID
	var kindText string
	var version int32
	var states, transitions []byte
	var publisherID pgtype.UUID
	var publisherName pgtype.Text
	var publishedAt time.Time
	if err := row.Scan(
		&workflowID, &kindText, &version, &states, &transitions,
		&publisherID, &publisherName, &publishedAt,
	); err != nil {
		return application.WorkflowVersionRecord{}, mapWorkflowAdminDatabaseError(err)
	}
	kind, err := workflowAdminKind(kindText)
	if err != nil || version < 1 || !publisherName.Valid && publisherID.Valid {
		return application.WorkflowVersionRecord{}, application.ErrConflict
	}
	definition, err := mapTicketWorkflow(workflowID, kind, version, states, transitions)
	if err != nil {
		return application.WorkflowVersionRecord{}, application.ErrConflict
	}
	var publisher *uuid.UUID
	if publisherID.Valid {
		value := uuid.UUID(publisherID.Bytes)
		if !authorizationUUIDv7(value) {
			return application.WorkflowVersionRecord{}, application.ErrConflict
		}
		publisher = &value
	}
	name := "System"
	if publisherName.Valid {
		name = publisherName.String
	}
	return application.WorkflowVersionRecord{
		TenantID: tenantID, Definition: definition, PublishedByMembershipID: publisher,
		PublisherDisplayName: name, PublishedAt: ticketTime(publishedAt),
	}, nil
}

func workflowAdminKind(value string) (kernel.AggregateKind, error) {
	switch value {
	case "alert":
		return kernel.AggregateAlert, nil
	case "case":
		return kernel.AggregateCase, nil
	default:
		return 0, application.ErrConflict
	}
}

func encodeWorkflowAdminCursor(identifier uuid.UUID) string {
	return base64.RawURLEncoding.EncodeToString(identifier[:])
}

func decodeWorkflowAdminCursor(value string) (uuid.UUID, error) {
	if value == "" {
		return uuid.Nil, nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != 16 || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return uuid.Nil, application.ErrInvalidInput
	}
	identifier, err := uuid.FromBytes(decoded)
	if err != nil || !authorizationUUIDv7(identifier) {
		return uuid.Nil, application.ErrInvalidInput
	}
	return identifier, nil
}

func nullableWorkflowAdminUUID(value uuid.UUID) any {
	if value == uuid.Nil {
		return nil
	}
	return value
}

func workflowAdminUUID(value kernel.EntityID) uuid.UUID {
	identifier, _ := uuid.Parse(value.String())
	return identifier
}

func mapWorkflowAdminDatabaseError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return application.ErrNotFound
	}
	switch postgresCode(err) {
	case "42501":
		return application.ErrForbidden
	case "P0002":
		return application.ErrNotFound
	case "40001":
		return application.ErrPreconditionFailed
	case "23503", "23505", "23514", "22023", "22P02", "40P01", "55000":
		return application.ErrConflict
	default:
		return err
	}
}
