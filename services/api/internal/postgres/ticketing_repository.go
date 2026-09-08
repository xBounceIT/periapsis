package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	customkernel "github.com/periapsis-im/periapsis/modules/customfields"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/postgres/dbsql"
	application "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

const ticketRecordProjection = `
%s.id, %s.number, %s.workflow_id, %s.workflow_version,
%s.state_key, %s.customer_visible,
%s.title, coalesce(%s.description, ''), %s,
%s.severity::text, %s.priority, %s.category,
coalesce(%s.classification, ''), %s, %s,
%s, %s, %s.tags, %s.custom_fields,
%s.customer_custom_fields, %s,
%s, %s, %s, %s,
%s, %s, %s, %s,
%s.created_at, %s.updated_at, %s.acknowledged_at, %s.closed_at,
%s.assigned_at, %s.first_response_at, %s.resolved_at, %s.claimed_at,
%s.assigned_team_id, %s.assignee_user_id, %s.claimed_by_user_id,
%s.version, workflow_version.states, workflow_version.transitions`

const alertRecordFrom = `
FROM public.alerts AS ticket
JOIN public.ticket_workflow_versions AS workflow_version
  ON workflow_version.tenant_id = ticket.tenant_id
 AND workflow_version.workflow_id = ticket.workflow_id
 AND workflow_version.aggregate_kind = 'alert'
 AND workflow_version.version = ticket.workflow_version
LEFT JOIN public.users AS creator_user ON creator_user.id = ticket.created_by
LEFT JOIN app.ticket_service_account_attributions_v1 AS creator_service
  ON creator_service.tenant_id = ticket.tenant_id
 AND creator_service.id = ticket.created_by_service_account_id`

const caseRecordFrom = `
FROM public.cases AS ticket
JOIN public.ticket_workflow_versions AS workflow_version
  ON workflow_version.tenant_id = ticket.tenant_id
 AND workflow_version.workflow_id = ticket.workflow_id
 AND workflow_version.aggregate_kind = 'case'
 AND workflow_version.version = ticket.workflow_version
JOIN public.users AS creator_user ON creator_user.id = ticket.created_by_user_id`

const alertCustomerRecordFrom = `
FROM public.alerts AS ticket
JOIN public.ticket_workflow_versions AS workflow_version
  ON workflow_version.tenant_id = ticket.tenant_id
 AND workflow_version.workflow_id = ticket.workflow_id
 AND workflow_version.aggregate_kind = 'alert'
 AND workflow_version.version = ticket.workflow_version
JOIN LATERAL (
  SELECT min(state.value ->> 'initial')::boolean AS initial,
         min(state.value ->> 'terminal')::boolean AS terminal,
         min(state.value ->> 'visibility') AS visibility
  FROM jsonb_array_elements(workflow_version.states) AS state(value)
  WHERE state.value ->> 'key' = ticket.state_key
  HAVING count(*) = 1
) AS customer_state ON true`

const caseCustomerRecordFrom = `
FROM public.cases AS ticket
JOIN public.ticket_workflow_versions AS workflow_version
  ON workflow_version.tenant_id = ticket.tenant_id
 AND workflow_version.workflow_id = ticket.workflow_id
 AND workflow_version.aggregate_kind = 'case'
 AND workflow_version.version = ticket.workflow_version
JOIN LATERAL (
  SELECT min(state.value ->> 'initial')::boolean AS initial,
         min(state.value ->> 'terminal')::boolean AS terminal,
         min(state.value ->> 'visibility') AS visibility
  FROM jsonb_array_elements(workflow_version.states) AS state(value)
  WHERE state.value ->> 'key' = ticket.state_key
  HAVING count(*) = 1
) AS customer_state ON true`

// Keep this expression byte-for-byte aligned with the Drizzle GIN indexes on
// alerts and cases. It intentionally contains only fields present in every
// customer-safe ticket projection so search cannot become an oracle for raw
// payloads or other operator-only data.
const ticketSearchDocument = `to_tsvector('simple'::regconfig,
	coalesce(ticket.number, '') || ' ' ||
	coalesce(ticket.title, '') || ' ' ||
	coalesce(ticket.description, ''))`

// TicketingRepository keeps projection reads behind FORCE RLS and delegates
// every mutation to the bounded SECURITY DEFINER ABI. No caller-supplied
// authorization fact is persisted or trusted by this adapter.
type TicketingRepository struct {
	pool      *pgxpool.Pool
	begin     transactionBeginner
	authority *AuthorizationRepository
	newID     func() (uuid.UUID, error)
}

func NewTicketingRepository(pool *pgxpool.Pool) *TicketingRepository {
	return &TicketingRepository{
		pool:  pool,
		begin: poolTransactionBeginner(pool), authority: NewAuthorizationRepository(pool), newID: uuid.NewV7,
	}
}

var _ application.Repository = (*TicketingRepository)(nil)

func (repository *TicketingRepository) ResolveAccess(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	capability application.Capability,
) (application.LiveAccess, error) {
	if repository == nil || repository.authority == nil || repository.begin == nil {
		return application.LiveAccess{}, application.ErrUnavailable
	}
	authority, err := repository.authority.ResolveAuthority(ctx, authorization.ResolveAuthorityParams{
		Actor: authorization.Actor{
			UserID: actor.UserID, SessionID: actor.SessionID, ActiveTenantID: actor.ActiveTenantID,
			AuthenticationMethod: actor.AuthenticationMethod,
		},
		TenantID: tenantID,
	})
	if err != nil {
		return application.LiveAccess{}, mapTicketAuthorizationError(err)
	}
	requiredPermissions, requirementsErr := ticketCapabilityPermissions(capability)
	if requirementsErr != nil {
		return application.LiveAccess{}, requirementsErr
	}
	matchedScopes := make([]map[application.Scope]struct{}, len(requiredPermissions))
	for index := range matchedScopes {
		matchedScopes[index] = make(map[application.Scope]struct{}, 4)
	}
	permissions := make([]kernel.Permission, 0, 16)
	permissionSeen := make(map[kernel.Permission]struct{})
	for _, granted := range authority.Permissions {
		for index, required := range requiredPermissions {
			if granted.Permission != required {
				continue
			}
			mapped, mapErr := ticketScope(granted.Scope)
			if mapErr == nil {
				matchedScopes[index][mapped] = struct{}{}
			}
		}
		permission, parseErr := kernel.ParsePermission(string(granted.Permission))
		if parseErr == nil {
			if _, duplicate := permissionSeen[permission]; !duplicate {
				permissionSeen[permission] = struct{}{}
				permissions = append(permissions, permission)
			}
		}
	}
	scopes := intersectTicketScopes(matchedScopes)
	if len(scopes) == 0 {
		return application.LiveAccess{}, application.ErrForbidden
	}
	roles := make([]kernel.Key, 0, len(authority.RoleGrants))
	roleSeen := make(map[string]struct{}, len(authority.RoleGrants))
	for _, grant := range authority.RoleGrants {
		if _, duplicate := roleSeen[grant.RoleKey]; duplicate {
			continue
		}
		role, roleErr := kernel.NewKey(grant.RoleKey)
		if roleErr != nil {
			return application.LiveAccess{}, application.ErrUnavailable
		}
		roleSeen[grant.RoleKey] = struct{}{}
		roles = append(roles, role)
	}
	tenant, tenantErr := ticketEntityID(tenantID)
	actorID, actorErr := ticketEntityID(actor.UserID)
	membershipID, membershipErr := ticketEntityID(authority.MembershipID)
	if tenantErr != nil || actorErr != nil || membershipErr != nil {
		return application.LiveAccess{}, application.ErrForbidden
	}
	principal, err := ticketPrincipalForCapability(capability)
	if err != nil {
		return application.LiveAccess{}, err
	}
	var customerContactID *kernel.EntityID
	if principal == kernel.PrincipalCustomer {
		contactID, contactErr := repository.resolveCustomerContact(
			ctx, actor.UserID, tenantID, authority.MembershipID,
		)
		if contactErr != nil {
			return application.LiveAccess{}, contactErr
		}
		customerContactID = &contactID
	}
	var claimable, manageable, operatorTeams []kernel.EntityID
	var roster []kernel.RosterPair
	if principal == kernel.PrincipalOperator {
		claimable, manageable, roster, operatorTeams, err = repository.assignmentAuthority(
			ctx, actor.UserID, tenantID,
		)
		if err != nil {
			return application.LiveAccess{}, err
		}
	}
	snapshot, err := kernel.NewAuthorizationSnapshot(
		tenant, actorID, principal, authority.MembershipStatus == authorization.MembershipStatusActive,
		roles, permissions, claimable, manageable, roster,
	)
	if err != nil {
		return application.LiveAccess{}, application.ErrUnavailable
	}
	return application.LiveAccess{
		Authority: snapshot, Scopes: scopes, OperatorTeams: operatorTeams,
		MembershipID: membershipID, CustomerContactID: customerContactID,
	}, nil
}

// Export is a compound route intent. Resolving its two grants from one
// authority read prevents an export from combining permissions observed on
// opposite sides of a concurrent grant/revocation.
func ticketCapabilityPermissions(capability application.Capability) ([]authorization.TenantPermission, error) {
	switch capability {
	case application.CapabilityAlertRelationManage:
		return []authorization.TenantPermission{
			authorization.TenantPermission(application.CapabilityAlertRead),
			authorization.TenantPermission(application.CapabilityAlertUpdate),
		}, nil
	case application.CapabilityAlertActivityFeed:
		return []authorization.TenantPermission{
			authorization.TenantPermission(application.CapabilityAlertRead),
			authorization.TenantPermission(application.CapabilityAlertActivityRead),
		}, nil
	case application.CapabilityCaseActivityFeed:
		return []authorization.TenantPermission{
			authorization.TenantPermission(application.CapabilityCaseRead),
			authorization.TenantPermission(application.CapabilityCaseActivityRead),
		}, nil
	case application.CapabilityPortalAlertExport:
		return []authorization.TenantPermission{
			authorization.TenantPermission(application.CapabilityPortalAlertRead),
			authorization.TenantPermission(application.CapabilityPortalCommentPublic),
		}, nil
	case application.CapabilityPortalCaseExport:
		return []authorization.TenantPermission{
			authorization.TenantPermission(application.CapabilityPortalCaseRead),
			authorization.TenantPermission(application.CapabilityPortalCommentPublic),
		}, nil
	case application.CapabilityAlertCommentPrivate:
		return []authorization.TenantPermission{
			authorization.TenantPermission(application.CapabilityAlertCommentPublic),
			authorization.TenantPermission(application.CapabilityAlertCommentPrivate),
		}, nil
	case application.CapabilityCaseCommentPrivate:
		return []authorization.TenantPermission{
			authorization.TenantPermission(application.CapabilityCaseCommentPublic),
			authorization.TenantPermission(application.CapabilityCaseCommentPrivate),
		}, nil
	default:
		if strings.TrimSpace(string(capability)) == "" {
			return nil, application.ErrForbidden
		}
		return []authorization.TenantPermission{authorization.TenantPermission(capability)}, nil
	}
}

func intersectTicketScopes(sets []map[application.Scope]struct{}) []application.Scope {
	if len(sets) == 0 {
		return nil
	}
	result := make([]application.Scope, 0, len(sets[0]))
	for _, scope := range []application.Scope{
		application.ScopeOwn, application.ScopeAssigned,
		application.ScopeOperatorTeam, application.ScopeTenant,
	} {
		present := true
		for _, set := range sets {
			if _, exists := set[scope]; !exists {
				present = false
				break
			}
		}
		if present {
			result = append(result, scope)
		}
	}
	return result
}

// ticketPrincipalForCapability derives principal class from the trusted use-case
// intent. Legacy or custom role names are authorization inputs only through
// their live permission grants; they never decide which projection is used.
func ticketPrincipalForCapability(capability application.Capability) (kernel.PrincipalKind, error) {
	switch capability {
	case application.CapabilityPortalAlertRead,
		application.CapabilityPortalCaseRead,
		application.CapabilityPortalCommentPublic,
		application.CapabilityPortalAlertExport,
		application.CapabilityPortalCaseExport:
		return kernel.PrincipalCustomer, nil
	case application.CapabilityAlertRead,
		application.CapabilityAlertActivityRead,
		application.CapabilityAlertActivityFeed,
		application.CapabilityAlertRelationManage,
		application.CapabilityAlertCommentRead,
		application.CapabilityAlertLinkRead,
		application.CapabilityAlertAssign,
		application.CapabilityAlertClaim,
		application.CapabilityAlertUpdate,
		application.CapabilityAlertDelete,
		application.CapabilityAlertEscalate,
		application.CapabilityAlertCommentPublic,
		application.CapabilityAlertCommentPrivate,
		application.CapabilityCaseRead,
		application.CapabilityCaseActivityRead,
		application.CapabilityCaseActivityFeed,
		application.CapabilityCaseCommentRead,
		application.CapabilityCaseLinkRead,
		application.CapabilityCaseCreate,
		application.CapabilityCaseUpdate,
		application.CapabilityCaseClaim,
		application.CapabilityCaseTransfer,
		application.CapabilityCaseTransition,
		application.CapabilityCaseCommentPublic,
		application.CapabilityCaseCommentPrivate,
		application.CapabilityDFIRIOCRead,
		application.CapabilityDFIRAssetRead,
		application.CapabilityDFIRAttachmentRead:
		return kernel.PrincipalOperator, nil
	default:
		return 0, application.ErrForbidden
	}
}

func (repository *TicketingRepository) resolveCustomerContact(
	ctx context.Context,
	actorID, tenantID, membershipID uuid.UUID,
) (kernel.EntityID, error) {
	contactID, err := withinTicketReadTransaction(ctx, repository, actorID, tenantID,
		func(tx databaseTransaction) (uuid.UUID, error) {
			var id uuid.UUID
			if queryErr := tx.QueryRow(ctx, `
				SELECT id
				FROM public.customer_contacts
				WHERE tenant_id = $1
				  AND linked_membership_id = $2
				  AND linked_user_id = $3
				  AND active
				  AND archived_at IS NULL`,
				tenantID, membershipID, actorID,
			).Scan(&id); queryErr != nil {
				if errors.Is(queryErr, pgx.ErrNoRows) {
					return uuid.Nil, application.ErrForbidden
				}
				return uuid.Nil, mapTicketDatabaseError(queryErr)
			}
			return id, nil
		},
	)
	if err != nil {
		return kernel.EntityID{}, err
	}
	return ticketEntityID(contactID)
}

func (repository *TicketingRepository) assignmentAuthority(
	ctx context.Context,
	actorID uuid.UUID,
	tenantID uuid.UUID,
) ([]kernel.EntityID, []kernel.EntityID, []kernel.RosterPair, []kernel.EntityID, error) {
	projection, err := withinTicketReadTransaction(ctx, repository, actorID, tenantID,
		func(tx databaseTransaction) (ticketAssignmentAuthority, error) {
			rows, err := tx.Query(ctx, `
				SELECT operator_team_id, target_user_id, team_manageable, team_claimable
				FROM app.resolve_current_ticket_assignment_authority_v1()`)
			if err != nil {
				return ticketAssignmentAuthority{}, mapTicketDatabaseError(err)
			}
			defer rows.Close()
			claimable := make([]kernel.EntityID, 0)
			manageable := make([]kernel.EntityID, 0)
			roster := make([]kernel.RosterPair, 0)
			operatorTeams := make([]kernel.EntityID, 0)
			claimSeen := map[kernel.EntityID]struct{}{}
			manageSeen := map[kernel.EntityID]struct{}{}
			teamSeen := map[kernel.EntityID]struct{}{}
			rosterSeen := map[kernel.RosterPair]struct{}{}
			for rows.Next() {
				var teamUUID uuid.UUID
				var target pgtype.UUID
				var mayManage, mayClaim bool
				if scanErr := rows.Scan(&teamUUID, &target, &mayManage, &mayClaim); scanErr != nil {
					return ticketAssignmentAuthority{}, mapTicketDatabaseError(scanErr)
				}
				team, mapErr := ticketEntityID(teamUUID)
				if mapErr != nil {
					return ticketAssignmentAuthority{}, mapErr
				}
				if mayClaim {
					if _, seen := claimSeen[team]; !seen {
						claimSeen[team] = struct{}{}
						claimable = append(claimable, team)
					}
					if _, seen := teamSeen[team]; !seen {
						teamSeen[team] = struct{}{}
						operatorTeams = append(operatorTeams, team)
					}
				}
				if target.Valid && target.Bytes == actorID {
					if _, seen := teamSeen[team]; !seen {
						teamSeen[team] = struct{}{}
						operatorTeams = append(operatorTeams, team)
					}
				}
				if mayManage {
					if _, seen := manageSeen[team]; !seen {
						manageSeen[team] = struct{}{}
						manageable = append(manageable, team)
					}
				}
				if target.Valid && (mayManage || mayClaim) {
					user, userErr := ticketEntityID(target.Bytes)
					if userErr != nil {
						return ticketAssignmentAuthority{}, userErr
					}
					pair, pairErr := kernel.NewRosterPair(team, user)
					if pairErr != nil {
						return ticketAssignmentAuthority{}, application.ErrUnavailable
					}
					if _, seen := rosterSeen[pair]; !seen {
						rosterSeen[pair] = struct{}{}
						roster = append(roster, pair)
					}
				}
			}
			if err := rows.Err(); err != nil {
				return ticketAssignmentAuthority{}, mapTicketDatabaseError(err)
			}
			return ticketAssignmentAuthority{claimable, manageable, roster, operatorTeams}, nil
		},
	)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return projection.claimable, projection.manageable, projection.roster, projection.operatorTeams, nil
}

type ticketAssignmentAuthority struct {
	claimable, manageable []kernel.EntityID
	roster                []kernel.RosterPair
	operatorTeams         []kernel.EntityID
}

func mapTicketAuthorizationError(err error) error {
	switch {
	case errors.Is(err, authorization.ErrForbidden):
		return application.ErrForbidden
	case errors.Is(err, authorization.ErrInvalidInput):
		return application.ErrInvalidInput
	default:
		return application.ErrUnavailable
	}
}

func ticketScope(scope authorization.Scope) (application.Scope, error) {
	switch scope {
	case authorization.ScopeOwn:
		return application.ScopeOwn, nil
	case authorization.ScopeAssigned:
		return application.ScopeAssigned, nil
	case authorization.ScopeOperatorTeam:
		return application.ScopeOperatorTeam, nil
	case authorization.ScopeTenant:
		return application.ScopeTenant, nil
	default:
		return "", application.ErrForbidden
	}
}

func (repository *TicketingRepository) Workflow(
	ctx context.Context,
	actorID uuid.UUID,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	workflowID *uuid.UUID,
) (kernel.WorkflowDefinition, error) {
	return withinTicketReadTransaction(ctx, repository, actorID, tenantID,
		func(tx databaseTransaction) (kernel.WorkflowDefinition, error) {
			query := `
				SELECT workflow.id, workflow.current_version,
				       version.states, version.transitions
				FROM public.ticket_workflows AS workflow
				JOIN public.ticket_workflow_versions AS version
				  ON version.tenant_id = workflow.tenant_id
				 AND version.workflow_id = workflow.id
				 AND version.aggregate_kind = workflow.aggregate_kind
				 AND version.version = workflow.current_version
				WHERE workflow.tenant_id = $1
				  AND workflow.aggregate_kind = $2::public.ticket_aggregate_kind
				  AND workflow.archived_at IS NULL`
			args := []any{tenantID, kind.String()}
			if workflowID == nil {
				query += ` AND workflow.is_default`
			} else {
				query += ` AND workflow.id = $3`
				args = append(args, *workflowID)
			}
			var id uuid.UUID
			var version int32
			var states, transitions []byte
			if err := tx.QueryRow(ctx, query, args...).Scan(&id, &version, &states, &transitions); err != nil {
				return kernel.WorkflowDefinition{}, mapTicketDatabaseError(err)
			}
			return mapTicketWorkflow(id, kind, version, states, transitions)
		},
	)
}

func (repository *TicketingRepository) ReserveID(context.Context, uuid.UUID) (kernel.EntityID, error) {
	if repository == nil || repository.newID == nil {
		return kernel.EntityID{}, application.ErrUnavailable
	}
	id, err := repository.newID()
	if err != nil {
		return kernel.EntityID{}, application.ErrUnavailable
	}
	return ticketEntityID(id)
}

func (repository *TicketingRepository) Get(
	ctx context.Context,
	actorID uuid.UUID,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	id uuid.UUID,
) (application.Record, error) {
	return withinTicketReadTransaction(ctx, repository, actorID, tenantID,
		func(tx databaseTransaction) (application.Record, error) {
			return getTicketRecord(ctx, tx, tenantID, kind, id)
		},
	)
}

func (repository *TicketingRepository) GetForAccess(
	ctx context.Context,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	id uuid.UUID,
	access application.LiveAccess,
) (application.Record, error) {
	actorID := uuid.UUID(access.Authority.Actor().Bytes())
	return withinTicketReadTransaction(ctx, repository, actorID, tenantID,
		func(tx databaseTransaction) (application.Record, error) {
			base, err := ticketRecordQueryForPrincipal(kind, access.Authority.Principal())
			if err != nil {
				return application.Record{}, err
			}
			arguments := []any{tenantID, id}
			add := func(value any) string {
				arguments = append(arguments, value)
				return fmt.Sprintf("$%d", len(arguments))
			}
			predicate, err := ticketAccessPredicate(kind, access, add)
			if err != nil {
				return application.Record{}, err
			}
			where := "ticket.tenant_id = $1 AND ticket.id = $2 AND " + predicate
			principal := access.Authority.Principal()
			if principal == kernel.PrincipalCustomer {
				where += " AND " + customerTicketVisibilityPredicate
			}
			return scanTicketRecordForPrincipal(
				tx.QueryRow(ctx, base+" WHERE "+where, arguments...), tenantID, kind, principal,
			)
		},
	)
}

func getTicketRecord(
	ctx context.Context,
	tx databaseTransaction,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	id uuid.UUID,
) (application.Record, error) {
	query, err := ticketRecordQuery(kind)
	if err != nil {
		return application.Record{}, err
	}
	query += ` WHERE ticket.tenant_id = $1 AND ticket.id = $2`
	record, err := scanTicketRecord(tx.QueryRow(ctx, query, tenantID, id), tenantID, kind)
	if err != nil {
		return application.Record{}, mapTicketDatabaseError(err)
	}
	return record, nil
}

func ticketRecordQuery(kind kernel.AggregateKind) (string, error) {
	if kind == kernel.AggregateAlert {
		projection := fmt.Sprintf(ticketRecordProjection,
			"ticket", "ticket", "ticket", "ticket", "ticket", "ticket",
			"ticket", "ticket", `''::text`, "ticket", "ticket", "ticket",
			"ticket", "ticket.source", "ticket.source_type", "ticket.external_id", "ticket.deduplication_key",
			"ticket", "ticket", "ticket", "ticket.raw_payload",
			`CASE WHEN ticket.created_by_service_account_id IS NOT NULL THEN 'service_account'
			      ELSE 'operator' END`,
			`coalesce(ticket.created_by_membership_id, ticket.created_by_service_account_id)`,
			`coalesce(creator_user.display_name, creator_service.display_name, 'Service account')`,
			"ticket.created_by",
			"ticket.detected_at", "ticket.received_at", `NULL::timestamptz`, `NULL::timestamptz`,
			"ticket", "ticket", "ticket", "ticket", "ticket", "ticket", "ticket", "ticket",
			"ticket", "ticket", "ticket", "ticket",
		)
		return "SELECT " + projection + alertRecordFrom, nil
	}
	if kind == kernel.AggregateCase {
		projection := fmt.Sprintf(ticketRecordProjection,
			"ticket", "ticket", "ticket", "ticket", "ticket", "ticket",
			"ticket", "ticket", "ticket.summary", "ticket", "ticket", "ticket",
			"ticket", `''::text`, `''::text`, `NULL::text`, `NULL::text`,
			"ticket", "ticket", "ticket", `'{}'::jsonb`,
			`'operator'::text`,
			"ticket.created_by_membership_id", "creator_user.display_name", "ticket.created_by_user_id",
			`NULL::timestamptz`, `NULL::timestamptz`, "ticket.detection_time", "ticket.opened_at",
			"ticket", "ticket", "ticket", "ticket", "ticket", "ticket", "ticket", "ticket",
			"ticket", "ticket", "ticket", "ticket",
		)
		return "SELECT " + projection + caseRecordFrom, nil
	}
	return "", application.ErrInvalidInput
}

func ticketRecordQueryForPrincipal(kind kernel.AggregateKind, principal kernel.PrincipalKind) (string, error) {
	switch principal {
	case kernel.PrincipalOperator:
		return ticketRecordQuery(kind)
	case kernel.PrincipalCustomer:
		return customerTicketRecordQuery(kind)
	default:
		return "", application.ErrForbidden
	}
}

const customerTicketVisibilityPredicate = `ticket.customer_visible AND customer_state.visibility = 'customer'`

// customerTicketRecordQuery is an allowlist at the SQL boundary. It deliberately
// does not read operator custom fields, raw payloads, classification, source,
// assignments, claims, creator identities, or private workflow topology. A
// lateral projection admits exactly one pinned current state and exposes only
// its three customer-safe flags to the dedicated scanner.
func customerTicketRecordQuery(kind kernel.AggregateKind) (string, error) {
	var summary, detectedAt, receivedAt, detectionTime, openedAt, from string
	switch kind {
	case kernel.AggregateAlert:
		summary = `''::text`
		detectedAt, receivedAt = "ticket.detected_at", "ticket.received_at"
		detectionTime, openedAt = `NULL::timestamptz`, `NULL::timestamptz`
		from = alertCustomerRecordFrom
	case kernel.AggregateCase:
		summary = "ticket.summary"
		detectedAt, receivedAt = `NULL::timestamptz`, `NULL::timestamptz`
		detectionTime, openedAt = "ticket.detection_time", "ticket.opened_at"
		from = caseCustomerRecordFrom
	default:
		return "", application.ErrInvalidInput
	}

	// Keep this order aligned with scanCustomerTicketRecord.
	fields := []string{
		"ticket.id", "ticket.number", "ticket.workflow_id", "ticket.workflow_version",
		"ticket.state_key", "ticket.customer_visible",
		"ticket.title", "coalesce(ticket.description, '')", summary,
		"ticket.severity::text", "ticket.priority", "ticket.category",
		"ticket.tags", "ticket.customer_custom_fields",
		detectedAt, receivedAt, detectionTime, openedAt,
		"ticket.created_at", "ticket.updated_at",
		"ticket.version", "customer_state.initial", "customer_state.terminal", "customer_state.visibility",
	}
	return "SELECT\n" + strings.Join(fields, ", ") + "\n" + from, nil
}

func scanTicketRecordForPrincipal(
	row ticketRecordScanner,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	principal kernel.PrincipalKind,
) (application.Record, error) {
	switch principal {
	case kernel.PrincipalOperator:
		return scanTicketRecord(row, tenantID, kind)
	case kernel.PrincipalCustomer:
		return scanCustomerTicketRecord(row, tenantID, kind)
	default:
		return application.Record{}, application.ErrForbidden
	}
}

func scanCustomerTicketRecord(
	row ticketRecordScanner,
	tenantUUID uuid.UUID,
	kind kernel.AggregateKind,
) (application.Record, error) {
	var (
		id, workflowID                                                           uuid.UUID
		number, state, title, description, summary, severity, priority, category string
		workflowVersion, version                                                 int32
		customerVisible                                                          bool
		tags                                                                     []string
		customerCustomJSON                                                       []byte
		detectedAt, receivedAt, detectionTime, openedAt                          pgtype.Timestamptz
		createdAt, updatedAt                                                     time.Time
		stateInitial, stateTerminal                                              bool
		stateVisibility                                                          string
	)
	if err := row.Scan(
		&id, &number, &workflowID, &workflowVersion, &state, &customerVisible,
		&title, &description, &summary, &severity, &priority, &category,
		&tags, &customerCustomJSON,
		&detectedAt, &receivedAt, &detectionTime, &openedAt,
		&createdAt, &updatedAt, &version,
		&stateInitial, &stateTerminal, &stateVisibility,
	); err != nil {
		return application.Record{}, err
	}
	workflow, err := customerProjectionWorkflow(
		workflowID, kind, workflowVersion, state, stateInitial, stateTerminal, stateVisibility,
	)
	if err != nil {
		return application.Record{}, err
	}
	tenantID, err := ticketEntityID(tenantUUID)
	if err != nil {
		return application.Record{}, err
	}
	ticketID, err := ticketEntityID(id)
	if err != nil {
		return application.Record{}, err
	}
	stateKey, err := kernel.NewKey(state)
	if err != nil {
		return application.Record{}, invalidTicketProjection("invalid customer ticket state")
	}
	assignment, err := kernel.NewAssignment(nil, nil, nil)
	if err != nil {
		return application.Record{}, invalidTicketProjection("invalid customer ticket assignment")
	}
	snapshot, err := kernel.NewTicketSnapshot(
		workflow, tenantID, ticketID, stateKey, uint64(version), customerVisible, assignment,
	)
	if err != nil {
		return application.Record{}, invalidTicketProjection("invalid customer ticket snapshot")
	}
	customerCustomFields, err := decodeTicketMap(customerCustomJSON)
	if err != nil {
		return application.Record{}, err
	}
	creatorUserID := id
	result := application.Record{
		Workflow: workflow, Snapshot: snapshot, Number: number, Title: title,
		Description: description, Summary: summary, Severity: severity, Priority: priority,
		Category: category, Source: "redacted", SourceType: "redacted", Tags: tags,
		CustomFields: maps.Clone(customerCustomFields), CustomerCustomFields: customerCustomFields,
		RawPayload: map[string]any{},
		// The customer transport structurally omits Creator. Reusing the already
		// public ticket ID is a non-identifying validator sentinel, never authority.
		Creator: application.Creator{
			Kind: kernel.PrincipalOperator, ID: id, UserID: &creatorUserID,
		},
		CreatedAt: ticketTime(createdAt), UpdatedAt: ticketTime(updatedAt),
	}
	if detectedAt.Valid {
		result.DetectedAt = ticketTime(detectedAt.Time)
	}
	if receivedAt.Valid {
		result.ReceivedAt = ticketTime(receivedAt.Time)
	}
	if detectionTime.Valid {
		result.DetectionTime = ticketTime(detectionTime.Time)
	}
	if openedAt.Valid {
		result.OpenedAt = ticketTime(openedAt.Time)
	}
	return result, nil
}

func customerProjectionWorkflow(
	workflowUUID uuid.UUID,
	kind kernel.AggregateKind,
	version int32,
	currentState string,
	initial bool,
	terminal bool,
	visibility string,
) (kernel.WorkflowDefinition, error) {
	if initial && terminal || visibility != "customer" {
		return kernel.WorkflowDefinition{}, invalidTicketProjection("invalid customer workflow state")
	}
	workflowID, err := ticketEntityID(workflowUUID)
	if err != nil || version < 1 {
		return kernel.WorkflowDefinition{}, invalidTicketProjection("invalid customer workflow identity")
	}
	currentKey, err := kernel.NewKey(currentState)
	if err != nil {
		return kernel.WorkflowDefinition{}, invalidTicketProjection("invalid customer workflow state")
	}
	effects, err := kernel.NewEffectPlan(kernel.EffectActivity, kernel.EffectAudit)
	if err != nil {
		return kernel.WorkflowDefinition{}, invalidTicketProjection("invalid customer workflow effects")
	}
	createAction, err := kernel.NewStateAction(kernel.ActionCreate, effects)
	if err != nil {
		return kernel.WorkflowDefinition{}, invalidTicketProjection("invalid customer workflow create action")
	}
	initialKey, err := customerProjectionKey(currentKey, "customer_projection_initial")
	if err != nil {
		return kernel.WorkflowDefinition{}, err
	}
	terminalKey, err := customerProjectionKey(currentKey, "customer_projection_terminal")
	if err != nil {
		return kernel.WorkflowDefinition{}, err
	}
	transitionOne, _ := kernel.NewKey("customer_projection_transition_one")
	transitionTwo, _ := kernel.NewKey("customer_projection_transition_two")

	states := make([]kernel.StateDefinition, 0, 3)
	transitions := make([]kernel.TransitionDefinition, 0, 2)
	if initial {
		current, stateErr := kernel.NewStateDefinition(
			currentKey, true, false, kernel.VisibilityCustomer, []kernel.StateAction{createAction},
		)
		end, endErr := kernel.NewStateDefinition(terminalKey, false, true, kernel.VisibilityInternal, nil)
		transition, transitionErr := kernel.NewTransitionDefinition(
			transitionOne, currentKey, terminalKey, false, false, nil, nil, nil, effects,
		)
		if stateErr != nil || endErr != nil || transitionErr != nil {
			return kernel.WorkflowDefinition{}, invalidTicketProjection("invalid initial customer workflow projection")
		}
		states, transitions = append(states, current, end), append(transitions, transition)
	} else if terminal {
		start, startErr := kernel.NewStateDefinition(
			initialKey, true, false, kernel.VisibilityInternal, []kernel.StateAction{createAction},
		)
		current, stateErr := kernel.NewStateDefinition(currentKey, false, true, kernel.VisibilityCustomer, nil)
		transition, transitionErr := kernel.NewTransitionDefinition(
			transitionOne, initialKey, currentKey, false, false, nil, nil, nil, effects,
		)
		if startErr != nil || stateErr != nil || transitionErr != nil {
			return kernel.WorkflowDefinition{}, invalidTicketProjection("invalid terminal customer workflow projection")
		}
		states, transitions = append(states, start, current), append(transitions, transition)
	} else {
		start, startErr := kernel.NewStateDefinition(
			initialKey, true, false, kernel.VisibilityInternal, []kernel.StateAction{createAction},
		)
		current, stateErr := kernel.NewStateDefinition(currentKey, false, false, kernel.VisibilityCustomer, nil)
		end, endErr := kernel.NewStateDefinition(terminalKey, false, true, kernel.VisibilityInternal, nil)
		first, firstErr := kernel.NewTransitionDefinition(
			transitionOne, initialKey, currentKey, false, false, nil, nil, nil, effects,
		)
		second, secondErr := kernel.NewTransitionDefinition(
			transitionTwo, currentKey, terminalKey, false, false, nil, nil, nil, effects,
		)
		if startErr != nil || stateErr != nil || endErr != nil || firstErr != nil || secondErr != nil {
			return kernel.WorkflowDefinition{}, invalidTicketProjection("invalid intermediate customer workflow projection")
		}
		states, transitions = append(states, start, current, end), append(transitions, first, second)
	}
	workflow, err := kernel.NewWorkflowDefinition(workflowID, kind, uint64(version), states, transitions)
	if err != nil {
		return kernel.WorkflowDefinition{}, invalidTicketProjection("invalid customer workflow projection")
	}
	return workflow, nil
}

func customerProjectionKey(current kernel.Key, preferred string) (kernel.Key, error) {
	if current.String() == preferred {
		preferred += "_alternate"
	}
	key, err := kernel.NewKey(preferred)
	if err != nil {
		return kernel.Key{}, invalidTicketProjection("invalid customer workflow sentinel")
	}
	return key, nil
}

type ticketCursor struct {
	Version     int             `json:"v"`
	Sort        string          `json:"s"`
	Instant     time.Time       `json:"t"`
	Priority    string          `json:"p,omitempty"`
	ID          uuid.UUID       `json:"i"`
	Fingerprint string          `json:"f"`
	Dynamic     json.RawMessage `json:"d,omitempty"`
	DynamicNull bool            `json:"n,omitempty"`
}

type ticketCustomFieldFilterPin struct {
	DefinitionID     uuid.UUID
	DefinitionDigest [sha256.Size]byte
	Key              string
	SchemaVersion    uint64
	DataType         customkernel.DataType
	Canonical        json.RawMessage
}

func (repository *TicketingRepository) List(
	ctx context.Context,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	input application.ListInput,
	access application.LiveAccess,
) (application.RecordPage, error) {
	actorID := uuid.UUID(access.Authority.Actor().Bytes())
	return withinTicketReadTransaction(ctx, repository, actorID, tenantID,
		func(tx databaseTransaction) (application.RecordPage, error) {
			principal := access.Authority.Principal()
			if principal == kernel.PrincipalCustomer && hasOperatorOnlyTicketListFilters(input) {
				return application.RecordPage{}, application.ErrForbidden
			}
			execution, effectiveInput, executionErr := resolveTicketSavedViewExecution(
				ctx, tx, tenantID, kind, input, access,
			)
			if executionErr != nil {
				return application.RecordPage{}, executionErr
			}
			input = effectiveInput
			customFilters := []ticketCustomFieldFilterPin{}
			if execution != nil {
				customFilters = dynamicCustomFilterPins(execution.filters)
			} else {
				customFilter, filterErr := resolveTicketCustomFieldFilter(
					ctx, tx, tenantID, kind, input, principal,
				)
				if filterErr != nil {
					return application.RecordPage{}, filterErr
				}
				if customFilter != nil {
					customFilters = append(customFilters, *customFilter)
				}
			}
			cursorFingerprint, fingerprintErr := ticketListCursorFingerprint(
				tenantID, kind, input, access, customFilters, execution,
			)
			if fingerprintErr != nil {
				return application.RecordPage{}, fingerprintErr
			}
			base, queryErr := ticketRecordQueryForPrincipal(kind, principal)
			if queryErr != nil {
				return application.RecordPage{}, queryErr
			}
			arguments := []any{tenantID}
			where := []string{"ticket.tenant_id = $1"}
			appendArgument := func(value any) string {
				arguments = append(arguments, value)
				return fmt.Sprintf("$%d", len(arguments))
			}
			accessSQL, accessErr := ticketAccessPredicate(kind, access, appendArgument)
			if accessErr != nil {
				return application.RecordPage{}, accessErr
			}
			where = append(where, accessSQL)
			if principal == kernel.PrincipalCustomer {
				where = append(where, customerTicketVisibilityPredicate)
			}
			if len(input.States) > 0 {
				values := make([]string, len(input.States))
				for index, value := range input.States {
					values[index] = value.String()
				}
				where = append(where, "ticket.state_key = ANY("+appendArgument(values)+"::text[])")
			}
			if len(input.Severities) > 0 {
				where = append(where, "ticket.severity::text = ANY("+appendArgument(input.Severities)+"::text[])")
			}
			if len(input.Priorities) > 0 {
				where = append(where, "ticket.priority = ANY("+appendArgument(input.Priorities)+"::text[])")
			}
			if input.AssignedTeamID != nil {
				where = append(where, "ticket.assigned_team_id = "+appendArgument(*input.AssignedTeamID))
			}
			if input.AssigneeUserID != nil {
				where = append(where, "ticket.assignee_user_id = "+appendArgument(*input.AssigneeUserID))
			}
			if input.ClaimedBy != nil {
				where = append(where, "ticket.claimed_by_user_id = "+appendArgument(*input.ClaimedBy))
			}
			if input.CustomerVisible != nil {
				where = append(where, "ticket.customer_visible = "+appendArgument(*input.CustomerVisible))
			}
			if input.Search != "" {
				where = append(where, ticketFullTextSearchPredicate(appendArgument(input.Search)))
			}
			for _, customFilter := range customFilters {
				predicate, predicateErr := ticketCustomFieldFilterPredicate(kind, customFilter, appendArgument)
				if predicateErr != nil {
					return application.RecordPage{}, predicateErr
				}
				where = append(where, predicate)
			}
			switch input.Queue {
			case "assigned_to_me":
				where = append(where, "ticket.assignee_user_id = "+appendArgument(actorID))
			case "my_operator_teams":
				teamIDs := make([]uuid.UUID, len(access.OperatorTeams))
				for index, value := range access.OperatorTeams {
					teamIDs[index] = uuid.UUID(value.Bytes())
				}
				where = append(where, "ticket.assigned_team_id = ANY("+appendArgument(teamIDs)+"::uuid[])")
			case "unassigned":
				where = append(where, "ticket.assigned_team_id IS NULL")
			}
			dynamicSort, cursorErr := resolveTicketDynamicSortPlan(ctx, tx, tenantID, kind, execution, appendArgument)
			if cursorErr != nil {
				return application.RecordPage{}, cursorErr
			}
			var sortName, order, cursorPredicate string
			if dynamicSort != nil {
				sortName, order, cursorPredicate, cursorErr = ticketDynamicSort(dynamicSort, input.After, cursorFingerprint, appendArgument)
			} else {
				sortName, order, cursorPredicate, cursorErr = ticketSort(input.Sort, input.After, cursorFingerprint, appendArgument)
			}
			if cursorErr != nil {
				return application.RecordPage{}, cursorErr
			}
			if cursorPredicate != "" {
				where = append(where, cursorPredicate)
			}
			if dynamicSort != nil {
				base += dynamicSort.join
			}
			query := base + " WHERE " + strings.Join(where, " AND ") + " ORDER BY " + order + " LIMIT " + appendArgument(input.Limit+1)
			rows, err := tx.Query(ctx, query, arguments...)
			if err != nil {
				return application.RecordPage{}, mapTicketDatabaseError(err)
			}
			defer rows.Close()
			items := make([]application.Record, 0, input.Limit+1)
			for rows.Next() {
				record, scanErr := scanTicketRecordForPrincipal(rows, tenantID, kind, principal)
				if scanErr != nil {
					return application.RecordPage{}, mapTicketDatabaseError(scanErr)
				}
				items = append(items, record)
			}
			if err := rows.Err(); err != nil {
				return application.RecordPage{}, mapTicketDatabaseError(err)
			}
			next := ""
			if len(items) > input.Limit {
				items = items[:input.Limit]
				if execution != nil {
					if loadErr := loadTicketSavedViewDynamicColumns(ctx, tx, tenantID, kind, execution, items); loadErr != nil {
						return application.RecordPage{}, loadErr
					}
				}
				encoded, encodeErr := encodeTicketCursorForPlan(sortName, cursorFingerprint, items[len(items)-1], dynamicSort)
				if encodeErr != nil {
					return application.RecordPage{}, encodeErr
				}
				next = encoded
			} else if execution != nil {
				if loadErr := loadTicketSavedViewDynamicColumns(ctx, tx, tenantID, kind, execution, items); loadErr != nil {
					return application.RecordPage{}, loadErr
				}
			}
			var applied *application.SavedViewRecord
			if execution != nil {
				value := execution.record
				applied = &value
			}
			return application.RecordPage{Items: items, NextCursor: next, AppliedView: applied}, nil
		},
	)
}

func hasOperatorOnlyTicketListFilters(input application.ListInput) bool {
	return input.AssignedTeamID != nil || input.AssigneeUserID != nil || input.ClaimedBy != nil || input.Queue != ""
}

func ticketAccessPredicate(kind kernel.AggregateKind, access application.LiveAccess, add func(any) string) (string, error) {
	if access.Authority.Principal() == kernel.PrincipalCustomer {
		if access.CustomerContactID == nil {
			return "FALSE", application.ErrForbidden
		}
		resourceColumn := "linked.alert_id"
		if kind == kernel.AggregateCase {
			resourceColumn = "linked.case_id"
		} else if kind != kernel.AggregateAlert {
			return "FALSE", application.ErrInvalidInput
		}
		return `EXISTS (
			SELECT 1
			FROM public.ticket_customer_contacts AS linked
			WHERE linked.tenant_id = ticket.tenant_id
			  AND ` + resourceColumn + ` = ticket.id
			  AND linked.contact_id = ` + add(uuid.UUID(access.CustomerContactID.Bytes())) + `
			  AND linked.archived_at IS NULL)`, nil
	}
	parts := make([]string, 0, 4)
	for _, scope := range access.Scopes {
		switch scope {
		case application.ScopeTenant:
			parts = append(parts, "TRUE")
		case application.ScopeOwn:
			creatorColumn := "ticket.created_by"
			if kind == kernel.AggregateCase {
				creatorColumn = "ticket.created_by_user_id"
			}
			parts = append(parts, creatorColumn+" = "+add(uuid.UUID(access.Authority.Actor().Bytes())))
		case application.ScopeAssigned:
			actor := add(uuid.UUID(access.Authority.Actor().Bytes()))
			parts = append(parts, "("+actor+" IN (ticket.assignee_user_id, ticket.claimed_by_user_id))")
		case application.ScopeOperatorTeam:
			teams := make([]uuid.UUID, len(access.OperatorTeams))
			for index, value := range access.OperatorTeams {
				teams[index] = uuid.UUID(value.Bytes())
			}
			parts = append(parts, "ticket.assigned_team_id = ANY("+add(teams)+"::uuid[])")
		default:
			return "", application.ErrForbidden
		}
	}
	if len(parts) == 0 {
		return "FALSE", application.ErrForbidden
	}
	return "(" + strings.Join(parts, " OR ") + ")", nil
}

func ticketSort(sortName, encoded string, fingerprint [sha256.Size]byte, add func(any) string) (string, string, string, error) {
	if sortName == "" {
		sortName = "updated_at_desc"
	}
	column, direction := "ticket.updated_at", "DESC"
	switch sortName {
	case "updated_at_desc":
	case "updated_at_asc":
		direction = "ASC"
	case "created_at_desc":
		column = "ticket.created_at"
	case "created_at_asc":
		column, direction = "ticket.created_at", "ASC"
	case "priority_desc":
		column = `CASE ticket.priority WHEN 'critical' THEN 5 WHEN 'urgent' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END`
	case "oldest_unclaimed":
		column, direction = "ticket.created_at", "ASC"
	default:
		return "", "", "", application.ErrInvalidInput
	}
	if encoded == "" {
		return sortName, column + " " + direction + ", ticket.id " + direction, "", nil
	}
	cursor, err := decodeTicketCursor(encoded, sortName, fingerprint)
	if err != nil || cursor.Dynamic != nil || cursor.DynamicNull {
		return "", "", "", application.ErrInvalidInput
	}
	operator := "<"
	if direction == "ASC" {
		operator = ">"
	}
	value := any(cursor.Instant)
	if sortName == "priority_desc" {
		ranks := map[string]int{"low": 1, "medium": 2, "high": 3, "urgent": 4, "critical": 5}
		rank, ok := ranks[cursor.Priority]
		if !ok {
			return "", "", "", application.ErrInvalidInput
		}
		value = rank
	} else if cursor.Instant.IsZero() || cursor.Instant.Nanosecond()%int(time.Microsecond) != 0 {
		return "", "", "", application.ErrInvalidInput
	}
	predicate := fmt.Sprintf("(%s, ticket.id) %s (%s, %s)", column, operator, add(value), add(cursor.ID))
	return sortName, column + " " + direction + ", ticket.id " + direction, predicate, nil
}

func decodeTicketCursor(encoded, sortName string, fingerprint [sha256.Size]byte) (ticketCursor, error) {
	bytes, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(bytes) != encoded {
		return ticketCursor{}, application.ErrInvalidInput
	}
	decoder := json.NewDecoder(strings.NewReader(string(bytes)))
	decoder.DisallowUnknownFields()
	var cursor ticketCursor
	if decoder.Decode(&cursor) != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		cursor.Version != 1 || cursor.Sort != sortName || cursor.ID.Version() != 7 ||
		cursor.Fingerprint != base64.RawURLEncoding.EncodeToString(fingerprint[:]) ||
		cursor.Dynamic != nil && !json.Valid(cursor.Dynamic) {
		return ticketCursor{}, application.ErrInvalidInput
	}
	return cursor, nil
}

func encodeTicketCursor(sortName string, fingerprint [sha256.Size]byte, record application.Record) (string, error) {
	cursor := ticketCursor{
		Version: 1, Sort: sortName, ID: uuid.UUID(record.Snapshot.ID().Bytes()),
		Fingerprint: base64.RawURLEncoding.EncodeToString(fingerprint[:]),
	}
	switch sortName {
	case "created_at_desc", "created_at_asc", "oldest_unclaimed":
		cursor.Instant = record.CreatedAt
	case "priority_desc":
		cursor.Priority = record.Priority
	default:
		cursor.Instant = record.UpdatedAt
	}
	encoded, err := json.Marshal(cursor)
	if err != nil {
		return "", application.ErrUnavailable
	}
	return base64.RawURLEncoding.EncodeToString(encoded), nil
}

func encodeTicketCursorForPlan(
	sortName string,
	fingerprint [sha256.Size]byte,
	record application.Record,
	plan *ticketDynamicSortPlan,
) (string, error) {
	if plan == nil {
		return encodeTicketCursor(sortName, fingerprint, record)
	}
	key := dynamicColumnKey(plan.source, plan.definition)
	value, exists := record.DynamicColumns[key]
	cursor := ticketCursor{
		Version: 1, Sort: sortName, ID: uuid.UUID(record.Snapshot.ID().Bytes()),
		Fingerprint: base64.RawURLEncoding.EncodeToString(fingerprint[:]), DynamicNull: !exists,
	}
	if exists {
		if !json.Valid(value.Value) || bytes.Equal(value.Value, []byte("null")) {
			cursor.DynamicNull = true
		} else {
			cursor.Dynamic = append(json.RawMessage(nil), value.Value...)
		}
	}
	encoded, err := json.Marshal(cursor)
	if err != nil {
		return "", application.ErrUnavailable
	}
	return base64.RawURLEncoding.EncodeToString(encoded), nil
}

func ticketListCursorFingerprint(
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	input application.ListInput,
	access application.LiveAccess,
	customFilters []ticketCustomFieldFilterPin,
	execution *ticketSavedViewExecution,
) ([sha256.Size]byte, error) {
	states := make([]string, len(input.States))
	for index, value := range input.States {
		states[index] = value.String()
	}
	slices.Sort(states)
	severities := slices.Clone(input.Severities)
	priorities := slices.Clone(input.Priorities)
	slices.Sort(severities)
	slices.Sort(priorities)
	scopes := slices.Clone(access.Scopes)
	slices.Sort(scopes)
	teams := make([]string, len(access.OperatorTeams))
	for index, value := range access.OperatorTeams {
		teams[index] = value.String()
	}
	slices.Sort(teams)
	sortName := input.Sort
	if sortName == "" {
		sortName = "updated_at_desc"
	}
	customFieldKey := ""
	if input.CustomFieldKey != nil {
		customFieldKey = input.CustomFieldKey.String()
	}
	payload := struct {
		Version           int                 `json:"version"`
		TenantID          uuid.UUID           `json:"tenant_id"`
		Kind              string              `json:"kind"`
		ActorID           string              `json:"actor_id"`
		Principal         string              `json:"principal"`
		Scopes            []application.Scope `json:"scopes"`
		OperatorTeams     []string            `json:"operator_teams"`
		CustomerContactID string              `json:"customer_contact_id"`
		States            []string            `json:"states"`
		Severities        []string            `json:"severities"`
		Priorities        []string            `json:"priorities"`
		AssignedTeamID    *uuid.UUID          `json:"assigned_team_id"`
		AssigneeUserID    *uuid.UUID          `json:"assignee_user_id"`
		ClaimedBy         *uuid.UUID          `json:"claimed_by"`
		Queue             string              `json:"queue"`
		CustomerVisible   *bool               `json:"customer_visible"`
		Search            string              `json:"search"`
		CustomFieldKey    string              `json:"custom_field_key"`
		CustomFieldValue  *string             `json:"custom_field_value"`
		SavedViewID       string              `json:"saved_view_id"`
		SavedViewRevision uint64              `json:"saved_view_revision"`
		SavedViewDigest   string              `json:"saved_view_digest"`
		MembershipID      string              `json:"membership_id"`
		Custom            []struct {
			DefinitionID  string `json:"definition_id"`
			DefinitionSum string `json:"definition_digest"`
			SchemaVersion uint64 `json:"schema_version"`
			DataType      string `json:"data_type"`
			CanonicalSum  string `json:"canonical_digest"`
		} `json:"custom"`
		Sort string `json:"sort"`
	}{
		Version: 1, TenantID: tenantID, Kind: kind.String(),
		ActorID: access.Authority.Actor().String(), Principal: string(access.Authority.Principal()),
		Scopes: scopes, OperatorTeams: teams, CustomerContactID: customerContactID(access),
		States: states, Severities: severities,
		Priorities: priorities, AssignedTeamID: input.AssignedTeamID,
		AssigneeUserID: input.AssigneeUserID, ClaimedBy: input.ClaimedBy,
		Queue: input.Queue, CustomerVisible: input.CustomerVisible, Search: input.Search,
		CustomFieldKey: customFieldKey, CustomFieldValue: input.CustomFieldValue, Sort: sortName,
		MembershipID: access.MembershipID.String(),
	}
	for _, customFilter := range customFilters {
		canonicalDigest := sha256.Sum256(customFilter.Canonical)
		payload.Custom = append(payload.Custom, struct {
			DefinitionID  string `json:"definition_id"`
			DefinitionSum string `json:"definition_digest"`
			SchemaVersion uint64 `json:"schema_version"`
			DataType      string `json:"data_type"`
			CanonicalSum  string `json:"canonical_digest"`
		}{
			DefinitionID:  customFilter.DefinitionID.String(),
			DefinitionSum: base64.RawURLEncoding.EncodeToString(customFilter.DefinitionDigest[:]),
			SchemaVersion: customFilter.SchemaVersion, DataType: string(customFilter.DataType),
			CanonicalSum: base64.RawURLEncoding.EncodeToString(canonicalDigest[:]),
		})
	}
	if execution != nil {
		payload.SavedViewID = savedViewUUID(execution.record.View.ID()).String()
		payload.SavedViewRevision = execution.record.View.Revision()
		payload.SavedViewDigest = base64.RawURLEncoding.EncodeToString(execution.canonicalHash[:])
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return [sha256.Size]byte{}, application.ErrUnavailable
	}
	return sha256.Sum256(encoded), nil
}

func resolveTicketCustomFieldFilter(
	ctx context.Context,
	tx databaseTransaction,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	input application.ListInput,
	principal kernel.PrincipalKind,
) (*ticketCustomFieldFilterPin, error) {
	if input.CustomFieldKey == nil {
		return nil, nil
	}
	if input.CustomFieldValue == nil {
		return nil, application.ErrInvalidInput
	}
	objectType := customkernel.ObjectAlert
	if kind == kernel.AggregateCase {
		objectType = customkernel.ObjectCase
	} else if kind != kernel.AggregateAlert {
		return nil, application.ErrInvalidInput
	}
	row, err := scanCustomDefinitionRow(tx.QueryRow(ctx, `SELECT `+customDefinitionColumns+`
		FROM public.custom_field_definitions AS definition
		WHERE definition.tenant_id = $1
		  AND definition.object_type = $2::public.custom_field_object_type
		  AND definition.key = $3`, tenantID, string(objectType), input.CustomFieldKey.String()))
	if errors.Is(err, pgx.ErrNoRows) {
		// Missing, archived, hidden, and non-filterable keys share the same
		// response so this endpoint is not a definition-existence oracle.
		return nil, application.ErrForbidden
	}
	if err != nil {
		return nil, mapTicketDatabaseError(err)
	}
	definition, err := hydrateCustomDefinition(ctx, tx, row)
	if err != nil {
		return nil, application.ErrUnavailable
	}
	audience := customkernel.AudienceOperator
	if principal == kernel.PrincipalCustomer {
		audience = customkernel.AudienceCustomer
	} else if principal != kernel.PrincipalOperator {
		return nil, application.ErrForbidden
	}
	filterKey, err := customkernel.NewKey(input.CustomFieldKey.String())
	if err != nil {
		return nil, application.ErrInvalidInput
	}
	filterTenantID, err := customkernel.ParseEntityID(tenantID.String())
	if err != nil {
		return nil, application.ErrForbidden
	}
	raw, err := ticketCustomFieldFilterJSON(definition.DataType(), *input.CustomFieldValue)
	if err != nil {
		return nil, err
	}
	plan, fieldErr := customkernel.PlanFilter(
		definition,
		customkernel.FilterInput{
			Key: filterKey, Operator: customkernel.FilterEqual,
			Value: customkernel.JSONInputValue(raw),
		},
		filterTenantID, objectType, audience, customkernel.SurfaceList,
	)
	if fieldErr != nil {
		if fieldErr.Code == "filter_denied" {
			return nil, application.ErrForbidden
		}
		return nil, application.ErrInvalidInput
	}
	canonical := plan.Value().CanonicalJSON()
	if plan.Value().Presence() != customkernel.PresencePresent || !json.Valid(canonical) {
		return nil, application.ErrUnavailable
	}
	definitionSnapshot, err := customDefinitionSnapshot(definition)
	if err != nil {
		return nil, application.ErrUnavailable
	}
	return &ticketCustomFieldFilterPin{
		DefinitionID: uuid.UUID(definition.ID().Bytes()), DefinitionDigest: sha256.Sum256(definitionSnapshot),
		Key: definition.Key().String(), SchemaVersion: definition.SchemaVersion(),
		DataType: definition.DataType(), Canonical: canonical,
	}, nil
}

func ticketCustomFieldFilterJSON(dataType customkernel.DataType, value string) (json.RawMessage, error) {
	switch dataType {
	case customkernel.TypeInteger, customkernel.TypeDecimal,
		customkernel.TypeBoolean, customkernel.TypeDuration:
		raw := json.RawMessage(value)
		if !json.Valid(raw) {
			return nil, application.ErrInvalidInput
		}
		return raw, nil
	case customkernel.TypeMultiSelect, customkernel.TypeStructuredJSON:
		// The current HTTP contract intentionally accepts one scalar equality
		// value. Collection/object operators require a separately versioned API.
		return nil, application.ErrInvalidInput
	default:
		encoded, err := json.Marshal(value)
		if err != nil {
			return nil, application.ErrInvalidInput
		}
		return encoded, nil
	}
}

func ticketCustomFieldFilterPredicate(
	kind kernel.AggregateKind,
	pin ticketCustomFieldFilterPin,
	add func(any) string,
) (string, error) {
	if add == nil || !authorizationUUIDv7(pin.DefinitionID) || pin.Key == "" ||
		pin.DefinitionDigest == ([sha256.Size]byte{}) || pin.SchemaVersion == 0 ||
		pin.DataType == "" || !json.Valid(pin.Canonical) {
		return "", application.ErrUnavailable
	}
	subject := "filtered.alert_id = ticket.id"
	if kind == kernel.AggregateCase {
		subject = "filtered.case_id = ticket.id"
	} else if kind != kernel.AggregateAlert {
		return "", application.ErrInvalidInput
	}
	typedEquality, err := ticketCustomFieldTypedEquality(pin, add)
	if err != nil {
		return "", err
	}
	return `EXISTS (
		SELECT 1
		FROM public.custom_field_values AS filtered
		WHERE filtered.tenant_id = ticket.tenant_id
		  AND filtered.object_type = ` + add(kind.String()) + `::public.custom_field_object_type
		  AND ` + subject + `
		  AND filtered.definition_id = ` + add(pin.DefinitionID) + `
		  AND filtered.definition_schema_version = ` + add(int64(pin.SchemaVersion)) + `
		  AND filtered.data_type = ` + add(string(pin.DataType)) + `::public.custom_field_data_type
		  AND filtered.presence = 'present'
		  AND ` + typedEquality + `
		  AND filtered.canonical_value = ` + add(string(pin.Canonical)) + `::jsonb
	)`, nil
}

func ticketCustomFieldTypedEquality(
	pin ticketCustomFieldFilterPin,
	add func(any) string,
) (string, error) {
	decodeText := func() (string, error) {
		var value string
		if err := json.Unmarshal(pin.Canonical, &value); err != nil {
			return "", application.ErrUnavailable
		}
		return value, nil
	}
	switch pin.DataType {
	case customkernel.TypeShortText, customkernel.TypeLongText,
		customkernel.TypeURL, customkernel.TypeEmail:
		value, err := decodeText()
		if err != nil {
			return "", err
		}
		return "filtered.text_value = " + add(value), nil
	case customkernel.TypeInteger, customkernel.TypeDuration:
		var value int64
		if err := json.Unmarshal(pin.Canonical, &value); err != nil {
			return "", application.ErrUnavailable
		}
		return "filtered.integer_value = " + add(value), nil
	case customkernel.TypeDecimal:
		return "filtered.decimal_value = " + add(string(pin.Canonical)) + "::numeric", nil
	case customkernel.TypeBoolean:
		var value bool
		if err := json.Unmarshal(pin.Canonical, &value); err != nil {
			return "", application.ErrUnavailable
		}
		return "filtered.boolean_value = " + add(value), nil
	case customkernel.TypeDate:
		value, err := decodeText()
		if err != nil {
			return "", err
		}
		return "filtered.date_value = " + add(value) + "::date", nil
	case customkernel.TypeDateTime:
		value, err := decodeText()
		if err != nil {
			return "", err
		}
		instant, parseErr := time.Parse(time.RFC3339Nano, value)
		if parseErr != nil || instant.Nanosecond()%1_000 != 0 {
			return "", application.ErrUnavailable
		}
		return "filtered.date_time_value = " + add(instant.UTC()), nil
	case customkernel.TypeIP:
		value, err := decodeText()
		if err != nil {
			return "", err
		}
		return "filtered.ip_value = " + add(value) + "::inet", nil
	case customkernel.TypeCIDR:
		value, err := decodeText()
		if err != nil {
			return "", err
		}
		return "filtered.cidr_value = " + add(value) + "::cidr", nil
	case customkernel.TypeUser, customkernel.TypeOperatorTeam,
		customkernel.TypeCustomerContact, customkernel.TypeAssetReference,
		customkernel.TypeIOCReference:
		value, err := decodeText()
		if err != nil {
			return "", err
		}
		reference, parseErr := uuid.Parse(value)
		if parseErr != nil || !authorizationUUIDv7(reference) {
			return "", application.ErrUnavailable
		}
		return "filtered.reference_id = " + add(reference), nil
	case customkernel.TypeSingleSelect:
		value, err := decodeText()
		if err != nil {
			return "", err
		}
		return "filtered.option_keys = ARRAY[" + add(value) + "]::text[]", nil
	default:
		return "", application.ErrInvalidInput
	}
}

func customerContactID(access application.LiveAccess) string {
	if access.CustomerContactID == nil {
		return ""
	}
	return access.CustomerContactID.String()
}

func ticketFullTextSearchPredicate(argument string) string {
	return ticketSearchDocument + ` @@ websearch_to_tsquery('simple'::regconfig, ` + argument + `)`
}

func (repository *TicketingRepository) CreateCase(
	ctx context.Context,
	write application.CreateCaseWrite,
) (application.WriteResult, error) {
	if len(write.Plans) < 1 || len(write.Plans) > 2 {
		return application.WriteResult{}, application.ErrInvalidInput
	}
	createPlan := write.Plans[0]
	tenantID := uuid.UUID(createPlan.Tenant().Bytes())
	caseID := uuid.UUID(createPlan.Ticket().Bytes())
	requestDigest, err := ticketRequestDigest(struct {
		Content application.CreateCaseInput `json:"content"`
	}{write.Content})
	if err != nil {
		return application.WriteResult{}, err
	}
	result, err := withinTicketWriteTransaction(ctx, repository, write.Actor, tenantID,
		func(tx databaseTransaction) (application.WriteResult, error) {
			var resultID uuid.UUID
			var resultVersion int32
			var replayed bool
			queryErr := tx.QueryRow(ctx, `
				SELECT case_id, result_version, replayed
				FROM app.create_tenant_case_v1(
				  $1,$2,$3,$4,$5,$6,$7::public.alert_severity,$8,$9,$10,
				  $11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23
				)`,
				caseID, uuid.UUID(createPlan.WorkflowID().Bytes()), int32(createPlan.WorkflowVersion()),
				write.Content.Title, write.Content.Description, write.Content.Summary,
				write.Content.Severity, write.Content.Priority, defaultTicketCategory(write.Content.Category),
				write.Content.Classification, write.Content.Tags, ticketJSON(write.Content.CustomFields),
				write.Content.CustomerVisible, ticketDatabaseTime(write.Content.DetectionTime),
				write.Content.AssignedTeamID, write.Content.AssigneeUserID,
				write.IdempotencyHash[:], requestDigest[:], write.Audit.RequestID,
				write.Audit.CorrelationID, write.Audit.RemoteAddress.Unmap(), write.Audit.UserAgent,
				write.Actor.AuthenticationMethod,
			).Scan(&resultID, &resultVersion, &replayed)
			if queryErr != nil {
				return application.WriteResult{}, mapTicketDatabaseError(queryErr)
			}
			record, getErr := getTicketRecord(ctx, tx, tenantID, kernel.AggregateCase, resultID)
			if getErr != nil || record.Snapshot.Version() != uint64(resultVersion) {
				if getErr != nil {
					return application.WriteResult{}, getErr
				}
				return application.WriteResult{}, application.ErrUnavailable
			}
			return application.WriteResult{Record: record, Replayed: replayed}, nil
		},
	)
	return result, mapTicketDatabaseError(err)
}

func (repository *TicketingRepository) ApplyMutation(
	ctx context.Context,
	write application.MutationWrite,
) (application.WriteResult, error) {
	plan := write.Plan
	tenantID := uuid.UUID(plan.Tenant().Bytes())
	ticketID := uuid.UUID(plan.Ticket().Bytes())
	assignment := plan.Assignment()
	teamID, assigneeID, claimantID := databaseTicketAssignment(assignment)
	var transitionKey, commentMarkdown, commentHTML *string
	customFields := map[string]any{}
	var keyDigest, requestDigest []byte
	if plan.Action() == kernel.ActionTransition {
		transitionKey = &write.TransitionKey
		customFields = write.CustomFields
		keyDigest = append([]byte(nil), write.IdempotencyHash[:]...)
		requestDigest = append([]byte(nil), write.Fingerprint[:]...)
		if comment, present := plan.Comment(); present {
			body := comment.Body()
			rendered, renderErr := application.RenderCommentMarkdown(body)
			if renderErr != nil {
				return application.WriteResult{}, renderErr
			}
			commentMarkdown, commentHTML = &body, &rendered
		}
	}
	result, err := withinTicketWriteTransaction(ctx, repository, write.Actor, tenantID,
		func(tx databaseTransaction) (application.WriteResult, error) {
			var resultVersion int32
			var replayed bool
			queryErr := tx.QueryRow(ctx, `
				SELECT result_version, replayed
				FROM app.apply_tenant_ticket_mutation_v2(
				  $1::public.ticket_aggregate_kind,$2,$3,$4,$5,$6,$7,$8,$9,$10,
				  $11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25
				)`,
				plan.Kind().String(), ticketID, plan.Action().String(), int32(plan.ExpectedVersion()),
				int32(plan.NextVersion()), uuid.UUID(plan.WorkflowID().Bytes()), int32(plan.WorkflowVersion()),
				plan.FromState().String(), plan.ToState().String(), transitionKey, plan.CustomerVisible(),
				teamID, assigneeID, claimantID, write.Reason, commentMarkdown, commentHTML,
				ticketJSON(customFields), keyDigest, requestDigest, write.Audit.RequestID,
				write.Audit.CorrelationID, write.Audit.RemoteAddress.Unmap(), write.Audit.UserAgent,
				write.Actor.AuthenticationMethod,
			).Scan(&resultVersion, &replayed)
			if queryErr != nil {
				return application.WriteResult{}, mapTicketDatabaseError(queryErr)
			}
			record, getErr := getTicketRecord(ctx, tx, tenantID, plan.Kind(), ticketID)
			if getErr != nil || record.Snapshot.Version() != uint64(resultVersion) {
				if getErr != nil {
					return application.WriteResult{}, getErr
				}
				return application.WriteResult{}, application.ErrUnavailable
			}
			return application.WriteResult{Record: record, Replayed: replayed}, nil
		},
	)
	return result, mapTicketDatabaseError(err)
}

func (repository *TicketingRepository) LookupMutationReplay(
	ctx context.Context,
	query application.MutationReplayQuery,
) (application.WriteResult, bool, error) {
	actor := application.Actor{UserID: query.ActorID, ActiveTenantID: query.TenantID}
	result, err := withinTicketActorTransaction(ctx, repository, actor, query.TenantID,
		func(tx databaseTransaction) (application.WriteResult, error) {
			var version int32
			err := tx.QueryRow(ctx, `
				SELECT result_version FROM app.lookup_tenant_ticket_mutation_replay_v1(
				  $1::public.ticket_aggregate_kind,$2,$3,$4,$5
				)`, query.Kind.String(), query.TicketID, query.Action.String(),
				query.KeyHash[:], query.Fingerprint[:]).Scan(&version)
			if err != nil {
				return application.WriteResult{}, err
			}
			record, getErr := getTicketRecord(ctx, tx, query.TenantID, query.Kind, query.TicketID)
			if getErr != nil || record.Snapshot.Version() < uint64(version) {
				if getErr != nil {
					return application.WriteResult{}, getErr
				}
				return application.WriteResult{}, application.ErrUnavailable
			}
			return application.WriteResult{Record: record, Replayed: true}, nil
		},
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return application.WriteResult{}, false, nil
	}
	if err != nil {
		return application.WriteResult{}, false, mapTicketDatabaseError(err)
	}
	return result, true, nil
}

func databaseTicketAssignment(assignment kernel.Assignment) (*uuid.UUID, *uuid.UUID, *uuid.UUID) {
	var teamID, assigneeID, claimantID *uuid.UUID
	if value, present := assignment.Team(); present {
		id := uuid.UUID(value.Bytes())
		teamID = &id
	}
	if value, present := assignment.Assignee(); present {
		id := uuid.UUID(value.Bytes())
		assigneeID = &id
	}
	if value, present := assignment.Claimant(); present {
		id := uuid.UUID(value.Bytes())
		claimantID = &id
	}
	return teamID, assigneeID, claimantID
}

func ticketRequestDigest(value any) ([sha256.Size]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > 512*1024 {
		return [sha256.Size]byte{}, application.ErrInvalidInput
	}
	return sha256.Sum256(encoded), nil
}

func ticketJSON(value any) []byte {
	encoded, _ := json.Marshal(value)
	return encoded
}

func defaultTicketCategory(value string) string {
	if value == "" {
		return "general"
	}
	return value
}

func (repository *TicketingRepository) ListActivities(
	ctx context.Context,
	record application.Record,
	page application.CursorPageInput,
	access application.LiveAccess,
) (application.StoredActivityPage, error) {
	tenantID := uuid.UUID(record.Snapshot.Tenant().Bytes())
	ticketID := uuid.UUID(record.Snapshot.ID().Bytes())
	actorID := uuid.UUID(access.Authority.Actor().Bytes())
	return withinTicketReadTransaction(ctx, repository, actorID, tenantID,
		func(tx databaseTransaction) (application.StoredActivityPage, error) {
			arguments := []any{tenantID, ticketID}
			resourceColumn := "activity.alert_id"
			prefix := "alert."
			if record.Snapshot.Kind() == kernel.AggregateCase {
				resourceColumn, prefix = "activity.case_id", "case."
			}
			selectClause := ticketActivitySelect
			if access.Authority.Principal() == kernel.PrincipalCustomer {
				selectClause = customerTicketActivitySelect
			}
			query := selectClause + ` WHERE activity.tenant_id = $1 AND ` + resourceColumn + ` = $2`
			if access.Authority.Principal() == kernel.PrincipalCustomer {
				query += ` AND (activity.kind IN ('` + prefix + `created','` + prefix + `transitioned','` + prefix + `escalated','` + prefix + `linked','` + prefix + `unlinked')
					OR activity.kind = '` + prefix + `commented' AND activity.details ->> 'visibility' = 'public')`
			}
			if page.After != nil {
				arguments = append(arguments, *page.After)
				query += fmt.Sprintf(" AND activity.id > $%d", len(arguments))
			}
			arguments = append(arguments, page.Limit+1)
			query += fmt.Sprintf(" ORDER BY activity.id LIMIT $%d", len(arguments))
			rows, err := tx.Query(ctx, query, arguments...)
			if err != nil {
				return application.StoredActivityPage{}, mapTicketDatabaseError(err)
			}
			defer rows.Close()
			items := make([]application.Activity, 0, page.Limit+1)
			for rows.Next() {
				item, scanErr := scanTicketActivity(
					rows, tenantID, record.Snapshot.Kind(), ticketID, access.Authority.Principal(),
				)
				if scanErr != nil {
					return application.StoredActivityPage{}, scanErr
				}
				items = append(items, item)
			}
			if err := rows.Err(); err != nil {
				return application.StoredActivityPage{}, mapTicketDatabaseError(err)
			}
			var next *uuid.UUID
			if len(items) > page.Limit {
				items = items[:page.Limit]
				value := items[len(items)-1].ID
				next = &value
			}
			return application.StoredActivityPage{Items: items, NextCursor: next}, nil
		},
	)
}

func (repository *TicketingRepository) ListActivityFeed(
	ctx context.Context,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	page application.CursorPageInput,
	access application.LiveAccess,
) (application.StoredActivityPage, error) {
	if access.Authority.Principal() != kernel.PrincipalOperator {
		return application.StoredActivityPage{}, application.ErrForbidden
	}
	actorID := uuid.UUID(access.Authority.Actor().Bytes())
	return withinTicketReadTransaction(ctx, repository, actorID, tenantID,
		func(tx databaseTransaction) (application.StoredActivityPage, error) {
			resourceColumn := "activity.alert_id"
			resourceJoin := `
	JOIN public.alerts AS ticket
	  ON ticket.tenant_id = activity.tenant_id
	 AND ticket.id = activity.alert_id`
			if kind == kernel.AggregateCase {
				resourceColumn = "activity.case_id"
				resourceJoin = `
	JOIN public.cases AS ticket
	  ON ticket.tenant_id = activity.tenant_id
	 AND ticket.id = activity.case_id`
			} else if kind != kernel.AggregateAlert {
				return application.StoredActivityPage{}, application.ErrInvalidInput
			}
			arguments := []any{tenantID}
			add := func(value any) string {
				arguments = append(arguments, value)
				return fmt.Sprintf("$%d", len(arguments))
			}
			predicate, err := ticketAccessPredicate(kind, access, add)
			if err != nil {
				return application.StoredActivityPage{}, err
			}
			query := "SELECT " + resourceColumn + ", " + ticketActivityColumns +
				ticketActivityFrom + resourceJoin +
				" WHERE activity.tenant_id = $1 AND " + resourceColumn + " IS NOT NULL AND " + predicate
			if page.After != nil {
				query += " AND activity.id < " + add(*page.After)
			}
			query += " ORDER BY activity.id DESC LIMIT " + add(page.Limit+1)
			rows, err := tx.Query(ctx, query, arguments...)
			if err != nil {
				return application.StoredActivityPage{}, mapTicketDatabaseError(err)
			}
			defer rows.Close()
			items := make([]application.Activity, 0, page.Limit+1)
			for rows.Next() {
				item, scanErr := scanActivityRow(rows, tenantID, kind, nil, kernel.PrincipalOperator)
				if scanErr != nil {
					return application.StoredActivityPage{}, scanErr
				}
				items = append(items, item)
			}
			if err := rows.Err(); err != nil {
				return application.StoredActivityPage{}, mapTicketDatabaseError(err)
			}
			var next *uuid.UUID
			if len(items) > page.Limit {
				items = items[:page.Limit]
				value := items[len(items)-1].ID
				next = &value
			}
			return application.StoredActivityPage{Items: items, NextCursor: next}, nil
		},
	)
}

const ticketActivityColumns = `activity.id, activity.kind, activity.summary,
	       activity.actor_principal_kind::text,
	       activity.actor_membership_id, activity.actor_service_account_id,
	       coalesce(identity.display_name, service_account.display_name, 'System'),
	       author_snapshot.audience,
	       activity.details, activity.occurred_at`

const ticketActivityFrom = `
	FROM public.ticket_activities AS activity
	JOIN public.ticket_activity_author_snapshots AS author_snapshot
	  ON author_snapshot.tenant_id = activity.tenant_id
	 AND author_snapshot.activity_id = activity.id
	LEFT JOIN public.users AS identity ON identity.id = activity.actor_user_id
	LEFT JOIN app.ticket_service_account_attributions_v1 AS service_account
	  ON service_account.tenant_id = activity.tenant_id
	 AND service_account.id = activity.actor_service_account_id`

const ticketActivitySelect = "	SELECT " + ticketActivityColumns + ticketActivityFrom

// The customer projection keeps no activity details or principal identifiers.
// The immutable route audience supplies the only customer-visible author label.
const customerTicketActivitySelect = `
	SELECT activity.id, activity.kind, activity.summary,
	       'redacted'::text, NULL::uuid, NULL::uuid,
	       CASE author_snapshot.audience
	         WHEN 'customer' THEN 'Customer'
	         WHEN 'operator' THEN 'Support team'
	       END,
	       author_snapshot.audience,
	       '{"visibility":"public"}'::jsonb, activity.occurred_at
	FROM public.ticket_activities AS activity
	LEFT JOIN public.ticket_activity_author_snapshots AS author_snapshot
	  ON author_snapshot.tenant_id = activity.tenant_id
	 AND author_snapshot.activity_id = activity.id`

func scanTicketActivity(
	row ticketRecordScanner,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	ticketID uuid.UUID,
	principal kernel.PrincipalKind,
) (application.Activity, error) {
	return scanActivityRow(row, tenantID, kind, &ticketID, principal)
}

func scanActivityRow(
	row ticketRecordScanner,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	fixedTicketID *uuid.UUID,
	principal kernel.PrincipalKind,
) (application.Activity, error) {
	var item application.Activity
	var storedKind string
	var actorKind string
	var actorMembership, actorServiceAccount pgtype.UUID
	var details []byte
	destinations := []any{
		&item.ID, &storedKind, &item.Summary, &actorKind,
		&actorMembership, &actorServiceAccount, &item.DisplayName,
		&item.Origin, &details, &item.OccurredAt,
	}
	if fixedTicketID == nil {
		destinations = append([]any{&item.ResourceID}, destinations...)
	} else {
		item.ResourceID = *fixedTicketID
	}
	if err := row.Scan(destinations...); err != nil {
		return application.Activity{}, mapTicketDatabaseError(err)
	}
	actorKindValue, actorID, err := mapTicketActivityActor(actorKind, actorMembership, actorServiceAccount)
	if err != nil {
		return application.Activity{}, application.ErrUnavailable
	}
	item.ActorKind, item.ActorID = actorKindValue, actorID
	item.TenantID, item.ResourceKind = tenantID, kind
	mapped, err := decodeTicketMap(details)
	if err != nil {
		return application.Activity{}, err
	}
	visibility, _ := mapped["visibility"].(string)
	item.Kind = mapTicketActivityKind(storedKind, principal, visibility)
	item.OccurredAt = ticketTime(item.OccurredAt)
	if principal != kernel.PrincipalCustomer {
		item.Details = mapped
	}
	return item, nil
}

func mapTicketActivityActor(
	storedKind string,
	membership pgtype.UUID,
	serviceAccount pgtype.UUID,
) (application.ActivityActorKind, uuid.UUID, error) {
	switch storedKind {
	case "human":
		if !membership.Valid || serviceAccount.Valid {
			return 0, uuid.Nil, application.ErrUnavailable
		}
		return application.ActivityActorHuman, uuid.UUID(membership.Bytes), nil
	case "service_account":
		if membership.Valid || !serviceAccount.Valid {
			return 0, uuid.Nil, application.ErrUnavailable
		}
		return application.ActivityActorServiceAccount, uuid.UUID(serviceAccount.Bytes), nil
	case "system":
		if membership.Valid || serviceAccount.Valid {
			return 0, uuid.Nil, application.ErrUnavailable
		}
		return application.ActivityActorSystem, uuid.Nil, nil
	case "redacted":
		if membership.Valid || serviceAccount.Valid {
			return 0, uuid.Nil, application.ErrUnavailable
		}
		return application.ActivityActorRedacted, uuid.Nil, nil
	default:
		return 0, uuid.Nil, application.ErrUnavailable
	}
}

func mapTicketActivityKind(value string, principal kernel.PrincipalKind, visibility string) string {
	if strings.HasPrefix(value, "alert.") {
		value = strings.TrimPrefix(value, "alert.")
	} else if strings.HasPrefix(value, "case.") {
		value = strings.TrimPrefix(value, "case.")
	}
	if value == "transitioned" && principal == kernel.PrincipalCustomer {
		return "status_changed"
	}
	if value == "commented" {
		if visibility == "private" {
			return "comment.private"
		}
		if visibility == "public" {
			return "comment.public"
		}
		return ""
	}
	return value
}

func (repository *TicketingRepository) ResolveEscalationSelection(
	ctx context.Context,
	actorID uuid.UUID,
	record application.Record,
	selection application.CopySelection,
) (application.SelectionEvidence, error) {
	tenantID := uuid.UUID(record.Snapshot.Tenant().Bytes())
	alertID := uuid.UUID(record.Snapshot.ID().Bytes())
	return withinTicketReadTransaction(ctx, repository, actorID, tenantID,
		func(tx databaseTransaction) (application.SelectionEvidence, error) {
			evidence := application.SelectionEvidence{}
			if len(selection.ItemIDs) > 0 {
				rows, err := tx.Query(ctx, `
					SELECT selected.field, selected.id
					FROM (
					  SELECT 'iocs'::text AS field, link.ioc_id AS id
					  FROM public.dfir_ioc_links AS link
					  JOIN public.dfir_iocs AS item
					    ON item.tenant_id = link.tenant_id AND item.id = link.ioc_id
					  WHERE link.tenant_id = $1 AND link.alert_id = $2
					    AND link.ioc_id = ANY($3::uuid[]) AND item.archived_at IS NULL
					  UNION ALL
					  SELECT 'assets'::text, link.asset_id
					  FROM public.dfir_asset_links AS link
					  JOIN public.dfir_assets AS item
					    ON item.tenant_id = link.tenant_id AND item.id = link.asset_id
					  WHERE link.tenant_id = $1 AND link.alert_id = $2
					    AND link.asset_id = ANY($4::uuid[]) AND item.archived_at IS NULL
					  UNION ALL
					  SELECT 'attachments'::text, attachment.id
					  FROM public.dfir_attachments AS attachment
					  JOIN public.dfir_storage_objects AS storage
					    ON storage.tenant_id = attachment.tenant_id
					   AND storage.id = attachment.storage_object_id
					  WHERE attachment.tenant_id = $1 AND attachment.alert_id = $2
					    AND attachment.subject_kind = 'alert'
					    AND attachment.id = ANY($5::uuid[])
					    AND attachment.scan_state IN ('available', 'retained')
					    AND storage.state IN ('available', 'retained')
					  UNION ALL
					  SELECT 'contacts'::text, link.contact_id
					FROM public.ticket_customer_contacts AS link
					JOIN public.customer_contacts AS contact
					  ON contact.tenant_id = link.tenant_id
					 AND contact.id = link.contact_id
					WHERE link.tenant_id = $1 AND link.alert_id = $2
					  AND link.contact_id = ANY($6::uuid[])
					  AND link.archived_at IS NULL
					  AND contact.active AND contact.archived_at IS NULL
					) AS selected
					ORDER BY selected.field COLLATE "C", selected.id`,
					tenantID,
					alertID,
					selection.ItemIDs[kernel.CopyIOCs],
					selection.ItemIDs[kernel.CopyAssets],
					selection.ItemIDs[kernel.CopyAttachments],
					selection.ItemIDs[kernel.CopyContacts],
				)
				if err != nil {
					return application.SelectionEvidence{}, mapTicketDatabaseError(err)
				}
				for rows.Next() {
					var storedField string
					var id uuid.UUID
					if scanErr := rows.Scan(&storedField, &id); scanErr != nil {
						rows.Close()
						return application.SelectionEvidence{}, mapTicketDatabaseError(scanErr)
					}
					field, fieldErr := escalationSelectionField(storedField)
					if fieldErr != nil {
						rows.Close()
						return application.SelectionEvidence{}, fieldErr
					}
					entity, entityErr := ticketEntityID(id)
					if entityErr != nil {
						rows.Close()
						return application.SelectionEvidence{}, entityErr
					}
					reference, referenceErr := kernel.NewCopyItemReference(field, entity)
					if referenceErr != nil {
						rows.Close()
						return application.SelectionEvidence{}, application.ErrUnavailable
					}
					evidence.Items = append(evidence.Items, reference)
				}
				if err := rows.Err(); err != nil {
					rows.Close()
					return application.SelectionEvidence{}, mapTicketDatabaseError(err)
				}
				rows.Close()
			}
			if len(selection.PublicCommentIDs) == 0 {
				return evidence, nil
			}
			rows, err := tx.Query(ctx, `
				SELECT result_comment_id
				FROM app.list_tenant_ticket_escalation_comment_selection_v1(
				  $1,$2::uuid[]
				)`, alertID, selection.PublicCommentIDs)
			if err != nil {
				return application.SelectionEvidence{}, mapTicketDatabaseError(err)
			}
			defer rows.Close()
			comments := make([]kernel.CommentReference, 0, len(selection.PublicCommentIDs))
			for rows.Next() {
				var id uuid.UUID
				if scanErr := rows.Scan(&id); scanErr != nil {
					return application.SelectionEvidence{}, mapTicketDatabaseError(scanErr)
				}
				entity, entityErr := ticketEntityID(id)
				if entityErr != nil {
					return application.SelectionEvidence{}, entityErr
				}
				reference, referenceErr := kernel.NewCommentReference(entity, kernel.CommentPublic)
				if referenceErr != nil {
					return application.SelectionEvidence{}, application.ErrUnavailable
				}
				comments = append(comments, reference)
			}
			if err := rows.Err(); err != nil {
				return application.SelectionEvidence{}, mapTicketDatabaseError(err)
			}
			evidence.Comments = comments
			return evidence, nil
		},
	)
}

func escalationSelectionField(value string) (kernel.CopyField, error) {
	switch value {
	case "iocs":
		return kernel.CopyIOCs, nil
	case "assets":
		return kernel.CopyAssets, nil
	case "attachments":
		return kernel.CopyAttachments, nil
	case "contacts":
		return kernel.CopyContacts, nil
	default:
		return 0, application.ErrUnavailable
	}
}

func (repository *TicketingRepository) ListLinks(
	ctx context.Context,
	source application.Record,
	page application.CursorPageInput,
	sourceAccess application.LiveAccess,
	otherAccess application.LiveAccess,
) (application.StoredLinkPage, error) {
	tenantID := uuid.UUID(source.Snapshot.Tenant().Bytes())
	sourceID := uuid.UUID(source.Snapshot.ID().Bytes())
	actorID := uuid.UUID(sourceAccess.Authority.Actor().Bytes())
	otherKind := kernel.AggregateCase
	linkSourceColumn, linkOtherColumn, otherTable := "link.alert_id", "link.case_id", "public.cases"
	if source.Snapshot.Kind() == kernel.AggregateCase {
		otherKind, linkSourceColumn, linkOtherColumn, otherTable = kernel.AggregateAlert, "link.case_id", "link.alert_id", "public.alerts"
	}
	return withinTicketReadTransaction(ctx, repository, actorID, tenantID,
		func(tx databaseTransaction) (application.StoredLinkPage, error) {
			arguments := []any{tenantID, sourceID, otherKind.String()}
			add := func(value any) string {
				arguments = append(arguments, value)
				return fmt.Sprintf("$%d", len(arguments))
			}
			predicate, predicateErr := ticketAccessPredicate(otherKind, otherAccess, add)
			if predicateErr != nil {
				return application.StoredLinkPage{}, predicateErr
			}
			predicate = strings.ReplaceAll(predicate, "ticket.", "other.")
			query := `
				SELECT link.id, link.alert_id, link.case_id, link.relation,
				       link.reason, link.linked_by_user_id, link.linked_at,
				       link.source_alert_version, link.copy_fields,
				       link.custom_field_keys, link.item_ids,
				       link.public_comment_ids, link.copied_field_snapshot,
				       ` + linkOtherColumn + `
				FROM public.alert_case_links AS link
				JOIN ` + otherTable + ` AS other
				  ON other.tenant_id = link.tenant_id AND other.id = ` + linkOtherColumn + `
				JOIN public.ticket_workflow_versions AS other_workflow
				  ON other_workflow.tenant_id = other.tenant_id
				 AND other_workflow.workflow_id = other.workflow_id
				 AND other_workflow.aggregate_kind = $3::public.ticket_aggregate_kind
				 AND other_workflow.version = other.workflow_version
				WHERE link.tenant_id = $1 AND ` + linkSourceColumn + ` = $2
				  AND NOT EXISTS (
				    SELECT 1
				    FROM public.alert_case_link_retractions AS retraction
				    WHERE retraction.tenant_id = link.tenant_id
				      AND retraction.link_id = link.id
				  )
				  AND ` + predicate
			if otherAccess.Authority.Principal() == kernel.PrincipalCustomer {
				query += ` AND other.customer_visible AND EXISTS (
					SELECT 1 FROM jsonb_array_elements(other_workflow.states) AS state(value)
					WHERE state.value ->> 'key' = other.state_key
					  AND state.value ->> 'visibility' = 'customer')`
			}
			if page.After != nil {
				arguments = append(arguments, *page.After)
				query += fmt.Sprintf(" AND link.id > $%d", len(arguments))
			}
			arguments = append(arguments, page.Limit+1)
			query += fmt.Sprintf(" ORDER BY link.id LIMIT $%d", len(arguments))
			rows, err := tx.Query(ctx, query, arguments...)
			if err != nil {
				return application.StoredLinkPage{}, mapTicketDatabaseError(err)
			}
			defer rows.Close()
			items := make([]application.LinkRecord, 0, page.Limit+1)
			for rows.Next() {
				link, otherID, scanErr := scanTicketLink(rows, tenantID)
				if scanErr != nil {
					return application.StoredLinkPage{}, scanErr
				}
				other, getErr := getTicketRecord(ctx, tx, tenantID, otherKind, otherID)
				if getErr != nil {
					return application.StoredLinkPage{}, getErr
				}
				items = append(items, application.LinkRecord{Link: link, Other: other})
			}
			if err := rows.Err(); err != nil {
				return application.StoredLinkPage{}, mapTicketDatabaseError(err)
			}
			var next *uuid.UUID
			if len(items) > page.Limit {
				items = items[:page.Limit]
				value := items[len(items)-1].Link.ID
				next = &value
			}
			return application.StoredLinkPage{Items: items, NextCursor: next}, nil
		},
	)
}

func scanTicketLink(row ticketRecordScanner, tenantID uuid.UUID) (application.Link, uuid.UUID, error) {
	var result application.Link
	var sourceVersion int32
	var itemJSON, copiedJSON []byte
	var otherID uuid.UUID
	if err := row.Scan(
		&result.ID, &result.AlertID, &result.CaseID, &result.Relation,
		&result.Reason, &result.LinkedBy, &result.LinkedAt, &sourceVersion,
		&result.CopyFields, &result.CustomFieldKeys, &itemJSON,
		&result.PublicCommentIDs, &copiedJSON, &otherID,
	); err != nil {
		return application.Link{}, uuid.Nil, mapTicketDatabaseError(err)
	}
	if sourceVersion < 1 {
		return application.Link{}, uuid.Nil, application.ErrUnavailable
	}
	result.TenantID, result.SourceAlertVersion, result.LinkedAt = tenantID, uint64(sourceVersion), ticketTime(result.LinkedAt)
	var stringItems map[string][]string
	if err := json.Unmarshal(itemJSON, &stringItems); err != nil {
		return application.Link{}, uuid.Nil, application.ErrUnavailable
	}
	result.ItemIDs = make(map[string][]uuid.UUID, len(stringItems))
	for field, values := range stringItems {
		ids := make([]uuid.UUID, len(values))
		for index, value := range values {
			id, err := uuid.Parse(value)
			if err != nil {
				return application.Link{}, uuid.Nil, application.ErrUnavailable
			}
			ids[index] = id
		}
		result.ItemIDs[field] = ids
	}
	copied, err := decodeTicketMap(copiedJSON)
	if err != nil {
		return application.Link{}, uuid.Nil, err
	}
	result.CopiedFieldSnapshot = copied
	return result, otherID, nil
}

func (repository *TicketingRepository) CommitEscalation(
	ctx context.Context,
	write application.EscalationWrite,
) (application.EscalationWriteResult, error) {
	commitStatement := `
		SELECT result_case_id, result_case_version,
		       result_path_alert_version, result_metadata, replayed
		FROM app.commit_tenant_ticket_escalation_v4(
		  $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15
		)`
	switch write.Operation {
	case application.EscalationOperationEscalate:
	case application.EscalationOperationLink:
		commitStatement = `
			SELECT result_case_id, result_case_version,
			       result_path_alert_version, result_metadata, replayed
			FROM app.commit_tenant_ticket_link_v1(
			  $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15
			)`
	default:
		return application.EscalationWriteResult{}, application.ErrInvalidInput
	}
	tenantID := uuid.UUID(write.Plan.Tenant().Bytes())
	casePlan := write.Plan.CaseMutation()
	caseID := uuid.UUID(casePlan.Ticket().Bytes())
	target, sources, buildErr := escalationDatabasePlan(write)
	if buildErr != nil {
		return application.EscalationWriteResult{}, buildErr
	}
	keyDigest := write.Plan.KeyDigest()
	result, err := withinTicketWriteTransaction(ctx, repository, write.Actor, tenantID,
		func(tx databaseTransaction) (application.EscalationWriteResult, error) {
			if err := lockEscalationSharedResources(ctx, tx, tenantID, sources); err != nil {
				return application.EscalationWriteResult{}, err
			}
			var returnedCaseID uuid.UUID
			var caseVersion, pathVersion int32
			var metadata []byte
			var replayed bool
			queryErr := tx.QueryRow(ctx, commitStatement,
				write.Content.PathAlertID, caseID, write.Content.Target.NewCase != nil,
				ticketJSON(target), ticketJSON(sources), write.Content.Relation, write.Content.Reason,
				keyDigest[:], write.Fingerprint[:], write.Effects, write.Audit.RequestID,
				write.Audit.CorrelationID, write.Audit.RemoteAddress.Unmap(), write.Audit.UserAgent,
				write.Actor.AuthenticationMethod,
			).Scan(&returnedCaseID, &caseVersion, &pathVersion, &metadata, &replayed)
			if queryErr != nil {
				return application.EscalationWriteResult{}, mapTicketDatabaseError(queryErr)
			}
			return loadEscalationResult(
				ctx, tx, tenantID, write.Content.PathAlertID, returnedCaseID,
				caseVersion, pathVersion, metadata, replayed,
			)
		},
	)
	return result, mapTicketDatabaseError(err)
}

func (repository *TicketingRepository) LookupEscalationReplay(
	ctx context.Context,
	query application.EscalationReplayQuery,
) (application.EscalationWriteResult, bool, error) {
	lookupStatement := `
		SELECT result_path_alert_id, result_case_id, result_case_version,
		       result_path_alert_version, result_metadata
		FROM app.lookup_tenant_ticket_escalation_replay_v3($1,$2)`
	switch query.Operation {
	case application.EscalationOperationEscalate:
	case application.EscalationOperationLink:
		lookupStatement = `
			SELECT result_path_alert_id, result_case_id, result_case_version,
			       result_path_alert_version, result_metadata
			FROM app.lookup_tenant_ticket_link_replay_v1($1,$2)`
	default:
		return application.EscalationWriteResult{}, false, application.ErrInvalidInput
	}
	tenantID := uuid.UUID(query.Identity.Tenant().Bytes())
	actorID := uuid.UUID(query.Identity.Actor().Bytes())
	actor := application.Actor{UserID: actorID, ActiveTenantID: tenantID}
	keyDigest := query.Identity.KeyDigest()
	result, err := withinTicketActorTransaction(ctx, repository, actor, tenantID,
		func(tx databaseTransaction) (application.EscalationWriteResult, error) {
			var pathAlertID, caseID uuid.UUID
			var caseVersion, pathVersion int32
			var metadata []byte
			queryErr := tx.QueryRow(ctx, lookupStatement,
				keyDigest[:], query.Fingerprint[:],
			).Scan(&pathAlertID, &caseID, &caseVersion, &pathVersion, &metadata)
			if queryErr != nil {
				return application.EscalationWriteResult{}, queryErr
			}
			return loadEscalationResult(
				ctx, tx, tenantID, pathAlertID, caseID, caseVersion, pathVersion,
				metadata, true,
			)
		},
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return application.EscalationWriteResult{}, false, nil
	}
	if err != nil {
		return application.EscalationWriteResult{}, false, mapTicketDatabaseError(err)
	}
	return result, true, nil
}

type escalationTargetJSON struct {
	WorkflowID      uuid.UUID       `json:"workflowId"`
	WorkflowVersion uint64          `json:"workflowVersion"`
	StateKey        string          `json:"stateKey"`
	ExpectedVersion *uint64         `json:"expectedVersion,omitempty"`
	ResultVersion   uint64          `json:"resultVersion"`
	Title           *string         `json:"title,omitempty"`
	Description     *string         `json:"description,omitempty"`
	Summary         *string         `json:"summary,omitempty"`
	Severity        *string         `json:"severity,omitempty"`
	Priority        *string         `json:"priority,omitempty"`
	Category        *string         `json:"category,omitempty"`
	Classification  *string         `json:"classification,omitempty"`
	Tags            *[]string       `json:"tags,omitempty"`
	CustomFields    *map[string]any `json:"customFields,omitempty"`
	CustomerVisible *bool           `json:"customerVisible,omitempty"`
	DetectionTime   *time.Time      `json:"detectionTime,omitempty"`
	AssignedTeamID  *uuid.UUID      `json:"assignedTeamId,omitempty"`
	AssigneeUserID  *uuid.UUID      `json:"assigneeUserId,omitempty"`
}

type escalationSourceJSON struct {
	AlertID          uuid.UUID              `json:"alertId"`
	LinkID           uuid.UUID              `json:"linkId"`
	LinkedAt         time.Time              `json:"linkedAt"`
	ExpectedVersion  uint64                 `json:"expectedVersion"`
	ResultVersion    uint64                 `json:"resultVersion"`
	WorkflowID       uuid.UUID              `json:"workflowId"`
	WorkflowVersion  uint64                 `json:"workflowVersion"`
	StateKey         string                 `json:"stateKey"`
	CopyFields       []string               `json:"copyFields"`
	CustomFieldKeys  []string               `json:"customFieldKeys"`
	ItemIDs          map[string][]uuid.UUID `json:"itemIds"`
	PublicCommentIDs []uuid.UUID            `json:"publicCommentIds"`
}

func escalationDatabasePlan(write application.EscalationWrite) (escalationTargetJSON, []escalationSourceJSON, error) {
	casePlan := write.Plan.CaseMutation()
	target := escalationTargetJSON{
		WorkflowID: uuid.UUID(casePlan.WorkflowID().Bytes()), WorkflowVersion: casePlan.WorkflowVersion(),
		StateKey: casePlan.FromState().String(), ResultVersion: casePlan.NextVersion(),
	}
	if write.Content.Target.NewCase != nil {
		content := write.Content.Target.NewCase
		state := casePlan.ToState().String()
		target.StateKey = state
		target.Title, target.Description, target.Summary = &content.Title, &content.Description, &content.Summary
		target.Severity, target.Priority = &content.Severity, &content.Priority
		category := defaultTicketCategory(content.Category)
		target.Category = &category
		target.Classification = content.Classification
		target.Tags, target.CustomFields = &content.Tags, &content.CustomFields
		target.CustomerVisible = &content.CustomerVisible
		if !content.DetectionTime.IsZero() {
			value := content.DetectionTime
			target.DetectionTime = &value
		}
		target.AssignedTeamID, target.AssigneeUserID = content.AssignedTeamID, content.AssigneeUserID
		if write.CaseAssignmentPlan != nil {
			target.ResultVersion = write.CaseAssignmentPlan.NextVersion()
		}
	} else {
		expected := casePlan.ExpectedVersion()
		target.ExpectedVersion = &expected
	}
	alertPlans := make(map[uuid.UUID]kernel.MutationPlan)
	for _, plan := range write.Plan.AlertMutations() {
		alertPlans[uuid.UUID(plan.Ticket().Bytes())] = plan
	}
	sources := make([]escalationSourceJSON, 0, len(write.Plan.Links()))
	for _, link := range write.Plan.Links() {
		alertID := uuid.UUID(link.Alert().Bytes())
		plan, found := alertPlans[alertID]
		if !found {
			return escalationTargetJSON{}, nil, application.ErrUnavailable
		}
		fields := make([]string, 0, len(link.CopyFields()))
		for _, field := range link.CopyFields() {
			fields = append(fields, field.String())
		}
		custom := make([]string, 0, len(link.CustomFields()))
		for _, field := range link.CustomFields() {
			custom = append(custom, field.String())
		}
		comments := make([]uuid.UUID, 0, len(link.PublicComments()))
		for _, comment := range link.PublicComments() {
			comments = append(comments, uuid.UUID(comment.ID().Bytes()))
		}
		items := make(map[string][]uuid.UUID)
		for _, item := range link.Items() {
			key := escalationItemDatabaseField(item.Field())
			if key == "" {
				return escalationTargetJSON{}, nil, application.ErrUnavailable
			}
			items[key] = append(items[key], uuid.UUID(item.ID().Bytes()))
		}
		sources = append(sources, escalationSourceJSON{
			AlertID: alertID, LinkID: uuid.UUID(link.LinkID().Bytes()), LinkedAt: link.LinkedAt(),
			ExpectedVersion: plan.ExpectedVersion(), ResultVersion: plan.NextVersion(),
			WorkflowID: uuid.UUID(plan.WorkflowID().Bytes()), WorkflowVersion: plan.WorkflowVersion(),
			StateKey: plan.FromState().String(), CopyFields: fields, CustomFieldKeys: custom,
			ItemIDs: items, PublicCommentIDs: comments,
		})
	}
	return target, sources, nil
}

func escalationItemDatabaseField(field kernel.CopyField) string {
	switch field {
	case kernel.CopyIOCs:
		return "iocIds"
	case kernel.CopyAssets:
		return "assetIds"
	case kernel.CopyAttachments:
		return "attachmentIds"
	case kernel.CopyContacts:
		return "contactIds"
	default:
		return ""
	}
}

type escalationResultMetadata struct {
	PathAlertVersion int32       `json:"pathAlertVersion"`
	LinkIDs          []uuid.UUID `json:"linkIds"`
	Effects          []string    `json:"effects"`
}

func loadEscalationResult(
	ctx context.Context,
	tx databaseTransaction,
	tenantID, pathAlertID, caseID uuid.UUID,
	caseVersion, pathVersion int32,
	metadataJSON []byte,
	replayed bool,
) (application.EscalationWriteResult, error) {
	var metadata escalationResultMetadata
	if json.Unmarshal(metadataJSON, &metadata) != nil || metadata.PathAlertVersion != pathVersion || len(metadata.LinkIDs) == 0 {
		return application.EscalationWriteResult{}, application.ErrUnavailable
	}
	alert, err := getTicketRecord(ctx, tx, tenantID, kernel.AggregateAlert, pathAlertID)
	if err != nil {
		return application.EscalationWriteResult{}, err
	}
	caseRecord, err := getTicketRecord(ctx, tx, tenantID, kernel.AggregateCase, caseID)
	if err != nil {
		return application.EscalationWriteResult{}, err
	}
	if alert.Snapshot.Version() < uint64(pathVersion) || caseRecord.Snapshot.Version() < uint64(caseVersion) {
		return application.EscalationWriteResult{}, application.ErrUnavailable
	}
	rows, err := tx.Query(ctx, `
		SELECT link.id, link.alert_id, link.case_id, link.relation,
		       link.reason, link.linked_by_user_id, link.linked_at,
		       link.source_alert_version, link.copy_fields,
		       link.custom_field_keys, link.item_ids, link.public_comment_ids,
		       link.copied_field_snapshot, link.case_id
		FROM public.alert_case_links AS link
		WHERE link.tenant_id = $1 AND link.id = ANY($2::uuid[])
		ORDER BY link.id`, tenantID, metadata.LinkIDs)
	if err != nil {
		return application.EscalationWriteResult{}, mapTicketDatabaseError(err)
	}
	defer rows.Close()
	links := make([]application.Link, 0, len(metadata.LinkIDs))
	for rows.Next() {
		link, _, scanErr := scanTicketLink(rows, tenantID)
		if scanErr != nil {
			return application.EscalationWriteResult{}, scanErr
		}
		links = append(links, link)
	}
	if err := rows.Err(); err != nil {
		return application.EscalationWriteResult{}, mapTicketDatabaseError(err)
	}
	if len(links) != len(metadata.LinkIDs) {
		return application.EscalationWriteResult{}, application.ErrUnavailable
	}
	return application.EscalationWriteResult{
		Alert: alert, Case: caseRecord, Links: links, Effects: metadata.Effects, Replayed: replayed,
	}, nil
}

func withinTicketReadTransaction[T any](
	ctx context.Context,
	repository *TicketingRepository,
	actorID uuid.UUID,
	tenantID uuid.UUID,
	work func(databaseTransaction) (T, error),
) (T, error) {
	actor := application.Actor{UserID: actorID, ActiveTenantID: tenantID}
	return withinTicketActorTransactionWithOptions(
		ctx, repository, actor, tenantID,
		pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, work,
	)
}

func withinTicketActorTransaction[T any](
	ctx context.Context,
	repository *TicketingRepository,
	actor application.Actor,
	tenantID uuid.UUID,
	work func(databaseTransaction) (T, error),
) (T, error) {
	return withinTicketActorTransactionWithOptions(
		ctx, repository, actor, tenantID, pgx.TxOptions{IsoLevel: pgx.ReadCommitted}, work,
	)
}

func withinTicketWriteTransaction[T any](
	ctx context.Context,
	repository *TicketingRepository,
	actor application.Actor,
	tenantID uuid.UUID,
	work func(databaseTransaction) (T, error),
) (T, error) {
	return withinTicketActorTransactionWithOptions(
		ctx, repository, actor, tenantID, pgx.TxOptions{IsoLevel: pgx.Serializable}, work,
	)
}

func withinTicketActorTransactionWithOptions[T any](
	ctx context.Context,
	repository *TicketingRepository,
	actor application.Actor,
	tenantID uuid.UUID,
	options pgx.TxOptions,
	work func(databaseTransaction) (T, error),
) (T, error) {
	return withinTicketActorTransactionWithOptionsAndMapper(
		ctx, repository, actor, tenantID, options, work, mapTicketDatabaseError,
	)
}

func withinTicketActorTransactionWithOptionsAndMapper[T any](
	ctx context.Context,
	repository *TicketingRepository,
	actor application.Actor,
	tenantID uuid.UUID,
	options pgx.TxOptions,
	work func(databaseTransaction) (T, error),
	mapDatabaseError func(error) error,
) (T, error) {
	var zero T
	if repository == nil || repository.begin == nil || work == nil || mapDatabaseError == nil ||
		actor.UserID == uuid.Nil || tenantID == uuid.Nil {
		return zero, application.ErrForbidden
	}
	result, err := withinTransactionWithOptions(ctx, repository.begin, options,
		func(tx databaseTransaction) (T, error) {
			installed, installErr := dbsql.New(tx).SetTenantContext(ctx, dbsql.SetTenantContextParams{
				TenantID: toDatabaseUUID(tenantID), UserID: toDatabaseUUID(actor.UserID),
			})
			if installErr != nil {
				return zero, mapDatabaseError(installErr)
			}
			if installed == nil || installed.TenantID != tenantID.String() || installed.UserID != actor.UserID.String() {
				return zero, application.ErrUnavailable
			}
			if traceErr := installPersistedTraceContext(ctx, tx); traceErr != nil {
				return zero, mapDatabaseError(traceErr)
			}
			return work(tx)
		},
	)
	if err != nil {
		return zero, mapDatabaseError(err)
	}
	return result, nil
}
