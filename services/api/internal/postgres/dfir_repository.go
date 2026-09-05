package postgres

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	kernel "github.com/periapsis-im/periapsis/modules/dfir"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	application "github.com/periapsis-im/periapsis/services/api/internal/dfir"
)

// DFIRRepository is the PostgreSQL adapter for the bounded DFIR application
// port. Every human operation installs an exact actor context and resolves
// current authority inside the transaction that consumes it.
type DFIRRepository struct {
	begin transactionBeginner
	newID func() (uuid.UUID, error)
}

func NewDFIRRepository(pool *pgxpool.Pool) *DFIRRepository {
	if pool == nil {
		return nil
	}
	return &DFIRRepository{begin: poolTransactionBeginner(pool), newID: uuid.NewV7}
}

var _ application.Repository = (*DFIRRepository)(nil)

func (repository *DFIRRepository) ResolveAccess(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	capability application.Capability,
	scope application.ResourceScope,
) (application.Access, error) {
	if repository == nil || repository.begin == nil {
		return application.Access{}, errors.New("DFIR repository is not configured")
	}
	access, err := withinTransactionWithOptions(
		ctx, repository.begin, phase4ReadOptions(),
		func(tx databaseTransaction) (application.Access, error) {
			return resolveDFIRAccessInTransaction(ctx, tx, actor, tenantID, capability, scope.CaseID)
		},
	)
	return access, mapDFIRDatabaseError(err)
}

func (repository *DFIRRepository) ResolveAlertAccess(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	capability application.Capability,
	scope application.AlertResourceScope,
) (application.Access, error) {
	if repository == nil || repository.begin == nil {
		return application.Access{}, errors.New("DFIR repository is not configured")
	}
	access, err := withinTransactionWithOptions(
		ctx, repository.begin, phase4ReadOptions(),
		func(tx databaseTransaction) (application.Access, error) {
			return resolveDFIRAlertAccessInTransaction(ctx, tx, actor, tenantID, capability, scope.AlertID)
		},
	)
	return access, mapDFIRDatabaseError(err)
}

func (repository *DFIRRepository) ResolveSubjectAccess(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	capability application.Capability,
	caseID kernel.EntityID,
	subject kernel.EntityReference,
) (application.SubjectAccess, error) {
	if repository == nil || repository.begin == nil {
		return application.SubjectAccess{}, errors.New("DFIR repository is not configured")
	}
	result, err := withinTransactionWithOptions(
		ctx, repository.begin, phase4ReadOptions(),
		func(tx databaseTransaction) (application.SubjectAccess, error) {
			authority, resolveErr := phase4Authority(ctx, tx, dfirAuthorizationActor(actor), tenantID)
			if resolveErr != nil {
				return application.SubjectAccess{}, resolveErr
			}
			if err := validateDFIRAuthority(authority, actor); err != nil {
				return application.SubjectAccess{}, err
			}
			caseUUID := uuid.UUID(caseID.Bytes())
			visibility, subjectErr := resolveDFIRCaseSubject(ctx, tx, tenantID, caseUUID, subject)
			if subjectErr != nil {
				return application.SubjectAccess{}, subjectErr
			}
			access, accessErr := dfirAccessForCase(ctx, tx, authority, actor, capability, caseUUID)
			if accessErr != nil {
				return application.SubjectAccess{}, accessErr
			}
			return application.SubjectAccess{CaseID: caseID, Access: access, SubjectVisibility: visibility}, nil
		},
	)
	return result, mapDFIRDatabaseError(err)
}

func (repository *DFIRRepository) ResolveAlertSubjectAccess(
	ctx context.Context,
	actor application.Actor,
	tenantID uuid.UUID,
	capability application.Capability,
	alertID kernel.EntityID,
	subject kernel.EntityReference,
) (application.AlertSubjectAccess, error) {
	if repository == nil || repository.begin == nil {
		return application.AlertSubjectAccess{}, errors.New("DFIR repository is not configured")
	}
	result, err := withinTransactionWithOptions(
		ctx, repository.begin, phase4ReadOptions(),
		func(tx databaseTransaction) (application.AlertSubjectAccess, error) {
			authority, resolveErr := phase4Authority(ctx, tx, dfirAuthorizationActor(actor), tenantID)
			if resolveErr != nil {
				return application.AlertSubjectAccess{}, resolveErr
			}
			if err := validateDFIRAuthority(authority, actor); err != nil || actor.Kind != application.PrincipalHuman {
				if err != nil {
					return application.AlertSubjectAccess{}, err
				}
				return application.AlertSubjectAccess{}, authorization.ErrForbidden
			}
			alertUUID := uuid.UUID(alertID.Bytes())
			visibility, subjectErr := resolveDFIRAlertSubject(ctx, tx, tenantID, alertUUID, subject)
			if subjectErr != nil {
				return application.AlertSubjectAccess{}, subjectErr
			}
			access, accessErr := dfirAccessForAlert(ctx, tx, authority, actor, capability, alertUUID)
			if accessErr != nil {
				return application.AlertSubjectAccess{}, accessErr
			}
			return application.AlertSubjectAccess{
				AlertID: entityID(alertUUID), Access: access, SubjectVisibility: visibility,
			}, nil
		},
	)
	return result, mapDFIRDatabaseError(err)
}

func resolveDFIRAccessInTransaction(
	ctx context.Context,
	tx databaseTransaction,
	actor application.Actor,
	tenantID uuid.UUID,
	capability application.Capability,
	caseID kernel.EntityID,
) (application.Access, error) {
	if caseID == (kernel.EntityID{}) {
		return application.Access{}, application.ErrRepositoryForbidden
	}
	authority, err := phase4Authority(ctx, tx, dfirAuthorizationActor(actor), tenantID)
	if err != nil {
		return application.Access{}, err
	}
	if err = validateDFIRAuthority(authority, actor); err != nil {
		return application.Access{}, err
	}
	return dfirAccessForCase(ctx, tx, authority, actor, capability, uuid.UUID(caseID.Bytes()))
}

func resolveDFIRAlertAccessInTransaction(
	ctx context.Context,
	tx databaseTransaction,
	actor application.Actor,
	tenantID uuid.UUID,
	capability application.Capability,
	alertID kernel.EntityID,
) (application.Access, error) {
	if alertID == (kernel.EntityID{}) || actor.Kind != application.PrincipalHuman {
		return application.Access{}, application.ErrRepositoryForbidden
	}
	authority, err := phase4Authority(ctx, tx, dfirAuthorizationActor(actor), tenantID)
	if err != nil {
		return application.Access{}, err
	}
	if err = validateDFIRAuthority(authority, actor); err != nil {
		return application.Access{}, err
	}
	return dfirAccessForAlert(ctx, tx, authority, actor, capability, uuid.UUID(alertID.Bytes()))
}

func dfirAccessForAlert(
	ctx context.Context,
	tx databaseTransaction,
	authority authorization.TenantAuthority,
	actor application.Actor,
	capability application.Capability,
	alertID uuid.UUID,
) (application.Access, error) {
	if actor.Kind != application.PrincipalHuman || !validAlertDFIRCapability(capability) || !authorizationUUIDv7(alertID) {
		return application.Access{}, authorization.ErrForbidden
	}
	record, err := loadDFIRAlertAccessRecord(ctx, tx, actor.TenantID, alertID)
	if err != nil {
		return application.Access{}, err
	}
	permission := string(capability)
	scope := application.Scope("")
	if phase4HasPermission(authority, permission, authorization.ScopeTenant) {
		scope = application.ScopeTenant
	} else if phase4HasPermission(authority, permission, authorization.ScopeAssigned) &&
		(record.assigneeUserID != nil && *record.assigneeUserID == actor.UserID ||
			record.claimedByUserID != nil && *record.claimedByUserID == actor.UserID) {
		scope = application.ScopeAssigned
	} else if phase4HasPermission(authority, permission, authorization.ScopeOperatorTeam) &&
		record.assignedTeamID != nil && record.assignedTeamEpochID != nil &&
		slices.ContainsFunc(authority.OperatorTeamRelationships, func(value authorization.OperatorTeamRelationship) bool {
			return value.OperatorTeamID == *record.assignedTeamID &&
				value.AssignmentEpochID == *record.assignedTeamEpochID
		}) {
		scope = application.ScopeOperatorTeam
	}
	if scope == "" {
		return application.Access{}, authorization.ErrForbidden
	}
	return application.Access{Audience: kernel.AudienceOperator, Scope: scope}, nil
}

func dfirAccessForCase(
	ctx context.Context,
	tx databaseTransaction,
	authority authorization.TenantAuthority,
	actor application.Actor,
	capability application.Capability,
	caseID uuid.UUID,
) (application.Access, error) {
	if !validDFIRCapability(capability) || !authorizationUUIDv7(caseID) {
		return application.Access{}, authorization.ErrForbidden
	}
	caseRecord, err := loadDFIRCaseAccessRecord(ctx, tx, actor.TenantID, caseID)
	if err != nil {
		return application.Access{}, err
	}
	customer := actor.Kind == application.PrincipalCustomer
	manage := dfirManageCapability(capability)
	if customer && (manage || !caseRecord.customerVisible || !caseRecord.customerState) {
		return application.Access{}, authorization.ErrForbidden
	}

	permission := string(capability)
	scope := application.Scope("")
	if phase4HasPermission(authority, permission, authorization.ScopeTenant) {
		scope = application.ScopeTenant
	} else if phase4HasPermission(authority, permission, authorization.ScopeAssigned) &&
		(customer || caseRecord.assigneeUserID != nil && *caseRecord.assigneeUserID == actor.UserID ||
			caseRecord.claimedByUserID != nil && *caseRecord.claimedByUserID == actor.UserID) {
		scope = application.ScopeAssigned
	} else if phase4HasPermission(authority, permission, authorization.ScopeOperatorTeam) &&
		caseRecord.assignedTeamID != nil && caseRecord.assignedTeamEpochID != nil &&
		slices.ContainsFunc(authority.OperatorTeamRelationships, func(value authorization.OperatorTeamRelationship) bool {
			return value.OperatorTeamID == *caseRecord.assignedTeamID &&
				value.AssignmentEpochID == *caseRecord.assignedTeamEpochID
		}) {
		scope = application.ScopeOperatorTeam
	}
	if scope == "" || customer && scope != application.ScopeAssigned {
		return application.Access{}, authorization.ErrForbidden
	}
	audience := kernel.AudienceOperator
	if customer {
		audience = kernel.AudienceCustomer
	}
	return application.Access{Audience: audience, Scope: scope}, nil
}

type dfirCaseAccessRecord struct {
	customerVisible     bool
	customerState       bool
	assigneeUserID      *uuid.UUID
	claimedByUserID     *uuid.UUID
	assignedTeamID      *uuid.UUID
	assignedTeamEpochID *uuid.UUID
}

type dfirAlertAccessRecord struct {
	assigneeUserID      *uuid.UUID
	claimedByUserID     *uuid.UUID
	assignedTeamID      *uuid.UUID
	assignedTeamEpochID *uuid.UUID
}

func loadDFIRAlertAccessRecord(
	ctx context.Context,
	tx databaseTransaction,
	tenantID uuid.UUID,
	alertID uuid.UUID,
) (dfirAlertAccessRecord, error) {
	var result dfirAlertAccessRecord
	err := tx.QueryRow(ctx, `
		SELECT alert.assignee_user_id, alert.claimed_by_user_id,
		       alert.assigned_team_id, alert.assigned_team_epoch_id
		FROM public.alerts AS alert
		WHERE alert.tenant_id = $1 AND alert.id = $2 AND alert.deleted_at IS NULL`,
		tenantID, alertID,
	).Scan(&result.assigneeUserID, &result.claimedByUserID, &result.assignedTeamID, &result.assignedTeamEpochID)
	if err != nil {
		return dfirAlertAccessRecord{}, err
	}
	if result.assignedTeamID == nil != (result.assignedTeamEpochID == nil) {
		return dfirAlertAccessRecord{}, errors.New("database returned an invalid DFIR Alert assignment")
	}
	return result, nil
}

func loadDFIRCaseAccessRecord(
	ctx context.Context,
	tx databaseTransaction,
	tenantID uuid.UUID,
	caseID uuid.UUID,
) (dfirCaseAccessRecord, error) {
	var result dfirCaseAccessRecord
	err := tx.QueryRow(ctx, `
		SELECT ticket.customer_visible, ticket.assignee_user_id,
		       ticket.claimed_by_user_id, ticket.assigned_team_id,
		       ticket.assigned_team_epoch_id,
		       EXISTS (
		         SELECT 1
		         FROM jsonb_array_elements(workflow.states) AS state(value)
		         WHERE state.value ->> 'key' = ticket.state_key
		           AND state.value ->> 'visibility' = 'customer'
		       )
		FROM public.cases AS ticket
		JOIN public.ticket_workflow_versions AS workflow
		  ON workflow.tenant_id = ticket.tenant_id
		 AND workflow.workflow_id = ticket.workflow_id
		 AND workflow.version = ticket.workflow_version
		 AND workflow.aggregate_kind = 'case'::public.ticket_aggregate_kind
		WHERE ticket.tenant_id = $1 AND ticket.id = $2`, tenantID, caseID).Scan(
		&result.customerVisible, &result.assigneeUserID, &result.claimedByUserID,
		&result.assignedTeamID, &result.assignedTeamEpochID, &result.customerState,
	)
	if err != nil {
		return dfirCaseAccessRecord{}, err
	}
	if result.assignedTeamID == nil != (result.assignedTeamEpochID == nil) {
		return dfirCaseAccessRecord{}, errors.New("database returned an invalid DFIR Case assignment")
	}
	return result, nil
}

func resolveDFIRAlertSubject(
	ctx context.Context,
	tx databaseTransaction,
	tenantID uuid.UUID,
	alertID uuid.UUID,
	subject kernel.EntityReference,
) (kernel.Visibility, error) {
	if subject.ID() == (kernel.EntityID{}) || uuid.UUID(subject.TenantID().Bytes()) != tenantID ||
		!authorizationUUIDv7(alertID) {
		return "", authorization.ErrForbidden
	}
	subjectID := uuid.UUID(subject.ID().Bytes())
	visibility := kernel.VisibilityPrivate
	switch subject.Kind() {
	case kernel.EntityAlert:
		if subjectID != alertID {
			return "", authorization.ErrForbidden
		}
		var customerVisible, customerState bool
		err := tx.QueryRow(ctx, `
			SELECT alert.customer_visible,
			       EXISTS (
			         SELECT 1 FROM jsonb_array_elements(workflow.states) AS state(value)
			         WHERE state.value ->> 'key' = alert.state_key
			           AND state.value ->> 'visibility' = 'customer'
			       )
			FROM public.alerts AS alert
			JOIN public.ticket_workflow_versions AS workflow
			  ON workflow.tenant_id = alert.tenant_id
			 AND workflow.workflow_id = alert.workflow_id
			 AND workflow.version = alert.workflow_version
			 AND workflow.aggregate_kind = 'alert'::public.ticket_aggregate_kind
			WHERE alert.tenant_id = $1 AND alert.id = $2 AND alert.deleted_at IS NULL`,
			tenantID, alertID,
		).Scan(&customerVisible, &customerState)
		if err != nil {
			return "", err
		}
		if customerVisible && customerState {
			visibility = kernel.VisibilityPublic
		}
	case kernel.EntityIOC, kernel.EntityAsset:
		linkTable, resourceTable, resourceColumn := "public.dfir_ioc_links", "public.dfir_iocs", "ioc_id"
		if subject.Kind() == kernel.EntityAsset {
			linkTable, resourceTable, resourceColumn = "public.dfir_asset_links", "public.dfir_assets", "asset_id"
		}
		var linked bool
		err := tx.QueryRow(ctx, `SELECT EXISTS (
			SELECT 1
			FROM `+linkTable+` AS link
			JOIN `+resourceTable+` AS resource
			  ON resource.tenant_id = link.tenant_id
			 AND resource.id = link.`+resourceColumn+`
			WHERE link.tenant_id = $1 AND link.alert_id = $2
			  AND link.`+resourceColumn+` = $3 AND resource.archived_at IS NULL
		)`, tenantID, alertID, subjectID).Scan(&linked)
		if err != nil {
			return "", err
		}
		if !linked {
			return "", pgx.ErrNoRows
		}
	default:
		return "", authorization.ErrForbidden
	}
	return visibility, nil
}

func dfirAttachmentSubject(
	kind string,
	alertID, caseID, iocID, assetID, evidenceID, taskID *uuid.UUID,
) (kernel.EntityKind, uuid.UUID, error) {
	values := map[kernel.EntityKind]*uuid.UUID{
		kernel.EntityAlert: alertID, kernel.EntityCase: caseID, kernel.EntityIOC: iocID,
		kernel.EntityAsset: assetID, kernel.EntityEvidence: evidenceID, kernel.EntityTask: taskID,
	}
	nestedKind := kernel.EntityKind(kind)
	value, exists := values[nestedKind]
	count := 0
	for _, candidate := range values {
		if candidate != nil {
			count++
		}
	}
	if !exists || value == nil || count != 1 || !authorizationUUIDv7(*value) {
		return "", uuid.Nil, errors.New("database returned an invalid attachment subject")
	}
	return nestedKind, *value, nil
}

func validateDFIRAuthority(authority authorization.TenantAuthority, actor application.Actor) error {
	if !validPhase4Authority(authority, actor.MembershipID) || authority.Principal.ID != actor.UserID ||
		authority.TenantID != actor.TenantID {
		return authorization.ErrForbidden
	}
	if actor.Kind != application.PrincipalCustomer && actor.Kind != application.PrincipalHuman {
		return authorization.ErrForbidden
	}
	return nil
}

func dfirAuthorizationActor(actor application.Actor) authorization.Actor {
	return authorization.Actor{
		UserID: actor.UserID, SessionID: actor.SessionID,
		ActiveTenantID: actor.ActiveTenantID, AuthenticationMethod: actor.AuthenticationMethod,
	}
}

func sameDFIRAccess(left, right application.Access) bool {
	return left.Audience == right.Audience && left.Scope == right.Scope
}

func validDFIRCapability(value application.Capability) bool {
	switch value {
	case application.CapabilityIOCRead, application.CapabilityIOCManage,
		application.CapabilityAssetRead, application.CapabilityAssetManage,
		application.CapabilityEvidenceRead, application.CapabilityEvidenceManage,
		application.CapabilityTimelineRead, application.CapabilityTimelineManage,
		application.CapabilityTaskRead, application.CapabilityTaskManage,
		application.CapabilityAttachmentRead, application.CapabilityAttachmentManage,
		application.CapabilityRelationshipRead, application.CapabilityRelationshipManage:
		return true
	default:
		return false
	}
}

func validAlertDFIRCapability(value application.Capability) bool {
	switch value {
	case application.CapabilityIOCRead, application.CapabilityIOCManage,
		application.CapabilityAssetRead, application.CapabilityAssetManage,
		application.CapabilityEvidenceRead, application.CapabilityEvidenceManage,
		application.CapabilityTimelineRead, application.CapabilityTimelineManage,
		application.CapabilityTaskRead, application.CapabilityTaskManage,
		application.CapabilityAttachmentRead, application.CapabilityAttachmentManage,
		application.CapabilityRelationshipRead, application.CapabilityRelationshipManage:
		return true
	default:
		return false
	}
}

func dfirManageCapability(value application.Capability) bool {
	switch value {
	case application.CapabilityIOCManage, application.CapabilityAssetManage,
		application.CapabilityEvidenceManage, application.CapabilityTimelineManage,
		application.CapabilityTaskManage, application.CapabilityAttachmentManage,
		application.CapabilityRelationshipManage:
		return true
	default:
		return false
	}
}

func validDFIRCommand(binding application.CommandBinding, operation string) bool {
	return binding.Operation == operation && binding.KeyDigest != [sha256.Size]byte{} &&
		binding.RequestDigest != [sha256.Size]byte{}
}

func mapDFIRDatabaseError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, application.ErrRepositoryForbidden), errors.Is(err, authorization.ErrForbidden):
		return application.ErrRepositoryForbidden
	case errors.Is(err, application.ErrRepositoryNotFound), errors.Is(err, authorization.ErrNotFound), errors.Is(err, pgx.ErrNoRows):
		return application.ErrRepositoryNotFound
	case errors.Is(err, application.ErrRepositoryPrecondition):
		return application.ErrRepositoryPrecondition
	case errors.Is(err, application.ErrRepositoryConflict), errors.Is(err, authorization.ErrConflict):
		return application.ErrRepositoryConflict
	}
	switch postgresCode(err) {
	case "42501":
		return application.ErrRepositoryForbidden
	case "P0002":
		return application.ErrRepositoryNotFound
	case "40001":
		return application.ErrRepositoryPrecondition
	case "23505", "23503", "23514", "40P01", "22023", "22P02", "55000":
		return application.ErrRepositoryConflict
	default:
		return err
	}
}

func entityID(value uuid.UUID) kernel.EntityID {
	result, _ := kernel.NewEntityID([16]byte(value))
	return result
}

func optionalEntityID(value *uuid.UUID) *kernel.EntityID {
	if value == nil {
		return nil
	}
	converted := entityID(*value)
	return &converted
}

func unexpectedDFIRProjection(message string) error {
	return fmt.Errorf("database returned an invalid DFIR projection: %s", message)
}
