package postgres

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/services/api/internal/identityprovider"
	"github.com/periapsis-im/periapsis/services/api/internal/postgres/dbsql"
)

type ldapAdministrationQueries interface {
	SetTenantContext(context.Context, dbsql.SetTenantContextParams) (*dbsql.SetTenantContextRow, error)
	ListTenantLDAPBindings(context.Context, dbsql.ListTenantLDAPBindingsParams) ([]*dbsql.ListTenantLDAPBindingsRow, error)
	GetTenantLDAPBinding(context.Context, dbsql.GetTenantLDAPBindingParams) (*dbsql.GetTenantLDAPBindingRow, error)
	GetTenantLDAPBindingMutationResult(context.Context, dbsql.GetTenantLDAPBindingMutationResultParams) (*dbsql.GetTenantLDAPBindingMutationResultRow, error)
	CreateTenantLDAPBinding(context.Context, dbsql.CreateTenantLDAPBindingParams) (*dbsql.CreateTenantLDAPBindingRow, error)
	UpdateTenantLDAPBinding(context.Context, dbsql.UpdateTenantLDAPBindingParams) (int32, error)
	ArchiveTenantLDAPBinding(context.Context, dbsql.ArchiveTenantLDAPBindingParams) (int32, error)
	ListTenantLDAPMappings(context.Context, dbsql.ListTenantLDAPMappingsParams) ([]*dbsql.ListTenantLDAPMappingsRow, error)
	GetTenantLDAPMapping(context.Context, dbsql.GetTenantLDAPMappingParams) (*dbsql.GetTenantLDAPMappingRow, error)
	GetTenantLDAPMappingMutationResult(context.Context, dbsql.GetTenantLDAPMappingMutationResultParams) (*dbsql.GetTenantLDAPMappingMutationResultRow, error)
	CreateTenantLDAPMapping(context.Context, dbsql.CreateTenantLDAPMappingParams) (*dbsql.CreateTenantLDAPMappingRow, error)
	UpdateTenantLDAPMapping(context.Context, dbsql.UpdateTenantLDAPMappingParams) (int32, error)
	ArchiveTenantLDAPMapping(context.Context, dbsql.ArchiveTenantLDAPMappingParams) (int32, error)
}

var _ identityprovider.AdministrationRepository = (*IdentityProviderRepository)(nil)

func (r *IdentityProviderRepository) ListBindings(
	ctx context.Context,
	params identityprovider.ListBindingParams,
) ([]identityprovider.Binding, error) {
	if !validLDAPAdministrationPage(params.HumanParams, params.After, params.Limit) {
		return nil, identityprovider.ErrInvalidInput
	}
	return withLDAPAdministrationTransaction(ctx, r, params.HumanParams,
		func(queries ldapAdministrationQueries) ([]identityprovider.Binding, error) {
			rows, err := queries.ListTenantLDAPBindings(ctx, dbsql.ListTenantLDAPBindingsParams{
				AfterBindingID: optionalDatabaseUUID(params.After), IncludeArchived: params.IncludeArchived,
				PageSize: params.Limit,
			})
			if err != nil {
				return nil, mapIdentityProviderDatabaseError(err)
			}
			if len(rows) > int(params.Limit) {
				return nil, invalidIdentityProviderProjection("oversized LDAP binding page")
			}
			result := make([]identityprovider.Binding, 0, len(rows))
			var previous uuid.UUID
			if params.After != nil {
				previous = *params.After
			}
			for _, row := range rows {
				binding, mapErr := mapListedLDAPBinding(params.TenantID, row)
				if mapErr != nil {
					return nil, mapErr
				}
				if previous != uuid.Nil && bytes.Compare(binding.ID[:], previous[:]) <= 0 ||
					!params.IncludeArchived && binding.ArchivedAt != nil {
					return nil, invalidIdentityProviderProjection("invalid LDAP binding page order or lifecycle")
				}
				previous = binding.ID
				result = append(result, binding)
			}
			return result, nil
		},
	)
}

func (r *IdentityProviderRepository) GetBinding(
	ctx context.Context,
	params identityprovider.GetBindingParams,
) (identityprovider.Binding, error) {
	if !validIdentityProviderHuman(params.HumanParams) || !identityProviderUUIDv7(params.BindingID) {
		return identityprovider.Binding{}, identityprovider.ErrInvalidInput
	}
	return withLDAPAdministrationTransaction(ctx, r, params.HumanParams,
		func(queries ldapAdministrationQueries) (identityprovider.Binding, error) {
			return getLDAPBinding(ctx, queries, params.TenantID, params.BindingID)
		},
	)
}

func (r *IdentityProviderRepository) CreateBinding(
	ctx context.Context,
	params identityprovider.CreateBindingParams,
) (identityprovider.BindingMutationResult, error) {
	if !validLDAPBindingCreate(params) {
		return identityprovider.BindingMutationResult{}, identityprovider.ErrInvalidInput
	}
	audit, err := identityProviderAuditArgumentsFor(params.Audit, params.OccurredAt, params.Actor.AuthenticationMethod)
	if err != nil {
		return identityprovider.BindingMutationResult{}, err
	}
	return withLDAPAdministrationTransaction(ctx, r, params.HumanParams,
		func(queries ldapAdministrationQueries) (identityprovider.BindingMutationResult, error) {
			row, queryErr := queries.CreateTenantLDAPBinding(ctx, dbsql.CreateTenantLDAPBindingParams{
				IdempotencyKeyDigest: append([]byte(nil), params.IdempotencyKeyDigest[:]...),
				ProviderID:           toDatabaseUUID(params.ProviderID), LoginKey: params.LoginKey,
				Enabled: params.Enabled, ProfilePriority: int32(params.ProfilePriority),
				AuditEventID: toDatabaseUUID(params.AuditEventID), RequestID: audit.requestID,
				CorrelationID: audit.correlationID, IpAddress: audit.remoteAddress,
				UserAgent: audit.userAgent, AuthenticationMethod: audit.authenticationMethod,
			})
			if queryErr != nil {
				return identityprovider.BindingMutationResult{}, mapIdentityProviderDatabaseError(queryErr)
			}
			if row == nil || row.ResultVersion < 1 || !row.Replayed && row.ResultVersion != 1 {
				return identityprovider.BindingMutationResult{}, invalidIdentityProviderProjection("invalid LDAP binding create result")
			}
			bindingID, mapErr := domainUUID(row.BindingID)
			if mapErr != nil || !identityProviderUUIDv7(bindingID) {
				return identityprovider.BindingMutationResult{}, invalidIdentityProviderProjection("invalid created LDAP binding ID")
			}
			binding, mapErr := getLDAPBindingMutationResult(ctx, queries, params.TenantID, bindingID)
			versionMatches := row.Replayed && binding.Version >= int64(row.ResultVersion) ||
				!row.Replayed && binding.Version == int64(row.ResultVersion)
			if mapErr != nil || !versionMatches {
				if mapErr != nil {
					return identityprovider.BindingMutationResult{}, mapErr
				}
				return identityprovider.BindingMutationResult{}, invalidIdentityProviderProjection("stale LDAP binding create result")
			}
			if binding.ProviderID != params.ProviderID || !row.Replayed &&
				!ldapBindingMatchesWrite(binding, params.LoginKey, params.Enabled, params.ProfilePriority) {
				return identityprovider.BindingMutationResult{}, invalidIdentityProviderProjection("divergent LDAP binding create result")
			}
			return identityprovider.BindingMutationResult{Binding: binding, Replayed: row.Replayed}, nil
		},
	)
}

func (r *IdentityProviderRepository) UpdateBinding(
	ctx context.Context,
	params identityprovider.UpdateBindingParams,
) (identityprovider.Binding, error) {
	version, err := identityProviderDatabaseVersion(params.ExpectedVersion)
	if err != nil || !validLDAPBindingUpdate(params) {
		return identityprovider.Binding{}, identityprovider.ErrInvalidInput
	}
	audit, err := identityProviderAuditArgumentsFor(params.Audit, params.OccurredAt, params.Actor.AuthenticationMethod)
	if err != nil {
		return identityprovider.Binding{}, err
	}
	return withLDAPAdministrationTransaction(ctx, r, params.HumanParams,
		func(queries ldapAdministrationQueries) (identityprovider.Binding, error) {
			updated, queryErr := queries.UpdateTenantLDAPBinding(ctx, dbsql.UpdateTenantLDAPBindingParams{
				BindingID: toDatabaseUUID(params.BindingID), ExpectedVersion: version,
				LoginKey: params.LoginKey, Enabled: params.Enabled, ProfilePriority: int32(params.ProfilePriority),
				RequestID: audit.requestID, CorrelationID: audit.correlationID, IpAddress: audit.remoteAddress,
				UserAgent: audit.userAgent, AuthenticationMethod: audit.authenticationMethod,
			})
			if queryErr != nil {
				return identityprovider.Binding{}, mapIdentityProviderDatabaseError(queryErr)
			}
			if int64(updated) != params.ExpectedVersion+1 {
				return identityprovider.Binding{}, invalidIdentityProviderProjection("unexpected LDAP binding update version")
			}
			binding, mapErr := getLDAPBindingMutationResult(ctx, queries, params.TenantID, params.BindingID)
			if mapErr != nil || int64(updated) != binding.Version {
				if mapErr != nil {
					return identityprovider.Binding{}, mapErr
				}
				return identityprovider.Binding{}, invalidIdentityProviderProjection("stale LDAP binding update result")
			}
			if !ldapBindingMatchesWrite(binding, params.LoginKey, params.Enabled, params.ProfilePriority) {
				return identityprovider.Binding{}, invalidIdentityProviderProjection("divergent LDAP binding update result")
			}
			return binding, nil
		},
	)
}

func (r *IdentityProviderRepository) ArchiveBinding(
	ctx context.Context,
	params identityprovider.ArchiveBindingParams,
) (int64, error) {
	version, err := identityProviderDatabaseVersion(params.ExpectedVersion)
	if err != nil || !validLDAPBindingArchive(params) {
		return 0, identityprovider.ErrInvalidInput
	}
	audit, err := identityProviderAuditArgumentsFor(params.Audit, params.OccurredAt, params.Actor.AuthenticationMethod)
	if err != nil {
		return 0, err
	}
	return withLDAPAdministrationTransaction(ctx, r, params.HumanParams,
		func(queries ldapAdministrationQueries) (int64, error) {
			updated, queryErr := queries.ArchiveTenantLDAPBinding(ctx, dbsql.ArchiveTenantLDAPBindingParams{
				BindingID: toDatabaseUUID(params.BindingID), ExpectedVersion: version, Reason: params.Reason,
				RequestID: audit.requestID, CorrelationID: audit.correlationID, IpAddress: audit.remoteAddress,
				UserAgent: audit.userAgent, AuthenticationMethod: audit.authenticationMethod,
			})
			if queryErr != nil {
				return 0, mapIdentityProviderDatabaseError(queryErr)
			}
			if int64(updated) != params.ExpectedVersion+1 {
				return 0, invalidIdentityProviderProjection("unexpected LDAP binding archive version")
			}
			return int64(updated), nil
		},
	)
}

func (r *IdentityProviderRepository) ListMappings(
	ctx context.Context,
	params identityprovider.ListMappingParams,
) ([]identityprovider.Mapping, error) {
	if !validLDAPMappingAdministrationPage(params.HumanParams, params.After, params.Limit) ||
		params.BindingID != nil && !identityProviderUUIDv7(*params.BindingID) {
		return nil, identityprovider.ErrInvalidInput
	}
	return withLDAPAdministrationTransaction(ctx, r, params.HumanParams,
		func(queries ldapAdministrationQueries) ([]identityprovider.Mapping, error) {
			var afterPriority *int32
			var afterMappingID pgtype.UUID
			var previous identityprovider.Mapping
			hasPrevious := false
			if params.After != nil {
				value := int32(params.After.Priority)
				afterPriority = &value
				afterMappingID = toDatabaseUUID(params.After.ID)
				previous = identityprovider.Mapping{Priority: params.After.Priority, ID: params.After.ID}
				hasPrevious = true
			}
			rows, err := queries.ListTenantLDAPMappings(ctx, dbsql.ListTenantLDAPMappingsParams{
				BindingID: optionalDatabaseUUID(params.BindingID), AfterPriority: afterPriority,
				AfterMappingID: afterMappingID, IncludeArchived: params.IncludeArchived,
				PageSize: params.Limit,
			})
			if err != nil {
				return nil, mapIdentityProviderDatabaseError(err)
			}
			if len(rows) > int(params.Limit) {
				return nil, invalidIdentityProviderProjection("oversized LDAP mapping page")
			}
			result := make([]identityprovider.Mapping, 0, len(rows))
			seen := make(map[uuid.UUID]struct{}, len(rows))
			for _, row := range rows {
				mapping, mapErr := mapListedLDAPMapping(params.TenantID, row)
				if mapErr != nil {
					return nil, mapErr
				}
				_, duplicate := seen[mapping.ID]
				if duplicate || !params.IncludeArchived && mapping.ArchivedAt != nil ||
					params.BindingID != nil && mapping.BindingID != *params.BindingID ||
					hasPrevious && compareLDAPMappingDatabaseOrder(previous, mapping) >= 0 {
					return nil, invalidIdentityProviderProjection("invalid LDAP mapping page order or lifecycle")
				}
				seen[mapping.ID] = struct{}{}
				previous = mapping
				hasPrevious = true
				result = append(result, mapping)
			}
			return result, nil
		},
	)
}

func (r *IdentityProviderRepository) GetMapping(
	ctx context.Context,
	params identityprovider.GetMappingParams,
) (identityprovider.Mapping, error) {
	if !validIdentityProviderHuman(params.HumanParams) || !identityProviderUUIDv7(params.MappingID) {
		return identityprovider.Mapping{}, identityprovider.ErrInvalidInput
	}
	return withLDAPAdministrationTransaction(ctx, r, params.HumanParams,
		func(queries ldapAdministrationQueries) (identityprovider.Mapping, error) {
			return getLDAPMapping(ctx, queries, params.TenantID, params.MappingID)
		},
	)
}

func (r *IdentityProviderRepository) CreateMapping(
	ctx context.Context,
	params identityprovider.CreateMappingParams,
) (identityprovider.MappingMutationResult, error) {
	if !validLDAPMappingCreate(params) {
		return identityprovider.MappingMutationResult{}, identityprovider.ErrInvalidInput
	}
	audit, err := identityProviderAuditArgumentsFor(params.Audit, params.OccurredAt, params.Actor.AuthenticationMethod)
	if err != nil {
		return identityprovider.MappingMutationResult{}, err
	}
	return withLDAPAdministrationTransaction(ctx, r, params.HumanParams,
		func(queries ldapAdministrationQueries) (identityprovider.MappingMutationResult, error) {
			arguments := ldapMappingWriteArguments(params.Matcher, params.Priority, params.Target, params.ReconciliationMode)
			row, queryErr := queries.CreateTenantLDAPMapping(ctx, dbsql.CreateTenantLDAPMappingParams{
				IdempotencyKeyDigest: append([]byte(nil), params.IdempotencyKeyDigest[:]...),
				BindingID:            toDatabaseUUID(params.BindingID), MatcherType: arguments.matcherType,
				MatcherValue: arguments.matcherValue, CaseMode: arguments.caseMode, Priority: arguments.priority,
				SecurityGroupID: arguments.securityGroupID, ReconciliationMode: arguments.reconciliationMode,
				RoleIds: arguments.roleIDs, OperatorTeamID: arguments.operatorTeamID,
				OperatorTeamAssignmentEpochID: arguments.assignmentEpochID,
				Notes:                         params.Notes, Reason: params.Reason, AuditEventID: toDatabaseUUID(params.AuditEventID),
				RequestID: audit.requestID, CorrelationID: audit.correlationID, IpAddress: audit.remoteAddress,
				UserAgent: audit.userAgent, AuthenticationMethod: audit.authenticationMethod,
			})
			if queryErr != nil {
				return identityprovider.MappingMutationResult{}, mapIdentityProviderDatabaseError(queryErr)
			}
			if row == nil || row.ResultVersion < 1 || !row.Replayed && row.ResultVersion != 1 {
				return identityprovider.MappingMutationResult{}, invalidIdentityProviderProjection("invalid LDAP mapping create result")
			}
			mappingID, mapErr := domainUUID(row.MappingID)
			if mapErr != nil || !identityProviderUUIDv7(mappingID) {
				return identityprovider.MappingMutationResult{}, invalidIdentityProviderProjection("invalid created LDAP mapping ID")
			}
			mapping, mapErr := getLDAPMappingMutationResult(ctx, queries, params.TenantID, mappingID)
			versionMatches := row.Replayed && mapping.Version >= int64(row.ResultVersion) ||
				!row.Replayed && mapping.Version == int64(row.ResultVersion)
			if mapErr != nil || !versionMatches {
				if mapErr != nil {
					return identityprovider.MappingMutationResult{}, mapErr
				}
				return identityprovider.MappingMutationResult{}, invalidIdentityProviderProjection("stale LDAP mapping create result")
			}
			if mapping.BindingID != params.BindingID || !row.Replayed && !ldapMappingMatchesWrite(
				mapping, params.Matcher, params.Priority, params.Target, params.ReconciliationMode, false, params.Notes,
			) {
				return identityprovider.MappingMutationResult{}, invalidIdentityProviderProjection("divergent LDAP mapping create result")
			}
			return identityprovider.MappingMutationResult{Mapping: mapping, Replayed: row.Replayed}, nil
		},
	)
}

func (r *IdentityProviderRepository) UpdateMapping(
	ctx context.Context,
	params identityprovider.UpdateMappingParams,
) (identityprovider.Mapping, error) {
	version, err := identityProviderDatabaseVersion(params.ExpectedVersion)
	if err != nil || !validLDAPMappingUpdate(params) {
		return identityprovider.Mapping{}, identityprovider.ErrInvalidInput
	}
	audit, err := identityProviderAuditArgumentsFor(params.Audit, params.OccurredAt, params.Actor.AuthenticationMethod)
	if err != nil {
		return identityprovider.Mapping{}, err
	}
	return withLDAPAdministrationTransaction(ctx, r, params.HumanParams,
		func(queries ldapAdministrationQueries) (identityprovider.Mapping, error) {
			arguments := ldapMappingWriteArguments(params.Matcher, params.Priority, params.Target, params.ReconciliationMode)
			updated, queryErr := queries.UpdateTenantLDAPMapping(ctx, dbsql.UpdateTenantLDAPMappingParams{
				MappingID: toDatabaseUUID(params.MappingID), ExpectedVersion: version,
				MatcherType: arguments.matcherType, MatcherValue: arguments.matcherValue,
				CaseMode: arguments.caseMode, Priority: arguments.priority,
				SecurityGroupID: arguments.securityGroupID, ReconciliationMode: arguments.reconciliationMode,
				RoleIds: arguments.roleIDs, OperatorTeamID: arguments.operatorTeamID,
				OperatorTeamAssignmentEpochID: arguments.assignmentEpochID, Enabled: params.Enabled,
				Notes: params.Notes, Reason: params.Reason, AuditEventID: toDatabaseUUID(params.AuditEventID),
				RequestID: audit.requestID, CorrelationID: audit.correlationID, IpAddress: audit.remoteAddress,
				UserAgent: audit.userAgent, AuthenticationMethod: audit.authenticationMethod,
			})
			if queryErr != nil {
				return identityprovider.Mapping{}, mapIdentityProviderDatabaseError(queryErr)
			}
			if int64(updated) != params.ExpectedVersion+1 {
				return identityprovider.Mapping{}, invalidIdentityProviderProjection("unexpected LDAP mapping update version")
			}
			mapping, mapErr := getLDAPMappingMutationResult(ctx, queries, params.TenantID, params.MappingID)
			if mapErr != nil || mapping.Version != int64(updated) {
				if mapErr != nil {
					return identityprovider.Mapping{}, mapErr
				}
				return identityprovider.Mapping{}, invalidIdentityProviderProjection("stale LDAP mapping update result")
			}
			if !ldapMappingMatchesWrite(
				mapping, params.Matcher, params.Priority, params.Target, params.ReconciliationMode, params.Enabled, params.Notes,
			) {
				return identityprovider.Mapping{}, invalidIdentityProviderProjection("divergent LDAP mapping update result")
			}
			return mapping, nil
		},
	)
}

func (r *IdentityProviderRepository) ArchiveMapping(
	ctx context.Context,
	params identityprovider.ArchiveMappingParams,
) (int64, error) {
	version, err := identityProviderDatabaseVersion(params.ExpectedVersion)
	if err != nil || !validLDAPMappingArchive(params) {
		return 0, identityprovider.ErrInvalidInput
	}
	audit, err := identityProviderAuditArgumentsFor(params.Audit, params.OccurredAt, params.Actor.AuthenticationMethod)
	if err != nil {
		return 0, err
	}
	return withLDAPAdministrationTransaction(ctx, r, params.HumanParams,
		func(queries ldapAdministrationQueries) (int64, error) {
			updated, queryErr := queries.ArchiveTenantLDAPMapping(ctx, dbsql.ArchiveTenantLDAPMappingParams{
				MappingID: toDatabaseUUID(params.MappingID), ExpectedVersion: version, Reason: params.Reason,
				AuditEventID: toDatabaseUUID(params.AuditEventID), RequestID: audit.requestID,
				CorrelationID: audit.correlationID, IpAddress: audit.remoteAddress,
				UserAgent: audit.userAgent, AuthenticationMethod: audit.authenticationMethod,
			})
			if queryErr != nil {
				return 0, mapIdentityProviderDatabaseError(queryErr)
			}
			if int64(updated) != params.ExpectedVersion+1 {
				return 0, invalidIdentityProviderProjection("unexpected LDAP mapping archive version")
			}
			return int64(updated), nil
		},
	)
}

func withLDAPAdministrationTransaction[T any](
	ctx context.Context,
	repository *IdentityProviderRepository,
	human identityprovider.HumanParams,
	work func(ldapAdministrationQueries) (T, error),
) (T, error) {
	var zero T
	if !validIdentityProviderHuman(human) {
		return zero, identityprovider.ErrForbidden
	}
	if repository == nil || repository.begin == nil || repository.administrationQueryFactory == nil || work == nil {
		return zero, fmt.Errorf("%w: LDAP administration repository dependencies are required", identityprovider.ErrUnavailable)
	}
	result, err := withinTransaction(ctx, repository.begin, func(tx databaseTransaction) (T, error) {
		queries := repository.administrationQueryFactory(tx)
		if queries == nil {
			return zero, invalidIdentityProviderProjection("LDAP administration query surface is unavailable")
		}
		installed, installErr := queries.SetTenantContext(ctx, dbsql.SetTenantContextParams{
			TenantID: toDatabaseUUID(human.TenantID), UserID: toDatabaseUUID(human.Actor.UserID),
		})
		if installErr != nil {
			return zero, mapIdentityProviderDatabaseError(installErr)
		}
		if installed == nil || installed.TenantID != human.TenantID.String() || installed.UserID != human.Actor.UserID.String() {
			return zero, invalidIdentityProviderProjection("database installed an unexpected LDAP administration context")
		}
		return work(queries)
	})
	if err != nil {
		return zero, mapIdentityProviderDatabaseError(err)
	}
	return result, nil
}

type ldapMappingWriteProjection struct {
	matcherType, matcherValue, caseMode, reconciliationMode string
	priority                                                int32
	securityGroupID                                         pgtype.UUID
	roleIDs                                                 []pgtype.UUID
	operatorTeamID, assignmentEpochID                       pgtype.UUID
}

func ldapMappingWriteArguments(
	matcher identityprovider.MappingMatcher,
	priority int,
	target identityprovider.MappingTarget,
	mode identityprovider.ReconciliationMode,
) ldapMappingWriteProjection {
	roles := make([]pgtype.UUID, len(target.RoleIDs))
	for index, roleID := range target.RoleIDs {
		roles[index] = toDatabaseUUID(roleID)
	}
	var teamID, epochID pgtype.UUID
	if target.OperatorTeamAssignment != nil {
		teamID = toDatabaseUUID(target.OperatorTeamAssignment.OperatorTeamID)
		epochID = toDatabaseUUID(target.OperatorTeamAssignment.AssignmentEpochID)
	}
	return ldapMappingWriteProjection{
		matcherType: string(matcher.Type), matcherValue: matcher.Value, caseMode: string(matcher.CaseMode),
		priority: int32(priority), securityGroupID: toDatabaseUUID(target.TenantSecurityGroupID),
		reconciliationMode: string(mode), roleIDs: roles, operatorTeamID: teamID, assignmentEpochID: epochID,
	}
}

func validLDAPAdministrationPage(
	human identityprovider.HumanParams,
	after *uuid.UUID,
	limit int32,
) bool {
	return validIdentityProviderHuman(human) && limit >= 1 && limit <= identityProviderPageLimit &&
		(after == nil || identityProviderUUIDv7(*after))
}

func validLDAPMappingAdministrationPage(
	human identityprovider.HumanParams,
	after *identityprovider.MappingCursor,
	limit int32,
) bool {
	return validIdentityProviderHuman(human) && limit >= 1 && limit <= identityProviderPageLimit &&
		(after == nil || after.Priority >= 0 && after.Priority <= 1_000_000 && identityProviderUUIDv7(after.ID))
}

func validLDAPBindingCreate(params identityprovider.CreateBindingParams) bool {
	return validIdentityProviderHuman(params.HumanParams) && validIdentityProviderAudit(params.Audit) &&
		validIdentityProviderOccurrence(params.OccurredAt) && identityProviderUUIDv7(params.AuditEventID) &&
		identityProviderUUIDv7(params.ProviderID) && !allZero(params.IdempotencyKeyDigest[:]) &&
		validLDAPLoginKey(params.LoginKey) && params.ProfilePriority >= 0 && params.ProfilePriority <= 1_000_000
}

func validLDAPBindingUpdate(params identityprovider.UpdateBindingParams) bool {
	return validIdentityProviderHuman(params.HumanParams) && validIdentityProviderAudit(params.Audit) &&
		validIdentityProviderOccurrence(params.OccurredAt) && identityProviderUUIDv7(params.BindingID) &&
		validLDAPLoginKey(params.LoginKey) && params.ProfilePriority >= 0 && params.ProfilePriority <= 1_000_000
}

func validLDAPBindingArchive(params identityprovider.ArchiveBindingParams) bool {
	return validIdentityProviderHuman(params.HumanParams) && validIdentityProviderAudit(params.Audit) &&
		validIdentityProviderOccurrence(params.OccurredAt) && identityProviderUUIDv7(params.BindingID) &&
		validLDAPAdministrationReason(params.Reason)
}

func validLDAPMappingCreate(params identityprovider.CreateMappingParams) bool {
	return validIdentityProviderHuman(params.HumanParams) && validIdentityProviderAudit(params.Audit) &&
		validIdentityProviderOccurrence(params.OccurredAt) && identityProviderUUIDv7(params.AuditEventID) &&
		!allZero(params.IdempotencyKeyDigest[:]) && identityProviderUUIDv7(params.BindingID) &&
		validLDAPMappingWrite(params.Matcher, params.Priority, params.Target, params.ReconciliationMode, params.Notes) &&
		validLDAPAdministrationReason(params.Reason)
}

func validLDAPMappingUpdate(params identityprovider.UpdateMappingParams) bool {
	return validIdentityProviderHuman(params.HumanParams) && validIdentityProviderAudit(params.Audit) &&
		validIdentityProviderOccurrence(params.OccurredAt) && identityProviderUUIDv7(params.AuditEventID) &&
		identityProviderUUIDv7(params.MappingID) &&
		validLDAPMappingWrite(params.Matcher, params.Priority, params.Target, params.ReconciliationMode, params.Notes) &&
		validLDAPAdministrationReason(params.Reason)
}

func validLDAPMappingArchive(params identityprovider.ArchiveMappingParams) bool {
	return validIdentityProviderHuman(params.HumanParams) && validIdentityProviderAudit(params.Audit) &&
		validIdentityProviderOccurrence(params.OccurredAt) && identityProviderUUIDv7(params.AuditEventID) &&
		identityProviderUUIDv7(params.MappingID) && validLDAPAdministrationReason(params.Reason)
}

func validLDAPMappingWrite(
	matcher identityprovider.MappingMatcher,
	priority int,
	target identityprovider.MappingTarget,
	mode identityprovider.ReconciliationMode,
	notes string,
) bool {
	if priority < 0 || priority > 1_000_000 || !validLDAPAdministrationText(notes, 0, 2000) ||
		mode != identityprovider.ReconciliationAdditive && mode != identityprovider.ReconciliationAuthoritative ||
		!validLDAPDatabaseMatcher(matcher) || !identityProviderUUIDv7(target.TenantSecurityGroupID) ||
		len(target.RoleIDs) < 1 || len(target.RoleIDs) > 32 {
		return false
	}
	if !slices.IsSortedFunc(target.RoleIDs, func(left, right uuid.UUID) int { return bytes.Compare(left[:], right[:]) }) {
		return false
	}
	for index, roleID := range target.RoleIDs {
		if !identityProviderUUIDv7(roleID) || index > 0 && roleID == target.RoleIDs[index-1] {
			return false
		}
	}
	if target.OperatorTeamAssignment != nil &&
		(!identityProviderUUIDv7(target.OperatorTeamAssignment.OperatorTeamID) ||
			!identityProviderUUIDv7(target.OperatorTeamAssignment.AssignmentEpochID)) {
		return false
	}
	return true
}

func validLDAPDatabaseMatcher(matcher identityprovider.MappingMatcher) bool {
	var kind identity.LDAPGroupMatcherKind
	switch matcher.Type {
	case identityprovider.MappingMatcherExactDN:
		kind = identity.LDAPGroupMatcherExactDN
	case identityprovider.MappingMatcherExactCN:
		kind = identity.LDAPGroupMatcherExactCN
	case identityprovider.MappingMatcherRegex:
		kind = identity.LDAPGroupMatcherRegex
	default:
		return false
	}
	var caseMode identity.LDAPGroupCaseMode
	switch matcher.CaseMode {
	case identityprovider.MappingCaseSensitive:
		caseMode = identity.LDAPGroupCaseSensitive
	case identityprovider.MappingCaseInsensitive:
		caseMode = identity.LDAPGroupCaseInsensitive
	default:
		return false
	}
	if _, err := identity.CompileLDAPGroupMatcher(identity.LDAPGroupMatcherSpec{
		Kind: kind, CaseMode: caseMode, Pattern: matcher.Value,
	}); err != nil {
		return false
	}
	if matcher.Type != identityprovider.MappingMatcherExactDN {
		return true
	}
	parsed, err := ldap.ParseDN(matcher.Value)
	return err == nil && parsed.String() == matcher.Value && len(matcher.Value) <= 8192
}

func validLDAPLoginKey(value string) bool {
	if len(value) < 3 || len(value) > 64 || value != strings.ToLower(strings.TrimSpace(value)) {
		return false
	}
	for index, character := range value {
		if index == 0 && (character < 'a' || character > 'z') ||
			index > 0 && !((character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '_' || character == '-') {
			return false
		}
	}
	return true
}

func validLDAPAdministrationReason(value string) bool {
	return value == strings.TrimSpace(value) && validLDAPAdministrationText(value, 1, 500)
}

func validLDAPAdministrationText(value string, minimum, maximum int) bool {
	if !utf8.ValidString(value) {
		return false
	}
	length := 0
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
		length++
	}
	return length >= minimum && length <= maximum
}

func compareLDAPMappingDatabaseOrder(left, right identityprovider.Mapping) int {
	if left.Priority < right.Priority {
		return -1
	}
	if left.Priority > right.Priority {
		return 1
	}
	return bytes.Compare(left.ID[:], right.ID[:])
}

func ldapBindingMatchesWrite(
	binding identityprovider.Binding,
	loginKey string,
	enabled bool,
	profilePriority int,
) bool {
	return binding.LoginKey == loginKey && binding.Enabled == enabled && binding.ProfilePriority == profilePriority
}

func ldapMappingMatchesWrite(
	mapping identityprovider.Mapping,
	matcher identityprovider.MappingMatcher,
	priority int,
	target identityprovider.MappingTarget,
	mode identityprovider.ReconciliationMode,
	enabled bool,
	notes string,
) bool {
	if mapping.Matcher != matcher || mapping.Priority != priority ||
		mapping.Target.TenantSecurityGroupID != target.TenantSecurityGroupID ||
		!slices.Equal(mapping.Target.RoleIDs, target.RoleIDs) ||
		(mapping.Target.OperatorTeamAssignment == nil) != (target.OperatorTeamAssignment == nil) ||
		mapping.ReconciliationMode != mode || mapping.Enabled != enabled || mapping.Notes != notes {
		return false
	}
	return mapping.Target.OperatorTeamAssignment == nil ||
		*mapping.Target.OperatorTeamAssignment == *target.OperatorTeamAssignment
}
