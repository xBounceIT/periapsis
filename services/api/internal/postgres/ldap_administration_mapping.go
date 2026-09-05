package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/periapsis-im/periapsis/services/api/internal/identityprovider"
	"github.com/periapsis-im/periapsis/services/api/internal/postgres/dbsql"
)

func mapListedLDAPBinding(
	tenantID uuid.UUID,
	row *dbsql.ListTenantLDAPBindingsRow,
) (identityprovider.Binding, error) {
	if row == nil {
		return identityprovider.Binding{}, invalidIdentityProviderProjection("null listed LDAP binding")
	}
	return mapLDAPBinding(
		tenantID, row.ID, row.ProviderID, row.LoginKey, row.Enabled, row.ProfilePriority,
		row.AuthRevision, row.CurrentAccessEpochID, row.ArchivedAt, row.Version,
		row.CreatedAt, row.UpdatedAt,
	)
}

func mapGotLDAPBinding(
	tenantID uuid.UUID,
	row *dbsql.GetTenantLDAPBindingRow,
) (identityprovider.Binding, error) {
	if row == nil {
		return identityprovider.Binding{}, invalidIdentityProviderProjection("null LDAP binding")
	}
	return mapLDAPBinding(
		tenantID, row.ID, row.ProviderID, row.LoginKey, row.Enabled, row.ProfilePriority,
		row.AuthRevision, row.CurrentAccessEpochID, row.ArchivedAt, row.Version,
		row.CreatedAt, row.UpdatedAt,
	)
}

func mapMutatedLDAPBinding(
	tenantID uuid.UUID,
	row *dbsql.GetTenantLDAPBindingMutationResultRow,
) (identityprovider.Binding, error) {
	if row == nil {
		return identityprovider.Binding{}, invalidIdentityProviderProjection("null LDAP binding mutation result")
	}
	return mapLDAPBinding(
		tenantID, row.ID, row.ProviderID, row.LoginKey, row.Enabled, row.ProfilePriority,
		row.AuthRevision, row.CurrentAccessEpochID, row.ArchivedAt, row.Version,
		row.CreatedAt, row.UpdatedAt,
	)
}

func mapLDAPBinding(
	tenantID uuid.UUID,
	bindingID, providerID pgtype.UUID,
	loginKey string,
	enabled bool,
	profilePriority, authRevision int32,
	currentEpochID pgtype.UUID,
	archivedAt pgtype.Timestamptz,
	version int32,
	createdAt, updatedAt pgtype.Timestamptz,
) (identityprovider.Binding, error) {
	identifier, err := domainUUID(bindingID)
	if err != nil || !identityProviderUUIDv7(identifier) {
		return identityprovider.Binding{}, invalidIdentityProviderProjection("invalid LDAP binding ID")
	}
	provider, err := domainUUID(providerID)
	if err != nil || !identityProviderUUIDv7(provider) {
		return identityprovider.Binding{}, invalidIdentityProviderProjection("invalid LDAP binding provider ID")
	}
	created, err := domainTime(createdAt)
	if err != nil {
		return identityprovider.Binding{}, invalidIdentityProviderProjection("invalid LDAP binding creation time")
	}
	updated, err := domainTime(updatedAt)
	if err != nil || updated.Before(created) || version < 1 || authRevision < 1 ||
		profilePriority < 0 || profilePriority > 1_000_000 || !validLDAPLoginKey(loginKey) {
		return identityprovider.Binding{}, invalidIdentityProviderProjection("invalid LDAP binding lifecycle")
	}
	archived, err := optionalIdentityProviderTime(archivedAt)
	if err != nil || archived != nil && (archived.Before(created) || archived.After(updated) || enabled) {
		return identityprovider.Binding{}, invalidIdentityProviderProjection("invalid LDAP binding archive state")
	}
	var epochID *uuid.UUID
	if currentEpochID.Valid {
		value, mapErr := domainUUID(currentEpochID)
		if mapErr != nil || !identityProviderUUIDv7(value) {
			return identityprovider.Binding{}, invalidIdentityProviderProjection("invalid LDAP binding access epoch")
		}
		epochID = &value
	}
	if enabled != (epochID != nil) {
		return identityprovider.Binding{}, invalidIdentityProviderProjection("incoherent LDAP binding access epoch")
	}
	return identityprovider.Binding{
		ID: identifier, TenantID: tenantID, ProviderID: provider, LoginKey: loginKey,
		Enabled: enabled, ProfilePriority: int(profilePriority), AuthRevision: int(authRevision),
		CurrentAccessEpochID: epochID, ArchivedAt: archived, Version: int64(version),
		CreatedAt: created, UpdatedAt: updated,
	}, nil
}

func mapListedLDAPMapping(
	tenantID uuid.UUID,
	row *dbsql.ListTenantLDAPMappingsRow,
) (identityprovider.Mapping, error) {
	if row == nil {
		return identityprovider.Mapping{}, invalidIdentityProviderProjection("null listed LDAP mapping")
	}
	return mapLDAPMapping(tenantID, ldapMappingDatabaseProjection{
		id: row.ID, bindingID: row.BindingID, matcherType: row.MatcherType, matcherValue: row.MatcherValue,
		caseMode: row.CaseMode, priority: row.Priority, securityGroupID: row.SecurityGroupID,
		reconciliationMode: row.ReconciliationMode, roleIDs: row.RoleIds,
		operatorTeamID: row.OperatorTeamID, assignmentEpochID: row.OperatorTeamAssignmentEpochID,
		enabled: row.Enabled, currentSourceEpochID: row.CurrentSourceEpochID,
		currentSourceEpochSequence:    row.CurrentSourceEpochSequence,
		currentSourceEpochActivatedAt: row.CurrentSourceEpochActivatedAt,
		notes:                         row.Notes, lastMatchedAt: row.LastMatchedAt, archivedAt: row.ArchivedAt,
		version: row.Version, createdAt: row.CreatedAt, updatedAt: row.UpdatedAt,
	})
}

func mapGotLDAPMapping(
	tenantID uuid.UUID,
	row *dbsql.GetTenantLDAPMappingRow,
) (identityprovider.Mapping, error) {
	if row == nil {
		return identityprovider.Mapping{}, invalidIdentityProviderProjection("null LDAP mapping")
	}
	return mapLDAPMapping(tenantID, ldapMappingDatabaseProjection{
		id: row.ID, bindingID: row.BindingID, matcherType: row.MatcherType, matcherValue: row.MatcherValue,
		caseMode: row.CaseMode, priority: row.Priority, securityGroupID: row.SecurityGroupID,
		reconciliationMode: row.ReconciliationMode, roleIDs: row.RoleIds,
		operatorTeamID: row.OperatorTeamID, assignmentEpochID: row.OperatorTeamAssignmentEpochID,
		enabled: row.Enabled, currentSourceEpochID: row.CurrentSourceEpochID,
		currentSourceEpochSequence:    row.CurrentSourceEpochSequence,
		currentSourceEpochActivatedAt: row.CurrentSourceEpochActivatedAt,
		notes:                         row.Notes, lastMatchedAt: row.LastMatchedAt, archivedAt: row.ArchivedAt,
		version: row.Version, createdAt: row.CreatedAt, updatedAt: row.UpdatedAt,
	})
}

func mapMutatedLDAPMapping(
	tenantID uuid.UUID,
	row *dbsql.GetTenantLDAPMappingMutationResultRow,
) (identityprovider.Mapping, error) {
	if row == nil {
		return identityprovider.Mapping{}, invalidIdentityProviderProjection("null LDAP mapping mutation result")
	}
	return mapLDAPMapping(tenantID, ldapMappingDatabaseProjection{
		id: row.ID, bindingID: row.BindingID, matcherType: row.MatcherType, matcherValue: row.MatcherValue,
		caseMode: row.CaseMode, priority: row.Priority, securityGroupID: row.SecurityGroupID,
		reconciliationMode: row.ReconciliationMode, roleIDs: row.RoleIds,
		operatorTeamID: row.OperatorTeamID, assignmentEpochID: row.OperatorTeamAssignmentEpochID,
		enabled: row.Enabled, currentSourceEpochID: row.CurrentSourceEpochID,
		currentSourceEpochSequence:    row.CurrentSourceEpochSequence,
		currentSourceEpochActivatedAt: row.CurrentSourceEpochActivatedAt,
		notes:                         row.Notes, lastMatchedAt: row.LastMatchedAt, archivedAt: row.ArchivedAt,
		version: row.Version, createdAt: row.CreatedAt, updatedAt: row.UpdatedAt,
	})
}

type ldapMappingDatabaseProjection struct {
	id, bindingID, securityGroupID                           pgtype.UUID
	matcherType, matcherValue, caseMode, reconciliationMode  string
	priority, currentSourceEpochSequence, version            int32
	roleIDs                                                  []pgtype.UUID
	operatorTeamID, assignmentEpochID, currentSourceEpochID  pgtype.UUID
	enabled                                                  bool
	currentSourceEpochActivatedAt, lastMatchedAt, archivedAt pgtype.Timestamptz
	createdAt, updatedAt                                     pgtype.Timestamptz
	notes                                                    string
}

func mapLDAPMapping(
	tenantID uuid.UUID,
	row ldapMappingDatabaseProjection,
) (identityprovider.Mapping, error) {
	identifier, err := domainUUID(row.id)
	if err != nil || !identityProviderUUIDv7(identifier) {
		return identityprovider.Mapping{}, invalidIdentityProviderProjection("invalid LDAP mapping ID")
	}
	bindingID, err := domainUUID(row.bindingID)
	if err != nil || !identityProviderUUIDv7(bindingID) {
		return identityprovider.Mapping{}, invalidIdentityProviderProjection("invalid LDAP mapping binding ID")
	}
	securityGroupID, err := domainUUID(row.securityGroupID)
	if err != nil || !identityProviderUUIDv7(securityGroupID) {
		return identityprovider.Mapping{}, invalidIdentityProviderProjection("invalid LDAP mapping security-group ID")
	}
	roles := make([]uuid.UUID, len(row.roleIDs))
	for index, databaseID := range row.roleIDs {
		roleID, mapErr := domainUUID(databaseID)
		if mapErr != nil || !identityProviderUUIDv7(roleID) {
			return identityprovider.Mapping{}, invalidIdentityProviderProjection("invalid LDAP mapping role ID")
		}
		roles[index] = roleID
	}
	var assignment *identityprovider.OperatorTeamAssignmentTarget
	if row.operatorTeamID.Valid != row.assignmentEpochID.Valid {
		return identityprovider.Mapping{}, invalidIdentityProviderProjection("incomplete LDAP mapping operator-team target")
	}
	if row.operatorTeamID.Valid {
		teamID, teamErr := domainUUID(row.operatorTeamID)
		epochID, epochErr := domainUUID(row.assignmentEpochID)
		if teamErr != nil || epochErr != nil || !identityProviderUUIDv7(teamID) || !identityProviderUUIDv7(epochID) {
			return identityprovider.Mapping{}, invalidIdentityProviderProjection("invalid LDAP mapping operator-team target")
		}
		assignment = &identityprovider.OperatorTeamAssignmentTarget{
			OperatorTeamID: teamID, AssignmentEpochID: epochID,
		}
	}
	created, err := domainTime(row.createdAt)
	if err != nil {
		return identityprovider.Mapping{}, invalidIdentityProviderProjection("invalid LDAP mapping creation time")
	}
	updated, err := domainTime(row.updatedAt)
	if err != nil || updated.Before(created) || row.version < 1 {
		return identityprovider.Mapping{}, invalidIdentityProviderProjection("invalid LDAP mapping lifecycle")
	}
	lastMatched, err := optionalIdentityProviderTime(row.lastMatchedAt)
	if err != nil || lastMatched != nil && lastMatched.Before(created) {
		return identityprovider.Mapping{}, invalidIdentityProviderProjection("invalid LDAP mapping match time")
	}
	archived, err := optionalIdentityProviderTime(row.archivedAt)
	if err != nil || archived != nil && (archived.Before(created) || archived.After(updated) || row.enabled) {
		return identityprovider.Mapping{}, invalidIdentityProviderProjection("invalid LDAP mapping archive state")
	}
	mode := identityprovider.ReconciliationMode(row.reconciliationMode)
	var sourceEpoch *identityprovider.MappingSourceEpoch
	if row.currentSourceEpochID.Valid {
		epochID, mapErr := domainUUID(row.currentSourceEpochID)
		activatedAt, timeErr := domainTime(row.currentSourceEpochActivatedAt)
		if mapErr != nil || timeErr != nil || !identityProviderUUIDv7(epochID) ||
			row.currentSourceEpochSequence < 1 || activatedAt.Before(created) || activatedAt.After(updated) {
			return identityprovider.Mapping{}, invalidIdentityProviderProjection("invalid LDAP mapping source epoch")
		}
		sourceEpoch = &identityprovider.MappingSourceEpoch{
			ID: epochID, Sequence: int(row.currentSourceEpochSequence),
			ReconciliationMode: mode, ActivatedAt: activatedAt,
		}
	} else if row.currentSourceEpochSequence != 0 || row.currentSourceEpochActivatedAt.Valid {
		return identityprovider.Mapping{}, invalidIdentityProviderProjection("partial LDAP mapping source epoch")
	}
	if row.enabled != (sourceEpoch != nil) {
		return identityprovider.Mapping{}, invalidIdentityProviderProjection("incoherent LDAP mapping source epoch")
	}
	mapping := identityprovider.Mapping{
		ID: identifier, TenantID: tenantID, BindingID: bindingID,
		Matcher: identityprovider.MappingMatcher{
			Type: identityprovider.MappingMatcherType(row.matcherType), Value: row.matcherValue,
			CaseMode: identityprovider.MappingCaseMode(row.caseMode),
		},
		Priority: int(row.priority), Target: identityprovider.MappingTarget{
			TenantSecurityGroupID: securityGroupID, RoleIDs: roles, OperatorTeamAssignment: assignment,
		},
		ReconciliationMode: mode, Enabled: row.enabled, Notes: row.notes,
		CurrentSourceEpoch: sourceEpoch, LastMatchedAt: lastMatched, ArchivedAt: archived,
		Version: int64(row.version), CreatedAt: created, UpdatedAt: updated,
	}
	if !validLDAPMappingWrite(
		mapping.Matcher,
		mapping.Priority,
		mapping.Target,
		mapping.ReconciliationMode,
		mapping.Notes,
	) {
		return identityprovider.Mapping{}, invalidIdentityProviderProjection("invalid LDAP mapping definition")
	}
	return mapping, nil
}

func getLDAPBinding(
	ctx context.Context,
	queries ldapAdministrationQueries,
	tenantID, bindingID uuid.UUID,
) (identityprovider.Binding, error) {
	row, err := queries.GetTenantLDAPBinding(ctx, dbsql.GetTenantLDAPBindingParams{
		BindingID: toDatabaseUUID(bindingID),
	})
	if err != nil {
		return identityprovider.Binding{}, mapIdentityProviderDatabaseError(err)
	}
	binding, err := mapGotLDAPBinding(tenantID, row)
	if err != nil {
		return identityprovider.Binding{}, err
	}
	if binding.ID != bindingID {
		return identityprovider.Binding{}, invalidIdentityProviderProjection("unexpected LDAP binding ID")
	}
	return binding, nil
}

func getLDAPBindingMutationResult(
	ctx context.Context,
	queries ldapAdministrationQueries,
	tenantID, bindingID uuid.UUID,
) (identityprovider.Binding, error) {
	row, err := queries.GetTenantLDAPBindingMutationResult(ctx, dbsql.GetTenantLDAPBindingMutationResultParams{
		BindingID: toDatabaseUUID(bindingID),
	})
	if err != nil {
		return identityprovider.Binding{}, mapIdentityProviderDatabaseError(err)
	}
	binding, err := mapMutatedLDAPBinding(tenantID, row)
	if err != nil {
		return identityprovider.Binding{}, err
	}
	if binding.ID != bindingID {
		return identityprovider.Binding{}, invalidIdentityProviderProjection("unexpected LDAP binding mutation result ID")
	}
	return binding, nil
}

func getLDAPMapping(
	ctx context.Context,
	queries ldapAdministrationQueries,
	tenantID, mappingID uuid.UUID,
) (identityprovider.Mapping, error) {
	row, err := queries.GetTenantLDAPMapping(ctx, dbsql.GetTenantLDAPMappingParams{
		MappingID: toDatabaseUUID(mappingID),
	})
	if err != nil {
		return identityprovider.Mapping{}, mapIdentityProviderDatabaseError(err)
	}
	mapping, err := mapGotLDAPMapping(tenantID, row)
	if err != nil {
		return identityprovider.Mapping{}, err
	}
	if mapping.ID != mappingID {
		return identityprovider.Mapping{}, invalidIdentityProviderProjection("unexpected LDAP mapping ID")
	}
	return mapping, nil
}

func getLDAPMappingMutationResult(
	ctx context.Context,
	queries ldapAdministrationQueries,
	tenantID, mappingID uuid.UUID,
) (identityprovider.Mapping, error) {
	row, err := queries.GetTenantLDAPMappingMutationResult(ctx, dbsql.GetTenantLDAPMappingMutationResultParams{
		MappingID: toDatabaseUUID(mappingID),
	})
	if err != nil {
		return identityprovider.Mapping{}, mapIdentityProviderDatabaseError(err)
	}
	mapping, err := mapMutatedLDAPMapping(tenantID, row)
	if err != nil {
		return identityprovider.Mapping{}, err
	}
	if mapping.ID != mappingID {
		return identityprovider.Mapping{}, invalidIdentityProviderProjection("unexpected LDAP mapping mutation result ID")
	}
	return mapping, nil
}
