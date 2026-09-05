package postgres

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/periapsis-im/periapsis/services/api/internal/identityprovider"
	"github.com/periapsis-im/periapsis/services/api/internal/postgres/dbsql"
)

const ldapSyncAdministrationPageLimit = int32(101)

type ldapSyncAdministrationQueries interface {
	SetTenantContext(context.Context, dbsql.SetTenantContextParams) (*dbsql.SetTenantContextRow, error)
	GetTenantLDAPSyncStatus(context.Context, dbsql.GetTenantLDAPSyncStatusParams) (*dbsql.GetTenantLDAPSyncStatusRow, error)
	ListTenantLDAPSyncRuns(context.Context, dbsql.ListTenantLDAPSyncRunsParams) ([]*dbsql.ListTenantLDAPSyncRunsRow, error)
	GetTenantLDAPSyncRun(context.Context, dbsql.GetTenantLDAPSyncRunParams) (*dbsql.GetTenantLDAPSyncRunRow, error)
	BeginTenantLDAPManualSyncV2(context.Context, dbsql.BeginTenantLDAPManualSyncV2Params) (*dbsql.BeginTenantLDAPManualSyncV2Row, error)
}

var _ identityprovider.SyncAdministrationRepository = (*IdentityProviderRepository)(nil)

func (r *IdentityProviderRepository) GetSyncStatus(
	ctx context.Context,
	params identityprovider.GetSyncStatusParams,
) (identityprovider.SyncStatus, error) {
	if !validIdentityProviderHuman(params.HumanParams) || !identityProviderUUIDv7(params.BindingID) {
		return identityprovider.SyncStatus{}, identityprovider.ErrInvalidInput
	}
	return withLDAPSyncAdministrationTransaction(ctx, r, params.HumanParams,
		func(queries ldapSyncAdministrationQueries) (identityprovider.SyncStatus, error) {
			row, err := queries.GetTenantLDAPSyncStatus(ctx, dbsql.GetTenantLDAPSyncStatusParams{
				BindingID: toDatabaseUUID(params.BindingID),
			})
			if err != nil {
				return identityprovider.SyncStatus{}, mapIdentityProviderDatabaseError(err)
			}
			return mapLDAPSyncStatus(row, params.BindingID)
		},
	)
}

func (r *IdentityProviderRepository) ListSyncRuns(
	ctx context.Context,
	params identityprovider.ListSyncRunParams,
) ([]identityprovider.SyncRun, error) {
	if !validIdentityProviderHuman(params.HumanParams) || !identityProviderUUIDv7(params.BindingID) ||
		params.Limit < 1 || params.Limit > ldapSyncAdministrationPageLimit ||
		params.After != nil && !identityProviderUUIDv7(*params.After) {
		return nil, identityprovider.ErrInvalidInput
	}
	return withLDAPSyncAdministrationTransaction(ctx, r, params.HumanParams,
		func(queries ldapSyncAdministrationQueries) ([]identityprovider.SyncRun, error) {
			rows, err := queries.ListTenantLDAPSyncRuns(ctx, dbsql.ListTenantLDAPSyncRunsParams{
				BindingID: toDatabaseUUID(params.BindingID), AfterRunID: optionalDatabaseUUID(params.After),
				PageSize: params.Limit,
			})
			if err != nil {
				return nil, mapIdentityProviderDatabaseError(err)
			}
			if len(rows) > int(params.Limit) {
				return nil, invalidIdentityProviderProjection("oversized LDAP sync-run page")
			}
			result := make([]identityprovider.SyncRun, 0, len(rows))
			var previous uuid.UUID
			if params.After != nil {
				previous = *params.After
			}
			for _, row := range rows {
				run, mapErr := mapListedLDAPSyncRun(row, params.TenantID, params.BindingID)
				if mapErr != nil {
					return nil, mapErr
				}
				if previous != uuid.Nil && bytes.Compare(previous[:], run.ID[:]) >= 0 {
					return nil, invalidIdentityProviderProjection("non-monotonic LDAP sync-run page")
				}
				previous = run.ID
				result = append(result, run)
			}
			return result, nil
		},
	)
}

func (r *IdentityProviderRepository) GetSyncRun(
	ctx context.Context,
	params identityprovider.GetSyncRunParams,
) (identityprovider.SyncRun, error) {
	if !validIdentityProviderHuman(params.HumanParams) || !identityProviderUUIDv7(params.BindingID) ||
		!identityProviderUUIDv7(params.RunID) {
		return identityprovider.SyncRun{}, identityprovider.ErrInvalidInput
	}
	return withLDAPSyncAdministrationTransaction(ctx, r, params.HumanParams,
		func(queries ldapSyncAdministrationQueries) (identityprovider.SyncRun, error) {
			return getLDAPSyncRun(ctx, queries, params.TenantID, params.BindingID, params.RunID)
		},
	)
}

func (r *IdentityProviderRepository) StartManualSync(
	ctx context.Context,
	params identityprovider.StartManualSyncParams,
) (identityprovider.SyncRunMutationResult, error) {
	version, versionErr := identityProviderDatabaseVersion(params.ExpectedVersion)
	if versionErr != nil || !validLDAPManualSyncMutation(params) {
		return identityprovider.SyncRunMutationResult{}, identityprovider.ErrInvalidInput
	}
	audit, err := identityProviderAuditArgumentsFor(
		params.Audit, params.OccurredAt, params.Actor.AuthenticationMethod,
	)
	if err != nil {
		return identityprovider.SyncRunMutationResult{}, err
	}
	return withLDAPSyncAdministrationTransaction(ctx, r, params.HumanParams,
		func(queries ldapSyncAdministrationQueries) (identityprovider.SyncRunMutationResult, error) {
			row, queryErr := queries.BeginTenantLDAPManualSyncV2(ctx, dbsql.BeginTenantLDAPManualSyncV2Params{
				IdempotencyKeyDigest:   append([]byte(nil), params.IdempotencyKeyDigest[:]...),
				RequestDigest:          append([]byte(nil), params.RequestDigest[:]...),
				SyncRunID:              toDatabaseUUID(params.RunID),
				BindingID:              toDatabaseUUID(params.BindingID),
				ExpectedBindingVersion: version,
				Reason:                 params.Reason,
				AuditEventID:           toDatabaseUUID(params.AuditEventID),
				RequestID:              audit.requestID,
				CorrelationID:          audit.correlationID,
				IpAddress:              audit.remoteAddress,
				UserAgent:              audit.userAgent,
				AuthenticationMethod:   audit.authenticationMethod,
			})
			if queryErr != nil {
				return identityprovider.SyncRunMutationResult{}, mapIdentityProviderDatabaseError(queryErr)
			}
			if row == nil {
				return identityprovider.SyncRunMutationResult{}, invalidIdentityProviderProjection("null LDAP manual-sync result")
			}
			runID, mapErr := domainUUID(row.SyncRunID)
			if mapErr != nil || !identityProviderUUIDv7(runID) || !row.Replayed && runID != params.RunID {
				return identityprovider.SyncRunMutationResult{}, invalidIdentityProviderProjection("invalid LDAP manual-sync result")
			}
			run, mapErr := getLDAPSyncRun(ctx, queries, params.TenantID, params.BindingID, runID)
			if mapErr != nil {
				return identityprovider.SyncRunMutationResult{}, mapErr
			}
			if run.Trigger != "manual" || run.ManualReason == nil || *run.ManualReason != params.Reason ||
				run.Snapshot.BindingVersion != params.ExpectedVersion ||
				!row.Replayed && (run.State != identityprovider.SyncRunQueued || run.Version != 1) {
				return identityprovider.SyncRunMutationResult{}, invalidIdentityProviderProjection("divergent LDAP manual-sync result")
			}
			return identityprovider.SyncRunMutationResult{Run: run, Replayed: row.Replayed}, nil
		},
	)
}

func withLDAPSyncAdministrationTransaction[T any](
	ctx context.Context,
	repository *IdentityProviderRepository,
	human identityprovider.HumanParams,
	work func(ldapSyncAdministrationQueries) (T, error),
) (T, error) {
	var zero T
	if !validIdentityProviderHuman(human) {
		return zero, identityprovider.ErrForbidden
	}
	if repository == nil || repository.begin == nil || repository.syncAdministrationQueryFactory == nil || work == nil {
		return zero, fmt.Errorf("%w: LDAP sync administration dependencies are required", identityprovider.ErrUnavailable)
	}
	result, err := withinTransaction(ctx, repository.begin, func(tx databaseTransaction) (T, error) {
		queries := repository.syncAdministrationQueryFactory(tx)
		if queries == nil {
			return zero, invalidIdentityProviderProjection("LDAP sync administration query surface is unavailable")
		}
		installed, installErr := queries.SetTenantContext(ctx, dbsql.SetTenantContextParams{
			TenantID: toDatabaseUUID(human.TenantID), UserID: toDatabaseUUID(human.Actor.UserID),
		})
		if installErr != nil {
			return zero, mapIdentityProviderDatabaseError(installErr)
		}
		if installed == nil || installed.TenantID != human.TenantID.String() || installed.UserID != human.Actor.UserID.String() {
			return zero, invalidIdentityProviderProjection("database installed an unexpected LDAP sync administration context")
		}
		return work(queries)
	})
	if err != nil {
		return zero, mapIdentityProviderDatabaseError(err)
	}
	return result, nil
}

func validLDAPManualSyncMutation(params identityprovider.StartManualSyncParams) bool {
	return validIdentityProviderHuman(params.HumanParams) &&
		validIdentityProviderAudit(params.Audit) && validIdentityProviderOccurrence(params.OccurredAt) &&
		identityProviderUUIDv7(params.RunID) && identityProviderUUIDv7(params.AuditEventID) &&
		identityProviderUUIDv7(params.BindingID) && params.ExpectedVersion >= 1 &&
		params.ExpectedVersion <= math.MaxInt32 && validLDAPSyncReason(params.Reason) &&
		!allZero(params.IdempotencyKeyDigest[:]) && !allZero(params.RequestDigest[:])
}

func validLDAPSyncReason(value string) bool {
	if value != strings.TrimSpace(value) || !utf8.ValidString(value) || utf8.RuneCountInString(value) < 1 ||
		utf8.RuneCountInString(value) > 500 {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func mapLDAPSyncStatus(
	row *dbsql.GetTenantLDAPSyncStatusRow,
	expectedBindingID uuid.UUID,
) (identityprovider.SyncStatus, error) {
	if row == nil {
		return identityprovider.SyncStatus{}, invalidIdentityProviderProjection("null LDAP sync status")
	}
	bindingID, err := domainUUID(row.BindingID)
	if err != nil || bindingID != expectedBindingID || !identityProviderUUIDv7(bindingID) ||
		row.Version < 1 || row.SyncIntervalSeconds < 0 ||
		row.SyncIntervalSeconds != 0 && (row.SyncIntervalSeconds < 300 || row.SyncIntervalSeconds > 2_592_000) {
		return identityprovider.SyncStatus{}, invalidIdentityProviderProjection("invalid LDAP sync status")
	}
	updatedAt, err := domainTime(row.UpdatedAt)
	if err != nil {
		return identityprovider.SyncStatus{}, invalidIdentityProviderProjection("invalid LDAP sync status timestamp")
	}
	activeRunID, err := optionalLDAPSyncUUID(row.ActiveRunID)
	if err != nil {
		return identityprovider.SyncStatus{}, err
	}
	lastRunID, err := optionalLDAPSyncUUID(row.LastRunID)
	if err != nil {
		return identityprovider.SyncStatus{}, err
	}
	lastCompletedAt, err := optionalIdentityProviderTime(row.LastCompletedAt)
	if err != nil {
		return identityprovider.SyncStatus{}, err
	}
	nextScheduledAt, err := optionalIdentityProviderTime(row.NextScheduledAt)
	if err != nil {
		return identityprovider.SyncStatus{}, err
	}
	var interval *int
	if row.SyncIntervalSeconds != 0 {
		value := int(row.SyncIntervalSeconds)
		interval = &value
	}
	var lastState *identityprovider.SyncRunState
	if row.LastRunState != "" {
		value := identityprovider.SyncRunState(row.LastRunState)
		lastState = &value
	}
	if (lastRunID == nil) != (lastState == nil) {
		return identityprovider.SyncStatus{}, invalidIdentityProviderProjection("partial LDAP last-sync status")
	}
	return identityprovider.SyncStatus{
		BindingID: bindingID, ScheduleState: row.ScheduleState, SyncIntervalSeconds: interval,
		ActiveRunID: activeRunID, LastRunID: lastRunID, LastRunState: lastState,
		LastCompletedAt: lastCompletedAt, NextScheduledAt: nextScheduledAt,
		Version: int64(row.Version), UpdatedAt: updatedAt,
	}, nil
}

type ldapSyncRunProjection struct {
	id, tenantID, bindingID, providerID, accessEpochID         pgtype.UUID
	trigger, manualReason, state                               string
	providerVersion, bindingVersion, configurationRevision     int32
	mappingRevisions                                           []byte
	enumerationState                                           string
	enumerationComplete, resultTruncated, absenceAllowed       bool
	entryCount, pageCount, responseBytes                       int32
	cursorState, enumerationErrorCategory                      string
	observed, staged, identitiesCreated, identitiesLinked      int32
	providerAccessAdded, providerAccessSuspended               int32
	groupEdgesAdded, groupEdgesRefreshed, groupEdgesRevoked    int32
	roleEdgesAdded, roleEdgesRefreshed, roleEdgesRevoked       int32
	rosterEdgesAdded, rosterEdgesRefreshed, rosterEdgesRevoked int32
	failed, version                                            int32
	runErrorCategory                                           string
	createdAt, startedAt, completedAt, updatedAt               pgtype.Timestamptz
}

func mapListedLDAPSyncRun(
	row *dbsql.ListTenantLDAPSyncRunsRow,
	tenantID, bindingID uuid.UUID,
) (identityprovider.SyncRun, error) {
	if row == nil {
		return identityprovider.SyncRun{}, invalidIdentityProviderProjection("null listed LDAP sync run")
	}
	return mapLDAPSyncRun(ldapSyncRunProjection{
		id: row.ID, tenantID: row.TenantID, bindingID: row.BindingID, providerID: row.ProviderID,
		accessEpochID: row.AccessEpochID, trigger: row.Trigger, manualReason: row.ManualReason, state: row.State,
		providerVersion: row.ProviderVersion, bindingVersion: row.BindingVersion,
		configurationRevision: row.ConfigurationRevision, mappingRevisions: row.MappingRevisions,
		enumerationState: row.EnumerationState, enumerationComplete: row.EnumerationComplete,
		resultTruncated: row.ResultTruncated, absenceAllowed: row.AbsenceAllowed,
		entryCount: row.EntryCount, pageCount: row.PageCount, responseBytes: row.ResponseBytes,
		cursorState: row.CursorState, enumerationErrorCategory: row.EnumerationErrorCategory,
		observed: row.Observed, staged: row.Staged, identitiesCreated: row.IdentitiesCreated,
		identitiesLinked: row.IdentitiesLinked, providerAccessAdded: row.ProviderAccessAdded,
		providerAccessSuspended: row.ProviderAccessSuspended, groupEdgesAdded: row.GroupEdgesAdded,
		groupEdgesRefreshed: row.GroupEdgesRefreshed, groupEdgesRevoked: row.GroupEdgesRevoked,
		roleEdgesAdded: row.RoleEdgesAdded, roleEdgesRefreshed: row.RoleEdgesRefreshed,
		roleEdgesRevoked: row.RoleEdgesRevoked, rosterEdgesAdded: row.RosterEdgesAdded,
		rosterEdgesRefreshed: row.RosterEdgesRefreshed, rosterEdgesRevoked: row.RosterEdgesRevoked,
		failed: row.Failed, runErrorCategory: row.RunErrorCategory,
		createdAt: row.CreatedAt, startedAt: row.StartedAt, completedAt: row.CompletedAt,
		version: row.Version, updatedAt: row.UpdatedAt,
	}, tenantID, bindingID, uuid.Nil)
}

func mapGotLDAPSyncRun(
	row *dbsql.GetTenantLDAPSyncRunRow,
	tenantID, bindingID, runID uuid.UUID,
) (identityprovider.SyncRun, error) {
	if row == nil {
		return identityprovider.SyncRun{}, invalidIdentityProviderProjection("null LDAP sync run")
	}
	return mapLDAPSyncRun(ldapSyncRunProjection{
		id: row.ID, tenantID: row.TenantID, bindingID: row.BindingID, providerID: row.ProviderID,
		accessEpochID: row.AccessEpochID, trigger: row.Trigger, manualReason: row.ManualReason, state: row.State,
		providerVersion: row.ProviderVersion, bindingVersion: row.BindingVersion,
		configurationRevision: row.ConfigurationRevision, mappingRevisions: row.MappingRevisions,
		enumerationState: row.EnumerationState, enumerationComplete: row.EnumerationComplete,
		resultTruncated: row.ResultTruncated, absenceAllowed: row.AbsenceAllowed,
		entryCount: row.EntryCount, pageCount: row.PageCount, responseBytes: row.ResponseBytes,
		cursorState: row.CursorState, enumerationErrorCategory: row.EnumerationErrorCategory,
		observed: row.Observed, staged: row.Staged, identitiesCreated: row.IdentitiesCreated,
		identitiesLinked: row.IdentitiesLinked, providerAccessAdded: row.ProviderAccessAdded,
		providerAccessSuspended: row.ProviderAccessSuspended, groupEdgesAdded: row.GroupEdgesAdded,
		groupEdgesRefreshed: row.GroupEdgesRefreshed, groupEdgesRevoked: row.GroupEdgesRevoked,
		roleEdgesAdded: row.RoleEdgesAdded, roleEdgesRefreshed: row.RoleEdgesRefreshed,
		roleEdgesRevoked: row.RoleEdgesRevoked, rosterEdgesAdded: row.RosterEdgesAdded,
		rosterEdgesRefreshed: row.RosterEdgesRefreshed, rosterEdgesRevoked: row.RosterEdgesRevoked,
		failed: row.Failed, runErrorCategory: row.RunErrorCategory,
		createdAt: row.CreatedAt, startedAt: row.StartedAt, completedAt: row.CompletedAt,
		version: row.Version, updatedAt: row.UpdatedAt,
	}, tenantID, bindingID, runID)
}

func mapLDAPSyncRun(
	row ldapSyncRunProjection,
	expectedTenantID, expectedBindingID, expectedRunID uuid.UUID,
) (identityprovider.SyncRun, error) {
	runID, err := requiredLDAPSyncUUID(row.id, expectedRunID)
	if err != nil {
		return identityprovider.SyncRun{}, err
	}
	tenantID, err := requiredLDAPSyncUUID(row.tenantID, expectedTenantID)
	if err != nil {
		return identityprovider.SyncRun{}, err
	}
	bindingID, err := requiredLDAPSyncUUID(row.bindingID, expectedBindingID)
	if err != nil {
		return identityprovider.SyncRun{}, err
	}
	providerID, err := requiredLDAPSyncUUID(row.providerID, uuid.Nil)
	if err != nil {
		return identityprovider.SyncRun{}, err
	}
	accessEpochID, err := requiredLDAPSyncUUID(row.accessEpochID, uuid.Nil)
	if err != nil {
		return identityprovider.SyncRun{}, err
	}
	createdAt, err := domainTime(row.createdAt)
	if err != nil {
		return identityprovider.SyncRun{}, invalidIdentityProviderProjection("invalid LDAP sync creation time")
	}
	updatedAt, err := domainTime(row.updatedAt)
	if err != nil || updatedAt.Before(createdAt) {
		return identityprovider.SyncRun{}, invalidIdentityProviderProjection("invalid LDAP sync update time")
	}
	startedAt, err := optionalIdentityProviderTime(row.startedAt)
	if err != nil {
		return identityprovider.SyncRun{}, err
	}
	completedAt, err := optionalIdentityProviderTime(row.completedAt)
	if err != nil {
		return identityprovider.SyncRun{}, err
	}
	revisions, err := mapLDAPPinnedMappingRevisions(row.mappingRevisions)
	if err != nil {
		return identityprovider.SyncRun{}, err
	}
	var manualReason *string
	if row.manualReason != "" {
		value := row.manualReason
		manualReason = &value
	}
	var enumerationError *string
	if row.enumerationErrorCategory != "" {
		value := row.enumerationErrorCategory
		enumerationError = &value
	}
	var runError *string
	if row.runErrorCategory != "" {
		value := row.runErrorCategory
		runError = &value
	}
	return identityprovider.SyncRun{
		ID: runID, TenantID: tenantID, BindingID: bindingID, ProviderID: providerID,
		Trigger: row.trigger, ManualReason: manualReason, State: identityprovider.SyncRunState(row.state),
		Snapshot: identityprovider.PinnedPlannerSnapshot{
			ProviderID: providerID, ProviderVersion: int64(row.providerVersion),
			BindingID: bindingID, BindingVersion: int64(row.bindingVersion),
			ConfigurationRevision: int(row.configurationRevision), AccessEpochID: accessEpochID,
			MappingRevisions: revisions,
		},
		Enumeration: identityprovider.SyncEnumeration{
			State: row.enumerationState, Complete: row.enumerationComplete, Truncated: row.resultTruncated,
			AbsenceBasedRevocationAllowed: row.absenceAllowed, EntryCount: int(row.entryCount),
			PageCount: int(row.pageCount), ResponseBytes: int(row.responseBytes),
			CursorState: row.cursorState, ErrorCategory: enumerationError,
		},
		Counters: identityprovider.SyncCounters{
			Observed: int(row.observed), Staged: int(row.staged), IdentitiesCreated: int(row.identitiesCreated),
			IdentitiesLinked: int(row.identitiesLinked), ProviderAccessAdded: int(row.providerAccessAdded),
			ProviderAccessSuspended: int(row.providerAccessSuspended), GroupEdgesAdded: int(row.groupEdgesAdded),
			GroupEdgesRefreshed: int(row.groupEdgesRefreshed), GroupEdgesRevoked: int(row.groupEdgesRevoked),
			RoleEdgesAdded: int(row.roleEdgesAdded), RoleEdgesRefreshed: int(row.roleEdgesRefreshed),
			RoleEdgesRevoked: int(row.roleEdgesRevoked), RosterEdgesAdded: int(row.rosterEdgesAdded),
			RosterEdgesRefreshed: int(row.rosterEdgesRefreshed), RosterEdgesRevoked: int(row.rosterEdgesRevoked),
			Failed: int(row.failed),
		},
		RunErrorCategory: runError, CreatedAt: createdAt, StartedAt: startedAt,
		CompletedAt: completedAt, Version: int64(row.version), UpdatedAt: updatedAt,
	}, nil
}

func getLDAPSyncRun(
	ctx context.Context,
	queries ldapSyncAdministrationQueries,
	tenantID, bindingID, runID uuid.UUID,
) (identityprovider.SyncRun, error) {
	row, err := queries.GetTenantLDAPSyncRun(ctx, dbsql.GetTenantLDAPSyncRunParams{
		BindingID: toDatabaseUUID(bindingID), SyncRunID: toDatabaseUUID(runID),
	})
	if err != nil {
		return identityprovider.SyncRun{}, mapIdentityProviderDatabaseError(err)
	}
	return mapGotLDAPSyncRun(row, tenantID, bindingID, runID)
}

func optionalLDAPSyncUUID(value pgtype.UUID) (*uuid.UUID, error) {
	if !value.Valid {
		return nil, nil
	}
	identifier, err := domainUUID(value)
	if err != nil || !identityProviderUUIDv7(identifier) {
		return nil, invalidIdentityProviderProjection("invalid optional LDAP sync identifier")
	}
	return &identifier, nil
}

func requiredLDAPSyncUUID(value pgtype.UUID, expected uuid.UUID) (uuid.UUID, error) {
	identifier, err := domainUUID(value)
	if err != nil || !identityProviderUUIDv7(identifier) || expected != uuid.Nil && identifier != expected {
		return uuid.Nil, invalidIdentityProviderProjection("unexpected LDAP sync identifier")
	}
	return identifier, nil
}
