package postgres

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/operatorteam"
	"github.com/periapsis-im/periapsis/services/api/internal/postgres/dbsql"
)

const (
	operatorTeamPageLimit int32 = 101

	operatorTeamVersionConflictMessage     = "operator team version conflict"
	operatorTeamAssignmentConflictMessage  = "operator-team assignment version conflict"
	operatorTeamRosterEntryConflictMessage = "operator-team roster entry version conflict"
	maximumOperatorTeamAuthenticationBytes = 64
	maximumOperatorTeamAuditUserAgentRunes = 1024
)

type operatorTeamQueries interface {
	SetUserContext(context.Context, dbsql.SetUserContextParams) (string, error)
	SetTenantContext(context.Context, dbsql.SetTenantContextParams) (*dbsql.SetTenantContextRow, error)
	ListPlatformOperatorTeams(context.Context, dbsql.ListPlatformOperatorTeamsParams) ([]*dbsql.ListPlatformOperatorTeamsRow, error)
	GetPlatformOperatorTeam(context.Context, dbsql.GetPlatformOperatorTeamParams) (*dbsql.GetPlatformOperatorTeamRow, error)
	CreatePlatformOperatorTeam(context.Context, dbsql.CreatePlatformOperatorTeamParams) (*dbsql.CreatePlatformOperatorTeamRow, error)
	UpdatePlatformOperatorTeamMetadata(context.Context, dbsql.UpdatePlatformOperatorTeamMetadataParams) (int32, error)
	ArchivePlatformOperatorTeam(context.Context, dbsql.ArchivePlatformOperatorTeamParams) (int32, error)
	ListTenantOperatorTeamAssignments(context.Context, dbsql.ListTenantOperatorTeamAssignmentsParams) ([]*dbsql.ListTenantOperatorTeamAssignmentsRow, error)
	GetTenantOperatorTeamAssignment(context.Context, dbsql.GetTenantOperatorTeamAssignmentParams) (*dbsql.GetTenantOperatorTeamAssignmentRow, error)
	StartTenantOperatorTeamAssignment(context.Context, dbsql.StartTenantOperatorTeamAssignmentParams) (*dbsql.StartTenantOperatorTeamAssignmentRow, error)
	EndTenantOperatorTeamAssignment(context.Context, dbsql.EndTenantOperatorTeamAssignmentParams) (int32, error)
	ListTenantOperatorTeamRosterEntries(context.Context, dbsql.ListTenantOperatorTeamRosterEntriesParams) ([]*dbsql.ListTenantOperatorTeamRosterEntriesRow, error)
	GetTenantOperatorTeamRosterEntry(context.Context, dbsql.GetTenantOperatorTeamRosterEntryParams) (*dbsql.GetTenantOperatorTeamRosterEntryRow, error)
	AddTenantOperatorTeamRosterEntry(context.Context, dbsql.AddTenantOperatorTeamRosterEntryParams) (*dbsql.AddTenantOperatorTeamRosterEntryRow, error)
	RevokeTenantOperatorTeamRosterEntry(context.Context, dbsql.RevokeTenantOperatorTeamRosterEntryParams) (int32, error)
}

// OperatorTeamRepository implements the platform-owned team identity and the
// tenant-owned exact assignment/roster relationship through the 0028 SECURITY
// DEFINER ABI. Every call installs only the context appropriate to that side of
// the trust boundary before invoking an entry point.
type OperatorTeamRepository struct {
	begin        transactionBeginner
	queryFactory func(databaseTransaction) operatorTeamQueries
	authority    *AuthorizationRepository
	newID        func() (uuid.UUID, error)
}

func NewOperatorTeamRepository(pool *pgxpool.Pool) *OperatorTeamRepository {
	return &OperatorTeamRepository{
		begin: poolTransactionBeginner(pool),
		queryFactory: func(tx databaseTransaction) operatorTeamQueries {
			return dbsql.New(tx)
		},
		authority: NewAuthorizationRepository(pool),
		newID:     uuid.NewV7,
	}
}

var _ operatorteam.Repository = (*OperatorTeamRepository)(nil)

func (r *OperatorTeamRepository) ResolveAuthority(
	ctx context.Context,
	params authorization.ResolveAuthorityParams,
) (authorization.TenantAuthority, error) {
	if r == nil || r.authority == nil {
		return authorization.TenantAuthority{}, fmt.Errorf("%w: authorization repository is required", operatorteam.ErrUnavailable)
	}
	return r.authority.ResolveAuthority(ctx, params)
}

func (r *OperatorTeamRepository) ListOperatorTeams(
	ctx context.Context,
	params operatorteam.ListOperatorTeamsParams,
) ([]operatorteam.OperatorTeam, error) {
	if !validOperatorTeamPlatformActor(params.Actor) ||
		operatorTeamPageError(params.After, params.Limit) != nil {
		return nil, operatorteam.ErrInvalidInput
	}
	return withOperatorTeamPlatformTransaction(ctx, r, params.Actor, pgx.ReadCommitted,
		func(queries operatorTeamQueries) ([]operatorteam.OperatorTeam, error) {
			rows, err := queries.ListPlatformOperatorTeams(ctx, dbsql.ListPlatformOperatorTeamsParams{
				AfterID: optionalDatabaseUUID(params.After), IncludeArchived: params.IncludeArchived,
				PageSize: params.Limit,
			})
			if err != nil {
				return nil, mapOperatorTeamDatabaseError(err)
			}
			if len(rows) > int(params.Limit) {
				return nil, invalidOperatorTeamProjection("oversized platform operator-team page")
			}
			items := make([]operatorteam.OperatorTeam, 0, len(rows))
			for _, row := range rows {
				team, mapErr := mapListedOperatorTeam(row)
				if mapErr != nil {
					return nil, mapErr
				}
				items = append(items, team)
			}
			return items, nil
		},
	)
}

func (r *OperatorTeamRepository) GetOperatorTeam(
	ctx context.Context,
	params operatorteam.GetOperatorTeamParams,
) (operatorteam.OperatorTeam, error) {
	if !validOperatorTeamPlatformActor(params.Actor) || !authorizationUUIDv7(params.OperatorTeamID) {
		return operatorteam.OperatorTeam{}, operatorteam.ErrInvalidInput
	}
	return withOperatorTeamPlatformTransaction(ctx, r, params.Actor, pgx.ReadCommitted,
		func(queries operatorTeamQueries) (operatorteam.OperatorTeam, error) {
			return getPlatformOperatorTeam(ctx, queries, params.OperatorTeamID)
		},
	)
}

func (r *OperatorTeamRepository) CreateOperatorTeam(
	ctx context.Context,
	params operatorteam.CreateOperatorTeamParams,
) (operatorteam.IdempotentCreateResult[operatorteam.OperatorTeam], error) {
	if !validCreateOperatorTeamParams(params) {
		return operatorteam.IdempotentCreateResult[operatorteam.OperatorTeam]{}, operatorteam.ErrInvalidInput
	}
	audit, err := r.operatorTeamAudit(params.Actor.AuthenticationMethod, params.Audit, params.OccurredAt)
	if err != nil {
		return operatorteam.IdempotentCreateResult[operatorteam.OperatorTeam]{}, err
	}
	digest := sha256.Sum256([]byte(params.IdempotencyKey))
	return withOperatorTeamPlatformTransaction(ctx, r, params.Actor, pgx.ReadCommitted,
		func(queries operatorTeamQueries) (operatorteam.IdempotentCreateResult[operatorteam.OperatorTeam], error) {
			result, queryErr := queries.CreatePlatformOperatorTeam(ctx, dbsql.CreatePlatformOperatorTeamParams{
				OperatorTeamID: toDatabaseUUID(params.OperatorTeamID), IdempotencyKeyDigest: digest[:],
				TeamKey: params.Key, DisplayName: params.Name, Description: params.Description,
				AuditID: audit.auditID, RequestID: audit.requestID, CorrelationID: audit.correlationID,
				IpAddress: audit.remoteAddress, UserAgent: audit.userAgent,
				AuthenticationMethod: audit.authenticationMethod,
			})
			if queryErr != nil {
				return operatorteam.IdempotentCreateResult[operatorteam.OperatorTeam]{}, mapOperatorTeamDatabaseError(queryErr)
			}
			if result == nil || result.ResultVersion < 1 {
				return operatorteam.IdempotentCreateResult[operatorteam.OperatorTeam]{}, invalidOperatorTeamProjection("invalid operator-team create result")
			}
			resultID, mapErr := operatorTeamUUID(result.ResultResourceID)
			if mapErr != nil || !result.Replayed && resultID != params.OperatorTeamID {
				return operatorteam.IdempotentCreateResult[operatorteam.OperatorTeam]{}, invalidOperatorTeamProjection("unexpected operator-team create result")
			}
			team, mapErr := getPlatformOperatorTeam(ctx, queries, resultID)
			if mapErr != nil {
				return operatorteam.IdempotentCreateResult[operatorteam.OperatorTeam]{}, mapErr
			}
			if team.Key != params.Key || team.CreatedByUserID == nil || *team.CreatedByUserID != params.Actor.UserID ||
				!authorizationCommandVersionMatches(result.ResultVersion, result.Replayed, team.Version) ||
				!result.Replayed && (team.Name != params.Name || team.Description != params.Description ||
					team.State != operatorteam.OperatorTeamStateActive) {
				return operatorteam.IdempotentCreateResult[operatorteam.OperatorTeam]{}, invalidOperatorTeamProjection("operator-team create representation mismatch")
			}
			return operatorteam.IdempotentCreateResult[operatorteam.OperatorTeam]{
				Value: team, Replayed: result.Replayed,
			}, nil
		},
	)
}

func (r *OperatorTeamRepository) PatchOperatorTeam(
	ctx context.Context,
	params operatorteam.PatchOperatorTeamParams,
) (operatorteam.OperatorTeam, error) {
	version, err := operatorTeamDatabaseVersion(params.ExpectedVersion)
	if err != nil || !validPatchOperatorTeamParams(params) {
		return operatorteam.OperatorTeam{}, operatorteam.ErrInvalidInput
	}
	audit, err := r.operatorTeamAudit(params.Actor.AuthenticationMethod, params.Audit, params.OccurredAt)
	if err != nil {
		return operatorteam.OperatorTeam{}, err
	}
	return withOperatorTeamPlatformTransaction(ctx, r, params.Actor, pgx.ReadCommitted,
		func(queries operatorTeamQueries) (operatorteam.OperatorTeam, error) {
			updatedVersion, queryErr := queries.UpdatePlatformOperatorTeamMetadata(
				ctx,
				dbsql.UpdatePlatformOperatorTeamMetadataParams{
					OperatorTeamID: toDatabaseUUID(params.OperatorTeamID), ExpectedVersion: version,
					DisplayName: params.Name, Description: params.Description,
					AuditID: audit.auditID, RequestID: audit.requestID, CorrelationID: audit.correlationID,
					IpAddress: audit.remoteAddress, UserAgent: audit.userAgent,
					AuthenticationMethod: audit.authenticationMethod,
				},
			)
			if queryErr != nil {
				return operatorteam.OperatorTeam{}, mapOperatorTeamDatabaseError(queryErr)
			}
			if updatedVersion != version+1 {
				return operatorteam.OperatorTeam{}, invalidOperatorTeamProjection("unexpected operator-team update version")
			}
			team, mapErr := getPlatformOperatorTeam(ctx, queries, params.OperatorTeamID)
			if mapErr != nil {
				return operatorteam.OperatorTeam{}, mapErr
			}
			if team.Version != int64(updatedVersion) || team.State != operatorteam.OperatorTeamStateActive ||
				params.Name != nil && team.Name != *params.Name ||
				params.Description != nil && team.Description != *params.Description {
				return operatorteam.OperatorTeam{}, invalidOperatorTeamProjection("operator-team update representation mismatch")
			}
			return team, nil
		},
	)
}

func (r *OperatorTeamRepository) ArchiveOperatorTeam(
	ctx context.Context,
	params operatorteam.ArchiveOperatorTeamParams,
) error {
	version, err := operatorTeamDatabaseVersion(params.ExpectedVersion)
	if err != nil || !validArchiveOperatorTeamParams(params) {
		return operatorteam.ErrInvalidInput
	}
	audit, err := r.operatorTeamAudit(params.Actor.AuthenticationMethod, params.Audit, params.OccurredAt)
	if err != nil {
		return err
	}
	_, err = withOperatorTeamPlatformTransaction(ctx, r, params.Actor, pgx.ReadCommitted,
		func(queries operatorTeamQueries) (struct{}, error) {
			updatedVersion, queryErr := queries.ArchivePlatformOperatorTeam(ctx, dbsql.ArchivePlatformOperatorTeamParams{
				OperatorTeamID: toDatabaseUUID(params.OperatorTeamID), ExpectedVersion: version,
				Reason: params.Reason, AuditID: audit.auditID, RequestID: audit.requestID,
				CorrelationID: audit.correlationID, IpAddress: audit.remoteAddress,
				UserAgent: audit.userAgent, AuthenticationMethod: audit.authenticationMethod,
			})
			if queryErr != nil {
				return struct{}{}, mapOperatorTeamDatabaseError(queryErr)
			}
			if updatedVersion != version+1 {
				return struct{}{}, invalidOperatorTeamProjection("unexpected operator-team archive version")
			}
			team, mapErr := getPlatformOperatorTeam(ctx, queries, params.OperatorTeamID)
			if mapErr != nil {
				return struct{}{}, mapErr
			}
			if team.Version != int64(updatedVersion) || team.State != operatorteam.OperatorTeamStateArchived ||
				team.ArchiveReason == nil || *team.ArchiveReason != params.Reason ||
				team.ArchivedByUserID == nil || *team.ArchivedByUserID != params.Actor.UserID ||
				team.ActiveAssignmentCount != 0 {
				return struct{}{}, invalidOperatorTeamProjection("operator-team archive representation mismatch")
			}
			return struct{}{}, nil
		},
	)
	return err
}

func (r *OperatorTeamRepository) ListTenantAssignments(
	ctx context.Context,
	params operatorteam.ListTenantAssignmentsParams,
) ([]operatorteam.TenantAssignment, error) {
	if !validOperatorTeamTenantActor(params.Actor, params.TenantID) ||
		operatorTeamPageError(params.After, params.Limit) != nil {
		return nil, operatorteam.ErrInvalidInput
	}
	return withOperatorTeamTenantTransaction(ctx, r, params.Actor, params.TenantID, pgx.ReadCommitted,
		func(queries operatorTeamQueries) ([]operatorteam.TenantAssignment, error) {
			rows, err := queries.ListTenantOperatorTeamAssignments(
				ctx,
				dbsql.ListTenantOperatorTeamAssignmentsParams{
					AfterEpochID: optionalDatabaseUUID(params.After), IncludeEnded: params.IncludeEnded,
					PageSize: params.Limit,
				},
			)
			if err != nil {
				return nil, mapOperatorTeamDatabaseError(err)
			}
			if len(rows) > int(params.Limit) {
				return nil, invalidOperatorTeamProjection("oversized operator-team assignment page")
			}
			items := make([]operatorteam.TenantAssignment, 0, len(rows))
			for _, row := range rows {
				assignment, mapErr := mapListedOperatorTeamAssignment(params.TenantID, row)
				if mapErr != nil {
					return nil, mapErr
				}
				items = append(items, assignment)
			}
			return items, nil
		},
	)
}

func (r *OperatorTeamRepository) GetTenantAssignment(
	ctx context.Context,
	params operatorteam.GetTenantAssignmentParams,
) (operatorteam.TenantAssignment, error) {
	if !validOperatorTeamTenantActor(params.Actor, params.TenantID) ||
		!authorizationUUIDv7(params.OperatorTeamID) || !authorizationUUIDv7(params.EpochID) {
		return operatorteam.TenantAssignment{}, operatorteam.ErrInvalidInput
	}
	return withOperatorTeamTenantTransaction(ctx, r, params.Actor, params.TenantID, pgx.ReadCommitted,
		func(queries operatorTeamQueries) (operatorteam.TenantAssignment, error) {
			return getTenantOperatorTeamAssignment(
				ctx, queries, params.TenantID, params.OperatorTeamID, params.EpochID,
			)
		},
	)
}

func (r *OperatorTeamRepository) StartTenantAssignment(
	ctx context.Context,
	params operatorteam.StartTenantAssignmentParams,
) (operatorteam.IdempotentCreateResult[operatorteam.TenantAssignment], error) {
	if !validStartOperatorTeamAssignmentParams(params) {
		return operatorteam.IdempotentCreateResult[operatorteam.TenantAssignment]{}, operatorteam.ErrInvalidInput
	}
	tenantAudit, err := r.operatorTeamAudit(params.Actor.AuthenticationMethod, params.Audit, params.OccurredAt)
	if err != nil {
		return operatorteam.IdempotentCreateResult[operatorteam.TenantAssignment]{}, err
	}
	platformAudit, err := r.operatorTeamAudit(params.Actor.AuthenticationMethod, params.Audit, params.OccurredAt)
	if err != nil {
		return operatorteam.IdempotentCreateResult[operatorteam.TenantAssignment]{}, err
	}
	if tenantAudit.auditID == platformAudit.auditID {
		return operatorteam.IdempotentCreateResult[operatorteam.TenantAssignment]{}, invalidOperatorTeamProjection("assignment audit IDs are not distinct")
	}
	digest := sha256.Sum256([]byte(params.IdempotencyKey))
	return withOperatorTeamTenantTransaction(ctx, r, params.Actor, params.TenantID, pgx.ReadCommitted,
		func(queries operatorTeamQueries) (operatorteam.IdempotentCreateResult[operatorteam.TenantAssignment], error) {
			result, queryErr := queries.StartTenantOperatorTeamAssignment(
				ctx,
				dbsql.StartTenantOperatorTeamAssignmentParams{
					AssignmentEpochID: toDatabaseUUID(params.EpochID), IdempotencyKeyDigest: digest[:],
					OperatorTeamID: toDatabaseUUID(params.OperatorTeamID), Reason: params.Reason,
					TenantAuditID: tenantAudit.auditID, PlatformAuditID: platformAudit.auditID,
					RequestID: tenantAudit.requestID, CorrelationID: tenantAudit.correlationID,
					IpAddress: tenantAudit.remoteAddress, UserAgent: tenantAudit.userAgent,
					AuthenticationMethod: tenantAudit.authenticationMethod,
				},
			)
			if queryErr != nil {
				return operatorteam.IdempotentCreateResult[operatorteam.TenantAssignment]{}, mapOperatorTeamDatabaseError(queryErr)
			}
			if result == nil || result.ResultVersion < 1 {
				return operatorteam.IdempotentCreateResult[operatorteam.TenantAssignment]{}, invalidOperatorTeamProjection("invalid assignment start result")
			}
			resultID, mapErr := operatorTeamUUID(result.ResultResourceID)
			if mapErr != nil || !result.Replayed && resultID != params.EpochID {
				return operatorteam.IdempotentCreateResult[operatorteam.TenantAssignment]{}, invalidOperatorTeamProjection("unexpected assignment start result")
			}
			assignment, mapErr := getTenantOperatorTeamAssignment(
				ctx, queries, params.TenantID, params.OperatorTeamID, resultID,
			)
			if mapErr != nil {
				return operatorteam.IdempotentCreateResult[operatorteam.TenantAssignment]{}, mapErr
			}
			if assignment.StartReason != params.Reason || assignment.StartedByUserID != params.Actor.UserID ||
				!authorizationCommandVersionMatches(result.ResultVersion, result.Replayed, assignment.Version) ||
				!result.Replayed && (assignment.EpochID != params.EpochID ||
					assignment.State != operatorteam.AssignmentStateActive) {
				return operatorteam.IdempotentCreateResult[operatorteam.TenantAssignment]{}, invalidOperatorTeamProjection("assignment start representation mismatch")
			}
			return operatorteam.IdempotentCreateResult[operatorteam.TenantAssignment]{
				Value: assignment, Replayed: result.Replayed,
			}, nil
		},
	)
}

func (r *OperatorTeamRepository) EndTenantAssignment(
	ctx context.Context,
	params operatorteam.EndTenantAssignmentParams,
) error {
	version, err := operatorTeamDatabaseVersion(params.ExpectedVersion)
	if err != nil || !validEndOperatorTeamAssignmentParams(params) {
		return operatorteam.ErrInvalidInput
	}
	tenantAudit, err := r.operatorTeamAudit(params.Actor.AuthenticationMethod, params.Audit, params.OccurredAt)
	if err != nil {
		return err
	}
	platformAudit, err := r.operatorTeamAudit(params.Actor.AuthenticationMethod, params.Audit, params.OccurredAt)
	if err != nil {
		return err
	}
	if tenantAudit.auditID == platformAudit.auditID {
		return invalidOperatorTeamProjection("assignment audit IDs are not distinct")
	}
	_, err = withOperatorTeamTenantTransaction(ctx, r, params.Actor, params.TenantID, pgx.ReadCommitted,
		func(queries operatorTeamQueries) (struct{}, error) {
			updatedVersion, queryErr := queries.EndTenantOperatorTeamAssignment(
				ctx,
				dbsql.EndTenantOperatorTeamAssignmentParams{
					OperatorTeamID:    toDatabaseUUID(params.OperatorTeamID),
					AssignmentEpochID: toDatabaseUUID(params.EpochID), ExpectedVersion: version,
					Reason: params.Reason, TenantAuditID: tenantAudit.auditID,
					PlatformAuditID: platformAudit.auditID, RequestID: tenantAudit.requestID,
					CorrelationID: tenantAudit.correlationID, IpAddress: tenantAudit.remoteAddress,
					UserAgent: tenantAudit.userAgent, AuthenticationMethod: tenantAudit.authenticationMethod,
				},
			)
			if queryErr != nil {
				return struct{}{}, mapOperatorTeamDatabaseError(queryErr)
			}
			if updatedVersion != version+1 {
				return struct{}{}, invalidOperatorTeamProjection("unexpected assignment end version")
			}
			assignment, mapErr := getTenantOperatorTeamAssignment(
				ctx, queries, params.TenantID, params.OperatorTeamID, params.EpochID,
			)
			if mapErr != nil {
				return struct{}{}, mapErr
			}
			if assignment.Version != int64(updatedVersion) || assignment.State != operatorteam.AssignmentStateEnded ||
				assignment.EndedByUserID == nil || *assignment.EndedByUserID != params.Actor.UserID ||
				assignment.EndReason == nil || *assignment.EndReason != params.Reason {
				return struct{}{}, invalidOperatorTeamProjection("assignment end representation mismatch")
			}
			return struct{}{}, nil
		},
	)
	return err
}

func (r *OperatorTeamRepository) ListRosterEntries(
	ctx context.Context,
	params operatorteam.ListRosterEntriesParams,
) ([]operatorteam.RosterEntry, error) {
	if !validOperatorTeamTenantActor(params.Actor, params.TenantID) ||
		!authorizationUUIDv7(params.OperatorTeamID) || !authorizationUUIDv7(params.AssignmentEpochID) ||
		operatorTeamPageError(params.After, params.Limit) != nil {
		return nil, operatorteam.ErrInvalidInput
	}
	return withOperatorTeamTenantTransaction(ctx, r, params.Actor, params.TenantID, pgx.ReadCommitted,
		func(queries operatorTeamQueries) ([]operatorteam.RosterEntry, error) {
			rows, err := queries.ListTenantOperatorTeamRosterEntries(
				ctx,
				dbsql.ListTenantOperatorTeamRosterEntriesParams{
					OperatorTeamID:    toDatabaseUUID(params.OperatorTeamID),
					AssignmentEpochID: toDatabaseUUID(params.AssignmentEpochID),
					AfterEntryID:      optionalDatabaseUUID(params.After), IncludeRevoked: params.IncludeRevoked,
					PageSize: params.Limit,
				},
			)
			if err != nil {
				return nil, mapOperatorTeamDatabaseError(err)
			}
			if len(rows) > int(params.Limit) {
				return nil, invalidOperatorTeamProjection("oversized operator-team roster page")
			}
			items := make([]operatorteam.RosterEntry, 0, len(rows))
			for _, row := range rows {
				record, mapErr := listedOperatorTeamRosterRecord(row)
				if mapErr != nil {
					return nil, mapErr
				}
				entry, mapErr := mapOperatorTeamRosterEntry(
					params.TenantID, params.OperatorTeamID, params.AssignmentEpochID, record,
				)
				if mapErr != nil {
					return nil, mapErr
				}
				items = append(items, entry)
			}
			return items, nil
		},
	)
}

func (r *OperatorTeamRepository) GetRosterEntry(
	ctx context.Context,
	params operatorteam.GetRosterEntryParams,
) (operatorteam.RosterEntry, error) {
	if !validOperatorTeamTenantActor(params.Actor, params.TenantID) ||
		!authorizationUUIDv7(params.OperatorTeamID) || !authorizationUUIDv7(params.AssignmentEpochID) ||
		!authorizationUUIDv7(params.RosterEntryID) {
		return operatorteam.RosterEntry{}, operatorteam.ErrInvalidInput
	}
	return withOperatorTeamTenantTransaction(ctx, r, params.Actor, params.TenantID, pgx.ReadCommitted,
		func(queries operatorTeamQueries) (operatorteam.RosterEntry, error) {
			return getTenantOperatorTeamRosterEntry(
				ctx, queries, params.TenantID, params.OperatorTeamID,
				params.AssignmentEpochID, params.RosterEntryID,
			)
		},
	)
}

func (r *OperatorTeamRepository) AddRosterEntry(
	ctx context.Context,
	params operatorteam.AddRosterEntryParams,
) (operatorteam.IdempotentCreateResult[operatorteam.RosterEntry], error) {
	if !validAddOperatorTeamRosterEntryParams(params) {
		return operatorteam.IdempotentCreateResult[operatorteam.RosterEntry]{}, operatorteam.ErrInvalidInput
	}
	expiresAt, err := optionalDatabaseTime(params.ExpiresAt)
	if err != nil {
		return operatorteam.IdempotentCreateResult[operatorteam.RosterEntry]{}, operatorteam.ErrInvalidInput
	}
	audit, err := r.operatorTeamAudit(params.Actor.AuthenticationMethod, params.Audit, params.OccurredAt)
	if err != nil {
		return operatorteam.IdempotentCreateResult[operatorteam.RosterEntry]{}, err
	}
	digest := sha256.Sum256([]byte(params.IdempotencyKey))
	return withOperatorTeamTenantTransaction(ctx, r, params.Actor, params.TenantID, pgx.ReadCommitted,
		func(queries operatorTeamQueries) (operatorteam.IdempotentCreateResult[operatorteam.RosterEntry], error) {
			result, queryErr := queries.AddTenantOperatorTeamRosterEntry(
				ctx,
				dbsql.AddTenantOperatorTeamRosterEntryParams{
					RosterEntryID: toDatabaseUUID(params.RosterEntryID), IdempotencyKeyDigest: digest[:],
					OperatorTeamID:    toDatabaseUUID(params.OperatorTeamID),
					AssignmentEpochID: toDatabaseUUID(params.AssignmentEpochID),
					MembershipID:      toDatabaseUUID(params.MembershipID), Reason: params.Reason,
					ExpiresAt: expiresAt, AuditID: audit.auditID, RequestID: audit.requestID,
					CorrelationID: audit.correlationID, IpAddress: audit.remoteAddress,
					UserAgent: audit.userAgent, AuthenticationMethod: audit.authenticationMethod,
				},
			)
			if queryErr != nil {
				return operatorteam.IdempotentCreateResult[operatorteam.RosterEntry]{}, mapOperatorTeamDatabaseError(queryErr)
			}
			if result == nil || result.ResultVersion < 1 {
				return operatorteam.IdempotentCreateResult[operatorteam.RosterEntry]{}, invalidOperatorTeamProjection("invalid roster add result")
			}
			resultID, mapErr := operatorTeamUUID(result.ResultResourceID)
			if mapErr != nil || !result.Replayed && resultID != params.RosterEntryID {
				return operatorteam.IdempotentCreateResult[operatorteam.RosterEntry]{}, invalidOperatorTeamProjection("unexpected roster add result")
			}
			entry, mapErr := getTenantOperatorTeamRosterEntry(
				ctx, queries, params.TenantID, params.OperatorTeamID, params.AssignmentEpochID, resultID,
			)
			if mapErr != nil {
				return operatorteam.IdempotentCreateResult[operatorteam.RosterEntry]{}, mapErr
			}
			if entry.Member.MembershipID != params.MembershipID || entry.Provenance.Reason != params.Reason ||
				!sameOperatorTeamTime(entry.Provenance.ExpiresAt, params.ExpiresAt) ||
				entry.Provenance.GrantedByUserID == nil || *entry.Provenance.GrantedByUserID != params.Actor.UserID ||
				!entry.ManagedByOperatorTeamAPI ||
				!authorizationCommandVersionMatches(result.ResultVersion, result.Replayed, entry.Version) ||
				!result.Replayed && (entry.ID != params.RosterEntryID || entry.State != operatorteam.RosterEntryStateActive) {
				return operatorteam.IdempotentCreateResult[operatorteam.RosterEntry]{}, invalidOperatorTeamProjection("roster add representation mismatch")
			}
			return operatorteam.IdempotentCreateResult[operatorteam.RosterEntry]{
				Value: entry, Replayed: result.Replayed,
			}, nil
		},
	)
}

func (r *OperatorTeamRepository) RevokeRosterEntry(
	ctx context.Context,
	params operatorteam.RevokeRosterEntryParams,
) error {
	parsedVersion, err := authorization.ParseEdgeEntityTag(params.ExpectedEntityTag)
	if err != nil || !validRevokeOperatorTeamRosterEntryParams(params) {
		return operatorteam.ErrInvalidInput
	}
	version, err := operatorTeamDatabaseVersion(parsedVersion)
	if err != nil {
		return operatorteam.ErrInvalidInput
	}
	audit, err := r.operatorTeamAudit(params.Actor.AuthenticationMethod, params.Audit, params.OccurredAt)
	if err != nil {
		return err
	}
	_, err = withOperatorTeamTenantTransaction(ctx, r, params.Actor, params.TenantID, pgx.Serializable,
		func(queries operatorTeamQueries) (struct{}, error) {
			current, getErr := getTenantOperatorTeamRosterEntry(
				ctx, queries, params.TenantID, params.OperatorTeamID,
				params.AssignmentEpochID, params.RosterEntryID,
			)
			if getErr != nil {
				return struct{}{}, getErr
			}
			currentEntityTag, tagErr := operatorteam.RosterEntryEntityTag(current)
			if tagErr != nil {
				return struct{}{}, invalidOperatorTeamProjection("cannot derive current roster validator")
			}
			if currentEntityTag != params.ExpectedEntityTag || current.Version != parsedVersion {
				return struct{}{}, operatorteam.ErrPreconditionFailed
			}
			if !current.ManagedByOperatorTeamAPI || current.State != operatorteam.RosterEntryStateActive {
				return struct{}{}, operatorteam.ErrConflict
			}
			updatedVersion, queryErr := queries.RevokeTenantOperatorTeamRosterEntry(
				ctx,
				dbsql.RevokeTenantOperatorTeamRosterEntryParams{
					OperatorTeamID:    toDatabaseUUID(params.OperatorTeamID),
					AssignmentEpochID: toDatabaseUUID(params.AssignmentEpochID),
					RosterEntryID:     toDatabaseUUID(params.RosterEntryID), ExpectedVersion: version,
					Reason: params.Reason, AuditID: audit.auditID, RequestID: audit.requestID,
					CorrelationID: audit.correlationID, IpAddress: audit.remoteAddress,
					UserAgent: audit.userAgent, AuthenticationMethod: audit.authenticationMethod,
				},
			)
			if queryErr != nil {
				return struct{}{}, mapOperatorTeamDatabaseError(queryErr)
			}
			if updatedVersion != version+1 {
				return struct{}{}, invalidOperatorTeamProjection("unexpected roster revoke version")
			}
			return struct{}{}, nil
		},
	)
	return err
}

func getPlatformOperatorTeam(
	ctx context.Context,
	queries operatorTeamQueries,
	operatorTeamID uuid.UUID,
) (operatorteam.OperatorTeam, error) {
	row, err := queries.GetPlatformOperatorTeam(
		ctx, dbsql.GetPlatformOperatorTeamParams{OperatorTeamID: toDatabaseUUID(operatorTeamID)},
	)
	if err != nil {
		return operatorteam.OperatorTeam{}, mapOperatorTeamDatabaseError(err)
	}
	team, err := mapGotOperatorTeam(row)
	if err != nil {
		return operatorteam.OperatorTeam{}, err
	}
	if team.ID != operatorTeamID {
		return operatorteam.OperatorTeam{}, invalidOperatorTeamProjection("unexpected platform operator-team identifier")
	}
	return team, nil
}

func getTenantOperatorTeamAssignment(
	ctx context.Context,
	queries operatorTeamQueries,
	tenantID, operatorTeamID, epochID uuid.UUID,
) (operatorteam.TenantAssignment, error) {
	row, err := queries.GetTenantOperatorTeamAssignment(
		ctx,
		dbsql.GetTenantOperatorTeamAssignmentParams{
			OperatorTeamID: toDatabaseUUID(operatorTeamID), AssignmentEpochID: toDatabaseUUID(epochID),
		},
	)
	if err != nil {
		return operatorteam.TenantAssignment{}, mapOperatorTeamDatabaseError(err)
	}
	assignment, err := mapGotOperatorTeamAssignment(tenantID, row)
	if err != nil {
		return operatorteam.TenantAssignment{}, err
	}
	if assignment.OperatorTeam.ID != operatorTeamID || assignment.EpochID != epochID {
		return operatorteam.TenantAssignment{}, invalidOperatorTeamProjection("unexpected assignment relationship identifiers")
	}
	return assignment, nil
}

func getTenantOperatorTeamRosterEntry(
	ctx context.Context,
	queries operatorTeamQueries,
	tenantID, operatorTeamID, epochID, rosterEntryID uuid.UUID,
) (operatorteam.RosterEntry, error) {
	row, err := queries.GetTenantOperatorTeamRosterEntry(
		ctx,
		dbsql.GetTenantOperatorTeamRosterEntryParams{
			OperatorTeamID: toDatabaseUUID(operatorTeamID), AssignmentEpochID: toDatabaseUUID(epochID),
			RosterEntryID: toDatabaseUUID(rosterEntryID),
		},
	)
	if err != nil {
		return operatorteam.RosterEntry{}, mapOperatorTeamDatabaseError(err)
	}
	record, err := gotOperatorTeamRosterRecord(row)
	if err != nil {
		return operatorteam.RosterEntry{}, err
	}
	entry, err := mapOperatorTeamRosterEntry(tenantID, operatorTeamID, epochID, record)
	if err != nil {
		return operatorteam.RosterEntry{}, err
	}
	if entry.ID != rosterEntryID {
		return operatorteam.RosterEntry{}, invalidOperatorTeamProjection("unexpected roster entry identifier")
	}
	return entry, nil
}

type operatorTeamAuditArguments struct {
	auditID              pgtype.UUID
	requestID            pgtype.UUID
	correlationID        pgtype.UUID
	remoteAddress        netip.Addr
	userAgent            string
	authenticationMethod string
}

func (r *OperatorTeamRepository) operatorTeamAudit(
	authenticationMethod string,
	audit authorization.AuditContext,
	occurredAt time.Time,
) (operatorTeamAuditArguments, error) {
	if r == nil || r.newID == nil || !validOperatorTeamOccurrence(occurredAt) ||
		!validOperatorTeamAuthenticationMethod(authenticationMethod) || !validOperatorTeamAudit(audit) {
		return operatorTeamAuditArguments{}, operatorteam.ErrInvalidInput
	}
	auditID, err := r.newID()
	if err != nil {
		return operatorTeamAuditArguments{}, err
	}
	if !authorizationUUIDv7(auditID) {
		return operatorTeamAuditArguments{}, invalidOperatorTeamProjection("audit ID generator returned a non-UUIDv7 identifier")
	}
	return operatorTeamAuditArguments{
		auditID: toDatabaseUUID(auditID), requestID: toDatabaseUUID(audit.RequestID),
		correlationID: toDatabaseUUID(audit.CorrelationID), remoteAddress: audit.RemoteAddress,
		userAgent: audit.UserAgent, authenticationMethod: authenticationMethod,
	}, nil
}

func withOperatorTeamPlatformTransaction[T any](
	ctx context.Context,
	repository *OperatorTeamRepository,
	actor operatorteam.PlatformActor,
	isolation pgx.TxIsoLevel,
	work func(operatorTeamQueries) (T, error),
) (T, error) {
	var zero T
	if !validOperatorTeamPlatformActor(actor) {
		return zero, operatorteam.ErrForbidden
	}
	if repository == nil || repository.begin == nil || repository.queryFactory == nil || work == nil {
		return zero, fmt.Errorf("%w: operator-team repository dependencies are required", operatorteam.ErrUnavailable)
	}
	result, err := withinTransactionWithOptions(
		ctx, repository.begin, pgx.TxOptions{IsoLevel: isolation},
		func(tx databaseTransaction) (T, error) {
			queries := repository.queryFactory(tx)
			if queries == nil {
				return zero, fmt.Errorf("%w: operator-team query surface is required", operatorteam.ErrUnavailable)
			}
			installed, installErr := queries.SetUserContext(
				ctx, dbsql.SetUserContextParams{UserID: toDatabaseUUID(actor.UserID)},
			)
			if installErr != nil {
				return zero, mapOperatorTeamDatabaseError(installErr)
			}
			if installed != actor.UserID.String() {
				return zero, invalidOperatorTeamProjection("database installed an unexpected platform actor")
			}
			return work(queries)
		},
	)
	if err != nil {
		return zero, mapOperatorTeamDatabaseError(err)
	}
	return result, nil
}

func withOperatorTeamTenantTransaction[T any](
	ctx context.Context,
	repository *OperatorTeamRepository,
	actor authorization.Actor,
	tenantID uuid.UUID,
	isolation pgx.TxIsoLevel,
	work func(operatorTeamQueries) (T, error),
) (T, error) {
	var zero T
	if !authorizationUUIDv7(tenantID) {
		return zero, operatorteam.ErrInvalidInput
	}
	if !validOperatorTeamTenantActor(actor, tenantID) {
		return zero, operatorteam.ErrForbidden
	}
	if repository == nil || repository.begin == nil || repository.queryFactory == nil || work == nil {
		return zero, fmt.Errorf("%w: operator-team repository dependencies are required", operatorteam.ErrUnavailable)
	}
	result, err := withinTransactionWithOptions(
		ctx, repository.begin, pgx.TxOptions{IsoLevel: isolation},
		func(tx databaseTransaction) (T, error) {
			queries := repository.queryFactory(tx)
			if queries == nil {
				return zero, fmt.Errorf("%w: operator-team query surface is required", operatorteam.ErrUnavailable)
			}
			installed, installErr := queries.SetTenantContext(ctx, dbsql.SetTenantContextParams{
				TenantID: toDatabaseUUID(tenantID), UserID: toDatabaseUUID(actor.UserID),
			})
			if installErr != nil {
				return zero, mapOperatorTeamDatabaseError(installErr)
			}
			if installed == nil || installed.TenantID != tenantID.String() || installed.UserID != actor.UserID.String() {
				return zero, invalidOperatorTeamProjection("database installed an unexpected tenant actor context")
			}
			return work(queries)
		},
	)
	if err != nil {
		return zero, mapOperatorTeamDatabaseError(err)
	}
	return result, nil
}

func validOperatorTeamPlatformActor(actor operatorteam.PlatformActor) bool {
	return authorizationUUIDv7(actor.UserID) && authorizationUUIDv7(actor.SessionID) &&
		validOperatorTeamAuthenticationMethod(actor.AuthenticationMethod)
}

func validOperatorTeamTenantActor(actor authorization.Actor, tenantID uuid.UUID) bool {
	return authorizationUUIDv7(tenantID) && authorizationUUIDv7(actor.UserID) &&
		authorizationUUIDv7(actor.SessionID) && actor.ActiveTenantID == tenantID &&
		validOperatorTeamAuthenticationMethod(actor.AuthenticationMethod)
}

func validOperatorTeamAuthenticationMethod(value string) bool {
	return validOperatorTeamText(value, 1, maximumOperatorTeamAuthenticationBytes, true)
}

func validOperatorTeamAudit(audit authorization.AuditContext) bool {
	if audit.RequestID != uuid.Nil && audit.RequestID.Variant() != uuid.RFC4122 ||
		audit.CorrelationID != uuid.Nil && audit.CorrelationID.Variant() != uuid.RFC4122 ||
		audit.RemoteAddress.IsValid() && audit.RemoteAddress.Zone() != "" {
		return false
	}
	return validOperatorTeamText(audit.UserAgent, 0, maximumOperatorTeamAuditUserAgentRunes, false)
}

func validOperatorTeamOccurrence(value time.Time) bool {
	if value.IsZero() || value.Nanosecond()%int(time.Microsecond) != 0 {
		return false
	}
	_, err := value.UTC().MarshalJSON()
	return err == nil
}

func operatorTeamPageError(after *uuid.UUID, limit int32) error {
	if limit < 1 || limit > operatorTeamPageLimit || after != nil && !authorizationUUIDv7(*after) {
		return operatorteam.ErrInvalidInput
	}
	return nil
}

func validCreateOperatorTeamParams(params operatorteam.CreateOperatorTeamParams) bool {
	return validOperatorTeamPlatformActor(params.Actor) && authorizationUUIDv7(params.OperatorTeamID) &&
		validOperatorTeamKey(params.Key) && validOperatorTeamText(params.Name, 1, 120, true) &&
		validOperatorTeamText(params.Description, 0, 500, false) &&
		validOperatorTeamIdempotencyKey(params.IdempotencyKey) && validOperatorTeamAudit(params.Audit) &&
		validOperatorTeamOccurrence(params.OccurredAt)
}

func validPatchOperatorTeamParams(params operatorteam.PatchOperatorTeamParams) bool {
	if !validOperatorTeamPlatformActor(params.Actor) || !authorizationUUIDv7(params.OperatorTeamID) ||
		params.Name == nil && params.Description == nil || !validOperatorTeamAudit(params.Audit) ||
		!validOperatorTeamOccurrence(params.OccurredAt) {
		return false
	}
	return (params.Name == nil || validOperatorTeamText(*params.Name, 1, 120, true)) &&
		(params.Description == nil || validOperatorTeamText(*params.Description, 0, 500, false))
}

func validArchiveOperatorTeamParams(params operatorteam.ArchiveOperatorTeamParams) bool {
	return validOperatorTeamPlatformActor(params.Actor) && authorizationUUIDv7(params.OperatorTeamID) &&
		validOperatorTeamText(params.Reason, 1, 500, true) && validOperatorTeamAudit(params.Audit) &&
		validOperatorTeamOccurrence(params.OccurredAt)
}

func validStartOperatorTeamAssignmentParams(params operatorteam.StartTenantAssignmentParams) bool {
	return validOperatorTeamTenantActor(params.Actor, params.TenantID) &&
		authorizationUUIDv7(params.OperatorTeamID) && authorizationUUIDv7(params.EpochID) &&
		validOperatorTeamText(params.Reason, 1, 500, true) &&
		validOperatorTeamIdempotencyKey(params.IdempotencyKey) && validOperatorTeamAudit(params.Audit) &&
		validOperatorTeamOccurrence(params.OccurredAt)
}

func validEndOperatorTeamAssignmentParams(params operatorteam.EndTenantAssignmentParams) bool {
	return validOperatorTeamTenantActor(params.Actor, params.TenantID) &&
		authorizationUUIDv7(params.OperatorTeamID) && authorizationUUIDv7(params.EpochID) &&
		validOperatorTeamText(params.Reason, 1, 500, true) && validOperatorTeamAudit(params.Audit) &&
		validOperatorTeamOccurrence(params.OccurredAt)
}

func validAddOperatorTeamRosterEntryParams(params operatorteam.AddRosterEntryParams) bool {
	if !validOperatorTeamTenantActor(params.Actor, params.TenantID) ||
		!authorizationUUIDv7(params.OperatorTeamID) || !authorizationUUIDv7(params.AssignmentEpochID) ||
		!authorizationUUIDv7(params.RosterEntryID) || !authorizationUUIDv7(params.MembershipID) ||
		!validOperatorTeamText(params.Reason, 1, 500, true) ||
		!validOperatorTeamIdempotencyKey(params.IdempotencyKey) || !validOperatorTeamAudit(params.Audit) ||
		!validOperatorTeamOccurrence(params.OccurredAt) {
		return false
	}
	if params.ExpiresAt == nil {
		return true
	}
	return !params.ExpiresAt.IsZero() && params.ExpiresAt.Nanosecond()%int(time.Microsecond) == 0
}

func validRevokeOperatorTeamRosterEntryParams(params operatorteam.RevokeRosterEntryParams) bool {
	return validOperatorTeamTenantActor(params.Actor, params.TenantID) &&
		authorizationUUIDv7(params.OperatorTeamID) && authorizationUUIDv7(params.AssignmentEpochID) &&
		authorizationUUIDv7(params.RosterEntryID) && params.ExpectedEntityTag != "" &&
		validOperatorTeamText(params.Reason, 1, 500, true) && validOperatorTeamAudit(params.Audit) &&
		validOperatorTeamOccurrence(params.OccurredAt)
}

func validOperatorTeamIdempotencyKey(value string) bool {
	if len(value) < 16 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || strings.ContainsRune("._~-", character) {
			continue
		}
		return false
	}
	return true
}

func operatorTeamDatabaseVersion(version int64) (int32, error) {
	if version < 1 || version > math.MaxInt32 {
		return 0, operatorteam.ErrInvalidInput
	}
	return int32(version), nil
}

func sameOperatorTeamTime(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Equal(*right)
}

func mapOperatorTeamDatabaseError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, operatorteam.ErrInvalidInput) || errors.Is(err, operatorteam.ErrForbidden) ||
		errors.Is(err, operatorteam.ErrNotFound) || errors.Is(err, operatorteam.ErrConflict) ||
		errors.Is(err, operatorteam.ErrPreconditionRequired) ||
		errors.Is(err, operatorteam.ErrPreconditionFailed) || errors.Is(err, operatorteam.ErrUnavailable) {
		return err
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return operatorteam.ErrNotFound
	}
	switch postgresCode(err) {
	case "22023", "22P02":
		return operatorteam.ErrInvalidInput
	case "42501":
		return operatorteam.ErrForbidden
	case "P0002":
		return operatorteam.ErrNotFound
	case "40001":
		if isOperatorTeamVersionConflict(err) {
			return operatorteam.ErrPreconditionFailed
		}
		return operatorteam.ErrUnavailable
	case "23503", "23505", "23514", "55000":
		return operatorteam.ErrConflict
	default:
		return err
	}
}

func isOperatorTeamVersionConflict(err error) bool {
	var databaseError *pgconn.PgError
	if !errors.As(err, &databaseError) || databaseError.Code != "40001" {
		return false
	}
	switch databaseError.Message {
	case operatorTeamVersionConflictMessage,
		operatorTeamAssignmentConflictMessage,
		operatorTeamRosterEntryConflictMessage:
		return true
	default:
		return false
	}
}
