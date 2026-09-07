package postgres

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/operatorteam"
	"github.com/periapsis-im/periapsis/services/api/internal/postgres/dbsql"
)

type operatorTeamQueriesStub struct {
	operatorTeamQueries
	tenantID uuid.UUID
	actorID  uuid.UUID

	createResult *dbsql.CreatePlatformOperatorTeamRow
	teamRow      *dbsql.GetPlatformOperatorTeamRow
	createParams dbsql.CreatePlatformOperatorTeamParams

	startResult *dbsql.StartTenantOperatorTeamAssignmentRow
	assignment  *dbsql.GetTenantOperatorTeamAssignmentRow
	startParams dbsql.StartTenantOperatorTeamAssignmentParams

	rosterRow    *dbsql.GetTenantOperatorTeamRosterEntryRow
	addResult    *dbsql.AddTenantOperatorTeamRosterEntryRow
	addParams    dbsql.AddTenantOperatorTeamRosterEntryParams
	addCalls     int
	revokeParams dbsql.RevokeTenantOperatorTeamRosterEntryParams
	revokeCalls  int
}

type operatorTeamAuthorityQueriesStub struct {
	authorizationQueries
	tenantID         uuid.UUID
	actorID          uuid.UUID
	membershipID     uuid.UUID
	evaluatedAt      time.Time
	operatorTeamRows []*dbsql.ResolveCurrentTenantOperatorTeamsRow
	operatorTeamPage int32
}

func (s *operatorTeamAuthorityQueriesStub) SetTenantContext(
	_ context.Context,
	params dbsql.SetTenantContextParams,
) (*dbsql.SetTenantContextRow, error) {
	s.tenantID = uuid.UUID(params.TenantID.Bytes)
	s.actorID = uuid.UUID(params.UserID.Bytes)
	return &dbsql.SetTenantContextRow{TenantID: s.tenantID.String(), UserID: s.actorID.String()}, nil
}

func (s *operatorTeamAuthorityQueriesStub) GetCurrentTenantAuthorizationContext(
	context.Context,
) (*dbsql.GetCurrentTenantAuthorizationContextRow, error) {
	return &dbsql.GetCurrentTenantAuthorizationContextRow{
		TenantID: toDatabaseUUID(s.tenantID), MembershipID: toDatabaseUUID(s.membershipID),
		AuthorizationRevision: 1, MembershipStatus: string(authorization.MembershipStatusActive),
		CompatibilityRole: string(authorization.LegacyMembershipRoleAnalyst),
		EvaluatedAt:       databaseTime(s.evaluatedAt),
	}, nil
}

func (*operatorTeamAuthorityQueriesStub) ResolveCurrentTenantHumanAuthority(
	context.Context,
	dbsql.ResolveCurrentTenantHumanAuthorityParams,
) ([]*dbsql.ResolveCurrentTenantHumanAuthorityRow, error) {
	return []*dbsql.ResolveCurrentTenantHumanAuthorityRow{}, nil
}

func (s *operatorTeamAuthorityQueriesStub) ResolveCurrentTenantOperatorTeams(
	_ context.Context,
	params dbsql.ResolveCurrentTenantOperatorTeamsParams,
) ([]*dbsql.ResolveCurrentTenantOperatorTeamsRow, error) {
	s.operatorTeamPage = params.PageSize
	return s.operatorTeamRows, nil
}

func (*operatorTeamAuthorityQueriesStub) ResolveCurrentTenantHumanRoleGrantPaths(
	context.Context,
	dbsql.ResolveCurrentTenantHumanRoleGrantPathsParams,
) ([]*dbsql.ResolveCurrentTenantHumanRoleGrantPathsRow, error) {
	return []*dbsql.ResolveCurrentTenantHumanRoleGrantPathsRow{}, nil
}

func TestAuthorizationRepositoryHydratesLiveOperatorTeamsInSameSnapshot(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV7())
	actor := authorizationRepositoryTestActor(t, tenantID)
	teamIDs := []uuid.UUID{uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())}
	epochIDs := []uuid.UUID{uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())}
	now := time.Now().UTC().Truncate(time.Microsecond)
	queries := &operatorTeamAuthorityQueriesStub{
		membershipID: uuid.Must(uuid.NewV7()), evaluatedAt: now,
		operatorTeamRows: []*dbsql.ResolveCurrentTenantOperatorTeamsRow{
			{OperatorTeamID: toDatabaseUUID(teamIDs[0]), AssignmentEpochID: toDatabaseUUID(epochIDs[0])},
			{OperatorTeamID: toDatabaseUUID(teamIDs[1]), AssignmentEpochID: toDatabaseUUID(epochIDs[1])},
		},
	}
	tx := &recordingTransaction{}
	var options pgx.TxOptions
	repository := &AuthorizationRepository{
		begin: func(_ context.Context, value pgx.TxOptions) (databaseTransaction, error) {
			options = value
			return tx, nil
		},
		queryFactory: func(databaseTransaction) authorizationQueries { return queries },
	}
	authority, err := repository.ResolveAuthority(context.Background(), authorization.ResolveAuthorityParams{
		Actor: actor, TenantID: tenantID,
	})
	if err != nil {
		t.Fatalf("ResolveAuthority() error = %v", err)
	}
	if options.IsoLevel != pgx.RepeatableRead || len(authority.OperatorTeamRelationships) != 2 ||
		authority.OperatorTeamRelationships[0] != (authorization.OperatorTeamRelationship{
			OperatorTeamID: teamIDs[0], AssignmentEpochID: epochIDs[0],
		}) || authority.OperatorTeamRelationships[1] != (authorization.OperatorTeamRelationship{
		OperatorTeamID: teamIDs[1], AssignmentEpochID: epochIDs[1],
	}) ||
		queries.operatorTeamPage != operatorTeamHydrationLimit || queries.tenantID != tenantID ||
		queries.actorID != actor.UserID || !tx.committed {
		t.Fatalf("authority=%+v options=%+v tenant=%s actor=%s committed=%t", authority, options, queries.tenantID, queries.actorID, tx.committed)
	}
}

func TestAuthorizationRepositoryRejectsDuplicateOrMalformedOperatorTeamRelationship(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV7())
	actor := authorizationRepositoryTestActor(t, tenantID)
	teamID := uuid.Must(uuid.NewV7())
	otherTeamID := uuid.Must(uuid.NewV7())
	assignmentEpochID := uuid.Must(uuid.NewV7())
	now := time.Now().UTC().Truncate(time.Microsecond)
	tests := []struct {
		name string
		rows []*dbsql.ResolveCurrentTenantOperatorTeamsRow
	}{
		{
			name: "duplicate team",
			rows: []*dbsql.ResolveCurrentTenantOperatorTeamsRow{
				{OperatorTeamID: toDatabaseUUID(teamID), AssignmentEpochID: toDatabaseUUID(uuid.Must(uuid.NewV7()))},
				{OperatorTeamID: toDatabaseUUID(teamID), AssignmentEpochID: toDatabaseUUID(uuid.Must(uuid.NewV7()))},
			},
		},
		{
			name: "duplicate assignment epoch",
			rows: []*dbsql.ResolveCurrentTenantOperatorTeamsRow{
				{OperatorTeamID: toDatabaseUUID(teamID), AssignmentEpochID: toDatabaseUUID(assignmentEpochID)},
				{OperatorTeamID: toDatabaseUUID(otherTeamID), AssignmentEpochID: toDatabaseUUID(assignmentEpochID)},
			},
		},
		{
			name: "non UUIDv7 epoch",
			rows: []*dbsql.ResolveCurrentTenantOperatorTeamsRow{
				{OperatorTeamID: toDatabaseUUID(teamID), AssignmentEpochID: toDatabaseUUID(uuid.New())},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			queries := &operatorTeamAuthorityQueriesStub{
				membershipID: uuid.Must(uuid.NewV7()), evaluatedAt: now, operatorTeamRows: test.rows,
			}
			tx := &recordingTransaction{}
			repository := &AuthorizationRepository{
				begin:        func(context.Context, pgx.TxOptions) (databaseTransaction, error) { return tx, nil },
				queryFactory: func(databaseTransaction) authorizationQueries { return queries },
			}
			_, err := repository.ResolveAuthority(context.Background(), authorization.ResolveAuthorityParams{
				Actor: actor, TenantID: tenantID,
			})
			if err == nil || tx.committed || !tx.rolledBack {
				t.Fatalf("ResolveAuthority() error=%v committed=%t rolledBack=%t", err, tx.committed, tx.rolledBack)
			}
		})
	}
}

func (s *operatorTeamQueriesStub) SetUserContext(
	_ context.Context,
	params dbsql.SetUserContextParams,
) (string, error) {
	s.actorID = uuid.UUID(params.UserID.Bytes)
	return s.actorID.String(), nil
}

func (s *operatorTeamQueriesStub) SetTenantContext(
	_ context.Context,
	params dbsql.SetTenantContextParams,
) (*dbsql.SetTenantContextRow, error) {
	s.tenantID = uuid.UUID(params.TenantID.Bytes)
	s.actorID = uuid.UUID(params.UserID.Bytes)
	return &dbsql.SetTenantContextRow{TenantID: s.tenantID.String(), UserID: s.actorID.String()}, nil
}

func (s *operatorTeamQueriesStub) CreatePlatformOperatorTeam(
	_ context.Context,
	params dbsql.CreatePlatformOperatorTeamParams,
) (*dbsql.CreatePlatformOperatorTeamRow, error) {
	s.createParams = params
	return s.createResult, nil
}

func (s *operatorTeamQueriesStub) GetPlatformOperatorTeam(
	context.Context,
	dbsql.GetPlatformOperatorTeamParams,
) (*dbsql.GetPlatformOperatorTeamRow, error) {
	return s.teamRow, nil
}

func (s *operatorTeamQueriesStub) StartTenantOperatorTeamAssignment(
	_ context.Context,
	params dbsql.StartTenantOperatorTeamAssignmentParams,
) (*dbsql.StartTenantOperatorTeamAssignmentRow, error) {
	s.startParams = params
	return s.startResult, nil
}

func (s *operatorTeamQueriesStub) GetTenantOperatorTeamAssignment(
	context.Context,
	dbsql.GetTenantOperatorTeamAssignmentParams,
) (*dbsql.GetTenantOperatorTeamAssignmentRow, error) {
	return s.assignment, nil
}

func (s *operatorTeamQueriesStub) GetTenantOperatorTeamRosterEntry(
	context.Context,
	dbsql.GetTenantOperatorTeamRosterEntryParams,
) (*dbsql.GetTenantOperatorTeamRosterEntryRow, error) {
	return s.rosterRow, nil
}

func (s *operatorTeamQueriesStub) AddTenantOperatorTeamRosterEntry(
	_ context.Context,
	params dbsql.AddTenantOperatorTeamRosterEntryParams,
) (*dbsql.AddTenantOperatorTeamRosterEntryRow, error) {
	s.addCalls++
	s.addParams = params
	return s.addResult, nil
}

func (s *operatorTeamQueriesStub) RevokeTenantOperatorTeamRosterEntry(
	_ context.Context,
	params dbsql.RevokeTenantOperatorTeamRosterEntryParams,
) (int32, error) {
	s.revokeCalls++
	s.revokeParams = params
	return params.ExpectedVersion + 1, nil
}

func TestOperatorTeamCreateReplayUsesPlatformContextAndCurrentRepresentation(t *testing.T) {
	actor := operatorteam.PlatformActor{
		UserID: uuid.Must(uuid.NewV7()), SessionID: uuid.Must(uuid.NewV7()),
		AuthenticationMethod: "totp",
	}
	requestedID := uuid.Must(uuid.NewV7())
	resultID := uuid.Must(uuid.NewV7())
	now := time.Now().UTC().Truncate(time.Microsecond)
	queries := &operatorTeamQueriesStub{
		createResult: &dbsql.CreatePlatformOperatorTeamRow{
			ResultResourceID: toDatabaseUUID(resultID), ResultVersion: 1, Replayed: true,
		},
		teamRow: validOperatorTeamTestRow(resultID, actor.UserID, now, 2),
	}
	tx := &recordingTransaction{}
	repository := &OperatorTeamRepository{
		begin:        func(context.Context, pgx.TxOptions) (databaseTransaction, error) { return tx, nil },
		queryFactory: func(databaseTransaction) operatorTeamQueries { return queries },
		newID:        uuid.NewV7,
	}
	audit := operatorTeamTestAudit()
	key := "operator-team-create-key"
	result, err := repository.CreateOperatorTeam(context.Background(), operatorteam.CreateOperatorTeamParams{
		Actor: actor, Audit: audit, OccurredAt: now, OperatorTeamID: requestedID,
		Key: "incident_ops", Name: "Incident operations", Description: "Current description",
		IdempotencyKey: key,
	})
	if err != nil {
		t.Fatalf("CreateOperatorTeam() error = %v", err)
	}
	if !result.Replayed || result.Value.ID != resultID || result.Value.Version != 2 || !tx.committed {
		t.Fatalf("CreateOperatorTeam() result = %+v, committed=%t", result, tx.committed)
	}
	if queries.tenantID != uuid.Nil || queries.actorID != actor.UserID {
		t.Fatalf("installed platform context tenant=%s actor=%s", queries.tenantID, queries.actorID)
	}
	wantDigest := sha256.Sum256([]byte(key))
	if !equalBytes(queries.createParams.IdempotencyKeyDigest, wantDigest[:]) ||
		uuid.UUID(queries.createParams.OperatorTeamID.Bytes) != requestedID ||
		uuid.UUID(queries.createParams.RequestID.Bytes) != audit.RequestID {
		t.Fatalf("create params = %+v", queries.createParams)
	}
}

func TestOperatorTeamAssignmentReplayUsesTwoAuditIDsAndNeverReopensEpoch(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV7())
	actor := authorizationRepositoryTestActor(t, tenantID)
	teamID := uuid.Must(uuid.NewV7())
	requestedEpochID := uuid.Must(uuid.NewV7())
	resultEpochID := uuid.Must(uuid.NewV7())
	assignerMembershipID := uuid.Must(uuid.NewV7())
	enderMembershipID := uuid.Must(uuid.NewV7())
	enderUserID := uuid.Must(uuid.NewV7())
	now := time.Now().UTC().Truncate(time.Microsecond)
	queries := &operatorTeamQueriesStub{
		startResult: &dbsql.StartTenantOperatorTeamAssignmentRow{
			ResultResourceID: toDatabaseUUID(resultEpochID), ResultVersion: 1, Replayed: true,
		},
		assignment: &dbsql.GetTenantOperatorTeamAssignmentRow{
			AssignmentEpochID: toDatabaseUUID(resultEpochID), OperatorTeamID: toDatabaseUUID(teamID),
			TeamKey: "incident_ops", TeamDisplayName: "Incident operations",
			AssignedByMembershipID: toDatabaseUUID(assignerMembershipID),
			AssignedByUserID:       toDatabaseUUID(actor.UserID), AssignmentReason: "On-call coverage",
			AssignedAt: databaseTime(now.Add(-2 * time.Hour)), EndedAt: databaseTime(now.Add(-time.Hour)),
			EndedByMembershipID: toDatabaseUUID(enderMembershipID), EndedByUserID: toDatabaseUUID(enderUserID),
			EndReason: "Coverage ended", Version: 2, UpdatedAt: databaseTime(now.Add(-time.Hour)),
		},
	}
	auditIDs := []uuid.UUID{uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())}
	generated := 0
	tx := &recordingTransaction{}
	repository := &OperatorTeamRepository{
		begin:        func(context.Context, pgx.TxOptions) (databaseTransaction, error) { return tx, nil },
		queryFactory: func(databaseTransaction) operatorTeamQueries { return queries },
		newID: func() (uuid.UUID, error) {
			id := auditIDs[generated]
			generated++
			return id, nil
		},
	}
	key := "assignment-replay-key"
	result, err := repository.StartTenantAssignment(context.Background(), operatorteam.StartTenantAssignmentParams{
		Actor: actor, Audit: operatorTeamTestAudit(), OccurredAt: now, TenantID: tenantID,
		OperatorTeamID: teamID, EpochID: requestedEpochID, Reason: "On-call coverage",
		IdempotencyKey: key,
	})
	if err != nil {
		t.Fatalf("StartTenantAssignment() error = %v", err)
	}
	if !result.Replayed || result.Value.EpochID != resultEpochID ||
		result.Value.State != operatorteam.AssignmentStateEnded || result.Value.Version != 2 {
		t.Fatalf("StartTenantAssignment() result = %+v", result)
	}
	if generated != 2 || queries.startParams.TenantAuditID == queries.startParams.PlatformAuditID ||
		uuid.UUID(queries.startParams.TenantAuditID.Bytes) != auditIDs[0] ||
		uuid.UUID(queries.startParams.PlatformAuditID.Bytes) != auditIDs[1] {
		t.Fatalf("audit IDs = tenant %v platform %v, generated=%d", queries.startParams.TenantAuditID, queries.startParams.PlatformAuditID, generated)
	}
	wantDigest := sha256.Sum256([]byte(key))
	if !equalBytes(queries.startParams.IdempotencyKeyDigest, wantDigest[:]) ||
		uuid.UUID(queries.startParams.AssignmentEpochID.Bytes) != requestedEpochID ||
		queries.tenantID != tenantID || queries.actorID != actor.UserID || !tx.committed {
		t.Fatalf("start params/context = %+v tenant=%s actor=%s committed=%t", queries.startParams, queries.tenantID, queries.actorID, tx.committed)
	}
}

func TestOperatorTeamAssignmentRejectsDuplicateCrossLedgerAuditIDsBeforeTransaction(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV7())
	actor := authorizationRepositoryTestActor(t, tenantID)
	now := time.Now().UTC().Truncate(time.Microsecond)
	auditID := uuid.Must(uuid.NewV7())
	beginCalled := false
	repository := &OperatorTeamRepository{
		begin: func(context.Context, pgx.TxOptions) (databaseTransaction, error) {
			beginCalled = true
			return &recordingTransaction{}, nil
		},
		queryFactory: func(databaseTransaction) operatorTeamQueries { return &operatorTeamQueriesStub{} },
		newID:        func() (uuid.UUID, error) { return auditID, nil },
	}
	_, err := repository.StartTenantAssignment(context.Background(), operatorteam.StartTenantAssignmentParams{
		Actor: actor, Audit: operatorTeamTestAudit(), OccurredAt: now, TenantID: tenantID,
		OperatorTeamID: uuid.Must(uuid.NewV7()), EpochID: uuid.Must(uuid.NewV7()),
		Reason: "On-call coverage", IdempotencyKey: "assignment-audit-key",
	})
	if !errors.Is(err, operatorteam.ErrUnavailable) || beginCalled {
		t.Fatalf("StartTenantAssignment() error=%v beginCalled=%t", err, beginCalled)
	}
}

func TestOperatorTeamRosterRevokeUsesStrongProjectionAndSerializableTransaction(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV7())
	actor := authorizationRepositoryTestActor(t, tenantID)
	teamID := uuid.Must(uuid.NewV7())
	epochID := uuid.Must(uuid.NewV7())
	rosterID := uuid.Must(uuid.NewV7())
	now := time.Now().UTC().Truncate(time.Microsecond)
	row := validOperatorTeamRosterTestRow(teamID, epochID, rosterID, actor.UserID, now)
	row.Email = ""
	record, err := gotOperatorTeamRosterRecord(row)
	if err != nil {
		t.Fatalf("gotOperatorTeamRosterRecord() error = %v", err)
	}
	entry, err := mapOperatorTeamRosterEntry(tenantID, teamID, epochID, record)
	if err != nil {
		t.Fatalf("mapOperatorTeamRosterEntry() error = %v", err)
	}
	etag, err := operatorteam.RosterEntryEntityTag(entry)
	if err != nil {
		t.Fatalf("RosterEntryEntityTag() error = %v", err)
	}
	queries := &operatorTeamQueriesStub{rosterRow: row}
	tx := &recordingTransaction{}
	var options pgx.TxOptions
	repository := &OperatorTeamRepository{
		begin: func(_ context.Context, value pgx.TxOptions) (databaseTransaction, error) {
			options = value
			return tx, nil
		},
		queryFactory: func(databaseTransaction) operatorTeamQueries { return queries },
		newID:        uuid.NewV7,
	}
	err = repository.RevokeRosterEntry(context.Background(), operatorteam.RevokeRosterEntryParams{
		Actor: actor, Audit: operatorTeamTestAudit(), OccurredAt: now, TenantID: tenantID,
		OperatorTeamID: teamID, AssignmentEpochID: epochID, RosterEntryID: rosterID,
		Reason: "Rotation completed", ExpectedEntityTag: etag,
	})
	if err != nil {
		t.Fatalf("RevokeRosterEntry() error = %v", err)
	}
	if options.IsoLevel != pgx.Serializable || queries.revokeCalls != 1 ||
		queries.revokeParams.ExpectedVersion != row.Version || !tx.committed {
		t.Fatalf("revoke options=%+v calls=%d params=%+v committed=%t", options, queries.revokeCalls, queries.revokeParams, tx.committed)
	}
}

func TestOperatorTeamRosterRevokeRejectsSameVersionDifferentProjection(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV7())
	actor := authorizationRepositoryTestActor(t, tenantID)
	teamID := uuid.Must(uuid.NewV7())
	epochID := uuid.Must(uuid.NewV7())
	rosterID := uuid.Must(uuid.NewV7())
	now := time.Now().UTC().Truncate(time.Microsecond)
	row := validOperatorTeamRosterTestRow(teamID, epochID, rosterID, actor.UserID, now)
	record, _ := gotOperatorTeamRosterRecord(row)
	entry, _ := mapOperatorTeamRosterEntry(tenantID, teamID, epochID, record)
	entry.Member.DisplayName = "Different current projection"
	staleTag, err := operatorteam.RosterEntryEntityTag(entry)
	if err != nil {
		t.Fatalf("RosterEntryEntityTag() error = %v", err)
	}
	queries := &operatorTeamQueriesStub{rosterRow: row}
	tx := &recordingTransaction{}
	repository := &OperatorTeamRepository{
		begin:        func(context.Context, pgx.TxOptions) (databaseTransaction, error) { return tx, nil },
		queryFactory: func(databaseTransaction) operatorTeamQueries { return queries },
		newID:        uuid.NewV7,
	}
	err = repository.RevokeRosterEntry(context.Background(), operatorteam.RevokeRosterEntryParams{
		Actor: actor, Audit: operatorTeamTestAudit(), OccurredAt: now, TenantID: tenantID,
		OperatorTeamID: teamID, AssignmentEpochID: epochID, RosterEntryID: rosterID,
		Reason: "Rotation completed", ExpectedEntityTag: staleTag,
	})
	if !errors.Is(err, operatorteam.ErrPreconditionFailed) || queries.revokeCalls != 0 || tx.committed || !tx.rolledBack {
		t.Fatalf("RevokeRosterEntry() error=%v calls=%d committed=%t rolledBack=%t", err, queries.revokeCalls, tx.committed, tx.rolledBack)
	}
}

func TestOperatorTeamRosterMappingAcceptsGenericDependencyExpiry(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	for _, test := range []struct {
		name   string
		mutate func(*dbsql.GetTenantOperatorTeamRosterEntryRow)
	}{
		{
			name: "assignment ended",
			mutate: func(row *dbsql.GetTenantOperatorTeamRosterEntryRow) {
				row.AssignmentEndedAt = databaseTime(now.Add(-time.Minute))
			},
		},
		{
			name: "membership suspended",
			mutate: func(row *dbsql.GetTenantOperatorTeamRosterEntryRow) {
				row.MembershipStatus = string(authorization.MembershipStatusSuspended)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			tenantID := uuid.Must(uuid.NewV7())
			teamID := uuid.Must(uuid.NewV7())
			epochID := uuid.Must(uuid.NewV7())
			row := validOperatorTeamRosterTestRow(
				teamID, epochID, uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), now,
			)
			row.RosterState = "expired"
			test.mutate(row)

			record, err := gotOperatorTeamRosterRecord(row)
			if err != nil {
				t.Fatalf("gotOperatorTeamRosterRecord() error = %v", err)
			}
			entry, err := mapOperatorTeamRosterEntry(tenantID, teamID, epochID, record)
			if err != nil || entry.State != operatorteam.RosterEntryStateExpired ||
				entry.Provenance.ExpiresAt != nil || entry.Provenance.RetiredAt != nil {
				t.Fatalf("mapOperatorTeamRosterEntry() = %#v, %v", entry, err)
			}

			row.RosterState = "active"
			record, err = gotOperatorTeamRosterRecord(row)
			if err != nil {
				t.Fatalf("gotOperatorTeamRosterRecord(active) error = %v", err)
			}
			if _, err = mapOperatorTeamRosterEntry(tenantID, teamID, epochID, record); !errors.Is(err, operatorteam.ErrUnavailable) {
				t.Fatalf("mapOperatorTeamRosterEntry(active dependency) error = %v, want unavailable", err)
			}
		})
	}
}

func TestOperatorTeamRosterCreateReplayReturnsCurrentExpiredRepresentation(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV7())
	actor := authorizationRepositoryTestActor(t, tenantID)
	teamID := uuid.Must(uuid.NewV7())
	epochID := uuid.Must(uuid.NewV7())
	requestedRosterID := uuid.Must(uuid.NewV7())
	existingRosterID := uuid.Must(uuid.NewV7())
	now := time.Now().UTC().Truncate(time.Microsecond)
	row := validOperatorTeamRosterTestRow(teamID, epochID, existingRosterID, actor.UserID, now)
	row.MembershipStatus = string(authorization.MembershipStatusSuspended)
	row.RosterState = "expired"
	queries := &operatorTeamQueriesStub{
		addResult: &dbsql.AddTenantOperatorTeamRosterEntryRow{
			ResultResourceID: toDatabaseUUID(existingRosterID), ResultVersion: row.Version, Replayed: true,
		},
		rosterRow: row,
	}
	tx := &recordingTransaction{}
	repository := &OperatorTeamRepository{
		begin:        func(context.Context, pgx.TxOptions) (databaseTransaction, error) { return tx, nil },
		queryFactory: func(databaseTransaction) operatorTeamQueries { return queries },
		newID:        uuid.NewV7,
	}
	key := "operator-team-roster-replay-key"
	result, err := repository.AddRosterEntry(context.Background(), operatorteam.AddRosterEntryParams{
		Actor: actor, Audit: operatorTeamTestAudit(), OccurredAt: now, TenantID: tenantID,
		OperatorTeamID: teamID, AssignmentEpochID: epochID, RosterEntryID: requestedRosterID,
		MembershipID: uuid.UUID(row.MembershipID.Bytes), Reason: row.GrantReason,
		IdempotencyKey: key,
	})
	if err != nil || !result.Replayed || result.Value.ID != existingRosterID ||
		result.Value.State != operatorteam.RosterEntryStateExpired || queries.addCalls != 1 || !tx.committed {
		t.Fatalf("AddRosterEntry() = %#v, %v; calls=%d committed=%t", result, err, queries.addCalls, tx.committed)
	}
	wantDigest := sha256.Sum256([]byte(key))
	if !equalBytes(queries.addParams.IdempotencyKeyDigest, wantDigest[:]) ||
		uuid.UUID(queries.addParams.RosterEntryID.Bytes) != requestedRosterID {
		t.Fatalf("add params = %#v", queries.addParams)
	}
}

func TestOperatorTeamMappingRejectsCrossRelationshipRosterProjection(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV7())
	teamID := uuid.Must(uuid.NewV7())
	epochID := uuid.Must(uuid.NewV7())
	row := validOperatorTeamRosterTestRow(
		uuid.Must(uuid.NewV7()), epochID, uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()),
		time.Now().UTC().Truncate(time.Microsecond),
	)
	record, err := gotOperatorTeamRosterRecord(row)
	if err != nil {
		t.Fatalf("gotOperatorTeamRosterRecord() error = %v", err)
	}
	_, err = mapOperatorTeamRosterEntry(tenantID, teamID, epochID, record)
	if !errors.Is(err, operatorteam.ErrUnavailable) {
		t.Fatalf("mapOperatorTeamRosterEntry() error = %v, want unavailable", err)
	}
}

func TestOperatorTeamMappingsRejectTamperedLifecycleAndOwnership(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	t.Run("partial archive tuple", func(t *testing.T) {
		row := validOperatorTeamTestRow(uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), now, 1)
		row.ArchivedAt = databaseTime(now)
		if _, err := mapGotOperatorTeam(row); !errors.Is(err, operatorteam.ErrUnavailable) {
			t.Fatalf("mapGotOperatorTeam() error = %v, want unavailable", err)
		}
	})

	t.Run("active assignment on archived team", func(t *testing.T) {
		row := &dbsql.GetTenantOperatorTeamAssignmentRow{
			AssignmentEpochID: toDatabaseUUID(uuid.Must(uuid.NewV7())),
			OperatorTeamID:    toDatabaseUUID(uuid.Must(uuid.NewV7())),
			TeamKey:           "incident_ops", TeamDisplayName: "Incident operations",
			TeamArchivedAt: databaseTime(now), AssignedByMembershipID: toDatabaseUUID(uuid.Must(uuid.NewV7())),
			AssignedByUserID: toDatabaseUUID(uuid.Must(uuid.NewV7())), AssignmentReason: "Coverage",
			AssignedAt: databaseTime(now.Add(-time.Hour)), Version: 1, UpdatedAt: databaseTime(now),
		}
		if _, err := mapGotOperatorTeamAssignment(uuid.Must(uuid.NewV7()), row); !errors.Is(err, operatorteam.ErrUnavailable) {
			t.Fatalf("mapGotOperatorTeamAssignment() error = %v, want unavailable", err)
		}
	})

	t.Run("canonical manual source lost ownership", func(t *testing.T) {
		tenantID := uuid.Must(uuid.NewV7())
		teamID := uuid.Must(uuid.NewV7())
		epochID := uuid.Must(uuid.NewV7())
		row := validOperatorTeamRosterTestRow(
			teamID, epochID, uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), now,
		)
		row.SourceAuthoritative = true
		record, err := gotOperatorTeamRosterRecord(row)
		if err != nil {
			t.Fatalf("gotOperatorTeamRosterRecord() error = %v", err)
		}
		if _, err = mapOperatorTeamRosterEntry(tenantID, teamID, epochID, record); !errors.Is(err, operatorteam.ErrUnavailable) {
			t.Fatalf("mapOperatorTeamRosterEntry() error = %v, want unavailable", err)
		}
	})

	t.Run("sub-microsecond timestamp", func(t *testing.T) {
		row := validOperatorTeamTestRow(uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), now, 1)
		row.UpdatedAt = databaseTime(now.Add(time.Nanosecond))
		if _, err := mapGotOperatorTeam(row); !errors.Is(err, operatorteam.ErrUnavailable) {
			t.Fatalf("mapGotOperatorTeam() error = %v, want unavailable", err)
		}
	})
}

func TestMapOperatorTeamDatabaseError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want error
	}{
		{name: "forbidden", err: &pgconn.PgError{Code: "42501"}, want: operatorteam.ErrForbidden},
		{name: "not found", err: &pgconn.PgError{Code: "P0002"}, want: operatorteam.ErrNotFound},
		{name: "active assignment", err: &pgconn.PgError{Code: "23503"}, want: operatorteam.ErrConflict},
		{name: "stale", err: &pgconn.PgError{Code: "40001", Message: operatorTeamVersionConflictMessage}, want: operatorteam.ErrPreconditionFailed},
		{name: "retry", err: &pgconn.PgError{Code: "40001", Message: "could not serialize access"}, want: operatorteam.ErrUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := mapOperatorTeamDatabaseError(test.err); !errors.Is(got, test.want) {
				t.Fatalf("mapOperatorTeamDatabaseError() = %v, want %v", got, test.want)
			}
		})
	}
}

func validOperatorTeamTestRow(
	teamID, creatorID uuid.UUID,
	now time.Time,
	version int32,
) *dbsql.GetPlatformOperatorTeamRow {
	return &dbsql.GetPlatformOperatorTeamRow{
		OperatorTeamID: toDatabaseUUID(teamID), TeamKey: "incident_ops",
		DisplayName: "Incident operations", Description: "Current description", Version: version,
		CreatedByUserID: toDatabaseUUID(creatorID), ActiveAssignmentCount: 0,
		CreatedAt: databaseTime(now.Add(-time.Hour)), UpdatedAt: databaseTime(now),
	}
}

func validOperatorTeamRosterTestRow(
	teamID, epochID, rosterID, actorID uuid.UUID,
	now time.Time,
) *dbsql.GetTenantOperatorTeamRosterEntryRow {
	return &dbsql.GetTenantOperatorTeamRosterEntryRow{
		RosterEntryID: toDatabaseUUID(rosterID), OperatorTeamID: toDatabaseUUID(teamID),
		TeamKey: "incident_ops", TeamDisplayName: "Incident operations",
		AssignmentEpochID: toDatabaseUUID(epochID), MembershipID: toDatabaseUUID(uuid.Must(uuid.NewV7())),
		TargetUserID: toDatabaseUUID(uuid.Must(uuid.NewV7())), Email: "analyst@example.test",
		DisplayName: "Incident analyst", MembershipStatus: string(authorization.MembershipStatusActive),
		CompatibilityRole: string(authorization.LegacyMembershipRoleAnalyst), UserActive: true,
		SourceID: toDatabaseUUID(uuid.Must(uuid.NewV7())), SourceKind: string(authorization.AuthorizationSourceManual),
		SourceKey: "manual", GrantedByMembershipID: toDatabaseUUID(uuid.Must(uuid.NewV7())),
		GrantedByUserID: toDatabaseUUID(actorID), GrantReason: "On-call coverage",
		GrantedAt: databaseTime(now.Add(-time.Hour)), RosterState: "active", Version: 1,
		UpdatedAt: databaseTime(now),
	}
}

func operatorTeamTestAudit() authorization.AuditContext {
	return authorization.AuditContext{
		RequestID: uuid.New(), CorrelationID: uuid.New(),
		RemoteAddress: netip.MustParseAddr("192.0.2.80"), UserAgent: "operator-team adapter test",
	}
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
