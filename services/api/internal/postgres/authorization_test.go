package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/postgres/dbsql"
)

func TestAuthorizationDatabaseErrorsMapToStableDomainSemantics(t *testing.T) {
	tests := []struct {
		code string
		want error
	}{
		{code: "22023", want: authorization.ErrInvalidInput},
		{code: "22P02", want: authorization.ErrInvalidInput},
		{code: "42501", want: authorization.ErrForbidden},
		{code: "P0002", want: authorization.ErrNotFound},
		{code: "23503", want: authorization.ErrConflict},
		{code: "23505", want: authorization.ErrConflict},
		{code: "23514", want: authorization.ErrConflict},
		{code: "55000", want: authorization.ErrConflict},
	}
	for _, test := range tests {
		t.Run(test.code, func(t *testing.T) {
			actual := mapAuthorizationDatabaseError(&pgconn.PgError{Code: test.code})
			if !errors.Is(actual, test.want) {
				t.Fatalf("mapAuthorizationDatabaseError(%s) = %v, want %v", test.code, actual, test.want)
			}
		})
	}
	if actual := mapAuthorizationDatabaseError(pgx.ErrNoRows); !errors.Is(actual, authorization.ErrNotFound) {
		t.Fatalf("no rows = %v, want not found", actual)
	}
	unknown := errors.New("connection failed")
	if actual := mapAuthorizationDatabaseError(unknown); !errors.Is(actual, unknown) {
		t.Fatalf("unknown error = %v, want original", actual)
	}
}

func TestAuthorizationSerializationErrorsRequireExactControlledMessage(t *testing.T) {
	controlledMessages := []string{
		"tenant membership lifecycle revision conflict",
		"tenant role version conflict",
		"tenant role grant version conflict",
		"tenant security group version conflict",
		"tenant security group membership version conflict",
		"tenant security group role grant version conflict",
	}
	for _, message := range controlledMessages {
		t.Run(message, func(t *testing.T) {
			for _, test := range []struct {
				name string
				err  error
			}{
				{name: "direct", err: &pgconn.PgError{Code: "40001", Message: message}},
				{
					name: "wrapped",
					err: fmt.Errorf(
						"execute authorization mutation: %w",
						&pgconn.PgError{Code: "40001", Message: message},
					),
				},
			} {
				t.Run(test.name, func(t *testing.T) {
					actual := mapAuthorizationDatabaseError(test.err)
					if !errors.Is(actual, authorization.ErrPreconditionFailed) {
						t.Fatalf("mapAuthorizationDatabaseError() = %v, want precondition failed", actual)
					}
				})
			}

			nearMatch := &pgconn.PgError{Code: "40001", Message: message + " "}
			if actual := mapAuthorizationDatabaseError(nearMatch); !errors.Is(actual, authorization.ErrUnavailable) {
				t.Fatalf("near-match serialization error = %v, want unavailable", actual)
			}
		})
	}

	for _, test := range []struct {
		name    string
		message string
	}{
		{name: "missing message"},
		{name: "concurrent update", message: "could not serialize access due to concurrent update"},
		{
			name:    "read write dependency",
			message: "could not serialize access due to read/write dependencies among transactions",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			databaseError := &pgconn.PgError{Code: "40001", Message: test.message}
			wrapped := fmt.Errorf("commit authorization transaction: %w", databaseError)
			actual := mapAuthorizationDatabaseError(wrapped)
			if !errors.Is(actual, authorization.ErrUnavailable) {
				t.Fatalf("mapAuthorizationDatabaseError() = %v, want unavailable", actual)
			}
			if errors.Is(actual, authorization.ErrPreconditionFailed) {
				t.Fatalf("mapAuthorizationDatabaseError() = %v, must not be precondition failed", actual)
			}
		})
	}
}

type authorizationMembershipLifecycleQueriesStub struct {
	authorizationQueries
	setParams    dbsql.SetTenantContextParams
	changeParams dbsql.ChangeTenantMembershipLifecycleParams
	row          *dbsql.ChangeTenantMembershipLifecycleRow
	err          error
}

func (s *authorizationMembershipLifecycleQueriesStub) SetTenantContext(
	_ context.Context,
	params dbsql.SetTenantContextParams,
) (*dbsql.SetTenantContextRow, error) {
	s.setParams = params
	return &dbsql.SetTenantContextRow{
		TenantID: uuid.UUID(params.TenantID.Bytes).String(),
		UserID:   uuid.UUID(params.UserID.Bytes).String(),
	}, nil
}

func (s *authorizationMembershipLifecycleQueriesStub) ChangeTenantMembershipLifecycle(
	_ context.Context,
	params dbsql.ChangeTenantMembershipLifecycleParams,
) (*dbsql.ChangeTenantMembershipLifecycleRow, error) {
	s.changeParams = params
	return s.row, s.err
}

func TestMembershipLifecycleRepositoryBindsDigestAuditAndExactReceipt(t *testing.T) {
	t.Parallel()

	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	membershipID := uuid.Must(uuid.NewV7())
	auditID := uuid.Must(uuid.NewV7())
	requestID := uuid.Must(uuid.NewV7())
	correlationID := uuid.Must(uuid.NewV7())
	actor := authorizationRepositoryTestActor(t, tenantID)
	updatedAt := time.Now().UTC().Truncate(time.Microsecond)
	tx := &recordingTransaction{}
	queries := &authorizationMembershipLifecycleQueriesStub{
		row: &dbsql.ChangeTenantMembershipLifecycleRow{
			TenantID: toDatabaseUUID(tenantID), MembershipID: toDatabaseUUID(membershipID),
			TargetUserID: toDatabaseUUID(userID), PreviousStatus: "active", Status: "suspended",
			LifecycleRevision: 8, UpdatedAt: databaseTime(updatedAt),
			RevokedSessionCount: 3, RevokedContinuationCount: 2, Replayed: true,
		},
	}
	repository := &AuthorizationRepository{
		begin:        func(context.Context, pgx.TxOptions) (databaseTransaction, error) { return tx, nil },
		queryFactory: func(databaseTransaction) authorizationQueries { return queries },
		newID:        func() (uuid.UUID, error) { return auditID, nil },
	}
	key := "membership-lifecycle-key-0001"
	params := authorization.ChangeTenantMembershipLifecycleParams{
		Actor: actor,
		Audit: authorization.AuditContext{
			RequestID: requestID, CorrelationID: correlationID,
			RemoteAddress: netip.MustParseAddr("192.0.2.41"), UserAgent: "membership-test",
		},
		OccurredAt: time.Now().UTC().Truncate(time.Microsecond),
		TenantID:   tenantID, UserID: userID,
		TargetStatus:     authorization.MembershipStatusSuspended,
		ExpectedRevision: 7, Reason: "Suspend access during offboarding review",
		IdempotencyKey: key,
	}
	receipt, err := repository.ChangeTenantMembershipLifecycle(context.Background(), params)
	if err != nil {
		t.Fatalf("ChangeTenantMembershipLifecycle() error = %v", err)
	}
	if !tx.committed || receipt.TenantID != tenantID ||
		receipt.MembershipID != membershipID || receipt.UserID != userID ||
		receipt.LifecycleRevision != 8 || receipt.EntityTag != `"v8"` ||
		receipt.RevokedSessionCount != 3 || receipt.RevokedContinuationCount != 2 ||
		!receipt.Replayed || !receipt.UpdatedAt.Equal(updatedAt) {
		t.Fatalf("transaction/receipt = committed:%t rolledBack:%t %+v", tx.committed, tx.rolledBack, receipt)
	}
	wantDigest := sha256.Sum256([]byte(key))
	got := queries.changeParams
	if uuid.UUID(got.ActorSessionID.Bytes) != actor.SessionID ||
		uuid.UUID(got.TargetUserID.Bytes) != userID || got.TargetStatus != "suspended" ||
		got.ExpectedRevision != 7 || got.Reason != params.Reason ||
		!bytes.Equal(got.IdempotencyKeyDigest, wantDigest[:]) ||
		uuid.UUID(got.AuditID.Bytes) != auditID || uuid.UUID(got.RequestID.Bytes) != requestID ||
		uuid.UUID(got.CorrelationID.Bytes) != correlationID ||
		got.IpAddress != params.Audit.RemoteAddress || got.UserAgent != params.Audit.UserAgent ||
		got.AuthenticationMethod != actor.AuthenticationMethod {
		t.Fatalf("membership lifecycle query params = %+v", got)
	}
}

func TestAuthorizationVersionConversionRejectsInt4Overflow(t *testing.T) {
	if version, err := databaseAuthorizationVersion(math.MaxInt32); err != nil || version != math.MaxInt32 {
		t.Fatalf("maximum int4 version = %d, %v", version, err)
	}
	for _, value := range []int64{0, -1, math.MaxInt32 + 1} {
		if _, err := databaseAuthorizationVersion(value); !errors.Is(err, authorization.ErrInvalidInput) {
			t.Fatalf("databaseAuthorizationVersion(%d) error = %v", value, err)
		}
	}
}

func TestAuthorizationRepositoryRejectsUnrepresentableExpiryBeforeTransaction(t *testing.T) {
	t.Parallel()

	tenantID := uuid.Must(uuid.NewV7())
	actor := authorizationRepositoryTestActor(t, tenantID)
	roleID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	groupID := uuid.Must(uuid.NewV7())
	invalidExpiries := []struct {
		name  string
		value time.Time
	}{
		{name: "zero", value: time.Time{}},
		{
			name: "UTC year overflow",
			value: time.Date(
				9999, time.December, 31, 23, 59, 59, 999999000,
				time.FixedZone("-23:59", -(23*60*60+59*60)),
			),
		},
		{
			name: "UTC year underflow",
			value: time.Date(
				0, time.January, 1, 0, 0, 0, 0,
				time.FixedZone("+23:59", 23*60*60+59*60),
			),
		},
		{
			name:  "sub-microsecond",
			value: time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond).Add(time.Nanosecond),
		},
	}
	operations := []struct {
		name   string
		invoke func(*AuthorizationRepository, *time.Time) error
	}{
		{
			name: "direct role grant",
			invoke: func(repository *AuthorizationRepository, expiresAt *time.Time) error {
				_, err := repository.GrantUserRole(
					context.Background(),
					authorization.GrantUserRoleParams{
						Actor: actor, OccurredAt: time.Now().UTC(), TenantID: tenantID,
						GrantID: uuid.Must(uuid.NewV7()), UserID: userID, RoleID: roleID,
						Reason: "Invalid expiry", ExpiresAt: expiresAt,
						IdempotencyKey: "invalid-expiry-direct-role",
					},
				)
				return err
			},
		},
		{
			name: "security group membership",
			invoke: func(repository *AuthorizationRepository, expiresAt *time.Time) error {
				_, err := repository.AddTenantSecurityGroupMembership(
					context.Background(),
					authorization.AddTenantSecurityGroupMembershipParams{
						Actor: actor, OccurredAt: time.Now().UTC(), TenantID: tenantID,
						GroupID: groupID, MembershipID: uuid.Must(uuid.NewV7()), UserID: userID,
						Reason: "Invalid expiry", ExpiresAt: expiresAt,
						IdempotencyKey: "invalid-expiry-group-member",
					},
				)
				return err
			},
		},
		{
			name: "security group role grant",
			invoke: func(repository *AuthorizationRepository, expiresAt *time.Time) error {
				_, err := repository.GrantTenantSecurityGroupRole(
					context.Background(),
					authorization.GrantTenantSecurityGroupRoleParams{
						Actor: actor, OccurredAt: time.Now().UTC(), TenantID: tenantID,
						GroupID: groupID, GrantID: uuid.Must(uuid.NewV7()), RoleID: roleID,
						Reason: "Invalid expiry", ExpiresAt: expiresAt,
						IdempotencyKey: "invalid-expiry-group-role",
					},
				)
				return err
			},
		},
	}

	for _, operation := range operations {
		for _, expiry := range invalidExpiries {
			t.Run(operation.name+"/"+expiry.name, func(t *testing.T) {
				beginCalled := false
				auditIDCalled := false
				repository := &AuthorizationRepository{
					begin: func(context.Context, pgx.TxOptions) (databaseTransaction, error) {
						beginCalled = true
						return nil, errors.New("unexpected transaction")
					},
					newID: func() (uuid.UUID, error) {
						auditIDCalled = true
						return uuid.NewV7()
					},
				}
				if err := operation.invoke(repository, &expiry.value); !errors.Is(err, authorization.ErrInvalidInput) {
					t.Fatalf("operation error = %v, want invalid input", err)
				}
				if beginCalled {
					t.Fatal("invalid expiry reached the database transaction boundary")
				}
				if auditIDCalled {
					t.Fatal("invalid expiry allocated an audit event identifier")
				}
			})
		}
	}
}

func TestEmptyAuthorizationPolicyUsesNonNullDatabaseArrays(t *testing.T) {
	permissionKeys, scopes, delegationKeys, delegationScopes, err :=
		databaseAuthorizationPolicy(authorization.TenantRolePolicy{})
	if err != nil {
		t.Fatalf("databaseAuthorizationPolicy() error = %v", err)
	}
	if permissionKeys == nil || scopes == nil || delegationKeys == nil || delegationScopes == nil {
		t.Fatal("empty role policy mapped to a null PostgreSQL array")
	}
}

type authorizationContextQueriesStub struct {
	authorizationQueries
	setParams dbsql.SetTenantContextParams
	setCalls  int
	result    *dbsql.SetTenantContextRow
}

type authorizationCommitErrorTransaction struct {
	recordingTransaction
	err error
}

func (tx *authorizationCommitErrorTransaction) Commit(context.Context) error {
	tx.committed = true
	return tx.err
}

func (s *authorizationContextQueriesStub) SetTenantContext(
	_ context.Context,
	params dbsql.SetTenantContextParams,
) (*dbsql.SetTenantContextRow, error) {
	s.setCalls++
	s.setParams = params
	return s.result, nil
}

func TestAuthorizationTransactionInstallsAndVerifiesTenantContextBeforeWork(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV7())
	actor := authorizationRepositoryTestActor(t, tenantID)
	tx := &recordingTransaction{}
	queries := &authorizationContextQueriesStub{result: &dbsql.SetTenantContextRow{
		TenantID: tenantID.String(), UserID: actor.UserID.String(),
	}}
	var transactionOptions pgx.TxOptions
	repository := &AuthorizationRepository{
		begin: func(_ context.Context, options pgx.TxOptions) (databaseTransaction, error) {
			transactionOptions = options
			return tx, nil
		},
		queryFactory: func(databaseTransaction) authorizationQueries {
			return queries
		},
	}
	workCalled := false
	result, err := withAuthorizationTransaction(
		context.Background(), repository, actor, tenantID,
		func(authorizationQueries) (string, error) {
			workCalled = true
			if queries.setCalls != 1 {
				t.Fatalf("SetTenantContext calls before work = %d", queries.setCalls)
			}
			return "ok", nil
		},
	)
	if err != nil || result != "ok" || !workCalled || !tx.committed {
		t.Fatalf("authorization transaction = %q, work=%t, committed=%t, error=%v", result, workCalled, tx.committed, err)
	}
	if transactionOptions.IsoLevel != pgx.ReadCommitted {
		t.Fatalf("write transaction isolation = %q, want read committed", transactionOptions.IsoLevel)
	}
	installedTenant, err := domainUUID(queries.setParams.TenantID)
	if err != nil || installedTenant != tenantID {
		t.Fatalf("installed tenant = %v, %v", installedTenant, err)
	}
	installedUser, err := domainUUID(queries.setParams.UserID)
	if err != nil || installedUser != actor.UserID {
		t.Fatalf("installed user = %v, %v", installedUser, err)
	}
}

func TestAuthorizationMultiQueryReadsUseOneRepeatableSnapshot(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV7())
	actor := authorizationRepositoryTestActor(t, tenantID)
	tx := &recordingTransaction{}
	queries := &authorizationContextQueriesStub{result: &dbsql.SetTenantContextRow{
		TenantID: tenantID.String(), UserID: actor.UserID.String(),
	}}
	var transactionOptions pgx.TxOptions
	repository := &AuthorizationRepository{
		begin: func(_ context.Context, options pgx.TxOptions) (databaseTransaction, error) {
			transactionOptions = options
			return tx, nil
		},
		queryFactory: func(databaseTransaction) authorizationQueries { return queries },
	}

	_, err := withAuthorizationReadTransaction(
		context.Background(), repository, actor, tenantID,
		func(authorizationQueries) (struct{}, error) { return struct{}{}, nil },
	)
	if err != nil {
		t.Fatalf("repeatable read transaction error = %v", err)
	}
	if transactionOptions.IsoLevel != pgx.RepeatableRead {
		t.Fatalf("read transaction isolation = %q, want repeatable read", transactionOptions.IsoLevel)
	}
}

func TestAuthorizationTransactionMapsDeferredCommitConstraint(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV7())
	actor := authorizationRepositoryTestActor(t, tenantID)
	tx := &authorizationCommitErrorTransaction{
		err: &pgconn.PgError{Code: "23514", ConstraintName: "tenant_last_recovery_admin_check"},
	}
	queries := &authorizationContextQueriesStub{result: &dbsql.SetTenantContextRow{
		TenantID: tenantID.String(), UserID: actor.UserID.String(),
	}}
	repository := &AuthorizationRepository{
		begin: func(context.Context, pgx.TxOptions) (databaseTransaction, error) { return tx, nil },
		queryFactory: func(databaseTransaction) authorizationQueries {
			return queries
		},
	}

	_, err := withAuthorizationTransaction(
		context.Background(), repository, actor, tenantID,
		func(authorizationQueries) (struct{}, error) { return struct{}{}, nil },
	)
	if !errors.Is(err, authorization.ErrConflict) || !tx.committed || !tx.rolledBack {
		t.Fatalf("deferred constraint error=%v, committed=%t, rolledBack=%t", err, tx.committed, tx.rolledBack)
	}
}

func TestAuthorizationTransactionMapsSerializationCommitFailureToUnavailable(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV7())
	actor := authorizationRepositoryTestActor(t, tenantID)
	tx := &authorizationCommitErrorTransaction{
		err: fmt.Errorf(
			"commit failed: %w",
			&pgconn.PgError{
				Code:    "40001",
				Message: "could not serialize access due to read/write dependencies among transactions",
			},
		),
	}
	queries := &authorizationContextQueriesStub{result: &dbsql.SetTenantContextRow{
		TenantID: tenantID.String(), UserID: actor.UserID.String(),
	}}
	repository := &AuthorizationRepository{
		begin: func(context.Context, pgx.TxOptions) (databaseTransaction, error) { return tx, nil },
		queryFactory: func(databaseTransaction) authorizationQueries {
			return queries
		},
	}

	_, err := withAuthorizationTransaction(
		context.Background(), repository, actor, tenantID,
		func(authorizationQueries) (struct{}, error) { return struct{}{}, nil },
	)
	if !errors.Is(err, authorization.ErrUnavailable) ||
		errors.Is(err, authorization.ErrPreconditionFailed) || !tx.committed || !tx.rolledBack {
		t.Fatalf("serialization commit error=%v, committed=%t, rolledBack=%t", err, tx.committed, tx.rolledBack)
	}
}

func TestAuthorizationTransactionRejectsUnexpectedInstalledContext(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV7())
	actor := authorizationRepositoryTestActor(t, tenantID)
	tx := &recordingTransaction{}
	queries := &authorizationContextQueriesStub{result: &dbsql.SetTenantContextRow{
		TenantID: uuid.Must(uuid.NewV7()).String(), UserID: actor.UserID.String(),
	}}
	repository := &AuthorizationRepository{
		begin: func(context.Context, pgx.TxOptions) (databaseTransaction, error) { return tx, nil },
		queryFactory: func(databaseTransaction) authorizationQueries {
			return queries
		},
	}
	workCalled := false
	_, err := withAuthorizationTransaction(
		context.Background(), repository, actor, tenantID,
		func(authorizationQueries) (struct{}, error) {
			workCalled = true
			return struct{}{}, nil
		},
	)
	if err == nil || workCalled || tx.committed || !tx.rolledBack {
		t.Fatalf("unexpected context error=%v, work=%t, committed=%t, rolledBack=%t", err, workCalled, tx.committed, tx.rolledBack)
	}
}

type authorizationCreateReplayQueriesStub struct {
	authorizationQueries
	tenantID     uuid.UUID
	actorID      uuid.UUID
	resultID     uuid.UUID
	createdAt    time.Time
	createParams dbsql.CreateTenantAuthorizationRoleParams
}

func (s *authorizationCreateReplayQueriesStub) SetTenantContext(
	_ context.Context,
	params dbsql.SetTenantContextParams,
) (*dbsql.SetTenantContextRow, error) {
	s.tenantID = uuid.UUID(params.TenantID.Bytes)
	s.actorID = uuid.UUID(params.UserID.Bytes)
	return &dbsql.SetTenantContextRow{
		TenantID: s.tenantID.String(), UserID: s.actorID.String(),
	}, nil
}

func (s *authorizationCreateReplayQueriesStub) CreateTenantAuthorizationRole(
	_ context.Context,
	params dbsql.CreateTenantAuthorizationRoleParams,
) (*dbsql.CreateTenantAuthorizationRoleRow, error) {
	s.createParams = params
	return &dbsql.CreateTenantAuthorizationRoleRow{
		ResultResourceID: toDatabaseUUID(s.resultID), ResultVersion: 1, Replayed: true,
	}, nil
}

func (s *authorizationCreateReplayQueriesStub) GetTenantAuthorizationRole(
	context.Context,
	dbsql.GetTenantAuthorizationRoleParams,
) (*dbsql.GetTenantAuthorizationRoleRow, error) {
	return &dbsql.GetTenantAuthorizationRoleRow{
		RoleID: toDatabaseUUID(s.resultID), RoleKey: "custom_role", DisplayName: "Custom role",
		Description: "Description", PrincipalKind: string(authorization.PrincipalKindHuman), Version: 2,
		CreatedAt: databaseTime(s.createdAt), UpdatedAt: databaseTime(s.createdAt.Add(time.Minute)),
	}, nil
}

func (*authorizationCreateReplayQueriesStub) GetTenantAuthorizationRolePolicy(
	context.Context,
	dbsql.GetTenantAuthorizationRolePolicyParams,
) ([]*dbsql.GetTenantAuthorizationRolePolicyRow, error) {
	return []*dbsql.GetTenantAuthorizationRolePolicyRow{}, nil
}

func TestCreateTenantRoleReturnsCurrentRepresentationAfterReplay(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV7())
	actor := authorizationRepositoryTestActor(t, tenantID)
	tx := &recordingTransaction{}
	queries := &authorizationCreateReplayQueriesStub{
		resultID: uuid.Must(uuid.NewV7()), createdAt: time.Now().UTC().Add(-time.Hour),
	}
	repository := &AuthorizationRepository{
		begin: func(context.Context, pgx.TxOptions) (databaseTransaction, error) { return tx, nil },
		queryFactory: func(databaseTransaction) authorizationQueries {
			return queries
		},
		newID: uuid.NewV7,
	}
	idempotencyKey := "create-role-key-0001"
	requestID := uuid.New()
	correlationID := uuid.New()
	result, err := repository.CreateTenantRole(context.Background(), authorization.CreateTenantRoleParams{
		Actor: actor,
		Audit: authorization.AuditContext{
			RequestID: requestID, CorrelationID: correlationID,
			RemoteAddress: netip.MustParseAddr("192.0.2.10"), UserAgent: "repository test",
		},
		OccurredAt: time.Now().UTC(), TenantID: tenantID, RoleID: uuid.Must(uuid.NewV7()),
		Key: "custom_role", Name: "Custom role", Description: "Description",
		Policy: authorization.TenantRolePolicy{
			Permissions:       make([]authorization.ScopedPermission, 0),
			DelegationCeiling: make([]authorization.ScopedPermission, 0),
		},
		IdempotencyKey: idempotencyKey,
	})
	role := result.Value
	if err != nil || !result.Replayed || role.ID != queries.resultID || role.Version != 2 || !tx.committed {
		t.Fatalf(
			"replayed changed role=%+v, error=%v, committed=%t, rolledBack=%t",
			role, err, tx.committed, tx.rolledBack,
		)
	}
	wantDigest := sha256.Sum256([]byte(idempotencyKey))
	if !bytes.Equal(queries.createParams.IdempotencyKeyDigest, wantDigest[:]) {
		t.Fatal("idempotency key was not SHA-256 digested before database use")
	}
	forwardedRequestID, requestErr := domainUUID(queries.createParams.RequestID)
	forwardedCorrelationID, correlationErr := domainUUID(queries.createParams.CorrelationID)
	if requestErr != nil || correlationErr != nil || forwardedRequestID != requestID ||
		forwardedCorrelationID != correlationID {
		t.Fatal("request audit identifier was not forwarded")
	}
}

type authorizationRolePolicyMutationQueriesStub struct {
	authorizationQueries
	tenantID       uuid.UUID
	actorID        uuid.UUID
	roleID         uuid.UUID
	now            time.Time
	mutationParams dbsql.ReplaceTenantAuthorizationRolePolicyParams
	postReadCalls  int
}

func (s *authorizationRolePolicyMutationQueriesStub) SetTenantContext(
	_ context.Context,
	params dbsql.SetTenantContextParams,
) (*dbsql.SetTenantContextRow, error) {
	s.tenantID = uuid.UUID(params.TenantID.Bytes)
	s.actorID = uuid.UUID(params.UserID.Bytes)
	return &dbsql.SetTenantContextRow{
		TenantID: s.tenantID.String(), UserID: s.actorID.String(),
	}, nil
}

func (s *authorizationRolePolicyMutationQueriesStub) ReplaceTenantAuthorizationRolePolicy(
	_ context.Context,
	params dbsql.ReplaceTenantAuthorizationRolePolicyParams,
) (*dbsql.ReplaceTenantAuthorizationRolePolicyRow, error) {
	s.mutationParams = params
	return &dbsql.ReplaceTenantAuthorizationRolePolicyRow{
		RoleID: toDatabaseUUID(s.roleID), RoleKey: "self_demoting_role",
		DisplayName: "Self-demoting role", Description: "Exercises mutation-owned hydration.",
		Version: 2, CreatedAt: databaseTime(s.now.Add(-time.Hour)), UpdatedAt: databaseTime(s.now),
		PermissionKeys: []string{
			string(authorization.TenantPermissionRoleRead),
			string(authorization.TenantPermissionUserRead),
		},
		PermissionScopes: []string{
			string(authorization.ScopeTenant),
			string(authorization.ScopeTenant),
		},
		DelegationPermissionKeys: []string{string(authorization.TenantPermissionRoleRead)},
		DelegationScopes:         []string{string(authorization.ScopeTenant)},
	}, nil
}

func (s *authorizationRolePolicyMutationQueriesStub) GetTenantAuthorizationRole(
	context.Context,
	dbsql.GetTenantAuthorizationRoleParams,
) (*dbsql.GetTenantAuthorizationRoleRow, error) {
	s.postReadCalls++
	return nil, errors.New("post-mutation role read must not be used")
}

func (s *authorizationRolePolicyMutationQueriesStub) GetTenantAuthorizationRolePolicy(
	context.Context,
	dbsql.GetTenantAuthorizationRolePolicyParams,
) ([]*dbsql.GetTenantAuthorizationRolePolicyRow, error) {
	s.postReadCalls++
	return nil, errors.New("post-mutation policy read must not be used")
}

func TestReplaceTenantRolePolicyUsesMutationOwnedRepresentation(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV7())
	roleID := uuid.Must(uuid.NewV7())
	actor := authorizationRepositoryTestActor(t, tenantID)
	now := time.Now().UTC().Truncate(time.Second)
	tx := &recordingTransaction{}
	queries := &authorizationRolePolicyMutationQueriesStub{roleID: roleID, now: now}
	repository := &AuthorizationRepository{
		begin:        func(context.Context, pgx.TxOptions) (databaseTransaction, error) { return tx, nil },
		queryFactory: func(databaseTransaction) authorizationQueries { return queries },
		newID:        uuid.NewV7,
	}
	requestedPolicy := authorization.TenantRolePolicy{
		Permissions: []authorization.ScopedPermission{
			{Permission: authorization.TenantPermissionRoleRead, Scope: authorization.ScopeTenant},
			{Permission: authorization.TenantPermissionUserRead, Scope: authorization.ScopeTenant},
		},
		DelegationCeiling: []authorization.ScopedPermission{
			{Permission: authorization.TenantPermissionRoleRead, Scope: authorization.ScopeTenant},
		},
	}

	role, err := repository.ReplaceTenantRolePolicy(
		context.Background(),
		authorization.ReplaceTenantRolePolicyParams{
			Actor: actor,
			Audit: authorization.AuditContext{
				RequestID: uuid.New(), CorrelationID: uuid.New(),
				RemoteAddress: netip.MustParseAddr("192.0.2.50"), UserAgent: "repository test",
			},
			OccurredAt: now, TenantID: tenantID, RoleID: roleID,
			Policy: requestedPolicy, ExpectedVersion: 1,
		},
	)
	if err != nil || !tx.committed {
		t.Fatalf("ReplaceTenantRolePolicy() error=%v, committed=%t", err, tx.committed)
	}
	if queries.postReadCalls != 0 {
		t.Fatalf("post-mutation authorized reads = %d, want 0", queries.postReadCalls)
	}
	if role.ID != roleID || role.TenantID != tenantID || role.Version != 2 ||
		role.Name != "Self-demoting role" || !role.UpdatedAt.Equal(now) {
		t.Fatalf("mutation-owned role = %+v", role)
	}
	if len(role.Policy.Permissions) != 2 || len(role.Policy.DelegationCeiling) != 1 ||
		role.Policy.Permissions[0] != requestedPolicy.Permissions[0] ||
		role.Policy.Permissions[1] != requestedPolicy.Permissions[1] ||
		role.Policy.DelegationCeiling[0] != requestedPolicy.DelegationCeiling[0] {
		t.Fatalf("mutation-owned policy = %+v, want %+v", role.Policy, requestedPolicy)
	}
	if queries.mutationParams.ExpectedVersion != 1 ||
		uuid.UUID(queries.mutationParams.RoleID.Bytes) != roleID {
		t.Fatalf("mutation params = %+v", queries.mutationParams)
	}
}

type authorizationDirectGrantReplayQueriesStub struct {
	authorizationQueries
	tenantID       uuid.UUID
	actorID        uuid.UUID
	resultID       uuid.UUID
	targetUserID   uuid.UUID
	targetMemberID uuid.UUID
	roleID         uuid.UUID
	sourceID       uuid.UUID
	revokerMember  uuid.UUID
	now            time.Time
	revokeReason   string
}

func (s *authorizationDirectGrantReplayQueriesStub) SetTenantContext(
	_ context.Context,
	params dbsql.SetTenantContextParams,
) (*dbsql.SetTenantContextRow, error) {
	s.tenantID = uuid.UUID(params.TenantID.Bytes)
	s.actorID = uuid.UUID(params.UserID.Bytes)
	return &dbsql.SetTenantContextRow{
		TenantID: s.tenantID.String(), UserID: s.actorID.String(),
	}, nil
}

func (s *authorizationDirectGrantReplayQueriesStub) GrantTenantUserRole(
	context.Context,
	dbsql.GrantTenantUserRoleParams,
) (*dbsql.GrantTenantUserRoleRow, error) {
	return &dbsql.GrantTenantUserRoleRow{
		ResultResourceID: toDatabaseUUID(s.resultID), ResultVersion: 1, Replayed: true,
	}, nil
}

func (s *authorizationDirectGrantReplayQueriesStub) GetTenantMembershipRoleGrant(
	context.Context,
	dbsql.GetTenantMembershipRoleGrantParams,
) (*dbsql.GetTenantMembershipRoleGrantRow, error) {
	return &dbsql.GetTenantMembershipRoleGrantRow{
		GrantID: toDatabaseUUID(s.resultID), MembershipID: toDatabaseUUID(s.targetMemberID),
		TargetUserID: toDatabaseUUID(s.targetUserID), RoleID: toDatabaseUUID(s.roleID),
		RoleKey: "triage_role", RoleName: "Triage role", RoleDescription: "Triage incidents",
		RoleVersion: 1, RoleCreatedAt: databaseTime(s.now.Add(-2 * time.Hour)),
		RoleUpdatedAt: databaseTime(s.now), SourceID: toDatabaseUUID(s.sourceID),
		SourceKind:                string(authorization.AuthorizationSourceManual),
		ManagedByAuthorizationApi: true,
		SourceType:                string(authorization.RoleGrantSourceDirect),
		GrantedByMembershipID:     toDatabaseUUID(s.revokerMember),
		GrantedByUserID:           toDatabaseUUID(s.actorID), GrantReason: "Original grant reason",
		GrantedAt: databaseTime(s.now.Add(-time.Hour)), RevokedAt: databaseTime(s.now.Add(-time.Minute)),
		RevokedByMembershipID: toDatabaseUUID(s.revokerMember),
		RevokedByUserID:       toDatabaseUUID(s.actorID), RevokeReason: s.revokeReason,
		GrantState: string(authorization.DirectRoleGrantStateRevoked),
		Version:    2, UpdatedAt: databaseTime(s.now),
	}, nil
}

func TestGrantUserRoleReplayReturnsCurrentRevokedRepresentation(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV7())
	actor := authorizationRepositoryTestActor(t, tenantID)
	tx := &recordingTransaction{}
	queries := &authorizationDirectGrantReplayQueriesStub{
		resultID: uuid.Must(uuid.NewV7()), targetUserID: uuid.Must(uuid.NewV7()),
		targetMemberID: uuid.Must(uuid.NewV7()), roleID: uuid.Must(uuid.NewV7()),
		sourceID: uuid.Must(uuid.NewV7()), revokerMember: uuid.Must(uuid.NewV7()),
		now: time.Now().UTC().Truncate(time.Second), revokeReason: "Removed after access review",
	}
	repository := &AuthorizationRepository{
		begin:        func(context.Context, pgx.TxOptions) (databaseTransaction, error) { return tx, nil },
		queryFactory: func(databaseTransaction) authorizationQueries { return queries },
		newID:        uuid.NewV7,
	}

	result, err := repository.GrantUserRole(
		context.Background(),
		authorization.GrantUserRoleParams{
			Actor: actor, OccurredAt: queries.now, TenantID: tenantID,
			GrantID: uuid.Must(uuid.NewV7()), UserID: queries.targetUserID, RoleID: queries.roleID,
			Reason: "Original grant reason", IdempotencyKey: "replay-direct-grant-0001",
		},
	)
	if err != nil {
		t.Fatalf("GrantUserRole() replay error = %v", err)
	}
	grant := result.Value
	if !result.Replayed || !tx.committed || grant.ID != queries.resultID ||
		grant.State != authorization.DirectRoleGrantStateRevoked || grant.Version != 2 ||
		grant.RevokedAt == nil || grant.RevokedByUserID == nil ||
		*grant.RevokedByUserID != actor.UserID || grant.RevokeReason == nil ||
		*grant.RevokeReason != queries.revokeReason {
		t.Fatalf("replayed current direct role grant = %+v, replayed=%t, committed=%t", grant, result.Replayed, tx.committed)
	}
}

func TestAuthorizationCommandVersionMatches(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		createdVersion int32
		replayed       bool
		currentVersion int64
		want           bool
	}{
		{name: "new command exact version", createdVersion: 1, currentVersion: 1, want: true},
		{name: "new command newer representation", createdVersion: 1, currentVersion: 2},
		{name: "replay exact version", createdVersion: 1, replayed: true, currentVersion: 1, want: true},
		{name: "replay newer representation", createdVersion: 1, replayed: true, currentVersion: 2, want: true},
		{name: "replay older representation", createdVersion: 2, replayed: true, currentVersion: 1},
		{name: "invalid created version", currentVersion: 1},
		{name: "invalid current version", createdVersion: 1},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := authorizationCommandVersionMatches(
				test.createdVersion, test.replayed, test.currentVersion,
			); got != test.want {
				t.Fatalf("authorizationCommandVersionMatches() = %t, want %t", got, test.want)
			}
		})
	}
}

type authorizationGroupCommandQueriesStub struct {
	authorizationQueries
	tenantID            uuid.UUID
	actorID             uuid.UUID
	targetMembershipID  uuid.UUID
	sourceID            uuid.UUID
	now                 time.Time
	addParams           dbsql.AddTenantAuthorizationSecurityGroupMemberParams
	getMembershipParams dbsql.GetTenantAuthorizationSecurityGroupMembershipParams
	grantParams         dbsql.GrantTenantAuthorizationSecurityGroupRoleParams
	getRoleGrantParams  dbsql.GetTenantAuthorizationSecurityGroupRoleGrantParams
}

func (s *authorizationGroupCommandQueriesStub) SetTenantContext(
	_ context.Context,
	params dbsql.SetTenantContextParams,
) (*dbsql.SetTenantContextRow, error) {
	s.tenantID = uuid.UUID(params.TenantID.Bytes)
	s.actorID = uuid.UUID(params.UserID.Bytes)
	return &dbsql.SetTenantContextRow{
		TenantID: s.tenantID.String(), UserID: s.actorID.String(),
	}, nil
}

func (s *authorizationGroupCommandQueriesStub) AddTenantAuthorizationSecurityGroupMember(
	_ context.Context,
	params dbsql.AddTenantAuthorizationSecurityGroupMemberParams,
) (*dbsql.AddTenantAuthorizationSecurityGroupMemberRow, error) {
	s.addParams = params
	return &dbsql.AddTenantAuthorizationSecurityGroupMemberRow{
		ResultResourceID: params.GroupMembershipID, ResultVersion: 1,
	}, nil
}

func (s *authorizationGroupCommandQueriesStub) GetTenantAuthorizationSecurityGroupMembership(
	_ context.Context,
	params dbsql.GetTenantAuthorizationSecurityGroupMembershipParams,
) (*dbsql.GetTenantAuthorizationSecurityGroupMembershipRow, error) {
	s.getMembershipParams = params
	return authorizationGroupMembershipTestRow(
		uuid.UUID(params.GroupID.Bytes), uuid.UUID(params.GroupMembershipID.Bytes),
		s.targetMembershipID, uuid.UUID(s.addParams.TargetUserID.Bytes), s.sourceID, s.actorID, s.now,
	), nil
}

func (s *authorizationGroupCommandQueriesStub) GrantTenantAuthorizationSecurityGroupRole(
	_ context.Context,
	params dbsql.GrantTenantAuthorizationSecurityGroupRoleParams,
) (*dbsql.GrantTenantAuthorizationSecurityGroupRoleRow, error) {
	s.grantParams = params
	return &dbsql.GrantTenantAuthorizationSecurityGroupRoleRow{
		ResultResourceID: params.GroupRoleGrantID, ResultVersion: 1,
	}, nil
}

func (s *authorizationGroupCommandQueriesStub) GetTenantAuthorizationSecurityGroupRoleGrant(
	_ context.Context,
	params dbsql.GetTenantAuthorizationSecurityGroupRoleGrantParams,
) (*dbsql.GetTenantAuthorizationSecurityGroupRoleGrantRow, error) {
	s.getRoleGrantParams = params
	return authorizationGroupRoleGrantTestRow(
		uuid.UUID(params.GroupID.Bytes), uuid.UUID(params.GroupRoleGrantID.Bytes),
		uuid.UUID(s.grantParams.RoleID.Bytes), s.sourceID, s.actorID, s.now,
	), nil
}

func TestAuthorizationGroupCommandsDigestKeysAndHydrateNestedResources(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV7())
	actor := authorizationRepositoryTestActor(t, tenantID)
	groupID := uuid.Must(uuid.NewV7())
	groupMembershipID := uuid.Must(uuid.NewV7())
	targetMembershipID := uuid.Must(uuid.NewV7())
	targetUserID := uuid.Must(uuid.NewV7())
	groupRoleGrantID := uuid.Must(uuid.NewV7())
	roleID := uuid.Must(uuid.NewV7())
	sourceID := uuid.Must(uuid.NewV7())
	auditID := uuid.Must(uuid.NewV7())
	now := time.Now().UTC().Truncate(time.Second)
	queries := &authorizationGroupCommandQueriesStub{
		targetMembershipID: targetMembershipID, sourceID: sourceID, now: now,
	}
	transactions := make([]*recordingTransaction, 0, 2)
	repository := &AuthorizationRepository{
		begin: func(context.Context, pgx.TxOptions) (databaseTransaction, error) {
			tx := &recordingTransaction{}
			transactions = append(transactions, tx)
			return tx, nil
		},
		queryFactory: func(databaseTransaction) authorizationQueries { return queries },
		newID:        func() (uuid.UUID, error) { return auditID, nil },
	}
	audit := authorization.AuditContext{
		RequestID: uuid.New(), CorrelationID: uuid.New(),
		RemoteAddress: netip.MustParseAddr("192.0.2.40"), UserAgent: "group adapter test",
	}
	membershipKey := "group-membership-command-key"
	membershipResult, err := repository.AddTenantSecurityGroupMembership(
		context.Background(),
		authorization.AddTenantSecurityGroupMembershipParams{
			Actor: actor, Audit: audit, OccurredAt: now, TenantID: tenantID,
			GroupID: groupID, MembershipID: groupMembershipID, UserID: targetUserID,
			Reason: "Assign incident responder", IdempotencyKey: membershipKey,
		},
	)
	if err != nil {
		t.Fatalf("AddTenantSecurityGroupMembership() error = %v", err)
	}
	if membershipResult.Replayed {
		t.Fatal("new group membership was reported as replayed")
	}
	membership := membershipResult.Value
	if membership.ID != groupMembershipID || membership.Group.ID != groupID ||
		membership.Member.MembershipID != targetMembershipID || membership.Member.User.ID != targetUserID {
		t.Fatalf("membership = %+v", membership)
	}
	wantMembershipDigest := sha256.Sum256([]byte(membershipKey))
	if !bytes.Equal(queries.addParams.IdempotencyKeyDigest, wantMembershipDigest[:]) ||
		uuid.UUID(queries.addParams.GroupID.Bytes) != groupID ||
		uuid.UUID(queries.addParams.GroupMembershipID.Bytes) != groupMembershipID ||
		uuid.UUID(queries.getMembershipParams.GroupID.Bytes) != groupID ||
		uuid.UUID(queries.getMembershipParams.GroupMembershipID.Bytes) != groupMembershipID {
		t.Fatalf("membership command/get params = %+v / %+v", queries.addParams, queries.getMembershipParams)
	}

	roleGrantKey := "group-role-command-key"
	roleGrantResult, err := repository.GrantTenantSecurityGroupRole(
		context.Background(),
		authorization.GrantTenantSecurityGroupRoleParams{
			Actor: actor, Audit: audit, OccurredAt: now, TenantID: tenantID,
			GroupID: groupID, GrantID: groupRoleGrantID, RoleID: roleID,
			Reason: "Grant triage role", IdempotencyKey: roleGrantKey,
		},
	)
	if err != nil {
		t.Fatalf("GrantTenantSecurityGroupRole() error = %v", err)
	}
	if roleGrantResult.Replayed {
		t.Fatal("new group role grant was reported as replayed")
	}
	roleGrant := roleGrantResult.Value
	if roleGrant.ID != groupRoleGrantID || roleGrant.Group.ID != groupID || roleGrant.Role.ID != roleID {
		t.Fatalf("role grant = %+v", roleGrant)
	}
	wantRoleGrantDigest := sha256.Sum256([]byte(roleGrantKey))
	if !bytes.Equal(queries.grantParams.IdempotencyKeyDigest, wantRoleGrantDigest[:]) ||
		uuid.UUID(queries.grantParams.GroupID.Bytes) != groupID ||
		uuid.UUID(queries.grantParams.GroupRoleGrantID.Bytes) != groupRoleGrantID ||
		uuid.UUID(queries.getRoleGrantParams.GroupID.Bytes) != groupID ||
		uuid.UUID(queries.getRoleGrantParams.GroupRoleGrantID.Bytes) != groupRoleGrantID {
		t.Fatalf("role grant command/get params = %+v / %+v", queries.grantParams, queries.getRoleGrantParams)
	}
	if len(transactions) != 2 || !transactions[0].committed || !transactions[1].committed {
		t.Fatalf("transactions = %+v", transactions)
	}
}

type authorizationGroupRevokeQueriesStub struct {
	authorizationQueries
	tenantID         uuid.UUID
	actorID          uuid.UUID
	membershipRow    *dbsql.GetTenantAuthorizationSecurityGroupMembershipRow
	roleGrantRow     *dbsql.GetTenantAuthorizationSecurityGroupRoleGrantRow
	membershipCalls  int
	roleGrantCalls   int
	membershipParams dbsql.RevokeTenantAuthorizationSecurityGroupMembershipParams
	roleGrantParams  dbsql.RevokeTenantAuthorizationSecurityGroupRoleGrantParams
}

func (s *authorizationGroupRevokeQueriesStub) SetTenantContext(
	_ context.Context,
	params dbsql.SetTenantContextParams,
) (*dbsql.SetTenantContextRow, error) {
	s.tenantID = uuid.UUID(params.TenantID.Bytes)
	s.actorID = uuid.UUID(params.UserID.Bytes)
	return &dbsql.SetTenantContextRow{
		TenantID: s.tenantID.String(), UserID: s.actorID.String(),
	}, nil
}

func (s *authorizationGroupRevokeQueriesStub) GetTenantAuthorizationSecurityGroupMembership(
	_ context.Context,
	_ dbsql.GetTenantAuthorizationSecurityGroupMembershipParams,
) (*dbsql.GetTenantAuthorizationSecurityGroupMembershipRow, error) {
	return s.membershipRow, nil
}

func (s *authorizationGroupRevokeQueriesStub) GetTenantAuthorizationSecurityGroupRoleGrant(
	_ context.Context,
	_ dbsql.GetTenantAuthorizationSecurityGroupRoleGrantParams,
) (*dbsql.GetTenantAuthorizationSecurityGroupRoleGrantRow, error) {
	return s.roleGrantRow, nil
}

func (s *authorizationGroupRevokeQueriesStub) RevokeTenantAuthorizationSecurityGroupMembership(
	_ context.Context,
	params dbsql.RevokeTenantAuthorizationSecurityGroupMembershipParams,
) (int32, error) {
	s.membershipCalls++
	s.membershipParams = params
	return params.ExpectedVersion + 1, nil
}

func (s *authorizationGroupRevokeQueriesStub) RevokeTenantAuthorizationSecurityGroupRoleGrant(
	_ context.Context,
	params dbsql.RevokeTenantAuthorizationSecurityGroupRoleGrantParams,
) (int32, error) {
	s.roleGrantCalls++
	s.roleGrantParams = params
	return params.ExpectedVersion + 1, nil
}

func TestAuthorizationGroupRevokesBindParentAndEdgeVersions(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV7())
	actor := authorizationRepositoryTestActor(t, tenantID)
	groupID := uuid.Must(uuid.NewV7())
	membershipID := uuid.Must(uuid.NewV7())
	grantID := uuid.Must(uuid.NewV7())
	targetMembershipID := uuid.Must(uuid.NewV7())
	targetUserID := uuid.Must(uuid.NewV7())
	roleID := uuid.Must(uuid.NewV7())
	sourceID := uuid.Must(uuid.NewV7())
	auditID := uuid.Must(uuid.NewV7())
	now := time.Now().UTC()
	membershipRow := authorizationGroupMembershipTestRow(
		groupID, membershipID, targetMembershipID, targetUserID, sourceID, actor.UserID, now,
	)
	membershipRow.Version = 3
	roleGrantRow := authorizationGroupRoleGrantTestRow(
		groupID, grantID, roleID, sourceID, actor.UserID, now,
	)
	roleGrantRow.Version = 5
	queries := &authorizationGroupRevokeQueriesStub{
		membershipRow: membershipRow, roleGrantRow: roleGrantRow,
	}
	transactions := make([]*recordingTransaction, 0, 2)
	transactionOptions := make([]pgx.TxOptions, 0, 3)
	repository := &AuthorizationRepository{
		begin: func(_ context.Context, options pgx.TxOptions) (databaseTransaction, error) {
			tx := &recordingTransaction{}
			transactions = append(transactions, tx)
			transactionOptions = append(transactionOptions, options)
			return tx, nil
		},
		queryFactory: func(databaseTransaction) authorizationQueries { return queries },
		newID:        func() (uuid.UUID, error) { return auditID, nil },
	}
	audit := authorization.AuditContext{
		RequestID: uuid.New(), CorrelationID: uuid.New(),
		RemoteAddress: netip.MustParseAddr("192.0.2.41"), UserAgent: "group revoke adapter test",
	}
	membership, err := mapGotAuthorizationSecurityGroupMembership(tenantID, groupID, membershipRow)
	if err != nil {
		t.Fatalf("map membership precondition fixture: %v", err)
	}
	membershipEntityTag, err := authorization.TenantSecurityGroupMembershipEntityTag(membership)
	if err != nil {
		t.Fatalf("compute membership precondition: %v", err)
	}
	roleGrant, err := mapGotAuthorizationSecurityGroupRoleGrant(tenantID, groupID, roleGrantRow)
	if err != nil {
		t.Fatalf("map role-grant precondition fixture: %v", err)
	}
	roleGrantEntityTag, err := authorization.TenantSecurityGroupRoleGrantEntityTag(roleGrant)
	if err != nil {
		t.Fatalf("compute role-grant precondition: %v", err)
	}
	if err := repository.RevokeTenantSecurityGroupMembership(
		context.Background(),
		authorization.RevokeTenantSecurityGroupMembershipParams{
			Actor: actor, Audit: audit, OccurredAt: now, TenantID: tenantID,
			GroupID: groupID, MembershipID: membershipID,
			Reason: "Close membership edge", ExpectedEntityTag: membershipEntityTag,
		},
	); err != nil {
		t.Fatalf("RevokeTenantSecurityGroupMembership() error = %v", err)
	}
	if uuid.UUID(queries.membershipParams.GroupID.Bytes) != groupID ||
		uuid.UUID(queries.membershipParams.GroupMembershipID.Bytes) != membershipID ||
		queries.membershipParams.ExpectedVersion != 3 ||
		queries.membershipParams.Reason != "Close membership edge" {
		t.Fatalf("membership revoke params = %+v", queries.membershipParams)
	}
	membershipRow.UserActive = false
	if err := repository.RevokeTenantSecurityGroupMembership(
		context.Background(),
		authorization.RevokeTenantSecurityGroupMembershipParams{
			Actor: actor, Audit: audit, OccurredAt: now, TenantID: tenantID,
			GroupID: groupID, MembershipID: membershipID,
			Reason: "Reject stale membership edge", ExpectedEntityTag: membershipEntityTag,
		},
	); !errors.Is(err, authorization.ErrPreconditionFailed) {
		t.Fatalf("stale representation revoke error = %v, want precondition failed", err)
	}
	if queries.membershipCalls != 1 {
		t.Fatalf("membership revoke query calls = %d, want 1", queries.membershipCalls)
	}
	if err := repository.RevokeTenantSecurityGroupRoleGrant(
		context.Background(),
		authorization.RevokeTenantSecurityGroupRoleGrantParams{
			Actor: actor, Audit: audit, OccurredAt: now, TenantID: tenantID,
			GroupID: groupID, GrantID: grantID,
			Reason: "Close role edge", ExpectedEntityTag: roleGrantEntityTag,
		},
	); err != nil {
		t.Fatalf("RevokeTenantSecurityGroupRoleGrant() error = %v", err)
	}
	if uuid.UUID(queries.roleGrantParams.GroupID.Bytes) != groupID ||
		uuid.UUID(queries.roleGrantParams.GroupRoleGrantID.Bytes) != grantID ||
		queries.roleGrantParams.ExpectedVersion != 5 ||
		queries.roleGrantParams.Reason != "Close role edge" {
		t.Fatalf("role-grant revoke params = %+v", queries.roleGrantParams)
	}
	if len(transactions) != 3 || !transactions[0].committed || transactions[1].committed ||
		!transactions[2].committed {
		t.Fatalf("transactions = %+v", transactions)
	}
	for index, options := range transactionOptions {
		if options.IsoLevel != pgx.Serializable {
			t.Fatalf("transaction %d isolation = %q, want serializable", index, options.IsoLevel)
		}
	}
}

func TestAuthorizationGroupEdgeMappersPreserveRevocationHistory(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV7())
	groupID := uuid.Must(uuid.NewV7())
	edgeID := uuid.Must(uuid.NewV7())
	membershipID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	roleID := uuid.Must(uuid.NewV7())
	sourceID := uuid.Must(uuid.NewV7())
	revokerID := uuid.Must(uuid.NewV7())
	now := time.Now().UTC().Truncate(time.Second)
	revokedAt := now.Add(-time.Minute)
	reason := "Removed after access review"

	membershipRow := authorizationGroupMembershipTestRow(
		groupID, edgeID, membershipID, userID, sourceID, revokerID, now,
	)
	membershipRow.GrantState = string(authorization.AuthorizationEdgeStateRevoked)
	membershipRow.RevokedAt = databaseTime(revokedAt)
	membershipRow.RevokedByUserID = toDatabaseUUID(revokerID)
	membershipRow.RevokeReason = reason
	membershipRow.Version = 2
	membership, err := mapGotAuthorizationSecurityGroupMembership(tenantID, groupID, membershipRow)
	if err != nil {
		t.Fatalf("map membership: %v", err)
	}
	if membership.RevokeReason == nil || *membership.RevokeReason != reason ||
		membership.RevokedAt == nil || membership.RevokedByUserID == nil ||
		*membership.RevokedByUserID != revokerID || membership.Provenance.SourceID == nil ||
		*membership.Provenance.SourceID != sourceID || !membership.ManagedByAuthorizationAPI {
		t.Fatalf("membership revocation projection = %+v", membership)
	}
	externalMembershipRow := authorizationGroupMembershipTestRow(
		groupID, edgeID, membershipID, userID, sourceID, revokerID, now,
	)
	externalMembershipRow.ManagedByAuthorizationApi = false
	externalMembership, err := mapGotAuthorizationSecurityGroupMembership(
		tenantID, groupID, externalMembershipRow,
	)
	if err != nil || externalMembership.ManagedByAuthorizationAPI {
		t.Fatalf("external manual membership projection = %+v, %v", externalMembership, err)
	}
	manualMembershipWithoutGrantor := authorizationGroupMembershipTestRow(
		groupID, edgeID, membershipID, userID, sourceID, revokerID, now,
	)
	manualMembershipWithoutGrantor.GrantedByUserID = pgtype.UUID{}
	if _, err := mapGotAuthorizationSecurityGroupMembership(
		tenantID, groupID, manualMembershipWithoutGrantor,
	); err == nil {
		t.Fatal("manual membership edge without a grantor was accepted")
	}

	roleGrantRow := authorizationGroupRoleGrantTestRow(
		groupID, edgeID, roleID, sourceID, revokerID, now,
	)
	roleGrantRow.GrantState = string(authorization.AuthorizationEdgeStateRevoked)
	roleGrantRow.RevokedAt = databaseTime(revokedAt)
	roleGrantRow.RevokedByUserID = toDatabaseUUID(revokerID)
	roleGrantRow.RevokeReason = reason
	roleGrantRow.Version = 2
	roleGrant, err := mapGotAuthorizationSecurityGroupRoleGrant(tenantID, groupID, roleGrantRow)
	if err != nil {
		t.Fatalf("map role grant: %v", err)
	}
	if roleGrant.RevokeReason == nil || *roleGrant.RevokeReason != reason ||
		roleGrant.RevokedAt == nil || roleGrant.RevokedByUserID == nil ||
		*roleGrant.RevokedByUserID != revokerID || roleGrant.Provenance.SourceID == nil ||
		*roleGrant.Provenance.SourceID != sourceID || !roleGrant.ManagedByAuthorizationAPI {
		t.Fatalf("role-grant revocation projection = %+v", roleGrant)
	}
	externalRoleGrantRow := authorizationGroupRoleGrantTestRow(
		groupID, edgeID, roleID, sourceID, revokerID, now,
	)
	externalRoleGrantRow.ManagedByAuthorizationApi = false
	externalRoleGrant, err := mapGotAuthorizationSecurityGroupRoleGrant(
		tenantID, groupID, externalRoleGrantRow,
	)
	if err != nil || externalRoleGrant.ManagedByAuthorizationAPI {
		t.Fatalf("external manual role-grant projection = %+v, %v", externalRoleGrant, err)
	}
	manualRoleGrantWithoutGrantor := authorizationGroupRoleGrantTestRow(
		groupID, edgeID, roleID, sourceID, revokerID, now,
	)
	manualRoleGrantWithoutGrantor.GrantedByUserID = pgtype.UUID{}
	if _, err := mapGotAuthorizationSecurityGroupRoleGrant(
		tenantID, groupID, manualRoleGrantWithoutGrantor,
	); err == nil {
		t.Fatal("manual group role grant without a grantor was accepted")
	}

	invalidOwner := authorizationGroupMembershipTestRow(
		groupID, edgeID, membershipID, userID, sourceID, revokerID, now,
	)
	invalidOwner.SourceKind = string(authorization.AuthorizationSourceIdentityMapping)
	invalidOwner.GrantedByUserID = pgtype.UUID{}
	if _, err := mapGotAuthorizationSecurityGroupMembership(
		tenantID, groupID, invalidOwner,
	); err == nil {
		t.Fatal("non-manual security group edge marked as API-managed was accepted")
	}
	invalidOwner = authorizationGroupMembershipTestRow(
		groupID, edgeID, membershipID, userID, sourceID, revokerID, now,
	)
	invalidOwner.SourceRetiredAt = databaseTime(now)
	if _, err := mapGotAuthorizationSecurityGroupMembership(
		tenantID, groupID, invalidOwner,
	); err == nil {
		t.Fatal("retired security group edge marked as API-managed was accepted")
	}

	roleGrantRow.GrantState = string(authorization.AuthorizationEdgeStateActive)
	if _, err := mapGotAuthorizationSecurityGroupRoleGrant(tenantID, groupID, roleGrantRow); err == nil {
		t.Fatal("active edge with revocation metadata was accepted")
	}
}

func TestDirectAuthorizationGrantMapperMapsOwnershipFailClosed(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	sourceID := uuid.Must(uuid.NewV7())
	grantorID := uuid.Must(uuid.NewV7())
	now := time.Now().UTC().Truncate(time.Second)
	retiredAt := now.Add(time.Minute)
	base := authorizationGrantRow{
		grantID: uuidDatabaseTestValue(t), roleID: uuidDatabaseTestValue(t),
		roleKey: "triage_role", roleName: "Triage role", roleDescription: "Triage",
		roleVersion: 1, roleCreatedAt: databaseTime(now.Add(-time.Hour)), roleUpdatedAt: databaseTime(now),
		sourceID: toDatabaseUUID(sourceID), grantedByUserID: toDatabaseUUID(grantorID),
		grantReason: "Direct assignment", grantedAt: databaseTime(now.Add(-time.Minute)),
		grantState: string(authorization.DirectRoleGrantStateActive), version: 1, updatedAt: databaseTime(now),
	}
	tests := []struct {
		name          string
		kind          authorization.AuthorizationSourceKind
		sourceType    authorization.RoleGrantSourceType
		authoritative bool
		retired       bool
		grantor       bool
		managed       bool
	}{
		{name: "managed manual", kind: authorization.AuthorizationSourceManual, sourceType: authorization.RoleGrantSourceDirect, grantor: true, managed: true},
		{name: "external manual", kind: authorization.AuthorizationSourceManual, sourceType: authorization.RoleGrantSourceDirect, grantor: true},
		{name: "identity mapping", kind: authorization.AuthorizationSourceIdentityMapping, sourceType: authorization.RoleGrantSourceIdentityProvider, authoritative: true, retired: true},
		{name: "system", kind: authorization.AuthorizationSourceSystem, sourceType: authorization.RoleGrantSourceSystem},
		{name: "tenant creation", kind: authorization.AuthorizationSourceTenantCreation, sourceType: authorization.RoleGrantSourceSystem, grantor: true},
		{name: "platform recovery", kind: authorization.AuthorizationSourcePlatformRecovery, sourceType: authorization.RoleGrantSourceSystem},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			row := base
			row.sourceKind = string(test.kind)
			row.sourceType = string(test.sourceType)
			row.sourceAuthoritative = test.authoritative
			row.managedByAuthorizationAPI = test.managed
			if test.retired {
				row.sourceRetiredAt = databaseTime(retiredAt)
			}
			if !test.grantor {
				row.grantedByUserID = pgtype.UUID{}
			}

			grant, err := mapDirectAuthorizationGrant(tenantID, userID, row)
			if err != nil {
				t.Fatalf("map direct grant: %v", err)
			}
			if grant.Provenance.SourceKind != test.kind ||
				grant.Provenance.SourceType != test.sourceType ||
				grant.Provenance.Authoritative != test.authoritative ||
				grant.ManagedByAuthorizationAPI != test.managed ||
				grant.Provenance.SourceID == nil || *grant.Provenance.SourceID != sourceID {
				t.Fatalf("source provenance = %+v", grant.Provenance)
			}
			if test.retired {
				if grant.Provenance.RetiredAt == nil || !grant.Provenance.RetiredAt.Equal(retiredAt) {
					t.Fatalf("source retirement = %v, want %v", grant.Provenance.RetiredAt, retiredAt)
				}
			} else if grant.Provenance.RetiredAt != nil {
				t.Fatalf("source retirement = %v, want nil", grant.Provenance.RetiredAt)
			}
			if test.grantor != (grant.Provenance.GrantedByUserID != nil) ||
				test.grantor && *grant.Provenance.GrantedByUserID != grantorID {
				t.Fatalf("source grantor = %v, want present=%t", grant.Provenance.GrantedByUserID, test.grantor)
			}
		})
	}

	for _, test := range tests {
		t.Run(test.name+" rejects mismatched source type", func(t *testing.T) {
			row := base
			row.sourceKind = string(test.kind)
			if test.sourceType == authorization.RoleGrantSourceDirect {
				row.sourceType = string(authorization.RoleGrantSourceSystem)
			} else {
				row.sourceType = string(authorization.RoleGrantSourceDirect)
			}
			if _, err := mapDirectAuthorizationGrant(tenantID, userID, row); err == nil {
				t.Fatal("mismatched direct-grant source type was accepted")
			}
		})
	}

	row := base
	row.sourceKind = "future_source_kind"
	row.sourceType = string(authorization.RoleGrantSourceSystem)
	if _, err := mapDirectAuthorizationGrant(tenantID, userID, row); err == nil {
		t.Fatal("unknown direct grant source was accepted")
	}
	row.sourceKind = string(authorization.AuthorizationSourceSystem)
	row.sourceType = "future_source_type"
	if _, err := mapDirectAuthorizationGrant(tenantID, userID, row); err == nil {
		t.Fatal("unknown direct grant source type was accepted")
	}
	row.sourceKind = string(authorization.AuthorizationSourceManual)
	row.sourceType = string(authorization.RoleGrantSourceDirect)
	row.grantedByUserID = pgtype.UUID{}
	if _, err := mapDirectAuthorizationGrant(tenantID, userID, row); err == nil {
		t.Fatal("manual direct grant without a grantor was accepted")
	}
	row = base
	row.sourceKind = string(authorization.AuthorizationSourceSystem)
	row.sourceType = string(authorization.RoleGrantSourceSystem)
	row.managedByAuthorizationAPI = true
	if _, err := mapDirectAuthorizationGrant(tenantID, userID, row); err == nil {
		t.Fatal("non-manual direct grant marked as API-managed was accepted")
	}
	row = base
	row.sourceKind = string(authorization.AuthorizationSourceManual)
	row.sourceType = string(authorization.RoleGrantSourceDirect)
	row.managedByAuthorizationAPI = true
	row.sourceRetiredAt = databaseTime(retiredAt)
	if _, err := mapDirectAuthorizationGrant(tenantID, userID, row); err == nil {
		t.Fatal("retired direct grant source marked as API-managed was accepted")
	}
}

func TestDirectAuthorizationGrantMapperPreservesAndRejectsRevocationLifecycle(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	revokerID := uuid.Must(uuid.NewV7())
	now := time.Now().UTC().Truncate(time.Second)
	revokedAt := now.Add(-time.Minute)
	reason := "Removed after access review"
	base := authorizationGrantRow{
		grantID: uuidDatabaseTestValue(t), roleID: uuidDatabaseTestValue(t),
		roleKey: "triage_role", roleName: "Triage role", roleDescription: "Triage",
		roleVersion: 1, roleCreatedAt: databaseTime(now.Add(-2 * time.Hour)),
		roleUpdatedAt: databaseTime(now), sourceID: uuidDatabaseTestValue(t),
		sourceKind:      string(authorization.AuthorizationSourceManual),
		sourceType:      string(authorization.RoleGrantSourceDirect),
		grantedByUserID: uuidDatabaseTestValue(t), grantReason: "Direct assignment",
		grantedAt: databaseTime(now.Add(-time.Hour)), revokedAt: databaseTime(revokedAt),
		revokedByUserID: toDatabaseUUID(revokerID), revokeReason: reason,
		grantState: string(authorization.DirectRoleGrantStateRevoked),
		version:    2, updatedAt: databaseTime(now),
	}

	grant, err := mapDirectAuthorizationGrant(tenantID, userID, base)
	if err != nil {
		t.Fatalf("map revoked direct grant: %v", err)
	}
	if grant.State != authorization.DirectRoleGrantStateRevoked ||
		grant.RevokedAt == nil || grant.RevokedByUserID == nil ||
		*grant.RevokedByUserID != revokerID || grant.RevokeReason == nil ||
		*grant.RevokeReason != reason {
		t.Fatalf("revoked direct role-grant projection = %+v", grant)
	}

	tests := []struct {
		name   string
		mutate func(*authorizationGrantRow)
	}{
		{
			name: "active with revocation metadata",
			mutate: func(row *authorizationGrantRow) {
				row.grantState = string(authorization.DirectRoleGrantStateActive)
			},
		},
		{
			name: "expired without expiry",
			mutate: func(row *authorizationGrantRow) {
				row.grantState = string(authorization.DirectRoleGrantStateExpired)
				row.revokedAt = pgtype.Timestamptz{}
				row.revokedByUserID = pgtype.UUID{}
				row.revokeReason = ""
			},
		},
		{
			name: "revoked without reason",
			mutate: func(row *authorizationGrantRow) {
				row.revokeReason = ""
			},
		},
		{
			name: "unknown state",
			mutate: func(row *authorizationGrantRow) {
				row.grantState = "future"
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			row := base
			test.mutate(&row)
			if _, err := mapDirectAuthorizationGrant(tenantID, userID, row); err == nil {
				t.Fatal("invalid direct role-grant lifecycle was accepted")
			}
		})
	}

	expired := base
	expired.grantState = string(authorization.DirectRoleGrantStateExpired)
	expired.expiresAt = databaseTime(now.Add(time.Hour))
	expired.revokedAt = pgtype.Timestamptz{}
	expired.revokedByUserID = pgtype.UUID{}
	expired.revokeReason = ""
	if _, err := mapDirectAuthorizationGrant(tenantID, userID, expired); err != nil {
		t.Fatalf("map expired direct grant: %v", err)
	}
}

func authorizationGroupMembershipTestRow(
	groupID uuid.UUID,
	edgeID uuid.UUID,
	membershipID uuid.UUID,
	userID uuid.UUID,
	sourceID uuid.UUID,
	grantorID uuid.UUID,
	now time.Time,
) *dbsql.GetTenantAuthorizationSecurityGroupMembershipRow {
	return &dbsql.GetTenantAuthorizationSecurityGroupMembershipRow{
		GroupMembershipID: toDatabaseUUID(edgeID), GroupID: toDatabaseUUID(groupID),
		GroupKey: "triage_group", GroupName: "Triage group", GroupDescription: "Triage responders",
		GroupVersion: 1, GroupCreatedAt: databaseTime(now.Add(-2 * time.Hour)), GroupUpdatedAt: databaseTime(now),
		MembershipID: toDatabaseUUID(membershipID), TargetUserID: toDatabaseUUID(userID),
		Email: "responder@example.test", DisplayName: "Incident Responder",
		MembershipStatus:  string(authorization.MembershipStatusActive),
		CompatibilityRole: string(authorization.LegacyMembershipRoleAnalyst), UserActive: true,
		MembershipCreatedAt: databaseTime(now.Add(-24 * time.Hour)), MembershipUpdatedAt: databaseTime(now),
		MembershipLifecycleRevision: 1,
		SourceID:                    toDatabaseUUID(sourceID), SourceKind: string(authorization.AuthorizationSourceManual),
		ManagedByAuthorizationApi: true,
		GrantedByUserID:           toDatabaseUUID(grantorID), GrantReason: "Assign incident responder",
		GrantedAt: databaseTime(now.Add(-time.Hour)), GrantState: string(authorization.AuthorizationEdgeStateActive),
		Version: 1, UpdatedAt: databaseTime(now),
	}
}

func authorizationGroupRoleGrantTestRow(
	groupID uuid.UUID,
	edgeID uuid.UUID,
	roleID uuid.UUID,
	sourceID uuid.UUID,
	grantorID uuid.UUID,
	now time.Time,
) *dbsql.GetTenantAuthorizationSecurityGroupRoleGrantRow {
	return &dbsql.GetTenantAuthorizationSecurityGroupRoleGrantRow{
		GroupRoleGrantID: toDatabaseUUID(edgeID), GroupID: toDatabaseUUID(groupID),
		GroupKey: "triage_group", GroupName: "Triage group", GroupDescription: "Triage responders",
		GroupVersion: 1, GroupCreatedAt: databaseTime(now.Add(-2 * time.Hour)), GroupUpdatedAt: databaseTime(now),
		RoleID: toDatabaseUUID(roleID), RoleKey: "triage_role", RoleName: "Triage role",
		RoleDescription: "Incident triage", RoleVersion: 1,
		RoleCreatedAt: databaseTime(now.Add(-2 * time.Hour)), RoleUpdatedAt: databaseTime(now),
		SourceID: toDatabaseUUID(sourceID), SourceKind: string(authorization.AuthorizationSourceManual),
		ManagedByAuthorizationApi: true,
		GrantedByUserID:           toDatabaseUUID(grantorID), GrantReason: "Grant triage role",
		GrantedAt: databaseTime(now.Add(-time.Hour)), GrantState: string(authorization.AuthorizationEdgeStateActive),
		Version: 1, UpdatedAt: databaseTime(now),
	}
}

func uuidDatabaseTestValue(t *testing.T) pgtype.UUID {
	t.Helper()
	return toDatabaseUUID(uuid.Must(uuid.NewV7()))
}

func authorizationRepositoryTestActor(t *testing.T, tenantID uuid.UUID) authorization.Actor {
	t.Helper()
	return authorization.Actor{
		UserID: uuid.Must(uuid.NewV7()), SessionID: uuid.Must(uuid.NewV7()),
		ActiveTenantID: tenantID, AuthenticationMethod: "totp",
	}
}
