package postgres

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/platform"
)

func TestAuthorizePlatformTenantAccessBindsExactAuthorityIdempotencyAndAudit(t *testing.T) {
	params, generated, authorizedAt := validPlatformTenantAccessRepositoryFixture(t)
	tx := &platformTenantAccessTransaction{
		actorID: params.ActorID,
		result: platformTenantAccessDatabaseResult{
			tenantID: params.Command.TenantID(), membershipID: generated[0], userID: params.ActorID,
			tenantVersion: params.Command.ExpectedVersion(), membershipRevision: 1,
			authorizationRevision: 27, authorizedAt: authorizedAt,
		},
	}
	next := 0
	repository := &PlatformRepository{
		begin: func(_ context.Context, options pgx.TxOptions) (databaseTransaction, error) {
			if options.IsoLevel != pgx.ReadCommitted {
				t.Fatalf("transaction isolation = %q", options.IsoLevel)
			}
			return tx, nil
		},
		newID: func() (uuid.UUID, error) {
			value := generated[next]
			next++
			return value, nil
		},
	}

	receipt, err := repository.AuthorizePlatformTenantAccess(context.Background(), params)
	if err != nil {
		t.Fatalf("AuthorizePlatformTenantAccess() error = %v", err)
	}
	if receipt.TenantID() != params.Command.TenantID() || receipt.MembershipID() != generated[0] ||
		receipt.UserID() != params.ActorID || receipt.TenantVersion() != params.Command.ExpectedVersion() ||
		receipt.MembershipRevision() != 1 || receipt.AuthorizationRevision() != 27 ||
		!receipt.AuthorizedAt().Equal(authorizedAt) || receipt.Replayed() {
		t.Fatalf("receipt = %#v", receipt)
	}
	if !tx.committed || !tx.rolledBack || len(tx.queries) != 2 ||
		!strings.Contains(tx.queries[0], "set_config('app.user_id'") ||
		!strings.Contains(tx.queries[1], "app.authorize_platform_tenant_access_v1") {
		t.Fatalf("transaction/queries = %t/%t/%#v", tx.committed, tx.rolledBack, tx.queries)
	}
	digest := sha256.Sum256([]byte(params.Command.IdempotencyKey()))
	want := []any{
		toDatabaseUUID(params.SessionID), toDatabaseUUID(params.Command.TenantID()),
		toDatabaseUUID(generated[0]), toDatabaseUUID(generated[1]),
		params.Command.ExpectedVersion(), params.Command.Reason(), digest[:],
		toDatabaseUUID(generated[2]), toDatabaseUUID(generated[3]),
		toDatabaseUUID(params.Event.RequestID), toDatabaseUUID(params.Event.CorrelationID),
		params.Event.RemoteAddress, params.Event.UserAgent, params.AuthenticationMethod,
	}
	if !reflect.DeepEqual(tx.arguments[1], want) {
		t.Fatalf("access arguments = %#v, want %#v", tx.arguments[1], want)
	}
}

func TestAuthorizePlatformTenantAccessMapsClosedDatabaseOutcomes(t *testing.T) {
	t.Parallel()
	params, generated, _ := validPlatformTenantAccessRepositoryFixture(t)
	for _, test := range []struct {
		name string
		code string
		want error
	}{
		{name: "permission or MFA", code: "42501", want: authentication.ErrForbidden},
		{name: "tenant absent", code: "P0002", want: authentication.ErrNotFound},
		{name: "stale precondition", code: "40001", want: platform.ErrPlatformTenantAccessPreconditionFailed},
		{name: "existing membership", code: "23505", want: platform.ErrPlatformTenantAccessConflict},
		{name: "invalid input", code: "22023", want: platform.ErrInvalidPlatformTenantAccess},
		{name: "constraint", code: "23514", want: platform.ErrInvalidPlatformTenantAccess},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			tx := &platformTenantAccessTransaction{
				actorID: params.ActorID, resultErr: &pgconn.PgError{Code: test.code},
			}
			next := 0
			repository := &PlatformRepository{
				begin: func(context.Context, pgx.TxOptions) (databaseTransaction, error) { return tx, nil },
				newID: func() (uuid.UUID, error) {
					value := generated[next]
					next++
					return value, nil
				},
			}
			_, err := repository.AuthorizePlatformTenantAccess(context.Background(), params)
			if !errors.Is(err, test.want) || tx.committed || !tx.rolledBack {
				t.Fatalf("error/transaction = %v/%t/%t, want %v", err, tx.committed, tx.rolledBack, test.want)
			}
		})
	}
}

func TestAuthorizePlatformTenantAccessRejectsMalformedBoundaryBeforeDatabase(t *testing.T) {
	t.Parallel()
	params, _, _ := validPlatformTenantAccessRepositoryFixture(t)
	for _, test := range []struct {
		name   string
		mutate func(*platform.AuthorizePlatformTenantAccessParams)
	}{
		{name: "invalid command", mutate: func(value *platform.AuthorizePlatformTenantAccessParams) {
			value.Command = platform.PlatformTenantAccessCommand{}
		}},
		{name: "invalid actor", mutate: func(value *platform.AuthorizePlatformTenantAccessParams) { value.ActorID = uuid.Nil }},
		{name: "invalid session", mutate: func(value *platform.AuthorizePlatformTenantAccessParams) { value.SessionID = uuid.Nil }},
		{name: "recovery method", mutate: func(value *platform.AuthorizePlatformTenantAccessParams) {
			value.AuthenticationMethod = "recovery_code"
		}},
		{name: "empty user agent", mutate: func(value *platform.AuthorizePlatformTenantAccessParams) { value.Event.UserAgent = "" }},
		{name: "invalid event", mutate: func(value *platform.AuthorizePlatformTenantAccessParams) { value.Event = authentication.EventContext{} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			candidate := params
			test.mutate(&candidate)
			beginCalls, idCalls := 0, 0
			repository := &PlatformRepository{
				begin: func(context.Context, pgx.TxOptions) (databaseTransaction, error) {
					beginCalls++
					return nil, errors.New("unexpected transaction")
				},
				newID: func() (uuid.UUID, error) { idCalls++; return uuid.NewV7() },
			}
			_, err := repository.AuthorizePlatformTenantAccess(context.Background(), candidate)
			if !errors.Is(err, authentication.ErrInvalidInput) || beginCalls != 0 || idCalls != 0 {
				t.Fatalf("error/begin/id = %v/%d/%d", err, beginCalls, idCalls)
			}
		})
	}
}

type platformTenantAccessDatabaseResult struct {
	tenantID, membershipID, userID    uuid.UUID
	tenantVersion, membershipRevision int32
	authorizationRevision             int64
	authorizedAt                      time.Time
	replayed                          bool
}

type platformTenantAccessTransaction struct {
	recordingTransaction
	actorID   uuid.UUID
	result    platformTenantAccessDatabaseResult
	resultErr error
	queries   []string
	arguments [][]any
}

func (tx *platformTenantAccessTransaction) QueryRow(
	_ context.Context,
	query string,
	arguments ...any,
) pgx.Row {
	tx.queries = append(tx.queries, query)
	tx.arguments = append(tx.arguments, append([]any(nil), arguments...))
	if strings.Contains(query, "set_config('app.user_id'") {
		return platformLifecycleRow(func(destinations ...any) error {
			*destinations[0].(*string) = tx.actorID.String()
			return nil
		})
	}
	return platformLifecycleRow(func(destinations ...any) error {
		if tx.resultErr != nil {
			return tx.resultErr
		}
		if len(destinations) != 8 {
			return errors.New("unexpected tenant-access receipt scan")
		}
		*destinations[0].(*pgtype.UUID) = toDatabaseUUID(tx.result.tenantID)
		*destinations[1].(*pgtype.UUID) = toDatabaseUUID(tx.result.membershipID)
		*destinations[2].(*pgtype.UUID) = toDatabaseUUID(tx.result.userID)
		*destinations[3].(*int32) = tx.result.tenantVersion
		*destinations[4].(*int32) = tx.result.membershipRevision
		*destinations[5].(*int64) = tx.result.authorizationRevision
		*destinations[6].(*pgtype.Timestamptz) = databaseTime(tx.result.authorizedAt)
		*destinations[7].(*bool) = tx.result.replayed
		return nil
	})
}

func validPlatformTenantAccessRepositoryFixture(
	t testing.TB,
) (platform.AuthorizePlatformTenantAccessParams, [4]uuid.UUID, time.Time) {
	t.Helper()
	tenantID := mustPostgresUUIDv7(t)
	command, err := platform.NewPlatformTenantAccessCommand(
		tenantID, 4, "Approved investigation SEC-2048", "tenant-access-key-0001",
	)
	if err != nil {
		t.Fatal(err)
	}
	return platform.AuthorizePlatformTenantAccessParams{
			ActorID: mustPostgresUUIDv7(t), SessionID: mustPostgresUUIDv7(t),
			AuthenticationMethod: "passkey", Command: command,
			Event: authentication.EventContext{
				RequestID: mustPostgresUUIDv7(t), CorrelationID: mustPostgresUUIDv7(t),
				RemoteAddress: netip.MustParseAddr("198.51.100.45"), UserAgent: "tenant-access-repository-test/1",
			},
		}, [4]uuid.UUID{
			mustPostgresUUIDv7(t), mustPostgresUUIDv7(t), mustPostgresUUIDv7(t), mustPostgresUUIDv7(t),
		}, time.Date(2026, 9, 1, 20, 30, 0, 123_456_000, time.UTC)
}
