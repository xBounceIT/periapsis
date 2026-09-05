package postgres

import (
	"context"
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
	"github.com/periapsis-im/periapsis/services/api/internal/postgres/dbsql"
)

func TestChangeTenantLifecycleBindsExactAuthorityAndAuditAttribution(t *testing.T) {
	params, auditID, updatedAt := validPlatformLifecycleRepositoryFixture(t)
	tx := &platformLifecycleTransaction{
		actorID: params.ActorID,
		result: platformLifecycleDatabaseResult{
			tenantID: params.Command.TenantID(), previous: "active", current: "suspended",
			version: params.Command.ExpectedVersion() + 1, updatedAt: updatedAt,
		},
	}
	repository := &PlatformRepository{
		begin: func(_ context.Context, options pgx.TxOptions) (databaseTransaction, error) {
			if options.IsoLevel != pgx.ReadCommitted {
				t.Fatalf("transaction isolation = %q, want read committed", options.IsoLevel)
			}
			return tx, nil
		},
		newID: func() (uuid.UUID, error) { return auditID, nil },
	}

	receipt, err := repository.ChangeTenantLifecycle(context.Background(), params)
	if err != nil {
		t.Fatalf("ChangeTenantLifecycle() error = %v", err)
	}
	if receipt.TenantID() != params.Command.TenantID() ||
		receipt.Previous() != platform.TenantLifecycleActive ||
		receipt.Current() != platform.TenantLifecycleSuspended ||
		receipt.Version() != params.Command.ExpectedVersion()+1 ||
		!receipt.UpdatedAt().Equal(updatedAt) || receipt.Replayed() {
		t.Fatalf("ChangeTenantLifecycle() receipt = %#v", receipt)
	}
	if !tx.committed || !tx.rolledBack {
		t.Fatalf("transaction committed = %t, rolled back = %t", tx.committed, tx.rolledBack)
	}
	if len(tx.queries) != 2 || !strings.Contains(tx.queries[0], "set_config('app.user_id'") ||
		!strings.Contains(tx.queries[1], "app.change_platform_tenant_lifecycle") {
		t.Fatalf("database queries = %#v", tx.queries)
	}
	if len(tx.arguments[0]) != 1 || !reflect.DeepEqual(
		tx.arguments[0][0], toDatabaseUUID(params.ActorID),
	) {
		t.Fatalf("user context arguments = %#v", tx.arguments[0])
	}
	want := []any{
		toDatabaseUUID(params.SessionID), toDatabaseUUID(params.Command.TenantID()),
		dbsql.TenantStatus(params.Command.Target()), params.Command.ExpectedVersion(),
		params.Command.Reason(), toDatabaseUUID(auditID),
		toDatabaseUUID(params.Event.RequestID), toDatabaseUUID(params.Event.CorrelationID),
		params.Event.RemoteAddress, params.Event.UserAgent, params.AuthenticationMethod,
	}
	if !reflect.DeepEqual(tx.arguments[1], want) {
		t.Fatalf("lifecycle arguments = %#v, want %#v", tx.arguments[1], want)
	}
}

func TestChangeTenantLifecycleMapsClosedDatabaseOutcomes(t *testing.T) {
	t.Parallel()
	params, auditID, _ := validPlatformLifecycleRepositoryFixture(t)
	tests := []struct {
		name string
		code string
		want error
	}{
		{name: "permission", code: "42501", want: authentication.ErrForbidden},
		{name: "missing tenant", code: "P0002", want: authentication.ErrNotFound},
		{name: "revision conflict", code: "40001", want: platform.ErrTenantLifecycleConflict},
		{name: "invalid command", code: "22023", want: platform.ErrInvalidTenantLifecycle},
		{name: "constraint", code: "23514", want: platform.ErrInvalidTenantLifecycle},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			tx := &platformLifecycleTransaction{
				actorID: params.ActorID, resultErr: &pgconn.PgError{Code: test.code},
			}
			repository := &PlatformRepository{
				begin: func(context.Context, pgx.TxOptions) (databaseTransaction, error) {
					return tx, nil
				},
				newID: func() (uuid.UUID, error) { return auditID, nil },
			}
			_, err := repository.ChangeTenantLifecycle(context.Background(), params)
			if !errors.Is(err, test.want) {
				t.Fatalf("ChangeTenantLifecycle() error = %v, want %v", err, test.want)
			}
			if tx.committed || !tx.rolledBack {
				t.Fatalf("transaction committed = %t, rolled back = %t", tx.committed, tx.rolledBack)
			}
		})
	}
}

func TestChangeTenantLifecycleRejectsMalformedBoundaryBeforeDatabase(t *testing.T) {
	t.Parallel()
	params, _, _ := validPlatformLifecycleRepositoryFixture(t)
	tests := []struct {
		name   string
		mutate func(*platform.ChangeTenantLifecycleParams)
	}{
		{name: "invalid command", mutate: func(value *platform.ChangeTenantLifecycleParams) {
			value.Command = platform.TenantLifecycleCommand{}
		}},
		{name: "invalid actor", mutate: func(value *platform.ChangeTenantLifecycleParams) {
			value.ActorID = uuid.Nil
		}},
		{name: "invalid session", mutate: func(value *platform.ChangeTenantLifecycleParams) {
			value.SessionID = uuid.Nil
		}},
		{name: "unknown authentication", mutate: func(value *platform.ChangeTenantLifecycleParams) {
			value.AuthenticationMethod = "future_method"
		}},
		{name: "invalid event", mutate: func(value *platform.ChangeTenantLifecycleParams) {
			value.Event = authentication.EventContext{}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			candidate := params
			test.mutate(&candidate)
			beginCalls := 0
			repository := &PlatformRepository{
				begin: func(context.Context, pgx.TxOptions) (databaseTransaction, error) {
					beginCalls++
					return nil, errors.New("unexpected transaction")
				},
				newID: uuid.NewV7,
			}
			_, err := repository.ChangeTenantLifecycle(context.Background(), candidate)
			if !errors.Is(err, authentication.ErrInvalidInput) {
				t.Fatalf("ChangeTenantLifecycle() error = %v, want invalid input", err)
			}
			if beginCalls != 0 {
				t.Fatalf("database transaction calls = %d, want zero", beginCalls)
			}
		})
	}
}

type platformLifecycleDatabaseResult struct {
	tenantID  uuid.UUID
	previous  string
	current   string
	version   int32
	updatedAt time.Time
	replayed  bool
}

type platformLifecycleTransaction struct {
	recordingTransaction
	actorID   uuid.UUID
	result    platformLifecycleDatabaseResult
	resultErr error
	queries   []string
	arguments [][]any
}

func (tx *platformLifecycleTransaction) QueryRow(
	_ context.Context,
	query string,
	arguments ...any,
) pgx.Row {
	tx.queries = append(tx.queries, query)
	tx.arguments = append(tx.arguments, append([]any(nil), arguments...))
	if strings.Contains(query, "set_config('app.user_id'") {
		return platformLifecycleRow(func(destinations ...any) error {
			if len(destinations) != 1 {
				return errors.New("unexpected user context scan")
			}
			*destinations[0].(*string) = tx.actorID.String()
			return nil
		})
	}
	return platformLifecycleRow(func(destinations ...any) error {
		if tx.resultErr != nil {
			return tx.resultErr
		}
		if len(destinations) != 6 {
			return errors.New("unexpected lifecycle receipt scan")
		}
		*destinations[0].(*pgtype.UUID) = toDatabaseUUID(tx.result.tenantID)
		*destinations[1].(*string) = tx.result.previous
		*destinations[2].(*string) = tx.result.current
		*destinations[3].(*int32) = tx.result.version
		*destinations[4].(*pgtype.Timestamptz) = databaseTime(tx.result.updatedAt)
		*destinations[5].(*bool) = tx.result.replayed
		return nil
	})
}

type platformLifecycleRow func(...any) error

func (row platformLifecycleRow) Scan(destinations ...any) error {
	return row(destinations...)
}

func validPlatformLifecycleRepositoryFixture(
	t testing.TB,
) (platform.ChangeTenantLifecycleParams, uuid.UUID, time.Time) {
	t.Helper()
	tenantID := mustPostgresUUIDv7(t)
	command, err := platform.NewTenantLifecycleCommand(
		tenantID, platform.TenantLifecycleSuspended, 4, "Approved incident containment hold",
	)
	if err != nil {
		t.Fatal(err)
	}
	return platform.ChangeTenantLifecycleParams{
		ActorID: mustPostgresUUIDv7(t), SessionID: mustPostgresUUIDv7(t),
		AuthenticationMethod: "passkey", Command: command,
		Event: authentication.EventContext{
			RequestID: mustPostgresUUIDv7(t), CorrelationID: mustPostgresUUIDv7(t),
			RemoteAddress: netip.MustParseAddr("198.51.100.44"), UserAgent: "platform-lifecycle-test/1",
		},
	}, mustPostgresUUIDv7(t), time.Date(2026, 8, 26, 16, 20, 0, 123_456_000, time.UTC)
}
