package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	application "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

func TestTicketingRepositoryListWatchersUsesBoundReadABI(t *testing.T) {
	t.Parallel()
	query, targetID := watcherAdapterListQuery(t, kernel.AggregateAlert)
	now := time.Date(2026, 9, 1, 9, 10, 11, 123_456_000, time.UTC)
	payload := watcherAdapterPayload(query.TenantID, query.TicketID, query.Kind, now, 7,
		ticketWatcherPayload{UserID: targetID, DisplayName: "Incident Responder", AddedAt: now.Add(-time.Minute)},
	)
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	abiCalls := 0
	tx := &platformLocalAccountAdapterTransaction{}
	tx.queryRow = func(sql string, arguments []any, destinations []any) error {
		switch {
		case strings.Contains(sql, "app.tenant_id"):
			*destinations[0].(*string) = query.TenantID.String()
			*destinations[1].(*string) = query.Actor.UserID.String()
		case strings.Contains(sql, "app.traceparent"):
			*destinations[0].(*string), *destinations[1].(*string) = "", ""
		case strings.Contains(sql, "list_tenant_ticket_watchers_v1"):
			abiCalls++
			if len(arguments) != 2 || arguments[0] != "alert" || arguments[1] != query.TicketID {
				t.Fatalf("list ABI arguments=%#v", arguments)
			}
			*destinations[0].(*int64) = 7
			*destinations[1].(*time.Time) = now
			*destinations[2].(*[]byte) = raw
		default:
			t.Fatalf("unexpected query: %s", sql)
		}
		return nil
	}
	beginCalls := 0
	repository := &TicketingRepository{begin: func(_ context.Context, options pgx.TxOptions) (databaseTransaction, error) {
		beginCalls++
		if options.IsoLevel != pgx.RepeatableRead || options.AccessMode != pgx.ReadOnly {
			t.Fatalf("read transaction options=%#v", options)
		}
		return tx, nil
	}}
	result, err := repository.ListWatchers(context.Background(), query)
	if err != nil || result.TenantID != query.TenantID || result.TicketID != query.TicketID ||
		result.Kind != kernel.AggregateAlert || result.Version != 7 || !result.UpdatedAt.Equal(now) ||
		len(result.Items) != 1 || result.Items[0].UserID != targetID {
		t.Fatalf("ListWatchers() = (%#v, %v)", result, err)
	}
	if beginCalls != 1 || abiCalls != 1 || !tx.committed || tx.rollbackCalls != 1 {
		t.Fatalf("begin=%d abi=%d committed=%t rollbacks=%d", beginCalls, abiCalls, tx.committed, tx.rollbackCalls)
	}
}

func TestTicketingRepositoryMutateWatcherUsesBoundTransactionalABI(t *testing.T) {
	t.Parallel()
	write := watcherAdapterWrite(t, kernel.AggregateCase, application.WatcherRemove)
	now := time.Date(2026, 9, 1, 9, 15, 12, 654_321_000, time.UTC)
	payload := watcherAdapterPayload(write.TenantID, write.TicketID, write.Kind, now, 12)
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	abiCalls := 0
	tx := &platformLocalAccountAdapterTransaction{}
	tx.queryRow = func(sql string, arguments []any, destinations []any) error {
		switch {
		case strings.Contains(sql, "app.tenant_id"):
			*destinations[0].(*string) = write.TenantID.String()
			*destinations[1].(*string) = write.Actor.UserID.String()
		case strings.Contains(sql, "app.traceparent"):
			*destinations[0].(*string), *destinations[1].(*string) = "", ""
		case strings.Contains(sql, "mutate_tenant_ticket_watcher_v1"):
			abiCalls++
			if len(arguments) != 12 || arguments[0] != "case" || arguments[1] != write.TicketID ||
				arguments[2] != int64(11) || arguments[3] != "remove" || arguments[4] != write.TargetUserID {
				t.Fatalf("mutation ABI identity arguments=%#v", arguments)
			}
			if key, ok := arguments[5].([]byte); !ok || string(key) != string(write.KeyHash[:]) {
				t.Fatal("mutation ABI key digest mismatch")
			}
			if request, ok := arguments[6].([]byte); !ok || string(request) != string(write.Fingerprint[:]) {
				t.Fatal("mutation ABI request digest mismatch")
			}
			if arguments[7] != write.Audit.RequestID || arguments[8] != write.Audit.CorrelationID ||
				arguments[9] != write.Audit.RemoteAddress.Unmap() || arguments[10] != write.Audit.UserAgent ||
				arguments[11] != write.Actor.AuthenticationMethod {
				t.Fatalf("mutation ABI audit arguments=%#v", arguments[7:])
			}
			*destinations[0].(*int64) = 12
			*destinations[1].(*time.Time) = now
			*destinations[2].(*[]byte) = raw
			*destinations[3].(*bool) = false
		default:
			t.Fatalf("unexpected query: %s", sql)
		}
		return nil
	}
	repository := &TicketingRepository{begin: platformLocalAccountAdapterBegin(t, tx)}
	result, err := repository.MutateWatcher(context.Background(), write)
	if err != nil || result.Replayed || result.Projection.Version != 12 ||
		result.Projection.TenantID != write.TenantID || len(result.Projection.Items) != 0 {
		t.Fatalf("MutateWatcher() = (%#v, %v)", result, err)
	}
	if abiCalls != 1 || !tx.committed || tx.rollbackCalls != 1 {
		t.Fatalf("abi=%d committed=%t rollbacks=%d", abiCalls, tx.committed, tx.rollbackCalls)
	}
}

func TestTicketingRepositoryMutateWatcherMapsDeniedStaleConflictAndTimeout(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		db   error
		want error
	}{
		{name: "inactive add target", db: &pgconn.PgError{Code: "42501"}, want: application.ErrForbidden},
		{name: "target lacks live read", db: &pgconn.PgError{Code: "42501"}, want: application.ErrForbidden},
		{name: "stale version", db: &pgconn.PgError{Code: "40001"}, want: application.ErrPreconditionFailed},
		{name: "idempotency conflict", db: &pgconn.PgError{Code: "23505"}, want: application.ErrConflict},
		{name: "deadline", db: context.DeadlineExceeded, want: application.ErrUnavailable},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			write := watcherAdapterWrite(t, kernel.AggregateAlert, application.WatcherAdd)
			tx := &platformLocalAccountAdapterTransaction{}
			tx.queryRow = func(sql string, _ []any, destinations []any) error {
				switch {
				case strings.Contains(sql, "app.tenant_id"):
					*destinations[0].(*string) = write.TenantID.String()
					*destinations[1].(*string) = write.Actor.UserID.String()
					return nil
				case strings.Contains(sql, "app.traceparent"):
					*destinations[0].(*string), *destinations[1].(*string) = "", ""
					return nil
				case strings.Contains(sql, "mutate_tenant_ticket_watcher_v1"):
					return test.db
				default:
					return errors.New("unexpected query")
				}
			}
			repository := &TicketingRepository{begin: platformLocalAccountAdapterBegin(t, tx)}
			_, err := repository.MutateWatcher(context.Background(), write)
			if !errors.Is(err, test.want) || tx.committed {
				t.Fatalf("error=%v committed=%t", err, tx.committed)
			}
		})
	}
}

func TestDecodeTicketWatcherProjectionFailsClosedOnDrift(t *testing.T) {
	t.Parallel()
	query, targetID := watcherAdapterListQuery(t, kernel.AggregateAlert)
	now := time.Date(2026, 9, 1, 9, 20, 0, 0, time.UTC)
	payload := watcherAdapterPayload(query.TenantID, query.TicketID, query.Kind, now, 4,
		ticketWatcherPayload{UserID: targetID, DisplayName: "Alpha Responder", AddedAt: now.Add(-time.Minute)},
		ticketWatcherPayload{UserID: mustPostgresUUIDv7(t), DisplayName: "Zulu Responder", AddedAt: now.Add(-time.Minute)},
	)
	base, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "unknown top-level field", mutate: func(value map[string]any) { value["membership_id"] = targetID }},
		{name: "missing watchers", mutate: func(value map[string]any) { delete(value, "watchers") }},
		{name: "null watchers", mutate: func(value map[string]any) { value["watchers"] = nil }},
		{name: "wrong tenant", mutate: func(value map[string]any) { value["tenant_id"] = mustPostgresUUIDv7(t) }},
		{name: "wrong scalar version", mutate: func(value map[string]any) { value["version"] = 5 }},
		{name: "duplicate user", mutate: func(value map[string]any) {
			items := value["watchers"].([]any)
			value["watchers"] = append(items, items[0])
		}},
		{name: "unknown watcher field", mutate: func(value map[string]any) {
			items := value["watchers"].([]any)
			items[0].(map[string]any)["membership_id"] = mustPostgresUUIDv7(t)
		}},
		{name: "watcher added after update", mutate: func(value map[string]any) {
			items := value["watchers"].([]any)
			items[0].(map[string]any)["added_at"] = now.Add(time.Second)
		}},
		{name: "noncanonical bytewise order", mutate: func(value map[string]any) {
			items := value["watchers"].([]any)
			items[0], items[1] = items[1], items[0]
		}},
		{name: "over maximum cardinality", mutate: func(value map[string]any) {
			items := make([]any, maximumTicketWatcherItems+1)
			for index := range items {
				items[index] = map[string]any{
					"user_id": mustPostgresUUIDv7(t), "display_name": fmt.Sprintf("Watcher %04d", index),
					"added_at": now.Add(-time.Minute),
				}
			}
			value["watchers"] = items
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var value map[string]any
			if err := json.Unmarshal(base, &value); err != nil {
				t.Fatal(err)
			}
			test.mutate(value)
			raw, marshalErr := json.Marshal(value)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			_, decodeErr := decodeTicketWatcherProjection(
				raw, 4, now, query.TenantID, query.TicketID, query.Kind,
			)
			if !errors.Is(decodeErr, application.ErrUnavailable) {
				t.Fatalf("decode error=%v", decodeErr)
			}
		})
	}
	if _, decodeErr := decodeTicketWatcherProjection(
		append(append([]byte{}, base...), []byte(` {}`)...),
		4, now, query.TenantID, query.TicketID, query.Kind,
	); !errors.Is(decodeErr, application.ErrUnavailable) {
		t.Fatalf("trailing JSON decode error=%v", decodeErr)
	}
	duplicateDocuments := [][]byte{
		[]byte(fmt.Sprintf(
			`{"schema_version":1,"schema_version":1,"tenant_id":%q,"ticket_id":%q,"aggregate_kind":"alert","version":4,"updated_at":%q,"watchers":[]}`,
			query.TenantID, query.TicketID, now.Format(time.RFC3339Nano),
		)),
		[]byte(fmt.Sprintf(
			`{"schema_version":1,"tenant_id":%q,"ticket_id":%q,"aggregate_kind":"alert","version":4,"updated_at":%q,"watchers":[{"user_id":%q,"display_name":"Watcher","display_name":"Duplicate","added_at":%q}]}`,
			query.TenantID, query.TicketID, now.Format(time.RFC3339Nano), targetID,
			now.Add(-time.Minute).Format(time.RFC3339Nano),
		)),
	}
	for _, document := range duplicateDocuments {
		if _, decodeErr := decodeTicketWatcherProjection(
			document, 4, now, query.TenantID, query.TicketID, query.Kind,
		); !errors.Is(decodeErr, application.ErrUnavailable) {
			t.Fatalf("duplicate JSON key decode error=%v", decodeErr)
		}
	}
}

func TestTicketingRepositoryWatchersRejectCancelledContextBeforeTransaction(t *testing.T) {
	t.Parallel()
	query, _ := watcherAdapterListQuery(t, kernel.AggregateAlert)
	write := watcherAdapterWrite(t, kernel.AggregateAlert, application.WatcherAdd)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	beginCalls := 0
	repository := &TicketingRepository{begin: func(context.Context, pgx.TxOptions) (databaseTransaction, error) {
		beginCalls++
		return nil, errors.New("must not begin")
	}}
	if _, err := repository.ListWatchers(cancelled, query); !errors.Is(err, application.ErrUnavailable) {
		t.Fatalf("list cancellation error=%v", err)
	}
	if _, err := repository.MutateWatcher(cancelled, write); !errors.Is(err, application.ErrUnavailable) {
		t.Fatalf("mutation cancellation error=%v", err)
	}
	if beginCalls != 0 {
		t.Fatalf("begin calls=%d", beginCalls)
	}
}

func watcherAdapterListQuery(t testing.TB, kind kernel.AggregateKind) (application.WatcherListQuery, uuid.UUID) {
	t.Helper()
	tenantID, ticketID, actorID := mustPostgresUUIDv7(t), mustPostgresUUIDv7(t), mustPostgresUUIDv7(t)
	actor := application.Actor{
		UserID: actorID, SessionID: mustPostgresUUIDv7(t), ActiveTenantID: tenantID,
		AuthenticationMethod: "totp",
	}
	return application.WatcherListQuery{
		Actor: actor, TenantID: tenantID, Kind: kind, TicketID: ticketID,
	}, mustPostgresUUIDv7(t)
}

func watcherAdapterWrite(
	t testing.TB,
	kind kernel.AggregateKind,
	action application.WatcherMutationAction,
) application.WatcherMutationWrite {
	t.Helper()
	query, targetID := watcherAdapterListQuery(t, kind)
	audit := application.AuditContext{
		RequestID: mustPostgresUUIDv7(t), CorrelationID: mustPostgresUUIDv7(t),
		RemoteAddress: netip.MustParseAddr("192.0.2.90"), UserAgent: "watcher-adapter-test",
	}
	query.Actor.Audit = audit
	keyHash := sha256.Sum256([]byte("watcher-key"))
	requestHash := sha256.Sum256([]byte("watcher-request"))
	return application.WatcherMutationWrite{
		Actor: query.Actor, TenantID: query.TenantID, Kind: kind, TicketID: query.TicketID,
		TargetUserID: targetID, Action: action, ExpectedVersion: 11,
		KeyHash: keyHash, Fingerprint: requestHash, Audit: audit,
	}
}

func watcherAdapterPayload(
	tenantID uuid.UUID,
	ticketID uuid.UUID,
	kind kernel.AggregateKind,
	updatedAt time.Time,
	version int64,
	watchers ...ticketWatcherPayload,
) ticketWatcherProjectionPayload {
	return ticketWatcherProjectionPayload{
		SchemaVersion: 1, TenantID: tenantID, TicketID: ticketID,
		AggregateKind: kind.String(), Version: version, UpdatedAt: updatedAt,
		Watchers: append([]ticketWatcherPayload{}, watchers...),
	}
}
