package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/trace"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/notification"
)

type traceContextRow struct {
	values []string
	err    error
}

func (r traceContextRow) Scan(destinations ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(destinations) != len(r.values) {
		return errors.New("unexpected trace row destination count")
	}
	for index, value := range r.values {
		destination, ok := destinations[index].(*string)
		if !ok {
			return errors.New("unexpected trace row destination")
		}
		*destination = value
	}
	return nil
}

type traceContextTransaction struct {
	rows      []pgx.Row
	queries   []string
	arguments [][]any
	committed bool
}

func (*traceContextTransaction) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, errors.New("unexpected Exec")
}

func (*traceContextTransaction) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("unexpected Query")
}

func (tx *traceContextTransaction) QueryRow(_ context.Context, query string, arguments ...any) pgx.Row {
	tx.queries = append(tx.queries, query)
	tx.arguments = append(tx.arguments, append([]any(nil), arguments...))
	if len(tx.rows) == 0 {
		return traceContextRow{err: errors.New("unexpected QueryRow")}
	}
	row := tx.rows[0]
	tx.rows = tx.rows[1:]
	return row
}

func (tx *traceContextTransaction) Commit(context.Context) error {
	tx.committed = true
	return nil
}

func (*traceContextTransaction) Rollback(context.Context) error { return nil }

func TestInstallPersistedTraceContextUsesOnlyCanonicalLocalSpan(t *testing.T) {
	traceID, err := trace.TraceIDFromHex("11111111111111111111111111111111")
	if err != nil {
		t.Fatal(err)
	}
	spanID, err := trace.SpanIDFromHex("2222222222222222")
	if err != nil {
		t.Fatal(err)
	}
	state, err := trace.ParseTraceState("vendor=value")
	if err != nil {
		t.Fatal(err)
	}
	span := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: traceID, SpanID: spanID, TraceFlags: trace.FlagsSampled,
		TraceState: state,
	})
	member, err := baggage.NewMember("private-token", "must-not-persist")
	if err != nil {
		t.Fatal(err)
	}
	bag, err := baggage.New(member)
	if err != nil {
		t.Fatal(err)
	}
	ctx := baggage.ContextWithBaggage(
		trace.ContextWithSpanContext(context.Background(), span),
		bag,
	)
	wantParent := "00-11111111111111111111111111111111-2222222222222222-01"
	tx := &traceContextTransaction{rows: []pgx.Row{
		traceContextRow{values: []string{wantParent, "vendor=value"}},
	}}
	if err := installPersistedTraceContext(ctx, tx); err != nil {
		t.Fatalf("installPersistedTraceContext() error = %v", err)
	}
	if len(tx.arguments) != 1 || len(tx.arguments[0]) != 2 ||
		tx.arguments[0][0] != wantParent || tx.arguments[0][1] != "vendor=value" ||
		strings.Contains(tx.queries[0], "private-token") || strings.Contains(tx.queries[0], "must-not-persist") {
		t.Fatalf("persisted trace query=%q arguments=%#v", tx.queries, tx.arguments)
	}
}

func TestInstallPersistedTraceContextClearsAbsentAndRemoteContext(t *testing.T) {
	remoteID, _ := trace.TraceIDFromHex("33333333333333333333333333333333")
	remoteSpanID, _ := trace.SpanIDFromHex("4444444444444444")
	contexts := []context.Context{
		context.Background(),
		trace.ContextWithSpanContext(context.Background(), trace.NewSpanContext(trace.SpanContextConfig{
			TraceID: remoteID, SpanID: remoteSpanID, Remote: true,
		})),
	}
	for index, ctx := range contexts {
		t.Run(string(rune('a'+index)), func(t *testing.T) {
			tx := &traceContextTransaction{rows: []pgx.Row{
				traceContextRow{values: []string{"", ""}},
			}}
			if err := installPersistedTraceContext(ctx, tx); err != nil {
				t.Fatalf("installPersistedTraceContext() error = %v", err)
			}
			if len(tx.arguments) != 1 || len(tx.arguments[0]) != 2 ||
				tx.arguments[0][0] != "" || tx.arguments[0][1] != "" {
				t.Fatalf("arguments = %#v, want two empty strings", tx.arguments)
			}
		})
	}
}

func TestInstallPersistedTraceContextFailsClosedOnDatabaseMismatch(t *testing.T) {
	databaseError := errors.New("trace context database error")
	for name, row := range map[string]pgx.Row{
		"query error": traceContextRow{err: databaseError},
		"mismatch":    traceContextRow{values: []string{"unexpected", ""}},
	} {
		t.Run(name, func(t *testing.T) {
			tx := &traceContextTransaction{rows: []pgx.Row{row}}
			if err := installPersistedTraceContext(context.Background(), tx); err == nil {
				t.Fatal("installPersistedTraceContext() accepted failed persistence")
			}
		})
	}
}

func TestTenantNotificationTransactionInstallsTraceBeforeMutationABI(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	tx := &traceContextTransaction{rows: []pgx.Row{
		traceContextRow{values: []string{tenantID.String(), userID.String()}},
		traceContextRow{values: []string{"", ""}},
	}}
	repository := &NotificationRepository{begin: func(context.Context, pgx.TxOptions) (databaseTransaction, error) {
		return tx, nil
	}}
	events := make([]string, 0, 3)
	value, err := withinTenantNotificationTransaction(
		context.Background(), repository,
		notification.HumanParams{TenantID: tenantID, Actor: authorization.Actor{
			UserID: userID, ActiveTenantID: tenantID,
		}}, false,
		func(databaseTransaction) (string, error) {
			events = append(events, "mutation-abi")
			return "ok", nil
		},
	)
	if err != nil || value != "ok" || !tx.committed || len(tx.queries) != 2 {
		t.Fatalf("transaction = value:%q error:%v committed:%t queries:%d", value, err, tx.committed, len(tx.queries))
	}
	if !strings.Contains(tx.queries[0], "app.tenant_id") ||
		!strings.Contains(tx.queries[1], "app.traceparent") ||
		len(events) != 1 || events[0] != "mutation-abi" {
		t.Fatalf("query order=%#v events=%#v", tx.queries, events)
	}
}

func TestDFIRWorkerMutationContextInstallsTenantThenTraceBeforeProducer(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV7())
	testCases := []struct {
		name       string
		traceRow   pgx.Row
		wantError  bool
		wantCalled bool
	}{
		{name: "exact", traceRow: traceContextRow{values: []string{"", ""}}, wantCalled: true},
		{name: "trace mismatch", traceRow: traceContextRow{values: []string{"unexpected", ""}}, wantError: true},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			tx := &traceContextTransaction{rows: []pgx.Row{
				traceContextRow{values: []string{tenantID.String()}},
				testCase.traceRow,
			}}
			producerCalled := false
			err := installDFIRWorkerMutationContext(context.Background(), tx, tenantID)
			if err == nil {
				producerCalled = true
			}
			if (err != nil) != testCase.wantError || producerCalled != testCase.wantCalled {
				t.Fatalf("context error=%v producerCalled=%t", err, producerCalled)
			}
			if len(tx.queries) != 2 || !strings.Contains(tx.queries[0], "app.tenant_id") ||
				!strings.Contains(tx.queries[1], "app.traceparent") {
				t.Fatalf("context query order = %#v", tx.queries)
			}
		})
	}
}
