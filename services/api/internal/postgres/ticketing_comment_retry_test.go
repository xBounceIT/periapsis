package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	application "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

type commentRetryTransaction struct {
	*dfirTransactionStub
	commitError error
	rolledBack  bool
	commits     int
}

func (tx *commentRetryTransaction) Commit(context.Context) error   { tx.commits++; return tx.commitError }
func (tx *commentRetryTransaction) Rollback(context.Context) error { tx.rolledBack = true; return nil }

func TestCommentTransactionRetriesOnlySerializationAborts(t *testing.T) {
	t.Parallel()
	serialization := &pgconn.PgError{Code: "40001", Message: "could not serialize access due to concurrent update"}
	for _, test := range []struct {
		name     string
		failures int
		commit   bool
		failure  error
		cancel   bool
		attempts int
		want     error
	}{
		{name: "statement aborts", failures: 2, failure: serialization, attempts: 3},
		{name: "commit abort", failures: 1, failure: serialization, commit: true, attempts: 2},
		{name: "revision conflict", failures: 1, failure: &pgconn.PgError{Code: "40001", Message: ticketCommentRevisionConflictMessage}, attempts: 1, want: application.ErrPreconditionFailed},
		{name: "ambiguous commit failure", failures: 1, failure: errors.New("connection lost"), commit: true, attempts: 1, want: application.ErrUnavailable},
		{name: "cancel retry", failures: 1, failure: serialization, cancel: true, attempts: 1, want: application.ErrUnavailable},
		{name: "bounded exhaustion", failures: 9, failure: serialization, attempts: 6, want: application.ErrUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			tenant, user := alertTestUUID(201), alertTestUUID(202)
			var transactions []*commentRetryTransaction
			contexts, calls := 0, 0
			repository := &TicketingRepository{begin: func(_ context.Context, options pgx.TxOptions) (databaseTransaction, error) {
				if options.IsoLevel != pgx.Serializable {
					t.Fatal("transaction isolation changed")
				}
				if len(transactions) > 0 && !transactions[len(transactions)-1].rolledBack {
					t.Fatal("retry began before prior transaction ended")
				}
				tx := &commentRetryTransaction{dfirTransactionStub: &dfirTransactionStub{row: func(query string, _ []any, d []any) error {
					if strings.Contains(query, "app.tenant_id") {
						contexts++
						*(d[0].(*string)), *(d[1].(*string)) = tenant.String(), user.String()
					}
					return nil
				}}}
				if test.commit && len(transactions) < test.failures {
					tx.commitError = test.failure
				}
				transactions = append(transactions, tx)
				return tx, nil
			}}
			value, err := withinTicketCommentWriteTransaction(ctx, repository, application.Actor{UserID: user, ActiveTenantID: tenant}, tenant, func(databaseTransaction) (int, error) {
				calls++
				if test.cancel {
					cancel()
				}
				if !test.commit && calls <= test.failures {
					return 99, mapTicketCommentDatabaseError(test.failure)
				}
				return 42, nil
			})
			if !errors.Is(err, test.want) || len(transactions) != test.attempts || contexts != test.attempts || calls != test.attempts {
				t.Fatalf("result error=%v attempts=%d contexts=%d calls=%d", err, len(transactions), contexts, calls)
			}
			if err == nil && value != 42 || err != nil && value != 0 {
				t.Fatal("uncommitted result escaped")
			}
			for _, tx := range transactions {
				if !tx.rolledBack {
					t.Fatal("transaction cleanup skipped")
				}
			}
		})
	}
}
