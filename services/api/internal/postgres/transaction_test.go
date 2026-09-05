package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type recordingTransaction struct {
	committed  bool
	rolledBack bool
}

func (*recordingTransaction) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	panic("unexpected Exec")
}

func (*recordingTransaction) Query(context.Context, string, ...any) (pgx.Rows, error) {
	panic("unexpected Query")
}

func (*recordingTransaction) QueryRow(context.Context, string, ...any) pgx.Row {
	panic("unexpected QueryRow")
}

func (tx *recordingTransaction) Commit(context.Context) error {
	tx.committed = true
	return nil
}

func (tx *recordingTransaction) Rollback(context.Context) error {
	tx.rolledBack = true
	return nil
}

func TestWithinTransactionRollsBackWhenHydrationFails(t *testing.T) {
	tx := &recordingTransaction{}
	hydrationErr := errors.New("hydrate session")
	_, err := withinTransaction(context.Background(),
		func(context.Context, pgx.TxOptions) (databaseTransaction, error) { return tx, nil },
		func(databaseTransaction) (struct{}, error) { return struct{}{}, hydrationErr },
	)
	if !errors.Is(err, hydrationErr) {
		t.Fatalf("withinTransaction() error = %v, want hydration error", err)
	}
	if tx.committed || !tx.rolledBack {
		t.Fatalf("transaction committed = %t, rolled back = %t", tx.committed, tx.rolledBack)
	}
}
