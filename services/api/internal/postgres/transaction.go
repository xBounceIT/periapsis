package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type databaseTransaction interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
	Commit(context.Context) error
	Rollback(context.Context) error
}

type transactionBeginner func(context.Context, pgx.TxOptions) (databaseTransaction, error)

func poolTransactionBeginner(pool *pgxpool.Pool) transactionBeginner {
	return func(ctx context.Context, options pgx.TxOptions) (databaseTransaction, error) {
		return pool.BeginTx(ctx, options)
	}
}

func withinTransaction[T any](
	ctx context.Context,
	begin transactionBeginner,
	work func(databaseTransaction) (T, error),
) (T, error) {
	return withinTransactionWithOptions(
		ctx, begin, pgx.TxOptions{IsoLevel: pgx.ReadCommitted}, work,
	)
}

func withinTransactionWithOptions[T any](
	ctx context.Context,
	begin transactionBeginner,
	options pgx.TxOptions,
	work func(databaseTransaction) (T, error),
) (result T, err error) {
	if begin == nil || work == nil {
		return result, errors.New("database transaction dependencies are required")
	}
	tx, err := begin(ctx, options)
	if err != nil {
		return result, fmt.Errorf("begin database transaction: %w", err)
	}
	defer func() {
		rollbackContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		rollbackErr := tx.Rollback(rollbackContext)
		if err == nil && rollbackErr != nil && !errors.Is(rollbackErr, pgx.ErrTxClosed) {
			err = fmt.Errorf("rollback database transaction: %w", rollbackErr)
		}
	}()

	result, err = work(tx)
	if err != nil {
		return result, err
	}
	if err = tx.Commit(ctx); err != nil {
		return result, fmt.Errorf("commit database transaction: %w", err)
	}
	return result, nil
}
