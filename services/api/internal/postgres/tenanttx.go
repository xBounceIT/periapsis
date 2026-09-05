package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/periapsis-im/periapsis/services/api/internal/postgres/dbsql"
)

// TransactionStarter is implemented by pgxpool.Pool.
type TransactionStarter interface {
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
}

// TenantTransaction installs transaction-local tenant and actor context before any query.
type TenantTransaction struct {
	pool TransactionStarter
}

// NewTenantTransaction creates a tenant-scoped transaction boundary.
func NewTenantTransaction(pool TransactionStarter) TenantTransaction {
	return TenantTransaction{pool: pool}
}

// Within executes work only after PostgreSQL has accepted both transaction-local settings.
func (t TenantTransaction) Within(
	ctx context.Context,
	tenantID uuid.UUID,
	actorID uuid.UUID,
	work func(*TenantQueries) error,
) (err error) {
	if tenantID == uuid.Nil || actorID == uuid.Nil {
		return errors.New("tenant and actor identifiers are required")
	}
	if work == nil {
		return errors.New("tenant transaction work is required")
	}

	tx, err := t.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return fmt.Errorf("begin tenant transaction: %w", err)
	}
	defer func() {
		rollbackErr := tx.Rollback(ctx)
		if err == nil && rollbackErr != nil && !errors.Is(rollbackErr, pgx.ErrTxClosed) {
			err = fmt.Errorf("rollback tenant transaction: %w", rollbackErr)
		}
	}()

	queries := dbsql.New(tx)
	tenantUUID := pgtype.UUID{Bytes: tenantID, Valid: true}
	_, err = queries.SetTenantContext(ctx, dbsql.SetTenantContextParams{
		TenantID: tenantUUID,
		UserID:   pgtype.UUID{Bytes: actorID, Valid: true},
	})
	if err != nil {
		return fmt.Errorf("set tenant transaction context: %w", err)
	}
	if err = work(newTenantQueries(queries, tenantUUID)); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit tenant transaction: %w", err)
	}
	return nil
}
