package postgres

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/periapsis-im/periapsis/services/api/internal/postgres/dbsql"
)

type alertQueries interface {
	GetAlert(context.Context, dbsql.GetAlertParams) (*dbsql.GetAlertRow, error)
	ListAlerts(context.Context, dbsql.ListAlertsParams) ([]*dbsql.ListAlertsRow, error)
}

// TenantQueries binds defense-in-depth SQL predicates to the transaction's authorized tenant.
// Callers cannot substitute a different tenant identifier for tenant-owned alert queries.
type TenantQueries struct {
	alerts   alertQueries
	tenantID pgtype.UUID
}

func newTenantQueries(queries alertQueries, tenantID pgtype.UUID) *TenantQueries {
	return &TenantQueries{alerts: queries, tenantID: tenantID}
}

// GetAlert returns an alert only when both its ID and the transaction tenant match.
func (q *TenantQueries) GetAlert(
	ctx context.Context,
	alertID pgtype.UUID,
) (*dbsql.GetAlertRow, error) {
	return q.alerts.GetAlert(ctx, dbsql.GetAlertParams{
		TenantID: q.tenantID,
		ID:       alertID,
	})
}

// ListAlerts lists alerts within the bound tenant using UUID cursor pagination.
func (q *TenantQueries) ListAlerts(
	ctx context.Context,
	afterID pgtype.UUID,
	pageSize int32,
) ([]*dbsql.ListAlertsRow, error) {
	return q.alerts.ListAlerts(ctx, dbsql.ListAlertsParams{
		TenantID: q.tenantID,
		AfterID:  afterID,
		PageSize: pageSize,
	})
}
