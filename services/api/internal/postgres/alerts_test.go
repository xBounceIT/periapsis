package postgres

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/periapsis-im/periapsis/services/api/internal/postgres/dbsql"
)

type recordingAlertQueries struct {
	getParams  dbsql.GetAlertParams
	listParams dbsql.ListAlertsParams
}

func (q *recordingAlertQueries) GetAlert(
	_ context.Context,
	params dbsql.GetAlertParams,
) (*dbsql.GetAlertRow, error) {
	q.getParams = params
	return &dbsql.GetAlertRow{}, nil
}

func (q *recordingAlertQueries) ListAlerts(
	_ context.Context,
	params dbsql.ListAlertsParams,
) ([]*dbsql.ListAlertsRow, error) {
	q.listParams = params
	return nil, nil
}

func TestTenantQueriesBindsAlertPredicatesToAuthorizedTenant(t *testing.T) {
	tenantID := databaseUUID(uuid.Must(uuid.NewV7()))
	alertID := databaseUUID(uuid.Must(uuid.NewV7()))
	afterID := databaseUUID(uuid.Must(uuid.NewV7()))
	queries := &recordingAlertQueries{}
	tenantQueries := newTenantQueries(queries, tenantID)

	if _, err := tenantQueries.GetAlert(context.Background(), alertID); err != nil {
		t.Fatalf("GetAlert() error = %v", err)
	}
	if _, err := tenantQueries.ListAlerts(context.Background(), afterID, 25); err != nil {
		t.Fatalf("ListAlerts() error = %v", err)
	}

	if queries.getParams.TenantID != tenantID || queries.getParams.ID != alertID {
		t.Fatalf("GetAlert params = %#v", queries.getParams)
	}
	if queries.listParams.TenantID != tenantID ||
		queries.listParams.AfterID != afterID ||
		queries.listParams.PageSize != 25 {
		t.Fatalf("ListAlerts params = %#v", queries.listParams)
	}
}

func databaseUUID(value uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: value, Valid: true}
}
