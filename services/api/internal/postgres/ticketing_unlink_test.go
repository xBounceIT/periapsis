package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	application "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

func TestQueryUnlinkReceiptAttestsExactTenantScopedRetraction(t *testing.T) {
	tenantID := mustPostgresUUIDv7(t)
	alertID := mustPostgresUUIDv7(t)
	caseID := mustPostgresUUIDv7(t)
	linkID := mustPostgresUUIDv7(t)
	retractedAt := time.Date(2026, 9, 2, 9, 0, 0, 123_000, time.UTC)
	tx := &workflowReplayTransaction{rows: []pgx.Row{
		rowFunc(func(destinations ...any) error {
			*destinations[0].(*uuid.UUID) = linkID
			*destinations[1].(*int32) = 4
			*destinations[2].(*int32) = 5
			*destinations[3].(*int32) = 8
			*destinations[4].(*int32) = 9
			*destinations[5].(*time.Time) = retractedAt
			*destinations[6].(*bool) = false
			return nil
		}),
		rowFunc(func(destinations ...any) error {
			*destinations[0].(*uuid.UUID) = tenantID
			*destinations[1].(*uuid.UUID) = alertID
			*destinations[2].(*uuid.UUID) = caseID
			return nil
		}),
	}}
	receipt, err := queryUnlinkReceipt(
		context.Background(), tx, tenantID, "SELECT unlink receipt",
	)
	if err != nil || receipt.TenantID != tenantID || receipt.AlertID != alertID ||
		receipt.CaseID != caseID || receipt.LinkID != linkID ||
		receipt.PreviousAlertVersion != 4 || receipt.AlertVersion != 5 ||
		receipt.PreviousCaseVersion != 8 || receipt.CaseVersion != 9 ||
		!receipt.RetractedAt.Equal(retractedAt) {
		t.Fatalf("queryUnlinkReceipt() receipt=%+v error=%v", receipt, err)
	}
	if len(tx.queries) != 2 ||
		!strings.Contains(tx.queries[1], "retraction.tenant_id = $2") ||
		len(tx.args[1]) != 2 || tx.args[1][0] != linkID || tx.args[1][1] != tenantID {
		t.Fatalf("receipt provenance lookup is not exact-tenant scoped: queries=%#v args=%#v", tx.queries, tx.args)
	}
}

func TestQueryUnlinkReceiptRejectsCrossTenantOrContradictoryVersions(t *testing.T) {
	tenantID := mustPostgresUUIDv7(t)
	for _, test := range []struct {
		name           string
		returnedTenant uuid.UUID
		alertVersion   int32
	}{
		{name: "cross tenant", returnedTenant: mustPostgresUUIDv7(t), alertVersion: 5},
		{name: "version gap", returnedTenant: tenantID, alertVersion: 6},
	} {
		t.Run(test.name, func(t *testing.T) {
			tx := &workflowReplayTransaction{rows: []pgx.Row{
				rowFunc(func(destinations ...any) error {
					*destinations[0].(*uuid.UUID) = mustPostgresUUIDv7(t)
					*destinations[1].(*int32) = 4
					*destinations[2].(*int32) = test.alertVersion
					*destinations[3].(*int32) = 8
					*destinations[4].(*int32) = 9
					*destinations[5].(*time.Time) = time.Date(2026, 9, 2, 9, 0, 0, 0, time.UTC)
					*destinations[6].(*bool) = false
					return nil
				}),
				rowFunc(func(destinations ...any) error {
					*destinations[0].(*uuid.UUID) = test.returnedTenant
					*destinations[1].(*uuid.UUID) = mustPostgresUUIDv7(t)
					*destinations[2].(*uuid.UUID) = mustPostgresUUIDv7(t)
					return nil
				}),
			}}
			_, err := queryUnlinkReceipt(context.Background(), tx, tenantID, "SELECT unlink receipt")
			if !errors.Is(err, application.ErrUnavailable) {
				t.Fatalf("queryUnlinkReceipt() error=%v, want unavailable", err)
			}
		})
	}
}
