package postgres

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	application "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

func TestTicketingRepositoryListAlertRelationsConsumesRowsBeforeRelatedReads(t *testing.T) {
	databaseURL := strings.TrimSpace(os.Getenv("PERIAPSIS_ALERT_RELATION_REPOSITORY_TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("PERIAPSIS_ALERT_RELATION_REPOSITORY_TEST_DATABASE_URL is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatalf("parse Alert relation repository database URL: %v", err)
	}
	// A single physical connection makes a query attempted before the relation
	// rows are consumed fail deterministically with pgx's connection-busy error.
	config.MaxConns = 1
	config.AfterConnect = func(ctx context.Context, connection *pgx.Conn) error {
		_, connectErr := connection.Exec(ctx, `SET ROLE "periapsis_api"`)
		return connectErr
	}
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatalf("connect Alert relation repository database: %v", err)
	}
	defer pool.Close()

	connection, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire Alert relation repository connection: %v", err)
	}
	defer connection.Release()
	assertTicketActivityFeedRole(t, ctx, connection, "periapsis_api", false)

	fixtureTx, err := connection.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		t.Fatalf("begin Alert relation repository fixture: %v", err)
	}
	defer func() { _ = fixtureTx.Rollback(ctx) }()
	if _, err = fixtureTx.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatalf("reset runtime role before Alert relation fixture setup: %v", err)
	}
	if _, err = fixtureTx.Exec(ctx, `SET LOCAL ROLE "periapsis_migrator"`); err != nil {
		t.Fatalf("set Alert relation fixture role: %v", err)
	}

	fixture := seedTicketActivityFeedFixture(t, ctx, fixtureTx)
	oldestRelationID, newestRelationID := seedAlertRelationRepositoryFixture(t, ctx, fixtureTx, fixture)

	if _, err = fixtureTx.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatalf("reset Alert relation fixture role: %v", err)
	}
	if _, err = fixtureTx.Exec(ctx, `SET LOCAL ROLE "periapsis_api"`); err != nil {
		t.Fatalf("restore API role after Alert relation fixture setup: %v", err)
	}
	assertTicketActivityFeedRole(t, ctx, fixtureTx, "periapsis_api", false)

	repository := NewTicketingRepository(pool)
	repository.begin = func(beginCtx context.Context, options pgx.TxOptions) (databaseTransaction, error) {
		if options.IsoLevel != pgx.RepeatableRead || options.AccessMode != pgx.ReadOnly {
			return nil, fmt.Errorf("unexpected Alert relation transaction options: %+v", options)
		}
		return fixtureTx.Begin(beginCtx)
	}
	access := ticketActivityFeedAccess(
		t, fixture.tenantID, fixture.operatorUserID, kernel.PrincipalOperator, application.ScopeTenant,
	)

	page, err := repository.ListAlertRelations(
		ctx, fixture.operatorUserID, fixture.tenantID, fixture.firstVisibleAlertID,
		application.CursorPageInput{Limit: 2}, access,
	)
	if err != nil {
		t.Fatalf("ListAlertRelations with two related reads error = %v", err)
	}
	if page.NextCursor != nil {
		t.Fatalf("Alert relation page cursor = %v, want nil", page.NextCursor)
	}
	if len(page.Items) != 2 {
		t.Fatalf("Alert relation page item count = %d, want 2: %+v", len(page.Items), page.Items)
	}
	want := []struct {
		relationID uuid.UUID
		relatedID  uuid.UUID
		direction  application.AlertRelationDirection
		reason     string
	}{
		{newestRelationID, fixture.hiddenAlertID, application.AlertRelationSymmetric, "Second relation evidence"},
		{oldestRelationID, fixture.secondVisibleAlertID, application.AlertRelationOutgoing, "First relation evidence"},
	}
	for index, expected := range want {
		item := page.Items[index]
		if item.Relation.ID != expected.relationID || item.Related.Snapshot.ID().Bytes() != [16]byte(expected.relatedID) ||
			item.Direction != expected.direction || item.Relation.Reason != expected.reason {
			t.Fatalf("Alert relation page item %d = %+v, want relation=%s related=%s direction=%s reason=%q",
				index, item, expected.relationID, expected.relatedID, expected.direction, expected.reason)
		}
	}
}

func seedAlertRelationRepositoryFixture(
	t testing.TB,
	ctx context.Context,
	tx pgx.Tx,
	fixture ticketActivityFeedFixture,
) (uuid.UUID, uuid.UUID) {
	t.Helper()
	var oldestRelationID, newestRelationID uuid.UUID
	if err := tx.QueryRow(ctx, `
		SELECT uuidv7(interval '2 days'), uuidv7(interval '2 days 1 millisecond')`,
	).Scan(&oldestRelationID, &newestRelationID); err != nil {
		t.Fatalf("reserve ordered Alert relation UUIDv7 identifiers: %v", err)
	}
	var createdAt time.Time
	if err := tx.QueryRow(ctx, `
		SELECT max(created_at)
		FROM public.alerts
		WHERE tenant_id = $1 AND id IN ($2, $3, $4)`,
		fixture.tenantID, fixture.firstVisibleAlertID, fixture.secondVisibleAlertID, fixture.hiddenAlertID,
	).Scan(&createdAt); err != nil {
		t.Fatalf("read Alert creation boundary for relation repository fixture: %v", err)
	}
	linkedAt := createdAt.UTC().Truncate(time.Microsecond).Add(time.Microsecond)
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.alert_relations (
		  id, tenant_id, source_alert_id, target_alert_id,
		  canonical_first_alert_id, canonical_second_alert_id,
		  relation_type, reason, linked_by_membership_id, linked_by_user_id,
		  prior_source_version, result_source_version,
		  prior_target_version, result_target_version, linked_at
		) VALUES
		  ($1, $3, $4::uuid, $5::uuid, least($4::uuid, $5::uuid), greatest($4::uuid, $5::uuid),
		   'duplicate_of', 'First relation evidence', $6, $7, 1, 2, 1, 2, $8),
		  ($2, $3, $4::uuid, $9::uuid, least($4::uuid, $9::uuid), greatest($4::uuid, $9::uuid),
		   'correlation', 'Second relation evidence', $6, $7, 2, 3, 1, 2, $8 + interval '1 microsecond')`,
		oldestRelationID, newestRelationID, fixture.tenantID,
		fixture.firstVisibleAlertID, fixture.secondVisibleAlertID,
		fixture.operatorMembershipID, fixture.operatorUserID, linkedAt, fixture.hiddenAlertID,
	); err != nil {
		t.Fatalf("insert Alert relation repository fixture: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE public.alerts
		SET version = CASE id WHEN $2 THEN 3 ELSE 2 END,
		    updated_at = $5
		WHERE tenant_id = $1 AND id IN ($2, $3, $4)`,
		fixture.tenantID, fixture.firstVisibleAlertID, fixture.secondVisibleAlertID,
		fixture.hiddenAlertID, linkedAt.Add(2*time.Microsecond),
	); err != nil {
		t.Fatalf("advance Alert versions for relation repository fixture: %v", err)
	}
	return oldestRelationID, newestRelationID
}
