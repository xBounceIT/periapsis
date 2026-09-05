package postgres

import (
	"context"
	"errors"
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

func TestTicketingRepositoryListActivityFeedEnforcesScopePaginationAndRLS(t *testing.T) {
	databaseURL := strings.TrimSpace(os.Getenv("PERIAPSIS_TICKET_ACTIVITY_FEED_TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("PERIAPSIS_TICKET_ACTIVITY_FEED_TEST_DATABASE_URL is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatalf("parse ticket activity feed database URL: %v", err)
	}
	config.MaxConns = 1
	config.AfterConnect = func(ctx context.Context, connection *pgx.Conn) error {
		_, connectErr := connection.Exec(ctx, `SET ROLE "periapsis_api"`)
		return connectErr
	}
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatalf("connect ticket activity feed database: %v", err)
	}
	defer pool.Close()

	connection, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire ticket activity feed connection: %v", err)
	}
	defer connection.Release()
	assertTicketActivityFeedRole(t, ctx, connection, "periapsis_api", false)

	fixtureTx, err := connection.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		t.Fatalf("begin ticket activity feed fixture: %v", err)
	}
	defer func() { _ = fixtureTx.Rollback(ctx) }()
	if _, err = fixtureTx.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatalf("reset runtime role before fixture setup: %v", err)
	}
	if _, err = fixtureTx.Exec(ctx, `SET LOCAL ROLE "periapsis_migrator"`); err != nil {
		t.Fatalf("set fixture role: %v", err)
	}
	assertTicketActivityFeedRole(t, ctx, fixtureTx, "periapsis_migrator", true)

	fixture := seedTicketActivityFeedFixture(t, ctx, fixtureTx)
	if _, err = fixtureTx.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatalf("reset fixture role: %v", err)
	}
	if _, err = fixtureTx.Exec(ctx, `SET LOCAL ROLE "periapsis_api"`); err != nil {
		t.Fatalf("restore API role: %v", err)
	}
	assertTicketActivityFeedRole(t, ctx, fixtureTx, "periapsis_api", false)

	repository := NewTicketingRepository(pool)
	repository.begin = func(beginCtx context.Context, options pgx.TxOptions) (databaseTransaction, error) {
		if options.IsoLevel != pgx.RepeatableRead || options.AccessMode != pgx.ReadOnly {
			return nil, fmt.Errorf("unexpected activity feed transaction options: %+v", options)
		}
		return fixtureTx.Begin(beginCtx)
	}
	operatorAccess := ticketActivityFeedAccess(
		t, fixture.tenantID, fixture.operatorUserID, kernel.PrincipalOperator, application.ScopeOwn,
	)

	first, err := repository.ListActivityFeed(ctx, fixture.tenantID, kernel.AggregateAlert,
		application.CursorPageInput{Limit: 2}, operatorAccess)
	if err != nil {
		t.Fatalf("ListActivityFeed(alert first page) error = %v", err)
	}
	assertTicketActivityFeedPage(t, first, []ticketActivityFeedExpected{
		{id: fixture.newestVisibleActivityID, resourceID: fixture.firstVisibleAlertID},
		{id: fixture.middleVisibleActivityID, resourceID: fixture.secondVisibleAlertID},
	}, fixture.tenantID, kernel.AggregateAlert, fixture.operatorMembershipID)
	if first.NextCursor == nil || *first.NextCursor != fixture.middleVisibleActivityID {
		t.Fatalf("first page cursor = %v, want %s", first.NextCursor, fixture.middleVisibleActivityID)
	}

	second, err := repository.ListActivityFeed(ctx, fixture.tenantID, kernel.AggregateAlert,
		application.CursorPageInput{After: first.NextCursor, Limit: 1}, operatorAccess)
	if err != nil {
		t.Fatalf("ListActivityFeed(alert second page) error = %v", err)
	}
	assertTicketActivityFeedPage(t, second, []ticketActivityFeedExpected{
		{id: fixture.oldestVisibleActivityID, resourceID: fixture.firstVisibleAlertID},
	}, fixture.tenantID, kernel.AggregateAlert, fixture.operatorMembershipID)
	if second.NextCursor == nil || *second.NextCursor != fixture.oldestVisibleActivityID {
		t.Fatalf("second page cursor = %v, want %s", second.NextCursor, fixture.oldestVisibleActivityID)
	}
	seen := make(map[uuid.UUID]struct{}, len(first.Items)+len(second.Items))
	for _, page := range []application.StoredActivityPage{first, second} {
		for _, item := range page.Items {
			if _, duplicate := seen[item.ID]; duplicate {
				t.Fatalf("activity %s appeared on more than one page", item.ID)
			}
			seen[item.ID] = struct{}{}
		}
	}
	for _, forbidden := range []uuid.UUID{fixture.hiddenNewerActivityID, fixture.foreignActivityID} {
		if _, leaked := seen[forbidden]; leaked {
			t.Fatalf("unauthorized activity %s affected the authorized pages", forbidden)
		}
	}

	casePage, err := repository.ListActivityFeed(ctx, fixture.tenantID, kernel.AggregateCase,
		application.CursorPageInput{Limit: 1}, operatorAccess)
	if err != nil {
		t.Fatalf("ListActivityFeed(case) error = %v", err)
	}
	assertTicketActivityFeedPage(t, casePage, []ticketActivityFeedExpected{
		{id: fixture.caseActivityID, resourceID: fixture.visibleCaseID},
	}, fixture.tenantID, kernel.AggregateCase, fixture.operatorMembershipID)
	if casePage.NextCursor != nil {
		t.Fatalf("case page cursor = %v, want nil", casePage.NextCursor)
	}

	var foreignVisible int
	if err = fixtureTx.QueryRow(ctx, `
		SELECT count(*)
		FROM public.ticket_activities
		WHERE tenant_id = $1 AND id = $2`,
		fixture.foreignTenantID, fixture.foreignActivityID,
	).Scan(&foreignVisible); err != nil {
		t.Fatalf("probe cross-tenant activity under API RLS: %v", err)
	}
	if foreignVisible != 0 {
		t.Fatalf("cross-tenant activity count = %d, want 0 under tenant RLS", foreignVisible)
	}

	customerAccess := ticketActivityFeedAccess(
		t, fixture.tenantID, fixture.operatorUserID, kernel.PrincipalCustomer, application.ScopeOwn,
	)
	if _, err = repository.ListActivityFeed(ctx, fixture.tenantID, kernel.AggregateAlert,
		application.CursorPageInput{Limit: 2}, customerAccess); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("customer activity feed error = %v, want forbidden", err)
	}
	if _, err = repository.ListActivityFeed(ctx, fixture.tenantID, kernel.AggregateKind(0),
		application.CursorPageInput{Limit: 2}, operatorAccess); !errors.Is(err, application.ErrInvalidInput) {
		t.Fatalf("invalid activity feed kind error = %v, want invalid input", err)
	}
}

type ticketActivityFeedFixture struct {
	tenantID                uuid.UUID
	foreignTenantID         uuid.UUID
	operatorUserID          uuid.UUID
	operatorMembershipID    uuid.UUID
	firstVisibleAlertID     uuid.UUID
	secondVisibleAlertID    uuid.UUID
	hiddenAlertID           uuid.UUID
	visibleCaseID           uuid.UUID
	oldestVisibleActivityID uuid.UUID
	middleVisibleActivityID uuid.UUID
	newestVisibleActivityID uuid.UUID
	hiddenNewerActivityID   uuid.UUID
	caseActivityID          uuid.UUID
	foreignActivityID       uuid.UUID
}

func seedTicketActivityFeedFixture(t testing.TB, ctx context.Context, tx pgx.Tx) ticketActivityFeedFixture {
	t.Helper()
	newID := func() uuid.UUID {
		identifier, err := uuid.NewV7()
		if err != nil {
			t.Fatalf("generate ticket activity feed UUIDv7: %v", err)
		}
		return identifier
	}
	fixture := ticketActivityFeedFixture{
		tenantID:             newID(),
		foreignTenantID:      newID(),
		operatorUserID:       newID(),
		operatorMembershipID: newID(),
		firstVisibleAlertID:  newID(),
		secondVisibleAlertID: newID(),
		hiddenAlertID:        newID(),
		visibleCaseID:        newID(),
	}
	otherUserID, otherMembershipID := newID(), newID()
	foreignUserID, foreignMembershipID := newID(), newID()
	foreignAlertID := newID()
	suffix := strings.ReplaceAll(fixture.tenantID.String(), "-", "")

	if _, err := tx.Exec(ctx, `
		INSERT INTO public.tenants (id, slug, name) VALUES
		  ($1, $2, 'Activity feed integration'),
		  ($3, $4, 'Foreign activity feed integration')`,
		fixture.tenantID, "activity-feed-go-"+suffix[len(suffix)-12:],
		fixture.foreignTenantID, "activity-feed-foreign-go-"+suffix[len(suffix)-12:],
	); err != nil {
		t.Fatalf("insert activity feed tenants: %v", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO public.audit_chain_heads (tenant_id) VALUES ($1), ($2)`,
		fixture.tenantID, fixture.foreignTenantID); err != nil {
		t.Fatalf("insert activity feed audit heads: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.users (id, email, display_name) VALUES
		  ($1, $2, 'Feed operator'),
		  ($3, $4, 'Other operator'),
		  ($5, $6, 'Foreign operator')`,
		fixture.operatorUserID, "activity-feed-operator-"+suffix[len(suffix)-12:]+"@example.invalid",
		otherUserID, "activity-feed-other-"+suffix[len(suffix)-12:]+"@example.invalid",
		foreignUserID, "activity-feed-foreign-"+suffix[len(suffix)-12:]+"@example.invalid",
	); err != nil {
		t.Fatalf("insert activity feed users: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.tenant_memberships (id, tenant_id, user_id, role, status) VALUES
		  ($1, $2, $3, 'tenant_admin', 'active'),
		  ($4, $2, $5, 'analyst', 'active'),
		  ($6, $7, $8, 'tenant_admin', 'active')`,
		fixture.operatorMembershipID, fixture.tenantID, fixture.operatorUserID,
		otherMembershipID, otherUserID,
		foreignMembershipID, fixture.foreignTenantID, foreignUserID,
	); err != nil {
		t.Fatalf("insert activity feed memberships: %v", err)
	}
	if _, err := tx.Exec(ctx, `SELECT app.seed_tenant_authorization($1, $2), app.seed_tenant_authorization($3, $4)`,
		fixture.tenantID, fixture.operatorMembershipID, fixture.foreignTenantID, foreignMembershipID); err != nil {
		t.Fatalf("seed activity feed tenant authorization: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.alerts (
		  id, tenant_id, number, workflow_id, workflow_version, state_key,
		  title, created_by, created_by_membership_id
		)
		SELECT input.id, input.tenant_id, input.number, workflow.id,
		       workflow.current_version, 'new', input.title,
		       input.user_id, input.membership_id
		FROM (VALUES
		  ($1::uuid, $2::uuid, 'ALT-2099-910001', 'Visible alert one', $3::uuid, $4::uuid),
		  ($5::uuid, $2::uuid, 'ALT-2099-910002', 'Visible alert two', $3::uuid, $4::uuid),
		  ($6::uuid, $2::uuid, 'ALT-2099-910003', 'Hidden newer alert', $7::uuid, $8::uuid),
		  ($9::uuid, $10::uuid, 'ALT-2099-910004', 'Foreign alert', $11::uuid, $12::uuid)
		) AS input(id, tenant_id, number, title, user_id, membership_id)
		JOIN public.ticket_workflows AS workflow
		  ON workflow.tenant_id = input.tenant_id
		 AND workflow.aggregate_kind = 'alert'
		 AND workflow.is_default AND workflow.archived_at IS NULL`,
		fixture.firstVisibleAlertID, fixture.tenantID, fixture.operatorUserID, fixture.operatorMembershipID,
		fixture.secondVisibleAlertID, fixture.hiddenAlertID, otherUserID, otherMembershipID,
		foreignAlertID, fixture.foreignTenantID, foreignUserID, foreignMembershipID,
	); err != nil {
		t.Fatalf("insert activity feed alerts: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.cases (
		  id, tenant_id, number, workflow_id, workflow_version, state_key,
		  title, created_by_membership_id, created_by_user_id
		)
		SELECT $1, $2, 'CAS-2099-910001', workflow.id,
		       workflow.current_version, 'new', 'Visible case', $3, $4
		FROM public.ticket_workflows AS workflow
		WHERE workflow.tenant_id = $2 AND workflow.aggregate_kind = 'case'
		  AND workflow.is_default AND workflow.archived_at IS NULL`,
		fixture.visibleCaseID, fixture.tenantID, fixture.operatorMembershipID, fixture.operatorUserID,
	); err != nil {
		t.Fatalf("insert activity feed case: %v", err)
	}
	if err := tx.QueryRow(ctx, `
		SELECT uuidv7(interval '1 day'),
		       uuidv7(interval '1 day 1 millisecond'),
		       uuidv7(interval '1 day 2 milliseconds'),
		       uuidv7(interval '1 day 3 milliseconds'),
		       uuidv7(interval '1 day 4 milliseconds'),
		       uuidv7(interval '1 day 5 milliseconds')`,
	).Scan(
		&fixture.oldestVisibleActivityID, &fixture.middleVisibleActivityID,
		&fixture.newestVisibleActivityID, &fixture.caseActivityID,
		&fixture.hiddenNewerActivityID, &fixture.foreignActivityID,
	); err != nil {
		t.Fatalf("reserve ordered activity feed UUIDv7 identifiers: %v", err)
	}
	occurredAt := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.ticket_activities (
		  id, tenant_id, alert_id, case_id, sequence, kind, summary,
		  actor_principal_kind, actor_membership_id, actor_user_id,
		  origin, details, occurred_at
		) VALUES
		  ($1, $7, $8, NULL, 1001, 'alert.created', 'Oldest visible activity',
		   'human', $9, $10, 'api', '{"rank":1}'::jsonb, $11),
		  ($2, $7, $12, NULL, 1001, 'alert.assigned', 'Middle visible activity',
		   'human', $9, $10, 'api', '{"rank":2}'::jsonb, $11 + interval '1 minute'),
		  ($3, $7, $8, NULL, 1002, 'alert.transitioned', 'Newest visible activity',
		   'human', $9, $10, 'api', '{"rank":3}'::jsonb, $11 + interval '2 minutes'),
		  ($4, $7, $13, NULL, 1001, 'alert.claimed', 'Hidden newer activity',
		   'human', $14, $15, 'api', '{"rank":4}'::jsonb, $11 + interval '3 minutes'),
		  ($5, $7, NULL, $16, 1001, 'case.created', 'Case activity',
		   'human', $9, $10, 'api', '{"kind":"case"}'::jsonb, $11 + interval '4 minutes'),
		  ($6, $17, $18, NULL, 1001, 'alert.created', 'Foreign activity',
		   'human', $19, $20, 'api', '{"tenant":"foreign"}'::jsonb, $11 + interval '5 minutes')`,
		fixture.oldestVisibleActivityID, fixture.middleVisibleActivityID,
		fixture.newestVisibleActivityID, fixture.hiddenNewerActivityID,
		fixture.caseActivityID, fixture.foreignActivityID,
		fixture.tenantID, fixture.firstVisibleAlertID,
		fixture.operatorMembershipID, fixture.operatorUserID, occurredAt,
		fixture.secondVisibleAlertID, fixture.hiddenAlertID, otherMembershipID, otherUserID,
		fixture.visibleCaseID, fixture.foreignTenantID, foreignAlertID,
		foreignMembershipID, foreignUserID,
	); err != nil {
		t.Fatalf("insert activity feed activities: %v", err)
	}
	return fixture
}

type ticketActivityFeedExpected struct {
	id         uuid.UUID
	resourceID uuid.UUID
}

func assertTicketActivityFeedPage(
	t testing.TB,
	page application.StoredActivityPage,
	expected []ticketActivityFeedExpected,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	actorID uuid.UUID,
) {
	t.Helper()
	if len(page.Items) != len(expected) {
		t.Fatalf("activity page item count = %d, want %d: %+v", len(page.Items), len(expected), page.Items)
	}
	for index, want := range expected {
		item := page.Items[index]
		if item.ID != want.id || item.TenantID != tenantID || item.ResourceID != want.resourceID ||
			item.ResourceKind != kind || item.ActorKind != application.ActivityActorHuman || item.ActorID != actorID ||
			item.DisplayName != "Feed operator" || item.Origin != "operator" {
			t.Fatalf("activity page item %d = %+v, want id=%s resource=%s tenant=%s kind=%s actor=%s",
				index, item, want.id, want.resourceID, tenantID, kind, actorID)
		}
	}
}

func ticketActivityFeedAccess(
	t testing.TB,
	tenantID uuid.UUID,
	actorID uuid.UUID,
	principal kernel.PrincipalKind,
	scopes ...application.Scope,
) application.LiveAccess {
	t.Helper()
	tenant, err := kernel.NewEntityID([16]byte(tenantID))
	if err != nil {
		t.Fatalf("construct activity feed tenant ID: %v", err)
	}
	actor, err := kernel.NewEntityID([16]byte(actorID))
	if err != nil {
		t.Fatalf("construct activity feed actor ID: %v", err)
	}
	authority, err := kernel.NewAuthorizationSnapshot(
		tenant, actor, principal, true, nil, nil, nil, nil, nil,
	)
	if err != nil {
		t.Fatalf("construct activity feed authority: %v", err)
	}
	return application.LiveAccess{Authority: authority, Scopes: scopes}
}

type ticketActivityFeedRoleQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func assertTicketActivityFeedRole(
	t testing.TB,
	ctx context.Context,
	query ticketActivityFeedRoleQuerier,
	expected string,
	expectedBypassRLS bool,
) {
	t.Helper()
	var current string
	var bypassRLS bool
	if err := query.QueryRow(ctx, `
		SELECT role.rolname, role.rolbypassrls
		FROM pg_catalog.pg_roles AS role
		WHERE role.rolname = current_user`).Scan(&current, &bypassRLS); err != nil {
		t.Fatalf("read ticket activity feed database role: %v", err)
	}
	if current != expected || bypassRLS != expectedBypassRLS {
		t.Fatalf("ticket activity feed database role = (%s, bypass_rls=%t), want (%s, %t)",
			current, bypassRLS, expected, expectedBypassRLS)
	}
}
