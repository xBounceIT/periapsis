package postgres

import (
	"context"
	"errors"
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

func TestCustomerPortalExportQueryEnforcesRLSLinkAndPublicProjection(t *testing.T) {
	databaseURL := strings.TrimSpace(os.Getenv("PERIAPSIS_CONTACTS_PORTAL_SECURITY_TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("PERIAPSIS_CONTACTS_PORTAL_SECURITY_TEST_DATABASE_URL is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect contacts portal database: %v", err)
	}
	defer pool.Close()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin customer export proof: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err = tx.Exec(ctx, `SET LOCAL ROLE "periapsis_migrator"`); err != nil {
		t.Fatalf("set fixture role: %v", err)
	}

	tenantID, foreignTenantID := exportIntegrationUUID(t), exportIntegrationUUID(t)
	adminUserID, adminMembershipID := exportIntegrationUUID(t), exportIntegrationUUID(t)
	customerUserID, customerMembershipID := exportIntegrationUUID(t), exportIntegrationUUID(t)
	customerRoleGrantID := exportIntegrationUUID(t)
	contactID, alertID, linkID := exportIntegrationUUID(t), exportIntegrationUUID(t), exportIntegrationUUID(t)
	publicCommentID, privateCommentID := exportIntegrationUUID(t), exportIntegrationUUID(t)
	publicActivityID, privateActivityID := exportIntegrationUUID(t), exportIntegrationUUID(t)
	suffix := strings.ReplaceAll(tenantID.String(), "-", "")
	if _, err = tx.Exec(ctx, `
		INSERT INTO public.tenants (id, slug, name) VALUES
		  ($1, $2, 'Customer export integration'),
		  ($3, $4, 'Foreign customer export integration')`,
		tenantID, "customer-export-go-"+suffix[len(suffix)-12:],
		foreignTenantID, "customer-export-foreign-go-"+suffix[len(suffix)-12:],
	); err != nil {
		t.Fatalf("insert customer export tenants: %v", err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO public.audit_chain_heads (tenant_id) VALUES ($1), ($2)`, tenantID, foreignTenantID); err != nil {
		t.Fatalf("insert customer export audit heads: %v", err)
	}
	if _, err = tx.Exec(ctx, `
		INSERT INTO public.users (id, email, display_name) VALUES
		  ($1, $2, 'Export operator'),
		  ($3, $4, 'Export customer')`,
		adminUserID, "customer-export-admin-"+suffix[len(suffix)-12:]+"@example.invalid",
		customerUserID, "customer-export-user-"+suffix[len(suffix)-12:]+"@example.invalid",
	); err != nil {
		t.Fatalf("insert customer export users: %v", err)
	}
	if _, err = tx.Exec(ctx, `
		INSERT INTO public.tenant_memberships (id, tenant_id, user_id, role, status) VALUES
		  ($1, $2, $3, 'tenant_admin', 'active'),
		  ($4, $2, $5, 'customer_user', 'active')`,
		adminMembershipID, tenantID, adminUserID, customerMembershipID, customerUserID,
	); err != nil {
		t.Fatalf("insert customer export memberships: %v", err)
	}
	if _, err = tx.Exec(ctx, `SELECT app.seed_tenant_authorization($1, $2)`, tenantID, adminMembershipID); err != nil {
		t.Fatalf("seed customer export authorization: %v", err)
	}
	if _, err = tx.Exec(ctx, `
		INSERT INTO public.tenant_membership_role_grants (
		  id, tenant_id, membership_id, role_id, source_id,
		  granted_by_membership_id, grant_reason
		)
		SELECT $1, $2, $3, role.id, source.id, $4,
		       'Customer portal export authorization proof.'
		FROM public.tenant_roles AS role
		JOIN public.tenant_authorization_sources AS source
		  ON source.tenant_id = role.tenant_id
		 AND source.key = 'manual'
		 AND source.kind = 'manual'
		 AND source.retired_at IS NULL
		WHERE role.tenant_id = $2
		  AND role.key = 'customer_user'
		  AND role.principal_kind = 'human'
		  AND role.system_role
		  AND role.archived_at IS NULL`,
		customerRoleGrantID, tenantID, customerMembershipID, adminMembershipID,
	); err != nil {
		t.Fatalf("grant customer export role: %v", err)
	}
	if _, err = tx.Exec(ctx, `
		INSERT INTO public.customer_contacts (
		  id, tenant_id, first_name, last_name, email, function, language,
		  timezone, contact_class, linked_membership_id, linked_user_id
		) VALUES ($1, $2, 'Export', 'Customer', $3, 'customer', 'en', 'UTC',
		          'standard', $4, $5)`,
		contactID, tenantID,
		"customer-export-user-"+suffix[len(suffix)-12:]+"@example.invalid",
		customerMembershipID, customerUserID,
	); err != nil {
		t.Fatalf("insert customer export contact: %v", err)
	}
	if _, err = tx.Exec(ctx, `
		INSERT INTO public.alerts (
		  id, tenant_id, number, workflow_id, workflow_version, state_key,
		  customer_visible, title, description, severity, priority, category,
		  created_by, created_by_membership_id, detected_at, received_at
		)
		SELECT $1, $2, 'ALT-2026-999991', workflow.id, workflow.current_version,
		       'new', true, '=Export title', '+Customer-safe description', 'high',
		       'urgent', '@category', $3, $4,
		       transaction_timestamp() - interval '1 hour',
		       transaction_timestamp() - interval '1 hour'
		FROM public.ticket_workflows AS workflow
		WHERE workflow.tenant_id = $2 AND workflow.aggregate_kind = 'alert'
		  AND workflow.is_default AND workflow.archived_at IS NULL`,
		alertID, tenantID, adminUserID, adminMembershipID,
	); err != nil {
		t.Fatalf("insert customer export alert: %v", err)
	}
	if _, err = tx.Exec(ctx, `
		INSERT INTO public.ticket_customer_contacts (
		  id, tenant_id, alert_id, contact_id, role, origin,
		  created_by_membership_id, created_by_user_id
		) VALUES ($1, $2, $3, $4, 'primary', 'manual', $5, $6)`,
		linkID, tenantID, alertID, contactID, adminMembershipID, adminUserID,
	); err != nil {
		t.Fatalf("insert customer export link: %v", err)
	}
	createdAt := time.Now().UTC().Add(-30 * time.Minute).Truncate(time.Microsecond)
	if _, err = tx.Exec(ctx, `
		INSERT INTO public.ticket_comments (
		  id, tenant_id, alert_id, visibility, body_markdown, body_html,
		  author_membership_id, author_user_id, created_at, updated_at
		) VALUES
		  ($1, $3, $4, 'public', '=PUBLIC_FORMULA()', '<p>public</p>', $5, $6, $7, $7),
		  ($2, $3, $4, 'private', 'PRIVATE_SECRET', '<p>PRIVATE_SECRET_HTML</p>', $5, $6, $8, $8)`,
		publicCommentID, privateCommentID, tenantID, alertID,
		adminMembershipID, adminUserID, createdAt, createdAt.Add(time.Minute),
	); err != nil {
		t.Fatalf("insert customer export comments: %v", err)
	}
	if _, err = tx.Exec(ctx, `
		INSERT INTO public.ticket_activities (
		  id, tenant_id, alert_id, sequence, kind, summary,
		  actor_principal_kind, actor_membership_id, actor_user_id, origin,
		  details, occurred_at
		) VALUES
		  ($1, $3, $4, 1001, 'alert.commented', 'Public comment added',
		   'human', $5, $6, 'api', '{"visibility":"public","privateNote":"must not project"}'::jsonb, $7),
		  ($2, $3, $4, 1002, 'alert.commented', 'Private comment added',
		   'human', $5, $6, 'api', '{"visibility":"private","secret":"PRIVATE_ACTIVITY"}'::jsonb, $8)`,
		publicActivityID, privateActivityID, tenantID, alertID,
		adminMembershipID, adminUserID, createdAt, createdAt.Add(time.Minute),
	); err != nil {
		t.Fatalf("insert customer export activities: %v", err)
	}

	query, err := customerPortalExportQuery(kernel.AggregateAlert)
	if err != nil {
		t.Fatal(err)
	}
	setCustomerExportAPIContext(t, ctx, tx, tenantID, customerUserID)
	projection, err := scanCustomerPortalExport(
		tx.QueryRow(ctx, query, kernel.AggregateAlert.String(), alertID, contactID, maximumCustomerPortalExportRows),
		tenantID, kernel.AggregateAlert, alertID,
	)
	if err != nil {
		t.Fatalf("load customer export projection: %v", err)
	}
	if len(projection.Comments) != 1 || projection.Comments[0].ID != publicCommentID ||
		projection.Comments[0].BodyMarkdown != "=PUBLIC_FORMULA()" ||
		projection.Comments[0].Visibility != kernel.CommentPublic {
		t.Fatalf("customer export comments = %+v", projection.Comments)
	}
	csvBytes, err := application.RenderCustomerPortalCSV(projection)
	if err != nil {
		t.Fatalf("render customer export: %v", err)
	}
	if csvText := string(csvBytes); strings.Contains(csvText, "PRIVATE_SECRET") ||
		!strings.Contains(csvText, "'=PUBLIC_FORMULA()") ||
		!strings.Contains(csvText, "'=Export title") {
		t.Fatalf("unsafe or leaking customer export: %q", csvText)
	}
	activity, err := scanTicketActivity(tx.QueryRow(ctx,
		customerTicketActivitySelect+`
		WHERE activity.tenant_id = $1 AND activity.alert_id = $2
		  AND (activity.kind IN ('alert.created','alert.transitioned','alert.escalated','alert.linked')
		    OR activity.kind = 'alert.commented' AND activity.details ->> 'visibility' = 'public')
		ORDER BY activity.id LIMIT 2`,
		tenantID, alertID,
	), tenantID, kernel.AggregateAlert, alertID, kernel.PrincipalCustomer)
	if err != nil || activity.ID != publicActivityID || activity.ActorKind != application.ActivityActorRedacted ||
		activity.ActorID != uuid.Nil || activity.DisplayName != "Support team" ||
		activity.Origin != "operator" || activity.Kind != "comment.public" || activity.Details != nil {
		t.Fatalf("customer activity projection = (%+v, %v)", activity, err)
	}
	if _, err = tx.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatalf("reset API role before permission-revocation proof: %v", err)
	}
	if _, err = tx.Exec(ctx, `SET LOCAL ROLE "periapsis_migrator"`); err != nil {
		t.Fatalf("restore fixture role before permission-revocation proof: %v", err)
	}
	command, err := tx.Exec(ctx, `
		DELETE FROM public.tenant_role_permissions AS grant_row
		USING public.tenant_roles AS role, public.tenant_permissions AS permission
		WHERE grant_row.tenant_id = $1
		  AND role.tenant_id = grant_row.tenant_id
		  AND role.id = grant_row.role_id
		  AND role.key = 'customer_user'
		  AND permission.id = grant_row.permission_id
		  AND permission.key = 'portal.comment.public'
		  AND grant_row.scope = 'own'`, tenantID)
	if err != nil || command.RowsAffected() != 1 {
		t.Fatalf("revoke live public-comment permission = (%d, %v)", command.RowsAffected(), err)
	}
	setCustomerExportAPIContext(t, ctx, tx, tenantID, customerUserID)
	_, err = scanCustomerPortalExport(
		tx.QueryRow(ctx, query, kernel.AggregateAlert.String(), alertID, contactID, maximumCustomerPortalExportRows),
		tenantID, kernel.AggregateAlert, alertID,
	)
	if !errors.Is(err, application.ErrNotFound) {
		t.Fatalf("revoked public-comment export error = %v, want not found", err)
	}
	if _, err = tx.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatalf("reset API role after permission-revocation proof: %v", err)
	}
	if _, err = tx.Exec(ctx, `SET LOCAL ROLE "periapsis_migrator"`); err != nil {
		t.Fatalf("restore fixture role after permission-revocation proof: %v", err)
	}
	if _, err = tx.Exec(ctx, `
		INSERT INTO public.tenant_role_permissions (
		  tenant_id, role_id, permission_id, scope, created_by_membership_id
		)
		SELECT $1, role.id, permission.id, 'own'::public.authorization_scope, NULL
		FROM public.tenant_roles AS role
		JOIN public.tenant_permissions AS permission
		  ON permission.key = 'portal.comment.public'
		WHERE role.tenant_id = $1
		  AND role.key = 'customer_user'
		  AND role.principal_kind = 'human'
		  AND role.system_role
		  AND role.archived_at IS NULL`, tenantID); err != nil {
		t.Fatalf("restore live public-comment permission: %v", err)
	}
	setCustomerExportAPIContext(t, ctx, tx, tenantID, customerUserID)
	if _, err = tx.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatalf("reset API role before snapshot proof: %v", err)
	}
	if _, err = tx.Exec(ctx, `SET LOCAL ROLE "periapsis_migrator"`); err != nil {
		t.Fatalf("restore fixture role before snapshot proof: %v", err)
	}
	if _, err = tx.Exec(ctx, `DELETE FROM public.ticket_comment_author_snapshots WHERE tenant_id = $1 AND comment_id = $2`, tenantID, publicCommentID); err != nil {
		t.Fatalf("remove public author snapshot: %v", err)
	}
	setCustomerExportAPIContext(t, ctx, tx, tenantID, customerUserID)
	_, err = scanCustomerPortalExport(
		tx.QueryRow(ctx, query, kernel.AggregateAlert.String(), alertID, contactID, maximumCustomerPortalExportRows),
		tenantID, kernel.AggregateAlert, alertID,
	)
	if !errors.Is(err, application.ErrUnavailable) {
		t.Fatalf("missing-author-snapshot export error = %v, want unavailable", err)
	}
	if _, err = tx.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatalf("reset API role after snapshot proof: %v", err)
	}
	if _, err = tx.Exec(ctx, `SET LOCAL ROLE "periapsis_migrator"`); err != nil {
		t.Fatalf("restore fixture role after snapshot proof: %v", err)
	}
	if _, err = tx.Exec(ctx, `
		INSERT INTO public.ticket_comment_author_snapshots (
		  tenant_id, comment_id, audience, author_membership_id, author_user_id
		) VALUES ($1, $2, 'operator', $3, $4)`,
		tenantID, publicCommentID, adminMembershipID, adminUserID,
	); err != nil {
		t.Fatalf("restore public author snapshot: %v", err)
	}
	setCustomerExportAPIContext(t, ctx, tx, tenantID, customerUserID)

	_, err = scanCustomerPortalExport(
		tx.QueryRow(ctx, query, kernel.AggregateAlert.String(), alertID, exportIntegrationUUID(t), maximumCustomerPortalExportRows),
		tenantID, kernel.AggregateAlert, alertID,
	)
	if !errors.Is(err, application.ErrNotFound) {
		t.Fatalf("wrong contact error = %v, want not found", err)
	}
	if _, err = tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, foreignTenantID.String()); err != nil {
		t.Fatalf("install foreign tenant context: %v", err)
	}
	_, err = scanCustomerPortalExport(
		tx.QueryRow(ctx, query, kernel.AggregateAlert.String(), alertID, contactID, maximumCustomerPortalExportRows),
		tenantID, kernel.AggregateAlert, alertID,
	)
	if !errors.Is(err, application.ErrNotFound) {
		t.Fatalf("cross-tenant export error = %v, want not found", err)
	}

	if _, err = tx.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatalf("reset fixture role: %v", err)
	}
	if _, err = tx.Exec(ctx, `SET LOCAL ROLE "periapsis_migrator"`); err != nil {
		t.Fatalf("restore fixture role: %v", err)
	}
	if _, err = tx.Exec(ctx, `UPDATE public.alerts SET state_key = 'missing_state' WHERE tenant_id = $1 AND id = $2`, tenantID, alertID); err != nil {
		t.Fatalf("make current workflow state incoherent: %v", err)
	}
	setCustomerExportAPIContext(t, ctx, tx, tenantID, customerUserID)
	_, err = scanCustomerPortalExport(
		tx.QueryRow(ctx, query, kernel.AggregateAlert.String(), alertID, contactID, maximumCustomerPortalExportRows),
		tenantID, kernel.AggregateAlert, alertID,
	)
	if !errors.Is(err, application.ErrNotFound) {
		t.Fatalf("incoherent-state export error = %v, want not found", err)
	}
	if _, err = tx.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatalf("reset API role after state proof: %v", err)
	}
	if _, err = tx.Exec(ctx, `SET LOCAL ROLE "periapsis_migrator"`); err != nil {
		t.Fatalf("restore fixture role after state proof: %v", err)
	}
	if _, err = tx.Exec(ctx, `UPDATE public.alerts SET state_key = 'new' WHERE tenant_id = $1 AND id = $2`, tenantID, alertID); err != nil {
		t.Fatalf("restore current workflow state: %v", err)
	}
	if _, err = tx.Exec(ctx, `UPDATE public.ticket_customer_contacts SET archived_at = transaction_timestamp() WHERE tenant_id = $1 AND id = $2`, tenantID, linkID); err != nil {
		t.Fatalf("archive customer link: %v", err)
	}
	setCustomerExportAPIContext(t, ctx, tx, tenantID, customerUserID)
	_, err = scanCustomerPortalExport(
		tx.QueryRow(ctx, query, kernel.AggregateAlert.String(), alertID, contactID, maximumCustomerPortalExportRows),
		tenantID, kernel.AggregateAlert, alertID,
	)
	if !errors.Is(err, application.ErrNotFound) {
		t.Fatalf("archived-link export error = %v, want not found", err)
	}
}

func setCustomerExportAPIContext(t testing.TB, ctx context.Context, tx pgx.Tx, tenantID, userID uuid.UUID) {
	t.Helper()
	if _, err := tx.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatalf("reset role before API context: %v", err)
	}
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE "periapsis_api"`); err != nil {
		t.Fatalf("set API role: %v", err)
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true), set_config('app.user_id', $2, true)`, tenantID.String(), userID.String()); err != nil {
		t.Fatalf("install API context: %v", err)
	}
}

func exportIntegrationUUID(t testing.TB) uuid.UUID {
	t.Helper()
	identifier, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("generate UUIDv7: %v", err)
	}
	return identifier
}
