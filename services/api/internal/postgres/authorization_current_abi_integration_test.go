package postgres

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

func authorizationCurrentABIFixture(t *testing.T) (context.Context, *pgxpool.Pool, *AuthorizationRepository, authorizationIntegrationFixture, authorization.Actor) {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv(authorizationIntegrationDatabaseURL))
	if databaseURL == "" {
		t.Skipf("%s is not set", authorizationIntegrationDatabaseURL)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	admin := authorizationIntegrationPool(t, ctx, databaseURL, "")
	t.Cleanup(admin.Close)
	fixture := seedAuthorizationIntegrationFixture(t, ctx, admin)
	runtime := authorizationIntegrationPool(t, ctx, databaseURL, "periapsis_api")
	t.Cleanup(runtime.Close)
	return ctx, admin, NewAuthorizationRepository(runtime), fixture, authorizationIntegrationActor(t, fixture.tenantID, fixture.adminUserID)
}

func TestAuthorizationRepositoryGroupMemberLifecycleProjectionPostgreSQL(t *testing.T) {
	ctx, admin, repository, fixture, actor := authorizationCurrentABIFixture(t)
	groupID := authorizationIntegrationUUID(t)
	if _, err := repository.CreateTenantSecurityGroup(ctx, authorization.CreateTenantSecurityGroupParams{
		Actor: actor, Audit: authorizationIntegrationAudit(t), OccurredAt: time.Now().UTC(), TenantID: fixture.tenantID,
		GroupID: groupID, Key: "member_lifecycle_projection", Name: "Member lifecycle projection",
		Description: "Verify the live embedded tenant membership revision.", IdempotencyKey: "lifecycle-group-" + groupID.String(),
	}); err != nil {
		t.Fatal(err)
	}
	edgeID := authorizationIntegrationUUID(t)
	created, err := repository.AddTenantSecurityGroupMembership(ctx, authorization.AddTenantSecurityGroupMembershipParams{
		Actor: actor, Audit: authorizationIntegrationAudit(t), OccurredAt: time.Now().UTC(), TenantID: fixture.tenantID,
		GroupID: groupID, MembershipID: edgeID, UserID: fixture.targetUserID,
		Reason: "Exercise current member lifecycle projection.", IdempotencyKey: "lifecycle-edge-" + edgeID.String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	assertMember := func(label string, edge authorization.TenantSecurityGroupMembership, revision int64) {
		t.Helper()
		wantTag, err := authorization.TenantMembershipLifecycleEntityTag(revision)
		if err != nil {
			t.Fatal(err)
		}
		if edge.ID != edgeID || edge.Group.ID != groupID || edge.Member.MembershipID != fixture.targetMemberID ||
			edge.Member.User.ID != fixture.targetUserID || edge.Member.TenantID != fixture.tenantID ||
			edge.Member.LifecycleRevision != revision || edge.Member.EntityTag != wantTag {
			t.Errorf("%s: member lifecycle revision/tag = %d/%q, want %d/%q", label, edge.Member.LifecycleRevision, edge.Member.EntityTag, revision, wantTag)
		}
	}
	assertMember("create", created.Value, 1)
	// A privileged fixture mutation exercises the real lifecycle revision trigger.
	if _, err := admin.Exec(ctx, `UPDATE public.tenant_memberships SET status='suspended', updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2`, fixture.tenantID, fixture.targetMemberID); err != nil {
		t.Fatal(err)
	}
	got, err := repository.GetTenantSecurityGroupMembership(ctx, authorization.GetTenantSecurityGroupMembershipParams{
		Actor: actor, TenantID: fixture.tenantID, GroupID: groupID, MembershipID: edgeID,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertMember("detail after suspension", got, 2)
	secondEdgeID := authorizationIntegrationUUID(t)
	if _, err := repository.AddTenantSecurityGroupMembership(ctx, authorization.AddTenantSecurityGroupMembershipParams{
		Actor: actor, Audit: authorizationIntegrationAudit(t), OccurredAt: time.Now().UTC(), TenantID: fixture.tenantID,
		GroupID: groupID, MembershipID: secondEdgeID, UserID: fixture.adminUserID,
		Reason: "Exercise ordered membership pagination.", IdempotencyKey: "lifecycle-page-" + secondEdgeID.String(),
	}); err != nil {
		t.Fatal(err)
	}
	listed, err := repository.ListTenantSecurityGroupMemberships(ctx, authorization.ListTenantSecurityGroupMembershipsParams{
		Actor: actor, TenantID: fixture.tenantID, GroupID: groupID, Limit: 100, IncludeRevoked: true,
	})
	if err != nil || len(listed) != 2 {
		t.Fatalf("list member lifecycle: rows=%d, %v", len(listed), err)
	}
	if listed[0].ID.String() >= listed[1].ID.String() {
		t.Fatal("member lifecycle join lost stable edge-ID ordering")
	}
	assertMember("list after suspension", listed[0], 2)
	page, err := repository.ListTenantSecurityGroupMemberships(ctx, authorization.ListTenantSecurityGroupMembershipsParams{
		Actor: actor, TenantID: fixture.tenantID, GroupID: groupID, After: &listed[0].ID, Limit: 1, IncludeRevoked: true,
	})
	if err != nil || len(page) != 1 || page[0].ID != secondEdgeID || page[0].Member.LifecycleRevision != 1 {
		t.Fatalf("membership cursor page: %+v, %v", page, err)
	}
	service, err := authorization.NewService(repository)
	if err != nil {
		t.Fatal(err)
	}
	edgeTag, err := authorization.TenantSecurityGroupMembershipEntityTag(got)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.RevokeTenantSecurityGroupMembership(ctx, actor, fixture.tenantID, groupID, edgeID, authorization.RevokeTenantSecurityGroupMembershipInput{
		Reason: "Remove membership after suspension.", ExpectedEntityTag: &edgeTag, Audit: authorizationIntegrationAudit(t),
	}); err != nil {
		t.Fatalf("service must accept the complete suspended member projection: %v", err)
	}
}

func TestAuthorizationRepositoryCurrentHumanAdminGrantPostgreSQL(t *testing.T) {
	ctx, admin, repository, fixture, actor := authorizationCurrentABIFixture(t)
	var adminRoleID, machineRoleID uuid.UUID
	if err := admin.QueryRow(ctx, `SELECT id FROM public.tenant_roles WHERE tenant_id=$1 AND key='tenant_admin'`, fixture.tenantID).Scan(&adminRoleID); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `SELECT id FROM public.tenant_roles WHERE tenant_id=$1 AND key='service_account'`, fixture.tenantID).Scan(&machineRoleID); err != nil {
		t.Fatal(err)
	}
	grantID := authorizationIntegrationUUID(t)
	params := authorization.GrantUserRoleParams{
		Actor: actor, Audit: authorizationIntegrationAudit(t), OccurredAt: time.Now().UTC(), TenantID: fixture.tenantID,
		GrantID: grantID, UserID: fixture.targetUserID, RoleID: adminRoleID,
		Reason: "Grant the complete human administrator policy.", IdempotencyKey: "human-admin-" + grantID.String(),
	}
	created, err := repository.GrantUserRole(ctx, params)
	if err != nil {
		t.Fatalf("grant human administrator including service-account administration permissions: %v", err)
	}
	if created.Replayed || created.Value.ID != grantID || created.Value.Role.ID != adminRoleID || created.Value.Role.PrincipalKind != authorization.PrincipalKindHuman {
		t.Fatalf("invalid human administrator grant: %+v", created)
	}
	params.GrantID = authorizationIntegrationUUID(t)
	params.Audit = authorizationIntegrationAudit(t)
	replayed, err := repository.GrantUserRole(ctx, params)
	if err != nil || !replayed.Replayed || replayed.Value.ID != grantID {
		t.Fatalf("exact administrator replay: %+v, %v", replayed, err)
	}
	var audits int
	if err := admin.QueryRow(ctx, `SELECT count(*)::integer FROM public.audit_events WHERE tenant_id=$1 AND resource_id=$2 AND action='tenant.role_grant.created'`, fixture.tenantID, grantID).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if audits != 1 {
		t.Fatalf("administrator grant audit count=%d, want1", audits)
	}
	params.RoleID = machineRoleID
	params.IdempotencyKey = "reject-machine-" + params.GrantID.String()
	if _, err := repository.GrantUserRole(ctx, params); !errors.Is(err, authorization.ErrConflict) {
		t.Fatalf("machine role passed through human grant ABI: %v", err)
	}
	var machineEdges int
	if err := admin.QueryRow(ctx, `SELECT count(*)::integer FROM public.tenant_membership_role_grants WHERE tenant_id=$1 AND role_id=$2`, fixture.tenantID, machineRoleID).Scan(&machineEdges); err != nil {
		t.Fatal(err)
	}
	if machineEdges != 0 {
		t.Fatalf("human grant ABI persisted %d machine edges", machineEdges)
	}
	tag, err := authorization.DirectUserRoleGrantEntityTag(replayed.Value)
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.RevokeRoleGrant(ctx, authorization.RevokeRoleGrantParams{
		Actor: actor, Audit: authorizationIntegrationAudit(t), OccurredAt: time.Now().UTC(), TenantID: fixture.tenantID,
		GrantID: grantID, ExpectedEntityTag: tag, Reason: "Remove the additional human administrator.",
	}); err != nil {
		t.Fatalf("revoke a non-last human administrator: %v", err)
	}
}

func TestAuthorizationRepositoryCurrentHumanGroupAdminGrantPostgreSQL(t *testing.T) {
	ctx, admin, repository, fixture, actor := authorizationCurrentABIFixture(t)
	var adminRoleID, machineRoleID uuid.UUID
	if err := admin.QueryRow(ctx, `SELECT id FROM public.tenant_roles WHERE tenant_id=$1 AND key='tenant_admin'`, fixture.tenantID).Scan(&adminRoleID); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `SELECT id FROM public.tenant_roles WHERE tenant_id=$1 AND key='service_account'`, fixture.tenantID).Scan(&machineRoleID); err != nil {
		t.Fatal(err)
	}
	groupID := authorizationIntegrationUUID(t)
	if _, err := repository.CreateTenantSecurityGroup(ctx, authorization.CreateTenantSecurityGroupParams{
		Actor: actor, Audit: authorizationIntegrationAudit(t), OccurredAt: time.Now().UTC(), TenantID: fixture.tenantID,
		GroupID: groupID, Key: "human_admin_grants", Name: "Human administrator grants", Description: "Verify full human group grants.",
		IdempotencyKey: "human-group-" + groupID.String(),
	}); err != nil {
		t.Fatal(err)
	}
	grantID := authorizationIntegrationUUID(t)
	params := authorization.GrantTenantSecurityGroupRoleParams{
		Actor: actor, Audit: authorizationIntegrationAudit(t), OccurredAt: time.Now().UTC(), TenantID: fixture.tenantID,
		GroupID: groupID, GrantID: grantID, RoleID: adminRoleID, Reason: "Grant the complete human policy to a security group.",
		IdempotencyKey: "human-group-grant-" + grantID.String(),
	}
	created, err := repository.GrantTenantSecurityGroupRole(ctx, params)
	if err != nil {
		t.Fatalf("grant human administrator through security group: %v", err)
	}
	if created.Replayed || created.Value.ID != grantID || created.Value.Role.PrincipalKind != authorization.PrincipalKindHuman {
		t.Fatalf("invalid group grant: %+v", created)
	}
	params.GrantID = authorizationIntegrationUUID(t)
	params.Audit = authorizationIntegrationAudit(t)
	replayed, err := repository.GrantTenantSecurityGroupRole(ctx, params)
	if err != nil || !replayed.Replayed || replayed.Value.ID != grantID {
		t.Fatalf("group administrator replay: %+v, %v", replayed, err)
	}
	var audits int
	if err := admin.QueryRow(ctx, `SELECT count(*)::integer FROM public.audit_events WHERE tenant_id=$1 AND resource_id=$2 AND action='tenant.security_group.role_grant_created'`, fixture.tenantID, grantID).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if audits != 1 {
		t.Fatalf("group grant audit count=%d, want 1", audits)
	}
	params.RoleID = machineRoleID
	params.IdempotencyKey = "machine-group-reject-" + params.GrantID.String()
	if _, err := repository.GrantTenantSecurityGroupRole(ctx, params); !errors.Is(err, authorization.ErrConflict) {
		t.Fatalf("machine group grant: %v", err)
	}
	var machineEdges int
	if err := admin.QueryRow(ctx, `SELECT count(*)::integer FROM public.tenant_security_group_role_grants WHERE tenant_id=$1 AND role_id=$2`, fixture.tenantID, machineRoleID).Scan(&machineEdges); err != nil {
		t.Fatal(err)
	}
	if machineEdges != 0 {
		t.Fatalf("human group ABI persisted %d machine edges", machineEdges)
	}
	tag, err := authorization.TenantSecurityGroupRoleGrantEntityTag(replayed.Value)
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.RevokeTenantSecurityGroupRoleGrant(ctx, authorization.RevokeTenantSecurityGroupRoleGrantParams{
		Actor: actor, Audit: authorizationIntegrationAudit(t), OccurredAt: time.Now().UTC(), TenantID: fixture.tenantID,
		GroupID: groupID, GrantID: grantID, ExpectedEntityTag: tag, Reason: "Revoke the human group policy.",
	}); err != nil {
		t.Fatalf("revoke human group administrator: %v", err)
	}
}

func TestAuthorizationRepositoryCurrentHumanGrantLiveDelegationPostgreSQL(t *testing.T) {
	for _, route := range []string{"direct", "group"} {
		t.Run(route, func(t *testing.T) {
			ctx, admin, repository, fixture, actor := authorizationCurrentABIFixture(t)
			read := authorization.ScopedPermission{Permission: authorization.TenantPermissionPermissionRead, Scope: authorization.ScopeTenant}
			grant := authorization.ScopedPermission{Permission: authorization.TenantPermissionRoleGrant, Scope: authorization.ScopeTenant}
			manage := authorization.ScopedPermission{Permission: authorization.TenantPermissionGroupManage, Scope: authorization.ScopeTenant}
			createRole := func(key string, permissions []authorization.ScopedPermission) uuid.UUID {
				t.Helper()
				id := authorizationIntegrationUUID(t)
				if _, err := repository.CreateTenantRole(ctx, authorization.CreateTenantRoleParams{
					Actor: actor, Audit: authorizationIntegrationAudit(t), OccurredAt: time.Now().UTC(), TenantID: fixture.tenantID,
					RoleID: id, Key: key, Name: key, Description: "Verify live human delegation.", IdempotencyKey: "live-role-" + id.String(),
					Policy: authorization.TenantRolePolicy{Permissions: permissions, DelegationCeiling: permissions},
				}); err != nil {
					t.Fatal(err)
				}
				return id
			}
			readerID := createRole("current_reader", []authorization.ScopedPermission{read})
			delegatorID := createRole("current_delegator", []authorization.ScopedPermission{read, grant, manage})
			delegatorGrantID := authorizationIntegrationUUID(t)
			if _, err := repository.GrantUserRole(ctx, authorization.GrantUserRoleParams{
				Actor: actor, Audit: authorizationIntegrationAudit(t), OccurredAt: time.Now().UTC(), TenantID: fixture.tenantID,
				GrantID: delegatorGrantID, RoleID: delegatorID, UserID: fixture.targetUserID, Reason: "Establish a bounded human delegator.", IdempotencyKey: "delegator-" + delegatorGrantID.String(),
			}); err != nil {
				t.Fatal(err)
			}
			groupID := authorizationIntegrationUUID(t)
			if route == "group" {
				if _, err := repository.CreateTenantSecurityGroup(ctx, authorization.CreateTenantSecurityGroupParams{
					Actor: actor, Audit: authorizationIntegrationAudit(t), OccurredAt: time.Now().UTC(), TenantID: fixture.tenantID,
					GroupID: groupID, Key: "live_delegation", Name: "Live delegation", Description: "Verify group delegation ceilings.", IdempotencyKey: "live-group-" + groupID.String(),
				}); err != nil {
					t.Fatal(err)
				}
			}
			targetActor := authorizationIntegrationActor(t, fixture.tenantID, fixture.targetUserID)
			call := func(roleID, grantID uuid.UUID, key string) (uuid.UUID, bool, error) {
				if route == "direct" {
					result, err := repository.GrantUserRole(ctx, authorization.GrantUserRoleParams{
						Actor: targetActor, Audit: authorizationIntegrationAudit(t), OccurredAt: time.Now().UTC(), TenantID: fixture.tenantID,
						GrantID: grantID, UserID: fixture.adminUserID, RoleID: roleID, Reason: "Exercise live delegation.", IdempotencyKey: key,
					})
					return result.Value.ID, result.Replayed, err
				}
				result, err := repository.GrantTenantSecurityGroupRole(ctx, authorization.GrantTenantSecurityGroupRoleParams{
					Actor: targetActor, Audit: authorizationIntegrationAudit(t), OccurredAt: time.Now().UTC(), TenantID: fixture.tenantID,
					GroupID: groupID, GrantID: grantID, RoleID: roleID, Reason: "Exercise live delegation.", IdempotencyKey: key,
				})
				return result.Value.ID, result.Replayed, err
			}
			grantID := authorizationIntegrationUUID(t)
			key := "live-human-grant-" + grantID.String()
			if id, replayed, err := call(readerID, grantID, key); err != nil || replayed || id != grantID {
				t.Fatalf("fresh bounded grant: %s/%t, %v", id, replayed, err)
			}
			if id, replayed, err := call(readerID, authorizationIntegrationUUID(t), key); err != nil || !replayed || id != grantID {
				t.Fatalf("live bounded replay: %s/%t, %v", id, replayed, err)
			}
			// Keep mutation permissions and the target permission effective, removing only its delegation ceiling.
			if _, err := repository.ReplaceTenantRolePolicy(ctx, authorization.ReplaceTenantRolePolicyParams{
				Actor: actor, Audit: authorizationIntegrationAudit(t), OccurredAt: time.Now().UTC(), TenantID: fixture.tenantID,
				RoleID: delegatorID, ExpectedVersion: 1,
				Policy: authorization.TenantRolePolicy{Permissions: []authorization.ScopedPermission{read, grant, manage}, DelegationCeiling: []authorization.ScopedPermission{grant, manage}},
			}); err != nil {
				t.Fatal(err)
			}
			if _, _, err := call(readerID, authorizationIntegrationUUID(t), key); !errors.Is(err, authorization.ErrForbidden) {
				t.Fatalf("replay after removing live delegation: %v", err)
			}
			if _, _, err := call(readerID, authorizationIntegrationUUID(t), "fresh-after-ceiling-"+grantID.String()); !errors.Is(err, authorization.ErrForbidden) {
				t.Fatalf("fresh grant after removing live delegation: %v", err)
			}
			foreign := seedAuthorizationIntegrationFixture(t, ctx, admin)
			var foreignRoleID uuid.UUID
			if err := admin.QueryRow(ctx, `SELECT id FROM public.tenant_roles WHERE tenant_id=$1 AND key='tenant_admin'`, foreign.tenantID).Scan(&foreignRoleID); err != nil {
				t.Fatal(err)
			}
			if _, _, err := call(foreignRoleID, authorizationIntegrationUUID(t), "foreign-role-"+grantID.String()); !errors.Is(err, authorization.ErrNotFound) {
				t.Fatalf("cross-tenant human role grant: %v", err)
			}
		})
	}
}

func TestAuthorizationRepositoryCurrentHumanRevokeRejectsMachinePostgreSQL(t *testing.T) {
	for _, route := range []string{"direct", "group"} {
		t.Run(route, func(t *testing.T) {
			ctx, admin, repository, fixture, actor := authorizationCurrentABIFixture(t)
			var machineRoleID uuid.UUID
			if err := admin.QueryRow(ctx, `SELECT id FROM public.tenant_roles WHERE tenant_id=$1 AND key='service_account'`, fixture.tenantID).Scan(&machineRoleID); err != nil {
				t.Fatal(err)
			}
			groupID := authorizationIntegrationUUID(t)
			if route == "group" {
				if _, err := repository.CreateTenantSecurityGroup(ctx, authorization.CreateTenantSecurityGroupParams{
					Actor: actor, Audit: authorizationIntegrationAudit(t), OccurredAt: time.Now().UTC(), TenantID: fixture.tenantID,
					GroupID: groupID, Key: "reject_machine_revoke", Name: "Reject machine revoke", Description: "Verify the human writer boundary.", IdempotencyKey: "machine-revoke-group-" + groupID.String(),
				}); err != nil {
					t.Fatal(err)
				}
			}
			for _, expired := range []bool{false, true} {
				t.Run(map[bool]string{false: "live", true: "expired"}[expired], func(t *testing.T) {
					// A rollback-only privileged fixture models a legacy malformed machine edge.
					// The actual revoke executes as the API role with ordinary tenant/user context.
					tx, err := admin.Begin(ctx)
					if err != nil {
						t.Fatal(err)
					}
					defer func() { _ = tx.Rollback(ctx) }()
					grantID := authorizationIntegrationUUID(t)
					if route == "direct" {
						_, err = tx.Exec(ctx, `INSERT INTO public.tenant_membership_role_grants
				 (id, tenant_id, membership_id, role_id, source_id, granted_by_membership_id, grant_reason, granted_at, expires_at)
				 SELECT $1,$2,$3,$4,source.id,$5,'Rollback-only machine fixture',transaction_timestamp()-interval '2 hours',
				 CASE WHEN $6 THEN transaction_timestamp()-interval '1 hour' ELSE NULL END
				 FROM public.tenant_authorization_sources AS source WHERE source.tenant_id=$2 AND source.key='manual'`,
							grantID, fixture.tenantID, fixture.targetMemberID, machineRoleID, fixture.adminMemberID, expired)
					} else {
						_, err = tx.Exec(ctx, `INSERT INTO public.tenant_security_group_role_grants
				 (id, tenant_id, group_id, role_id, source_id, granted_by_membership_id, grant_reason, granted_at, expires_at)
				 SELECT $1,$2,$3,$4,source.id,$5,'Rollback-only machine fixture',transaction_timestamp()-interval '2 hours',
				 CASE WHEN $6 THEN transaction_timestamp()-interval '1 hour' ELSE NULL END
				 FROM public.tenant_authorization_sources AS source WHERE source.tenant_id=$2 AND source.key='manual'`,
							grantID, fixture.tenantID, groupID, machineRoleID, fixture.adminMemberID, expired)
					}
					if err != nil {
						t.Fatal(err)
					}
					if _, err := tx.Exec(ctx, `SET LOCAL ROLE periapsis_api`); err != nil {
						t.Fatal(err)
					}
					if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id',$1,true),set_config('app.user_id',$2,true)`, fixture.tenantID.String(), fixture.adminUserID.String()); err != nil {
						t.Fatal(err)
					}
					if route == "direct" {
						_, err = tx.Exec(ctx, `SELECT app.revoke_tenant_human_user_role_grant_v1($1,1,'Reject machine role',$2,$3,$4,'192.0.2.40','Current human ABI test','totp')`, grantID, authorizationIntegrationUUID(t), authorizationIntegrationUUID(t), authorizationIntegrationUUID(t))
					} else {
						_, err = tx.Exec(ctx, `SELECT app.revoke_tenant_human_security_group_role_grant_v1($1,$2,1,'Reject machine role',$3,$4,$5,'192.0.2.40','Current human ABI test','totp')`, groupID, grantID, authorizationIntegrationUUID(t), authorizationIntegrationUUID(t), authorizationIntegrationUUID(t))
					}
					var pgErr *pgconn.PgError
					if !errors.As(err, &pgErr) || pgErr.Code != "55000" || pgErr.Message != "human role revoke cannot target a machine role" {
						t.Fatalf("machine edge revoke crossed human ABI: %v", err)
					}
				})
			}
		})
	}
}
