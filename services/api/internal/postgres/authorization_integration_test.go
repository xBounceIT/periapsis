package postgres

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
)

const (
	authorizationIntegrationDatabaseURL    = "PERIAPSIS_AUTHORIZATION_TEST_DATABASE_URL"
	authorizationIntegrationCustomReason   = "Exercise active direct-grant hydration."
	authorizationIntegrationRecoveryReason = "Establish a second recovery administrator."
)

type authorizationIntegrationFixture struct {
	tenantID       uuid.UUID
	adminUserID    uuid.UUID
	adminMemberID  uuid.UUID
	targetUserID   uuid.UUID
	targetMemberID uuid.UUID
}

func TestAuthorizationRepositoryPostgreSQL(t *testing.T) {
	databaseURL := strings.TrimSpace(os.Getenv(authorizationIntegrationDatabaseURL))
	if databaseURL == "" {
		t.Skipf("%s is not set", authorizationIntegrationDatabaseURL)
	}
	t.Run("policy self-demotion commits without post-mutation read authority", func(t *testing.T) {
		testAuthorizationRepositoryPolicySelfDemotionPostgreSQL(t, databaseURL)
	})
	t.Run("archived custom roles retain manual grant cleanup", func(t *testing.T) {
		testAuthorizationRepositoryArchivedRoleGrantCleanupPostgreSQL(t, databaseURL)
	})
	t.Run("external manual group edges expose canonical ownership", func(t *testing.T) {
		testAuthorizationRepositoryExternalManualGroupOwnershipPostgreSQL(t, databaseURL)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	adminPool := authorizationIntegrationPool(t, ctx, databaseURL, "")
	defer adminPool.Close()
	fixture := seedAuthorizationIntegrationFixture(t, ctx, adminPool)

	runtimePool := authorizationIntegrationPool(t, ctx, databaseURL, "periapsis_api")
	defer runtimePool.Close()
	var databaseRole string
	if err := runtimePool.QueryRow(ctx, `SELECT current_user`).Scan(&databaseRole); err != nil {
		t.Fatalf("read authorization integration database role: %v", err)
	}
	if databaseRole != "periapsis_api" {
		t.Fatalf("authorization integration database role = %q, want periapsis_api", databaseRole)
	}
	rateLimitDigest := sha256.Sum256([]byte("authorization-integration:" + fixture.tenantID.String()))
	blockedUntil, err := NewAuthenticationRepository(runtimePool).AdmitRateLimits(
		ctx,
		authentication.AdmitRateLimitsParams{
			Rules: []authentication.RateLimitRule{
				{
					Key: authentication.RateLimitKey{
						Scope: "local_login", Digest: rateLimitDigest[:],
					},
					Policy: authentication.RateLimitPolicy{
						Limit: 5, Window: time.Minute, BlockFor: time.Minute,
					},
				},
			},
			OccurredAt: time.Now().UTC(),
		},
	)
	if err != nil {
		t.Fatalf("admit authentication attempt with non-empty scope array: %v", err)
	}
	if !blockedUntil.IsZero() {
		t.Fatalf("first authentication attempt unexpectedly blocked until %s", blockedUntil)
	}

	repository := NewAuthorizationRepository(runtimePool)
	adminActor := authorizationIntegrationActor(t, fixture.tenantID, fixture.adminUserID)
	targetActor := authorizationIntegrationActor(t, fixture.tenantID, fixture.targetUserID)
	service, err := authorization.NewService(repository)
	if err != nil {
		t.Fatalf("create authorization service for repository integration: %v", err)
	}
	adminAuthority, err := repository.ResolveAuthority(ctx, authorization.ResolveAuthorityParams{Actor: adminActor, TenantID: fixture.tenantID})
	if err != nil {
		t.Fatalf("hydrate complete administrator authority: %v", err)
	}
	if len(adminAuthority.Permissions) <= 100 {
		t.Fatalf("administrator fixture must cross the public page bound, got %d permission tuples", len(adminAuthority.Permissions))
	}
	if _, err := service.GetTenantAuthority(ctx, adminActor, fixture.tenantID); err != nil {
		t.Fatalf("validate complete administrator authority: %v", err)
	}

	recoveryGrantPage, err := service.ListUserRoleGrants(
		ctx,
		adminActor,
		fixture.tenantID,
		fixture.adminUserID,
		authorization.ListUserRoleGrantsInput{
			IncludeRevoked: true,
		},
	)
	if err != nil {
		t.Fatalf("list tenant-creation recovery grant: %v", err)
	}
	recoveryGrants := recoveryGrantPage.Items
	if len(recoveryGrants) != 1 {
		t.Fatalf("tenant-creation recovery grant list = %+v, want one row", recoveryGrants)
	}
	recoveryGrant := recoveryGrants[0]
	if recoveryGrant.Role.Key != "tenant_admin" || !recoveryGrant.Role.System ||
		recoveryGrant.Role.Archived || recoveryGrant.PathType != authorization.RoleGrantPathDirect ||
		recoveryGrant.Provenance.SourceType != authorization.RoleGrantSourceSystem ||
		recoveryGrant.Provenance.SourceKind != authorization.AuthorizationSourceTenantCreation ||
		recoveryGrant.ManagedByAuthorizationAPI ||
		recoveryGrant.Provenance.SourceID == nil || recoveryGrant.Provenance.Authoritative ||
		recoveryGrant.Provenance.RetiredAt != nil ||
		recoveryGrant.Provenance.GrantedByUserID == nil ||
		*recoveryGrant.Provenance.GrantedByUserID != fixture.adminUserID ||
		recoveryGrant.Provenance.Reason != "Protected tenant recovery administrator." ||
		recoveryGrant.Provenance.ExpiresAt != nil ||
		recoveryGrant.State != authorization.DirectRoleGrantStateActive ||
		recoveryGrant.RevokedAt != nil || recoveryGrant.RevokedByUserID != nil ||
		recoveryGrant.RevokeReason != nil || recoveryGrant.Version != 1 {
		t.Fatalf("tenant-creation recovery grant projection = %+v", recoveryGrant)
	}
	recoveryGrantDetail, err := repository.GetUserRoleGrant(
		ctx,
		authorization.GetUserRoleGrantParams{
			Actor: adminActor, TenantID: fixture.tenantID, GrantID: recoveryGrant.ID,
		},
	)
	if err != nil {
		t.Fatalf("get tenant-creation recovery grant: %v", err)
	}
	recoveryEntityTag, err := authorization.DirectUserRoleGrantEntityTag(recoveryGrant)
	if err != nil {
		t.Fatalf("compute listed tenant-creation grant entity tag: %v", err)
	}
	detailEntityTag, err := authorization.DirectUserRoleGrantEntityTag(recoveryGrantDetail)
	if err != nil {
		t.Fatalf("compute detailed tenant-creation grant entity tag: %v", err)
	}
	if detailEntityTag != recoveryEntityTag {
		t.Fatalf("tenant-creation grant list/detail entity tags differ: %q != %q", recoveryEntityTag, detailEntityTag)
	}
	if err = service.RevokeRoleGrant(
		ctx,
		adminActor,
		fixture.tenantID,
		recoveryGrant.ID,
		authorization.RevokeRoleGrantInput{
			Reason:            "A manual actor must not revoke source-owned recovery authority.",
			ExpectedEntityTag: &recoveryEntityTag,
			Audit:             authorizationIntegrationAudit(t),
		},
	); !errors.Is(err, authorization.ErrConflict) {
		t.Fatalf("tenant-creation grant revoke error = %v, want conflict", err)
	}
	var sourceOwnedRevokeAudits int
	if err = adminPool.QueryRow(
		ctx,
		`SELECT count(*)::integer
		 FROM public.audit_events
		 WHERE tenant_id = $1
		   AND action = 'tenant.role_grant.revoked'
		   AND resource_id = $2`,
		fixture.tenantID,
		recoveryGrant.ID,
	).Scan(&sourceOwnedRevokeAudits); err != nil {
		t.Fatalf("count rejected tenant-creation revoke audit events: %v", err)
	}
	if sourceOwnedRevokeAudits != 0 {
		t.Fatalf("rejected tenant-creation revoke persisted %d audit events", sourceOwnedRevokeAudits)
	}

	authority, err := repository.ResolveAuthority(ctx, authorization.ResolveAuthorityParams{
		Actor: adminActor, TenantID: fixture.tenantID,
	})
	if err != nil {
		t.Fatalf("resolve seeded tenant administrator authority: %v", err)
	}
	if authority.TenantID != fixture.tenantID || authority.Principal.ID != fixture.adminUserID ||
		authority.MembershipID != fixture.adminMemberID ||
		authority.MembershipStatus != authorization.MembershipStatusActive {
		t.Fatalf("unexpected seeded tenant authority: %+v", authority)
	}
	if len(authority.RoleGrants) != 1 ||
		authority.RoleGrants[0].Provenance.SourceType != authorization.RoleGrantSourceSystem {
		t.Fatalf("seeded authority role grants = %+v, want one system grant", authority.RoleGrants)
	}

	permissionCatalog, err := repository.ListTenantPermissions(
		ctx,
		authorization.ListTenantPermissionsParams{
			Actor: adminActor, TenantID: fixture.tenantID, Limit: authorizationHydrationLimit,
		},
	)
	if err != nil {
		t.Fatalf("list tenant permission catalog: %v", err)
	}
	document, err := contract.GetSpec()
	if err != nil {
		t.Fatal(err)
	}
	canonicalPermissions := document.Components.Schemas["TenantPermissionKey"].Value.Enum
	if len(permissionCatalog) != len(canonicalPermissions) {
		t.Fatalf("permission catalog length = %d, canonical contract = %d", len(permissionCatalog), len(canonicalPermissions))
	}
	seenPermissions := make(map[string]bool, len(permissionCatalog))
	for _, permission := range permissionCatalog {
		if permission.ID.Version() != 7 || seenPermissions[string(permission.Key)] || !slices.Contains(permission.PrincipalKinds, authorization.PrincipalKindHuman) {
			t.Fatalf("unexpected permission catalog projection: %+v", permission)
		}
		seenPermissions[string(permission.Key)] = true
	}
	for _, key := range canonicalPermissions {
		if !seenPermissions[key.(string)] {
			t.Errorf("canonical permission %q missing", key)
		}
	}
	// The service validates every projected scope/principal-kind tuple against
	// the independent backend evaluator catalog, not just permission names.
	validatedCatalog, err := service.ListTenantPermissions(ctx, adminActor, fixture.tenantID, authorization.PageInput{Limit: 100})
	if err != nil || len(validatedCatalog.Items) != len(permissionCatalog) {
		t.Fatalf("validate current permission catalog: %v", err)
	}
	adminPermissions := authorizationIntegrationAdminPermissions(permissionCatalog)
	assertAuthorizationIntegrationAuthority(t, authority, adminPermissions)

	users, err := repository.ListTenantUsers(ctx, authorization.ListTenantUsersParams{
		Actor: adminActor, TenantID: fixture.tenantID, Limit: authorizationHydrationLimit,
	})
	if err != nil {
		t.Fatalf("list tenant authorization users: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("tenant user projection length = %d, want 2", len(users))
	}

	roles, err := repository.ListTenantRoles(ctx, authorization.ListTenantRolesParams{
		Actor: adminActor, TenantID: fixture.tenantID, Limit: authorizationHydrationLimit,
	})
	if err != nil {
		t.Fatalf("list tenant authorization roles: %v", err)
	}
	adminRole := authorizationIntegrationRole(t, roles, "tenant_admin")
	adminRoleWithPolicy, err := repository.GetTenantRole(ctx, authorization.GetTenantRoleParams{
		Actor: adminActor, TenantID: fixture.tenantID, RoleID: adminRole.ID,
	})
	if err != nil {
		t.Fatalf("hydrate tenant administrator role and policy: %v", err)
	}
	if adminRoleWithPolicy.ID != adminRole.ID || adminRoleWithPolicy.Version != 1 {
		t.Fatalf("unexpected tenant administrator role projection: %+v", adminRoleWithPolicy)
	}
	assertAuthorizationIntegrationPolicy(
		t,
		adminRoleWithPolicy.Policy,
		adminPermissions,
		adminPermissions,
	)

	customRoleID := authorizationIntegrationUUID(t)
	customRoleCreateKey := "integration-create-role-" + customRoleID.String()
	initialPolicy := authorization.TenantRolePolicy{
		Permissions: []authorization.ScopedPermission{
			{Permission: authorization.TenantPermissionPermissionRead, Scope: authorization.ScopeTenant},
		},
		DelegationCeiling: []authorization.ScopedPermission{
			{Permission: authorization.TenantPermissionPermissionRead, Scope: authorization.ScopeTenant},
		},
	}
	customRoleResult, err := repository.CreateTenantRole(ctx, authorization.CreateTenantRoleParams{
		Actor: adminActor, Audit: authorizationIntegrationAudit(t), OccurredAt: time.Now().UTC(),
		TenantID: fixture.tenantID, RoleID: customRoleID, Key: "integration_operator",
		Name: "Integration operator", Description: "Exercises PostgreSQL authorization hydration.",
		Policy: initialPolicy, IdempotencyKey: customRoleCreateKey,
	})
	if err != nil {
		t.Fatalf("create tenant role with non-empty enum-backed policy: %v", err)
	}
	if customRoleResult.Replayed {
		t.Fatal("new tenant role creation was reported as replayed")
	}
	customRole := customRoleResult.Value
	if customRole.ID != customRoleID || customRole.Version != 1 || customRole.System || customRole.Archived {
		t.Fatalf("unexpected created role projection: %+v", customRole)
	}
	assertAuthorizationIntegrationPolicy(t, customRole.Policy, initialPolicy.Permissions, initialPolicy.DelegationCeiling)

	groupID := authorizationIntegrationUUID(t)
	groupCreateKey := "integration-create-group-" + groupID.String()
	securityGroupResult, err := repository.CreateTenantSecurityGroup(
		ctx,
		authorization.CreateTenantSecurityGroupParams{
			Actor: adminActor, Audit: authorizationIntegrationAudit(t), OccurredAt: time.Now().UTC(),
			TenantID: fixture.tenantID, GroupID: groupID, Key: "integration_triage",
			Name: "Integration triage", Description: "Exercises inherited group authority.",
			IdempotencyKey: groupCreateKey,
		},
	)
	if err != nil {
		t.Fatalf("create tenant security group: %v", err)
	}
	if securityGroupResult.Replayed {
		t.Fatal("new tenant security group creation was reported as replayed")
	}
	securityGroup := securityGroupResult.Value
	if securityGroup.ID != groupID || securityGroup.Version != 1 || securityGroup.Archived {
		t.Fatalf("unexpected created security group: %+v", securityGroup)
	}
	updatedGroupName := "Integration incident triage"
	securityGroup, err = repository.UpdateTenantSecurityGroup(
		ctx,
		authorization.UpdateTenantSecurityGroupParams{
			Actor: adminActor, Audit: authorizationIntegrationAudit(t), OccurredAt: time.Now().UTC(),
			TenantID: fixture.tenantID, GroupID: groupID, Name: &updatedGroupName,
			ExpectedVersion: securityGroup.Version,
		},
	)
	if err != nil {
		t.Fatalf("update tenant security group: %v", err)
	}
	if securityGroup.Name != updatedGroupName || securityGroup.Version != 2 {
		t.Fatalf("unexpected updated security group: %+v", securityGroup)
	}

	groupMembershipID := authorizationIntegrationUUID(t)
	groupMembershipCreateKey := "integration-add-group-member-" + groupMembershipID.String()
	groupMembershipResult, err := repository.AddTenantSecurityGroupMembership(
		ctx,
		authorization.AddTenantSecurityGroupMembershipParams{
			Actor: adminActor, Audit: authorizationIntegrationAudit(t), OccurredAt: time.Now().UTC(),
			TenantID: fixture.tenantID, GroupID: groupID, MembershipID: groupMembershipID,
			UserID: fixture.targetUserID, Reason: "Assign integration target to triage.",
			IdempotencyKey: groupMembershipCreateKey,
		},
	)
	if err != nil {
		t.Fatalf("add tenant security group membership: %v", err)
	}
	if groupMembershipResult.Replayed {
		t.Fatal("new tenant security group membership was reported as replayed")
	}
	groupMembership := groupMembershipResult.Value
	if groupMembership.ID != groupMembershipID || groupMembership.Group.ID != groupID ||
		groupMembership.Member.MembershipID != fixture.targetMemberID ||
		groupMembership.Member.User.ID != fixture.targetUserID ||
		groupMembership.Provenance.SourceKind != authorization.AuthorizationSourceManual ||
		!groupMembership.ManagedByAuthorizationAPI ||
		groupMembership.State != authorization.AuthorizationEdgeStateActive || groupMembership.Version != 1 {
		t.Fatalf("unexpected security group membership: %+v", groupMembership)
	}

	groupRoleGrantID := authorizationIntegrationUUID(t)
	groupRoleGrantCreateKey := "integration-grant-group-role-" + groupRoleGrantID.String()
	groupRoleGrantResult, err := repository.GrantTenantSecurityGroupRole(
		ctx,
		authorization.GrantTenantSecurityGroupRoleParams{
			Actor: adminActor, Audit: authorizationIntegrationAudit(t), OccurredAt: time.Now().UTC(),
			TenantID: fixture.tenantID, GroupID: groupID, GrantID: groupRoleGrantID,
			RoleID: customRoleID, Reason: "Grant integration triage authority.",
			IdempotencyKey: groupRoleGrantCreateKey,
		},
	)
	if err != nil {
		t.Fatalf("grant tenant security group role: %v", err)
	}
	if groupRoleGrantResult.Replayed {
		t.Fatal("new tenant security group role grant was reported as replayed")
	}
	groupRoleGrant := groupRoleGrantResult.Value
	if groupRoleGrant.ID != groupRoleGrantID || groupRoleGrant.Group.ID != groupID ||
		groupRoleGrant.Role.ID != customRoleID ||
		groupRoleGrant.Provenance.SourceKind != authorization.AuthorizationSourceManual ||
		!groupRoleGrant.ManagedByAuthorizationAPI ||
		groupRoleGrant.State != authorization.AuthorizationEdgeStateActive || groupRoleGrant.Version != 1 {
		t.Fatalf("unexpected security group role grant: %+v", groupRoleGrant)
	}

	groupAuthority, err := repository.ResolveAuthority(ctx, authorization.ResolveAuthorityParams{
		Actor: targetActor, TenantID: fixture.tenantID,
	})
	if err != nil {
		t.Fatalf("resolve group-derived target authority: %v", err)
	}
	if len(groupAuthority.RoleGrants) != 1 ||
		groupAuthority.RoleGrants[0].GrantID != groupRoleGrantID ||
		groupAuthority.RoleGrants[0].Path.PathType != authorization.RoleGrantPathGroup ||
		groupAuthority.RoleGrants[0].Path.Group == nil ||
		groupAuthority.RoleGrants[0].Path.Group.Group.ID != groupID ||
		groupAuthority.RoleGrants[0].Path.Group.MembershipEdge.ID != groupMembershipID ||
		groupAuthority.RoleGrants[0].Path.Group.RoleGrantEdge.ID != groupRoleGrantID {
		t.Fatalf("unexpected group-derived authority path: %+v", groupAuthority.RoleGrants)
	}

	groupRoleRevokeReason := "Close integration group role grant."
	groupRoleEntityTag, err := authorization.TenantSecurityGroupRoleGrantEntityTag(groupRoleGrant)
	if err != nil {
		t.Fatalf("compute group role-grant entity tag: %v", err)
	}
	if err := repository.RevokeTenantSecurityGroupRoleGrant(
		ctx,
		authorization.RevokeTenantSecurityGroupRoleGrantParams{
			Actor: adminActor, Audit: authorizationIntegrationAudit(t), OccurredAt: time.Now().UTC(),
			TenantID: fixture.tenantID, GroupID: groupID, GrantID: groupRoleGrantID,
			Reason: groupRoleRevokeReason, ExpectedEntityTag: groupRoleEntityTag,
		},
	); err != nil {
		t.Fatalf("revoke tenant security group role grant: %v", err)
	}
	revokedGroupRoleGrants, err := repository.ListTenantSecurityGroupRoleGrants(
		ctx,
		authorization.ListTenantSecurityGroupRoleGrantsParams{
			Actor: adminActor, TenantID: fixture.tenantID, GroupID: groupID,
			Limit: authorizationHydrationLimit, IncludeRevoked: true,
		},
	)
	if err != nil {
		t.Fatalf("list revoked tenant security group role grants: %v", err)
	}
	if len(revokedGroupRoleGrants) != 1 ||
		!revokedGroupRoleGrants[0].ManagedByAuthorizationAPI ||
		revokedGroupRoleGrants[0].State != authorization.AuthorizationEdgeStateRevoked ||
		revokedGroupRoleGrants[0].RevokeReason == nil ||
		*revokedGroupRoleGrants[0].RevokeReason != groupRoleRevokeReason ||
		revokedGroupRoleGrants[0].Version != 2 {
		t.Fatalf("unexpected revoked security group role grant history: %+v", revokedGroupRoleGrants)
	}
	replayedGroupRoleGrantResult, err := repository.GrantTenantSecurityGroupRole(
		ctx,
		authorization.GrantTenantSecurityGroupRoleParams{
			Actor: adminActor, Audit: authorizationIntegrationAudit(t), OccurredAt: time.Now().UTC(),
			TenantID: fixture.tenantID, GroupID: groupID, GrantID: authorizationIntegrationUUID(t),
			RoleID: customRoleID, Reason: "Grant integration triage authority.",
			IdempotencyKey: groupRoleGrantCreateKey,
		},
	)
	if err != nil {
		t.Fatalf("replay revoked tenant security group role grant: %v", err)
	}
	if !replayedGroupRoleGrantResult.Replayed {
		t.Fatal("tenant security group role grant retry was not reported as replayed")
	}
	replayedGroupRoleGrant := replayedGroupRoleGrantResult.Value
	if replayedGroupRoleGrant.ID != groupRoleGrantID ||
		!replayedGroupRoleGrant.ManagedByAuthorizationAPI ||
		replayedGroupRoleGrant.State != authorization.AuthorizationEdgeStateRevoked ||
		replayedGroupRoleGrant.Version != 2 {
		t.Fatalf("unexpected replayed security group role grant: %+v", replayedGroupRoleGrant)
	}

	groupMembershipRevokeReason := "Close integration group membership."
	groupMembershipEntityTag, err := authorization.TenantSecurityGroupMembershipEntityTag(groupMembership)
	if err != nil {
		t.Fatalf("compute group-membership entity tag: %v", err)
	}
	if err := repository.RevokeTenantSecurityGroupMembership(
		ctx,
		authorization.RevokeTenantSecurityGroupMembershipParams{
			Actor: adminActor, Audit: authorizationIntegrationAudit(t), OccurredAt: time.Now().UTC(),
			TenantID: fixture.tenantID, GroupID: groupID, MembershipID: groupMembershipID,
			Reason: groupMembershipRevokeReason, ExpectedEntityTag: groupMembershipEntityTag,
		},
	); err != nil {
		t.Fatalf("revoke tenant security group membership: %v", err)
	}
	revokedGroupMemberships, err := repository.ListTenantSecurityGroupMemberships(
		ctx,
		authorization.ListTenantSecurityGroupMembershipsParams{
			Actor: adminActor, TenantID: fixture.tenantID, GroupID: groupID,
			Limit: authorizationHydrationLimit, IncludeRevoked: true,
		},
	)
	if err != nil {
		t.Fatalf("list revoked tenant security group memberships: %v", err)
	}
	if len(revokedGroupMemberships) != 1 ||
		!revokedGroupMemberships[0].ManagedByAuthorizationAPI ||
		revokedGroupMemberships[0].State != authorization.AuthorizationEdgeStateRevoked ||
		revokedGroupMemberships[0].RevokeReason == nil ||
		*revokedGroupMemberships[0].RevokeReason != groupMembershipRevokeReason ||
		revokedGroupMemberships[0].Version != 2 {
		t.Fatalf("unexpected revoked security group membership history: %+v", revokedGroupMemberships)
	}
	replayedGroupMembershipResult, err := repository.AddTenantSecurityGroupMembership(
		ctx,
		authorization.AddTenantSecurityGroupMembershipParams{
			Actor: adminActor, Audit: authorizationIntegrationAudit(t), OccurredAt: time.Now().UTC(),
			TenantID: fixture.tenantID, GroupID: groupID, MembershipID: authorizationIntegrationUUID(t),
			UserID: fixture.targetUserID, Reason: "Assign integration target to triage.",
			IdempotencyKey: groupMembershipCreateKey,
		},
	)
	if err != nil {
		t.Fatalf("replay revoked tenant security group membership: %v", err)
	}
	if !replayedGroupMembershipResult.Replayed {
		t.Fatal("tenant security group membership retry was not reported as replayed")
	}
	replayedGroupMembership := replayedGroupMembershipResult.Value
	if replayedGroupMembership.ID != groupMembershipID ||
		!replayedGroupMembership.ManagedByAuthorizationAPI ||
		replayedGroupMembership.State != authorization.AuthorizationEdgeStateRevoked ||
		replayedGroupMembership.Version != 2 {
		t.Fatalf("unexpected replayed security group membership: %+v", replayedGroupMembership)
	}

	if err := repository.ArchiveTenantSecurityGroup(
		ctx,
		authorization.ArchiveTenantSecurityGroupParams{
			Actor: adminActor, Audit: authorizationIntegrationAudit(t), OccurredAt: time.Now().UTC(),
			TenantID: fixture.tenantID, GroupID: groupID, ExpectedVersion: securityGroup.Version,
		},
	); err != nil {
		t.Fatalf("archive tenant security group: %v", err)
	}
	archivedGroups, err := repository.ListTenantSecurityGroups(
		ctx,
		authorization.ListTenantSecurityGroupsParams{
			Actor: adminActor, TenantID: fixture.tenantID,
			Limit: authorizationHydrationLimit, IncludeArchived: true,
		},
	)
	if err != nil {
		t.Fatalf("list archived tenant security groups: %v", err)
	}
	if len(archivedGroups) != 1 || archivedGroups[0].ID != groupID ||
		!archivedGroups[0].Archived || archivedGroups[0].ArchivedAt == nil ||
		archivedGroups[0].Version != 3 {
		t.Fatalf("unexpected archived security group history: %+v", archivedGroups)
	}
	replayedSecurityGroupResult, err := repository.CreateTenantSecurityGroup(
		ctx,
		authorization.CreateTenantSecurityGroupParams{
			Actor: adminActor, Audit: authorizationIntegrationAudit(t), OccurredAt: time.Now().UTC(),
			TenantID: fixture.tenantID, GroupID: authorizationIntegrationUUID(t), Key: "integration_triage",
			Name: "Integration triage", Description: "Exercises inherited group authority.",
			IdempotencyKey: groupCreateKey,
		},
	)
	if err != nil {
		t.Fatalf("replay archived tenant security group: %v", err)
	}
	if !replayedSecurityGroupResult.Replayed {
		t.Fatal("tenant security group retry was not reported as replayed")
	}
	replayedSecurityGroup := replayedSecurityGroupResult.Value
	if replayedSecurityGroup.ID != groupID || replayedSecurityGroup.Name != updatedGroupName ||
		!replayedSecurityGroup.Archived || replayedSecurityGroup.Version != 3 {
		t.Fatalf("unexpected replayed archived security group: %+v", replayedSecurityGroup)
	}
	_, err = repository.CreateTenantSecurityGroup(
		ctx,
		authorization.CreateTenantSecurityGroupParams{
			Actor: adminActor, Audit: authorizationIntegrationAudit(t), OccurredAt: time.Now().UTC(),
			TenantID: fixture.tenantID, GroupID: authorizationIntegrationUUID(t), Key: "integration_triage",
			Name: "Drifted integration triage", Description: "Exercises inherited group authority.",
			IdempotencyKey: groupCreateKey,
		},
	)
	if !errors.Is(err, authorization.ErrConflict) {
		t.Fatalf("payload-drifted security group replay error = %v, want conflict", err)
	}

	replacementPolicy := authorization.TenantRolePolicy{
		Permissions: []authorization.ScopedPermission{
			{Permission: authorization.TenantPermissionRoleRead, Scope: authorization.ScopeTenant},
			{Permission: authorization.TenantPermissionUserRead, Scope: authorization.ScopeTenant},
		},
		DelegationCeiling: []authorization.ScopedPermission{
			{Permission: authorization.TenantPermissionRoleRead, Scope: authorization.ScopeTenant},
		},
	}
	customRole, err = repository.ReplaceTenantRolePolicy(
		ctx,
		authorization.ReplaceTenantRolePolicyParams{
			Actor: adminActor, Audit: authorizationIntegrationAudit(t), OccurredAt: time.Now().UTC(),
			TenantID: fixture.tenantID, RoleID: customRoleID, Policy: replacementPolicy,
			ExpectedVersion: customRole.Version,
		},
	)
	if err != nil {
		t.Fatalf("replace tenant role with non-empty enum-backed policy: %v", err)
	}
	if customRole.Version != 2 {
		t.Fatalf("replaced role version = %d, want 2", customRole.Version)
	}
	assertAuthorizationIntegrationPolicy(
		t, customRole.Policy, replacementPolicy.Permissions, replacementPolicy.DelegationCeiling,
	)
	replayedCustomRoleResult, err := repository.CreateTenantRole(ctx, authorization.CreateTenantRoleParams{
		Actor: adminActor, Audit: authorizationIntegrationAudit(t), OccurredAt: time.Now().UTC(),
		TenantID: fixture.tenantID, RoleID: authorizationIntegrationUUID(t), Key: "integration_operator",
		Name: "Integration operator", Description: "Exercises PostgreSQL authorization hydration.",
		Policy: initialPolicy, IdempotencyKey: customRoleCreateKey,
	})
	if err != nil {
		t.Fatalf("replay updated tenant role: %v", err)
	}
	if !replayedCustomRoleResult.Replayed {
		t.Fatal("tenant role retry was not reported as replayed")
	}
	replayedCustomRole := replayedCustomRoleResult.Value
	if replayedCustomRole.ID != customRoleID || replayedCustomRole.Version != 2 {
		t.Fatalf("unexpected replayed tenant role: %+v", replayedCustomRole)
	}
	assertAuthorizationIntegrationPolicy(
		t, replayedCustomRole.Policy, replacementPolicy.Permissions, replacementPolicy.DelegationCeiling,
	)

	customGrantID := authorizationIntegrationUUID(t)
	customGrantCreateKey := "integration-grant-custom-role-" + customGrantID.String()
	customGrantResult, err := repository.GrantUserRole(ctx, authorization.GrantUserRoleParams{
		Actor: adminActor, Audit: authorizationIntegrationAudit(t), OccurredAt: time.Now().UTC(),
		TenantID: fixture.tenantID, GrantID: customGrantID, UserID: fixture.targetUserID,
		RoleID: customRoleID, Reason: authorizationIntegrationCustomReason,
		IdempotencyKey: customGrantCreateKey,
	})
	if err != nil {
		t.Fatalf("grant custom role and hydrate direct grant: %v", err)
	}
	if customGrantResult.Replayed {
		t.Fatal("new direct role grant was reported as replayed")
	}
	customGrant := customGrantResult.Value
	assertAuthorizationIntegrationGrant(
		t, customGrant, fixture.tenantID, fixture.targetUserID, customGrantID,
		customRole.TenantRoleSummary, fixture.adminUserID, authorizationIntegrationCustomReason,
		authorization.DirectRoleGrantStateActive, 1,
	)
	if customGrant.Provenance.ExpiresAt != nil || customGrant.RevokedAt != nil ||
		customGrant.RevokedByUserID != nil || customGrant.RevokeReason != nil {
		t.Fatalf("active direct grant contains terminal timestamps: %+v", customGrant)
	}

	activeGrants, err := repository.ListUserRoleGrants(ctx, authorization.ListUserRoleGrantsParams{
		Actor: adminActor, TenantID: fixture.tenantID, UserID: fixture.targetUserID,
		Limit: authorizationHydrationLimit,
	})
	if err != nil {
		t.Fatalf("list active direct grants: %v", err)
	}
	if len(activeGrants) != 1 {
		t.Fatalf("active direct grant list = %+v, want one row", activeGrants)
	}
	assertAuthorizationIntegrationGrant(
		t, activeGrants[0], fixture.tenantID, fixture.targetUserID, customGrantID,
		customRole.TenantRoleSummary, fixture.adminUserID, authorizationIntegrationCustomReason,
		authorization.DirectRoleGrantStateActive, 1,
	)

	customGrantEntityTag, err := authorization.DirectUserRoleGrantEntityTag(customGrant)
	if err != nil {
		t.Fatalf("compute custom direct-grant entity tag: %v", err)
	}
	directGrantRevokeReason := "Exercise successful revoke projection."
	if err := repository.RevokeRoleGrant(ctx, authorization.RevokeRoleGrantParams{
		Actor: adminActor, Audit: authorizationIntegrationAudit(t), OccurredAt: time.Now().UTC(),
		TenantID: fixture.tenantID, GrantID: customGrantID,
		Reason: directGrantRevokeReason, ExpectedEntityTag: customGrantEntityTag,
	}); err != nil {
		t.Fatalf("revoke custom role grant: %v", err)
	}
	revokedGrants, err := repository.ListUserRoleGrants(ctx, authorization.ListUserRoleGrantsParams{
		Actor: adminActor, TenantID: fixture.tenantID, UserID: fixture.targetUserID,
		Limit: authorizationHydrationLimit, IncludeRevoked: true,
	})
	if err != nil {
		t.Fatalf("list revoked direct grants: %v", err)
	}
	if len(revokedGrants) != 1 {
		t.Fatalf("revoked direct grant list = %+v, want one row", revokedGrants)
	}
	assertAuthorizationIntegrationGrant(
		t, revokedGrants[0], fixture.tenantID, fixture.targetUserID, customGrantID,
		customRole.TenantRoleSummary, fixture.adminUserID, authorizationIntegrationCustomReason,
		authorization.DirectRoleGrantStateRevoked, 2,
	)
	if revokedGrants[0].RevokedAt == nil || revokedGrants[0].RevokedByUserID == nil ||
		*revokedGrants[0].RevokedByUserID != fixture.adminUserID ||
		revokedGrants[0].RevokeReason == nil ||
		*revokedGrants[0].RevokeReason != directGrantRevokeReason {
		t.Fatalf("revoked direct grant lacks revocation attribution: %+v", revokedGrants[0])
	}
	revokedGrant, err := repository.GetUserRoleGrant(ctx, authorization.GetUserRoleGrantParams{
		Actor: adminActor, TenantID: fixture.tenantID, GrantID: customGrantID,
	})
	if err != nil {
		t.Fatalf("get revoked direct grant: %v", err)
	}
	if revokedGrant.RevokeReason == nil || *revokedGrant.RevokeReason != directGrantRevokeReason ||
		revokedGrant.State != authorization.DirectRoleGrantStateRevoked || revokedGrant.Version != 2 {
		t.Fatalf("unexpected revoked direct grant detail: %+v", revokedGrant)
	}
	replayedCustomGrantResult, err := repository.GrantUserRole(ctx, authorization.GrantUserRoleParams{
		Actor: adminActor, Audit: authorizationIntegrationAudit(t), OccurredAt: time.Now().UTC(),
		TenantID: fixture.tenantID, GrantID: authorizationIntegrationUUID(t), UserID: fixture.targetUserID,
		RoleID: customRoleID, Reason: authorizationIntegrationCustomReason,
		IdempotencyKey: customGrantCreateKey,
	})
	if err != nil {
		t.Fatalf("replay revoked direct role grant: %v", err)
	}
	if !replayedCustomGrantResult.Replayed {
		t.Fatal("direct role grant retry was not reported as replayed")
	}
	replayedCustomGrant := replayedCustomGrantResult.Value
	assertAuthorizationIntegrationGrant(
		t, replayedCustomGrant, fixture.tenantID, fixture.targetUserID, customGrantID,
		customRole.TenantRoleSummary, fixture.adminUserID, authorizationIntegrationCustomReason,
		authorization.DirectRoleGrantStateRevoked, 2,
	)
	if replayedCustomGrant.RevokeReason == nil ||
		*replayedCustomGrant.RevokeReason != directGrantRevokeReason {
		t.Fatalf("replayed direct role grant lacks current revocation reason: %+v", replayedCustomGrant)
	}

	adminGrantID := authorizationIntegrationUUID(t)
	adminGrantResult, err := repository.GrantUserRole(ctx, authorization.GrantUserRoleParams{
		Actor: adminActor, Audit: authorizationIntegrationAudit(t), OccurredAt: time.Now().UTC(),
		TenantID: fixture.tenantID, GrantID: adminGrantID, UserID: fixture.targetUserID,
		RoleID: adminRole.ID, Reason: authorizationIntegrationRecoveryReason,
		IdempotencyKey: "integration-grant-admin-role-" + adminGrantID.String(),
	})
	if err != nil {
		t.Fatalf("grant tenant administrator role: %v", err)
	}
	if adminGrantResult.Replayed {
		t.Fatal("new tenant administrator grant was reported as replayed")
	}
	adminGrant := adminGrantResult.Value
	assertAuthorizationIntegrationGrant(
		t, adminGrant, fixture.tenantID, fixture.targetUserID, adminGrantID,
		adminRoleWithPolicy.TenantRoleSummary, fixture.adminUserID,
		authorizationIntegrationRecoveryReason, authorization.DirectRoleGrantStateActive, 1,
	)

	targetAuthority, err := repository.ResolveAuthority(ctx, authorization.ResolveAuthorityParams{
		Actor: targetActor, TenantID: fixture.tenantID,
	})
	if err != nil {
		t.Fatalf("resolve manually granted tenant administrator authority: %v", err)
	}
	if targetAuthority.TenantID != fixture.tenantID ||
		targetAuthority.Principal.ID != fixture.targetUserID ||
		targetAuthority.MembershipID != fixture.targetMemberID ||
		targetAuthority.MembershipStatus != authorization.MembershipStatusActive {
		t.Fatalf("unexpected target tenant authority: %+v", targetAuthority)
	}
	assertAuthorizationIntegrationAuthority(t, targetAuthority, adminPermissions)
	if len(targetAuthority.RoleGrants) != 1 || targetAuthority.RoleGrants[0].GrantID != adminGrantID ||
		targetAuthority.RoleGrants[0].RoleID != adminRole.ID ||
		targetAuthority.RoleGrants[0].RoleKey != adminRole.Key ||
		targetAuthority.RoleGrants[0].Provenance.SourceType != authorization.RoleGrantSourceDirect ||
		targetAuthority.RoleGrants[0].Provenance.SourceID == nil ||
		targetAuthority.RoleGrants[0].Provenance.GrantedByUserID == nil ||
		*targetAuthority.RoleGrants[0].Provenance.GrantedByUserID != fixture.adminUserID ||
		targetAuthority.RoleGrants[0].Provenance.ExpiresAt != nil {
		t.Fatalf("unexpected target tenant authority role grants: %+v", targetAuthority.RoleGrants)
	}

	const groupAuthorityPathCount = 101
	seedAuthorizationIntegrationGroupAuthorityPaths(
		t, ctx, adminPool, fixture, customRoleID, groupAuthorityPathCount,
	)
	targetAuthority, err = repository.ResolveAuthority(ctx, authorization.ResolveAuthorityParams{
		Actor: targetActor, TenantID: fixture.tenantID,
	})
	if err != nil {
		t.Fatalf("resolve authority with more than one page of group-derived paths: %v", err)
	}
	groupAuthorityPaths := 0
	for _, grant := range targetAuthority.RoleGrants {
		if grant.Path.PathType == authorization.RoleGrantPathGroup {
			groupAuthorityPaths++
		}
	}
	if groupAuthorityPaths != groupAuthorityPathCount ||
		len(targetAuthority.RoleGrants) != groupAuthorityPathCount+1 {
		t.Fatalf(
			"hydrated authority paths = %d group-derived / %d total, want %d / %d",
			groupAuthorityPaths,
			len(targetAuthority.RoleGrants),
			groupAuthorityPathCount,
			groupAuthorityPathCount+1,
		)
	}

	suspendAuthorizationIntegrationAdmin(t, ctx, adminPool, fixture)
	adminGrantEntityTag, err := authorization.DirectUserRoleGrantEntityTag(adminGrant)
	if err != nil {
		t.Fatalf("compute administrator direct-grant entity tag: %v", err)
	}
	if err := repository.RevokeRoleGrant(ctx, authorization.RevokeRoleGrantParams{
		Actor: targetActor, Audit: authorizationIntegrationAudit(t), OccurredAt: time.Now().UTC(),
		TenantID: fixture.tenantID, GrantID: adminGrantID,
		Reason: "Attempt to remove the last recovery administrator.", ExpectedEntityTag: adminGrantEntityTag,
	}); !errors.Is(err, authorization.ErrConflict) {
		t.Fatalf("last recovery administrator revoke error = %v, want conflict", err)
	}

	remainingGrants, err := repository.ListUserRoleGrants(ctx, authorization.ListUserRoleGrantsParams{
		Actor: targetActor, TenantID: fixture.tenantID, UserID: fixture.targetUserID,
		Limit: authorizationHydrationLimit,
	})
	if err != nil {
		t.Fatalf("list grants after rejected last-administrator revoke: %v", err)
	}
	if len(remainingGrants) != 1 {
		t.Fatalf("active grants after rejected last-administrator revoke = %+v, want one row", remainingGrants)
	}
	assertAuthorizationIntegrationGrant(
		t, remainingGrants[0], fixture.tenantID, fixture.targetUserID, adminGrantID,
		adminRoleWithPolicy.TenantRoleSummary, fixture.adminUserID,
		authorizationIntegrationRecoveryReason, authorization.DirectRoleGrantStateActive, 1,
	)

	var rolledBackAuditEvents int
	if err := adminPool.QueryRow(
		ctx,
		`SELECT count(*)::integer
		 FROM public.audit_events
		 WHERE tenant_id = $1
		   AND action = 'tenant.role_grant.revoked'
		   AND resource_id = $2`,
		fixture.tenantID,
		adminGrantID,
	).Scan(&rolledBackAuditEvents); err != nil {
		t.Fatalf("count rejected last-administrator audit events: %v", err)
	}
	if rolledBackAuditEvents != 0 {
		t.Fatalf("rejected last-administrator revoke persisted %d audit events", rolledBackAuditEvents)
	}
}

func testAuthorizationRepositoryExternalManualGroupOwnershipPostgreSQL(
	t *testing.T,
	databaseURL string,
) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	adminPool := authorizationIntegrationPool(t, ctx, databaseURL, "")
	defer adminPool.Close()
	fixture := seedAuthorizationIntegrationFixture(t, ctx, adminPool)
	runtimePool := authorizationIntegrationPool(t, ctx, databaseURL, "periapsis_api")
	defer runtimePool.Close()

	sourceID := authorizationIntegrationUUID(t)
	groupID := authorizationIntegrationUUID(t)
	membershipID := authorizationIntegrationUUID(t)
	roleGrantID := authorizationIntegrationUUID(t)
	var roleID uuid.UUID
	if err := adminPool.QueryRow(
		ctx,
		`SELECT id
		 FROM public.tenant_roles
		 WHERE tenant_id = $1 AND key = 'tenant_admin'`,
		fixture.tenantID,
	).Scan(&roleID); err != nil {
		t.Fatalf("load external-manual integration role: %v", err)
	}
	if _, err := adminPool.Exec(
		ctx,
		`INSERT INTO public.tenant_authorization_sources (
		   id, tenant_id, kind, key, authoritative, protected
		 ) VALUES ($1, $2, 'manual', 'manual.external', false, true)`,
		sourceID,
		fixture.tenantID,
	); err != nil {
		t.Fatalf("insert external manual source: %v", err)
	}
	if _, err := adminPool.Exec(
		ctx,
		`INSERT INTO public.tenant_security_groups (
		   id, tenant_id, key, display_name, description, created_by_membership_id
		 ) VALUES ($1, $2, 'external_manual_group', 'External manual group',
		           'Repository ownership integration proof.', $3)`,
		groupID,
		fixture.tenantID,
		fixture.adminMemberID,
	); err != nil {
		t.Fatalf("insert external manual group: %v", err)
	}
	if _, err := adminPool.Exec(
		ctx,
		`INSERT INTO public.tenant_security_group_memberships (
		   id, tenant_id, group_id, membership_id, source_id,
		   granted_by_membership_id, grant_reason
		 ) VALUES ($1, $2, $3, $4, $5, $6, 'External manual membership.')`,
		membershipID,
		fixture.tenantID,
		groupID,
		fixture.targetMemberID,
		sourceID,
		fixture.adminMemberID,
	); err != nil {
		t.Fatalf("insert external manual group membership: %v", err)
	}
	if _, err := adminPool.Exec(
		ctx,
		`INSERT INTO public.tenant_security_group_role_grants (
		   id, tenant_id, group_id, role_id, source_id,
		   granted_by_membership_id, grant_reason
		 ) VALUES ($1, $2, $3, $4, $5, $6, 'External manual group role.')`,
		roleGrantID,
		fixture.tenantID,
		groupID,
		roleID,
		sourceID,
		fixture.adminMemberID,
	); err != nil {
		t.Fatalf("insert external manual group role grant: %v", err)
	}

	repository := NewAuthorizationRepository(runtimePool)
	actor := authorizationIntegrationActor(t, fixture.tenantID, fixture.adminUserID)
	membership, err := repository.GetTenantSecurityGroupMembership(
		ctx,
		authorization.GetTenantSecurityGroupMembershipParams{
			Actor: actor, TenantID: fixture.tenantID, GroupID: groupID,
			MembershipID: membershipID,
		},
	)
	if err != nil {
		t.Fatalf("get external manual group membership: %v", err)
	}
	roleGrant, err := repository.GetTenantSecurityGroupRoleGrant(
		ctx,
		authorization.GetTenantSecurityGroupRoleGrantParams{
			Actor: actor, TenantID: fixture.tenantID, GroupID: groupID,
			GrantID: roleGrantID,
		},
	)
	if err != nil {
		t.Fatalf("get external manual group role grant: %v", err)
	}
	if membership.Provenance.SourceKind != authorization.AuthorizationSourceManual ||
		membership.ManagedByAuthorizationAPI ||
		roleGrant.Provenance.SourceKind != authorization.AuthorizationSourceManual ||
		roleGrant.ManagedByAuthorizationAPI {
		t.Fatalf("external manual ownership projection = %+v / %+v", membership, roleGrant)
	}

	service, err := authorization.NewService(repository)
	if err != nil {
		t.Fatalf("create external-manual authorization service: %v", err)
	}
	membershipTag, err := authorization.TenantSecurityGroupMembershipEntityTag(membership)
	if err != nil {
		t.Fatalf("compute external membership entity tag: %v", err)
	}
	if err = service.RevokeTenantSecurityGroupMembership(
		ctx,
		actor,
		fixture.tenantID,
		groupID,
		membershipID,
		authorization.RevokeTenantSecurityGroupMembershipInput{
			Reason:            "Reject external manual membership mutation.",
			ExpectedEntityTag: &membershipTag,
			Audit:             authorizationIntegrationAudit(t),
		},
	); !errors.Is(err, authorization.ErrConflict) {
		t.Fatalf("external manual membership revoke error = %v, want conflict", err)
	}
	roleGrantTag, err := authorization.TenantSecurityGroupRoleGrantEntityTag(roleGrant)
	if err != nil {
		t.Fatalf("compute external role-grant entity tag: %v", err)
	}
	if err = service.RevokeTenantSecurityGroupRoleGrant(
		ctx,
		actor,
		fixture.tenantID,
		groupID,
		roleGrantID,
		authorization.RevokeTenantSecurityGroupRoleGrantInput{
			Reason:            "Reject external manual group role mutation.",
			ExpectedEntityTag: &roleGrantTag,
			Audit:             authorizationIntegrationAudit(t),
		},
	); !errors.Is(err, authorization.ErrConflict) {
		t.Fatalf("external manual group role revoke error = %v, want conflict", err)
	}

	var membershipVersion, roleGrantVersion, auditCount int
	if err := adminPool.QueryRow(
		ctx,
		`SELECT membership.version, role_grant.version,
		        (SELECT count(*)::integer
		         FROM public.audit_events AS audit
		         WHERE audit.tenant_id = $1
		           AND audit.resource_id IN ($2, $3))
		 FROM public.tenant_security_group_memberships AS membership
		 JOIN public.tenant_security_group_role_grants AS role_grant
		   ON role_grant.tenant_id = membership.tenant_id
		 WHERE membership.tenant_id = $1
		   AND membership.id = $2
		   AND role_grant.id = $3`,
		fixture.tenantID,
		membershipID,
		roleGrantID,
	).Scan(&membershipVersion, &roleGrantVersion, &auditCount); err != nil {
		t.Fatalf("read rejected external manual mutation state: %v", err)
	}
	if membershipVersion != 1 || roleGrantVersion != 1 || auditCount != 0 {
		t.Fatalf(
			"rejected external manual mutation state = membership %d, grant %d, audits %d",
			membershipVersion,
			roleGrantVersion,
			auditCount,
		)
	}
}

func testAuthorizationRepositoryPolicySelfDemotionPostgreSQL(t *testing.T, databaseURL string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	adminPool := authorizationIntegrationPool(t, ctx, databaseURL, "")
	defer adminPool.Close()
	fixture := seedAuthorizationIntegrationFixture(t, ctx, adminPool)
	runtimePool := authorizationIntegrationPool(t, ctx, databaseURL, "periapsis_api")
	defer runtimePool.Close()
	repository := NewAuthorizationRepository(runtimePool)
	service, err := authorization.NewService(repository)
	if err != nil {
		t.Fatalf("create authorization service for self-demotion regression: %v", err)
	}
	adminActor := authorizationIntegrationActor(t, fixture.tenantID, fixture.adminUserID)

	selfDemotingUserID := authorizationIntegrationUUID(t)
	selfDemotingMembershipID := authorizationIntegrationUUID(t)
	compactID := strings.ReplaceAll(selfDemotingUserID.String(), "-", "")
	tx, err := adminPool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin self-demotion fixture transaction: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err = tx.Exec(ctx, `SET LOCAL ROLE "periapsis_migrator"`); err != nil {
		t.Fatalf("set self-demotion fixture role: %v", err)
	}
	if _, err = tx.Exec(
		ctx,
		`INSERT INTO public.users (id, email, display_name)
		 VALUES ($1, $2, 'Self-demoting role manager')`,
		selfDemotingUserID,
		"authorization-self-demotion-"+compactID[len(compactID)-12:]+"@example.invalid",
	); err != nil {
		t.Fatalf("insert self-demoting user: %v", err)
	}
	if _, err = tx.Exec(
		ctx,
		`INSERT INTO public.tenant_memberships (id, tenant_id, user_id, role, status)
		 VALUES ($1, $2, $3, 'read_only', 'active')`,
		selfDemotingMembershipID,
		fixture.tenantID,
		selfDemotingUserID,
	); err != nil {
		t.Fatalf("insert self-demoting tenant membership: %v", err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatalf("commit self-demotion fixture: %v", err)
	}

	roleID := authorizationIntegrationUUID(t)
	roleAdministrationPolicy := authorization.TenantRolePolicy{
		Permissions: []authorization.ScopedPermission{
			{Permission: authorization.TenantPermissionRoleRead, Scope: authorization.ScopeTenant},
			{Permission: authorization.TenantPermissionRoleManage, Scope: authorization.ScopeTenant},
			{Permission: authorization.TenantPermissionRoleGrant, Scope: authorization.ScopeTenant},
		},
		DelegationCeiling: []authorization.ScopedPermission{
			{Permission: authorization.TenantPermissionRoleRead, Scope: authorization.ScopeTenant},
			{Permission: authorization.TenantPermissionRoleManage, Scope: authorization.ScopeTenant},
			{Permission: authorization.TenantPermissionRoleGrant, Scope: authorization.ScopeTenant},
		},
	}
	created, err := repository.CreateTenantRole(ctx, authorization.CreateTenantRoleParams{
		Actor: adminActor, Audit: authorizationIntegrationAudit(t), OccurredAt: time.Now().UTC(),
		TenantID: fixture.tenantID, RoleID: roleID, Key: "self_demoting_role",
		Name: "Self-demoting role manager", Description: "Exercises mutation-owned response hydration.",
		Policy: roleAdministrationPolicy, IdempotencyKey: "self-demoting-role-" + roleID.String(),
	})
	if err != nil {
		t.Fatalf("create self-demoting role: %v", err)
	}
	if created.Replayed || created.Value.Version != 1 {
		t.Fatalf("created self-demoting role = %+v", created)
	}
	grantID := authorizationIntegrationUUID(t)
	granted, err := repository.GrantUserRole(ctx, authorization.GrantUserRoleParams{
		Actor: adminActor, Audit: authorizationIntegrationAudit(t), OccurredAt: time.Now().UTC(),
		TenantID: fixture.tenantID, GrantID: grantID, UserID: selfDemotingUserID, RoleID: roleID,
		Reason:         "Delegate role administration for the self-demotion regression.",
		IdempotencyKey: "self-demoting-role-grant-" + grantID.String(),
	})
	if err != nil || granted.Replayed {
		t.Fatalf("grant self-demoting role = %+v, error=%v", granted, err)
	}

	selfDemotingActor := authorizationIntegrationActor(t, fixture.tenantID, selfDemotingUserID)
	authority, err := repository.ResolveAuthority(ctx, authorization.ResolveAuthorityParams{
		Actor: selfDemotingActor, TenantID: fixture.tenantID,
	})
	if err != nil {
		t.Fatalf("resolve self-demoting authority before replacement: %v", err)
	}
	if authority.MembershipID != selfDemotingMembershipID || len(authority.RoleGrants) != 1 ||
		authority.RoleGrants[0].RoleID != roleID || len(authority.Permissions) != 3 ||
		len(authority.DelegationCeiling) != 3 {
		t.Fatalf("self-demoting authority before replacement = %+v", authority)
	}

	expectedVersion := created.Value.Version
	replaced, err := service.ReplaceTenantRolePolicy(
		ctx,
		selfDemotingActor,
		fixture.tenantID,
		roleID,
		authorization.ReplaceTenantRolePolicyInput{
			Audit: authorizationIntegrationAudit(t), ExpectedVersion: &expectedVersion,
			Policy: authorization.TenantRolePolicy{
				Permissions:       make([]authorization.ScopedPermission, 0),
				DelegationCeiling: make([]authorization.ScopedPermission, 0),
			},
		},
	)
	if err != nil {
		t.Fatalf("replace role policy while removing the caller's sole authority: %v", err)
	}
	if replaced.ID != roleID || replaced.Version != 2 || len(replaced.Policy.Permissions) != 0 ||
		len(replaced.Policy.DelegationCeiling) != 0 {
		t.Fatalf("self-demoted role mutation result = %+v", replaced)
	}

	authority, err = repository.ResolveAuthority(ctx, authorization.ResolveAuthorityParams{
		Actor: selfDemotingActor, TenantID: fixture.tenantID,
	})
	if err != nil {
		t.Fatalf("resolve self-demoting authority after replacement: %v", err)
	}
	if len(authority.Permissions) != 0 || len(authority.DelegationCeiling) != 0 {
		t.Fatalf("self-demoting authority remained effective after replacement: %+v", authority)
	}
	if _, err = repository.GetTenantRole(ctx, authorization.GetTenantRoleParams{
		Actor: selfDemotingActor, TenantID: fixture.tenantID, RoleID: roleID,
	}); !errors.Is(err, authorization.ErrForbidden) {
		t.Fatalf("post-demotion role read error = %v, want forbidden", err)
	}

	stored, err := repository.GetTenantRole(ctx, authorization.GetTenantRoleParams{
		Actor: adminActor, TenantID: fixture.tenantID, RoleID: roleID,
	})
	if err != nil {
		t.Fatalf("read self-demoted role as tenant administrator: %v", err)
	}
	if stored.Version != 2 || len(stored.Policy.Permissions) != 0 ||
		len(stored.Policy.DelegationCeiling) != 0 {
		t.Fatalf("stored self-demoted role = %+v", stored)
	}
	var auditCount int
	if err = adminPool.QueryRow(
		ctx,
		`SELECT count(*)::integer
		 FROM public.audit_events
		 WHERE tenant_id = $1
		   AND action = 'tenant.role.policy_replaced'
		   AND resource_id = $2
		   AND actor_type = 'user'
		   AND actor_user_id = $3
		   AND ("before" ->> 'permissions')::integer = 3
		   AND ("before" ->> 'delegation_ceiling')::integer = 3
		   AND ("after" ->> 'permissions')::integer = 0
		   AND ("after" ->> 'delegation_ceiling')::integer = 0
		   AND ("after" ->> 'version')::integer = 2
		   AND metadata ->> 'actor_membership_id' = $4::text`,
		fixture.tenantID,
		roleID,
		selfDemotingUserID,
		selfDemotingMembershipID,
	).Scan(&auditCount); err != nil {
		t.Fatalf("count committed self-demotion audit event: %v", err)
	}
	if auditCount != 1 {
		t.Fatalf("committed self-demotion audit events = %d, want 1", auditCount)
	}
}

func testAuthorizationRepositoryArchivedRoleGrantCleanupPostgreSQL(
	t *testing.T,
	databaseURL string,
) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	adminPool := authorizationIntegrationPool(t, ctx, databaseURL, "")
	defer adminPool.Close()
	fixture := seedAuthorizationIntegrationFixture(t, ctx, adminPool)
	runtimePool := authorizationIntegrationPool(t, ctx, databaseURL, "periapsis_api")
	defer runtimePool.Close()
	repository := NewAuthorizationRepository(runtimePool)
	service, err := authorization.NewService(repository)
	if err != nil {
		t.Fatalf("create authorization service for archived-role cleanup regression: %v", err)
	}
	adminActor := authorizationIntegrationActor(t, fixture.tenantID, fixture.adminUserID)

	roleID := authorizationIntegrationUUID(t)
	rolePolicy := authorization.TenantRolePolicy{
		Permissions: []authorization.ScopedPermission{
			{Permission: authorization.TenantPermissionPermissionRead, Scope: authorization.ScopeTenant},
		},
		DelegationCeiling: []authorization.ScopedPermission{
			{Permission: authorization.TenantPermissionPermissionRead, Scope: authorization.ScopeTenant},
		},
	}
	created, err := repository.CreateTenantRole(ctx, authorization.CreateTenantRoleParams{
		Actor: adminActor, Audit: authorizationIntegrationAudit(t), OccurredAt: time.Now().UTC(),
		TenantID: fixture.tenantID, RoleID: roleID, Key: "archived_grant_cleanup",
		Name: "Archived grant cleanup", Description: "Exercises cleanup after role archival.",
		Policy: rolePolicy, IdempotencyKey: "archived-grant-cleanup-role-" + roleID.String(),
	})
	if err != nil {
		t.Fatalf("create role for archived-role grant cleanup: %v", err)
	}
	if created.Replayed || created.Value.Version != 1 {
		t.Fatalf("created archived-role cleanup role = %+v", created)
	}

	grantID := authorizationIntegrationUUID(t)
	grantReason := "Establish an unbounded manual grant before archival."
	granted, err := repository.GrantUserRole(ctx, authorization.GrantUserRoleParams{
		Actor: adminActor, Audit: authorizationIntegrationAudit(t), OccurredAt: time.Now().UTC(),
		TenantID: fixture.tenantID, GrantID: grantID, UserID: fixture.targetUserID,
		RoleID: roleID, Reason: grantReason,
		IdempotencyKey: "archived-grant-cleanup-grant-" + grantID.String(),
	})
	if err != nil {
		t.Fatalf("create manual grant before role archival: %v", err)
	}
	if granted.Replayed || granted.Value.State != authorization.DirectRoleGrantStateActive ||
		granted.Value.Provenance.ExpiresAt != nil || granted.Value.Version != 1 {
		t.Fatalf("created archived-role cleanup grant = %+v", granted)
	}

	expectedRoleVersion := created.Value.Version
	if err = service.ArchiveTenantRole(
		ctx,
		adminActor,
		fixture.tenantID,
		roleID,
		authorization.ArchiveTenantRoleInput{
			ExpectedVersion: &expectedRoleVersion,
			Audit:           authorizationIntegrationAudit(t),
		},
	); err != nil {
		t.Fatalf("archive role with a live manual grant: %v", err)
	}

	current, err := repository.GetUserRoleGrant(ctx, authorization.GetUserRoleGrantParams{
		Actor: adminActor, TenantID: fixture.tenantID, GrantID: grantID,
	})
	if err != nil {
		t.Fatalf("read live manual grant after role archival: %v", err)
	}
	if !current.Role.Archived || current.Role.Version != 2 ||
		current.State != authorization.DirectRoleGrantStateActive || current.Version != 1 {
		t.Fatalf("manual grant after role archival = %+v", current)
	}
	entityTag, err := authorization.DirectUserRoleGrantEntityTag(current)
	if err != nil {
		t.Fatalf("compute archived-role grant entity tag: %v", err)
	}

	revokeReason := "Remove the stranded grant after its role was archived."
	if err = service.RevokeRoleGrant(
		ctx,
		adminActor,
		fixture.tenantID,
		grantID,
		authorization.RevokeRoleGrantInput{
			Reason: revokeReason, ExpectedEntityTag: &entityTag,
			Audit: authorizationIntegrationAudit(t),
		},
	); err != nil {
		t.Fatalf("revoke live manual grant after role archival: %v", err)
	}

	revoked, err := repository.GetUserRoleGrant(ctx, authorization.GetUserRoleGrantParams{
		Actor: adminActor, TenantID: fixture.tenantID, GrantID: grantID,
	})
	if err != nil {
		t.Fatalf("read revoked manual grant after role archival: %v", err)
	}
	if !revoked.Role.Archived || revoked.Role.Version != 2 ||
		revoked.State != authorization.DirectRoleGrantStateRevoked || revoked.Version != 2 ||
		revoked.RevokedAt == nil || revoked.RevokedByUserID == nil ||
		*revoked.RevokedByUserID != fixture.adminUserID || revoked.RevokeReason == nil ||
		*revoked.RevokeReason != revokeReason {
		t.Fatalf("revoked archived-role manual grant = %+v", revoked)
	}

	var auditCount int
	if err = adminPool.QueryRow(
		ctx,
		`SELECT count(*)::integer
		 FROM public.audit_events
		 WHERE tenant_id = $1
		   AND action = 'tenant.role_grant.revoked'
		   AND resource_type = 'tenant_membership_role_grant'
		   AND resource_id = $2
		   AND actor_type = 'user'
		   AND actor_user_id = $3
		   AND "before" -> 'revoked_at' = 'null'::jsonb
		   AND ("before" ->> 'version')::integer = 1
		   AND "after" ->> 'reason' = $4
		   AND ("after" ->> 'version')::integer = 2
		   AND "after" ->> 'revoked_at' IS NOT NULL
		   AND metadata ->> 'actor_membership_id' = $5::text`,
		fixture.tenantID,
		grantID,
		fixture.adminUserID,
		revokeReason,
		fixture.adminMemberID,
	).Scan(&auditCount); err != nil {
		t.Fatalf("count archived-role manual-grant revoke audit event: %v", err)
	}
	if auditCount != 1 {
		t.Fatalf("archived-role manual-grant revoke audit events = %d, want 1", auditCount)
	}
}

func authorizationIntegrationPool(
	t *testing.T,
	ctx context.Context,
	databaseURL string,
	role string,
) *pgxpool.Pool {
	t.Helper()
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatalf("parse authorization integration database URL: %v", err)
	}
	config.MaxConns = 2
	config.ConnConfig.RuntimeParams["statement_timeout"] = "15s"
	if role != "" {
		config.AfterConnect = func(connectContext context.Context, connection *pgx.Conn) error {
			if _, connectErr := connection.Exec(
				connectContext, fmt.Sprintf(`SET ROLE %s`, pgx.Identifier{role}.Sanitize()),
			); connectErr != nil {
				return fmt.Errorf("set authorization integration role: %w", connectErr)
			}
			return nil
		}
	}
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatalf("create authorization integration database pool: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Fatalf("connect to authorization integration database: %v", err)
	}
	return pool
}

func seedAuthorizationIntegrationFixture(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
) authorizationIntegrationFixture {
	t.Helper()
	fixture := authorizationIntegrationFixture{
		tenantID:       authorizationIntegrationUUID(t),
		adminUserID:    authorizationIntegrationUUID(t),
		adminMemberID:  authorizationIntegrationUUID(t),
		targetUserID:   authorizationIntegrationUUID(t),
		targetMemberID: authorizationIntegrationUUID(t),
	}
	compactID := strings.ReplaceAll(fixture.tenantID.String(), "-", "")
	fixtureSuffix := compactID[len(compactID)-12:]

	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin authorization integration fixture transaction: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE "periapsis_migrator"`); err != nil {
		t.Fatalf("set authorization integration fixture role: %v", err)
	}
	if _, err := tx.Exec(
		ctx,
		`INSERT INTO public.tenants (id, slug, name)
		 VALUES ($1, $2, $3)`,
		fixture.tenantID,
		"authorization-go-"+fixtureSuffix,
		"Go authorization repository integration",
	); err != nil {
		t.Fatalf("insert authorization integration tenant: %v", err)
	}
	if _, err := tx.Exec(
		ctx,
		`INSERT INTO public.audit_chain_heads (tenant_id) VALUES ($1)`,
		fixture.tenantID,
	); err != nil {
		t.Fatalf("insert authorization integration audit head: %v", err)
	}
	if _, err := tx.Exec(
		ctx,
		`INSERT INTO public.users (id, email, display_name)
		 VALUES
		   ($1, $2, 'Go authorization administrator'),
		   ($3, $4, 'Go authorization target')`,
		fixture.adminUserID,
		"authorization-admin-"+fixtureSuffix+"@example.invalid",
		fixture.targetUserID,
		"authorization-target-"+fixtureSuffix+"@example.invalid",
	); err != nil {
		t.Fatalf("insert authorization integration users: %v", err)
	}
	if _, err := tx.Exec(
		ctx,
		`INSERT INTO public.tenant_memberships (id, tenant_id, user_id, role, status)
		 VALUES
		   ($1, $2, $3, 'tenant_admin', 'active'),
		   ($4, $2, $5, 'read_only', 'active')`,
		fixture.adminMemberID,
		fixture.tenantID,
		fixture.adminUserID,
		fixture.targetMemberID,
		fixture.targetUserID,
	); err != nil {
		t.Fatalf("insert authorization integration memberships: %v", err)
	}
	if _, err := tx.Exec(
		ctx,
		`SELECT app.seed_tenant_authorization($1, $2)`,
		fixture.tenantID,
		fixture.adminMemberID,
	); err != nil {
		t.Fatalf("seed authorization integration tenant RBAC: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit authorization integration fixture: %v", err)
	}
	return fixture
}

func seedAuthorizationIntegrationGroupAuthorityPaths(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	fixture authorizationIntegrationFixture,
	roleID uuid.UUID,
	count int,
) {
	t.Helper()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin group authority path fixture transaction: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE "periapsis_migrator"`); err != nil {
		t.Fatalf("set group authority path fixture role: %v", err)
	}
	var inserted int
	err = tx.QueryRow(
		ctx,
		`WITH manual_source AS (
		   SELECT source.id
		   FROM public.tenant_authorization_sources AS source
		   WHERE source.tenant_id = $1
		     AND source.key = 'manual'
		     AND source.kind = 'manual'
		     AND source.retired_at IS NULL
		 ), inserted_groups AS (
		   INSERT INTO public.tenant_security_groups (
		     id, tenant_id, key, display_name, description, created_by_membership_id
		   )
		   SELECT uuidv7(), $1, 'hydration_group_' || series.value,
		          'Hydration group ' || series.value,
		          'Exercises authority hydration above one API page.', $3
		   FROM generate_series(1, $5::integer) AS series(value)
		   RETURNING id
		 ), inserted_memberships AS (
		   INSERT INTO public.tenant_security_group_memberships (
		     id, tenant_id, group_id, membership_id, source_id,
		     granted_by_membership_id, grant_reason
		   )
		   SELECT uuidv7(), $1, inserted_group.id, $2, manual_source.id,
		          $3, 'Exercise authority hydration above one API page.'
		   FROM inserted_groups AS inserted_group
		   CROSS JOIN manual_source
		   RETURNING group_id
		 ), inserted_role_grants AS (
		   INSERT INTO public.tenant_security_group_role_grants (
		     id, tenant_id, group_id, role_id, source_id,
		     granted_by_membership_id, grant_reason
		   )
		   SELECT uuidv7(), $1, inserted_membership.group_id, $4, manual_source.id,
		          $3, 'Exercise authority hydration above one API page.'
		   FROM inserted_memberships AS inserted_membership
		   CROSS JOIN manual_source
		   RETURNING id
		 )
		 SELECT count(*)::integer FROM inserted_role_grants`,
		fixture.tenantID,
		fixture.targetMemberID,
		fixture.adminMemberID,
		roleID,
		count,
	).Scan(&inserted)
	if err != nil {
		t.Fatalf("insert group authority path fixtures: %v", err)
	}
	if inserted != count {
		t.Fatalf("inserted group authority paths = %d, want %d", inserted, count)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit group authority path fixtures: %v", err)
	}
}

func suspendAuthorizationIntegrationAdmin(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	fixture authorizationIntegrationFixture,
) {
	t.Helper()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin administrator suspension transaction: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE "periapsis_migrator"`); err != nil {
		t.Fatalf("set administrator suspension role: %v", err)
	}
	commandTag, err := tx.Exec(
		ctx,
		`UPDATE public.tenant_memberships
		 SET status = 'suspended', updated_at = transaction_timestamp()
		 WHERE tenant_id = $1 AND id = $2`,
		fixture.tenantID,
		fixture.adminMemberID,
	)
	if err != nil {
		t.Fatalf("suspend seeded administrator: %v", err)
	}
	if commandTag.RowsAffected() != 1 {
		t.Fatalf("suspend seeded administrator affected %d rows, want 1", commandTag.RowsAffected())
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit seeded administrator suspension: %v", err)
	}
}

func authorizationIntegrationActor(
	t *testing.T,
	tenantID uuid.UUID,
	userID uuid.UUID,
) authorization.Actor {
	t.Helper()
	return authorization.Actor{
		UserID: userID, SessionID: authorizationIntegrationUUID(t), ActiveTenantID: tenantID,
		AuthenticationMethod: "totp",
	}
}

func authorizationIntegrationAudit(t *testing.T) authorization.AuditContext {
	t.Helper()
	return authorization.AuditContext{
		RequestID: authorizationIntegrationUUID(t), CorrelationID: authorizationIntegrationUUID(t),
		RemoteAddress: netip.MustParseAddr("192.0.2.61"),
		UserAgent:     "Periapsis Go authorization repository integration test",
	}
}

func authorizationIntegrationUUID(t *testing.T) uuid.UUID {
	t.Helper()
	identifier, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("generate authorization integration UUIDv7: %v", err)
	}
	return identifier
}

func authorizationIntegrationRole(
	t *testing.T,
	roles []authorization.TenantRoleSummary,
	key string,
) authorization.TenantRoleSummary {
	t.Helper()
	for _, role := range roles {
		if role.Key == key {
			return role
		}
	}
	t.Fatalf("tenant role %q was not returned: %+v", key, roles)
	return authorization.TenantRoleSummary{}
}

func authorizationIntegrationAdminPermissions(catalog []authorization.TenantPermissionDefinition) []authorization.ScopedPermission {
	var permissions []authorization.ScopedPermission
	for _, permission := range catalog {
		if slices.Contains(permission.PrincipalKinds, authorization.PrincipalKindHuman) {
			for _, scope := range permission.AllowedScopes {
				permissions = append(permissions, authorization.ScopedPermission{Permission: permission.Key, Scope: scope})
			}
		}
	}
	return permissions
}

func assertAuthorizationIntegrationAuthority(
	t *testing.T,
	authority authorization.TenantAuthority,
	wantPermissions []authorization.ScopedPermission,
) {
	t.Helper()
	delegation := make([]authorization.ScopedPermission, 0, len(authority.DelegationCeiling))
	for _, grant := range authority.DelegationCeiling {
		if grant.ExpiresAt != nil {
			t.Fatalf("tenant administrator delegation unexpectedly expires: %+v", grant)
		}
		delegation = append(delegation, grant.ScopedPermission)
	}
	assertAuthorizationIntegrationPolicy(
		t,
		authorization.TenantRolePolicy{
			Permissions: authority.Permissions, DelegationCeiling: delegation,
		},
		wantPermissions,
		wantPermissions,
	)
}

func assertAuthorizationIntegrationPolicy(
	t *testing.T,
	policy authorization.TenantRolePolicy,
	wantPermissions []authorization.ScopedPermission,
	wantDelegation []authorization.ScopedPermission,
) {
	t.Helper()
	assertAuthorizationIntegrationTuples(t, "permissions", policy.Permissions, wantPermissions)
	assertAuthorizationIntegrationTuples(t, "delegation ceiling", policy.DelegationCeiling, wantDelegation)
}

func assertAuthorizationIntegrationTuples(
	t *testing.T,
	label string,
	got []authorization.ScopedPermission,
	want []authorization.ScopedPermission,
) {
	t.Helper()
	gotSet := make(map[authorization.ScopedPermission]int, len(got))
	for _, tuple := range got {
		gotSet[tuple]++
	}
	wantSet := make(map[authorization.ScopedPermission]int, len(want))
	for _, tuple := range want {
		wantSet[tuple]++
	}
	if len(gotSet) != len(wantSet) || len(got) != len(want) {
		t.Fatalf("%s = %+v, want %+v", label, got, want)
	}
	for tuple, count := range wantSet {
		if gotSet[tuple] != count {
			t.Fatalf("%s = %+v, want %+v", label, got, want)
		}
	}
}

func assertAuthorizationIntegrationGrant(
	t *testing.T,
	grant authorization.DirectUserRoleGrant,
	tenantID uuid.UUID,
	userID uuid.UUID,
	grantID uuid.UUID,
	role authorization.TenantRoleSummary,
	grantorID uuid.UUID,
	reason string,
	state authorization.DirectRoleGrantState,
	version int64,
) {
	t.Helper()
	if grant.ID != grantID || grant.TenantID != tenantID || grant.UserID != userID ||
		grant.Role.ID != role.ID || grant.Role.TenantID != role.TenantID ||
		grant.Role.Key != role.Key || grant.Role.Name != role.Name ||
		grant.Role.Description != role.Description || grant.Role.System != role.System ||
		grant.Role.Archived != role.Archived || grant.Role.Version != role.Version ||
		grant.Role.CreatedAt.IsZero() || grant.Role.UpdatedAt.IsZero() ||
		!grant.ManagedByAuthorizationAPI ||
		grant.State != state || grant.Version != version ||
		grant.Provenance.SourceType != authorization.RoleGrantSourceDirect ||
		grant.Provenance.SourceID == nil || grant.Provenance.GrantedByUserID == nil ||
		*grant.Provenance.GrantedByUserID != grantorID || grant.Provenance.Reason != reason ||
		grant.Provenance.GrantedAt.IsZero() ||
		grant.UpdatedAt.IsZero() {
		t.Fatalf("unexpected direct role-grant projection: %+v", grant)
	}
}
