package postgres

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

func TestAuthorizationRepositoryInvalidExpiryDoesNotPersist(t *testing.T) {
	databaseURL := strings.TrimSpace(os.Getenv(authorizationIntegrationDatabaseURL))
	if databaseURL == "" {
		t.Skipf("%s is not set", authorizationIntegrationDatabaseURL)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	adminPool := authorizationIntegrationPool(t, ctx, databaseURL, "")
	defer adminPool.Close()
	fixture := seedAuthorizationIntegrationFixture(t, ctx, adminPool)
	runtimePool := authorizationIntegrationPool(t, ctx, databaseURL, "periapsis_api")
	defer runtimePool.Close()
	repository := NewAuthorizationRepository(runtimePool)
	actor := authorizationIntegrationActor(t, fixture.tenantID, fixture.adminUserID)
	audit := authorizationIntegrationAudit(t)
	var roleID uuid.UUID
	if err := adminPool.QueryRow(
		ctx,
		`SELECT id
		 FROM public.tenant_roles
		 WHERE tenant_id = $1 AND key = 'tenant_admin'`,
		fixture.tenantID,
	).Scan(&roleID); err != nil {
		t.Fatalf("load tenant administrator role: %v", err)
	}
	groupID := authorizationIntegrationUUID(t)
	groupResult, err := repository.CreateTenantSecurityGroup(
		ctx,
		authorization.CreateTenantSecurityGroupParams{
			Actor: actor, Audit: audit, OccurredAt: time.Now().UTC(), TenantID: fixture.tenantID,
			GroupID: groupID, Key: "invalid_expiry_guard", Name: "Invalid expiry guard",
			Description:    "Verifies invalid expiry requests never persist.",
			IdempotencyKey: "invalid-expiry-guard-" + groupID.String(),
		},
	)
	if err != nil || groupResult.Replayed {
		t.Fatalf("create invalid-expiry test group result=%+v error=%v", groupResult, err)
	}
	invalidExpiries := []struct {
		name  string
		value time.Time
	}{
		{name: "zero", value: time.Time{}},
		{
			name: "UTC-year-overflow",
			value: time.Date(
				9999, time.December, 31, 23, 59, 59, 999999000,
				time.FixedZone("-23:59", -(23*60*60+59*60)),
			),
		},
		{
			name: "UTC-year-underflow",
			value: time.Date(
				0, time.January, 1, 0, 0, 0, 0,
				time.FixedZone("+23:59", 23*60*60+59*60),
			),
		},
		{
			name: "sub-microsecond",
			value: time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond).
				Add(time.Nanosecond),
		},
	}
	shapes := []struct {
		name                 string
		tableName            string
		idempotencyKeyPrefix string
		invoke               func(uuid.UUID, string, *time.Time) error
	}{
		{
			name:                 "direct role grant",
			tableName:            "tenant_membership_role_grants",
			idempotencyKeyPrefix: "invalid-direct-expiry-",
			invoke: func(grantID uuid.UUID, idempotencyKey string, expiresAt *time.Time) error {
				_, err := repository.GrantUserRole(ctx, authorization.GrantUserRoleParams{
					Actor: actor, Audit: audit, OccurredAt: time.Now().UTC(), TenantID: fixture.tenantID,
					GrantID: grantID, UserID: fixture.targetUserID, RoleID: roleID,
					Reason: "Reject invalid direct expiry", ExpiresAt: expiresAt,
					IdempotencyKey: idempotencyKey,
				})
				return err
			},
		},
		{
			name:                 "group membership",
			tableName:            "tenant_security_group_memberships",
			idempotencyKeyPrefix: "invalid-membership-expiry-",
			invoke: func(membershipID uuid.UUID, idempotencyKey string, expiresAt *time.Time) error {
				_, err := repository.AddTenantSecurityGroupMembership(
					ctx,
					authorization.AddTenantSecurityGroupMembershipParams{
						Actor: actor, Audit: audit, OccurredAt: time.Now().UTC(), TenantID: fixture.tenantID,
						GroupID: groupID, MembershipID: membershipID, UserID: fixture.targetUserID,
						Reason: "Reject invalid membership expiry", ExpiresAt: expiresAt,
						IdempotencyKey: idempotencyKey,
					},
				)
				return err
			},
		},
		{
			name:                 "group role grant",
			tableName:            "tenant_security_group_role_grants",
			idempotencyKeyPrefix: "invalid-group-role-expiry-",
			invoke: func(grantID uuid.UUID, idempotencyKey string, expiresAt *time.Time) error {
				_, err := repository.GrantTenantSecurityGroupRole(
					ctx,
					authorization.GrantTenantSecurityGroupRoleParams{
						Actor: actor, Audit: audit, OccurredAt: time.Now().UTC(), TenantID: fixture.tenantID,
						GroupID: groupID, GrantID: grantID, RoleID: roleID,
						Reason: "Reject invalid group-role expiry", ExpiresAt: expiresAt,
						IdempotencyKey: idempotencyKey,
					},
				)
				return err
			},
		},
	}

	for _, shape := range shapes {
		for _, expiry := range invalidExpiries {
			t.Run(shape.name+"/"+expiry.name, func(t *testing.T) {
				resourceID := authorizationIntegrationUUID(t)
				idempotencyKey := shape.idempotencyKeyPrefix + expiry.name
				for attempt := 1; attempt <= 2; attempt++ {
					err := shape.invoke(resourceID, idempotencyKey, &expiry.value)
					if !errors.Is(err, authorization.ErrInvalidInput) {
						t.Fatalf("attempt %d operation error = %v, want invalid input", attempt, err)
					}
				}
				assertAuthorizationMutationAbsent(
					t, ctx, adminPool, fixture.tenantID,
					shape.tableName, resourceID, idempotencyKey,
				)
			})
		}
	}
}

func TestAuthorizationRepositoryExpiredCreateReplaySemantics(t *testing.T) {
	databaseURL := strings.TrimSpace(os.Getenv(authorizationIntegrationDatabaseURL))
	if databaseURL == "" {
		t.Skipf("%s is not set", authorizationIntegrationDatabaseURL)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	adminPool := authorizationIntegrationPool(t, ctx, databaseURL, "")
	defer adminPool.Close()
	fixture := seedAuthorizationIntegrationFixture(t, ctx, adminPool)
	runtimePool := authorizationIntegrationPool(t, ctx, databaseURL, "periapsis_api")
	defer runtimePool.Close()
	repository := NewAuthorizationRepository(runtimePool)
	actor := authorizationIntegrationActor(t, fixture.tenantID, fixture.adminUserID)
	now := time.Now().UTC()
	audit := authorizationIntegrationAudit(t)

	roleID := authorizationIntegrationUUID(t)
	roleResult, err := repository.CreateTenantRole(ctx, authorization.CreateTenantRoleParams{
		Actor: actor, Audit: audit, OccurredAt: now, TenantID: fixture.tenantID,
		RoleID: roleID, Key: "expired_replay_role", Name: "Expired replay role",
		Description: "Exercises create replay after expiry.",
		Policy: authorization.TenantRolePolicy{
			Permissions: []authorization.ScopedPermission{{
				Permission: authorization.TenantPermissionPermissionRead, Scope: authorization.ScopeTenant,
			}},
		},
		IdempotencyKey: "expired-replay-role-" + roleID.String(),
	})
	if err != nil || roleResult.Replayed {
		t.Fatalf("create replay-test role result=%+v error=%v", roleResult, err)
	}
	groupID := authorizationIntegrationUUID(t)
	groupResult, err := repository.CreateTenantSecurityGroup(
		ctx,
		authorization.CreateTenantSecurityGroupParams{
			Actor: actor, Audit: audit, OccurredAt: now, TenantID: fixture.tenantID,
			GroupID: groupID, Key: "expired_replay_group", Name: "Expired replay group",
			Description:    "Exercises expiring group edges.",
			IdempotencyKey: "expired-replay-group-" + groupID.String(),
		},
	)
	if err != nil || groupResult.Replayed {
		t.Fatalf("create replay-test group result=%+v error=%v", groupResult, err)
	}

	expiresAt := time.Now().UTC().Add(3 * time.Second).Truncate(time.Microsecond)
	directID := authorizationIntegrationUUID(t)
	directKey := "expired-replay-direct-" + directID.String()
	directParams := authorization.GrantUserRoleParams{
		Actor: actor, Audit: audit, OccurredAt: time.Now().UTC(), TenantID: fixture.tenantID,
		GrantID: directID, UserID: fixture.targetUserID, RoleID: roleID,
		Reason: "Temporary direct replay", ExpiresAt: &expiresAt, IdempotencyKey: directKey,
	}
	directResult, err := repository.GrantUserRole(ctx, directParams)
	if err != nil || directResult.Replayed {
		t.Fatalf("create expiring direct grant result=%+v error=%v", directResult, err)
	}

	membershipID := authorizationIntegrationUUID(t)
	membershipKey := "expired-replay-membership-" + membershipID.String()
	membershipParams := authorization.AddTenantSecurityGroupMembershipParams{
		Actor: actor, Audit: audit, OccurredAt: time.Now().UTC(), TenantID: fixture.tenantID,
		GroupID: groupID, MembershipID: membershipID, UserID: fixture.targetUserID,
		Reason: "Temporary membership replay", ExpiresAt: &expiresAt, IdempotencyKey: membershipKey,
	}
	membershipResult, err := repository.AddTenantSecurityGroupMembership(ctx, membershipParams)
	if err != nil || membershipResult.Replayed {
		t.Fatalf("create expiring group membership result=%+v error=%v", membershipResult, err)
	}

	groupRoleID := authorizationIntegrationUUID(t)
	groupRoleKey := "expired-replay-group-role-" + groupRoleID.String()
	groupRoleParams := authorization.GrantTenantSecurityGroupRoleParams{
		Actor: actor, Audit: audit, OccurredAt: time.Now().UTC(), TenantID: fixture.tenantID,
		GroupID: groupID, GrantID: groupRoleID, RoleID: roleID,
		Reason: "Temporary group-role replay", ExpiresAt: &expiresAt, IdempotencyKey: groupRoleKey,
	}
	groupRoleResult, err := repository.GrantTenantSecurityGroupRole(ctx, groupRoleParams)
	if err != nil || groupRoleResult.Replayed {
		t.Fatalf("create expiring group role result=%+v error=%v", groupRoleResult, err)
	}

	subMicrosecondExpiry := expiresAt.Add(time.Nanosecond)
	directParams.GrantID = authorizationIntegrationUUID(t)
	directParams.ExpiresAt = &subMicrosecondExpiry
	_, err = repository.GrantUserRole(ctx, directParams)
	if !errors.Is(err, authorization.ErrInvalidInput) {
		t.Fatalf("sub-microsecond direct replay error=%v, want invalid input", err)
	}
	membershipParams.MembershipID = authorizationIntegrationUUID(t)
	membershipParams.ExpiresAt = &subMicrosecondExpiry
	_, err = repository.AddTenantSecurityGroupMembership(ctx, membershipParams)
	if !errors.Is(err, authorization.ErrInvalidInput) {
		t.Fatalf("sub-microsecond membership replay error=%v, want invalid input", err)
	}
	groupRoleParams.GrantID = authorizationIntegrationUUID(t)
	groupRoleParams.ExpiresAt = &subMicrosecondExpiry
	_, err = repository.GrantTenantSecurityGroupRole(ctx, groupRoleParams)
	if !errors.Is(err, authorization.ErrInvalidInput) {
		t.Fatalf("sub-microsecond group-role replay error=%v, want invalid input", err)
	}
	directParams.ExpiresAt = &expiresAt
	membershipParams.ExpiresAt = &expiresAt
	groupRoleParams.ExpiresAt = &expiresAt

	if wait := time.Until(expiresAt.Add(100 * time.Millisecond)); wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			t.Fatalf("waiting for edge expiry: %v", ctx.Err())
		case <-timer.C:
		}
	}

	directParams.GrantID = authorizationIntegrationUUID(t)
	directParams.OccurredAt = time.Now().UTC()
	directReplay, err := repository.GrantUserRole(ctx, directParams)
	if err != nil || !directReplay.Replayed || directReplay.Value.ID != directID ||
		directReplay.Value.State != authorization.DirectRoleGrantStateExpired {
		t.Fatalf("expired direct replay result=%+v error=%v", directReplay, err)
	}
	membershipParams.MembershipID = authorizationIntegrationUUID(t)
	membershipParams.OccurredAt = time.Now().UTC()
	membershipReplay, err := repository.AddTenantSecurityGroupMembership(ctx, membershipParams)
	if err != nil || !membershipReplay.Replayed || membershipReplay.Value.ID != membershipID ||
		membershipReplay.Value.State != authorization.AuthorizationEdgeStateExpired {
		t.Fatalf("expired membership replay result=%+v error=%v", membershipReplay, err)
	}
	groupRoleParams.GrantID = authorizationIntegrationUUID(t)
	groupRoleParams.OccurredAt = time.Now().UTC()
	groupRoleReplay, err := repository.GrantTenantSecurityGroupRole(ctx, groupRoleParams)
	if err != nil || !groupRoleReplay.Replayed || groupRoleReplay.Value.ID != groupRoleID ||
		groupRoleReplay.Value.State != authorization.AuthorizationEdgeStateExpired {
		t.Fatalf("expired group-role replay result=%+v error=%v", groupRoleReplay, err)
	}

	pastExpiry := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	directParams.GrantID = authorizationIntegrationUUID(t)
	directParams.ExpiresAt = &pastExpiry
	directParams.IdempotencyKey = "fresh-past-direct-" + directParams.GrantID.String()
	_, err = repository.GrantUserRole(ctx, directParams)
	if !errors.Is(err, authorization.ErrInvalidInput) {
		t.Fatalf("fresh past-expiry direct grant error=%v, want invalid input", err)
	}
	membershipParams.MembershipID = authorizationIntegrationUUID(t)
	membershipParams.ExpiresAt = &pastExpiry
	membershipParams.IdempotencyKey = "fresh-past-membership-" + membershipParams.MembershipID.String()
	_, err = repository.AddTenantSecurityGroupMembership(ctx, membershipParams)
	if !errors.Is(err, authorization.ErrInvalidInput) {
		t.Fatalf("fresh past-expiry membership error=%v, want invalid input", err)
	}
	groupRoleParams.GrantID = authorizationIntegrationUUID(t)
	groupRoleParams.ExpiresAt = &pastExpiry
	groupRoleParams.IdempotencyKey = "fresh-past-group-role-" + groupRoleParams.GrantID.String()
	_, err = repository.GrantTenantSecurityGroupRole(ctx, groupRoleParams)
	if !errors.Is(err, authorization.ErrInvalidInput) {
		t.Fatalf("fresh past-expiry group role error=%v, want invalid input", err)
	}
	for _, mutation := range []struct {
		tableName      string
		resourceID     uuid.UUID
		idempotencyKey string
	}{
		{
			tableName: "tenant_membership_role_grants", resourceID: directParams.GrantID,
			idempotencyKey: directParams.IdempotencyKey,
		},
		{
			tableName: "tenant_security_group_memberships", resourceID: membershipParams.MembershipID,
			idempotencyKey: membershipParams.IdempotencyKey,
		},
		{
			tableName: "tenant_security_group_role_grants", resourceID: groupRoleParams.GrantID,
			idempotencyKey: groupRoleParams.IdempotencyKey,
		},
	} {
		assertAuthorizationMutationAbsent(
			t, ctx, adminPool, fixture.tenantID,
			mutation.tableName, mutation.resourceID, mutation.idempotencyKey,
		)
	}

	directParams.ExpiresAt = &expiresAt
	directParams.IdempotencyKey = directKey
	directParams.Reason = "Drifted direct payload"
	_, err = repository.GrantUserRole(ctx, directParams)
	if !errors.Is(err, authorization.ErrConflict) {
		t.Fatalf("expired direct payload drift error=%v, want conflict", err)
	}
	membershipParams.ExpiresAt = &expiresAt
	membershipParams.IdempotencyKey = membershipKey
	membershipParams.Reason = "Drifted membership payload"
	_, err = repository.AddTenantSecurityGroupMembership(ctx, membershipParams)
	if !errors.Is(err, authorization.ErrConflict) {
		t.Fatalf("expired membership payload drift error=%v, want conflict", err)
	}
	groupRoleParams.ExpiresAt = &expiresAt
	groupRoleParams.IdempotencyKey = groupRoleKey
	groupRoleParams.Reason = "Drifted group-role payload"
	_, err = repository.GrantTenantSecurityGroupRole(ctx, groupRoleParams)
	if !errors.Is(err, authorization.ErrConflict) {
		t.Fatalf("expired group-role payload drift error=%v, want conflict", err)
	}
}

func assertAuthorizationMutationAbsent(
	t *testing.T,
	ctx context.Context,
	adminPool *pgxpool.Pool,
	tenantID uuid.UUID,
	tableName string,
	resourceID uuid.UUID,
	idempotencyKey string,
) {
	t.Helper()
	keyDigest := sha256.Sum256([]byte(idempotencyKey))
	var edgeExists, auditExists, commandExists bool
	query := fmt.Sprintf(`
SELECT EXISTS (
         SELECT 1 FROM public.%s WHERE tenant_id = $1 AND id = $2
       ),
       EXISTS (
         SELECT 1 FROM public.audit_events
         WHERE tenant_id = $1 AND resource_id = $2
       ),
       EXISTS (
         SELECT 1 FROM public.tenant_authorization_commands
         WHERE tenant_id = $1 AND key_digest = $3
       )`, tableName)
	if err := adminPool.QueryRow(
		ctx, query, tenantID, resourceID, keyDigest[:],
	).Scan(&edgeExists, &auditExists, &commandExists); err != nil {
		t.Fatalf("inspect rejected mutation persistence: %v", err)
	}
	if edgeExists || auditExists || commandExists {
		t.Fatalf(
			"rejected mutation persisted edge/audit/command = %t/%t/%t",
			edgeExists, auditExists, commandExists,
		)
	}
}
