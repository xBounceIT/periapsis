package postgres

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	"github.com/periapsis-im/periapsis/services/api/internal/postgres/dbsql"
)

func TestAuthorizationPermissionMapperMatchesCanonicalCatalog(t *testing.T) {
	document, err := contract.GetSpec()
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range document.Components.Schemas["TenantPermissionKey"].Value.Enum {
		key := value.(string)
		if permission, err := domainTenantPermission(key); err != nil || string(permission) != key {
			t.Errorf("canonical permission %q: %q, %v", key, permission, err)
		}
	}
	for _, key := range []string{"", "future.permission", "platform.tenant.read"} {
		if _, err := domainTenantPermission(key); err == nil {
			t.Errorf("unknown tenant permission %q accepted", key)
		}
	}
}

func TestAuthorizationGroupMemberLifecycleMapperFailsClosed(t *testing.T) {
	tenantID, groupID, edgeID := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	for _, revision := range []int32{-1, 0, 1, 2147483647} {
		row := authorizationGroupMembershipTestRow(groupID, edgeID, uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), time.Now().UTC())
		row.MembershipLifecycleRevision = revision
		mapped, err := mapGotAuthorizationSecurityGroupMembership(tenantID, groupID, row)
		if revision <= 0 {
			if err == nil {
				t.Errorf("invalid member lifecycle revision %d accepted", revision)
			}
			continue
		}
		tag, tagErr := authorization.TenantMembershipLifecycleEntityTag(int64(revision))
		if err != nil || tagErr != nil || mapped.Member.LifecycleRevision != int64(revision) || mapped.Member.EntityTag != tag {
			t.Errorf("lifecycle revision %d: %+v, %v", revision, mapped.Member, err)
		}
	}
}

func TestAuthorizationAuthorityHydrationBoundIsIndependentOfListPage(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV7())
	actor := authorizationRepositoryTestActor(t, tenantID)
	contextRow := &dbsql.GetCurrentTenantAuthorizationContextRow{
		TenantID: toDatabaseUUID(tenantID), MembershipID: toDatabaseUUID(uuid.Must(uuid.NewV7())),
		AuthorizationRevision: 1, MembershipStatus: "active", CompatibilityRole: "tenant_admin",
		EvaluatedAt: databaseTime(time.Now().UTC()),
	}
	// This isolates the repository's truncation guard; duplicate tuple validation
	// is independently enforced by the service and is covered there.
	for _, count := range []int{100, 101, 500, 501} {
		rows := make([]*dbsql.ResolveCurrentTenantHumanAuthorityRow, count)
		for index := range rows {
			rows[index] = &dbsql.ResolveCurrentTenantHumanAuthorityRow{PermissionKey: "role.read", Scope: "tenant"}
		}
		result, err := mapResolvedTenantAuthority(actor, tenantID, contextRow, rows, nil, nil)
		if count <= 500 && (err != nil || len(result.Permissions) != count) {
			t.Errorf("%d hydrated tuples: %d, %v", count, len(result.Permissions), err)
		}
		if count == 501 && err == nil {
			t.Error("truncation sentinel accepted")
		}
	}
	if err := validateAuthorizationPage(nil, 101); err != nil {
		t.Fatalf("list page sentinel: %v", err)
	}
	if err := validateAuthorizationPage(nil, 102); err == nil {
		t.Fatal("list page bound was enlarged with authority hydration")
	}
}

func TestAuthorizationStoredPolicyHydratesBeyondListPage(t *testing.T) {
	document, err := contract.GetSpec()
	if err != nil {
		t.Fatal(err)
	}
	var keys, scopes []string
	for _, value := range document.Components.Schemas["TenantPermissionKey"].Value.Enum {
		for _, scope := range []string{"tenant", "assigned"} {
			keys = append(keys, value.(string))
			scopes = append(scopes, scope)
		}
	}
	if len(keys) <= 100 {
		t.Fatal("fixture no longer crosses the legacy page bound")
	}
	policy, err := mapAuthorizationRolePolicyArrays(keys, scopes, keys, scopes)
	if err != nil || len(policy.Permissions) != len(keys) || len(policy.DelegationCeiling) != len(keys) {
		t.Fatalf("full stored policy: %d tuples, %v", len(policy.Permissions), err)
	}
	if _, err := mapAuthorizationRolePolicyArrays(make([]string, 501), make([]string, 501), nil, nil); err == nil {
		t.Fatal("stored policy sentinel accepted")
	}
}
