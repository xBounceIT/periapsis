package authorization

import (
	"fmt"
	"testing"
)

func TestServiceHydratesCompleteCanonicalHumanAuthorityAndStoredPolicy(t *testing.T) {
	service := &Service{}
	authority := serviceTestAuthority()
	authority.Permissions = nil
	authority.DelegationCeiling = nil
	for key, metadata := range initialTenantPermissions {
		if _, human := metadata.principalKinds[PrincipalKindHuman]; !human {
			continue
		}
		for scope := range metadata.scopes {
			tuple := ScopedPermission{Permission: key, Scope: scope}
			authority.Permissions = append(authority.Permissions, tuple)
			authority.DelegationCeiling = append(authority.DelegationCeiling, DelegationGrant{ScopedPermission: tuple})
		}
	}
	if len(authority.Permissions) <= 100 {
		t.Fatal("canonical policy must exercise the legacy page overflow")
	}
	if !service.validResolvedAuthority(authority, serviceTestActor(), testTenantID) {
		t.Fatal("complete canonical authority rejected")
	}
	policy := TenantRolePolicy{Permissions: authority.Permissions, DelegationCeiling: authority.Permissions}
	role := serviceTestRole(serviceTestID(80), true, policy)
	if !service.validStoredRole(role, testTenantID) {
		t.Fatal("complete stored system role rejected")
	}
	if _, err := service.normalizedRolePolicy(policy); err == nil {
		t.Fatal("public policy write bound was enlarged")
	}
	authority.Permissions = append(authority.Permissions, authority.Permissions[0])
	if service.validResolvedAuthority(authority, serviceTestActor(), testTenantID) {
		t.Fatal("duplicate effective tuple accepted")
	}
}

func TestServiceHydrationTruncationBoundary(t *testing.T) {
	// A synthetic evaluator catalog permits exact capacity tests independently of
	// the current built-in catalog size, without accepting unknown permissions.
	for _, count := range []int{100, 101, 500, 501} {
		service := &Service{evaluator: Evaluator{tenantPermissions: map[TenantPermission]tenantPermissionMetadata{}}}
		authority := serviceTestAuthority()
		authority.Permissions = nil
		authority.DelegationCeiling = nil
		for index := 0; index < count; index++ {
			key := TenantPermission(fmt.Sprintf("bounded_permission_%d.read", index))
			service.evaluator.tenantPermissions[key] = tenantAdministrativePermission
			tuple := ScopedPermission{Permission: key, Scope: ScopeTenant}
			authority.Permissions = append(authority.Permissions, tuple)
			authority.DelegationCeiling = append(authority.DelegationCeiling, DelegationGrant{ScopedPermission: tuple})
		}
		want := count <= 500
		if got := service.validResolvedAuthority(authority, serviceTestActor(), testTenantID); got != want {
			t.Errorf("authority tuples %d valid=%t, want %t", count, got, want)
		}
		policy := TenantRolePolicy{Permissions: authority.Permissions, DelegationCeiling: authority.Permissions}
		if got := service.validStoredRole(serviceTestRole(serviceTestID(80), true, policy), testTenantID); got != want {
			t.Errorf("stored tuples %d valid=%t, want %t", count, got, want)
		}
		_, err := service.normalizedRolePolicy(policy)
		if (err == nil) != (count <= 100) {
			t.Errorf("public write tuples %d error=%v", count, err)
		}
	}
}
