package authorization

import (
	"errors"
	"testing"
)

func TestEvaluatorDeniesByDefault(t *testing.T) {
	evaluator := Evaluator{}
	tests := []struct {
		name      string
		grants    []Permission
		requested Permission
		wantErr   bool
	}{
		{name: "explicit grant", grants: []Permission{PermissionPlatformTenantRead}, requested: PermissionPlatformTenantRead},
		{name: "missing grant", grants: []Permission{PermissionPlatformTenantRead}, requested: PermissionPlatformTenantCreate, wantErr: true},
		{name: "no grants", requested: PermissionPlatformTenantRead, wantErr: true},
		{name: "unknown request", grants: []Permission{"future.superuser"}, requested: "future.superuser", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := evaluator.Require(test.grants, test.requested)
			if test.wantErr && !errors.Is(err, ErrDenied) {
				t.Fatalf("Require() error = %v, want ErrDenied", err)
			}
			if !test.wantErr && err != nil {
				t.Fatalf("Require() error = %v", err)
			}
		})
	}
}

func TestEvaluatorRecognizesClosedPlatformPermissionCatalog(t *testing.T) {
	t.Parallel()

	evaluator := Evaluator{}
	for _, permission := range []Permission{
		PermissionPlatformTenantRead,
		PermissionPlatformTenantCreate,
		PermissionPlatformTenantManage,
		PermissionPlatformTenantAccess,
		PermissionPlatformOperatorTeamRead,
		PermissionPlatformOperatorTeamManage,
		PermissionPlatformIdentityProviderRead,
		PermissionPlatformIdentityProviderManage,
		PermissionPlatformIdentityProviderTest,
		PermissionPlatformIdentityBindingRead,
		PermissionPlatformIdentityBindingManage,
		PermissionPlatformIdentityPolicyRead,
		PermissionPlatformIdentityPolicyManage,
		PermissionPlatformIdentityAccountRead,
		PermissionPlatformIdentityAccountManage,
		PermissionPlatformNotificationManage,
		PermissionPlatformAuditRead,
		PermissionPlatformAuditExport,
		PermissionPlatformAuditRetentionManage,
		PermissionPlatformUserRead,
		PermissionPlatformOperationsRead,
		PermissionPlatformSettingsRead,
		PermissionPlatformSettingsManage,
		PermissionPlatformFeatureFlagRead,
		PermissionPlatformFeatureFlagManage,
	} {
		permission := permission
		t.Run(string(permission), func(t *testing.T) {
			t.Parallel()
			if err := evaluator.Require([]Permission{permission}, permission); err != nil {
				t.Fatalf("Require() error = %v", err)
			}
		})
	}
}
