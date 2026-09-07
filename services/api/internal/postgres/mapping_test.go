package postgres

import (
	"bytes"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/postgres/dbsql"
)

func TestMapRateRulesPreservesDistinctAtomicPoliciesAndCopiesDigests(t *testing.T) {
	accountDigest := bytes.Repeat([]byte{0x41}, sha256DigestBytes)
	networkDigest := bytes.Repeat([]byte{0x42}, sha256DigestBytes)
	mapped, err := mapRateRules([]authentication.RateLimitRule{
		{
			Key: authentication.RateLimitKey{Scope: "local_login", Digest: accountDigest},
			Policy: authentication.RateLimitPolicy{
				Limit: 5, Window: 15 * time.Minute, BlockFor: 30 * time.Minute,
			},
		},
		{
			Key: authentication.RateLimitKey{Scope: "local_login", Digest: networkDigest},
			Policy: authentication.RateLimitPolicy{
				Limit: 20, Window: time.Hour, BlockFor: 2 * time.Hour,
			},
		},
	})
	if err != nil {
		t.Fatalf("mapRateRules() error = %v", err)
	}
	if len(mapped.scopes) != 2 ||
		mapped.scopes[0] != string(dbsql.AuthRateLimitScopeLocalLogin) ||
		mapped.scopes[1] != string(dbsql.AuthRateLimitScopeLocalLogin) ||
		mapped.maxAttempts[0] != 5 || mapped.maxAttempts[1] != 20 ||
		mapped.windowSeconds[0] != 900 || mapped.windowSeconds[1] != 3600 ||
		mapped.blockSeconds[0] != 1800 || mapped.blockSeconds[1] != 7200 {
		t.Fatalf("mapped rate rules = %+v", mapped)
	}
	accountDigest[0] = 0
	networkDigest[0] = 0
	if mapped.keyDigests[0][0] != 0x41 || mapped.keyDigests[1][0] != 0x42 {
		t.Fatal("mapped rate rules retained caller-owned digest slices")
	}
}

func TestMapRateRulesRejectsDuplicateOrNonIntegralPolicy(t *testing.T) {
	digest := bytes.Repeat([]byte{0x43}, sha256DigestBytes)
	valid := authentication.RateLimitRule{
		Key: authentication.RateLimitKey{Scope: "tenant_switch", Digest: digest},
		Policy: authentication.RateLimitPolicy{
			Limit: 1, Window: time.Minute, BlockFor: time.Minute,
		},
	}
	if _, err := mapRateRules([]authentication.RateLimitRule{valid, valid}); err == nil {
		t.Fatal("mapRateRules() accepted a duplicate scope/digest")
	}
	valid.Policy.Window = time.Second + time.Nanosecond
	if _, err := mapRateRules([]authentication.RateLimitRule{valid}); err == nil {
		t.Fatal("mapRateRules() accepted a fractional-second window")
	}
}

func TestRetryAfterIsBoundedAndDatabaseInputErrorsRemainPublicInputErrors(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	rateLimit := retryAfter(
		pgtype.Timestamptz{Time: now.Add(7 * 24 * time.Hour), Valid: true}, now,
	)
	if rateLimit == nil || rateLimit.RetryAfter != maximumRetryAfter {
		t.Fatalf("retryAfter() = %+v, want cap %s", rateLimit, maximumRetryAfter)
	}
	databaseError := &pgconn.PgError{Code: "22023"}
	if err := mapCommonDatabaseError(databaseError); !errors.Is(err, authentication.ErrInvalidInput) {
		t.Fatalf("mapCommonDatabaseError(22023) = %v", err)
	}
}

func TestCurrentSessionLogoutReasonMatchesTheAuditedDatabaseContract(t *testing.T) {
	if currentSessionLogoutReason != "user_logout" {
		t.Fatalf("current-session logout reason = %q", currentSessionLogoutReason)
	}
}

func TestMapPermissionsRecognizesClosedPlatformPermissionCatalog(t *testing.T) {
	t.Parallel()

	want := []authorization.Permission{
		authorization.PermissionPlatformTenantRead,
		authorization.PermissionPlatformTenantCreate,
		authorization.PermissionPlatformTenantManage,
		authorization.PermissionPlatformTenantAccess,
		authorization.PermissionPlatformOperatorTeamRead,
		authorization.PermissionPlatformOperatorTeamManage,
		authorization.PermissionPlatformIdentityProviderRead,
		authorization.PermissionPlatformIdentityProviderManage,
		authorization.PermissionPlatformIdentityProviderTest,
		authorization.PermissionPlatformIdentityBindingRead,
		authorization.PermissionPlatformIdentityBindingManage,
		authorization.PermissionPlatformIdentityPolicyRead,
		authorization.PermissionPlatformIdentityPolicyManage,
		authorization.PermissionPlatformIdentityAccountRead,
		authorization.PermissionPlatformIdentityAccountManage,
		authorization.PermissionPlatformNotificationManage,
		authorization.PermissionPlatformAuditRead,
		authorization.PermissionPlatformAuditExport,
		authorization.PermissionPlatformAuditRetentionManage,
		authorization.PermissionPlatformUserRead,
		authorization.PermissionPlatformOperationsRead,
		authorization.PermissionPlatformSettingsRead,
		authorization.PermissionPlatformSettingsManage,
		authorization.PermissionPlatformFeatureFlagRead,
		authorization.PermissionPlatformFeatureFlagManage,
	}
	values := make([]string, 0, len(want)+1)
	for _, permission := range want {
		values = append(values, string(permission))
	}
	values = append(values, string(want[0]))

	permissions, err := mapPermissions(values)
	if err != nil {
		t.Fatalf("mapPermissions() error = %v", err)
	}
	if !slices.Equal(permissions, want) {
		t.Fatalf("mapPermissions() = %#v, want %#v", permissions, want)
	}
	if _, err := mapPermissions([]string{"platform.audit.superuser"}); err == nil {
		t.Fatal("mapPermissions() accepted an unknown platform permission")
	}
}

func TestDomainTenantPermissionRecognizesDedicatedAuditRead(t *testing.T) {
	t.Parallel()

	permission, err := domainTenantPermission(string(authorization.TenantPermissionAuditRead))
	if err != nil || permission != authorization.TenantPermissionAuditRead {
		t.Fatalf("domainTenantPermission(audit.read) = %q, %v", permission, err)
	}
}

func TestDomainTenantPermissionRecognizesSLAPermissions(t *testing.T) {
	t.Parallel()

	for _, expected := range []authorization.TenantPermission{
		authorization.TenantPermissionSLARead,
		authorization.TenantPermissionSLAManage,
		authorization.TenantPermissionSLASimulate,
		authorization.TenantPermissionAlertSLAOverride,
		authorization.TenantPermissionCaseSLAOverride,
	} {
		actual, err := domainTenantPermission(string(expected))
		if err != nil || actual != expected {
			t.Fatalf("domainTenantPermission(%q) = %q, %v", expected, actual, err)
		}
	}
}

func TestDomainTenantPermissionRecognizesWorkflowAdministrationPermissions(t *testing.T) {
	t.Parallel()

	for _, expected := range []authorization.TenantPermission{
		authorization.TenantPermissionWorkflowRead,
		authorization.TenantPermissionWorkflowManage,
	} {
		actual, err := domainTenantPermission(string(expected))
		if err != nil || actual != expected {
			t.Fatalf("domainTenantPermission(%q) = %q, %v", expected, actual, err)
		}
	}
}
