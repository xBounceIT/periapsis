package authorization

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestEvaluatorInitialTenantPermissionCanBeDelegatedExactly(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 23, 12, 0, 0, 0, time.UTC)
	horizon := now.Add(time.Hour)
	authority := testTenantAuthority(TenantPermissionRoleManage, ScopeTenant)
	authority.DelegationCeiling = []DelegationGrant{{
		ScopedPermission: authority.Permissions[0],
		ExpiresAt:        timePointer(horizon),
	}}
	requested := []DelegationRequest{{
		ScopedPermission: authority.Permissions[0],
		ExpiresAt:        timePointer(horizon),
	}}

	if err := (Evaluator{}).RequireDelegation(authority, requested, now); err != nil {
		t.Fatalf("RequireDelegation() error = %v", err)
	}
}

func TestTicketPermissionDelegationUsesExactCatalogTuples(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 25, 12, 0, 0, 0, time.UTC)
	evaluator := Evaluator{}
	assignedUpdate := ScopedPermission{
		Permission: TenantPermissionAlertUpdate,
		Scope:      ScopeAssigned,
	}
	authority := testTenantAuthority(assignedUpdate.Permission, assignedUpdate.Scope)
	authority.DelegationCeiling = []DelegationGrant{{ScopedPermission: assignedUpdate}}

	if err := evaluator.RequireDelegablePolicy(authority, []ScopedPermission{assignedUpdate}, now); err != nil {
		t.Fatalf("RequireDelegablePolicy(exact ticket tuple) error = %v", err)
	}

	for _, requested := range []ScopedPermission{
		{Permission: TenantPermissionAlertUpdate, Scope: ScopeOwn},
		{Permission: TenantPermissionAlertUpdate, Scope: ScopeTenant},
		{Permission: TenantPermissionCaseTransition, Scope: ScopeAssigned},
		{Permission: TenantPermissionCaseCreate, Scope: ScopeAssigned},
	} {
		assertAuthorizationDenied(t, evaluator.RequireDelegablePolicy(
			authority,
			[]ScopedPermission{requested},
			now,
		))
	}
}

func TestTicketPermissionsCannotBeDelegatedByServiceAccounts(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 25, 12, 0, 0, 0, time.UTC)
	permission := ScopedPermission{Permission: TenantPermissionAlertCreate, Scope: ScopeTenant}
	authority := testTenantAuthority(permission.Permission, permission.Scope)
	authority.Principal.Kind = PrincipalKindServiceAccount
	authority.MembershipID = uuid.Nil
	authority.MembershipStatus = ""
	authority.LegacyRole = ""
	authority.DelegationCeiling = []DelegationGrant{{ScopedPermission: permission}}

	assertAuthorizationDenied(t, (Evaluator{}).RequireDelegablePolicy(
		authority,
		[]ScopedPermission{permission},
		now,
	))
}

func TestTemporaryCeilingCanDefinePolicyButBoundsRoleGrant(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 23, 12, 0, 0, 0, time.UTC)
	horizon := now.Add(time.Hour)
	authority := testTenantAuthority(TenantPermissionRoleManage, ScopeTenant)
	authority.DelegationCeiling = []DelegationGrant{{
		ScopedPermission: authority.Permissions[0],
		ExpiresAt:        timePointer(horizon),
	}}
	evaluator := Evaluator{}

	if err := evaluator.RequireDelegablePolicy(authority, authority.Permissions, now); err != nil {
		t.Fatalf("RequireDelegablePolicy() error = %v", err)
	}

	for _, test := range []struct {
		name        string
		expiresAt   *time.Time
		wantAllowed bool
	}{
		{name: "grant before horizon", expiresAt: timePointer(horizon.Add(-time.Nanosecond)), wantAllowed: true},
		{name: "grant at horizon", expiresAt: timePointer(horizon), wantAllowed: true},
		{name: "grant after horizon", expiresAt: timePointer(horizon.Add(time.Nanosecond))},
		{name: "non-expiring grant"},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			requested := []DelegationRequest{{
				ScopedPermission: authority.Permissions[0],
				ExpiresAt:        test.expiresAt,
			}}
			err := evaluator.RequireDelegation(authority, requested, now)
			if test.wantAllowed {
				if err != nil {
					t.Fatalf("RequireDelegation() error = %v", err)
				}
				return
			}
			assertAuthorizationDenied(t, err)
		})
	}

	assertAuthorizationDenied(t, evaluator.RequireDelegablePolicy(authority, authority.Permissions, horizon))
}

func TestEvaluatorRequiresExactLiveCeilingForRolePolicy(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 23, 12, 0, 0, 0, time.UTC)
	horizon := now.Add(time.Hour)
	evaluator := testRelationshipEvaluator()
	authority := testTenantAuthority(tenantPermissionTestResourceRead, ScopeOwn)
	authority.Permissions = append(authority.Permissions, ScopedPermission{
		Permission: tenantPermissionTestResourceRead,
		Scope:      ScopeAssigned,
	})
	authority.DelegationCeiling = []DelegationGrant{{
		ScopedPermission: authority.Permissions[0],
		ExpiresAt:        timePointer(horizon),
	}}

	for _, test := range []struct {
		name        string
		requested   []ScopedPermission
		evaluatedAt time.Time
		wantAllowed bool
	}{
		{
			name:        "empty policy is a subset",
			evaluatedAt: now,
			wantAllowed: true,
		},
		{
			name:        "exact temporary ceiling",
			requested:   []ScopedPermission{authority.Permissions[0]},
			evaluatedAt: now,
			wantAllowed: true,
		},
		{
			name:        "incomparable leaf without ceiling",
			requested:   []ScopedPermission{authority.Permissions[1]},
			evaluatedAt: now,
		},
		{
			name: "unknown permission",
			requested: []ScopedPermission{{
				Permission: "future.read",
				Scope:      ScopeOwn,
			}},
			evaluatedAt: now,
		},
		{
			name:        "ceiling expires at evaluation boundary",
			requested:   []ScopedPermission{authority.Permissions[0]},
			evaluatedAt: horizon,
		},
		{
			name:        "zero evaluation time",
			requested:   []ScopedPermission{authority.Permissions[0]},
			evaluatedAt: time.Time{},
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := evaluator.RequireDelegablePolicy(authority, test.requested, test.evaluatedAt)
			if test.wantAllowed {
				if err != nil {
					t.Fatalf("RequireDelegablePolicy() error = %v", err)
				}
				return
			}
			assertAuthorizationDenied(t, err)
		})
	}
}

func TestEvaluatorRequiresExactDelegationCeilingSubset(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 23, 12, 0, 0, 0, time.UTC)
	horizon := now.Add(2 * time.Hour)
	requestedExpiry := now.Add(time.Hour)
	evaluator := testRelationshipEvaluator()

	allPermissions := []ScopedPermission{
		{Permission: tenantPermissionTestResourceRead, Scope: ScopeOwn},
		{Permission: tenantPermissionTestResourceRead, Scope: ScopeAssigned},
		{Permission: tenantPermissionTestResourceRead, Scope: ScopeOperatorTeam},
		{Permission: tenantPermissionTestResourceRead, Scope: ScopeTenant},
	}
	baseAuthority := func() TenantAuthority {
		authority := testTenantAuthority(tenantPermissionTestResourceRead, ScopeOwn)
		authority.Permissions = allPermissions
		authority.DelegationCeiling = []DelegationGrant{
			{
				ScopedPermission: ScopedPermission{Permission: tenantPermissionTestResourceRead, Scope: ScopeOwn},
				ExpiresAt:        timePointer(horizon),
			},
			{
				ScopedPermission: ScopedPermission{Permission: tenantPermissionTestResourceRead, Scope: ScopeAssigned},
				ExpiresAt:        timePointer(horizon),
			},
		}
		return authority
	}
	request := func(scope Scope) DelegationRequest {
		return DelegationRequest{
			ScopedPermission: ScopedPermission{Permission: tenantPermissionTestResourceRead, Scope: scope},
			ExpiresAt:        timePointer(requestedExpiry),
		}
	}

	tests := []struct {
		name        string
		authority   TenantAuthority
		requested   []DelegationRequest
		wantAllowed bool
	}{
		{
			name:        "empty set is a subset",
			authority:   baseAuthority(),
			wantAllowed: true,
		},
		{
			name:        "exact own tuple",
			authority:   baseAuthority(),
			requested:   []DelegationRequest{request(ScopeOwn)},
			wantAllowed: true,
		},
		{
			name:        "exact assigned tuple",
			authority:   baseAuthority(),
			requested:   []DelegationRequest{request(ScopeAssigned)},
			wantAllowed: true,
		},
		{
			name:        "all tuples have exact ceilings",
			authority:   baseAuthority(),
			requested:   []DelegationRequest{request(ScopeOwn), request(ScopeAssigned)},
			wantAllowed: true,
		},
		{
			name:      "tenant permission does not imply tenant ceiling",
			authority: baseAuthority(),
			requested: []DelegationRequest{request(ScopeTenant)},
		},
		{
			name:      "team permission does not imply team ceiling",
			authority: baseAuthority(),
			requested: []DelegationRequest{request(ScopeOperatorTeam)},
		},
		{
			name: "tenant ceiling does not imply own ceiling",
			authority: func() TenantAuthority {
				authority := baseAuthority()
				authority.DelegationCeiling = []DelegationGrant{{
					ScopedPermission: ScopedPermission{Permission: tenantPermissionTestResourceRead, Scope: ScopeTenant},
					ExpiresAt:        timePointer(horizon),
				}}
				return authority
			}(),
			requested: []DelegationRequest{request(ScopeOwn)},
		},
		{
			name: "one missing tuple denies the full set",
			authority: func() TenantAuthority {
				authority := baseAuthority()
				authority.DelegationCeiling = authority.DelegationCeiling[:1]
				return authority
			}(),
			requested: []DelegationRequest{request(ScopeOwn), request(ScopeAssigned)},
		},
		{
			name: "ceiling must be backed by effective permission",
			authority: func() TenantAuthority {
				authority := baseAuthority()
				authority.Permissions = []ScopedPermission{{
					Permission: tenantPermissionTestResourceRead,
					Scope:      ScopeOwn,
				}}
				return authority
			}(),
			requested: []DelegationRequest{request(ScopeOwn)},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := evaluator.RequireDelegation(test.authority, test.requested, now)
			if test.wantAllowed {
				if err != nil {
					t.Fatalf("RequireDelegation() error = %v", err)
				}
				return
			}
			assertAuthorizationDenied(t, err)
		})
	}
}

func TestEvaluatorDelegationLifetimeBoundaries(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 23, 12, 0, 0, 0, time.UTC)
	oneHour := now.Add(time.Hour)
	justBeforeOneHour := oneHour.Add(-time.Nanosecond)
	justAfterOneHour := oneHour.Add(time.Nanosecond)
	justBeforeNow := now.Add(-time.Nanosecond)
	justAfterNow := now.Add(time.Nanosecond)
	twoHours := now.Add(2 * time.Hour)
	evaluator := testRelationshipEvaluator()

	tests := []struct {
		name        string
		ceilings    []*time.Time
		validUntil  *time.Time
		wantAllowed bool
	}{
		{
			name:        "request before finite ceiling",
			ceilings:    []*time.Time{timePointer(oneHour)},
			validUntil:  timePointer(justBeforeOneHour),
			wantAllowed: true,
		},
		{
			name:        "request equal to finite ceiling",
			ceilings:    []*time.Time{timePointer(oneHour)},
			validUntil:  timePointer(oneHour),
			wantAllowed: true,
		},
		{
			name:       "request after finite ceiling",
			ceilings:   []*time.Time{timePointer(oneHour)},
			validUntil: timePointer(justAfterOneHour),
		},
		{
			name:       "non-expiring request under finite ceiling",
			ceilings:   []*time.Time{timePointer(oneHour)},
			validUntil: nil,
		},
		{
			name:       "request expiring exactly now",
			ceilings:   []*time.Time{timePointer(oneHour)},
			validUntil: timePointer(now),
		},
		{
			name:       "request already expired",
			ceilings:   []*time.Time{timePointer(oneHour)},
			validUntil: timePointer(justBeforeNow),
		},
		{
			name:       "ceiling expiring exactly now",
			ceilings:   []*time.Time{timePointer(now)},
			validUntil: timePointer(justAfterNow),
		},
		{
			name:       "ceiling already expired",
			ceilings:   []*time.Time{timePointer(justBeforeNow)},
			validUntil: timePointer(justAfterNow),
		},
		{
			name:        "non-expiring ceiling covers non-expiring request",
			ceilings:    []*time.Time{nil},
			validUntil:  nil,
			wantAllowed: true,
		},
		{
			name:        "non-expiring ceiling covers finite request",
			ceilings:    []*time.Time{nil},
			validUntil:  timePointer(twoHours),
			wantAllowed: true,
		},
		{
			name:        "another active exact ceiling may cover request",
			ceilings:    []*time.Time{timePointer(justBeforeNow), timePointer(twoHours)},
			validUntil:  timePointer(oneHour),
			wantAllowed: true,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			authority := testTenantAuthority(tenantPermissionTestResourceRead, ScopeOwn)
			for _, expiry := range test.ceilings {
				authority.DelegationCeiling = append(authority.DelegationCeiling, DelegationGrant{
					ScopedPermission: authority.Permissions[0],
					ExpiresAt:        expiry,
				})
			}
			requested := []DelegationRequest{{
				ScopedPermission: authority.Permissions[0],
				ExpiresAt:        test.validUntil,
			}}
			err := evaluator.RequireDelegation(authority, requested, now)
			if test.wantAllowed {
				if err != nil {
					t.Fatalf("RequireDelegation() error = %v", err)
				}
				return
			}
			assertAuthorizationDenied(t, err)
		})
	}
}

func TestEvaluatorDelegationUsesEarliestRequiredHorizon(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 23, 12, 0, 0, 0, time.UTC)
	oneHour := now.Add(time.Hour)
	twoHours := now.Add(2 * time.Hour)
	evaluator := testRelationshipEvaluator()

	authority := testTenantAuthority(tenantPermissionTestResourceRead, ScopeOwn)
	authority.Permissions = append(authority.Permissions, ScopedPermission{
		Permission: tenantPermissionTestResourceRead,
		Scope:      ScopeAssigned,
	})
	authority.DelegationCeiling = []DelegationGrant{
		{ScopedPermission: authority.Permissions[0], ExpiresAt: timePointer(oneHour)},
		{ScopedPermission: authority.Permissions[1], ExpiresAt: timePointer(twoHours)},
	}

	for _, test := range []struct {
		name        string
		validUntil  time.Time
		wantAllowed bool
	}{
		{name: "equal to earliest horizon", validUntil: oneHour, wantAllowed: true},
		{name: "after earliest horizon", validUntil: oneHour.Add(time.Nanosecond)},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			requested := []DelegationRequest{
				{ScopedPermission: authority.Permissions[0], ExpiresAt: timePointer(test.validUntil)},
				{ScopedPermission: authority.Permissions[1], ExpiresAt: timePointer(test.validUntil)},
			}
			err := evaluator.RequireDelegation(authority, requested, now)
			if test.wantAllowed {
				if err != nil {
					t.Fatalf("RequireDelegation() error = %v", err)
				}
				return
			}
			assertAuthorizationDenied(t, err)
		})
	}
}

func TestEvaluatorDelegationUnknownAndMalformedValuesDeny(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 23, 12, 0, 0, 0, time.UTC)
	horizon := now.Add(time.Hour)
	evaluator := testRelationshipEvaluator()
	validAuthority := func() TenantAuthority {
		authority := testTenantAuthority(tenantPermissionTestResourceRead, ScopeOwn)
		authority.DelegationCeiling = []DelegationGrant{{
			ScopedPermission: authority.Permissions[0],
			ExpiresAt:        timePointer(horizon),
		}}
		return authority
	}
	validRequest := func() []DelegationRequest {
		return []DelegationRequest{{
			ScopedPermission: ScopedPermission{
				Permission: tenantPermissionTestResourceRead,
				Scope:      ScopeOwn,
			},
			ExpiresAt: timePointer(horizon),
		}}
	}

	tests := []struct {
		name      string
		evaluator Evaluator
		authority TenantAuthority
		requested []DelegationRequest
		now       time.Time
	}{
		{
			name:      "zero evaluation time",
			evaluator: evaluator,
			authority: validAuthority(),
			requested: validRequest(),
		},
		{
			name:      "unknown request permission",
			evaluator: evaluator,
			authority: validAuthority(),
			requested: []DelegationRequest{{
				ScopedPermission: ScopedPermission{Permission: "future.read", Scope: ScopeOwn},
				ExpiresAt:        timePointer(horizon),
			}},
			now: now,
		},
		{
			name:      "unknown request scope",
			evaluator: evaluator,
			authority: validAuthority(),
			requested: []DelegationRequest{{
				ScopedPermission: ScopedPermission{Permission: tenantPermissionTestResourceRead, Scope: "future_scope"},
				ExpiresAt:        timePointer(horizon),
			}},
			now: now,
		},
		{
			name:      "platform request scope",
			evaluator: evaluator,
			authority: validAuthority(),
			requested: []DelegationRequest{{
				ScopedPermission: ScopedPermission{Permission: tenantPermissionTestResourceRead, Scope: ScopePlatform},
				ExpiresAt:        timePointer(horizon),
			}},
			now: now,
		},
		{
			name:      "unknown principal kind",
			evaluator: evaluator,
			authority: func() TenantAuthority {
				authority := validAuthority()
				authority.Principal.Kind = "future_principal"
				return authority
			}(),
			requested: validRequest(),
			now:       now,
		},
		{
			name: "service account cannot delegate",
			evaluator: Evaluator{tenantPermissions: map[TenantPermission]tenantPermissionMetadata{
				tenantPermissionTestResourceRead: {
					principalKinds: setOf(PrincipalKindHuman, PrincipalKindServiceAccount),
					scopes:         setOf(ScopeOwn),
				},
			}},
			authority: func() TenantAuthority {
				authority := validAuthority()
				authority.Principal.Kind = PrincipalKindServiceAccount
				return authority
			}(),
			requested: validRequest(),
			now:       now,
		},
		{
			name:      "ceiling tuple without matching permission",
			evaluator: evaluator,
			authority: func() TenantAuthority {
				authority := validAuthority()
				authority.DelegationCeiling[0].Scope = ScopeAssigned
				return authority
			}(),
			requested: validRequest(),
			now:       now,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assertAuthorizationDenied(t, test.evaluator.RequireDelegation(test.authority, test.requested, test.now))
		})
	}
}

func timePointer(value time.Time) *time.Time {
	return &value
}
