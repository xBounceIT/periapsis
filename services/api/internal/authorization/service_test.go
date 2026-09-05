package authorization

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

var serviceTestNow = time.Date(2026, time.August, 23, 14, 0, 0, 0, time.UTC)

func TestServiceRejectsWrongActiveTenantBeforeAnyRepositoryAccess(t *testing.T) {
	version := int64(1)
	roleID := serviceTestID(30)
	userID := serviceTestID(31)
	grantID := serviceTestID(32)
	edgeEntityTag := serviceTestEdgeEntityTag(1)
	name := "Updated role"
	actor := serviceTestActor()
	actor.ActiveTenantID = testOtherTenantID

	operations := []struct {
		name   string
		invoke func(*Service) error
	}{
		{
			name: "get authority",
			invoke: func(service *Service) error {
				_, err := service.GetTenantAuthority(context.Background(), actor, testTenantID)
				return err
			},
		},
		{
			name: "list permissions",
			invoke: func(service *Service) error {
				_, err := service.ListTenantPermissions(context.Background(), actor, testTenantID, PageInput{})
				return err
			},
		},
		{
			name: "list roles",
			invoke: func(service *Service) error {
				_, err := service.ListTenantRoles(context.Background(), actor, testTenantID, ListTenantRolesInput{})
				return err
			},
		},
		{
			name: "create role",
			invoke: func(service *Service) error {
				_, err := service.CreateTenantRole(context.Background(), actor, testTenantID, validCreateRoleInput())
				return err
			},
		},
		{
			name: "get role",
			invoke: func(service *Service) error {
				_, err := service.GetTenantRole(context.Background(), actor, testTenantID, roleID)
				return err
			},
		},
		{
			name: "update role",
			invoke: func(service *Service) error {
				_, err := service.UpdateTenantRole(context.Background(), actor, testTenantID, roleID, UpdateTenantRoleInput{
					Name: &name, ExpectedVersion: &version, Audit: serviceTestAudit(),
				})
				return err
			},
		},
		{
			name: "archive role",
			invoke: func(service *Service) error {
				return service.ArchiveTenantRole(context.Background(), actor, testTenantID, roleID, ArchiveTenantRoleInput{
					ExpectedVersion: &version, Audit: serviceTestAudit(),
				})
			},
		},
		{
			name: "replace role policy",
			invoke: func(service *Service) error {
				_, err := service.ReplaceTenantRolePolicy(context.Background(), actor, testTenantID, roleID, ReplaceTenantRolePolicyInput{
					Policy: validRolePolicy(), ExpectedVersion: &version, Audit: serviceTestAudit(),
				})
				return err
			},
		},
		{
			name: "list users",
			invoke: func(service *Service) error {
				_, err := service.ListTenantUsers(context.Background(), actor, testTenantID, PageInput{})
				return err
			},
		},
		{
			name: "list user grants",
			invoke: func(service *Service) error {
				_, err := service.ListUserRoleGrants(context.Background(), actor, testTenantID, userID, ListUserRoleGrantsInput{})
				return err
			},
		},
		{
			name: "grant user role",
			invoke: func(service *Service) error {
				_, err := service.GrantUserRole(context.Background(), actor, testTenantID, userID, validGrantRoleInput(roleID))
				return err
			},
		},
		{
			name: "revoke role grant",
			invoke: func(service *Service) error {
				return service.RevokeRoleGrant(context.Background(), actor, testTenantID, grantID, RevokeRoleGrantInput{
					Reason: "Administrative revocation", ExpectedEntityTag: &edgeEntityTag, Audit: serviceTestAudit(),
				})
			},
		},
	}

	for _, operation := range operations {
		operation := operation
		t.Run(operation.name, func(t *testing.T) {
			repository := &serviceRepositoryStub{}
			service := newTestService(t, repository)
			assertServiceError(t, operation.invoke(service), ErrForbidden)
			if repository.calls != 0 {
				t.Fatalf("repository calls = %d, want 0", repository.calls)
			}
		})
	}
}

func TestServicePermissionDenialStopsBeforeProtectedRepositoryOperation(t *testing.T) {
	repository := &serviceRepositoryStub{
		resolveAuthorityFunc: func(ResolveAuthorityParams) (TenantAuthority, error) {
			return serviceTestAuthority(TenantPermissionPermissionRead), nil
		},
		listRolesFunc: func(ListTenantRolesParams) ([]TenantRoleSummary, error) {
			t.Fatal("ListTenantRoles must not be reached without role.read")
			return nil, nil
		},
	}
	service := newTestService(t, repository)

	_, err := service.ListTenantRoles(
		context.Background(), serviceTestActor(), testTenantID, ListTenantRolesInput{},
	)
	assertServiceError(t, err, ErrForbidden)
	if repository.resolveAuthorityCalls != 1 || repository.listRolesCalls != 0 {
		t.Fatalf("resolve calls = %d, list calls = %d", repository.resolveAuthorityCalls, repository.listRolesCalls)
	}
}

func TestServiceResolvesAuthorityAgainForEveryOperation(t *testing.T) {
	repository := &serviceRepositoryStub{}
	repository.resolveAuthorityFunc = func(ResolveAuthorityParams) (TenantAuthority, error) {
		if repository.resolveAuthorityCalls == 1 {
			return serviceTestAuthority(TenantPermissionRoleRead), nil
		}
		return serviceTestAuthority(), nil
	}
	repository.listRolesFunc = func(ListTenantRolesParams) ([]TenantRoleSummary, error) {
		return []TenantRoleSummary{}, nil
	}
	service := newTestService(t, repository)

	if _, err := service.ListTenantRoles(
		context.Background(), serviceTestActor(), testTenantID, ListTenantRolesInput{},
	); err != nil {
		t.Fatalf("first ListTenantRoles() error = %v", err)
	}
	_, err := service.ListTenantRoles(
		context.Background(), serviceTestActor(), testTenantID, ListTenantRolesInput{},
	)
	assertServiceError(t, err, ErrForbidden)
	if repository.resolveAuthorityCalls != 2 || repository.listRolesCalls != 1 {
		t.Fatalf("resolve calls = %d, list calls = %d", repository.resolveAuthorityCalls, repository.listRolesCalls)
	}
}

func TestRoleReadsExposeBothPrincipalKindsButHumanMutationRejectsMachineRole(t *testing.T) {
	t.Parallel()

	human := serviceTestRole(serviceTestID(201), false, TenantRolePolicy{})
	machine := serviceTestRole(serviceTestID(202), false, TenantRolePolicy{})
	machine.PrincipalKind = PrincipalKindServiceAccount
	readRepository := &serviceRepositoryStub{
		resolveAuthorityFunc: func(ResolveAuthorityParams) (TenantAuthority, error) {
			return serviceTestAuthority(TenantPermissionRoleRead), nil
		},
		listRolesFunc: func(ListTenantRolesParams) ([]TenantRoleSummary, error) {
			return []TenantRoleSummary{human.TenantRoleSummary, machine.TenantRoleSummary}, nil
		},
	}
	page, err := newTestService(t, readRepository).ListTenantRoles(
		context.Background(), serviceTestActor(), testTenantID, ListTenantRolesInput{},
	)
	if err != nil || len(page.Items) != 2 || page.Items[0].PrincipalKind != PrincipalKindHuman ||
		page.Items[1].PrincipalKind != PrincipalKindServiceAccount {
		t.Fatalf("ListTenantRoles() = (%#v, %v)", page, err)
	}

	mutationRepository := &serviceRepositoryStub{
		resolveAuthorityFunc: func(ResolveAuthorityParams) (TenantAuthority, error) {
			return serviceTestAuthority(TenantPermissionRoleManage), nil
		},
		getRoleFunc: func(GetTenantRoleParams) (TenantRole, error) { return machine, nil },
		updateRoleFunc: func(UpdateTenantRoleParams) (TenantRole, error) {
			t.Fatal("machine role reached the human-role mutation repository method")
			return TenantRole{}, nil
		},
	}
	version := machine.Version
	name := "Renamed machine role"
	_, err = newTestService(t, mutationRepository).UpdateTenantRole(
		context.Background(), serviceTestActor(), testTenantID, machine.ID,
		UpdateTenantRoleInput{Name: &name, ExpectedVersion: &version, Audit: serviceTestAudit()},
	)
	assertServiceError(t, err, ErrConflict)
	if mutationRepository.updateRoleCalls != 0 {
		t.Fatalf("update role calls = %d", mutationRepository.updateRoleCalls)
	}
}

func TestServiceValidatesPageLimitAndUUIDv7CursorBeforeAuthorityLookup(t *testing.T) {
	invalidVersionFour := uuid.MustParse("00000000-0000-4000-8000-000000000001")
	tests := []struct {
		name  string
		input PageInput
	}{
		{name: "negative limit", input: PageInput{Limit: -1}},
		{name: "limit above maximum", input: PageInput{Limit: 101}},
		{name: "nil uuid cursor", input: PageInput{After: uuidPointer(uuid.Nil)}},
		{name: "non v7 cursor", input: PageInput{After: uuidPointer(invalidVersionFour)}},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			repository := &serviceRepositoryStub{}
			service := newTestService(t, repository)
			_, err := service.ListTenantPermissions(
				context.Background(), serviceTestActor(), testTenantID, test.input,
			)
			assertServiceError(t, err, ErrInvalidInput)
			if repository.calls != 0 {
				t.Fatalf("repository calls = %d, want 0", repository.calls)
			}
		})
	}
}

func TestMembershipLifecycleRejectsUnsafeReasonBeforeAuthorityLookup(t *testing.T) {
	t.Parallel()

	expectedRevision := int64(1)
	unsafeReasons := []string{
		"",
		" leading whitespace",
		"trailing whitespace ",
		"line\nbreak",
		"hidden\u200bseparator",
		"password=correct-horse-battery-staple",
		"Bearer abcdefghijklmnopqrstuvwxyz",
		"eyJheader12345.eyJpayload12345.signature12345",
		strings.Repeat("x", 2049),
	}
	for _, reason := range unsafeReasons {
		reason := reason
		t.Run(fmt.Sprintf("%q", reason), func(t *testing.T) {
			repository := &serviceRepositoryStub{}
			_, err := newTestService(t, repository).ChangeTenantMembershipLifecycle(
				context.Background(), serviceTestActor(), testTenantID, serviceTestID(31),
				MembershipStatusSuspended,
				TenantMembershipLifecycleInput{
					ExpectedRevision: &expectedRevision,
					Reason:           reason,
					IdempotencyKey:   "membership-lifecycle-key-0001",
					Audit:            serviceTestAudit(),
				},
			)
			assertServiceError(t, err, ErrInvalidInput)
			if repository.calls != 0 {
				t.Fatalf("repository calls = %d, want 0", repository.calls)
			}
		})
	}
}

func TestMembershipLifecycleRequiresPermissionAndForwardsExactCommand(t *testing.T) {
	t.Parallel()

	targetUserID := serviceTestID(31)
	targetMembershipID := serviceTestID(32)
	expectedRevision := int64(7)
	wantReceipt := TenantMembershipLifecycleReceipt{
		TenantID:                 testTenantID,
		MembershipID:             targetMembershipID,
		UserID:                   targetUserID,
		PreviousStatus:           MembershipStatusActive,
		Status:                   MembershipStatusSuspended,
		LifecycleRevision:        expectedRevision + 1,
		EntityTag:                `"v8"`,
		UpdatedAt:                serviceTestNow,
		RevokedSessionCount:      2,
		RevokedContinuationCount: 1,
	}

	deniedRepository := &serviceRepositoryStub{
		resolveAuthorityFunc: func(ResolveAuthorityParams) (TenantAuthority, error) {
			return serviceTestAuthority(TenantPermissionUserRead), nil
		},
		changeMembershipLifecycleFunc: func(ChangeTenantMembershipLifecycleParams) (TenantMembershipLifecycleReceipt, error) {
			t.Fatal("membership mutation reached without membership.manage")
			return TenantMembershipLifecycleReceipt{}, nil
		},
	}
	input := TenantMembershipLifecycleInput{
		ExpectedRevision: &expectedRevision,
		Reason:           "Suspend access during the offboarding review",
		IdempotencyKey:   "membership-lifecycle-key-0002",
		Audit:            serviceTestAudit(),
	}
	_, err := newTestService(t, deniedRepository).ChangeTenantMembershipLifecycle(
		context.Background(), serviceTestActor(), testTenantID, targetUserID,
		MembershipStatusSuspended, input,
	)
	assertServiceError(t, err, ErrForbidden)
	if deniedRepository.changeMembershipLifecycleCalls != 0 {
		t.Fatalf("membership lifecycle calls = %d, want 0", deniedRepository.changeMembershipLifecycleCalls)
	}

	allowedRepository := &serviceRepositoryStub{
		resolveAuthorityFunc: func(ResolveAuthorityParams) (TenantAuthority, error) {
			return serviceTestAuthority(TenantPermissionMembershipManage), nil
		},
		changeMembershipLifecycleFunc: func(params ChangeTenantMembershipLifecycleParams) (TenantMembershipLifecycleReceipt, error) {
			if params.Actor != serviceTestActor() || params.TenantID != testTenantID ||
				params.UserID != targetUserID || params.TargetStatus != MembershipStatusSuspended ||
				params.ExpectedRevision != expectedRevision || params.Reason != input.Reason ||
				params.IdempotencyKey != input.IdempotencyKey || params.Audit != input.Audit ||
				!params.OccurredAt.Equal(serviceTestNow) {
				t.Fatalf("membership lifecycle params = %+v", params)
			}
			return wantReceipt, nil
		},
	}
	receipt, err := newTestService(t, allowedRepository).ChangeTenantMembershipLifecycle(
		context.Background(), serviceTestActor(), testTenantID, targetUserID,
		MembershipStatusSuspended, input,
	)
	if err != nil || receipt != wantReceipt {
		t.Fatalf("membership lifecycle receipt = (%+v, %v)", receipt, err)
	}
	if allowedRepository.resolveAuthorityCalls != 1 || allowedRepository.changeMembershipLifecycleCalls != 1 {
		t.Fatalf("authority/mutation calls = %d/%d, want 1/1", allowedRepository.resolveAuthorityCalls, allowedRepository.changeMembershipLifecycleCalls)
	}
}

func TestServiceUsesLimitPlusOneAndReturnsLastVisibleRoleCursor(t *testing.T) {
	roleIDs := []uuid.UUID{serviceTestID(40), serviceTestID(41), serviceTestID(42)}
	roles := []TenantRoleSummary{
		serviceTestRole(roleIDs[0], false, TenantRolePolicy{}).TenantRoleSummary,
		serviceTestRole(roleIDs[1], false, TenantRolePolicy{}).TenantRoleSummary,
		serviceTestRole(roleIDs[2], false, TenantRolePolicy{}).TenantRoleSummary,
	}
	after := serviceTestID(39)
	var received ListTenantRolesParams
	repository := &serviceRepositoryStub{
		resolveAuthorityFunc: func(ResolveAuthorityParams) (TenantAuthority, error) {
			return serviceTestAuthority(TenantPermissionRoleRead), nil
		},
		listRolesFunc: func(params ListTenantRolesParams) ([]TenantRoleSummary, error) {
			received = params
			return roles, nil
		},
	}
	service := newTestService(t, repository)

	page, err := service.ListTenantRoles(context.Background(), serviceTestActor(), testTenantID, ListTenantRolesInput{
		PageInput: PageInput{After: &after, Limit: 2}, IncludeArchived: true,
	})
	if err != nil {
		t.Fatalf("ListTenantRoles() error = %v", err)
	}
	if received.Limit != 3 || received.After == nil || *received.After != after || !received.IncludeArchived {
		t.Fatalf("repository params = %#v", received)
	}
	if len(page.Items) != 2 || page.Items[0].ID != roleIDs[0] || page.Items[1].ID != roleIDs[1] {
		t.Fatalf("page items = %#v", page.Items)
	}
	if page.NextCursor == nil || *page.NextCursor != roleIDs[1] {
		t.Fatalf("next cursor = %v, want %s", page.NextCursor, roleIDs[1])
	}
}

func TestServiceTenantUserPageCursorUsesMembershipID(t *testing.T) {
	users := []TenantUserSummary{
		serviceTestUser(serviceTestID(50), serviceTestID(60)),
		serviceTestUser(serviceTestID(51), serviceTestID(61)),
	}
	users[0].MembershipStatus = MembershipStatusInvited
	repository := &serviceRepositoryStub{
		resolveAuthorityFunc: func(ResolveAuthorityParams) (TenantAuthority, error) {
			return serviceTestAuthority(TenantPermissionUserRead), nil
		},
		listUsersFunc: func(params ListTenantUsersParams) ([]TenantUserSummary, error) {
			if params.Limit != 2 {
				t.Fatalf("repository limit = %d, want 2", params.Limit)
			}
			return users, nil
		},
	}
	service := newTestService(t, repository)

	page, err := service.ListTenantUsers(
		context.Background(), serviceTestActor(), testTenantID, PageInput{Limit: 1},
	)
	if err != nil {
		t.Fatalf("ListTenantUsers() error = %v", err)
	}
	if len(page.Items) != 1 || page.NextCursor == nil || *page.NextCursor != users[0].MembershipID {
		t.Fatalf("page = %#v", page)
	}
	if *page.NextCursor == users[0].User.ID {
		t.Fatal("next cursor must use membership ID, not global user ID")
	}
}

func TestServiceAllInventoriesRejectImmediateCursorRepeat(t *testing.T) {
	after := serviceTestID(200)
	userID := serviceTestID(201)
	roleID := serviceTestID(202)
	groupID := serviceTestID(203)
	sourceID := serviceTestID(204)
	role := serviceTestRole(roleID, false, TenantRolePolicy{})
	cursorRole := serviceTestRole(after, false, TenantRolePolicy{})
	group := serviceTestGroup(groupID, "cursor_group")
	permission := TenantPermissionDefinition{
		ID: after, Key: TenantPermissionPermissionRead,
		Name: "Read permission catalog", Description: "Lists tenant permission definitions.",
		AllowedScopes: []Scope{ScopeTenant}, PrincipalKinds: []PrincipalKind{PrincipalKindHuman},
	}
	user := serviceTestUser(after, userID)
	directGrant := serviceTestDirectGrant(after, userID, role, "Direct access", nil)
	membership := serviceTestGroupMembership(after, userID, group)
	groupRoleGrant := TenantSecurityGroupRoleGrant{
		ID: after, TenantID: testTenantID, Group: group, Role: role.TenantRoleSummary,
		Provenance: AuthorizationEdgeProvenance{
			SourceKind: AuthorizationSourceManual, SourceID: &sourceID,
			GrantedByUserID: uuidPointer(testPrincipalID), GrantedAt: serviceTestNow.Add(-time.Hour),
			Reason: "Group role grant",
		},
		State: AuthorizationEdgeStateActive, Version: 1, UpdatedAt: serviceTestNow,
	}
	repository := &serviceRepositoryStub{
		resolveAuthorityFunc: func(ResolveAuthorityParams) (TenantAuthority, error) {
			return serviceTestAuthority(
				TenantPermissionPermissionRead,
				TenantPermissionRoleRead,
				TenantPermissionUserRead,
				TenantPermissionGroupRead,
			), nil
		},
		listPermissionsFunc: func(ListTenantPermissionsParams) ([]TenantPermissionDefinition, error) {
			return []TenantPermissionDefinition{permission}, nil
		},
		listRolesFunc: func(ListTenantRolesParams) ([]TenantRoleSummary, error) {
			return []TenantRoleSummary{cursorRole.TenantRoleSummary}, nil
		},
		listUsersFunc: func(ListTenantUsersParams) ([]TenantUserSummary, error) {
			return []TenantUserSummary{user}, nil
		},
		listGrantsFunc: func(ListUserRoleGrantsParams) ([]DirectUserRoleGrant, error) {
			return []DirectUserRoleGrant{directGrant}, nil
		},
		listGroupsFunc: func(ListTenantSecurityGroupsParams) ([]TenantSecurityGroup, error) {
			return []TenantSecurityGroup{serviceTestGroup(after, "cursor_group")}, nil
		},
		listGroupMembershipsFunc: func(ListTenantSecurityGroupMembershipsParams) ([]TenantSecurityGroupMembership, error) {
			return []TenantSecurityGroupMembership{membership}, nil
		},
		listGroupRoleGrantsFunc: func(ListTenantSecurityGroupRoleGrantsParams) ([]TenantSecurityGroupRoleGrant, error) {
			return []TenantSecurityGroupRoleGrant{groupRoleGrant}, nil
		},
	}
	service := newTestService(t, repository)
	page := PageInput{After: &after, Limit: 1}
	tests := []struct {
		name   string
		invoke func() error
	}{
		{
			name: "permissions",
			invoke: func() error {
				_, err := service.ListTenantPermissions(
					context.Background(), serviceTestActor(), testTenantID, page,
				)
				return err
			},
		},
		{
			name: "roles",
			invoke: func() error {
				_, err := service.ListTenantRoles(
					context.Background(), serviceTestActor(), testTenantID,
					ListTenantRolesInput{PageInput: page},
				)
				return err
			},
		},
		{
			name: "users",
			invoke: func() error {
				_, err := service.ListTenantUsers(
					context.Background(), serviceTestActor(), testTenantID, page,
				)
				return err
			},
		},
		{
			name: "direct role grants",
			invoke: func() error {
				_, err := service.ListUserRoleGrants(
					context.Background(), serviceTestActor(), testTenantID, userID,
					ListUserRoleGrantsInput{PageInput: page},
				)
				return err
			},
		},
		{
			name: "security groups",
			invoke: func() error {
				_, err := service.ListTenantSecurityGroups(
					context.Background(), serviceTestActor(), testTenantID,
					ListTenantSecurityGroupsInput{PageInput: page},
				)
				return err
			},
		},
		{
			name: "security group memberships",
			invoke: func() error {
				_, err := service.ListTenantSecurityGroupMemberships(
					context.Background(), serviceTestActor(), testTenantID, groupID,
					ListTenantSecurityGroupEdgesInput{PageInput: page},
				)
				return err
			},
		},
		{
			name: "security group role grants",
			invoke: func() error {
				_, err := service.ListTenantSecurityGroupRoleGrants(
					context.Background(), serviceTestActor(), testTenantID, groupID,
					ListTenantSecurityGroupEdgesInput{PageInput: page},
				)
				return err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertServiceError(t, test.invoke(), ErrUnavailable)
		})
	}
	if repository.resolveAuthorityCalls != len(tests) {
		t.Fatalf("authority resolutions = %d, want %d", repository.resolveAuthorityCalls, len(tests))
	}
}

func TestServiceReadOperationsReturnValidatedDomainModels(t *testing.T) {
	roleID := serviceTestID(62)
	userID := serviceTestID(63)
	grantID := serviceTestID(64)
	role := serviceTestRole(roleID, false, validRolePolicy())
	permission := TenantPermissionDefinition{
		ID: serviceTestID(65), Key: TenantPermissionPermissionRead,
		Name: "Read permission catalog", Description: "Lists tenant permission definitions.",
		AllowedScopes: []Scope{ScopeTenant}, PrincipalKinds: []PrincipalKind{PrincipalKindHuman},
	}
	grant := serviceTestDirectGrant(grantID, userID, role, "Administrative role grant", nil)
	var permissionParams ListTenantPermissionsParams
	var grantParams ListUserRoleGrantsParams
	repository := &serviceRepositoryStub{
		resolveAuthorityFunc: func(ResolveAuthorityParams) (TenantAuthority, error) {
			return serviceTestAuthority(
				TenantPermissionPermissionRead,
				TenantPermissionRoleRead,
			), nil
		},
		listPermissionsFunc: func(params ListTenantPermissionsParams) ([]TenantPermissionDefinition, error) {
			permissionParams = params
			return []TenantPermissionDefinition{permission}, nil
		},
		getRoleFunc: func(GetTenantRoleParams) (TenantRole, error) {
			return role, nil
		},
		listGrantsFunc: func(params ListUserRoleGrantsParams) ([]DirectUserRoleGrant, error) {
			grantParams = params
			return []DirectUserRoleGrant{grant}, nil
		},
	}
	service := newTestService(t, repository)
	actor := serviceTestActor()

	authority, err := service.GetTenantAuthority(context.Background(), actor, testTenantID)
	if err != nil || authority.Principal.ID != actor.UserID {
		t.Fatalf("GetTenantAuthority() = %#v, %v", authority, err)
	}
	permissionPage, err := service.ListTenantPermissions(context.Background(), actor, testTenantID, PageInput{})
	if err != nil || len(permissionPage.Items) != 1 || permissionPage.Items[0].ID != permission.ID ||
		permissionPage.NextCursor != nil || permissionParams.Limit != defaultPageSize+1 {
		t.Fatalf("ListTenantPermissions() = %#v, params = %#v, error = %v", permissionPage, permissionParams, err)
	}
	gotRole, err := service.GetTenantRole(context.Background(), actor, testTenantID, roleID)
	if err != nil || gotRole.ID != roleID {
		t.Fatalf("GetTenantRole() = %#v, %v", gotRole, err)
	}
	grantPage, err := service.ListUserRoleGrants(context.Background(), actor, testTenantID, userID, ListUserRoleGrantsInput{
		IncludeRevoked: true,
	})
	if err != nil || len(grantPage.Items) != 1 || grantPage.Items[0].ID != grantID ||
		grantPage.NextCursor != nil || grantParams.Limit != defaultPageSize+1 || !grantParams.IncludeRevoked {
		t.Fatalf("ListUserRoleGrants() = %#v, params = %#v, error = %v", grantPage, grantParams, err)
	}
	if repository.resolveAuthorityCalls != 4 {
		t.Fatalf("authority resolutions = %d, want 4", repository.resolveAuthorityCalls)
	}
}

func TestServiceRolePolicyRejectsNonCatalogAndPlatformScopes(t *testing.T) {
	tests := []struct {
		name       string
		permission ScopedPermission
	}{
		{
			name:       "relationship scope not yet allowed",
			permission: ScopedPermission{Permission: TenantPermissionRoleRead, Scope: ScopeOwn},
		},
		{
			name:       "platform scope",
			permission: ScopedPermission{Permission: TenantPermissionRoleRead, Scope: ScopePlatform},
		},
		{
			name:       "unknown permission",
			permission: ScopedPermission{Permission: "future.read", Scope: ScopeTenant},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			repository := &serviceRepositoryStub{}
			service := newTestService(t, repository)
			input := validCreateRoleInput()
			input.Policy = TenantRolePolicy{Permissions: []ScopedPermission{test.permission}}
			_, err := service.CreateTenantRole(context.Background(), serviceTestActor(), testTenantID, input)
			assertServiceError(t, err, ErrInvalidInput)
			if repository.calls != 0 {
				t.Fatalf("repository calls = %d, want 0", repository.calls)
			}
		})
	}
}

func TestServiceCreateRoleRequiresExactLivePolicyCeiling(t *testing.T) {
	policyPermission := ScopedPermission{Permission: TenantPermissionRoleRead, Scope: ScopeTenant}
	horizon := serviceTestNow.Add(time.Hour)
	newRoleID := serviceTestID(70)
	input := validCreateRoleInput()
	input.Policy = TenantRolePolicy{
		Permissions:       []ScopedPermission{policyPermission},
		DelegationCeiling: []ScopedPermission{policyPermission},
	}

	t.Run("temporary exact ceiling may define policy", func(t *testing.T) {
		authority := serviceTestAuthority(TenantPermissionRoleManage, TenantPermissionRoleRead)
		authority.DelegationCeiling = []DelegationGrant{{
			ScopedPermission: policyPermission,
			ExpiresAt:        timePointer(horizon),
		}}
		var received CreateTenantRoleParams
		repository := &serviceRepositoryStub{
			resolveAuthorityFunc: func(ResolveAuthorityParams) (TenantAuthority, error) {
				return authority, nil
			},
			createRoleFunc: func(params CreateTenantRoleParams) (TenantRole, error) {
				received = params
				role := serviceTestRole(params.RoleID, false, params.Policy)
				role.Key = params.Key
				role.Name = params.Name
				role.Description = params.Description
				return role, nil
			},
		}
		service := newTestService(t, repository)
		service.newID = func() (uuid.UUID, error) { return newRoleID, nil }

		role, err := service.CreateTenantRole(context.Background(), serviceTestActor(), testTenantID, input)
		if err != nil {
			t.Fatalf("CreateTenantRole() error = %v", err)
		}
		if role.ID != newRoleID || received.RoleID != newRoleID ||
			received.IdempotencyKey != input.IdempotencyKey || received.Actor != serviceTestActor() ||
			received.OccurredAt != serviceTestNow || received.Audit != input.Audit {
			t.Fatalf("mutation params = %#v", received)
		}
	})

	t.Run("permission without exact ceiling denies mutation", func(t *testing.T) {
		repository := &serviceRepositoryStub{
			resolveAuthorityFunc: func(ResolveAuthorityParams) (TenantAuthority, error) {
				return serviceTestAuthority(TenantPermissionRoleManage, TenantPermissionRoleRead), nil
			},
			createRoleFunc: func(CreateTenantRoleParams) (TenantRole, error) {
				return TenantRole{}, ErrForbidden
			},
		}
		service := newTestService(t, repository)
		_, err := service.CreateTenantRole(context.Background(), serviceTestActor(), testTenantID, input)
		assertServiceError(t, err, ErrForbidden)
		if repository.createRoleCalls != 1 {
			t.Fatalf("create calls = %d, want 1 atomic replay/new-command decision", repository.createRoleCalls)
		}
	})
}

func TestServiceCreateRoleAcceptsRepositorySuccessAfterConcurrentDelegationGain(t *testing.T) {
	permission := ScopedPermission{Permission: TenantPermissionRoleRead, Scope: ScopeTenant}
	input := validCreateRoleInput()
	input.Policy = TenantRolePolicy{Permissions: []ScopedPermission{permission}}
	roleID := serviceTestID(150)
	repository := &serviceRepositoryStub{
		resolveAuthorityFunc: func(ResolveAuthorityParams) (TenantAuthority, error) {
			// This snapshot permits role management but cannot delegate the requested policy.
			// The repository represents a later atomic check after the delegation ceiling is gained.
			return serviceTestAuthority(TenantPermissionRoleManage), nil
		},
		createRoleFunc: func(params CreateTenantRoleParams) (TenantRole, error) {
			role := serviceTestRole(params.RoleID, false, params.Policy)
			role.Key = params.Key
			role.Name = params.Name
			role.Description = params.Description
			return role, nil
		},
	}
	service := newTestService(t, repository)
	service.newID = func() (uuid.UUID, error) { return roleID, nil }

	role, err := service.CreateTenantRole(
		context.Background(), serviceTestActor(), testTenantID, input,
	)
	if err != nil || role.ID != roleID {
		t.Fatalf("CreateTenantRole() = %#v, %v", role, err)
	}
	if repository.resolveAuthorityCalls != 1 || repository.createRoleCalls != 1 {
		t.Fatalf(
			"resolve calls = %d, create calls = %d, want 1 each",
			repository.resolveAuthorityCalls, repository.createRoleCalls,
		)
	}
}

func TestServiceAcceptsAtomicCreateIdempotencyReplayID(t *testing.T) {
	permission := ScopedPermission{Permission: TenantPermissionRoleRead, Scope: ScopeTenant}
	authority := serviceTestAuthority(TenantPermissionRoleManage, TenantPermissionRoleRead)
	replayedRoleID := serviceTestID(71)
	repository := &serviceRepositoryStub{
		createRoleReplayed: true,
		resolveAuthorityFunc: func(ResolveAuthorityParams) (TenantAuthority, error) {
			return authority, nil
		},
		createRoleFunc: func(params CreateTenantRoleParams) (TenantRole, error) {
			role := serviceTestRole(replayedRoleID, false, params.Policy)
			role.Key = params.Key
			role.Name = params.Name
			role.Description = params.Description
			role.Archived = true
			role.ArchivedAt = timePointer(serviceTestNow)
			role.Version = 2
			return role, nil
		},
	}
	service := newTestService(t, repository)
	service.newID = func() (uuid.UUID, error) { return serviceTestID(72), nil }
	input := validCreateRoleInput()
	input.Policy = TenantRolePolicy{Permissions: []ScopedPermission{permission}}

	role, err := service.CreateTenantRole(context.Background(), serviceTestActor(), testTenantID, input)
	if err != nil || role.ID != replayedRoleID || !role.Archived || role.Version != 2 {
		t.Fatalf("CreateTenantRole() replay = %#v, %v", role, err)
	}
}

func TestServiceRejectsArchivedNewRoleResult(t *testing.T) {
	permission := ScopedPermission{Permission: TenantPermissionRoleRead, Scope: ScopeTenant}
	authority := serviceTestAuthority(TenantPermissionRoleManage, TenantPermissionRoleRead)
	authority.DelegationCeiling = []DelegationGrant{{ScopedPermission: permission}}
	repository := &serviceRepositoryStub{
		resolveAuthorityFunc: func(ResolveAuthorityParams) (TenantAuthority, error) {
			return authority, nil
		},
		createRoleFunc: func(params CreateTenantRoleParams) (TenantRole, error) {
			role := serviceTestRole(params.RoleID, false, params.Policy)
			role.Key = params.Key
			role.Archived = true
			role.ArchivedAt = timePointer(serviceTestNow)
			return role, nil
		},
	}
	service := newTestService(t, repository)
	input := validCreateRoleInput()
	input.Policy = TenantRolePolicy{Permissions: []ScopedPermission{permission}}

	_, err := service.CreateTenantRole(
		context.Background(), serviceTestActor(), testTenantID, input,
	)
	assertServiceError(t, err, ErrUnavailable)
}

func TestServiceRejectsDelegationCeilingOutsideRolePermissions(t *testing.T) {
	repository := &serviceRepositoryStub{}
	service := newTestService(t, repository)
	input := validCreateRoleInput()
	input.Policy = TenantRolePolicy{
		Permissions: []ScopedPermission{{Permission: TenantPermissionRoleRead, Scope: ScopeTenant}},
		DelegationCeiling: []ScopedPermission{{
			Permission: TenantPermissionUserRead,
			Scope:      ScopeTenant,
		}},
	}

	_, err := service.CreateTenantRole(context.Background(), serviceTestActor(), testTenantID, input)
	assertServiceError(t, err, ErrInvalidInput)
	if repository.calls != 0 {
		t.Fatalf("repository calls = %d, want 0", repository.calls)
	}
}

func TestServiceProtectsSystemRoleMutationsBeforeDelegation(t *testing.T) {
	roleID := serviceTestID(80)
	version := int64(1)
	role := serviceTestRole(roleID, true, validRolePolicy())
	repository := &serviceRepositoryStub{
		resolveAuthorityFunc: func(ResolveAuthorityParams) (TenantAuthority, error) {
			return serviceTestAuthority(TenantPermissionRoleManage), nil
		},
		getRoleFunc: func(GetTenantRoleParams) (TenantRole, error) {
			return role, nil
		},
		updateRoleFunc: func(UpdateTenantRoleParams) (TenantRole, error) {
			t.Fatal("system role update mutation must not be reached")
			return TenantRole{}, nil
		},
		archiveRoleFunc: func(ArchiveTenantRoleParams) error {
			t.Fatal("system role archive mutation must not be reached")
			return nil
		},
		replaceRolePolicyFunc: func(ReplaceTenantRolePolicyParams) (TenantRole, error) {
			t.Fatal("system role policy mutation must not be reached")
			return TenantRole{}, nil
		},
	}
	service := newTestService(t, repository)
	name := "Cannot change"

	_, err := service.UpdateTenantRole(context.Background(), serviceTestActor(), testTenantID, roleID, UpdateTenantRoleInput{
		Name: &name, ExpectedVersion: &version, Audit: serviceTestAudit(),
	})
	assertServiceError(t, err, ErrConflict)
	err = service.ArchiveTenantRole(context.Background(), serviceTestActor(), testTenantID, roleID, ArchiveTenantRoleInput{
		ExpectedVersion: &version, Audit: serviceTestAudit(),
	})
	assertServiceError(t, err, ErrConflict)
	_, err = service.ReplaceTenantRolePolicy(context.Background(), serviceTestActor(), testTenantID, roleID, ReplaceTenantRolePolicyInput{
		Policy:          TenantRolePolicy{Permissions: []ScopedPermission{{Permission: TenantPermissionRoleRead, Scope: ScopeTenant}}},
		ExpectedVersion: &version,
		Audit:           serviceTestAudit(),
	})
	assertServiceError(t, err, ErrConflict)

	if repository.resolveAuthorityCalls != 3 || repository.getRoleCalls != 3 ||
		repository.updateRoleCalls != 0 || repository.archiveRoleCalls != 0 ||
		repository.replaceRolePolicyCalls != 0 {
		t.Fatalf("unexpected repository calls: %#v", repository)
	}
}

func TestServiceRejectsArchivedRoleMutationsAsConflictsBeforeWrite(t *testing.T) {
	roleID := serviceTestID(82)
	version := int64(2)
	archivedAt := serviceTestNow.Add(-time.Minute)
	role := serviceTestRole(roleID, false, validRolePolicy())
	role.Version = version
	role.Archived = true
	role.ArchivedAt = &archivedAt
	repository := &serviceRepositoryStub{
		resolveAuthorityFunc: func(ResolveAuthorityParams) (TenantAuthority, error) {
			return serviceTestAuthority(TenantPermissionRoleManage), nil
		},
		getRoleFunc: func(GetTenantRoleParams) (TenantRole, error) {
			return role, nil
		},
		updateRoleFunc: func(UpdateTenantRoleParams) (TenantRole, error) {
			t.Fatal("archived role update mutation must not be reached")
			return TenantRole{}, nil
		},
		archiveRoleFunc: func(ArchiveTenantRoleParams) error {
			t.Fatal("archived role archive mutation must not be reached")
			return nil
		},
		replaceRolePolicyFunc: func(ReplaceTenantRolePolicyParams) (TenantRole, error) {
			t.Fatal("archived role policy mutation must not be reached")
			return TenantRole{}, nil
		},
	}
	service := newTestService(t, repository)
	name := "Cannot change"

	_, err := service.UpdateTenantRole(context.Background(), serviceTestActor(), testTenantID, roleID, UpdateTenantRoleInput{
		Name: &name, ExpectedVersion: &version, Audit: serviceTestAudit(),
	})
	assertServiceError(t, err, ErrConflict)
	err = service.ArchiveTenantRole(context.Background(), serviceTestActor(), testTenantID, roleID, ArchiveTenantRoleInput{
		ExpectedVersion: &version, Audit: serviceTestAudit(),
	})
	assertServiceError(t, err, ErrConflict)
	_, err = service.ReplaceTenantRolePolicy(context.Background(), serviceTestActor(), testTenantID, roleID, ReplaceTenantRolePolicyInput{
		Policy:          TenantRolePolicy{Permissions: []ScopedPermission{{Permission: TenantPermissionRoleRead, Scope: ScopeTenant}}},
		ExpectedVersion: &version,
		Audit:           serviceTestAudit(),
	})
	assertServiceError(t, err, ErrConflict)

	if repository.resolveAuthorityCalls != 3 || repository.getRoleCalls != 3 ||
		repository.updateRoleCalls != 0 || repository.archiveRoleCalls != 0 ||
		repository.replaceRolePolicyCalls != 0 {
		t.Fatalf("unexpected repository calls: %#v", repository)
	}
}

func TestServiceStaleRoleValidatorsTakePrecedenceOverImmutableStateConflicts(t *testing.T) {
	roleID := serviceTestID(83)
	staleVersion := int64(1)
	currentVersion := int64(2)
	name := "Cannot change"

	for _, test := range []struct {
		name     string
		system   bool
		archived bool
	}{
		{name: "system role", system: true},
		{name: "archived role", archived: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			role := serviceTestRole(roleID, test.system, validRolePolicy())
			role.Version = currentVersion
			if test.archived {
				archivedAt := serviceTestNow.Add(-time.Minute)
				role.Archived = true
				role.ArchivedAt = &archivedAt
			}
			repository := &serviceRepositoryStub{
				resolveAuthorityFunc: func(ResolveAuthorityParams) (TenantAuthority, error) {
					return serviceTestAuthority(TenantPermissionRoleManage), nil
				},
				getRoleFunc: func(GetTenantRoleParams) (TenantRole, error) {
					return role, nil
				},
				updateRoleFunc: func(UpdateTenantRoleParams) (TenantRole, error) {
					t.Fatal("stale update mutation must not be reached")
					return TenantRole{}, nil
				},
				archiveRoleFunc: func(ArchiveTenantRoleParams) error {
					t.Fatal("stale archive mutation must not be reached")
					return nil
				},
				replaceRolePolicyFunc: func(ReplaceTenantRolePolicyParams) (TenantRole, error) {
					t.Fatal("stale policy mutation must not be reached")
					return TenantRole{}, nil
				},
			}
			service := newTestService(t, repository)

			_, err := service.UpdateTenantRole(context.Background(), serviceTestActor(), testTenantID, roleID, UpdateTenantRoleInput{
				Name: &name, ExpectedVersion: &staleVersion, Audit: serviceTestAudit(),
			})
			assertServiceError(t, err, ErrPreconditionFailed)
			err = service.ArchiveTenantRole(context.Background(), serviceTestActor(), testTenantID, roleID, ArchiveTenantRoleInput{
				ExpectedVersion: &staleVersion, Audit: serviceTestAudit(),
			})
			assertServiceError(t, err, ErrPreconditionFailed)
			_, err = service.ReplaceTenantRolePolicy(context.Background(), serviceTestActor(), testTenantID, roleID, ReplaceTenantRolePolicyInput{
				Policy:          TenantRolePolicy{Permissions: []ScopedPermission{{Permission: TenantPermissionRoleRead, Scope: ScopeTenant}}},
				ExpectedVersion: &staleVersion,
				Audit:           serviceTestAudit(),
			})
			assertServiceError(t, err, ErrPreconditionFailed)

			if repository.resolveAuthorityCalls != 3 || repository.getRoleCalls != 3 ||
				repository.updateRoleCalls != 0 || repository.archiveRoleCalls != 0 ||
				repository.replaceRolePolicyCalls != 0 {
				t.Fatalf("unexpected repository calls: %#v", repository)
			}
		})
	}
}

func TestServiceCustomRoleMutationsForwardVersionAndAuditBoundary(t *testing.T) {
	roleID := serviceTestID(81)
	version := int64(3)
	role := serviceTestRole(roleID, false, validRolePolicy())
	role.Version = version
	permission := ScopedPermission{Permission: TenantPermissionRoleRead, Scope: ScopeTenant}
	authority := serviceTestAuthority(TenantPermissionRoleManage, TenantPermissionRoleRead)
	authority.DelegationCeiling = []DelegationGrant{{ScopedPermission: permission}}
	var updateParams UpdateTenantRoleParams
	var archiveParams ArchiveTenantRoleParams
	var replaceParams ReplaceTenantRolePolicyParams
	repository := &serviceRepositoryStub{
		resolveAuthorityFunc: func(ResolveAuthorityParams) (TenantAuthority, error) {
			return authority, nil
		},
		getRoleFunc: func(GetTenantRoleParams) (TenantRole, error) {
			return role, nil
		},
		updateRoleFunc: func(params UpdateTenantRoleParams) (TenantRole, error) {
			updateParams = params
			updated := role
			updated.Name = *params.Name
			updated.Description = *params.Description
			updated.Version++
			return updated, nil
		},
		archiveRoleFunc: func(params ArchiveTenantRoleParams) error {
			archiveParams = params
			return nil
		},
		replaceRolePolicyFunc: func(params ReplaceTenantRolePolicyParams) (TenantRole, error) {
			replaceParams = params
			updated := role
			updated.Policy = params.Policy
			updated.Version++
			return updated, nil
		},
	}
	service := newTestService(t, repository)
	name := "  Updated custom role  "
	description := "  Updated description  "

	updated, err := service.UpdateTenantRole(context.Background(), serviceTestActor(), testTenantID, roleID, UpdateTenantRoleInput{
		Name: &name, Description: &description, ExpectedVersion: &version, Audit: serviceTestAudit(),
	})
	if err != nil || updated.Name != "Updated custom role" || updated.Description != "Updated description" {
		t.Fatalf("UpdateTenantRole() = %#v, %v", updated, err)
	}
	if updateParams.ExpectedVersion != version || updateParams.OccurredAt != serviceTestNow ||
		*updateParams.Name != "Updated custom role" || *updateParams.Description != "Updated description" {
		t.Fatalf("update params = %#v", updateParams)
	}

	if err := service.ArchiveTenantRole(context.Background(), serviceTestActor(), testTenantID, roleID, ArchiveTenantRoleInput{
		ExpectedVersion: &version, Audit: serviceTestAudit(),
	}); err != nil {
		t.Fatalf("ArchiveTenantRole() error = %v", err)
	}
	if archiveParams.ExpectedVersion != version || archiveParams.OccurredAt != serviceTestNow {
		t.Fatalf("archive params = %#v", archiveParams)
	}

	replaced, err := service.ReplaceTenantRolePolicy(context.Background(), serviceTestActor(), testTenantID, roleID, ReplaceTenantRolePolicyInput{
		Policy: validRolePolicy(), ExpectedVersion: &version, Audit: serviceTestAudit(),
	})
	if err != nil || replaced.ID != roleID {
		t.Fatalf("ReplaceTenantRolePolicy() = %#v, %v", replaced, err)
	}
	if replaceParams.ExpectedVersion != version || replaceParams.OccurredAt != serviceTestNow ||
		len(replaceParams.Policy.Permissions) != 1 {
		t.Fatalf("replace params = %#v", replaceParams)
	}
}

func TestServiceSystemRoleGrantRequiresExactLifetimeBoundedCeiling(t *testing.T) {
	roleID := serviceTestID(90)
	userID := serviceTestID(91)
	grantID := serviceTestID(92)
	permission := ScopedPermission{Permission: TenantPermissionRoleRead, Scope: ScopeTenant}
	horizon := serviceTestNow.Add(time.Hour)
	systemRole := serviceTestRole(roleID, true, TenantRolePolicy{
		Permissions:       []ScopedPermission{permission},
		DelegationCeiling: []ScopedPermission{permission},
	})

	tests := []struct {
		name          string
		ceilingExpiry *time.Time
		grantExpiry   *time.Time
		wantAllowed   bool
	}{
		{
			name:          "finite system grant at horizon",
			ceilingExpiry: timePointer(horizon),
			grantExpiry:   timePointer(horizon),
			wantAllowed:   true,
		},
		{
			name:          "finite system grant after horizon",
			ceilingExpiry: timePointer(horizon),
			grantExpiry:   timePointer(horizon.Add(time.Microsecond)),
		},
		{
			name:          "non-expiring system grant under finite ceiling",
			ceilingExpiry: timePointer(horizon),
		},
		{
			name:        "non-expiring system grant under permanent ceiling",
			wantAllowed: true,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			authority := serviceTestAuthority(TenantPermissionRoleGrant, TenantPermissionRoleRead)
			authority.DelegationCeiling = []DelegationGrant{{
				ScopedPermission: permission,
				ExpiresAt:        test.ceilingExpiry,
			}}
			var received GrantUserRoleParams
			repository := &serviceRepositoryStub{
				resolveAuthorityFunc: func(ResolveAuthorityParams) (TenantAuthority, error) {
					return authority, nil
				},
				getRoleFunc: func(GetTenantRoleParams) (TenantRole, error) {
					return systemRole, nil
				},
				grantRoleFunc: func(params GrantUserRoleParams) (DirectUserRoleGrant, error) {
					if !test.wantAllowed {
						return DirectUserRoleGrant{}, ErrForbidden
					}
					received = params
					return serviceTestDirectGrant(params.GrantID, params.UserID, systemRole, params.Reason, params.ExpiresAt), nil
				},
			}
			service := newTestService(t, repository)
			service.newID = func() (uuid.UUID, error) { return grantID, nil }
			input := validGrantRoleInput(roleID)
			input.ExpiresAt = test.grantExpiry

			grant, err := service.GrantUserRole(context.Background(), serviceTestActor(), testTenantID, userID, input)
			if test.wantAllowed {
				if err != nil {
					t.Fatalf("GrantUserRole() error = %v", err)
				}
				if grant.ID != grantID || received.Reason != input.Reason ||
					received.IdempotencyKey != input.IdempotencyKey || received.OccurredAt != serviceTestNow {
					t.Fatalf("grant = %#v, mutation params = %#v", grant, received)
				}
				return
			}
			assertServiceError(t, err, ErrForbidden)
			if repository.grantRoleCalls != 1 {
				t.Fatalf("grant mutation calls = %d, want 1 atomic replay/new-command decision", repository.grantRoleCalls)
			}
		})
	}
}

func TestServiceGrantUserRoleAcceptsRepositorySuccessAfterConcurrentRoleReduction(t *testing.T) {
	roleID := serviceTestID(151)
	userID := serviceTestID(152)
	grantID := serviceTestID(153)
	permission := ScopedPermission{Permission: TenantPermissionUserRead, Scope: ScopeTenant}
	staleRole := serviceTestRole(roleID, false, TenantRolePolicy{
		Permissions: []ScopedPermission{permission},
	})
	currentRole := staleRole
	currentRole.Policy = TenantRolePolicy{}
	currentRole.Version = 2
	currentRole.UpdatedAt = serviceTestNow.Add(time.Minute)
	input := validGrantRoleInput(roleID)
	repository := &serviceRepositoryStub{
		resolveAuthorityFunc: func(ResolveAuthorityParams) (TenantAuthority, error) {
			return serviceTestAuthority(TenantPermissionRoleGrant), nil
		},
		getRoleFunc: func(GetTenantRoleParams) (TenantRole, error) {
			// The former service precheck saw this stronger role and denied delegation.
			return staleRole, nil
		},
		grantRoleFunc: func(params GrantUserRoleParams) (DirectUserRoleGrant, error) {
			// The repository atomically observes the concurrently reduced role and commits.
			return serviceTestDirectGrant(
				params.GrantID, params.UserID, currentRole, params.Reason, params.ExpiresAt,
			), nil
		},
	}
	service := newTestService(t, repository)
	service.newID = func() (uuid.UUID, error) { return grantID, nil }

	grant, err := service.GrantUserRole(
		context.Background(), serviceTestActor(), testTenantID, userID, input,
	)
	if err != nil || grant.ID != grantID || grant.Role.Version != currentRole.Version {
		t.Fatalf("GrantUserRole() = %#v, %v", grant, err)
	}
	if repository.getRoleCalls != 0 || repository.grantRoleCalls != 1 {
		t.Fatalf(
			"role reads = %d, grant calls = %d, want 0 and 1",
			repository.getRoleCalls, repository.grantRoleCalls,
		)
	}
}

func TestServiceArchivedRoleCannotBeGranted(t *testing.T) {
	roleID := serviceTestID(93)
	userID := serviceTestID(94)
	permission := ScopedPermission{Permission: TenantPermissionRoleRead, Scope: ScopeTenant}
	authority := serviceTestAuthority(TenantPermissionRoleGrant, TenantPermissionRoleRead)
	authority.DelegationCeiling = []DelegationGrant{{ScopedPermission: permission}}
	role := serviceTestRole(roleID, true, TenantRolePolicy{Permissions: []ScopedPermission{permission}})
	role.Archived = true
	role.ArchivedAt = timePointer(serviceTestNow)
	repository := &serviceRepositoryStub{
		resolveAuthorityFunc: func(ResolveAuthorityParams) (TenantAuthority, error) {
			return authority, nil
		},
		getRoleFunc: func(GetTenantRoleParams) (TenantRole, error) {
			return role, nil
		},
		grantRoleFunc: func(GrantUserRoleParams) (DirectUserRoleGrant, error) {
			return DirectUserRoleGrant{}, ErrConflict
		},
	}
	service := newTestService(t, repository)

	_, err := service.GrantUserRole(
		context.Background(), serviceTestActor(), testTenantID, userID, validGrantRoleInput(roleID),
	)
	assertServiceError(t, err, ErrConflict)
	if repository.grantRoleCalls != 1 {
		t.Fatalf("grant calls = %d, want 1 atomic replay/new-command decision", repository.grantRoleCalls)
	}
}

func TestServiceGrantUserRoleLetsRepositoryDistinguishExpiredReplayFromNewCommand(t *testing.T) {
	roleID := serviceTestID(141)
	userID := serviceTestID(142)
	grantID := serviceTestID(143)
	expiresAt := serviceTestNow.Add(-time.Minute)
	permission := ScopedPermission{Permission: TenantPermissionRoleRead, Scope: ScopeTenant}
	role := serviceTestRole(roleID, false, TenantRolePolicy{Permissions: []ScopedPermission{permission}})
	delegatingAuthority := serviceTestAuthority(TenantPermissionRoleGrant, TenantPermissionRoleRead)
	delegatingAuthority.DelegationCeiling = []DelegationGrant{{ScopedPermission: permission}}
	input := validGrantRoleInput(roleID)
	input.ExpiresAt = &expiresAt

	t.Run("exact replay returns current expired representation despite archived role", func(t *testing.T) {
		archivedRole := role
		archivedRole.Archived = true
		archivedRole.ArchivedAt = timePointer(serviceTestNow)
		grant := serviceTestDirectGrant(grantID, userID, archivedRole, input.Reason, &expiresAt)
		grant.Provenance.GrantedAt = serviceTestNow.Add(-time.Hour)
		grant.State = DirectRoleGrantStateExpired
		repository := &serviceRepositoryStub{
			grantRoleReplayed: true,
			resolveAuthorityFunc: func(ResolveAuthorityParams) (TenantAuthority, error) {
				return serviceTestAuthority(TenantPermissionRoleGrant), nil
			},
			getRoleFunc:   func(GetTenantRoleParams) (TenantRole, error) { return archivedRole, nil },
			grantRoleFunc: func(GrantUserRoleParams) (DirectUserRoleGrant, error) { return grant, nil },
		}
		service := newTestService(t, repository)

		got, err := service.GrantUserRole(
			context.Background(), serviceTestActor(), testTenantID, userID, input,
		)
		if err != nil || got.ID != grantID || got.State != DirectRoleGrantStateExpired || !got.Role.Archived {
			t.Fatalf("GrantUserRole() replay = %#v, %v", got, err)
		}
	})

	for _, test := range []struct {
		name          string
		repositoryErr error
		want          error
	}{
		{name: "fresh past expiry remains invalid", repositoryErr: ErrInvalidInput, want: ErrInvalidInput},
		{name: "payload drift remains conflict", repositoryErr: ErrConflict, want: ErrConflict},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			repository := &serviceRepositoryStub{
				resolveAuthorityFunc: func(ResolveAuthorityParams) (TenantAuthority, error) {
					return delegatingAuthority, nil
				},
				getRoleFunc: func(GetTenantRoleParams) (TenantRole, error) { return role, nil },
				grantRoleFunc: func(GrantUserRoleParams) (DirectUserRoleGrant, error) {
					return DirectUserRoleGrant{}, test.repositoryErr
				},
			}
			service := newTestService(t, repository)

			_, err := service.GrantUserRole(
				context.Background(), serviceTestActor(), testTenantID, userID, input,
			)
			assertServiceError(t, err, test.want)
			if repository.grantRoleCalls != 1 {
				t.Fatalf("grant repository calls = %d, want 1", repository.grantRoleCalls)
			}
		})
	}

	t.Run("successful new expired result fails closed", func(t *testing.T) {
		grant := serviceTestDirectGrant(grantID, userID, role, input.Reason, &expiresAt)
		grant.Provenance.GrantedAt = serviceTestNow.Add(-time.Hour)
		grant.State = DirectRoleGrantStateExpired
		repository := &serviceRepositoryStub{
			resolveAuthorityFunc: func(ResolveAuthorityParams) (TenantAuthority, error) {
				return delegatingAuthority, nil
			},
			getRoleFunc:   func(GetTenantRoleParams) (TenantRole, error) { return role, nil },
			grantRoleFunc: func(GrantUserRoleParams) (DirectUserRoleGrant, error) { return grant, nil },
		}
		service := newTestService(t, repository)

		_, err := service.GrantUserRole(
			context.Background(), serviceTestActor(), testTenantID, userID, input,
		)
		assertServiceError(t, err, ErrUnavailable)
	})
}

func TestServiceGrantUserRoleRequiresDirectGrantAPIOwnershipForNewAndReplayedResults(t *testing.T) {
	roleID := serviceTestID(205)
	userID := serviceTestID(206)
	grantID := serviceTestID(207)
	role := serviceTestRole(roleID, false, TenantRolePolicy{})
	input := validGrantRoleInput(roleID)
	grant := serviceTestDirectGrant(grantID, userID, role, input.Reason, nil)
	grant.ManagedByAuthorizationAPI = false

	for _, replayed := range []bool{false, true} {
		replayed := replayed
		name := "new result"
		if replayed {
			name = "replayed result"
		}
		t.Run(name, func(t *testing.T) {
			repository := &serviceRepositoryStub{
				grantRoleReplayed: replayed,
				resolveAuthorityFunc: func(ResolveAuthorityParams) (TenantAuthority, error) {
					return serviceTestAuthority(TenantPermissionRoleGrant), nil
				},
				grantRoleFunc: func(GrantUserRoleParams) (DirectUserRoleGrant, error) {
					return grant, nil
				},
			}
			service := newTestService(t, repository)

			_, err := service.GrantUserRole(
				context.Background(), serviceTestActor(), testTenantID, userID, input,
			)
			assertServiceError(t, err, ErrUnavailable)
			if repository.grantRoleCalls != 1 {
				t.Fatalf("grant repository calls = %d, want 1", repository.grantRoleCalls)
			}
		})
	}
}

func TestServicePreconditionsAndRepositoryErrorsRemainDistinct(t *testing.T) {
	roleID := serviceTestID(100)
	name := "Updated"
	repository := &serviceRepositoryStub{}
	service := newTestService(t, repository)

	_, err := service.UpdateTenantRole(context.Background(), serviceTestActor(), testTenantID, roleID, UpdateTenantRoleInput{
		Name: &name, Audit: serviceTestAudit(),
	})
	assertServiceError(t, err, ErrPreconditionRequired)
	if repository.calls != 0 {
		t.Fatalf("repository calls = %d, want 0", repository.calls)
	}

	for _, expected := range []error{
		ErrInvalidInput,
		ErrForbidden,
		ErrNotFound,
		ErrConflict,
		ErrPreconditionRequired,
		ErrPreconditionFailed,
		ErrUnavailable,
	} {
		if actual := mapRepositoryError(expected); !errors.Is(actual, expected) {
			t.Fatalf("mapRepositoryError(%v) = %v", expected, actual)
		}
	}
	if actual := mapRepositoryError(errors.New("database failed")); !errors.Is(actual, ErrUnavailable) {
		t.Fatalf("unknown repository error = %v", actual)
	}
}

func TestServiceRejectsVersionsOutsideDatabaseIntegerRangeBeforeRepositoryAccess(t *testing.T) {
	roleID := serviceTestID(121)
	name := "Updated"
	version := maximumResourceVersion + 1
	repository := &serviceRepositoryStub{}
	service := newTestService(t, repository)

	_, err := service.UpdateTenantRole(
		context.Background(), serviceTestActor(), testTenantID, roleID,
		UpdateTenantRoleInput{
			Name: &name, ExpectedVersion: &version, Audit: serviceTestAudit(),
		},
	)

	assertServiceError(t, err, ErrInvalidInput)
	if repository.calls != 0 {
		t.Fatalf("repository calls = %d, want 0", repository.calls)
	}
}

func TestServiceRevokeRoleGrantForwardsReasonVersionAndAudit(t *testing.T) {
	grantID := serviceTestID(101)
	version := int64(4)
	userID := serviceTestID(102)
	role := serviceTestRole(serviceTestID(103), false, validRolePolicy())
	grant := serviceTestDirectGrant(grantID, userID, role, "Administrative grant", nil)
	grant.Version = version
	entityTag := mustDirectGrantEntityTag(t, grant)
	var received RevokeRoleGrantParams
	repository := &serviceRepositoryStub{
		resolveAuthorityFunc: func(ResolveAuthorityParams) (TenantAuthority, error) {
			return serviceTestAuthority(TenantPermissionRoleGrant), nil
		},
		getGrantFunc: func(GetUserRoleGrantParams) (DirectUserRoleGrant, error) {
			return grant, nil
		},
		revokeGrantFunc: func(params RevokeRoleGrantParams) error {
			received = params
			return nil
		},
	}
	service := newTestService(t, repository)

	err := service.RevokeRoleGrant(context.Background(), serviceTestActor(), testTenantID, grantID, RevokeRoleGrantInput{
		Reason: "  Access no longer required  ", ExpectedEntityTag: &entityTag, Audit: serviceTestAudit(),
	})
	if err != nil {
		t.Fatalf("RevokeRoleGrant() error = %v", err)
	}
	if received.GrantID != grantID || received.ExpectedEntityTag != entityTag ||
		received.Reason != "Access no longer required" || received.OccurredAt != serviceTestNow ||
		received.Actor != serviceTestActor() || received.Audit != serviceTestAudit() {
		t.Fatalf("revoke params = %#v", received)
	}
}

func TestServiceRevokeRoleGrantRejectsManualKindWithoutCanonicalOwnership(t *testing.T) {
	grantID := serviceTestID(208)
	userID := serviceTestID(209)
	role := serviceTestRole(serviceTestID(210), false, validRolePolicy())
	grant := serviceTestDirectGrant(grantID, userID, role, "Imported manual grant", nil)
	grant.ManagedByAuthorizationAPI = false
	entityTag := mustDirectGrantEntityTag(t, grant)
	repository := &serviceRepositoryStub{
		resolveAuthorityFunc: func(ResolveAuthorityParams) (TenantAuthority, error) {
			return serviceTestAuthority(TenantPermissionRoleGrant), nil
		},
		getGrantFunc: func(GetUserRoleGrantParams) (DirectUserRoleGrant, error) {
			return grant, nil
		},
		revokeGrantFunc: func(RevokeRoleGrantParams) error {
			t.Fatal("noncanonical manual grant reached the revoke repository")
			return nil
		},
	}
	service := newTestService(t, repository)

	err := service.RevokeRoleGrant(
		context.Background(), serviceTestActor(), testTenantID, grantID,
		RevokeRoleGrantInput{
			Reason: "Remove imported grant", ExpectedEntityTag: &entityTag, Audit: serviceTestAudit(),
		},
	)
	assertServiceError(t, err, ErrConflict)
	if repository.getGrantCalls != 1 || repository.revokeGrantCalls != 0 {
		t.Fatalf(
			"grant read/revoke calls = %d/%d, want 1/0",
			repository.getGrantCalls, repository.revokeGrantCalls,
		)
	}
}

func TestServiceDirectGrantRejectsStaleRepresentationEntityTag(t *testing.T) {
	t.Parallel()

	grantID := serviceTestID(104)
	userID := serviceTestID(105)
	role := serviceTestRole(serviceTestID(106), false, validRolePolicy())
	issued := serviceTestDirectGrant(grantID, userID, role, "Administrative grant", nil)
	entityTag := mustDirectGrantEntityTag(t, issued)
	current := issued
	current.Role.Name = "Renamed after the validator was issued"
	repository := &serviceRepositoryStub{
		resolveAuthorityFunc: func(ResolveAuthorityParams) (TenantAuthority, error) {
			return serviceTestAuthority(TenantPermissionRoleGrant), nil
		},
		getGrantFunc: func(GetUserRoleGrantParams) (DirectUserRoleGrant, error) {
			return current, nil
		},
		revokeGrantFunc: func(RevokeRoleGrantParams) error {
			t.Fatal("stale representation validator reached the revoke repository")
			return nil
		},
	}
	service := newTestService(t, repository)

	err := service.RevokeRoleGrant(
		context.Background(), serviceTestActor(), testTenantID, grantID,
		RevokeRoleGrantInput{
			Reason: "Remove stale grant", ExpectedEntityTag: &entityTag, Audit: serviceTestAudit(),
		},
	)
	assertServiceError(t, err, ErrPreconditionFailed)
	if repository.revokeGrantCalls != 0 {
		t.Fatalf("revoke repository calls = %d, want 0", repository.revokeGrantCalls)
	}
}

func serviceTestEdgeEntityTag(version int64) string {
	return fmt.Sprintf("\"v%d-%s\"", version, strings.Repeat("A", 43))
}

func mustDirectGrantEntityTag(t testing.TB, grant DirectUserRoleGrant) string {
	t.Helper()
	value, err := DirectUserRoleGrantEntityTag(grant)
	if err != nil {
		t.Fatalf("DirectUserRoleGrantEntityTag(): %v", err)
	}
	return value
}

func mustGroupMembershipEntityTag(t testing.TB, edge TenantSecurityGroupMembership) string {
	t.Helper()
	value, err := TenantSecurityGroupMembershipEntityTag(edge)
	if err != nil {
		t.Fatalf("TenantSecurityGroupMembershipEntityTag(): %v", err)
	}
	return value
}

func mustGroupRoleGrantEntityTag(t testing.TB, edge TenantSecurityGroupRoleGrant) string {
	t.Helper()
	value, err := TenantSecurityGroupRoleGrantEntityTag(edge)
	if err != nil {
		t.Fatalf("TenantSecurityGroupRoleGrantEntityTag(): %v", err)
	}
	return value
}

func newTestService(t *testing.T, repository Repository) *Service {
	t.Helper()
	service, err := NewService(repository)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	service.now = func() time.Time { return serviceTestNow }
	service.newID = func() (uuid.UUID, error) { return serviceTestID(120), nil }
	return service
}

func serviceTestActor() Actor {
	return Actor{
		UserID:               testPrincipalID,
		SessionID:            serviceTestID(20),
		ActiveTenantID:       testTenantID,
		AuthenticationMethod: "local",
	}
}

func serviceTestAudit() AuditContext {
	return AuditContext{
		RequestID:     serviceTestID(21),
		CorrelationID: serviceTestID(22),
		RemoteAddress: netip.MustParseAddr("192.0.2.10"),
		UserAgent:     "authorization-service-test",
	}
}

func serviceTestAuthority(permissions ...TenantPermission) TenantAuthority {
	authority := TenantAuthority{
		TenantID:         testTenantID,
		Principal:        TenantPrincipal{ID: testPrincipalID, Kind: PrincipalKindHuman},
		MembershipID:     serviceTestID(23),
		MembershipStatus: MembershipStatusActive,
		LegacyRole:       LegacyMembershipRoleTenantAdmin,
		EvaluatedAt:      serviceTestNow,
	}
	for _, permission := range permissions {
		authority.Permissions = append(authority.Permissions, ScopedPermission{
			Permission: permission,
			Scope:      ScopeTenant,
		})
	}
	return authority
}

func validCreateRoleInput() CreateTenantRoleInput {
	return CreateTenantRoleInput{
		Key:            "custom_role",
		Name:           "Custom role",
		Description:    "Custom role description",
		Policy:         validRolePolicy(),
		IdempotencyKey: "create-role-key-0001",
		Audit:          serviceTestAudit(),
	}
}

func validRolePolicy() TenantRolePolicy {
	permission := ScopedPermission{Permission: TenantPermissionRoleRead, Scope: ScopeTenant}
	return TenantRolePolicy{
		Permissions:       []ScopedPermission{permission},
		DelegationCeiling: []ScopedPermission{permission},
	}
}

func validGrantRoleInput(roleID uuid.UUID) GrantUserRoleInput {
	return GrantUserRoleInput{
		RoleID:         roleID,
		Reason:         "Administrative role grant",
		IdempotencyKey: "grant-role-key-0001",
		Audit:          serviceTestAudit(),
	}
}

func serviceTestRole(id uuid.UUID, system bool, policy TenantRolePolicy) TenantRole {
	key := "custom_role"
	name := "Custom role"
	if system {
		key = "tenant_admin"
		name = "Tenant administrator"
	}
	return TenantRole{
		TenantRoleSummary: TenantRoleSummary{
			ID: id, TenantID: testTenantID, Key: key, Name: name,
			Description: "Role description", PrincipalKind: PrincipalKindHuman, System: system, Version: 1,
			CreatedAt: serviceTestNow.Add(-time.Hour), UpdatedAt: serviceTestNow,
		},
		Policy: policy,
	}
}

func serviceTestUser(membershipID, userID uuid.UUID) TenantUserSummary {
	return TenantUserSummary{
		TenantID: testTenantID, MembershipID: membershipID,
		User: TenantUserProfile{
			ID: userID, Email: "user@example.test", DisplayName: "Test User", Active: true,
		},
		MembershipStatus: MembershipStatusActive, LegacyMembershipRole: LegacyMembershipRoleAnalyst,
		LifecycleRevision: 1, EntityTag: `"v1"`,
		CreatedAt: serviceTestNow.Add(-time.Hour), UpdatedAt: serviceTestNow,
	}
}

func serviceTestDirectGrant(
	id uuid.UUID,
	userID uuid.UUID,
	role TenantRole,
	reason string,
	expiresAt *time.Time,
) DirectUserRoleGrant {
	provenance := RoleGrantProvenance{
		SourceType: RoleGrantSourceDirect, SourceKind: AuthorizationSourceManual,
		SourceID: uuidPointer(serviceTestID(91)), GrantedByUserID: uuidPointer(testPrincipalID),
		GrantedAt: serviceTestNow, Reason: reason, ExpiresAt: expiresAt,
	}
	return DirectUserRoleGrant{
		ID: id, TenantID: testTenantID, UserID: userID, Role: role.TenantRoleSummary,
		Provenance: provenance, PathType: RoleGrantPathDirect,
		State: DirectRoleGrantStateActive, Version: 1, UpdatedAt: serviceTestNow,
		ManagedByAuthorizationAPI: true,
	}
}

func serviceTestID(value byte) uuid.UUID {
	id := uuid.MustParse("00000000-0000-7000-8000-000000000000")
	id[15] = value
	return id
}

func assertServiceError(t *testing.T, actual, expected error) {
	t.Helper()
	if !errors.Is(actual, expected) {
		t.Fatalf("error = %v, want %v", actual, expected)
	}
}
