package authorization

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSecurityGroupCreateAcceptsArchivedCurrentReplayAndForwardsPayloadBoundCommand(t *testing.T) {
	t.Parallel()

	replayedID := serviceTestID(80)
	archivedAt := serviceTestNow
	var captured CreateTenantSecurityGroupParams
	repository := &serviceRepositoryStub{
		createGroupReplayed: true,
		resolveAuthorityFunc: func(ResolveAuthorityParams) (TenantAuthority, error) {
			return serviceTestAuthority(TenantPermissionGroupManage), nil
		},
		createGroupFunc: func(params CreateTenantSecurityGroupParams) (TenantSecurityGroup, error) {
			captured = params
			group := serviceTestGroup(replayedID, "triage_group")
			group.Archived = true
			group.ArchivedAt = &archivedAt
			group.Version = 2
			return group, nil
		},
	}
	service := newTestService(t, repository)

	group, err := service.CreateTenantSecurityGroup(
		context.Background(), serviceTestActor(), testTenantID,
		CreateTenantSecurityGroupInput{
			Key: "triage_group", Name: "  Triage Group  ", Description: "  Analysts  ",
			IdempotencyKey: "create-group-key-0001", Audit: serviceTestAudit(),
		},
	)
	if err != nil {
		t.Fatalf("CreateTenantSecurityGroup() error = %v", err)
	}
	if group.ID != replayedID || !group.Archived || group.Version != 2 ||
		captured.GroupID != serviceTestID(120) ||
		captured.Name != "Triage Group" || captured.Description != "Analysts" ||
		captured.IdempotencyKey != "create-group-key-0001" ||
		captured.OccurredAt != serviceTestNow || captured.Audit != serviceTestAudit() {
		t.Fatalf("group/captured = %#v / %#v", group, captured)
	}
}

func TestSecurityGroupCreateRejectsArchivedNewResult(t *testing.T) {
	t.Parallel()

	archivedAt := serviceTestNow
	repository := &serviceRepositoryStub{
		resolveAuthorityFunc: func(ResolveAuthorityParams) (TenantAuthority, error) {
			return serviceTestAuthority(TenantPermissionGroupManage), nil
		},
		createGroupFunc: func(params CreateTenantSecurityGroupParams) (TenantSecurityGroup, error) {
			group := serviceTestGroup(params.GroupID, params.Key)
			group.Archived = true
			group.ArchivedAt = &archivedAt
			return group, nil
		},
	}
	service := newTestService(t, repository)

	_, err := service.CreateTenantSecurityGroup(
		context.Background(), serviceTestActor(), testTenantID,
		CreateTenantSecurityGroupInput{
			Key: "triage_group", Name: "Triage Group", IdempotencyKey: "create-group-key-0001",
			Audit: serviceTestAudit(),
		},
	)
	assertServiceError(t, err, ErrUnavailable)
}

func TestSecurityGroupMembershipReadRequiresGroupAndUserRead(t *testing.T) {
	t.Parallel()

	groupID := serviceTestID(81)
	repository := &serviceRepositoryStub{
		resolveAuthorityFunc: func(ResolveAuthorityParams) (TenantAuthority, error) {
			return serviceTestAuthority(TenantPermissionGroupRead), nil
		},
		listGroupMembershipsFunc: func(ListTenantSecurityGroupMembershipsParams) ([]TenantSecurityGroupMembership, error) {
			t.Fatal("repository list must not run without user.read")
			return nil, nil
		},
	}
	service := newTestService(t, repository)

	_, err := service.ListTenantSecurityGroupMemberships(
		context.Background(), serviceTestActor(), testTenantID, groupID,
		ListTenantSecurityGroupEdgesInput{},
	)
	assertServiceError(t, err, ErrForbidden)
	if repository.resolveAuthorityCalls != 1 || repository.listGroupMembershipsCalls != 0 {
		t.Fatalf("repository calls = resolve %d, list %d", repository.resolveAuthorityCalls, repository.listGroupMembershipsCalls)
	}
}

func TestSecurityGroupMembershipListUsesUUIDCursorAndValidatesRows(t *testing.T) {
	t.Parallel()

	groupID := serviceTestID(82)
	first := serviceTestGroupMembership(serviceTestID(83), serviceTestID(84), serviceTestGroup(groupID, "triage_group"))
	second := serviceTestGroupMembership(serviceTestID(85), serviceTestID(86), serviceTestGroup(groupID, "triage_group"))
	var captured ListTenantSecurityGroupMembershipsParams
	repository := &serviceRepositoryStub{
		resolveAuthorityFunc: func(ResolveAuthorityParams) (TenantAuthority, error) {
			return serviceTestAuthority(TenantPermissionGroupRead, TenantPermissionUserRead), nil
		},
		listGroupMembershipsFunc: func(params ListTenantSecurityGroupMembershipsParams) ([]TenantSecurityGroupMembership, error) {
			captured = params
			return []TenantSecurityGroupMembership{first, second}, nil
		},
	}
	service := newTestService(t, repository)

	page, err := service.ListTenantSecurityGroupMemberships(
		context.Background(), serviceTestActor(), testTenantID, groupID,
		ListTenantSecurityGroupEdgesInput{PageInput: PageInput{Limit: 1}, IncludeRevoked: true},
	)
	if err != nil {
		t.Fatalf("ListTenantSecurityGroupMemberships() error = %v", err)
	}
	if len(page.Items) != 1 || page.Items[0].ID != first.ID || page.NextCursor == nil ||
		*page.NextCursor != first.ID || captured.Limit != 2 || !captured.IncludeRevoked {
		t.Fatalf("page/captured = %#v / %#v", page, captured)
	}
}

func TestSecurityGroupMembershipMutationsRequireRoleGrantAndManualOwnership(t *testing.T) {
	t.Parallel()

	groupID := serviceTestID(87)
	edgeID := serviceTestID(88)
	userID := serviceTestID(89)
	repository := &serviceRepositoryStub{
		resolveAuthorityFunc: func(ResolveAuthorityParams) (TenantAuthority, error) {
			return serviceTestAuthority(TenantPermissionGroupMembershipManage), nil
		},
	}
	service := newTestService(t, repository)

	_, err := service.AddTenantSecurityGroupMembership(
		context.Background(), serviceTestActor(), testTenantID, groupID,
		AddTenantSecurityGroupMembershipInput{
			UserID: userID, Reason: "Add analyst", IdempotencyKey: "group-member-key-0001", Audit: serviceTestAudit(),
		},
	)
	assertServiceError(t, err, ErrForbidden)

	repository.resolveAuthorityFunc = func(ResolveAuthorityParams) (TenantAuthority, error) {
		return serviceTestAuthority(TenantPermissionGroupMembershipManage, TenantPermissionRoleGrant), nil
	}
	foreign := serviceTestGroupMembership(edgeID, userID, serviceTestGroup(groupID, "triage_group"))
	foreign.ManagedByAuthorizationAPI = false
	entityTag := mustGroupMembershipEntityTag(t, foreign)
	repository.getGroupMembershipFunc = func(GetTenantSecurityGroupMembershipParams) (TenantSecurityGroupMembership, error) {
		return foreign, nil
	}
	err = service.RevokeTenantSecurityGroupMembership(
		context.Background(), serviceTestActor(), testTenantID, groupID, edgeID,
		RevokeTenantSecurityGroupMembershipInput{
			Reason: "Removed from manual access", ExpectedEntityTag: &entityTag, Audit: serviceTestAudit(),
		},
	)
	assertServiceError(t, err, ErrConflict)
	if repository.revokeGroupMembershipCalls != 0 {
		t.Fatalf("unmanaged manual edge reached revoke repository")
	}
}

func TestSecurityGroupMutationResultsRequireCanonicalOwnership(t *testing.T) {
	groupID := serviceTestID(170)
	userID := serviceTestID(171)
	edgeID := serviceTestID(172)
	roleID := serviceTestID(173)
	sourceID := serviceTestID(174)
	group := serviceTestGroup(groupID, "triage_group")

	for _, replayed := range []bool{false, true} {
		replayed := replayed
		name := "new result"
		if replayed {
			name = "replayed result"
		}
		t.Run("membership "+name, func(t *testing.T) {
			edge := serviceTestGroupMembership(edgeID, userID, group)
			edge.ManagedByAuthorizationAPI = false
			repository := &serviceRepositoryStub{
				addGroupMembershipReplayed: replayed,
				resolveAuthorityFunc: func(ResolveAuthorityParams) (TenantAuthority, error) {
					return serviceTestAuthority(
						TenantPermissionGroupMembershipManage, TenantPermissionRoleGrant,
					), nil
				},
				addGroupMembershipFunc: func(AddTenantSecurityGroupMembershipParams) (TenantSecurityGroupMembership, error) {
					return edge, nil
				},
			}
			service := newTestService(t, repository)
			service.newID = func() (uuid.UUID, error) { return edgeID, nil }

			_, err := service.AddTenantSecurityGroupMembership(
				context.Background(), serviceTestActor(), testTenantID, groupID,
				AddTenantSecurityGroupMembershipInput{
					UserID: userID, Reason: edge.Provenance.Reason,
					IdempotencyKey: "unmanaged-group-membership", Audit: serviceTestAudit(),
				},
			)
			assertServiceError(t, err, ErrUnavailable)
		})

		t.Run("role grant "+name, func(t *testing.T) {
			edge := TenantSecurityGroupRoleGrant{
				ID: edgeID, TenantID: testTenantID, Group: group,
				Role: serviceTestRole(roleID, false, TenantRolePolicy{}).TenantRoleSummary,
				Provenance: AuthorizationEdgeProvenance{
					SourceKind: AuthorizationSourceManual, SourceID: &sourceID,
					GrantedByUserID: uuidPointer(testPrincipalID), GrantedAt: serviceTestNow,
					Reason: "Unmanaged group role",
				},
				State: AuthorizationEdgeStateActive, Version: 1, UpdatedAt: serviceTestNow,
			}
			repository := &serviceRepositoryStub{
				grantGroupRoleReplayed: replayed,
				resolveAuthorityFunc: func(ResolveAuthorityParams) (TenantAuthority, error) {
					return serviceTestAuthority(TenantPermissionGroupManage, TenantPermissionRoleGrant), nil
				},
				grantGroupRoleFunc: func(GrantTenantSecurityGroupRoleParams) (TenantSecurityGroupRoleGrant, error) {
					return edge, nil
				},
			}
			service := newTestService(t, repository)
			service.newID = func() (uuid.UUID, error) { return edgeID, nil }

			_, err := service.GrantTenantSecurityGroupRole(
				context.Background(), serviceTestActor(), testTenantID, groupID,
				GrantTenantSecurityGroupRoleInput{
					RoleID: roleID, Reason: edge.Provenance.Reason,
					IdempotencyKey: "unmanaged-group-role", Audit: serviceTestAudit(),
				},
			)
			assertServiceError(t, err, ErrUnavailable)
		})
	}
}

func TestSecurityGroupRoleRevokeRejectsManualKindWithoutCanonicalOwnership(t *testing.T) {
	groupID := serviceTestID(175)
	grantID := serviceTestID(176)
	roleID := serviceTestID(177)
	sourceID := serviceTestID(178)
	edge := TenantSecurityGroupRoleGrant{
		ID: grantID, TenantID: testTenantID,
		Group: serviceTestGroup(groupID, "triage_group"),
		Role:  serviceTestRole(roleID, false, TenantRolePolicy{}).TenantRoleSummary,
		Provenance: AuthorizationEdgeProvenance{
			SourceKind: AuthorizationSourceManual, SourceID: &sourceID,
			GrantedByUserID: uuidPointer(testPrincipalID), GrantedAt: serviceTestNow.Add(-time.Hour),
			Reason: "Imported manual group role",
		},
		State: AuthorizationEdgeStateActive, Version: 1, UpdatedAt: serviceTestNow,
	}
	entityTag := mustGroupRoleGrantEntityTag(t, edge)
	repository := &serviceRepositoryStub{
		resolveAuthorityFunc: func(ResolveAuthorityParams) (TenantAuthority, error) {
			return serviceTestAuthority(TenantPermissionGroupManage, TenantPermissionRoleGrant), nil
		},
		getGroupRoleGrantFunc: func(GetTenantSecurityGroupRoleGrantParams) (TenantSecurityGroupRoleGrant, error) {
			return edge, nil
		},
		revokeGroupRoleGrantFunc: func(RevokeTenantSecurityGroupRoleGrantParams) error {
			t.Fatal("unmanaged manual role grant reached revoke repository")
			return nil
		},
	}
	service := newTestService(t, repository)

	err := service.RevokeTenantSecurityGroupRoleGrant(
		context.Background(), serviceTestActor(), testTenantID, groupID, grantID,
		RevokeTenantSecurityGroupRoleGrantInput{
			Reason: "Remove imported role", ExpectedEntityTag: &entityTag, Audit: serviceTestAudit(),
		},
	)
	assertServiceError(t, err, ErrConflict)
}

func TestExpiredManualSecurityGroupMembershipRemainsRevocable(t *testing.T) {
	t.Parallel()

	groupID := serviceTestID(121)
	edgeID := serviceTestID(122)
	userID := serviceTestID(123)
	expiresAt := serviceTestNow.Add(-time.Minute)
	edge := serviceTestGroupMembership(edgeID, userID, serviceTestGroup(groupID, "triage_group"))
	edge.Provenance.ExpiresAt = &expiresAt
	edge.State = AuthorizationEdgeStateExpired
	entityTag := mustGroupMembershipEntityTag(t, edge)
	var captured RevokeTenantSecurityGroupMembershipParams
	repository := &serviceRepositoryStub{
		resolveAuthorityFunc: func(ResolveAuthorityParams) (TenantAuthority, error) {
			return serviceTestAuthority(TenantPermissionGroupMembershipManage, TenantPermissionRoleGrant), nil
		},
		getGroupMembershipFunc: func(GetTenantSecurityGroupMembershipParams) (TenantSecurityGroupMembership, error) {
			return edge, nil
		},
		revokeGroupMembershipFunc: func(params RevokeTenantSecurityGroupMembershipParams) error {
			captured = params
			return nil
		},
	}
	service := newTestService(t, repository)

	err := service.RevokeTenantSecurityGroupMembership(
		context.Background(), serviceTestActor(), testTenantID, groupID, edgeID,
		RevokeTenantSecurityGroupMembershipInput{
			Reason: "Close expired membership", ExpectedEntityTag: &entityTag, Audit: serviceTestAudit(),
		},
	)
	if err != nil {
		t.Fatalf("RevokeTenantSecurityGroupMembership() error = %v", err)
	}
	if repository.revokeGroupMembershipCalls != 1 || captured.MembershipID != edgeID ||
		captured.GroupID != groupID || captured.Reason != "Close expired membership" {
		t.Fatalf("revoke calls/input = %d/%#v", repository.revokeGroupMembershipCalls, captured)
	}
}

func TestExpiredManualSecurityGroupRoleGrantRemainsRevocable(t *testing.T) {
	t.Parallel()

	groupID := serviceTestID(124)
	grantID := serviceTestID(125)
	roleID := serviceTestID(126)
	sourceID := serviceTestID(127)
	version := int64(1)
	expiresAt := serviceTestNow.Add(-time.Minute)
	edge := TenantSecurityGroupRoleGrant{
		ID: grantID, TenantID: testTenantID, Group: serviceTestGroup(groupID, "triage_group"),
		Role: serviceTestRole(roleID, false, TenantRolePolicy{}).TenantRoleSummary,
		Provenance: AuthorizationEdgeProvenance{
			SourceKind: AuthorizationSourceManual, SourceID: &sourceID,
			GrantedByUserID: uuidPointer(testPrincipalID), GrantedAt: serviceTestNow.Add(-time.Hour),
			Reason: "Temporary group access", ExpiresAt: &expiresAt,
		},
		State: AuthorizationEdgeStateExpired, Version: version, UpdatedAt: serviceTestNow,
		ManagedByAuthorizationAPI: true,
	}
	entityTag := mustGroupRoleGrantEntityTag(t, edge)
	var captured RevokeTenantSecurityGroupRoleGrantParams
	repository := &serviceRepositoryStub{
		resolveAuthorityFunc: func(ResolveAuthorityParams) (TenantAuthority, error) {
			return serviceTestAuthority(TenantPermissionGroupManage, TenantPermissionRoleGrant), nil
		},
		getGroupRoleGrantFunc: func(GetTenantSecurityGroupRoleGrantParams) (TenantSecurityGroupRoleGrant, error) {
			return edge, nil
		},
		revokeGroupRoleGrantFunc: func(params RevokeTenantSecurityGroupRoleGrantParams) error {
			captured = params
			return nil
		},
	}
	service := newTestService(t, repository)

	err := service.RevokeTenantSecurityGroupRoleGrant(
		context.Background(), serviceTestActor(), testTenantID, groupID, grantID,
		RevokeTenantSecurityGroupRoleGrantInput{
			Reason: "Close expired role grant", ExpectedEntityTag: &entityTag, Audit: serviceTestAudit(),
		},
	)
	if err != nil {
		t.Fatalf("RevokeTenantSecurityGroupRoleGrant() error = %v", err)
	}
	if repository.revokeGroupRoleGrantCalls != 1 || captured.GrantID != grantID ||
		captured.GroupID != groupID || captured.Reason != "Close expired role grant" {
		t.Fatalf("revoke calls/input = %d/%#v", repository.revokeGroupRoleGrantCalls, captured)
	}
}

func TestServiceGroupEdgesRejectStaleRepresentationEntityTags(t *testing.T) {
	t.Parallel()

	groupID := serviceTestID(128)
	userID := serviceTestID(129)
	membershipID := serviceTestID(130)
	roleGrantID := serviceTestID(131)
	roleID := serviceTestID(132)
	sourceID := serviceTestID(133)
	group := serviceTestGroup(groupID, "triage_group")
	membership := serviceTestGroupMembership(membershipID, userID, group)
	membershipTag := mustGroupMembershipEntityTag(t, membership)
	currentMembership := membership
	currentMembership.Member.User.Active = false
	roleGrant := TenantSecurityGroupRoleGrant{
		ID: roleGrantID, TenantID: testTenantID, Group: group,
		Role: serviceTestRole(roleID, false, validRolePolicy()).TenantRoleSummary,
		Provenance: AuthorizationEdgeProvenance{
			SourceKind: AuthorizationSourceManual, SourceID: &sourceID,
			GrantedByUserID: uuidPointer(testPrincipalID), GrantedAt: serviceTestNow.Add(-time.Hour),
			Reason: "Group role grant",
		},
		State: AuthorizationEdgeStateActive, Version: 1, UpdatedAt: serviceTestNow,
		ManagedByAuthorizationAPI: true,
	}
	roleGrantTag := mustGroupRoleGrantEntityTag(t, roleGrant)
	currentRoleGrant := roleGrant
	currentRoleGrant.Role.Name = "Renamed after the validator was issued"

	t.Run("membership user changed", func(t *testing.T) {
		repository := &serviceRepositoryStub{
			resolveAuthorityFunc: func(ResolveAuthorityParams) (TenantAuthority, error) {
				return serviceTestAuthority(TenantPermissionGroupMembershipManage, TenantPermissionRoleGrant), nil
			},
			getGroupMembershipFunc: func(GetTenantSecurityGroupMembershipParams) (TenantSecurityGroupMembership, error) {
				return currentMembership, nil
			},
			revokeGroupMembershipFunc: func(RevokeTenantSecurityGroupMembershipParams) error {
				t.Fatal("stale membership validator reached the revoke repository")
				return nil
			},
		}
		service := newTestService(t, repository)
		err := service.RevokeTenantSecurityGroupMembership(
			context.Background(), serviceTestActor(), testTenantID, groupID, membershipID,
			RevokeTenantSecurityGroupMembershipInput{
				Reason: "Remove stale membership", ExpectedEntityTag: &membershipTag, Audit: serviceTestAudit(),
			},
		)
		assertServiceError(t, err, ErrPreconditionFailed)
	})

	t.Run("role summary changed", func(t *testing.T) {
		repository := &serviceRepositoryStub{
			resolveAuthorityFunc: func(ResolveAuthorityParams) (TenantAuthority, error) {
				return serviceTestAuthority(TenantPermissionGroupManage, TenantPermissionRoleGrant), nil
			},
			getGroupRoleGrantFunc: func(GetTenantSecurityGroupRoleGrantParams) (TenantSecurityGroupRoleGrant, error) {
				return currentRoleGrant, nil
			},
			revokeGroupRoleGrantFunc: func(RevokeTenantSecurityGroupRoleGrantParams) error {
				t.Fatal("stale group-role validator reached the revoke repository")
				return nil
			},
		}
		service := newTestService(t, repository)
		err := service.RevokeTenantSecurityGroupRoleGrant(
			context.Background(), serviceTestActor(), testTenantID, groupID, roleGrantID,
			RevokeTenantSecurityGroupRoleGrantInput{
				Reason: "Remove stale role grant", ExpectedEntityTag: &roleGrantTag, Audit: serviceTestAudit(),
			},
		)
		assertServiceError(t, err, ErrPreconditionFailed)
	})
}

func TestSecurityGroupRoleGrantChecksExactDelegationBeforeRepository(t *testing.T) {
	t.Parallel()

	groupID := serviceTestID(90)
	roleID := serviceTestID(91)
	permission := ScopedPermission{Permission: TenantPermissionGroupRead, Scope: ScopeTenant}
	role := serviceTestRole(roleID, false, TenantRolePolicy{Permissions: []ScopedPermission{permission}})
	authority := serviceTestAuthority(
		TenantPermissionGroupManage,
		TenantPermissionRoleGrant,
		TenantPermissionGroupRead,
	)
	authority.DelegationCeiling = []DelegationGrant{{ScopedPermission: permission}}
	repository := &serviceRepositoryStub{
		resolveAuthorityFunc: func(ResolveAuthorityParams) (TenantAuthority, error) { return authority, nil },
		getRoleFunc:          func(GetTenantRoleParams) (TenantRole, error) { return role, nil },
		grantGroupRoleFunc: func(GrantTenantSecurityGroupRoleParams) (TenantSecurityGroupRoleGrant, error) {
			return TenantSecurityGroupRoleGrant{}, ErrForbidden
		},
	}
	service := newTestService(t, repository)
	authority.DelegationCeiling = nil

	_, err := service.GrantTenantSecurityGroupRole(
		context.Background(), serviceTestActor(), testTenantID, groupID,
		GrantTenantSecurityGroupRoleInput{
			RoleID: roleID, Reason: "Grant triage visibility",
			IdempotencyKey: "group-role-key-0001", Audit: serviceTestAudit(),
		},
	)
	assertServiceError(t, err, ErrForbidden)
	if repository.grantGroupRoleCalls != 1 {
		t.Fatalf("grant repository calls = %d, want 1 atomic replay/new-command decision", repository.grantGroupRoleCalls)
	}
}

func TestSecurityGroupRoleGrantAcceptsRepositorySuccessAfterConcurrentRoleReduction(t *testing.T) {
	groupID := serviceTestID(154)
	roleID := serviceTestID(155)
	edgeID := serviceTestID(156)
	sourceID := serviceTestID(157)
	permission := ScopedPermission{Permission: TenantPermissionGroupRead, Scope: ScopeTenant}
	staleRole := serviceTestRole(roleID, false, TenantRolePolicy{
		Permissions: []ScopedPermission{permission},
	})
	currentRole := staleRole
	currentRole.Policy = TenantRolePolicy{}
	currentRole.Version = 2
	currentRole.UpdatedAt = serviceTestNow.Add(time.Minute)
	input := GrantTenantSecurityGroupRoleInput{
		RoleID: roleID, Reason: "Grant triage visibility",
		IdempotencyKey: "concurrent-group-role-key", Audit: serviceTestAudit(),
	}
	repository := &serviceRepositoryStub{
		resolveAuthorityFunc: func(ResolveAuthorityParams) (TenantAuthority, error) {
			return serviceTestAuthority(TenantPermissionGroupManage, TenantPermissionRoleGrant), nil
		},
		getRoleFunc: func(GetTenantRoleParams) (TenantRole, error) {
			// The former service precheck saw this stronger role and denied delegation.
			return staleRole, nil
		},
		grantGroupRoleFunc: func(params GrantTenantSecurityGroupRoleParams) (TenantSecurityGroupRoleGrant, error) {
			// The repository atomically observes the concurrently reduced role and commits.
			return TenantSecurityGroupRoleGrant{
				ID: params.GrantID, TenantID: testTenantID,
				Group: serviceTestGroup(groupID, "triage_group"), Role: currentRole.TenantRoleSummary,
				Provenance: AuthorizationEdgeProvenance{
					SourceKind: AuthorizationSourceManual, SourceID: &sourceID,
					GrantedByUserID: uuidPointer(testPrincipalID), GrantedAt: serviceTestNow,
					Reason: params.Reason, ExpiresAt: params.ExpiresAt,
				},
				State: AuthorizationEdgeStateActive, Version: 1, UpdatedAt: serviceTestNow,
				ManagedByAuthorizationAPI: true,
			}, nil
		},
	}
	service := newTestService(t, repository)
	service.newID = func() (uuid.UUID, error) { return edgeID, nil }

	edge, err := service.GrantTenantSecurityGroupRole(
		context.Background(), serviceTestActor(), testTenantID, groupID, input,
	)
	if err != nil || edge.ID != edgeID || edge.Role.Version != currentRole.Version {
		t.Fatalf("GrantTenantSecurityGroupRole() = %#v, %v", edge, err)
	}
	if repository.getRoleCalls != 0 || repository.grantGroupRoleCalls != 1 {
		t.Fatalf(
			"role reads = %d, grant calls = %d, want 0 and 1",
			repository.getRoleCalls, repository.grantGroupRoleCalls,
		)
	}
}

func TestGroupMembershipCreateLetsRepositoryDistinguishExpiredReplayFromNewCommand(t *testing.T) {
	groupID := serviceTestID(141)
	userID := serviceTestID(142)
	edgeID := serviceTestID(143)
	expiresAt := serviceTestNow.Add(-time.Minute)
	input := AddTenantSecurityGroupMembershipInput{
		UserID: userID, Reason: "Temporary group access", ExpiresAt: &expiresAt,
		IdempotencyKey: "expired-group-member-key", Audit: serviceTestAudit(),
	}
	authority := serviceTestAuthority(TenantPermissionGroupMembershipManage, TenantPermissionRoleGrant)

	t.Run("exact replay returns current expired representation after group archive", func(t *testing.T) {
		group := serviceTestGroup(groupID, "triage_group")
		group.Archived = true
		group.ArchivedAt = timePointer(serviceTestNow)
		edge := serviceTestGroupMembership(edgeID, userID, group)
		edge.Provenance.Reason = input.Reason
		edge.Provenance.ExpiresAt = &expiresAt
		edge.State = AuthorizationEdgeStateExpired
		repository := &serviceRepositoryStub{
			addGroupMembershipReplayed: true,
			resolveAuthorityFunc: func(ResolveAuthorityParams) (TenantAuthority, error) {
				return authority, nil
			},
			addGroupMembershipFunc: func(AddTenantSecurityGroupMembershipParams) (TenantSecurityGroupMembership, error) {
				return edge, nil
			},
		}
		service := newTestService(t, repository)

		got, err := service.AddTenantSecurityGroupMembership(
			context.Background(), serviceTestActor(), testTenantID, groupID, input,
		)
		if err != nil || got.ID != edgeID || got.State != AuthorizationEdgeStateExpired || !got.Group.Archived {
			t.Fatalf("AddTenantSecurityGroupMembership() replay = %#v, %v", got, err)
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
					return authority, nil
				},
				addGroupMembershipFunc: func(AddTenantSecurityGroupMembershipParams) (TenantSecurityGroupMembership, error) {
					return TenantSecurityGroupMembership{}, test.repositoryErr
				},
			}
			service := newTestService(t, repository)

			_, err := service.AddTenantSecurityGroupMembership(
				context.Background(), serviceTestActor(), testTenantID, groupID, input,
			)
			assertServiceError(t, err, test.want)
			if repository.addGroupMembershipCalls != 1 {
				t.Fatalf("membership repository calls = %d, want 1", repository.addGroupMembershipCalls)
			}
		})
	}

	t.Run("successful new expired result fails closed", func(t *testing.T) {
		edge := serviceTestGroupMembership(edgeID, userID, serviceTestGroup(groupID, "triage_group"))
		edge.Provenance.Reason = input.Reason
		edge.Provenance.ExpiresAt = &expiresAt
		edge.State = AuthorizationEdgeStateExpired
		repository := &serviceRepositoryStub{
			resolveAuthorityFunc: func(ResolveAuthorityParams) (TenantAuthority, error) {
				return authority, nil
			},
			addGroupMembershipFunc: func(AddTenantSecurityGroupMembershipParams) (TenantSecurityGroupMembership, error) {
				return edge, nil
			},
		}
		service := newTestService(t, repository)

		_, err := service.AddTenantSecurityGroupMembership(
			context.Background(), serviceTestActor(), testTenantID, groupID, input,
		)
		assertServiceError(t, err, ErrUnavailable)
	})
}

func TestGroupRoleCreateLetsRepositoryDistinguishExpiredReplayFromNewCommand(t *testing.T) {
	groupID := serviceTestID(144)
	roleID := serviceTestID(145)
	edgeID := serviceTestID(146)
	sourceID := serviceTestID(147)
	expiresAt := serviceTestNow.Add(-time.Minute)
	permission := ScopedPermission{Permission: TenantPermissionGroupRead, Scope: ScopeTenant}
	role := serviceTestRole(roleID, false, TenantRolePolicy{Permissions: []ScopedPermission{permission}})
	delegatingAuthority := serviceTestAuthority(
		TenantPermissionGroupManage, TenantPermissionRoleGrant, TenantPermissionGroupRead,
	)
	delegatingAuthority.DelegationCeiling = []DelegationGrant{{ScopedPermission: permission}}
	input := GrantTenantSecurityGroupRoleInput{
		RoleID: roleID, Reason: "Temporary group role", ExpiresAt: &expiresAt,
		IdempotencyKey: "expired-group-role-key", Audit: serviceTestAudit(),
	}
	newEdge := func(group TenantSecurityGroup, roleSummary TenantRoleSummary) TenantSecurityGroupRoleGrant {
		return TenantSecurityGroupRoleGrant{
			ID: edgeID, TenantID: testTenantID, Group: group, Role: roleSummary,
			Provenance: AuthorizationEdgeProvenance{
				SourceKind: AuthorizationSourceManual, SourceID: &sourceID,
				GrantedByUserID: uuidPointer(testPrincipalID), GrantedAt: serviceTestNow.Add(-time.Hour),
				Reason: input.Reason, ExpiresAt: &expiresAt,
			},
			State: AuthorizationEdgeStateExpired, Version: 1, UpdatedAt: serviceTestNow,
			ManagedByAuthorizationAPI: true,
		}
	}

	t.Run("exact replay returns current expired representation after role and group archive", func(t *testing.T) {
		archivedRole := role
		archivedRole.Archived = true
		archivedRole.ArchivedAt = timePointer(serviceTestNow)
		group := serviceTestGroup(groupID, "triage_group")
		group.Archived = true
		group.ArchivedAt = timePointer(serviceTestNow)
		edge := newEdge(group, archivedRole.TenantRoleSummary)
		repository := &serviceRepositoryStub{
			grantGroupRoleReplayed: true,
			resolveAuthorityFunc: func(ResolveAuthorityParams) (TenantAuthority, error) {
				return serviceTestAuthority(TenantPermissionGroupManage, TenantPermissionRoleGrant), nil
			},
			getRoleFunc: func(GetTenantRoleParams) (TenantRole, error) { return archivedRole, nil },
			grantGroupRoleFunc: func(GrantTenantSecurityGroupRoleParams) (TenantSecurityGroupRoleGrant, error) {
				return edge, nil
			},
		}
		service := newTestService(t, repository)

		got, err := service.GrantTenantSecurityGroupRole(
			context.Background(), serviceTestActor(), testTenantID, groupID, input,
		)
		if err != nil || got.ID != edgeID || got.State != AuthorizationEdgeStateExpired ||
			!got.Group.Archived || !got.Role.Archived {
			t.Fatalf("GrantTenantSecurityGroupRole() replay = %#v, %v", got, err)
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
				grantGroupRoleFunc: func(GrantTenantSecurityGroupRoleParams) (TenantSecurityGroupRoleGrant, error) {
					return TenantSecurityGroupRoleGrant{}, test.repositoryErr
				},
			}
			service := newTestService(t, repository)

			_, err := service.GrantTenantSecurityGroupRole(
				context.Background(), serviceTestActor(), testTenantID, groupID, input,
			)
			assertServiceError(t, err, test.want)
			if repository.grantGroupRoleCalls != 1 {
				t.Fatalf("group-role repository calls = %d, want 1", repository.grantGroupRoleCalls)
			}
		})
	}

	t.Run("successful new expired result fails closed", func(t *testing.T) {
		edge := newEdge(serviceTestGroup(groupID, "triage_group"), role.TenantRoleSummary)
		repository := &serviceRepositoryStub{
			resolveAuthorityFunc: func(ResolveAuthorityParams) (TenantAuthority, error) {
				return delegatingAuthority, nil
			},
			getRoleFunc: func(GetTenantRoleParams) (TenantRole, error) { return role, nil },
			grantGroupRoleFunc: func(GrantTenantSecurityGroupRoleParams) (TenantSecurityGroupRoleGrant, error) {
				return edge, nil
			},
		}
		service := newTestService(t, repository)

		_, err := service.GrantTenantSecurityGroupRole(
			context.Background(), serviceTestActor(), testTenantID, groupID, input,
		)
		assertServiceError(t, err, ErrUnavailable)
	})
}

func TestGroupAuthorityPathRequiresExactEdgeProvenanceAndExpiry(t *testing.T) {
	t.Parallel()

	membershipExpiry := serviceTestNow.Add(4 * time.Hour)
	roleExpiry := serviceTestNow.Add(2 * time.Hour)
	roleSourceID := serviceTestID(92)
	membershipSourceID := serviceTestID(93)
	roleProvenance := AuthorizationEdgeProvenance{
		SourceKind: AuthorizationSourceManual, SourceID: &roleSourceID,
		GrantedByUserID: uuidPointer(testPrincipalID), GrantedAt: serviceTestNow.Add(-time.Hour),
		Reason: "Group role", ExpiresAt: &roleExpiry,
	}
	grant := EffectiveTenantRoleGrant{
		GrantID: serviceTestID(94), RoleID: serviceTestID(95), RoleKey: "triage_role", RoleName: "Triage role",
		Provenance: RoleGrantProvenance{
			SourceType: RoleGrantSourceGroup, SourceKind: roleProvenance.SourceKind,
			SourceID: roleProvenance.SourceID, GrantedByUserID: roleProvenance.GrantedByUserID,
			GrantedAt: roleProvenance.GrantedAt, Reason: roleProvenance.Reason, ExpiresAt: roleProvenance.ExpiresAt,
		},
		Path: EffectiveTenantRoleAuthorityPath{
			PathType: RoleGrantPathGroup,
			Group: &GroupTenantRoleAuthorityPath{
				Group: TenantSecurityGroupAuthoritySummary{ID: serviceTestID(96), Key: "triage_group", Name: "Triage group"},
				MembershipEdge: TenantSecurityGroupAuthorityEdge{
					ID: serviceTestID(97),
					Provenance: AuthorizationEdgeProvenance{
						SourceKind: AuthorizationSourceManual, SourceID: &membershipSourceID,
						GrantedByUserID: uuidPointer(testPrincipalID), GrantedAt: serviceTestNow.Add(-time.Hour),
						Reason: "Group membership", ExpiresAt: &membershipExpiry,
					},
				},
				RoleGrantEdge: TenantSecurityGroupAuthorityEdge{ID: serviceTestID(94), Provenance: roleProvenance},
			},
		},
		EffectiveExpiresAt: &roleExpiry,
	}
	if !validEffectiveRoleGrant(grant) {
		t.Fatal("valid group authority path was rejected")
	}

	tampered := grant
	tampered.Path.Group = cloneGroupAuthorityPath(grant.Path.Group)
	tampered.Path.Group.RoleGrantEdge.Provenance.Reason = "Contradictory provenance"
	if validEffectiveRoleGrant(tampered) {
		t.Fatal("contradictory compatible and edge provenance was accepted")
	}

	tampered = grant
	later := membershipExpiry
	tampered.EffectiveExpiresAt = &later
	if validEffectiveRoleGrant(tampered) {
		t.Fatal("non-minimum effective expiry was accepted")
	}

	tampered = grant
	tampered.Path.Group = cloneGroupAuthorityPath(grant.Path.Group)
	tampered.Provenance.GrantedByUserID = nil
	tampered.Path.Group.RoleGrantEdge.Provenance.GrantedByUserID = nil
	if validEffectiveRoleGrant(tampered) {
		t.Fatal("manual group role provenance without a grantor was accepted")
	}

	tampered = grant
	tampered.Path.Group = cloneGroupAuthorityPath(grant.Path.Group)
	tampered.Path.Group.MembershipEdge.Provenance.GrantedByUserID = nil
	if validEffectiveRoleGrant(tampered) {
		t.Fatal("manual group membership provenance without a grantor was accepted")
	}
}

func TestSecurityGroupEdgeLifecycleRequiresCanonicalRevokeReason(t *testing.T) {
	t.Parallel()

	revokedAt := serviceTestNow.Add(-time.Minute)
	revokedBy := serviceTestID(119)
	reason := "Removed after access review"
	expiresAt := serviceTestNow.Add(time.Hour)

	for _, test := range []struct {
		name         string
		state        AuthorizationEdgeState
		expiresAt    *time.Time
		revokedAt    *time.Time
		revokedBy    *uuid.UUID
		revokeReason *string
		valid        bool
	}{
		{name: "active omits revocation history", state: AuthorizationEdgeStateActive, valid: true},
		{name: "active rejects revoke reason", state: AuthorizationEdgeStateActive, revokeReason: &reason},
		{name: "expired omits revocation history", state: AuthorizationEdgeStateExpired, expiresAt: &expiresAt, valid: true},
		{name: "revoked requires reason", state: AuthorizationEdgeStateRevoked, revokedAt: &revokedAt, revokedBy: &revokedBy},
		{name: "revoked accepts complete history", state: AuthorizationEdgeStateRevoked, revokedAt: &revokedAt, revokedBy: &revokedBy, revokeReason: &reason, valid: true},
		{name: "revoked rejects non-canonical reason", state: AuthorizationEdgeStateRevoked, revokedAt: &revokedAt, revokedBy: &revokedBy, revokeReason: stringPointer("  Removed after access review  ")},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := validAuthorizationEdgeLifecycle(
				test.state,
				test.expiresAt,
				test.revokedAt,
				test.revokedBy,
				test.revokeReason,
			); got != test.valid {
				t.Fatalf("validAuthorizationEdgeLifecycle() = %t, want %t", got, test.valid)
			}
		})
	}
}

func TestConcurrentSecurityGroupReadsResolveLiveAuthorityPerRequest(t *testing.T) {
	t.Parallel()

	repository := &concurrentGroupRepository{}
	service, err := NewService(repository)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	service.now = func() time.Time { return serviceTestNow }

	const calls = 20
	var wait sync.WaitGroup
	wait.Add(calls)
	errorsByCall := make(chan error, calls)
	for index := 0; index < calls; index++ {
		go func() {
			defer wait.Done()
			_, callErr := service.ListTenantSecurityGroups(
				context.Background(), serviceTestActor(), testTenantID, ListTenantSecurityGroupsInput{},
			)
			errorsByCall <- callErr
		}()
	}
	wait.Wait()
	close(errorsByCall)
	allowed := 0
	denied := 0
	for callErr := range errorsByCall {
		switch {
		case callErr == nil:
			allowed++
		case errors.Is(callErr, ErrForbidden):
			denied++
		default:
			t.Fatalf("concurrent call error = %v", callErr)
		}
	}
	if allowed != calls/2 || denied != calls/2 || repository.resolves.Load() != calls ||
		repository.lists.Load() != calls/2 {
		t.Fatalf("allowed=%d denied=%d resolves=%d lists=%d", allowed, denied, repository.resolves.Load(), repository.lists.Load())
	}
}

type concurrentGroupRepository struct {
	serviceRepositoryStub
	resolves atomic.Int32
	lists    atomic.Int32
}

func (r *concurrentGroupRepository) ResolveAuthority(
	_ context.Context,
	_ ResolveAuthorityParams,
) (TenantAuthority, error) {
	call := r.resolves.Add(1)
	if call%2 == 0 {
		return serviceTestAuthority(), nil
	}
	return serviceTestAuthority(TenantPermissionGroupRead), nil
}

func (r *concurrentGroupRepository) ListTenantSecurityGroups(
	_ context.Context,
	_ ListTenantSecurityGroupsParams,
) ([]TenantSecurityGroup, error) {
	r.lists.Add(1)
	return []TenantSecurityGroup{}, nil
}

func serviceTestGroup(id uuid.UUID, key string) TenantSecurityGroup {
	return TenantSecurityGroup{
		ID: id, TenantID: testTenantID, Key: key, Name: "Triage group",
		Description: "Security group", Version: 1,
		CreatedAt: serviceTestNow.Add(-time.Hour), UpdatedAt: serviceTestNow,
	}
}

func serviceTestGroupMembership(
	id, userID uuid.UUID,
	group TenantSecurityGroup,
) TenantSecurityGroupMembership {
	sourceID := serviceTestID(98)
	return TenantSecurityGroupMembership{
		ID: id, TenantID: testTenantID, Group: group,
		Member: serviceTestUser(serviceTestID(byte(userID[15]+1)), userID),
		Provenance: AuthorizationEdgeProvenance{
			SourceKind: AuthorizationSourceManual, SourceID: &sourceID,
			GrantedByUserID: uuidPointer(testPrincipalID), GrantedAt: serviceTestNow.Add(-time.Hour),
			Reason: "Group membership",
		},
		State: AuthorizationEdgeStateActive, Version: 1, UpdatedAt: serviceTestNow,
		ManagedByAuthorizationAPI: true,
	}
}

func cloneGroupAuthorityPath(value *GroupTenantRoleAuthorityPath) *GroupTenantRoleAuthorityPath {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func stringPointer(value string) *string {
	return &value
}
