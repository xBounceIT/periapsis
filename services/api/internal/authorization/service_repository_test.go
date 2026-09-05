package authorization

import "context"

type serviceRepositoryStub struct {
	calls int

	resolveAuthorityCalls int
	resolveAuthorityFunc  func(ResolveAuthorityParams) (TenantAuthority, error)

	listPermissionsCalls int
	listPermissionsFunc  func(ListTenantPermissionsParams) ([]TenantPermissionDefinition, error)

	listRolesCalls int
	listRolesFunc  func(ListTenantRolesParams) ([]TenantRoleSummary, error)

	createRoleCalls    int
	createRoleFunc     func(CreateTenantRoleParams) (TenantRole, error)
	createRoleReplayed bool

	getRoleCalls int
	getRoleFunc  func(GetTenantRoleParams) (TenantRole, error)

	updateRoleCalls int
	updateRoleFunc  func(UpdateTenantRoleParams) (TenantRole, error)

	archiveRoleCalls int
	archiveRoleFunc  func(ArchiveTenantRoleParams) error

	replaceRolePolicyCalls int
	replaceRolePolicyFunc  func(ReplaceTenantRolePolicyParams) (TenantRole, error)

	listUsersCalls                 int
	listUsersFunc                  func(ListTenantUsersParams) ([]TenantUserSummary, error)
	changeMembershipLifecycleCalls int
	changeMembershipLifecycleFunc  func(ChangeTenantMembershipLifecycleParams) (TenantMembershipLifecycleReceipt, error)

	listGrantsCalls int
	listGrantsFunc  func(ListUserRoleGrantsParams) ([]DirectUserRoleGrant, error)
	getGrantCalls   int
	getGrantFunc    func(GetUserRoleGrantParams) (DirectUserRoleGrant, error)

	grantRoleCalls    int
	grantRoleFunc     func(GrantUserRoleParams) (DirectUserRoleGrant, error)
	grantRoleReplayed bool

	revokeGrantCalls int
	revokeGrantFunc  func(RevokeRoleGrantParams) error

	listGroupsCalls            int
	listGroupsFunc             func(ListTenantSecurityGroupsParams) ([]TenantSecurityGroup, error)
	createGroupCalls           int
	createGroupFunc            func(CreateTenantSecurityGroupParams) (TenantSecurityGroup, error)
	createGroupReplayed        bool
	getGroupCalls              int
	getGroupFunc               func(GetTenantSecurityGroupParams) (TenantSecurityGroup, error)
	updateGroupCalls           int
	updateGroupFunc            func(UpdateTenantSecurityGroupParams) (TenantSecurityGroup, error)
	archiveGroupCalls          int
	archiveGroupFunc           func(ArchiveTenantSecurityGroupParams) error
	listGroupMembershipsCalls  int
	listGroupMembershipsFunc   func(ListTenantSecurityGroupMembershipsParams) ([]TenantSecurityGroupMembership, error)
	getGroupMembershipCalls    int
	getGroupMembershipFunc     func(GetTenantSecurityGroupMembershipParams) (TenantSecurityGroupMembership, error)
	addGroupMembershipCalls    int
	addGroupMembershipFunc     func(AddTenantSecurityGroupMembershipParams) (TenantSecurityGroupMembership, error)
	addGroupMembershipReplayed bool
	revokeGroupMembershipCalls int
	revokeGroupMembershipFunc  func(RevokeTenantSecurityGroupMembershipParams) error
	listGroupRoleGrantsCalls   int
	listGroupRoleGrantsFunc    func(ListTenantSecurityGroupRoleGrantsParams) ([]TenantSecurityGroupRoleGrant, error)
	getGroupRoleGrantCalls     int
	getGroupRoleGrantFunc      func(GetTenantSecurityGroupRoleGrantParams) (TenantSecurityGroupRoleGrant, error)
	grantGroupRoleCalls        int
	grantGroupRoleFunc         func(GrantTenantSecurityGroupRoleParams) (TenantSecurityGroupRoleGrant, error)
	grantGroupRoleReplayed     bool
	revokeGroupRoleGrantCalls  int
	revokeGroupRoleGrantFunc   func(RevokeTenantSecurityGroupRoleGrantParams) error
}

func (r *serviceRepositoryStub) ResolveAuthority(
	_ context.Context,
	params ResolveAuthorityParams,
) (TenantAuthority, error) {
	r.calls++
	r.resolveAuthorityCalls++
	if r.resolveAuthorityFunc == nil {
		return TenantAuthority{}, ErrUnavailable
	}
	return r.resolveAuthorityFunc(params)
}

func (r *serviceRepositoryStub) ListTenantPermissions(
	_ context.Context,
	params ListTenantPermissionsParams,
) ([]TenantPermissionDefinition, error) {
	r.calls++
	r.listPermissionsCalls++
	if r.listPermissionsFunc == nil {
		return nil, ErrUnavailable
	}
	return r.listPermissionsFunc(params)
}

func (r *serviceRepositoryStub) ListTenantRoles(
	_ context.Context,
	params ListTenantRolesParams,
) ([]TenantRoleSummary, error) {
	r.calls++
	r.listRolesCalls++
	if r.listRolesFunc == nil {
		return nil, ErrUnavailable
	}
	return r.listRolesFunc(params)
}

func (r *serviceRepositoryStub) CreateTenantRole(
	_ context.Context,
	params CreateTenantRoleParams,
) (IdempotentCreateResult[TenantRole], error) {
	r.calls++
	r.createRoleCalls++
	if r.createRoleFunc == nil {
		return IdempotentCreateResult[TenantRole]{}, ErrUnavailable
	}
	value, err := r.createRoleFunc(params)
	return IdempotentCreateResult[TenantRole]{Value: value, Replayed: r.createRoleReplayed}, err
}

func (r *serviceRepositoryStub) GetTenantRole(
	_ context.Context,
	params GetTenantRoleParams,
) (TenantRole, error) {
	r.calls++
	r.getRoleCalls++
	if r.getRoleFunc == nil {
		return TenantRole{}, ErrUnavailable
	}
	return r.getRoleFunc(params)
}

func (r *serviceRepositoryStub) UpdateTenantRole(
	_ context.Context,
	params UpdateTenantRoleParams,
) (TenantRole, error) {
	r.calls++
	r.updateRoleCalls++
	if r.updateRoleFunc == nil {
		return TenantRole{}, ErrUnavailable
	}
	return r.updateRoleFunc(params)
}

func (r *serviceRepositoryStub) ArchiveTenantRole(
	_ context.Context,
	params ArchiveTenantRoleParams,
) error {
	r.calls++
	r.archiveRoleCalls++
	if r.archiveRoleFunc == nil {
		return ErrUnavailable
	}
	return r.archiveRoleFunc(params)
}

func (r *serviceRepositoryStub) ReplaceTenantRolePolicy(
	_ context.Context,
	params ReplaceTenantRolePolicyParams,
) (TenantRole, error) {
	r.calls++
	r.replaceRolePolicyCalls++
	if r.replaceRolePolicyFunc == nil {
		return TenantRole{}, ErrUnavailable
	}
	return r.replaceRolePolicyFunc(params)
}

func (r *serviceRepositoryStub) ListTenantUsers(
	_ context.Context,
	params ListTenantUsersParams,
) ([]TenantUserSummary, error) {
	r.calls++
	r.listUsersCalls++
	if r.listUsersFunc == nil {
		return nil, ErrUnavailable
	}
	return r.listUsersFunc(params)
}

func (r *serviceRepositoryStub) ChangeTenantMembershipLifecycle(
	_ context.Context,
	params ChangeTenantMembershipLifecycleParams,
) (TenantMembershipLifecycleReceipt, error) {
	r.calls++
	r.changeMembershipLifecycleCalls++
	if r.changeMembershipLifecycleFunc == nil {
		return TenantMembershipLifecycleReceipt{}, ErrUnavailable
	}
	return r.changeMembershipLifecycleFunc(params)
}

func (r *serviceRepositoryStub) ListUserRoleGrants(
	_ context.Context,
	params ListUserRoleGrantsParams,
) ([]DirectUserRoleGrant, error) {
	r.calls++
	r.listGrantsCalls++
	if r.listGrantsFunc == nil {
		return nil, ErrUnavailable
	}
	return r.listGrantsFunc(params)
}

func (r *serviceRepositoryStub) GetUserRoleGrant(
	_ context.Context,
	params GetUserRoleGrantParams,
) (DirectUserRoleGrant, error) {
	r.calls++
	r.getGrantCalls++
	if r.getGrantFunc == nil {
		return DirectUserRoleGrant{}, ErrUnavailable
	}
	return r.getGrantFunc(params)
}

func (r *serviceRepositoryStub) GrantUserRole(
	_ context.Context,
	params GrantUserRoleParams,
) (IdempotentCreateResult[DirectUserRoleGrant], error) {
	r.calls++
	r.grantRoleCalls++
	if r.grantRoleFunc == nil {
		return IdempotentCreateResult[DirectUserRoleGrant]{}, ErrUnavailable
	}
	value, err := r.grantRoleFunc(params)
	return IdempotentCreateResult[DirectUserRoleGrant]{Value: value, Replayed: r.grantRoleReplayed}, err
}

func (r *serviceRepositoryStub) RevokeRoleGrant(
	_ context.Context,
	params RevokeRoleGrantParams,
) error {
	r.calls++
	r.revokeGrantCalls++
	if r.revokeGrantFunc == nil {
		return ErrUnavailable
	}
	return r.revokeGrantFunc(params)
}

func (r *serviceRepositoryStub) ListTenantSecurityGroups(
	_ context.Context,
	params ListTenantSecurityGroupsParams,
) ([]TenantSecurityGroup, error) {
	r.calls++
	r.listGroupsCalls++
	if r.listGroupsFunc == nil {
		return nil, ErrUnavailable
	}
	return r.listGroupsFunc(params)
}

func (r *serviceRepositoryStub) CreateTenantSecurityGroup(
	_ context.Context,
	params CreateTenantSecurityGroupParams,
) (IdempotentCreateResult[TenantSecurityGroup], error) {
	r.calls++
	r.createGroupCalls++
	if r.createGroupFunc == nil {
		return IdempotentCreateResult[TenantSecurityGroup]{}, ErrUnavailable
	}
	value, err := r.createGroupFunc(params)
	return IdempotentCreateResult[TenantSecurityGroup]{Value: value, Replayed: r.createGroupReplayed}, err
}

func (r *serviceRepositoryStub) GetTenantSecurityGroup(
	_ context.Context,
	params GetTenantSecurityGroupParams,
) (TenantSecurityGroup, error) {
	r.calls++
	r.getGroupCalls++
	if r.getGroupFunc == nil {
		return TenantSecurityGroup{}, ErrUnavailable
	}
	return r.getGroupFunc(params)
}

func (r *serviceRepositoryStub) UpdateTenantSecurityGroup(
	_ context.Context,
	params UpdateTenantSecurityGroupParams,
) (TenantSecurityGroup, error) {
	r.calls++
	r.updateGroupCalls++
	if r.updateGroupFunc == nil {
		return TenantSecurityGroup{}, ErrUnavailable
	}
	return r.updateGroupFunc(params)
}

func (r *serviceRepositoryStub) ArchiveTenantSecurityGroup(
	_ context.Context,
	params ArchiveTenantSecurityGroupParams,
) error {
	r.calls++
	r.archiveGroupCalls++
	if r.archiveGroupFunc == nil {
		return ErrUnavailable
	}
	return r.archiveGroupFunc(params)
}

func (r *serviceRepositoryStub) ListTenantSecurityGroupMemberships(
	_ context.Context,
	params ListTenantSecurityGroupMembershipsParams,
) ([]TenantSecurityGroupMembership, error) {
	r.calls++
	r.listGroupMembershipsCalls++
	if r.listGroupMembershipsFunc == nil {
		return nil, ErrUnavailable
	}
	return r.listGroupMembershipsFunc(params)
}

func (r *serviceRepositoryStub) GetTenantSecurityGroupMembership(
	_ context.Context,
	params GetTenantSecurityGroupMembershipParams,
) (TenantSecurityGroupMembership, error) {
	r.calls++
	r.getGroupMembershipCalls++
	if r.getGroupMembershipFunc == nil {
		return TenantSecurityGroupMembership{}, ErrUnavailable
	}
	return r.getGroupMembershipFunc(params)
}

func (r *serviceRepositoryStub) AddTenantSecurityGroupMembership(
	_ context.Context,
	params AddTenantSecurityGroupMembershipParams,
) (IdempotentCreateResult[TenantSecurityGroupMembership], error) {
	r.calls++
	r.addGroupMembershipCalls++
	if r.addGroupMembershipFunc == nil {
		return IdempotentCreateResult[TenantSecurityGroupMembership]{}, ErrUnavailable
	}
	value, err := r.addGroupMembershipFunc(params)
	return IdempotentCreateResult[TenantSecurityGroupMembership]{
		Value: value, Replayed: r.addGroupMembershipReplayed,
	}, err
}

func (r *serviceRepositoryStub) RevokeTenantSecurityGroupMembership(
	_ context.Context,
	params RevokeTenantSecurityGroupMembershipParams,
) error {
	r.calls++
	r.revokeGroupMembershipCalls++
	if r.revokeGroupMembershipFunc == nil {
		return ErrUnavailable
	}
	return r.revokeGroupMembershipFunc(params)
}

func (r *serviceRepositoryStub) ListTenantSecurityGroupRoleGrants(
	_ context.Context,
	params ListTenantSecurityGroupRoleGrantsParams,
) ([]TenantSecurityGroupRoleGrant, error) {
	r.calls++
	r.listGroupRoleGrantsCalls++
	if r.listGroupRoleGrantsFunc == nil {
		return nil, ErrUnavailable
	}
	return r.listGroupRoleGrantsFunc(params)
}

func (r *serviceRepositoryStub) GetTenantSecurityGroupRoleGrant(
	_ context.Context,
	params GetTenantSecurityGroupRoleGrantParams,
) (TenantSecurityGroupRoleGrant, error) {
	r.calls++
	r.getGroupRoleGrantCalls++
	if r.getGroupRoleGrantFunc == nil {
		return TenantSecurityGroupRoleGrant{}, ErrUnavailable
	}
	return r.getGroupRoleGrantFunc(params)
}

func (r *serviceRepositoryStub) GrantTenantSecurityGroupRole(
	_ context.Context,
	params GrantTenantSecurityGroupRoleParams,
) (IdempotentCreateResult[TenantSecurityGroupRoleGrant], error) {
	r.calls++
	r.grantGroupRoleCalls++
	if r.grantGroupRoleFunc == nil {
		return IdempotentCreateResult[TenantSecurityGroupRoleGrant]{}, ErrUnavailable
	}
	value, err := r.grantGroupRoleFunc(params)
	return IdempotentCreateResult[TenantSecurityGroupRoleGrant]{
		Value: value, Replayed: r.grantGroupRoleReplayed,
	}, err
}

func (r *serviceRepositoryStub) RevokeTenantSecurityGroupRoleGrant(
	_ context.Context,
	params RevokeTenantSecurityGroupRoleGrantParams,
) error {
	r.calls++
	r.revokeGroupRoleGrantCalls++
	if r.revokeGroupRoleGrantFunc == nil {
		return ErrUnavailable
	}
	return r.revokeGroupRoleGrantFunc(params)
}
