package authorization

import (
	"context"

	"github.com/google/uuid"
)

func (s *Service) ListTenantSecurityGroups(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	input ListTenantSecurityGroupsInput,
) (TenantSecurityGroupPage, error) {
	if err := validateActiveTenant(actor, tenantID); err != nil {
		return TenantSecurityGroupPage{}, err
	}
	page, err := normalizedPageInput(input.PageInput)
	if err != nil {
		return TenantSecurityGroupPage{}, err
	}
	if _, err = s.resolveAndRequire(ctx, actor, tenantID, TenantPermissionGroupRead); err != nil {
		return TenantSecurityGroupPage{}, err
	}
	rows, err := s.repository.ListTenantSecurityGroups(ctx, ListTenantSecurityGroupsParams{
		Actor: actor, TenantID: tenantID, After: page.After, Limit: int32(page.Limit + 1),
		IncludeArchived: input.IncludeArchived,
	})
	if err != nil {
		return TenantSecurityGroupPage{}, mapRepositoryError(err)
	}
	for _, row := range rows {
		if !validStoredSecurityGroup(row, tenantID) {
			return TenantSecurityGroupPage{}, ErrUnavailable
		}
	}
	items, next, err := boundedPage(rows, page.After, page.Limit, func(group TenantSecurityGroup) uuid.UUID {
		return group.ID
	})
	if err != nil {
		return TenantSecurityGroupPage{}, err
	}
	return TenantSecurityGroupPage{Items: items, NextCursor: next}, nil
}

func (s *Service) CreateTenantSecurityGroup(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	input CreateTenantSecurityGroupInput,
) (TenantSecurityGroup, error) {
	if err := validateActiveTenant(actor, tenantID); err != nil {
		return TenantSecurityGroup{}, err
	}
	normalized, err := normalizeCreateSecurityGroupInput(input)
	if err != nil {
		return TenantSecurityGroup{}, err
	}
	if _, err = s.resolveAndRequire(ctx, actor, tenantID, TenantPermissionGroupManage); err != nil {
		return TenantSecurityGroup{}, err
	}
	now, err := s.currentTime()
	if err != nil {
		return TenantSecurityGroup{}, err
	}
	groupID, err := s.nextID()
	if err != nil {
		return TenantSecurityGroup{}, err
	}
	result, err := s.repository.CreateTenantSecurityGroup(ctx, CreateTenantSecurityGroupParams{
		Actor: actor, Audit: normalized.Audit, OccurredAt: now,
		TenantID: tenantID, GroupID: groupID, Key: normalized.Key, Name: normalized.Name,
		Description: normalized.Description, IdempotencyKey: normalized.IdempotencyKey,
	})
	if err != nil {
		return TenantSecurityGroup{}, mapRepositoryError(err)
	}
	group := result.Value
	if group.Key != normalized.Key || !validStoredSecurityGroup(group, tenantID) {
		return TenantSecurityGroup{}, ErrUnavailable
	}
	if !result.Replayed && group.Archived {
		return TenantSecurityGroup{}, ErrUnavailable
	}
	return group, nil
}

func (s *Service) GetTenantSecurityGroup(
	ctx context.Context,
	actor Actor,
	tenantID, groupID uuid.UUID,
) (TenantSecurityGroup, error) {
	if err := validateActiveTenant(actor, tenantID); err != nil {
		return TenantSecurityGroup{}, err
	}
	if !validUUIDv7(groupID) {
		return TenantSecurityGroup{}, ErrInvalidInput
	}
	if _, err := s.resolveAndRequire(ctx, actor, tenantID, TenantPermissionGroupRead); err != nil {
		return TenantSecurityGroup{}, err
	}
	return s.loadTenantSecurityGroup(ctx, actor, tenantID, groupID)
}

func (s *Service) UpdateTenantSecurityGroup(
	ctx context.Context,
	actor Actor,
	tenantID, groupID uuid.UUID,
	input UpdateTenantSecurityGroupInput,
) (TenantSecurityGroup, error) {
	if err := validateActiveTenant(actor, tenantID); err != nil {
		return TenantSecurityGroup{}, err
	}
	normalized, version, err := normalizeUpdateSecurityGroupInput(groupID, input)
	if err != nil {
		return TenantSecurityGroup{}, err
	}
	if _, err = s.resolveAndRequire(ctx, actor, tenantID, TenantPermissionGroupManage); err != nil {
		return TenantSecurityGroup{}, err
	}
	current, err := s.loadTenantSecurityGroup(ctx, actor, tenantID, groupID)
	if err != nil {
		return TenantSecurityGroup{}, err
	}
	if current.Version != version {
		return TenantSecurityGroup{}, ErrPreconditionFailed
	}
	if current.Archived {
		return TenantSecurityGroup{}, ErrConflict
	}
	now, err := s.currentTime()
	if err != nil {
		return TenantSecurityGroup{}, err
	}
	group, err := s.repository.UpdateTenantSecurityGroup(ctx, UpdateTenantSecurityGroupParams{
		Actor: actor, Audit: normalized.Audit, OccurredAt: now, TenantID: tenantID,
		GroupID: groupID, Name: normalized.Name, Description: normalized.Description,
		ExpectedVersion: version,
	})
	if err != nil {
		return TenantSecurityGroup{}, mapRepositoryError(err)
	}
	if group.ID != groupID || group.Archived || !validStoredSecurityGroup(group, tenantID) {
		return TenantSecurityGroup{}, ErrUnavailable
	}
	return group, nil
}

func (s *Service) ArchiveTenantSecurityGroup(
	ctx context.Context,
	actor Actor,
	tenantID, groupID uuid.UUID,
	input ArchiveTenantSecurityGroupInput,
) error {
	if err := validateActiveTenant(actor, tenantID); err != nil {
		return err
	}
	version, err := validateVersionedMutation(groupID, input.ExpectedVersion, input.Audit)
	if err != nil {
		return err
	}
	if _, err = s.resolveAndRequire(ctx, actor, tenantID, TenantPermissionGroupManage); err != nil {
		return err
	}
	current, err := s.loadTenantSecurityGroup(ctx, actor, tenantID, groupID)
	if err != nil {
		return err
	}
	if current.Version != version {
		return ErrPreconditionFailed
	}
	if current.Archived {
		return ErrConflict
	}
	now, err := s.currentTime()
	if err != nil {
		return err
	}
	return mapRepositoryError(s.repository.ArchiveTenantSecurityGroup(ctx, ArchiveTenantSecurityGroupParams{
		Actor: actor, Audit: input.Audit, OccurredAt: now, TenantID: tenantID,
		GroupID: groupID, ExpectedVersion: version,
	}))
}

func (s *Service) ListTenantSecurityGroupMemberships(
	ctx context.Context,
	actor Actor,
	tenantID, groupID uuid.UUID,
	input ListTenantSecurityGroupEdgesInput,
) (TenantSecurityGroupMembershipPage, error) {
	if err := validateActiveTenant(actor, tenantID); err != nil {
		return TenantSecurityGroupMembershipPage{}, err
	}
	if !validUUIDv7(groupID) {
		return TenantSecurityGroupMembershipPage{}, ErrInvalidInput
	}
	page, err := normalizedPageInput(input.PageInput)
	if err != nil {
		return TenantSecurityGroupMembershipPage{}, err
	}
	if _, err = s.resolveAndRequireAll(
		ctx, actor, tenantID, TenantPermissionGroupRead, TenantPermissionUserRead,
	); err != nil {
		return TenantSecurityGroupMembershipPage{}, err
	}
	rows, err := s.repository.ListTenantSecurityGroupMemberships(
		ctx,
		ListTenantSecurityGroupMembershipsParams{
			Actor: actor, TenantID: tenantID, GroupID: groupID, After: page.After,
			Limit: int32(page.Limit + 1), IncludeRevoked: input.IncludeRevoked,
		},
	)
	if err != nil {
		return TenantSecurityGroupMembershipPage{}, mapRepositoryError(err)
	}
	for _, row := range rows {
		if !validSecurityGroupMembership(row, tenantID, groupID) {
			return TenantSecurityGroupMembershipPage{}, ErrUnavailable
		}
	}
	items, next, err := boundedPage(rows, page.After, page.Limit, func(edge TenantSecurityGroupMembership) uuid.UUID {
		return edge.ID
	})
	if err != nil {
		return TenantSecurityGroupMembershipPage{}, err
	}
	return TenantSecurityGroupMembershipPage{Items: items, NextCursor: next}, nil
}

func (s *Service) AddTenantSecurityGroupMembership(
	ctx context.Context,
	actor Actor,
	tenantID, groupID uuid.UUID,
	input AddTenantSecurityGroupMembershipInput,
) (TenantSecurityGroupMembership, error) {
	if err := validateActiveTenant(actor, tenantID); err != nil {
		return TenantSecurityGroupMembership{}, err
	}
	if !validUUIDv7(groupID) {
		return TenantSecurityGroupMembership{}, ErrInvalidInput
	}
	normalized, err := normalizeAddSecurityGroupMembershipInput(input)
	if err != nil {
		return TenantSecurityGroupMembership{}, err
	}
	now, err := s.currentTime()
	if err != nil {
		return TenantSecurityGroupMembership{}, err
	}
	newCommandValid := normalized.ExpiresAt == nil || normalized.ExpiresAt.After(now)
	if _, err = s.resolveAndRequireAll(
		ctx, actor, tenantID, TenantPermissionGroupMembershipManage, TenantPermissionRoleGrant,
	); err != nil {
		return TenantSecurityGroupMembership{}, err
	}
	edgeID, err := s.nextID()
	if err != nil {
		return TenantSecurityGroupMembership{}, err
	}
	result, err := s.repository.AddTenantSecurityGroupMembership(
		ctx,
		AddTenantSecurityGroupMembershipParams{
			Actor: actor, Audit: normalized.Audit, OccurredAt: now, TenantID: tenantID,
			GroupID: groupID, MembershipID: edgeID, UserID: normalized.UserID,
			Reason: normalized.Reason, ExpiresAt: normalized.ExpiresAt,
			IdempotencyKey: normalized.IdempotencyKey,
		},
	)
	if err != nil {
		return TenantSecurityGroupMembership{}, mapRepositoryError(err)
	}
	edge := result.Value
	if edge.Member.User.ID != normalized.UserID || !edge.ManagedByAuthorizationAPI ||
		!validSecurityGroupMembership(edge, tenantID, groupID) {
		return TenantSecurityGroupMembership{}, ErrUnavailable
	}
	if !result.Replayed && (!newCommandValid || edge.State != AuthorizationEdgeStateActive ||
		edge.Group.Archived || edge.Provenance.RetiredAt != nil ||
		edge.Provenance.Reason != normalized.Reason ||
		!equalOptionalInstant(edge.Provenance.ExpiresAt, normalized.ExpiresAt) ||
		edge.Provenance.ExpiresAt != nil && !edge.Provenance.ExpiresAt.After(now)) {
		return TenantSecurityGroupMembership{}, ErrUnavailable
	}
	return edge, nil
}

func (s *Service) RevokeTenantSecurityGroupMembership(
	ctx context.Context,
	actor Actor,
	tenantID, groupID, membershipID uuid.UUID,
	input RevokeTenantSecurityGroupMembershipInput,
) error {
	if err := validateActiveTenant(actor, tenantID); err != nil {
		return err
	}
	if !validUUIDv7(groupID) {
		return ErrInvalidInput
	}
	expectedEntityTag, _, err := validateEdgeMutation(
		membershipID, input.ExpectedEntityTag, input.Audit,
	)
	if err != nil {
		return err
	}
	reason, ok := normalizedReason(input.Reason)
	if !ok {
		return ErrInvalidInput
	}
	if _, err = s.resolveAndRequireAll(
		ctx, actor, tenantID, TenantPermissionGroupMembershipManage, TenantPermissionRoleGrant,
	); err != nil {
		return err
	}
	current, err := s.loadTenantSecurityGroupMembership(ctx, actor, tenantID, groupID, membershipID)
	if err != nil {
		return err
	}
	currentEntityTag, err := TenantSecurityGroupMembershipEntityTag(current)
	if err != nil {
		return ErrUnavailable
	}
	if currentEntityTag != expectedEntityTag {
		return ErrPreconditionFailed
	}
	if !current.ManagedByAuthorizationAPI || current.State == AuthorizationEdgeStateRevoked {
		return ErrConflict
	}
	now, err := s.currentTime()
	if err != nil {
		return err
	}
	return mapRepositoryError(s.repository.RevokeTenantSecurityGroupMembership(
		ctx,
		RevokeTenantSecurityGroupMembershipParams{
			Actor: actor, Audit: input.Audit, OccurredAt: now, TenantID: tenantID,
			GroupID: groupID, MembershipID: membershipID, Reason: reason,
			ExpectedEntityTag: expectedEntityTag,
		},
	))
}

func (s *Service) ListTenantSecurityGroupRoleGrants(
	ctx context.Context,
	actor Actor,
	tenantID, groupID uuid.UUID,
	input ListTenantSecurityGroupEdgesInput,
) (TenantSecurityGroupRoleGrantPage, error) {
	if err := validateActiveTenant(actor, tenantID); err != nil {
		return TenantSecurityGroupRoleGrantPage{}, err
	}
	if !validUUIDv7(groupID) {
		return TenantSecurityGroupRoleGrantPage{}, ErrInvalidInput
	}
	page, err := normalizedPageInput(input.PageInput)
	if err != nil {
		return TenantSecurityGroupRoleGrantPage{}, err
	}
	if _, err = s.resolveAndRequireAll(
		ctx, actor, tenantID, TenantPermissionGroupRead, TenantPermissionRoleRead,
	); err != nil {
		return TenantSecurityGroupRoleGrantPage{}, err
	}
	rows, err := s.repository.ListTenantSecurityGroupRoleGrants(
		ctx,
		ListTenantSecurityGroupRoleGrantsParams{
			Actor: actor, TenantID: tenantID, GroupID: groupID, After: page.After,
			Limit: int32(page.Limit + 1), IncludeRevoked: input.IncludeRevoked,
		},
	)
	if err != nil {
		return TenantSecurityGroupRoleGrantPage{}, mapRepositoryError(err)
	}
	for _, row := range rows {
		if !validSecurityGroupRoleGrant(row, tenantID, groupID) {
			return TenantSecurityGroupRoleGrantPage{}, ErrUnavailable
		}
	}
	items, next, err := boundedPage(rows, page.After, page.Limit, func(edge TenantSecurityGroupRoleGrant) uuid.UUID {
		return edge.ID
	})
	if err != nil {
		return TenantSecurityGroupRoleGrantPage{}, err
	}
	return TenantSecurityGroupRoleGrantPage{Items: items, NextCursor: next}, nil
}

func (s *Service) GrantTenantSecurityGroupRole(
	ctx context.Context,
	actor Actor,
	tenantID, groupID uuid.UUID,
	input GrantTenantSecurityGroupRoleInput,
) (TenantSecurityGroupRoleGrant, error) {
	if err := validateActiveTenant(actor, tenantID); err != nil {
		return TenantSecurityGroupRoleGrant{}, err
	}
	if !validUUIDv7(groupID) {
		return TenantSecurityGroupRoleGrant{}, ErrInvalidInput
	}
	normalized, err := normalizeGrantSecurityGroupRoleInput(input)
	if err != nil {
		return TenantSecurityGroupRoleGrant{}, err
	}
	now, err := s.currentTime()
	if err != nil {
		return TenantSecurityGroupRoleGrant{}, err
	}
	_, err = s.resolveAndRequireAll(
		ctx, actor, tenantID, TenantPermissionGroupManage, TenantPermissionRoleGrant,
	)
	if err != nil {
		return TenantSecurityGroupRoleGrant{}, err
	}
	freshLifetimeValid := normalized.ExpiresAt == nil || normalized.ExpiresAt.After(now)
	grantID, err := s.nextID()
	if err != nil {
		return TenantSecurityGroupRoleGrant{}, err
	}
	result, err := s.repository.GrantTenantSecurityGroupRole(
		ctx,
		GrantTenantSecurityGroupRoleParams{
			Actor: actor, Audit: normalized.Audit, OccurredAt: now, TenantID: tenantID,
			GroupID: groupID, GrantID: grantID, RoleID: normalized.RoleID,
			Reason: normalized.Reason, ExpiresAt: normalized.ExpiresAt,
			IdempotencyKey: normalized.IdempotencyKey,
		},
	)
	if err != nil {
		return TenantSecurityGroupRoleGrant{}, mapRepositoryError(err)
	}
	edge := result.Value
	if edge.Role.ID != normalized.RoleID || !edge.ManagedByAuthorizationAPI ||
		!validSecurityGroupRoleGrant(edge, tenantID, groupID) {
		return TenantSecurityGroupRoleGrant{}, ErrUnavailable
	}
	if !result.Replayed && (!freshLifetimeValid || edge.State != AuthorizationEdgeStateActive ||
		edge.Group.Archived || edge.Role.Archived || edge.Provenance.RetiredAt != nil ||
		edge.Provenance.Reason != normalized.Reason ||
		!equalOptionalInstant(edge.Provenance.ExpiresAt, normalized.ExpiresAt) ||
		edge.Provenance.ExpiresAt != nil && !edge.Provenance.ExpiresAt.After(now)) {
		return TenantSecurityGroupRoleGrant{}, ErrUnavailable
	}
	return edge, nil
}

func (s *Service) RevokeTenantSecurityGroupRoleGrant(
	ctx context.Context,
	actor Actor,
	tenantID, groupID, grantID uuid.UUID,
	input RevokeTenantSecurityGroupRoleGrantInput,
) error {
	if err := validateActiveTenant(actor, tenantID); err != nil {
		return err
	}
	if !validUUIDv7(groupID) {
		return ErrInvalidInput
	}
	expectedEntityTag, _, err := validateEdgeMutation(grantID, input.ExpectedEntityTag, input.Audit)
	if err != nil {
		return err
	}
	reason, ok := normalizedReason(input.Reason)
	if !ok {
		return ErrInvalidInput
	}
	if _, err = s.resolveAndRequireAll(
		ctx, actor, tenantID, TenantPermissionGroupManage, TenantPermissionRoleGrant,
	); err != nil {
		return err
	}
	current, err := s.loadTenantSecurityGroupRoleGrant(ctx, actor, tenantID, groupID, grantID)
	if err != nil {
		return err
	}
	currentEntityTag, err := TenantSecurityGroupRoleGrantEntityTag(current)
	if err != nil {
		return ErrUnavailable
	}
	if currentEntityTag != expectedEntityTag {
		return ErrPreconditionFailed
	}
	if !current.ManagedByAuthorizationAPI || current.State == AuthorizationEdgeStateRevoked {
		return ErrConflict
	}
	now, err := s.currentTime()
	if err != nil {
		return err
	}
	return mapRepositoryError(s.repository.RevokeTenantSecurityGroupRoleGrant(
		ctx,
		RevokeTenantSecurityGroupRoleGrantParams{
			Actor: actor, Audit: input.Audit, OccurredAt: now, TenantID: tenantID,
			GroupID: groupID, GrantID: grantID, Reason: reason, ExpectedEntityTag: expectedEntityTag,
		},
	))
}

func (s *Service) resolveAndRequireAll(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	permissions ...TenantPermission,
) (TenantAuthority, error) {
	authority, err := s.resolveLiveAuthority(ctx, actor, tenantID)
	if err != nil {
		return TenantAuthority{}, err
	}
	for _, permission := range permissions {
		if err := s.evaluator.RequireTenant(
			authority,
			permission,
			ResourceContext{TenantID: tenantID},
		); err != nil {
			return TenantAuthority{}, ErrForbidden
		}
	}
	return authority, nil
}

func (s *Service) loadTenantSecurityGroup(
	ctx context.Context,
	actor Actor,
	tenantID, groupID uuid.UUID,
) (TenantSecurityGroup, error) {
	group, err := s.repository.GetTenantSecurityGroup(ctx, GetTenantSecurityGroupParams{
		Actor: actor, TenantID: tenantID, GroupID: groupID,
	})
	if err != nil {
		return TenantSecurityGroup{}, mapRepositoryError(err)
	}
	if group.ID != groupID || !validStoredSecurityGroup(group, tenantID) {
		return TenantSecurityGroup{}, ErrUnavailable
	}
	return group, nil
}

func (s *Service) loadTenantSecurityGroupMembership(
	ctx context.Context,
	actor Actor,
	tenantID, groupID, membershipID uuid.UUID,
) (TenantSecurityGroupMembership, error) {
	edge, err := s.repository.GetTenantSecurityGroupMembership(
		ctx,
		GetTenantSecurityGroupMembershipParams{
			Actor: actor, TenantID: tenantID, GroupID: groupID, MembershipID: membershipID,
		},
	)
	if err != nil {
		return TenantSecurityGroupMembership{}, mapRepositoryError(err)
	}
	if edge.ID != membershipID || !validSecurityGroupMembership(edge, tenantID, groupID) {
		return TenantSecurityGroupMembership{}, ErrUnavailable
	}
	return edge, nil
}

func (s *Service) loadTenantSecurityGroupRoleGrant(
	ctx context.Context,
	actor Actor,
	tenantID, groupID, grantID uuid.UUID,
) (TenantSecurityGroupRoleGrant, error) {
	edge, err := s.repository.GetTenantSecurityGroupRoleGrant(
		ctx,
		GetTenantSecurityGroupRoleGrantParams{
			Actor: actor, TenantID: tenantID, GroupID: groupID, GrantID: grantID,
		},
	)
	if err != nil {
		return TenantSecurityGroupRoleGrant{}, mapRepositoryError(err)
	}
	if edge.ID != grantID || !validSecurityGroupRoleGrant(edge, tenantID, groupID) {
		return TenantSecurityGroupRoleGrant{}, ErrUnavailable
	}
	return edge, nil
}
