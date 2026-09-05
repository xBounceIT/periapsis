package authorization

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

const (
	defaultPageSize = 50
	maximumPageSize = 100
	// MaximumHydratedPermissionTuples matches the PostgreSQL authority/policy
	// read ABI. Built-in roles can exceed the public list and policy-write limit.
	MaximumHydratedPermissionTuples = 500
	// The repository fetches one extra path as a truncation sentinel.
	maximumEffectiveRolePaths = 200
	// PostgreSQL fetches one extra relationship as a truncation sentinel.
	maximumOperatorTeamRelationships = 200
)

// Service implements tenant-authorization application use cases. All methods
// resolve authority live after checking the session's active tenant.
type Service struct {
	repository Repository
	evaluator  Evaluator
	now        func() time.Time
	newID      func() (uuid.UUID, error)
}

func NewService(repository Repository) (*Service, error) {
	if repository == nil {
		return nil, errors.New("authorization repository is required")
	}
	return &Service{
		repository: repository,
		evaluator:  Evaluator{},
		now:        time.Now,
		newID:      uuid.NewV7,
	}, nil
}

func (s *Service) GetTenantAuthority(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
) (TenantAuthority, error) {
	if err := validateActiveTenant(actor, tenantID); err != nil {
		return TenantAuthority{}, err
	}
	return s.resolveLiveAuthority(ctx, actor, tenantID)
}

func (s *Service) ListTenantPermissions(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	input PageInput,
) (TenantPermissionPage, error) {
	if err := validateActiveTenant(actor, tenantID); err != nil {
		return TenantPermissionPage{}, err
	}
	page, err := normalizedPageInput(input)
	if err != nil {
		return TenantPermissionPage{}, err
	}
	if _, err = s.resolveAndRequire(ctx, actor, tenantID, TenantPermissionPermissionRead); err != nil {
		return TenantPermissionPage{}, err
	}
	rows, err := s.repository.ListTenantPermissions(ctx, ListTenantPermissionsParams{
		Actor: actor, TenantID: tenantID, After: page.After, Limit: int32(page.Limit + 1),
	})
	if err != nil {
		return TenantPermissionPage{}, mapRepositoryError(err)
	}
	for _, row := range rows {
		if !s.validPermissionDefinition(row) {
			return TenantPermissionPage{}, ErrUnavailable
		}
	}
	items, next, err := boundedPage(rows, page.After, page.Limit, func(item TenantPermissionDefinition) uuid.UUID {
		return item.ID
	})
	if err != nil {
		return TenantPermissionPage{}, err
	}
	return TenantPermissionPage{Items: items, NextCursor: next}, nil
}

func (s *Service) ListTenantRoles(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	input ListTenantRolesInput,
) (TenantRolePage, error) {
	if err := validateActiveTenant(actor, tenantID); err != nil {
		return TenantRolePage{}, err
	}
	page, err := normalizedPageInput(input.PageInput)
	if err != nil {
		return TenantRolePage{}, err
	}
	if _, err = s.resolveAndRequire(ctx, actor, tenantID, TenantPermissionRoleRead); err != nil {
		return TenantRolePage{}, err
	}
	rows, err := s.repository.ListTenantRoles(ctx, ListTenantRolesParams{
		Actor: actor, TenantID: tenantID, After: page.After, Limit: int32(page.Limit + 1),
		IncludeArchived: input.IncludeArchived,
	})
	if err != nil {
		return TenantRolePage{}, mapRepositoryError(err)
	}
	for _, row := range rows {
		if !validStoredRoleSummary(row, tenantID) {
			return TenantRolePage{}, ErrUnavailable
		}
	}
	items, next, err := boundedPage(rows, page.After, page.Limit, func(item TenantRoleSummary) uuid.UUID {
		return item.ID
	})
	if err != nil {
		return TenantRolePage{}, err
	}
	return TenantRolePage{Items: items, NextCursor: next}, nil
}

func (s *Service) CreateTenantRole(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	input CreateTenantRoleInput,
) (TenantRole, error) {
	if err := validateActiveTenant(actor, tenantID); err != nil {
		return TenantRole{}, err
	}
	normalized, err := s.normalizeCreateRoleInput(input)
	if err != nil {
		return TenantRole{}, err
	}
	if _, err = s.resolveAndRequire(ctx, actor, tenantID, TenantPermissionRoleManage); err != nil {
		return TenantRole{}, err
	}
	now, err := s.currentTime()
	if err != nil {
		return TenantRole{}, err
	}
	roleID, err := s.nextID()
	if err != nil {
		return TenantRole{}, err
	}
	result, err := s.repository.CreateTenantRole(ctx, CreateTenantRoleParams{
		Actor: actor, Audit: normalized.Audit, OccurredAt: now,
		TenantID: tenantID, RoleID: roleID, Key: normalized.Key, Name: normalized.Name,
		Description: normalized.Description, Policy: normalized.Policy,
		IdempotencyKey: normalized.IdempotencyKey,
	})
	if err != nil {
		return TenantRole{}, mapRepositoryError(err)
	}
	role := result.Value
	if role.PrincipalKind != PrincipalKindHuman || role.System || role.Key != normalized.Key || !s.validStoredRole(role, tenantID) {
		return TenantRole{}, ErrUnavailable
	}
	if !result.Replayed && role.Archived {
		return TenantRole{}, ErrUnavailable
	}
	return role, nil
}

func (s *Service) GetTenantRole(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	roleID uuid.UUID,
) (TenantRole, error) {
	if err := validateActiveTenant(actor, tenantID); err != nil {
		return TenantRole{}, err
	}
	if !validUUIDv7(roleID) {
		return TenantRole{}, ErrInvalidInput
	}
	if _, err := s.resolveAndRequire(ctx, actor, tenantID, TenantPermissionRoleRead); err != nil {
		return TenantRole{}, err
	}
	return s.loadTenantRole(ctx, actor, tenantID, roleID)
}

func (s *Service) UpdateTenantRole(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	roleID uuid.UUID,
	input UpdateTenantRoleInput,
) (TenantRole, error) {
	if err := validateActiveTenant(actor, tenantID); err != nil {
		return TenantRole{}, err
	}
	normalized, version, err := normalizeUpdateRoleInput(roleID, input)
	if err != nil {
		return TenantRole{}, err
	}
	if _, err = s.resolveAndRequire(ctx, actor, tenantID, TenantPermissionRoleManage); err != nil {
		return TenantRole{}, err
	}
	current, err := s.loadTenantRole(ctx, actor, tenantID, roleID)
	if err != nil {
		return TenantRole{}, err
	}
	if current.Version != version {
		return TenantRole{}, ErrPreconditionFailed
	}
	if current.PrincipalKind != PrincipalKindHuman || current.System || current.Archived {
		return TenantRole{}, ErrConflict
	}
	now, err := s.currentTime()
	if err != nil {
		return TenantRole{}, err
	}
	role, err := s.repository.UpdateTenantRole(ctx, UpdateTenantRoleParams{
		Actor: actor, Audit: normalized.Audit, OccurredAt: now,
		TenantID: tenantID, RoleID: roleID, Name: normalized.Name,
		Description: normalized.Description, ExpectedVersion: version,
	})
	if err != nil {
		return TenantRole{}, mapRepositoryError(err)
	}
	if role.ID != roleID || role.PrincipalKind != PrincipalKindHuman || role.System || !s.validStoredRole(role, tenantID) {
		return TenantRole{}, ErrUnavailable
	}
	return role, nil
}

func (s *Service) ArchiveTenantRole(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	roleID uuid.UUID,
	input ArchiveTenantRoleInput,
) error {
	if err := validateActiveTenant(actor, tenantID); err != nil {
		return err
	}
	version, err := validateVersionedMutation(roleID, input.ExpectedVersion, input.Audit)
	if err != nil {
		return err
	}
	if _, err = s.resolveAndRequire(ctx, actor, tenantID, TenantPermissionRoleManage); err != nil {
		return err
	}
	current, err := s.loadTenantRole(ctx, actor, tenantID, roleID)
	if err != nil {
		return err
	}
	if current.Version != version {
		return ErrPreconditionFailed
	}
	if current.PrincipalKind != PrincipalKindHuman || current.System || current.Archived {
		return ErrConflict
	}
	now, err := s.currentTime()
	if err != nil {
		return err
	}
	return mapRepositoryError(s.repository.ArchiveTenantRole(ctx, ArchiveTenantRoleParams{
		Actor: actor, Audit: input.Audit, OccurredAt: now,
		TenantID: tenantID, RoleID: roleID, ExpectedVersion: version,
	}))
}

func (s *Service) ReplaceTenantRolePolicy(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	roleID uuid.UUID,
	input ReplaceTenantRolePolicyInput,
) (TenantRole, error) {
	if err := validateActiveTenant(actor, tenantID); err != nil {
		return TenantRole{}, err
	}
	version, err := validateVersionedMutation(roleID, input.ExpectedVersion, input.Audit)
	if err != nil {
		return TenantRole{}, err
	}
	policy, err := s.normalizedRolePolicy(input.Policy)
	if err != nil {
		return TenantRole{}, err
	}
	authority, err := s.resolveAndRequire(ctx, actor, tenantID, TenantPermissionRoleManage)
	if err != nil {
		return TenantRole{}, err
	}
	current, err := s.loadTenantRole(ctx, actor, tenantID, roleID)
	if err != nil {
		return TenantRole{}, err
	}
	if current.Version != version {
		return TenantRole{}, ErrPreconditionFailed
	}
	if current.PrincipalKind != PrincipalKindHuman || current.System || current.Archived {
		return TenantRole{}, ErrConflict
	}
	now, err := s.currentTime()
	if err != nil {
		return TenantRole{}, err
	}
	if err := s.evaluator.RequireDelegablePolicy(authority, policy.Permissions, now); err != nil {
		return TenantRole{}, ErrForbidden
	}
	role, err := s.repository.ReplaceTenantRolePolicy(ctx, ReplaceTenantRolePolicyParams{
		Actor: actor, Audit: input.Audit, OccurredAt: now,
		TenantID: tenantID, RoleID: roleID, Policy: policy, ExpectedVersion: version,
	})
	if err != nil {
		return TenantRole{}, mapRepositoryError(err)
	}
	if role.ID != roleID || role.PrincipalKind != PrincipalKindHuman || role.System || !s.validStoredRole(role, tenantID) {
		return TenantRole{}, ErrUnavailable
	}
	return role, nil
}

func (s *Service) ListTenantUsers(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	input PageInput,
) (TenantUserPage, error) {
	if err := validateActiveTenant(actor, tenantID); err != nil {
		return TenantUserPage{}, err
	}
	page, err := normalizedPageInput(input)
	if err != nil {
		return TenantUserPage{}, err
	}
	if _, err = s.resolveAndRequire(ctx, actor, tenantID, TenantPermissionUserRead); err != nil {
		return TenantUserPage{}, err
	}
	rows, err := s.repository.ListTenantUsers(ctx, ListTenantUsersParams{
		Actor: actor, TenantID: tenantID, After: page.After, Limit: int32(page.Limit + 1),
	})
	if err != nil {
		return TenantUserPage{}, mapRepositoryError(err)
	}
	for _, row := range rows {
		if !validTenantUserSummary(row, tenantID) {
			return TenantUserPage{}, ErrUnavailable
		}
	}
	items, next, err := boundedPage(rows, page.After, page.Limit, func(item TenantUserSummary) uuid.UUID {
		return item.MembershipID
	})
	if err != nil {
		return TenantUserPage{}, err
	}
	return TenantUserPage{Items: items, NextCursor: next}, nil
}

// ChangeTenantMembershipLifecycle applies one exact active/suspended
// transition. The repository repeats authority, state, idempotency, session
// fencing, audit, and recovery-floor checks in the database transaction.
func (s *Service) ChangeTenantMembershipLifecycle(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	userID uuid.UUID,
	targetStatus MembershipStatus,
	input TenantMembershipLifecycleInput,
) (TenantMembershipLifecycleReceipt, error) {
	if err := validateActiveTenant(actor, tenantID); err != nil {
		return TenantMembershipLifecycleReceipt{}, err
	}
	if !validUUIDv7(userID) ||
		(targetStatus != MembershipStatusActive && targetStatus != MembershipStatusSuspended) {
		return TenantMembershipLifecycleReceipt{}, ErrInvalidInput
	}
	if input.ExpectedRevision == nil {
		return TenantMembershipLifecycleReceipt{}, ErrPreconditionRequired
	}
	expectedRevision := *input.ExpectedRevision
	if expectedRevision < 1 || expectedRevision >= maximumResourceVersion ||
		!idempotencyKeyPattern.MatchString(input.IdempotencyKey) ||
		!validLifecycleReason(input.Reason) || !validAuditContext(input.Audit) {
		return TenantMembershipLifecycleReceipt{}, ErrInvalidInput
	}
	if _, err := s.resolveAndRequire(
		ctx, actor, tenantID, TenantPermissionMembershipManage,
	); err != nil {
		return TenantMembershipLifecycleReceipt{}, err
	}
	now, err := s.currentTime()
	if err != nil {
		return TenantMembershipLifecycleReceipt{}, err
	}
	receipt, err := s.repository.ChangeTenantMembershipLifecycle(
		ctx,
		ChangeTenantMembershipLifecycleParams{
			Actor: actor, Audit: input.Audit, OccurredAt: now,
			TenantID: tenantID, UserID: userID, TargetStatus: targetStatus,
			ExpectedRevision: expectedRevision, Reason: input.Reason,
			IdempotencyKey: input.IdempotencyKey,
		},
	)
	if err != nil {
		return TenantMembershipLifecycleReceipt{}, mapRepositoryError(err)
	}
	if !validTenantMembershipLifecycleReceipt(
		receipt, tenantID, userID, targetStatus, expectedRevision,
	) {
		return TenantMembershipLifecycleReceipt{}, ErrUnavailable
	}
	return receipt, nil
}

func (s *Service) ListUserRoleGrants(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	userID uuid.UUID,
	input ListUserRoleGrantsInput,
) (DirectUserRoleGrantPage, error) {
	if err := validateActiveTenant(actor, tenantID); err != nil {
		return DirectUserRoleGrantPage{}, err
	}
	if !validUUIDv7(userID) {
		return DirectUserRoleGrantPage{}, ErrInvalidInput
	}
	page, err := normalizedPageInput(input.PageInput)
	if err != nil {
		return DirectUserRoleGrantPage{}, err
	}
	if _, err = s.resolveAndRequire(ctx, actor, tenantID, TenantPermissionRoleRead); err != nil {
		return DirectUserRoleGrantPage{}, err
	}
	rows, err := s.repository.ListUserRoleGrants(ctx, ListUserRoleGrantsParams{
		Actor: actor, TenantID: tenantID, UserID: userID, After: page.After,
		Limit: int32(page.Limit + 1), IncludeRevoked: input.IncludeRevoked,
	})
	if err != nil {
		return DirectUserRoleGrantPage{}, mapRepositoryError(err)
	}
	for _, row := range rows {
		if !validDirectRoleGrant(row, tenantID, userID) {
			return DirectUserRoleGrantPage{}, ErrUnavailable
		}
	}
	items, next, err := boundedPage(rows, page.After, page.Limit, func(item DirectUserRoleGrant) uuid.UUID {
		return item.ID
	})
	if err != nil {
		return DirectUserRoleGrantPage{}, err
	}
	return DirectUserRoleGrantPage{Items: items, NextCursor: next}, nil
}

func (s *Service) GrantUserRole(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	userID uuid.UUID,
	input GrantUserRoleInput,
) (DirectUserRoleGrant, error) {
	if err := validateActiveTenant(actor, tenantID); err != nil {
		return DirectUserRoleGrant{}, err
	}
	normalized, err := normalizeGrantUserRoleInput(userID, input)
	if err != nil {
		return DirectUserRoleGrant{}, err
	}
	now, err := s.currentTime()
	if err != nil {
		return DirectUserRoleGrant{}, err
	}
	if _, err = s.resolveAndRequire(ctx, actor, tenantID, TenantPermissionRoleGrant); err != nil {
		return DirectUserRoleGrant{}, err
	}
	freshLifetimeValid := normalized.ExpiresAt == nil || normalized.ExpiresAt.After(now)
	grantID, err := s.nextID()
	if err != nil {
		return DirectUserRoleGrant{}, err
	}
	result, err := s.repository.GrantUserRole(ctx, GrantUserRoleParams{
		Actor: actor, Audit: normalized.Audit, OccurredAt: now,
		TenantID: tenantID, GrantID: grantID, UserID: userID, RoleID: normalized.RoleID,
		Reason: normalized.Reason, ExpiresAt: normalized.ExpiresAt,
		IdempotencyKey: normalized.IdempotencyKey,
	})
	if err != nil {
		return DirectUserRoleGrant{}, mapRepositoryError(err)
	}
	grant := result.Value
	if grant.Role.ID != normalized.RoleID || !grant.ManagedByAuthorizationAPI ||
		!validDirectRoleGrant(grant, tenantID, userID) {
		return DirectUserRoleGrant{}, ErrUnavailable
	}
	if !result.Replayed {
		if grant.State != DirectRoleGrantStateActive || grant.Role.Archived ||
			grant.Provenance.RetiredAt != nil ||
			grant.Provenance.Reason != normalized.Reason ||
			!equalOptionalInstant(grant.Provenance.ExpiresAt, normalized.ExpiresAt) ||
			grant.Provenance.ExpiresAt != nil && !grant.Provenance.ExpiresAt.After(now) ||
			!freshLifetimeValid {
			return DirectUserRoleGrant{}, ErrUnavailable
		}
	}
	return grant, nil
}

func (s *Service) RevokeRoleGrant(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	grantID uuid.UUID,
	input RevokeRoleGrantInput,
) error {
	if err := validateActiveTenant(actor, tenantID); err != nil {
		return err
	}
	expectedEntityTag, _, err := validateEdgeMutation(grantID, input.ExpectedEntityTag, input.Audit)
	if err != nil {
		return err
	}
	reason, ok := normalizedReason(input.Reason)
	if !ok {
		return ErrInvalidInput
	}
	if _, err = s.resolveAndRequire(ctx, actor, tenantID, TenantPermissionRoleGrant); err != nil {
		return err
	}
	current, err := s.loadDirectUserRoleGrant(ctx, actor, tenantID, grantID)
	if err != nil {
		return err
	}
	currentEntityTag, err := DirectUserRoleGrantEntityTag(current)
	if err != nil {
		return ErrUnavailable
	}
	if currentEntityTag != expectedEntityTag {
		return ErrPreconditionFailed
	}
	if !current.ManagedByAuthorizationAPI || current.State == DirectRoleGrantStateRevoked {
		return ErrConflict
	}
	now, err := s.currentTime()
	if err != nil {
		return err
	}
	return mapRepositoryError(s.repository.RevokeRoleGrant(ctx, RevokeRoleGrantParams{
		Actor: actor, Audit: input.Audit, OccurredAt: now,
		TenantID: tenantID, GrantID: grantID, Reason: reason, ExpectedEntityTag: expectedEntityTag,
	}))
}

func (s *Service) resolveAndRequire(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	permission TenantPermission,
) (TenantAuthority, error) {
	return s.resolveAndRequireAll(ctx, actor, tenantID, permission)
}

func (s *Service) resolveLiveAuthority(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
) (TenantAuthority, error) {
	authority, err := s.repository.ResolveAuthority(ctx, ResolveAuthorityParams{
		Actor: actor, TenantID: tenantID,
	})
	if err != nil {
		if errors.Is(err, ErrForbidden) || errors.Is(err, ErrNotFound) || errors.Is(err, ErrDenied) {
			return TenantAuthority{}, ErrForbidden
		}
		return TenantAuthority{}, mapRepositoryError(err)
	}
	if !s.validResolvedAuthority(authority, actor, tenantID) {
		return TenantAuthority{}, ErrUnavailable
	}
	return authority, nil
}

func (s *Service) loadTenantRole(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	roleID uuid.UUID,
) (TenantRole, error) {
	role, err := s.repository.GetTenantRole(ctx, GetTenantRoleParams{
		Actor: actor, TenantID: tenantID, RoleID: roleID,
	})
	if err != nil {
		return TenantRole{}, mapRepositoryError(err)
	}
	if role.ID != roleID || !s.validStoredRole(role, tenantID) {
		return TenantRole{}, ErrUnavailable
	}
	return role, nil
}

func (s *Service) loadDirectUserRoleGrant(
	ctx context.Context,
	actor Actor,
	tenantID, grantID uuid.UUID,
) (DirectUserRoleGrant, error) {
	grant, err := s.repository.GetUserRoleGrant(ctx, GetUserRoleGrantParams{
		Actor: actor, TenantID: tenantID, GrantID: grantID,
	})
	if err != nil {
		return DirectUserRoleGrant{}, mapRepositoryError(err)
	}
	if grant.ID != grantID || !validUUIDv7(grant.UserID) ||
		!validDirectRoleGrant(grant, tenantID, grant.UserID) {
		return DirectUserRoleGrant{}, ErrUnavailable
	}
	return grant, nil
}

func (s *Service) currentTime() (time.Time, error) {
	value := s.now().UTC()
	if value.IsZero() {
		return time.Time{}, ErrUnavailable
	}
	return value, nil
}

func (s *Service) nextID() (uuid.UUID, error) {
	value, err := s.newID()
	if err != nil || !validUUIDv7(value) {
		return uuid.Nil, ErrUnavailable
	}
	return value, nil
}

func mapRepositoryError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, ErrDenied), errors.Is(err, ErrForbidden):
		return ErrForbidden
	case errors.Is(err, ErrInvalidInput):
		return ErrInvalidInput
	case errors.Is(err, ErrNotFound):
		return ErrNotFound
	case errors.Is(err, ErrConflict):
		return ErrConflict
	case errors.Is(err, ErrPreconditionRequired):
		return ErrPreconditionRequired
	case errors.Is(err, ErrPreconditionFailed):
		return ErrPreconditionFailed
	case errors.Is(err, ErrUnavailable):
		return ErrUnavailable
	default:
		return ErrUnavailable
	}
}
