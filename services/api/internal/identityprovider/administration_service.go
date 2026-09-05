package identityprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"slices"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

const ldapAdministrationRepositoryPageLimit = int32(101)

func (s *Service) ListBindings(
	ctx context.Context,
	actor authorization.Actor,
	tenantID uuid.UUID,
	input ListBindingsInput,
) (BindingPage, error) {
	normalized, err := normalizeListBindings(input)
	if err != nil {
		return BindingPage{}, err
	}
	authority, err := s.resolveAndRequire(ctx, actor, tenantID, authorization.TenantPermissionIdentityProviderRead)
	if err != nil {
		return BindingPage{}, err
	}
	if s.administration == nil {
		return BindingPage{}, ErrUnavailable
	}
	rows, err := s.administration.ListBindings(ctx, ListBindingParams{
		HumanParams: HumanParams{Actor: actor, MembershipID: authority.MembershipID, TenantID: tenantID},
		After:       normalized.After, Limit: int32(normalized.Limit + 1), IncludeArchived: normalized.IncludeArchived,
	})
	if err != nil {
		return BindingPage{}, mapRepositoryError(err)
	}
	if len(rows) > normalized.Limit+1 || len(rows) > int(ldapAdministrationRepositoryPageLimit) {
		return BindingPage{}, ErrUnavailable
	}
	for index, row := range rows {
		if !validBinding(row, tenantID) || !normalized.IncludeArchived && row.ArchivedAt != nil ||
			normalized.After != nil && bytes.Compare(row.ID[:], normalized.After[:]) <= 0 ||
			index > 0 && bytes.Compare(rows[index-1].ID[:], row.ID[:]) >= 0 {
			return BindingPage{}, ErrUnavailable
		}
	}
	items, next := bindingPage(rows, normalized.Limit)
	return BindingPage{Items: items, NextCursor: next}, nil
}

func (s *Service) GetBinding(
	ctx context.Context,
	actor authorization.Actor,
	tenantID, bindingID uuid.UUID,
) (Binding, error) {
	if !validUUIDv7(bindingID) {
		return Binding{}, ErrInvalidInput
	}
	authority, err := s.resolveAndRequire(ctx, actor, tenantID, authorization.TenantPermissionIdentityProviderRead)
	if err != nil {
		return Binding{}, err
	}
	if s.administration == nil {
		return Binding{}, ErrUnavailable
	}
	result, err := s.administration.GetBinding(ctx, GetBindingParams{
		HumanParams: HumanParams{Actor: actor, MembershipID: authority.MembershipID, TenantID: tenantID},
		BindingID:   bindingID,
	})
	if err != nil {
		return Binding{}, mapRepositoryError(err)
	}
	if result.ID != bindingID || !validBinding(result, tenantID) {
		return Binding{}, ErrUnavailable
	}
	return result, nil
}

func (s *Service) CreateBinding(
	ctx context.Context,
	actor authorization.Actor,
	tenantID uuid.UUID,
	input CreateBindingInput,
) (Binding, error) {
	normalized, err := normalizeCreateBinding(input)
	if err != nil {
		return Binding{}, err
	}
	authority, err := s.resolveAndRequire(ctx, actor, tenantID, authorization.TenantPermissionIdentityProviderManage)
	if err != nil {
		return Binding{}, err
	}
	if s.administration == nil {
		return Binding{}, ErrUnavailable
	}
	now, err := s.currentTime()
	if err != nil {
		return Binding{}, err
	}
	auditEventID, err := s.nextID()
	if err != nil {
		return Binding{}, err
	}
	digest := sha256.Sum256([]byte(normalized.IdempotencyKey))
	defer clear(digest[:])
	result, err := s.administration.CreateBinding(ctx, CreateBindingParams{
		HumanParams: HumanParams{Actor: actor, MembershipID: authority.MembershipID, TenantID: tenantID},
		Audit:       normalized.Audit, OccurredAt: now, AuditEventID: auditEventID,
		IdempotencyKeyDigest: digest, ProviderID: normalized.ProviderID,
		LoginKey: normalized.LoginKey, Enabled: normalized.Enabled,
		ProfilePriority: normalized.ProfilePriority,
	})
	if err != nil {
		return Binding{}, mapRepositoryError(err)
	}
	if !validBinding(result.Binding, tenantID) || result.Binding.ProviderID != normalized.ProviderID {
		return Binding{}, ErrUnavailable
	}
	if !result.Replayed && (result.Binding.Version != 1 ||
		result.Binding.LoginKey != normalized.LoginKey || result.Binding.Enabled != normalized.Enabled ||
		result.Binding.ProfilePriority != normalized.ProfilePriority) {
		return Binding{}, ErrUnavailable
	}
	return result.Binding, nil
}

func (s *Service) UpdateBinding(
	ctx context.Context,
	actor authorization.Actor,
	tenantID, bindingID uuid.UUID,
	input UpdateBindingInput,
) (Binding, error) {
	normalized, version, err := normalizeUpdateBinding(bindingID, input)
	if err != nil {
		return Binding{}, err
	}
	authority, err := s.resolveAndRequire(ctx, actor, tenantID, authorization.TenantPermissionIdentityProviderManage)
	if err != nil {
		return Binding{}, err
	}
	if s.administration == nil {
		return Binding{}, ErrUnavailable
	}
	now, err := s.currentTime()
	if err != nil {
		return Binding{}, err
	}
	result, err := s.administration.UpdateBinding(ctx, UpdateBindingParams{
		HumanParams: HumanParams{Actor: actor, MembershipID: authority.MembershipID, TenantID: tenantID},
		Audit:       normalized.Audit, OccurredAt: now, BindingID: bindingID, ExpectedVersion: version,
		LoginKey: normalized.LoginKey, Enabled: normalized.Enabled, ProfilePriority: normalized.ProfilePriority,
	})
	if err != nil {
		return Binding{}, mapRepositoryError(err)
	}
	if result.ID != bindingID || result.Version != version+1 || !validBinding(result, tenantID) ||
		result.LoginKey != normalized.LoginKey || result.Enabled != normalized.Enabled ||
		result.ProfilePriority != normalized.ProfilePriority {
		return Binding{}, ErrUnavailable
	}
	return result, nil
}

func (s *Service) ArchiveBinding(
	ctx context.Context,
	actor authorization.Actor,
	tenantID, bindingID uuid.UUID,
	input ArchiveBindingInput,
) (int64, error) {
	normalized, version, err := normalizeArchiveBinding(bindingID, input)
	if err != nil {
		return 0, err
	}
	authority, err := s.resolveAndRequire(ctx, actor, tenantID, authorization.TenantPermissionIdentityProviderManage)
	if err != nil {
		return 0, err
	}
	if s.administration == nil {
		return 0, ErrUnavailable
	}
	now, err := s.currentTime()
	if err != nil {
		return 0, err
	}
	updated, err := s.administration.ArchiveBinding(ctx, ArchiveBindingParams{
		HumanParams: HumanParams{Actor: actor, MembershipID: authority.MembershipID, TenantID: tenantID},
		Audit:       normalized.Audit, OccurredAt: now, BindingID: bindingID,
		ExpectedVersion: version, Reason: normalized.Reason,
	})
	if err != nil {
		return 0, mapRepositoryError(err)
	}
	if updated != version+1 {
		return 0, ErrUnavailable
	}
	return updated, nil
}

func (s *Service) ListMappings(
	ctx context.Context,
	actor authorization.Actor,
	tenantID uuid.UUID,
	input ListMappingsInput,
) (MappingPage, error) {
	normalized, err := normalizeListMappings(input)
	if err != nil {
		return MappingPage{}, err
	}
	authority, err := s.resolveAndRequire(ctx, actor, tenantID, authorization.TenantPermissionIdentityMappingRead)
	if err != nil {
		return MappingPage{}, err
	}
	if s.administration == nil {
		return MappingPage{}, ErrUnavailable
	}
	rows, err := s.administration.ListMappings(ctx, ListMappingParams{
		HumanParams: HumanParams{Actor: actor, MembershipID: authority.MembershipID, TenantID: tenantID},
		After:       normalized.After, Limit: int32(normalized.Limit + 1),
		IncludeArchived: normalized.IncludeArchived, BindingID: normalized.BindingID,
	})
	if err != nil {
		return MappingPage{}, mapRepositoryError(err)
	}
	if len(rows) > normalized.Limit+1 || len(rows) > int(ldapAdministrationRepositoryPageLimit) {
		return MappingPage{}, ErrUnavailable
	}
	seen := make(map[uuid.UUID]struct{}, len(rows))
	for index, row := range rows {
		_, duplicate := seen[row.ID]
		if !validMapping(row, tenantID) || duplicate || !normalized.IncludeArchived && row.ArchivedAt != nil ||
			normalized.BindingID != nil && row.BindingID != *normalized.BindingID ||
			normalized.After != nil && compareMappingTuple(
				normalized.After.Priority, normalized.After.ID, row.Priority, row.ID,
			) >= 0 ||
			index > 0 && compareMappingOrder(rows[index-1], row) >= 0 {
			return MappingPage{}, ErrUnavailable
		}
		seen[row.ID] = struct{}{}
	}
	items, next := mappingPage(rows, normalized.Limit)
	return MappingPage{Items: items, NextCursor: next}, nil
}

func (s *Service) GetMapping(
	ctx context.Context,
	actor authorization.Actor,
	tenantID, mappingID uuid.UUID,
) (Mapping, error) {
	if !validUUIDv7(mappingID) {
		return Mapping{}, ErrInvalidInput
	}
	authority, err := s.resolveAndRequire(ctx, actor, tenantID, authorization.TenantPermissionIdentityMappingRead)
	if err != nil {
		return Mapping{}, err
	}
	if s.administration == nil {
		return Mapping{}, ErrUnavailable
	}
	result, err := s.administration.GetMapping(ctx, GetMappingParams{
		HumanParams: HumanParams{Actor: actor, MembershipID: authority.MembershipID, TenantID: tenantID},
		MappingID:   mappingID,
	})
	if err != nil {
		return Mapping{}, mapRepositoryError(err)
	}
	if result.ID != mappingID || !validMapping(result, tenantID) {
		return Mapping{}, ErrUnavailable
	}
	return result, nil
}

func (s *Service) CreateMapping(
	ctx context.Context,
	actor authorization.Actor,
	tenantID uuid.UUID,
	input CreateMappingInput,
) (Mapping, error) {
	normalized, err := normalizeCreateMapping(input)
	if err != nil {
		return Mapping{}, err
	}
	authority, err := s.resolveMappingMutation(ctx, actor, tenantID, normalized.Target)
	if err != nil {
		return Mapping{}, err
	}
	if s.administration == nil {
		return Mapping{}, ErrUnavailable
	}
	now, err := s.currentTime()
	if err != nil {
		return Mapping{}, err
	}
	auditEventID, err := s.nextID()
	if err != nil {
		return Mapping{}, err
	}
	digest := sha256.Sum256([]byte(normalized.IdempotencyKey))
	defer clear(digest[:])
	result, err := s.administration.CreateMapping(ctx, CreateMappingParams{
		HumanParams: HumanParams{Actor: actor, MembershipID: authority.MembershipID, TenantID: tenantID},
		Audit:       normalized.Audit, OccurredAt: now, AuditEventID: auditEventID,
		IdempotencyKeyDigest: digest, BindingID: normalized.BindingID, Matcher: normalized.Matcher,
		Priority: normalized.Priority, Target: normalized.Target,
		ReconciliationMode: normalized.ReconciliationMode, Notes: normalized.Notes, Reason: normalized.Reason,
	})
	if err != nil {
		return Mapping{}, mapRepositoryError(err)
	}
	if !validMapping(result.Mapping, tenantID) || result.Mapping.BindingID != normalized.BindingID {
		return Mapping{}, ErrUnavailable
	}
	if !result.Replayed && (result.Mapping.Version != 1 || result.Mapping.Enabled ||
		!sameMappingDefinition(result.Mapping, normalized.Matcher, normalized.Priority, normalized.Target,
			normalized.ReconciliationMode, normalized.Notes)) {
		return Mapping{}, ErrUnavailable
	}
	return result.Mapping, nil
}

func (s *Service) UpdateMapping(
	ctx context.Context,
	actor authorization.Actor,
	tenantID, mappingID uuid.UUID,
	input UpdateMappingInput,
) (Mapping, error) {
	normalized, version, err := normalizeUpdateMapping(mappingID, input)
	if err != nil {
		return Mapping{}, err
	}
	authority, err := s.resolveMappingMutation(ctx, actor, tenantID, normalized.Target)
	if err != nil {
		return Mapping{}, err
	}
	if s.administration == nil {
		return Mapping{}, ErrUnavailable
	}
	now, err := s.currentTime()
	if err != nil {
		return Mapping{}, err
	}
	auditEventID, err := s.nextID()
	if err != nil {
		return Mapping{}, err
	}
	result, err := s.administration.UpdateMapping(ctx, UpdateMappingParams{
		HumanParams: HumanParams{Actor: actor, MembershipID: authority.MembershipID, TenantID: tenantID},
		Audit:       normalized.Audit, OccurredAt: now, AuditEventID: auditEventID,
		MappingID: mappingID, ExpectedVersion: version, Matcher: normalized.Matcher,
		Priority: normalized.Priority, Target: normalized.Target,
		ReconciliationMode: normalized.ReconciliationMode, Enabled: normalized.Enabled,
		Notes: normalized.Notes, Reason: normalized.Reason,
	})
	if err != nil {
		return Mapping{}, mapRepositoryError(err)
	}
	if result.ID != mappingID || result.Version != version+1 || !validMapping(result, tenantID) ||
		result.Enabled != normalized.Enabled || !sameMappingDefinition(result, normalized.Matcher,
		normalized.Priority, normalized.Target, normalized.ReconciliationMode, normalized.Notes) {
		return Mapping{}, ErrUnavailable
	}
	return result, nil
}

func (s *Service) ArchiveMapping(
	ctx context.Context,
	actor authorization.Actor,
	tenantID, mappingID uuid.UUID,
	input ArchiveMappingInput,
) (int64, error) {
	normalized, version, err := normalizeArchiveMapping(mappingID, input)
	if err != nil {
		return 0, err
	}
	authority, err := s.resolveAndRequire(ctx, actor, tenantID, authorization.TenantPermissionIdentityMappingManage)
	if err != nil {
		return 0, err
	}
	if s.evaluator.RequireTenant(authority, authorization.TenantPermissionRoleGrant,
		authorization.ResourceContext{TenantID: tenantID}) != nil {
		return 0, ErrForbidden
	}
	if s.administration == nil {
		return 0, ErrUnavailable
	}
	now, err := s.currentTime()
	if err != nil {
		return 0, err
	}
	auditEventID, err := s.nextID()
	if err != nil {
		return 0, err
	}
	updated, err := s.administration.ArchiveMapping(ctx, ArchiveMappingParams{
		HumanParams: HumanParams{Actor: actor, MembershipID: authority.MembershipID, TenantID: tenantID},
		Audit:       normalized.Audit, OccurredAt: now, AuditEventID: auditEventID,
		MappingID: mappingID, ExpectedVersion: version, Reason: normalized.Reason,
	})
	if err != nil {
		return 0, mapRepositoryError(err)
	}
	if updated != version+1 {
		return 0, ErrUnavailable
	}
	return updated, nil
}

func (s *Service) resolveMappingMutation(
	ctx context.Context,
	actor authorization.Actor,
	tenantID uuid.UUID,
	target MappingTarget,
) (authorization.TenantAuthority, error) {
	authority, err := s.resolveAndRequire(ctx, actor, tenantID, authorization.TenantPermissionIdentityMappingManage)
	if err != nil {
		return authorization.TenantAuthority{}, err
	}
	resource := authorization.ResourceContext{TenantID: tenantID}
	if s.evaluator.RequireTenant(authority, authorization.TenantPermissionRoleGrant, resource) != nil {
		return authorization.TenantAuthority{}, ErrForbidden
	}
	if target.OperatorTeamAssignment != nil {
		relationship := authorization.OperatorTeamRelationship{
			OperatorTeamID:    target.OperatorTeamAssignment.OperatorTeamID,
			AssignmentEpochID: target.OperatorTeamAssignment.AssignmentEpochID,
		}
		resource.OperatorTeamRelationship = &relationship
		if s.evaluator.RequireTenant(authority, authorization.TenantPermissionOperatorTeamRosterManage, resource) != nil {
			return authorization.TenantAuthority{}, ErrForbidden
		}
	}
	return authority, nil
}

func bindingPage(rows []Binding, limit int) ([]Binding, *uuid.UUID) {
	if len(rows) <= limit {
		return append([]Binding(nil), rows...), nil
	}
	items := append([]Binding(nil), rows[:limit]...)
	next := items[len(items)-1].ID
	return items, &next
}

func mappingPage(rows []Mapping, limit int) ([]Mapping, *MappingCursor) {
	if len(rows) <= limit {
		return append([]Mapping(nil), rows...), nil
	}
	items := append([]Mapping(nil), rows[:limit]...)
	last := items[len(items)-1]
	next := MappingCursor{Priority: last.Priority, ID: last.ID}
	return items, &next
}

func compareMappingOrder(left, right Mapping) int {
	return compareMappingTuple(left.Priority, left.ID, right.Priority, right.ID)
}

func compareMappingTuple(leftPriority int, leftID uuid.UUID, rightPriority int, rightID uuid.UUID) int {
	if leftPriority < rightPriority {
		return -1
	}
	if leftPriority > rightPriority {
		return 1
	}
	return bytes.Compare(leftID[:], rightID[:])
}

func validBinding(value Binding, tenantID uuid.UUID) bool {
	if !validUUIDv7(value.ID) || value.TenantID != tenantID || !validUUIDv7(value.ProviderID) ||
		!providerKeyPattern.MatchString(value.LoginKey) || value.ProfilePriority < 0 ||
		value.ProfilePriority > maximumLDAPAdministrationPriority || value.AuthRevision < 1 ||
		value.AuthRevision > maximumResourceVersion || value.Version < 1 || value.Version > maximumResourceVersion ||
		!validInstant(value.CreatedAt) || !validInstant(value.UpdatedAt) || value.UpdatedAt.Before(value.CreatedAt) {
		return false
	}
	if value.Enabled != (value.CurrentAccessEpochID != nil) {
		return false
	}
	if value.CurrentAccessEpochID != nil && !validUUIDv7(*value.CurrentAccessEpochID) {
		return false
	}
	if value.ArchivedAt != nil {
		return !value.Enabled && validInstant(*value.ArchivedAt) &&
			!value.ArchivedAt.Before(value.CreatedAt) && !value.ArchivedAt.After(value.UpdatedAt)
	}
	return true
}

func validMapping(value Mapping, tenantID uuid.UUID) bool {
	definition, ok := normalizedMappingDefinition(value.Matcher, value.Target, value.ReconciliationMode)
	if !ok || definition.Matcher != value.Matcher || !sameMappingTarget(definition.Target, value.Target) ||
		!validUUIDv7(value.ID) || value.TenantID != tenantID || !validUUIDv7(value.BindingID) ||
		value.Priority < 0 || value.Priority > maximumLDAPAdministrationPriority ||
		!validText(value.Notes, 0, 2000) || value.Version < 1 || value.Version > maximumResourceVersion ||
		!validInstant(value.CreatedAt) || !validInstant(value.UpdatedAt) || value.UpdatedAt.Before(value.CreatedAt) {
		return false
	}
	if value.Enabled != (value.CurrentSourceEpoch != nil) {
		return false
	}
	if value.CurrentSourceEpoch != nil {
		epoch := value.CurrentSourceEpoch
		if !validUUIDv7(epoch.ID) || epoch.Sequence < 1 || epoch.Sequence > maximumResourceVersion ||
			epoch.ReconciliationMode != value.ReconciliationMode || !validInstant(epoch.ActivatedAt) ||
			epoch.ActivatedAt.Before(value.CreatedAt) || epoch.ActivatedAt.After(value.UpdatedAt) {
			return false
		}
	}
	if value.LastMatchedAt != nil && (!validInstant(*value.LastMatchedAt) || value.LastMatchedAt.Before(value.CreatedAt)) {
		return false
	}
	if value.ArchivedAt != nil {
		return !value.Enabled && validInstant(*value.ArchivedAt) &&
			!value.ArchivedAt.Before(value.CreatedAt) && !value.ArchivedAt.After(value.UpdatedAt)
	}
	return true
}

func sameMappingDefinition(
	value Mapping,
	matcher MappingMatcher,
	priority int,
	target MappingTarget,
	mode ReconciliationMode,
	notes string,
) bool {
	return value.Matcher == matcher && value.Priority == priority && sameMappingTarget(value.Target, target) &&
		value.ReconciliationMode == mode && value.Notes == notes
}

func sameMappingTarget(left, right MappingTarget) bool {
	if left.TenantSecurityGroupID != right.TenantSecurityGroupID ||
		!slices.Equal(left.RoleIDs, right.RoleIDs) ||
		(left.OperatorTeamAssignment == nil) != (right.OperatorTeamAssignment == nil) {
		return false
	}
	return left.OperatorTeamAssignment == nil || *left.OperatorTeamAssignment == *right.OperatorTeamAssignment
}
