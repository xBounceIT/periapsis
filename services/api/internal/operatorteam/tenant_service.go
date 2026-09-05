package operatorteam

import (
	"context"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

func (s *Service) ListTenantAssignments(ctx context.Context, actor authorization.Actor, tenantID uuid.UUID, input ListTenantAssignmentsInput) (TenantAssignmentPage, error) {
	if err := validateTenantActor(actor, tenantID); err != nil {
		return TenantAssignmentPage{}, err
	}
	page, err := normalizedPageInput(input.PageInput)
	if err != nil {
		return TenantAssignmentPage{}, err
	}
	if _, err = s.resolveAndRequire(ctx, actor, tenantID, tenantPermissionCheck{
		Permission: authorization.TenantPermissionOperatorTeamRead,
		Resource:   authorization.ResourceContext{TenantID: tenantID},
	}); err != nil {
		return TenantAssignmentPage{}, err
	}
	rows, err := s.repository.ListTenantAssignments(ctx, ListTenantAssignmentsParams{
		Actor: actor, TenantID: tenantID, After: page.After, Limit: int32(page.Limit + 1),
		IncludeEnded: input.IncludeEnded,
	})
	if err != nil {
		return TenantAssignmentPage{}, mapRepositoryError(err)
	}
	for _, row := range rows {
		if !validAssignment(row, tenantID, row.OperatorTeam.ID, row.EpochID) ||
			!input.IncludeEnded && row.State == AssignmentStateEnded {
			return TenantAssignmentPage{}, ErrUnavailable
		}
	}
	items, next, err := boundedPage(rows, page.After, page.Limit, func(assignment TenantAssignment) uuid.UUID {
		return assignment.EpochID
	})
	if err != nil {
		return TenantAssignmentPage{}, err
	}
	return TenantAssignmentPage{Items: items, NextCursor: next}, nil
}

func (s *Service) GetTenantAssignment(ctx context.Context, actor authorization.Actor, tenantID, operatorTeamID, epochID uuid.UUID) (TenantAssignment, error) {
	if err := validateTenantActor(actor, tenantID); err != nil {
		return TenantAssignment{}, err
	}
	if !validUUIDv7(operatorTeamID) || !validUUIDv7(epochID) {
		return TenantAssignment{}, ErrInvalidInput
	}
	if _, err := s.resolveAndRequire(ctx, actor, tenantID, tenantPermissionCheck{
		Permission: authorization.TenantPermissionOperatorTeamRead,
		Resource: authorization.ResourceContext{
			TenantID: tenantID,
			OperatorTeamRelationship: &authorization.OperatorTeamRelationship{
				OperatorTeamID: operatorTeamID, AssignmentEpochID: epochID,
			},
		},
	}); err != nil {
		return TenantAssignment{}, err
	}
	return s.loadTenantAssignment(ctx, actor, tenantID, operatorTeamID, epochID)
}

func (s *Service) StartTenantAssignment(ctx context.Context, actor authorization.Actor, tenantID, operatorTeamID uuid.UUID, input StartTenantAssignmentInput) (TenantAssignment, error) {
	if err := validateTenantActor(actor, tenantID); err != nil {
		return TenantAssignment{}, err
	}
	normalized, err := normalizeStartAssignmentInput(operatorTeamID, input)
	if err != nil {
		return TenantAssignment{}, err
	}
	_, err = s.resolveAndRequire(ctx, actor, tenantID, tenantPermissionCheck{
		Permission: authorization.TenantPermissionOperatorTeamManage,
		Resource:   authorization.ResourceContext{TenantID: tenantID},
	})
	if err != nil {
		return TenantAssignment{}, err
	}
	now, err := s.currentTime()
	if err != nil {
		return TenantAssignment{}, err
	}
	epochID, err := s.nextID()
	if err != nil {
		return TenantAssignment{}, err
	}
	result, err := s.repository.StartTenantAssignment(ctx, StartTenantAssignmentParams{
		Actor: actor, Audit: normalized.Audit, OccurredAt: now, TenantID: tenantID,
		OperatorTeamID: operatorTeamID, EpochID: epochID, Reason: normalized.Reason,
		IdempotencyKey: normalized.IdempotencyKey,
	})
	if err != nil {
		return TenantAssignment{}, mapRepositoryError(err)
	}
	assignment := result.Value
	if !validAssignment(assignment, tenantID, operatorTeamID, assignment.EpochID) ||
		assignment.StartReason != normalized.Reason || assignment.StartedByUserID != actor.UserID {
		return TenantAssignment{}, ErrUnavailable
	}
	if !result.Replayed && (assignment.EpochID != epochID || assignment.State != AssignmentStateActive) {
		return TenantAssignment{}, ErrUnavailable
	}
	return assignment, nil
}

func (s *Service) EndTenantAssignment(ctx context.Context, actor authorization.Actor, tenantID, operatorTeamID, epochID uuid.UUID, input EndTenantAssignmentInput) error {
	if err := validateTenantActor(actor, tenantID); err != nil {
		return err
	}
	normalized, version, err := normalizeEndAssignmentInput(operatorTeamID, epochID, input)
	if err != nil {
		return err
	}
	_, err = s.resolveAndRequire(ctx, actor, tenantID,
		tenantPermissionCheck{
			Permission: authorization.TenantPermissionOperatorTeamManage,
			Resource:   authorization.ResourceContext{TenantID: tenantID},
		},
		tenantPermissionCheck{
			Permission: authorization.TenantPermissionRoleGrant,
			Resource:   authorization.ResourceContext{TenantID: tenantID},
		},
	)
	if err != nil {
		return err
	}
	current, err := s.loadTenantAssignment(ctx, actor, tenantID, operatorTeamID, epochID)
	if err != nil {
		return err
	}
	if current.Version != version {
		return ErrPreconditionFailed
	}
	if current.State == AssignmentStateEnded {
		return ErrConflict
	}
	now, err := s.currentTime()
	if err != nil {
		return err
	}
	return mapRepositoryError(s.repository.EndTenantAssignment(ctx, EndTenantAssignmentParams{
		Actor: actor, Audit: normalized.Audit, OccurredAt: now, TenantID: tenantID,
		OperatorTeamID: operatorTeamID, EpochID: epochID, Reason: normalized.Reason,
		ExpectedVersion: version,
	}))
}

func (s *Service) ListRosterEntries(ctx context.Context, actor authorization.Actor, tenantID, operatorTeamID, epochID uuid.UUID, input ListRosterEntriesInput) (RosterEntryPage, error) {
	if err := validateTenantActor(actor, tenantID); err != nil {
		return RosterEntryPage{}, err
	}
	if !validUUIDv7(operatorTeamID) || !validUUIDv7(epochID) {
		return RosterEntryPage{}, ErrInvalidInput
	}
	page, err := normalizedPageInput(input.PageInput)
	if err != nil {
		return RosterEntryPage{}, err
	}
	if _, err = s.resolveAndRequire(ctx, actor, tenantID,
		tenantPermissionCheck{
			Permission: authorization.TenantPermissionOperatorTeamRead,
			Resource: authorization.ResourceContext{
				TenantID: tenantID,
				OperatorTeamRelationship: &authorization.OperatorTeamRelationship{
					OperatorTeamID: operatorTeamID, AssignmentEpochID: epochID,
				},
			},
		},
		tenantPermissionCheck{
			Permission: authorization.TenantPermissionUserRead,
			Resource:   authorization.ResourceContext{TenantID: tenantID},
		},
	); err != nil {
		return RosterEntryPage{}, err
	}
	assignment, err := s.loadTenantAssignment(ctx, actor, tenantID, operatorTeamID, epochID)
	if err != nil {
		return RosterEntryPage{}, err
	}
	rows, err := s.repository.ListRosterEntries(ctx, ListRosterEntriesParams{
		Actor: actor, TenantID: tenantID, OperatorTeamID: operatorTeamID,
		AssignmentEpochID: epochID, After: page.After, Limit: int32(page.Limit + 1),
		IncludeRevoked: input.IncludeRevoked,
	})
	if err != nil {
		return RosterEntryPage{}, mapRepositoryError(err)
	}
	now, err := s.currentTime()
	if err != nil {
		return RosterEntryPage{}, err
	}
	for _, row := range rows {
		if !validRosterEntry(row, assignment, now) ||
			!input.IncludeRevoked && row.State == RosterEntryStateRevoked {
			return RosterEntryPage{}, ErrUnavailable
		}
	}
	items, next, err := boundedPage(rows, page.After, page.Limit, func(entry RosterEntry) uuid.UUID {
		return entry.ID
	})
	if err != nil {
		return RosterEntryPage{}, err
	}
	return RosterEntryPage{Items: items, NextCursor: next}, nil
}

func (s *Service) AddRosterEntry(ctx context.Context, actor authorization.Actor, tenantID, operatorTeamID, epochID uuid.UUID, input AddRosterEntryInput) (RosterEntry, error) {
	if err := validateTenantActor(actor, tenantID); err != nil {
		return RosterEntry{}, err
	}
	normalized, err := normalizeAddRosterEntryInput(operatorTeamID, epochID, input)
	if err != nil {
		return RosterEntry{}, err
	}
	now, err := s.currentTime()
	if err != nil {
		return RosterEntry{}, err
	}
	freshLifetimeValid := normalized.ExpiresAt == nil || normalized.ExpiresAt.After(now)
	_, err = s.resolveAndRequire(ctx, actor, tenantID,
		tenantPermissionCheck{
			Permission: authorization.TenantPermissionOperatorTeamRosterManage,
			Resource: authorization.ResourceContext{
				TenantID: tenantID,
				OperatorTeamRelationship: &authorization.OperatorTeamRelationship{
					OperatorTeamID: operatorTeamID, AssignmentEpochID: epochID,
				},
			},
		},
		tenantPermissionCheck{
			Permission: authorization.TenantPermissionRoleGrant,
			Resource:   authorization.ResourceContext{TenantID: tenantID},
		},
	)
	if err != nil {
		return RosterEntry{}, err
	}
	assignment, err := s.loadTenantAssignment(ctx, actor, tenantID, operatorTeamID, epochID)
	if err != nil {
		return RosterEntry{}, err
	}
	freshAssignmentValid := assignment.State == AssignmentStateActive
	rosterEntryID, err := s.nextID()
	if err != nil {
		return RosterEntry{}, err
	}
	result, err := s.repository.AddRosterEntry(ctx, AddRosterEntryParams{
		Actor: actor, Audit: normalized.Audit, OccurredAt: now, TenantID: tenantID,
		OperatorTeamID: operatorTeamID, AssignmentEpochID: epochID, RosterEntryID: rosterEntryID,
		MembershipID: normalized.MembershipID, Reason: normalized.Reason,
		ExpiresAt: normalized.ExpiresAt, IdempotencyKey: normalized.IdempotencyKey,
	})
	if err != nil {
		return RosterEntry{}, mapRepositoryError(err)
	}
	entry := result.Value
	if entry.Member.MembershipID != normalized.MembershipID || !entry.ManagedByOperatorTeamAPI ||
		entry.Provenance.GrantedByUserID == nil || *entry.Provenance.GrantedByUserID != actor.UserID ||
		entry.Provenance.Reason != normalized.Reason ||
		!equalOptionalInstant(entry.Provenance.ExpiresAt, normalized.ExpiresAt) ||
		!validRosterEntry(entry, assignment, now) {
		return RosterEntry{}, ErrUnavailable
	}
	if !result.Replayed && (!freshAssignmentValid || !freshLifetimeValid ||
		entry.ID != rosterEntryID || entry.State != RosterEntryStateActive ||
		entry.Member.Status != authorization.MembershipStatusActive) {
		return RosterEntry{}, ErrUnavailable
	}
	return entry, nil
}

func (s *Service) RevokeRosterEntry(ctx context.Context, actor authorization.Actor, tenantID, operatorTeamID, epochID, rosterEntryID uuid.UUID, input RevokeRosterEntryInput) error {
	if err := validateTenantActor(actor, tenantID); err != nil {
		return err
	}
	normalized, expectedEntityTag, version, err := normalizeRevokeRosterEntryInput(operatorTeamID, epochID, rosterEntryID, input)
	if err != nil {
		return err
	}
	if _, err = s.resolveAndRequire(ctx, actor, tenantID,
		tenantPermissionCheck{
			Permission: authorization.TenantPermissionOperatorTeamRosterManage,
			Resource: authorization.ResourceContext{
				TenantID: tenantID,
				OperatorTeamRelationship: &authorization.OperatorTeamRelationship{
					OperatorTeamID: operatorTeamID, AssignmentEpochID: epochID,
				},
			},
		},
		tenantPermissionCheck{
			Permission: authorization.TenantPermissionRoleGrant,
			Resource:   authorization.ResourceContext{TenantID: tenantID},
		},
	); err != nil {
		return err
	}
	assignment, err := s.loadTenantAssignment(ctx, actor, tenantID, operatorTeamID, epochID)
	if err != nil {
		return err
	}
	if assignment.State != AssignmentStateActive {
		return ErrConflict
	}
	current, err := s.loadRosterEntry(ctx, actor, assignment, rosterEntryID)
	if err != nil {
		return err
	}
	if current.Version != version {
		return ErrPreconditionFailed
	}
	currentEntityTag, err := RosterEntryEntityTag(current)
	if err != nil {
		return ErrUnavailable
	}
	if currentEntityTag != expectedEntityTag {
		return ErrPreconditionFailed
	}
	if !current.ManagedByOperatorTeamAPI || current.State != RosterEntryStateActive {
		return ErrConflict
	}
	now, err := s.currentTime()
	if err != nil {
		return err
	}
	return mapRepositoryError(s.repository.RevokeRosterEntry(ctx, RevokeRosterEntryParams{
		Actor: actor, Audit: normalized.Audit, OccurredAt: now, TenantID: tenantID,
		OperatorTeamID: operatorTeamID, AssignmentEpochID: epochID, RosterEntryID: rosterEntryID,
		Reason: normalized.Reason, ExpectedEntityTag: expectedEntityTag,
	}))
}

type tenantPermissionCheck struct {
	Permission authorization.TenantPermission
	Resource   authorization.ResourceContext
}

func (s *Service) resolveAndRequire(ctx context.Context, actor authorization.Actor, tenantID uuid.UUID, checks ...tenantPermissionCheck) (authorization.TenantAuthority, error) {
	authority, err := s.repository.ResolveAuthority(ctx, authorization.ResolveAuthorityParams{
		Actor: actor, TenantID: tenantID,
	})
	if err != nil {
		return authorization.TenantAuthority{}, mapRepositoryError(err)
	}
	if authority.TenantID != tenantID || authority.Principal.ID != actor.UserID ||
		authority.Principal.Kind != authorization.PrincipalKindHuman ||
		!validUUIDv7(authority.MembershipID) {
		return authorization.TenantAuthority{}, ErrUnavailable
	}
	for _, check := range checks {
		if err := s.evaluator.RequireTenant(authority, check.Permission, check.Resource); err != nil {
			return authorization.TenantAuthority{}, ErrForbidden
		}
	}
	return authority, nil
}

func (s *Service) loadTenantAssignment(ctx context.Context, actor authorization.Actor, tenantID, operatorTeamID, epochID uuid.UUID) (TenantAssignment, error) {
	assignment, err := s.repository.GetTenantAssignment(ctx, GetTenantAssignmentParams{
		Actor: actor, TenantID: tenantID, OperatorTeamID: operatorTeamID, EpochID: epochID,
	})
	if err != nil {
		return TenantAssignment{}, mapRepositoryError(err)
	}
	if !validAssignment(assignment, tenantID, operatorTeamID, epochID) {
		return TenantAssignment{}, ErrUnavailable
	}
	return assignment, nil
}

func (s *Service) loadRosterEntry(ctx context.Context, actor authorization.Actor, assignment TenantAssignment, rosterEntryID uuid.UUID) (RosterEntry, error) {
	entry, err := s.repository.GetRosterEntry(ctx, GetRosterEntryParams{
		Actor: actor, TenantID: assignment.TenantID, OperatorTeamID: assignment.OperatorTeam.ID,
		AssignmentEpochID: assignment.EpochID, RosterEntryID: rosterEntryID,
	})
	if err != nil {
		return RosterEntry{}, mapRepositoryError(err)
	}
	now, err := s.currentTime()
	if err != nil {
		return RosterEntry{}, err
	}
	if entry.ID != rosterEntryID || !validRosterEntry(entry, assignment, now) {
		return RosterEntry{}, ErrUnavailable
	}
	return entry, nil
}
