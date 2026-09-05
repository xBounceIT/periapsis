package operatorteam

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

type Service struct {
	repository Repository
	evaluator  authorization.Evaluator
	now        func() time.Time
	newID      func() (uuid.UUID, error)
}

func NewService(repository Repository) (*Service, error) {
	if repository == nil {
		return nil, errors.New("operator team repository is required")
	}
	return &Service{
		repository: repository,
		evaluator:  authorization.Evaluator{},
		now:        time.Now,
		newID:      uuid.NewV7,
	}, nil
}

func (s *Service) ListOperatorTeams(ctx context.Context, session authentication.Session, input ListOperatorTeamsInput) (OperatorTeamPage, error) {
	actor, err := s.requirePlatform(session, authorization.PermissionPlatformOperatorTeamRead)
	if err != nil {
		return OperatorTeamPage{}, err
	}
	page, err := normalizedPageInput(input.PageInput)
	if err != nil {
		return OperatorTeamPage{}, err
	}
	rows, err := s.repository.ListOperatorTeams(ctx, ListOperatorTeamsParams{
		Actor: actor, After: page.After, Limit: int32(page.Limit + 1),
		IncludeArchived: input.IncludeArchived,
	})
	if err != nil {
		return OperatorTeamPage{}, mapRepositoryError(err)
	}
	for _, row := range rows {
		if !validOperatorTeam(row) || !input.IncludeArchived && row.State == OperatorTeamStateArchived {
			return OperatorTeamPage{}, ErrUnavailable
		}
	}
	items, next, err := boundedPage(rows, page.After, page.Limit, func(team OperatorTeam) uuid.UUID {
		return team.ID
	})
	if err != nil {
		return OperatorTeamPage{}, err
	}
	return OperatorTeamPage{Items: items, NextCursor: next}, nil
}

func (s *Service) GetOperatorTeam(ctx context.Context, session authentication.Session, operatorTeamID uuid.UUID) (OperatorTeam, error) {
	actor, err := s.requirePlatform(session, authorization.PermissionPlatformOperatorTeamRead)
	if err != nil {
		return OperatorTeam{}, err
	}
	if !validUUIDv7(operatorTeamID) {
		return OperatorTeam{}, ErrInvalidInput
	}
	return s.loadOperatorTeam(ctx, actor, operatorTeamID)
}

func (s *Service) CreateOperatorTeam(ctx context.Context, session authentication.Session, input CreateOperatorTeamInput) (OperatorTeam, error) {
	actor, err := s.requirePlatform(session, authorization.PermissionPlatformOperatorTeamManage)
	if err != nil {
		return OperatorTeam{}, err
	}
	normalized, err := normalizeCreateOperatorTeamInput(input)
	if err != nil {
		return OperatorTeam{}, err
	}
	now, err := s.currentTime()
	if err != nil {
		return OperatorTeam{}, err
	}
	operatorTeamID, err := s.nextID()
	if err != nil {
		return OperatorTeam{}, err
	}
	result, err := s.repository.CreateOperatorTeam(ctx, CreateOperatorTeamParams{
		Actor: actor, Audit: normalized.Audit, OccurredAt: now, OperatorTeamID: operatorTeamID,
		Key: normalized.Key, Name: normalized.Name, Description: normalized.Description,
		IdempotencyKey: normalized.IdempotencyKey,
	})
	if err != nil {
		return OperatorTeam{}, mapRepositoryError(err)
	}
	team := result.Value
	if team.Key != normalized.Key || !validOperatorTeam(team) {
		return OperatorTeam{}, ErrUnavailable
	}
	if !result.Replayed && (team.ID != operatorTeamID || team.State != OperatorTeamStateActive) {
		return OperatorTeam{}, ErrUnavailable
	}
	if team.CreatedByUserID == nil || *team.CreatedByUserID != actor.UserID {
		return OperatorTeam{}, ErrUnavailable
	}
	return team, nil
}

func (s *Service) PatchOperatorTeam(ctx context.Context, session authentication.Session, operatorTeamID uuid.UUID, input PatchOperatorTeamInput) (OperatorTeam, error) {
	actor, err := s.requirePlatform(session, authorization.PermissionPlatformOperatorTeamManage)
	if err != nil {
		return OperatorTeam{}, err
	}
	normalized, version, err := normalizePatchOperatorTeamInput(operatorTeamID, input)
	if err != nil {
		return OperatorTeam{}, err
	}
	current, err := s.loadOperatorTeam(ctx, actor, operatorTeamID)
	if err != nil {
		return OperatorTeam{}, err
	}
	if current.Version != version {
		return OperatorTeam{}, ErrPreconditionFailed
	}
	if current.State == OperatorTeamStateArchived {
		return OperatorTeam{}, ErrConflict
	}
	now, err := s.currentTime()
	if err != nil {
		return OperatorTeam{}, err
	}
	team, err := s.repository.PatchOperatorTeam(ctx, PatchOperatorTeamParams{
		Actor: actor, Audit: normalized.Audit, OccurredAt: now, OperatorTeamID: operatorTeamID,
		Name: normalized.Name, Description: normalized.Description, ExpectedVersion: version,
	})
	if err != nil {
		return OperatorTeam{}, mapRepositoryError(err)
	}
	if team.ID != operatorTeamID || team.State != OperatorTeamStateActive || !validOperatorTeam(team) {
		return OperatorTeam{}, ErrUnavailable
	}
	return team, nil
}

func (s *Service) ArchiveOperatorTeam(ctx context.Context, session authentication.Session, operatorTeamID uuid.UUID, input ArchiveOperatorTeamInput) error {
	actor, err := s.requirePlatform(session, authorization.PermissionPlatformOperatorTeamManage)
	if err != nil {
		return err
	}
	normalized, version, err := normalizeArchiveOperatorTeamInput(operatorTeamID, input)
	if err != nil {
		return err
	}
	current, err := s.loadOperatorTeam(ctx, actor, operatorTeamID)
	if err != nil {
		return err
	}
	if current.Version != version {
		return ErrPreconditionFailed
	}
	if current.State == OperatorTeamStateArchived || current.ActiveAssignmentCount > 0 {
		return ErrConflict
	}
	now, err := s.currentTime()
	if err != nil {
		return err
	}
	return mapRepositoryError(s.repository.ArchiveOperatorTeam(ctx, ArchiveOperatorTeamParams{
		Actor: actor, Audit: normalized.Audit, OccurredAt: now,
		OperatorTeamID: operatorTeamID, Reason: normalized.Reason, ExpectedVersion: version,
	}))
}

func (s *Service) requirePlatform(session authentication.Session, permission authorization.Permission) (PlatformActor, error) {
	actor, err := validatePlatformSession(session)
	if err != nil {
		return PlatformActor{}, err
	}
	if err := s.evaluator.Require(session.Permissions, permission); err != nil {
		return PlatformActor{}, ErrForbidden
	}
	return actor, nil
}

func (s *Service) loadOperatorTeam(ctx context.Context, actor PlatformActor, operatorTeamID uuid.UUID) (OperatorTeam, error) {
	team, err := s.repository.GetOperatorTeam(ctx, GetOperatorTeamParams{Actor: actor, OperatorTeamID: operatorTeamID})
	if err != nil {
		return OperatorTeam{}, mapRepositoryError(err)
	}
	if team.ID != operatorTeamID || !validOperatorTeam(team) {
		return OperatorTeam{}, ErrUnavailable
	}
	return team, nil
}

func (s *Service) currentTime() (time.Time, error) {
	value := s.now().UTC().Truncate(time.Microsecond)
	if value.IsZero() {
		return time.Time{}, ErrUnavailable
	}
	if _, err := value.MarshalJSON(); err != nil {
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
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, authorization.ErrDenied), errors.Is(err, authorization.ErrForbidden), errors.Is(err, ErrForbidden):
		return ErrForbidden
	case errors.Is(err, authorization.ErrInvalidInput), errors.Is(err, ErrInvalidInput):
		return ErrInvalidInput
	case errors.Is(err, authorization.ErrNotFound), errors.Is(err, ErrNotFound):
		return ErrNotFound
	case errors.Is(err, authorization.ErrConflict), errors.Is(err, ErrConflict):
		return ErrConflict
	case errors.Is(err, authorization.ErrPreconditionRequired), errors.Is(err, ErrPreconditionRequired):
		return ErrPreconditionRequired
	case errors.Is(err, authorization.ErrPreconditionFailed), errors.Is(err, ErrPreconditionFailed):
		return ErrPreconditionFailed
	case errors.Is(err, authorization.ErrUnavailable), errors.Is(err, ErrUnavailable):
		return ErrUnavailable
	default:
		return ErrUnavailable
	}
}
